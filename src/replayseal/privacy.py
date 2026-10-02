"""Deterministic keyed redaction. Policy rules run before filesystem writes."""
from __future__ import annotations

import hashlib
import hmac
import re
from dataclasses import dataclass, field

from .integrity import canonical, digest, IntegrityError

TOKEN = re.compile(r"~rs1:[0-9a-f]{64}~")
DEFAULT_FIELDS = ("password", "secret", "token", "api_key", "authorization",
                  "cookie", "set_cookie", "access_token", "refresh_token",
                  "client_secret", "user_id", "customer_id", "account_id")
DEFAULT_PATTERNS = (
    r"(?i)[a-z0-9.!#$%&'*+/=?^_`{|}~-]+@[a-z0-9](?:[a-z0-9.-]*[a-z0-9])?\.[a-z]{2,}",
    r"(?i)\bBearer\s+[a-z0-9._~+/-]+=*",
    r"\b(?:sk|ghp|github_pat)[_-][A-Za-z0-9_-]{16,}\b",
)


class PrivacyError(ValueError):
    pass


class _Pseudonym(str):
    """Replay-issued value; ordinary matching-looking strings remain untrusted."""
    def __new__(cls, value: str, key_id: str):
        obj = super().__new__(cls, value)
        obj.key_id = key_id
        return obj


def _field(name: str) -> str:
    return re.sub(r"[_\-\s]", "", name).casefold()


@dataclass(frozen=True)
class Policy:
    key: bytes = field(repr=False)
    fields: tuple[str, ...] = DEFAULT_FIELDS
    paths: tuple[str, ...] = ()
    patterns: tuple[str, ...] = DEFAULT_PATTERNS

    def __post_init__(self) -> None:
        if type(self.key) is not bytes or len(self.key) < 32:
            raise PrivacyError("supply a private key of at least 32 bytes")
        for attribute in ("fields", "paths", "patterns"):
            rules = getattr(self, attribute)
            if type(rules) not in (tuple, list):
                raise PrivacyError("policy rules must be a list or tuple")
            object.__setattr__(self, attribute, tuple(rules))
        if any(type(x) is not str for x in (*self.fields, *self.paths, *self.patterns)):
            raise PrivacyError("policy rules must be strings")
        try:
            for pattern in self.patterns:
                re.compile(pattern)
        except re.error as exc:
            raise PrivacyError("invalid redaction expression") from exc
        if any(not path.startswith("/") for path in self.paths):
            raise PrivacyError("paths must use JSON Pointer syntax starting with /")

    @property
    def key_id(self) -> str:
        return hmac.new(self.key, b"replayseal/key-id/v1", hashlib.sha256).hexdigest()

    @property
    def policy_id(self) -> str:
        return digest({"version": 1, "fields": list(self.fields), "paths": list(self.paths),
                       "patterns": list(self.patterns)})

    def _token(self, value: object) -> str:
        mac = hmac.new(self.key, b"replayseal/value/v1\0" + canonical(value), hashlib.sha256).hexdigest()
        return f"~rs1:{mac}~"

    def _text(self, value: str) -> str:
        # Reserve the token namespace: user-supplied lookalikes cannot impersonate a replay value.
        value = TOKEN.sub(lambda match: self._token(match.group()), value)
        for pattern in self.patterns:
            value = re.sub(pattern, lambda match: self._token(match.group()), value)
        return value

    def _path_matches(self, path: tuple[str, ...]) -> bool:
        for pattern in self.paths:
            parts = tuple(part.replace("~1", "/").replace("~0", "~") for part in pattern[1:].split("/"))
            if len(parts) == len(path) and all(a == "*" or a == b for a, b in zip(parts, path)):
                return True
        return False

    def redact(self, value: object, *, root: str = "arguments") -> object:
        """Return an independent JSON snapshot. No raw values are placed on disk."""
        fields = {_field(name) for name in self.fields}

        def visit(item: object, path: tuple[str, ...], sensitive: bool = False, depth: int = 0):
            if depth > 100:
                raise PrivacyError("JSON nesting exceeds 100 levels")
            if isinstance(item, _Pseudonym):
                if item.key_id != self.key_id:
                    raise PrivacyError("pseudonym belongs to a different key")
                return str(item)
            if sensitive or self._path_matches(path):
                return self._token(item)
            if type(item) is str:
                return self._text(item)
            if type(item) is list:
                return [visit(child, (*path, str(i)), depth=depth + 1) for i, child in enumerate(item)]
            if type(item) is dict:
                result = {}
                for name, child in item.items():
                    if type(name) is not str:
                        raise PrivacyError("JSON object keys must be strings")
                    safe_name = self._text(name)
                    if safe_name in result:
                        raise PrivacyError("redaction produced a duplicate object key")
                    result[safe_name] = visit(child, (*path, name), _field(name) in fields, depth + 1)
                return result
            canonical(item)
            return item

        try:
            result = visit(value, (root,))
            canonical(result)
            return result
        except IntegrityError as exc:
            raise PrivacyError("unsupported value at tool boundary; use plain JSON") from exc

    def restore(self, value: object) -> object:
        """Restore token provenance in a previously verified sanitized output."""
        if type(value) is str and TOKEN.fullmatch(value):
            return _Pseudonym(value, self.key_id)
        if type(value) is list:
            return [self.restore(child) for child in value]
        if type(value) is dict:
            return {key: self.restore(child) for key, child in value.items()}
        return value

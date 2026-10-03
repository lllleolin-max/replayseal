"""Deterministic keyed redaction. Policy rules run before filesystem writes."""
from __future__ import annotations

import hashlib
import hmac
import re
from bisect import bisect_right
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
    """Replay-issued sanitized text; ordinary token-looking strings remain untrusted."""
    def __new__(cls, value: str, key_id: str, policy_id: str):
        obj = super().__new__(cls, value)
        obj.key_id = key_id
        obj.policy_id = policy_id
        return obj

    def __copy__(self):
        # A fresh string subtype also keeps its provenance attributes detached.
        # Reconstruct only existing replay provenance, never infer it from text.
        return type(self)(str(self), self.key_id, self.policy_id)

    def __deepcopy__(self, memo):
        copied = self.__copy__()
        memo[id(self)] = copied
        return copied


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
        return digest({"version": 3, "fields": list(self.fields), "paths": list(self.paths),
                       "patterns": list(self.patterns)})

    def _token(self, value: object) -> str:
        mac = hmac.new(self.key, b"replayseal/value/v1\0" + canonical(value), hashlib.sha256).hexdigest()
        return f"~rs1:{mac}~"

    def _text(self, value: str) -> str:
        verified = isinstance(value, _Pseudonym)
        if verified:
            if value.key_id != self.key_id:
                raise PrivacyError("pseudonym belongs to a different key")
            if TOKEN.fullmatch(value) or value.policy_id == self.policy_id:
                return str(value)
        # A different policy must inspect readable portions even if this string
        # came from verified replay. Complete tokens are already opaque; avoid
        # matching target regexes solely inside their implementation syntax.
        protected = [match.span() for match in TOKEN.finditer(value)] if verified else []
        protected_starts = [start for start, _ in protected]
        # Find every span on the ORIGINAL source. Union overlaps before replacing,
        # so a short earlier rule cannot hide a larger match from a later rule.
        spans = []
        expressions = [re.compile(pattern) for pattern in self.patterns]
        if not verified:
            expressions.insert(0, TOKEN)
        for expression in expressions:
            for match in expression.finditer(value):
                start, end = match.span()
                if start == end:
                    raise PrivacyError("redaction expressions must not match empty spans")
                token_index = bisect_right(protected_starts, start) - 1
                if token_index >= 0 and end <= protected[token_index][1]:
                    continue
                # A target match spanning readable text and a token replaces the
                # complete token too, never leaving token fragments behind.
                token_index = max(token_index, 0)
                while token_index < len(protected) and protected[token_index][0] < end:
                    a, b = protected[token_index]
                    if start < b and a < end:
                        start, end = min(start, a), max(end, b)
                    token_index += 1
                spans.append((start, end))
        merged = []
        for start, end in sorted(spans):
            if merged and start < merged[-1][1]:
                merged[-1] = (merged[-1][0], max(merged[-1][1], end))
            else:
                merged.append((start, end))
        pieces, cursor = [], 0
        for start, end in merged:
            pieces.extend((value[cursor:start], self._token(value[start:end])))
            cursor = end
        pieces.append(value[cursor:])
        return "".join(pieces)

    def _path_matches(self, path: tuple[str, ...]) -> bool:
        for pattern in self.paths:
            parts = tuple(part.replace("~1", "/").replace("~0", "~") for part in pattern[1:].split("/"))
            if len(parts) == len(path) and all(a == "*" or a == b for a, b in zip(parts, path)):
                return True
        return False

    def redact(self, value: object, *, root: str = "arguments") -> object:
        """Return an independent JSON snapshot. No raw values are placed on disk."""
        return self._redact(value, root=root)[0]

    def _redact(self, value: object, *, root: str = "arguments") -> tuple[object, bool]:
        """Also report whole-value promotion for an actionable replay mismatch."""
        fields = {_field(name) for name in self.fields}
        promoted = False

        def plain(item: object, depth: int):
            nonlocal promoted
            if depth > 100:
                raise PrivacyError("JSON nesting exceeds 100 levels")
            if isinstance(item, _Pseudonym):
                if item.key_id != self.key_id:
                    raise PrivacyError("pseudonym belongs to a different key")
                if not TOKEN.fullmatch(item):
                    promoted = True
                return str(item)
            if type(item) is list:
                return [plain(child, depth + 1) for child in item]
            if type(item) is dict:
                result = {}
                for name, child in item.items():
                    if type(name) is not str and not isinstance(name, _Pseudonym):
                        raise PrivacyError("JSON object keys must be strings")
                    result[plain(name, depth + 1)] = plain(child, depth + 1)
                return result
            canonical(item)
            return item

        def visit(item: object, path: tuple[str, ...], sensitive: bool = False, depth: int = 0):
            nonlocal promoted
            if depth > 100:
                raise PrivacyError("JSON nesting exceeds 100 levels")
            protect_whole = sensitive or self._path_matches(path)
            if isinstance(item, _Pseudonym):
                if item.key_id != self.key_id:
                    raise PrivacyError("pseudonym belongs to a different key")
                if TOKEN.fullmatch(item):
                    return str(item)
                if protect_whole:
                    promoted = True
                    return self._token(str(item))
                return self._text(item)
            if protect_whole:
                return self._token(plain(item, depth))
            if type(item) is str:
                return self._text(item)
            if type(item) is list:
                return [visit(child, (*path, str(i)), depth=depth + 1) for i, child in enumerate(item)]
            if type(item) is dict:
                result = {}
                for name, child in item.items():
                    if type(name) is not str and not isinstance(name, _Pseudonym):
                        raise PrivacyError("JSON object keys must be strings")
                    safe_name = self._text(name)
                    if safe_name in result:
                        raise PrivacyError("redaction produced a duplicate object key")
                    result[safe_name] = visit(child, (*path, name), _field(name) in fields, depth + 1)
                return result
            canonical(item)
            return item

        try:
            # Arbitrary exception messages often interpolate otherwise protected
            # field values. Opaque whole-message tokens avoid an error-channel leak.
            result = visit(value, (root,), sensitive=root == "error")
            canonical(result)
            return result, promoted
        except IntegrityError as exc:
            raise PrivacyError("unsupported value at tool boundary; use plain JSON") from exc

    def restore(self, value: object) -> object:
        """Restore token provenance in a previously verified sanitized output."""
        if type(value) is str and TOKEN.search(value):
            return _Pseudonym(value, self.key_id, self.policy_id)
        if type(value) is list:
            return [self.restore(child) for child in value]
        if type(value) is dict:
            return {self.restore(key): self.restore(child) for key, child in value.items()}
        return value

"""Synchronous tool boundary recording and fail-closed deterministic replay."""
from __future__ import annotations

import functools
import inspect
import json
import os
from pathlib import Path
import shutil
import tempfile
import threading
import zipfile

from . import integrity
from .integrity import canonical, digest, verify, IntegrityError, TOOL
from .privacy import Policy, PrivacyError


class ReplayMismatch(AssertionError):
    """The next operation does not match the recorded contract."""


class RecordedToolError(RuntimeError):
    def __init__(self, error_type: str, message: str):
        self.error_type = error_type
        super().__init__(f"recorded {error_type}: {message}")


def _dependencies(values, seen: set[str]) -> list[str]:
    if isinstance(values, str):
        raise ValueError("depends_on must be a sequence of event identifiers")
    result = list(values)
    if any(type(x) is not str for x in result) or len(set(result)) != len(result) or not set(result) <= seen:
        raise ValueError("dependencies must refer to unique earlier events")
    return sorted(result)


class _Boundary:
    def tool(self, name: str | None = None):
        """Decorate synchronous JSON tools; bind defaults for stable signatures."""
        def decorate(function):
            if inspect.iscoroutinefunction(function):
                raise TypeError("async tools are not supported")
            signature = inspect.signature(function)
            tool_name = name or function.__name__

            @functools.wraps(function)
            def wrapped(*args, **kwargs):
                bound = signature.bind(*args, **kwargs)
                bound.apply_defaults()
                return self.call(tool_name, dict(bound.arguments), lambda _: function(*args, **kwargs))
            return wrapped
        return decorate


class Recorder(_Boundary):
    """Record one synchronous run; persist only sanitized event objects on seal."""
    def __init__(self, path: str | Path, policy: Policy):
        self.path, self.policy = Path(path), policy
        self.events: list[dict] = []
        self.closed = False
        self.failed = False
        self._busy = False
        self._owner_thread = threading.get_ident()
        self._seen: set[str] = set()
        self.root: str | None = None

    @property
    def last_id(self) -> str | None:
        return self.events[-1]["id"] if self.events else None

    def call(self, tool: str, arguments: dict, invoke, *, depends_on=()):
        if self.closed or self.failed:
            raise RuntimeError("recorder is sealed or failed")
        if self._busy or threading.get_ident() != self._owner_thread:
            self.failed = True
            raise RuntimeError("nested or cross-thread recording is not supported")
        if type(tool) is not str or not TOOL.fullmatch(tool):
            raise ValueError("tool name must be a static identifier")
        if type(arguments) is not dict:
            raise TypeError("tool arguments must be an object")
        deps = _dependencies(depends_on, self._seen)
        safe_args = self.policy.redact(arguments, root="arguments")
        event = {"id": f"e{len(self.events) + 1:06d}", "tool": tool, "arguments": safe_args,
                 "signature": digest({"tool": tool, "arguments": safe_args}), "depends_on": deps}
        self._busy = True
        completed = False
        try:
            try:
                result = invoke(arguments)
            except Exception as exc:
                if self.failed:
                    raise
                event["outcome"] = {"kind": "error", "type": type(exc).__name__,
                                    "message": self.policy.redact(str(exc), root="error")}
                self.events.append(event)
                self._seen.add(event["id"])
                completed = True
                raise
            if self.failed:
                raise RuntimeError("recorder failed during invocation")
            event["outcome"] = {"kind": "return", "value": self.policy.redact(result, root="result")}
            self.events.append(event)
            self._seen.add(event["id"])
            completed = True
            return result
        finally:
            self._busy = False
            if not completed:
                self.failed = True

    def seal(self) -> str:
        if self.failed or self._busy:
            raise RuntimeError("cannot seal a failed or active recording")
        if self.closed:
            return self.root
        if self.path.exists():
            raise FileExistsError("refusing to replace existing evidence")
        self.path.parent.mkdir(parents=True, exist_ok=True)
        stage = Path(tempfile.mkdtemp(prefix=".replayseal-", dir=self.path.parent))
        try:
            (stage / "objects").mkdir()
            refs = []
            for event in self.events:
                ref = digest(event)
                (stage / "objects" / (ref + ".json")).write_bytes(canonical(event))
                refs.append(ref)
            manifest = {"format": integrity.FORMAT, "policy_id": self.policy.policy_id,
                        "key_id": self.policy.key_id, "events": refs}
            manifest["root"] = digest(manifest)
            (stage / "manifest.json").write_bytes(canonical(manifest))
            verify(stage)
            stage.rename(self.path)
            self.root = manifest["root"]
            self.closed = True
            return self.root
        finally:
            if stage.exists():
                shutil.rmtree(stage)

    def __enter__(self):
        return self

    def __exit__(self, error_type, error, traceback):
        if self.failed and error_type is not None:
            return False
        self.seal()


class Replay(_Boundary):
    """Replay verifies every event up front and never calls the supplied callable."""
    def __init__(self, path: str | Path, policy: Policy, *, expected_root: str | None = None):
        evidence = verify(path, expected_root)
        manifest = evidence["manifest"]
        if manifest["key_id"] != policy.key_id or manifest["policy_id"] != policy.policy_id:
            raise ReplayMismatch("replay requires the recording policy and pseudonym key")
        self.events, self.policy = evidence["events"], policy
        self.position, self.failed, self.closed = 0, False, False
        self._seen: set[str] = set()

    @property
    def last_id(self) -> str | None:
        return self.events[self.position - 1]["id"] if self.position else None

    def _mismatch(self, reason: str):
        self.failed = True
        raise ReplayMismatch(reason)

    def call(self, tool: str, arguments: dict, invoke=None, *, depends_on=()):
        if self.failed or self.closed:
            raise ReplayMismatch("replay is closed or failed")
        if self.position >= len(self.events):
            self._mismatch("unexpected call after end of recording")
        expected = self.events[self.position]
        index = self.position + 1
        if tool != expected["tool"]:
            self._mismatch(f"event {index}: tool differs")
        try:
            if type(arguments) is not dict:
                self._mismatch(f"event {index}: arguments must be an object")
            actual = self.policy.redact(arguments, root="arguments")
        except PrivacyError:
            self._mismatch(f"event {index}: arguments violate the JSON/privacy contract")
        if digest({"tool": tool, "arguments": actual}) != expected["signature"]:
            self._mismatch(f"event {index}: arguments differ")
        try:
            deps = _dependencies(depends_on, self._seen)
        except (ValueError, TypeError):
            self._mismatch(f"event {index}: invalid dependencies")
        if deps != expected["depends_on"]:
            self._mismatch(f"event {index}: causal dependencies differ")
        self.position += 1
        self._seen.add(expected["id"])
        outcome = expected["outcome"]
        if outcome["kind"] == "error":
            raise RecordedToolError(outcome["type"], outcome["message"])
        return self.policy.restore(outcome["value"])

    def finish(self):
        if self.failed:
            raise ReplayMismatch("replay failed previously")
        if self.position != len(self.events):
            self._mismatch(f"replay ended early: {len(self.events) - self.position} unconsumed events")
        self.closed = True

    def __enter__(self):
        return self

    def __exit__(self, error_type, error, traceback):
        if error_type is None:
            self.finish()
        else:
            self.closed = True


def _difference(left, right, path="$"):
    if type(left) is not type(right):
        return path, "type changed"
    if isinstance(left, dict):
        for key in sorted(set(left) | set(right)):
            child = path + "/" + key.replace("~", "~0").replace("/", "~1")
            if key not in left or key not in right:
                return child, "field added or removed"
            found = _difference(left[key], right[key], child)
            if found:
                return found
    elif isinstance(left, list):
        for index, (a, b) in enumerate(zip(left, right)):
            found = _difference(a, b, path + "/" + str(index))
            if found:
                return found
        if len(left) != len(right):
            return path, "list length changed"
    elif left != right:
        return path, "value changed"
    return None


def compare(left: str | Path, right: str | Path) -> dict:
    """Small first-divergence explanation; never include differing payload values."""
    a, b = verify(left), verify(right)
    for field in ("policy_id", "key_id"):
        if a["manifest"][field] != b["manifest"][field]:
            return {"equal": False, "comparable": False, "reason": field + " differs"}
    for index, (x, y) in enumerate(zip(a["events"], b["events"]), 1):
        for field in ("tool", "arguments", "depends_on", "outcome"):
            found = _difference(x[field], y[field], "$/" + field)
            if found:
                return {"equal": False, "comparable": True, "event": index,
                        "path": found[0], "reason": found[1]}
    if len(a["events"]) != len(b["events"]):
        return {"equal": False, "comparable": True, "event": min(len(a["events"]), len(b["events"])) + 1,
                "path": "$/events", "reason": "event added or removed"}
    return {"equal": True, "comparable": True, "events": len(a["events"])}


def export_bundle(path: str | Path, destination: str | Path) -> str:
    """Export only verified, referenced evidence and an independent stdlib verifier."""
    checked = verify(path)
    source, destination = Path(path), Path(destination)
    files = {"manifest.json": canonical(checked["manifest"]),
             "verify_bundle.py": Path(integrity.__file__).read_bytes()}
    for ref, event in zip(checked["manifest"]["events"], checked["events"]):
        files[f"objects/{ref}.json"] = canonical(event)
    with zipfile.ZipFile(destination, "x", compression=zipfile.ZIP_DEFLATED) as archive:
        for name, data in sorted(files.items()):
            info = zipfile.ZipInfo(name, date_time=(1980, 1, 1, 0, 0, 0))
            info.compress_type = zipfile.ZIP_DEFLATED
            info.external_attr = 0o600 << 16
            archive.writestr(info, data)
    return checked["manifest"]["root"]

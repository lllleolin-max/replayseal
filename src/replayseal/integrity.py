"""Standalone, dependency-free verifier. Also copied into exported evidence ZIPs."""
from __future__ import annotations

import hashlib
import json
import re
from pathlib import Path

FORMAT = "replayseal/v1"
MAX_FILE_BYTES = 16 * 1024 * 1024
MAX_TOTAL_BYTES = 64 * 1024 * 1024
MAX_EVENTS = 100_000
HEX = re.compile(r"^[0-9a-f]{64}$")
TOOL = re.compile(r"^[A-Za-z][A-Za-z0-9_.:-]{0,127}$")
ERROR_NAMES = {"ValueError", "TypeError", "RuntimeError", "OSError", "KeyError", "IndexError",
               "LookupError", "TimeoutError", "ConnectionError", "PermissionError",
               "FileNotFoundError", "AssertionError", "ZeroDivisionError", "ToolError"}
PSEUDONYM = re.compile(r"^~rs1:[0-9a-f]{64}~$")


class IntegrityError(ValueError):
    """Evidence is malformed, incomplete, or does not match its content address."""


def canonical(value: object) -> bytes:
    """Canonical UTF-8 JSON; type distinctions and list order are retained."""
    def check(item: object, depth: int = 0) -> None:
        if depth > 100:
            raise IntegrityError("JSON nesting exceeds 100 levels")
        if item is None or type(item) in (bool, int, str):
            return
        if type(item) is float:
            if not (-float("inf") < item < float("inf")):
                raise IntegrityError("non-finite numbers are not supported")
            return
        if type(item) is list:
            for child in item:
                check(child, depth + 1)
            return
        if type(item) is dict and all(type(key) is str for key in item):
            for child in item.values():
                check(child, depth + 1)
            return
        raise IntegrityError("only plain JSON types are supported")
    check(value)
    try:
        return json.dumps(value, sort_keys=True, ensure_ascii=False,
                          allow_nan=False, separators=(",", ":")).encode("utf-8")
    except (ValueError, UnicodeError, RecursionError) as exc:
        raise IntegrityError("invalid JSON representation") from exc


def digest(value: object) -> str:
    return hashlib.sha256(canonical(value)).hexdigest()


def _pairs(pairs: list[tuple[str, object]]) -> dict:
    result = {}
    for key, value in pairs:
        if key in result:
            raise IntegrityError("duplicate JSON object key")
        result[key] = value
    return result


def read_json(path: Path, *, budget: list[int] | None = None) -> object:
    if path.is_symlink():
        raise IntegrityError("symlinked evidence is not accepted")
    try:
        limit = min(MAX_FILE_BYTES, budget[0]) if budget is not None else MAX_FILE_BYTES
        with path.open("rb") as stream:
            data = stream.read(limit + 1)
        if len(data) > limit:
            raise IntegrityError("evidence exceeds file or total size limit")
        if budget is not None:
            budget[0] -= len(data)
        result = json.loads(data, object_pairs_hook=_pairs)
        canonical(result)
        return result
    except (OSError, ValueError, UnicodeError, RecursionError) as exc:
        if isinstance(exc, IntegrityError):
            raise
        raise IntegrityError("cannot read a valid evidence JSON file") from exc


def _keys(value: object, names: set[str]) -> None:
    if type(value) is not dict or set(value) != names:
        raise IntegrityError("unexpected evidence schema")


def verify(path: str | Path, expected_root: str | None = None) -> dict:
    """Return validated manifest/events. expected_root must come from a trusted channel."""
    folder = Path(path)
    for directory in (folder, folder / "objects"):
        if directory.is_symlink() or getattr(directory, "is_junction", lambda: False)():
            raise IntegrityError("linked evidence directories are not accepted")
    budget = [MAX_TOTAL_BYTES]
    manifest = read_json(folder / "manifest.json", budget=budget)
    _keys(manifest, {"format", "policy_id", "key_id", "events", "root"})
    if manifest["format"] != FORMAT:
        raise IntegrityError("unsupported evidence format")
    for key in ("root", "key_id", "policy_id"):
        if type(manifest[key]) is not str or not HEX.fullmatch(manifest[key]):
            raise IntegrityError("invalid manifest digest")
    payload = {key: val for key, val in manifest.items() if key != "root"}
    if digest(payload) != manifest["root"]:
        raise IntegrityError("manifest root mismatch")
    if expected_root is not None and expected_root != manifest["root"]:
        raise IntegrityError("trusted root mismatch")
    refs = manifest["events"]
    if type(refs) is not list or len(refs) > MAX_EVENTS:
        raise IntegrityError("invalid event list")
    events, seen = [], set()
    for index, ref in enumerate(refs, 1):
        if type(ref) is not str or not HEX.fullmatch(ref):
            raise IntegrityError("invalid event content address")
        event = read_json(folder / "objects" / (ref + ".json"), budget=budget)
        if digest(event) != ref:
            raise IntegrityError(f"event {index} content hash mismatch")
        _keys(event, {"id", "tool", "arguments", "signature", "depends_on", "outcome"})
        if event["id"] != f"e{index:06d}":
            raise IntegrityError("event sequence is not contiguous")
        if type(event["tool"]) is not str or not TOOL.fullmatch(event["tool"]):
            raise IntegrityError("invalid tool identifier")
        if type(event["arguments"]) is not dict:
            raise IntegrityError("tool arguments must be an object")
        if event["signature"] != digest({"tool": event["tool"], "arguments": event["arguments"]}):
            raise IntegrityError("call signature mismatch")
        deps = event["depends_on"]
        if type(deps) is not list or any(type(dep) is not str for dep in deps):
            raise IntegrityError("invalid dependency list")
        if len(set(deps)) != len(deps) or deps != sorted(deps) or not set(deps) <= seen:
            raise IntegrityError("dependencies must refer to unique earlier events")
        outcome = event["outcome"]
        if type(outcome) is not dict or outcome.get("kind") not in ("return", "error"):
            raise IntegrityError("invalid outcome")
        _keys(outcome, {"kind", "value"} if outcome["kind"] == "return" else {"kind", "type", "message"})
        if outcome["kind"] == "error":
            if type(outcome["type"]) is not str or outcome["type"] not in ERROR_NAMES:
                raise IntegrityError("invalid error type label")
            if type(outcome["message"]) is not str or not PSEUDONYM.fullmatch(outcome["message"]):
                raise IntegrityError("error messages must be opaque pseudonyms")
        seen.add(event["id"])
        events.append(event)
    return {"manifest": manifest, "events": events}


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="Verify an extracted replayseal evidence bundle")
    parser.add_argument("path", nargs="?", default=".")
    parser.add_argument("--expected-root")
    args = parser.parse_args()
    try:
        checked = verify(args.path, args.expected_root)
        print(json.dumps({"root": checked["manifest"]["root"], "events": len(checked["events"]), "verified": True}))
    except IntegrityError as error:
        parser.exit(2, f"verification failed: {error}\n")

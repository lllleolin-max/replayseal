"""Data-only replay plans: prior result references, never Python/tool loading."""
from __future__ import annotations

import re

from .core import Replay, ReplayMismatch, RecordedToolError
from .integrity import canonical, MAX_EVENTS, TOOL

FORMAT = "replayseal/plan/v1"


def _pointer(value, pointer):
    if type(pointer) is not str or (pointer and not pointer.startswith("/")):
        raise ValueError("result pointer must be a JSON Pointer")
    if re.search(r"~(?![01])", pointer):
        raise ValueError("invalid JSON Pointer escape")
    if not pointer:
        return value
    for part in pointer[1:].split("/"):
        part = part.replace("~1", "/").replace("~0", "~")
        if isinstance(value, dict) and part in value:
            value = value[part]
        elif isinstance(value, list) and re.fullmatch(r"0|[1-9][0-9]*", part):
            index = int(part)
            if index >= len(value):
                raise ValueError("result pointer does not exist")
            value = value[index]
        else:
            raise ValueError("result pointer does not exist")
    return value


def _resolve(value, outputs):
    if type(value) is dict:
        if "$result" in value:
            if set(value) != {"$result", "pointer"} or type(value["$result"]) is not str:
                raise ValueError("invalid result reference")
            if value["$result"] not in outputs:
                raise ValueError("result reference must name an earlier successful event")
            # Preserve replay-issued pseudonym provenance; serializing and reloading
            # here would incorrectly turn these into untrusted caller tokens.
            return _pointer(outputs[value["$result"]], value["pointer"])
        return {key: _resolve(child, outputs) for key, child in value.items()}
    if type(value) is list:
        return [_resolve(child, outputs) for child in value]
    return value


def run_plan(path, plan: dict, policy, *, expected_root=None) -> dict:
    """Consume an entire strict replay using JSON templates and earlier outputs.

    An expected recorded exception must set ``expect_error: true``. Plan errors
    are ValueError; behavioral mismatches are ReplayMismatch. No results or keys
    are included in the returned summary.
    """
    canonical(plan)
    if type(plan) is not dict or set(plan) != {"format", "calls"} or plan["format"] != FORMAT:
        raise ValueError("invalid replay plan format")
    calls = plan["calls"]
    if type(calls) is not list or len(calls) > MAX_EVENTS:
        raise ValueError("invalid replay plan call list")
    for call in calls:
        if type(call) is not dict or not {"tool", "arguments"} <= set(call) \
                or not set(call) <= {"tool", "arguments", "depends_on", "expect_error"}:
            raise ValueError("invalid replay plan call")
        if type(call["tool"]) is not str or not TOOL.fullmatch(call["tool"]):
            raise ValueError("plan tool must be a static identifier")
        if type(call["arguments"]) is not dict or type(call.get("expect_error", False)) is not bool:
            raise ValueError("invalid plan arguments or error expectation")
        deps = call.get("depends_on", [])
        if type(deps) is not list or any(type(dep) is not str for dep in deps):
            raise ValueError("invalid plan dependencies")
    outputs, errors = {}, 0
    with Replay(path, policy, expected_root=expected_root) as replay:
        for index, call in enumerate(calls, 1):
            arguments = _resolve(call["arguments"], outputs)
            try:
                result = replay.call(call["tool"], arguments, depends_on=call.get("depends_on", []))
            except RecordedToolError:
                if not call.get("expect_error", False):
                    raise ReplayMismatch(f"event {index}: unexpected recorded tool error") from None
                errors += 1
            else:
                if call.get("expect_error", False):
                    raise ReplayMismatch(f"event {index}: expected recorded tool error")
                outputs[replay.last_id] = result
    return {"replayed": True, "events": len(calls), "recorded_errors": errors, "live_calls": 0}

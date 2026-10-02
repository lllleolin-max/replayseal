"""Synthetic replay-to-recording handoff with a stricter target policy."""
import argparse
import json
from pathlib import Path

from replayseal import Policy, Recorder, Replay, verify
from replayseal.privacy import DEFAULT_FIELDS

DEMO_KEY = b"public-composition-demo-only-000000"  # Published synthetic key only.


def workflow(boundary, output, counts):
    def prepare(_):
        counts["live"] += 1
        return output

    def login(_):
        counts["live"] += 1
        return {"accepted": True}

    prepared = boundary.call("fixture.prepare", {}, prepare)
    return boundary.call("login", {"password": prepared["note"], "customer_id": prepared["customer_id"]},
                         login, depends_on=[boundary.last_id])


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", default="demo-output/composition")
    args = parser.parse_args()
    output_dir = Path(args.output)
    source, target = output_dir / "source", output_dir / "target"
    source_policy = Policy(DEMO_KEY)
    with Recorder(source, source_policy) as rec:
        rec.call("lookup", {}, lambda _: {"note": "bare-sensitive-prefix owner@example.test",
                                          "customer_id": "customer-017"})
    source_bytes = {p.name: p.read_bytes() for p in source.rglob("*.json")}
    with Replay(source, source_policy, expected_root=rec.root) as replay:
        prior = replay.call("lookup", {})
    rules = {"fields": [*DEFAULT_FIELDS, "note"]}
    target_policy, counts = Policy(DEMO_KEY, **rules), {"live": 0}
    with Recorder(target, target_policy) as rec:
        workflow(rec, prior, counts)
    captured = counts["live"]
    with Replay(target, target_policy, expected_root=rec.root) as replay:
        result = workflow(replay, prior, counts)
    target_bytes = b"".join(p.read_bytes() for p in target.rglob("*.json"))
    assert b"bare-sensitive-prefix" not in target_bytes
    assert b"owner@example.test" not in target_bytes
    assert source_bytes == {p.name: p.read_bytes() for p in source.rglob("*.json")}
    assert result == {"accepted": True} and counts["live"] == captured
    plan = {"format": "replayseal/plan/v1", "calls": [
        {"tool": "fixture.prepare", "arguments": {}},
        {"tool": "login", "arguments": {
            "password": {"$result": "e000001", "pointer": "/note"},
            "customer_id": {"$result": "e000001", "pointer": "/customer_id"}},
         "depends_on": ["e000001"]}]}
    (output_dir / "target.plan.json").write_text(json.dumps(plan, indent=2), encoding="utf-8")
    (output_dir / "target.policy.json").write_text(json.dumps(rules, indent=2), encoding="utf-8")
    print(json.dumps({"target_root": verify(target)["manifest"]["root"],
                      "target_capture_calls": captured, "replay_live_calls": counts["live"] - captured,
                      "configured_target_literals_absent": True, "source_unchanged": True}, indent=2))


if __name__ == "__main__":
    main()

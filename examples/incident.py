"""Offline support-agent incident: catch a cross-customer invoice notification."""
import argparse
import json
from pathlib import Path

from replayseal import Policy, Recorder, Replay, ReplayMismatch, export_bundle, verify

DEMO_KEY = b"public-demo-only-replace-me-000000"  # Synthetic data only.


def workflow(boundary, *, wrong_customer=False, counts=None):
    def lookup(_):
        if counts is not None:
            counts["live"] += 1
        return {"customer_id": "customer-017", "email": "owner@example.test", "invoice": "inv-204"}

    account = boundary.call("crm.lookup", {"ticket": "ticket-81"}, lookup)
    lookup_id = boundary.last_id

    def notify(_):
        if counts is not None:
            counts["live"] += 1
        return {"queued": True}  # A fake boundary; this demo never sends messages.

    recipient = "customer-999" if wrong_customer else account["customer_id"]
    return boundary.call("notification.enqueue", {"customer_id": recipient, "invoice": account["invoice"]},
                         notify, depends_on=[lookup_id])


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", default="demo-output")
    args = parser.parse_args()
    output = Path(args.output)
    output.mkdir(parents=True, exist_ok=True)
    policy, counts = Policy(DEMO_KEY), {"live": 0}
    trace = output / "incident"
    with Recorder(trace, policy) as boundary:
        workflow(boundary, counts=counts)
    recorded_count = counts["live"]
    with Replay(trace, policy, expected_root=boundary.root) as replay:
        workflow(replay, counts=counts)
    caught = None
    try:
        with Replay(trace, policy) as replay:
            workflow(replay, wrong_customer=True, counts=counts)
    except ReplayMismatch as error:
        caught = str(error)
    assert caught and counts["live"] == recorded_count
    data = b"".join(path.read_bytes() for path in trace.rglob("*.json"))
    assert b"customer-017" not in data and b"owner@example.test" not in data
    export_bundle(trace, output / "incident.seal.zip")
    plan = {"format": "replayseal/plan/v1", "calls": [
        {"tool": "crm.lookup", "arguments": {"ticket": "ticket-81"}},
        {"tool": "notification.enqueue", "arguments": {
            "customer_id": {"$result": "e000001", "pointer": "/customer_id"},
            "invoice": {"$result": "e000001", "pointer": "/invoice"}},
         "depends_on": ["e000001"]}]}
    (output / "incident.plan.json").write_text(json.dumps(plan, indent=2), encoding="utf-8")
    print(json.dumps({"verified_root": verify(trace)["manifest"]["root"],
                      "recorded_calls": recorded_count, "replay_live_calls": counts["live"] - recorded_count,
                      "regression_caught": caught, "synthetic_sensitive_literals_absent": True}, indent=2))


if __name__ == "__main__":
    main()

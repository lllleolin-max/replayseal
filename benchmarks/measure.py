"""Measure synthetic calls; record/verify include local filesystem costs."""
import argparse
import json
import platform
from pathlib import Path
import statistics
import tempfile
import time

from replayseal import Policy, Recorder, Replay, verify


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--calls", type=int, default=500)
    parser.add_argument("--rounds", type=int, default=5)
    args = parser.parse_args()
    if args.calls < 1 or args.rounds < 1:
        parser.error("calls and rounds must be positive")
    measured = {"record_and_seal_ms": [], "verify_ms": [], "replay_with_verify_ms": []}
    policy = Policy(b"public-benchmark-key-000000000000")
    sizes = []
    for _ in range(args.rounds):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "trace"
            start = time.perf_counter()
            with Recorder(path, policy) as rec:
                for i in range(args.calls):
                    rec.call("crm.lookup", {"customer_id": f"customer-{i}", "page": i},
                             lambda row: {"customer_id": row["customer_id"], "active": True})
            measured["record_and_seal_ms"].append((time.perf_counter() - start) * 1000)
            start = time.perf_counter()
            verify(path)
            measured["verify_ms"].append((time.perf_counter() - start) * 1000)
            start = time.perf_counter()
            with Replay(path, policy) as replay:
                for i in range(args.calls):
                    replay.call("crm.lookup", {"customer_id": f"customer-{i}", "page": i})
            measured["replay_with_verify_ms"].append((time.perf_counter() - start) * 1000)
            sizes.append(sum(file.stat().st_size for file in path.rglob("*.json")))
    print(json.dumps({"python": platform.python_version(), "platform": platform.platform(),
                      "calls_per_round": args.calls, "rounds": args.rounds,
                      "median_ms": {key: round(statistics.median(values), 3) for key, values in measured.items()},
                      "samples_ms": {key: [round(x, 3) for x in values] for key, values in measured.items()},
                      "evidence_bytes": sizes, "workload": "synthetic small JSON CRM tool; zero network"}, indent=2))


if __name__ == "__main__":
    main()

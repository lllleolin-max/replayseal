"""Executable mechanism contrast, NOT a benchmark of named competing products."""
import json
from pathlib import Path
import tempfile

from replayseal import Policy, Recorder, Replay, ReplayMismatch
from replayseal.integrity import digest


def constant_identity(row):
    """Minimal disclosed baseline: keep shape, replace each customer identity."""
    return {key: "[REDACTED]" if key == "customer_id" else value for key, value in row.items()}


def signature_contract(tool, arguments, transform):
    """A signature-only stub matcher; deliberately no causal edge contract."""
    return digest({"tool": tool, "arguments": transform(arguments)})


def main():
    policy = Policy(b"synthetic-ablation-key-0000000000")
    identities = ("account-017", "account-999")
    plain = [{"customer_id": who} for who in identities]
    constant = [constant_identity(row) for row in plain]
    keyed = [policy.redact(row) for row in plain]
    checks = {"raw_recording_retains_sensitive_values": "account-017" in json.dumps(plain),
              "constant_redaction_collapses_distinct_recipients": constant[0] == constant[1],
              "keyed_redaction_distinguishes_recipients": keyed[0] != keyed[1],
              "keyed_recording_omits_literal": "account-017" not in json.dumps(keyed),
              "constant_contract_accepts_cross_customer_regression":
                  signature_contract("send", plain[0], constant_identity) ==
                  signature_contract("send", plain[1], constant_identity),
              "signature_only_contract_accepts_removed_edge":
                  signature_contract("send", plain[0], policy.redact) ==
                  signature_contract("send", plain[0], policy.redact)}
    with tempfile.TemporaryDirectory() as folder:
        path = Path(folder) / "trace"
        with Recorder(path, policy) as rec:
            rec.call("lookup", {}, lambda _: {"customer_id": identities[0]})
            rec.call("send", plain[0], lambda _: True, depends_on=[rec.last_id])
        replay = Replay(path, policy)
        result = replay.call("lookup", {})
        # Baseline signatures above are unchanged when the dependency disappears;
        # the real engine must reject that otherwise identical call below.
        try:
            replay.call("send", result)  # Values and order match, causal edge was removed.
            checks["explicit_causality_catches_removed_edge"] = False
        except ReplayMismatch:
            checks["explicit_causality_catches_removed_edge"] = True
        replay = Replay(path, policy)
        replay.call("lookup", {})
        try:
            replay.call("send", plain[1], depends_on=[replay.last_id])
            checks["keyed_replay_catches_cross_customer_regression"] = False
        except ReplayMismatch:
            checks["keyed_replay_catches_cross_customer_regression"] = True
    assert all(checks.values()), checks
    print(json.dumps({"scope": "synthetic mechanism ablation; no competitor execution", "checks": checks}, indent=2))


if __name__ == "__main__":
    main()

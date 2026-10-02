"""Target-field redaction must still apply to verified partially masked text."""
from pathlib import Path
import tempfile
from replayseal import Policy, Recorder, Replay

policy = Policy(b"reviewer-composition-synthetic-00000")
with tempfile.TemporaryDirectory() as folder:
    root = Path(folder)
    source = root / "source"
    with Recorder(source, policy) as rec:
        rec.call("lookup", {}, lambda _: {"note": "bare-sensitive-prefix owner@example.test"})
    with Replay(source, policy) as replay:
        note = replay.call("lookup", {})["note"]
    captured = root / "target"
    with Recorder(captured, policy) as rec:
        rec.call("login", {"password": note}, lambda _: True)
    serialized = b"".join(path.read_bytes() for path in captured.rglob("*.json"))
    leak = b"bare-sensitive-prefix" in serialized
    print({"same_key_and_policy": True, "target_field": "password",
           "replay_issued_partially_masked_value": True, "configured_field_raw_prefix_persisted": leak})
    assert not leak, "A configured password field must hide its entire value, including prior unmasked text"

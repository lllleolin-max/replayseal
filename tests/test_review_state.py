"""Adversarial state-machine probes from self-review round one."""
from pathlib import Path
import tempfile
import unittest

from replayseal import Policy, Recorder, Replay, ReplayMismatch, PrivacyError, verify


class StateReview(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.path = Path(self.tmp.name) / "trace"
        self.policy = Policy(b"synthetic-state-review-key-000000")

    def test_unserializable_result_must_not_seal_incomplete_success(self):
        rec = Recorder(self.path, self.policy)
        with self.assertRaises(PrivacyError):
            rec.call("write", {}, lambda _: object())
        with self.assertRaises(RuntimeError):
            rec.seal()
        self.assertFalse(self.path.exists())

    def test_nested_boundary_rejected_before_inner_invocation(self):
        rec = Recorder(self.path, self.policy)
        invoked = []
        def outer(_):
            return rec.call("inner", {}, lambda _: invoked.append(True))
        with self.assertRaises(RuntimeError):
            rec.call("outer", {}, outer)
        self.assertEqual(invoked, [])

    def test_mutating_original_rule_list_cannot_change_policy(self):
        fields = ["private"]
        policy = Policy(self.policy.key, fields=fields)
        before = policy.policy_id
        fields.clear()
        self.assertEqual(policy.policy_id, before)
        self.assertNotEqual(policy.redact({"private": "value"}), {"private": "value"})

    def test_invalid_replay_arguments_poison_session(self):
        with Recorder(self.path, self.policy) as rec:
            rec.call("read", {}, lambda _: 1)
        replay = Replay(self.path, self.policy)
        with self.assertRaises((PrivacyError, ReplayMismatch)):
            replay.call("read", {"invalid": object()})
        with self.assertRaises(ReplayMismatch):
            replay.call("read", {})


if __name__ == "__main__":
    unittest.main()

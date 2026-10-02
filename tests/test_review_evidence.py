"""Adversarial evidence and canonical-contract probes from self-review round three."""
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from replayseal import Policy, Recorder, IntegrityError, compare, verify
from replayseal.integrity import canonical, digest


class EvidenceReview(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.base = Path(self.tmp.name)
        self.path = self.base / "trace"
        self.policy = Policy(b"synthetic-evidence-review-key-000")

    def test_rehashed_malformed_error_is_rejected(self):
        with Recorder(self.path, self.policy) as rec:
            rec.call("lookup", {}, lambda _: 1)
        bundle = verify(self.path)
        event = bundle["events"][0]
        event["outcome"] = {"kind": "error", "type": [], "message": {}}
        event_hash = digest(event)
        (self.path / "objects" / (event_hash + ".json")).write_bytes(canonical(event))
        manifest = bundle["manifest"]
        manifest["events"] = [event_hash]
        manifest["root"] = digest({k: v for k, v in manifest.items() if k != "root"})
        (self.path / "manifest.json").write_bytes(canonical(manifest))
        with self.assertRaises(IntegrityError):
            verify(self.path)

    def test_signed_zero_difference_is_not_reported_equal(self):
        other = self.base / "other"
        for path, value in ((self.path, -0.0), (other, 0.0)):
            with Recorder(path, self.policy) as rec:
                rec.call("number", {}, lambda _: value)
        self.assertFalse(compare(self.path, other)["equal"])

    def test_public_event_inspection_cannot_modify_saved_evidence(self):
        with Recorder(self.path, self.policy) as rec:
            rec.call("read", {}, lambda _: {"safe": True})
            rec.events[0]["outcome"]["value"] = "unredacted-password"
        event = verify(self.path)["events"][0]
        self.assertEqual(event["outcome"]["value"], {"safe": True})

    def test_total_evidence_budget_is_enforced(self):
        with Recorder(self.path, self.policy) as rec:
            rec.call("read", {}, lambda _: {"data": "x" * 4000})
        with patch("replayseal.integrity.MAX_TOTAL_BYTES", 1024, create=True):
            with self.assertRaises(IntegrityError):
                verify(self.path)


if __name__ == "__main__":
    unittest.main()

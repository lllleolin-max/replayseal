"""Privacy/provenance probes from self-review round two."""
from pathlib import Path
import tempfile
import unittest

from replayseal import Policy, Recorder, Replay, ReplayMismatch, verify


class PrivacyReview(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.path = Path(self.tmp.name) / "trace"
        self.policy = Policy(b"synthetic-privacy-review-key-0000")

    def chain(self, value):
        with Recorder(self.path, self.policy) as rec:
            result = rec.call("read", {}, lambda _: value)
            rec.call("write", {"data": result}, lambda _: True)
        with Replay(self.path, self.policy) as replay:
            result = replay.call("read", {})
            self.assertTrue(replay.call("write", {"data": result}))

    def test_embedded_pseudonym_preserves_unchanged_text_flow(self):
        self.chain("Please contact owner@example.test to continue")

    def test_redacted_dictionary_key_preserves_unchanged_flow(self):
        self.chain({"owner@example.test": {"active": True}})

    def test_overlapping_patterns_redact_original_spans_not_generated_tokens(self):
        # Longer overlapping source match must win; later expressions cannot leave a tail.
        policy = Policy(self.policy.key, patterns=(r"secret", r"secret-more"))
        sanitized = policy.redact("secret-more")
        self.assertNotIn("more", sanitized)

    def test_exception_does_not_leak_bare_secret_or_dynamic_class_name(self):
        secret = "bare-unpatterned-private-value"
        sensitive_error = type(secret, (Exception,), {})
        with Recorder(self.path, self.policy) as rec:
            with self.assertRaises(sensitive_error):
                rec.call("login", {"password": secret},
                         lambda _: (_ for _ in ()).throw(sensitive_error(secret)))
        all_data = b"".join(file.read_bytes() for file in self.path.rglob("*.json"))
        self.assertNotIn(secret.encode(), all_data)


if __name__ == "__main__":
    unittest.main()

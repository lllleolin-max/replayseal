"""Public-API privacy composition regressions from independent review."""
from pathlib import Path
import tempfile
import unittest

from replayseal import Policy, PrivacyError, Recorder, Replay, ReplayMismatch, run_plan, verify
from replayseal.privacy import DEFAULT_FIELDS, DEFAULT_PATTERNS, TOKEN


KEY = b"synthetic-composition-review-key-0000"
RAW_NOTE = "bare-sensitive-prefix owner@example.test"


class CompositionReview(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.base = Path(self.tmp.name)

    def source(self, policy):
        path = self.base / "source"
        with Recorder(path, policy) as rec:
            rec.call("lookup", {}, lambda _: {"note": RAW_NOTE, "customer_id": "customer-017"})
        before = {p.name: p.read_bytes() for p in path.rglob("*.json")}
        with Replay(path, policy, expected_root=rec.root) as replay:
            output = replay.call("lookup", {})
        self.source_bytes = before
        self.source_path = path
        return output

    def saved_bytes(self, path):
        return b"".join(p.read_bytes() for p in path.rglob("*.json"))

    def test_partial_text_promoted_to_password_is_fully_protected(self):
        policy = Policy(KEY)
        output = self.source(policy)
        target = self.base / "target"
        with Recorder(target, policy) as rec:
            rec.call("login", {"password": output["note"]}, lambda _: True)
        self.assertNotIn(b"bare-sensitive-prefix", self.saved_bytes(target))
        self.assertRegex(verify(target)["events"][0]["arguments"]["password"], TOKEN)
        with Replay(target, policy) as replay:
            self.assertTrue(replay.call("login", {"password": output["note"]}))
        self.assertEqual(self.source_bytes, {p.name: p.read_bytes() for p in self.source_path.rglob("*.json")})

    def test_partial_text_promoted_by_array_path_and_result_path(self):
        policy = Policy(KEY, paths=("/arguments/credentials/*/label", "/result/private"))
        output = self.source(policy)
        target = self.base / "target"
        arguments = {"credentials": [{"label": output["note"]}]}
        with Recorder(target, policy) as rec:
            rec.call("login", arguments, lambda _: {"private": output["note"]})
        self.assertNotIn(b"bare-sensitive-prefix", self.saved_bytes(target))
        with Replay(target, policy) as replay:
            result = replay.call("login", arguments)
        self.assertTrue(TOKEN.fullmatch(result["private"]))

    def test_whole_container_promotion_normalizes_nested_verified_values(self):
        policy = Policy(KEY)
        output = self.source(policy)
        arguments = {"password": {"nested": [output["note"], output["customer_id"]]}}
        before = {"password": {"nested": [str(output["note"]), str(output["customer_id"])]}}
        target = self.base / "target"
        with Recorder(target, policy) as rec:
            rec.call("login", arguments, lambda _: True)
        self.assertNotIn(b"bare-sensitive-prefix", self.saved_bytes(target))
        self.assertEqual(arguments, before)
        with Replay(target, policy) as replay:
            self.assertTrue(replay.call("login", arguments))

    def test_stricter_field_policy_applies_to_partial_source_text(self):
        output = self.source(Policy(KEY))
        stricter = Policy(KEY, fields=(*DEFAULT_FIELDS, "note"))
        target = self.base / "target"
        with Recorder(target, stricter) as rec:
            rec.call("log", {"note": output["note"]}, lambda _: True)
        self.assertNotIn(b"bare-sensitive-prefix", self.saved_bytes(target))
        with Replay(target, stricter) as replay:
            self.assertTrue(replay.call("log", {"note": output["note"]}))

    def test_stricter_path_policy_protects_nested_partial_source_text(self):
        output = self.source(Policy(KEY))
        stricter = Policy(KEY, paths=("/arguments/items/*/note",))
        target = self.base / "target"
        arguments = {"items": [{"note": output["note"]}]}
        with Recorder(target, stricter) as rec:
            rec.call("log", arguments, lambda _: True)
        self.assertNotIn(b"bare-sensitive-prefix", self.saved_bytes(target))
        with Replay(target, stricter) as replay:
            self.assertTrue(replay.call("log", arguments))

    def test_stricter_regex_spanning_token_protects_complete_matched_region(self):
        output = self.source(Policy(KEY))
        stricter = Policy(KEY, patterns=(*DEFAULT_PATTERNS, r"bare-sensitive-prefix.*$"))
        safe = stricter.redact({"note": output["note"]})
        self.assertTrue(TOKEN.fullmatch(safe["note"]))

    def test_stricter_regex_applies_to_readable_parts_and_dictionary_keys(self):
        output = self.source(Policy(KEY))
        stricter = Policy(KEY, patterns=(*DEFAULT_PATTERNS, r"bare-sensitive-prefix"))
        target = self.base / "target"
        arguments = {"note": output["note"], output["note"]: "safe"}
        with Recorder(target, stricter) as rec:
            rec.call("log", arguments, lambda _: True)
        self.assertNotIn(b"bare-sensitive-prefix", self.saved_bytes(target))
        with Replay(target, stricter) as replay:
            self.assertTrue(replay.call("log", arguments))

    def test_complete_identity_tokens_remain_stable_across_stricter_policy(self):
        output = self.source(Policy(KEY))
        stricter = Policy(KEY, fields=(*DEFAULT_FIELDS, "note"), patterns=(*DEFAULT_PATTERNS, r"rs1"))
        target = self.base / "target"
        with Recorder(target, stricter) as rec:
            rec.call("read", {"customer_id": output["customer_id"]}, lambda _: {"customer_id": output["customer_id"]})
            rec.call("write", {"customer_id": output["customer_id"]}, lambda _: True, depends_on=[rec.last_id])
        events = verify(target)["events"]
        self.assertEqual(events[0]["arguments"]["customer_id"], output["customer_id"])
        with Replay(target, stricter) as replay:
            identity = replay.call("read", {"customer_id": output["customer_id"]})
            self.assertTrue(replay.call("write", identity, depends_on=[replay.last_id]))

    def test_different_key_rejected_before_invocation_in_sensitive_container(self):
        output = self.source(Policy(KEY))
        invoked = []
        rec = Recorder(self.base / "target", Policy(b"x" * 32))
        with self.assertRaises(PrivacyError):
            rec.call("login", {"password": {"value": output["note"]}}, lambda _: invoked.append(True))
        self.assertEqual(invoked, [])
        self.assertFalse(rec.path.exists())

    def test_original_plaintext_promotion_stops_replay_with_explicit_domain_error(self):
        policy = Policy(KEY)
        path = self.base / "trace"
        calls = []
        with Recorder(path, policy) as rec:
            value = rec.call("read", {}, lambda _: RAW_NOTE)
            rec.call("login", {"password": value}, lambda _: True, depends_on=[rec.last_id])
        self.assertNotIn(b"bare-sensitive-prefix", verify(path)["events"][1]["arguments"]["password"].encode())
        replay = Replay(path, policy)
        partial = replay.call("read", {})
        with self.assertRaisesRegex(ReplayMismatch, "whole-value promotion"):
            replay.call("login", {"password": partial}, lambda _: calls.append(True), depends_on=[replay.last_id])
        self.assertEqual(calls, [])
        with self.assertRaises(ReplayMismatch):
            replay.call("login", {"password": RAW_NOTE}, depends_on=[replay.last_id])

    def test_protecting_upstream_field_preserves_original_sdk_and_cli_replay(self):
        policy = Policy(KEY, fields=(*DEFAULT_FIELDS, "note"))
        path = self.base / "trace"
        with Recorder(path, policy) as rec:
            original = rec.call("read", {}, lambda _: {"note": RAW_NOTE})
            rec.call("login", {"password": original["note"]}, lambda _: True, depends_on=[rec.last_id])
        self.assertNotIn(b"bare-sensitive-prefix", self.saved_bytes(path))
        with Replay(path, policy) as replay:
            protected = replay.call("read", {}, lambda _: self.fail("live read"))
            self.assertTrue(replay.call("login", {"password": protected["note"]},
                                       lambda _: self.fail("live login"), depends_on=[replay.last_id]))
        plan = {"format": "replayseal/plan/v1", "calls": [
            {"tool": "read", "arguments": {}},
            {"tool": "login", "arguments": {"password": {"$result": "e000001", "pointer": "/note"}},
             "depends_on": ["e000001"]}]}
        self.assertEqual(run_plan(path, plan, policy)["events"], 2)


if __name__ == "__main__":
    unittest.main()

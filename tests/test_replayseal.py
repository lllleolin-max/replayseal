import copy
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
import zipfile

from replayseal import (Policy, Recorder, Replay, ReplayMismatch, RecordedToolError,
                        IntegrityError, PrivacyError, compare, export_bundle, verify)
from replayseal.integrity import canonical, digest

KEY = bytes(range(32))  # Public synthetic test key. Never use this key for real records.


class Workspace(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.base = Path(self.temp.name)
        self.path = self.base / "trace"
        self.policy = Policy(KEY)

    def record(self, result=None, arguments=None, name="lookup"):
        with Recorder(self.path, self.policy) as rec:
            rec.call(name, arguments or {"query": "receipt"}, lambda _: result)
        return rec


class CoreTests(Workspace):
    def test_round_trip_never_invokes_live_callable(self):
        self.record({"ok": True})
        with Replay(self.path, self.policy) as replay:
            result = replay.call("lookup", {"query": "receipt"}, lambda _: self.fail("external call"))
        self.assertEqual(result, {"ok": True})

    def test_tool_argument_order_and_extra_calls_fail_closed(self):
        self.record(2, {"a": 1, "b": 2})
        with Replay(self.path, self.policy) as replay:
            self.assertEqual(replay.call("lookup", {"b": 2, "a": 1}), 2)
        for name, args in (("write", {"a": 1, "b": 2}), ("lookup", {"a": 2, "b": 2})):
            replay = Replay(self.path, self.policy)
            with self.assertRaises(ReplayMismatch):
                replay.call(name, args)
            with self.assertRaises(ReplayMismatch):
                replay.call("lookup", {"a": 1, "b": 2})

    def test_underconsumption_and_overconsumption(self):
        self.record(2)
        with self.assertRaises(ReplayMismatch):
            with Replay(self.path, self.policy):
                pass
        replay = Replay(self.path, self.policy)
        replay.call("lookup", {"query": "receipt"})
        with self.assertRaises(ReplayMismatch):
            replay.call("lookup", {"query": "receipt"})

    def test_repeated_identical_calls_are_distinct_events(self):
        with Recorder(self.path, self.policy) as rec:
            rec.call("poll", {}, lambda _: 1)
            rec.call("poll", {}, lambda _: 2)
        with Replay(self.path, self.policy) as replay:
            self.assertEqual([replay.call("poll", {}), replay.call("poll", {})], [1, 2])

    def test_explicit_causality_is_part_of_contract(self):
        with Recorder(self.path, self.policy) as rec:
            rec.call("read", {}, lambda _: "ok")
            rec.call("write", {}, lambda _: True, depends_on=[rec.last_id])
        replay = Replay(self.path, self.policy)
        replay.call("read", {})
        with self.assertRaisesRegex(ReplayMismatch, "causal"):
            replay.call("write", {})

    def test_invalid_dependency_prevents_invocation(self):
        rec = Recorder(self.path, self.policy)
        with self.assertRaises(ValueError):
            rec.call("read", {}, lambda _: self.fail("invoked"), depends_on=["e000099"])

    def test_input_and_output_mutation_do_not_change_snapshots(self):
        arguments, output = {"items": [1]}, {"nested": [2]}
        with Recorder(self.path, self.policy) as rec:
            def invoke(args):
                args["items"].append(9)
                return output
            rec.call("read", arguments, invoke)
            output["nested"].append(3)
        event = verify(self.path)["events"][0]
        self.assertEqual(event["arguments"], {"items": [1]})
        self.assertEqual(event["outcome"]["value"], {"nested": [2]})

    def test_decorator_binds_defaults_and_never_calls_in_replay(self):
        with Recorder(self.path, self.policy) as rec:
            @rec.tool("add")
            def add(a, b=2):
                return a + b
            self.assertEqual(add(3), 5)
        with Replay(self.path, self.policy) as replay:
            @replay.tool("add")
            def add(a, b=2):
                self.fail("live invocation")
            self.assertEqual(add(b=2, a=3), 5)

    def test_exception_is_recorded_and_replayed_without_class_execution(self):
        with Recorder(self.path, self.policy) as rec:
            with self.assertRaises(ValueError):
                rec.call("read", {}, lambda _: (_ for _ in ()).throw(ValueError("email a@example.com")))
        with Replay(self.path, self.policy) as replay:
            with self.assertRaises(RecordedToolError) as caught:
                replay.call("read", {})
        self.assertNotIn("a@example.com", str(caught.exception))

    def test_existing_evidence_never_overwritten(self):
        self.record(1)
        before = (self.path / "manifest.json").read_bytes()
        with self.assertRaises(FileExistsError):
            Recorder(self.path, self.policy).seal()
        self.assertEqual(before, (self.path / "manifest.json").read_bytes())


class PrivacyTests(Workspace):
    def test_nested_fields_email_dictionary_keys_and_bearer(self):
        original = {"nested": [{"API-Key": "my-secret", "note": "a@example.com"}],
                    "a@example.com": "Bearer abcdef123456"}
        before = copy.deepcopy(original)
        self.record(original, original)
        saved = b"".join(file.read_bytes() for file in self.path.rglob("*.json"))
        for literal in (b"my-secret", b"a@example.com", b"abcdef123456"):
            self.assertNotIn(literal, saved)
        self.assertEqual(original, before)

    def test_keyed_identity_distinguishes_people(self):
        a = self.policy.redact({"customer_id": "alice"})
        b = self.policy.redact({"customer_id": "bob"})
        self.assertNotEqual(a, b)
        self.assertEqual(a, self.policy.redact({"customer_id": "alice"}))
        self.assertNotEqual(a, Policy(b"b" * 32).redact({"customer_id": "alice"}))

    def test_output_identity_can_be_consumed_downstream(self):
        with Recorder(self.path, self.policy) as rec:
            result = rec.call("lookup", {}, lambda _: {"customer_id": "alice"})
            rec.call("send", result, lambda _: True, depends_on=[rec.last_id])
        with Replay(self.path, self.policy) as replay:
            result = replay.call("lookup", {})
            self.assertTrue(replay.call("send", result, depends_on=[replay.last_id]))

    def test_forged_token_string_cannot_impersonate_a_replay_value(self):
        self.record(True, {"customer_id": "alice"})
        token = verify(self.path)["events"][0]["arguments"]["customer_id"]
        with self.assertRaises(ReplayMismatch):
            Replay(self.path, self.policy).call("lookup", {"customer_id": token})

    def test_wildcard_json_pointer_and_custom_regex(self):
        policy = Policy(KEY, paths=("/arguments/people/*/name",), patterns=(r"ID-\d{4}",))
        safe = policy.redact({"people": [{"name": "Ada", "level": 1}], "text": "owner ID-1234"})
        self.assertNotIn("Ada", str(safe))
        self.assertNotIn("ID-1234", str(safe))
        self.assertEqual(safe["people"][0]["level"], 1)

    def test_json_type_precision(self):
        self.assertNotEqual(digest({"a": 1}), digest({"a": True}))
        self.assertNotEqual(digest({"a": 1}), digest({"a": 1.0}))
        for value in (float("nan"), float("inf"), b"bytes", {1: "bad"}, (1, 2)):
            with self.subTest(value=type(value).__name__), self.assertRaises(PrivacyError):
                self.policy.redact(value)

    def test_wrong_key_or_policy_rejected(self):
        self.record(1)
        for policy in (Policy(b"b" * 32), Policy(KEY, fields=())):
            with self.assertRaises(ReplayMismatch):
                Replay(self.path, policy)


class EvidenceTests(Workspace):
    def test_tampering_and_trusted_root(self):
        rec = self.record({"answer": 42})
        verify(self.path, expected_root=rec.root)
        with self.assertRaises(IntegrityError):
            verify(self.path, expected_root="0" * 64)
        ref = verify(self.path)["manifest"]["events"][0]
        file = self.path / "objects" / (ref + ".json")
        file.write_bytes(file.read_bytes().replace(b"42", b"43"))
        with self.assertRaises(IntegrityError):
            verify(self.path)

    def test_missing_object_rejected(self):
        self.record(1)
        next((self.path / "objects").iterdir()).unlink()
        with self.assertRaises(IntegrityError):
            verify(self.path)

    def test_export_is_deterministic_and_independently_verifiable(self):
        rec = self.record({"email": "a@example.com"})
        one, two = self.base / "one.zip", self.base / "two.zip"
        export_bundle(self.path, one)
        export_bundle(self.path, two)
        self.assertEqual(one.read_bytes(), two.read_bytes())
        extracted = self.base / "extracted"
        with zipfile.ZipFile(one) as archive:
            archive.extractall(extracted)
        process = subprocess.run([sys.executable, "-I", str(extracted / "verify_bundle.py"),
                                  str(extracted), "--expected-root", rec.root], capture_output=True, text=True)
        self.assertEqual(process.returncode, 0, process.stderr)
        self.assertTrue(json.loads(process.stdout)["verified"])

    def test_first_divergence_omits_payload_values(self):
        self.record({"total": 1})
        other = self.base / "other"
        with Recorder(other, self.policy) as rec:
            rec.call("lookup", {"query": "receipt"}, lambda _: {"total": 2})
        self.assertEqual(compare(self.path, other), {"equal": False, "comparable": True,
                         "event": 1, "path": "$/outcome/value/total", "reason": "value changed"})


if __name__ == "__main__":
    unittest.main()

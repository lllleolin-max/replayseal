"""Final handoff probes: bounded capture, executable plans and portable CLI errors."""
import contextlib
import copy
import io
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from replayseal import IntegrityError, Policy, Recorder, ReplayMismatch, run_plan, verify
from replayseal.integrity import canonical, digest
from replayseal.cli import main


KEY = b"synthetic-final-review-key-000000"


class FinalReview(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.base = Path(self.tmp.name)
        self.path = self.base / "trace"
        self.policy = Policy(KEY)

    def capture(self):
        with Recorder(self.path, self.policy) as rec:
            rec.call("read", {}, lambda _: {"customer_id": "private-alice", "items": [3]})
            rec.call("write", {"customer_id": "private-alice", "number": 3},
                     lambda _: True, depends_on=[rec.last_id])
        self.root = rec.root
        self.plan = {"format": "replayseal/plan/v1", "calls": [
            {"tool": "read", "arguments": {}},
            {"tool": "write", "arguments": {
                "customer_id": {"$result": "e000001", "pointer": "/customer_id"},
                "number": {"$result": "e000001", "pointer": "/items/0"}},
             "depends_on": ["e000001"]}]}

    def cli(self, plan, *, key=KEY.hex()):
        plan_file = self.base / "plan.json"
        plan_file.write_text(json.dumps(plan), encoding="utf-8")
        out, err = io.StringIO(), io.StringIO()
        with patch.dict(os.environ, {"REPLAYSEAL_KEY": key}), \
                contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            code = main(["replay", str(self.path), str(plan_file), "--expected-root", self.root])
        return code, out.getvalue(), err.getvalue()

    def test_capture_aggregate_budget_fails_before_sealing(self):
        rec = Recorder(self.path, self.policy)
        with patch("replayseal.integrity.MAX_TOTAL_BYTES", 1100):
            rec.call("one", {}, lambda _: "x" * 200)
            with self.assertRaises(IntegrityError):
                rec.call("two", {}, lambda _: "x" * 200)
        self.assertTrue(rec.failed)
        with self.assertRaises(RuntimeError):
            rec.seal()
        self.assertFalse(self.path.exists())

    def test_cli_plan_passes_results_with_token_provenance(self):
        self.capture()
        code, out, err = self.cli(self.plan)
        self.assertEqual(code, 0, err)
        self.assertTrue(json.loads(out)["replayed"])
        self.assertNotIn("private-alice", out + err)

    def test_cli_plan_wrong_recipient_and_removed_edge_are_regressions(self):
        self.capture()
        for change in ("recipient", "edge", "missing_call"):
            plan = copy.deepcopy(self.plan)
            if change == "recipient":
                plan["calls"][1]["arguments"]["customer_id"] = "private-bob"
            elif change == "edge":
                plan["calls"][1].pop("depends_on")
            else:
                plan["calls"].pop()
            code, out, err = self.cli(plan)
            self.assertEqual(code, 1, err)
            self.assertFalse(json.loads(out)["replayed"])
            self.assertNotIn("private-bob", out + err)

    def test_cli_invalid_reference_and_key_are_private_operation_errors(self):
        self.capture()
        for event, pointer in (("e000002", ""), ("e000001", "/missing"), ("e000001", "/~2")):
            plan = copy.deepcopy(self.plan)
            plan["calls"][1]["arguments"]["customer_id"] = {"$result": event, "pointer": pointer}
            code, out, err = self.cli(plan)
            self.assertEqual(code, 2)
            self.assertEqual(out, "")
            self.assertNotIn("private-alice", err)
        code, out, err = self.cli(self.plan, key="not-a-secret-key")
        self.assertEqual(code, 2)
        self.assertNotIn("not-a-secret-key", out + err)

    def test_plan_recorded_errors_need_explicit_expectation(self):
        with Recorder(self.path, self.policy) as rec:
            with self.assertRaises(ValueError):
                rec.call("read", {}, lambda _: (_ for _ in ()).throw(ValueError("private-message")))
        plan = {"format": "replayseal/plan/v1", "calls": [{"tool": "read", "arguments": {}}]}
        with self.assertRaises(ReplayMismatch):
            run_plan(self.path, plan, self.policy)
        plan["calls"][0]["expect_error"] = True
        self.assertEqual(run_plan(self.path, plan, self.policy)["recorded_errors"], 1)

    def test_rehashed_drop_reorder_and_mutation_need_original_trusted_root(self):
        self.capture()
        bundle = verify(self.path)
        for change in ("drop", "reorder", "mutation"):
            folder = self.base / change
            (folder / "objects").mkdir(parents=True)
            events = copy.deepcopy(bundle["events"])
            if change == "drop":
                events.pop()
            elif change == "reorder":
                events.reverse()
            else:
                events[0]["outcome"]["value"]["items"] = [99]
            refs = []
            for event in events:
                ref = digest(event)
                (folder / "objects" / (ref + ".json")).write_bytes(canonical(event))
                refs.append(ref)
            manifest = {**bundle["manifest"], "events": refs}
            manifest["root"] = digest({k: v for k, v in manifest.items() if k != "root"})
            (folder / "manifest.json").write_bytes(canonical(manifest))
            with self.assertRaises(IntegrityError):
                verify(folder, self.root)
        # A internally consistent shortened history needs the original root to
        # detect rewriting: do not confuse content addressing with authenticity.
        self.assertEqual(len(verify(self.base / "drop")["events"]), 1)


if __name__ == "__main__":
    unittest.main()

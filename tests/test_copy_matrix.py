"""Stricter-policy and original-fixture compositions use copied public values."""

import copy
from pathlib import Path
import tempfile
import unittest

from replayseal import Policy, PrivacyError, Recorder, Replay, run_plan, verify
from replayseal.privacy import DEFAULT_FIELDS, DEFAULT_PATTERNS, TOKEN

KEY = b'public-copy-matrix-only-0000000000'
RAW = 'prefix-A owner@example.test prefix-B second@example.test prefix-C'


class CopyMatrixTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.base = Path(self.temp.name)
        self.policy = Policy(KEY)
        self.source = self.base / 'source'
        with Recorder(self.source, self.policy) as recorder:
            recorder.call('source', {}, lambda _: {'note': RAW, 'customer_id': 'customer-017'})
        self.source_root = recorder.root
        self.before = {p.relative_to(self.source): p.read_bytes() for p in self.source.rglob('*.json')}
        with Replay(self.source, self.policy, expected_root=recorder.root) as replay:
            self.output = replay.call('source', {}, lambda _: self.fail('live source'))

    def capture_and_replay(self, target, policy, arguments):
        calls = []
        with Recorder(target, policy) as recorder:
            recorder.call('handoff', arguments, lambda _: calls.append(True) or True)
        with Replay(target, policy, expected_root=recorder.root) as replay:
            self.assertTrue(replay.call('handoff', copy.deepcopy(arguments), lambda _: self.fail('live handoff')))
        self.assertEqual(calls, [True])
        return recorder.root

    def assert_source_unchanged(self):
        self.assertEqual(self.before,
                         {p.relative_to(self.source): p.read_bytes() for p in self.source.rglob('*.json')})

    def test_copied_stricter_field_path_container_and_regex_match_direct_evidence(self):
        cases = (
            (Policy(KEY, fields=(*DEFAULT_FIELDS, 'note')), {'note': self.output['note']}),
            (Policy(KEY, paths=('/arguments/items/*/note',)), {'items': [{'note': self.output['note']}]}),
            (self.policy, {'password': {'notes': [self.output['note'], self.output['customer_id']]}}),
            (Policy(KEY, patterns=(*DEFAULT_PATTERNS, r'prefix-[ABC]')),
             {'note': self.output['note'], self.output['note']: self.output['customer_id']}),
            (Policy(KEY, patterns=(*DEFAULT_PATTERNS, r'prefix-A.*prefix-C')),
             {'note': self.output['note'], self.output['note']: self.output['customer_id']}),
        )
        for number, (policy, arguments) in enumerate(cases):
            direct_root = self.capture_and_replay(self.base / f'direct-{number}', policy, arguments)
            for copier in (copy.copy, copy.deepcopy):
                target = self.base / f'copy-{number}-{copier.__name__}'
                copied = copier(arguments)
                self.assertEqual(self.capture_and_replay(target, policy, copied), direct_root)
                evidence = b''.join(p.read_bytes() for p in target.rglob('*.json'))
                for literal in (b'owner@example.test', b'second@example.test', b'prefix-A', b'prefix-B', b'prefix-C'):
                    self.assertNotIn(literal, evidence)
        self.assert_source_unchanged()

    def test_complete_token_copies_stay_stable_under_stricter_token_matching_rules(self):
        strict = Policy(KEY, fields=(*DEFAULT_FIELDS, 'opaque'), paths=('/arguments/*',),
                        patterns=(*DEFAULT_PATTERNS, 'rs1', '[a-f0-9]{6}'))
        for copier in (copy.copy, copy.deepcopy):
            copied = copier(self.output['customer_id'])
            target = self.base / copier.__name__
            self.capture_and_replay(target, strict, {'opaque': copied})
            self.assertEqual(verify(target)['events'][0]['arguments']['opaque'], self.output['customer_id'])
        self.assert_source_unchanged()

    def test_foreign_copied_dictionary_key_is_rejected_inside_whole_container(self):
        foreign = Policy(b'z' * 32)
        for copier in (copy.copy, copy.deepcopy):
            copied = copier(self.output['note'])
            target = self.base / copier.__name__
            called = []
            with self.assertRaises(PrivacyError):
                Recorder(target, foreign).call('handoff', {'password': {copied: 'safe'}},
                                               lambda _: called.append(True))
            self.assertEqual(called, [])
            self.assertFalse(target.exists())
        self.assert_source_unchanged()

    def test_copied_upstream_full_protection_replays_sdk_and_result_reference_plan(self):
        policy = Policy(KEY, fields=(*DEFAULT_FIELDS, 'note'))
        target = self.base / 'upstream-whole'
        calls = []
        def workflow(boundary):
            prepared = boundary.call('read', {}, lambda _: calls.append('read') or {'note': RAW})
            copied = copy.deepcopy(prepared)
            if isinstance(boundary, Replay):
                self.assertTrue(TOKEN.fullmatch(copied['note']))
            return boundary.call('login', {'password': copied['note']},
                                 lambda _: calls.append('login') or True, depends_on=[boundary.last_id])
        with Recorder(target, policy) as recorder:
            self.assertTrue(workflow(recorder))
        with Replay(target, policy, expected_root=recorder.root) as replay:
            self.assertTrue(workflow(replay))
        self.assertEqual(calls, ['read', 'login'])
        plan = {'format': 'replayseal/plan/v1', 'calls': [
            {'tool': 'read', 'arguments': {}},
            {'tool': 'login', 'arguments': {'password': {'$result': 'e000001', 'pointer': '/note'}},
             'depends_on': ['e000001']}]}
        self.assertEqual(run_plan(target, plan, policy),
                         {'events': 2, 'live_calls': 0, 'recorded_errors': 0, 'replayed': True})
        self.assert_source_unchanged()


if __name__ == '__main__':
    unittest.main()

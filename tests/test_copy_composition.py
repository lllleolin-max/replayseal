"""Copies of public Replay results retain provenance without widening trust."""

import copy
from pathlib import Path
import tempfile
import unittest

from replayseal import Policy, PrivacyError, Recorder, Replay, ReplayMismatch, verify
from replayseal.privacy import TOKEN

KEY = b'public-copy-regression-only-000000'
RAW = 'readable-prefix owner@example.test'


class CopyCompositionTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.base = Path(self.temp.name)
        self.policy = Policy(KEY)
        self.source = self.base / 'source'
        self.calls = {'capture': 0, 'replay': 0, 'target': 0}
        def capture(_):
            self.calls['capture'] += 1
            return {'customer_id': 'customer-017', 'note': RAW,
                    'nested': [{'account_id': 'account-1'}],
                    'keys': {'owner@example.test': ['safe']}}
        with Recorder(self.source, self.policy) as recorder:
            recorder.call('lookup', {}, capture)
        self.root = recorder.root
        self.source_bytes = {p.relative_to(self.source): p.read_bytes() for p in self.source.rglob('*.json')}
        def live(_):
            self.calls['replay'] += 1
            self.fail('Replay invoked a live callback')
        with Replay(self.source, self.policy, expected_root=self.root) as replay:
            self.output = replay.call('lookup', {}, live)
        self.assertEqual(self.calls, {'capture': 1, 'replay': 0, 'target': 0})

    def assert_source_unchanged(self):
        self.assertEqual(self.source_bytes,
                         {p.relative_to(self.source): p.read_bytes() for p in self.source.rglob('*.json')})

    def test_shallow_and_deep_complete_and_partial_strings_after_context(self):
        for copier in (copy.copy, copy.deepcopy):
            for value in (self.output['customer_id'], self.output['note'], next(iter(self.output['keys']))):
                with self.subTest(copier=copier.__name__, value_kind=bool(TOKEN.fullmatch(value))):
                    copied = copier(value)
                    self.assertEqual(type(copied), type(value))
                    self.assertEqual(str(copied), str(value))
                    self.assertEqual((copied.key_id, copied.policy_id),
                                     (self.policy.key_id, self.policy.policy_id))
                    self.assertIsNot(copied, value)
                    copied.key_id = 'changed-copy-only'
                    self.assertEqual(value.key_id, self.policy.key_id)
        self.assert_source_unchanged()

    def test_deepcopy_nested_containers_keys_and_repeated_references(self):
        value = self.output['note']
        original = {'result': self.output, 'aliases': [value, value], value: value}
        shallow = copy.copy(original)
        self.assertIsNot(shallow, original)
        self.assertIs(shallow['result'], original['result'])  # Standard shallow-copy semantics.
        copied = copy.deepcopy(original)
        self.assertIsNot(copied, original)
        self.assertIsNot(copied['result'], self.output)
        self.assertIsNot(copied['result']['nested'], self.output['nested'])
        self.assertIsNot(copied['result']['nested'][0], self.output['nested'][0])
        self.assertIs(copied['aliases'][0], copied['aliases'][1])
        key = next(k for k in copied if k == value)
        self.assertIs(key, copied['aliases'][0])
        self.assertIs(copied[key], copied['aliases'][0])
        copied['result']['nested'][0]['extra'] = 'detached'
        self.assertNotIn('extra', self.output['nested'][0])
        self.assert_source_unchanged()

    def test_copy_does_not_upgrade_plain_token_looking_strings(self):
        raw = str(self.output['customer_id'])
        for copier in (copy.copy, copy.deepcopy):
            copied = copier(raw)
            self.assertIs(type(copied), str)
            self.assertFalse(hasattr(copied, 'key_id'))
            self.assertNotEqual(self.policy.redact({'customer_id': copied})['customer_id'], raw)
        self.assert_source_unchanged()

    def test_same_key_copied_values_compose_without_live_replay(self):
        arguments = copy.deepcopy({'payload': [self.output], self.output['note']: self.output['customer_id']})
        target = self.base / 'target'
        def invoke(_):
            self.calls['target'] += 1
            return arguments
        with Recorder(target, self.policy) as recorder:
            recorder.call('handoff', arguments, invoke)
        with Replay(target, self.policy, expected_root=recorder.root) as replay:
            returned = replay.call('handoff', copy.deepcopy(arguments),
                                   lambda _: self.fail('live target replay'))
        self.assertEqual(returned['payload'][0]['customer_id'], self.output['customer_id'])
        self.assertEqual(self.calls, {'capture': 1, 'replay': 0, 'target': 1})
        self.assert_source_unchanged()

    def test_copied_foreign_key_is_rejected_before_invocation(self):
        target = self.base / 'foreign'
        recorder = Recorder(target, Policy(b'x' * 32))
        invoked = []
        copied = copy.deepcopy({'password': {'nested': [self.output['note'], self.output['customer_id']]}})
        with self.assertRaises(PrivacyError):
            recorder.call('handoff', copied, lambda _: invoked.append(True))
        self.assertEqual(invoked, [])
        self.assertFalse(target.exists())
        self.assert_source_unchanged()

    def test_copy_cannot_recover_original_full_value_hmac(self):
        trace = self.base / 'original-full'
        with Recorder(trace, self.policy) as recorder:
            original = recorder.call('read', {}, lambda _: RAW)
            recorder.call('login', {'password': original}, lambda _: True, depends_on=[recorder.last_id])
        before = verify(trace)['manifest']['root']
        replay = Replay(trace, self.policy, expected_root=before)
        partial = copy.deepcopy(replay.call('read', {}, lambda _: self.fail('live read')))
        invoked = []
        with self.assertRaisesRegex(ReplayMismatch, 'whole-value promotion'):
            replay.call('login', {'password': partial}, lambda _: invoked.append(True),
                        depends_on=[replay.last_id])
        with self.assertRaises(ReplayMismatch):
            replay.call('login', {'password': RAW})
        self.assertEqual(invoked, [])
        self.assertEqual(verify(trace)['manifest']['root'], before)
        self.assert_source_unchanged()


if __name__ == '__main__':
    unittest.main()

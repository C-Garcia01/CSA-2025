import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'src'))
from repair_agent import RepairAgent
from repair_auto import PLAN_SCHEMA


class AgentOutputTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.folder = Path(self.temp.name) / 'agent'
        self.proposal = {'summary': 'Repair', 'edits': [{
            'path': 'Demo.java', 'old': 'old();',
            'new': 'String pattern = "\\\\d+";\nnewCall();'}]}

    def response(self, value):
        return {'timed_out': False, 'returncode': 0, 'output': json.dumps({
            'is_error': False, 'result': json.dumps(value)})}

    def test_missing_edits_retries_with_specific_feedback(self):
        with patch('repair_agent.run_command', side_effect=[
                self.response({'summary': 'Missing edit array'}), self.response(self.proposal)]) as run:
            result = RepairAgent('claude').generate('repair', self.folder, 30)
        self.assertEqual(result, self.proposal)
        self.assertEqual(run.call_count, 2)
        self.assertIn("missing required property 'edits'", run.call_args.args[4])
        self.assertNotIn('--json-schema', run.call_args.args[0])
        self.assertTrue((self.folder / 'validation-1.txt').exists())
        self.assertTrue((self.folder / 'prompt-2.txt').exists())

    def test_source_escaping_is_decoded_exactly_once(self):
        with patch('repair_agent.run_command', return_value=self.response(self.proposal)):
            result = RepairAgent('claude').generate('repair', self.folder, 30)
        self.assertEqual(result['edits'][0]['new'], self.proposal['edits'][0]['new'])
        self.assertIn('\n', result['edits'][0]['new'])
        self.assertIn('\\\\d+', result['edits'][0]['new'])

    def test_fenced_json_is_accepted_without_changing_strings(self):
        response = self.response(self.proposal)
        response['output'] = json.dumps({'result': '```json\n' + json.dumps(self.proposal) + '\n```'})
        with patch('repair_agent.run_command', return_value=response):
            self.assertEqual(RepairAgent('claude').generate('repair', self.folder, 30), self.proposal)

    def test_invalid_edit_shape_is_rejected_after_bounded_retries(self):
        bad = {'summary': 'Wrong type', 'edits': [{'path': 'Demo.java', 'old': 'old();', 'new': []}]}
        with patch('repair_agent.run_command', return_value=self.response(bad)) as run:
            with self.assertRaisesRegex(ValueError, r'after 3 attempt.*root.edits\[0\].new: expected string'):
                RepairAgent('claude').generate('repair', self.folder, 30)
        self.assertEqual(run.call_count, 3)
        self.assertFalse((self.folder / 'reply.json').exists())

    def test_empty_edits_cannot_be_accepted_as_a_repair(self):
        with patch('repair_agent.run_command', return_value=self.response({'summary': 'empty', 'edits': []})):
            with self.assertRaisesRegex(ValueError, 'at least 1'):
                RepairAgent('claude').generate('repair', self.folder, 30)

    def test_broken_json_retries(self):
        bad = {'timed_out': False, 'returncode': 0, 'output': json.dumps({'result': '{"summary":'})}
        with patch('repair_agent.run_command', side_effect=[bad, self.response(self.proposal)]) as run:
            self.assertEqual(RepairAgent('claude').generate('repair', self.folder, 30), self.proposal)
        self.assertEqual(run.call_count, 2)

    def test_authentication_errors_are_not_retried(self):
        bad = {'timed_out': False, 'returncode': 1, 'output': json.dumps({
            'is_error': True, 'result': 'Please log in'})}
        with patch('repair_agent.run_command', return_value=bad) as run:
            with self.assertRaisesRegex(RuntimeError, 'Please log in'):
                RepairAgent('claude').generate('repair', self.folder, 30)
        self.assertEqual(run.call_count, 1)

    def test_plan_schema_remains_supported(self):
        plan = {key: [] if schema['type'] == 'array' else ''
                for key, schema in PLAN_SCHEMA['properties'].items()}
        plan.update(summary='Blocked', status='blocked', reason='Missing service')
        with patch('repair_agent.run_command', return_value=self.response(plan)):
            self.assertEqual(RepairAgent('claude').generate('prepare', self.folder, 30, PLAN_SCHEMA), plan)

    def test_retries_share_one_timeout_budget(self):
        with patch('repair_agent.time.monotonic', side_effect=[0, 1, 31]), patch(
                'repair_agent.run_command', return_value=self.response({'summary': 'missing'})) as run:
            with self.assertRaisesRegex(RuntimeError, 'timed out'):
                RepairAgent('claude').generate('repair', self.folder, 30)
        self.assertEqual(run.call_count, 1)
        self.assertEqual(run.call_args.args[2], 29)


if __name__ == '__main__':
    unittest.main()

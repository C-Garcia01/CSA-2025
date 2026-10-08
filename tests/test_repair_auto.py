import csv
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'src'))
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'examples'))
from create_repair_demo import create_demo
from repair_auto import run_auto, target_spec, materialize_plan, inspect_commit, output_path
from repair_workspace import git_command
from repair_agent import RepairAgent


class AutoTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        scenario = create_demo(self.root / 'demo')
        self.config = json.loads(scenario.read_text())
        self.repo = scenario.parent / 'repository'
        self.revision = self.config['revision']
        self.corpus = scenario.parent / 'repairs.jsonl'
        self.proposal = json.loads((scenario.parent / 'proposal.json').read_text())
        self.plan = {'summary': 'SQL input is a value; exact searches remain functional',
            'status': 'ready', 'reason': '', 'cwe': 'CWE-89', 'mechanism': 'SQL concatenation',
            'required_behavior': 'Return exact name matches', 'editable_files': ['app.py', 'storage.py'],
            'context_files': ['app.py', 'storage.py'],
            'files': [{'path': '.vcc-generated/note.txt', 'content': 'Frozen preparation artifact'}],
            **{k: self.config[k] for k in ['build_command', 'test_command', 'security_command']}}

    def tearDown(self):
        self.temp.cleanup()

    def run_auto(self, plan=None):
        with patch('repair_auto.RepairAgent.generate', side_effect=[plan or self.plan, self.proposal]) as model:
            report = run_auto(self.revision, self.root / 'run', repository=str(self.repo), corpus=self.corpus)
        return report, model

    def test_end_to_end_generation_and_export(self):
        report, model = self.run_auto()
        self.assertEqual(report['status'], 'validated', report)
        self.assertEqual(model.call_count, 2)
        self.assertEqual(report['provider'], 'claude')
        self.assertEqual(report['model'], 'claude-opus-4-8')
        self.assertEqual(report['input_vcc'], self.revision)
        self.assertNotEqual(report['prepared_revision'], self.revision)
        candidate = self.root / 'run/repair/attempt_1/repository'
        self.assertEqual(git_command(candidate, 'rev-parse', 'HEAD^'), report['prepared_revision'])
        self.assertEqual(git_command(self.repo, 'rev-parse', 'HEAD'), self.revision)
        with (self.root / 'run/pairs.csv').open(newline='') as f:
            rows = list(csv.DictReader(f))
        self.assertEqual(len(rows), 2)
        self.assertNotIn('before', rows[0])
        self.assertTrue(all(len(r['before_sha256']) == 64 for r in rows))
        self.assertTrue((self.root / 'run/history.bundle').is_file())
        config = json.loads((self.root / 'run/scenario.json').read_text())
        self.assertIn('.vcc-generated/note.txt', config['protected_files'])
        self.assertNotIn('proposal', config)

    def test_blocked_preparation_never_calls_repair_or_exports_pairs(self):
        report, model = self.run_auto({'summary': 'missing service', 'status': 'blocked', 'reason': 'Requires unavailable database'})
        self.assertEqual(report['status'], 'inconclusive')
        self.assertEqual(model.call_count, 1)
        self.assertIn('unavailable database', report['reason'])
        self.assertEqual((self.root / 'run/pairs.jsonl').read_text(), '')

    def test_unproven_baseline_never_calls_repair(self):
        self.plan['security_command'] = [sys.executable, '-c', 'print("VCC_SECURITY_PASS")']
        report, model = self.run_auto()
        self.assertEqual(report['status'], 'inconclusive')
        self.assertEqual(model.call_count, 1)
        self.assertEqual(report['exported_files'], 0)

    def test_generated_files_cannot_escape_or_overwrite(self):
        inventory = inspect_commit(self.repo, self.revision)
        for name in ['../outside', '.git/config', 'checks.py', '.vcc-generated/../../outside']:
            self.plan['files'] = [{'path': name, 'content': 'x'}]
            with self.assertRaises(ValueError):
                materialize_plan(self.plan, self.repo, inventory, 'demo/test', self.corpus)
        self.assertFalse((self.root / 'outside').exists())

    def test_tests_cannot_be_selected_as_editable(self):
        inventory = inspect_commit(self.repo, self.revision)
        # An explicit tests directory is always excluded from production candidates.
        (self.repo / 'tests').mkdir()
        (self.repo / 'tests/test_app.py').write_text('assert True')
        git_command(self.repo, 'add', '.')
        git_command(self.repo, '-c', 'user.name=T', '-c', 'user.email=t@t', 'commit', '-qm', 'tests')
        inventory = inspect_commit(self.repo, git_command(self.repo, 'rev-parse', 'HEAD'))
        self.plan['editable_files'] = self.plan['context_files'] = ['tests/test_app.py']
        with self.assertRaises(ValueError):
            materialize_plan(self.plan, self.repo, inventory, 'demo/test', self.corpus)

    def test_context_does_not_read_future_worktree(self):
        (self.repo / 'future.py').write_text('FUTURE_FIX_SECRET')
        inventory = inspect_commit(self.repo, self.revision)
        self.assertNotIn('FUTURE_FIX_SECRET', json.dumps(inventory))

    def test_target_parsing_and_unique_outputs(self):
        self.assertEqual(target_spec('https://github.com/a/b/commit/' + 'a'*40),
                         ('https://github.com/a/b.git', 'a'*40, 'a/b'))
        for target in ['https://evil.example/a/b/commit/' + 'a'*40, 'https://github.com/a/b/commit/main', '--help']:
            with self.assertRaises(ValueError): target_spec(target)
        self.assertNotEqual(output_path(), output_path())

    def test_agent_failure_is_persisted(self):
        with patch('repair_auto.RepairAgent.generate', side_effect=RuntimeError('Agent unavailable')):
            report = run_auto(self.revision, self.root / 'run', repository=str(self.repo))
        self.assertEqual(report['status'], 'inconclusive')
        self.assertEqual(json.loads((self.root / 'run/result.json').read_text())['reason'], 'Agent unavailable')

    def test_generated_behavioral_harness_is_run_and_frozen(self):
        content = (self.repo / 'checks.py').read_text()
        content = 'import sys\nfrom pathlib import Path\nsys.path.insert(0, str(Path(__file__).resolve().parents[1]))\n' + content
        name = '.vcc-generated/probe.py'
        self.plan['files'] = [{'path': name, 'content': content}]
        self.plan['test_command'] = [sys.executable, name, 'functional']
        self.plan['security_command'] = [sys.executable, name, 'security']
        report, _ = self.run_auto()
        self.assertEqual(report['status'], 'validated', report)
        hashes = report['protected_files_sha256']
        self.assertIn(name, hashes)

    def test_repair_cannot_modify_generated_harness(self):
        self.proposal['edits'] = [{'path': '.vcc-generated/note.txt', 'old': 'Frozen', 'new': 'Changed'}]
        with patch('repair_auto.RepairAgent.generate', side_effect=[self.plan, self.proposal, self.proposal]):
            report = run_auto(self.revision, self.root / 'run', repository=str(self.repo), corpus=self.corpus)
        self.assertEqual(report['status'], 'rejected')
        self.assertEqual(report['exported_files'], 0)

    def test_cli_needs_only_target(self):
        from repair_main import main
        with patch('sys.argv', ['repair_main.py', 'https://github.com/a/b/commit/' + 'a'*40]), \
             patch('repair_auto.run_auto', return_value={'status': 'inconclusive'}) as run, \
             patch('builtins.print'):
            self.assertEqual(main(), 1)
        self.assertIn('auto-', run.call_args.args[1])
        self.assertEqual(run.call_args.args[2], 'claude')

    def test_structured_provider_error_is_reported(self):
        error = {'returncode': 1, 'timed_out': False,
                 'output': json.dumps({'type': 'error', 'message': 'Provider declined request'})}
        with patch('repair_agent.run_command', return_value=error), \
             self.assertRaisesRegex(RuntimeError, 'Provider declined request'):
            RepairAgent('codex').generate('prompt', self.root / 'agent', 30)


if __name__ == '__main__':
    unittest.main()

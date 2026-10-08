import csv
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch
import zipfile

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'src'))
from repair_juliet import aggregate, inventory, run_juliet, seed_case, select_cases, vulnerable_source
from repair_workspace import git_command

SOURCE = b'''package testcases.CWE15;
public class CWE15_Demo__input_01 {
    public void bad() { String s = "} literal"; System.out.println(s); }
    public void good() throws Throwable { goodB2G(); }
    private void goodB2G() { String fix = "SECRET_REFERENCE_FIX"; }
}
'''


class JulietTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.archive = self.root / 'juliet.zip'
        with zipfile.ZipFile(self.archive, 'w') as z:
            for cwe in [15, 78]:
                z.writestr(f'Java/src/testcases/CWE{cwe}_Demo/CWE{cwe}_Demo__input_01.java', SOURCE)
                z.writestr(f'Java/src/testcases/CWE{cwe}_Demo/CWE{cwe}_Demo__input_51a.java', SOURCE)
                z.writestr(f'Java/src/testcases/CWE{cwe}_Demo/CWE{cwe}_Demo__input_51b.java', SOURCE)
            z.writestr('Java/src/testcases/CWE15_Demo/antbuild/CWE15_Demo__input_01.java', 'duplicate')
            z.writestr('Java/src/testcasesupport/IO.java', 'class IO {}')

    def tearDown(self):
        self.temp.cleanup()

    def test_strip_good_code_without_touching_bad_literals(self):
        source = vulnerable_source(SOURCE)
        self.assertNotIn('SECRET_REFERENCE_FIX', source)
        self.assertNotIn('goodB2G', source)
        self.assertIn('public void good() throws Throwable {', source)
        self.assertIn('String s = "} literal";', source)

    def test_comments_do_not_leak_solution_or_break_brace_scan(self):
        source = SOURCE.replace(b'goodB2G();', b'/* } GoodSink: SECRET_COMMENT */ goodB2G();')
        self.assertNotIn('SECRET_COMMENT', vulnerable_source(source))

    def test_case_grouping_keeps_companions(self):
        with zipfile.ZipFile(self.archive) as z:
            cases = inventory(z)
        self.assertEqual(len(cases), 4)
        self.assertEqual(len(select_cases(cases)), 2)
        self.assertTrue(all(c['id'].endswith('_01') for c in select_cases(cases)))
        self.assertEqual(len(select_cases(cases, 0)), 4)
        self.assertTrue(all(len(c['members']) == 2 for c in cases if c['id'].endswith('_51')))

    def test_seed_is_real_git_commit_without_reference_fix(self):
        with zipfile.ZipFile(self.archive) as z:
            case = select_cases(inventory(z))[0]
            revision, metadata = seed_case(z, case, self.root / 'seed', 'archive-hash')
        self.assertEqual(len(revision), 40)
        self.assertFalse(metadata['historical_vcc'])
        self.assertNotIn('SECRET_REFERENCE_FIX', git_command(self.root / 'seed', 'show', revision))
        self.assertEqual(git_command(self.root / 'seed', 'status', '--porcelain'), '')

    def test_provider_block_stops_batch_and_does_not_invent_fixed_hash(self):
        def blocked(target, output, **kwargs):
            self.assertNotIn('proposal', kwargs)
            output.mkdir(parents=True)
            report = {'status': 'inconclusive', 'reason': 'Agent failed: provider blocked', 'input_vcc': target}
            (output / 'result.json').write_text(json.dumps(report))
            return report
        with patch('repair_juliet.run_direct', side_effect=blocked) as runner:
            state = run_juliet(self.archive, self.root / 'run')
        self.assertEqual(runner.call_count, 1)
        self.assertEqual(state['counts'], {'inconclusive': 1, 'pending': 1})
        with (self.root / 'run/results.csv').open(newline='') as f:
            rows = list(csv.DictReader(f))
        self.assertEqual(len(rows[0]['before_commit']), 40)
        self.assertTrue(all(r['after_commit'] == '' for r in rows))
        self.assertEqual((self.root / 'run/pairs.jsonl').read_text(), '')

    def test_validated_hashes_are_taken_from_pipeline_report(self):
        output = self.root / 'run'
        folder = output / 'runs/demo'
        folder.mkdir(parents=True)
        report = {'status': 'validated', 'input_vcc': 'a'*40, 'fixed_commit': 'b'*40}
        (folder / 'result.json').write_text(json.dumps(report))
        (folder / 'pairs.jsonl').write_text(json.dumps({'path': 'Demo.java', 'status': 'validated', 'cwe': 'CWE-15', 'before_sha256': 'c'*64, 'after_sha256': 'd'*64}) + '\n')
        state = {'cases': [{'id': 'demo', 'cwe': 15, 'status': 'validated'}], 'provider': 'codex', 'model': None}
        aggregate(output, state)
        with (output / 'pairs.csv').open(newline='') as f:
            row = next(csv.DictReader(f))
        self.assertEqual(row['before_commit'], 'a'*40)
        self.assertEqual(row['after_commit'], 'b'*40)
        self.assertNotIn('before', row)

    def test_direct_repair_exports_real_parent_and_child_hashes(self):
        def repair(prompt, folder, timeout):
            self.assertIn('repair_examples', prompt)
            self.assertNotIn('SECRET_REFERENCE_FIX', prompt)
            self.assertNotIn('Generate any missing harness', prompt)
            bundle = json.loads(prompt.split('\n\n')[1])
            return {'summary': 'Generated edit', 'edits': [{
                'path': bundle['editable_files'][0],
                'old': 'System.out.println(s);', 'new': 'System.out.println(s.trim());'}]}
        corpus = self.root / 'corpus.jsonl'
        corpus.write_text('')
        with patch('repair_direct.RepairAgent.generate', side_effect=repair) as agent:
            state = run_juliet(self.archive, self.root / 'direct', corpus=corpus)
        self.assertEqual(agent.call_count, 2)
        self.assertEqual(state['counts'], {'generated_unvalidated': 2})
        self.assertEqual(state['validated_file_pairs'], 0)
        with (self.root / 'direct/results.csv').open(newline='') as stream:
            rows = list(csv.DictReader(stream))
        self.assertEqual(len(rows), 2)
        for row in rows:
            repo = self.root / 'direct/runs' / row['case_id'] / 'repository'
            self.assertEqual(git_command(repo, 'rev-parse', 'HEAD'), row['after_commit'])
            self.assertEqual(git_command(repo, 'rev-parse', 'HEAD^'), row['before_commit'])
            self.assertEqual(row['status'], 'generated_unvalidated')
            self.assertIn('behavioral validation not run', row['validation_scope'])

    def test_retry_failed_preserves_evidence_and_successful_cases(self):
        def repair(prompt, folder, timeout):
            bundle = json.loads(prompt.split('\n\n')[1])
            return {'summary': 'Generated edit', 'edits': [{
                'path': bundle['editable_files'][0],
                'old': 'System.out.println(s);', 'new': 'System.out.println(s.trim());'}]}

        def first_pass(prompt, folder, timeout):
            if 'CWE15_Demo/' in prompt:
                raise ValueError('Missing edits')
            return repair(prompt, folder, timeout)

        corpus = self.root / 'corpus.jsonl'
        corpus.write_text('')
        output = self.root / 'retry'
        with patch('repair_direct.RepairAgent.generate', side_effect=first_pass):
            state = run_juliet(self.archive, output, corpus=corpus)
        failed, succeeded = state['cases']
        old_failure = output / 'runs' / failed['id'] / 'result.json'
        success = output / 'runs' / succeeded['id'] / 'result.json'
        failure_bytes, success_bytes = old_failure.read_bytes(), success.read_bytes()
        with patch('repair_direct.RepairAgent.generate', side_effect=repair) as agent:
            state = run_juliet(self.archive, output, corpus=corpus, resume=True, retry_failed=True)
        self.assertEqual(agent.call_count, 1)
        self.assertEqual(state['counts'], {'generated_unvalidated': 2})
        self.assertEqual(old_failure.read_bytes(), failure_bytes)
        self.assertEqual(success.read_bytes(), success_bytes)
        self.assertEqual(state['cases'][0]['input_vcc'], failed['input_vcc'])
        self.assertTrue((output / state['cases'][0]['run_path'] / 'result.json').is_file())
        with (output / 'results.csv').open(newline='') as stream:
            rows = list(csv.DictReader(stream))
        self.assertTrue(rows[0]['evidence'].startswith('retries/'))
        self.assertEqual(rows[0]['before_commit'], failed['input_vcc'])

    def test_archive_traversal_is_rejected(self):
        with zipfile.ZipFile(self.archive, 'a') as z:
            z.writestr('Java/src/testcases/CWE15_Demo/../CWE15_Demo__input_02.java', SOURCE)
        with zipfile.ZipFile(self.archive) as z, self.assertRaises(ValueError):
            inventory(z)


if __name__ == '__main__':
    unittest.main()

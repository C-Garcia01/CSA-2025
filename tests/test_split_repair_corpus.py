import json
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'src'))

from split_repair_corpus import make_groups, split_corpus
from repair_context import RepairContext


def row(repo, cve, vcc=''):
    return dict(repository_id=repo, cve=cve, vcc=vcc, fixes=[], cwe='CWE-89')


class SplitTests(unittest.TestCase):
    def test_missing_vcc_does_not_join_unrelated_projects(self):
        self.assertEqual(len(make_groups([row('a/a', 'CVE-1'), row('b/b', 'CVE-2')], [])), 2)

    def test_transitive_cve_and_repository_groups(self):
        rows = [row('a/a', 'CVE-1'), row('b/b', 'CVE-1'), row('b/b', 'CVE-2')]
        self.assertEqual(len(make_groups(rows, [])), 1)

    def test_duplicate_repairs_stay_together(self):
        repairs = [dict(repository_id=r, before='old', after='new') for r in ['a/a', 'b/b']]
        self.assertEqual(len(make_groups([row('a/a', 'CVE-1'), row('b/b', 'CVE-2')], repairs)), 1)

    def test_held_out_reviewed_repairs_cannot_be_retrieved(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / 'references.jsonl'
            path.write_text(json.dumps(dict(reviewed=True, split='test')) + '\n')
            config = dict(flow={}, cwe='CWE-89', corpus=str(path), top_k=3)
            self.assertEqual(RepairContext(config, folder).retrieve(), [])

    def test_real_split_is_disjoint_and_reproducible(self):
        source = Path(__file__).resolve().parents[1] / 'data/all_repairs'
        with tempfile.TemporaryDirectory() as folder:
            first = split_corpus(source, Path(folder) / 'first')
            second = split_corpus(source, Path(folder) / 'second')
            self.assertEqual(first, second)
            partitions = {}
            for split in ['rag', 'dev', 'test']:
                path = Path(folder) / 'first' / split / 'vccs.jsonl'
                rows = [json.loads(line) for line in path.read_text().splitlines()]
                keys = set()
                for record in rows:
                    keys.add(('repo', record['repository_id']))
                    keys.add(('cve', record['cve']))
                    keys.update(('commit', x.strip()) for x in record['fixes'] + [record['vcc']] if x.strip())
                partitions[split] = keys
            self.assertFalse(partitions['rag'] & partitions['test'])
            self.assertFalse(partitions['rag'] & partitions['dev'])
            self.assertFalse(partitions['test'] & partitions['dev'])
            self.assertEqual(sum(r['csv_rows'] for r in first['coverage']), 70)
            self.assertEqual(len(first['coverage']), 10)


if __name__ == '__main__':
    unittest.main()

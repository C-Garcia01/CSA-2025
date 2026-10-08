import json
from pathlib import Path
import sys
import tempfile
import unittest
import zipfile

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'src'))
from import_juliet import import_archive, method


class JulietImportTests(unittest.TestCase):
    def test_method_balancing_ignores_comments_and_literals(self):
        text = '''    public void bad() throws Throwable
    {
        String braces = "\\\"}";
        // }
        /* { */
        if (true) { System.out.println('{'); }
    }
    public void good() { }
'''
        got = method(text, 'bad')
        self.assertIn("System.out.println('{')", got)
        self.assertNotIn('void good', got)
        self.assertTrue(got.endswith('    }'))
        self.assertIsNone(method(text, 'missing'))

    def test_multifile_cases_stay_together_and_references_are_not_repairs(self):
        with tempfile.TemporaryDirectory() as tmp:
            archive = Path(tmp) / 'source.zip'
            with zipfile.ZipFile(archive, 'w') as z:
                base = 'Java/src/testcases/CWE89_SQL_Injection/'
                z.writestr(base + 'CWE89_SQL_Injection__input_01.java', '    public void bad() { }\n    private void goodB2G() { }\n')
                for part in ['51a', '51b', '81a', '81_base', '81_bad', '81_goodB2G']:
                    z.writestr(base + 'CWE89_SQL_Injection__input_' + part + '.java', '// source')
                z.writestr(base + 'antbuild/CWE89_SQL_Injection__input_01.java', '// duplicate')
                z.writestr('Java/manifest.xml', '<broken>')
            output = Path(tmp) / 'import'
            report = import_archive(archive, output)
            self.assertEqual(report['source_files'], 7)
            self.assertEqual(report['case_groups'], 3)
            records = [json.loads(s) for s in (output / 'cases.jsonl').read_text().splitlines()]
            self.assertEqual(len({r['family'] for r in records}), 1)
            self.assertTrue(all(r['historical_vcc'] is None for r in records))
            refs = [json.loads(s) for s in (output / 'references.jsonl').read_text().splitlines()]
            self.assertEqual(refs[0]['reference_kind'], 'goodB2G')
            self.assertEqual(refs[0]['validation'], 'not_runtime_validated')
            other = Path(tmp) / 'second'
            import_archive(archive, other)
            self.assertEqual((output / 'sources.zip').read_bytes(), (other / 'sources.zip').read_bytes())

    def test_rejects_traversal(self):
        with tempfile.TemporaryDirectory() as tmp:
            archive = Path(tmp) / 'source.zip'
            with zipfile.ZipFile(archive, 'w') as z:
                z.writestr('Java/src/testcases/CWE89_SQL_Injection/../CWE89_bad_01.java', 'bad')
            with self.assertRaisesRegex(ValueError, 'Unsafe'):
                import_archive(archive, Path(tmp) / 'out')

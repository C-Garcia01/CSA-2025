import csv
import json
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from import_repair_csv import build_record, read_csv, split_patch


class ImportTests(unittest.TestCase):
    def test_side_by_side_tables_are_joined_by_identity(self):
        fields = ["repo_link", "commit_hash", "CVE_ID", "CWE_ID", "Repository", "VCC SHA", "CVE",
                  "CWE", "Fix SHAs", "Source file", "VCC label status", "Datasets", "Source record", "Notes"]
        left = ["https://github.com/a/one", "a" * 40, "CVE-1", "CWE-89"]
        right = ["https://github.com/b/two", "b" * 40, "CVE-2", "CWE-078", "c" * 40,
                 "Two.java", "candidate", "source", "record", ""]
        other_left = ["https://github.com/b/two", "b" * 40, "CVE-2", "CWE-78"]
        other_right = ["https://github.com/a/one", "a" * 40, "CVE-1", "CWE-089", "d" * 40,
                       "One.java", "candidate", "source", "record", ""]
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "input.csv"
            with path.open("w", newline="") as output:
                writer = csv.writer(output)
                writer.writerow(fields)
                writer.writerow(left + right)
                writer.writerow(other_left + other_right)
            records, unmatched = read_csv(path)
        self.assertEqual(unmatched, [])
        self.assertEqual(records[0]["left_rows"], [3])
        self.assertEqual(records[1]["left_rows"], [2])
        self.assertEqual(records[1]["fixes"], ["d" * 40])

    def test_changed_hunks_keep_both_versions(self):
        before, after = split_patch("A.java", "@@ -1,2 +1,2 @@\n context\n-unsafe();\n+safe();")
        self.assertIn("unsafe();", before)
        self.assertNotIn("safe();\n", before)
        self.assertIn("safe();", after)
        self.assertNotIn("unsafe();", after)

    def test_import_does_not_promote_candidates(self):
        commit = {"sha": "a" * 40, "parents": [{"sha": "b" * 40}], "commit": {"message": "Fix query"},
                  "files": [{"filename": "A.java", "patch": "@@ -1 +1 @@\n-old\n+new"}]}
        rows = [{"cwe": "CWE-89"}]
        with patch("import_repair_csv.fetch_commit", return_value=commit):
            record = build_record(("owner/repo", "CVE-1", "a" * 40), rows, Path("unused"), {})
        self.assertFalse(record["reviewed"])
        self.assertEqual(record["before_revision_kind"], "fix parent, not necessarily the VCC")


if __name__ == "__main__":
    unittest.main()

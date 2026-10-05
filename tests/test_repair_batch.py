import json
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "examples"))

from create_repair_demo import create_demo
from repair_batch import discover, run_batch


class BatchTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.scenario = create_demo(self.root / "demo")

    def tearDown(self):
        self.temp.cleanup()

    def test_discover_expands_directories_and_files(self):
        found = discover([self.scenario.parent])
        self.assertIn(self.scenario, found)

    def test_prepare_only_batch_summarizes_each_scenario(self):
        summary = run_batch([self.scenario], self.root / "out", prepare_only=True)
        self.assertEqual(summary["total"], 1)
        self.assertEqual(summary["counts"]["prepared"], 1)
        self.assertEqual(summary["runs"][0]["id"], "local-sql-demo")
        written = json.loads((self.root / "out" / "summary.json").read_text())
        self.assertEqual(written["counts"]["prepared"], 1)

    def test_missing_scenario_is_recorded_as_error_not_raised(self):
        summary = run_batch([self.root / "nope.json"], self.root / "out")
        self.assertEqual(summary["counts"]["error"], 1)
        self.assertIn("reason", summary["runs"][0])


if __name__ == "__main__":
    unittest.main()

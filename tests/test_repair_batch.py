import json
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "examples"))

from create_repair_demo import create_demo
from repair_batch import discover, run_batch, run_manifest


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

    def test_manifest_builds_prebuilt_and_setup_cases(self):
        scenario = str(self.scenario)
        manifest = self.root / "manifest.json"
        manifest.write_text(json.dumps({"cases": [
            {"id": "prebuilt", "scenario": scenario},
            {"id": "viasetup", "setup": ["python3", "-c", "import sys; print(sys.argv[1])", scenario]},
        ]}))
        summary = run_manifest(manifest, self.root / "mout", prepare_only=True)
        self.assertEqual(summary["total"], 2)
        self.assertEqual(summary["counts"]["prepared"], 2)
        self.assertEqual([r["id"] for r in summary["runs"]], ["prebuilt", "viasetup"])

    def test_manifest_setup_failure_is_error_not_raised(self):
        manifest = self.root / "manifest.json"
        manifest.write_text(json.dumps({"cases": [{"id": "broken", "setup": ["false"]}]}))
        summary = run_manifest(manifest, self.root / "mout")
        self.assertEqual(summary["counts"]["error"], 1)
        self.assertIn("Setup failed", summary["runs"][0]["reason"])


if __name__ == "__main__":
    unittest.main()

import json
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "examples"))

from create_java_repair_demo import create_demo
from repair_workspace import read_config

# These checks are Java-free; running the scenario itself needs mvn and JDK 8.


class JavaDemoTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.scenario = create_demo(Path(self.temp.name) / "demo")
        self.repo = self.scenario.parent / "repository"

    def tearDown(self):
        self.temp.cleanup()

    def test_scenario_validates_and_targets_java(self):
        config = read_config(self.scenario)
        self.assertEqual(config["cwe"], "CWE-89")
        self.assertEqual(config["environment"]["language"], "java")
        self.assertEqual(config["editable_files"], ["src/main/java/com/example/ReportDao.java"])
        self.assertNotIn(config["editable_files"][0], config["protected_files"])

    def test_reference_proposal_matches_the_vulnerable_method_once(self):
        config = read_config(self.scenario)
        proposal = json.loads((self.scenario.parent / "proposal.json").read_text())
        edit = proposal["edits"][0]
        source = (self.repo / edit["path"]).read_text(encoding="utf-8")
        self.assertEqual(source.count(edit["old"]), 1)
        self.assertIn("createStatement", edit["old"])
        self.assertNotIn("createStatement", edit["new"])
        self.assertIn("setString", edit["new"])

    def test_tests_and_adapter_are_protected(self):
        config = read_config(self.scenario)
        for name in config["protected_files"]:
            self.assertTrue((self.repo / name).is_file(), name)
        self.assertIn("security_check.py", config["protected_files"])


if __name__ == "__main__":
    unittest.main()

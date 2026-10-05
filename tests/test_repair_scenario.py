import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from repair_scenario import build_scenario, detect_build, nearest_pom, qualify


def git(repo, *args):
    return subprocess.check_output(["git", "-C", str(repo), *args], text=True).strip()


def commit(repo, message):
    git(repo, "add", "-A")
    git(repo, "-c", "user.name=T", "-c", "user.email=t@t.invalid", "commit", "-qm", message)
    return git(repo, "rev-parse", "HEAD")


class ScenarioTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.repo = Path(self.temp.name)
        git(self.repo, "init", "-q")
        self.source = "module/src/main/java/app/Dao.java"
        self.write("pom.xml", "<project><properties><maven.compiler.source>8</maven.compiler.source>"
                              "</properties></project>")
        self.write("module/pom.xml", "<project />")
        self.write(self.source, "class Dao {\n  String q(String id) {\n"
                                '    return "select x where id=\'" + id + "\'";\n  }\n}\n')
        self.write(".gitmodules", '[submodule "x"]\n  path = x\n  url = https://e.invalid/x.git\n')
        self.vcc = commit(self.repo, "introduce concatenated query")
        self.write(self.source, "class Dao {\n  String q(String id) {\n"
                                '    return bind("select x where id=?", id);\n  }\n}\n')
        self.fix = commit(self.repo, "bind the value")

    def tearDown(self):
        self.temp.cleanup()

    def write(self, name, content):
        path = self.repo / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content, encoding="utf-8")

    def test_qualification_attributes_deleted_line_to_introducing_commit(self):
        other = "0" * 40
        result = qualify(self.repo, self.fix, self.vcc, [self.vcc, other], [self.source])
        self.assertGreater(result["deleted_lines"], 0)
        by_vcc = {row["vcc"]: row for row in result["candidates"]}
        self.assertEqual(by_vcc[self.vcc]["verdict"], "introduces_fixed_lines")
        self.assertEqual(by_vcc[other]["verdict"], "no_fixed_lines_attributed")
        self.assertEqual(result["top_introducers"][0]["commit"], self.vcc)

    def test_build_detection_reads_tool_version_and_submodules(self):
        build = detect_build(self.repo, self.fix, [self.source])
        self.assertEqual(build["tool"], "maven")
        self.assertEqual(build["java_version"], "8")
        self.assertTrue(build["has_submodules"])
        self.assertEqual(nearest_pom(self.repo, self.fix, self.source), "module/pom.xml")

    def test_draft_scenario_leaves_security_check_for_the_curator(self):
        record = {"id": "demo/x@fix:CVE", "repository_id": "demo/x", "fix_sha": self.fix,
                  "fix_parent": self.vcc, "cwe": "CWE-89", "group": "CVE", "files": [self.source],
                  "candidate_vccs": [self.vcc]}
        result = build_scenario(self.repo, record, self.repo.parent)
        scenario = result["scenario"]
        self.assertEqual(scenario["revision"], self.vcc)
        self.assertEqual(scenario["editable_files"], [self.source])
        self.assertEqual(scenario["security_command"][0], "TODO")
        self.assertEqual(scenario["build_command"][:1], ["mvn"])
        self.assertEqual(result["qualification"]["candidates"][0]["verdict"], "introduces_fixed_lines")


if __name__ == "__main__":
    unittest.main()

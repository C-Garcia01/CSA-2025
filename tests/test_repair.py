import json
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "examples"))

from create_repair_demo import create_demo
from repair_agent import RepairAgent
from repair_context import RepairContext
from repair_main import run_repair
from repair_workspace import RepairWorkspace, checked_path, git_command, read_config, run_command


class RepairTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.scenario = create_demo(self.root / "demo")
        self.proposal = self.scenario.parent / "proposal.json"
        self.config = read_config(self.scenario)

    def tearDown(self):
        self.temp.cleanup()

    def run_proposal(self, proposal=None):
        if proposal is not None:
            self.proposal.write_text(json.dumps(proposal))
        return run_repair(self.scenario, self.root / "output", proposal_path=self.proposal)

    def test_multifile_repair_and_replay(self):
        result = self.run_proposal()
        self.assertEqual(result["status"], "validated")
        self.assertEqual(result["kind"], "synthetic_repair")
        self.assertEqual(result["review_status"], "not_reviewed")
        self.assertEqual(result["baseline"]["checks"]["security"]["returncode"], 1)
        patch_file = self.root / "output" / "repair.patch"
        workspace = RepairWorkspace(self.root / "replay")
        workspace.prepare(self.config["repository"], self.config["revision"])
        git_command(workspace.root, "apply", str(patch_file))
        checked = workspace.validate(self.config, self.root / "replay_checks", vulnerable=False)
        self.assertEqual(checked["status"], "passed")
        self.assertEqual(git_command(self.config["repository"], "status", "--porcelain"), "")

    def test_protected_test_edit_is_rejected(self):
        result = self.run_proposal({"edits": [{"path": "checks.py", "old": "FAIL", "new": "PASS"}]})
        self.assertEqual(result["status"], "rejected")
        self.assertIn("not editable", result["attempts"][0]["reason"])

    def test_broken_feature_is_rejected(self):
        content = (Path(self.config["repository"]) / "app.py").read_text()
        proposal = {"edits": [{"path": "app.py", "old": content,
                               "new": "def report_search(connection, name):\n    return []\n"}]}
        result = self.run_proposal(proposal)
        self.assertEqual(result["status"], "rejected")
        self.assertIn("test", result["attempts"][0]["reason"])

    def test_crash_is_not_baseline_vulnerability(self):
        config = json.loads(self.scenario.read_text())
        config["security_command"] = [sys.executable, "-c", "raise RuntimeError('crash')"]
        self.scenario.write_text(json.dumps(config))
        result = self.run_proposal()
        self.assertEqual(result["status"], "inconclusive")
        self.assertEqual(result["attempts"], [])

    def test_noop_is_rejected(self):
        result = self.run_proposal({"edits": [{"path": "app.py", "old": "name", "new": "name"}]})
        self.assertEqual(result["status"], "rejected")

    def test_invalid_proposal_is_rejected(self):
        self.assertEqual(self.run_proposal([])["status"], "rejected")

    def test_retry_starts_from_original(self):
        valid = json.loads(self.proposal.read_text())
        broken = {"edits": [{"path": "app.py", "old": "return find_reports", "new": "return missing"}]}
        with patch("repair_agent.RepairAgent.generate", side_effect=[broken, valid]) as generator:
            result = run_repair(self.scenario, self.root / "output")
        self.assertEqual(result["status"], "validated")
        self.assertEqual(result["accepted_attempt"], 2)
        self.assertIn("Unexpected test result", generator.call_args.args[0])

    def test_checks_cannot_modify_tracked_files(self):
        config = json.loads(self.scenario.read_text())
        script = "from pathlib import Path; p = Path('checks.py'); p.write_text(p.read_text() + '\\n')"
        config["build_command"] = [sys.executable, "-c", script]
        self.scenario.write_text(json.dumps(config))
        result = self.run_proposal()
        self.assertEqual(result["status"], "inconclusive")
        self.assertIn("modified tracked files", result["reason"])

    def test_existing_output_is_not_overwritten(self):
        self.run_proposal()
        result_file = self.root / "output" / "result.json"
        before = result_file.read_bytes()
        with self.assertRaises(FileExistsError):
            self.run_proposal()
        self.assertEqual(result_file.read_bytes(), before)

    def test_edits_are_atomic(self):
        root = Path(self.config["repository"])
        original = (root / "app.py").read_text()
        proposal = json.loads(self.proposal.read_text())
        proposal["edits"][1]["old"] = "missing code"
        with self.assertRaises(ValueError):
            RepairWorkspace(root).apply(proposal, self.config["editable_files"])
        self.assertEqual((root / "app.py").read_text(), original)

    def test_paths_cannot_escape_or_follow_symlinks(self):
        root = Path(self.config["repository"])
        (root / "link.py").symlink_to(self.scenario)
        for name in ["../scenario.json", str(self.scenario), ".git/config", "link.py"]:
            with self.assertRaises(ValueError):
                checked_path(root, name)

    def test_retrieval_filters_and_deduplicates(self):
        record = {"id": "valid", "cwe": "CWE-89", "repository_id": "other/repo", "group": "other",
                  "provenance": "test fixture", "reviewed": True, "mechanism": "SQL syntax",
                  "before": "unsafe", "after": "safe", "transformation": "bind value", "validation": "fixture"}
        records = [record, dict(record, id="duplicate"), dict(record, id="unreviewed", reviewed=False),
                   dict(record, id="same_group", group=self.config["group"]),
                   dict(record, id="same_repo", repository_id="https://github.com/demo/report-search.git"),
                   dict(record, id="other_cwe", cwe="CWE-78")]
        Path(self.config["corpus"]).write_text("\n".join(json.dumps(x) for x in records))
        found = RepairContext(self.config, self.config["repository"]).retrieve()
        self.assertEqual([x["id"] for x in found], ["valid"])

    def test_prepare_does_not_execute_commands(self):
        config = json.loads(self.scenario.read_text())
        config["build_command"] = ["this-command-does-not-exist"]
        self.scenario.write_text(json.dumps(config))
        result = run_repair(self.scenario, self.root / "prepared", prepare_only=True)
        self.assertEqual(result["status"], "prepared")
        self.assertTrue((self.root / "prepared" / "prompt.txt").is_file())

    def test_timeout(self):
        result = run_command([sys.executable, "-c", "import time; time.sleep(10)"], self.root, timeout=0.05)
        self.assertTrue(result["timed_out"])

    def test_agent_failures_leave_inconclusive_evidence(self):
        with patch("repair_agent.run_command", return_value={"timed_out": False, "returncode": 1, "output": ""}):
            result = run_repair(self.scenario, self.root / "output")
        self.assertEqual(result["status"], "inconclusive")
        self.assertIn("Agent failed", result["reason"])
        self.assertTrue((self.root / "output" / "result.json").exists())

    def test_claude_structured_result(self):
        proposal = json.loads(self.proposal.read_text())
        response = {"structured_output": proposal, "is_error": False}
        result = {"timed_out": False, "returncode": 0, "output": json.dumps(response)}
        with patch("repair_agent.run_command", return_value=result) as runner:
            actual = RepairAgent("claude").generate("repair", self.root / "agent", 30)
        self.assertEqual(actual, proposal)
        self.assertIn("--json-schema", runner.call_args.args[0])

    def test_codex_reads_final_json(self):
        proposal = json.loads(self.proposal.read_text())

        def fake_run(command, cwd, *args):
            Path(command[command.index("-o") + 1]).write_text(json.dumps(proposal))
            return {"timed_out": False, "returncode": 0, "output": "event stream"}

        with patch("repair_agent.run_command", side_effect=fake_run):
            actual = RepairAgent("codex").generate("repair", self.root / "agent", 30)
        self.assertEqual(actual, proposal)


if __name__ == "__main__":
    unittest.main()

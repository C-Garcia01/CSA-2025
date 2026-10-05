import argparse
import json
import shutil
import subprocess
import sys
from pathlib import Path


def create_demo(folder):
    folder = Path(folder).resolve()
    folder.mkdir(parents=True, exist_ok=False)
    repo = folder / "repository"
    shutil.copytree(Path(__file__).parent / "repair_demo", repo, ignore=shutil.ignore_patterns("__pycache__"))
    commands = [["init", "-q"], ["add", "."], ["-c", "user.name=Repair Demo",
                "-c", "user.email=demo@example.invalid", "commit", "-qm", "Add local demonstration"]]
    for command in commands:
        subprocess.run(["git", "-c", "core.hooksPath=/dev/null", *command], cwd=repo, check=True)
    revision = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=repo, text=True).strip()
    (folder / "repairs.jsonl").write_text("", encoding="utf-8")
    scenario = {
        "id": "local-sql-demo", "repository": "repository", "repository_id": "demo/report-search",
        "revision": revision, "cwe": "CWE-89", "group": "demo-report-search",
        "flow": {"source": "report_search name argument", "sink": "sqlite3 execute",
                 "path": ["app.py:report_search", "storage.py:find_reports"],
                 "mechanism": "The name becomes SQL syntax instead of a bound value",
                 "requirement": "Return exact name matches, including names with quotes"},
        "context_files": ["app.py", "storage.py"], "editable_files": ["app.py", "storage.py"],
        "protected_files": ["checks.py"], "corpus": "repairs.jsonl",
        "build_command": [sys.executable, "-m", "py_compile", "app.py", "storage.py"],
        "test_command": [sys.executable, "checks.py", "functional"],
        "security_command": [sys.executable, "checks.py", "security"],
        "environment": {"python": sys.version, "database": "stdlib sqlite3", "fixture": True},
        "timeout": 30, "max_attempts": 2,
    }
    proposal = {"summary": "Keep names as bound values across the service and storage boundary", "edits": [
        {"path": "app.py", "old": 'find_reports(connection, "name = \'" + name + "\'")',
         "new": "find_reports(connection, name)"},
        {"path": "storage.py", "old": "def find_reports(connection, condition):\n"
         '    return connection.execute("SELECT name FROM reports WHERE " + condition).fetchall()',
         "new": "def find_reports(connection, name):\n"
         '    return connection.execute("SELECT name FROM reports WHERE name = ?", (name,)).fetchall()'},
    ]}
    for name, data in [("scenario.json", scenario), ("proposal.json", proposal)]:
        (folder / name).write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")
    return folder / "scenario.json"


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Create a local fixture, not a historical VCC")
    parser.add_argument("folder")
    args = parser.parse_args()
    print(create_demo(args.folder))

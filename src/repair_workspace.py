import hashlib
import json
import os
import re
import signal
import subprocess
from pathlib import Path


def run_command(command, cwd, timeout=120, log=None, prompt=None):
    if not isinstance(command, list) or not command or not all(isinstance(x, str) for x in command):
        raise ValueError("Commands must be non-empty lists of strings")
    with subprocess.Popen(command, cwd=cwd, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                          stderr=subprocess.STDOUT, text=True, start_new_session=True) as process:
        timed_out = False
        try:
            output, _ = process.communicate(prompt, timeout=timeout)
        except subprocess.TimeoutExpired:
            timed_out = True
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            output, _ = process.communicate()
    if log:
        Path(log).write_text(output, encoding="utf-8")
    return {"command": command, "returncode": process.returncode, "timed_out": timed_out, "output": output}


def git_command(repo, *args):
    result = run_command(["git", "-c", "core.hooksPath=/dev/null", "-C", str(repo), *args], repo)
    if result["returncode"] != 0:
        raise RuntimeError(result["output"])
    return result["output"].rstrip("\n")


def checked_path(root, name):
    path = Path(name)
    if path.is_absolute() or not path.parts or any(x in ("..", ".git") for x in path.parts):
        raise ValueError(f"Invalid repository path: {name}")
    target = Path(root)
    for part in path.parts:
        target = target / part
        if target.is_symlink():
            raise ValueError(f"Symlinks are not supported: {name}")
    if not target.is_file():
        raise ValueError(f"Missing regular file: {name}")
    return target


def read_config(path):
    path = Path(path).resolve()
    config = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(config, dict):
        raise ValueError("The scenario must be a JSON object")
    required = ["id", "repository", "repository_id", "revision", "cwe", "group", "flow",
                "context_files", "editable_files", "protected_files", "build_command",
                "test_command", "security_command", "environment", "corpus"]
    for key in required:
        if not config.get(key):
            raise ValueError(f"Missing configuration: {key}")
    if not re.fullmatch(r"[0-9a-f]{40}", config["revision"]):
        raise ValueError("revision must be a full, pinned commit SHA")
    if not re.fullmatch(r"CWE-[0-9]+", config["cwe"]):
        raise ValueError("Use a CWE identifier such as CWE-89")
    for key in ["context_files", "editable_files", "protected_files"]:
        if not isinstance(config[key], list) or not all(isinstance(x, str) for x in config[key]):
            raise ValueError(f"{key} must be a list of file paths")
    if set(config["editable_files"]) & set(config["protected_files"]):
        raise ValueError("Editable files must not include protected files")
    if not set(config["editable_files"]).issubset(config["context_files"]):
        raise ValueError("Include every editable file in context_files")
    for key in ["build_command", "test_command", "security_command"]:
        command = config[key]
        if not isinstance(command, list) or not command or not all(isinstance(x, str) for x in command):
            raise ValueError(f"{key} must be an argument list")
    config["corpus"] = str((path.parent / config["corpus"]).resolve())
    if "://" not in config["repository"] and not config["repository"].startswith("git@"):
        config["repository"] = str((path.parent / config["repository"]).resolve())
    config.setdefault("timeout", 300)
    config.setdefault("agent_timeout", 300)
    config.setdefault("max_attempts", 2)
    config.setdefault("top_k", 3)
    config.setdefault("context_limit", 60000)
    for key in ["timeout", "agent_timeout", "max_attempts", "top_k", "context_limit"]:
        if type(config[key]) is not int or config[key] <= 0:
            raise ValueError(f"{key} must be a positive integer")
    if config["max_attempts"] > 5:
        raise ValueError("max_attempts must be at most 5")
    return config


class RepairWorkspace:
    def __init__(self, root):
        self.root = Path(root)

    def prepare(self, repository, revision, submodules=False):
        result = run_command(["git", "-c", "core.hooksPath=/dev/null", "clone", "--no-hardlinks",
                              "--no-checkout", "--", repository, str(self.root)], self.root.parent)
        if result["returncode"] != 0:
            raise RuntimeError(result["output"])
        git_command(self.root, "checkout", "--detach", revision)
        if git_command(self.root, "rev-parse", "HEAD") != revision:
            raise ValueError("Checkout does not match the pinned revision")
        if submodules:
            git_command(self.root, "submodule", "update", "--init", "--recursive")
        git_command(self.root, "remote", "remove", "origin")

    def tracked_files(self):
        """Tracked blobs, excluding submodule gitlinks which are not readable files."""
        entries = git_command(self.root, "ls-files", "--stage").splitlines()
        return [line.split("\t", 1)[1] for line in entries if not line.startswith("160000 ")]

    def hashes(self, files):
        return {name: hashlib.sha256(checked_path(self.root, name).read_bytes()).hexdigest() for name in files}

    def apply(self, proposal, editable_files):
        if not isinstance(proposal, dict):
            raise ValueError("The proposal must be a JSON object")
        edits = proposal.get("edits")
        if not isinstance(edits, list) or not edits:
            raise ValueError("The proposal contains no edits")
        changed = {}
        for edit in edits:
            if not isinstance(edit, dict) or set(edit) != {"path", "old", "new"}:
                raise ValueError("Each edit must contain path, old, and new")
            name = edit["path"]
            if not isinstance(name, str) or name not in editable_files:
                raise ValueError(f"File is not editable: {name}")
            target = checked_path(self.root, name)
            content = changed.get(name, target.read_bytes().decode("utf-8"))
            old, new = edit["old"], edit["new"]
            if not isinstance(old, str) or not isinstance(new, str) or not old or old == new:
                raise ValueError("Each edit needs different old and new strings")
            if content.count(old) != 1:
                raise ValueError(f"Edit must match exactly once: {name}")
            changed[name] = content.replace(old, new, 1)
        # Validate every edit before writing any files.
        for name, content in changed.items():
            checked_path(self.root, name).write_bytes(content.encode("utf-8"))
        return git_command(self.root, "diff", "--binary", "--no-ext-diff", "--no-textconv", "HEAD") + "\n"

    def validate(self, config, logs, vulnerable):
        logs.mkdir()
        results = {}
        for stage in ["build", "test", "security"]:
            result = run_command(config[f"{stage}_command"], self.root, config["timeout"], logs / f"{stage}.log")
            results[stage] = {key: value for key, value in result.items() if key != "output"}
            if result["timed_out"]:
                return {"status": "inconclusive", "reason": f"{stage} timed out", "checks": results}
            expected = 1 if stage == "security" and vulnerable else 0
            passed = result["returncode"] == expected
            if stage == "security":
                marker = "VCC_SECURITY_FAIL" if vulnerable else "VCC_SECURITY_PASS"
                opposite = "VCC_SECURITY_PASS" if vulnerable else "VCC_SECURITY_FAIL"
                lines = result["output"].splitlines()
                passed = passed and marker in lines and opposite not in lines
            if not passed:
                return {"status": "rejected", "reason": f"Unexpected {stage} result", "checks": results}
        return {"status": "passed", "checks": results}

import argparse
import json
import re
from pathlib import Path

from repair_workspace import run_command

HEX40 = re.compile(r"^[0-9a-f]{40}$")
JAVA_VERSION_KEYS = ("maven.compiler.source", "maven.compiler.release", "compiler.version")
GITHUB = "https://github.com/"


def git(repo, *args):
    result = run_command(["git", "-C", str(repo), *args], repo)
    if result["returncode"] != 0:
        raise RuntimeError(result["output"])
    return result["output"].rstrip("\n")


def mirror(repository_id, mirrors):
    if not re.fullmatch(r"[\w.-]+/[\w.-]+", repository_id):
        raise ValueError(f"repository_id must be owner/name: {repository_id}")
    path = Path(mirrors).resolve() / (repository_id.replace("/", "_") + ".git")
    if path.is_dir():
        return path
    path.parent.mkdir(parents=True, exist_ok=True)
    result = run_command(["git", "clone", "--bare", "--", GITHUB + repository_id + ".git", str(path)],
                         path.parent, timeout=1800)
    if result["returncode"] != 0:
        raise RuntimeError(result["output"])
    return path


def removed_lines(repo, fix_sha, path):
    """Parent-side line numbers the fix deleted or changed in one file."""
    diff = git(repo, "diff", "--unified=0", "--no-color", f"{fix_sha}^", fix_sha, "--", path)
    old = 0
    lines = []
    for line in diff.splitlines():
        header = re.match(r"^@@ -(\d+)(?:,(\d+))? ", line)
        if header:
            old = int(header.group(1))
            continue
        if line.startswith("-") and not line.startswith("---"):
            lines.append(old)
            old += 1
        elif line.startswith(" "):
            old += 1
    return lines


def blame_map(repo, revision, path):
    """Line number in `revision` -> commit that last touched it."""
    porcelain = git(repo, "blame", "--line-porcelain", revision, "--", path)
    mapping = {}
    sha = None
    for line in porcelain.splitlines():
        head = re.match(r"^([0-9a-f]{40}) \d+ (\d+)", line)
        if head:
            sha, final = head.group(1), int(head.group(2))
            mapping[final] = sha
    return mapping


def qualify(repo, fix_sha, fix_parent, candidates, files):
    """Attribute each fix-deleted line to the commit that introduced it."""
    introduced = {}
    total = 0
    for path in files:
        blame = blame_map(repo, fix_parent, path)
        for number in removed_lines(repo, fix_sha, path):
            sha = blame.get(number)
            if sha:
                introduced[sha] = introduced.get(sha, 0) + 1
                total += 1
    report = []
    for candidate in candidates:
        count = introduced.get(candidate, 0)
        report.append({"vcc": candidate, "introduced_lines": count,
                       "fraction": round(count / total, 3) if total else 0.0,
                       "verdict": "introduces_fixed_lines" if count else "no_fixed_lines_attributed"})
    top = sorted(introduced.items(), key=lambda item: -item[1])[:5]
    return {"deleted_lines": total, "candidates": report,
            "top_introducers": [{"commit": sha, "lines": count} for sha, count in top]}


def nearest_pom(repo, revision, path):
    tracked = set(git(repo, "ls-tree", "-r", "--name-only", revision).splitlines())
    directory = Path(path).parent
    while True:
        candidate = (directory / "pom.xml").as_posix() if directory.parts else "pom.xml"
        if candidate in tracked:
            return candidate
        if not directory.parts:
            return None
        directory = directory.parent


def detect_build(repo, revision, files):
    tracked = set(git(repo, "ls-tree", "-r", "--name-only", revision).splitlines())
    if any(name == "pom.xml" or name.endswith("/pom.xml") for name in tracked):
        tool = "maven"
    elif any(name.endswith(("build.gradle", "build.gradle.kts")) for name in tracked):
        tool = "gradle"
    else:
        tool = "unknown"
    java_version = None
    pom = nearest_pom(repo, revision, files[0]) if files else None
    root_pom = git(repo, "show", f"{revision}:pom.xml") if "pom.xml" in tracked else ""
    for source in (git(repo, "show", f"{revision}:{pom}") if pom else "", root_pom):
        for key in JAVA_VERSION_KEYS:
            match = re.search(rf"<{key}>\s*(?:1\.)?(\d+)\s*</{key}>", source)
            if match:
                java_version = match.group(1)
                break
        if java_version:
            break
    return {"tool": tool, "module_pom": pom, "java_version": java_version,
            "has_submodules": ".gitmodules" in tracked}


def build_scenario(repo, record, mirrors, revision=None):
    repository_id = record["repository_id"]
    fix_sha = record["fix_sha"]
    fix_parent = record.get("fix_parent") or git(repo, "rev-parse", f"{fix_sha}^")
    files = record["files"]
    revision = revision or fix_parent
    if not HEX40.fullmatch(revision):
        raise ValueError("revision must be a full 40-character SHA")
    build = detect_build(repo, revision, files)
    candidates = record.get("candidate_vccs", [])
    scenario = {
        "id": record["id"],
        "repository": GITHUB + repository_id + ".git",
        "repository_id": repository_id,
        "revision": revision,
        "cwe": record["cwe"],
        "group": record["group"],
        "flow": record.get("flow", {"source": "", "sink": "", "mechanism": record.get("mechanism", ""),
                                    "required_behavior": ""}),
        "context_files": files,
        "editable_files": files,
        "protected_files": record.get("test_files", []),
        "build_command": _build_command(build),
        "test_command": ["TODO", "functional test that fails when the feature is broken"],
        "security_command": ["TODO", "security adapter printing VCC_SECURITY_PASS/FAIL per REPAIR.md"],
        "environment": {"language": "java", "build_tool": build["tool"],
                        "java_version": build["java_version"], "submodules": build["has_submodules"],
                        "note": "Pin dependencies and provision the toolchain before running."},
        "corpus": "../../splits/rag/repairs.jsonl",
    }
    return {"scenario": scenario,
            "qualification": qualify(repo, fix_sha, fix_parent, candidates, files) if candidates else None,
            "build": build}


def _build_command(build):
    if build["tool"] == "maven":
        module = Path(build["module_pom"]).parent.as_posix() if build["module_pom"] else "."
        return ["mvn", "-q", "-pl", module, "-am", "-DskipTests", "package"]
    if build["tool"] == "gradle":
        return ["./gradlew", "assemble"]
    return ["TODO", "build command for " + build["tool"]]


def load_record(args):
    if args.record:
        return json.loads(Path(args.record).read_text(encoding="utf-8"))
    for key in ("repository_id", "fix_sha", "cwe", "group", "files"):
        if not getattr(args, key, None):
            raise ValueError(f"--{key.replace('_', '-')} is required without --record")
    return {"id": f"{args.repository_id}@{args.fix_sha}:{args.group}",
            "repository_id": args.repository_id, "fix_sha": args.fix_sha,
            "cwe": args.cwe, "group": args.group, "files": args.files,
            "candidate_vccs": args.candidate or [], "test_files": []}


def main():
    parser = argparse.ArgumentParser(description="Qualify a VCC and draft a repair scenario from a fixing commit")
    parser.add_argument("--record", help="JSON reference record with repository_id, fix_sha, cwe, group, files")
    parser.add_argument("--repository-id")
    parser.add_argument("--fix-sha")
    parser.add_argument("--cwe")
    parser.add_argument("--group")
    parser.add_argument("--files", nargs="+")
    parser.add_argument("--candidate", nargs="+", help="Candidate VCC SHAs to qualify against the fix")
    parser.add_argument("--revision", help="Vulnerable snapshot SHA (default: fix parent)")
    parser.add_argument("--mirrors", default="data/runs/mirrors")
    parser.add_argument("--output", help="Write the draft scenario here instead of stdout")
    args = parser.parse_args()
    record = load_record(args)
    repo = mirror(record["repository_id"], args.mirrors)
    result = build_scenario(repo, record, args.mirrors, args.revision)
    if args.output:
        Path(args.output).write_text(json.dumps(result["scenario"], indent=2) + "\n", encoding="utf-8")
        print(json.dumps({"scenario": args.output, "qualification": result["qualification"],
                          "build": result["build"]}, indent=2))
    else:
        print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()

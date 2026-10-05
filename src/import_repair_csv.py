import argparse
import csv
import difflib
import hashlib
import json
import re
import subprocess
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from urllib.parse import quote
from urllib.request import urlopen

from repair_context import repository_id


def write_json(path, data):
    path.write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")


def write_records(path, records):
    path.write_text("".join(json.dumps(record) + "\n" for record in records), encoding="utf-8")


def read_csv(path):
    with open(path, encoding="utf-8-sig", newline="") as source:
        reader = csv.DictReader(source)
        required = {"repo_link", "commit_hash", "CVE_ID", "Repository", "VCC SHA", "CVE", "CWE", "Fix SHAs"}
        if not required.issubset(reader.fieldnames or []):
            raise ValueError("Expected the original side-by-side VCC export columns")
        rows = list(reader)
    index = {}
    for number, row in enumerate(rows, 2):
        if not row["Repository"]:
            continue
        key = (repository_id(row["Repository"]), row["CVE"], row["VCC SHA"])
        if key in index:
            raise ValueError(f"Duplicate detailed record at row {number}")
        index[key] = {"repository_id": key[0], "cve": key[1], "vcc": key[2],
                      "cwe": "CWE-" + str(int(row["CWE"].split("-")[-1])),
                      "source_file": row["Source file"], "fixes": row["Fix SHAs"].split(";"),
                      "label_status": row["VCC label status"], "dataset": row["Datasets"],
                      "source_record": row["Source record"], "notes": row["Notes"],
                      "detail_row": number, "left_rows": []}
    unmatched = []
    for number, row in enumerate(rows, 2):
        if not row["repo_link"]:
            continue
        key = (repository_id(row["repo_link"]), row["CVE_ID"], row["commit_hash"])
        if key not in index:
            unmatched.append({"row": number, "repository_id": key[0], "cve": key[1], "vcc": key[2]})
        else:
            expected = "CWE-" + str(int(row["CWE_ID"].split("-")[-1]))
            if expected != index[key]["cwe"]:
                raise ValueError(f"CWE mismatch for matched record at row {number}")
            index[key]["left_rows"].append(number)
    return list(index.values()), unmatched


def fetch_commit(repo, revision, cache):
    path = cache / (repo.replace("/", "_") + "_" + revision + ".json")
    if path.exists():
        return json.loads(path.read_text())
    command = ["gh", "api", f"repos/{repo}/commits/{revision}?per_page=100"]
    result = subprocess.run(command, text=True, capture_output=True, timeout=90)
    if result.returncode:
        raise RuntimeError(result.stderr.strip())
    commit = json.loads(result.stdout)
    page = 2
    count = len(commit.get("files", []))
    while count == 100:
        result = subprocess.run(command[:-1] + [command[-1] + f"&page={page}"],
                                text=True, capture_output=True, timeout=90)
        if result.returncode:
            raise RuntimeError(result.stderr.strip())
        more = json.loads(result.stdout)["files"]
        commit["files"].extend(more)
        count = len(more)
        page += 1
        if page > 31:
            raise ValueError("Commit exceeds GitHub's file listing limit")
    write_json(path, commit)
    return commit


def fetch_source(repo, revision, name, cache):
    url = f"https://raw.githubusercontent.com/{repo}/{revision}/{quote(name)}"
    path = cache / (hashlib.sha256(url.encode()).hexdigest() + ".txt")
    if not path.exists():
        with urlopen(url, timeout=60) as response:
            path.write_bytes(response.read())
    return path.read_bytes().decode("utf-8"), url


def split_patch(name, patch):
    before, after = [f"File: {name}"], [f"File: {name}"]
    for line in patch.splitlines():
        if line.startswith(("--- ", "+++ ")):
            continue
        if line.startswith("@@"):
            before.append(line)
            after.append(line)
        elif line.startswith(" "):
            before.append(line[1:])
            after.append(line[1:])
        elif line.startswith("-"):
            before.append(line[1:])
        elif line.startswith("+"):
            after.append(line[1:])
    return "\n".join(before), "\n".join(after)


def build_record(key, rows, cache, reviews, all_languages=False):
    repo, cve, requested = key
    commit = fetch_commit(repo, requested, cache)
    sha = commit["sha"]
    if not sha.startswith(requested):
        raise ValueError("GitHub returned a different commit")
    if len(commit["parents"]) != 1:
        raise ValueError("Merge/root fixing commits require explicit parent review")
    parent = commit["parents"][0]["sha"]
    record_id = f"{repo}@{sha}:{cve}"
    review = reviews.get(record_id)
    files = commit["files"]
    java_files = [item for item in files if item["filename"].endswith(".java")]
    if not java_files and not all_languages:
        raise ValueError("No changed Java files in this candidate fix")
    cwes = {row["cwe"] for row in rows}
    if len(cwes) != 1:
        raise ValueError("Conflicting CWE labels need review")
    if review:
        if review["cwe"] not in cwes:
            raise ValueError("Review CWE differs from the CSV")
        selected = [item for item in files if item["filename"] in review["files"]]
        if len(selected) != len(review["files"]):
            raise ValueError("A reviewed file is absent from the commit")
    else:
        selected = [item for item in (files if all_languages else java_files) if item.get("patch")]
    before, after, evidence = [], [], []
    for item in selected:
        name = item["filename"]
        patch = item.get("patch", "")
        if review:
            if item["status"] != "modified":
                raise ValueError("Reviewed source extraction currently requires modified files")
            old, old_url = fetch_source(repo, parent, name, cache)
            new, new_url = fetch_source(repo, sha, name, cache)
            patch = "".join(difflib.unified_diff(old.splitlines(True), new.splitlines(True), n=5))
            evidence.append({"path": name, "before_url": old_url, "after_url": new_url,
                             "before_sha256": hashlib.sha256(old.encode()).hexdigest(),
                             "after_sha256": hashlib.sha256(new.encode()).hexdigest()})
        old_part, new_part = split_patch(name, patch)
        before.append(old_part)
        after.append(new_part)
    record = {"id": record_id, "cwe": cwes.pop(), "repository_id": repo, "group": cve,
              "reviewed": bool(review), "provenance": f"https://github.com/{repo}/commit/{sha}",
              "fix_sha": sha, "fix_parent": parent, "mechanism": commit["commit"]["message"],
              "before": "\n\n".join(before), "after": "\n\n".join(after),
              "transformation": "Pending repair-pattern review",
              "validation": "CSV association and downloaded commit only; not executed",
              "csv_records": rows, "files": [item["filename"] for item in files],
              "test_files": [item["filename"] for item in files if "test" in item["filename"].lower()],
              "source_evidence": evidence, "snippet_kind": "changed hunks, not complete files",
              "before_revision_kind": "fix parent, not necessarily the VCC"}
    if review:
        for field in ["mechanism", "transformation", "validation", "reviewer", "review_date"]:
            record[field] = review[field]
    return record


def import_csv(csv_path, output, reviews_path=None, all_languages=False):
    output = Path(output)
    output.mkdir(parents=True, exist_ok=True)
    cache = output / "cache"
    cache.mkdir(exist_ok=True)
    records, unmatched = read_csv(csv_path)
    review_data = json.loads(Path(reviews_path).read_text()) if reviews_path else {}
    reviews = {row["id"]: row for row in review_data.get("repairs", [])}
    for record in records:
        record["known_conflicts"] = [item for item in review_data.get("vcc_conflicts", [])
                                    if item["vcc"] == record["vcc"] and item["cve"] == record["cve"]]
    write_json(output / "vcc_index.json", records)
    jobs = {}
    java_records = [row for row in records if row["source_file"].endswith(".java") or row["left_rows"]]
    for row in (records if all_languages else java_records):
        for revision in row["fixes"]:
            revision = revision.strip()
            if re.fullmatch(r"[0-9a-f]{6,40}", revision):
                jobs.setdefault((row["repository_id"], row["cve"], revision), []).append(row)
    candidates, errors = [], []

    def fetch(key):
        try:
            return build_record(key, jobs[key], cache, reviews, all_languages), None
        except (OSError, RuntimeError, ValueError, subprocess.SubprocessError) as error:
            return None, {"key": key, "error": str(error)}

    with ThreadPoolExecutor(max_workers=4) as pool:
        for record, error in pool.map(fetch, jobs):
            if error:
                errors.append(error)
            else:
                candidates.append(record)
    candidates.sort(key=lambda row: row["id"])
    write_records(output / "candidates.jsonl", candidates)
    reviewed = [row for row in candidates if row["reviewed"]]
    write_records(output / "repairs.jsonl", reviewed)
    report = {"csv": str(Path(csv_path).resolve()), "csv_sha256": hashlib.sha256(Path(csv_path).read_bytes()).hexdigest(),
              "detailed_records": len(records), "left_records_matched": sum(len(x["left_rows"]) for x in records),
              "unmatched_left_records": unmatched, "java_records": len(java_records),
              "requested_fixes": len(jobs), "downloaded_candidates": len(candidates),
              "reviewed_repairs": len(reviewed), "errors": errors,
              "missing_reviews": sorted(set(reviews) - {row["id"] for row in reviewed})}
    write_json(output / "import_report.json", report)
    return report


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Build repair retrieval records from the VCC CSV")
    parser.add_argument("csv")
    parser.add_argument("--output", required=True)
    parser.add_argument("--reviews")
    parser.add_argument("--all-languages", action="store_true")
    args = parser.parse_args()
    print(json.dumps(import_csv(args.csv, args.output, args.reviews, args.all_languages), indent=2))

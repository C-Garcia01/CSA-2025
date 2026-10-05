import argparse
import json
import shutil
import subprocess
from pathlib import Path

# Rebuilds the CVE-2020-13921 repair scenario: a vulnerable SkyWalking snapshot
# plus the reproduction harness as protected files. The model only edits the
# four query DAOs. This is a real historical VCC used for repair research.

REPOSITORY = "https://github.com/apache/skywalking.git"
REPOSITORY_ID = "apache/skywalking"
FIX_PARENT = "cc9ea271a720e8def161a583595f75da9bda77a5"
CVE = "CVE-2020-13921"
MODULE = "oap-server/server-storage-plugin/storage-jdbc-hikaricp-plugin"
TEST_PACKAGE = MODULE + "/src/test/java/org/apache/skywalking/oap/server/storage/plugin/jdbc/vccprobe"
DAO = MODULE + "/src/main/java/org/apache/skywalking/oap/server/storage/plugin/jdbc"
EDITABLE = [DAO + "/h2/dao/H2AlarmQueryDAO.java", DAO + "/h2/dao/H2MetadataQueryDAO.java",
            DAO + "/h2/dao/H2TraceQueryDAO.java", DAO + "/mysql/MySQLAlarmQueryDAO.java"]
HARNESS = ["AlarmFixture.java", "AlarmFunctionalTest.java", "SqlInjectionProbeTest.java"]


def git(repo, *args):
    subprocess.run(["git", "-c", "core.hooksPath=/dev/null", "-C", str(repo), *args], check=True)


def mvn(args, cwd):
    subprocess.run(["mvn", *args], cwd=cwd, check=True)


def scenario(repository, revision, corpus):
    base = ["mvn", "-o", "-q", "-pl", MODULE, "-Dcheckstyle.skip=true", "-Drat.skip=true", "-Dlicense.skip=true"]
    return {
        "id": f"{REPOSITORY_ID}@fb7912c6:{CVE}", "repository": str(repository),
        "repository_id": REPOSITORY_ID, "revision": revision, "cwe": "CWE-89", "group": CVE,
        "flow": {"source": "alarm/trace/metadata keyword and endpointName query arguments",
                 "sink": "JDBCHikariCPClient.executeQuery LIKE predicate",
                 "mechanism": "Search strings are concatenated into SQL LIKE predicates across several JDBC query DAOs",
                 "requirement": "Keyword search still matches substrings; crafted keywords cannot alter the query"},
        "context_files": EDITABLE, "editable_files": EDITABLE,
        "protected_files": [f"{TEST_PACKAGE}/{name}" for name in HARNESS] + ["security_check.py"],
        "corpus": str(corpus),
        "build_command": base + ["-DskipTests", "test-compile"],
        "test_command": base + ["-Dtest=AlarmFunctionalTest", "-Dsurefire.failIfNoSpecifiedTests=false", "test"],
        "security_command": ["python3", "security_check.py"],
        "environment": {"language": "java", "build_tool": "maven", "java_version": "8", "submodules": False,
                        "note": "Upstream modules must be installed to ~/.m2 first; see --install."},
        "context_limit": 200000, "timeout": 600, "max_attempts": 2,
    }


def main():
    here = Path(__file__).resolve().parent
    parser = argparse.ArgumentParser(description="Build the CVE-2020-13921 repair scenario")
    parser.add_argument("work", help="Empty directory to create the prepared repository and scenario in")
    parser.add_argument("--repository", default=REPOSITORY, help="Clone URL or local mirror of apache/skywalking")
    parser.add_argument("--corpus", default=str(here.parents[1] / "data/splits/rag/repairs.jsonl"))
    parser.add_argument("--install", action="store_true",
                        help="Install upstream modules to ~/.m2 (needed once; requires JDK 8 and mvn)")
    args = parser.parse_args()
    work = Path(args.work).resolve()
    repo = work / "repository"
    work.mkdir(parents=True, exist_ok=False)

    git(work, "clone", "--no-hardlinks", "--", args.repository, str(repo))
    git(repo, "checkout", "--detach", FIX_PARENT)
    (repo / ".gitignore").write_text("target/\n**/target/\n", encoding="utf-8")
    destination = repo / TEST_PACKAGE
    destination.mkdir(parents=True, exist_ok=True)
    for name in HARNESS:
        shutil.copy(here / "harness" / name, destination / name)
    shutil.copy(here / "harness" / "security_check.py", repo / "security_check.py")
    git(repo, "add", "-A")
    git(repo, "-c", "user.name=VCC Harness", "-c", "user.email=harness@example.invalid",
        "commit", "-qm", f"Add {CVE} reproduction harness (protected)")
    revision = subprocess.check_output(["git", "-C", str(repo), "rev-parse", "HEAD"], text=True).strip()

    if args.install:
        git(repo, "submodule", "update", "--init", "--recursive")
        mvn(["-pl", MODULE, "-am", "-DskipTests", "-Dmaven.test.skip=true", "-Dcheckstyle.skip=true",
             "-Drat.skip=true", "-Dlicense.skip=true", "install"], repo)

    config = scenario(repo, revision, Path(args.corpus).resolve())
    (work / "scenario.json").write_text(json.dumps(config, indent=2) + "\n", encoding="utf-8")
    print(work / "scenario.json")


if __name__ == "__main__":
    main()

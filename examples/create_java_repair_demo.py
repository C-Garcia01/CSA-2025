import argparse
import json
import subprocess
from pathlib import Path

# A real Java/Maven/H2 scenario, not a historical CVE. It exercises the full
# pipeline on real build, functional and security tooling for CWE-89, mirroring
# the concatenated `id in ('...')` pattern seen in the reviewed SkyWalking fix.

POM = """<project xmlns="http://maven.apache.org/POM/4.0.0">
  <modelVersion>4.0.0</modelVersion>
  <groupId>com.example</groupId>
  <artifactId>report-service</artifactId>
  <version>1.0.0</version>
  <packaging>jar</packaging>
  <properties>
    <maven.compiler.source>8</maven.compiler.source>
    <maven.compiler.target>8</maven.compiler.target>
    <project.build.sourceEncoding>UTF-8</project.build.sourceEncoding>
  </properties>
  <dependencies>
    <dependency>
      <groupId>com.h2database</groupId>
      <artifactId>h2</artifactId>
      <version>1.4.200</version>
    </dependency>
    <dependency>
      <groupId>junit</groupId>
      <artifactId>junit</artifactId>
      <version>4.13.2</version>
      <scope>test</scope>
    </dependency>
  </dependencies>
</project>
"""

DAO = """package com.example;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.ArrayList;
import java.util.List;

public class ReportDao {

    private final Connection connection;

    public ReportDao(Connection connection) {
        this.connection = connection;
    }

    public List<String> namesByIds(List<String> ids) throws SQLException {
        StringBuilder in = new StringBuilder();
        for (int i = 0; i < ids.size(); i++) {
            if (i != 0) {
                in.append(",");
            }
            in.append("'").append(ids.get(i)).append("'");
        }
        List<String> names = new ArrayList<>();
        try (Statement statement = connection.createStatement();
             ResultSet rs = statement.executeQuery(
                 "select name from reports where id in (" + in + ")")) {
            while (rs.next()) {
                names.add(rs.getString("name"));
            }
        }
        return names;
    }
}
"""

# The exact method the reference proposal rewrites.
VULNERABLE_METHOD = """    public List<String> namesByIds(List<String> ids) throws SQLException {
        StringBuilder in = new StringBuilder();
        for (int i = 0; i < ids.size(); i++) {
            if (i != 0) {
                in.append(",");
            }
            in.append("'").append(ids.get(i)).append("'");
        }
        List<String> names = new ArrayList<>();
        try (Statement statement = connection.createStatement();
             ResultSet rs = statement.executeQuery(
                 "select name from reports where id in (" + in + ")")) {
            while (rs.next()) {
                names.add(rs.getString("name"));
            }
        }
        return names;
    }"""

REPAIRED_METHOD = """    public List<String> namesByIds(List<String> ids) throws SQLException {
        if (ids.isEmpty()) {
            return new ArrayList<>();
        }
        StringBuilder placeholders = new StringBuilder();
        for (int i = 0; i < ids.size(); i++) {
            if (i != 0) {
                placeholders.append(",");
            }
            placeholders.append("?");
        }
        List<String> names = new ArrayList<>();
        try (PreparedStatement statement = connection.prepareStatement(
                 "select name from reports where id in (" + placeholders + ")")) {
            for (int i = 0; i < ids.size(); i++) {
                statement.setString(i + 1, ids.get(i));
            }
            try (ResultSet rs = statement.executeQuery()) {
                while (rs.next()) {
                    names.add(rs.getString("name"));
                }
            }
        }
        return names;
    }"""

FIXTURE = """package com.example;

import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.SQLException;
import java.sql.Statement;

final class Fixture {

    static Connection seeded(String name) throws SQLException {
        Connection connection = DriverManager.getConnection(
            "jdbc:h2:mem:" + name + ";DB_CLOSE_DELAY=-1");
        try (Statement statement = connection.createStatement()) {
            statement.execute("create table reports (id varchar primary key, name varchar)");
            statement.execute("create table secrets (secret varchar)");
            statement.execute("insert into reports values ('r1', 'Alpha')");
            statement.execute("insert into reports values ('r2', 'O''Brien Report')");
            statement.execute("insert into secrets values ('TOP-SECRET')");
        }
        return connection;
    }

    private Fixture() {
    }
}
"""

FUNCTIONAL_TEST = """package com.example;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

import java.util.Arrays;
import java.util.List;
import org.junit.Test;

public class ReportServiceFunctionalTest {

    @Test
    public void returnsNamesForMatchingIds() throws Exception {
        ReportDao dao = new ReportDao(Fixture.seeded("functional"));
        List<String> names = dao.namesByIds(Arrays.asList("r1", "r2"));
        assertEquals(2, names.size());
        assertTrue(names.contains("Alpha"));
        assertTrue(names.contains("O'Brien Report"));
    }
}
"""

SECURITY_TEST = """package com.example;

import static org.junit.Assert.assertFalse;

import java.util.Collections;
import java.util.List;
import org.junit.Test;

public class SqlInjectionProbeTest {

    @Test
    public void idValuesCannotLeakAnotherTable() throws Exception {
        ReportDao dao = new ReportDao(Fixture.seeded("security"));
        List<String> names = dao.namesByIds(Collections.singletonList(
            "missing') UNION SELECT secret FROM secrets --"));
        assertFalse("SQL injection leaked a secret", names.contains("TOP-SECRET"));
    }
}
"""

SECURITY_ADAPTER = '''import re
import subprocess
import sys

# Security adapter for the contract in REPAIR.md. It runs the injection probe
# test and reports the security property, not the mere exit code.

def main():
    result = subprocess.run(
        ["mvn", "-B", "-Dtest=SqlInjectionProbeTest",
         "-Dsurefire.failIfNoSpecifiedTests=false", "test"],
        capture_output=True, text=True)
    output = result.stdout + result.stderr
    counts = re.findall(r"Tests run: (\\d+), Failures: (\\d+), Errors: (\\d+)", output)
    if not counts:
        return 2
    run, failures, errors = (int(value) for value in counts[-1])
    if errors > 0 or run < 1:
        return 2
    if failures > 0:
        print("VCC_SECURITY_FAIL")
        return 1
    print("VCC_SECURITY_PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
'''


def write(repo, name, content):
    path = repo / name
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")


def create_demo(folder):
    folder = Path(folder).resolve()
    folder.mkdir(parents=True, exist_ok=False)
    repo = folder / "repository"
    repo.mkdir()
    main_dir = "src/main/java/com/example"
    test_dir = "src/test/java/com/example"
    write(repo, "pom.xml", POM)
    write(repo, f"{main_dir}/ReportDao.java", DAO)
    write(repo, f"{test_dir}/Fixture.java", FIXTURE)
    write(repo, f"{test_dir}/ReportServiceFunctionalTest.java", FUNCTIONAL_TEST)
    write(repo, f"{test_dir}/SqlInjectionProbeTest.java", SECURITY_TEST)
    write(repo, "security_check.py", SECURITY_ADAPTER)
    write(repo, ".gitignore", "target/\n")
    commands = [["init", "-q"], ["add", "."], ["-c", "user.name=Repair Demo",
                "-c", "user.email=demo@example.invalid", "commit", "-qm", "Add Java demonstration"]]
    for command in commands:
        subprocess.run(["git", "-c", "core.hooksPath=/dev/null", *command], cwd=repo, check=True)
    revision = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=repo, text=True).strip()
    (folder / "repairs.jsonl").write_text("", encoding="utf-8")
    dao_path = f"{main_dir}/ReportDao.java"
    scenario = {
        "id": "local-java-sql-demo", "repository": "repository", "repository_id": "demo/report-service",
        "revision": revision, "cwe": "CWE-89", "group": "demo-java-report-service",
        "flow": {"source": "namesByIds ids argument", "sink": "Statement.executeQuery",
                 "path": [f"{dao_path}:namesByIds"],
                 "mechanism": "Each id is concatenated into the SQL in-clause instead of bound",
                 "requirement": "Return names for the requested ids and reject injected id values"},
        "context_files": [dao_path], "editable_files": [dao_path],
        "protected_files": [f"{test_dir}/Fixture.java",
                            f"{test_dir}/ReportServiceFunctionalTest.java",
                            f"{test_dir}/SqlInjectionProbeTest.java",
                            "security_check.py", "pom.xml"],
        "corpus": "repairs.jsonl",
        "build_command": ["mvn", "-q", "-DskipTests", "test-compile"],
        "test_command": ["mvn", "-q", "-Dtest=ReportServiceFunctionalTest",
                         "-Dsurefire.failIfNoSpecifiedTests=false", "test"],
        "security_command": ["python3", "security_check.py"],
        "environment": {"language": "java", "build_tool": "maven", "java_version": "8",
                        "database": "H2 in-memory", "fixture": True,
                        "note": "Requires mvn and JDK 8 on PATH; first run downloads dependencies."},
        "java_context": {"depth": 1}, "timeout": 600, "max_attempts": 2,
    }
    proposal = {"summary": "Bind each id as a parameter instead of quoting it into the in-clause",
                "edits": [{"path": dao_path, "old": VULNERABLE_METHOD, "new": REPAIRED_METHOD}]}
    for name, data in [("scenario.json", scenario), ("proposal.json", proposal)]:
        (folder / name).write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")
    return folder / "scenario.json"


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Create a local Java fixture, not a historical VCC")
    parser.add_argument("folder")
    args = parser.parse_args()
    print(create_demo(args.folder))

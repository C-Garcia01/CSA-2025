import re
import subprocess
import sys

MODULE = "oap-server/server-storage-plugin/storage-jdbc-hikaricp-plugin"

# Runs the injection probe against the real DAO and reports the security
# property per REPAIR.md, distinguishing an assertion failure from a setup error.

def main():
    result = subprocess.run(
        ["mvn", "-o", "-B", "-pl", MODULE, "-Dtest=SqlInjectionProbeTest",
         "-Dsurefire.failIfNoSpecifiedTests=false", "-Dcheckstyle.skip=true",
         "-Drat.skip=true", "-Dlicense.skip=true", "test"],
        capture_output=True, text=True)
    output = result.stdout + result.stderr
    counts = re.findall(r"Tests run: (\d+), Failures: (\d+), Errors: (\d+)", output)
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

import sqlite3
import sys

from app import report_search


def database():
    connection = sqlite3.connect(":memory:")
    connection.execute("CREATE TABLE reports (name TEXT)")
    connection.executemany("INSERT INTO reports VALUES (?)", [("Alice",), ("Bob",), ("O'Brien",)])
    return connection


def main():
    connection = database()
    if sys.argv[1] == "functional":
        assert report_search(connection, "Alice") == [("Alice",)]
        assert report_search(connection, "missing") == []
        print("Functional checks passed")
        return 0
    # Require a real query result instead of treating exceptions as evidence.
    for value in ["' OR 1=1 --", "' OR 'a'='a"]:
        if report_search(connection, value) != []:
            print("VCC_SECURITY_FAIL")
            return 1
    assert report_search(connection, "O'Brien") == [("O'Brien",)]
    assert report_search(connection, "") == []
    print("VCC_SECURITY_PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

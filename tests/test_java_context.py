import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from java_context import inventory


class JavaContextTests(unittest.TestCase):
    def test_follows_repository_import_chain_and_reports_external_import(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            (root / "pom.xml").write_text("<project />")
            sources = {
                "src/a/Start.java": "package a; import b.Middle; import java.util.List; class Start { Middle m; List<String> xs; }",
                "src/b/Middle.java": "package b; import c.End; class Middle { End end; }",
                "src/c/End.java": "package c; class End {}",
                "src/unrelated/Other.java": "package unrelated; class Other {}",
            }
            for name, content in sources.items():
                path = root / name
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text(content)

            result = inventory(root, ["src/a/Start.java"], depth=2)
            self.assertEqual([item["path"] for item in result["files"]],
                             ["src/a/Start.java", "src/b/Middle.java", "src/c/End.java"])
            self.assertEqual(result["descriptors"], ["pom.xml"])
            imports = result["files"][0]["imports"]
            self.assertEqual(imports[0]["status"], "resolved")
            self.assertEqual(imports[1]["status"], "unresolved_external")

    def test_depth_and_byte_budgets_are_enforced(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            (root / "A.java").write_text("import b.B; class A { B value; }")
            (root / "B.java").write_text("package b; class B {}")
            bounded = inventory(root, ["A.java"], depth=0)
            self.assertEqual([item["path"] for item in bounded["files"]], ["A.java"])
            with self.assertRaisesRegex(ValueError, "max_bytes"):
                inventory(root, ["A.java"], max_bytes=4)

    def test_wildcard_imports_can_leave_a_simple_type_ambiguous(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            sources = {
                "src/main/Use.java": "package main; import left.*; import right.*; class Use { Thing item; }",
                "src/left/Thing.java": "package left; class Thing {}",
                "src/right/Thing.java": "package right; class Thing {}",
            }
            for name, content in sources.items():
                path = root / name
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text(content)

            result = inventory(root, ["src/main/Use.java"], depth=1)
            use_file = next(item for item in result["files"] if item["path"] == "src/main/Use.java")
            reference = use_file["type_references"][0]
            self.assertEqual(reference["name"], "Thing")
            self.assertEqual(reference["status"], "ambiguous")
            self.assertEqual(len(reference["matches"]), 2)

    def test_rejects_traversal_and_symlink_seeds(self):
        with tempfile.TemporaryDirectory() as folder, tempfile.TemporaryDirectory() as outside:
            root = Path(folder)
            external = Path(outside) / "Secret.java"
            external.write_text("class Secret {}")
            (root / "Link.java").symlink_to(external)
            (root / "Seed.java").write_text("class Seed {}")
            with self.assertRaisesRegex(ValueError, "inside the checkout"):
                inventory(root, ["../Secret.java"])
            with self.assertRaisesRegex(ValueError, "symlinks"):
                inventory(root, ["Link.java"])

    def test_output_does_not_claim_to_resolve_calls(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            (root / "Seed.java").write_text("class Seed { void run() { work(); } }")
            result = inventory(root, ["Seed.java"])
            self.assertIn("does not resolve calls", result["scope"])
            self.assertIn("sound taint/callgraph analysis", result["scope"])
            self.assertNotIn("calls", result["files"][0])
            self.assertNotIn("callgraph", result)


if __name__ == "__main__":
    unittest.main()

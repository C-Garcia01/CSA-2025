import argparse
import json
import os
import re
from collections import deque
from pathlib import Path


DESCRIPTORS = {"pom.xml", "build.gradle", "build.gradle.kts", "settings.gradle",
               "settings.gradle.kts", "gradle.properties", "ivy.xml", "build.xml"}
SKIP_DIRS = {".git", ".gradle", ".idea", "build", "target", "node_modules"}
TYPE_RE = re.compile(r"\b(?:class|interface|enum|record)\s+([A-Za-z_$][\w$]*)")
PACKAGE_RE = re.compile(r"\bpackage\s+([\w.]+)\s*;")
IMPORT_RE = re.compile(r"\bimport\s+(static\s+)?([\w.*]+)\s*;")
IDENT_RE = re.compile(r"\b[A-Za-z_$][\w$]*\b")


def _source_text(path):
    text = path.read_text(encoding="utf-8", errors="replace")
    text = re.sub(r"/\*.*?\*/", " ", text, flags=re.S)
    return re.sub(r"//[^\n]*", " ", text)


def _safe_relative(root, value):
    path = Path(value)
    if path.is_absolute() or ".." in path.parts:
        raise ValueError("Seed paths must stay inside the checkout")
    candidate = root / path
    current = root
    for part in path.parts:
        current = current / part
        if current.is_symlink():
            raise ValueError("Seed paths cannot pass through symlinks")
    resolved = candidate.resolve()
    if not resolved.is_relative_to(root):
        raise ValueError("Seed paths must stay inside the checkout")
    return resolved


def _walk(root, max_files):
    found = []
    for directory, names, files in os.walk(root, followlinks=False):
        base = Path(directory)
        names[:] = sorted(name for name in names
                          if name not in SKIP_DIRS and not (base / name).is_symlink())
        for name in sorted(files):
            path = base / name
            if path.is_symlink():
                continue
            if path.suffix == ".java" or name in DESCRIPTORS:
                found.append(path)
                if len(found) > max_files:
                    raise ValueError("Repository inventory exceeds max_files")
    return found


def inventory(checkout, seeds, depth=2, max_files=5000, max_bytes=8_000_000):
    root = Path(checkout).resolve()
    if not root.is_dir():
        raise ValueError("Checkout must be a directory")
    if depth < 0 or max_files < 1 or max_bytes < 1:
        raise ValueError("depth, max_files, and max_bytes must be positive (depth may be zero)")

    files = _walk(root, max_files)
    java_paths = [path for path in files if path.suffix == ".java"]
    descriptor_paths = sorted(path.relative_to(root).as_posix() for path in files
                              if path.name in DESCRIPTORS)
    by_relative = {path.relative_to(root).as_posix(): path for path in java_paths}
    seed_names = []
    for seed in seeds:
        path = _safe_relative(root, seed)
        if path.suffix != ".java" or not path.is_file():
            raise ValueError("Each seed must be a Java source file")
        name = path.relative_to(root).as_posix()
        if name not in by_relative:
            raise ValueError("Seed Java file was not included in the repository scan")
        seed_names.append(name)
    if not seed_names:
        raise ValueError("At least one seed Java path is required")

    parsed = {}
    total_bytes = 0
    type_paths = {}
    package_paths = {}
    for name, path in sorted(by_relative.items()):
        content = path.read_bytes()
        total_bytes += len(content)
        if total_bytes > max_bytes:
            raise ValueError("Repository inventory exceeds max_bytes")
        text = _source_text(path)
        package_match = PACKAGE_RE.search(text)
        package = package_match.group(1) if package_match else ""
        types = sorted(set(TYPE_RE.findall(text)))
        imports = [{"name": match.group(2), "static": bool(match.group(1))}
                   for match in IMPORT_RE.finditer(text)]
        visible_text = IMPORT_RE.sub(" ", PACKAGE_RE.sub(" ", text))
        parsed[name] = {"path": name, "package": package, "declared_types": types,
                        "imports": imports, "identifiers": set(IDENT_RE.findall(visible_text))}
        package_paths.setdefault(package, []).append(name)
        for type_name in types:
            qualified = f"{package}.{type_name}" if package else type_name
            type_paths.setdefault(qualified, []).append(name)

    edges = {}
    for name, item in parsed.items():
        candidate_types = set()
        normalized_imports = []
        wildcard_packages = set()
        for imported in item["imports"]:
            value = imported["name"]
            if imported["static"]:
                parts = value.split(".")
                owner = ".".join(parts[:-1]) if len(parts) > 1 else value
                matches = sorted(type_paths.get(owner, []))
            elif value.endswith(".*"):
                package = value[:-2]
                wildcard_packages.add(package)
                matches = sorted(package_paths.get(package, []))
            else:
                matches = sorted(type_paths.get(value, []))
                candidate_types.update((value, path) for path in matches)
            normalized_imports.append({"name": value, "static": imported["static"],
                                       "matches": matches,
                                       "status": "resolved" if matches else "unresolved_external"})

        for package in wildcard_packages:
            for source_name in package_paths.get(package, []):
                for type_name in parsed[source_name]["declared_types"]:
                    qualified = f"{package}.{type_name}" if package else type_name
                    candidate_types.add((qualified, source_name))
        for source_name in package_paths.get(item["package"], []):
            for type_name in parsed[source_name]["declared_types"]:
                qualified = f"{item['package']}.{type_name}" if item["package"] else type_name
                candidate_types.add((qualified, source_name))
        references = []
        for simple in sorted({q.rsplit(".", 1)[-1] for q, _ in candidate_types}
                             & item["identifiers"]):
            candidates = sorted({(q, path) for q, path in candidate_types
                                 if q.rsplit(".", 1)[-1] == simple})
            references.append({"name": simple,
                               "matches": [{"type": q, "path": path} for q, path in candidates],
                               "status": "resolved" if len(candidates) == 1 else "ambiguous"})
        edges[name] = sorted({path for imp in normalized_imports for path in imp["matches"]}
                             | {match["path"] for ref in references for match in ref["matches"]})
        item["imports"] = normalized_imports
        item["type_references"] = references
        item.pop("identifiers")

    depths = {name: 0 for name in sorted(set(seed_names))}
    queue = deque(sorted(depths))
    while queue:
        name = queue.popleft()
        if depths[name] >= depth:
            continue
        for target in edges[name]:
            if target not in depths:
                depths[target] = depths[name] + 1
                queue.append(target)

    return {"checkout": ".", "seeds": sorted(set(seed_names)), "max_depth": depth,
            "limits": {"max_files": max_files, "max_bytes": max_bytes},
            "descriptors": descriptor_paths,
            "scope": "Package/import and same-repository type context inventory only; "
                     "does not resolve calls or provide sound taint/callgraph analysis.",
            "files": [dict(parsed[name], depth=depths[name]) for name in sorted(depths)]}


def main():
    parser = argparse.ArgumentParser(description="Inventory bounded Java dependency context")
    parser.add_argument("checkout")
    parser.add_argument("seeds", nargs="+")
    parser.add_argument("--depth", type=int, default=2)
    parser.add_argument("--max-files", type=int, default=5000)
    parser.add_argument("--max-bytes", type=int, default=8_000_000)
    args = parser.parse_args()
    try:
        result = inventory(args.checkout, args.seeds, args.depth, args.max_files, args.max_bytes)
    except (OSError, ValueError) as error:
        parser.error(str(error))
    print(json.dumps(result, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()

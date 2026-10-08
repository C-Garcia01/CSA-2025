"""Compile all imported sources by CWE; compilation is not security validation."""
import argparse
import json
import os
from pathlib import Path
import subprocess
import sys
import zipfile

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / 'src'))
from import_juliet import sha, write_json


def compile_suite(dataset, archive, java_home, output):
    dataset, output = Path(dataset), Path(output).resolve()
    output.mkdir(parents=True, exist_ok=False)
    source_root = output / 'source'
    with zipfile.ZipFile(dataset / 'imported/sources.zip') as z:
        for entry in z.infolist():
            if Path(entry.filename).is_absolute() or '..' in Path(entry.filename).parts:
                raise ValueError('Unsafe source path')
            if entry.filename.endswith('.java'):
                target = source_root / entry.filename
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_bytes(z.read(entry))
    libraries = []
    with zipfile.ZipFile(archive) as z:
        for name in sorted(z.namelist()):
            if name.startswith('Java/lib/') and name.endswith('.jar'):
                target = output / Path(name).name
                target.write_bytes(z.read(name))
                libraries.append(target)
    support = sorted((source_root / 'src/testcasesupport').glob('*.java'))
    results = []
    javac = str(Path(java_home).resolve() / 'bin/javac')
    version = subprocess.run([javac, '-version'], capture_output=True, text=True, check=True)
    for directory in sorted((source_root / 'src/testcases').iterdir()):
        files = sorted(directory.rglob('*.java'))
        classes = output / directory.name
        classes.mkdir()
        argfile = output / (directory.name + '.args')
        argfile.write_text('\n'.join('"' + str(p) + '"' for p in support + files))
        command = [javac, '-J-Xmx1536m', '-encoding', 'UTF-8', '-cp', os.pathsep.join(map(str, libraries)), '-d', str(classes), '@' + str(argfile)]
        log = output / (directory.name + '.log')
        try:
            run = subprocess.run(command, capture_output=True, text=True, timeout=300)
            log.write_text(run.stdout + run.stderr)
            row = {'cwe': directory.name.split('_')[0].replace('CWE', 'CWE-'), 'files': len(files), 'status': 'compiled' if run.returncode == 0 else 'compile_failed', 'returncode': run.returncode, 'log': log.name}
        except subprocess.TimeoutExpired:
            log.write_text('Compilation timed out after 300 seconds\n')
            row = {'cwe': directory.name.split('_')[0].replace('CWE', 'CWE-'), 'files': len(files), 'status': 'timeout', 'log': log.name}
        results.append(row)
        print(json.dumps(row), flush=True)
        write_json(output / 'report.json', {'scope': 'Original source compilation only; no execution or security validation',
            'sources_sha256': sha((dataset / 'imported/sources.zip').read_bytes()), 'jdk': (version.stdout + version.stderr).strip(),
            'dependencies_sha256': {p.name: sha(p.read_bytes()) for p in libraries}, 'results': results})
    return results


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--dataset', required=True)
    parser.add_argument('--archive', required=True)
    parser.add_argument('--java-home', required=True)
    parser.add_argument('--output', required=True)
    args = parser.parse_args()
    rows = compile_suite(args.dataset, args.archive, args.java_home, args.output)
    sys.exit(0 if all(r['status'] == 'compiled' for r in rows) else 1)

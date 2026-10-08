"""Import Juliet source/reference pairs without claiming generated or validated fixes."""
import argparse
import collections
import hashlib
import json
import re
import zipfile
from pathlib import Path

CWES = (15, 78, 80, 81, 83, 89, 113, 129, 134, 606)
CASE = re.compile(r'(.*)_(\d\d)(?:[a-z]|_(?:bad|base|good\w*))?\.java$')


def sha(data):
    return hashlib.sha256(data).hexdigest()


def write_json(path, value):
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + '\n')


def method(source, name):
    """Extract a Juliet void method, balancing braces outside Java literals/comments."""
    match = re.search(r'(?m)^    (?:public|private|protected) void ' + re.escape(name) + r'\([^)]*\)[^{]*\{', source)
    if not match:
        return None
    token = re.compile(r'"(?:\\.|[^"\\])*"|\'(?:\\.|[^\'\\])*\'|//[^\n]*|/\*.*?\*/|[{}]', re.S)
    depth = 1
    for item in token.finditer(source, match.end()):
        if item[0] == '{':
            depth += 1
        elif item[0] == '}':
            depth -= 1
            if not depth:
                return source[match.start():item.end()]
    raise ValueError('Unbalanced method: ' + name)


def import_archive(archive, output, cwes=CWES):
    output = Path(output)
    output.mkdir(parents=True, exist_ok=False)
    groups = collections.defaultdict(list)
    counts = collections.Counter()
    references = []
    with zipfile.ZipFile(archive) as source, zipfile.ZipFile(output / 'sources.zip', 'w', zipfile.ZIP_DEFLATED, compresslevel=9) as dest:
        for name in sorted(source.namelist()):
            m = re.match(r'Java/src/testcases/CWE(\d+)_', name)
            if not m or int(m[1]) not in cwes or '/antbuild/' in name:
                continue
            if '..' in Path(name).parts or '\\' in name:
                raise ValueError('Unsafe archive member: ' + name)
            case = CASE.fullmatch(Path(name).name)
            if not case:
                continue
            raw = source.read(name)
            relative = name.removeprefix('Java/')
            info = zipfile.ZipInfo(relative, (2017, 10, 1, 0, 0, 0))
            info.compress_type = zipfile.ZIP_DEFLATED
            dest.writestr(info, raw)
            cwe = 'CWE-' + m[1]
            group = case[1] + '_' + case[2]
            groups[(cwe, group)].append({'path': relative, 'sha256': sha(raw)})
            counts[cwe] += 1
            if case[2] == '01':
                text = raw.decode('utf-8').replace('\r\n', '\n')
                before = method(text, 'bad')
                # B2G preserves the bad input source; G2B commonly replaces it by a constant.
                after = method(text, 'goodB2G') or method(text, 'good')
                if before and after:
                    references.append({'id': group, 'cwe': cwe, 'family': case[1],
                        'kind': 'juliet_supplied_reference', 'validation': 'not_runtime_validated',
                        'source': relative, 'source_sha256': sha(raw), 'before': before,
                        'reference_good_method': after,
                        'reference_kind': 'goodB2G' if method(text, 'goodB2G') else 'good',
                        'warning': 'Supplied good method may change the input source or require helpers; not a generated feature-preserving repair.'})
        # Retain support source and dependency license texts, not prebuilt executables.
        for name in sorted(source.namelist()):
            if (name.startswith('Java/src/testcasesupport/') and name.endswith('.java')) or (name.startswith('Java/lib/') and name.endswith('.txt')):
                info = zipfile.ZipInfo(name.removeprefix('Java/'), (2017, 10, 1, 0, 0, 0))
                info.compress_type = zipfile.ZIP_DEFLATED
                dest.writestr(info, source.read(name))
        manifest = source.read('Java/manifest.xml')
    with (output / 'cases.jsonl').open('w') as stream:
        for (cwe, group), files in sorted(groups.items()):
            record = {'id': group, 'cwe': cwe, 'family': group.rsplit('_', 1)[0],
                      'kind': 'juliet_synthetic_testcase', 'files': files,
                      'validation': 'not_runtime_validated', 'historical_vcc': None}
            stream.write(json.dumps(record, sort_keys=True) + '\n')
    with (output / 'references.jsonl').open('w') as stream:
        for record in sorted(references, key=lambda r: r['id']):
            stream.write(json.dumps(record, sort_keys=True) + '\n')
    report = {'archive': Path(archive).name, 'archive_sha256': sha(Path(archive).read_bytes()),
              'cwes': ['CWE-' + str(n) for n in cwes], 'source_files': sum(counts.values()),
              'case_groups': len(groups), 'baseline_reference_pairs': len(references),
              'source_files_by_cwe': dict(sorted(counts.items())),
              'case_groups_by_cwe': dict(sorted(collections.Counter(c for c, _ in groups).items())),
              'manifest_sha256': sha(manifest),
              'grouping': 'Filename flow variant, retaining all inter-file companions. family removes the flow variant; keep families together in future splits.',
              'manifest_note': 'Original manifest has malformed XML (extra closing testcase tag); no silent XML repair. Case inventory uses canonical source filenames, excludes antbuild and Main/ServletMain drivers.',
              'sources_sha256': sha((output / 'sources.zip').read_bytes()),
              'references_are_generated_repairs': False}
    write_json(output / 'import_report.json', report)
    return report


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('archive')
    parser.add_argument('--output', required=True)
    args = parser.parse_args()
    print(json.dumps(import_archive(args.archive, args.output), indent=2))

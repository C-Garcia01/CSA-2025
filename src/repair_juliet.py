"""Feed Juliet Java cases to commit-only model generation, never saved repairs."""
import argparse
import collections
import csv
from datetime import datetime, timezone
import hashlib
import json
import logging
from pathlib import Path, PurePosixPath
import re
from uuid import uuid4
import zipfile

from repair_agent import DEFAULT_PROVIDER, resolve_model
from repair_auto import ROOT, run_auto, save
from repair_direct import run_direct
from repair_workspace import git_command

CWES = (15, 78, 80, 81, 83, 89, 113, 129, 134, 606)
CASE = re.compile(r'(.*)_(\d\d)(?:[a-z]|_(?:bad|base|good\w*))?\.java$')
TOKEN = re.compile(r'"(?:\\.|[^"\\])*"|\'(?:\\.|[^\'\\])*\'|//[^\n]*|/\*.*?\*/', re.S)
GOOD = re.compile(r'\b(?:public|protected|private)\s+(?:(?:static|final|synchronized)\s+)*[\w<>\[\], ?]+\s+(good\w*)\s*\([^)]*\)\s*(?:throws\s+[\w.,\s]+)?\{')


def sha(data):
    return hashlib.sha256(data).hexdigest()


def mask_token(match):
    return ''.join('\n' if c == '\n' else ' ' for c in match[0])


def vulnerable_source(raw):
    """Strip solution comments/good methods, preserving bad code and class shape.

    The public good() dispatcher becomes an empty stub for the original abstract
    superclass contract. It is never a repair candidate or a reference solution.
    Unsupported leftover good calls are rejected rather than leaked to models.
    """
    source = raw.decode('utf-8').replace('\r\n', '\n')
    source = TOKEN.sub(lambda m: mask_token(m) if m[0].startswith(('//', '/*')) else m[0], source)
    masked = TOKEN.sub(mask_token, source)
    removals = []
    for match in GOOD.finditer(masked):
        depth = 1
        end = match.end()
        while end < len(masked) and depth:
            depth += (masked[end] == '{') - (masked[end] == '}')
            end += 1
        if depth:
            raise ValueError('Unbalanced good-method declaration')
        replacement = source[match.start():match.end()] + '\n    }' if match[1] == 'good' else ''
        removals.append((match.start(), end, replacement))
    for start, end, replacement in reversed(removals):
        source = source[:start] + replacement + source[end:]
    masked = TOKEN.sub(mask_token, source)
    if re.search(r'\bgood(?!\s*\()[\w]*\s*\(', masked):
        raise ValueError('Unsupported good-method reference remains')
    # Compaction affects whitespace only; literals retain their original contents.
    return source


def inventory(archive, cwes=CWES):
    groups = collections.defaultdict(list)
    for info in archive.infolist():
        name = info.filename
        match = re.match(r'Java/src/testcases/CWE(\d+)_', name)
        if not match or int(match[1]) not in cwes or '/antbuild/' in name:
            continue
        if '..' in PurePosixPath(name).parts or '\\' in name:
            raise ValueError('Unsafe archive path: ' + name)
        case = CASE.fullmatch(PurePosixPath(name).name)
        if case:
            groups[(int(match[1]), case[1] + '_' + case[2])].append(name)
    return [{'cwe': cwe, 'id': name, 'members': sorted(members)} for (cwe, name), members in sorted(groups.items())]


def select_cases(cases, per_cwe=1):
    selected = []
    for cwe in sorted({case['cwe'] for case in cases}):
        candidates = [case for case in cases if case['cwe'] == cwe]
        candidates.sort(key=lambda c: (not c['id'].endswith('_01'), 'getParameter_Servlet' not in c['id'],
                                      'console_readLine' not in c['id'], c['id']))
        selected.extend(candidates if per_cwe == 0 else candidates[:per_cwe])
    return selected


def seed_case(archive, case, folder, archive_sha):
    repo = Path(folder).resolve()
    repo.mkdir(parents=True, exist_ok=False)
    provenance = []
    for name in case['members']:
        if re.search(r'_good\w*\.java$', name):
            continue
        raw = archive.read(name)
        relative = name.removeprefix('Java/')
        target = repo / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        converted = vulnerable_source(raw)
        target.write_text(converted, encoding='utf-8')
        provenance.append({'archive_path': name, 'repository_path': relative,
                           'original_sha256': sha(raw), 'input_sha256': sha(converted.encode())})
    # Runtime support contains abstract contracts, not testcase reference repairs.
    for name in archive.namelist():
        if (name.startswith('Java/src/testcasesupport/') and name.endswith('.java') and '/antbuild/' not in name
                or re.fullmatch(r'Java/lib/[^/]+\.(jar|txt)', name)):
            if '..' in PurePosixPath(name).parts or '\\' in name:
                raise ValueError('Unsafe support path')
            target = repo / name.removeprefix('Java/')
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(archive.read(name))
    metadata = {'kind': 'juliet_synthetic_vulnerable_snapshot', 'historical_vcc': False,
                'id': case['id'], 'cwe': 'CWE-' + str(case['cwe']), 'archive_sha256': archive_sha,
                'files': provenance, 'adaptations': ['LF normalization', 'remove testcase comments and supplied good-method implementations',
                    'retain empty good() compatibility stubs; exclude separate good implementation classes']}
    save(repo / 'juliet-input.json', metadata)
    (repo / 'README.md').write_text(
        '# Juliet input for automated repair\n\n'
        'This is a synthetic Juliet Java 1.3 testcase, not a historical VCC.\n'
        'The target is the original bad entry point and its companions under src/testcases/.\n'
        'Reference good implementations are excluded; good() stubs only satisfy the abstract base contract.\n'
        'Generate functional/security probes that call bad directly; do not use the good stubs.\n'
        'Original support is in src/testcasesupport/, original dependency jars/licenses in lib/.\n'
        'IO database connection settings are originally empty. If the case requires a database or other\n'
        'service, prepare the environment or report the specific blocker; do not claim mock sinks\n'
        'establish exploitability in a real deployed service. Do not disable the original bad behavior\n'
        'during preparation. No target-specific fix or hand-written harness is provided.\n', encoding='utf-8')
    (repo / '.gitignore').write_text('*.class\n__pycache__/\nbuild/\ntarget/\n')
    git_command(repo, 'init', '-q')
    # Shared identity lets existing retrieval exclude every other Juliet target.
    git_command(repo, 'remote', 'add', 'origin', 'https://github.com/nist/juliet-java-1.3.git')
    git_command(repo, 'add', '.')
    git_command(repo, '-c', 'user.name=Juliet Import', '-c', 'user.email=juliet@localhost',
                'commit', '-qm', 'Import vulnerable Juliet testcase without reference repairs')
    return git_command(repo, 'rev-parse', 'HEAD'), metadata


def aggregate(output, state):
    """Export every attempted outcome; generated and validated repairs retain their distinct status."""
    rows, pairs = [], []
    for case in state['cases']:
        run = output / case.get('run_path', f"runs/{case['id']}")
        report_path = run / 'result.json'
        report = json.loads(report_path.read_text()) if report_path.exists() else {}
        if report.get('status') in ('validated', 'generated_unvalidated'):
            records = [json.loads(line) for line in (run / 'pairs.jsonl').read_text().splitlines() if line]
            for record in records:
                record.update({'case_id': case['id'], 'historical_vcc': False,
                               'before_commit': report['input_vcc'], 'after_commit': report['fixed_commit']})
                record['evidence'] = str(run.relative_to(output) / 'result.json')
                pairs.append(record)
                rows.append({**record, 'reason': ''})
        else:
            rows.append({'case_id': case['id'], 'cwe': 'CWE-' + str(case['cwe']),
                'status': case.get('status', 'pending'), 'before_commit': case.get('input_vcc', ''),
                'after_commit': '', 'reason': report.get('reason', case.get('reason', '')),
                'provider': state['provider'], 'model': state['model'], 'historical_vcc': False,
                'path': ';'.join(f['repository_path'] for f in case.get('input_metadata', {}).get('files', [])),
                'before_sha256': ';'.join(f['input_sha256'] for f in case.get('input_metadata', {}).get('files', [])),
                'evidence': str(run.relative_to(output) / 'result.json') if report_path.exists() else ''})
    fields = ['case_id', 'cwe', 'status', 'before_commit', 'after_commit', 'prepared_revision', 'path',
              'before_sha256', 'after_sha256', 'provider', 'model', 'retrieved_examples',
              'historical_vcc', 'review_status', 'validation_scope', 'reason', 'evidence']
    for name, records in [('results.csv', rows), ('pairs.csv', pairs)]:
        with (output / name).open('w', newline='', encoding='utf-8') as stream:
            writer = csv.DictWriter(stream, fieldnames=fields, extrasaction='ignore')
            writer.writeheader()
            for row in records:
                writer.writerow({k: json.dumps(v) if isinstance(v, (list, dict)) else v for k, v in row.items()})
    (output / 'pairs.jsonl').write_text(''.join(json.dumps(row) + '\n' for row in pairs), encoding='utf-8')
    state['counts'] = dict(collections.Counter(case.get('status', 'pending') for case in state['cases']))
    state['validated_file_pairs'] = sum(r['status'] == 'validated' for r in pairs)
    state['generated_file_pairs'] = len(pairs)
    save(output / 'summary.json', state)


def run_juliet(archive_path, output=None, provider=DEFAULT_PROVIDER, model=None, corpus=None, per_cwe=1, resume=False, prepare_only=False, validate=False, retry_failed=False):
    if retry_failed and not resume:
        raise ValueError('--retry-failed requires --resume')
    model = resolve_model(provider, model)
    archive_path = Path(archive_path).resolve()
    archive_sha = sha(archive_path.read_bytes())
    output = Path(output or ROOT / 'data/runs' / ('juliet-' + datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ') + '-' + uuid4().hex[:8])).resolve()
    with zipfile.ZipFile(archive_path) as archive:
        if resume:
            state = json.loads((output / 'summary.json').read_text())
            if state.get('workflow', 'validated') != ('validated' if validate else 'direct'):
                raise ValueError('Resume must use the same workflow (--validate)')
            if any(state[k] != v for k, v in [('archive_sha256', archive_sha), ('provider', provider), ('model', model), ('corpus', str(Path(corpus).resolve()) if corpus else None)]):
                raise ValueError('Resume must use the same archive, provider, model and corpus')
        else:
            output.mkdir(parents=True, exist_ok=False)
            cases = inventory(archive)
            state = {'archive': archive_path.name, 'archive_sha256': archive_sha, 'provider': provider,
                     'model': model, 'corpus': str(Path(corpus).resolve()) if corpus else None,
                     'available_cases': len(cases), 'cases': select_cases(cases, per_cwe),
                     'generation': 'pipeline_model_generation', 'workflow': 'validated' if validate else 'direct',
                     'output': str(output)}
        if retry_failed:
            for case in state['cases']:
                if case.get('status') == 'inconclusive':
                    case.setdefault('previous_attempts', []).append({
                        'run_path': case.get('run_path', f"runs/{case['id']}"),
                        'status': case['status'], 'reason': case.get('reason', '')})
                    case['run_path'] = f"retries/{case['id']}/{uuid4().hex[:8]}"
                    case.pop('status', None)
                    case.pop('reason', None)
        state.pop('stopped_reason', None)
        logging.info('Juliet results: %s; selected %s cases', output, len(state['cases']))
        aggregate(output, state)
        # Prepare all selected input commits before any provider calls. This also
        # allows a blocked pilot to retain all requested vulnerable input hashes.
        for case in state['cases']:
            if case.get('input_vcc') or case.get('status') not in (None, 'pending'):
                continue
            try:
                revision, metadata = seed_case(archive, case, output / 'inputs' / case['id'], archive_sha)
                case['input_vcc'], case['input_metadata'] = revision, metadata
            except (OSError, ValueError, RuntimeError, KeyError) as error:
                case['status'], case['reason'] = 'inconclusive', str(error)
            aggregate(output, state)
        if prepare_only:
            return state
        for case in state['cases']:
            if case.get('status') not in (None, 'pending'):
                continue
            try:
                seed = output / 'inputs' / case['id']
                revision = case['input_vcc']
                if git_command(seed, 'rev-parse', 'HEAD') != revision or git_command(seed, 'status', '--porcelain'):
                    raise ValueError('Seed repository changed since preparation')
                runner = run_auto if validate else run_direct
                options = {} if validate else {'case': case}
                report = runner(revision, output / case.get('run_path', f"runs/{case['id']}"), provider=provider, model=model,
                                corpus=corpus, repository=str(seed), **options)
                case['status'] = report['status']
                case['reason'] = report.get('reason', '')
            except (OSError, ValueError, RuntimeError, KeyError) as error:
                case['status'], case['reason'] = 'inconclusive', str(error)
            aggregate(output, state)
            logging.info('%s: %s', case['id'], case['status'])
            # Do not issue thousands of calls after provider/auth/policy failure.
            if 'Agent failed' in case.get('reason', '') or 'No such file or directory' in case.get('reason', ''):
                state['stopped_reason'] = case['reason']
                aggregate(output, state)
                break
    return state


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('archive')
    parser.add_argument('--output')
    parser.add_argument('--provider', choices=['codex', 'claude'], default=DEFAULT_PROVIDER)
    parser.add_argument("--model", help="Model override (Claude default: claude-opus-4-8; Codex: CLI default)")
    parser.add_argument('--corpus')
    parser.add_argument('--per-cwe', type=int, default=1, help='Cases per CWE; default 1, use 0 for all')
    parser.add_argument('--validate', action='store_true', help='Generate a separate harness and require behavioral validation; default: direct RAG repair')
    parser.add_argument('--retry-failed', action='store_true', help='With --resume, retry inconclusive cases in new folders, preserving prior evidence')
    parser.add_argument('--resume', action='store_true', help='Continue pending cases in --output; completed outcomes are retained')
    parser.add_argument('--prepare-only', action='store_true', help='Create input commits and CSV inventory without model calls')
    args = parser.parse_args()
    if args.per_cwe < 0 or args.resume and not args.output or args.retry_failed and not args.resume:
        parser.error('--per-cwe must be nonnegative; --resume requires --output; --retry-failed requires --resume')
    logging.basicConfig(level=logging.INFO, format='%(levelname)s %(message)s')
    state = run_juliet(args.archive, args.output, args.provider, args.model, args.corpus, args.per_cwe, args.resume, args.prepare_only, args.validate, args.retry_failed)
    print(json.dumps({k: state.get(k) for k in ['output', 'counts', 'validated_file_pairs', 'generated_file_pairs', 'stopped_reason']}, indent=2))
    return 0 if args.prepare_only or all(c.get('status') in ('validated', 'generated_unvalidated') for c in state['cases']) else 1


if __name__ == '__main__':
    raise SystemExit(main())

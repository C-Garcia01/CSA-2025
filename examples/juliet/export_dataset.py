"""Export auditable snapshots and Git history from validated Juliet repair runs."""
import argparse
import json
from pathlib import Path
import shutil
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / 'src'))
from import_juliet import sha, write_json


def git(repo, *args):
    return subprocess.check_output(['git', '-c', 'core.hooksPath=/dev/null', '-C', str(repo), *args], text=True).strip()


def export(dataset, runs, baseline=False):
    dataset, runs = Path(dataset).resolve(), Path(runs).resolve()
    records = []
    summary = json.loads((runs / 'summary.json').read_text())
    for row in summary['runs']:
        run = Path(row['output']) / 'repair'
        report = json.loads((run / 'result.json').read_text())
        if report['status'] != 'validated':
            raise ValueError('Cannot export an unvalidated pair: ' + report['id'])
        scenario = json.loads((run / 'scenario.json').read_text())
        key = scenario['cwe'].removeprefix('CWE-')
        out = dataset / 'cases' / key
        out.mkdir(parents=True, exist_ok=True)
        source = scenario['editable_files'][0]
        if baseline:
            before = (run / 'original' / source).read_bytes()
            (out / 'before.java').write_bytes(before)
            for name in ['scenario.json', 'context.json', 'prompt.txt']:
                shutil.copyfile(run / name, out / name)
            shutil.copytree(run / 'baseline_checks', out / 'baseline_checks', dirs_exist_ok=True)
            git(run / 'original', 'bundle', 'create', str(out / 'history.bundle'), 'HEAD')
            continue
        original = run / 'original'
        candidate = run / f"attempt_{report['accepted_attempt']}" / 'repository'
        before, after = (original / source).read_bytes(), (candidate / source).read_bytes()
        if (out / 'before.java').read_bytes() != before:
            raise ValueError('Baseline export changed')
        (out / 'after.java').write_bytes(after)
        for name in ['result.json', 'repair.patch']:
            shutil.copyfile(run / name, out / name)
        attempt = run / f"attempt_{report['accepted_attempt']}"
        shutil.copyfile(attempt / 'proposal.json', out / 'proposal.json')
        shutil.copytree(attempt / 'checks', out / 'repaired_checks', dirs_exist_ok=True)
        git(candidate, 'add', '--', source)
        if git(candidate, 'diff', '--cached', '--name-only'):
            git(candidate, '-c', 'user.name=Juliet Dataset', '-c', 'user.email=juliet@localhost', 'commit', '-qm', 'Repair synthetic Juliet case after protected runtime validation')
        fixed = git(candidate, 'rev-parse', 'HEAD')
        if git(candidate, 'rev-parse', 'HEAD^') != scenario['revision']:
            raise ValueError('Fix must directly follow vulnerable snapshot')
        git(candidate, 'bundle', 'create', str(out / 'history.bundle'), 'HEAD')
        records.append({'id': report['id'], 'cwe': scenario['cwe'], 'group': scenario['group'],
            'kind': 'juliet_synthetic_repair', 'historical_vcc': False,
            'vcc_kind': 'synthetic_vulnerable_snapshot_not_proven_introducing_commit',
            'vulnerable_commit': scenario['revision'], 'fixed_commit': fixed,
            'git_bundle': f'cases/{key}/history.bundle', 'repository_path': source,
            'before': before.decode(), 'after': after.decode(),
            'before_sha256': sha(before), 'after_sha256': sha(after),
            'original_archive_source': scenario['environment']['original_source'],
            'original_archive_source_sha256': scenario['environment']['original_sha256'],
            'adaptations': scenario['environment']['adaptations'],
            'generation': 'assistant-authored saved proposal; replayed by repair runner; not an autonomous CLI-generation benchmark',
            'retrieved_examples': report['retrieved_examples'],
            'retrieval_mode': 'historical_context' if report['retrieved_examples'] else 'repository_only',
            'status': 'validated', 'review_status': 'not_independently_reviewed',
            'validation_scope': scenario['environment']['validation_scope'],
            'evidence': f'cases/{key}/result.json'})
    if not baseline:
        with (dataset / 'repairs.jsonl').open('w') as stream:
            for record in sorted(records, key=lambda r: int(r['cwe'][4:])):
                stream.write(json.dumps(record, sort_keys=True) + '\n')
        write_json(dataset / 'repair_summary.json', {'validated_pairs': len(records),
            'with_historical_retrieval': sum(bool(r['retrieved_examples']) for r in records),
            'repository_only': sum(not r['retrieved_examples'] for r in records),
            'all_imported_cases_runtime_validated': False,
            'run_kind': 'saved_assistant_proposal_replay',
            'cwes': [r['cwe'] for r in records]})


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--dataset', required=True)
    parser.add_argument('--runs', required=True)
    parser.add_argument('--baseline', action='store_true')
    args = parser.parse_args()
    export(args.dataset, args.runs, args.baseline)

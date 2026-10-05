import argparse
import hashlib
import json
from pathlib import Path

from import_repair_csv import write_json, write_records
from repair_context import repository_id


CWES = [15, 78, 80, 81, 83, 89, 113, 129, 134, 606]


def make_groups(rows, repairs):
    parents = list(range(len(rows)))

    def root(index):
        while parents[index] != index:
            parents[index] = parents[parents[index]]
            index = parents[index]
        return index

    seen = {}
    for index, row in enumerate(rows):
        keys = [('repo', repository_id(row['repository_id'])), ('cve', row['cve'])]
        if row['vcc']:
            keys.append(('vcc', row['vcc']))
        keys.extend(('fix', sha.strip()) for sha in row['fixes'] if sha.strip())
        for key in keys:
            if key in seen:
                parents[root(index)] = root(seen[key])
            seen[key] = index
    #Keep identical repair snippets in the same partition.
    fingerprints = {}
    for repair in repairs:
        index = seen.get(('repo', repository_id(repair['repository_id'])))
        if index is None:
            raise ValueError('Repair repository absent from the CSV index')
        digest = hashlib.sha256((repair['before'] + repair['after']).encode()).hexdigest()
        if digest in fingerprints:
            parents[root(index)] = root(fingerprints[digest])
        fingerprints[digest] = index
    groups = {}
    for index, row in enumerate(rows):
        groups.setdefault(root(index), []).append(row)
    return list(groups.values())


def split_corpus(source, output, seed='vcc-2026'):
    source, output = Path(source), Path(output)
    rows = json.loads((source / 'vcc_index.json').read_text())
    repairs = [json.loads(line) for line in (source / 'candidates.jsonl').read_text().splitlines()]
    groups = make_groups(rows, repairs)
    reviewed_repos = {repository_id(r['repository_id']) for r in repairs if r['reviewed']}

    def group_key(group):
        names = sorted({repository_id(row['repository_id']) for row in group})
        digest = hashlib.sha256((seed + '|'.join(names)).encode()).hexdigest()
        return (not bool(set(names) & reviewed_repos), digest)

    groups.sort(key=group_key)
    #Allocate whole groups; ratios are targets, not row-level guarantees.
    counts = {'rag': 0, 'dev': 0, 'test': 0}
    targets = {'rag': .6, 'dev': .2, 'test': .2}
    assignments, manifest, covered = {}, [], set()
    split_cwes = {name: set() for name in counts}
    for group in groups:
        repos = {repository_id(row['repository_id']) for row in group}
        cwes = {r['cwe'] for r in repairs if r['reviewed']
                and repository_id(r['repository_id']) in repos}
        split = 'rag' if cwes - covered else min(counts, key=lambda name: counts[name] / targets[name])
        row_cwes = {row['cwe'] for row in group}
        if not cwes - covered:
            for name in ['test', 'dev']:
                if row_cwes & (covered - split_cwes[name]):
                    split = name
                    break
        if split == 'rag':
            covered.update(cwes)
        split_cwes[split].update(row_cwes)
        counts[split] += 1
        for row in group:
            assignments[repository_id(row['repository_id'])] = split
            manifest.append(dict(row, split=split, runtime_validated=False))
    output.mkdir(parents=True, exist_ok=True)
    write_records(output / 'manifest.jsonl', manifest)
    quarantine = [r for r in manifest if not r['vcc'] or r.get('known_conflicts')]
    write_records(output / 'quarantine.jsonl', quarantine)
    for split in counts:
        folder = output / split
        folder.mkdir(exist_ok=True)
        selected = [row for row in manifest if row['split'] == split]
        candidates = [dict(r, split=split) for r in repairs
                      if assignments[repository_id(r['repository_id'])] == split]
        write_records(folder / 'vccs.jsonl', selected)
        #Held-out fixes belong to evaluator references, never to retrieval.
        name = 'candidates.jsonl' if split == 'rag' else 'references.jsonl'
        write_records(folder / name, candidates)
        if split == 'rag':
            eligible = [r for r in candidates if r['reviewed']]
            write_records(folder / 'repairs.jsonl', eligible)
        queries = [{key: row[key] for key in ['repository_id', 'cve', 'vcc', 'cwe', 'split',
                                             'label_status', 'runtime_validated']}
                   for row in selected if row['vcc'] and not row.get('known_conflicts')]
        write_records(folder / 'queries.jsonl', queries)
    coverage = []
    for number in CWES:
        cwe = f'CWE-{number}'
        subset = [r for r in manifest if r['cwe'] == cwe]
        eligible = [r for r in repairs if r['cwe'] == cwe and r['reviewed']
                    and assignments[repository_id(r['repository_id'])] == 'rag']
        coverage.append({'cwe': cwe, 'csv_rows': len(subset),
                         'splits': {s: sum(r['split'] == s for r in subset) for s in counts},
                         'reviewed_rag_repairs': len(eligible),
                         'has_dev_rows': any(r['split'] == 'dev' and r['vcc'] for r in subset),
                         'has_test_rows': any(r['split'] == 'test' and r['vcc'] for r in subset),
                         'status': 'missing_csv_examples' if not subset else
                         'needs_rag_review' if not eligible else 'needs_runtime_validation'})
    report = {'seed': seed, 'group_counts': counts, 'coverage': coverage,
              'policy': 'Disjoint repositories, CVEs, commit IDs and exact repair snippets',
              'assignment': 'Reserve reviewed RAG coverage, prioritize held-out CWE coverage, then 60/20/20 targets',
              'limitations': ['No historical runtime validation', 'Near-duplicate code not detected',
                              'Test references are evaluator-only; never pass them to the model'],
              'input_sha256': {name: hashlib.sha256((source / name).read_bytes()).hexdigest()
                               for name in ['vcc_index.json', 'candidates.jsonl']}}
    write_json(output / 'coverage.json', report)
    return report


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Split CSV repairs without repository leakage')
    parser.add_argument('--source', required=True)
    parser.add_argument('--output', required=True)
    parser.add_argument('--seed', default='vcc-2026')
    args = parser.parse_args()
    print(json.dumps(split_corpus(args.source, args.output, args.seed), indent=2))

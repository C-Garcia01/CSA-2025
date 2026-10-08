"""Generate a repair directly from vulnerable source and retrieved examples."""
import hashlib
import json
import logging
from pathlib import Path

from repair_agent import DEFAULT_PROVIDER, RepairAgent, resolve_model
from repair_auto import DEFAULT_CORPUS, save
from repair_context import RepairContext, make_prompt
from repair_workspace import RepairWorkspace, checked_path, git_command


def run_direct(target, output, *, repository, case, provider=DEFAULT_PROVIDER,
               model=None, corpus=None):
    output = Path(output).resolve()
    output.mkdir(parents=True, exist_ok=False)
    model = resolve_model(provider, model)
    report = {'status': 'inconclusive', 'input_vcc': target, 'provider': provider,
              'model': model, 'cwe': f"CWE-{case['cwe']}",
              'repository': 'nist/juliet-java-1.3', 'review_status': 'not_reviewed',
              'validation_scope': 'Generated repair; behavioral validation not run',
              'generation': 'direct_rag_repair', 'fixed_commit': ''}
    rows = []
    try:
        workspace = RepairWorkspace(output / 'repository')
        workspace.prepare(str(repository), target)
        editable = [f['repository_path'] for f in case['input_metadata']['files']]
        support = [p for p in workspace.tracked_files()
                   if p.startswith('src/testcasesupport/') and p.endswith('.java')]
        config = {'revision': target, 'cwe': report['cwe'],
                  'repository_id': report['repository'], 'group': case['id'],
                  'editable_files': editable, 'context_files': editable + support,
                  'flow': {'mechanism': case['id'],
                           'required_behavior': 'Fix the unsafe bad entry point while preserving legitimate functionality.'},
                  'corpus': str(Path(corpus or DEFAULT_CORPUS).resolve()),
                  'top_k': 2, 'context_limit': 180000}
        bundle = RepairContext(config, workspace.root).build()
        save(output / 'context.json', bundle)
        report['retrieved_examples'] = [r['id'] for r in bundle['repair_examples']]
        report['corpus_sha256'] = hashlib.sha256(Path(config['corpus']).read_bytes()).hexdigest()
        prompt = make_prompt(bundle)
        report['prompt_characters'] = len(prompt)
        logging.info('%s: direct repair, %s RAG examples, %s prompt characters',
                     report['cwe'], len(report['retrieved_examples']), len(prompt))
        before = {name: checked_path(workspace.root, name).read_bytes() for name in editable}
        proposal = RepairAgent(provider, model).generate(prompt, output / 'agent', 600)
        save(output / 'proposal.json', proposal)
        patch = workspace.apply(proposal, editable)
        if not patch.strip():
            raise ValueError('Proposal made no changes')
        (output / 'repair.patch').write_text(patch, encoding='utf-8')
        git_command(workspace.root, 'add', '--', *editable)
        git_command(workspace.root, '-c', 'user.name=Repair Pipeline',
                    '-c', 'user.email=repair@localhost', 'commit', '-qm',
                    'Generate RAG-assisted repair (not behaviorally validated)')
        fixed = git_command(workspace.root, 'rev-parse', 'HEAD')
        git_command(workspace.root, 'bundle', 'create', str(output / 'history.bundle'), 'HEAD')
        for name in editable:
            after = checked_path(workspace.root, name).read_bytes()
            if before[name] != after:
                rows.append({**report, 'status': 'generated_unvalidated', 'fixed_commit': fixed,
                             'path': name, 'before': before[name].decode('utf-8'),
                             'after': after.decode('utf-8'),
                             'before_sha256': hashlib.sha256(before[name]).hexdigest(),
                             'after_sha256': hashlib.sha256(after).hexdigest()})
        report.update(status='generated_unvalidated', fixed_commit=fixed,
                      summary=proposal['summary'])
    except (OSError, RuntimeError, ValueError, KeyError, TypeError) as error:
        report['reason'] = str(error)
        rows = []
    finally:
        report['exported_files'] = len(rows)
        (output / 'pairs.jsonl').write_text(''.join(json.dumps(r) + '\n' for r in rows), encoding='utf-8')
        save(output / 'result.json', report)
    return report

"""Build ten pinned Juliet bad-only scenarios; never include supplied good methods."""
import argparse
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import zipfile

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / 'src'))
from import_juliet import method, sha, write_json
from repair_context import RepairContext, make_prompt

SELECT = {
15: 'CWE15_External_Control_of_System_or_Configuration_Setting__getParameter_Servlet_01',
78: 'CWE78_OS_Command_Injection__getParameter_Servlet_01',
80: 'CWE80_XSS__Servlet_getParameter_Servlet_01',
81: 'CWE81_XSS_Error_Message__Servlet_getParameter_Servlet_01',
83: 'CWE83_XSS_Attribute__Servlet_getParameter_Servlet_01',
89: 'CWE89_SQL_Injection__getParameter_Servlet_executeQuery_01',
113: 'CWE113_HTTP_Response_Splitting__getParameter_Servlet_addHeaderServlet_01',
129: 'CWE129_Improper_Validation_of_Array_Index__getParameter_Servlet_array_read_no_check_01',
134: 'CWE134_Uncontrolled_Format_String__console_readLine_printf_01',
606: 'CWE606_Unchecked_Loop_Condition__getParameter_Servlet_01',
}
BEHAVIOR = {
15: 'Allow selection of public and reporting catalogs only; reject every other catalog without selecting it. Catalog sink is simulated.',
78: 'List a caller-supplied filesystem path on Linux, including spaces, without interpreting the path as command options. Tests expose process exit status. No shell-injection claim.',
80: 'Preserve user text in HTML body output using HTML entity encoding for ampersand, both quotes, less-than and greater-than.',
81: 'Preserve user text in error-message output using HTML entity encoding for ampersand, both quotes, less-than and greater-than. Check is at sendError sink, not a real container/browser.',
83: 'Preserve image filename in quoted HTML attribute, encoding ampersand, both quotes, less-than and greater-than. Scope is attribute breakout, not URL policy.',
89: 'Query users by exact supplied name including apostrophes, without allowing SQL structure manipulation. Harness executes queries in H2.',
113: 'Preserve ordinary Location header language values. Reject any value containing CR or LF before setting a header. Check is at servlet sink.',
129: 'Preserve valid indices 0 through 4 and prevent out-of-bounds access for every other integer.',
134: 'Print supplied console text literally, including percent signs and format directives.',
606: 'Preserve requested loop counts in inclusive range 0..100. Reject counts outside that range without running the loop.',
}


def git(repo, *args):
    return subprocess.check_output(['git', '-c', 'core.hooksPath=/dev/null', '-C', str(repo), *args], text=True).strip()


def setup(archive, output, java_home, h2, generate=False):
    output = Path(output).resolve()
    work = output / 'work'
    work.mkdir(parents=True, exist_ok=False)
    libs = output / 'dependencies'
    libs.mkdir(exist_ok=True)
    with zipfile.ZipFile(archive) as z:
        (libs / 'servlet-api.jar').write_bytes(z.read('Java/lib/servlet-api.jar'))
        shutil.copyfile(h2, libs / 'h2.jar')
        libraries = os.pathsep.join(str(libs / n) for n in ['servlet-api.jar', 'h2.jar'])
        manifest = []
        for cwe, name in SELECT.items():
            case = work / str(cwe)
            repo = case / 'repository'
            repo.mkdir(parents=True)
            source = next(n for n in z.namelist() if n.endswith('/' + name + '.java') and '/antbuild/' not in n)
            raw = z.read(source)
            text = raw.decode().replace('\r\n', '\n')
            bad = method(text, 'bad')
            if cwe == 78:
                bad = bad.replace('process.waitFor();', 'IO.writeLine(process.waitFor());')
            package = re.search(r'^package (.*);', text, re.M)[1]
            imports = '\n'.join(re.findall(r'^import .*;', text, re.M))
            # Remove class inheritance, good methods, main and explanatory solution labels.
            target = f'package {package};\n{imports}\n\npublic class {name}\n{{\n{bad}\n}}\n'
            rel = 'src/' + package.replace('.', '/') + '/' + name + '.java'
            path = repo / rel
            path.parent.mkdir(parents=True)
            path.write_text(target)
            support = repo / 'src/testcasesupport'
            support.mkdir(parents=True, exist_ok=True)
            io = z.read('Java/src/testcasesupport/IO.java').decode().replace('\r\n', '\n')
            io = io.replace('return DriverManager.getConnection(dbUrl, dbUsername, dbPassword);', 'return ProbeDB.connect();')
            (support / 'IO.java').write_text(io)
            shutil.copyfile(Path(__file__).with_name('ProbeDB.java'), support / 'ProbeDB.java')
            shutil.copyfile(Path(__file__).with_name('Probe.java'), repo / 'src/Probe.java')
            shutil.copyfile(Path(__file__).with_name('check.py'), repo / 'check.py')
            write_json(repo / 'harness.json', {'cwe': cwe, 'class': package + '.' + name,
                'java': str(Path(java_home).resolve() / 'bin/java'), 'javac': str(Path(java_home).resolve() / 'bin/javac'),
                'libraries': libraries, 'classpath': 'classes' + os.pathsep + libraries})
            (repo / '.gitignore').write_text('classes/\nfixture.txt\nfile with spaces.txt\n')
            git(repo, 'init', '-q')
            git(repo, 'add', '.')
            git(repo, '-c', 'user.name=Juliet Dataset', '-c', 'user.email=juliet@localhost', 'commit', '-qm', 'Import synthetic vulnerable Juliet entry point and protected probes')
            revision = git(repo, 'rev-parse', 'HEAD')
            protected = [str(p.relative_to(repo)) for p in repo.rglob('*') if p.is_file() and '.git' not in p.parts and str(p.relative_to(repo)) != rel]
            config = {'id': name, 'repository': str(repo), 'repository_id': 'nist/juliet-java-1.3',
                'revision': revision, 'cwe': 'CWE-' + str(cwe), 'group': name.rsplit('_', 1)[0],
                'flow': {'source': 'Console input' if cwe == 134 else 'HTTP name parameter', 'required_behavior': BEHAVIOR[cwe]},
                'context_files': [rel], 'editable_files': [rel], 'protected_files': sorted(protected),
                'build_command': [sys.executable, 'check.py', 'build'],
                'test_command': [sys.executable, 'check.py', 'functional'],
                'security_command': [sys.executable, 'check.py', 'security'],
                'corpus': str(ROOT / 'data/splits/rag/repairs.jsonl'),
                'timeout': 60, 'agent_timeout': 300, 'max_attempts': 2, 'top_k': 3, 'context_limit': 60000,
                'environment': {'kind': 'juliet_adapted_bad_only', 'original_source': source, 'original_sha256': sha(raw),
                    'adaptations': ['LF normalization', 'bad method only in standalone class', 'protected IO database adapter'] + (['Expose process exit code through IO.writeLine'] if cwe == 78 else []),
                    'java_home': str(java_home), 'dependencies_sha256': {p.name: sha(p.read_bytes()) for p in libs.iterdir()},
                    'validation_scope': BEHAVIOR[cwe]}}
            write_json(case / 'scenario.json', config)
            bundle = RepairContext(config, repo).build()
            write_json(case / 'context.json', bundle)
            (case / 'prompt.txt').write_text(make_prompt(bundle))
            entry = {'id': str(cwe), 'scenario': str(case / 'scenario.json')}
            if not generate:
                proposal = json.loads(Path(__file__).with_name('proposals.json').read_text())[str(cwe)]
                write_json(case / 'proposal.json', proposal)
                entry['proposal'] = str(case / 'proposal.json')
            manifest.append(entry)
        write_json(output / 'manifest.json', {'cases': manifest})
    return manifest


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('archive')
    parser.add_argument('--output', required=True)
    parser.add_argument('--java-home', required=True)
    parser.add_argument('--h2', required=True)
    parser.add_argument('--generate', action='store_true', help='Generate fresh proposals through repair_batch instead of replaying saved assistant proposals')
    args = parser.parse_args()
    setup(args.archive, args.output, args.java_home, args.h2, args.generate)

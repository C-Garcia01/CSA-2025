"""Protected, bounded behavioral probes. Only explicit observations emit markers."""
import json
import subprocess
import sys
from pathlib import Path

config = json.loads(Path('harness.json').read_text())
cwe = config['cwe']


def invoke(value):
    result = subprocess.run([config['java'], '-cp', config['classpath'], 'Probe', config['class'], value],
                            text=True, capture_output=True, timeout=10)
    if result.returncode:
        raise RuntimeError(result.stdout + result.stderr)
    print(json.dumps({'input': value, 'stdout': result.stdout, 'stderr': result.stderr}))
    if result.stderr:
        raise RuntimeError('Unexpected Java diagnostics')
    return result.stdout


def functional():
    if cwe == 15:
        return all('CATALOG:' + x in invoke(x) for x in ['public', 'reporting'])
    if cwe == 78:
        Path('fixture.txt').write_text('fixture')
        return all(invoke(x).strip() == '00' for x in ['.', 'fixture.txt'])
    if cwe in (80, 81, 83):
        return all(x in invoke(x) for x in ['Alice', 'image.png'])
    if cwe == 89:
        return all('ROWS:[' + x + ']' in invoke(x) for x in ['Alice', 'Bob'])
    if cwe == 113:
        return all('HEADER:Location:/author.jsp?lang=' + x in invoke(x) for x in ['en', 'fr'])
    if cwe == 129:
        return all(invoke(str(x)).strip() == '%02d' % x for x in [0, 2, 4])
    if cwe == 134:
        return all(invoke(x) == x for x in ['hello', 'hello world'])
    if cwe == 606:
        return all(invoke(str(x)).count('hello world') == x for x in [0, 1, 5])
    raise ValueError(cwe)


def security():
    if cwe == 15:
        return all('CATALOG:' not in invoke(x) for x in ['admin', '../private', 'PUBLIC'])
    if cwe == 78:
        # Runtime.exec(String) permits injected ls options, not shell syntax on Linux.
        attacks = all(invoke(x).strip() != '00' for x in ['--version', '--help'])
        Path('file with spaces.txt').write_text('fixture')
        return invoke('file with spaces.txt').strip() == '00' and attacks
    if cwe in (80, 81, 83):
        # Assert encoded data at the servlet sink. No browser/container claim.
        for value in ['<script>alert(1)</script>', '\"><img src=x onerror=alert(1)>', "'&<>"]:
            out = invoke(value)
            encoded = value.replace('&', '&amp;').replace('<', '&lt;').replace('>', '&gt;').replace('"', '&quot;').replace("'", '&#39;')
            if encoded not in out or value in out:
                return False
        return True
    if cwe == 89:
        return all('ROWS:[]' in invoke(x) for x in ["missing' OR '1'='1", "missing' UNION SELECT name FROM users --"]) and "ROWS:[O'Brien]" in invoke("O'Brien")
    if cwe == 113:
        return all('HEADER:' not in invoke(x) for x in ['en\r\nX-Injected: yes', 'en\rfoo', 'en\nfoo'])
    if cwe == 129:
        return all('OBSERVED_WEAKNESS:' not in invoke(x) for x in ['-1', '5', '2147483647', '-2147483648'])
    if cwe == 134:
        return all(invoke(x) == x for x in ['%s%s', '%n', '%1$08x', '100%'])
    if cwe == 606:
        return all(invoke(str(x)).count('hello world') == 0 for x in [-1, 101, 200]) and invoke('100').count('hello world') == 100
    raise ValueError(cwe)


if sys.argv[1] == 'build':
    Path('classes').mkdir(exist_ok=True)
    result = subprocess.run([config['javac'], '-encoding', 'UTF-8', '-cp', config['libraries'], '-d', 'classes', *[str(p) for p in sorted(Path('src').rglob('*.java'))]])
    sys.exit(result.returncode)
try:
    passed = functional() if sys.argv[1] == 'functional' else security()
except Exception as error:
    print('PROBE_SETUP_ERROR:', error)
    sys.exit(2)
if sys.argv[1] == 'security':
    print('VCC_SECURITY_PASS' if passed else 'VCC_SECURITY_FAIL')
sys.exit(0 if passed else 1)

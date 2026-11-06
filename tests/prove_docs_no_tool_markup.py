#!/usr/bin/env python3
"""No tracked document or workflow may carry an authoring tool's call markup.

WHY THIS EXISTS
    Every sheet in docs/security-review/ (23 files, commit 4a181ff) ended with two stray lines,
    `</content>` and `</invoke>`, and two of them also carried a whole shell command wrapped in
    `<invoke name="Bash">` / `<parameter name="command">`. They were left by the tool that wrote the
    files, not by a person. Every check was green: the markup is not a secret, not a state word and
    not a broken link, so nothing looked for it. The same thing happened again on the next lane's new
    files before anyone noticed (fixed on the trunk in 9b3c66e and on the CAB change-review lane).

    A reviewer printing the checklist gets the fragments on paper. A document that carries a pasted
    shell command looks like an instruction. And a workflow file carrying them may still parse while
    holding text nobody meant to ship.

WHAT THIS CHECKS
    Every file git tracks with a .md, .yml or .yaml extension, for any of these fragments:
        </invoke>    <invoke name=    <parameter name=    </parameter>
        a line that is only </content>
        the authoring namespace prefix (built below so this file does not carry it)
    This file itself is .py and is not scanned; it names the fragments in prose only.

    --self-test seeds a clean file and one mutant per fragment in a temporary git repository and
    requires the clean one to pass and every mutant to be named.

EXIT
    0  no tracked .md / .yml / .yaml file carries a fragment
    1  a fragment was found (each file and line is named)
    2  could not check (git unavailable, not a work tree) -- UNKNOWN, never PASS
"""
import io
import os
import re
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
EXTS = ('.md', '.yml', '.yaml')
NS = 'ant' + 'ml:'          # built, so this file never matches its own pattern
PATTERNS = [
    ('closing invoke tag', re.compile(r'</invoke>')),
    ('opening invoke tag', re.compile(r'<invoke name=')),
    ('parameter tag', re.compile(r'<parameter name=|</parameter>')),
    ('lone closing content tag', re.compile(r'^\s*</content>\s*$')),
    ('authoring namespace prefix', re.compile(re.escape('<' + NS) + '|' + re.escape('</' + NS))),
]


def tracked(root):
    p = subprocess.run(['git', 'ls-files', '-z'], cwd=root, capture_output=True)
    if p.returncode != 0:
        return None
    return [f for f in p.stdout.decode('utf-8', 'replace').split('\0') if f.endswith(EXTS)]


def scan(root):
    files = tracked(root)
    if files is None:
        return None
    hits = []
    for f in files:
        try:
            text = io.open(os.path.join(root, f), encoding='utf-8', errors='replace').read()
        except OSError:
            continue        # a tracked file deleted in the work tree is git's question, not this one
        for n, line in enumerate(text.splitlines(), 1):
            for name, rx in PATTERNS:
                if rx.search(line):
                    hits.append((f, n, name))
    return hits


def self_test():
    seeds = {
        'invoke-close.md': 'text\n</invoke>\n',
        'invoke-open.md': '<invoke name="Bash">\n',
        'parameter.yml': 'a: 1\n<parameter name="command">ls\n',
        'content.md': 'end of sheet\n</content>\n',
        'namespace.yaml': 'x: <' + NS + 'invoke>\n',
    }
    clean = {'clean.md': '# A sheet\n\nIt mentions content and parameters in prose, and `<role>`.\n'}
    with tempfile.TemporaryDirectory() as d:
        if subprocess.run(['git', 'init', '-q', d], capture_output=True).returncode != 0:
            print('UNKNOWN: git init failed')
            return 2
        for name, body in list(seeds.items()) + list(clean.items()):
            io.open(os.path.join(d, name), 'w', encoding='utf-8', newline='\n').write(body)
        subprocess.run(['git', 'add', '-A'], cwd=d, capture_output=True)
        hits = scan(d)
    if hits is None:
        print('UNKNOWN: git ls-files failed in the seeded repository')
        return 2
    named = {h[0] for h in hits}
    missed = sorted(set(seeds) - named)
    false = sorted(named & set(clean))
    for m in missed:
        print('SELF-TEST FAIL: mutant not caught: %s' % m)
    for f in false:
        print('SELF-TEST FAIL: clean file flagged: %s' % f)
    if missed or false:
        return 1
    print('SELF-TEST PASS: %d mutants caught, the clean file passed' % len(seeds))
    return 0


def main(argv):
    if '--self-test' in argv:
        return self_test()
    hits = scan(ROOT)
    if hits is None:
        print('UNKNOWN: git ls-files failed; nothing was checked')
        return 2
    if hits:
        for f, n, name in hits:
            print('MARKUP %s:%d  %s' % (f, n, name))
        print('FAIL: %d line(s) of authoring-tool markup in tracked documents or workflows' % len(hits))
        return 1
    print('PASS: no tracked .md / .yml / .yaml file carries authoring-tool markup')
    return 0


if __name__ == '__main__':
    sys.exit(main(sys.argv[1:]))

#!/usr/bin/env python3
"""A bundled script may import only what the bundle carries (completion ledger L61).

WHY THIS EXISTS

    The kit-scripts bundle is written to /tmp by one bootstrap job and is ALL a consumer's scanner
    jobs have: no checkout of the kit, no scripts/ directory, only the runner's Python. A bundled
    script that imports a kit module the bundle does not ship -- or a third-party package -- fails
    at consumer runtime and nowhere else, because every local proof imports from scripts/, where the
    module sits beside it. That is C1's exact shape (scan_report imported two identity modules the
    bundle never shipped). The closure held only by coincidence and `inline_normalizer.py --check`
    did not look.

WHAT IT PROVES (a copy of scripts/ and .github/ in a temp directory; the real tree is never touched)
    C1  a bundled script given `import finding_identity` (a kit module NOT in the bundle), with the
        workflow regenerated so nothing else drifts: --check FAILS and names the import closure
    C2  the same with a third-party import (`import yaml`) inside a function: --check FAILS
    C3  CONTROL: the same script given a standard-library import (`import tempfile`) inside a
        function, regenerated: --check PASSES

EXIT  0 all hold   1 any does not   2 could not be checked
"""
import io
import os
import shutil
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
TARGET = 'sarif_validity.py'


def copy_tree(dst):
    shutil.copytree(os.path.join(ROOT, 'scripts'), os.path.join(dst, 'scripts'),
                    ignore=shutil.ignore_patterns('__pycache__'))
    shutil.copytree(os.path.join(ROOT, '.github'), os.path.join(dst, '.github'))


def normalizer(root, *args):
    p = subprocess.run([sys.executable, os.path.join(root, 'scripts', 'inline_normalizer.py')]
                       + list(args), cwd=root, capture_output=True, text=True, encoding='utf-8',
                       errors='replace')
    return p.returncode, p.stdout + p.stderr


def seed(root, text_after_imports):
    p = os.path.join(root, 'scripts', TARGET)
    src = io.open(p, encoding='utf-8').read()
    marker = 'import sys\n'
    assert marker in src, 'the seed anchor moved; update the proof'
    src = src.replace(marker, marker + text_after_imports, 1)
    io.open(p, 'w', encoding='utf-8', newline='\n').write(src)


def main():
    work = tempfile.mkdtemp(prefix='bundle-closure-')
    bad = []
    try:
        cases = [
            ('C1 kit module not in the bundle', 'import finding_identity  # noqa: F401\n', 1),
            ('C2 third-party, inside a function',
             'def _seeded():\n    import yaml  # noqa: F401\n    return yaml\n', 1),
            ('C3 CONTROL stdlib, inside a function',
             'def _seeded():\n    import tempfile  # noqa: F401\n    return tempfile\n', 0),
        ]
        for label, text, want in cases:
            root = os.path.join(work, label.split()[0])
            copy_tree(root)
            seed(root, text)
            rc, out = normalizer(root)               # regenerate: nothing else may drift
            if rc != 0:
                bad.append('%s: could not regenerate (%s)' % (label, out[-300:]))
                continue
            rc, out = normalizer(root, '--check')
            named = 'import closure' in out
            ok = rc == want and (named if want else True)
            print('  %-40s --check rc=%s closure-named=%s %s'
                  % (label, rc, named, 'ok' if ok else 'WRONG'))
            if not ok:
                bad.append('%s: --check rc=%s (want %s); output tail: %s'
                           % (label, rc, want, out[-400:]))
    finally:
        shutil.rmtree(work, ignore_errors=True)
    for b in bad:
        print(('FAIL ' + b).encode('ascii', 'replace').decode('ascii'))
    if bad:
        return 1
    print('PASS: a bundled script importing a kit module outside the bundle, or a third-party')
    print('      package, fails --check by name; a standard-library import does not.')
    return 0


if __name__ == '__main__':
    sys.exit(main())

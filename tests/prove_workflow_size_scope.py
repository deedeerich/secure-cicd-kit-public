#!/usr/bin/env python3
"""The size gate measures every file GitHub loads, in the bytes GitHub reads (completion ledger L66).

WHY THIS EXISTS

    tests/check_workflow_size.py exists because a workflow over GitHub's size limit does not fail --
    it never starts. Its scope was `.github/workflows/*.yml`, so the decomposition moved bytes out
    of the one measured file into composites nobody measured (resolve is ~100 KB), and the overlay
    workflows were never read. Its unit was on-disk bytes, so a Windows checkout (CRLF) measured
    every file one byte per line fatter than the blob GitHub reads.

WHAT IT PROVES (constructed trees; the checker run as a subprocess with --root, from that root)
    S1  a composite action over the fail threshold fails the gate, by name
    S2  an overlay workflow over the fail threshold fails the gate, by name
    S3  a workflow whose LF bytes are under the threshold and whose CRLF bytes are over it PASSES:
        the size is the one GitHub reads
    S4  a workflow whose LF bytes are over the threshold fails, however it is checked out
    S5  CONTROL: a small tree passes

EXIT  0 all hold   1 any does not   2 could not be checked
"""
import os
import shutil
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
CHECK = os.path.join(HERE, 'check_workflow_size.py')
FAIL_AT = 486400
SMALL = b'name: x\non: [push]\njobs: {}\n'


def padded(n_bytes, eol=b'\n'):
    """A YAML file of about `n_bytes` LF bytes, written with `eol` line endings."""
    line = b'# ' + b'x' * 17          # short lines, so CRLF adds ~5%
    n_lines = n_bytes // (len(line) + 1) + 1
    return SMALL.replace(b'\n', eol) + (line + eol) * n_lines


def build(work, name, files):
    root = os.path.join(work, name)
    for rel, data in files.items():
        p = os.path.join(root, rel)
        os.makedirs(os.path.dirname(p), exist_ok=True)
        with open(p, 'wb') as fh:
            fh.write(data)
    return root


def run(root):
    p = subprocess.run([sys.executable, CHECK, '--root', root], cwd=root, capture_output=True,
                       text=True, encoding='utf-8', errors='replace')
    return p.returncode, p.stdout + p.stderr


def main():
    work = tempfile.mkdtemp(prefix='size-scope-')
    bad = []
    try:
        wf = '.github/workflows/ci.yml'
        crlf = padded(FAIL_AT - 10000, b'\r\n')
        assert len(crlf) > FAIL_AT > len(crlf.replace(b'\r\n', b'\n'))
        cases = [
            ('S1 composite over the threshold', {wf: SMALL,
                                                 '.github/actions/big/action.yml': padded(FAIL_AT + 4000)},
             1, 'big/action.yml'),
            ('S2 overlay workflow over the threshold', {wf: SMALL,
                                                        'overlays/x/workflows/o.yml': padded(FAIL_AT + 4000)},
             1, 'overlays/x/workflows/o.yml'),
            ('S3 CRLF over, LF under: passes', {wf: crlf}, 0, None),
            ('S4 LF over the threshold', {wf: padded(FAIL_AT + 4000, b'\r\n')}, 1, 'ci.yml'),
            ('S5 CONTROL small tree', {wf: SMALL, '.github/actions/a/action.yml': SMALL}, 0, None),
        ]
        for label, files, want, named in cases:
            rc, out = run(build(work, label.split()[0], files))
            ok = rc == want and (named is None or named in out.replace('\\', '/'))
            print('  %-42s rc=%s %s' % (label, rc, 'ok' if ok else 'WRONG'))
            if not ok:
                bad.append('%s: rc=%s (want %s)%s\n%s' % (label, rc, want,
                           ', not named' if named and named not in out else '', out[-600:]))
    finally:
        shutil.rmtree(work, ignore_errors=True)
    for b in bad:
        print('FAIL ' + b.encode('ascii', 'replace').decode())
    if bad:
        return 1
    print('PASS: composites and overlay workflows are measured, and in the LF bytes GitHub reads.')
    return 0


if __name__ == '__main__':
    sys.exit(main())

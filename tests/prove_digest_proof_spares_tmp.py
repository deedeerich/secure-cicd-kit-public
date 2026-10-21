#!/usr/bin/env python3
"""Prove that the bundle-digest proof leaves the shell's /tmp exactly as it found it.

WHY THIS EXISTS

    `prove_kit_script_digests.py` runs the bootstrap step verbatim in the shell's REAL /tmp. It
    stashes anything already occupying the names it writes, and puts it back afterwards. Then, on
    its way out, it called `shutil.rmtree(tmp)` on that same /tmp.

    On a runner, /tmp is shared with every other step in the job. Under MSYS on Windows, /tmp is the
    operator's whole user Temp folder. A proof that its subject is harmless deleted everything
    beside it that it never wrote. The stash-and-restore above that line was correct, and the line
    undid it.

    A test must never destroy what it did not create. That is the rule this proves, by running the
    real `main()` against a sandbox that stands in for /tmp and holds a file the proof never wrote.

HOW IT STAYS SAFE

    `tmpdir_of`, `shutil.which` and `subprocess.run` are replaced, so no shell runs and the real
    /tmp is never resolved. The stand-in shell writes what the bootstrap step would write. If the
    fix regresses, the only thing deleted is this test's own sandbox.

WHAT IT CANNOT ESTABLISH
    That the bootstrap step itself writes nothing else into /tmp. The step is the subject of the
    digest proof, not of this one.

EXIT
    0  a file the proof did not write survives the proof
    1  the proof deleted, or failed to restore, something it did not create
    2  could not be checked -- reported as UNKNOWN, never as PASS
"""
import io
import os
import shutil
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, HERE)
sys.path.insert(0, os.path.join(ROOT, 'scripts'))


def main():
    try:
        import yaml  # noqa: F401 -- the proof under test needs it
        import inline_normalizer as gen
        import prove_kit_script_digests as proof
    except ImportError as e:
        print('UNKNOWN: could not import the proof under test (%s).' % e)
        return 2

    work = tempfile.mkdtemp(prefix='digest-proof-sandbox-')
    try:
        fake_tmp = os.path.join(work, 'tmp')
        os.makedirs(fake_tmp)
        # Two things the proof must leave alone: a file it never names, and a file occupying a name
        # it DOES write, which it must stash and put back byte for byte.
        bystander = os.path.join(fake_tmp, 'not-written-by-the-proof.txt')
        io.open(bystander, 'w', encoding='utf-8').write('unrelated\n')
        occupied_name = os.path.basename(gen.SCRIPTS[0][3])
        occupied = os.path.join(fake_tmp, occupied_name)
        io.open(occupied, 'wb').write(b'pre-existing bytes\n')

        def fake_run(cmd, *a, **k):
            # Stand in for the bootstrap shell: write what it writes, where the proof reads it.
            for canon, _t, _g, dest in gen.SCRIPTS:
                io.open(os.path.join(fake_tmp, os.path.basename(dest)), 'wb').write(
                    gen.materialised(canon))
            io.open(os.path.join(fake_tmp, 'kit-scripts.sha256'), 'w', encoding='utf-8',
                    newline='').write(gen.manifest_body())
            return subprocess.CompletedProcess(cmd, 0, stdout='', stderr='')

        saved = (proof.tmpdir_of, proof.shutil.which, proof.subprocess.run, tempfile.tempdir)
        proof.tmpdir_of = lambda bash: fake_tmp
        proof.shutil.which = lambda name: '/stand-in/' + name
        proof.subprocess.run = fake_run
        tempfile.tempdir = work  # the proof's own stash lands in the sandbox too
        try:
            rc = proof.main()
        finally:
            (proof.tmpdir_of, proof.shutil.which, proof.subprocess.run,
             tempfile.tempdir) = saved

        print('')
        print('  proof exit code                      : %s' % rc)
        failures = []
        if not os.path.isdir(fake_tmp):
            failures.append('the stand-in /tmp itself was deleted')
        elif not os.path.exists(bystander):
            failures.append('a file the proof never wrote was deleted')
        if os.path.isdir(fake_tmp):
            got = io.open(occupied, 'rb').read() if os.path.exists(occupied) else None
            if got != b'pre-existing bytes\n':
                failures.append('a pre-existing %s was not restored byte for byte'
                                % occupied_name)
            left = sorted(set(os.listdir(fake_tmp))
                          - {'not-written-by-the-proof.txt', occupied_name})
            if left:
                failures.append('the proof left its own files behind: %s' % ', '.join(left))
        for f in failures:
            print('FAIL: %s.' % f)
        if failures:
            return 1
        print('PASS: the digest proof restored /tmp exactly: the bystander survived and the')
        print('      occupied name holds its original bytes.')
        return 0
    finally:
        shutil.rmtree(work, ignore_errors=True)


if __name__ == '__main__':
    sys.exit(main())

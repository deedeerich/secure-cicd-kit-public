#!/usr/bin/env python3
"""Run the bootstrap job's own shell and prove the pinned digest is the digest it produces.

WHY A PROOF AND NOT A CALCULATION

    `scripts/inline_normalizer.py` pins one sha256 into fourteen download sites. That value is
    DERIVED: the generator right-strips every emitted line, YAML strips the block scalar's common
    indent, and bash's heredoc writes whatever survives. Three transformations between a file in
    `scripts/` and the bytes a scanner executes.

    A digest computed by re-implementing those three transformations is a SECOND implementation of
    them. If it is wrong, it is wrong in both places at once and agrees with itself perfectly --
    and the first anyone hears of it is `sha256sum: WARNING: 1 computed checksum did NOT match`
    on a live dispatch, in fourteen jobs, with the bootstrap job already green.

    So this does not recompute anything. It takes the workflow AS SHIPPED, extracts the two steps
    the bootstrap job actually runs, RUNS THEM, and compares the manifest bash wrote against the
    value pinned at the call sites. The same shape as the kit's own founding rule: a parseable
    file is not a runnable file, and a derived constant is not a verified one.

WHAT IT CANNOT ESTABLISH
    That the artifact reaches a consuming job, or that the download is not tampered with in
    transit. It establishes that the pin and the producer agree, which is the half that can be
    settled without a runner.

EXIT
    0  the shell wrote exactly what the workflow pins
    1  drift between what is written and what is pinned
    2  could not be checked -- reported as UNKNOWN, never as PASS
"""
import io
import os
import re
import shutil
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, os.path.join(ROOT, 'scripts'))

WF = os.path.join(ROOT, '.github', 'workflows', 'reusable-security.yml')
# Spelled here rather than imported from the generator's module constants. An all-caps
# underscored Python identifier reads as controlled vocabulary to scripts/reconcile_taxonomy.py,
# and these are a job name, a step name and a region marker -- nothing branches on them.
BOOTSTRAP = 'kit-scripts'
FETCH_MARKER = 'FETCH_KIT_SCRIPTS'
WRITE_STEP = 'Write the canonical scripts'
PIN_STEP = 'Pin what was written, and assert it is what this file promises'


def tmpdir_of(bash):
    """The shell's own /tmp, as a path THIS process can open.

    On a runner they are the same string. Under MSYS on Windows `/tmp` is a mount point the
    Python process cannot see by that name, and silently writing somewhere else would make the
    comparison meaningless rather than wrong-looking.
    """
    for cmd in ('cd /tmp && pwd -W', 'cd /tmp && pwd'):
        try:
            r = subprocess.run([bash, '-c', cmd], capture_output=True, text=True)
        except OSError:
            return None
        cand = (r.stdout or '').strip()
        if r.returncode == 0 and cand and os.path.isdir(cand):
            return cand
    return None


def step_run(doc, job, name):
    for s in (doc['jobs'][job].get('steps') or []):
        if s.get('name') == name:
            return s.get('run')
    return None


def main():
    try:
        import yaml
    except ImportError:
        print('UNKNOWN: PyYAML unavailable. Failure to observe is not an observation.')
        return 2
    bash = shutil.which('bash')
    sha = shutil.which('sha256sum')
    if not bash or not sha:
        print('UNKNOWN: bash and sha256sum are required to RUN the step; found bash=%r '
              'sha256sum=%r. A check that could not execute is not a pass.' % (bash, sha))
        return 2

    import inline_normalizer as gen

    doc = yaml.safe_load(io.open(WF, encoding='utf-8'))
    write = step_run(doc, BOOTSTRAP, WRITE_STEP)
    pin = step_run(doc, BOOTSTRAP, PIN_STEP)
    if not write or not pin:
        print('UNKNOWN: could not find both steps in %s (write=%s pin=%s).'
              % (BOOTSTRAP, bool(write), bool(pin)))
        print('A check with nothing to run is not a pass.')
        return 2

    # THE SHELL IS RUN VERBATIM, IN THE REAL /tmp. The first version of this rewrote `/tmp/` to a
    # sandbox, which also rewrote the string `/tmp/redact_all.sh` INSIDE one of the scripts being
    # written -- so the harness manufactured a mismatch and reported drift that did not exist. A
    # proof that edits its subject is testing its edit. So: move aside anything already occupying
    # those names, run the step exactly as shipped, compare, put everything back.
    ok = True
    tmp = tmpdir_of(bash)
    if tmp is None:
        print('UNKNOWN: could not resolve the shell\'s /tmp to a path this process can read.')
        return 2
    names = [os.path.basename(d) for _c, _t, _g, d in gen.SCRIPTS] + ['kit-scripts.sha256']
    stash = tempfile.mkdtemp(prefix='kitscripts-stash-')
    for n in names:
        p_ = os.path.join(tmp, n)
        if os.path.exists(p_):
            shutil.move(p_, os.path.join(stash, n))
    try:
        # WRITTEN TO A FILE, NOT PASSED WITH -c. The bootstrap step is ~300 KB of heredoc;
        # Windows caps a command line at 32 KB and refuses the process outright. A check that
        # cannot start is not a check that passed.
        runner = os.path.join(stash, '_step.sh')
        io.open(runner, 'w', encoding='utf-8', newline='\n').write(write + '\n' + pin)
        p = subprocess.run([bash, runner], capture_output=True, text=True)
        print(p.stdout[-4000:])
        if p.stderr.strip():
            print('--- stderr ---')
            print(p.stderr[-4000:])
        man = os.path.join(tmp, 'kit-scripts.sha256')
        actual = (io.open(man, encoding='utf-8', newline='').read()
                  if os.path.exists(man) else None)
        per_file = []
        for canon, _t, _g, dest in gen.SCRIPTS:
            f = os.path.join(tmp, os.path.basename(dest))
            got = io.open(f, 'rb').read() if os.path.exists(f) else b''
            per_file.append((os.path.basename(dest), got == gen.materialised(canon), len(got)))
    finally:
        for n in names:
            try:
                os.remove(os.path.join(tmp, n))
            except OSError:
                pass
            src = os.path.join(stash, n)
            if os.path.exists(src):
                shutil.move(src, os.path.join(tmp, n))
        shutil.rmtree(stash, ignore_errors=True)

    print('')
    for name, same, size in per_file:
        print('  %-22s %-9s %d bytes' % (name, 'identical' if same else 'DIFFERS', size))
        if not same:
            ok = False
    if p.returncode != 0:
        print('FAIL: the bootstrap shell exited %d. It asserts its own digest, so a non-zero '
              'exit here IS the drift.' % p.returncode)
        ok = False
    if actual is None:
        print('FAIL: no manifest was written. Every consuming job would fail on a missing file.')
        return 1

    expected = gen.manifest_body()
    if actual != expected:
        print('FAIL: the manifest bash wrote differs from what the generator derives.')
        for a, b in zip(actual.split('\n'), expected.split('\n')):
            if a != b:
                print('    shell     : %s' % a)
                print('    generator : %s' % b)
        ok = False

    import hashlib
    got = hashlib.sha256(actual.encode('utf-8')).hexdigest()
    pinned = gen.manifest_digest()
    print('')
    print('  manifest digest written by the shell : %s' % got)
    print('  manifest digest pinned in the workflow: %s' % pinned)
    if got != pinned:
        print('FAIL: the pinned digest is not the digest the producer produces. Fourteen jobs')
        print('      would refuse the bundle on the first dispatch.')
        ok = False

    # The pin must actually BE in the workflow text at every download site, not merely
    # computable. A constant the generator knows and the file does not is not a pin.
    text = io.open(WF, encoding='utf-8').read()
    sites = text.count('%s  kit-scripts.sha256' % pinned)
    fetches = text.count('# BEGIN ' + FETCH_MARKER + ' ')
    print('  script-bundle download sites          : %d' % fetches)
    print('  pinned occurrences in the workflow    : %d (= %d download + 1 producer)'
          % (sites, fetches))
    if sites != fetches + 1:
        print('FAIL: %d download site(s) and %d pinned digest(s). A download whose bytes nobody'
              % (fetches, sites))
        print('      checked is a supply chain step with no integrity check.')
        ok = False

    # Nothing is removed here. The `finally` above already took out exactly what the step wrote and
    # put back what it displaced. `tmp` is the shell's shared /tmp -- on MSYS, the operator's whole
    # Temp folder -- and a proof must never delete what it did not create.
    # (tests/prove_digest_proof_spares_tmp.py)
    print('')
    if not ok:
        return 1
    print('PASS: the shipped bootstrap shell writes exactly the manifest the workflow pins, and')
    print('      every download site carries that pin. RUN, not recomputed.')
    return 0


if __name__ == '__main__':
    sys.exit(main())

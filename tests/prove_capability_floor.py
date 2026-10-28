#!/usr/bin/env python3
"""A pull request that deletes a scanner row must not teach the gate the scanner was never expected
(owner ruling 4, 2026-10-27, KDEC-033): the adversarial test of the protected capability floor.

THE EXACT MUTATION

    A contributor deletes `sast-go` everywhere a contributor can: its scanner-registry.yaml row, its
    job, its place in the gate's `needs:`, its report row (`add "gosec"`), its `expect:` entry and its
    gate env lines. The workflow and the registry then agree perfectly.

WHAT MUST HAPPEN

    F1  the real tree holds the floor (static), and the floor file is under CODEOWNERS for both the
        pipeline maintainers and the security approvers -- kit-owned, not a contributor row.
    F2  THE CONTROL THAT IS NOT ENOUGH: tests/check_scanner_registry.py, run on the mutated pair,
        PASSES. A registry check alone has been taught the scanner was never expected.
    F3  the floor's static check, run on the same mutated pair with the floor unchanged, is
        BREACHED and names sast-go and gosec.
    F4  the same deletion made in the floor too, with no tombstone, is BREACHED against the base.
    F5  the runtime: the gate's floor step, run as shipped over this run's evidence with
        state-gosec.json missing (what the mutated workflow would produce), reports BREACHED and
        names gosec; with every identity present it reports HELD.
    F6  the gate's verdict step, run as shipped, FAILS on a BREACHED or absent floor and is
        unchanged on HELD (advisory_mode does not soften it: an expected scanner gone is not a
        finding).
    F7  the floor step sits in the security-gate job, runs `if: always()`, reads the floor from the
        kit (`$/`), never from the consumer's checkout.

EXIT  0 all hold   1 a violation   2 could not be checked
"""
import copy
import io
import os
import re
import shutil
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, HERE)
sys.path.insert(0, os.path.join(ROOT, 'scripts'))

import yaml  # noqa: E402
import capability_floor as cf  # noqa: E402

WF = os.path.join(ROOT, '.github', 'workflows', 'reusable-security.yml')
REG = os.path.join(ROOT, 'scanner-registry.yaml')
VICTIM, IDENT = 'sast-go', 'gosec'


def mutate(wf_text, reg):
    """The PR: sast-go removed from every contributor-editable place, as TEXT edits to the shipped
    workflow (a re-dump would reformat every script and prove nothing about the real text)."""
    reg = copy.deepcopy(reg)
    reg['jobs'].pop(VICTIM)
    reg.get('version_support', {}).pop(VICTIM, None)
    text = wf_text.replace('\r\n', '\n')
    m = re.search(r'(?ms)^  %s:\n.*?(?=^  [a-z][\w-]*:\s*$)' % re.escape(VICTIM), text)
    text = text[:m.start()] + text[m.end():]
    out = []
    for line in text.split('\n'):
        if line.strip() == '- %s' % VICTIM:
            continue                                   # the gate's needs list
        if 'needs.%s.' % VICTIM in line:
            continue                                   # every env line reading it
        if re.search(r'^\s*add\s+"%s"\s' % IDENT, line):
            continue                                   # its report row
        if re.match(r'^\s+expect:', line):
            line = line.replace(',%s,' % IDENT, ',')   # its expected-roster entry
        out.append(line)
    text = '\n'.join(out)
    text = re.sub(r'(needs: \[[^\]]*?), %s(\b[^\]]*\])' % re.escape(VICTIM), r'\1\2', text)
    doc = yaml.safe_load(text)
    return text, reg, doc


def run_floor_step(bash, step, states):
    import _step_harness as h
    home = tempfile.mkdtemp(prefix='floor-')
    try:
        ctx = {'inputs.states-dir': states.replace(os.sep, '/')}
        return h.run(bash, step, ctx, home, composite=True,
                     extra_env={'GITHUB_ACTION_PATH': os.path.join(ROOT, '.github', 'actions',
                                                                   'capability-floor').replace(os.sep, '/')})
    finally:
        shutil.rmtree(home, ignore_errors=True)


def main():
    import _step_harness as h
    import check_scanner_registry as csr
    import reconcile_validation as rv
    bad = []
    wf_text = io.open(WF, encoding='utf-8').read()
    reg = yaml.safe_load(io.open(REG, encoding='utf-8'))
    floor, tombs = cf.load_floor()

    # F1
    p = cf.check_tree(floor, wf_text, reg)
    bad += ['F1 the real tree breaches the floor: %s' % x for x in p]
    owners = io.open(os.path.join(ROOT, 'CODEOWNERS'), encoding='utf-8').read()
    m = re.search(r'(?m)^/capability-floor\.json\s+(.+)$', owners)
    if not m or 'security-approvers' not in m.group(1) or 'pipeline-maintainers' not in m.group(1):
        bad.append('F1 CODEOWNERS does not put /capability-floor.json under both the pipeline '
                   'maintainers and the security approvers')

    # The mutation.
    mtext, mreg, mdoc = mutate(wf_text, reg)
    caps = set(rv.CAPABILITY_REGISTRY.get('reusable-security.yml') or [])
    # F2
    reg_probs = csr.check(mdoc, mreg, caps)
    if reg_probs:
        bad.append('F2 expected the registry check to be FOOLED by the coordinated deletion (that is '
                   'the point of the floor); it objected: %s' % reg_probs[:3])
    else:
        print('F2 control: check_scanner_registry PASSES the mutated pair -- the registry alone was '
              'taught that %s was never expected' % VICTIM)
    # F3
    p = cf.check_tree(floor, mtext, mreg)
    if not p or not any(VICTIM in x for x in p) or not any(IDENT in x for x in p):
        bad.append('F3 the floor did not catch the deletion: %s' % p)
    else:
        print('F3 floor (static) on the mutated pair: BREACHED (%d): %s' % (len(p), p[0]))
    # F4
    mfloor = [e for e in floor if e['capability'] != VICTIM]
    probs, state = cf.check_base(mfloor, tombs, floor, '2026-10-27')
    if state != cf.BREACHED or not any(VICTIM in x for x in probs):
        bad.append('F4 deleting the floor entry with no tombstone was not refused: %s %s' % (state, probs))
    else:
        print('F4 floor shrunk with no tombstone: BREACHED: %s' % probs[0])

    # F7
    doc = yaml.safe_load(wf_text)
    gsteps = doc['jobs']['security-gate']['steps']
    fstep = next((s for s in gsteps if s.get('id') == 'floor'), None)
    if not fstep:
        bad.append('F7 the security-gate job has no floor step')
    else:
        if fstep.get('uses') != '$/.github/actions/capability-floor':
            bad.append('F7 the floor step does not run the kit composite: %r' % fstep.get('uses'))
        if str(fstep.get('if', '')).replace(' ', '') != 'always()':
            bad.append('F7 the floor step is not if: always()')
        ids = [s.get('id') for s in gsteps]
        if not ('render' in ids and 'clear_ws' in ids and ids.index('render') < ids.index('floor') < ids.index('clear_ws')):
            bad.append('F7 the floor step must read the evidence after the report renders and before '
                       'the workspace is cleared: %s' % ids)
    comp = os.path.join(ROOT, '.github', 'actions', 'capability-floor', 'action.yml')
    if not os.path.isfile(comp):
        bad.append('F7 no .github/actions/capability-floor/action.yml')
    bash, why = h.usable_bash()
    if not bash:
        print('UNKNOWN: no usable bash (%s); F5 and F6 not run.' % why)
        for b in bad:
            print('VIOLATION: ' + b)
        return 1 if bad else 2
    if os.path.isfile(comp):
        cdoc = yaml.safe_load(io.open(comp, encoding='utf-8'))
        cstep = next(s for s in cdoc['runs']['steps'] if s.get('id') == 'f')
        if 'kit_root' not in str(cstep.get('run')) or 'GITHUB_WORKSPACE' in str(cstep.get('run')):
            bad.append('F7 the composite must read the floor from the kit root, never the workspace')
        # F5
        d = tempfile.mkdtemp(prefix='floor-states-')
        try:
            for i in cf.floor_identities(floor):
                io.open(os.path.join(d, 'state-%s.json' % i), 'w').write('{}')
            r = run_floor_step(bash, cstep, d)
            if r['outputs'].get('floor_state') != 'HELD':
                bad.append('F5 every identity present -> %r, want HELD: %s' % (r['outputs'], r['log'][-300:]))
            os.remove(os.path.join(d, 'state-%s.json' % IDENT))
            r = run_floor_step(bash, cstep, d)
            if r['outputs'].get('floor_state') != 'BREACHED' or IDENT not in r['outputs'].get('floor_missing', ''):
                bad.append('F5 state-%s.json missing -> %r, want BREACHED naming it' % (IDENT, r['outputs']))
            else:
                print('F5 runtime, %s state missing: BREACHED, missing=%s' % (IDENT, r['outputs']['floor_missing']))
        finally:
            shutil.rmtree(d, ignore_errors=True)
    # F6: the verdict step, through the existing gate scenario harness.
    import prove_bootstrap_failure as pbf
    for floor_state, advisory, want_fail in (('HELD', 'false', False), ('BREACHED', 'false', True),
                                             ('BREACHED', 'true', True), ('', 'false', True)):
        c = pbf.ctx(advisory=advisory)
        c['steps.floor.outputs.floor_state'] = floor_state
        c['steps.floor.outputs.floor_missing'] = IDENT if floor_state == 'BREACHED' else ''
        body, _seen = pbf.substitute(pbf.gate_script(), c)
        rc, emitted, log, _summary = pbf.run(bash, body, pbf.gate_env(c))
        failed = rc != 0
        print('F6 floor %-9r advisory=%-5s -> gate exit %d, enforcement %s'
              % (floor_state, advisory, rc, emitted.get('enforcement_state')))
        if failed != want_fail:
            bad.append('F6 floor %r advisory=%s -> gate %s, want %s'
                       % (floor_state, advisory, 'FAIL' if failed else 'PASS', 'FAIL' if want_fail else 'PASS'))
    for b in bad:
        print('VIOLATION: ' + b)
    if bad:
        print('FAIL: %d violation(s)' % len(bad))
        return 1
    print('PASS: deleting %s from every contributor-editable place passes the registry check and is '
          'refused by the protected floor -- statically, against the base, at runtime, and by the gate.'
          % VICTIM)
    return 0


if __name__ == '__main__':
    sys.exit(main())

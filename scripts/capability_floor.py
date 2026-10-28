#!/usr/bin/env python3
"""The protected capability floor: what the gate must expect whatever the registry says.

WHY THIS EXISTS (owner ruling 4, 2026-10-27, KDEC-033)

    The cost redesign makes scanner-registry.yaml the single source the workflow is generated from
    (proposal step 4). A registry that is the source is also a registry a pull request can edit: a
    PR that deletes a scanner's row, its job and its report line leaves a workflow that agrees with
    the registry perfectly -- tests/check_scanner_registry.py goes green, and the gate has been
    taught that the scanner was never expected. A row deleted is coverage removed with no failure
    anywhere.

    The floor is the answer. capability-floor.json is KIT-OWNED and separate from the registry rows
    contributors edit: CODEOWNERS puts it under both the pipeline maintainers and the security
    approvers, and it can only SHRINK through a tombstone -- a recorded decision that names the
    capability, the scanner identities it had (its history keeps them), whether its gap is
    uncovered, and either the proven replacement or an authorised, time-limited gap decision
    (owner ruling 8). Three readers hold it, none of which reads the registry for what is expected:

      static   every floor capability still has a registry row, a job the gate waits for, and every
               identity in the report's expected roster and its state builder (`--check-tree`)
      base     against the PR's base, every floor entry that disappeared has a valid tombstone
               (`--base-floor <file>`); an expired gap decision is refused, never auto-restored
      runtime  in the security gate, every floor identity has a state file in this run's evidence
               (`--states <dir>`); one missing is BREACHED, and the gate fails

STATES (assurance-taxonomy.yaml capability_floor_state)

    HELD         every floor identity is present (runtime) / every check holds (static, base)
    GAP_DECIDED  a tombstoned capability with an unexpired, authorised gap decision and no proven
                 replacement: not a breach, and never a clean coverage claim
    BREACHED     something the floor requires is missing, or a tombstone is invalid or expired

    The runtime mode always exits 0 and reports through --github-output: a verdict belongs to the
    gate. A crash leaves the output unset, and the gate reads an unset floor as BREACHED.

EXIT (static, base, self-test)  0 holds   1 breached   2 could not be checked
"""
import argparse
import datetime
import io
import json
import os
import re
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
FLOOR = os.path.join(ROOT, 'capability-floor.json')

HELD, GAP, BREACHED = 'HELD', 'GAP_DECIDED', 'BREACHED'
TOMBSTONE_FIELDS = ('capability', 'identities', 'decision', 'approved_by', 'decided_on', 'reason',
                    'uncovered_gap')


def load_floor(path=FLOOR):
    with io.open(path, encoding='utf-8') as fh:
        doc = json.load(fh)
    floor = doc.get('floor') or []
    tombs = doc.get('tombstones') or []
    if not isinstance(floor, list) or not isinstance(tombs, list):
        raise ValueError('floor and tombstones must be lists')
    return floor, tombs


def floor_identities(floor):
    out = []
    for e in floor:
        out += list(e.get('identities') or [])
    return out


def tombstone_problems(tomb, floor, today):
    """-> (problems, state) for one tombstone. state is HELD (proven replacement), GAP or BREACHED."""
    probs = []
    for f in TOMBSTONE_FIELDS:
        if tomb.get(f) in (None, '', []):
            probs.append('tombstone for %r lacks %s' % (tomb.get('capability'), f))
    if probs:
        return probs, BREACHED
    caps = {e.get('capability') for e in floor}
    rep = tomb.get('replacement')
    if rep:
        if rep not in caps:
            return (['tombstone for %r names replacement %r, which is not in the floor (a replacement '
                     'that is not itself required is not proven)' % (tomb['capability'], rep)], BREACHED)
        return [], HELD
    gap = tomb.get('gap_decision') or {}
    exp = str(gap.get('expires') or '')
    if not (gap.get('approved_by') and gap.get('reference') and re.match(r'^\d{4}-\d{2}-\d{2}$', exp)):
        return (['tombstone for %r has no proven replacement and no authorised, time-limited gap '
                 'decision (approved_by, reference, expires)' % tomb['capability']], BREACHED)
    if exp < today:
        return (['tombstone for %r: the gap decision expired %s. Expiry needs a renewed decision or a '
                 'replacement; it never restores the removed tool' % (tomb['capability'], exp)], BREACHED)
    return [], GAP


def check_base(head_floor, head_tombs, base_floor, today):
    """Every capability the base floor had and the head floor lacks needs a valid tombstone."""
    probs, state = [], HELD
    head_caps = {e.get('capability') for e in head_floor}
    tomb_by = {t.get('capability'): t for t in head_tombs}
    for e in base_floor:
        cap = e.get('capability')
        if cap in head_caps:
            head_e = next(x for x in head_floor if x.get('capability') == cap)
            lost = set(e.get('identities') or []) - set(head_e.get('identities') or [])
            if lost:
                probs.append('floor capability %r lost identities %s with no tombstone (an identity '
                             'removed silently is coverage removed silently)' % (cap, sorted(lost)))
                state = BREACHED
            continue
        t = tomb_by.get(cap)
        if not t:
            probs.append('floor capability %r was removed with no tombstone' % cap)
            state = BREACHED
            continue
        missing = set(e.get('identities') or []) - set(t.get('identities') or [])
        if missing:
            probs.append('tombstone for %r drops the historical identities %s' % (cap, sorted(missing)))
            state = BREACHED
        p, s = tombstone_problems(t, head_floor, today)
        probs += p
        if s == BREACHED:
            state = BREACHED
        elif s == GAP and state == HELD:
            state = GAP
    return probs, state


def check_tree(floor, workflow_text, registry):
    """Static: the contributor-editable files still carry everything the floor requires."""
    import yaml
    probs = []
    wf = yaml.safe_load(workflow_text) or {}
    jobs = wf.get('jobs') or {}
    gate = jobs.get('security-gate') or {}
    gneeds = gate.get('needs') or []
    gneeds = [gneeds] if isinstance(gneeds, str) else list(gneeds)
    rows = (registry or {}).get('jobs') or {}
    by_cap = {}
    for name, row in rows.items():
        if (row or {}).get('class') == 'scanner':
            by_cap.setdefault((row or {}).get('capability'), []).append(name)
    m = re.search(r'(?m)^\s+expect:\s*(\S+)', workflow_text)
    expect = set(m.group(1).split(',')) if m else set()
    for e in floor:
        cap = e.get('capability')
        hosts = by_cap.get(cap) or []
        if not hosts:
            probs.append('floor capability %r has no scanner row in scanner-registry.yaml' % cap)
        for h in hosts:
            if h not in jobs:
                probs.append('floor capability %r: registry names job %r, which does not exist' % (cap, h))
            elif h not in gneeds:
                probs.append('floor capability %r: the gate does not wait for job %r' % (cap, h))
        for ident in e.get('identities') or []:
            if ident not in expect:
                probs.append('floor identity %r (%s) is not in the report\'s expected roster' % (ident, cap))
            pat = (r'cq_lang\s+%s\s' % re.escape(ident[len('codeql-'):]) if ident.startswith('codeql-')
                   else r'add\s+"%s"\s' % re.escape(ident))
            if not re.search(pat, workflow_text):
                probs.append('floor identity %r (%s) has no row in the state builder' % (ident, cap))
    return probs


def check_states(floor, tombs, states_dir, today):
    """Runtime: -> (state, missing identities, notes)."""
    if not os.path.isdir(states_dir):
        return BREACHED, floor_identities(floor), ['no states directory %s' % states_dir]
    present = {n[len('state-'):-len('.json')] for n in os.listdir(states_dir)
               if n.startswith('state-') and n.endswith('.json')}
    missing = [i for i in floor_identities(floor) if i not in present]
    state = BREACHED if missing else HELD
    notes = []
    for t in tombs:
        p, s = tombstone_problems(t, floor, today)
        notes += p
        if s == BREACHED:
            state = BREACHED
        elif s == GAP and state == HELD:
            state = GAP
            notes.append('capability %r removed under gap decision %s until %s: no clean coverage claim'
                         % (t.get('capability'), (t.get('gap_decision') or {}).get('reference'),
                            (t.get('gap_decision') or {}).get('expires')))
    return state, missing, notes


def emit(path, **kv):
    with io.open(path, 'a', encoding='utf-8') as fh:
        for k, v in kv.items():
            fh.write('%s=%s\n' % (k, str(v).replace('\r', ' ').replace('\n', ' ')))


def self_test():
    today = '2026-10-27'
    floor = [{'capability': 'a', 'identities': ['x', 'y']}, {'capability': 'b', 'identities': ['z']}]
    fails = []

    def expect(label, cond):
        if not cond:
            fails.append(label)
    import tempfile
    import shutil
    d = tempfile.mkdtemp(prefix='floor-')
    try:
        for i in ('x', 'y', 'z'):
            io.open(os.path.join(d, 'state-%s.json' % i), 'w').write('{}')
        expect('all present -> HELD', check_states(floor, [], d, today)[0] == HELD)
        os.remove(os.path.join(d, 'state-y.json'))
        s, miss, _ = check_states(floor, [], d, today)
        expect('one missing -> BREACHED naming it', s == BREACHED and miss == ['y'])
    finally:
        shutil.rmtree(d, ignore_errors=True)
    expect('no directory -> BREACHED', check_states(floor, [], '/nonexistent/x', today)[0] == BREACHED)
    base = floor + [{'capability': 'c', 'identities': ['w']}]
    expect('silent removal -> BREACHED', check_base(floor, [], base, today)[1] == BREACHED)
    tomb = {'capability': 'c', 'identities': ['w'], 'decision': 'KDEC-999', 'approved_by': 'security-approvers',
            'decided_on': today, 'reason': 'malicious binary', 'uncovered_gap': True}
    expect('tombstone, no replacement, no gap decision -> BREACHED',
           check_base(floor, [tomb], base, today)[1] == BREACHED)
    expect('tombstone with proven replacement -> HELD',
           check_base(floor, [dict(tomb, replacement='a', uncovered_gap=False)], base, today)[1] == HELD)
    gd = {'approved_by': 'security-approvers', 'reference': 'EXC-1', 'expires': '2026-12-31'}
    expect('unexpired gap decision -> GAP_DECIDED',
           check_base(floor, [dict(tomb, gap_decision=gd)], base, today)[1] == GAP)
    expect('expired gap decision -> BREACHED, never restored',
           check_base(floor, [dict(tomb, gap_decision=dict(gd, expires='2026-01-01'))], base, today)[1] == BREACHED)
    expect('identity dropped from a kept capability -> BREACHED',
           check_base([{'capability': 'a', 'identities': ['x']}, floor[1]], [], floor, today)[1] == BREACHED)
    expect('tombstone dropping history -> BREACHED',
           check_base(floor, [dict(tomb, identities=[], replacement='a')], base, today)[1] == BREACHED)
    if fails:
        print('SELF-TEST FAILED: ' + '; '.join(fails))
        return 1
    print('self-test ok: 10 cases (runtime presence, silent removal, tombstones, gap expiry, history)')
    return 0


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.split('\n')[0])
    ap.add_argument('--floor', default=FLOOR)
    ap.add_argument('--states')
    ap.add_argument('--github-output')
    ap.add_argument('--check-tree', action='store_true')
    ap.add_argument('--base-floor')
    ap.add_argument('--today', default=datetime.date.today().isoformat())
    ap.add_argument('--self-test', action='store_true')
    a = ap.parse_args(argv)
    if a.self_test:
        return self_test()
    try:
        floor, tombs = load_floor(a.floor)
    except (OSError, ValueError) as e:
        print('BREACHED: the floor could not be read (%s). An unreadable floor is not an empty one.' % e)
        if a.github_output:
            emit(a.github_output, floor_state=BREACHED, floor_missing='(the floor file could not be read)')
        return 0 if a.states else 1
    if a.states:
        state, missing, notes = check_states(floor, tombs, a.states, a.today)
        for n in notes:
            print(n)
        print('capability floor: %s (%d identities required, %d missing%s)'
              % (state, len(floor_identities(floor)), len(missing),
                 (': ' + ' '.join(missing)) if missing else ''))
        if a.github_output:
            emit(a.github_output, floor_state=state, floor_missing=' '.join(missing))
        return 0
    probs, state = [], HELD
    if a.check_tree:
        import yaml
        wf = io.open(os.path.join(ROOT, '.github', 'workflows', 'reusable-security.yml'), encoding='utf-8').read()
        reg = yaml.safe_load(io.open(os.path.join(ROOT, 'scanner-registry.yaml'), encoding='utf-8'))
        probs += check_tree(floor, wf, reg)
    if a.base_floor:
        base_floor, _ = load_floor(a.base_floor)
        p, state = check_base(floor, tombs, base_floor, a.today)
        probs += p
    for p in probs:
        print('BREACHED: ' + p)
    if probs:
        return 1
    print('capability floor: %s (%d capabilities, %d identities, %d tombstone(s))'
          % (state, len(floor), len(floor_identities(floor)), len(tombs)))
    return 0


if __name__ == '__main__':
    sys.exit(main())

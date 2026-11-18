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
    contributors edit: CODEOWNERS puts it solely under the declared protected owner (KDEC-050;
    scripts/protected_paths.py), and it can only SHRINK through a tombstone -- a recorded decision that names the
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

SHRINK IS LOUD (KE-04, KDEC-050, 2026-11-11)

    A tombstone is never deleted or changed: every tombstone the base carried must be in the head
    byte-for-byte (canonical JSON), and a capability removed in THIS change is covered only by a
    tombstone that is NEW in this change -- an old tombstone of a capability that was later
    restored never covers its second removal. Every registry scanner row must belong to a floor
    capability (a scanner outside the floor could be deleted with nothing failing), and against the
    base a capability_selection candidate that disappeared needs a selection tombstone (same
    append-only rule). `--base-ref <ref>` reads the base floor and registry from git, so the push
    and dispatch paths are compared too, not only pull requests.

TOMBSTONE POLICY SEAM (KE-03, KDEC-050: PROPOSED for the owner; the STRICTER answer is the default)

    capability-floor.json `tombstone_policy` holds the two answers the owner has not given yet, each a
    one-line setting: `replacement_requires_proof` (default true: a replacement must cite
    `replacement_proof`, a tests/ file that exists and names both capabilities) and
    `gap_decision_max_days` (default 90: `expires` at most that many days after `decided_on`; null
    or 0 removes the cap). Loosening either against the base needs a `decision` the base did not have.

EXIT (static, base, self-test)  0 holds   1 breached   2 could not be checked
"""
import argparse
import datetime
import io
import json
import os
import re
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
FLOOR = os.path.join(ROOT, 'capability-floor.json')

HELD, GAP, BREACHED = 'HELD', 'GAP_DECIDED', 'BREACHED'
TOMBSTONE_FIELDS = ('capability', 'identities', 'decision', 'approved_by', 'decided_on', 'reason',
                    'uncovered_gap')
SELECTION_TOMBSTONE_FIELDS = ('selection', 'candidate', 'decision', 'approved_by', 'decided_on', 'reason')
# KE-03 seam: the STRICTER answer until the owner rules (KDEC-050 PROPOSED).
DEFAULT_POLICY = {'replacement_requires_proof': True, 'gap_decision_max_days': 90}


def load_doc(path=FLOOR):
    with io.open(path, encoding='utf-8') as fh:
        doc = json.load(fh)
    if not isinstance(doc, dict):
        raise ValueError('the floor file is not an object')
    for k in ('floor', 'tombstones', 'selection_tombstones'):
        if not isinstance(doc.get(k) or [], list):
            raise ValueError('%s must be a list' % k)
    if not isinstance(doc.get('tombstone_policy') or {}, dict):
        raise ValueError('tombstone_policy must be an object')
    return doc


def load_floor(path=FLOOR):
    doc = load_doc(path)
    return doc.get('floor') or [], doc.get('tombstones') or []


def policy_of(doc):
    p = dict(DEFAULT_POLICY)
    p.update((doc or {}).get('tombstone_policy') or {})
    return p


def _canon(x):
    return json.dumps(x, sort_keys=True, separators=(',', ':'))


def _date(s):
    try:
        return datetime.date(*[int(x) for x in str(s).split('-')]) if re.match(
            r'^\d{4}-\d{2}-\d{2}$', str(s)) else None
    except ValueError:
        return None


def policy_loosened(head_doc, base_doc):
    """-> [problems]: a policy looser than the base's with no new decision is a silent shrink."""
    hp, bp = policy_of(head_doc), policy_of(base_doc)
    looser = []
    if bp.get('replacement_requires_proof') and not hp.get('replacement_requires_proof'):
        looser.append('replacement_requires_proof true -> false')
    bmax, hmax = bp.get('gap_decision_max_days'), hp.get('gap_decision_max_days')
    if bmax and (not hmax or hmax > bmax):
        looser.append('gap_decision_max_days %s -> %s' % (bmax, hmax))
    if looser and (not hp.get('decision') or hp.get('decision') == bp.get('decision')):
        return ['tombstone_policy loosened (%s) with no new decision recorded in tombstone_policy.decision'
                % '; '.join(looser)]
    return []


def floor_identities(floor):
    out = []
    for e in floor:
        out += list(e.get('identities') or [])
    return out


def tombstone_problems(tomb, floor, today, policy=None, root=None):
    """-> (problems, state) for one tombstone. state is HELD (proven replacement), GAP or BREACHED."""
    policy = policy_of({'tombstone_policy': policy or {}})
    root = root or ROOT
    probs = []
    for f in TOMBSTONE_FIELDS:
        if tomb.get(f) in (None, '', []):
            probs.append('tombstone for %r lacks %s' % (tomb.get('capability'), f))
    if probs:
        return probs, BREACHED
    decided, now = _date(tomb.get('decided_on')), _date(today)
    if not decided or (now and decided > now):
        return (['tombstone for %r: decided_on %r is not a date on or before %s'
                 % (tomb['capability'], tomb.get('decided_on'), today)], BREACHED)
    caps = {e.get('capability') for e in floor}
    rep = tomb.get('replacement')
    if rep:
        if rep not in caps:
            return (['tombstone for %r names replacement %r, which is not in the floor (a replacement '
                     'that is not itself required is not proven)' % (tomb['capability'], rep)], BREACHED)
        if policy.get('replacement_requires_proof'):
            proof = str(tomb.get('replacement_proof') or '').replace('\\', '/')
            path = os.path.join(root, *proof.split('/')) if proof else ''
            text = ''
            if proof.startswith('tests/') and '..' not in proof.split('/') and os.path.isfile(path):
                text = io.open(path, encoding='utf-8', errors='replace').read()
            if not (tomb['capability'] in text and rep in text):
                return (['tombstone for %r: replacement %r cites no proof (replacement_proof %r must be a '
                         'tests/ file that exists and names both capabilities; tombstone_policy.'
                         'replacement_requires_proof)' % (tomb['capability'], rep, proof)], BREACHED)
        return [], HELD
    gap = tomb.get('gap_decision') or {}
    exp = str(gap.get('expires') or '')
    if not (gap.get('approved_by') and gap.get('reference') and _date(exp)):
        return (['tombstone for %r has no proven replacement and no authorised, time-limited gap '
                 'decision (approved_by, reference, expires)' % tomb['capability']], BREACHED)
    cap_days = policy.get('gap_decision_max_days')
    if cap_days and (_date(exp) - decided).days > int(cap_days):
        return (['tombstone for %r: the gap decision runs %d days (%s to %s), over the %s-day cap '
                 '(tombstone_policy.gap_decision_max_days)' % (tomb['capability'], (_date(exp) - decided).days,
                                                              tomb['decided_on'], exp, cap_days)], BREACHED)
    if exp < today:
        return (['tombstone for %r: the gap decision expired %s. Expiry needs a renewed decision or a '
                 'replacement; it never restores the removed tool' % (tomb['capability'], exp)], BREACHED)
    return [], GAP


def check_append_only(head_list, base_list, kind, key):
    """A tombstone is never deleted or changed: every base entry is in the head, byte for byte."""
    head = {_canon(t) for t in head_list or []}
    return ['%s for %r was deleted or changed (a tombstone is never deleted: the history it names is '
            'permanent)' % (kind, t.get(key) if isinstance(t, dict) else t)
            for t in base_list or [] if _canon(t) not in head]


def check_base(head_floor, head_tombs, base_floor, today, base_tombs=None, policy=None, root=None):
    """Every capability the base floor had and the head floor lacks needs a valid tombstone that is
    NEW in this change; every tombstone the base had is still there, unchanged."""
    probs, state = [], HELD
    head_caps = {e.get('capability') for e in head_floor}
    base_canon = {_canon(t) for t in base_tombs or []}
    probs += check_append_only(head_tombs, base_tombs, 'tombstone', 'capability')
    if probs:
        state = BREACHED
    tomb_by = {}
    for t in head_tombs:
        if _canon(t) not in base_canon:
            tomb_by[t.get('capability')] = t
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
            probs.append('floor capability %r was removed with no tombstone new in this change' % cap)
            state = BREACHED
            continue
        missing = set(e.get('identities') or []) - set(t.get('identities') or [])
        if missing:
            probs.append('tombstone for %r drops the historical identities %s' % (cap, sorted(missing)))
            state = BREACHED
        p, s = tombstone_problems(t, head_floor, today, policy, root)
        probs += p
        if s == BREACHED:
            state = BREACHED
        elif s == GAP and state == HELD:
            state = GAP
    return probs, state


def selection_candidates(registry):
    out = set()
    for name, row in (((registry or {}).get('capability_selection') or {}).items()):
        for c in (row or {}).get('candidates') or []:
            out.add((str(name), str(c)))
    return out


def check_registry_base(head_reg, base_reg, head_sel, base_sel, today):
    """Against the base: a capability_selection candidate that disappeared needs a selection
    tombstone (append-only, like the floor's). Scanner rows are held by the floor binding."""
    probs = check_append_only(head_sel, base_sel, 'selection tombstone', 'candidate')
    covered = {}
    for t in head_sel or []:
        covered[(str(t.get('selection')), str(t.get('candidate')))] = t
    for sel, cand in sorted(selection_candidates(base_reg) - selection_candidates(head_reg)):
        t = covered.get((sel, cand))
        if not t:
            probs.append('scanner-registry.yaml capability_selection %r lost candidate %r with no selection '
                         'tombstone (a candidate removed silently is coverage removed silently)' % (sel, cand))
            continue
        lacks = [f for f in SELECTION_TOMBSTONE_FIELDS if t.get(f) in (None, '', [])]
        decided, now = _date(t.get('decided_on')), _date(today)
        if lacks or not decided or (now and decided > now):
            probs.append('selection tombstone for %r/%r is incomplete (lacks %s, decided_on %r)'
                         % (sel, cand, lacks, t.get('decided_on')))
    return probs


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
    floor_caps = {e.get('capability') for e in floor}
    for cap in sorted((c for c in by_cap if c not in floor_caps), key=str):
        probs.append('registry scanner job(s) %s (capability %r) are not in the protected floor: a scanner '
                     'outside the floor can be deleted with nothing failing (KE-04)' % (by_cap[cap], cap))
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


def tombstone_line(t):
    """KE-03 (c): every run names every tombstone, so a shrink is visible in every summary."""
    gd = t.get('gap_decision') or {}
    how = ('replacement %s (proof %s)' % (t.get('replacement'), t.get('replacement_proof') or 'none')
           if t.get('replacement') else 'gap decision %s until %s' % (gd.get('reference'), gd.get('expires')))
    return ('tombstone: %r removed by %s, approved_by %s on %s, %s. Its authority is the code-owner '
            'approval of the change that added it' % (t.get('capability'), t.get('decision'),
                                                      t.get('approved_by'), t.get('decided_on'), how))


def check_states(floor, tombs, states_dir, today, policy=None, root=None):
    """Runtime: -> (state, missing identities, notes)."""
    if not os.path.isdir(states_dir):
        return BREACHED, floor_identities(floor), ['no states directory %s' % states_dir]
    present = {n[len('state-'):-len('.json')] for n in os.listdir(states_dir)
               if n.startswith('state-') and n.endswith('.json')}
    missing = [i for i in floor_identities(floor) if i not in present]
    state = BREACHED if missing else HELD
    notes = []
    caps = {e.get('capability') for e in floor}
    for t in tombs:
        notes.append(tombstone_line(t))
        if t.get('capability') in caps:
            notes.append('capability %r is back in the floor: its tombstone is history, not a gap'
                         % t.get('capability'))
            continue
        p, s = tombstone_problems(t, floor, today, policy, root)
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
    lax = {'replacement_requires_proof': False, 'gap_decision_max_days': None}
    expect('tombstone with a replacement, proof not required -> HELD',
           check_base(floor, [dict(tomb, replacement='a', uncovered_gap=False)], base, today, policy=lax)[1] == HELD)
    expect('tombstone with a replacement and no proof, strict default -> BREACHED',
           check_base(floor, [dict(tomb, replacement='a', uncovered_gap=False)], base, today)[1] == BREACHED)
    gd = {'approved_by': 'security-approvers', 'reference': 'EXC-1', 'expires': '2026-12-31'}
    expect('unexpired gap decision within the cap -> GAP_DECIDED',
           check_base(floor, [dict(tomb, gap_decision=gd)], base, today)[1] == GAP)
    expect('gap decision over the 90-day cap -> BREACHED',
           check_base(floor, [dict(tomb, gap_decision=dict(gd, expires='2099-12-31'))], base, today)[1] == BREACHED)
    expect('expired gap decision -> BREACHED, never restored',
           check_base(floor, [dict(tomb, gap_decision=dict(gd, expires='2026-01-01'))], base, today,
                      policy=lax)[1] == BREACHED)
    expect('identity dropped from a kept capability -> BREACHED',
           check_base([{'capability': 'a', 'identities': ['x']}, floor[1]], [], floor, today)[1] == BREACHED)
    expect('tombstone dropping history -> BREACHED',
           check_base(floor, [dict(tomb, identities=[], replacement='a')], base, today, policy=lax)[1] == BREACHED)
    old = dict(tomb, gap_decision=dict(gd, expires='2026-01-01'))
    expect('a base tombstone deleted -> BREACHED',
           check_base(floor, [], floor, today, base_tombs=[old])[1] == BREACHED)
    expect('an old tombstone never covers a second removal -> BREACHED',
           check_base(floor, [old], base, today, base_tombs=[old], policy=lax)[1] == BREACHED)
    if fails:
        print('SELF-TEST FAILED: ' + '; '.join(fails))
        return 1
    print('self-test ok: 15 cases (runtime presence, silent removal, tombstones, proof, gap cap and expiry, '
          'history, append-only)')
    return 0


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.split('\n')[0])
    ap.add_argument('--floor', default=FLOOR)
    ap.add_argument('--states')
    ap.add_argument('--github-output')
    ap.add_argument('--check-tree', action='store_true')
    ap.add_argument('--base-floor')
    ap.add_argument('--base-registry')
    ap.add_argument('--base-ref', help='read the base floor and registry from this git commit')
    ap.add_argument('--root', default=ROOT)
    ap.add_argument('--today', default=datetime.date.today().isoformat())
    ap.add_argument('--self-test', action='store_true')
    a = ap.parse_args(argv)
    if a.self_test:
        return self_test()
    try:
        doc = load_doc(a.floor)
        floor, tombs = doc.get('floor') or [], doc.get('tombstones') or []
    except (OSError, ValueError) as e:
        print('BREACHED: the floor could not be read (%s). An unreadable floor is not an empty one.' % e)
        if a.github_output:
            emit(a.github_output, floor_state=BREACHED, floor_missing='(the floor file could not be read)')
        return 0 if a.states else 1
    policy = policy_of(doc)
    if a.states:
        state, missing, notes = check_states(floor, tombs, a.states, a.today, policy, a.root)
        for n in notes:
            print(n)
        print('capability floor: %s (%d identities required, %d missing%s)'
              % (state, len(floor_identities(floor)), len(missing),
                 (': ' + ' '.join(missing)) if missing else ''))
        if a.github_output:
            emit(a.github_output, floor_state=state, floor_missing=' '.join(missing))
        return 0
    probs, state = [], HELD
    import yaml
    reg_path = os.path.join(a.root, 'scanner-registry.yaml')
    if a.check_tree:
        wf = io.open(os.path.join(a.root, '.github', 'workflows', 'reusable-security.yml'), encoding='utf-8').read()
        reg = yaml.safe_load(io.open(reg_path, encoding='utf-8'))
        probs += check_tree(floor, wf, reg)
    base_doc = base_reg = None
    if a.base_ref:
        if git_show(a.root, a.base_ref, None) is None:
            print('UNKNOWN: base commit %r could not be read: the floor was NOT compared with its base. '
                  'An unread base is not a held one.' % a.base_ref)
            return 2
        text = git_show(a.root, a.base_ref, 'capability-floor.json')
        if text is None:
            print('no base floor at %s (the base predates the floor)' % a.base_ref)
        else:
            base_doc = json.loads(text)
        rtext = git_show(a.root, a.base_ref, 'scanner-registry.yaml')
        base_reg = yaml.safe_load(rtext) if rtext is not None else None
    if a.base_floor:
        base_doc = load_doc(a.base_floor)
    if a.base_registry:
        base_reg = yaml.safe_load(io.open(a.base_registry, encoding='utf-8'))
    if base_doc is not None:
        p, state = check_base(floor, tombs, base_doc.get('floor') or [], a.today,
                              base_doc.get('tombstones') or [], policy, a.root)
        probs += p + policy_loosened(doc, base_doc)
    if base_reg is not None:
        head_reg = yaml.safe_load(io.open(reg_path, encoding='utf-8'))
        probs += check_registry_base(head_reg, base_reg, doc.get('selection_tombstones') or [],
                                     (base_doc or {}).get('selection_tombstones') or [], a.today)
    for t in tombs:
        print(tombstone_line(t))
    for p in probs:
        print('BREACHED: ' + p)
    if probs:
        return 1
    print('capability floor: %s (%d capabilities, %d identities, %d tombstone(s)%s)'
          % (state, len(floor), len(floor_identities(floor)), len(tombs),
             ', compared with base %s' % a.base_ref if a.base_ref else ''))
    return 0


def git_show(root, ref, rel):
    """-> the file's text at ref (None when absent); rel None: '' when the commit exists, else None."""
    spec = ('%s^{commit}' % ref) if rel is None else ('%s:%s' % (ref, rel))
    try:
        r = subprocess.run(['git', '-C', root, 'cat-file', '-e' if rel is None else '-p', spec],
                           stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    except OSError:
        return None
    if r.returncode != 0:
        return None
    return r.stdout.decode('utf-8', 'replace')


if __name__ == '__main__':
    sys.exit(main())

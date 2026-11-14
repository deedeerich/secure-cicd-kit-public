#!/usr/bin/env python3
"""Removing a scanner, or shrinking the registry, fails loudly unless a recorded, reviewed decision
covers it (KE-03 seam, KE-04, KE-05, KE-06 and the self-test bypass; KDEC-050, 2026-11-11).

Each guard has a positive (the normal path holds), a negative (the shrink is refused, and the
refusal names the guard's own message), and a NAMED MUTANT: the guard's own source with that guard
removed, executed, must let the negative through -- so the negative is proven to reach the guard.

  KE-04  F-P1 the real tree, against itself as base: HELD
         F-N1 a base tombstone deleted (the expired-gap two-step, probe G1): 'was deleted or changed'
         F-N2 an old tombstone re-used for a second removal: 'no tombstone new in this change'
         F-N3 a registry scanner row whose capability is not in the floor: 'not in the protected floor'
         F-N4 a capability_selection candidate removed with no selection tombstone; F-P4 with one: held
         F-N5 the push path: --base-ref, on a base served from git, a floor entry deleted: exit 1
         F-W  the contract step compares with the base on EVERY event (no pull_request-only condition)
         mutants M-append-only, M-new-only, M-floor-binding, M-selection
  KE-03  S-N1 a replacement citing no proof (probe E1): BREACHED; S-P1 citing a real tests/ file: HELD
         S-N2 a gap decision running past 90 days (probe F1, 2099-12-31): BREACHED; S-P2 within: GAP
         S-P3 the seam: the one-line lax setting turns both into HELD / GAP_DECIDED
         S-N3 the policy loosened against the base with no new decision: BREACHED
         mutants M-proof, M-cap
  KE-06  I-P1 the real registry: ESTABLISHED, bound to the floor
         I-N1 (N19h) the sbom row deleted: NOT_ESTABLISHED naming sbom; the population gap names sbom
         I-N2 (N19i) the sbom row as a block mapping: NOT_ESTABLISHED naming sbom
         I-N3 a capability tombstoned out under a gap decision: a population gap naming it
         mutants M-shape, M-bind
  KE-05  O-P1 the real CODEOWNERS: every protected path solely the protected owner
         O-N1 /.github/ unowned; O-N2 a second owner on the registry line; O-N3 an adopted copy (the
         export watermark) still naming the placeholder; O-P3 the same copy with real teams: holds
         mutants M-sole-owner, M-adopted
  BYPASS B-1  self-test runs on pull_request and the `required` verdict runs the checkout's own
              scripts/selftest_required.py: a pull request CAN rewrite what "Self-test required" means
         B-N1 such a change with no decision record is refused; B-P1 with a record naming it: holds
         B-2  self-test.yml and a NEW workflow file are owned solely by the protected owner
         mutant M-guarded

EXIT  0 all hold   1 a violation   2 could not be checked
"""
import copy
import io
import json
import os
import re
import shutil
import sys
import tempfile
import types

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, os.path.join(ROOT, 'scripts'))

import yaml  # noqa: E402
import capability_floor as cf  # noqa: E402
import protected_paths as pp  # noqa: E402
import reconcile_tickets as rt  # noqa: E402

TODAY = '2026-11-11'
FAILS = []


def check(cond, label, detail=''):
    print('%s %s%s' % ('ok  ' if cond else 'FAIL', label, (': %s' % detail) if not cond and detail else ''))
    if not cond:
        FAILS.append(label)


def mutant(rel, old, new, name):
    """The module at `rel` with one guard removed (textual), executed as a fresh module."""
    path = os.path.join(ROOT, *rel.split('/'))
    src = io.open(path, encoding='utf-8').read()
    if old not in src:
        FAILS.append('%s could not be applied (the guard text moved): %r' % (name, old[:60]))
        return None
    mod = types.ModuleType(name)
    mod.__file__ = path
    exec(compile(src.replace(old, new, 1), path, 'exec'), mod.__dict__)
    return mod


def killed(name, mod, still_refused):
    """A mutant is KILLED when the negative is no longer refused under it."""
    if mod is None:
        return
    ok = not still_refused(mod)
    check(ok, '%s killed (the negative passes once the guard is removed: it reaches the guard)' % name)


def floor_doc():
    return json.loads(io.open(os.path.join(ROOT, 'capability-floor.json'), encoding='utf-8').read())


def gap_tomb(expires='2026-12-31', decided='2026-11-01'):
    return {'capability': 'sast-go', 'identities': ['gosec'], 'decision': 'KDEC-999', 'approved_by': 'security',
            'decided_on': decided, 'reason': 'test', 'uncovered_gap': True,
            'gap_decision': {'approved_by': 'security', 'reference': 'EXC-1', 'expires': expires}}


def ke04():
    doc = floor_doc()
    floor = doc['floor']
    without = [e for e in floor if e['capability'] != 'sast-go']
    p, s = cf.check_base(floor, [], floor, TODAY, [])
    check(s == cf.HELD and not p, 'F-P1 the real floor against itself: HELD', p)
    # F-N1: the two-step. Base carries an expired gap tombstone; the head deletes it.
    old = gap_tomb(expires='2026-01-01', decided='2025-12-01')
    neg1 = lambda m: m.check_base(without, [], without, TODAY, [old])
    p, s = neg1(cf)
    check(s == cf.BREACHED and any("'sast-go' was deleted or changed" in x for x in p), 'F-N1 tombstone deleted', p)
    killed('M-append-only', mutant('scripts/capability_floor.py',
                                   "    probs += check_append_only(head_tombs, base_tombs, 'tombstone', 'capability')",
                                   '    pass', 'm_append'), lambda m: neg1(m)[1] == m.BREACHED)
    # F-N2: an old (base) tombstone re-used when the restored capability is removed again.
    reuse = gap_tomb()
    neg2 = lambda m: m.check_base(without, [reuse], floor, TODAY, [reuse])
    p, s = neg2(cf)
    check(s == cf.BREACHED and any('no tombstone new in this change' in x for x in p), 'F-N2 old tombstone re-used', p)
    killed('M-new-only', mutant('scripts/capability_floor.py', '        if _canon(t) not in base_canon:\n',
                                '        if True:\n', 'm_new'), lambda m: neg2(m)[1] == m.BREACHED)
    p, s = cf.check_base(without, [reuse], floor, TODAY, [])
    check(s == cf.GAP and not p, 'F-P2 the same tombstone, new in this change: GAP_DECIDED', p)
    # F-N3: a scanner outside the floor.
    wf = io.open(os.path.join(ROOT, '.github', 'workflows', 'reusable-security.yml'), encoding='utf-8').read()
    reg = yaml.safe_load(io.open(os.path.join(ROOT, 'scanner-registry.yaml'), encoding='utf-8'))
    check(not cf.check_tree(floor, wf, reg), 'F-P3 the real tree: every registry scanner is in the floor')
    reg3 = copy.deepcopy(reg)
    reg3['jobs']['sast-ruby'] = {'class': 'scanner', 'capability': 'sast-ruby', 'applies': 'always'}
    neg3 = lambda m: any('not in the protected floor' in x for x in m.check_tree(floor, wf, reg3))
    check(neg3(cf), 'F-N3 a registry scanner outside the floor is refused')
    killed('M-floor-binding', mutant('scripts/capability_floor.py',
                                     '    for cap in sorted((c for c in by_cap if c not in floor_caps), key=str):',
                                     '    for cap in []:', 'm_bind'), neg3)
    # F-N4 / F-P4: a capability_selection candidate removed.
    reg4 = copy.deepcopy(reg)
    reg4['capability_selection']['go-sast']['candidates'].remove('sast-go/gosec')
    neg4 = lambda m: m.check_registry_base(reg4, reg, [], [], TODAY)
    p = neg4(cf)
    check(any("lost candidate 'sast-go/gosec'" in x for x in p), 'F-N4 a selection candidate removed silently', p)
    sel = {'selection': 'go-sast', 'candidate': 'sast-go/gosec', 'decision': 'KDEC-999', 'approved_by': 'security',
           'decided_on': '2026-11-01', 'reason': 'test'}
    p = cf.check_registry_base(reg4, reg, [sel], [], TODAY)
    check(not p, 'F-P4 the same removal with a selection tombstone holds', p)
    p = cf.check_registry_base(reg4, reg, [], [sel], TODAY)
    check(any('selection tombstone' in x and 'deleted or changed' in x for x in p), 'F-N4b a selection tombstone deleted', p)
    killed('M-selection', mutant('scripts/capability_floor.py',
                                 '    for sel, cand in sorted(selection_candidates(base_reg) - selection_candidates(head_reg)):',
                                 '    for sel, cand in []:', 'm_sel'), lambda m: bool(m.check_registry_base(reg4, reg, [], [], TODAY)))
    # F-N5: the push path, --base-ref end to end through main(), the base served from "git".
    d = tempfile.mkdtemp(prefix='floor-base-')
    try:
        head = dict(doc, floor=without)
        io.open(os.path.join(d, 'capability-floor.json'), 'w', encoding='utf-8').write(json.dumps(head))
        shutil.copy(os.path.join(ROOT, 'scanner-registry.yaml'), os.path.join(d, 'scanner-registry.yaml'))
        base_files = {'capability-floor.json': json.dumps(doc),
                      'scanner-registry.yaml': io.open(os.path.join(ROOT, 'scanner-registry.yaml'), encoding='utf-8').read()}
        real = cf.git_show
        cf.git_show = lambda root, ref, rel: '' if rel is None else base_files.get(rel)
        try:
            rc = cf.main(['--floor', os.path.join(d, 'capability-floor.json'), '--root', d, '--base-ref', 'BEFORE',
                          '--today', TODAY])
            check(rc == 1, 'F-N5 push path: a floor entry deleted, compared with --base-ref: exit 1 (got %s)' % rc)
            cf.git_show = lambda root, ref, rel: None
            rc = cf.main(['--floor', os.path.join(d, 'capability-floor.json'), '--root', d, '--base-ref', 'BEFORE'])
            check(rc == 2, 'F-N5b an unreadable base is exit 2, never HELD (got %s)' % rc)
        finally:
            cf.git_show = real
    finally:
        shutil.rmtree(d, ignore_errors=True)
    st = yaml.safe_load(io.open(os.path.join(ROOT, '.github', 'workflows', 'self-test.yml'), encoding='utf-8').read())
    step = next((s for s in st['jobs']['contract']['steps'] if 'capability_floor.py' in str(s.get('run'))), {})
    run = str(step.get('run') or '')
    line = next((ln for ln in run.splitlines() if 'capability_floor.py' in ln), '')
    check('--base-ref "$base"' in line and not line.lstrip().startswith('if') and 'github.event.before' in str(step.get('env')),
          'F-W the contract step compares the floor with its base on every event, push included', line)


def ke03():
    doc = floor_doc()
    floor = [e for e in doc['floor'] if e['capability'] != 'sast-go']
    rep = {'capability': 'sast-go', 'identities': ['gosec'], 'decision': 'KDEC-999', 'approved_by': 'security',
           'decided_on': '2026-11-01', 'reason': 'test', 'uncovered_gap': False, 'replacement': 'sast-semgrep'}
    strict = cf.policy_of(doc)
    check(strict == dict(cf.DEFAULT_POLICY, decision='KDEC-050') and strict['replacement_requires_proof']
          and strict['gap_decision_max_days'] == 90, 'S-0 the shipped setting is the stricter answer', strict)
    neg1 = lambda m: m.tombstone_problems(rep, floor, TODAY, strict)
    p, s = neg1(cf)
    check(s == cf.BREACHED and any('cites no proof' in x for x in p), 'S-N1 a replacement citing no proof (probe E1)', p)
    killed('M-proof', mutant('scripts/capability_floor.py', "        if policy.get('replacement_requires_proof'):",
                             '        if False:', 'm_proof'), lambda m: neg1(m)[1] == m.BREACHED)
    p, s = cf.tombstone_problems(dict(rep, replacement_proof='tests/prove_scanner_floor_shrink.py'), floor, TODAY, strict)
    check(s == cf.HELD and not p, 'S-P1 a replacement citing a real tests/ proof naming both: HELD', p)
    p, s = cf.tombstone_problems(dict(rep, replacement_proof='tests/../README.md'), floor, TODAY, strict)
    check(s == cf.BREACHED, 'S-N1b a proof path outside tests/ is refused', p)
    far = gap_tomb(expires='2099-12-31')
    neg2 = lambda m: m.tombstone_problems(far, floor, TODAY, strict)
    p, s = neg2(cf)
    check(s == cf.BREACHED and any('over the 90-day cap' in x for x in p), 'S-N2 a gap decision to 2099 (probe F1)', p)
    killed('M-cap', mutant('scripts/capability_floor.py', "    if cap_days and (_date(exp) - decided).days > int(cap_days):",
                           '    if False:', 'm_cap'), lambda m: neg2(m)[1] == m.BREACHED)
    p, s = cf.tombstone_problems(gap_tomb(), floor, TODAY, strict)
    check(s == cf.GAP, 'S-P2 a gap decision within 90 days: GAP_DECIDED', p)
    lax = {'replacement_requires_proof': False, 'gap_decision_max_days': None}
    check(cf.tombstone_problems(rep, floor, TODAY, lax)[1] == cf.HELD
          and cf.tombstone_problems(far, floor, TODAY, lax)[1] == cf.GAP,
          'S-P3 the seam: the lax one-line setting turns E1 into HELD and F1 into GAP_DECIDED')
    future = gap_tomb(decided='2027-01-01', expires='2027-02-01')
    check(cf.tombstone_problems(future, floor, TODAY, strict)[1] == cf.BREACHED, 'S-N4 decided_on in the future is refused')
    loose = dict(doc, tombstone_policy=lax)
    p = cf.policy_loosened(loose, doc)
    check(bool(p) and 'loosened' in p[0], 'S-N3 the policy loosened with no new decision: refused', p)
    check(not cf.policy_loosened(dict(doc, tombstone_policy=dict(lax, decision='KDEC-999')), doc),
          'S-P3b loosened under a new decision: accepted (the owner\'s answer is one line)')


def ke06(work):
    reg_text = io.open(os.path.join(ROOT, 'scanner-registry.yaml'), encoding='utf-8').read()
    floor_text = io.open(os.path.join(ROOT, 'capability-floor.json'), encoding='utf-8').read()

    def tree(name, reg, floor=floor_text):
        d = os.path.join(work, name)
        os.makedirs(d)
        io.open(os.path.join(d, 'scanner-registry.yaml'), 'w', encoding='utf-8').write(reg)
        io.open(os.path.join(d, 'capability-floor.json'), 'w', encoding='utf-8').write(floor)
        return os.path.join(d, 'scanner-registry.yaml')
    inv = rt.load_scanner_inventory()
    check(inv['state'] == rt.INVENTORY_ESTABLISHED and 'sbom' in inv['jobs'] and 'bound to 15 floor' in inv['note'],
          'I-P1 the real registry: ESTABLISHED, bound to the floor', inv['note'])
    sbom_line = next(ln for ln in reg_text.splitlines() if ln.startswith('  sbom:'))
    gone = tree('n19h', reg_text.replace(sbom_line + '\n', ''))
    neg1 = lambda m: m.load_scanner_inventory(gone)
    inv1 = neg1(rt)
    check(inv1['state'] == rt.INVENTORY_NOT_ESTABLISHED and 'sbom' in inv1['note'] and 'floor' in inv1['note'],
          'I-N1 (N19h) the sbom row deleted: NOT_ESTABLISHED naming sbom', inv1)
    lin = {'integrity': 'TAMPERED', 'events': []}
    entry = {'member_identities': ['x' * 40]}
    gaps = rt.population_gaps(entry, {}, lin, {}, [], True, inv1)
    check(bool(gaps) and 'sbom' in gaps[0], 'I-N1b the population gap names sbom', gaps)
    m_bind = mutant('scripts/reconcile_tickets.py', '    if not floor_caps or lost:', '    if False:', 'm_rt_bind')
    killed('M-bind', m_bind, lambda m: neg1(m)['state'] == m.INVENTORY_NOT_ESTABLISHED)
    block = '  sbom:\n    class: scanner\n    capability: sbom\n    applies: input.enable_sbom\n    composite: null\n'
    blk = tree('n19i', reg_text.replace(sbom_line + '\n', block))
    neg2 = lambda m: m.load_scanner_inventory(blk)
    inv2 = neg2(rt)
    check(inv2['state'] == rt.INVENTORY_NOT_ESTABLISHED and 'sbom' in inv2['note'] and 'shape' in inv2['note'],
          'I-N2 (N19i) the sbom row as a block mapping: NOT_ESTABLISHED naming sbom', inv2)
    # The block row is refused by TWO guards (the shape, and the floor binding a dropped row then
    # breaks). Reached-the-guard: with the binding removed (M-bind) the SHAPE guard still refuses by
    # its own message; with the shape guard removed as well (M-shape), the negative passes.
    if m_bind is not None:
        inv_b = neg2(m_bind)
        check(inv_b['state'] == rt.INVENTORY_NOT_ESTABLISHED and 'shape' in inv_b['note'],
              'I-N2 under M-bind: the shape guard itself refuses', inv_b['note'])
        both_src = io.open(os.path.join(ROOT, 'scripts', 'reconcile_tickets.py'), encoding='utf-8').read()
        if '    if unread:' in both_src:
            m_shape = types.ModuleType('m_rt_shape')
            m_shape.__file__ = os.path.join(ROOT, 'scripts', 'reconcile_tickets.py')
            exec(compile(both_src.replace('    if unread:', '    if False:', 1).replace(
                '    if not floor_caps or lost:', '    if False:', 1), m_shape.__file__, 'exec'), m_shape.__dict__)
            killed('M-shape (on top of M-bind)', m_shape, lambda m: neg2(m)['state'] == m.INVENTORY_NOT_ESTABLISHED)
        else:
            FAILS.append('M-shape could not be applied (the guard text moved)')
    fdoc = json.loads(floor_text)
    fdoc['floor'] = [e for e in fdoc['floor'] if e['capability'] != 'sast-go']
    fdoc['tombstones'] = [gap_tomb()]
    go_line = next(ln for ln in reg_text.splitlines() if ln.startswith('  sast-go:'))
    tg = tree('gap', reg_text.replace(go_line + '\n', ''), json.dumps(fdoc))
    inv3 = rt.load_scanner_inventory(tg)
    gaps = rt.population_gaps(entry, {}, lin, {}, [], True, inv3)
    check(inv3['state'] == rt.INVENTORY_ESTABLISHED and inv3.get('gap_tombstones') == ['sast-go']
          and bool(gaps) and 'sast-go was removed under a gap decision' in gaps[0],
          'I-N3 a capability tombstoned out under a gap decision: the population gap names it', gaps)


def ke05_and_bypass(work):
    check(not pp.check_codeowners(ROOT), 'O-P1 the real CODEOWNERS: every protected path solely the protected owner',
          pp.check_codeowners(ROOT)[:3])
    text = io.open(os.path.join(ROOT, 'CODEOWNERS'), encoding='utf-8').read()
    # The fixtures start from the TEMPLATE form of the real file: an adopted copy (the public mirror, a
    # consumer) names its real owners, and O-N3 needs a copy that still names the placeholder.
    declared, owner_rules = pp.parse(text)
    for real_owner in sorted({declared} | {o for _p, os_ in owner_rules for o in os_}, key=len, reverse=True):
        if real_owner and real_owner.startswith('@') and not pp.PLACEHOLDER.search(real_owner):
            text = re.sub(r'(?<![\w/@-])%s(?![\w/-])' % re.escape(real_owner), pp.PLACEHOLDER_OWNER, text)

    def root_with(name, owners, watermark=False):
        d = os.path.join(work, name)
        os.makedirs(d)
        io.open(os.path.join(d, 'CODEOWNERS'), 'w', encoding='utf-8').write(owners)
        os.makedirs(os.path.join(d, '.github', 'actions', 'resolve'))
        io.open(os.path.join(d, '.github', 'actions', 'resolve', 'action.yml'), 'w').write('x')
        if watermark:
            io.open(os.path.join(d, pp.WATERMARK), 'w').write('{}')
        return d
    d1 = root_with('o-n1', re.sub(r'(?m)^/\.github/\s.*\n', '', text))
    p = pp.check_codeowners(d1)
    check(any('.github/actions/resolve/action.yml' in x and 'unowned' in x for x in p), 'O-N1 /.github/ unowned', p)
    d2 = root_with('o-n2', text + '/scanner-registry.yaml @YOUR_ORG/replace-me-kit-control-owners @YOUR_ORG/anyone\n')
    neg2 = lambda m: any('scanner-registry.yaml' in x and 'ANY one owner' in x for x in m.check_codeowners(d2))
    check(neg2(pp), 'O-N2 a second owner on the registry line is refused')
    killed('M-sole-owner', mutant('scripts/protected_paths.py', '        elif hit[1] != [declared]:',
                                  '        elif not hit[1]:', 'm_sole'), neg2)
    d3 = root_with('o-n3', text, watermark=True)
    neg3 = lambda m: any('placeholder owner' in x for x in m.check_codeowners(d3))
    check(neg3(pp), 'O-N3 an adopted copy still naming the placeholder team is refused')
    killed('M-adopted', mutant('scripts/protected_paths.py', '    if adopted:\n', '    if False:\n', 'm_adopted'), neg3)
    real = text.replace('@YOUR_ORG/replace-me-kit-control-owners', '@acme/kit-control-owners').replace(
        '@YOUR_ORG/security-approvers', '@acme/security-approvers')
    d4 = root_with('o-p3', real, watermark=True)
    check(not pp.check_codeowners(d4), 'O-P3 the adopted copy with real teams holds', pp.check_codeowners(d4)[:2])
    # B-1: the evidence that a pull request can redefine "Self-test required".
    st_text = io.open(os.path.join(ROOT, '.github', 'workflows', 'self-test.yml'), encoding='utf-8').read()
    st = yaml.safe_load(st_text)
    on = st.get('on', st.get(True)) or {}
    req = st['jobs']['required']
    co = next(s for s in req['steps'] if 'checkout' in str(s.get('uses')))
    verdict = next(s for s in req['steps'] if s.get('id') == 'verdict')
    bypassable = ('pull_request' in on and 'pull_request_target' not in on and not (co.get('with') or {}).get('ref')
                  and 'scripts/selftest_required.py' in str(verdict.get('run')))
    check(bypassable, 'B-1 (evidence) "Self-test required" runs the pull request\'s own workflow and '
          'scripts/selftest_required.py: in-repo checks alone cannot stop a PR redefining it')
    rec = '| 2026-11-11 | KDEC-999 | .github/workflows/self-test.yml |'
    neg = lambda m: bool(m.check_change(['.github/workflows/self-test.yml'], [], []))
    check(neg(pp) and 'no decision record' in pp.check_change(['.github/workflows/self-test.yml'], [], [])[0],
          'B-N1 a change to self-test.yml with no decision record is refused')
    check(not pp.check_change(['.github/workflows/self-test.yml'], [rec], []), 'B-P1 the same change with a record holds')
    check(bool(pp.check_change(['scripts/selftest_required.py'], [rec], [])),
          'B-N2 a record that does not name the changed validator is refused')
    killed('M-guarded', mutant('scripts/protected_paths.py',
                               "    return any(path == g or (g.endswith('/') and path.startswith(g)) for g in CHANGE_GUARDED)",
                               '    return False', 'm_guarded'), neg)
    _decl, rules = pp.parse(text)
    for path in ('.github/workflows/self-test.yml', '.github/workflows/a-new-workflow.yml', 'scripts/selftest_required.py'):
        hit = pp.owners_of(rules, path)
        check(hit and hit[1] == [_decl], 'B-2 %s is owned solely by the protected owner' % path, hit)


def main():
    work = tempfile.mkdtemp(prefix='floor-shrink-')
    try:
        ke04()
        ke03()
        ke06(work)
        ke05_and_bypass(work)
    finally:
        shutil.rmtree(work, ignore_errors=True)
    if FAILS:
        print('FAIL: %d violation(s): %s' % (len(FAILS), '; '.join(FAILS)))
        return 1
    print('PASS: every shrink is refused by name; every guard is reached (each named mutant is killed).')
    return 0


if __name__ == '__main__':
    sys.exit(main())

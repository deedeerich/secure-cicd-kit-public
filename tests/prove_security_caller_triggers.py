#!/usr/bin/env python3
"""One security caller per repository, superseded PR runs cancelled, NVD left on PRs until proven
(cost redesign step 2; owner ruling 2, 2026-10-27, KDEC-033).

WHY THIS EXISTS

    W5 (the cost redesign proposal, section 2): the adoption sequence added templates/build-deploy.yml,
    whose `security` job calls reusable-security on the same push/pull_request to main as
    templates/security.yml, and nothing said to remove the latter -- the full suite ran twice per
    event. templates/security.yml had no `concurrency:`, so a superseded PR push kept billing.

    Owner ruling 2: one security caller per repository, and PROVE the replacement preserves every
    required security and deployment trigger and the `Security gate` check BEFORE the old caller is
    removed. This file is that proof, at fixture level (it reads the shipped templates; it does not
    run them on GitHub -- the Level 2 consumer run is the integration half, and is not claimed here).

WHAT IT ASSERTS

    T1  build-deploy's triggers cover security.yml's: the same events, the same branch filters, and
        no paths filter on either pull_request trigger (a path-filtered required workflow never
        starts, and its required check stays pending forever).
    T2  the `security` caller job has the same id in both, so the required check keeps its name:
        `security / Security gate`; and reusable-security's verdict job is still named `Security gate`.
    T3  build-deploy's `security` job calls the same reusable with the same `with:` and `secrets:`,
        is granted at least the permissions security.yml grants, and its `if:` is true on push,
        pull_request and a non-promotion dispatch. The one deliberate difference -- a PROMOTION
        dispatch scans nothing, because the promoted record carries its verdict -- is named.
    T4  the deployment triggers are untouched: build and verdict never run on pull_request, and
        nothing cancels a push or dispatch run.
    C1  both templates cancel a superseded run ON pull_request ONLY: cancel-in-progress is exactly
        `github.event_name == 'pull_request'`, and the group carries the run id for every other
        event, so a push to main is never cancelled and never queued behind another.
    D1  the adoption docs say build-deploy REPLACES security.yml, and security.yml's header says so.
    N1  templates/nvd-cve.yml stays on pull_request while parity with deps-scan is unproven. The
        parity check is computed here and its reasons printed; dropping pull_request without
        parity fails this proof.
    M*  mutations: `cancel-in-progress: true`, a paths filter, a renamed caller job and a dropped
        branch are each caught, so this proof can fail.

FAILED-FIRST: before the change security.yml has no concurrency and the docs do not say replace.

EXIT  0 all hold   1 a violation   2 could not be checked
"""
import copy
import io
import os
import re
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
SEC = os.path.join(ROOT, 'templates', 'security.yml')
BD = os.path.join(ROOT, 'templates', 'build-deploy.yml')
NVD = os.path.join(ROOT, 'templates', 'nvd-cve.yml')
RS = os.path.join(ROOT, '.github', 'workflows', 'reusable-security.yml')
NVD_RW = os.path.join(ROOT, '.github', 'workflows', 'reusable-nvd-cve.yml')
DEPS = os.path.join(ROOT, '.github', 'actions', 'deps-scan', 'action.yml')
USAGE = os.path.join(ROOT, 'docs', 'adoption', 'USAGE.md')

import yaml  # noqa: E402

WANT_CANCEL = "${{ github.event_name == 'pull_request' }}"
WANT_GROUP = ("${{ github.workflow }}-${{ github.event_name == 'pull_request' && "
              "format('pr-{0}', github.event.pull_request.number) || github.run_id }}")


def load(p):
    return yaml.safe_load(io.open(p, encoding='utf-8'))


def on_of(doc):
    # PyYAML reads the bare key `on` as boolean True.
    return doc.get('on', doc.get(True)) or {}


def norm_on(on):
    out = {}
    for ev, spec in (on or {}).items():
        if not isinstance(spec, dict):      # `schedule:` is a list of crons
            out[ev] = {'_': spec}
            continue
        out[ev] = {k: (sorted(v) if isinstance(v, list) else v) for k, v in spec.items()}
    return out


def kit_path(uses):
    return str(uses or '').split('@', 1)[0].split('/', 1)[-1]


def caller_if_true(cond, event, promote=''):
    """Evaluate the two caller `if:` shapes the templates use, for one event."""
    c = ' '.join(str(cond or '').split())
    if not c:
        return True
    if c == "inputs.promote_from_run_id == ''":
        # On push and pull_request `inputs` is empty, so the comparison is '' == ''.
        return (promote if event == 'workflow_dispatch' else '') == ''
    if c == "github.event_name != 'pull_request' && inputs.promote_from_run_id == ''":
        return event != 'pull_request' and \
            (promote if event == 'workflow_dispatch' else '') == ''
    raise ValueError('unrecognised caller condition: %r' % c)


def check_concurrency(doc, name):
    bad = []
    cc = doc.get('concurrency')
    if not isinstance(cc, dict):
        return ['%s: no workflow-level concurrency; a superseded PR push keeps billing' % name]
    if ' '.join(str(cc.get('cancel-in-progress')).split()) != WANT_CANCEL:
        bad.append('%s: cancel-in-progress is %r, want %s (pull_request ONLY; a push to main '
                   'must never be cancelled)' % (name, cc.get('cancel-in-progress'), WANT_CANCEL))
    if ' '.join(str(cc.get('group')).split()) != WANT_GROUP:
        bad.append('%s: concurrency group is %r, want %s (the run id for every non-PR event, so '
                   'pushes and dispatches never cancel or queue each other)'
                   % (name, cc.get('group'), WANT_GROUP))
    return bad


def check_pair(sec, bd, rs):
    bad = []
    s_on, b_on = norm_on(on_of(sec)), norm_on(on_of(bd))
    # T1
    for ev, spec in s_on.items():
        if ev not in b_on:
            bad.append('T1 build-deploy lacks the %s trigger security.yml has' % ev)
            continue
        for k in ('branches', 'branches-ignore', 'tags', 'types'):
            if spec.get(k) != b_on[ev].get(k):
                bad.append('T1 %s.%s differs: security.yml %r, build-deploy %r'
                           % (ev, k, spec.get(k), b_on[ev].get(k)))
    for name, on in (('security.yml', s_on), ('build-deploy.yml', b_on)):
        pr = on.get('pull_request') or {}
        for k in ('paths', 'paths-ignore'):
            if k in pr:
                bad.append('T1 %s pull_request carries %s: a required check whose workflow never '
                           'starts stays pending forever' % (name, k))
    # T2
    sj, bj = (sec.get('jobs') or {}), (bd.get('jobs') or {})
    s_callers = [j for j, v in sj.items() if 'reusable-security.yml' in str(v.get('uses', ''))]
    b_callers = [j for j, v in bj.items() if 'reusable-security.yml' in str(v.get('uses', ''))]
    if s_callers != ['security'] or b_callers != ['security']:
        bad.append('T2 the reusable-security caller job must be `security` in both (one each); '
                   'security.yml %r, build-deploy %r' % (s_callers, b_callers))
    for j in s_callers + b_callers:
        if (sj.get(j) or bj.get(j) or {}).get('name'):
            bad.append('T2 caller job %s carries a name:, which renames the required check' % j)
    gate = ((rs.get('jobs') or {}).get('security-gate') or {}).get('name')
    if gate != 'Security gate':
        bad.append('T2 reusable-security verdict job is named %r, not "Security gate"' % gate)
    if bad:
        return bad
    s, b = sj['security'], bj['security']
    # T3
    if kit_path(s.get('uses')) != kit_path(b.get('uses')):
        bad.append('T3 the callers call different reusables: %r vs %r' % (s.get('uses'), b.get('uses')))
    if (s.get('with') or {}) != (b.get('with') or {}):
        bad.append('T3 with: differs: %r vs %r' % (s.get('with'), b.get('with')))
    if (s.get('secrets') or {}) != (b.get('secrets') or {}):
        bad.append('T3 secrets: differ: %r vs %r' % (s.get('secrets'), b.get('secrets')))
    s_perm = s.get('permissions') or sec.get('permissions') or {}
    b_perm = b.get('permissions') or bd.get('permissions') or {}
    for k, v in s_perm.items():
        if b_perm.get(k) != v:
            bad.append('T3 build-deploy security job grants %s=%r, security.yml grants %r'
                       % (k, b_perm.get(k), v))
    for ev in s_on:
        try:
            if not caller_if_true(b.get('if'), ev):
                bad.append('T3 build-deploy security job does not run on %s' % ev)
        except ValueError as e:
            bad.append('T3 %s' % e)
    try:
        promo = caller_if_true(b.get('if'), 'workflow_dispatch', promote='123')
    except ValueError as e:
        promo = None
        bad.append('T3 %s' % e)
    if promo is not False:
        bad.append('T3 the promotion dispatch was expected to scan nothing (the promoted record '
                   'carries the verdict); it now %s' % ('scans' if promo else 'is unreadable'))
    # T4
    for j in ('build', 'verdict'):
        cond = (bj.get(j) or {}).get('if')
        for ev, want in (('pull_request', False), ('push', True), ('workflow_dispatch', True)):
            try:
                if caller_if_true(cond, ev) != want:
                    bad.append('T4 %s runs=%s on %s, want %s' % (j, not want, ev, want))
            except ValueError as e:
                bad.append('T4 %s: %s' % (j, e))
    # C1
    bad += check_concurrency(sec, 'security.yml')
    bad += check_concurrency(bd, 'build-deploy.yml')
    return bad


def nvd_parity():
    """-> list of reasons parity with deps-scan is NOT proven (empty = proven)."""
    why = []
    rw = load(NVD_RW)
    deps = load(DEPS)
    tv = None
    for j in (rw.get('jobs') or {}).values():
        for s in j.get('steps') or []:
            if s.get('id') == 'trivy_fs':
                tv = s
    dv = None
    for s in ((deps.get('runs') or {}).get('steps') or []):
        if 'TRIVY_OUTPUT' in (s.get('env') or {}) and 'trivy-deps' in str((s.get('env') or {}).get('TRIVY_OUTPUT')):
            dv = s
    if not tv or not dv:
        return ['the two Trivy steps could not both be located, so nothing is proven']
    te, de = tv.get('env') or {}, dv.get('env') or {}
    ts = set(str(te.get('TRIVY_SCANNERS') or 'vuln,secret').split(','))
    ds = set(str(de.get('TRIVY_SCANNERS') or 'vuln,secret').split(','))
    if ts != ds:
        why.append('scanner sets differ: NVD PR pass %s, deps-scan %s' % (sorted(ts), sorted(ds)))
    if str(te.get('SCAN_REF')) != str(de.get('SCAN_REF')):
        why.append('scan roots differ: NVD scans %r, deps-scan scans %r (the caller\'s `paths`)'
                   % (te.get('SCAN_REF'), de.get('SCAN_REF')))
    tmpl = load(NVD)
    w = ((tmpl.get('jobs') or {}).get('cve') or {}).get('with') or {}
    if 'trivy_fail_severities' in w:
        why.append('the NVD caller sets its own trivy_fail_severities (%r) and routes its own '
                   'routing_result; no equivalence to the security gate\'s per-tier policy is '
                   'established' % w.get('trivy_fail_severities'))
    return why


def check_nvd():
    bad = []
    why = nvd_parity()
    on = norm_on(on_of(load(NVD)))
    print('N1 NVD/deps-scan PR parity: %s' % ('PROVEN' if not why else 'UNPROVEN'))
    for w in why:
        print('     - %s' % w)
    if why and 'pull_request' not in on:
        bad.append('N1 templates/nvd-cve.yml dropped pull_request while parity with deps-scan is '
                   'unproven (owner ruling 2: off pull_request ONLY if parity is proven)')
    return bad


def check_docs():
    bad = []
    u = io.open(USAGE, encoding='utf-8').read()
    if not re.search(r'build-deploy\.yml`?\)?[^\n]*\bREPLACES\b[^\n]*security\.yml', u):
        bad.append('D1 docs/adoption/USAGE.md does not say build-deploy.yml REPLACES security.yml '
                   '(one security caller per repository)')
    head = io.open(SEC, encoding='utf-8').read().split('\nname:', 1)[0]
    if 'REPLACES' not in head or 'build-deploy.yml' not in head:
        bad.append('D1 templates/security.yml\'s header does not say build-deploy.yml REPLACES it')
    return bad


def mutations(sec, bd, rs):
    """Each mutant must be caught; -> list of mutants that went undetected."""
    blind = []
    m = copy.deepcopy(sec)
    m.setdefault('concurrency', {})['cancel-in-progress'] = True
    if not check_pair(m, bd, rs):
        blind.append('cancel-in-progress: true on security.yml')
    m = copy.deepcopy(bd)
    on_of(m).setdefault('pull_request', {})['paths'] = ['src/**']
    if not check_pair(sec, m, rs):
        blind.append('a paths filter on build-deploy pull_request')
    m = copy.deepcopy(bd)
    m['jobs']['scan'] = m['jobs'].pop('security')
    if not check_pair(sec, m, rs):
        blind.append('the caller job renamed scan (required check becomes scan / Security gate)')
    m = copy.deepcopy(bd)
    on_of(m)['push']['branches'] = ['release']
    if not check_pair(sec, m, rs):
        blind.append('build-deploy push narrowed to another branch')
    return blind


def main():
    sec, bd, rs = load(SEC), load(BD), load(RS)
    bad = check_pair(sec, bd, rs)
    bad += check_nvd()
    bad += check_docs()
    blind = mutations(sec, bd, rs)
    bad += ['M mutation went undetected: %s' % b for b in blind]
    for b in bad:
        print('VIOLATION: ' + b)
    if bad:
        print('FAIL: %d violation(s)' % len(bad))
        return 1
    print('PASS: build-deploy.yml keeps every trigger and the `security / Security gate` check of '
          'security.yml, so it replaces it; both cancel superseded runs on pull_request only; NVD '
          'stays on pull_request while parity is unproven; 4 mutations caught.')
    return 0


if __name__ == '__main__':
    sys.exit(main())

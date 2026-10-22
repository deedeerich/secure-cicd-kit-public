#!/usr/bin/env python3
"""Check reusable-security.yml against scanner-registry.yaml, totally and in both directions.

WHY THIS EXISTS

    Decomposition plan §E.3, §7 step 10. `tests/check_gate.py` compares the gate's `needs:` against
    the job list. That is one enumeration. The gate's scanner LOOP -- the `needs.<job>.result` it
    actually reads -- is a second, and nothing compared them. `image-scan` once sat in `needs` and
    not in the loop: the gate waited for the container scan and never read what it said.

    A registry makes the comparison arithmetic. For every registered job:

      1  the job exists
      2  once a composite is named, the job uses it through `$/`
      3  security-gate.needs contains it, and the gate step reads `needs.<job>.result`
      4  report.needs contains it                                         (scanners)
      5  its capability is registered for reusable-security.yml           (scanners, gate)

    and the half that matters most: no job exists that is not registered.

    Phase 2 then moves logic into composites one job at a time, and this check must stay green after
    every step. That is what makes each step revertible on its own.

WHAT IT CANNOT ESTABLISH
    What the gate DECIDES from a result. tests/prove_bootstrap_failure.py runs the gate for that.

EXIT
    0  the workflow and the registry agree completely
    1  a disagreement
    2  could not be checked -- UNKNOWN, never PASS
"""
import io
import os
import re
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, HERE)
WF = os.path.join(ROOT, '.github', 'workflows', 'reusable-security.yml')
REG = os.path.join(ROOT, 'scanner-registry.yaml')
GATE, REPORT = 'security-gate', 'report'
CLASSES = {'scanner', 'infrastructure', 'evidence', 'gate', 'governance'}
# A GOVERNANCE JOB RUNS AFTER THE GATE AND MUST NOT BE ABLE TO FAIL IT. propose-ledger's only
# authority is a pull request (SINGLE_PIPELINE_TARGET.md section 9.3); a job the gate waited for
# could not run after the gate, and a proposal that could fail a verdict would make the ledger a
# scanner output. So for this class the rule inverts: NOT in the gate's needs, and it must need
# `report`, whose findings file it consumes. Its write scope is held by
# tests/prove_propose_ledger_job_scope.py, not here.
AFTER_GATE = {'governance'}


def as_list(v):
    return [v] if isinstance(v, str) else list(v or [])


def composite_on_disk(comp):
    """True when .github/actions/<comp>/action.yml (or .yaml) exists in this repository."""
    base = os.path.join(ROOT, '.github', 'actions', comp)
    return any(os.path.isfile(os.path.join(base, f)) for f in ('action.yml', 'action.yaml'))


def check(doc, reg, capabilities, composite_exists=composite_on_disk):
    """-> list of problems. Pure, so the self-test can feed it broken inputs.

    `composite_exists(name)` answers whether the named composite is on disk. A job that `uses:` a
    composite which does not exist fails at RUN time, on the runner, as "Can't find action.yml"
    -- every static check here would have agreed with itself while the scanner never ran (L64)."""
    problems = []
    jobs = doc.get('jobs') or {}
    rows = reg.get('jobs') or {}
    if not rows:
        return ['the registry has no rows; a denominator of zero proves nothing']

    gate = jobs.get(GATE) or {}
    gate_needs = set(as_list(gate.get('needs')))
    # A value reaches the gate script through `env:` (L38; and a script holding expressions is a
    # template GitHub caps at 21,000 characters), so an env entry counts as READ only when the script
    # actually uses its variable -- an unused env entry is waiting, not enforcing.
    parts = []
    for st in (gate.get('steps') or []):
        run = str(st.get('run') or '')
        parts.append(run)
        for k, v in (st.get('env') or {}).items():
            if re.search(r'\$\{?%s\b' % re.escape(str(k)), run):
                parts.append(str(v))
    gate_text = '\n'.join(parts)
    report_needs = set(as_list((jobs.get(REPORT) or {}).get('needs')))

    for name in sorted(set(jobs) - set(rows)):
        problems.append('%s: a job with no registry row. Unregistered is unenforced.' % name)

    for name, row in sorted(rows.items()):
        row = row or {}
        cls = row.get('class')
        if cls not in CLASSES:
            problems.append('%s: class %r is not one of %s' % (name, cls, sorted(CLASSES)))
            continue
        job = jobs.get(name)
        if job is None:
            problems.append('%s: registered, but no such job exists' % name)
            continue
        comp = row.get('composite')
        if comp:
            want = '$/.github/actions/%s' % comp
            used = [s.get('uses') for s in (job.get('steps') or []) if s.get('uses')]
            if want not in used:
                problems.append('%s: registered composite %s, but the job does not use it '
                                '(uses: %s)' % (name, want, used or 'none'))
            if not composite_exists(comp):
                problems.append('%s: registered composite %s has no action.yml under '
                                '.github/actions/%s -- the job would fail on the runner, not here'
                                % (name, want, comp))
        if cls in AFTER_GATE:
            if name in gate_needs:
                problems.append('%s: a %s job is in %s.needs -- the gate must never wait for a job '
                                'that runs after it, and a proposal must never be able to fail a '
                                'verdict' % (name, cls, GATE))
            if REPORT not in as_list(job.get('needs')):
                problems.append('%s: a %s job that does not need %s, whose findings file it consumes'
                                % (name, cls, REPORT))
            continue
        if cls == 'gate':
            pass
        elif name not in gate_needs:
            problems.append('%s: not in %s.needs -- the gate does not wait for it' % (name, GATE))
        elif not re.search(r'needs\.%s\.result' % re.escape(name), gate_text):
            problems.append('%s: in %s.needs but the gate never reads needs.%s.result -- '
                            'waiting for a job is not enforcing on it' % (name, GATE, name))
        if cls == 'scanner' and name not in report_needs:
            problems.append('%s: a scanner the report does not wait for' % name)
        if cls in ('scanner', 'gate'):
            cap = row.get('capability')
            if not cap:
                problems.append('%s: a %s with no capability' % (name, cls))
            elif cap not in capabilities:
                problems.append('%s: capability %r is not registered for reusable-security.yml '
                                'in tests/reconcile_validation.py' % (name, cap))
    return problems


def self_test():
    """The checker must fail on each defect it claims to catch, or it proves nothing."""
    base_doc = {'jobs': {
        's1': {}, 'infra': {},
        REPORT: {'needs': ['s1']},
        GATE: {'needs': ['s1', 'infra', REPORT],
               'steps': [{'run': 'x=${{ needs.s1.result }} ${{ needs.infra.result }} '
                                 '${{ needs.report.result }}'}]},
        'gov': {'needs': REPORT}}}
    base_reg = {'jobs': {'s1': {'class': 'scanner', 'capability': 'c1'},
                         'infra': {'class': 'infrastructure'},
                         REPORT: {'class': 'evidence'},
                         GATE: {'class': 'gate', 'capability': 'g'},
                         'gov': {'class': 'governance'}}}
    caps = {'c1', 'g'}
    import copy

    real = globals()['check']

    def on_disk(_comp):
        return True

    def check(d, r, c, composite_exists=on_disk):
        return real(d, r, c, composite_exists)
    if check(base_doc, base_reg, caps):
        return 'the control failed: %s' % check(base_doc, base_reg, caps)
    cases = []
    d = copy.deepcopy(base_doc); d['jobs']['rogue'] = {}
    cases.append(('unregistered job', d, base_reg, caps))
    d = copy.deepcopy(base_doc); d['jobs'][GATE]['steps'][0]['run'] = '${{ needs.infra.result }}'
    cases.append(('gate waits but never reads (the image-scan defect)', d, base_reg, caps))
    d = copy.deepcopy(base_doc); d['jobs'][GATE]['needs'].remove('infra')
    cases.append(('gate does not wait for infrastructure', d, base_reg, caps))
    d = copy.deepcopy(base_doc); d['jobs'][REPORT]['needs'] = []
    cases.append(('report does not wait for a scanner', d, base_reg, caps))
    cases.append(('capability unregistered', base_doc, base_reg, {'g'}))
    r = copy.deepcopy(base_reg); r['jobs']['s1']['composite'] = 'scan-s1'
    cases.append(('composite named but not used', base_doc, r, caps))
    d = copy.deepcopy(base_doc)
    d['jobs']['s1']['steps'] = [{'uses': '$/.github/actions/scan-s1'}]
    cases.append(('composite used but absent from .github/actions',
                  d, r, caps, lambda _c: False))
    # The inverted rule for a post-gate job: the gate waiting for it, or it not consuming the
    # report, is each a defect.
    d = copy.deepcopy(base_doc); d['jobs'][GATE]['needs'].append('gov')
    cases.append(('gate waits for a governance job', d, base_reg, caps))
    d = copy.deepcopy(base_doc); d['jobs']['gov']['needs'] = ['s1']
    cases.append(('governance job does not need the report', d, base_reg, caps))
    for case in cases:
        label, d, r, c = case[:4]
        exists = case[4] if len(case) > 4 else on_disk
        if not check(d, r, c, exists):
            return 'did not catch: %s' % label
    # The composite case must fail ONLY for the absence: the same doc with the file present passes.
    d = copy.deepcopy(base_doc)
    d['jobs']['s1']['steps'] = [{'uses': '$/.github/actions/scan-s1'}]
    r = copy.deepcopy(base_reg); r['jobs']['s1']['composite'] = 'scan-s1'
    if check(d, r, caps):
        return 'the composite control failed: %s' % check(d, r, caps)
    return None


def main():
    try:
        import yaml
        import reconcile_validation as rv
    except ImportError as e:
        print('UNKNOWN: %s' % e)
        return 2
    err = self_test()
    if err:
        print('SELF-TEST FAILED: %s. A checker that misses its own defect class proves nothing.'
              % err)
        return 1
    print('self-test ok: 9 seeded defects caught, the controls pass')
    doc = yaml.safe_load(io.open(WF, encoding='utf-8'))
    reg = yaml.safe_load(io.open(REG, encoding='utf-8'))
    caps = set(rv.CAPABILITY_REGISTRY.get('reusable-security.yml') or [])
    problems = check(doc, reg, caps)
    n = len(reg.get('jobs') or {})
    print('registry rows: %d   workflow jobs: %d' % (n, len(doc.get('jobs') or {})))
    if problems:
        for p in problems:
            print('FAIL: %s' % p)
        return 1
    print('PASS: every job is registered, every registered job is waited for and read by the gate,')
    print('      every scanner reaches the report, and every capability is registered.')
    return 0


if __name__ == '__main__':
    sys.exit(main())

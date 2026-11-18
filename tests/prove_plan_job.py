#!/usr/bin/env python3
"""G1 `plan`: kit-scripts + discover + resolve in one job, with the kit scripts materialised BEFORE
the checkout as a tested invariant (cost redesign step 3; owner ruling 1, 2026-10-27, KDEC-033).

WHY ONE JOB

    The three upstream jobs did ~20 s of work between them and billed 3 minutes (W2). Merged they
    bill 1. None of them holds a scanner, so plug-and-play is unchanged.

WHAT THE MERGE MUST NOT CHANGE

    The three were separate jobs, and the gate reads each AS ITSELF (needs.<job>.result): a failed
    bootstrap, a dead discovery and a dead resolver each fail the gate on their own, and a resolver
    failure never stopped a scanner from starting (no scanner waited for it). So:

    P1  kit-scripts, discover and resolve no longer exist as jobs; `plan` does, and nothing reads
        needs.kit-scripts / needs.discover / needs.resolve any more.
    P2  ORDER: every kit-scripts step -- write, pin, redact, publish -- runs before the first
        checkout, so consumer content is never in the workspace while the scripts are written,
        digested and uploaded. Nothing before the checkout is a `uses:` other than the upload, and
        everything published is under /tmp.
    P3  least privilege: the union of the three (contents: read, security-events: read), no write,
        no id-token.
    P4  every output the three jobs published is still published, under the same name (resolve's
        `state` becomes `resolve_state`, the one collision), plus one RESULT per part.
    P5  the per-part results reproduce the old job results, run through the marker steps as shipped:
        kit_scripts_result is the job status after the bootstrap steps; discover_result is success
        only when checkout, the survey, the platform probe and the CodeQL plan all succeeded;
        resolve_result is the resolver's own outcome (skipped when discovery did not complete).
    P6  discovery still runs when the bootstrap failed (it was an independent job); the resolver
        runs only on a completed discovery and is continue-on-error, so its failure fails the GATE
        (through resolve_result) without failing `plan` -- the scanners still start, as before.
    P7  the gate reads the three results from plan's per-part outputs, and an ABSENT output (plan
        torn down) is not `success`, so it still fails the gate.
    M*  mutations: checkout moved first; resolver without continue-on-error; discovery gated on the
        bootstrap; a write permission -- each caught.

FAILED-FIRST: before the merge there is no `plan` job.

EXIT  0 all hold   1 a violation   2 could not be checked
"""
import copy
import io
import os
import re
import shutil
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, HERE)

import yaml  # noqa: E402

WF = os.path.join(ROOT, '.github', 'workflows', 'reusable-security.yml')
BOOT_NAMES = ('Write the canonical scripts', 'Pin what was written, and assert it is what this file promises',
              'Redact credential material before upload', 'Publish them for every other job in this run')

# Outputs the three jobs published at fecc3a5, by name (resolve's `state` renamed resolve_state).
DISCOVER_OUT = ('python', 'node', 'go', 'dotnet', 'java', 'cpp', 'php', 'kotlin', 'swift', 'mobile',
                'iac', 'workflows', 'shell', 'powershell', 'dockerfile', 'state', 'unsupported',
                'coverage_gaps', 'coverage_gap_count', 'ghas_available', 'code_scanning',
                'secret_scanning', 'push_protection', 'dependabot_alerts', 'dependabot_updates',
                'dependabot_config', 'visibility', 'platform_source', 'push_ruleset', 'branch_gate',
                'local_baseline', 'codeql_matrix')
RESOLVE_OUT = ('versions', 'capability', 'version_gaps', 'version_gap_count',
               'version_undetermined_count', 'coverage', 'plan', 'selection', 'substitutions',
               'capability_gaps', 'capability_gap_count', 'capped_jobs', 'proven_gap_jobs',
               'not_selected_jobs', 'fitness_notes', 'dependabot_state', 'dependabot_open_alerts',
               'dependabot_basis', 'dependabot_owner_role', 'dataflow_capability', 'platform_owners')
PARTS = ('kit_scripts_result', 'discover_result', 'resolve_result')


def load():
    return yaml.safe_load(io.open(WF, encoding='utf-8'))


def is_checkout(s):
    return 'actions/checkout' in str(s.get('uses', ''))


def structure(doc):
    """-> violations of P1-P4, P6, P7 over a parsed workflow."""
    bad = []
    jobs = doc.get('jobs') or {}
    for gone in ('kit-scripts', 'discover', 'resolve'):
        if gone in jobs:
            bad.append('P1 job %s still exists (G1 merges it into plan)' % gone)
    plan = jobs.get('plan')
    if not plan:
        return bad + ['P1 no `plan` job']
    text = yaml.safe_dump(doc, width=100000)
    for ref in ('needs.kit-scripts.', 'needs.discover.', 'needs.resolve.'):
        if ref in text:
            bad.append('P1 the workflow still reads %s* (a job that no longer exists reads as '
                       'empty, never as an error)' % ref)
    for jid, job in jobs.items():
        n = job.get('needs') or []
        n = [n] if isinstance(n, str) else n
        if any(x in n for x in ('kit-scripts', 'discover', 'resolve')):
            bad.append('P1 job %s still needs a merged job: %s' % (jid, n))
    # P2
    steps = plan.get('steps') or []
    names = [s.get('name') or '' for s in steps]
    co = [i for i, s in enumerate(steps) if is_checkout(s)]
    if len(co) != 1:
        bad.append('P2 plan must check out exactly once; found %d' % len(co))
    else:
        first = co[0]
        for n in BOOT_NAMES:
            if n not in names:
                bad.append('P2 bootstrap step %r is missing from plan' % n)
            elif names.index(n) > first:
                bad.append('P2 bootstrap step %r runs AFTER the checkout: consumer content would '
                           'be in the workspace while the kit scripts are written' % n)
        for s in steps[:first]:
            u = str(s.get('uses', ''))
            if u and 'upload-artifact' not in u:
                bad.append('P2 %r runs an action (%s) before the checkout' % (s.get('name'), u))
            if 'upload-artifact' in u:
                paths = [p.strip() for p in str((s.get('with') or {}).get('path', '')).split('\n') if p.strip()]
                if not paths or any(not p.startswith('/tmp/') for p in paths):
                    bad.append('P2 the bootstrap upload publishes outside /tmp: %r' % paths)
            if s.get('working-directory'):
                bad.append('P2 %r sets a working-directory before the checkout' % s.get('name'))
    # P3
    perm = plan.get('permissions')
    if perm != {'contents': 'read', 'security-events': 'read'}:
        bad.append('P3 plan permissions are %r, want contents: read, security-events: read' % perm)
    # P4
    outs = plan.get('outputs') or {}
    for k in DISCOVER_OUT + RESOLVE_OUT + PARTS + ('resolve_state',):
        if k not in outs:
            bad.append('P4 plan does not publish %s' % k)
    if 'resolve_state' in outs and 'steps.resolve.outputs.state' not in str(outs['resolve_state']):
        bad.append('P4 resolve_state is not the resolver\'s own state: %r' % outs['resolve_state'])
    if 'state' in outs and 'steps.d.outputs.state' not in str(outs['state']):
        bad.append('P4 `state` must stay discovery\'s state: %r' % outs['state'])
    # P6
    by_id = {s.get('id'): s for s in steps if s.get('id')}
    for sid in ('d', 'platform'):
        cond = str((by_id.get(sid) or {}).get('if', ''))
        if '!cancelled()' not in cond.replace(' ', ''):
            bad.append('P6 discovery step %s is not `!cancelled()`: a bootstrap failure would '
                       'now also kill discovery (they were independent jobs)' % sid)
    rs = by_id.get('resolve') or {}
    if rs.get('continue-on-error') is not True:
        bad.append('P6 the resolver is not continue-on-error: its failure would fail plan and '
                   'skip every scanner, which a separate resolve job never did')
    if "steps.disc_part.outputs.discover_result == 'success'" not in ' '.join(str(rs.get('if', '')).split()):
        bad.append('P6 the resolver must run only on a completed discovery (it needed discover)')
    # P7
    gate = jobs.get('security-gate') or {}
    env = {}
    for s in gate.get('steps') or []:
        if s.get('id') == 'gate':
            env = s.get('env') or {}
    run = str(next((s.get('run') for s in gate.get('steps') or [] if s.get('id') == 'gate'), ''))
    for part in PARTS:
        want = '${{ needs.plan.outputs.%s }}' % part
        keys = [k for k, v in env.items() if str(v).strip() == want]
        if not keys:
            bad.append('P7 the gate step reads no env entry of %s' % want)
        elif not any(re.search(r'\$\{?%s\b' % re.escape(k), run) for k in keys):
            bad.append('P7 the gate step maps %s to %s and never uses it' % (want, keys))
    return bad


def run_marker(bash, step, ctx):
    import _step_harness as h
    ws = tempfile.mkdtemp(prefix='plan-')
    try:
        return h.run(bash, step, ctx, ws)
    finally:
        shutil.rmtree(ws, ignore_errors=True)


def semantics(bash, doc):
    """P5: the marker steps reproduce the separate jobs' results."""
    bad = []
    steps = {s.get('id'): s for s in ((doc.get('jobs') or {}).get('plan') or {}).get('steps') or []
             if s.get('id')}
    for sid in ('ks_part', 'disc_part', 'res_part'):
        if sid not in steps:
            bad.append('P5 no marker step %s' % sid)
        elif 'always()' not in str(steps[sid].get('if', '')):
            bad.append('P5 marker %s does not run if: always(); a failure would leave its result '
                       'unset' % sid)
    if bad:
        return bad
    for status in ('success', 'failure', 'cancelled'):
        r = run_marker(bash, steps['ks_part'], {'job.status': status})
        got = r['outputs'].get('kit_scripts_result')
        if r['rc'] != 0 or got != status:
            bad.append('P5 kit-scripts job status %s -> kit_scripts_result %r (rc %d)' % (status, got, r['rc']))
    ok = 'success'
    cases = [((ok, ok, ok, ok), 'success'),
             (('failure', 'skipped', 'skipped', 'skipped'), 'failure'),
             ((ok, 'failure', ok, 'skipped'), 'failure'),
             ((ok, ok, 'failure', ok), 'failure'),
             ((ok, ok, ok, 'failure'), 'failure'),
             (('cancelled', 'skipped', 'skipped', 'skipped'), 'cancelled'),
             (('', '', '', ''), 'failure')]
    for (co, d, pl, cq), want in cases:
        ctx = {'steps.co.outcome': co, 'steps.d.outcome': d, 'steps.platform.outcome': pl,
               'steps.cqm.outcome': cq}
        r = run_marker(bash, steps['disc_part'], ctx)
        got = r['outputs'].get('discover_result')
        if r['rc'] != 0 or got != want:
            bad.append('P5 discover parts %s -> %r, want %r' % ((co, d, pl, cq), got, want))
    for outcome, want in (('success', 'success'), ('failure', 'failure'), ('skipped', 'skipped'),
                          ('cancelled', 'cancelled'), ('', 'failure')):
        r = run_marker(bash, steps['res_part'], {'steps.resolve.outcome': outcome})
        got = r['outputs'].get('resolve_result')
        if r['rc'] != 0 or got != want:
            bad.append('P5 resolver outcome %r -> resolve_result %r, want %r' % (outcome, got, want))
    return bad


def mutations(doc):
    blind = []
    plan_steps = lambda d: d['jobs']['plan']['steps']  # noqa: E731
    m = copy.deepcopy(doc)
    st = plan_steps(m)
    i = [k for k, s in enumerate(st) if is_checkout(s)][0]
    st.insert(0, st.pop(i))
    if not structure(m):
        blind.append('checkout moved to the first step')
    m = copy.deepcopy(doc)
    for s in plan_steps(m):
        if s.get('id') == 'resolve':
            s.pop('continue-on-error', None)
    if not structure(m):
        blind.append('resolver without continue-on-error')
    m = copy.deepcopy(doc)
    for s in plan_steps(m):
        if s.get('id') == 'd':
            s['if'] = 'success()'
    if not structure(m):
        blind.append('discovery gated on the bootstrap succeeding')
    m = copy.deepcopy(doc)
    m['jobs']['plan']['permissions'] = {'contents': 'write', 'security-events': 'read'}
    if not structure(m):
        blind.append('contents: write on plan')
    return blind


def main():
    import _step_harness as h
    doc = load()
    bad = structure(doc)
    if not any(b.startswith('P1 no `plan`') for b in bad):
        bash, why = h.usable_bash()
        if not bash:
            print('UNKNOWN: no usable bash (%s); the marker steps cannot be run.' % why)
            return 2
        bad += semantics(bash, doc)
        bad += ['M mutation went undetected: %s' % b for b in mutations(doc)]
    for b in bad:
        print('VIOLATION: ' + b)
    if bad:
        print('FAIL: %d violation(s)' % len(bad))
        return 1
    print('PASS: plan merges kit-scripts, discover and resolve; the kit scripts are written, '
          'pinned, redacted and published before the checkout; the per-part results reproduce '
          'the three job results; the gate reads them; 4 mutations caught.')
    return 0


if __name__ == '__main__':
    sys.exit(main())

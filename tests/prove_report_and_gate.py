#!/usr/bin/env python3
"""G3 report-and-gate: the evidence and the verdict in one job, still named `Security gate`
(cost redesign step 3; owner ruling 1, 2026-10-27, KDEC-033).

WHY ONE JOB

    `report` and `security-gate` were both terminal and `always()`, did ~16 s of work and billed 2
    minutes (W2). Merged they bill 1. Neither holds a scanner.

WHAT THE MERGE MUST NOT CHANGE

    R1  `report` no longer exists; `security-gate` does, is still named `Security gate` (consumers
        require `security / Security gate`) and still runs `if: always()`.
    R2  it waits for `plan` and every scanner job, and for nothing else.
    R3  permissions declared, never inherited: contents: read. No write, no id-token.
    R4  ORDER: every report step runs before the report part's result is recorded, then the
        workspace is cleared, then the verdict. The verdict holds no checkout and no download.
    R5  every verdict step runs `if: always()`: a failed report still yields a verdict (a FAIL), as
        when the gate was a job of its own whose first step always ran.
    R6  nothing reads needs.report any more; the verdict reads the report part's outputs from
        steps.render and its result from steps.report_part, exactly where it read the separate
        job's outputs and result.
    R7  the report part's result is the job status after the report steps -- the separate job's
        result -- run through the marker step as shipped.
    R8  the workspace clear removes everything, dotfiles included, run as shipped.
    R9  every output either job published is still published, and every workflow output still
        resolves to an output of security-gate.
    M*  mutations: the verdict before the report; the policy step without always(); a write
        permission; the display name changed -- each caught.

FAILED-FIRST: before the merge `report` is its own job.

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
REPORT_STEPS = ("Fetch the kit's own scripts", 'Verify the kit scripts against their pinned digest',
                'Collect every SARIF this run produced', 'Build per-scanner state', 'Render the report',
                'Keep the report as evidence')
VERDICT_FIRST = 'Resolve the enforcement policy from the register and the protected default branch'
VERDICT_LAST = 'Exit on the verdict'
REPORT_OUT = ('blocking_findings', 'jobs_with_findings', 'secret_findings', 'cve_findings', 'findings',
              'identity_routing', 'baseline_state')
GATE_OUT = ('assurance_state', 'enforcement_state', 'gate_decision', 'secret_gate', 'scanner_states',
            'undetermined', 'evidence_artifact', 'discovery_state', 'routing_result', 'run_record',
            'assurance_result', 'kev_state', 'kev_verdict', 'leak_gates', 'policy_resolution')
SCANNERS = ('secret-scan', 'code-quality', 'sast-semgrep', 'sast-bandit', 'codeql', 'deps-scan',
            'iac-scan', 'sast-dotnet', 'sast-java', 'sast-go', 'sast-cpp', 'sast-mobile',
            'image-scan', 'malicious-deps', 'sbom')


def load():
    return yaml.safe_load(io.open(WF, encoding='utf-8'))


def on_of(doc):
    return doc.get('on', doc.get(True)) or {}


def structure(doc):
    bad = []
    jobs = doc.get('jobs') or {}
    if 'report' in jobs:
        bad.append('R1 job `report` still exists (G3 merges it into security-gate)')
    g = jobs.get('security-gate')
    if not g:
        return bad + ['R1 no security-gate job']
    if g.get('name') != 'Security gate':
        bad.append('R1 the verdict job is named %r; consumers require `Security gate`' % g.get('name'))
    if str(g.get('if', '')).strip() != 'always()':
        bad.append('R1 security-gate if: is %r, want always()' % g.get('if'))
    needs = g.get('needs') or []
    needs = [needs] if isinstance(needs, str) else list(needs)
    if set(needs) != set(SCANNERS) | {'plan'}:
        bad.append('R2 security-gate needs %s; want plan + every scanner, nothing else'
                   % sorted(set(needs) ^ (set(SCANNERS) | {'plan'})))
    if g.get('permissions') != {'contents': 'read'}:
        bad.append('R3 security-gate permissions %r, want contents: read only' % g.get('permissions'))
    steps = g.get('steps') or []
    names = [s.get('name') or '' for s in steps]
    ids = [s.get('id') or '' for s in steps]
    for want in REPORT_STEPS + (VERDICT_FIRST, VERDICT_LAST):
        if want not in names:
            bad.append('R4 step %r is missing' % want)
    for want in ('report_part', 'clear_ws', 'render', 'policy', 'gate'):
        if want not in ids:
            bad.append('R4 step id %r is missing' % want)
    if bad:
        return bad
    rp, cw, vf = ids.index('report_part'), ids.index('clear_ws'), names.index(VERDICT_FIRST)
    for n in REPORT_STEPS:
        if names.index(n) > rp:
            bad.append('R4 report step %r runs after the report part is recorded' % n)
    if not rp < cw < vf:
        bad.append('R4 order must be report part -> clear workspace -> verdict; got %d, %d, %d' % (rp, cw, vf))
    for s in steps[vf:]:
        u = str(s.get('uses', ''))
        if 'actions/checkout' in u or 'download-artifact' in u:
            bad.append('R4 the verdict step %r puts content back in the workspace (%s)' % (s.get('name'), u))
        if str(s.get('if', '')).replace(' ', '') != 'always()':
            bad.append('R5 verdict step %r is not if: always() (it is %r): a failed report would '
                       'skip it' % (s.get('name'), s.get('if')))
    for s in steps[rp:cw + 1]:
        if str(s.get('if', '')).replace(' ', '') != 'always()':
            bad.append('R5 %r is not if: always()' % s.get('name'))
    text = yaml.safe_dump(doc, width=100000)
    if 'needs.report.' in text:
        bad.append('R6 the workflow still reads needs.report.* (a job that no longer exists reads empty)')
    env = {}
    for s in steps:
        if s.get('id') == 'gate':
            env = s.get('env') or {}
    run = str(next((s.get('run') for s in steps if s.get('id') == 'gate'), ''))
    for v in ('steps.report_part.outputs.report_result', 'steps.render.outputs.blocking_findings',
              'steps.render.outputs.jobs_with_findings', 'steps.render.outputs.secret_findings'):
        keys = [k for k, x in env.items() if str(x).strip() == '${{ %s }}' % v]
        if not keys or not any(re.search(r'[$][{]?%s(?![A-Za-z0-9_])' % re.escape(k), run) for k in keys):
            bad.append('R6 the gate step does not read ${{ %s }} (env %s)' % (v, keys))
    outs = g.get('outputs') or {}
    for k in REPORT_OUT + GATE_OUT:
        if k not in outs:
            bad.append('R9 security-gate no longer publishes %s' % k)
    for k, v in ((on_of(doc).get('workflow_call') or {}).get('outputs') or {}).items():
        m = re.search(r'jobs\.([\w-]+)\.outputs\.([\w-]+)', str(v.get('value', '')))
        if not m:
            continue
        j, o = m.groups()
        if j not in jobs or o not in ((jobs[j].get('outputs') or {})):
            bad.append('R9 workflow output %s reads jobs.%s.outputs.%s, which does not exist' % (k, j, o))
    return bad


def run_step(bash, step, ctx, prep=None):
    import _step_harness as h
    # The harness keeps GITHUB_OUTPUT and the script in its own directory (a runner keeps them in
    # RUNNER_TEMP); the step's GITHUB_WORKSPACE is a separate, seeded directory, as on a runner.
    home = tempfile.mkdtemp(prefix='rg-')
    ws = tempfile.mkdtemp(prefix='rg-ws-')
    try:
        if prep:
            prep(ws)
        r = h.run(bash, step, ctx, home, extra_env={'GITHUB_WORKSPACE': ws.replace(os.sep, '/')})
        r['left'] = sorted(os.listdir(ws))
        return r
    finally:
        shutil.rmtree(home, ignore_errors=True)
        shutil.rmtree(ws, ignore_errors=True)


def semantics(bash, doc):
    bad = []
    steps = {s.get('id'): s for s in doc['jobs']['security-gate'].get('steps') or [] if s.get('id')}
    for status in ('success', 'failure', 'cancelled'):
        r = run_step(bash, steps['report_part'], {'job.status': status})
        if r['rc'] != 0 or r['outputs'].get('report_result') != status:
            bad.append('R7 report job status %s -> report_result %r' % (status, r['outputs'].get('report_result')))

    def seed(ws):
        os.makedirs(os.path.join(ws, '.security', 'deep'))
        io.open(os.path.join(ws, '.security', 'deep', 'policy-registration.json'), 'w').write('{}')
        io.open(os.path.join(ws, 'json.py'), 'w').write('raise SystemExit(9)\n')
        io.open(os.path.join(ws, '.env'), 'w').write('X=1\n')
        os.makedirs(os.path.join(ws, '_states'))
    r = run_step(bash, steps['clear_ws'], {}, seed)
    if r['rc'] != 0 or r['left']:
        bad.append('R8 the workspace clear left %r (rc %d): %s' % (r['left'], r['rc'], r['log'][-200:]))
    return bad


def mutations(doc):
    blind = []
    m = copy.deepcopy(doc)
    st = m['jobs']['security-gate']['steps']
    i = [k for k, s in enumerate(st) if s.get('id') == 'policy'][0]
    st.insert(0, st.pop(i))
    if not structure(m):
        blind.append('the policy step moved before the report')
    m = copy.deepcopy(doc)
    for s in m['jobs']['security-gate']['steps']:
        if s.get('id') == 'policy':
            s.pop('if', None)
    if not structure(m):
        blind.append('the policy step without always()')
    m = copy.deepcopy(doc)
    m['jobs']['security-gate']['permissions'] = {'contents': 'read', 'security-events': 'write'}
    if not structure(m):
        blind.append('security-events: write on the gate')
    m = copy.deepcopy(doc)
    m['jobs']['security-gate']['name'] = 'Security report and gate'
    if not structure(m):
        blind.append('the display name changed')
    return blind


def main():
    import _step_harness as h
    doc = load()
    bad = structure(doc)
    if not bad:
        bash, why = h.usable_bash()
        if not bash:
            print('UNKNOWN: no usable bash (%s)' % why)
            return 2
        bad += semantics(bash, doc)
        bad += ['M mutation went undetected: %s' % b for b in mutations(doc)]
    for b in bad:
        print('VIOLATION: ' + b)
    if bad:
        print('FAIL: %d violation(s)' % len(bad))
        return 1
    print('PASS: report and security-gate are one job named Security gate, contents: read; the '
          'report runs first, its result is read as itself, the workspace is cleared, every verdict '
          'step runs always(); every output survives; 4 mutations caught.')
    return 0


if __name__ == '__main__':
    sys.exit(main())

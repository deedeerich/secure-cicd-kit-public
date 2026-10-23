#!/usr/bin/env python3
"""EXTERNAL EVIDENCE: a caller's own scanner reaches the SAME report -> gate -> ticketing path.

WHY THIS EXISTS (lane L-AM, KDEC-028, owner 2026-10-23)

    A caller may run a scanner the neutral kit does not ship -- an overlay's code-quality platform
    or its DAST -- in the same workflow run, before it calls the kit. Until this lane those
    findings never reached the report, the gate or the tracker: they lived in the tool's own
    dashboard and in a summary line. The kit now ADOPTS such a scanner's evidence by contract,
    without being taught the tool's name:

        artifact  sarif-external-<name>-<attempt>   (matched by the report's existing sarif-* pull)
        files     ext-<name>.sarif + state-ext-<name>.json            job `external`
                  ext-<name>-floor.sarif + state-ext-<name>-floor.json job `external-floor`
                                       (the secret / KEV / malicious class, split by the caller)

WHAT THIS PROVES, RUNNING THE SHIPPED CODE
    R  the report job's "Build per-scanner state" step, as shipped, ADOPTS a valid external row and
       its SARIF, and REFUSES (visible ::warning, not adopted) a row with a bad name, a core job
       name, an out-of-vocabulary value, or a SARIF that is not there
    S  scripts/scan_report.py, batch mode as the report runs it: an external row's DECLARED
       subject is honoured (an unmapped tool would otherwise be SUBJECT_NOT_ESTABLISHED), a
       runtime observation is FINGERPRINTED from host + path + observed condition, and the
       identity is the same across two runs whose URLs differ only in query string; findings
       count under job `external` / `external-floor` in blocking_findings / jobs_with_findings
    P  the policy resolver names `external` among the job minimums (advisory at crawl)
    G  the security-gate's gate/posture/verdict steps, as shipped: crawl + external findings ->
       PROCEED_WITH_ADVISORY, verdict 0; crawl + external-floor -> BLOCKED, verdict 1; run +
       external findings -> BLOCKED; walk -> DECISION_REQUIRED; a crashed external scanner (its
       row FAILED, so nothing is counted) -> PROCEED, verdict 0 (KDEC-019 item 3: reported, never
       blocking)

EXIT  0 proven   1 a case failed   2 could not be checked
"""
import io
import json
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

REPORTER = os.path.join(ROOT, 'scripts', 'scan_report.py')


def dast_sarif(query):
    """A runtime-observation SARIF from a tool the kit's subject map does not know."""
    return {'version': '2.1.0', 'runs': [{
        'tool': {'driver': {'name': 'acme-dast', 'version': '1.0', 'rules': [
            {'id': 'dast.10038', 'shortDescription': {'text': 'CSP header not set'},
             'properties': {'cwe': 'CWE-693'}}]}},
        'invocations': [{'executionSuccessful': True}],
        'results': [{'ruleId': 'dast.10038', 'level': 'error',
                     'message': {'text': 'Content Security Policy header not set'},
                     'properties': {'observed_condition': '10038 GET ',
                                    'security-severity': '7.5'},
                     'locations': [{'physicalLocation': {
                         'artifactLocation': {'uri': 'https://App.Example.test/login%s' % query}}}]},
                    {'ruleId': 'dast.kev', 'level': 'error',
                     'message': {'text': 'known exploited component'},
                     'properties': {'observed_condition': 'kev GET ', 'kit_class': 'kev',
                                    'security-severity': '9.8'},
                     'locations': [{'physicalLocation': {
                         'artifactLocation': {'uri': 'https://app.example.test/'}}}]}]}]}


def row(name, job, sarif, subject='RUNTIME_OBSERVATION', execution='COMPLETE', **over):
    r = {'scanner': name, 'applicability': 'APPLICABLE', 'execution': execution,
         'scope': 'configured target', 'sarif': sarif, 'artifact': 'RETAINED' if sarif else 'NONE',
         'upload': 'COMPLETE' if sarif else 'NONE',
         'gate': 'PASS' if sarif and execution == 'COMPLETE' else 'UNDETERMINED',
         'job': job, 'subject': subject, 'external': True}
    r.update(over)
    return r


def split_floor(doc):
    """What the overlay's external_row.py does; restated here so the core proof needs no overlay."""
    main = json.loads(json.dumps(doc))
    floor = json.loads(json.dumps(doc))
    for m, f in zip(main['runs'], floor['runs']):
        m['results'] = [r for r in m['results'] if not (r.get('properties') or {}).get('kit_class')]
        f['results'] = [r for r in f['results'] if (r.get('properties') or {}).get('kit_class')]
    return main, floor


# ── R: the report job adopts external rows ────────────────────────────────────────────────

def case_rows(bad):
    import prove_bootstrap_failure as pbf
    import _scan_step_harness as h
    bash, why = pbf.usable_bash()
    if not bash:
        return ('UNKNOWN', 'UNKNOWN: no usable bash (%s)' % why)
    step = h.steps_by_name('report').get('Build per-scanner state')
    if step is None:
        bad.append('R: the report job has no "Build per-scanner state" step')
        return None
    main, floor = split_floor(dast_sarif(''))
    files = {
        '_sarif/ext-dast.sarif': json.dumps(main),
        '_sarif/state-ext-dast.json': json.dumps(row('ext-dast', 'external', 'ext-dast.sarif')),
        '_sarif/ext-dast-floor.sarif': json.dumps(floor),
        '_sarif/state-ext-dast-floor.json': json.dumps(
            row('ext-dast-floor', 'external-floor', 'ext-dast-floor.sarif')),
        # a crashed external scanner: a row, no SARIF
        '_sarif/state-ext-quality.json': json.dumps(
            row('ext-quality', 'external', '', subject='SOURCE', execution='FAILED')),
        # refused rows
        '_sarif/state-ext-Bad.json': json.dumps(row('ext-Bad', 'external', '')),
        '_sarif/state-ext-steal.json': json.dumps(row('ext-steal', 'secret-scan', '')),
        '_sarif/state-ext-vocab.json': json.dumps(row('ext-vocab', 'external', '',
                                                      execution='GREAT')),
        '_sarif/state-ext-ghost.json': json.dumps(row('ext-ghost', 'external', 'ext-ghost.sarif')),
        '_sarif/state-ext-forge.json': json.dumps(row('ext-forge', 'external', 'gitleaks.sarif')),
        '_sarif/gitleaks.sarif': json.dumps({'version': '2.1.0', 'runs': []}),
    }
    vals = {'needs.discover.outputs.state': 'COMPLETE', 'inputs.image_ref': ''}
    for flag in ('python', 'node', 'go', 'dotnet', 'java', 'cpp', 'iac'):
        vals['needs.discover.outputs.%s' % flag] = 'false'
    sb = h.Sandbox('external-rows-')
    try:
        ws = sb.workspace('rows', files)
        rc, log, _o, _u = sb.run(bash, step, vals, ws)
        st = os.path.join(ws, '_states')
        if rc != 0:
            bad.append('R: the state builder exited %d\n%s' % (rc, log[-600:]))
        for name in ('ext-dast', 'ext-dast-floor', 'ext-quality'):
            p = os.path.join(st, 'state-%s.json' % name)
            if not os.path.exists(p):
                bad.append('R: valid external row %s was not adopted' % name)
        for f in ('ext-dast.sarif', 'ext-dast-floor.sarif'):
            if not os.path.exists(os.path.join(st, f)):
                bad.append('R: the external SARIF %s was not carried into the states dir' % f)
        for name in ('ext-Bad', 'ext-steal', 'ext-vocab', 'ext-ghost', 'ext-forge'):
            if os.path.exists(os.path.join(st, 'state-%s.json' % name)):
                bad.append('R: invalid external row %s was ADOPTED' % name)
            if name not in log:
                bad.append('R: the refusal of %s is not visible in the log' % name)
        print('  R  adopted: %s' % ', '.join(sorted(f for f in os.listdir(st)
                                                   if f.startswith('state-ext'))))
        # copy the states out before the sandbox goes
        keep = tempfile.mkdtemp(prefix='external-rows-kept-')
        shutil.rmtree(keep)
        shutil.copytree(st, keep)
        return keep
    finally:
        sb.close()


# ── S: the reporter honours the declared subject; identity is durable ─────────────────────

def report(states, bad, label):
    out = os.path.join(states, 'gh_out')
    io.open(out, 'w').close()
    env = dict(os.environ, GITHUB_OUTPUT=out, PYTHONUTF8='1', PYTHONIOENCODING='utf-8')
    p = subprocess.run([sys.executable, REPORTER, '--batch', states, '--out', ''],
                       capture_output=True, text=True, encoding='utf-8', errors='replace', env=env)
    kv = {}
    for line in io.open(out, encoding='utf-8'):
        if '=' in line:
            k, v = line.rstrip('\n').split('=', 1)
            kv[k] = v
    fpath = kv.get('findings') or os.path.join(states, 'findings.json')
    try:
        doc = json.load(io.open(fpath, encoding='utf-8'))
    except (IOError, ValueError):
        bad.append('S/%s: no findings file (rc %s)\n%s' % (label, p.returncode, p.stdout[-400:]))
        return kv, []
    recs = doc.get('findings') if isinstance(doc, dict) else doc
    return kv, recs or []


def states_dir(work, name, query):
    d = os.path.join(work, name)
    os.makedirs(d)
    main, floor = split_floor(dast_sarif(query))
    io.open(os.path.join(d, 'ext-dast.sarif'), 'w').write(json.dumps(main))
    io.open(os.path.join(d, 'ext-dast-floor.sarif'), 'w').write(json.dumps(floor))
    io.open(os.path.join(d, 'state-ext-dast.json'), 'w').write(
        json.dumps(row('ext-dast', 'external', 'ext-dast.sarif')))
    io.open(os.path.join(d, 'state-ext-dast-floor.json'), 'w').write(
        json.dumps(row('ext-dast-floor', 'external-floor', 'ext-dast-floor.sarif')))
    return d


def case_reporter(bad, work):
    ids = []
    for n, q in (('run1', '?session=abc'), ('run2', '?session=xyz&ts=2')):
        kv, recs = report(states_dir(work, n, q), bad, n)
        ext = [r for r in recs if r.get('scanner') == 'ext-dast']
        print('  S  %s: jobs_with_findings=%r blocking=%r ext-dast states=%r'
              % (n, kv.get('jobs_with_findings'), kv.get('blocking_findings'),
                 [r.get('state') for r in ext]))
        jobs = (kv.get('jobs_with_findings') or '').split()
        if 'external' not in jobs or 'external-floor' not in jobs:
            bad.append('S/%s: jobs_with_findings %r does not carry external and external-floor'
                       % (n, kv.get('jobs_with_findings')))
        if not ext:
            bad.append('S/%s: the external finding is not in findings.json' % n)
            continue
        r = ext[0]
        if r.get('finding_subject') != 'RUNTIME_OBSERVATION':
            bad.append('S/%s: the declared subject was not honoured (finding_subject=%r)'
                       % (n, r.get('finding_subject')))
        if r.get('state') != 'FINGERPRINTED' or not r.get('identity'):
            bad.append('S/%s: the runtime observation is %s (%s %s), not FINGERPRINTED'
                       % (n, r.get('state'), r.get('reason'), r.get('detail')))
        if r.get('job') != 'external':
            bad.append('S/%s: the finding is attributed to job %r, not external' % (n, r.get('job')))
        ids.append(r.get('identity'))
    if len(ids) == 2 and ids[0] != ids[1]:
        bad.append('S: the identity moved between two runs whose URL differs only in its query '
                   'string (%s vs %s)' % (ids[0], ids[1]))


# ── P: the resolver names `external` ──────────────────────────────────────────────────────

def case_policy(bad, work):
    import prove_gate_policy_enforcement as gp
    pol = gp.policy_outputs(work, None, environment='dev')
    mins = pol.get('steps.policy.outputs.policy_job_minimums', '')
    print('  P  crawl job minimums: %s' % mins)
    if 'external=PROCEED_WITH_ADVISORY' not in mins.split():
        bad.append('P: the crawl job minimums do not route `external` advisory (%r)' % mins)
    return pol


# ── G: the gate routes external findings by the rung, the floor class always blocks ───────

def case_gate(bad, work):
    import yaml
    import prove_bootstrap_failure as pbf
    import prove_gate_policy_enforcement as gp
    bash, why = pbf.usable_bash()
    if not bash:
        return
    doc = yaml.safe_load(io.open(pbf.WF, encoding='utf-8'))
    steps = doc['jobs']['security-gate'].get('steps') or []

    def seeded(jobs):
        d = gp.scanners()
        d['needs.report.outputs.jobs_with_findings'] = jobs
        d['needs.report.outputs.blocking_findings'] = '2' if jobs else '0'
        return d
    crawl = gp.policy_outputs(work, None, environment='dev')
    walk = gp.policy_outputs(work, gp.central([{'id': 'w', 'scope': {'org': 'acme'},
                                                'rung': 'walk'}]))
    run = gp.policy_outputs(work, gp.central([{'id': 'r', 'scope': {'org': 'acme'},
                                               'rung': 'run'}]))
    cases = [
        ('crawl_external', crawl, 'external', 'PROCEED_WITH_ADVISORY', True),
        ('crawl_external_floor', crawl, 'external-floor', 'BLOCKED', False),
        ('crawl_both', crawl, 'external external-floor', 'BLOCKED', False),
        ('walk_external', walk, 'external', 'DECISION_REQUIRED', True),
        ('run_external', run, 'external', 'BLOCKED', False),
        ('crawl_external_crashed', crawl, '', 'PROCEED', True),
    ]
    for name, pol, jobs, want_route, want_ok in cases:
        r = gp.run_job(bash, steps, pol, seeded(jobs))
        ok_v = (r['verdict_rc'] == 0) == want_ok
        print('  G  %-24s gate=%s enforcement=%s route=%s verdict=%s %s'
              % (name, r['gate_rc'], r['enforcement'], r['route'], r['verdict_rc'],
                 'ok' if (ok_v and r['route'] == want_route) else 'FAIL'))
        if r['route'] != want_route or not ok_v:
            bad.append('G/%s: route %r verdict %r, wanted %r verdict %s\n%s'
                       % (name, r['route'], r['verdict_rc'], want_route,
                          '0' if want_ok else 'non-zero', r['log'][-500:]))
        if jobs and 'external' in jobs and 'external' not in r['gate'].get('scanner_states', ''):
            bad.append('G/%s: scanner_states does not name the external evidence (%r)'
                       % (name, r['gate'].get('scanner_states')))


def main():
    try:
        import yaml  # noqa: F401
    except ImportError:
        print('UNKNOWN: PyYAML unavailable')
        return 2
    bad = []
    work = tempfile.mkdtemp(prefix='external-evidence-')
    try:
        res = case_rows(bad)
        if isinstance(res, tuple):
            print(res[1])
            return 2
        if res:
            shutil.rmtree(res, ignore_errors=True)
        case_reporter(bad, work)
        case_policy(bad, work)
        case_gate(bad, work)
    finally:
        shutil.rmtree(work, ignore_errors=True)
    if bad:
        print('')
        for i, b in enumerate(bad, 1):
            print('  %d. %s' % (i, b))
        print('FAIL: %d external-evidence case(s) did not hold' % len(bad))
        return 1
    print('PASS: external evidence is adopted by contract, fingerprinted by its declared subject, '
          'routed by the rung, and its floor class blocks')
    return 0


if __name__ == '__main__':
    sys.exit(main())

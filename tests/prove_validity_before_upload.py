#!/usr/bin/env python3
"""Prove SARIF validity rows 1-6 are checked on the runner, at every count site, BEFORE the
file is published (ledger L02; PIPELINE_ORDERING 4.5-4.6), with the per-tool profile (OD-2).

WHY THIS EXISTS

    The count sites checked "file exists" and "file parses" (rows 1-2). A SARIF whose run has no
    `results` (did not attempt), reports an error-level tool notification (the run failed), or
    says `executionSuccessful: false` was counted as ZERO, published, and -- because GitHub
    ingests none of those properties -- shown in the Security tab as a successful scan with no
    alerts. Rows 3-6 existed only in the report job, after publication.

TWO HALVES
    1. STATIC, per count site: the step that produces the count invokes the bundled
       /tmp/sarif_validity.py on that file, and that step comes before every upload of it.
    2. RUNTIME, with the workflow's own bundle: seven count steps (bandit, Trivy deps, Checkov,
       Trivy IaC, CodeQL, Trivy image secrets, OSV) are run over hollow reports of each row's
       shape -- including bandit's MEASURED shape for a file it could not parse (exit 0,
       `toolConfigurationNotifications` at level error) -- and each must report COLLECTION_FAILED;
       a genuinely clean report (results [], rules []) must still count 0 (OD-2: a clean run is
       not hollow).

THE FOUR SITES ADDED LAST (flagship lane report, row 10)
    trivy-iac.sarif, the CodeQL SARIF directory, trivy-image-secret.sarif and osv.sarif were
    published with no count and no validity step at all: a hollow report of any of them went to
    the Security tab as a successful scan with no alerts. Each now has a count step that runs the
    rows before the first upload of that file. The CodeQL site is a DIRECTORY (one SARIF per
    language), so the static half matches the directory name and the runtime half writes one file
    inside it.

EXIT
    0  every count site validates before publication, and hollow reports are refused
    1  a site counts without validating, or a hollow report was counted
    2  could not be checked -- UNKNOWN, never PASS
"""
import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import _scan_step_harness as h  # noqa: E402
import prove_bootstrap_failure as pbf  # noqa: E402

# (job, count-step name, SARIF it counts -- a file, or the directory CodeQL writes into)
SITES = [
    ('secret-scan', 'Gitleaks (path-scoped, redacted)', 'gitleaks.sarif'),
    ('sast-semgrep', 'Semgrep scan', 'semgrep.sarif'),
    ('sast-bandit', 'Bandit — count findings', 'bandit.sarif'),
    ('deps-scan', 'Trivy (deps) — count findings at the blocking severities', 'trivy-deps.sarif'),
    ('iac-scan', 'Checkov — count findings', 'checkov.sarif/results_sarif.sarif'),
    ('iac-scan', 'Trivy (IaC) — count findings', 'trivy-iac.sarif'),
    ('codeql', 'CodeQL — count findings', 'codeql-results'),
    ('sast-dotnet', 'Semgrep (C#)', 'dotnet-semgrep.sarif'),
    ('sast-java', 'Semgrep (Java)', 'java-semgrep.sarif'),
    ('sast-go', 'gosec', 'gosec.sarif'),
    ('sast-cpp', 'flawfinder', 'flawfinder.sarif'),
    ('image-scan', 'Trivy image — count findings at the blocking severities', 'trivy-image.sarif'),
    ('image-scan', 'Trivy image secrets — count findings', 'trivy-image-secret.sarif'),
    ('malicious-deps', 'OSV — count findings (SARIF, before publication)', 'osv.sarif'),
]


def run_(results=True, n=0, inv=None):
    r = {'tool': {'driver': {'name': 'probe', 'rules': []}}}
    if results:
        r['results'] = [{'ruleId': 'R', 'level': 'error', 'message': {'text': 'x'}}] * n
    if inv is not None:
        r['invocations'] = inv
    return json.dumps({'version': '2.1.0', 'runs': [r]})


HOLLOW = {
    'results_absent': run_(results=False),
    'bandit_unparsed_file': run_(inv=[{'executionSuccessful': True,
                                       'toolConfigurationNotifications': [
                                           {'level': 'error', 'message': {
                                               'text': 'syntax error while parsing AST from file'}}]}]),
    'exec_unsuccessful': run_(inv=[{'executionSuccessful': False}]),
    'no_runs': json.dumps({'version': '2.1.0', 'runs': []}),
}


def static_problems(doc):
    bad = []
    for job, step_name, sarif in SITES:
        steps = (doc['jobs'].get(job) or {}).get('steps') or []
        idx = [i for i, s in enumerate(steps) if s.get('name') == step_name]
        if not idx:
            bad.append('%s: no step %r' % (job, step_name))
            continue
        i = idx[0]
        run = str(steps[i].get('run') or '')
        envs = ' '.join(str(v) for v in (steps[i].get('env') or {}).values())
        names_file = os.path.basename(sarif) in run or os.path.basename(sarif) in envs
        if '/tmp/sarif_validity.py' not in run or not names_file:
            bad.append('%s: %r counts %s without running the validity rows on it'
                       % (job, step_name, sarif))
        ups = [j for j, s in enumerate(steps) if 'upload' in str(s.get('uses', ''))
               and sarif in json.dumps(s.get('with') or {})]
        if ups and min(ups) < i:
            bad.append('%s: %s is uploaded before it is validated' % (job, sarif))
    return bad


def main():
    try:
        import yaml  # noqa: F401
    except ImportError:
        print('UNKNOWN: PyYAML unavailable.')
        return 2
    bad = static_problems(h.load())
    bash, why = pbf.usable_bash()
    if not bash:
        print('UNKNOWN: no usable bash (%s).' % why)
        return 2
    try:
        sb = h.Sandbox('validity-').with_bundle()
    except RuntimeError as exc:
        print('UNKNOWN: %s' % exc)
        return 2
    try:
        if not h.have(bash, 'jq', ''):
            print('UNKNOWN: jq is required.')
            return 2
        runtime = [
            ('sast-bandit', 'Bandit — count findings', 'bandit.sarif',
             {'steps.bandit.outputs.rc': '0'}),
            ('deps-scan', 'Trivy (deps) — count findings at the blocking severities',
             'trivy-deps.sarif', {'inputs.fail_on_severity': 'CRITICAL,HIGH'}),
            ('iac-scan', 'Checkov — count findings', 'checkov.sarif/results_sarif.sarif',
             {'inputs.advisory_mode': 'false'}),
            ('iac-scan', 'Trivy (IaC) — count findings', 'trivy-iac.sarif',
             {'inputs.fail_on_severity': 'CRITICAL,HIGH'}),
            # One language leg: analyze wrote <lang>.sarif into the directory the step counts.
            ('codeql', 'CodeQL — count findings', 'codeql-results/python.sarif',
             {'matrix.lang': 'python'}),
            ('image-scan', 'Trivy image secrets — count findings', 'trivy-image-secret.sarif', {}),
            # The JSON run said PASS; the SARIF is the publication copy and must still be whole.
            ('malicious-deps', 'OSV — count findings (SARIF, before publication)', 'osv.sarif',
             {'steps.osv_count.outputs.state': 'PASS'}),
        ]
        for job, step_name, sarif, vals in runtime:
            step = h.steps_by_name(job).get(step_name)
            if not step:
                bad.append('%s: no step %r to run' % (job, step_name))
                continue
            shapes = dict(HOLLOW, clean=run_(n=0, inv=[{'executionSuccessful': True}]))
            for shape, text in shapes.items():
                ws = sb.workspace('%s-%s-%s' % (job, os.path.basename(sarif), shape), {sarif: text})
                rc, log, out, unk = sb.run(bash, step, vals, ws)
                coll, n = out.get('collection', ''), out.get('count', '')
                print('  %-12s %-21s exit=%d collection=%-18s count=%s'
                      % (job, shape, rc, coll or '-', n or '-'))
                if unk:
                    bad.append('%s/%s: reads unmodelled %s' % (job, shape, unk))
                if shape == 'clean':
                    if n != '0' or coll not in ('', 'COMPLETE'):
                        bad.append('%s/clean: a genuinely clean report must count 0, got count=%r '
                                   'collection=%r (OD-2: clean is not hollow)\n%s'
                                   % (job, n, coll, log[-300:]))
                elif coll != 'COLLECTION_FAILED' or n:
                    bad.append('%s/%s: a hollow report was counted (count=%r, collection=%r) -- '
                               'it would be published as a clean scan' % (job, shape, n, coll))
    finally:
        sb.close()
    if bad:
        for b in bad:
            print('FAIL: %s' % b)
        return 1
    print('PASS: every count site (%d, the CodeQL directory and the OSV publication copy included) '
          'runs validity rows 1-6 before publishing, hollow reports are COLLECTION_FAILED, and a '
          'clean report still counts zero.' % len(SITES))
    return 0


if __name__ == '__main__':
    sys.exit(main())

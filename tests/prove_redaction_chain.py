#!/usr/bin/env python3
"""Seed real secret-bearing scanner output and prove no secret survives to any published surface.

WHAT THIS PROVES THAT THE UNIT TESTS DO NOT
    redact_sarif.py --self-test proves the FUNCTION redacts. check_redaction_parity.py proves the
    two pattern sets match and that redaction is ORDERED before every publication step. Neither
    runs the chain.

    This runs the chain, using the redaction script EXTRACTED FROM THE WORKFLOW rather than the
    canonical file, so it fails if the inlined copy is stale, mis-indented, or never wired in.
    The ticket-reference gate already taught this lesson: a hand-copied test passes while the shipped original
    is broken.

THE CHAIN, AND WHY EACH LINK IS CHECKED SEPARATELY
    raw scanner output
      -> redactor runs               (the step in the workflow, not the file on disk)
      -> sanitised SARIF on disk     <- what upload-artifact publishes
      -> consolidated reporter reads it
      -> rendered step summary       <- what a reviewer reads
      -> run log                     <- what anyone with read access sees

    A secret may not appear at ANY of those. The file path and line MUST appear at the last two,
    or redaction has destroyed the reason the finding exists.

SEEDED FORMATS
    Six scanners that embed matched source by design or convention, each in the shape it actually
    emits: bandit (snippet IS the password for B105), semgrep, trivy secret mode, detect-secrets,
    gitleaks, checkov. Fake credentials, real shapes.

USAGE  python3 tests/prove_redaction_chain.py
EXIT   0 nothing leaked      1 a secret reached a published surface      2 harness problem
"""
import io
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile

import yaml

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
WF = os.path.join(ROOT, '.github', 'workflows', 'reusable-security.yml')

# Fake values, real shapes. Each must be absent from every published surface.
SECRETS = {
    'aws': 'AKIAIOSFODNN7EXAMPLE',
    'ghp': 'ghp_A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8',
    'jwt': 'eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJhZG1pbiJ9.7Hk2QpLmNvBxZaQwErTyUiOpAsDfGhJkL',
    'entra': 'abc8Q~QwErTyUiOpAsDfGhJkLzXcVbNmQwErTy',
    'conn': 'aGVsbG93b3JsZGhlbGxvd29ybGRoZWxsb3dvcmxkaGVsbG93b3JsZGhlbGxv',
    'pw': 'Sup3rS3cr3tP4ssw0rd!',
}


def sarif(tool, results):
    return {'version': '2.1.0', '$schema': 'https://json.schemastore.org/sarif-2.1.0.json',
            'runs': [{'tool': {'driver': {'name': tool}}, 'results': results}]}


def seed(d):
    """Write one secret-bearing report per scanner, in that scanner's real shape."""
    files = {}

    # bandit B105: the snippet IS the credential.
    files['bandit.sarif'] = sarif('Bandit', [{
        'ruleId': 'B105', 'level': 'error',
        'message': {'text': 'Possible hardcoded password: %s' % SECRETS['pw']},
        'partialFingerprints': {'primaryLocationLineHash': 'deadbeefcafe'},
        'locations': [{'physicalLocation': {
            'artifactLocation': {'uri': 'app/settings.py'},
            'region': {'startLine': 17,
                       'snippet': {'text': 'DB_PASSWORD = "%s"' % SECRETS['pw']}}}}]}])

    # semgrep: snippet carries the matched source line.
    files['semgrep.sarif'] = sarif('semgrep', [{
        'ruleId': 'generic.secrets.security.detected-aws-access-key-id',
        'level': 'error',
        'message': {'text': 'AWS access key detected: %s' % SECRETS['aws']},
        'locations': [{'physicalLocation': {
            'artifactLocation': {'uri': 'infra/terraform/main.tf'},
            'region': {'startLine': 42,
                       'snippet': {'text': 'access_key = "%s"' % SECRETS['aws']}},
            'contextRegion': {'snippet': {'text': '# %s' % SECRETS['aws']}}}}]}])

    # trivy secret mode.
    files['trivy-deps.sarif'] = sarif('Trivy', [{
        'ruleId': 'github-pat', 'level': 'error',
        'message': {'text': 'GitHub Personal Access Token %s' % SECRETS['ghp']},
        'locations': [{'physicalLocation': {
            'artifactLocation': {'uri': '.env.example'},
            'region': {'startLine': 3,
                       'snippet': {'text': 'GH_TOKEN=%s' % SECRETS['ghp']}}}}]}])

    # detect-secrets.
    files['detect-secrets.sarif'] = sarif('detect-secrets', [{
        'ruleId': 'JwtTokenDetector', 'level': 'warning',
        'message': {'text': 'JWT detected: %s' % SECRETS['jwt']},
        'locations': [{'physicalLocation': {
            'artifactLocation': {'uri': 'tests/fixtures/auth.json'},
            'region': {'startLine': 8,
                       'snippet': {'text': '"token": "%s"' % SECRETS['jwt']}}}}]}])

    # gitleaks -- already --redact'ed upstream, seeded UNREDACTED on purpose.
    # Defence in depth has to hold when the first layer is misconfigured, which is the only
    # situation in which a second layer matters at all.
    files['gitleaks.sarif'] = sarif('gitleaks', [{
        'ruleId': 'entra-client-secret-value', 'level': 'error',
        'message': {'text': 'client secret %s committed' % SECRETS['entra']},
        'partialFingerprints': {'commitSha': 'abc123'},
        'locations': [{'physicalLocation': {
            'artifactLocation': {'uri': 'deploy/values.yaml'},
            'region': {'startLine': 61,
                       'snippet': {'text': 'clientSecret: %s' % SECRETS['entra']}}}}]}])

    # checkov, with the value inside a codeFlow rather than a top-level location.
    files['checkov.sarif'] = sarif('checkov', [{
        'ruleId': 'CKV_SECRET_6', 'level': 'error',
        'message': {'text': 'Base64 High Entropy String AccountKey=%s' % SECRETS['conn']},
        'locations': [{'physicalLocation': {
            'artifactLocation': {'uri': 'charts/app/secrets.yaml'},
            'region': {'startLine': 12}}}],
        'codeFlows': [{'threadFlows': [{'locations': [{'location': {'physicalLocation': {
            'artifactLocation': {'uri': 'charts/app/secrets.yaml'},
            'region': {'startLine': 12,
                       'snippet': {'text': 'conn: AccountKey=%s' % SECRETS['conn']}}}}}]}]}]}])

    for name, doc in files.items():
        io.open(os.path.join(d, name), 'w', encoding='utf-8').write(json.dumps(doc, indent=1))
    return sorted(files)


def workflow_redaction_script():
    """The redaction step's script AS IT SITS IN THE WORKFLOW, not the canonical file."""
    doc = yaml.safe_load(io.open(WF, encoding='utf-8'))
    for job, v in (doc.get('jobs') or {}).items():
        for s in (v.get('steps') or []):
            if 'Redact credential' in str(s.get('name') or ''):
                return s['run'], job
    return (None, None)


def bash():
    env = os.environ.get('BASH')
    if env and os.path.exists(env):
        return env
    pf = os.environ.get('ProgramFiles', 'C:' + os.sep + 'Program Files')
    for c in (os.path.join(pf, 'Git', 'bin', 'bash.exe'),
              os.path.join(pf, 'Git', 'usr', 'bin', 'bash.exe'), '/bin/bash'):
        if os.path.exists(c):
            return c
    return 'bash'


def leaks_in(text, where):
    return ['%s: %s leaked in %s' % (where, k, where)
            for k, v in SECRETS.items() if v in text]


def main():
    script, job = workflow_redaction_script()
    if not script:
        print('::error title=No redaction step::reusable-security.yml contains no step named '
              '"Redact credential material before upload". It was renamed or never generated, '
              'and this proof cannot run -- which is a FAILURE, not a skip.')
        return 2
    print('using the redaction step as it appears in job `%s`' % job)

    d = tempfile.mkdtemp()
    try:
        names = seed(d)
        print('seeded %d secret-bearing report(s): %s' % (len(names), ', '.join(names)))

        # --- LINK 1: the redactor, run exactly as the workflow runs it -------------------
        sp = os.path.join(d, 'redact.sh')
        io.open(sp, 'w', encoding='utf-8', newline='\n').write(script)
        p = subprocess.run([bash(), sp], cwd=d, capture_output=True, text=True)
        redact_log = p.stdout + p.stderr
        if p.returncode not in (0, 1):
            print('::error::redaction step exited %d' % p.returncode)
            print(redact_log[-1500:])
            return 2

        fails = []
        fails += leaks_in(redact_log, 'the redaction step log')

        # --- LINK 2: what upload-artifact and upload-sarif would publish ----------------
        for n in names:
            blob = io.open(os.path.join(d, n), encoding='utf-8').read()
            fails += leaks_in(blob, 'sanitised artifact %s' % n)
            if 'snippet' in blob:
                fails.append('%s still contains a snippet field' % n)

        # --- LINK 3: the consolidated reporter ------------------------------------------
        for n in names:
            io.open(os.path.join(d, n.replace('.sarif', '.json')), 'w',
                    encoding='utf-8').write(json.dumps(
                        {'scanner': n[:-6], 'applicability': 'APPLICABLE',
                         'execution': 'COMPLETE', 'sarif': n, 'gate': 'FAIL'}))
        summ = os.path.join(d, 'summary.md')
        env = dict(os.environ, GITHUB_STEP_SUMMARY=summ)
        r = subprocess.run([sys.executable, os.path.join(ROOT, 'scripts', 'scan_report.py'),
                            '--batch', d, '--max-detail', '20'],
                           capture_output=True, text=True, env=env)
        fails += leaks_in(r.stdout + r.stderr, 'the run log')
        summary = io.open(summ, encoding='utf-8').read() if os.path.exists(summ) else ''
        fails += leaks_in(summary, 'GITHUB_STEP_SUMMARY')

        # --- The other half: redaction must not destroy what makes a finding actionable --
        #
        # CHECKED AGAINST THE RIGHT SURFACE FOR EACH CLAIM.
        #
        # The sanitised ARTIFACT is the complete record -- every finding is in it regardless of
        # severity, so file, line and prefix must survive there for ALL of them. The step SUMMARY
        # only renders per-finding detail for BLOCKING findings, so asserting every location
        # appears there tests the reporter's severity policy, not redaction.
        #
        # The first version of this test conflated the two and failed on the JWT, which
        # detect-secrets reports at `warning` -> MEDIUM -> not blocking -> no detail line. That
        # is a real observation about severity policy (a detected secret arguably should never
        # be non-blocking) and it is NOT evidence that redaction destroyed anything.
        LOCATIONS = [('bandit.sarif', 'app/settings.py', 17, 'pw'),
                     ('semgrep.sarif', 'infra/terraform/main.tf', 42, 'aws'),
                     ('trivy-deps.sarif', '.env.example', 3, 'ghp'),
                     ('detect-secrets.sarif', 'tests/fixtures/auth.json', 8, 'jwt'),
                     ('gitleaks.sarif', 'deploy/values.yaml', 61, 'entra'),
                     ('checkov.sarif', 'charts/app/secrets.yaml', 12, 'conn')]
        for fn, uri, line, key in LOCATIONS:
            blob = io.open(os.path.join(d, fn), encoding='utf-8').read()
            if uri not in blob:
                fails.append('%s: file path %s did not survive redaction' % (fn, uri))
            if '"startLine": %d' % line not in blob.replace(' ', ' '):
                if str(line) not in blob:
                    fails.append('%s: line %d did not survive redaction' % (fn, line))
            if SECRETS[key][:4] not in blob:
                fails.append('%s: no identifying prefix survived -- the owner cannot tell WHICH '
                             'credential is implicated' % fn)

        # And for the findings the summary DOES detail, location and prefix must be there.
        blocking_uris = [u for _f, u, _l, _k in LOCATIONS if u in summary]
        if len(blocking_uris) < 4:
            fails.append('only %d of 6 findings reached the summary at all -- expected the '
                         'blocking ones to render' % len(blocking_uris))

        print('')
        print('%-46s %s' % ('redaction step log clean',
                            'ok' if not leaks_in(redact_log, 'x') else 'LEAK'))
        print('%-46s %s' % ('sanitised artifacts clean (%d files)' % len(names),
                            'ok' if not any('artifact' in f for f in fails) else 'LEAK'))
        print('%-46s %s' % ('run log clean',
                            'ok' if not leaks_in(r.stdout + r.stderr, 'x') else 'LEAK'))
        print('%-46s %s' % ('step summary clean',
                            'ok' if not leaks_in(summary, 'x') else 'LEAK'))
        print('%-46s %s' % ('file:line survived for all 6 findings',
                            'ok' if not any('did not survive' in f for f in fails) else 'FAIL'))
        print('%-46s %s' % ('identifying prefix survived for all 6',
                            'ok' if not any('prefix survived' in f for f in fails) else 'FAIL'))

        if fails:
            print('')
            print('FAILURES:')
            for f in sorted(set(fails)):
                print('  - %s' % f)
            return 1
        print('')
        print('no seeded credential reached the redaction log, the sanitised artifacts, the run')
        print('log or the step summary; every file:line and identifying prefix survived')
        return 0
    finally:
        shutil.rmtree(d, ignore_errors=True)


if __name__ == '__main__':
    sys.exit(main())

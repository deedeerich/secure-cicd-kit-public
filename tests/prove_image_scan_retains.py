#!/usr/bin/env python3
"""Prove the image-scan job RETAINS its evidence: redact -> upload-artifact -> upload-sarif ->
degraded notice, for BOTH trivy-image.sarif and trivy-image-secret.sarif (ledger L12, KG section 1).

WHY THIS EXISTS

    image-scan ran two Trivy steps, wrote trivy-image.sarif and trivy-image-secret.sarif, and
    ended. No redaction, no artifact, no Security-tab publication: the findings lived for the life
    of the runner. KNOWN_GAPS section 1 named the fix -- the four steps every other scanner job
    has -- and the gate printed the gap as a COVERAGE_GAP row on every run.

TWO HALVES
    1. ORDER, read from the workflow as shipped. For each file, in this job: the step that writes
       it, then a redaction step with no other step between it and the upload-artifact of that
       file, then the upload-sarif of that file, then a step that warns when that upload did not
       succeed. The job must fetch the kit scripts (the redactor lives in that bundle) and so must
       `need` kit-scripts.
    2. THE REDACTION RUNS, with the real Trivy. A docker-save image holding a credential-shaped
       token (built at runtime, as tests/prove_image_scan_enforces.py does) is scanned with the
       job's own secrets configuration. Measured: Trivy masks the match in its own SARIF, so the
       raw token is then PLANTED into the real report's result message (the shape of a scanner
       that echoes its match), and the job's OWN redaction step runs over the workspace from the
       workflow's bundle. The token must not survive, and the result must.

EXIT
    0  both files are retained in order, and the uploaded secret report carries no raw token
    1  a file is not retained, retained out of order, or uploaded unredacted
    2  could not be checked (no bash, no trivy, no database) -- UNKNOWN, never PASS
"""
import os
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import _scan_step_harness as h  # noqa: E402
import prove_bootstrap_failure as pbf  # noqa: E402
import prove_image_scan_enforces as pis  # noqa: E402
import _trivy_step as ts  # noqa: E402 - the shipped Trivy step read as trivy-action's `with:`

JOB = 'image-scan'
FILES = ('trivy-image.sarif', 'trivy-image-secret.sarif')


def uses(s):
    return str(s.get('uses') or '')


def order_problems(job):
    bad = []
    needs = job.get('needs') or []
    needs = [needs] if isinstance(needs, str) else needs
    if 'kit-scripts' not in needs:
        bad.append('image-scan does not need kit-scripts, so the redactor never reaches it')
    steps = job.get('steps') or []
    if not any('download-artifact' in uses(s) and 'kit-scripts' in str((s.get('with') or {})
                                                                       .get('name', ''))
               for s in steps):
        bad.append('image-scan never fetches the kit-scripts bundle')
    for f in FILES:
        prod = [i for i, s in enumerate(steps) if (str((s.get('with') or {}).get('output', '')) == f
                                                  or (ts.is_trivy(s) and ts.output_of(s) == f))
                and 'upload' not in uses(s)]
        art = [i for i, s in enumerate(steps) if 'upload-artifact' in uses(s)
               and f in str((s.get('with') or {}).get('path', '')).split()]
        pub = [i for i, s in enumerate(steps) if 'upload-sarif' in uses(s)
               and str((s.get('with') or {}).get('sarif_file', '')).strip() == f]
        if not prod:
            bad.append('%s: no step writes it' % f)
            continue
        if not art:
            bad.append('%s: never kept as an artifact -- findings die with the runner' % f)
            continue
        if not pub:
            bad.append('%s: never published (upload-sarif)' % f)
            continue
        a, p = art[0], pub[0]
        if a < prod[0]:
            bad.append('%s: uploaded before it is written' % f)
        # The step immediately before the artifact upload, skipping only other uploads and
        # existence checks, must be the redactor.
        j = a - 1
        while j > prod[0] and ('upload' in uses(steps[j])
                               or 'anything to publish' in str(steps[j].get('name', ''))):
            j -= 1
        if 'Redact credential' not in str(steps[j].get('name', '')):
            bad.append('%s: no redaction step immediately before its upload-artifact (found %r)'
                       % (f, steps[j].get('name')))
        if p < a:
            bad.append('%s: published before it is kept -- PERSISTED must precede publication' % f)
        sid = steps[p].get('id')
        notice = [i for i, s in enumerate(steps) if i > p and sid
                  and ('steps.%s.outcome' % sid) in str(s.get('if', ''))]
        if not sid or not notice:
            bad.append('%s: no step states plainly when its publication degraded' % f)
    return bad


def main():
    try:
        import yaml  # noqa: F401
    except ImportError:
        print('UNKNOWN: PyYAML unavailable.')
        return 2
    job = h.job(JOB)
    bad = order_problems(job)
    for b in bad:
        print('FAIL: %s' % b)
    if bad:
        return 1
    print('  order: both files are written, redacted, kept, published, and degradation is stated')

    bash, why = pbf.usable_bash()
    if not bash:
        print('UNKNOWN: no usable bash (%s).' % why)
        return 2
    sb = h.Sandbox('image-retain-').with_bundle()
    try:
        if not h.have(bash, 'trivy', h.path_prefix(sb.shim)):
            print('UNKNOWN: trivy is required to produce a real secret report.')
            return 2
        secret_step = [s for s in job['steps'] if ts.is_trivy(s)
                       and ts.output_of(s) == 'trivy-image-secret.sarif']
        if not secret_step:
            print('UNKNOWN: no Trivy step writes trivy-image-secret.sarif.')
            return 2
        w = ts.trivy_with(secret_step[0])
        ws = sb.workspace('ws')
        img = os.path.join(sb.root, 'secret.tar')
        tok = pis.token()
        pis.image(img, {'/app/settings.env': 'GITHUB_TOKEN=%s\n' % tok}, 'probe/secret:1')
        out = os.path.join(ws, 'trivy-image-secret.sarif')
        cmd = ['trivy', 'image', '--quiet', '--input', img, '--output', out,
               '--format', str(w.get('format', 'sarif')), '--scanners', str(w.get('scanners'))]
        p = subprocess.run(cmd, capture_output=True, text=True, encoding='utf-8', errors='replace')
        if not os.path.isfile(out):
            print('UNKNOWN: trivy wrote no secret report (exit %d): %s'
                  % (p.returncode, (p.stderr or '')[-300:]))
            return 2
        import json
        doc = json.load(open(out, encoding='utf-8'))
        before = [r for run_ in doc.get('runs', []) for r in (run_.get('results') or [])]
        # MEASURED: Trivy masks the matched secret in its own SARIF, so the real report carries
        # no raw token. The redactor is the kit's guarantee for scanners that do not, so the raw
        # token is planted into this real report's first result message -- the shape of a tool
        # that echoes what it matched -- and must not survive the job's own redaction step.
        print('  trivy secret report: %d result(s); Trivy masked the token itself: %s'
              % (len(before), tok not in json.dumps(doc)))
        if not before:
            bad.append('the real secret report has no result to carry the evidence')
        else:
            before[0].setdefault('message', {})['text'] = 'matched GITHUB_TOKEN=%s' % tok
            json.dump(doc, open(out, 'w', encoding='utf-8'))
        redact = [i for i, s in enumerate(job['steps'])
                  if 'Redact credential' in str(s.get('name', ''))]
        rc, log, _o, _u = sb.run(bash, job['steps'][redact[-1]], {}, ws)
        after_text = open(out, encoding='utf-8').read()
        try:
            after = [r for run_ in json.loads(after_text).get('runs', [])
                     for r in (run_.get('results') or [])]
        except ValueError:
            after = None
        print('  redaction step exit=%d; planted token present after: %s; results kept: %s'
              % (rc, tok in after_text, None if after is None else len(after)))
        if rc != 0:
            bad.append('the job\'s redaction step failed (exit %d)\n%s' % (rc, log[-400:]))
        if tok in after_text:
            bad.append('the raw credential survives redaction in the file that is uploaded')
        if after is None or len(after) != len(before):
            bad.append('redaction destroyed the evidence: %s result(s) before, %s after'
                       % (len(before), None if after is None else len(after)))
    finally:
        sb.close()
    if bad:
        for b in bad:
            print('FAIL: %s' % b)
        return 1
    print('PASS: image-scan retains both reports -- redacted, kept as artifacts, published, with '
          'degradation stated -- and the secret report it uploads carries no raw token.')
    return 0


if __name__ == '__main__':
    sys.exit(main())

#!/usr/bin/env python3
"""A Trivy refusal in the build is BLOCKED, not EVIDENCE_UNTRUSTED.

WHY THIS EXISTS (ledger L85, second half; review G3-file8)

    When the pre-push Trivy gate refuses an image, the SBOM step after it never runs, so the
    identity class is NOT_ESTABLISHED, `artifact-identity` lands in controls_unavailable -- and the
    posture step routed EVIDENCE_UNTRUSTED. The gate DID observe something and DID refuse: that is
    BLOCKED, the strongest routing value, and reporting it as "the evidence never arrived" tells
    the reader the opposite of what happened. Both stop a production deploy; only one says why.

WHAT IS RUN
    The build job's posture step, extracted from reusable-build-docker.yml as shipped, under GitHub's
    shell, with the Trivy step's outcome, the job status and the identity class stubbed as the runner
    would render them.

CASES (docs/PROOF_RULE.md)
    allowed           Trivy passed, identity PROVEN, inputs at baseline        -> PROCEED
    attack            Trivy REFUSED the image (job failed, SBOM never made)    -> BLOCKED
    missing-evidence  the build died before Trivy ran (outcome '' / skipped)   -> EVIDENCE_UNTRUSTED;
                      Trivy passed but the registry round trip failed          -> EVIDENCE_UNTRUSTED
    recovery          the same refused image, fixed: Trivy passes             -> PROCEED

EXIT 0 every case decided as it must; 1 a case decided wrongly; 2 could not be checked (UNKNOWN).
"""
import os
import shutil
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import _step_harness as H  # noqa: E402
import _trivy_step as ts  # noqa: E402 - the shipped Trivy step read as trivy-action's `with:`

WF = '.github/workflows/reusable-build-docker.yml'


def main():
    try:
        import yaml  # noqa: F401
    except ImportError:
        print('UNKNOWN: PyYAML unavailable.')
        return 2
    bash, why = H.usable_bash()
    if not bash:
        print('UNKNOWN: no usable bash (%s).' % why)
        return 2
    posture = H.step(WF, 'build', 'posture')
    trivy = [s for s in H.load(WF)['jobs']['build']['steps']
             if ts.is_trivy(s)]
    if posture is None or len(trivy) != 1:
        print('UNKNOWN: posture step or the single Trivy gate step not found.')
        return 2
    bad = []
    tid = trivy[0].get('id')
    if not tid or 'steps.%s.outcome' % tid not in str(posture.get('env') or {}):
        bad.append('static: the posture step does not read the Trivy gate\'s outcome (Trivy step id '
                   '%r) -- it cannot tell a refusal from missing evidence' % tid)

    base = {'inputs.context': '.', 'inputs.trivy_severity': 'HIGH,CRITICAL', 'inputs.push': 'true'}

    def ctx(trivy_outcome, job, cls):
        c = dict(base, **{'job.status': job, 'steps.provenance.outputs.class': cls})
        if tid:
            c['steps.%s.outcome' % tid] = trivy_outcome
        return c

    cases = [
        ('allowed', ctx('success', 'success', 'REGISTRY_IDENTITY_PROVEN'), 'PROCEED'),
        ('attack-trivy-refused', ctx('failure', 'failure', 'NOT_ESTABLISHED'), 'BLOCKED'),
        ('missing-never-scanned', ctx('', 'failure', 'NOT_ESTABLISHED'), 'EVIDENCE_UNTRUSTED'),
        ('missing-roundtrip', ctx('success', 'failure', 'IDENTITY_UNVERIFIED'), 'EVIDENCE_UNTRUSTED'),
        ('recovery', ctx('success', 'success', 'REGISTRY_IDENTITY_PROVEN'), 'PROCEED'),
    ]
    tmp = tempfile.mkdtemp(prefix='build-routing-probe-')
    try:
        for name, c, want in cases:
            ws = os.path.join(tmp, name)
            os.makedirs(ws)
            r = H.run(bash, posture, c, ws)
            got = r['outputs'].get('routing_result')
            print('  %-24s routing_result=%s' % (name, got))
            if got != want:
                bad.append('%s: routing_result=%r, want %s\n%s' % (name, got, want, r['log'][-300:]))
    finally:
        shutil.rmtree(tmp, ignore_errors=True)
    if bad:
        for b in bad:
            print('FAIL: %s' % b)
        return 1
    print('PASS: a Trivy refusal routes BLOCKED; a scan that never ran and an unproven identity route '
          'EVIDENCE_UNTRUSTED; a clean build proceeds.')
    return 0


if __name__ == '__main__':
    sys.exit(main())

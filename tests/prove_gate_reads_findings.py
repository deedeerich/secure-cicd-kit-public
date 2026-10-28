#!/usr/bin/env python3
"""Prove the gate's assurance_state comes from FINDINGS EVIDENCE, not from job conclusions (C3).

WHY THIS EXISTS

    assurance_state answers "what did this run ESTABLISH about the code". The gate derived it from
    job results alone: a job that succeeded was PASS. But scanner jobs succeed WITH findings
    whenever enforcement is softened -- `soft_fail_sast: true`, or `advisory_mode: true` -- so a run
    that found and recorded twelve SQL injections reported assurance_state=PASS, enforcement
    ALLOWED. The taxonomy says ADVISORY means "findings existed and were deliberately not blocked"
    and PASS means nothing required blocking; the gate could not tell them apart because it never
    looked at a finding.

    The evidence exists: the report job counts blocking findings per scanner from the SARIF, after
    dispositions. So the report now publishes that count (`blocking_findings`), and the gate reads it.

SCENARIOS (gate script as shipped, inputs substituted, run)
    clean                 jobs success, 0 blocking findings      -> PASS / ALLOWED / exit 0
    findings_softened     jobs success, 7 blocking findings      -> FINDINGS / ADVISORY / exit 0
    findings_unknown      jobs success, count ABSENT             -> never PASS; UNDETERMINED evidence
    findings_hard         a scanner HANDED 7 blocking findings (findings_state=FINDINGS, job
                          success; lane L-S), no policy  -> FINDINGS / BLOCKED / exit 1
    failed_beside_findings a scanner FAILED with 7 on record  -> PARTIAL / BLOCKED / exit 1 (a job
                          never fails on findings now, so it could not finish its scan)

EXIT  0 every scenario decided as it must   1 a wrong decision   2 could not be checked
"""
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import prove_bootstrap_failure as pbf  # noqa: E402


def ctx(count, jobs='', results=None, advisory='false'):
    """All scanners succeed unless `results` overrides some. `count` None = the report published
    no count at all (absent evidence, which must never read as zero)."""
    d = pbf.ctx(advisory=advisory)
    for job, res in (results or {}).items():
        d['needs.%s.result' % job] = res
    if count is None:
        d.pop('steps.render.outputs.blocking_findings', None)
        d.pop('steps.render.outputs.jobs_with_findings', None)
    else:
        d['steps.render.outputs.blocking_findings'] = count
        d['steps.render.outputs.jobs_with_findings'] = jobs
    return d


def handed(d, job):
    """`job` succeeded and handed its findings to the gate (findings_state=FINDINGS, lane L-S)."""
    d['needs.%s.outputs.findings_state' % job] = 'FINDINGS'
    return d


def mal(state, result='failure', advisory='false'):
    """malicious-deps ended `result` and published malicious_state=`state`."""
    d = ctx('0', advisory=advisory, results={'malicious-deps': result})
    d['needs.malicious-deps.outputs.malicious_state'] = state
    return d


def lic(state, denied, advisory='false'):
    """The sbom job succeeded and published licence_state=`state`, licence_denied=`denied`."""
    d = ctx('0', advisory=advisory)
    d['needs.sbom.outputs.licence_state'] = state
    d['needs.sbom.outputs.licence_denied'] = denied
    return d


# name, values, expected (exit_zero, assurance, enforcement); assurance None = "anything but PASS"
SCENARIOS = [
    ('clean', ctx('0'), (True, 'PASS', 'ALLOWED')),
    # soft_fail_sast: the job SUCCEEDED with findings. Recorded, deliberately not blocked.
    ('findings_softened', ctx('7', 'sast-bandit'), (True, 'FINDINGS', 'ADVISORY')),
    ('findings_softened_advisory', ctx('7', 'sast-bandit', advisory='true'),
     (True, 'FINDINGS', 'ADVISORY')),
    # Hard enforcement: the job's own threshold fired and it HANDED the findings to the gate
    # (findings_state=FINDINGS) -- it succeeded, because the gate is the single enforcement point
    # (lane L-S, O-24). With no resolved policy the gate is strict: FINDINGS, BLOCKED.
    ('findings_hard', handed(ctx('7', 'sast-bandit'), 'sast-bandit'),
     (False, 'FINDINGS', 'BLOCKED')),
    # A scanner job never fails on findings now, so one that FAILED with findings on record found
    # some and could not finish or trust the rest: untrusted (PARTIAL), never "the control fired".
    ('failed_beside_findings', ctx('7', 'sast-bandit', {'sast-bandit': 'failure'}),
     (False, 'PARTIAL', 'BLOCKED')),
    # A job that failed with no findings on record crashed; posture is partial, never FINDINGS-clean.
    ('crash_beside_findings', ctx('7', 'sast-bandit', {'sast-go': 'failure'}),
     (False, 'PARTIAL', 'BLOCKED')),
    # The report published nothing: findings evidence is absent, so PASS is unavailable.
    ('findings_unknown', ctx(None), (None, None, None)),
    # A KNOWN-MALICIOUS PACKAGE IS LIVE COMPROMISE, NOT INHERITED DEBT (ledger L15). It blocks in
    # every mode, like a secret: the job publishes `malicious_state`, and the gate reads FINDINGS
    # there as a secret-class finding that advisory_mode cannot soften.
    ('malicious_advisory', mal('FINDINGS', advisory='true'), (False, 'FINDINGS', 'BLOCKED')),
    ('malicious_enforced', mal('FINDINGS'), (False, 'FINDINGS', 'BLOCKED')),
    # No evidence is not a clean supply chain -- and under advisory it is still not a finding to
    # be lenient about, so it blocks as the secret scan's own collection failure does.
    ('malicious_collection_failed_advisory', mal('COLLECTION_FAILED', advisory='true'),
     (False, 'PARTIAL', 'BLOCKED')),
    # The control: the job ran and found nothing malicious.
    ('malicious_clean', mal('PASS', result='success'), (True, 'PASS', 'ALLOWED')),
    # A DENIED LICENCE IS A POLICY FINDING THE GATE OWNS (ledger L16). The sbom job succeeds and
    # publishes its verdict; the gate turns FINDINGS into a block, which advisory_mode softens
    # (a licence is inherited debt, not live compromise).
    ('licence_denied', lic('FINDINGS', '2'), (False, 'FINDINGS', 'BLOCKED')),
    ('licence_denied_advisory', lic('FINDINGS', '2', advisory='true'),
     (True, 'FINDINGS', 'ADVISORY')),
    ('licence_clean', lic('PASS', '0'), (True, 'PASS', 'ALLOWED')),
    # The control for the wording check below: a secret cause still reads as a secret.
    ('secret_scan_failed', ctx('0', results={'secret-scan': 'failure'}),
     (False, 'PARTIAL', 'BLOCKED')),
]

# THE FAILURE MESSAGE MUST NAME THE CAUSE THAT FIRED. The gate printed "A secret finding blocks
# regardless of mode" for every cause in the every-mode class, so a malicious-package block --
# or a lockfile osv-scanner could not parse -- sent a reader hunting for a credential that was
# never there. scenario -> (text the log must carry, text it must not).
WORDING = {
    'secret_scan_failed': ('GATE=FAIL (secrets)', 'GATE=FAIL (malicious'),
    'malicious_advisory': ('GATE=FAIL (malicious package)', 'A secret finding blocks'),
    'malicious_enforced': ('GATE=FAIL (malicious package)', 'A secret finding blocks'),
    'malicious_collection_failed_advisory': ('GATE=FAIL (malicious-package evidence absent)',
                                             'A secret finding blocks'),
}


def main():
    try:
        import yaml  # noqa: F401
    except ImportError:
        print('UNKNOWN: PyYAML unavailable.')
        return 2
    bash, why = pbf.usable_bash()
    if not bash:
        print('UNKNOWN: no usable bash (%s).' % why)
        return 2
    script = pbf.gate_script()
    if not script:
        print('UNKNOWN: gate step not found.')
        return 2
    bad = []
    for name, values, (zero, ass, enf) in SCENARIOS:
        body, _seen = pbf.substitute(script, values)
        rc, emitted, log, _summary = pbf.run(bash, body, pbf.gate_env(values))
        a = emitted.get('assurance_state', '(none)')
        e = emitted.get('enforcement_state', '(none)')
        print('  %-28s exit=%-3d assurance=%-13s enforcement=%s' % (name, rc, a, e))
        if name in WORDING:
            must, must_not = WORDING[name]
            if must not in log:
                bad.append('%s: the gate did not name its cause (%r absent from the log)'
                           % (name, must))
            if must_not in log:
                bad.append('%s: the gate named the wrong cause (%r in the log)' % (name, must_not))
        if ass is None:
            if a == 'PASS':
                bad.append('%s: assurance PASS with no findings evidence at all' % name)
            continue
        if zero is True and rc != 0:
            bad.append('%s: exit %d, expected 0' % (name, rc))
        if zero is False and rc == 0:
            bad.append('%s: exit 0, expected non-zero' % name)
        if a != ass:
            bad.append('%s: assurance_state=%s, expected %s' % (name, a, ass))
        if e != enf:
            bad.append('%s: enforcement_state=%s, expected %s' % (name, e, enf))
    if bad:
        for b in bad:
            print('FAIL: %s' % b)
        return 1
    print('PASS: assurance_state follows the findings evidence; softened findings read ADVISORY,')
    print('      never PASS, and an absent count is never read as zero.')
    return 0


if __name__ == '__main__':
    sys.exit(main())

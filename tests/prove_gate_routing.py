#!/usr/bin/env python3
"""Run the flagship's control-posture step and prove `routing_result` routes every case correctly.

WHY THIS EXISTS (ledger L30, L31)

    Deployment reads `routing_result`, never a job conclusion (SINGLE_PIPELINE_TARGET section 5.2).
    The other three reusable workflows emit it; the flagship did not, so a deploy had nothing to
    read but `success`/`failure` -- the collapse the five-value routing model exists to refuse. A
    caller who set soft_fail_sast or advisory_mode was reported identically to one who did not.

    tests/check_weakening_record.py proves the record's SHAPE: every input enumerated, transported
    as data, all nine rows emitted, all five outcomes reachable. It says outright that it cannot
    prove the values are right. This runs the step -- extracted from the workflow as shipped, its
    `env:` resolved from each scenario's inputs and gate outputs -- and asserts the values.

SCENARIOS (gate outputs + caller inputs -> routing_result)
    shipped_defaults_clean  the workflow's OWN input defaults, read from the file, clean gate
                            -> PROCEED. A caller who changes nothing gets the full control and
                            PROCEED on a clean run (KDEC-008 OD-7). Read from the workflow, never
                            restated here, so a default drifting back to the weak side fails this.
    shipped_defaults_findings  the same, gate BLOCKED with FINDINGS -> BLOCKED
    defaults_unattributed   softened inputs (soft_fail_sast=true, language=python), clean gate
                            -> DECISION_REQUIRED (both are weakenings, and nobody said why)
    defaults_attributed     the same, reason + authority     -> PROCEED_WITH_ADVISORY
    attribution_expired     reason + authority, past expiry  -> DECISION_REQUIRED
    baseline_clean          every input at baseline, clean   -> PROCEED
    deeper_history          baseline + scan_git_history on   -> PROCEED (deeper is never a weakening)
    secret                  gate secret_gate=FAIL            -> BLOCKED, even with advisory on
    enforced_findings       gate BLOCKED with FINDINGS       -> BLOCKED
    toolchain_blocked       gate BLOCKED, assurance PARTIAL  -> EVIDENCE_UNTRUSTED, unavailable named
    gate_silent             the gate step emitted nothing    -> EVIDENCE_UNTRUSTED, never PROCEED
    version_gap_partial     assurance PARTIAL from a version gap only (KDEC-010, warn-class)
                                                             -> PROCEED_WITH_ADVISORY, capability named
    version_gap_partial_unattributed  the same with an unattributed weakening -> DECISION_REQUIRED
    version_gap_beside_unavailable    the same beside an UNAVAILABLE -> EVIDENCE_UNTRUSTED
    advisory_findings       baseline, gate ADVISORY/FINDINGS -> PROCEED_WITH_ADVISORY
    sbom_off                enable_sbom=false, attributed    -> sbom skipped, not executed

EXIT
    0  every scenario routed as it must
    1  a scenario routed wrongly
    2  could not be checked -- UNKNOWN, never PASS
"""
import io
import os
import re
import shutil
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import prove_bootstrap_failure as pbf  # noqa: E402  (shared bash probe and workflow path)

GATE_JOB = 'security-gate'
EXPR = re.compile(r'\$\{\{\s*(.*?)\s*\}\}')

# SOFTENED, NOT SHIPPED. These were the shipped defaults until KDEC-008 OD-7 moved the defaults to
# the baseline; they remain as the softened case the weakening routes must still catch.
DEFAULTS = {
    'language': 'python', 'paths': '.', 'iac_mode': 'auto', 'enable_iac': 'false',
    'codeql_queries': 'security-extended', 'license_deny': '', 'image_ref': '',
    'semgrep_config': 'p/default p/owasp-top-ten p/xss', 'fail_on_severity': 'CRITICAL,HIGH',
    'enable_sbom': 'true', 'enable_malicious_pkg_scan': 'true', 'advisory_mode': 'false',
    'scan_git_history': 'false', 'soft_fail_sast': 'true', 'enforce_lint': 'false',
    'weakening_reason': '', 'weakening_authority': '', 'weakening_exception_ref': '',
    'weakening_expires': '', 'environment': '',
}
BASELINE = dict(DEFAULTS, language='multi', soft_fail_sast='false')
CLEAN_GATE = {'assurance_state': 'PASS', 'enforcement_state': 'ALLOWED', 'secret_gate': 'PASS',
              'unestablished': ''}
ATTRIB = {'weakening_reason': 'baseline inventory on first adoption',
          'weakening_authority': 'security lead', 'weakening_exception_ref': 'DISP-1'}


def S(name, inputs, gate, route, check=None):
    return (name, inputs, gate, route, check)


def shipped_defaults():
    """The workflow_call input defaults AS SHIPPED, rendered the way GitHub renders them.

    KDEC-008 OD-7: a caller who changes nothing must get the full control and PROCEED on a clean
    run. Restating the defaults here would prove this file's opinion of them; reading them proves
    the workflow's. An input with no default renders as '' exactly as GitHub would.
    """
    import yaml
    doc = yaml.safe_load(io.open(pbf.WF, encoding='utf-8'))
    on = doc.get('on', doc.get(True)) or {}
    out = {}
    for name, spec in ((on.get('workflow_call') or {}).get('inputs') or {}).items():
        v = (spec or {}).get('default', '')
        out[name] = ('true' if v else 'false') if isinstance(v, bool) else str(v)
    return out


SHIPPED = shipped_defaults()

SCENARIOS = [
    S('shipped_defaults_clean', SHIPPED, CLEAN_GATE, 'PROCEED',
      lambda o: (o.get('weakening_attribution') == 'WEAKENING_AT_BASELINE',
                 'a caller who changes nothing must be AT BASELINE, got %r'
                 % o.get('weakening_attribution'))),
    S('shipped_defaults_findings', SHIPPED,
      dict(CLEAN_GATE, assurance_state='FINDINGS', enforcement_state='BLOCKED'), 'BLOCKED'),
    S('defaults_unattributed', DEFAULTS, CLEAN_GATE, 'DECISION_REQUIRED'),
    S('defaults_attributed', dict(DEFAULTS, **ATTRIB), CLEAN_GATE, 'PROCEED_WITH_ADVISORY'),
    S('attribution_expired', dict(DEFAULTS, weakening_expires='2000-01-01', **ATTRIB), CLEAN_GATE,
      'DECISION_REQUIRED'),
    S('baseline_clean', BASELINE, CLEAN_GATE, 'PROCEED'),
    # AN EXPIRY NOBODY CAN READ IS NOT AN EXPIRY THAT HAS NOT ARRIVED. The check compared dates as
    # strings, so `never` (n > 2) and `31/12/1999` (3 > 2) sorted after every ISO date and read as
    # unexpired forever (estate review W4K, 2026-10-14).
    S('expiry_never', dict(DEFAULTS, weakening_expires='never', **ATTRIB), CLEAN_GATE,
      'DECISION_REQUIRED'),
    S('expiry_not_iso', dict(DEFAULTS, weakening_expires='31/12/1999', **ATTRIB), CLEAN_GATE,
      'DECISION_REQUIRED'),
    S('expiry_impossible', dict(DEFAULTS, weakening_expires='2099-13-45', **ATTRIB), CLEAN_GATE,
      'DECISION_REQUIRED'),
    S('expiry_future_iso', dict(DEFAULTS, weakening_expires='2099-12-31', **ATTRIB), CLEAN_GATE,
      'PROCEED_WITH_ADVISORY'),
    S('deeper_history', dict(BASELINE, scan_git_history='true'), CLEAN_GATE, 'PROCEED'),
    S('lint_enforced', dict(BASELINE, enforce_lint='true'), CLEAN_GATE, 'PROCEED'),
    S('secret', dict(BASELINE, advisory_mode='true'),
      dict(CLEAN_GATE, assurance_state='FINDINGS', enforcement_state='BLOCKED', secret_gate='FAIL'),
      'BLOCKED'),
    S('enforced_findings', BASELINE,
      dict(CLEAN_GATE, assurance_state='FINDINGS', enforcement_state='BLOCKED'), 'BLOCKED'),
    S('toolchain_blocked', BASELINE,
      dict(CLEAN_GATE, assurance_state='PARTIAL', enforcement_state='BLOCKED',
           unestablished='codeql(UNAVAILABLE) sast-go(COLLECTION_FAILED)'),
      'EVIDENCE_UNTRUSTED',
      lambda o: (o.get('controls_unavailable') == 'codeql,sast-go',
                 'controls_unavailable=%r, expected the two unestablished capabilities by name'
                 % o.get('controls_unavailable'))),
    S('gate_silent', BASELINE, {}, 'EVIDENCE_UNTRUSTED'),
    # KDEC-010: A VERSION GAP IS WARN-CLASS. scanner_state.PARTIAL "warns; does not block", so an
    # assurance PARTIAL whose every unestablished entry is a (PARTIAL) routes
    # PROCEED_WITH_ADVISORY -- advisory, never PROCEED, and the capability is named unavailable.
    # The same PARTIAL beside an UNAVAILABLE or COLLECTION_FAILED is still missing evidence
    # (EVIDENCE_UNTRUSTED), and an unattributed weakening still owes its decision first.
    S('version_gap_partial', BASELINE,
      dict(CLEAN_GATE, assurance_state='PARTIAL', enforcement_state='ALLOWED',
           unestablished='iac-scan(PARTIAL)'),
      'PROCEED_WITH_ADVISORY',
      lambda o: (o.get('controls_unavailable') == 'iac-scan',
                 'controls_unavailable=%r, expected the capped capability by name'
                 % o.get('controls_unavailable'))),
    S('version_gap_partial_unattributed', DEFAULTS,
      dict(CLEAN_GATE, assurance_state='PARTIAL', enforcement_state='ALLOWED',
           unestablished='iac-scan(PARTIAL)'),
      'DECISION_REQUIRED'),
    S('version_gap_beside_unavailable', BASELINE,
      dict(CLEAN_GATE, assurance_state='PARTIAL', enforcement_state='ALLOWED',
           unestablished='iac-scan(PARTIAL) codeql(UNAVAILABLE)'),
      'EVIDENCE_UNTRUSTED'),
    S('advisory_findings', dict(BASELINE, advisory_mode='true', **ATTRIB),
      dict(CLEAN_GATE, assurance_state='FINDINGS', enforcement_state='ADVISORY'),
      'PROCEED_WITH_ADVISORY'),
    S('sbom_off', dict(BASELINE, enable_sbom='false', **ATTRIB), CLEAN_GATE,
      'PROCEED_WITH_ADVISORY',
      lambda o: ('sbom' in o.get('controls_skipped', '').split(',')
                 and 'sbom' not in o.get('controls_executed', '').split(','),
                 'sbom must be skipped and not executed: skipped=%r executed=%r'
                 % (o.get('controls_skipped'), o.get('controls_executed')))),
]


def posture_step():
    import yaml
    doc = yaml.safe_load(io.open(pbf.WF, encoding='utf-8'))
    for s in (doc['jobs'][GATE_JOB].get('steps') or []):
        if s.get('id') == 'posture':
            return s
    return None


def resolve_env(env_map, inputs, gate):
    out, unknown = {}, []
    for k, v in (env_map or {}).items():
        def sub(m):
            key = m.group(1)
            if key.startswith('inputs.'):
                name = key[len('inputs.'):]
                if name not in inputs:
                    unknown.append(key)
                return inputs.get(name, '')
            if key.startswith('steps.gate.outputs.'):
                return gate.get(key[len('steps.gate.outputs.'):], '')
            unknown.append(key)
            return ''
        out[k] = EXPR.sub(sub, str(v))
    return out, unknown


def run(bash, script, env_extra):
    tmp = tempfile.mkdtemp(prefix='gate-routing-')
    try:
        out = os.path.join(tmp, 'o')
        summ = os.path.join(tmp, 's')
        io.open(out, 'w').close()
        io.open(summ, 'w').close()
        f = os.path.join(tmp, 'step.sh')
        io.open(f, 'w', encoding='utf-8', newline='\n').write(script)
        env = dict(os.environ, GITHUB_OUTPUT=out, GITHUB_STEP_SUMMARY=summ, **env_extra)
        p = subprocess.run([bash, f], capture_output=True, text=True, encoding='utf-8',
                           errors='replace', env=env, cwd=tmp)
        outputs = {}
        for line in io.open(out, encoding='utf-8'):
            if '=' in line:
                k, v = line.rstrip('\n').split('=', 1)
                outputs[k] = v
        return p.returncode, (p.stdout or '') + (p.stderr or ''), outputs
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


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
    step = posture_step()
    if not step:
        print('FAIL: job %r has no step with `id: posture`. Deployment has no routing_result to '
              'read, only a job conclusion -- the collapse the routing model exists to refuse.'
              % GATE_JOB)
        return 1
    bad = []
    for name, inputs, gate, want, check in SCENARIOS:
        env, unknown = resolve_env(step.get('env'), inputs, gate)
        if unknown:
            bad.append('%s: the step reads %s, which this probe does not model -- add it to '
                       'DEFAULTS rather than let it resolve empty' % (name, sorted(set(unknown))))
            continue
        rc, log, out = run(bash, step.get('run') or '', env)
        got = out.get('routing_result', '')
        print('  %-22s routing_result=%-22s attribution=%s' % (name, got or '(none)',
                                                               out.get('weakening_attribution')))
        if rc != 0:
            bad.append('%s: the posture step exited %d. It must record, not decide.\n%s'
                       % (name, rc, log[-500:]))
        if got != want:
            bad.append('%s: routing_result=%r, expected %r' % (name, got, want))
        if check:
            ok, msg = check(out)
            if not ok:
                bad.append('%s: %s' % (name, msg))
    if bad:
        for b in bad:
            print('FAIL: %s' % b)
        return 1
    print('PASS: the flagship emits routing_result, and it routes secrets and enforced findings to '
          'BLOCKED, missing evidence to EVIDENCE_UNTRUSTED, unattributed or expired weakenings to '
          'DECISION_REQUIRED, attributed or advisory ones to PROCEED_WITH_ADVISORY, and a clean run '
          'at baseline to PROCEED.')
    return 0


if __name__ == '__main__':
    sys.exit(main())

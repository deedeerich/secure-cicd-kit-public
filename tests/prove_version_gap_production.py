#!/usr/bin/env python3
"""A version-gap advisory is DEV/TEST ONLY: uat and prod refuse it unless a named person accepts it.

WHY THIS EXISTS (KDEC-014, owner rulings 2026-10-16)

    KDEC-010 routes a run whose only unestablished claims are version gaps -- no carried scanner
    can read the target version, so the job is capped at PARTIAL -- to PROCEED_WITH_ADVISORY, and
    both deploy reusables proceeded on PROCEED_WITH_ADVISORY at every tier. The owner ruled:
    "Version-gap-only PROCEED_WITH_ADVISORY is DEV/TEST ONLY. UAT and prod refuse it until the
    scanner gap is closed or a named person accepts it as an attributed exception." Then chose
    "Ship with the test sets": enforcement at uat/prod turns on only where READ (corpus-proven or
    cited) scanner ranges establish the gap -- data, not a caller toggle -- and until then the
    gap is recorded prominently. And "Weakening record + reviewers": the exception is the deploy's
    existing weakening record (weakening_authority names the accepter, weakening_reason, an
    unexpired YYYY-MM-DD weakening_expires) in a GitHub environment whose required reviewers
    approve the job; the deploy records which environment it ran in.

    So: resolve names the capped jobs whose gap every candidate's READ range establishes
    (proven_gap_jobs); the gate names each advisory's cause (advisory_causes: VERSION_GAP for an
    established gap, VERSION_GAP_UNVERIFIED for one resting on an UNVERIFIED range); the deploy's
    verdict step applies the ruling before login (vocabulary :: version_gap_ruling).

WHAT IS RUN (all as shipped, stubbed; nothing reaches a cloud)
    resolve   a Terraform 1.6.0 gap resting on Checkov/Trivy-config UNVERIFIED ranges ->
              gap_ranges UNVERIFIED, proven_gap_jobs empty. The same tree with both rows READ
              -> gap_ranges READ, proven_gap_jobs names iac-scan. And the SHIPPED rows, which the
              seeded corpus made READ (D-VF-4, 0.12..1.14): Terraform 9.0.0 above them -> READ,
              iac-scan proven -- the enforcement switch turned on by data alone.
    gate      the gate step then its posture step, both states: unproven -> VERSION_GAP_UNVERIFIED;
              proven -> VERSION_GAP. The posture step alone for every other cause.
    verdict   the deploy's `Gate verdict (refuse before login)` step, both reusables:
                uat/prod + VERSION_GAP, no exception             -> refused, VERSION_GAP_REFUSED
                prod + VERSION_GAP beside an unverified gap      -> refused (partly a proven gap)
                uat/prod + VERSION_GAP + valid weakening record  -> proceeds, accepted
                                                                    (VERSION_GAP_EXCEPTION_ACCEPTED)
                prod + record expired / unnamed / no reason /
                       no expiry / unreadable expiry             -> refused
                uat/prod + VERSION_GAP_UNVERIFIED only           -> proceeds, recorded loudly
                test, dev, sandbox + either gap                  -> proceeds, VERSION_GAP_RECORDED
                prod + a non-version-gap cause, or PROCEED       -> proceeds, VERSION_GAP_NOT_ENGAGED
                prod + PROCEED_WITH_ADVISORY, cause absent or
                       unregistered                              -> refused, ADVISORY_CAUSE_UNKNOWN
                any tier + BLOCKED / DECISION_REQUIRED /
                       EVIDENCE_UNTRUSTED / no or unknown verdict -> refused, VERSION_GAP_NOT_ENGAGED
              EXACTLY ONE registered ruling on EVERY path through the step, refused or not: the
              posture step must be able to tell "not engaged" from "the verdict step never
              answered" (scripts/trace_assurance_flow.py UNGUARDED, 2026-10-21).
    posture   a refused gap routes DECISION_REQUIRED; an unknown cause EVIDENCE_UNTRUSTED; an
              accepted exception and an unverified record are shown, with the environment. An
              EMPTY ruling is an absent answer: EVIDENCE_UNTRUSTED (never weaker than BLOCKED
              where that already applies), shown as "not reported", never as "not engaged".
    job       the WHOLE deploy job against the stub cloud: refused at prod with no az call and the
              login skipped; accepted at uat with the record and environment in outcome.json;
              unverified at prod deploys with the ruling in outcome.json.
    static    inputs; the security reusable's outputs; the starter template passes the causes.

    The reviewer half of the exception is a GitHub environment setting the kit cannot read; it is
    documented as required, not proven here.

EXIT 0 every case decided as it must; 1 a case decided wrongly; 2 could not be checked (UNKNOWN).
"""
import io
import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import _deploy_steps as D  # noqa: E402
import prove_bootstrap_failure as pbf  # noqa: E402
import prove_gate_routing as G  # noqa: E402

VERDICT_STEP = 'Gate verdict (refuse before login)'
# The gate-routing probe's clean gate and job name, under local names.
CLEAN_GATE = G.CLEAN_GATE
GATE_JOB = G.GATE_JOB
TEMPLATE = os.path.join(D.ROOT, 'templates', 'build-deploy.yml')
FUTURE, PAST = '2099-12-31', '2020-01-01'
REMOVED_INPUTS = ('version_gap_accepted_by', 'version_gap_acceptance_reason',
                  'version_gap_acceptance_expires')
VALID = {'weakening_authority': 'A. Named Person', 'weakening_reason':
         'no carried scanner reads this target yet; compensating review done',
         'weakening_exception_ref': 'EXC-1', 'weakening_expires': FUTURE}
RECORD_FIELDS = ('weakening_authority', 'weakening_reason', 'weakening_exception_ref',
                 'weakening_expires')
TF = {'infra/main.tf': 'terraform {\n  required_version = "= 1.6.0"\n}\n'}
# Above the shipped corpus-measured ceiling (scanner-registry.yaml iac-scan, 0.12..1.14).
TF_ABOVE_SHIPPED = {'infra/main.tf': 'terraform {\n  required_version = "= 9.0.0"\n}\n'}
NOT_ENGAGED = 'VERSION_GAP_NOT_ENGAGED'
# Counts the rulings the step wrote, however it ends (exit 0, refuse's exit 1, or set -e): a test
# prologue, never shipped. The count is appended AFTER it is taken, so it never counts itself.
COUNT_RULINGS = ('trap \'echo "ruling_lines=$(grep -c "^version_gap_ruling=" "$GITHUB_OUTPUT")"'
                 ' >> "$GITHUB_OUTPUT"\' EXIT\n')


def registered_rulings():
    """-> the values assurance-taxonomy.yaml registers under version_gap_ruling, or None."""
    import yaml
    doc = yaml.safe_load(io.open(os.path.join(D.ROOT, 'assurance-taxonomy.yaml'), encoding='utf-8'))
    ns = ((doc or {}).get('namespaces') or {}).get('version_gap_ruling') or {}
    vals = ns.get('values')
    return set(vals) if isinstance(vals, dict) else None


def causes_set(text):
    return set(c for c in (text or '').split(',') if c)


# ----------------------------------------------------------------------------- resolve
def prove_resolve(bad):
    """-> proven_gap_jobs for (unverified, proven), or None when resolve could not be run."""
    import test_resolve as R
    shell = R.extract_resolve_shell(R.load_workflow())
    got = []
    # Since D-VF-4 the SHIPPED IaC rows are corpus-proven READ (0.12..1.14), so the unverified
    # state is built here from the shipped step, exactly as the proven one was before them.
    unverified_shell, proven_shell = shell, shell
    for tool in ('checkov', 'trivy-config'):
        unverified_shell = R.with_entry(unverified_shell, 'iac-scan', 'iac', tool, min=None,
                                        max=None, verified='UNVERIFIED')
        proven_shell = R.with_entry(proven_shell, 'iac-scan', 'iac', tool, min='0.12', max='1.5',
                                    verified='READ')
    for label, sh, tf, want_ranges, want_proven in (
            ('unverified (UNVERIFIED)', unverified_shell, TF, 'UNVERIFIED', ''),
            ('corpus-proven (READ)', proven_shell, TF, 'READ', 'iac-scan'),
            ('shipped, above (READ)', shell, TF_ABOVE_SHIPPED, 'READ', 'iac-scan')):
        r = R.run_case(sh, tf, discover={'iac': 'true'})
        row = R.sel(r, capability='iac', root='infra')
        print('  resolve %-24s state=%s gap_ranges=%s capped=%r proven_gap_jobs=%r'
              % (label, row.get('state'), row.get('gap_ranges'), r.get('capped_jobs'),
                 r.get('proven_gap_jobs')))
        if row.get('state') != 'VERSION_GAP' or 'iac-scan' not in (r.get('capped_jobs') or '').split():
            bad.append('resolve %s: Terraform %s is not a capped VERSION_GAP (row=%r)'
                       % (label, row.get('target'), row))
        if row.get('gap_ranges') != want_ranges or (r.get('proven_gap_jobs') or '') != want_proven:
            bad.append('resolve %s: gap_ranges=%r proven_gap_jobs=%r, want %s / %r -- the '
                       'enforcement switch must be the registry data' % (
                           label, row.get('gap_ranges'), r.get('proven_gap_jobs'), want_ranges,
                           want_proven))
        got.append(r.get('proven_gap_jobs') or '')
    return got


# ----------------------------------------------------------------------------- gate side
def prove_gate(bash, bad):
    gate = pbf.gate_script()
    step = G.posture_step()
    if not gate or not step:
        bad.append('gate: the security gate step or its posture step is missing')
        return
    for label, proven, want in (('unproven', '', 'VERSION_GAP_UNVERIFIED'),
                                ('proven', 'iac-scan', 'VERSION_GAP')):
        values = pbf.ctx(capped_jobs='iac-scan', capability_gaps='iac@infra', capability_gap_count='1')
        values['needs.resolve.outputs.proven_gap_jobs'] = proven
        body, _seen = pbf.substitute(gate, values)
        rc, emitted, log, _summ = pbf.run(bash, body, pbf.gate_env(values))
        env, unknown = G.resolve_env(step.get('env'), G.BASELINE, emitted)
        if unknown:
            bad.append('gate chain: the posture step reads %s, unmodelled here' % sorted(set(unknown)))
            return
        rc2, log2, out = G.run(bash, step.get('run') or '', env)
        print('  gate   chain %-9s version_gapped=%r unverified=%r -> %s advisory_causes=%r'
              % (label, emitted.get('version_gapped'), emitted.get('version_gapped_unverified'),
                 out.get('routing_result'), out.get('advisory_causes')))
        if out.get('routing_result') != 'PROCEED_WITH_ADVISORY' or \
                causes_set(out.get('advisory_causes')) != {want}:
            bad.append('gate chain %s: want PROCEED_WITH_ADVISORY with advisory_causes=%s; got %r / %r'
                       % (label, want, out.get('routing_result'), out.get('advisory_causes')))
    partial = dict(CLEAN_GATE, assurance_state='PARTIAL', unestablished='iac-scan(PARTIAL)')
    cases = [
        ('proven_gap_only', G.BASELINE, dict(partial, version_gapped='iac-scan'),
         'PROCEED_WITH_ADVISORY', {'VERSION_GAP'}),
        ('unverified_gap_only', G.BASELINE, dict(partial, version_gapped_unverified='iac-scan'),
         'PROCEED_WITH_ADVISORY', {'VERSION_GAP_UNVERIFIED'}),
        ('partial_not_a_gap', G.BASELINE, partial, 'PROCEED_WITH_ADVISORY', {'COVERAGE_PARTIAL'}),
        ('weakening_attributed', dict(G.DEFAULTS, **G.ATTRIB), CLEAN_GATE,
         'PROCEED_WITH_ADVISORY', {'WEAKENING_ATTRIBUTED'}),
        ('findings_not_blocked', dict(G.BASELINE, advisory_mode='true', **G.ATTRIB),
         dict(CLEAN_GATE, assurance_state='FINDINGS', enforcement_state='ADVISORY'),
         'PROCEED_WITH_ADVISORY', {'FINDINGS_NOT_BLOCKED', 'WEAKENING_ATTRIBUTED'}),
        ('gap_and_weakening', dict(G.DEFAULTS, **G.ATTRIB), dict(partial, version_gapped='iac-scan'),
         'PROCEED_WITH_ADVISORY', {'VERSION_GAP', 'WEAKENING_ATTRIBUTED'}),
        ('clean', G.BASELINE, CLEAN_GATE, 'PROCEED', set()),
        ('blocked', G.BASELINE, dict(CLEAN_GATE, assurance_state='FINDINGS',
                                     enforcement_state='BLOCKED'), 'BLOCKED', set()),
    ]
    for name, inputs, gate_out, route, want in cases:
        env, unknown = G.resolve_env(step.get('env'), inputs, gate_out)
        rc, log, out = G.run(bash, step.get('run') or '', env)
        got = causes_set(out.get('advisory_causes'))
        print('  gate   %-22s routing_result=%-22s advisory_causes=%s'
              % (name, out.get('routing_result'), ','.join(sorted(got)) or '(none)'))
        if 'advisory_causes' not in out:
            bad.append('gate %s: the posture step emits no advisory_causes' % name)
        if out.get('routing_result') != route or got != want:
            bad.append('gate %s: routing_result=%r advisory_causes=%r, want %s %s'
                       % (name, out.get('routing_result'), out.get('advisory_causes'), route,
                          sorted(want)))


# ----------------------------------------------------------------------------- deploy verdict
def V(name, tier, route, causes, exc, must, ruling, phrase=None):
    return (name, tier, route, causes, exc, must, ruling, phrase)


VERDICT_CASES = [
    V('uat-gap-no-exception', 'uat', 'PROCEED_WITH_ADVISORY', 'VERSION_GAP', {}, False,
      'VERSION_GAP_REFUSED', 'KDEC-014'),
    V('prod-gap-no-exception', 'prod', 'PROCEED_WITH_ADVISORY', 'VERSION_GAP', {}, False,
      'VERSION_GAP_REFUSED', 'KDEC-014'),
    V('prod-gap-partly', 'prod', 'PROCEED_WITH_ADVISORY', 'FINDINGS_NOT_BLOCKED,VERSION_GAP', {},
      False, 'VERSION_GAP_REFUSED', 'KDEC-014'),
    V('prod-gap-beside-unverified', 'prod', 'PROCEED_WITH_ADVISORY',
      'VERSION_GAP_UNVERIFIED,VERSION_GAP', {}, False, 'VERSION_GAP_REFUSED', 'KDEC-014'),
    V('uat-gap-valid-exception', 'uat', 'PROCEED_WITH_ADVISORY', 'VERSION_GAP', VALID, True,
      'VERSION_GAP_EXCEPTION_ACCEPTED'),
    V('prod-gap-valid-exception', 'prod', 'PROCEED_WITH_ADVISORY', 'VERSION_GAP', VALID, True,
      'VERSION_GAP_EXCEPTION_ACCEPTED'),
    V('prod-gap-expired', 'prod', 'PROCEED_WITH_ADVISORY', 'VERSION_GAP',
      dict(VALID, weakening_expires=PAST), False, 'VERSION_GAP_REFUSED', 'expired'),
    V('prod-gap-unnamed', 'prod', 'PROCEED_WITH_ADVISORY', 'VERSION_GAP',
      dict(VALID, weakening_authority='  '), False, 'VERSION_GAP_REFUSED', 'named'),
    V('prod-gap-no-reason', 'prod', 'PROCEED_WITH_ADVISORY', 'VERSION_GAP',
      dict(VALID, weakening_reason=''), False, 'VERSION_GAP_REFUSED', 'reason'),
    V('prod-gap-no-expiry', 'prod', 'PROCEED_WITH_ADVISORY', 'VERSION_GAP',
      dict(VALID, weakening_expires=''), False, 'VERSION_GAP_REFUSED', 'expiry'),
    V('prod-gap-unreadable-expiry', 'prod', 'PROCEED_WITH_ADVISORY', 'VERSION_GAP',
      dict(VALID, weakening_expires='2099-13-45'), False, 'VERSION_GAP_REFUSED', 'expiry'),
    V('uat-unverified-recorded', 'uat', 'PROCEED_WITH_ADVISORY', 'VERSION_GAP_UNVERIFIED', {}, True,
      'VERSION_GAP_UNVERIFIED_RECORDED', 'RECORDED NOT ENFORCED'),
    V('prod-unverified-recorded', 'prod', 'PROCEED_WITH_ADVISORY', 'VERSION_GAP_UNVERIFIED', {},
      True, 'VERSION_GAP_UNVERIFIED_RECORDED', 'RECORDED NOT ENFORCED'),
    V('test-gap-proceeds', 'test', 'PROCEED_WITH_ADVISORY', 'VERSION_GAP', {}, True,
      'VERSION_GAP_RECORDED'),
    V('dev-gap-proceeds', 'dev', 'PROCEED_WITH_ADVISORY', 'VERSION_GAP', {}, True,
      'VERSION_GAP_RECORDED'),
    V('sandbox-gap-proceeds', 'sandbox', 'PROCEED_WITH_ADVISORY', 'VERSION_GAP', {}, True,
      'VERSION_GAP_RECORDED'),
    V('test-unverified-proceeds', 'test', 'PROCEED_WITH_ADVISORY', 'VERSION_GAP_UNVERIFIED', {}, True,
      'VERSION_GAP_RECORDED'),
    V('prod-weakening-unchanged', 'prod', 'PROCEED_WITH_ADVISORY', 'WEAKENING_ATTRIBUTED', {}, True,
      NOT_ENGAGED),
    V('prod-findings-unchanged', 'prod', 'PROCEED_WITH_ADVISORY', 'FINDINGS_NOT_BLOCKED', {}, True,
      NOT_ENGAGED),
    V('prod-partial-unchanged', 'prod', 'PROCEED_WITH_ADVISORY', 'COVERAGE_PARTIAL', {}, True,
      NOT_ENGAGED),
    V('prod-proceed-unchanged', 'prod', 'PROCEED', '', {}, True, NOT_ENGAGED),
    # The paths that wrote NO ruling at a279f5a: the verdict step answers on every one of them.
    V('dev-proceed', 'dev', 'PROCEED', '', {}, True, NOT_ENGAGED),
    V('dev-findings-no-gap', 'dev', 'PROCEED_WITH_ADVISORY', 'FINDINGS_NOT_BLOCKED', {}, True,
      NOT_ENGAGED),
    V('dev-cause-absent', 'dev', 'PROCEED_WITH_ADVISORY', '', {}, True, NOT_ENGAGED),
    V('uat-proceed', 'uat', 'PROCEED', '', {}, True, NOT_ENGAGED),
    V('prod-blocked', 'prod', 'BLOCKED', '', {}, False, NOT_ENGAGED, 'BLOCKED'),
    V('prod-decision-required', 'prod', 'DECISION_REQUIRED', '', {}, False, NOT_ENGAGED,
      'DECISION_REQUIRED'),
    V('prod-evidence-untrusted', 'prod', 'EVIDENCE_UNTRUSTED', '', {}, False, NOT_ENGAGED,
      'EVIDENCE_UNTRUSTED'),
    V('prod-no-verdict', 'prod', '', '', {}, False, NOT_ENGAGED, 'no gate verdict'),
    V('dev-unknown-verdict', 'dev', 'MAYBE', '', {}, False, NOT_ENGAGED, None),
    V('prod-cause-absent', 'prod', 'PROCEED_WITH_ADVISORY', '', {}, False,
      'ADVISORY_CAUSE_UNKNOWN', 'cause'),
    V('prod-cause-unregistered', 'prod', 'PROCEED_WITH_ADVISORY', 'version_gap', {}, False,
      'ADVISORY_CAUSE_UNKNOWN', 'not a registered'),
]


def verdict_values(tier, route, causes, exc):
    v = {'inputs.routing_result': route, 'inputs.environment_tier': tier,
         'inputs.advisory_causes': causes}
    for k in RECORD_FIELDS:
        v['inputs.' + k] = exc.get(k, '')
    return v


def prove_verdict(bash, bad):
    for wf in D.deploy_workflows:
        name = os.path.basename(wf)
        doc = D.load(wf)
        declared = D.inputs_of(doc)
        if 'advisory_causes' not in declared:
            bad.append('%s: does not declare advisory_causes' % name)
        stale = [i for i in REMOVED_INPUTS if i in declared]
        if stale:
            bad.append('%s: declares %s; the exception is the existing weakening record' % (name, stale))
        _, step = D.step_named(doc, VERDICT_STEP)
        if step is None:
            bad.append('%s: no step %r' % (name, VERDICT_STEP))
            continue
        registered = registered_rulings()
        if registered is None:
            bad.append('assurance-taxonomy.yaml: no namespaces.version_gap_ruling.values')
            registered = set()
        for case, tier, route, causes, exc, must, ruling, phrase in VERDICT_CASES:
            env = D.step_env(doc, step, verdict_values(tier, route, causes, exc))
            rc, out, log, summ = D.run_script(bash, COUNT_RULINGS + step['run'], env)
            got = out.get('version_gap_ruling', '')
            if out.get('ruling_lines') != '1':
                bad.append('%s %s: the verdict step wrote %s version_gap_ruling line(s); it must answer '
                           'exactly once on every path, or the posture step cannot tell "not engaged" '
                           'from "never answered"' % (name, case, out.get('ruling_lines', '?')))
            if got and got not in registered:
                bad.append('%s %s: version_gap_ruling=%r is not registered in assurance-taxonomy.yaml'
                           % (name, case, got))
            print('  verdict %-30s %-28s exit=%d ruling=%s' % (name, case, rc, got or '(none)'))
            if must and rc != 0:
                bad.append('%s %s: refused (exit %d) a deploy the ruling permits.\n%s'
                           % (name, case, rc, log[-400:]))
            if must and phrase and phrase not in log:
                bad.append('%s %s: proceeded without the prominent record %r' % (name, case, phrase))
            if not must:
                if rc == 0:
                    bad.append('%s %s: PROCEEDED. KDEC-014: uat and prod refuse a proven version-gap '
                               'advisory without an attributed exception.' % (name, case))
                elif phrase and phrase not in log:
                    bad.append('%s %s: refused, but not for the stated reason (wanted %r).\n%s'
                               % (name, case, phrase, log[-400:]))
            if got != ruling:
                bad.append('%s %s: version_gap_ruling=%r, want %r' % (name, case, got, ruling))


# ----------------------------------------------------------------------------- deploy posture
def prove_posture(bash, bad):
    import prove_deploy_posture as P
    for wf in D.deploy_workflows:
        name = os.path.basename(wf)
        doc = D.load(wf)
        step = [s for s in D.steps(doc) if s.get('id') == 'posture'][0]
        refused = P.outcomes(verdict='failure', tier='skipped', capability='skipped', cap_value='',
                             report='failure', deployment='DEPLOY_REFUSED', job='failure')
        for case, ruling, want in (('gap-refused', 'VERSION_GAP_REFUSED', 'DECISION_REQUIRED'),
                                   ('cause-unknown', 'ADVISORY_CAUSE_UNKNOWN', 'EVIDENCE_UNTRUSTED')):
            values = dict(P.base_inputs(wf), **refused)
            values.update({'inputs.routing_result': 'PROCEED_WITH_ADVISORY',
                           'inputs.environment_tier': 'prod',
                           'steps.verdict.outputs.version_gap_ruling': ruling})
            env = D.step_env(doc, step, values)
            rc, out, log, _s = D.run_script(bash, step.get('run') or '', env)
            print('  posture %-30s %-14s routing_result=%s' % (name, case, out.get('routing_result')))
            if out.get('routing_result') != want:
                bad.append('%s posture %s: routing_result=%r, want %s'
                           % (name, case, out.get('routing_result'), want))
        # AN EMPTY RULING IS AN ABSENT ANSWER, never "not engaged". The verdict step answers on
        # every path it reaches, so empty means it never ran or never finished: EVIDENCE_UNTRUSTED,
        # and never weaker than the precedence already gives (a tier refusal stays BLOCKED).
        for case, outs, gate, want in (
                ('absent-clean', P.outcomes(), 'PROCEED', 'EVIDENCE_UNTRUSTED'),
                ('absent-advisory', P.outcomes(), 'PROCEED_WITH_ADVISORY', 'EVIDENCE_UNTRUSTED'),
                ('absent-tier-refused', P.outcomes(tier='failure', capability='skipped',
                                                   cap_value='', report='failure',
                                                   deployment='DEPLOY_REFUSED', job='failure'),
                 'PROCEED', 'BLOCKED'),
                ('not-engaged-clean', P.outcomes(), 'PROCEED', 'PROCEED')):
            values = dict(P.base_inputs(wf), **outs)
            values.update({'inputs.routing_result': gate, 'inputs.environment_tier': 'prod',
                           'steps.verdict.outputs.version_gap_ruling':
                               NOT_ENGAGED if case.startswith('not-engaged') else ''})
            env = D.step_env(doc, step, values)
            rc, out, log, summ = D.run_script(bash, step.get('run') or '', env)
            print('  posture %-30s %-20s routing_result=%s' % (name, case, out.get('routing_result')))
            if out.get('routing_result') != want:
                bad.append('%s posture %s: routing_result=%r, want %s -- an absent ruling was given '
                           'meaning' % (name, case, out.get('routing_result'), want))
            row = [ln for ln in summ.splitlines() if 'version-gap ruling' in ln]
            shown = 'not reported' if case.startswith('absent') else NOT_ENGAGED
            if not row or shown not in row[0] or (case.startswith('absent') and 'not engaged' in row[0]):
                bad.append('%s posture %s: the ruling row reads %r, want %r'
                           % (name, case, row[0] if row else None, shown))
        for case, ruling, causes, extra, needs in (
                ('accepted', 'VERSION_GAP_EXCEPTION_ACCEPTED', 'VERSION_GAP', VALID,
                 ('VERSION_GAP_EXCEPTION_ACCEPTED', 'A. Named Person', FUTURE, 'uat-env')),
                ('unverified', 'VERSION_GAP_UNVERIFIED_RECORDED', 'VERSION_GAP_UNVERIFIED', {},
                 ('VERSION_GAP_UNVERIFIED_RECORDED', 'RECORDED AND NOT ENFORCED', 'uat-env'))):
            ok = dict(P.base_inputs(wf), **P.outcomes())
            ok.update({'inputs.routing_result': 'PROCEED_WITH_ADVISORY',
                       'inputs.environment_tier': 'uat', 'inputs.github_environment': 'uat-env',
                       'inputs.advisory_causes': causes,
                       'steps.verdict.outputs.version_gap_ruling': ruling})
            ok.update({'inputs.' + k: v for k, v in extra.items()})
            env = D.step_env(doc, step, ok)
            rc, out, log, summ = D.run_script(bash, step.get('run') or '', env)
            print('  posture %-30s %-14s routing_result=%s' % (name, case, out.get('routing_result')))
            if out.get('routing_result') != 'PROCEED_WITH_ADVISORY':
                bad.append('%s posture %s: routing_result=%r' % (name, case, out.get('routing_result')))
            for need in needs:
                if need not in summ:
                    bad.append('%s posture %s: the posture summary does not record %r'
                               % (name, case, need))


# ----------------------------------------------------------------------------- whole job
def prove_job(bad):
    import _workflow_runner as W
    import prove_deploy_outcome as O
    # Multiple-revision mode: at uat the capability step refuses a target it cannot reverse.
    worlds = ((W.D.CONTAINERAPP, O.ca_inputs, W.containerapp_state),
              (W.D.APPSERVICE, O.as_inputs, W.appservice_state))

    def outcome_of(res):
        o = res['evidence'].get('outcome.json')
        return o if isinstance(o, dict) else {}

    for wf, inputs, state in worlds:
        name = os.path.basename(wf)
        res, _final, calls = W.run_world(wf, inputs(routing_result='PROCEED_WITH_ADVISORY',
                                                    environment_tier='prod',
                                                    advisory_causes='VERSION_GAP'), state())
        login = [o for n, o in res['order'] if n == 'Azure login (OIDC)']
        o = outcome_of(res)
        print('  job    %-30s refused: az calls=%d login=%s outcome=%s'
              % (name, len(calls), login, o.get('deployment_outcome')))
        if calls:
            bad.append('%s job: %d az call(s) made on a refused version-gap deploy at prod'
                       % (name, len(calls)))
        if login != ['skipped']:
            bad.append('%s job: the login step was %r, not skipped' % (name, login))
        if o.get('deployment_outcome') != 'DEPLOY_REFUSED' or \
                o.get('gate', {}).get('version_gap_ruling') != 'VERSION_GAP_REFUSED':
            bad.append('%s job: refused run outcome=%r gate=%r'
                       % (name, o.get('deployment_outcome'), o.get('gate')))

        res, _final, calls = W.run_world(wf, inputs(routing_result='PROCEED_WITH_ADVISORY',
                                                    environment_tier='uat', github_environment='uat-env',
                                                    advisory_causes='VERSION_GAP', **VALID), state())
        o = outcome_of(res)
        g = o.get('gate', {})
        print('  job    %-30s accepted: outcome=%s ruling=%s exception=%s env=%r'
              % (name, o.get('deployment_outcome'), g.get('version_gap_ruling'),
                 json.dumps(g.get('version_gap_exception')), g.get('github_environment')))
        if o.get('deployment_outcome') != 'DEPLOY_HEALTHY':
            bad.append('%s job: an accepted exception at uat did not deploy (%r)\n%s'
                       % (name, o.get('deployment_outcome'), res['log'][-600:]))
        want_exc = {'accepted_by': VALID['weakening_authority'], 'reason': VALID['weakening_reason'],
                    'exception_ref': VALID['weakening_exception_ref'], 'expires': FUTURE}
        if g.get('version_gap_ruling') != 'VERSION_GAP_EXCEPTION_ACCEPTED' or \
                g.get('version_gap_exception') != want_exc or g.get('advisory_causes') != ['VERSION_GAP'] \
                or g.get('github_environment') != 'uat-env':
            bad.append('%s job: outcome.json does not record the accepted exception and the '
                       'environment: gate=%r' % (name, g))

        res, _final, calls = W.run_world(wf, inputs(routing_result='PROCEED_WITH_ADVISORY',
                                                    environment_tier='prod', github_environment='prod-env',
                                                    advisory_causes='VERSION_GAP_UNVERIFIED'), state())
        o = outcome_of(res)
        g = o.get('gate', {})
        print('  job    %-30s unverified: outcome=%s ruling=%s'
              % (name, o.get('deployment_outcome'), g.get('version_gap_ruling')))
        if o.get('deployment_outcome') != 'DEPLOY_HEALTHY' or \
                g.get('version_gap_ruling') != 'VERSION_GAP_UNVERIFIED_RECORDED' or \
                'RECORDED AND NOT ENFORCED' not in res['summary']:
            bad.append('%s job: an unverified gap at prod must deploy with the gap recorded '
                       'prominently: outcome=%r gate=%r' % (name, o.get('deployment_outcome'), g))


# ----------------------------------------------------------------------------- static
def prove_static(bad):
    import yaml
    doc = yaml.safe_load(io.open(pbf.WF, encoding='utf-8'))
    on = doc.get('on', doc.get(True)) or {}
    outs = (on.get('workflow_call') or {}).get('outputs') or {}
    if 'security-gate.outputs.advisory_causes' not in str((outs.get('advisory_causes') or {}).get('value')):
        bad.append('reusable-security.yml: no workflow output advisory_causes from the gate job')
    jobs = doc['jobs']
    if 'steps.posture.outputs.advisory_causes' not in str((jobs[GATE_JOB].get('outputs') or {})
                                                          .get('advisory_causes')):
        bad.append('reusable-security.yml: the security-gate job does not export advisory_causes')
    if 'steps.resolve.outputs.proven_gap_jobs' not in str((jobs['resolve'].get('outputs') or {})
                                                          .get('proven_gap_jobs')):
        bad.append('reusable-security.yml: the resolve job does not export proven_gap_jobs')
    t = D.load(TEMPLATE)
    w = ((t.get('jobs') or {}).get('deploy') or {}).get('with') or {}
    if 'needs.security.outputs.advisory_causes' not in str(w.get('advisory_causes', '')):
        bad.append('templates/build-deploy.yml: the deploy job does not pass advisory_causes')


def main():
    try:
        import yaml  # noqa: F401
    except ImportError:
        print('UNKNOWN: PyYAML unavailable.')
        return 2
    bash, why = D.bash()
    if not bash:
        print('UNKNOWN: no usable bash (%s).' % why)
        return 2
    bad = []
    prove_static(bad)
    prove_resolve(bad)
    prove_gate(bash, bad)
    prove_verdict(bash, bad)
    prove_posture(bash, bad)
    prove_job(bad)
    if bad:
        for b in bad:
            print('FAIL: %s' % b)
        return 1
    print('PASS: resolve classifies a version gap by the ranges behind it (READ -> enforced, '
          'UNVERIFIED -> recorded), the gate names the cause, and the deploy proceeds below uat '
          'with the gap recorded; at uat/prod it records an UNVERIFIED gap prominently and refuses '
          'an established one before login unless the weakening record names the accepter, a '
          'reason and an unexpired expiry, recording it and the environment. Other causes are '
          'unchanged (KDEC-014).')
    print('      STUBBED: no live gate run or live deploy has exercised this. The reviewer half of '
          'the exception is a GitHub environment setting, documented, not proven here.')
    return 0


if __name__ == '__main__':
    sys.exit(main())

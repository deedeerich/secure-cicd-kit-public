#!/usr/bin/env python3
"""The starter template hands the deploy the COMBINED verdict, the vended tier and names, and a pin.

WHY THIS EXISTS (ledger P-01 / L87, LZ-1; PROVENANCE_AND_ATTESTATION.md section 9 steps 2-3;
docs/architecture/LZ_KIT_HANDOFF_CONTRACT.md)

    templates/build-deploy.yml computed a combined verdict in its `verdict` job -- the
    precedence-maximum of the security verdict, the build verdict and the artifact identity -- and
    then passed the deploy the SECURITY verdict alone, so a build that routed DECISION_REQUIRED, or
    an identity nobody proved, still reached the deploy as PROCEED wherever the verdict job's
    `deploy_allowed` was bypassed. It hard-coded `environment_tier: prod`, so every consumer
    deployed under the production rules whatever it was deploying to, and the tier was a string
    the caller typed rather than the value the landing zone vended. It read un-prefixed variables
    (the resource group, the app name, ...) where the hand-off contract names KIT_*; ran the build
    and the deploy in one GitHub environment ("production"), so one identity both pushed and
    deployed; and pinned the kit `@v1`, a moving tag -- the template's own header said to replace it.

WHAT THE DEPLOY IS GIVEN NOW
    routing_result   needs.verdict.outputs.deploy_routing_result: the precedence-maximum of the
                     security verdict, the build verdict and the identity check. The V1
                     attestation verification is NOT folded into it: the deploy reusable runs V1
                     itself before login (P-02), and a plan-held V1 (PROCEED_WITH_ADVISORY) has no
                     registered advisory_cause -- folded in, it would read at uat/prod as an
                     advisory whose cause is absent and refuse every private repository's deploy
                     (KDEC-014 ADVISORY_CAUSE_UNKNOWN). V1 still gates here: deploy_allowed reads it.
    environment_tier vars.KIT_ENVIRONMENT_TIER, never a literal; the deploy reusable binds it to its
                     own GitHub environment's KIT_ENVIRONMENT_TIER and refuses a mismatch (B-13).
    names            vars.KIT_RESOURCE_GROUP, KIT_APP_NAME, KIT_ACR_LOGIN_SERVER,
                     KIT_IMAGE_REPOSITORY, KIT_CLOUD (the contract's names).
    identities       the build runs in its own GitHub environment (the build identity, AcrPush
                     only), separate from the deploy environment the dispatch names.
    pin              every kit `uses:` is a 40-hex commit SHA (a placeholder the adopter replaces).

WHAT IS RUN
    Static reads of the template, then the template's `decide` step AS SHIPPED under GitHub's shell
    with the upstream outputs stubbed, then the deploy reusable's own `Gate verdict (refuse before
    login)` step at tier prod with exactly what the template hands it.

CASES (docs/PROOF_RULE.md)
    allowed           security, build, identity clean, V1 held by the plan -> deploy_routing_result
                      PROCEED; the reusable's verdict step at prod proceeds
    attack            build DECISION_REQUIRED, identity unverified, V1 contradicted -> not allowed;
                      the deploy routing_result carries the worst of the release verdicts
    missing-evidence  an absent security verdict -> EVIDENCE_UNTRUSTED
    recovery          the same run with the security verdict restored -> PROCEED
    contrast          what the template USED to hand over at prod (the V1-folded advisory, no cause)
                      is refused by the reusable -- the reason the deploy verdict excludes V1

EXIT 0 proven   1 a case decided wrongly   2 could not be checked (UNKNOWN, never PASS)
"""
import os
import re
import shutil
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import _deploy_steps as D  # noqa: E402
import _step_harness as H  # noqa: E402

TPL = 'templates/build-deploy.yml'
PROVEN = 'REGISTRY_IDENTITY_PROVEN'
REQ = "github.event_name == 'workflow_dispatch' && inputs.deploy"
VERDICT_STEP = 'Gate verdict (refuse before login)'
SHA_REF = re.compile(r'@[0-9a-f]{40}$')
CONTRACT = {'resource_group': 'vars.KIT_RESOURCE_GROUP',
            'containerapp_name': 'vars.KIT_APP_NAME',
            'acr_login_server': 'vars.KIT_ACR_LOGIN_SERVER',
            'image_repository': 'vars.KIT_IMAGE_REPOSITORY',
            'environment_tier': 'vars.KIT_ENVIRONMENT_TIER',
            'cloud': 'vars.KIT_CLOUD'}
TIERS = ('sandbox', 'dev', 'test', 'uat', 'prod')


def norm(v):
    return ' '.join(str(v or '').split())


def static(doc, bad):
    jobs = doc.get('jobs') or {}
    dep, build, ver = jobs.get('deploy') or {}, jobs.get('build') or {}, jobs.get('verdict') or {}
    w = dep.get('with') or {}
    rr = norm(w.get('routing_result'))
    if rr != '${{ needs.verdict.outputs.deploy_routing_result }}':
        bad.append('deploy routing_result is %r: the deploy must be handed the COMBINED verdict '
                   '(needs.verdict.outputs.deploy_routing_result), not one stage\'s' % rr)
    outs = ver.get('outputs') or {}
    if norm(outs.get('deploy_routing_result')) != '${{ steps.decide.outputs.deploy_routing_result }}':
        bad.append('the verdict job does not publish deploy_routing_result from its decide step')
    tier = norm(w.get('environment_tier'))
    if tier in TIERS or 'vars.KIT_ENVIRONMENT_TIER' not in tier:
        bad.append('deploy environment_tier is %r: a literal tier, or not the vended '
                   'vars.KIT_ENVIRONMENT_TIER' % tier)
    for k, want in CONTRACT.items():
        if want not in norm(w.get(k)):
            bad.append('deploy %s is %r, not the contract name %s' % (k, w.get(k), want))
    bw = build.get('with') or {}
    for k in ('acr_login_server', 'image_repository'):
        if CONTRACT[k] not in norm(bw.get(k)):
            bad.append('build %s is %r, not the contract name %s' % (k, bw.get(k), CONTRACT[k]))
    for jname, j in (('build', build), ('deploy', dep)):
        for k, v in ((j.get('with') or {}).items()):
            for name in re.findall(r'vars\.([A-Za-z0-9_]+)', str(v)):
                if not (name.startswith('KIT_') or name.startswith('AZURE_')
                        # the plan flag V1 reads; a setting, not vocabulary (hence the spelling)
                        or name == 'attestations_available'.upper()):
                    bad.append('%s %s reads vars.%s, a name the hand-off contract does not '
                               'define' % (jname, k, name))
        sec = j.get('secrets') or {}
        for s in ('AZURE_TENANT_ID', 'AZURE_SUBSCRIPTION_ID', 'AZURE_CLIENT_ID'):
            if 'vars.%s' % s not in norm(sec.get(s)):
                bad.append('%s secret %s is %r: the contract delivers it as a VARIABLE, so the '
                           'variable must be read when no secret exists' % (jname, s, sec.get(s)))
    be, de = norm(bw.get('github_environment')), norm(w.get('github_environment'))
    if not be or be == de:
        bad.append('build and deploy run in the same GitHub environment (%r): one identity would '
                   'both push and deploy; the contract separates them' % be)
    if de.lower() in ('production', 'prod') or not de.startswith('${{'):
        bad.append('deploy github_environment is %r: a fixed environment, not the one the dispatch '
                   'names' % de)
    for jname, j in jobs.items():
        refs = [str(j.get('uses', ''))] + [str(s.get('uses', '')) for s in j.get('steps') or []]
        for u in refs:
            if 'secure-cicd-kit/' in u and not SHA_REF.search(u.split('#')[0].strip()):
                bad.append('%s: %s is not pinned to a 40-hex commit SHA' % (jname, u))
    decide = [s for s in ver.get('steps') or [] if s.get('id') == 'decide']
    return decide[0] if decide else None


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
    bad = []
    decide = static(H.load(TPL), bad)
    if decide is None:
        bad.append('the verdict job has no decide step')
        for b in bad:
            print('FAIL: %s' % b)
        return 1

    def ctx(sec, brt, ident, verify, requested='true'):
        return {'needs.security.outputs.routing_result': sec,
                'needs.build.outputs.routing_result': brt,
                'steps.attestation.outputs.routing_result': verify,
                'needs.build.outputs.artifact_identity': ident, REQ: requested}

    # (name, ctx, deploy_allowed, deploy_routing_result)
    cases = [
        ('allowed-held-v1', ctx('PROCEED', 'PROCEED', PROVEN, 'PROCEED_WITH_ADVISORY'), True,
         'PROCEED'),
        ('allowed-advisory', ctx('PROCEED_WITH_ADVISORY', 'PROCEED', PROVEN, 'PROCEED'), True,
         'PROCEED_WITH_ADVISORY'),
        ('attack-build-decision', ctx('PROCEED', 'DECISION_REQUIRED', PROVEN, 'PROCEED'), False,
         'DECISION_REQUIRED'),
        ('attack-identity', ctx('PROCEED', 'PROCEED', 'IDENTITY_UNVERIFIED', 'PROCEED'), False,
         'EVIDENCE_UNTRUSTED'),
        ('attack-v1-contradicted', ctx('PROCEED', 'PROCEED', PROVEN, 'BLOCKED'), False, 'PROCEED'),
        ('missing-security', ctx('', 'PROCEED', PROVEN, 'PROCEED'), False, 'EVIDENCE_UNTRUSTED'),
        ('recovery', ctx('PROCEED', 'PROCEED', PROVEN, 'PROCEED'), True, 'PROCEED'),
    ]
    tmp = tempfile.mkdtemp(prefix='deploy-template-probe-')
    handed = {}
    try:
        for name, c, allowed, route in cases:
            ws = os.path.join(tmp, name)
            os.makedirs(ws)
            r = H.run(bash, decide, c, ws)
            o = r['outputs']
            print('  %-24s exit=%d deploy_allowed=%-5s routing=%-22s deploy_routing=%s'
                  % (name, r['rc'], o.get('deploy_allowed'), o.get('routing_result'),
                     o.get('deploy_routing_result')))
            handed[name] = o
            if (o.get('deploy_allowed') == 'true') != allowed:
                bad.append('%s: deploy_allowed=%r, want %s\n%s'
                           % (name, o.get('deploy_allowed'), allowed, r['log'][-300:]))
            if o.get('deploy_routing_result') != route:
                bad.append('%s: deploy_routing_result=%r, want %s'
                           % (name, o.get('deploy_routing_result'), route))

        # The hand-off, end to end: what the template gives the deploy, through the deploy's own
        # verdict step, at the production tier with the security stage's (empty) causes.
        doc = D.load(D.CONTAINERAPP)
        _, gate = D.step_named(doc, VERDICT_STEP)
        given = (handed.get('allowed-held-v1') or {}).get('deploy_routing_result', '')
        for label, verdict, must in (('handed (deploy_routing_result)', given, True),
                                     ('contrast (V1-folded advisory)', 'PROCEED_WITH_ADVISORY',
                                      False)):
            env = D.step_env(doc, gate, {'inputs.routing_result': verdict,
                                         'inputs.environment_tier': 'prod',
                                         'inputs.advisory_causes': ''})
            rc, out, log, _ = D.run_script(bash, gate['run'], env)
            print('  reusable verdict step at prod, %-32s %-22s exit=%d ruling=%s'
                  % (label, verdict or '(empty)', rc, out.get('version_gap_ruling')))
            if (rc == 0) != must:
                bad.append('%s: the deploy reusable at prod %s it (exit %d)\n%s'
                           % (label, 'refused' if must else 'proceeded on', rc, log[-300:]))
    finally:
        shutil.rmtree(tmp, ignore_errors=True)

    if bad:
        for b in bad:
            print('FAIL: %s' % b)
        return 1
    print('PASS: the template hands the deploy the combined release verdict, the vended tier and '
          'the contract\'s KIT_* names, runs build and deploy in separate environments, reads the '
          'AZURE_* identifiers as variables, and pins the kit by commit SHA; at prod the deploy '
          'proceeds on what the template hands it.')
    print('      STATIC + STUBBED. A hosted run of the template (scan -> verdict -> build -> deploy) '
          'is owed (S-15).')
    return 0


if __name__ == '__main__':
    sys.exit(main())

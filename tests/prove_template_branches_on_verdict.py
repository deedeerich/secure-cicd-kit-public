#!/usr/bin/env python3
"""The shipped caller template must BRANCH on identity and verdict, and hand the deploy its stamp.

WHY THIS EXISTS (ledger L87; PROVENANCE_AND_ATTESTATION.md section 2.3, section 7, section 9 steps 2-3)

    templates/build-deploy.yml passed `image_digest` and nothing else. The stamp the kit renders was
    therefore invoked by nothing a consumer would adopt (section 2.3), and a bad artifact identity
    stopped the deploy only as a SIDE EFFECT of the build job failing (section 7): add
    `continue-on-error` to the build, or consume a failed job's outputs, and the protection is gone
    without a sign. The kit emits a four-value `artifact_identity` precisely so a consumer can
    branch on it, and its own template did not.

WHAT IS RUN
    The template's `verdict` job decision step, extracted as shipped, under GitHub's shell, with the
    upstream outputs STUBBED: `needs.security.outputs.routing_result` (the security verdict),
    `needs.build.outputs.routing_result` and `needs.build.outputs.artifact_identity`. Then the
    render-version-metadata step, fed exactly what the template's `with:` maps into it, to show the
    metadata the deploy receives names the digest the build pushed. The wiring between the jobs is
    checked statically: a decision nobody reads is not a branch.

CASES (docs/PROOF_RULE.md)
    allowed           PROCEED / PROCEED_WITH_ADVISORY, identity REGISTRY_IDENTITY_PROVEN, deploy
                      requested -> allowed; the stamp carries the pushed digest
    attack            security BLOCKED; build DECISION_REQUIRED; identity IDENTITY_UNVERIFIED or
                      LOCAL_BUILD_ONLY -> refused, and the run FAILS (a refused deploy is never a
                      silently skipped job)
    missing-evidence  security verdict absent (''), identity absent, an unregistered verdict word
                      -> refused as EVIDENCE_UNTRUSTED, never a pass
    recovery          a run that did not ask to deploy records the refusal and exits 0; the same
                      inputs with the verdict restored to PROCEED are allowed

EXIT 0 every case decided as it must; 1 a case decided wrongly; 2 could not be checked (UNKNOWN).
"""
import json
import os
import shutil
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import _step_harness as H  # noqa: E402

TPL = 'templates/build-deploy.yml'
RENDER = '.github/actions/render-version-metadata/action.yml'
DIGEST = 'sha256:' + 'e' * 64
CONFIG = 'sha256:' + 'f' * 64
REQ = "github.event_name == 'workflow_dispatch' && inputs.deploy"
PROVEN = 'REGISTRY_IDENTITY_PROVEN'


def norm(v):
    return ' '.join(str(v or '').split())


def static(doc, bad):
    jobs = doc.get('jobs') or {}
    v, d = jobs.get('verdict'), jobs.get('deploy') or {}
    if v is None:
        bad.append('the template has no `verdict` job: nothing branches on artifact_identity or on '
                   'the security verdict (L87; PROV section 7)')
        return None
    needs = d.get('needs') or []
    needs = [needs] if isinstance(needs, str) else needs
    if 'verdict' not in needs:
        bad.append('deploy does not need `verdict`; the decision is not upstream of the mutation')
    if "needs.verdict.outputs.deploy_allowed == 'true'" not in norm(d.get('if')):
        bad.append('deploy `if:` does not read needs.verdict.outputs.deploy_allowed: %r' % d.get('if'))
    vm = norm((d.get('with') or {}).get('version_metadata'))
    if vm != '${{ needs.verdict.outputs.version_metadata }}':
        bad.append('deploy does not pass version_metadata from the verdict job (got %r)' % vm)
    vneeds = v.get('needs') or []
    for n in ('security', 'build'):
        if n not in vneeds:
            bad.append('verdict job does not need %r' % n)
    decide = render = None
    for s in v.get('steps') or []:
        if s.get('id') == 'decide':
            decide = s
        if 'render-version-metadata' in str(s.get('uses', '')):
            render = s
    if decide is None or render is None:
        bad.append('verdict job lacks the `decide` step or the render-version-metadata step')
        return None
    want = {'image-digest': 'needs.build.outputs.image_digest',
            'sbom-sha256': 'needs.build.outputs.sbom_sha256',
            'config-digest': 'needs.build.outputs.image_config_digest',
            'artifact-identity': 'needs.build.outputs.artifact_identity',
            'build-inputs': 'needs.build.outputs.build_inputs'}
    w = render.get('with') or {}
    for k, expr in want.items():
        if norm(w.get(k)) != '${{ %s }}' % expr:
            bad.append('render `with.%s` is %r, want ${{ %s }}' % (k, w.get(k), expr))
    outs = v.get('outputs') or {}
    rid = render.get('id')
    if norm(outs.get('version_metadata')) != '${{ steps.%s.outputs.metadata }}' % rid:
        bad.append('verdict job does not publish the rendered metadata as version_metadata')
    if norm(outs.get('deploy_allowed')) != '${{ steps.decide.outputs.deploy_allowed }}':
        bad.append('verdict job does not publish deploy_allowed from the decide step')
    return decide, w


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
    if not shutil.which('jq'):
        print('UNKNOWN: jq is required to RUN the render step.')
        return 2
    bad = []
    got = static(H.load(TPL), bad)
    if got is None:
        for b in bad:
            print('FAIL: %s' % b)
        return 1
    decide, rwith = got

    def ctx(sec, brt, ident, requested='true', verify='PROCEED'):
        # The V1 verification's contribution (L89; tests/prove_attestation_verify.py proves the
        # step itself). PROCEED here so these cases isolate identity and verdict.
        return {'needs.security.outputs.routing_result': sec,
                'needs.build.outputs.routing_result': brt,
                'steps.attestation.outputs.routing_result': verify,
                'needs.build.outputs.artifact_identity': ident, REQ: requested}

    cases = [
        ('allowed', ctx('PROCEED', 'PROCEED', PROVEN), True, 'PROCEED'),
        ('allowed-advisory', ctx('PROCEED_WITH_ADVISORY', 'PROCEED', PROVEN), True,
         'PROCEED_WITH_ADVISORY'),
        ('attack-security-blocked', ctx('BLOCKED', 'PROCEED', PROVEN), False, 'BLOCKED'),
        ('attack-build-decision', ctx('PROCEED', 'DECISION_REQUIRED', PROVEN), False,
         'DECISION_REQUIRED'),
        ('attack-identity-unverified', ctx('PROCEED', 'PROCEED', 'IDENTITY_UNVERIFIED'), False,
         'EVIDENCE_UNTRUSTED'),
        ('attack-local-build', ctx('PROCEED', 'PROCEED', 'LOCAL_BUILD_ONLY'), False,
         'EVIDENCE_UNTRUSTED'),
        ('missing-security-verdict', ctx('', 'PROCEED', PROVEN), False, 'EVIDENCE_UNTRUSTED'),
        ('missing-identity', ctx('PROCEED', 'PROCEED', ''), False, 'EVIDENCE_UNTRUSTED'),
        ('missing-unregistered-word', ctx('PASS', 'PROCEED', PROVEN), False, 'EVIDENCE_UNTRUSTED'),
        ('recovery-not-requested', ctx('BLOCKED', 'PROCEED', PROVEN, 'false'), False, 'BLOCKED'),
        ('recovery-restored', ctx('PROCEED', 'PROCEED', PROVEN), True, 'PROCEED'),
        ('attack-attestation-contradicted', ctx('PROCEED', 'PROCEED', PROVEN, verify='BLOCKED'),
         False, 'BLOCKED'),
        ('missing-attestation-verdict', ctx('PROCEED', 'PROCEED', PROVEN, verify=''), False,
         'EVIDENCE_UNTRUSTED'),
        ('allowed-attestation-held', ctx('PROCEED', 'PROCEED', PROVEN,
                                         verify='PROCEED_WITH_ADVISORY'), True,
         'PROCEED_WITH_ADVISORY'),
    ]
    tmp = tempfile.mkdtemp(prefix='template-verdict-probe-')
    try:
        for name, c, allowed, route in cases:
            ws = os.path.join(tmp, name)
            os.makedirs(ws)
            r = H.run(bash, decide, c, ws)
            out = r['outputs']
            got_allowed = out.get('deploy_allowed') == 'true'
            requested = c[REQ] == 'true'
            print('  %-28s exit=%d deploy_allowed=%-5s routing=%s'
                  % (name, r['rc'], out.get('deploy_allowed'), out.get('routing_result')))
            if got_allowed != allowed:
                bad.append('%s: deploy_allowed=%r, want %s\n%s'
                           % (name, out.get('deploy_allowed'), allowed, r['log'][-400:]))
            if route and out.get('routing_result') != route:
                bad.append('%s: routing_result=%r, want %s' % (name, out.get('routing_result'), route))
            if allowed and r['rc'] != 0:
                bad.append('%s: an allowed deploy failed the verdict job (exit %d)' % (name, r['rc']))
            if not allowed and requested and r['rc'] == 0:
                bad.append('%s: a REQUESTED deploy was refused and the job still succeeded -- a '
                           'refusal must be visible, not a silently skipped deploy' % name)
            if not requested and r['rc'] != 0:
                bad.append('%s: a run that did not ask to deploy failed on the decision' % name)

        # the stamp the deploy receives names what the build pushed
        rstep = H.load(RENDER)['runs']['steps'][0]
        build_out = {'needs.build.outputs.image_digest': DIGEST,
                     'needs.build.outputs.sbom_sha256': 'd' * 64,
                     'needs.build.outputs.image_config_digest': CONFIG,
                     'needs.build.outputs.artifact_identity': PROVEN,
                     'needs.build.outputs.build_inputs': json.dumps({'base_images': [],
                                                                    'lockfiles': []})}
        rctx = {'github.sha': 'c' * 40, 'github.run_id': '7', 'github.ref_name': 'main'}
        for k, v in rwith.items():
            rctx['inputs.%s' % k] = H.substitute(v, build_out)[0]
        ws = os.path.join(tmp, 'render')
        os.makedirs(ws)
        rr = H.run(bash, rstep, rctx, ws, composite=True)
        try:
            meta = json.loads(rr['outputs'].get('metadata', ''))
        except ValueError:
            meta = {}
        if meta.get('image_digest') != DIGEST or meta.get('artifact_identity') != PROVEN or \
                meta.get('scanned_config_digest') != CONFIG:
            bad.append('the metadata handed to deploy does not carry the pushed digest and identity: '
                       '%s (exit %d)\n%s' % (meta, rr['rc'], rr['log'][-400:]))
        else:
            print('  %-28s stamp carries %s... %s' % ('stamp', DIGEST[:15], PROVEN))
    finally:
        shutil.rmtree(tmp, ignore_errors=True)

    if bad:
        for b in bad:
            print('FAIL: %s' % b)
        return 1
    print('PASS: the template deploys only on a proven identity and a PROCEED-class verdict, fails '
          'visibly when a requested deploy is refused, treats an absent or unregistered verdict as '
          'EVIDENCE_UNTRUSTED, and hands the deploy a stamp naming the pushed digest.')
    return 0


if __name__ == '__main__':
    sys.exit(main())

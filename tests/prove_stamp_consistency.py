#!/usr/bin/env python3
"""The provenance stamp may not claim a proven identity it carries no evidence for.

WHY THIS EXISTS (ledger L92; PROVENANCE_AND_ATTESTATION.md section 2.2; review G1-file3)

    render-version-metadata refuses an unrecognised identity class and a malformed hash. It did NOT
    refuse `artifact-identity: REGISTRY_IDENTITY_PROVEN` with an empty image digest or an empty
    scanned config digest -- a stamp asserting that the registry agreed about two values it does
    not contain. That is the strongest claim the stamp can make, rendered over a hole.

    Separately, `github.ref_name` was interpolated into the script body inside double quotes. A
    branch name is chosen by whoever can push one, and `$( )` is legal in a ref name.

WHAT IS RUN
    The composite's own render step, extracted as shipped, under `bash --noprofile --norc -eo
    pipefail` (how GitHub runs a composite `shell: bash` step). jq is real.

CASES (docs/PROOF_RULE.md)
    allowed           PROVEN with both digests -> rendered, identity PROVEN
    attack            PROVEN with an empty image digest; PROVEN with an empty config digest ->
                      REFUSED, naming the missing field. A ref name carrying a command
                      substitution -> no command runs, and the stamp records the name literally
    missing-evidence  NOT_ESTABLISHED with no digests -> rendered (an under-claim is honest)
    recovery          the refused PROVEN call, re-run with the digests supplied -> rendered
    static            no `${{ }}` expression remains in the step's script body

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

RENDER = '.github/actions/render-version-metadata/action.yml'
D = 'sha256:' + '1' * 63 + 'a'
C = 'sha256:' + '2' * 63 + 'b'
S = '3' * 63 + 'c'


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
        print('UNKNOWN: jq is required to RUN the step.')
        return 2
    step = H.load(RENDER)['runs']['steps'][0]
    bad = []
    if H.EXPR.search(step.get('run') or ''):
        bad.append('static: the script body still interpolates %s -- every caller input and '
                   'context value must arrive through env'
                   % sorted(set(H.EXPR.findall(step.get('run') or ''))))

    tmp = tempfile.mkdtemp(prefix='stamp-consistency-probe-')
    try:
        def render(name, identity, digest, config, ref='main'):
            ws = os.path.join(tmp, name)
            os.makedirs(ws)
            ctx = {'inputs.image-digest': digest, 'inputs.config-digest': config,
                   'inputs.sbom-sha256': S, 'inputs.artifact-identity': identity,
                   'inputs.build-inputs': '', 'github.sha': 'a' * 40, 'github.run_id': '9',
                   'github.ref_name': ref}
            r = H.run(bash, step, ctx, ws, composite=True)
            try:
                meta = json.loads(r['outputs'].get('metadata', ''))
            except ValueError:
                meta = None
            return r, meta, ws

        r, meta, _ = render('allowed', 'REGISTRY_IDENTITY_PROVEN', D, C)
        print('  allowed            exit=%d identity=%s' % (r['rc'], (meta or {}).get('artifact_identity')))
        if r['rc'] != 0 or not meta or meta.get('artifact_identity') != 'REGISTRY_IDENTITY_PROVEN':
            bad.append('allowed: a fully evidenced PROVEN stamp did not render (exit %d)\n%s'
                       % (r['rc'], r['log'][-400:]))

        for name, dg, cf, field in (('attack-no-digest', '', C, 'image-digest'),
                                    ('attack-no-config', D, '', 'config-digest')):
            r, meta, _ = render(name, 'REGISTRY_IDENTITY_PROVEN', dg, cf)
            print('  %-18s exit=%d' % (name, r['rc']))
            if r['rc'] == 0:
                bad.append('%s: REGISTRY_IDENTITY_PROVEN rendered with an empty %s -- the stamp '
                           'claims the registry agreed about a value it does not carry' % (name, field))
            elif field not in r['log']:
                bad.append('%s: refused, but not for the stated reason (the message does not name '
                           '%s):\n%s' % (name, field, r['log'][-300:]))

        evil = 'feat/$(touch pwned)'
        r, meta, ws = render('attack-ref', 'NOT_ESTABLISHED', '', '', ref=evil)
        ran = os.path.exists(os.path.join(ws, 'pwned'))
        print('  attack-ref         exit=%d command-ran=%s git_ref=%r'
              % (r['rc'], ran, (meta or {}).get('git_ref')))
        if ran:
            bad.append('attack-ref: a command substitution in the ref name EXECUTED')
        if not meta or meta.get('git_ref') != evil:
            bad.append('attack-ref: the stamp does not record the ref name literally: %r'
                       % (meta or {}).get('git_ref'))

        r, meta, _ = render('missing-evidence', 'NOT_ESTABLISHED', '', '')
        print('  missing-evidence   exit=%d identity=%s' % (r['rc'], (meta or {}).get('artifact_identity')))
        if r['rc'] != 0 or not meta or meta.get('artifact_identity') != 'NOT_ESTABLISHED':
            bad.append('missing-evidence: an honest under-claim did not render (exit %d)' % r['rc'])

        r, meta, _ = render('recovery', 'REGISTRY_IDENTITY_PROVEN', D, C)
        print('  recovery           exit=%d image_digest=%s...' % (r['rc'], (meta or {}).get('image_digest', '')[:14]))
        if r['rc'] != 0 or not meta or meta.get('image_digest') != D:
            bad.append('recovery: the evidenced call did not render after a refusal')
    finally:
        shutil.rmtree(tmp, ignore_errors=True)

    if bad:
        for b in bad:
            print('FAIL: %s' % b)
        return 1
    print('PASS: the stamp refuses a PROVEN identity without both digests, carries caller and context '
          'values as data, and renders an honest under-claim.')
    return 0


if __name__ == '__main__':
    sys.exit(main())

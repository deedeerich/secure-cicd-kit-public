#!/usr/bin/env python3
"""The docker-build-push composite must push the bytes it scanned, and say whether it proved it.

WHY THIS EXISTS (ledger L85; review G3-5)

    The composite built twice -- a loaded build that Trivy and Syft inspected, and a second
    `push: true` build that reached the registry -- and returned that second build's digest with no
    identity class. tests/check_artifact_identity.py now reads composites and refuses that SHAPE.
    This file runs the composite's own push, registry-assertion and classify steps, extracted as
    shipped, so the BEHAVIOUR is proven too.

    SHIMMED: `docker` (push, RepoDigests, the registry's manifest). jq is real. No registry is
    contacted: the registry's answer is the fixture.

CASES (docs/PROOF_RULE.md)
    allowed           the registry holds the scanned config -> assertion passes, class PROVEN
    attack            the registry holds a DIFFERENT config (a rebuilt image) -> assertion FAILS,
                      class IDENTITY_UNVERIFIED
    missing-evidence  the digest resolves to an index with no config -> assertion FAILS,
                      class IDENTITY_UNVERIFIED; no SBOM at all -> class NOT_ESTABLISHED
    recovery          push=false -> no push, no assertion, class LOCAL_BUILD_ONLY
    static            exactly one docker/build-push-action step, and it does not push

EXIT 0 every case decided as it must; 1 a case decided wrongly; 2 could not be checked (UNKNOWN).
"""
import io
import os
import shutil
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import _step_harness as H  # noqa: E402

ACTION = '.github/actions/docker-build-push/action.yml'
SCANNED = 'sha256:' + '5' * 64
OTHER = 'sha256:' + '6' * 64
PUSHED = 'sha256:' + '7' * 64

DOCKER = r'''
case "$1" in
  push) exit 0 ;;
  image) printf 'reg.example/app@%s\n' "$SHIM_PUSHED" ;;
  buildx) case "$SHIM_REGISTRY" in
            index) printf '{"manifests":[]}' ;;
            *) printf '{"config":{"digest":"%s"}}' "$SHIM_REGISTRY" ;;
          esac ;;
  *) echo "docker shim: unhandled $*" >&2; exit 64 ;;
esac
'''


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
        print('UNKNOWN: jq is required.')
        return 2
    bad = []
    doc = H.load(ACTION)
    steps = doc['runs']['steps']
    builds = [s for s in steps if 'docker/build-push-action' in str(s.get('uses', ''))]
    if len(builds) != 1 or str((builds[0].get('with') or {}).get('push', '')).lower() == 'true':
        bad.append('static: %d build-push-action step(s); want exactly one, loading not pushing'
                   % len(builds))
    for key in ('artifact-identity', 'config-digest'):
        if key not in (doc.get('outputs') or {}):
            bad.append('static: the composite publishes no %s output' % key)
    push, assert_, classify = (H.step(ACTION, None, k) for k in ('push', 'assert_identity',
                                                                 'classify'))
    if not (push and assert_ and classify):
        bad.append('static: push, assert_identity or classify step missing')
        for b in bad:
            print('FAIL: %s' % b)
        return 1

    tmp = tempfile.mkdtemp(prefix='composite-build-once-probe-')
    try:
        shims = os.path.join(tmp, 'shim')
        H.shim(shims, 'docker', DOCKER)
        base = {'inputs.acr-login-server': 'reg.example', 'inputs.image-repository': 'app',
                'inputs.image-tag': 't', 'steps.built.outputs.config_digest': SCANNED}

        def chain(name, registry, push_flag='true', sbom=True):
            ws = os.path.join(tmp, name)
            os.makedirs(ws)
            if sbom:
                io.open(os.path.join(ws, 'sbom.spdx.json'), 'w').write('{}')
            ctx = dict(base, **{'inputs.push': push_flag})
            env = {'SHIM_PUSHED': PUSHED, 'SHIM_REGISTRY': registry}
            outcome = 'skipped'
            if push_flag == 'true':
                p = H.run(bash, push, ctx, ws, shims, env, composite=True)
                ctx['steps.push.outputs.digest'] = p['outputs'].get('digest', '')
                a = H.run(bash, assert_, ctx, ws, shims, env, composite=True)
                outcome = 'success' if a['rc'] == 0 else 'failure'
            ctx['steps.assert_identity.outcome'] = outcome
            c = H.run(bash, classify, ctx, ws, shims, env, composite=True)
            cls = c['outputs'].get('class')
            print('  %-18s assertion=%-8s class=%s' % (name, outcome, cls))
            return outcome, cls

        for name, reg, flag, sbom, want_outcome, want_cls in (
                ('allowed', SCANNED, 'true', True, 'success', 'REGISTRY_IDENTITY_PROVEN'),
                ('attack-rebuilt', OTHER, 'true', True, 'failure', 'IDENTITY_UNVERIFIED'),
                ('missing-index', 'index', 'true', True, 'failure', 'IDENTITY_UNVERIFIED'),
                ('missing-sbom', SCANNED, 'true', False, 'success', 'NOT_ESTABLISHED'),
                ('recovery-local', SCANNED, 'false', True, 'skipped', 'LOCAL_BUILD_ONLY')):
            outcome, cls = chain(name, reg, flag, sbom)
            if outcome != want_outcome or cls != want_cls:
                bad.append('%s: assertion %s / class %s, want %s / %s'
                           % (name, outcome, cls, want_outcome, want_cls))
    finally:
        shutil.rmtree(tmp, ignore_errors=True)

    if bad:
        for b in bad:
            print('FAIL: %s' % b)
        return 1
    print('PASS: the composite builds once, pushes the scanned bytes, refuses a registry that holds a '
          'different config or an index, and names the SBOM by what it proved.')
    return 0


if __name__ == '__main__':
    sys.exit(main())

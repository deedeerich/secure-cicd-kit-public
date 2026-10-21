#!/usr/bin/env python3
"""The build record must say what went INTO the build, and the stamp must carry it.

WHY THIS EXISTS (ledger L86; PROVENANCE_AND_ATTESTATION.md section 3 links 2-4, section 9 step 1)

    The kit proves the scanned bytes are the pushed bytes, and records nothing about what produced
    them: no base image digest, no lockfile hash, no toolchain version. A floating `FROM` tag makes
    every later claim about "the same build inputs" unfalsifiable, and an attestation signed over a
    record with those fields empty signs nothing interesting. The design says do this FIRST, even
    if attestation is never adopted, because it needs no permission and works on every plan.

WHAT IS RUN
    The build job's own `build_inputs` step, extracted from reusable-build-docker.yml as shipped,
    under the shell GitHub uses, against a throwaway build context. Then the render step of
    .github/actions/render-version-metadata, fed that step's output, as a caller would.

    SHIMMED (fixtures, not the tools): `docker` (so a registry lookup has a known answer, and an
    unknown image has none), `syft` and `trivy` (version strings only). jq is real.

CASES (docs/PROOF_RULE.md)
    allowed           tag FROM resolved to a digest; digest FROM kept; stage alias and scratch
                      excluded; two lockfiles hashed; toolchain recorded; the stamp carries it all
    missing-evidence  a FROM the registry cannot resolve, and a FROM built from a build-arg:
                      digest empty, resolved false, and all_base_images_resolved FALSE -- never a
                      record that reads complete
    attack            a build-inputs value that is not a JSON object is REFUSED by the stamp
    recovery          the same step, re-run with the registry answering, records the digest

EXIT 0 every case decided as it must; 1 a case decided wrongly; 2 could not be checked (UNKNOWN).
"""
import hashlib
import io
import json
import os
import shutil
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import _step_harness as H  # noqa: E402

WF = '.github/workflows/reusable-build-docker.yml'
RENDER = '.github/actions/render-version-metadata/action.yml'
A = 'sha256:' + 'a' * 64
B = 'sha256:' + 'b' * 64

DOCKER_SHIM = r'''
case "$1 $2 $3" in
  "buildx imagetools inspect")
    case "$4" in
      python:3.12-slim) printf '{"mediaType":"application/vnd.oci.image.index.v1+json","digest":"%s","size":1}\n' "$SHIM_TAG_DIGEST" ;;
      unknown/thing:1)  if [ -n "${SHIM_UNKNOWN_DIGEST:-}" ]; then
                          printf '{"digest":"%s"}\n' "$SHIM_UNKNOWN_DIGEST"
                        else echo "ERROR: not found" >&2; exit 1; fi ;;
      *) echo "ERROR: shim has no answer for $4" >&2; exit 1 ;;
    esac ;;
  "version --format {{.Server.Version}}") echo "27.0.1" ;;
  "buildx version ") echo "github.com/docker/buildx v0.17.1 1234567" ;;
  *) echo "docker shim: unhandled: $*" >&2; exit 64 ;;
esac
'''

DOCKERFILE_OK = '''# syntax=docker/dockerfile:1
FROM --platform=linux/amd64 python:3.12-slim AS build
RUN echo build
from build as test
FROM registry.example/base@%s
FROM scratch
''' % B

DOCKERFILE_GAP = '''ARG BASE=python:3.12-slim
FROM ${BASE}
FROM unknown/thing:1
'''


def write(path, text):
    os.makedirs(os.path.dirname(path) or '.', exist_ok=True)
    io.open(path, 'w', encoding='utf-8', newline='\n').write(text)


def sha(path):
    return hashlib.sha256(io.open(path, 'rb').read()).hexdigest()


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
    rec = H.step(WF, 'build', 'build_inputs')
    if rec is None:
        print('FAIL: reusable-build-docker.yml has no `build_inputs` step. The build records no base '
              'image digest, no lockfile hash and no toolchain version (L86; PROV section 3 links '
              '2-4), so nothing downstream can say what went into the image.')
        return 1
    outputs = (H.load(WF)['jobs']['build'].get('outputs') or {})
    if 'build_inputs' not in outputs:
        print('FAIL: the build job does not publish build_inputs; the record dies in the step.')
        return 1
    rstep = H.load(RENDER)['runs']['steps'][0]
    if 'build-inputs' not in (H.load(RENDER).get('inputs') or {}):
        print('FAIL: render-version-metadata has no build-inputs input; the stamp cannot carry them.')
        return 1

    tmp = tempfile.mkdtemp(prefix='build-inputs-probe-')
    bad = []
    try:
        shims = os.path.join(tmp, 'shim')
        H.shim(shims, 'docker', DOCKER_SHIM)
        H.shim(shims, 'syft', 'echo "Application:   syft"; echo "Version:       1.18.0"')
        H.shim(shims, 'trivy', 'echo "Version: 0.71.2"; echo "Vulnerability DB:"')
        ctx = {'inputs.dockerfile': 'Dockerfile', 'inputs.context': '.',
               'github.sha': 'c' * 40, 'github.run_id': '1', 'github.ref_name': 'main'}

        # ---- allowed
        ws = os.path.join(tmp, 'ok')
        write(os.path.join(ws, 'Dockerfile'), DOCKERFILE_OK)
        write(os.path.join(ws, 'requirements.txt'), 'flask==3.0.0\n')
        write(os.path.join(ws, 'web', 'package-lock.json'), '{"lockfileVersion": 3}\n')
        write(os.path.join(ws, 'node_modules', 'x', 'package-lock.json'), '{}\n')
        r = H.run(bash, rec, ctx, ws, shims, {'SHIM_TAG_DIGEST': A})
        doc = parse(r, 'allowed', bad)
        if doc is not None:
            bases = {b.get('ref'): b for b in doc.get('base_images', [])}
            want = {'python:3.12-slim': (A, False), 'registry.example/base@' + B: (B, True)}
            if set(bases) != set(want):
                bad.append('allowed: base images %s, want exactly %s (stage alias and scratch '
                           'excluded)' % (sorted(bases), sorted(want)))
            for ref, (dg, pinned) in want.items():
                b = bases.get(ref) or {}
                if b.get('digest') != dg or b.get('pinned_by_digest') is not pinned \
                        or b.get('resolved') is not True:
                    bad.append('allowed: %s recorded as %s' % (ref, b))
            if doc.get('all_base_images_resolved') is not True:
                bad.append('allowed: all_base_images_resolved is %r with every FROM resolved'
                           % doc.get('all_base_images_resolved'))
            locks = {l.get('path'): l.get('sha256') for l in doc.get('lockfiles', [])}
            want_l = {'requirements.txt': sha(os.path.join(ws, 'requirements.txt')),
                      'web/package-lock.json': sha(os.path.join(ws, 'web', 'package-lock.json'))}
            if locks != want_l:
                bad.append('allowed: lockfiles %s, want %s (node_modules excluded)' % (locks, want_l))
            tc = doc.get('toolchain') or {}
            for k, v in (('docker_engine', '27.0.1'), ('buildx', 'v0.17.1'), ('syft', '1.18.0'),
                         ('trivy', '0.71.2')):
                if tc.get(k) != v:
                    bad.append('allowed: toolchain.%s = %r, want %r' % (k, tc.get(k), v))
            # the stamp carries it
            rctx = dict(ctx, **{'inputs.image-digest': A, 'inputs.sbom-sha256': 'd' * 64,
                                'inputs.config-digest': B,
                                'inputs.artifact-identity': 'REGISTRY_IDENTITY_PROVEN',
                                'inputs.build-inputs': r['outputs'].get('record', '')})
            rr = H.run(bash, rstep, rctx, ws, shims, composite=True)
            try:
                meta = json.loads(rr['outputs'].get('metadata', ''))
            except ValueError:
                meta = None
                bad.append('allowed: render produced no metadata (exit %d)\n%s'
                           % (rr['rc'], rr['log'][-500:]))
            if meta is not None and (meta.get('build_inputs') or {}).get('base_images') != \
                    doc.get('base_images'):
                bad.append('allowed: the stamp does not carry the recorded base images: %s'
                           % meta.get('build_inputs'))
            print('  allowed           exit=%d bases=%d lockfiles=%d stamp=%s'
                  % (r['rc'], len(bases), len(locks), 'carried' if meta else 'none'))

        # ---- missing evidence
        ws = os.path.join(tmp, 'gap')
        write(os.path.join(ws, 'Dockerfile'), DOCKERFILE_GAP)
        r = H.run(bash, rec, ctx, ws, shims, {'SHIM_TAG_DIGEST': A})
        doc = parse(r, 'missing-evidence', bad)
        if doc is not None:
            if doc.get('all_base_images_resolved') is not False:
                bad.append('missing-evidence: all_base_images_resolved is %r with two unresolvable '
                           'FROMs -- a record with holes must not read complete'
                           % doc.get('all_base_images_resolved'))
            for b in doc.get('base_images', []):
                if b.get('resolved') is not False or b.get('digest'):
                    bad.append('missing-evidence: %s recorded as %s' % (b.get('ref'), b))
            if len(doc.get('base_images', [])) != 2:
                bad.append('missing-evidence: %d base images recorded, want 2'
                           % len(doc.get('base_images', [])))
            if doc.get('lockfiles') != []:
                bad.append('missing-evidence: lockfiles %r, want [] (none present)'
                           % doc.get('lockfiles'))
            print('  missing-evidence  exit=%d resolved=%s' % (r['rc'],
                                                              doc.get('all_base_images_resolved')))

        # ---- attack: the stamp refuses a build-inputs value that is not a JSON object
        for evil in ('not json', '["a"]', '{"x": 1}; touch pwned'):
            rctx = dict(ctx, **{'inputs.image-digest': A, 'inputs.sbom-sha256': 'd' * 64,
                                'inputs.artifact-identity': 'LOCAL_BUILD_ONLY',
                                'inputs.build-inputs': evil})
            rr = H.run(bash, rstep, rctx, ws, shims, composite=True)
            if rr['rc'] == 0 or os.path.exists(os.path.join(ws, 'pwned')):
                bad.append('attack: render accepted build-inputs %r' % evil)
        print('  attack            malformed build-inputs refused')

        # ---- recovery
        r = H.run(bash, rec, ctx, ws, shims, {'SHIM_TAG_DIGEST': A, 'SHIM_UNKNOWN_DIGEST': B})
        doc = parse(r, 'recovery', bad)
        if doc is not None:
            got = {b.get('ref'): b.get('digest') for b in doc.get('base_images', [])}
            if got.get('unknown/thing:1') != B:
                bad.append('recovery: with the registry answering, unknown/thing:1 -> %r'
                           % got.get('unknown/thing:1'))
            print('  recovery          exit=%d unknown/thing:1 -> %s' % (r['rc'],
                                                                         got.get('unknown/thing:1')))
    finally:
        shutil.rmtree(tmp, ignore_errors=True)

    if bad:
        for b in bad:
            print('FAIL: %s' % b)
        return 1
    print('PASS: the build records base image digests, lockfile hashes and toolchain versions; an '
          'unresolvable base reads unresolved, never complete; the stamp carries the record and '
          'refuses one that is not a JSON object.')
    return 0


def parse(r, name, bad):
    if r['rc'] != 0:
        bad.append('%s: the step failed (exit %d) -- recording inputs must never fail a build\n%s'
                   % (name, r['rc'], r['log'][-600:]))
        return None
    try:
        return json.loads(r['outputs'].get('record', ''))
    except ValueError:
        bad.append('%s: the step emitted no JSON `record` output: %r'
                   % (name, r['outputs'].get('record')))
        return None


if __name__ == '__main__':
    sys.exit(main())

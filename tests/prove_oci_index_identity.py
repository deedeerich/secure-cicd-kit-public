#!/usr/bin/env python3
"""The identity round trip resolves an OCI index to the built platform's image manifest, and never
guesses. Docker-free: the registry's answers are recorded documents (KDEC-065).

WHY THIS EXISTS (hosted self-test run 44128522569, 2026-11-17)

    GitHub's ubuntu-latest moved to ubuntu-26.04, whose Docker uses the containerd image store.
    There `docker push` publishes an OCI image INDEX (the image manifest plus an attestation
    manifest), RepoDigests names the INDEX, and `docker image inspect .Id` is the index digest, not
    the image config digest. The assertion read `.config.digest` off the index, found none, and
    refused: IDENTITY_UNVERIFIED, posture EVIDENCE_UNTRUSTED. Safe (it failed closed), but every
    consumer on ubuntu-latest had its deploys refused. tests/prove_build_push_round_trip.py proves
    the chain against a real registry:2 and needs Docker; this file proves the resolution logic on
    any host with bash and jq.

WHAT IS RUN
    The `built` and `assert_identity` steps of BOTH .github/workflows/reusable-build-docker.yml
    (job `build`) and .github/actions/docker-build-push/action.yml, extracted as shipped, under
    GitHub's shell, with `docker` SHIMMED: `imagetools inspect --raw <repo>@<digest>` serves the
    recorded document for that digest, `image inspect` serves the daemon's Id / platform /
    RepoDigests. The documents follow the shapes buildkit and the distribution spec publish
    (OCI image index with a `vnd.docker.reference.type: attestation-manifest` entry on platform
    unknown/unknown; Docker manifest list v2; OCI and Docker v2 image manifests). They are
    RECORDED SHAPES, not captures from the failing run: no Docker here to capture with.

CASES (docs/PROOF_RULE.md)
    allowed           a single image manifest (classic store) proves, platform manifest = pushed;
                      an OCI index with an attestation proves on its amd64 manifest; a Docker
                      manifest list proves on its amd64 entry; an attestation entry LABELLED
                      linux/amd64 is still ignored; a build that declares linux/arm64 selects arm64
    attack            the index's amd64 manifest (or a single manifest) carries a different config
                      -> ARTIFACT IDENTITY MISMATCH, never an UNESTABLISHED refusal
    missing-evidence  two distinct amd64 manifests -> AMBIGUOUS_PLATFORM_MANIFEST (never the first);
                      none for the platform -> NO_PLATFORM_MANIFEST; the selected entry is itself an
                      index -> refused; build metadata without a config digest -> refused; a daemon
                      Id that is neither the config nor the image target -> refused (the tag moved)
    recovery          the config digest is the build's containerimage.config.digest on BOTH stores:
                      the classic Id (= config) and the containerd Id (= index) each yield it
    registry (M5)     the registry serves bytes that are NOT the document the requested digest
                      names -- for the pushed digest (index and single manifest) and for the
                      selected platform manifest -- and the step must refuse ARTIFACT IDENTITY
                      MISMATCH. `docker buildx imagetools inspect --raw` prints the registry's bytes
                      unchanged and does not check them (measured 2026-11-18, buildx v0.34.1, a local
                      registry serving other bytes for <repo>@<digest>: printed, exit 0), so the step
                      hashes what it fetched. Every recorded document is now content-addressed (its
                      digest is the sha256 of the bytes served, trailing newline included); a control
                      serves a compact document with no trailing newline and must still prove
    mutants           each new branch, broken in the shipped text, is caught by a case above

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
ACTION = '.github/actions/docker-build-push/action.yml'
REG, NAME, TAG = 'reg.example', 'team/app', 't'
REPO = '%s/%s' % (REG, NAME)


def d(c):
    return 'sha256:' + c * 64


# Config digests are never fetched, so they stay symbolic. Every DOCUMENT the registry serves is
# content-addressed below: its digest is the sha256 of exactly the bytes the shim serves.
SCANNED, OTHER, ARMCFG, ATTCFG = d('5'), d('6'), d('8'), d('9')
OCI_M = 'application/vnd.oci.image.manifest.v1+json'
OCI_I = 'application/vnd.oci.image.index.v1+json'
DKR_M = 'application/vnd.docker.distribution.manifest.v2+json'
DKR_L = 'application/vnd.docker.distribution.manifest.list.v2+json'
AMD = {'architecture': 'amd64', 'os': 'linux'}
ARM = {'architecture': 'arm64', 'os': 'linux'}


def manifest(cfg, mt=OCI_M):
    return {'schemaVersion': 2, 'mediaType': mt,
            'config': {'mediaType': 'application/vnd.oci.image.config.v1+json', 'digest': cfg,
                       'size': 412},
            'layers': [{'mediaType': 'application/vnd.oci.image.layer.v1.tar+gzip',
                        'digest': d('4'), 'size': 180}]}


def entry(dg, platform, mt=OCI_M, att=False):
    e = {'mediaType': mt, 'digest': dg, 'size': 482, 'platform': dict(platform)}
    if att:
        e['annotations'] = {'vnd.docker.reference.digest': M1,
                            'vnd.docker.reference.type': 'attestation-manifest'}
    return e


def index(entries, mt=OCI_I):
    return {'schemaVersion': 2, 'mediaType': mt, 'manifests': entries}


UNKNOWN_P = {'architecture': 'unknown', 'os': 'unknown'}
DOCS = {}   # digest -> the exact bytes the registry shim serves for <repo>@<digest>


def blob(doc):
    return (json.dumps(doc, indent=2) + '\n').encode('utf-8')


def put(data, served=None):
    """Register a document by its content address; `served` (M5 attacks) is what the registry
    returns instead of `data` when asked for that address."""
    dg = 'sha256:' + hashlib.sha256(data).hexdigest()
    DOCS[dg] = data if served is None else served
    return dg


M1, M2, M3 = put(blob(manifest(SCANNED))), put(blob(manifest(SCANNED, DKR_M))), put(blob(manifest(ARMCFG)))
M4, M5, ATT = put(blob(manifest(d('3')))), put(blob(manifest(OTHER))), put(blob(manifest(ATTCFG)))
I1 = put(blob(index([entry(M1, AMD), entry(ATT, UNKNOWN_P, att=True)])))
I2 = put(blob(index([entry(ATT, AMD, att=True), entry(M1, AMD)])))
I3 = put(blob(index([entry(M1, AMD), entry(M4, AMD), entry(ATT, UNKNOWN_P, att=True)])))
I4 = put(blob(index([entry(M3, ARM), entry(ATT, UNKNOWN_P, att=True)])))
I5 = put(blob(index([entry(M5, AMD), entry(ATT, UNKNOWN_P, att=True)])))
I6 = put(blob(index([entry(I1, AMD, mt=OCI_I)])))
L1 = put(blob(index([entry(M2, AMD, mt=DKR_M), entry(M3, ARM, mt=DKR_M)], mt=DKR_L)))
# A compact document with NO trailing newline: hashing must be over the bytes as fetched, never over
# a shell variable (a command substitution drops trailing newlines, so every other document, which
# ends in one, would then mismatch -- and a document without one must not gain one).
N1 = put(json.dumps(manifest(SCANNED), separators=(',', ':')).encode('utf-8'))
# M5 -- THE REGISTRY SERVES OTHER BYTES THAN THE DIGEST NAMES. Each requested address is the hash of
# a genuine document; what comes back is a different (well-formed, otherwise provable) document.
#   T_TOP  the pushed index: serves I1's bytes (containerd store: the scanned Id IS T_TOP, so before
#          the hash check CONTENT_ADDRESS_INDEX "proved" it on the strength of the string alone)
#   T_ONE  a pushed single manifest: serves M1's bytes (classic store, config matches)
#   T_PM   the platform manifest named by a genuine index I7: serves M1's bytes
T_TOP = put(blob(index([entry(M1, AMD), entry(ATT, UNKNOWN_P, att=True)], mt=DKR_L)), served=DOCS[I1])
T_ONE = put(blob(dict(manifest(SCANNED), annotations={'kit.example/variant': 'genuine'})), served=DOCS[M1])
T_PM = put(blob(dict(manifest(SCANNED), annotations={'kit.example/variant': 'platform'})), served=DOCS[M1])
I7 = put(blob(index([entry(T_PM, AMD), entry(ATT, UNKNOWN_P, att=True)])))

DOCKER = r'''
case "$1 $2" in
  "image inspect")
    case "$*" in
      *RepoDigests*) printf '%s@%s\n' "$SHIM_REPO" "$SHIM_PUSHED" ;;
      *Architecture*) printf '%s\n' "$SHIM_PLATFORM" ;;
      *) printf '%s\n' "$SHIM_ID" ;;
    esac ;;
  "push "*) exit 0 ;;
  "buildx imagetools")
    ref="${@: -1}"; f="$SHIM_DOCS/${ref##*@sha256:}.json"
    [ -f "$f" ] || { echo "ERROR: $ref: not found" >&2; exit 1; }
    cat "$f" ;;
  *) echo "docker shim: unhandled $*" >&2; exit 64 ;;
esac
'''

# (name, pushed digest, scanned image Id, build-metadata config, platform, want rc 0?,
#  want platform manifest, want identity_rule, want text in the log)
# KDEC-065 rev 2 (hosted run 44156650539): the scanned image is the daemon's Id. On the containerd
# store it is the pushed index or manifest itself (content address); on the classic store it is the
# platform manifest's config digest. The registry answers; build metadata only cross-checks.
ASSERT_CASES = (
    ('allowed-classic-single', M1, SCANNED, '', 'linux/amd64', True, M1, 'CONFIG_DIGEST', None),
    ('allowed-classic-meta', M1, SCANNED, SCANNED, 'linux/amd64', True, M1, 'CONFIG_DIGEST', None),
    ('allowed-containerd-index', I1, I1, '', 'linux/amd64', True, M1, 'CONTENT_ADDRESS_INDEX', None),
    ('allowed-containerd-index-meta', I1, I1, SCANNED, 'linux/amd64', True, M1, 'CONTENT_ADDRESS_INDEX', None),
    ('allowed-containerd-manifest', M1, M1, '', 'linux/amd64', True, M1, 'CONTENT_ADDRESS_MANIFEST', None),
    ('allowed-docker-list', L1, SCANNED, '', 'linux/amd64', True, M2, 'CONFIG_DIGEST', None),
    ('allowed-att-labelled-amd64', I2, SCANNED, '', 'linux/amd64', True, M1, 'CONFIG_DIGEST', None),
    ('allowed-declared-arm64', I4, ARMCFG, '', 'linux/arm64', True, M3, 'CONFIG_DIGEST', None),
    ('allowed-platform-unset', I1, I1, '', '', True, M1, 'CONTENT_ADDRESS_INDEX', None),
    ('allowed-no-trailing-newline', N1, SCANNED, '', 'linux/amd64', True, N1, 'CONFIG_DIGEST', None),
    ('attack-registry-index', T_TOP, T_TOP, '', 'linux/amd64', False, '', '', 'ARTIFACT IDENTITY MISMATCH'),
    ('attack-registry-manifest', T_ONE, SCANNED, '', 'linux/amd64', False, '', '', 'ARTIFACT IDENTITY MISMATCH'),
    ('attack-registry-platform', I7, SCANNED, '', 'linux/amd64', False, '', '', 'ARTIFACT IDENTITY MISMATCH'),
    ('attack-containerd', I1, I5, '', 'linux/amd64', False, '', '', 'ARTIFACT IDENTITY MISMATCH'),
    ('attack-classic', M1, OTHER, '', 'linux/amd64', False, '', '', 'ARTIFACT IDENTITY MISMATCH'),
    ('attack-index-config', I5, SCANNED, '', 'linux/amd64', False, '', '', 'ARTIFACT IDENTITY MISMATCH'),
    ('attack-metadata-contradicts', I1, I1, OTHER, 'linux/amd64', False, '', '', 'ARTIFACT IDENTITY MISMATCH'),
    ('missing-two-amd64', I3, I3, '', 'linux/amd64', False, '', '', 'AMBIGUOUS_PLATFORM_MANIFEST'),
    ('missing-no-amd64', I4, I4, '', 'linux/amd64', False, '', '', 'NO_PLATFORM_MANIFEST'),
    ('missing-nested-index', I6, I6, '', 'linux/amd64', False, '', '', 'UNESTABLISHED'),
    ('missing-no-scanned-id', M1, '', '', 'linux/amd64', False, '', '', 'UNESTABLISHED'),
)
PROVENANCE_ONLY = json.dumps({'buildx.build.provenance': {}, 'buildx.build.ref': 'default/default/x'})


def meta(cfg, target):
    m = {'image.name': '%s:%s' % (REPO, TAG)}
    if cfg:
        m['containerimage.config.digest'] = cfg
    if target:
        m['containerimage.digest'] = target
    return json.dumps(m)


# (name, daemon Id, action imageid, metadata, platform, want rc 0?, want scanned_image_id,
#  want build_config_digest, want log text)
BUILT_CASES = (
    ('recovery-classic-store', SCANNED, SCANNED, meta(SCANNED, M1), 'linux/amd64', True, SCANNED, SCANNED, None),
    ('recovery-containerd-no-metadata', I1, I1, PROVENANCE_ONLY, 'linux/amd64', True, I1, '', None),
    ('recovery-containerd-metadata', I1, I1, meta(SCANNED, I1), 'linux/amd64', True, I1, SCANNED, None),
    ('recovery-metadata-empty', I1, I1, '', 'linux/amd64', True, I1, '', None),
    ('missing-malformed-metadata-config', I1, I1, meta('sha256:zz', I1), 'linux/amd64', False, '', '',
     'config digest'),
    ('missing-action-disagrees', SCANNED, OTHER, meta(SCANNED, M1), 'linux/amd64', False, '', '', 'disagreement'),
    ('missing-no-platform', SCANNED, SCANNED, meta(SCANNED, M1), '/', False, '', '', 'platform'),
)

# A mutant names the step, the shipped text it breaks, the replacement, and the case that must
# then decide wrongly. A needle the shipped text no longer contains FAILS: a stale mutant proves
# nothing.
MUTANTS = (
    ('assert_identity', '!= "attestation-manifest"', '!= "kit-no-such-type"', 'allowed-att-labelled-amd64'),
    ('assert_identity', '| unique | .[]', '| .[0:1] | .[]', 'missing-two-amd64'),
    ('assert_identity', '.platform.os == $o and .platform.architecture == $a', 'true',
     'allowed-docker-list'),
    ('assert_identity', 'PLATFORM="${PLATFORM:-linux/amd64}"', 'PLATFORM="linux/amd64"',
     'allowed-declared-arm64'),
    ('assert_identity', '[ "$SCANNED_ID" = "$REGISTRY_CONFIG" ]', 'true', 'attack-containerd'),
    ('assert_identity', '[ "$SCANNED_ID" = "$DIGEST" ]', 'false', 'allowed-containerd-index'),
    ('assert_identity', '[ "$BUILD_CONFIG" != "$REGISTRY_CONFIG" ]', 'false', 'attack-metadata-contradicts'),
    ('assert_identity', 'RULE=CONTENT_ADDRESS_INDEX', 'RULE=CONTENT_ADDRESS_MANIFEST', 'allowed-containerd-index'),
    ('built', '[ -n "$BUILD_CONFIG" ] && ! printf', '! printf', 'recovery-containerd-no-metadata'),
    # KDEC-065 M5: the fetched bytes are hashed, and the hash is over the file, not a shell variable.
    ('assert_identity', '[ "$got" != "$1" ]', 'false', 'attack-registry-platform'),
    ('assert_identity', 'fetch_exact "$DIGEST" "$DOC"', 'docker buildx imagetools inspect --raw "$REPO@$DIGEST" > "$DOC"',
     'attack-registry-index'),
    ('assert_identity', 'sha256sum < "$2"', 'printf %s "$(cat "$2")" | sha256sum', 'allowed-classic-single'),
)


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
    tmp = tempfile.mkdtemp(prefix='oci-index-identity-')
    try:
        shims, docs = os.path.join(tmp, 'shim'), os.path.join(tmp, 'docs')
        H.shim(shims, 'docker', DOCKER)
        os.makedirs(docs)
        for dg, data in DOCS.items():
            with io.open(os.path.join(docs, dg[7:] + '.json'), 'wb') as fh:
                fh.write(data)
        n = [0]

        def run(s, ctx, env, composite):
            n[0] += 1
            ws = os.path.join(tmp, 'ws%d' % n[0])
            os.makedirs(ws)
            base = {'SHIM_DOCS': docs, 'SHIM_REPO': REPO, 'REPO': REPO,
                    'IMAGE': '%s:%s' % (REPO, TAG), 'MSYS2_ENV_CONV_EXCL': '*',
                    'MSYS_NO_PATHCONV': '1'}
            base.update(env)
            return H.run(bash, s, ctx, ws, shims, base, composite=composite)

        def ctx_for(composite, extra):
            c = {'inputs.acr-login-server': REG, 'inputs.image-repository': NAME,
                 'inputs.image-tag': TAG, 'inputs.push': 'true', 'env.IMAGE': '%s:%s' % (REPO, TAG)}
            c.update(extra)
            return c

        def assert_case(st, composite, case):
            name, pushed, scanned, bcfg, plat, ok, want_pm, want_rule, text = case
            ctx = ctx_for(composite, {'steps.push.outputs.digest': pushed,
                                      'steps.built.outputs.scanned_image_id': scanned,
                                      'steps.built.outputs.build_config_digest': bcfg,
                                      'steps.built.outputs.platform': plat})
            r = run(st, ctx, {}, composite)
            o = r['outputs']
            wrong = []
            if (r['rc'] == 0) != ok:
                wrong.append('exit %d' % r['rc'])
            if ok and (o.get('platform_manifest_digest') != want_pm
                       or o.get('identity_rule') != want_rule
                       or not str(o.get('config_digest', '')).startswith('sha256:')):
                wrong.append('platform manifest %r rule %r config %r, want %r %r'
                             % (o.get('platform_manifest_digest'), o.get('identity_rule'),
                                o.get('config_digest'), want_pm, want_rule))
            if not ok and text and text not in r['log']:
                wrong.append('refused without %r' % text)
            if not ok and text != 'ARTIFACT IDENTITY MISMATCH' and 'MISMATCH' in r['log']:
                wrong.append('an unresolvable index reported as a MISMATCH')
            return wrong, r

        def built_case(st, composite, case):
            name, did, aid, md, plat, ok, want_id, want_bc, text = case
            ctx = ctx_for(composite, {'steps.build.outputs.imageid': aid,
                                      'steps.build.outputs.metadata': md})
            r = run(st, ctx, {'SHIM_ID': did, 'SHIM_PLATFORM': plat}, composite)
            o = r['outputs']
            wrong = []
            if (r['rc'] == 0) != ok:
                wrong.append('exit %d' % r['rc'])
            if ok and (o.get('scanned_image_id') != want_id or o.get('build_config_digest', '') != want_bc
                       or o.get('platform') != plat):
                wrong.append('scanned id %r build config %r platform %r'
                             % (o.get('scanned_image_id'), o.get('build_config_digest'), o.get('platform')))
            if not ok and text and text not in r['log']:
                wrong.append('refused without %r' % text)
            return wrong, r

        surfaces = ((WF, 'build', False), (ACTION, None, True))
        for path, job, composite in surfaces:
            label = 'workflow' if job else 'composite'
            st = {k: H.step(path, job, k) for k in ('built', 'assert_identity')}
            if not all(st.values()):
                bad.append('%s: a built or assert_identity step is missing' % label)
                continue
            for case in ASSERT_CASES:
                wrong, r = assert_case(st['assert_identity'], composite, case)
                print('  %-9s %-30s exit=%d pm=%s' % (label, case[0], r['rc'],
                                                      r['outputs'].get('platform_manifest_digest', '')[7:15]))
                if wrong:
                    bad.append('%s %s: %s\n%s' % (label, case[0], '; '.join(wrong), r['log'][-500:]))
            for case in BUILT_CASES:
                wrong, r = built_case(st['built'], composite, case)
                print('  %-9s %-30s exit=%d scanned=%s' % (label, case[0], r['rc'],
                                                          r['outputs'].get('scanned_image_id', '')[7:15]))
                if wrong:
                    bad.append('%s %s: %s\n%s' % (label, case[0], '; '.join(wrong), r['log'][-500:]))
            for key, needle, repl, case_name in MUTANTS:
                text = st[key].get('run') or ''
                if needle not in text:
                    bad.append('%s mutant: %r is not in the shipped %s step (stale mutant)'
                               % (label, needle, key))
                    continue
                mutant = dict(st[key], run=text.replace(needle, repl))
                if key == 'assert_identity':
                    case = [c for c in ASSERT_CASES if c[0] == case_name][0]
                    wrong, _r = assert_case(mutant, composite, case)
                else:
                    case = [c for c in BUILT_CASES if c[0] == case_name][0]
                    wrong, _r = built_case(mutant, composite, case)
                print('  %-9s mutant %-23s %s' % (label, needle[:23], 'CAUGHT' if wrong else 'SURVIVED'))
                if not wrong:
                    bad.append('%s mutant %r -> %r survived: %s still decides as shipped'
                               % (label, needle, repl, case_name))
    finally:
        shutil.rmtree(tmp, ignore_errors=True)

    if bad:
        for b in bad:
            print('FAIL: %s' % b)
        return 1
    print('PASS: on both the reusable workflow and the composite, an OCI index or Docker manifest '
          'list resolves to the one image manifest for the built platform, attestation manifests '
          'are never selected, none or several refuse by name, a different config is a MISMATCH, '
          'bytes that do not hash to the requested digest (pushed or platform manifest) are a '
          'MISMATCH, and the scanned config digest is the build\'s own config digest on either '
          'image store.')
    return 0


if __name__ == '__main__':
    sys.exit(main())

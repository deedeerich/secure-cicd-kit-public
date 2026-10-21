#!/usr/bin/env python3
"""Exactly one job may hold `attestations: write`, and it signs only a proven digest.

WHY THIS EXISTS (ledger L88; PROVENANCE_AND_ATTESTATION.md section 8.2, section 9 step 4)

    Nothing in the kit signs anything (section 3 link 8). The design adds ONE attest job, separate
    from the build: in a reusable workflow the file-level `permissions:` block is the ceiling for
    every job, so signing authority granted there would reach the job that runs a caller-supplied
    Dockerfile. It must be job-level, on a job that does nothing else -- no Azure login, no
    registry login, no build, no caller-supplied script -- and it must never sign a digest the
    registry round trip did not prove.

WHAT THIS PROVES, AND WHAT IT CANNOT
    STATIC: the permission topology across EVERY workflow, and the attest job's shape.
    EXTRACTED STEP: the attest job's subject guard, run as shipped under GitHub's shell.
    NOT PROVEN HERE, AND OWED TO A HOSTED RUN: that `actions/attest` actually signs on GitHub,
    whether `artifact-metadata: write` is needed (section 4.4), and that a private repository on a
    plan without attestations is skipped rather than failed. Nothing local can sign with GitHub's
    Sigstore instance.

CASES (docs/PROOF_RULE.md)
    allowed           PROVEN identity, well-formed digest and subject name -> guard passes
    attack            identity IDENTITY_UNVERIFIED or LOCAL_BUILD_ONLY -> guard refuses;
                      a subject name carrying a command substitution -> no command runs
    missing-evidence  empty digest; a digest that is not sha256:<64 hex> -> guard refuses
    recovery          the refused call with the proven digest restored -> guard passes

EXIT 0 every case decided as it must; 1 a case decided wrongly; 2 could not be checked (UNKNOWN).
"""
import glob
import os
import shutil
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import _step_harness as H  # noqa: E402

WF = '.github/workflows/reusable-build-docker.yml'
D = 'sha256:' + '4' * 64
FORBIDDEN_IN_ATTEST = ('azure/login', 'docker/build-push-action', 'docker/setup-buildx-action',
                       'az acr login', 'docker build', 'docker push', 'actions/checkout')


def perms_write_attest(p):
    return isinstance(p, dict) and str(p.get('attestations', '')).strip() == 'write'


def static(bad):
    holders = []
    for f in sorted(glob.glob(os.path.join(H.ROOT, '.github', 'workflows', '*.yml'))):
        doc = H.load(os.path.relpath(f, H.ROOT))
        rel = os.path.basename(f)
        if perms_write_attest(doc.get('permissions')) or doc.get('permissions') == 'write-all':
            bad.append('%s grants attestations: write (or write-all) at FILE level: every job in '
                       'the file inherits the ceiling, including the one that builds' % rel)
        for jn, j in (doc.get('jobs') or {}).items():
            # A job that only CALLS the build workflow grants a CEILING, not a holding: GitHub refuses
            # the run unless the caller grants what the called attest job requests (first hosted run,
            # 2026-10-15; tests/check_caller_permissions.py). It runs no step of its own with the scope.
            if isinstance(j, dict) and 'reusable-build-docker.yml' in str(j.get('uses') or '') \
                    and not j.get('steps'):
                continue
            if isinstance(j, dict) and perms_write_attest(j.get('permissions')):
                holders.append((rel, jn))
    if holders != [('reusable-build-docker.yml', 'attest')]:
        bad.append('attestations: write is held by %s; want exactly reusable-build-docker.yml :: '
                   'attest' % (holders or 'NO job'))
    job = (H.load(WF).get('jobs') or {}).get('attest')
    if not job:
        return None
    perms = job.get('permissions') or {}
    extra = {k: v for k, v in perms.items() if str(v) == 'write'} if isinstance(perms, dict) else {}
    if set(extra) - {'attestations', 'id-token'}:
        bad.append('attest job holds extra write permissions %s (packages: write buys nothing '
                   'on ACR, section 8.2)' % sorted(set(extra) - {'attestations', 'id-token'}))
    needs = job.get('needs') or []
    if 'build' not in ([needs] if isinstance(needs, str) else needs):
        bad.append('attest job does not need build')
    if job.get('environment'):
        bad.append('attest job declares an environment: it needs no Azure secret and must get none')
    cond = ' '.join(str(job.get('if', '')).split())
    if "needs.build.outputs.artifact_identity == 'REGISTRY_IDENTITY_PROVEN'" not in cond:
        bad.append('attest job `if:` does not require REGISTRY_IDENTITY_PROVEN: %r' % cond)
    attest = guard = None
    for s in job.get('steps') or []:
        text = '%s %s' % (s.get('uses', ''), s.get('run', ''))
        for f in FORBIDDEN_IN_ATTEST:
            if f in text:
                bad.append('attest job step %r contains %r: the signing job must do nothing else'
                           % (s.get('name'), f))
        if str(s.get('uses', '')).startswith('actions/attest'):
            attest = s
        if s.get('id') == 'subject':
            guard = s
    if attest is None or guard is None:
        bad.append('attest job lacks the subject guard step or the actions/attest step')
        return None
    w = attest.get('with') or {}
    if ' '.join(str(w.get('subject-digest', '')).split()) != '${{ steps.subject.outputs.digest }}':
        bad.append('actions/attest subject-digest is not the guarded digest: %r'
                   % w.get('subject-digest'))
    if 'subject-path' in w:
        bad.append('actions/attest signs a subject-path; the digest is the artifact')
    if str(w.get('push-to-registry', 'false')).lower() == 'true':
        bad.append('push-to-registry is on; against ACR that is unestablished (section 11.1) and '
                   'interacts with the identity assertion (section 11.9)')
    return guard


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
    guard = static(bad)
    if guard is None:
        bad.insert(0, 'no attest job with a subject guard in %s (L88): nothing signs anything' % WF)
        for b in bad:
            print('FAIL: %s' % b)
        return 1

    tmp = tempfile.mkdtemp(prefix='attest-probe-')
    try:
        def run(name, ident, digest, server='reg.example', repo='app'):
            ws = os.path.join(tmp, name)
            os.makedirs(ws)
            ctx = {'needs.build.outputs.artifact_identity': ident,
                   'needs.build.outputs.image_digest': digest,
                   'inputs.acr_login_server': server, 'inputs.image_repository': repo}
            r = H.run(bash, guard, ctx, ws)
            pwned = os.path.exists(os.path.join(ws, 'pwned'))
            print('  %-24s exit=%d digest=%s name=%s' % (name, r['rc'],
                                                      r['outputs'].get('digest', '')[:14],
                                                      r['outputs'].get('name', '')))
            return r, pwned

        P = 'REGISTRY_IDENTITY_PROVEN'
        r, _ = run('allowed', P, D)
        if r['rc'] != 0 or r['outputs'].get('digest') != D or \
                r['outputs'].get('name') != 'reg.example/app':
            bad.append('allowed: guard did not pass a proven subject\n%s' % r['log'][-300:])
        for name, ident, dg in (('attack-unverified', 'IDENTITY_UNVERIFIED', D),
                                ('attack-local', 'LOCAL_BUILD_ONLY', D),
                                ('missing-digest', P, ''),
                                ('missing-malformed', P, 'sha256:abc')):
            r, _ = run(name, ident, dg)
            if r['rc'] == 0:
                bad.append('%s: the guard let a subject through (%s, %r)' % (name, ident, dg))
        r, pwned = run('attack-name-injection', P, D, repo='app$(touch pwned)')
        if pwned:
            bad.append('attack-name-injection: a command in the image repository name EXECUTED')
        r, _ = run('recovery', P, D)
        if r['rc'] != 0:
            bad.append('recovery: the proven subject was refused after a refusal')
    finally:
        shutil.rmtree(tmp, ignore_errors=True)

    if bad:
        for b in bad:
            print('FAIL: %s' % b)
        return 1
    print('PASS: one job holds attestations: write, at job level, doing nothing else, and it signs '
          'only a proven sha256 digest. OWED to a hosted run: the signature itself.')
    return 0


if __name__ == '__main__':
    sys.exit(main())

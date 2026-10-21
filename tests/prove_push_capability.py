#!/usr/bin/env python3
"""The push is the point of no return: capability is established and the change is planned BEFORE it.

WHY THIS EXISTS (DCR section 5 gap 10, section 3.5; ledger L95)

    `reusable-build-docker.yml` proved the scanned bytes are the pushed bytes (d49bd22) and then
    pushed with no pre-mutation gate: nothing asked whether the tag it was about to write or move
    could be put back, and nothing recorded the push in a change manifest, so a downstream
    reversal had no entry to account for. The deploy contract (scripts/deploy_contract.py) does
    all three before it mutates -- capture the previous state, establish rollback_capability,
    plan the manifest -- and the build did none of them.

WHAT IS RUN
    The build job's `push_capability` and `push` steps, extracted from the workflow as shipped,
    under GitHub's shell, with `docker` SHIMMED (the registry's answer is the fixture; nothing
    is contacted) and every push the shim receives written to a log.

CASES (docs/PROOF_RULE.md)
    allowed           the tag resolves in the registry  -> EXISTING_DEPLOYMENT, AVAILABLE, a
                      MODIFIED entry planned with the prior digest; the push then marks it
                      applied with the pushed digest
    allowed-empty     the registry answers and holds no such tag -> EMPTY, NO_PRIOR_STATE, a
                      CREATED entry planned
    attack            the push step is reached with no planned manifest (the capability step
                      never ran) -> it refuses, and the shim records NO push
    missing-evidence  the registry cannot be read -> UNKNOWN, UNAVAILABLE, the step FAILS, no
                      manifest is planned, and the push step afterwards refuses
    recovery          the same registry, readable again -> allowed
    static            push_capability precedes push, is conditioned on inputs.push, the push
                      reads the manifest, the posture step reads the capability outcome, and
                      the evidence directory is uploaded on every pushing path

EXIT 0 every case decided as it must; 1 a case decided wrongly; 2 could not be checked (UNKNOWN).
"""
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
PRIOR = 'sha256:' + '3' * 64
PUSHED = 'sha256:' + '7' * 64
REPO = 'registry.example/app'
IMAGE = REPO + ':t'

DOCKER = r'''
case "$1 $2" in
  "buildx imagetools")
    case "$SHIM_REGISTRY" in
      absent) echo "ERROR: $SHIM_IMAGE: not found" >&2; exit 1 ;;
      down)   echo "ERROR: unauthorized: authentication required" >&2; exit 1 ;;
      *)      printf '{"digest":"%s","mediaType":"application/vnd.oci.image.manifest.v1+json"}\n' "$SHIM_REGISTRY" ;;
    esac ;;
  "push "*) echo "push $2" >> "$SHIM_LOG"; exit 0 ;;
  "image inspect") printf '%s@%s\n' "$SHIM_REPO" "$SHIM_PUSHED" ;;
  *) echo "docker shim: unhandled $*" >&2; exit 64 ;;
esac
'''


def static_problems(doc):
    bad = []
    steps = doc['jobs']['build']['steps']
    ids = [s.get('id') for s in steps]
    if 'push_capability' not in ids:
        bad.append('static: no step with id push_capability -- nothing establishes '
                   'rollback_capability before the push')
        return bad, None, None
    cap, push = steps[ids.index('push_capability')], steps[ids.index('push')]
    if ids.index('push_capability') > ids.index('push'):
        bad.append('static: push_capability comes AFTER the push -- a gate after the mutation is '
                   'a report, not a gate')
    if 'inputs.push' not in str(cap.get('if', '')):
        bad.append('static: push_capability is not conditioned on inputs.push')
    if 'manifest.json' not in str(push.get('run', '')):
        bad.append('static: the push step does not read or record the change manifest')
    posture = [s for s in steps if s.get('id') == 'posture']
    if not posture or 'steps.push_capability.outcome' not in str(posture[0].get('env') or {}):
        bad.append('static: the posture step does not read the push_capability outcome')
    ups = [i for i, s in enumerate(steps) if 'upload-artifact' in str(s.get('uses', ''))
           and 'build-evidence' in str((s.get('with') or {}).get('path', ''))]
    if not ups:
        bad.append('static: the build evidence (snapshot, capability, manifest) is not uploaded; '
                   'it dies with the runner')
    elif ups[0] < ids.index('push') or 'always()' not in str(steps[ups[0]].get('if', '')):
        bad.append('static: the build evidence upload must come after the push and run on every path')
    return bad, cap, push


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
    doc = H.load(WF)
    bad, cap, push = static_problems(doc)
    if bad:
        for b in bad:
            print('FAIL: %s' % b)
        return 1
    cap = H.step(WF, 'build', 'push_capability')
    push = H.step(WF, 'build', 'push')

    tmp = tempfile.mkdtemp(prefix='push-capability-probe-')
    try:
        shims = os.path.join(tmp, 'shim')
        H.shim(shims, 'docker', DOCKER)

        def world(name, registry):
            ws = os.path.join(tmp, name)
            os.makedirs(ws)
            log = os.path.join(ws, 'pushes.log')
            io.open(log, 'w').close()
            env = {'SHIM_REGISTRY': registry, 'SHIM_LOG': log, 'SHIM_IMAGE': IMAGE,
                   'SHIM_REPO': REPO, 'SHIM_PUSHED': PUSHED, 'REPO': REPO, 'IMAGE': IMAGE,
                   'RUNNER_TEMP': ws, 'MSYS2_ENV_CONV_EXCL': '*', 'MSYS_NO_PATHCONV': '1'}
            return ws, log, env

        def evidence(ws, name):
            p = os.path.join(ws, 'build-evidence', name)
            if not os.path.isfile(p):
                return None
            try:
                return json.load(io.open(p, encoding='utf-8'))
            except ValueError:
                return 'UNPARSEABLE'

        def pushes(log):
            return [l for l in io.open(log, encoding='utf-8').read().splitlines() if l]

        ctx = {'inputs.push': 'true'}

        def capability(name, registry):
            ws, log, env = world(name, registry)
            r = H.run(bash, cap, ctx, ws, shims, env)
            print('  %-18s capability exit=%d previous_state=%-20s rollback_capability=%s'
                  % (name, r['rc'], r['outputs'].get('previous_state'),
                     r['outputs'].get('rollback_capability')))
            return ws, log, env, r

        # allowed: an existing tag is a rollback point, and the push applies the planned entry.
        for name in ('allowed', 'recovery'):
            ws, log, env, r = capability(name, PRIOR)
            m = evidence(ws, 'manifest.json')
            if (r['rc'] != 0 or r['outputs'].get('previous_state') != 'EXISTING_DEPLOYMENT'
                    or r['outputs'].get('rollback_capability') != 'AVAILABLE'):
                bad.append('%s: an existing tag must be EXISTING_DEPLOYMENT / AVAILABLE\n%s'
                           % (name, r['log'][-400:]))
            if not isinstance(m, dict) or m.get('status') != 'planned' or not m.get('entries') \
                    or m['entries'][0].get('action') != 'MODIFIED' \
                    or m['entries'][0].get('prior') != '%s@%s' % (REPO, PRIOR):
                bad.append('%s: the manifest must be planned as MODIFIED with the prior digest '
                           'before the push (got %r)' % (name, m))
            p = H.run(bash, push, ctx, ws, shims, env)
            m2 = evidence(ws, 'manifest.json')
            print('  %-18s push exit=%d digest=%s manifest=%s' % (
                name, p['rc'], p['outputs'].get('digest'), (m2 or {}).get('status')
                if isinstance(m2, dict) else m2))
            if p['rc'] != 0 or p['outputs'].get('digest') != PUSHED or pushes(log) != ['push ' + IMAGE]:
                bad.append('%s: the push must push the image once and return its digest\n%s'
                           % (name, p['log'][-400:]))
            if not isinstance(m2, dict) or m2.get('status') != 'applied' \
                    or m2['entries'][0].get('post') != '%s@%s' % (REPO, PUSHED):
                bad.append('%s: after the push the manifest must be applied with the pushed '
                           'digest (got %r)' % (name, m2))

        # allowed-empty: a tag the registry does not hold is NO_PRIOR_STATE, planned as CREATED.
        ws, log, env, r = capability('allowed-empty', 'absent')
        m = evidence(ws, 'manifest.json')
        if (r['rc'] != 0 or r['outputs'].get('previous_state') != 'EMPTY'
                or r['outputs'].get('rollback_capability') != 'NO_PRIOR_STATE'):
            bad.append('allowed-empty: a measured-absent tag must be EMPTY / NO_PRIOR_STATE\n%s'
                       % r['log'][-400:])
        if not isinstance(m, dict) or m.get('status') != 'planned' \
                or (m.get('entries') or [{}])[0].get('action') != 'CREATED':
            bad.append('allowed-empty: the manifest must plan a CREATED entry (got %r)' % m)

        # missing-evidence: a registry that cannot be read is UNKNOWN, never empty; refused.
        ws, log, env, r = capability('missing-evidence', 'down')
        if r['rc'] == 0 or r['outputs'].get('previous_state') != 'UNKNOWN' \
                or r['outputs'].get('rollback_capability') != 'UNAVAILABLE':
            bad.append('missing-evidence: an unreadable registry must be UNKNOWN / UNAVAILABLE '
                       'and FAIL before the push (exit %d, %r)' % (r['rc'], r['outputs']))
        if evidence(ws, 'manifest.json') is not None:
            bad.append('missing-evidence: a manifest was planned on an unknown previous state')
        p = H.run(bash, push, ctx, ws, shims, env)
        print('  %-18s push exit=%d pushes=%s' % ('missing-evidence', p['rc'], pushes(log)))
        if p['rc'] == 0 or pushes(log):
            bad.append('missing-evidence: the push went ahead after the capability step refused')

        # attack: the push reached with no planned manifest at all must refuse to mutate.
        ws, log, env = world('attack', PRIOR)
        p = H.run(bash, push, ctx, ws, shims, env)
        print('  %-18s push exit=%d pushes=%s' % ('attack', p['rc'], pushes(log)))
        if p['rc'] == 0 or pushes(log):
            bad.append('attack: the push mutated the registry with no change manifest planned')
    finally:
        shutil.rmtree(tmp, ignore_errors=True)

    if bad:
        for b in bad:
            print('FAIL: %s' % b)
        return 1
    print('PASS: rollback_capability is established and the change manifest planned before the '
          'push; an unreadable registry refuses; a push with no manifest refuses; the push '
          'records what it wrote.')
    return 0


if __name__ == '__main__':
    sys.exit(main())

#!/usr/bin/env python3
"""V1: verification before mutation, five outcomes, rung routing, and a plan gate held as debt.

WHY THIS EXISTS (ledger L89; PROVENANCE_AND_ATTESTATION.md section 6.1-6.4, section 9 step 5)

    "A stamp is a write. An attestation is a signature. A verification is a refusal. Only the third
    one is a control." Nothing in the kit verified anything. Section 6.2 requires four outcomes that
    must not collapse -- verified, absent, contradicted, not-establishable -- and section 6.4 requires
    that "this plan does not offer attestations" render DIFFERENTLY from "this image has no
    attestation", as held debt with a plan trigger rather than a permanently red gate.

WHAT IS RUN
    The verify-attestation composite's own step, extracted as shipped, under the composite shell,
    with `gh` SHIMMED: each scenario is a recorded answer from `gh attestation verify` (verified JSON,
    "no attestations found", a signature failure, a network error, a JSON whose subject is another
    digest). The shim also records whether it was called at all. jq is real.

    The template's wiring is checked statically: the verify result must feed the deploy decision.

    OWED TO A HOSTED RUN: that real `gh attestation verify` output for an image in ACR is classified
    as these recorded answers are (PROV section 11.2 -- whether the oci:// lookup resolves for a
    registry GitHub never saw is itself unestablished).

CASES (docs/PROOF_RULE.md) -- each at crawl, walk and run, against the section 6.3 table
    allowed           verified                                   -> PROCEED at every rung
    attack            contradicted (bad signature; subject is a different digest)
                                                                 -> BLOCKED at every rung
    missing-evidence  absent -> PROCEED_WITH_ADVISORY / DECISION_REQUIRED / DECISION_REQUIRED;
                      not-establishable (network; gh missing)    -> EVIDENCE_UNTRUSTED at every rung
    held              private repository, plan offers none       -> held, gh NEVER called, NOT the
                      absent outcome, debt IMPLEMENTATION_HELD
    recovery          the held repository made public            -> armed, verified -> PROCEED

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

ACTION = '.github/actions/verify-attestation/action.yml'
TPL = 'templates/build-deploy.yml'
D = 'sha256:' + '8' * 64
OTHER = '9' * 64

GH = r'''
echo "$*" >> "$SHIM_CALLS"
case "$SHIM_MODE" in
  verified) printf '[{"verificationResult":{"statement":{"subject":[{"name":"x","digest":{"sha256":"%s"}}]}}}]\n' "${SHIM_DIGEST#sha256:}" ;;
  wrongsubject) printf '[{"verificationResult":{"statement":{"subject":[{"name":"x","digest":{"sha256":"%s"}}]}}}]\n' "$SHIM_OTHER" ;;
  absent) echo "Error: no attestations found for subject" >&2; exit 1 ;;
  badsig) echo "Error: failed to verify signature: certificate identity does not match expected signer workflow" >&2; exit 1 ;;
  network) echo "Error: Get \"https://api.github.com/\": dial tcp: lookup api.github.com: no such host" >&2; exit 1 ;;
  *) echo "gh shim: unknown mode" >&2; exit 64 ;;
esac
'''

TABLE = {  # PROVENANCE_AND_ATTESTATION.md section 6.3
    'ATTESTATION_VERIFIED': ('PROCEED', 'PROCEED', 'PROCEED'),
    'ATTESTATION_ABSENT': ('PROCEED_WITH_ADVISORY', 'DECISION_REQUIRED', 'DECISION_REQUIRED'),
    'ATTESTATION_CONTRADICTED': ('BLOCKED', 'BLOCKED', 'BLOCKED'),
    'ATTESTATION_NOT_ESTABLISHABLE': ('EVIDENCE_UNTRUSTED',) * 3,
}
RUNGS = ('crawl', 'walk', 'run')


def static(bad):
    v = ((H.load(TPL).get('jobs') or {}).get('verdict') or {})
    steps = v.get('steps') or []
    ver = [s for s in steps if 'verify-attestation' in str(s.get('uses', ''))]
    dec = [s for s in steps if s.get('id') == 'decide']
    if not ver:
        bad.append('template verdict job does not run verify-attestation before deploy (V1)')
        return
    vid = ver[0].get('id')
    if not dec or 'steps.%s.outputs.routing_result' % vid not in str(dec[0].get('env')):
        bad.append('the deploy decision does not read the verification routing_result: a '
                   'verification nobody reads is not a control')
    if steps.index(ver[0]) > steps.index(dec[0]) if dec else True:
        bad.append('verification runs after the decision')
    perms = v.get('permissions') or {}
    if any(str(x) == 'write' for x in perms.values()):
        bad.append('the verdict job holds a write permission; verification only reads (8.2)')


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
    if not os.path.exists(os.path.join(H.ROOT, ACTION)):
        print('FAIL: %s does not exist. Nothing verifies an attestation anywhere (L89; PROV 6.1 V1): '
              'every provenance claim in the kit is a stamp nobody can contradict.' % ACTION)
        return 1
    step = H.load(ACTION)['runs']['steps'][0]
    bad = []
    static(bad)
    tmp = tempfile.mkdtemp(prefix='verify-attestation-probe-')
    try:
        shims = os.path.join(tmp, 'shim')
        H.shim(shims, 'gh', GH)
        nogh = os.path.join(tmp, 'nogh')
        os.makedirs(nogh)

        def run(name, mode, rung, visibility='private', available='true', path=None):
            ws = os.path.join(tmp, '%s-%s' % (name, rung))
            os.makedirs(ws)
            calls = os.path.join(ws, 'calls')
            ctx = {'inputs.image-digest': D, 'inputs.subject-name': 'reg.example/app',
                   'inputs.repository': 'org/repo',
                   'inputs.signer-workflow': 'org/kit/.github/workflows/reusable-build-docker.yml',
                   'inputs.rung': rung, 'inputs.repository-visibility': visibility,
                   'inputs.attestations-available': available, 'github.token': 't'}
            env = {'SHIM_MODE': mode, 'SHIM_CALLS': calls, 'SHIM_DIGEST': D, 'SHIM_OTHER': OTHER}
            if path is not None:
                env['PATH'] = path
            r = H.run(bash, step, ctx, ws, None if path is not None else shims, env, composite=True)
            o = r['outputs']
            return r, o, os.path.exists(calls)

        expect = [('verified', 'verified', 'ATTESTATION_VERIFIED'),
                  ('attack-badsig', 'badsig', 'ATTESTATION_CONTRADICTED'),
                  ('attack-wrong-subject', 'wrongsubject', 'ATTESTATION_CONTRADICTED'),
                  ('missing-absent', 'absent', 'ATTESTATION_ABSENT'),
                  ('missing-network', 'network', 'ATTESTATION_NOT_ESTABLISHABLE')]
        for name, mode, outcome in expect:
            for i, rung in enumerate(RUNGS):
                r, o, called = run(name, mode, rung)
                want = TABLE[outcome][i]
                ok = o.get('outcome') == outcome and o.get('routing_result') == want
                print('  %-22s %-5s outcome=%-30s routing=%s' % (name, rung, o.get('outcome'),
                                                                o.get('routing_result')))
                if not ok:
                    bad.append('%s at %s: %s / %s, want %s / %s\n%s' % (
                        name, rung, o.get('outcome'), o.get('routing_result'), outcome, want,
                        r['log'][-300:]))
        # gh absent entirely: the check could not be performed
        # Dropping every PATH directory that holds gh is not "gh absent" on a hosted runner:
        # there gh lives in /usr/bin beside bash, jq and coreutils, so the step lost its whole
        # toolchain and wrote no outputs at all (self-test run 38784408737: None / None). Keep
        # each such directory's OTHER executables, re-exposed through a sandbox directory.
        kept = os.path.join(tmp, 'sysbin-without-gh')
        os.makedirs(kept)
        sysdirs = []
        for p in os.environ.get('PATH', '').split(os.pathsep):
            if not p or not shutil.which('gh', path=p):
                sysdirs.append(p)
                continue
            for f in sorted(os.listdir(p)):
                src = os.path.join(p, f)
                if os.path.splitext(f)[0].lower() == 'gh' or not os.path.isfile(src) \
                        or not os.access(src, os.X_OK) or os.path.exists(os.path.join(kept, f)):
                    continue
                try:
                    os.symlink(src, os.path.join(kept, f))
                except OSError:
                    H.shim(kept, f, '#!/usr/bin/env bash\nexec "%s" "$@"\n'
                           % src.replace('\\', '/'))
            sysdirs.append(kept)
        if shutil.which('gh', path=os.pathsep.join(sysdirs)):
            print('UNKNOWN: could not construct a PATH without gh.')
            return 2
        sysdirs = os.pathsep.join(sysdirs)
        r, o, _ = run('missing-no-gh', 'verified', 'run', path=nogh + os.pathsep + sysdirs)
        print('  %-22s %-5s outcome=%-30s routing=%s' % ('missing-no-gh', 'run', o.get('outcome'),
                                                        o.get('routing_result')))
        if o.get('outcome') != 'ATTESTATION_NOT_ESTABLISHABLE' or \
                o.get('routing_result') != 'EVIDENCE_UNTRUSTED':
            bad.append('missing-no-gh: %s / %s' % (o.get('outcome'), o.get('routing_result')))
        # held by plan
        r, o, called = run('held', 'verified', 'run', visibility='private', available='false')
        print('  %-22s %-5s outcome=%-30s debt=%s gh-called=%s' % ('held', 'run', o.get('outcome'),
                                                                  o.get('debt'), called))
        if called:
            bad.append('held: gh was called on a plan that offers no attestations')
        if o.get('outcome') in TABLE or not o.get('outcome'):
            bad.append('held: outcome %r renders like a verification result; plan unavailability '
                       'must be spelled differently (6.4)' % o.get('outcome'))
        if o.get('debt') != 'IMPLEMENTATION_HELD':
            bad.append('held: debt %r, want IMPLEMENTATION_HELD' % o.get('debt'))
        if o.get('routing_result') in ('BLOCKED', 'EVIDENCE_UNTRUSTED', 'PROCEED'):
            bad.append('held: routing %r -- held is neither a permanent stop nor a clean pass'
                       % o.get('routing_result'))
        # recovery: public repository arms regardless of the plan input
        r, o, called = run('recovery-public', 'verified', 'run', visibility='public',
                           available='false')
        print('  %-22s %-5s outcome=%-30s gh-called=%s' % ('recovery-public', 'run',
                                                          o.get('outcome'), called))
        if not called or o.get('outcome') != 'ATTESTATION_VERIFIED':
            bad.append('recovery-public: a public repository must arm verification immediately')
        # bad rung refused
        r, o, _ = run('attack-bad-rung', 'verified', 'sprint')
        if r['rc'] == 0:
            bad.append('attack-bad-rung: an unknown rung was accepted')
    finally:
        shutil.rmtree(tmp, ignore_errors=True)
    if bad:
        for b in bad:
            print('FAIL: %s' % b)
        return 1
    print('PASS: verification yields five distinct outcomes routed per the section 6.3 table; plan '
          'unavailability is held as IMPLEMENTATION_HELD and never calls gh; the template decision '
          'reads it. OWED: real gh output against an ACR image on a hosted run.')
    return 0


if __name__ == '__main__':
    sys.exit(main())

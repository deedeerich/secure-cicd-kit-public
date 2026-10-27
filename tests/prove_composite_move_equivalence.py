#!/usr/bin/env python3
"""A scanner job moved into a `$/` composite is the SAME job: proven by expansion, not by reading.

WHY THIS EXISTS (completion ledger L64, B-01; decomposition plan section 7 step 12)

    The flagship's scanner job bodies move into `.github/actions/<scanner>/` so the file GitHub
    must parse shrinks well below its fail line. A move is only worth making if it changes nothing
    a consumer or the gate can observe: every artefact name, every annotation, every SARIF category,
    every `if:` and every step order must be what it was. "Looks the same" is how a kit loses
    controls silently, so this proof establishes it mechanically:

      1  the job now delegates: its first step is `uses: $/.github/actions/<composite>` with no
         `if:` (status functions inside a composite see only the composite's steps; as the job's
         FIRST step, they see exactly what they saw inline), and the only other step is the
         generated Result summary, which reads `job.status`;
      2  expanding the call back into the job (tests/_composite_expand.py: every `${{ inputs.X }}`
         replaced by the expression the job passes) raises no problem -- no `needs`/`secrets`
         inside the composite, no string-typed input standing in for a boolean in an expression;
      3  the expanded job -- its own keys (needs, if, name, runs-on, timeout, permissions, outputs,
         env) and every step's name, id, if, uses, with, env, run, shell, continue-on-error -- has
         the SAME canonical digest as the job had at the base commit, with one declared
         normalisation: a `run:` step with no shell is `bash -e {0}`, the default it ran under.
         When the base commit is in this clone, the two are also compared step by step and any
         difference is printed.

    The behavioural proofs (prove_secret_denominator, prove_secrets_always_block,
    prove_test_only_seeds_add_only, prove_cppcheck_collects, prove_sast_cpp_runs, ...) then RUN the
    composite's steps through the same expansion, so the moved steps are executed as well as
    compared.

    A LATER, DELIBERATE CHANGE to a moved scanner re-pins with `--repin <job>` and says why in its
    commit: the pin then records reviewed content, exactly like the kit-scripts manifest digest.

EXIT  0 every moved job is equivalent   1 a difference or a broken move   2 UNKNOWN (cannot check)
"""
import copy
import hashlib
import io
import json
import os
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, HERE)
import _composite_expand as ce  # noqa: E402

WF_REL = '.github/workflows/reusable-security.yml'
WF = os.path.join(ROOT, *WF_REL.split('/'))
STATUS_STEP = 'Result summary'

# job -> (composite, base commit the move was made from, canonical digest of the job AT that base)
#
# RE-PINNED 2026-10-22, lane L-H (ledger L82, O-23), all six with `--repin <job>`. Reason: every
# remote `uses:` in the job and its composite moved from a tag to the full commit SHA that tag
# named that day, with its exact release in a trailing comment (tests/check_action_pins.py). The
# step-level diff against 11d1d56 before the re-pin showed `uses:` values ONLY -- 35 of them, no
# name, if, with, env, run, shell or job key changed. The digests the move itself established were:
#   secret-scan 5c2dfb3f...2bab  sast-cpp 37f22a09...689ec  iac-scan c388f450...445d
#   deps-scan e11eb98c...0c25    sast-dotnet 750fb3fb...f14d sast-java 14edcb1a...b767
#
# RE-PINNED 2026-10-22, lane L-S (owner ruling O-24: the security gate is the single enforcement
# point), five jobs with `--repin <job>`: deps-scan, iac-scan, sast-cpp, sast-dotnet, sast-java.
# Reason: each enforce step now HANDS findings to the gate as findings_state=FINDINGS and exits 0
# instead of failing the job (an `id:` on each enforce step, the composite's `outputs:`, the job's
# `outputs:`, and the run text); Checkov's COLLECTION_FAILED no longer passes under advisory_mode.
# The step-level diff against 7515088 before the re-pin showed exactly that and nothing else: job
# key `outputs` added, and `id` + `run` on the enforce step(s) only. The L-H pins were:
#   sast-cpp 98a596e2...3cfc  iac-scan 40a4ebe0...5f99  deps-scan 7503e7af...aa63d
#   sast-dotnet b60fe634...21ff  sast-java c653d8c1...d381
#
# RE-PINNED 2026-10-22, lane L-S, secret-scan with `--repin secret-scan`. Reason: owner ruling of
# 2026-10-22 -- a secret may be excepted by a ticketed, attributed, finding-scoped register entry,
# and only the gate holds the policy -- so the Enforce step HANDS secrets to the gate
# (findings_state, secret_count) and exits 0 instead of failing the job; the gate blocks them at
# every tier unless each is excepted. The step-level diff against 5b06ccb was the job `outputs` key
# and `id` + `run` on the Enforce step only. The L-H pin was 12d86c1c...51f5.
MOVES = {
    # RE-PINNED 2026-10-23, lane L-PIN (KDEC-027), `--repin deps-scan` and `--repin iac-scan`. Reason:
    # aquasecurity/trivy-action -> setup-trivy checks out `aquasecurity/trivy` against github.server_url,
    # which a GHE.com tenant does not have, so every Trivy step failed to install there. Each Trivy step
    # is now "Install Trivy (pinned release binary)" + "Trivy database cache" (actions/cache) + a `run:`
    # step carrying trivy-action's own TRIVY_* settings. The step-level diff was those three steps in
    # place of the trivy-action step, nothing else.
    # RE-PINNED 2026-10-23, lane L-PIN (KDEC-027), all six with `--repin <job>`. Reason: every
    # $GITHUB_OUTPUT write of external text is single-line sanitised (tests/check_output_writes.py:
    # `echo "count=${n//[$'\r\n']/ }"`), and sast-cpp's Python writer joins a value's lines. The
    # step-level diff was `run` on the count/collection steps only.
    # RE-PINNED 2026-10-22, lane L-FX, `--repin secret-scan`. Reason: KDEC-018 (owner, 2026-10-22:
    # "You can't drop below crawl ever") -- the secret scan always covers the repository root, so
    # the job hands the composite `paths: "."` instead of the caller's `paths`, which narrowed the
    # secret scan below crawl (tests/prove_crawl_floor.py K1). The step-level diff against 109cff8
    # was IN_PATHS on the seeds, gitleaks and detect-secrets steps only ('${{ inputs.paths }}' ->
    # '.'). The L-S pin was 32f72944...1ff6.
    # RE-PINNED 2026-10-22, lane L-SD, `--repin secret-scan`. Reason: with the scope at the root,
    # the kit's own rules file (and history log, staged binary, detect-secrets report) landed in
    # the scanned scope and was counted, so an empty repository was never COLLECTION_FAILED
    # (hosted job 119995060869; tests/prove_secret_denominator.py). They now go to RUNNER_TEMP,
    # and detect-secrets leaves out the kit's own gitleaks.sarif. The step-level diff against
    # a31c0a6 was `run` on Write the Azure/Entra rules, Install gitleaks, Gitleaks and
    # detect-secrets only. The L-FX pin was dbd82bc7...fc8f.
    # RE-PINNED 2026-10-27, lane L-MIRROR (KDEC-032, the gaps closed), `--repin secret-scan`. Reason: gitleaks is pinned BY DIGEST and may come from the organisation's image mirror. The canonical diff
    # against the previous pin is: runs-on becomes `vars.KIT_FEED_MIRROR_RUNNER || 'ubuntu-latest'`; the Install
    # gitleaks step gains env W_IMAGE_REGISTRY (vars.KIT_SCANNER_IMAGE_REGISTRY) and its IMG line becomes
    # `zricethezav/gitleaks:v8.21.2@sha256:0e99e882...7f46`, redirected to <registry>/zricethezav/gitleaks@<the
    # same digest> when the registry is set. Nothing else in the step or the job changed.
    # The previous pin was 72d388c0...2d9d.
    'secret-scan': ('secret-scan', '11d1d56',
                    'ab72005d155316870bc604ccb193a5fd599a8a2221971225743bf2fcf0ed9134'),
    # RE-PINNED 2026-10-23, integration lane L-INT1, `--repin sast-cpp`, after the merge pin
    # 7981aba5...99f1. Reason: KDEC-027 -- L-SCAN-B's new `C/C++ build metadata` step wrote
    # scan_state/scan_reason as `$(cat ...)` straight into $GITHUB_OUTPUT; each is now read into a
    # variable and flattened to one line. The step-level diff was `run` on that step only.
    # RE-PINNED 2026-10-23, integration lane L-INT1, `--repin sast-cpp`. Reason: L-PIN (KDEC-027,
    # sanitised output writes; its pin was f7228a0c...350a) and L-SCAN-B (KDEC-026, below; its pin
    # was 4b0c6fce...7c39) each re-pinned sast-cpp from c7e1ea9; the merged composite carries both.
    # RE-PINNED 2026-10-23, lane L-SCAN-B, `--repin sast-cpp`. Reason: KDEC-026, build-aware C/C++
    # -- a new `C/C++ build metadata` step (id cpp_build) before cppcheck, the cppcheck step's run
    # text (one pass per trusted compilation database, then source-only over what none covers, the
    # converter reading every pass and writing repository-relative paths), and job/composite
    # outputs scan_state and scan_reason (CPP_ANALYSIS_PARTIAL). No other step changed. The pin
    # before was 2763b67b...eeeb. tests/prove_cpp_build_aware.py runs the changed steps.
    'sast-cpp': ('sast-cpp', '11d1d56',
                 'b90b7c7495d9a02fe32b4c03cd937d16ff47caa878674bb5610014c6ccbe148e'),
    # RE-PINNED 2026-10-23, integration lane L-INT1, `--repin iac-scan` and `--repin deps-scan`.
    # Reason: L-SCAN-A (KDEC-025, the lint steps below) and L-PIN (KDEC-027, the pinned Trivy
    # binary and sanitised output writes above) each re-pinned these two from c7e1ea9; merged, the
    # composites carry both changes, so neither lane's digest holds. The step-level diff against
    # 11d1d56 is the union of the two lanes' diffs and nothing else. The lanes' pins were iac-scan
    # 3cac4182...9ed4 (L-SCAN-A) / d3aff382...4ab0 (L-PIN) and deps-scan dd57ab7f...aef9 (L-SCAN-A)
    # / fe573f0e...f37c (L-PIN).
    # RE-PINNED 2026-10-23, lane L-SCAN-A, `--repin iac-scan` and `--repin deps-scan`. Reason:
    # KDEC-025 (owner, 2026-10-23: "All the gaps need to be addressed as closed", cost-beneficially)
    # -- the pipeline linters ride in jobs that already run instead of jobs of their own. Against
    # c7e1ea9 the change is ADDITIVE ONLY: iac-scan gains the `dockerfile` input and the hadolint
    # steps (lint, enforce, publish check, a generated redaction, upload, Security-tab upload,
    # degraded notice) after its last Trivy step, and its findings_state also reads hadolint's;
    # deps-scan gains the `workflows`/`shell`/`powershell` inputs and the pipeline-lint steps
    # (install, actionlint + zizmor, shellcheck, PSScriptAnalyzer, enforce, publish check, a
    # generated redaction, four uploads, four Security-tab uploads, degraded notice) after its last
    # Trivy step, and its findings_state also reads lint_enforce's. No existing step's name, id,
    # if, uses, with, env, run or shell changed; each job passes the new inputs from discovery.
    # The L-S pins were iac-scan d66edea4...0806 and deps-scan bb038edc...905e.
    # RE-PINNED 2026-10-27, lane L-MIRROR (KDEC-032, the gaps closed), `--repin iac-scan`. Reason: Trivy's misconfiguration checks bundle may come from the organisation mirror. The canonical diff
    # against the previous pin is: runs-on becomes `vars.KIT_FEED_MIRROR_RUNNER || 'ubuntu-latest'`, and ONE step
    # after the Trivy database cache -- `Trivy checks bundle from the organisation mirror (KDEC-032)`, running
    # scripts/feed_mirror_step.sh with M_FEED trivy-checks and the three vars.KIT_FEED_MIRROR_* values,
    # `if: always()` because it follows Checkov's enforce step (tests/prove_scanners_survive_enforce.py).
    # The previous pin was 49d9144a...3093.
    'iac-scan': ('iac-scan', '11d1d56',
                 'edd6c6c638e7fb0d586840a63266ab81890152248258dcd66a8031b8ca187469'),
    # RE-PINNED 2026-10-27, lane L-MIRROR (KDEC-032 PROPOSED, Release 4 feed mirrors), `--repin
    # deps-scan`. Reason: the Trivy database may come from the organisation mirror. Against 9bdbb23 the
    # canonical diff is ADDITIVE ONLY: runs-on becomes `vars.KIT_FEED_MIRROR_RUNNER || 'ubuntu-latest'`
    # (the private runner that reaches the mirror, the hosted runner as before when unset), and ONE step
    # after the Trivy database cache -- `Trivy database from the organisation mirror (KDEC-032)`, running
    # scripts/feed_mirror_step.sh with the job's three vars.KIT_FEED_MIRROR_* values. No existing step's
    # name, id, if, uses, with, env, run or shell changed. The L-INT1 pin was 980ac662...8197.
    'deps-scan': ('deps-scan', '11d1d56',
                  '751648420b56b57d32dccb1c3275277a9c92a8f752adf8f637e45fa10c3a405e'),
    # RE-PINNED 2026-10-23, integration lane L-INT1, `--repin sast-dotnet`. Reason: L-PIN (KDEC-027,
    # its pin was 5ffff3c6...cf1d) and L-SCAN-B (KDEC-026, below; its pin was 5194ff9c...94ec) each
    # re-pinned sast-dotnet from c7e1ea9; the merged composite carries both.
    # RE-PINNED 2026-10-23, lane L-SCAN-B, `--repin sast-dotnet`. Reason: KDEC-026 -- the first
    # run over a real-shaped solution (tests/prove_dotnet_solution_detects.py) found every NuGet
    # advisory filed against the .sln at line 1; the `NuGet audit — count` run text now files each
    # result against the project dotnet reports. No other step changed. The pin before was
    # 08291421...bdf4.
    'sast-dotnet': ('sast-dotnet', '11d1d56',
                    '7390c5846d1d2b05a1334050ebec771c60b9aca342f3cc5b4f1a6e9e621e04c2'),
    'sast-java': ('sast-java', '11d1d56',
                  'c8e8ce39fc7e1baef5b733affb890d387fd726645e739e269cd9261f7b5a4571'),
}


def load(text):
    import yaml
    return yaml.safe_load(text)


def canonical(doc, job_name, root=ROOT):
    """-> (canonical JSON text, [problem]) for one job with its composites expanded."""
    job = copy.deepcopy(((doc or {}).get('jobs') or {}).get(job_name))
    if job is None:
        return None, ['%s: no such job' % job_name]
    # `reads`: a scanner composite called with an id hands the job its outputs (findings_state,
    # lane L-S); the job's reads of them are rewritten to the composite's own expression, so the
    # canonical job is the one the runner evaluates.
    reads = {}
    steps, problems = ce.expand_steps(job.get('steps') or [], doc, root, None, reads)
    if reads and 'outputs' in job:
        job['outputs'] = ce.rewrite_reads(job['outputs'], reads)
    job['steps'] = [ce.normalise_shell(ce.rewrite_reads(s, reads)) for s in steps]
    return json.dumps(job, sort_keys=True, ensure_ascii=False, indent=1), problems


def digest(text):
    return hashlib.sha256(text.encode('utf-8')).hexdigest()


def structure(doc, job_name, comp):
    """-> [problem]: the job delegates to its composite and keeps only its Result summary."""
    job = ((doc or {}).get('jobs') or {}).get(job_name) or {}
    steps = job.get('steps') or []
    want = ce.PREFIX + comp
    if not steps or steps[0].get('uses') != want:
        return ['%s: the first step is not `uses: %s` (it is %r) -- the job body has not moved'
                % (job_name, want, (steps[0].get('uses') or steps[0].get('name')) if steps else None)]
    probs = []
    if 'if' in steps[0]:
        probs.append('%s: the composite call carries `if:`' % job_name)
    rest = [s.get('name') for s in steps[1:]]
    if rest != [STATUS_STEP]:
        probs.append('%s: steps after the composite call are %r; only %r (it reads job.status) '
                     'belongs in the job' % (job_name, rest, STATUS_STEP))
    if not ce.action_file(comp):
        probs.append('%s: .github/actions/%s/action.yml does not exist' % (job_name, comp))
    return probs


def git_show(rev, rel):
    try:
        p = subprocess.run(['git', 'show', '%s:%s' % (rev, rel)], cwd=ROOT, capture_output=True,
                           text=True, encoding='utf-8', errors='replace')
    except OSError:
        return None
    return p.stdout if p.returncode == 0 else None


def step_diff(old_text, new_text):
    o, n = json.loads(old_text), json.loads(new_text)
    out = []
    for k in sorted(set(o) | set(n)):
        if k != 'steps' and o.get(k) != n.get(k):
            out.append('  job key %r: %r -> %r' % (k, o.get(k), n.get(k)))
    os_, ns = o.get('steps') or [], n.get('steps') or []
    if len(os_) != len(ns):
        out.append('  step count %d -> %d' % (len(os_), len(ns)))
    for i, (a, b) in enumerate(zip(os_, ns)):
        if a != b:
            for k in sorted(set(a) | set(b)):
                if a.get(k) != b.get(k):
                    out.append('  step %d (%s) %s: %r -> %r'
                               % (i + 1, a.get('name') or a.get('uses'), k,
                                  str(a.get(k))[:160], str(b.get(k))[:160]))
    return out


def self_test():
    """Each defect class the proof claims to catch, seeded on a synthetic job and composite."""
    import tempfile
    import shutil
    tmp = tempfile.mkdtemp(prefix='move-eq-')
    try:
        os.makedirs(os.path.join(tmp, '.github', 'actions', 'c'))
        action = ('name: c\ndescription: d\ninputs:\n'
                  '  paths: {description: p, required: true}\n'
                  '  flag: {description: f, required: true}\n'
                  'runs:\n  using: composite\n  steps:\n'
                  '    - name: scan\n      if: inputs.paths != \'\'\n      shell: bash -e {0}\n'
                  '      env:\n        IN_PATHS: ${{ inputs.paths }}\n'
                  '      run: echo "$IN_PATHS" ${{ inputs.flag }}\n')
        ap = os.path.join(tmp, '.github', 'actions', 'c', 'action.yml')
        io.open(ap, 'w', encoding='utf-8').write(action)
        on = {'workflow_call': {'inputs': {'paths': {'type': 'string'}, 'flag': {'type': 'boolean'}}}}
        old = {'on': on, 'jobs': {'j': {'steps': [
            {'name': 'scan', 'if': "inputs.paths != ''", 'env': {'IN_PATHS': '${{ inputs.paths }}'},
             'run': 'echo "$IN_PATHS" ${{ inputs.flag }}'},
            {'name': STATUS_STEP, 'run': 's'}]}}}
        new = {'on': on, 'jobs': {'j': {'steps': [
            {'name': 'call', 'uses': ce.PREFIX + 'c',
             'with': {'paths': '${{ inputs.paths }}', 'flag': '${{ inputs.flag }}'}},
            {'name': STATUS_STEP, 'run': 's'}]}}}
        a, pa = canonical(old, 'j', tmp)
        b, pb = canonical(new, 'j', tmp)
        if pa or pb or a != b:
            return 'the control failed: %s %s %s' % (pa, pb, step_diff(a, b))
        if structure(old, 'j', 'c') == []:
            return 'did not catch: an unmoved job read as delegating'
        cases = []
        d = copy.deepcopy(new); d['jobs']['j']['steps'][0]['if'] = 'always()'
        cases.append(('a guarded composite call', d, lambda c, p, s: bool(s)))
        d = copy.deepcopy(new); d['jobs']['j']['steps'][0]['with']['paths'] = '${{ inputs.paths }}x'
        cases.append(('a changed input expression', d, lambda c, p, s: c != a))
        d = copy.deepcopy(new); del d['jobs']['j']['steps'][0]['with']['flag']
        cases.append(('a required input not passed', d, lambda c, p, s: bool(p)))
        d = copy.deepcopy(new); d['jobs']['j']['steps'].insert(1, {'name': 'x', 'run': 'y'})
        cases.append(('a step left behind in the job', d, lambda c, p, s: bool(s)))
        for label, doc, caught in cases:
            c, p = canonical(doc, 'j', tmp)
            if not caught(c, p, structure(doc, 'j', 'c')):
                return 'did not catch: %s' % label
        # Composite-side defects: a byte changed in a run body; a boolean used inside an
        # expression through a string input; a context that does not exist in a composite.
        for label, old_s, new_s in (
                ('a byte changed in a moved run body', 'echo "$IN_PATHS"', 'echo "$IN_PATH"'),
                ('a boolean input inside an expression', "if: inputs.paths != ''",
                 "if: inputs.flag"),
                ('needs inside a composite', 'IN_PATHS: ${{ inputs.paths }}',
                 'IN_PATHS: ${{ needs.discover.outputs.cpp }}')):
            io.open(ap, 'w', encoding='utf-8').write(action.replace(old_s, new_s))
            c, p = canonical(new, 'j', tmp)
            if c == a and not p:
                return 'did not catch: %s' % label
        return None
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


def main(argv):
    try:
        import yaml  # noqa: F401
    except ImportError as e:
        print('UNKNOWN: %s' % e)
        return 2
    err = self_test()
    if err:
        print('SELF-TEST FAILED: %s' % err)
        return 1
    print('self-test ok: 8 seeded defects caught, the control passes')

    if '--repin' in argv:
        job = argv[argv.index('--repin') + 1]
        doc = load(io.open(WF, encoding='utf-8').read())
        c, p = canonical(doc, job)
        print('%s %s%s' % (job, digest(c), ('  PROBLEMS: %s' % p) if p else ''))
        return 1 if p else 0
    if '--base-digest' in argv:
        # --base-digest <job> [<rev>]: the pin to record for a job about to move.
        i = argv.index('--base-digest')
        job = argv[i + 1]
        base = MOVES[job][1] if job in MOVES else (argv[i + 2] if len(argv) > i + 2 else 'HEAD')
        old = git_show(base, WF_REL)
        if old is None:
            print('UNKNOWN: %s is not in this clone' % base)
            return 2
        c, p = canonical(load(old), job)
        print('%s @ %s %s' % (job, base, digest(c)))
        return 0

    doc = load(io.open(WF, encoding='utf-8').read())
    failures = 0
    for job, (comp, base, pin) in sorted(MOVES.items()):
        probs = structure(doc, job, comp)
        c, p = canonical(doc, job)
        probs += p
        got = digest(c) if c else None
        if got != pin:
            probs.append('%s: expanded digest %s, pinned %s (the job as it stood at %s)'
                         % (job, got, pin, base))
            old = git_show(base, WF_REL)
            if old is not None:
                oc, _op = canonical(load(old), job)
                probs += step_diff(oc, c) or ['  (no step-level difference: the pin is stale)']
            else:
                probs.append('  (%s is not in this clone; no step-level diff)' % base)
        if probs:
            failures += 1
            for x in probs:
                print('FAIL: %s' % x)
        else:
            n = len(json.loads(c).get('steps') or [])
            print('PASS: %s -> $/.github/actions/%s: %d steps, digest %s = the job at %s'
                  % (job, comp, n, got[:16], base))
    if failures:
        print('%d moved job(s) are NOT equivalent to the job they replaced.' % failures)
        return 1
    print('every moved scanner job expands to exactly the job it replaced')
    return 0


if __name__ == '__main__':
    sys.exit(main(sys.argv[1:]))

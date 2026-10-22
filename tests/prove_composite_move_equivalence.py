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
MOVES = {
    'secret-scan': ('secret-scan', '11d1d56',
                    '5c2dfb3f1d52683eb0c5107673e24b900620535b20241ee4be222174521a2bab'),
    'sast-cpp': ('sast-cpp', '11d1d56',
                 '37f22a09af091fd8fe24d4f587181ef03359a5d11733265341c7bbf6440689ec'),
    'iac-scan': ('iac-scan', '11d1d56',
                 'c388f450821c18611fb639c4caa2f64923672831589695e397c992a279ed445d'),
    'deps-scan': ('deps-scan', '11d1d56',
                  'e11eb98c7da62eadc6e7d00526ce71307d0610633a1e937b6419dd008ba10c25'),
    'sast-dotnet': ('sast-dotnet', '11d1d56',
                    '750fb3fb83422a11976bab9b9599dd80d0d5678453f53fcf79715af93cd2f14d'),
    'sast-java': ('sast-java', '11d1d56',
                  '14edcb1ab93452f69c453c7068b61c7351f288669a323b0071ae08802dabb767'),
}


def load(text):
    import yaml
    return yaml.safe_load(text)


def canonical(doc, job_name, root=ROOT):
    """-> (canonical JSON text, [problem]) for one job with its composites expanded."""
    job = copy.deepcopy(((doc or {}).get('jobs') or {}).get(job_name))
    if job is None:
        return None, ['%s: no such job' % job_name]
    steps, problems = ce.expand_steps(job.get('steps') or [], doc, root)
    job['steps'] = [ce.normalise_shell(s) for s in steps]
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

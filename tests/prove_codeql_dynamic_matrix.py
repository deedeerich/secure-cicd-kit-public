#!/usr/bin/env python3
"""CodeQL starts a leg only for a language discovery FOUND (cost redesign step 1, W1/L35).

WHY THIS EXISTS

    The codeql job used one job-level `if:` (the OR of seven discovery flags) over a STATIC
    six-leg matrix. On a Python-only repository all six legs started; five did nothing and each
    billed its one-minute minimum (the cost redesign proposal, section 2, W1: 4 of 20 billed minutes on
    the small class). The fix is a matrix built from discovery: one leg per discovered language,
    none for the rest, and no job at all when nothing CodeQL can read was found.

WHAT MUST NOT CHANGE (the proposal's invariants)

    - The legs that RUN are exactly the legs whose static `gate` used to be 'true', for every one
      of the 2^7 discovery combinations, in the same order, with the same `lang` ids (the SARIF
      category and the artifact name are keyed on them).
    - The job runs if and only if the old job-level `if:` was true.
    - Each leg still carries `gate: 'true'`, so every step condition reads exactly as before.
    - The per-language report rows are untouched: they are built from discovery, not from legs.
    - No status function on the job `if:` (no always()): a failed discovery still skips CodeQL,
      exactly as the implicit success() did before.

    The matrix producer is found by the output name `codeql_matrix`, so this proof holds whether
    discovery runs in its own job or inside `plan` (step 3, G1).

FAILED-FIRST: before the change there is no `codeql_matrix` output and the matrix is static, so
this proof reports the matrix as not data-driven and exits 1.

EXIT  0 all hold   1 a violation   2 could not be checked (no bash)
"""
import io
import itertools
import json
import os
import re
import shutil
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, HERE)

import yaml  # noqa: E402

WF = '.github/workflows/reusable-security.yml'
FLAGS = ('python', 'node', 'go', 'dotnet', 'java', 'cpp', 'kotlin')

# THE REFERENCE: the static table as it stood at 82e95a7, transcribed once, as a function of the
# discovery flags. A leg ran (gate 'true') exactly when this said so.
LEGACY = (
    ('python', lambda f: f['python']),
    ('javascript-typescript', lambda f: f['node']),
    ('go', lambda f: f['go']),
    ('csharp', lambda f: f['dotnet']),
    ('java-kotlin', lambda f: f['java'] or f['kotlin']),
    ('c-cpp', lambda f: f['cpp']),
)


def legacy_legs(f):
    return [lang for lang, on in LEGACY if on(f)]


def legacy_job_runs(f):
    return any(f[k] for k in FLAGS)


def load():
    return yaml.safe_load(io.open(os.path.join(ROOT, WF), encoding='utf-8'))


def producer(doc):
    """(job id, step) that writes the codeql_matrix output, or (None, None)."""
    for jid, job in (doc.get('jobs') or {}).items():
        out = (job.get('outputs') or {}).get('codeql_matrix')
        if not out:
            continue
        m = re.search(r'steps\.([A-Za-z0-9_-]+)\.outputs\.codeql_matrix', str(out))
        if not m:
            return jid, None
        for s in job.get('steps') or []:
            if s.get('id') == m.group(1):
                return jid, s
        return jid, None
    return None, None


def run_step(bash, step, flags, step_ids):
    import _step_harness as h
    ctx = {}
    for k in FLAGS:
        for sid in step_ids:
            ctx['steps.%s.outputs.%s' % (sid, k)] = 'true' if flags[k] else 'false'
    ws = tempfile.mkdtemp(prefix='cqm-')
    try:
        r = h.run(bash, step, ctx, ws)
    finally:
        shutil.rmtree(ws, ignore_errors=True)
    return r


def check_combinations(bash, step, step_ids):
    """-> list of violations over all 2^7 discovery combinations."""
    bad = []
    for bits in itertools.product((False, True), repeat=len(FLAGS)):
        f = dict(zip(FLAGS, bits))
        r = run_step(bash, step, f, step_ids)
        if r['rc'] != 0:
            bad.append('%s: step exited %d: %s' % (f, r['rc'], r['log'][-300:]))
            continue
        raw = r['outputs'].get('codeql_matrix')
        try:
            legs = json.loads(raw)
        except (TypeError, ValueError):
            bad.append('%s: codeql_matrix is not JSON: %r' % (f, raw))
            continue
        if not isinstance(legs, list) or any(not isinstance(x, dict) for x in legs):
            bad.append('%s: codeql_matrix is not a list of objects: %r' % (f, raw))
            continue
        langs = [x.get('lang') for x in legs]
        if langs != legacy_legs(f):
            bad.append('%s: legs %s, the static table ran %s' % (f, langs, legacy_legs(f)))
        if any(x.get('gate') != 'true' for x in legs):
            bad.append('%s: a leg without gate "true": %r' % (f, legs))
        if (len(legs) > 0) != legacy_job_runs(f):
            bad.append('%s: job would %s, the static job-level if said %s'
                       % (f, 'run' if legs else 'not run', legacy_job_runs(f)))
    return bad


def main():
    import _step_harness as h
    bash, why = h.usable_bash()
    if not bash:
        print('UNKNOWN: no usable bash on this host (%s); the matrix step cannot be run.' % why)
        return 2
    doc = load()
    jobs = doc.get('jobs') or {}
    bad = []
    cq = jobs.get('codeql') or {}
    pj, pstep = producer(doc)
    if not pj:
        bad.append('no job publishes a codeql_matrix output: the CodeQL matrix is not built '
                   'from discovery')
    elif pstep is None:
        bad.append('job %s publishes codeql_matrix but not from a step of its own' % pj)

    inc = (((cq.get('strategy') or {}).get('matrix')) or {}).get('include')
    want_inc = '${{ fromJSON(needs.%s.outputs.codeql_matrix) }}' % pj
    if not isinstance(inc, str) or inc.strip() != want_inc:
        bad.append('codeql matrix.include is %r, want %s (one leg per discovered language)'
                   % (inc if isinstance(inc, str) else 'a static list', want_inc))
    cond = ' '.join(str(cq.get('if', '')).split())
    if pj:
        for guard in ("needs.%s.outputs.codeql_matrix != ''" % pj,
                      "needs.%s.outputs.codeql_matrix != '[]'" % pj):
            if guard not in cond:
                bad.append('codeql job if: lacks the guard %r (an empty or [] matrix must not '
                           'start a job, and fromJSON of empty would error): %r' % (guard, cond))
    if re.search(r'\b(always|failure|cancelled)\s*\(', cond):
        bad.append('codeql job if: carries a status function (%r): a failed discovery must still '
                   'skip CodeQL as the implicit success() did' % cond)
    if pj and pj not in (cq.get('needs') or []):
        bad.append('codeql does not need %s, so its matrix output is unreadable' % pj)

    # Each step's matrix.gate condition is preserved (every dynamic leg carries gate 'true').
    gated = [s.get('name') or s.get('uses') for s in cq.get('steps') or []
             if "matrix.gate == 'true'" in str(s.get('if', ''))]
    if len(gated) < 6:
        bad.append('only %d codeql steps still read matrix.gate; the step conditions were '
                   'rewritten rather than kept' % len(gated))

    if pstep is not None:
        sids = set()
        for v in (pstep.get('env') or {}).values():
            sids.update(re.findall(r'steps\.([A-Za-z0-9_-]+)\.outputs\.', str(v)))
        if not sids:
            bad.append('the matrix step reads no discovery output through env:')
        bad += check_combinations(bash, pstep, sorted(sids))

        # THE PROOF CAN FAIL: a mutant that forgets Kotlin-only code must be caught.
        mutant = dict(pstep)
        mutant['run'] = re.sub(r'\|\|\s*\[\s*"\$D_KOTLIN"\s*=\s*"?true"?\s*\]', '',
                               str(pstep.get('run') or ''))
        if mutant['run'] == pstep.get('run'):
            bad.append('mutation self-check: the Kotlin clause was not found to remove')
        elif not check_combinations(bash, mutant, sorted(sids)):
            bad.append('mutation self-check: dropping Kotlin went UNDETECTED; this proof is blind')

    # The report rows are per language and built from discovery, never from legs.
    text = io.open(os.path.join(ROOT, WF), encoding='utf-8').read()
    for lang, _ in LEGACY:
        if not re.search(r'cq_lang\s+%s\s' % re.escape(lang), text):
            bad.append('report row for codeql-%s is gone' % lang)

    for b in bad:
        print('VIOLATION: ' + b)
    if bad:
        print('FAIL: %d violation(s)' % len(bad))
        return 1
    print('PASS: CodeQL legs = discovered languages, for all %d discovery combinations; job runs '
          'iff the static if did; mutation (Kotlin dropped) detected' % 2 ** len(FLAGS))
    return 0


if __name__ == '__main__':
    sys.exit(main())

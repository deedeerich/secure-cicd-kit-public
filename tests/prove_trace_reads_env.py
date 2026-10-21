#!/usr/bin/env python3
"""The assurance tracer must see a hand-off wherever the workflow writes it -- including `env:`.

WHY THIS EXISTS

    scripts/trace_assurance_flow.py reads every step-output hand-off and convicts two defects:
    PHANTOM (a value read that nothing produces) and UNGUARDED (a value defaulted to something
    benign, `${X:-0}`, with no absence check). It read hand-offs only in a step's `run:` text.

    The kit's own injection rule (lint_injection.py; the 2026-10-16 env-transport fixes) moves
    every `${{ steps.x.outputs.y }}` and `${{ needs.j.outputs.y }}` out of `run:` and into an
    `env:` mapping, with `"$Y"` left in the script. Measured on the flagship at that point: 21 of
    its 35 step-output references sat in `env:`, and the tracer saw 14. So the better the
    workflows got at injection safety, the less of them this control could read -- and it kept
    printing "every traced handoff is guarded" over the part it could no longer see. needs.*
    references were matched by a pattern that nothing used.

WHAT IT PROVES (against a synthetic workflow, through the tracer as shipped)
    T1  an env-transported step output defaulted with ${X:-0} in run is UNGUARDED (step env)
    T2  the same through a JOB-level env mapping of a needs.* output is UNGUARDED
    T3  an env mapping reading an output its producer never emits is PHANTOM
    T4  an env mapping reading needs.<job>.outputs.<x> that the job does not declare is PHANTOM
    T5  a reference to a step id that does not exist in the job is PHANTOM, not "externally
        declared" (an id nobody wrote is not an observability limit)
    T6  CONTROL: a guarded env hand-off and a correct needs hand-off yield no finding, so the
        refusals above are caused by the defects and not by env mappings as such
    T7  every env hand-off is in the boundary map (the traced count includes them)
    T8  a `case "${X:-}"` whose only route for absence is a `*)` catch-all is still UNGUARDED
        (`*) pass` and `*) fail` look the same to a reader of text)
    T9  CONTROL: a case that gives the empty value its own arm (`''|...)`) is a guard
    T10 CONTROL: `[ -n "${X:-}" ] || exit 1` is a guard, as `-z` always was

EXIT 0 all hold, 1 any does not, 2 could not run
"""
import importlib.util
import os
import shutil
import sys
import tempfile

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
TRACER = os.path.join(ROOT, 'scripts', 'trace_assurance_flow.py')

FIXTURE = r'''name: fixture
on:
  push:
jobs:
  produce:
    runs-on: ubuntu-latest
    outputs:
      count: ${{ steps.p.outputs.count }}
    steps:
      - id: p
        run: echo "count=3" >> "$GITHUB_OUTPUT"
  consume:
    runs-on: ubuntu-latest
    needs: [produce]
    env:
      JOBCOUNT: ${{ needs.produce.outputs.count }}
    steps:
      - id: c
        run: echo "n=1" >> "$GITHUB_OUTPUT"
      - name: t1-step-env-default
        env:
          N: ${{ steps.c.outputs.n }}
        run: echo "found ${N:-0}"
      - name: t2-job-env-default
        run: echo "found ${JOBCOUNT:-0}"
      - name: t3-env-phantom
        env:
          M: ${{ steps.c.outputs.never_written }}
        run: echo "$M"
      - name: t4-needs-phantom
        env:
          G: ${{ needs.produce.outputs.not_declared }}
        run: echo "$G"
      - name: t5-no-such-step
        env:
          Z: ${{ steps.nobody.outputs.n }}
        run: echo "$Z"
      - name: t6-guarded-control
        env:
          K: ${{ steps.c.outputs.n }}
          L: ${{ needs.produce.outputs.count }}
        run: |
          if [ -z "$K" ]; then echo "COLLECTION_FAILED"; exit 1; fi
          echo "${K:-0} $L"
      - name: t8-case-catch-all-only
        env:
          P: ${{ steps.c.outputs.n }}
        run: |
          case "${P:-}" in
            BAD) exit 1 ;;
            *) echo pass ;;
          esac
      - name: t9-case-names-empty
        env:
          Q: ${{ steps.c.outputs.n }}
        run: |
          case "${Q:-}" in
            ''|BAD) exit 1 ;;
            *) echo pass ;;
          esac
      - name: t10-dash-n-guard
        env:
          R: ${{ steps.c.outputs.n }}
        run: |
          [ -n "${R:-}" ] || exit 1
          echo "${R:-0}"
'''


def main():
    spec = importlib.util.spec_from_file_location('trace_under_test', TRACER)
    mod = importlib.util.module_from_spec(spec)
    try:
        spec.loader.exec_module(mod)
    except SystemExit:
        print('UNKNOWN: the tracer could not be loaded (PyYAML?)')
        return 2
    d = tempfile.mkdtemp(prefix='trace-env-')
    try:
        with open(os.path.join(d, 'fixture.yml'), 'w', encoding='utf-8', newline='\n') as f:
            f.write(FIXTURE)
        mod.WF = d
        findings, edges, unverified = mod.analyse('fixture.yml')
    finally:
        shutil.rmtree(d, ignore_errors=True)

    def has(kind, where_prefix):
        return any(k == kind and str(w).startswith(where_prefix)
                   for k, _wf, _jn, w, _msg in findings)

    fails = []
    if not has('UNGUARDED', 't1-step-env-default'):
        fails.append('T1 ${N:-0} over an env-transported step output was not UNGUARDED')
    if not has('UNGUARDED', 't2-job-env-default'):
        fails.append('T2 ${JOBCOUNT:-0} over a job-env needs output was not UNGUARDED')
    if not has('PHANTOM', 't3-env-phantom'):
        fails.append('T3 an env mapping of an output nothing emits was not PHANTOM')
    if not has('PHANTOM', 't4-needs-phantom'):
        fails.append('T4 an env mapping of an undeclared needs output was not PHANTOM')
    if not has('PHANTOM', 't5-no-such-step'):
        fails.append('T5 a reference to a step id that does not exist was not PHANTOM')
    if any(str(w).startswith('t6-guarded-control') for _k, _wf, _jn, w, _m in findings):
        fails.append('T6 CONTROL: the guarded, correct hand-offs were convicted: %r'
                     % [f for f in findings if str(f[3]).startswith('t6')])
    if not has('UNGUARDED', 't8-case-catch-all-only'):
        fails.append('T8 a case whose only route for absence is `*)` was accepted as a guard')
    for t in ('t9-case-names-empty', 't10-dash-n-guard'):
        if any(str(w).startswith(t) for _k, _wf, _jn, w, _m in findings):
            fails.append('T9/T10 CONTROL: an explicit absence check (%s) was convicted' % t)
    if any(str(u[4]).startswith('t5-no-such-step') for u in unverified):
        fails.append('T5 the missing step id was filed as an observability limit')
    env_edges = [e for e in edges if '(env ' in str(e[4]) or str(e[4]).startswith('job env ')]
    if len(env_edges) < 7:
        fails.append('T7 only %d env hand-off(s) in the boundary map; the fixture has 7'
                     % len(env_edges))
    for f in fails:
        print('FAIL ' + f)
    if fails:
        return 1
    print('PASS: env-transported hand-offs (step and job level, steps.* and needs.*) are traced;')
    print('      PHANTOM and UNGUARDED convict through them, and a guarded hand-off is left alone.')
    return 0


if __name__ == '__main__':
    sys.exit(main())

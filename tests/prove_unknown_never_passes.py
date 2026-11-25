#!/usr/bin/env python3
"""A missing tool is UNKNOWN, never PASS, anywhere the kit runs its own checks; and every check this laptop
cannot run is exercised by a job "Self-test required" needs.

WHY THIS EXISTS (kit revision 2026-11-25, brief item 7): the local battery reports 13 checks UNKNOWN on the
owner's machine (actionlint, osv-scanner, gosec, cppcheck, syft, gitleaks/jq, docker, Linux-only steps). That is
honest only if (a) each of them runs where the tool is installed -- the hosted self-test -- under a job the
required check waits for, and (b) no runner of the kit's checks ever turns an exit 2 into a pass. The tree-clean
sweep printed "PASS ... none failed" over tests that exited 2, and read any exit other than 1 as passing.

  U1  every check line in a job "Self-test required" needs runs at the top level of a `bash -e` step: no
      continue-on-error, no `set +e`, no `|| true`-style swallow on the line
  U2  each of the 13 checks UNKNOWN locally on 2026-11-24 runs in such a job (the table is printed)
  U3  the battery: rc 0 PASS, rc 2 UNKNOWN, anything else FAIL; --strict turns UNKNOWN into exit 2
  U4  the tree-clean sweep names every test that exited 2 as UNKNOWN (never inside its PASS line) and fails
      on an exit that is neither 0, 1 nor 2
  MUTANTS (each must be caught): a swallowed check line; a check moved to a job the required check does not
      need; the battery reading rc 2 as PASS; the sweep folding rc 2 into its pass.

EXIT 0 all hold   1 any does not   2 PyYAML unavailable
"""
import copy
import io
import os
import re
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, HERE)
sys.path.insert(0, os.path.join(ROOT, 'tools'))
WF = os.path.join(ROOT, '.github', 'workflows', 'self-test.yml')
FAILS = []
# The 13 checks the battery reported UNKNOWN on the owner's machine (kit_fast_1124b, 2026-11-24).
LOCAL_UNKNOWN = [
    'tests/check_actionlint.py', 'tests/prove_kit_init.py --actionlint', 'tests/prove_malicious_deps_enforces.py',
    'tests/prove_gosec_modules.py', 'tests/prove_cppcheck_collects.py', 'tests/prove_pipeline_lint.py',
    'tests/prove_sast_cpp_runs.py', 'tests/prove_sbom_licence_verdict.py', 'tests/prove_secret_denominator.py',
    'tests/prove_build_push_round_trip.py', 'tests/prove_feed_mirror_gaps.py', 'tests/prove_sast_mobile_detects.py',
    'tests/prove_cpp_build_aware.py']
CHECK = re.compile(r'(?:^|\s)(?:python3?|bash)\s+(?:tests|scripts|tools)/\S+')
SWALLOW = re.compile(r'\|\|\s*(?:true|:|echo\b|exit 0)|;\s*true\b|;\s*exit 0\b')


def check(cond, label, detail=''):
    print('  %s  %s%s' % ('ok  ' if cond else 'FAIL', label, ('  -- %s' % detail) if (detail and not cond) else ''))
    if not cond:
        FAILS.append(label)


def required_jobs(wf):
    return set((wf['jobs'].get('required') or {}).get('needs') or [])


def swallow_problems(wf):
    probs = []
    for jid in sorted(required_jobs(wf)):
        j = wf['jobs'].get(jid) or {}
        if j.get('continue-on-error'):
            probs.append('%s: continue-on-error on the job' % jid)
        for s in j.get('steps') or []:
            r = s.get('run') or ''
            if s.get('continue-on-error') and CHECK.search(r):
                probs.append('%s / %s: continue-on-error on a check step' % (jid, s.get('name')))
            if re.search(r'^\s*set \+e\b', r, re.M) and CHECK.search(r):
                probs.append('%s / %s: set +e in a check step' % (jid, s.get('name')))
            for line in r.splitlines():
                if CHECK.search(line) and SWALLOW.search(line):
                    probs.append('%s / %s: a check line swallows its exit: %s' % (jid, s.get('name'), line.strip()[:120]))
    return probs


def coverage(wf):
    """-> {check: [(job id, job name, step name)]} over the jobs the required check needs."""
    req = required_jobs(wf)
    out = {}
    for c in LOCAL_UNKNOWN:
        out[c] = []
        for jid in sorted(req):
            j = wf['jobs'].get(jid) or {}
            for s in j.get('steps') or []:
                for line in (s.get('run') or '').splitlines():
                    if line.strip().startswith('#'):
                        continue
                    if re.search(r'(?:^|\s)python3?\s+' + re.escape(c) + r'(?:\s|$)', line):
                        out[c].append((jid, j.get('name') or jid, s.get('name') or ''))
    return out


def battery_problems(B):
    probs = []
    for rc, want in ((0, 'PASS'), (2, 'UNKNOWN'), (1, 'FAIL'), (3, 'FAIL'), ('timeout', 'FAIL')):
        if B.verdict_of(rc) != want:
            probs.append('battery reads rc %r as %s, not %s' % (rc, B.verdict_of(rc), want))
    src = io.open(os.path.join(ROOT, 'tools', 'battery.py'), encoding='utf-8').read()
    if 'if unknown and a.strict:' not in src or 'return 2' not in src.split('if unknown and a.strict:')[1][:40]:
        probs.append('battery --strict no longer turns UNKNOWN into exit 2')
    return probs


def sweep_problems(S):
    probs = []
    for rc, want in ((0, 'PASS'), (2, 'UNKNOWN'), (1, 'FAIL'), ('timeout', 'FAIL'), (3, 'FAIL'), (-9, 'FAIL')):
        got = S.verdict_of(rc)
        if got != want:
            probs.append('the sweep reads exit %r as %s, not %s' % (rc, got, want))
    line, code = S.summary([], [], ['prove_x.py'])
    if code != 0 or 'UNKNOWN' not in line or 'prove_x.py' not in line or line.startswith('PASS'):
        probs.append('the sweep\'s summary over an UNKNOWN test is %r (exit %r): it must name it and not say PASS'
                     % (line, code))
    line, code = S.summary([], [('prove_y.py', 3, '')], [])
    if code != 1:
        probs.append('the sweep passes over a test that exited 3')
    line, code = S.summary([], [], [])
    if code != 0 or not line.startswith('PASS'):
        probs.append('the sweep no longer passes a clean, all-zero run (%r)' % line)
    return probs


def main():
    try:
        import yaml
    except ImportError:
        print('UNKNOWN: PyYAML unavailable')
        return 2
    import battery as B
    import prove_tests_leave_tree_clean as S
    wf = yaml.safe_load(io.open(WF, encoding='utf-8'))
    print('A missing tool is UNKNOWN, never PASS; every locally-UNKNOWN check runs hosted under "Self-test required"')
    p = swallow_problems(wf)
    check(not p, 'U1 every check line in a required job runs under bash -e, nothing swallows its exit', p)
    cov = coverage(wf)
    for c, where in cov.items():
        print('       %-44s %s' % (c, '; '.join('%s ("%s")' % (j, n) for j, n, _ in where) or 'NOT RUN HOSTED'))
    check(all(cov.values()), 'U2 each of the 13 locally-UNKNOWN checks runs in a job "Self-test required" needs',
          [c for c, w in cov.items() if not w])
    p = battery_problems(B)
    check(not p, 'U3 the battery: 0 PASS, 2 UNKNOWN, anything else FAIL; --strict fails UNKNOWN', p)
    p = sweep_problems(S)
    check(not p, 'U4 the tree-clean sweep names an exit 2 as UNKNOWN and fails any exit that is not 0, 1 or 2', p)

    print('Mutants (each must be caught):')
    bad = copy.deepcopy(wf)
    for s in bad['jobs']['normalizer-drift']['steps']:
        if 'tests/prove_gosec_modules.py' in (s.get('run') or ''):
            s['run'] = s['run'].replace('python3 tests/prove_gosec_modules.py', 'python3 tests/prove_gosec_modules.py || true')
    check(bool(swallow_problems(bad)), 'M1 a swallowed check line is caught')
    bad = copy.deepcopy(wf)
    bad['jobs']['required']['needs'] = [n for n in bad['jobs']['required']['needs'] if n != 'platform-scanners']
    check(not all(coverage(bad).values()), 'M2 a check whose job the required check does not need is caught')

    class FakeB(object):
        verdict_of = staticmethod(lambda rc: 'PASS' if rc in (0, 2) else 'FAIL')
    check(bool(battery_problems(FakeB)), 'M3 the battery reading rc 2 as PASS is caught')

    class FakeS(object):
        verdict_of = staticmethod(lambda rc: 'FAIL' if rc in (1, 'timeout') else 'PASS')
        summary = staticmethod(lambda d, f, u: ('PASS: none failed', 1 if f else 0))
    check(bool(sweep_problems(FakeS)), 'M4 the sweep folding rc 2 into its pass is caught')
    if FAILS:
        print('FAIL: %d claim(s)' % len(FAILS))
        return 1
    print('PASS: no runner of the kit\'s checks reads a missing tool as a pass, and the 13 checks this machine '
          'cannot run each run hosted under "Self-test required"; four mutants caught.')
    return 0


if __name__ == '__main__':
    sys.exit(main())

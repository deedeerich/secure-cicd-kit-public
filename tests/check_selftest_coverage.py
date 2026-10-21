#!/usr/bin/env python3
"""The self-test's green means "these files are well-formed". It reads as "the kit works".

WHY THIS EXISTS

    `reusable-security.yml` sat 108 KB over GitHub's limit for six days. It started zero times.
    The self-test was green throughout.

    That was not a missing check. It was the DENOMINATOR. Counted on 2026-09-22:

        self-test steps that INVOKE a kit workflow :  0
        self-test steps that only READ or inspect  : 26

    Twelve workflows. The self-test parses all twelve and invokes exactly one
    (`workflow-policy-check.yml`, via `uses: ./`). Everything that does invoke the others --
    `consumer-path-test.yml`, `consumer-path-negative.yml`, `nvd-cve.yml` -- is dispatch-only or
    scheduled, so nothing exercises them on the push that breaks them.

    A GREEN THAT COVERS PARSING, READ AS A GREEN THAT COVERS RUNNING. Same shape as the CISO
    packet's `RESULT: READY`, which meant "the harness machinery works" and was read as "the
    packet is ready to produce findings". Both are a composite verdict stronger than its weakest
    axis, and this repository's governing rule forbids exactly that.

WHAT THIS DOES

    It does not add a thirteenth inspection. It makes the self-test STATE ITS OWN COVERAGE, so a
    green can never again be read as more than it is. Three classes, and they must not collapse:

        EXERCISED_ON_PUSH        invoked on the commit that could break it
        EXERCISED_ON_SCHEDULE    invoked weekly -- a break lands and waits for the cron
        EXERCISED_ON_DISPATCH    invoked only when a human asks
        EXERCISED_BY_NOTHING     nothing in this repository invokes it at all

    The third is not automatically a failure -- a workflow needing a real Azure target is honestly
    unexercisable here. But it must be ACCOUNTED FOR in the deferral registry. Unexercised and
    undeclared is the state that produced the six days.

WHAT IT STILL CANNOT TELL YOU

    That an exercised workflow does anything useful. Invocation is not detection. This measures
    reach, not depth, and says so in its own output rather than leaving a reader to assume.

EXIT
    0  every workflow is either exercised or has a dated deferral saying why not
    1  a workflow is exercised by nothing and nothing accounts for it
    2  could not be checked -- reported as UNKNOWN, never as PASS
"""
import argparse
import datetime
import glob
import io
import os
import re
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, HERE)

WORKFLOWS = os.path.join(ROOT, '.github', 'workflows', '*.yml')
# SCHEDULE IS NOT PUSH, and collapsing them hides the exact gap that cost six days: a weekly
# job does not catch a break introduced by the commit that caused it. The first draft of this
# file put them in one bucket and reported reusable-security.yml as exercised on push. It is not.
PUSH_TRIGGERS = ('push', 'pull_request', 'merge_group')
SCHEDULE_TRIGGERS = ('schedule',)
# Its OWN workflow_dispatch makes it human-runnable. The first draft only looked at who CALLS a
# workflow and reported a dispatchable one as reached by nothing, which is false and would have
# taught a reader to distrust the column.
DISPATCH_TRIGGERS = ('workflow_dispatch',)
CALL_RX = re.compile(r'uses:\s*\./(\.github/workflows/[A-Za-z0-9._-]+\.ya?ml)')


def triggers(doc):
    on = doc.get('on', doc.get(True)) or {}
    if isinstance(on, str):
        return {on}
    if isinstance(on, list):
        return set(on)
    return set(on) if isinstance(on, dict) else set()


def deferral_problem(d, today):
    """-> None when `d` is a complete deferral that has not expired on `today`, else why not."""
    if d is None:
        return 'no deferral'
    missing = [k for k in ('reason', 'owner', 'proves', 'expires') if not d.get(k)]
    if missing:
        return 'deferral incomplete (missing %s)' % ', '.join(missing)
    try:
        exp = datetime.date.fromisoformat(str(d['expires']))
    except ValueError:
        return 'deferral expiry unreadable (%r)' % d['expires']
    if exp < today:
        return 'deferral EXPIRED %s' % exp
    return None


# ── THE SECOND DENOMINATOR: PROOFS (completion ledger G-03 / L72, lane L-E, 2026-10-21) ──────────
#
# The census above counts WORKFLOWS. It said nothing about PROOFS, and nine existed that no workflow
# ran -- check_stage_phase, prove_identity_durability, prove_pin_check_sees_v_tags_and_action_refs,
# check_shell_continuations, check_context_current, build_pipeline_overlays --check,
# capability_inventory, prove_gate_reads_rung and scan_report.py --self-test. A proof nothing runs
# is a string: it was green the day it was written and nobody would see it turn red.
#
# So every tests/*.py (helpers start with `_`) must be RUN by a workflow or composite -- a
# `python... tests/<file>` line that is not a comment -- and every scripts/*.py that has a
# `--self-test` mode must have that mode run. Anything else needs an entry below: a RUNTIME tool
# (needs arguments or a live target by design; reason only), or an UNWIRED proof with a reason, an
# owner role and an expiry. An expired UNWIRED entry fails, as a deferral does.
RUNTIME_TOOLS = {
    'live_ticketing_run.py': 'runs against the owner\'s PERSONAL tracker with live credentials '
                             '(KDEC-004); never on CI by design. Its offline half is '
                             'prove_live_runner_offline.py, which self-test runs',
    # In the kit, consumer-path-test.yml runs it and the census counts it as run. A neutral export
    # withholds that workflow, so in a public copy it is a tool a consumer runs against their own
    # consumer-path results; its behaviour is proven by prove_expected_signals_honest.py.
    'verify_expected_signals.py': 'checks a consumer-path run\'s signals against an expected list; '
                                  'run by the kit\'s internal consumer-path workflow (withheld from '
                                  'exports) or by a consumer. prove_expected_signals_honest.py, '
                                  'which self-test runs, proves its behaviour',
}
UNWIRED = {
    'check_context_current.py': {
        'reason': 'fails on the trunk today: the .context record was reconciled against 9b18e49 and '
                  'HEAD is further ahead than its limit. Wiring it now turns self-test red on a '
                  'documentation lag, not a code defect; .context belongs to lane L-G',
        'owner': 'documentation lane (L-G)',
        'closes': 'L-G restates the context against the trunk; then wire it in self-test',
        'expires': '2026-11-15'},
    'prove_gate_reads_rung.py': {
        'reason': 'EXPECTED TO FAIL until the rung patch is applied (ledger S-01, wiring/'
                  'gate-rung.patch.md); a proof of an unbuilt wiring cannot be green',
        'owner': 'gate and policy lane (L-A)',
        'closes': 'L-A applies the rung patch; prove_gate_reads_rung reports 0 failures; wire it',
        'expires': '2026-12-31'},
}
# A line that RUNS it: not a comment (the lookahead anchors at the line start, so leading blanks
# cannot be backtracked into satisfying it), naming python, then the path.
INVOKE_RX = r'^(?![ \t]*#)[^\n]*\bpython3?\b[^\n]*\b%s%s'


def _hay(root):
    out = ''
    for p in sorted(glob.glob(os.path.join(root, '.github', 'workflows', '*.yml'))
                    + glob.glob(os.path.join(root, '.github', 'actions', '*', 'action.yml'))):
        out += io.open(p, encoding='utf-8', errors='replace').read() + '\n'
    return out


def proof_census(root, today, runtime=None, unwired=None):
    """-> (problems, counts). A problem is a proof no workflow runs that nothing accounts for, or an
    UNWIRED entry that has expired or is no longer needed."""
    runtime = RUNTIME_TOOLS if runtime is None else runtime
    unwired = UNWIRED if unwired is None else unwired
    hay = _hay(root)
    problems, counts = [], {'run': 0, 'runtime': 0, 'unwired': 0}
    for p in sorted(glob.glob(os.path.join(root, 'tests', '*.py'))):
        b = os.path.basename(p)
        if b.startswith('_'):
            continue
        ran = re.search(INVOKE_RX % (r'tests/', re.escape(b)), hay, re.M)
        if ran:
            counts['run'] += 1
            if b in unwired:
                problems.append('tests/%s is now run by a workflow; delete its UNWIRED entry' % b)
            continue
        if b in runtime:
            counts['runtime'] += 1
            continue
        if b in unwired:
            why = deferral_problem(dict(unwired[b], proves=unwired[b].get('closes')), today)
            if why:
                problems.append('tests/%s is run by no workflow and its UNWIRED entry is not in '
                                'force: %s' % (b, why))
            else:
                counts['unwired'] += 1
            continue
        problems.append('tests/%s exists and NO WORKFLOW RUNS IT. Wire it into self-test, or record '
                        'why not in UNWIRED (reason, owner, closes, expires).' % b)
    for p in sorted(glob.glob(os.path.join(root, 'scripts', '*.py'))):
        b = os.path.basename(p)
        src = io.open(p, encoding='utf-8', errors='replace').read()
        if "'--self-test'" not in src and '"--self-test"' not in src:
            continue
        if re.search(INVOKE_RX % (r'scripts/', re.escape(b) + r'[^\n]*--self-test'), hay, re.M):
            counts['run'] += 1
            continue
        if 'scripts/' + b in unwired:
            counts['unwired'] += 1
            continue
        problems.append('scripts/%s has a --self-test mode and NO WORKFLOW RUNS IT.' % b)
    return problems, counts


def parse_args(argv):
    ap = argparse.ArgumentParser(description='State what the self-test reaches, and refuse what '
                                             'nothing reaches without a dated decision.')
    ap.add_argument('--today', default=None,
                    help='ISO date override, so expiry behaviour is testable')
    ap.add_argument('--workflows-only', action='store_true',
                    help='check workflow reach only; skip the proof-wiring census')
    return ap.parse_args(argv)


def main():
    a = parse_args(sys.argv[1:])
    today = datetime.date.fromisoformat(a.today) if a.today else datetime.date.today()
    try:
        import yaml
    except ImportError:
        print('UNKNOWN: PyYAML unavailable. Failure to observe is not an observation.')
        return 2

    files = sorted(f for f in glob.glob(WORKFLOWS) if os.path.isfile(f))
    if not files:
        print('UNKNOWN: no workflows found. Nothing inspected is not nothing wrong.')
        return 2

    parsed, auto, sched, disp = {}, {}, {}, {}
    for f in files:
        rel = '.github/workflows/' + os.path.basename(f)
        try:
            doc = yaml.safe_load(io.open(f, encoding='utf-8', errors='replace')) or {}
        except Exception:
            doc = {}
        parsed[rel] = doc
        tg = triggers(doc)
        auto[rel] = bool(tg & set(PUSH_TRIGGERS))
        sched[rel] = bool(tg & set(SCHEDULE_TRIGGERS))
        disp[rel] = bool(tg & set(DISPATCH_TRIGGERS))

    # who calls whom
    callers = {rel: set() for rel in parsed}
    for f in files:
        rel = '.github/workflows/' + os.path.basename(f)
        text = io.open(f, encoding='utf-8', errors='replace').read()
        for target in CALL_RX.findall(text):
            if target in callers and target != rel:
                callers[target].add(rel)

    reached = {}
    for rel in parsed:
        by = callers[rel]
        if auto[rel]:
            reached[rel] = ('EXERCISED_ON_PUSH', 'own push/PR trigger')
        elif any(auto[c] for c in by):
            reached[rel] = ('EXERCISED_ON_PUSH', 'called by ' + ', '.join(sorted(c for c in by if auto[c])))
        elif sched[rel] or any(sched[c] for c in by):
            reached[rel] = ('EXERCISED_ON_SCHEDULE', 'scheduled only -- a break lands and waits')
        elif by:
            reached[rel] = ('EXERCISED_ON_DISPATCH', 'called only by ' + ', '.join(sorted(by)))
        elif disp[rel]:
            reached[rel] = ('EXERCISED_ON_DISPATCH', 'own workflow_dispatch -- human-runnable only')
        else:
            reached[rel] = ('EXERCISED_BY_NOTHING', 'nothing in this repository invokes it')

    # ACCOUNTED FOR MEANS A DATED DECISION, NOTHING ELSE (completion ledger L70). This used to
    # accept a capability whose registry state was `requires-integration-environment` with no
    # deferral at all, and any deferral whatever its expiry. "Needs infrastructure" is a reason to
    # defer, never an exemption (VALIDATION_DEBT rule 4), and an expired deferral is a decision
    # nobody renewed. Only a complete deferral that has not expired accounts for a workflow nothing
    # exercises; tests/prove_registry_hygiene.py H3 seeds both and the control.
    try:
        import reconcile_validation as R
        deferred_artifacts, refused = set(), {}
        for artifact, caps in R.CAPABILITY_REGISTRY.items():
            for c in caps:
                why = deferral_problem(R.DEFERRALS.get(c), today)
                if why is None:
                    deferred_artifacts.add(artifact)
                    break
                refused.setdefault(artifact, []).append('%s: %s' % (c, why))
    except Exception as e:
        print('UNKNOWN: could not read the validation registry (%s).' % e)
        return 2

    print('=== what the self-test actually reaches ===')
    order = {'EXERCISED_ON_PUSH': 0, 'EXERCISED_ON_SCHEDULE': 1,
             'EXERCISED_ON_DISPATCH': 2, 'EXERCISED_BY_NOTHING': 3}
    unaccounted = []
    counts = {k: 0 for k in order}
    for rel in sorted(parsed, key=lambda r: (order[reached[r][0]], r)):
        state, why = reached[rel]
        counts[state] += 1
        base = os.path.basename(rel)
        note = ''
        if state == 'EXERCISED_BY_NOTHING':
            if base in deferred_artifacts:
                note = '  [accounted for: dated deferral]'
            else:
                note = '  [UNACCOUNTED]'
                unaccounted.append(rel)
                for why in refused.get(base, []):
                    note += '\n%27s not accounted: %s' % ('', why)
        print('  %-22s %-46s %s%s' % (state, base, why[:46], note))

    print('\n  on push/PR: %d   on schedule only: %d   on dispatch only: %d   by nothing: %d'
          % (counts['EXERCISED_ON_PUSH'], counts['EXERCISED_ON_SCHEDULE'],
             counts['EXERCISED_ON_DISPATCH'], counts['EXERCISED_BY_NOTHING']))

    proof_problems = []
    if not a.workflows_only:
        proof_problems, pc = proof_census(ROOT, today)
        print('\n=== which proofs a workflow actually runs (G-03) ===')
        print('  run by a workflow: %d   runtime tools: %d   unwired under a dated entry: %d'
              % (pc['run'], pc['runtime'], pc['unwired']))
        for b, e in sorted(UNWIRED.items()):
            print('  UNWIRED %-40s until %s -- %s' % (b, e['expires'], e['owner']))

    print('\n' + '=' * 72)
    if unaccounted or proof_problems:
        for rel in unaccounted:
            print('FAIL: %s is invoked by nothing and no deferral accounts for it.' % rel)
        for p in proof_problems:
            print('FAIL: %s' % p)
        if unaccounted:
            print('\nUnexercised AND undeclared is the state that let a workflow sit 108 KB over')
            print('GitHub\'s limit for six days while every check reported green.')
        if proof_problems:
            print('\nA proof no workflow runs is a string: green the day it was written, and nobody')
            print('would see it turn red.')
        return 1

    print('PASS, AND SAY EXACTLY WHAT IT COVERS:')
    print('      %d of %d workflow(s) run on the commit that could break them.'
          % (counts['EXERCISED_ON_PUSH'], len(parsed)))
    print('      %d run ONLY ON A SCHEDULE -- a break lands and waits for the cron, which is'
          % counts['EXERCISED_ON_SCHEDULE'])
    print('      exactly what let a workflow sit 108 KB over the limit for six days.')
    print('      %d run only on dispatch; %d are exercised by nothing, each with a dated'
          % (counts['EXERCISED_ON_DISPATCH'], counts['EXERCISED_BY_NOTHING']))
    print('      deferral saying why.')
    print('')
    print('      THIS MEASURES REACH, NOT DEPTH. A workflow being invoked says nothing about')
    print('      whether it detects anything. And a green self-test covers the files it READ,')
    print('      not the workflows it RAN -- which is the distinction that cost six days.')
    return 0


if __name__ == '__main__':
    sys.exit(main())

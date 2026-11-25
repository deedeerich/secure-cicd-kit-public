#!/usr/bin/env python3
"""The report job must read the baseline ledger the PR-safe way, with every input as data (L45 wiring).

WHY THIS EXISTS

    baseline_ledger.read_for_evaluation needs the MERGE BASE of the run's commit and the default
    branch: grandfathering comes from there, removals from the tip. A shallow checkout has no merge
    base and the reader says so -- "a shallow clone looks exactly like this". The report job checked
    out at the default depth of 1, so every evaluation would have been BASELINE_UNAVAILABLE forever
    and nobody would have been told why. And the composite fetched the default branch with
    `--depth=1`, which makes even a full checkout shallow at that branch.

WHAT IT PROVES, statically, from the workflow and the composite as shipped

    history         the report job's checkout asks for fetch-depth 0, and the composite fetches the
                    default branch WITHOUT a depth limit
    reader called   the composite runs scripts/baseline_ledger.py, and every value on that command
                    line is a shell variable or a literal flag -- never a `${{ }}` expression and
                    never a caller-supplied literal; the variables it reads come from `env:`
    environment     the reusable workflow declares an `environment` input with NO environment
                    named by default, the report job passes it to the composite, and the composite
                    hands it to the reporter as `--environment`
    reporter fed    the composite passes --ledger, --environment and --rule-families to the
                    reporter, and the reporter's argparse accepts every flag the composite uses
    published       the composite and the report job expose identity_routing and baseline_state

EXIT  0 proven   1 a case failed (named)   2 could not be checked (UNKNOWN, never PASS)
"""
import io
import os
import re
import shlex
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
WF = os.path.join(ROOT, '.github', 'workflows', 'reusable-security.yml')
ACTION = os.path.join(ROOT, '.github', 'actions', 'scan-report', 'action.yml')
REPORTER = os.path.join(ROOT, 'scripts', 'scan_report.py')


def command_lines(run_text, needle):
    """-> every logical command line (continuations joined) containing `needle`."""
    joined = re.sub(r'\\\r?\n\s*', ' ', run_text or '')
    return [l.strip() for l in joined.splitlines() if needle in l and not l.strip().startswith('#')]


def main():
    try:
        import yaml
    except ImportError:
        print('UNKNOWN: PyYAML unavailable.')
        return 2
    wf = yaml.safe_load(io.open(WF, encoding='utf-8'))
    act = yaml.safe_load(io.open(ACTION, encoding='utf-8'))
    fails = []

    def check(cond, msg):
        if not cond:
            fails.append(msg)

    report = (wf.get('jobs') or {}).get('security-gate') or {}
    steps = report.get('steps') or []

    # ── history ──────────────────────────────────────────────────────────────────────
    checkouts = [s for s in steps if 'actions/checkout' in str(s.get('uses') or '')]
    check(checkouts, 'history: the report job has no checkout step')
    for s in checkouts:
        depth = str((s.get('with') or {}).get('fetch-depth', ''))
        check(depth == '0', 'history: the report checkout has fetch-depth %r, not 0. Without '
                            'history there is no merge base, and without a merge base the ledger '
                            'is BASELINE_UNAVAILABLE on every run' % (depth or 'default (1)'))
    astep = None
    for s in (act.get('runs') or {}).get('steps') or []:
        if 'baseline_ledger.py' in str(s.get('run') or ''):
            astep = s
    if astep is None:
        fails.append('reader called: no step in the scan-report composite runs baseline_ledger.py')
        return _report(fails)
    run = astep.get('run') or ''
    env = astep.get('env') or {}
    for line in command_lines(run, 'git fetch'):
        check('--depth' not in line, 'history: the composite fetches with a depth limit (%s); that '
                                     'makes the checkout shallow at the branch the merge base needs' % line)

    # ── reader called, inputs as data ────────────────────────────────────────────────
    calls = command_lines(run, 'baseline_ledger.py')
    check(len(calls) == 1, 'reader called: expected exactly one baseline_ledger.py invocation, got %d'
          % len(calls))
    for line in calls:
        check('${{' not in line, 'reader called: an expression is interpolated into the ledger read')
        # The command only: a trailing `|| true` is the step's failure isolation, not an input.
        toks = shlex.split(re.split(r'\s(?:\|\||&&)\s', line)[0], posix=True)
        values = [t for t in toks[1:] if not t.startswith('-') and not t.endswith('baseline_ledger.py')]
        for v in values:
            # a path flag's value must be a variable expansion, HEAD, or `.`
            ok = v.startswith('$') or '$' in v or v in ('HEAD', '.')
            check(ok, 'reader called: literal value %r on the ledger command line. Every input '
                      'reaches the reader through env: (%s)' % (v, line))
    check('${{' not in run, 'reader called: the composite step interpolates `${{ }}` into its script')
    for var, src in (('DEFAULT_BRANCH', 'inputs.default-branch'), ('ENVIRONMENT', 'inputs.environment')):
        check(src in str(env.get(var, '')), 'reader called: env %s is not mapped from %s (%r)'
              % (var, src, env.get(var)))

    # ── environment ──────────────────────────────────────────────────────────────────
    on = wf.get('on', wf.get(True)) or {}
    ins = ((on.get('workflow_call') or {}).get('inputs') or {})
    spec = ins.get('environment')
    check(isinstance(spec, dict), 'environment: reusable-security.yml declares no `environment` input')
    if isinstance(spec, dict):
        check(not str(spec.get('default') or '').strip(),
              'environment: the input names a default environment (%r). A finding grandfathered '
              'into an environment nobody named is grandfathered into the wrong one' % spec.get('default'))
    render = [s for s in steps if str(s.get('uses') or '').endswith('.github/actions/scan-report')]
    check(render, 'environment: the report job does not use the scan-report composite')
    if render:
        w = render[0].get('with') or {}
        check('inputs.environment' in str(w.get('environment', '')),
              'environment: the report job does not pass `environment: ${{ inputs.environment }}` '
              'to the composite (%r)' % w.get('environment'))
    check(isinstance((act.get('inputs') or {}).get('environment'), dict),
          'environment: the composite declares no `environment` input')

    # ── reporter fed ─────────────────────────────────────────────────────────────────
    # The composite names the reporter once (`reporter=.../scan_report.py`) and invokes it as
    # `"$reporter"`; the invocation is the line that passes --batch.
    rcalls = command_lines(run, '--batch')
    check(rcalls, 'reporter fed: no reporter invocation (a line passing --batch) found in the composite')
    flags_used = set()
    for line in rcalls:
        flags_used |= set(re.findall(r'(--[a-z-]+)', line))
    for flag in ('--ledger', '--environment', '--rule-families', '--batch', '--expect'):
        check(flag in flags_used, 'reporter fed: the composite does not pass %s to the reporter' % flag)
    src = io.open(REPORTER, encoding='utf-8').read()
    declared = set(re.findall(r"add_argument\('(--[a-z-]+)'", src))
    for flag in sorted(flags_used):
        check(flag in declared, 'reporter fed: the composite passes %s, which the reporter does not '
                                'declare' % flag)

    # ── published ────────────────────────────────────────────────────────────────────
    for key in ('identity_routing', 'baseline_state', 'findings'):
        check(key in (act.get('outputs') or {}), 'published: the composite exposes no %s output' % key)
        check(key in (report.get('outputs') or {}), 'published: the report job exposes no %s output' % key)
    return _report(fails)


def _report(fails):
    if fails:
        for f in fails:
            print('FAIL: ' + f)
        return 1
    print('PASS: the report job checks out history, the composite fetches without a depth limit, '
          'reads the ledger with every input as data, names the environment with no default, '
          'feeds the reporter --ledger/--environment/--rule-families, and publishes the identity '
          'routing and baseline state.')
    return 0


if __name__ == '__main__':
    sys.exit(main())

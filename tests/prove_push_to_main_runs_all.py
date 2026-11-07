#!/usr/bin/env python3
"""Every push to main runs the kit's whole CI, and every job that does not run there is named, with why.

WHY THIS EXISTS (owner, 2026-11-04: "With full running on push to main right?")

    A push to main is a release. Until 2026-11-04 the self-test skipped docs-only pushes
    (paths-ignore: docs/**, **/*.md) although Normalizer drift reads docs; validate-scanners ran on
    main only when one of six path globs matched; the consumer path test never ran on a push at all.
    "Full" means: every workflow that can run on a push to main does, with NO filter that can stop
    it, and every job inside runs -- except a job that cannot run on a push, which is skipped BY
    NAME with a reason, never silently. A workflow that cannot run on a push at all is named too.

WHAT IT PROVES
    P1  every workflow under .github/workflows/ that is not callable-only is either EXEMPT (named
        below, with its reason, and carrying no push trigger) or has `push: branches: [main]`
        with no paths, paths-ignore, branches-ignore or tags filter -- except PATH_SCOPED, named
        with its reason -- and keeps workflow_dispatch
    P2  every job of every such workflow is evaluated for a push to main (its `if:`, and its needs:
        a job whose need skipped is skipped unless it runs always()): the jobs that do NOT run are
        exactly PUSH_SKIPS, each with a reason -- no unnamed skip, no stale entry
    P3  self-test's push-skipped jobs are the ones the required verdict excuses by their own event
        condition (scripts/selftest_required.py EVENTGATED excludes push), and the plan skips
        nothing on a push
    P4  an OPT-IN workflow (the consumer path test, dispatch-only by default in a recipient's copy,
        owner ruling 2026-11-03) runs EVERY job on a push with its variable 'true', and NO job with
        it unset
    P5  the checks themselves can fail (seeded in copies): paths-ignore on self-test's push; the
        push trigger removed; a new pull_request-only job not named; a stale named skip; an
        opt-in job that loses its variable gate

USAGE  python3 tests/prove_push_to_main_runs_all.py
EXIT   0 all hold   1 any does not   2 PyYAML unavailable (UNKNOWN)
"""
import copy
import glob
import io
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, HERE)
sys.path.insert(0, os.path.join(ROOT, 'scripts'))

# Workflows that do not run on a push to main at all, and why. Each must carry no push trigger.
EXEMPT = {
    'consumer-path-negative.yml': 'EXPECTED TO END RED: the consumer path test DISPATCHES it and asserts '
                                  'it failed (assert-seeded-blocks); run on its own it would only add red',
    'live-deploy-acceptance.yml': 'deploys to a live Azure target named by its dispatch inputs (adapter, '
                                  'environment, digest); a push has none of them and must deploy nothing',
    'verify-azure-oidc.yml': 'asserts one Azure identity against resource groups given as dispatch inputs; '
                             'a push supplies no environment or scopes to assert',
    'nvd-cve.yml': 'the NVD pass needs a dispatch-chosen environment holding NVD_API_KEY; without it the '
                   'database update is rate-limited for 20-40 minutes',
    'external-findings.yml': 'pulls SonarQube / Aikido with secrets this repository does not hold; a push '
                             'run would only end SOURCE_NOT_CONFIGURED (owner 2026-11-06: dispatch only here)',
}
# Workflows whose push trigger is deliberately path-scoped, and why.
PATH_SCOPED = {
    'probe-scanner-corpora.yml': 'it MEASURES the IaC version ranges, a deterministic function of the '
                                 'registry, the corpus and the probe\'s own pinned scanners -- exactly its '
                                 'paths; any branch pushing those re-measures, and the weekly schedule '
                                 'catches upstream drift (tests/prove_iac_corpus.py C8)',
}
# Opt-in workflows: workflow -> the repository variable that turns its push runs on.
OPT_IN = {'consumer-path-test.yml': 'KIT_CONSUMER_PATH_ON_PUSH'}
# (workflow, job) -> why it does not run on a push to main.
PUSH_SKIPS = {
    ('self-test.yml', 'ticket-reconcile-refuses-pr'):
        'a hosted NEGATIVE control for a pull request: the reconcile guard must refuse a PR; a push '
        'runs exception-due-lists-on-push instead',
    ('self-test.yml', 'ledger-proposal-refuses-pr'):
        'a hosted NEGATIVE control for a pull request: the ledger proposal must never run from a PR',
    ('dependabot-triage.yml', 'triage'):
        'classifies ONE Dependabot pull request (pull_request_target); a push carries none -- the '
        'keep-current job beside it runs on the push and asks behind Dependabot PRs to rebase',
}

FAILS = []


def check(cond, label):
    print('  %s %s' % ('ok  ' if cond else 'FAIL', label))
    if not cond:
        FAILS.append(label)


def on_of(doc):
    return doc.get('on', doc.get(True)) or {}


def callable_only(on):
    return isinstance(on, dict) and set(on) == {'workflow_call'}


def push_skipped(doc, ctx):
    """-> {job: reason-or-None for the jobs that do NOT run on this push}. Evaluates `if:` with the
    consumer-path proof's evaluator (anything it cannot read raises), then needs."""
    from prove_consumer_path_preflight import eval_if
    jobs = doc.get('jobs') or {}
    runs = {}

    def run(j):
        if j in runs:
            return runs[j]
        runs[j] = None
        job = jobs[j] or {}
        cond = job.get('if')
        ok = eval_if(cond, ctx)
        needs = job.get('needs') or []
        needs = [needs] if isinstance(needs, str) else needs
        always = 'always()' in str(cond or '')
        if ok and not always and not all(run(n) for n in needs):
            ok = False
        runs[j] = bool(ok)
        return runs[j]
    for j in jobs:
        run(j)
    return {j for j, r in runs.items() if not r}


def ctx_push(var_on=None):
    import selftest_required as sr
    plan = sr.plan('push', ['docs/a.md'])
    ctx = {'github.event_name': 'push', 'github.ref': 'refs/heads/main'}
    for job, skip in plan.items():
        ctx['needs.contract.outputs.skip_%s' % job.replace('-', '_')] = 'true' if skip else 'false'
    if var_on:
        ctx['vars.' + var_on] = 'true'
    return ctx, plan


def evaluate(wfdir):
    """-> (problems, {(wf, job): ...} skipped) over the workflows in wfdir."""
    import yaml
    problems, skipped = [], set()
    seen = set()
    for path in sorted(glob.glob(os.path.join(wfdir, '*.yml'))):
        name = os.path.basename(path)
        doc = yaml.safe_load(io.open(path, encoding='utf-8')) or {}
        on = on_of(doc)
        if callable_only(on):
            continue
        seen.add(name)
        push = on.get('push', 'absent') if isinstance(on, dict) else 'absent'
        if name in EXEMPT:
            if push != 'absent':
                problems.append('P1 %s is EXEMPT but has a push trigger: say which it is' % name)
            continue
        if push == 'absent' or not isinstance(push, dict):
            problems.append('P1 %s does not run on a push to main (no push trigger, and not EXEMPT)' % name)
            continue
        filters = set(push) - {'branches'}
        if name in PATH_SCOPED:
            if 'paths' not in push:
                problems.append('P1 %s is PATH_SCOPED but its push has no paths: say which it is' % name)
        else:
            if push.get('branches') != ['main']:
                problems.append('P1 %s: push is not `branches: [main]` (%r)' % (name, push.get('branches')))
            if filters:
                problems.append('P1 %s: the push to main carries %s, which can stop a push to main from '
                                'running it' % (name, sorted(filters)))
        if 'workflow_dispatch' not in on:
            problems.append('P1 %s lost workflow_dispatch' % name)
        var = OPT_IN.get(name)
        try:
            ctx, plan = ctx_push(var)
            sk = push_skipped(doc, ctx)
            if var:
                ctx_off, _ = ctx_push(None)
                off = push_skipped(doc, ctx_off)
                if off != set(doc.get('jobs') or {}):
                    problems.append('P4 %s: with %s unset a push still runs %s (dispatch-only by default '
                                    'in a recipient\'s copy)' % (name, var, sorted(set(doc['jobs']) - off)))
        except (ValueError, AssertionError, IndexError) as e:
            problems.append('P2 %s: a job `if:` could not be read (%s)' % (name, e))
            continue
        for j in sk:
            skipped.add((name, j))
        if name == 'self-test.yml' and any(plan.values()):
            problems.append('P3 the self-test plan skips %s on a push' % [k for k, v in plan.items() if v])
    for (wf, j) in sorted(skipped - set(PUSH_SKIPS)):
        problems.append('P2 %s / %s does not run on a push to main and is not named in PUSH_SKIPS' % (wf, j))
    for (wf, j) in sorted(set(PUSH_SKIPS) - skipped):
        if wf in seen:
            problems.append('P2 %s / %s is named in PUSH_SKIPS but runs on a push: a stale entry' % (wf, j))
    for wf in sorted(set(EXEMPT) | set(PATH_SCOPED)):
        if not os.path.isfile(os.path.join(wfdir, wf)):
            problems.append('P1 %s is named but does not exist: a stale entry' % wf)
    return problems, skipped


def p3():
    import selftest_required as sr
    for (wf, j) in PUSH_SKIPS:
        if wf != 'self-test.yml':
            continue
        cond = sr.EVENTGATED.get(j)
        check(cond is not None and sr.runs_on(cond, 'push') is False,
              'P3 self-test / %s: the verdict excuses its push skip by its own event condition (%r)' % (j, cond))


def mutant(label, edit):
    import yaml
    import tempfile
    import shutil
    tmp = tempfile.mkdtemp(prefix='push-main-')
    try:
        wfdir = os.path.join(tmp, 'wf')
        shutil.copytree(os.path.join(ROOT, '.github', 'workflows'), wfdir)
        edit(wfdir, yaml)
        probs, _ = evaluate(wfdir)
        check(bool(probs), 'P5 refused: %s (%s)' % (label, probs[0] if probs else 'NOT refused'))
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


def rewrite(wfdir, yaml, name, fn):
    p = os.path.join(wfdir, name)
    d = yaml.safe_load(io.open(p, encoding='utf-8'))
    fn(d)
    io.open(p, 'w', encoding='utf-8').write(yaml.safe_dump(d, sort_keys=False))


def main():
    try:
        import yaml  # noqa: F401
    except ImportError:
        print('UNKNOWN: PyYAML unavailable')
        return 2
    for k, why in list(EXEMPT.items()) + list(PATH_SCOPED.items()) + [(k, v) for k, v in PUSH_SKIPS.items()]:
        check(len(str(why)) > 30, 'every named exception carries its reason: %s' % (k,))
    problems, skipped = evaluate(os.path.join(ROOT, '.github', 'workflows'))
    for p in problems:
        check(False, p)
    if not problems:
        check(True, 'P1/P2/P4 every workflow runs on a push to main or is named; %d job(s) skipped there, '
                    'each named: %s' % (len(skipped), ', '.join('%s/%s' % x for x in sorted(skipped))))
    p3()

    def on_get(d):
        return d.get('on', d.get(True))
    mutant('paths-ignore on self-test\'s push',
           lambda w, y: rewrite(w, y, 'self-test.yml',
                                lambda d: on_get(d)['push'].update({'paths-ignore': ['docs/**']})))
    mutant('self-test\'s push trigger removed',
           lambda w, y: rewrite(w, y, 'self-test.yml', lambda d: on_get(d).pop('push')))
    mutant('a new pull_request-only job, not named',
           lambda w, y: rewrite(w, y, 'self-test.yml', lambda d: d['jobs'].update(
               {'pr-only-new': {'if': "github.event_name == 'pull_request'", 'runs-on': 'ubuntu-latest',
                                'steps': [{'run': 'true'}]}})))
    mutant('a stale named skip (the PR-only control now runs on push)',
           lambda w, y: rewrite(w, y, 'self-test.yml',
                                lambda d: d['jobs']['ticket-reconcile-refuses-pr'].pop('if')))

    def ungate(d):
        d['jobs']['clean']['if'] = "github.event_name != 'schedule' || vars.KIT_CONSUMER_PATH_SCHEDULE == 'true'"
    if os.path.isfile(os.path.join(ROOT, '.github', 'workflows', 'consumer-path-test.yml')):
        mutant('an opt-in job loses its push variable gate',
               lambda w, y: rewrite(w, y, 'consumer-path-test.yml', ungate))
    else:
        # The neutral export withholds the consumer path test (scripts/export_for_adoption.py): in
        # that copy there is no opt-in workflow to seed, and nothing here passes for it.
        print('  n/a  P5 the opt-in mutant: consumer-path-test.yml is not in this copy')
    mutant('validate-scanners\' push to main gets a paths filter back',
           lambda w, y: rewrite(w, y, 'validate-scanners.yml',
                                lambda d: on_get(d)['push'].update({'paths': ['tests/**']})))
    if FAILS:
        print('FAIL: %d check(s) -- a push to main does not run everything, or skips something unnamed.' % len(FAILS))
        return 1
    print('PASS: every push to main runs the whole CI; each job or workflow that does not is named with why.')
    return 0


if __name__ == '__main__':
    sys.exit(main())

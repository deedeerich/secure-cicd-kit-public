#!/usr/bin/env python3
"""Self-test's required check: never green by skipping, never pending by path filter.

WHY THIS EXISTS (owner ruling 2026-10-27 on the cost redesign's step 8, KDEC-033)

    Skipping a required job with a job-level `if:` reports SUCCESS: GitHub counts a skipped job as
    passing a required status check. "Skipped = green" -- a pull request whose required job never
    ran merges as if it had passed. And a required workflow filtered by `paths:` never starts, so
    its check stays PENDING forever. Both turn a cost saving into a hole in the gate.

    So the kit's own CI keeps ONE cheap required check that runs on every pull request and every
    event, and skips heavy work only where that skip is PROVEN safe:

      plan     (the `contract` job, always runs, no `if:`) lists the files a pull request changes
               and, per skippable job, says skip only when EVERY changed path is inside that job's
               proven-safe set. Any doubt -- not a pull request, no diff, an empty diff, an
               unreadable list -- skips nothing.
      verdict  (the `required` job, `if: always()`, the ONE check branch protection requires)
               fails unless every other job SUCCEEDED, or was skipped for a reason it can name: the
               plan skipped it, or its own `if:` excludes this event. A skip with no reason, a
               failure, a cancellation, or a plan that did not finish is a red required check.

    PROVEN SAFE is not a judgement. A job's safe set is a glob list here; tests/prove_selftest_required.py
    reads every script the job runs (and the kit modules those import) and fails if any of them
    reads a path in that set. normalizer-drift reads docs (check_doc_currency, check_export_safety
    and more), so it has NO safe set and is never skipped.

EXIT  plan / verdict: 0 decided (verdict: passed)   1 verdict failed   2 could not decide
"""
import argparse
import fnmatch
import io
import json
import os
import sys

# job -> globs. The job may be skipped on a pull request only when EVERY changed path matches one.
# Each entry is held to its proof by tests/prove_selftest_required.py (no script it runs reads them).
SKIPPABLE = {
    # docs/** only. A root README.md or a .md under .github/ is not in the set: a string scan can prove
    # that no module of the job names docs/, not that none of them reads some Markdown file.
    'platform-scanners': ['docs/**'],
}

# job -> the job-level `if:` it carries on github.event_name, verbatim. A job skipped on an event its
# own condition excludes is skipped BY DESIGN. tests/prove_selftest_required.py holds this table equal
# to the workflow, so a new event-gated job cannot be skipped silently.
EVENTGATED = {
    'ticket-reconcile-refuses-pr': "github.event_name == 'pull_request'",
    'ticket-reference-not-assessed-off-pr': "github.event_name != 'pull_request'",
    'exception-due-lists-on-push': "github.event_name == 'push'",
    'ticket-reference-outcome-asserted': "github.event_name != 'pull_request'",
    'ledger-proposal-refuses-pr': "github.event_name == 'pull_request'",
}

PLANJOB, VERDICTJOB = 'contract', 'required'


def runs_on(cond, event):
    """Evaluate one `github.event_name == / != 'x'` condition. None = cannot evaluate."""
    c = ' '.join(str(cond).split())
    for op in ('==', '!='):
        pre = 'github.event_name %s ' % op
        if c.startswith(pre) and c.endswith("'") and c[len(pre)] == "'":
            want = c[len(pre) + 1:-1]
            return (event == want) if op == '==' else (event != want)
    return None


def matches(path, globs):
    p = path.replace(chr(92), '/')
    while p.startswith('./'):
        p = p[2:]
    for g in globs:
        if fnmatch.fnmatchcase(p, g):
            return True
        if g.startswith('**/') and fnmatch.fnmatchcase(p, g[3:]):
            return True
        if g.endswith('/**') and p.startswith(g[:-2]):
            return True
    return False


def plan(event, changed):
    """-> {job: True if it may be skipped}. Fail-safe: anything uncertain skips nothing."""
    out = {j: False for j in SKIPPABLE}
    if event != 'pull_request' or changed is None:
        return out
    files = [f for f in changed if f.strip()]
    if not files:
        return out
    for job, globs in SKIPPABLE.items():
        out[job] = all(matches(f, globs) for f in files)
    return out


def verdict(needs, event, skips):
    """-> list of problems. `needs` is toJSON(needs): {job: {result, outputs}}."""
    bad = []
    if PLANJOB not in needs:
        bad.append('the plan job %s is not among the verdict\'s needs' % PLANJOB)
    elif needs[PLANJOB].get('result') != 'success':
        bad.append('the plan job %s was %r: nothing it decided can be trusted'
                   % (PLANJOB, needs[PLANJOB].get('result')))
    for job, v in sorted(needs.items()):
        r = (v or {}).get('result')
        if r == 'success':
            continue
        if r == 'skipped':
            if job in EVENTGATED and runs_on(EVENTGATED[job], event) is False:
                continue
            if skips.get(job) is True and job in SKIPPABLE:
                continue
            bad.append('%s was SKIPPED with no proven reason (not excluded by its own event '
                       'condition, not skipped by the plan): skipped is never green' % job)
            continue
        bad.append('%s: %s' % (job, r))
    return bad


def emit(path, **kv):
    with io.open(path, 'a', encoding='utf-8') as fh:
        for k, v in kv.items():
            fh.write('%s=%s\n' % (k, v))


def self_test():
    fails = []

    def expect(label, cond):
        if not cond:
            fails.append(label)
    expect('docs-only PR skips platform-scanners', plan('pull_request', ['docs/a.md', 'docs/b/c.md'])['platform-scanners'])
    expect('a root README is not in the safe set', not plan('pull_request', ['README.md'])['platform-scanners'])
    expect('a script change skips nothing', not plan('pull_request', ['docs/a.md', 'scripts/x.py'])['platform-scanners'])
    expect('a workflow change is not a doc', not plan('pull_request', ['.github/workflows/x.yml'])['platform-scanners'])
    expect('a push skips nothing', not plan('push', ['docs/a.md'])['platform-scanners'])
    expect('an empty diff skips nothing', not plan('pull_request', [])['platform-scanners'])
    expect('an unreadable diff skips nothing', not plan('pull_request', None)['platform-scanners'])
    ok = {'contract': {'result': 'success'}, 'normalizer-drift': {'result': 'success'},
          'platform-scanners': {'result': 'success'}, 'ticket-reconcile-refuses-pr': {'result': 'skipped'}}
    pr = dict(ok, **{'ticket-reconcile-refuses-pr': {'result': 'success'}})
    expect('all green + event-excluded skip passes', not verdict(ok, 'push', {}))
    m = dict(pr, **{'platform-scanners': {'result': 'skipped'}})
    expect('an unplanned skip fails', verdict(m, 'pull_request', {'platform-scanners': False}))
    expect('a planned skip passes', not verdict(m, 'pull_request', {'platform-scanners': True}))
    m = dict(pr, **{'normalizer-drift': {'result': 'skipped'}})
    expect('a non-skippable job skipped fails even if the plan says so',
           verdict(m, 'pull_request', {'normalizer-drift': True}))
    expect('an event-gated job skipped on its own event fails',
           verdict(ok, 'pull_request', {}))
    expect('a failure fails', verdict(dict(ok, **{'normalizer-drift': {'result': 'failure'}}), 'push', {}))
    expect('a cancellation fails', verdict(dict(ok, **{'normalizer-drift': {'result': 'cancelled'}}), 'push', {}))
    expect('a failed plan fails', verdict(dict(ok, contract={'result': 'failure'}), 'push', {}))
    if fails:
        print('SELF-TEST FAILED: ' + '; '.join(fails))
        return 1
    print('self-test ok: 15 cases (plan fail-safe, skipped-is-never-green, event gates, failures)')
    return 0


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.split('\n')[0])
    ap.add_argument('--plan', action='store_true')
    ap.add_argument('--verdict', action='store_true')
    ap.add_argument('--event', default=os.environ.get('GITHUB_EVENT_NAME', ''))
    ap.add_argument('--changed-files', help='file with one changed path per line; absent = unknown')
    ap.add_argument('--github-output')
    ap.add_argument('--json', action='store_true', help='--plan: print only the decision as compact JSON')
    ap.add_argument('--self-test', action='store_true')
    a = ap.parse_args(argv)
    if a.self_test:
        return self_test()
    if a.plan:
        changed = None
        if a.changed_files and os.path.isfile(a.changed_files):
            changed = io.open(a.changed_files, encoding='utf-8').read().splitlines()
        p = plan(a.event, changed)
        if a.json:
            print(json.dumps(p, sort_keys=True, separators=(',', ':')))
            return 0
        for job, skip in sorted(p.items()):
            print('%-20s %s' % (job, 'SKIP (every changed path is proven safe for it)' if skip else 'RUN'))
        if a.github_output:
            emit(a.github_output, skips=json.dumps(p, sort_keys=True, separators=(',', ':')),
                 **{'skip_%s' % j.replace('-', '_'): str(s).lower() for j, s in p.items()})
        return 0
    if a.verdict:
        try:
            needs = json.loads(os.environ.get('NEEDS_JSON') or '')
            skips = json.loads(os.environ.get('PLAN_SKIPS') or '{}')
        except ValueError as e:
            print('::error title=Self-test verdict could not decide::%s' % e)
            return 2
        bad = verdict(needs, a.event, skips)
        for b in bad:
            print('::error title=Self-test required check::%s' % b)
        if bad:
            return 1
        print('self-test required: every job succeeded or was skipped for a proven reason (%d jobs)' % len(needs))
        return 0
    ap.print_help()
    return 2


if __name__ == '__main__':
    sys.exit(main())

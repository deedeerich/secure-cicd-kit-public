#!/usr/bin/env python3
"""KREQ-632 (FW section 12, owner ruling O-26 option (b), accepted 2026-11-13 in KDEC-052): the negative control
runs only for a reader.

WHY
    `.github/workflows/consumer-path-negative.yml` is the expensive suite that MUST end red. It was dispatchable
    by hand, so it could run with nothing asserting on its result (FW section 12: on 2026-08-18 an operator
    dispatched it beside `consumer-path-test.yml`, which dispatches it itself: a full duplicate invocation that
    no one graded). Option (b): keep it a separate workflow (GitHub forbids `continue-on-error` on a job that
    calls a reusable workflow, so an expected failure cannot be absorbed inline), but not independently
    runnable.

WHY THE `workflow_dispatch` TRIGGER STAYS
    Its readers start it through the dispatch API (`gh workflow run`): `consumer-path-test.yml` (the
    `kit dispatch correlated` block) and `scripts/measure_cost.py dispatch`. GitHub refuses a dispatch of a
    workflow that has no `workflow_dispatch` trigger, and the other API triggers (`repository_dispatch`,
    `workflow_run`) run only on the default branch, which would stop the contract test on every other branch.
    A `workflow_call` would make the reader's own run red, because this suite ends red by design. So the
    trigger stays and this check is the FIRST job: every other job needs it, and a run with no reader stops
    here, after about ten seconds, before any scanner starts.

THE RULE
    A run proceeds only when its correlation id names its reader:
      <run id>-<attempt>-<scope>-<epoch>       consumer-path-test.yml: the run id must be a run of
                                               .github/workflows/consumer-path-test.yml in THIS repository
                                               that has not completed, and <scope> must be this run's scope
      cost-<class>-<phase>-<n>-<epoch>         scripts/measure_cost.py: class monorepo -> scope full,
                                               class iac-heavy -> scope iac; phase before or after
    Anything else (the empty id of a hand dispatch above all) is refused NOT_ESTABLISHED, by name.
    Residual (recorded in the KREQ-632 decision entry): the cost form cannot be confirmed from inside the run; a person who types a
    cost id by hand gets a run, which the cost tool's manifest does not list.

EXIT  0 a reader is named   1 refused (the reason is printed)   2 usage
"""
import argparse
import json
import os
import re
import sys
import urllib.request

reader_workflow = '.github/workflows/consumer-path-test.yml'
CONTRACT_ID = re.compile(r'^([0-9]+)-([0-9]+)-(full|php|iac)-[0-9]+$')
COST_ID = re.compile(r'^cost-(monorepo|iac-heavy)-(before|after)-[0-9]+-[0-9]+$')
COST_CLASS_SCOPE = {'monorepo': 'full', 'iac-heavy': 'iac'}
SCOPES = ('full', 'php', 'iac')


def judge(cid, scope, repo, fetch_run):
    """-> (proceed, reason). `fetch_run(run_id)` returns the run's API document, or raises."""
    cid = (cid or '').strip()
    if scope not in SCOPES:
        return False, 'NOT_ESTABLISHED: scope %r is not one of %s' % (scope, ', '.join(SCOPES))
    if not cid:
        return False, ('NOT_ESTABLISHED: no correlation id, so nothing reads this run (a hand dispatch). The '
                       'negative control runs only when %s or scripts/measure_cost.py dispatches it (KREQ-632)'
                       % os.path.basename(reader_workflow))
    m = COST_ID.match(cid)
    if m:
        want = COST_CLASS_SCOPE[m.group(1)]
        if want != scope:
            return False, ('NOT_ESTABLISHED: cost class %s measures scope %s, not %s' % (m.group(1), want, scope))
        return True, 'reader: scripts/measure_cost.py (class %s, phase %s)' % (m.group(1), m.group(2))
    m = CONTRACT_ID.match(cid)
    if not m:
        return False, 'NOT_ESTABLISHED: correlation id %r names no reader' % cid
    if m.group(3) != scope:
        return False, 'NOT_ESTABLISHED: the id was made for scope %s; this run is scope %s' % (m.group(3), scope)
    try:
        doc = fetch_run(m.group(1))
    except Exception as exc:  # noqa: BLE001 -- an unread caller is never a confirmed one
        return False, 'NOT_ESTABLISHED: run %s could not be read (%s)' % (m.group(1), type(exc).__name__)
    doc = doc if isinstance(doc, dict) else {}
    path = str(doc.get('path') or '').split('@', 1)[0]
    owner = str((doc.get('repository') or {}).get('full_name') or '').lower()
    if path != reader_workflow:
        return False, 'NOT_ESTABLISHED: run %s is %r, not %s' % (m.group(1), path or 'unknown', reader_workflow)
    if owner != (repo or '').lower():
        return False, 'NOT_ESTABLISHED: run %s belongs to %r, not %r' % (m.group(1), owner, repo)
    if doc.get('status') == 'completed':
        return False, 'NOT_ESTABLISHED: run %s has completed, so nothing is waiting to read this one' % m.group(1)
    return True, 'reader: %s run %s (in progress)' % (reader_workflow, m.group(1))


def api_fetch(repo):
    """The run document from the API host that issued the token (KDEC-027: GITHUB_API_URL, the run's own
    host; the public host only when the variable is unset, i.e. outside a runner)."""
    base = os.environ.get('GITHUB_API_URL', 'https://api.github.com')
    token = os.environ.get('GITHUB_TOKEN') or ''

    def fetch(run_id):
        req = urllib.request.Request('%s/repos/%s/actions/runs/%s' % (base.rstrip('/'), repo, run_id),
                                     headers={'Authorization': 'Bearer ' + token,
                                              'Accept': 'application/vnd.github+json'})
        with urllib.request.urlopen(req, timeout=20) as r:  # noqa: S310 -- the run's own API host
            return json.loads(r.read().decode('utf-8'))
    return fetch


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument('--correlation-id', default='')
    ap.add_argument('--scope', required=True)
    # OWNER/REPO for the REST path, read from the run itself (not a gh -R argument, which needs a host).
    ap.add_argument('--repo', default=os.environ.get('GITHUB_REPOSITORY', ''))
    a = ap.parse_args(argv)
    ok, why = judge(a.correlation_id, a.scope, a.repo, api_fetch(a.repo))
    if ok:
        print('Negative control: %s' % why)
        return 0
    print('::error title=NOT_ESTABLISHED::%s' % why.split(': ', 1)[-1])
    print('Refused: %s' % why)
    return 1


if __name__ == '__main__':
    sys.exit(main())

#!/usr/bin/env python3
"""A caller of a reusable workflow must grant every permission any of its jobs requests.

WHY THIS EXISTS

    GitHub caps a called workflow's permissions at what the CALLER grants, and when a called job asks
    for more it refuses the whole run before any job starts (`startup_failure`, no log, no reason in
    the API). The first hosted milestone run (2026-10-15) hit it: the consumer-path test grants
    `contents: read, security-events: write`, while the flagship's `codeql` job asks for
    `actions: read` and its new `propose-ledger` job asked for `contents: write, pull-requests: write`.
    Every local proof was green; nothing local models the permission ceiling. This check does.

    It also enforces a design consequence: anything a reusable workflow requests, EVERY consumer must
    grant on EVERY run. A write scope inside the security scan therefore means every pull request's scan
    runs with write access -- which is why the ledger proposal moved to its own reusable workflow.

RULE
    For every job in this repository's workflows that calls a local reusable workflow
    (`./.github/workflows/<file>` or `$/.github/workflows/<file>`): the caller job's permissions (or
    the caller workflow's top-level permissions when the job declares none) must grant, for every
    scope, at least the level each called job requests (its own `permissions:`, else the called
    workflow's top-level ones). write > read > none.

EXIT
    0  every caller grants enough
    1  a caller grants less than a called job requests (named)
    2  could not be checked -- UNKNOWN, never PASS
"""
import glob
import io
import os
import re
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
LEVEL = {'none': 0, 'read': 1, 'write': 2}
# ./ and $/ references, and owner/repo/.github/workflows/<file>@<ref> references whose <file> exists
# in THIS repository (the starter template calls the kit that way, with a placeholder owner).
LOCAL = re.compile(r'^(?:\./|\$/|[^/@\s]+/[^/@\s]+/)(\.github/workflows/[^@\s]+\.ya?ml)(?:@\S+)?$')


def perms(p):
    """-> {scope: level} for a permissions value; None when undeclared."""
    if p is None:
        return None
    if isinstance(p, str):
        lvl = {'read-all': 1, 'write-all': 2}.get(p, 0)
        return {'*': lvl}
    return {k: LEVEL.get(str(v), 0) for k, v in (p or {}).items()}


def grants(granted, scope):
    if granted is None:
        return None
    if '*' in granted:
        return granted['*']
    return granted.get(scope, 0)


def requested(doc):
    """-> {job: {scope: level}} for every job of a reusable workflow."""
    top = perms(doc.get('permissions'))
    out = {}
    for name, job in (doc.get('jobs') or {}).items():
        out[name] = perms((job or {}).get('permissions')) or top or {}
    return out


def check(files, load):
    bad = []
    for f in files:
        doc = load(f)
        top = perms(doc.get('permissions'))
        for jname, job in (doc.get('jobs') or {}).items():
            m = LOCAL.match(str((job or {}).get('uses') or ''))
            if not m:
                continue
            callee_path = os.path.join(ROOT, m.group(1))
            if not os.path.isfile(callee_path):
                bad.append('%s job %s: calls %s, which does not exist' % (rel(f), jname, m.group(1)))
                continue
            granted = perms(job.get('permissions'))
            if granted is None:
                granted = top
            if granted is None:
                bad.append('%s job %s: calls %s and declares no permissions; the grant would depend '
                           'on the repository default, which nobody can see from here'
                           % (rel(f), jname, m.group(1)))
                continue
            for cjob, req in requested(load(callee_path)).items():
                for scope, lvl in req.items():
                    if scope == '*':
                        continue
                    if (grants(granted, scope) or 0) < lvl:
                        bad.append('%s job %s grants %s=%s, but %s job %s requests %s -- GitHub '
                                   'refuses the whole run (startup_failure)'
                                   % (rel(f), jname, scope,
                                      [k for k, v in LEVEL.items() if v == (grants(granted, scope) or 0)][0],
                                      m.group(1), cjob,
                                      [k for k, v in LEVEL.items() if v == lvl][0]))
    return bad


def rel(f):
    return os.path.relpath(f, ROOT).replace('\\', '/')


def main():
    try:
        import yaml
    except ImportError:
        print('UNKNOWN: PyYAML unavailable.')
        return 2
    cache = {}

    def load(p):
        if p not in cache:
            cache[p] = yaml.safe_load(io.open(p, encoding='utf-8')) or {}
        return cache[p]

    # self-test: a caller that grants read where the callee asks write must be refused
    callee = {'jobs': {'w': {'permissions': {'contents': 'write'}}}}
    caller = {'jobs': {'c': {'uses': './.github/workflows/x.yml', 'permissions': {'contents': 'read'}}}}
    g = perms(caller['jobs']['c']['permissions'])
    if not (grants(g, 'contents') < requested(callee)['w']['contents']):
        print('SELF-TEST FAILED: an insufficient grant was not detected')
        return 2

    files = sorted(glob.glob(os.path.join(ROOT, '.github', 'workflows', '*.yml')) +
                   glob.glob(os.path.join(ROOT, 'templates', '*.yml')))
    if not files:
        print('UNKNOWN: no workflows found.')
        return 2
    bad = check(files, load)
    if bad:
        for b in bad:
            print('FAIL: ' + b)
        return 1
    print('PASS: every in-repository caller grants every permission its called workflow requests.')
    return 0


if __name__ == '__main__':
    sys.exit(main())

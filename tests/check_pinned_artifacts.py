#!/usr/bin/env python3
"""Verify every pinned container image RESOLVES, and that docs agree with code.

WHY THIS EXISTS
    On 2026-09-02 `securego/gosec:2.28.0` was found pinned in `reusable-security.yml`. That tag has
    never existed -- upstream stops at 2.24.x. Every `docker run` failed at manifest lookup, `|| true`
    swallowed it, and "the scanner could not be acquired" was recorded as "the scanner found nothing".
    A seeded G401/G204 fixture sat unscanned behind a green job for two weeks.

    The pin came from `docs/roadmap/FUTURE_WORK.md`, which listed 2.28.0 as the currency target. So
    the documentation was not merely stale -- it was the defect's provenance.

    Two failure classes, neither of which anything checked:

      1  A PIN THAT CANNOT RESOLVE.   An unresolvable pin is worse than a stale one: a stale scanner
                                      still runs. Chasing "current" reached past the end of the shelf.
      2  DOCS DISAGREEING WITH CODE.  A roadmap is an instruction. If it names a version the workflows
                                      do not use, somebody will eventually reconcile them the wrong way.

    Checked here so neither can recur silently.

EXIT
    0  every pin resolves and docs agree with code
    1  a pin does not resolve, or a doc contradicts the workflows
    2  could not reach the registry -- reported as UNKNOWN, never as PASS
       (failure to observe is not an observation)
"""
import glob
import io
import json
import os
import re
import sys
import urllib.error
import urllib.request

WORKFLOWS = '.github/workflows/*.yml'
DOCS = ['docs/**/*.md', 'README.md']

# `owner/name:tag` where the tag looks like a version. Deliberately narrow: matching every colon in
# a workflow finds YAML keys, not images.
IMAGE = re.compile(r'\b([a-z0-9][a-z0-9._-]*/[a-z0-9][a-z0-9._-]*):(\d+\.\d+[\w.-]*)\b')

# A self-test tag that must NOT resolve. Without this the checker cannot distinguish "everything
# resolves" from "the resolver is broken and returns True for everything" -- which is precisely the
# class of defect it exists to catch.
SELF_TEST_BAD = ('securego/gosec', '2.28.0')
SELF_TEST_GOOD = ('securego/gosec', '2.24.6')


def uncommented(path):
    for i, line in enumerate(io.open(path, encoding='utf-8', errors='replace').read().split('\n')):
        if not line.lstrip().startswith('#'):
            yield i + 1, line


def find_images(patterns):
    """-> {(repo, tag): [locations]}"""
    out = {}
    for pat in patterns:
        for f in glob.glob(pat, recursive=True):
            if not os.path.isfile(f):
                continue
            for lineno, line in uncommented(f):
                for repo, tag in IMAGE.findall(line):
                    out.setdefault((repo, tag), []).append('%s:%d' % (f, lineno))
    return out


def resolves(repo, tag, timeout=15):
    """True / False / None(unknown). Docker Hub only; other registries report unknown rather than pass."""
    if repo.count('/') != 1:
        return None
    url = 'https://hub.docker.com/v2/repositories/%s/tags/%s' % (repo, tag)
    try:
        req = urllib.request.Request(url, headers={'User-Agent': 'secure-cicd-kit-pin-check'})
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return bool(json.load(r).get('name'))
    except urllib.error.HTTPError as e:
        if e.code == 404:
            return False
        return None
    except Exception:
        return None


def self_test():
    bad = resolves(*SELF_TEST_BAD)
    good = resolves(*SELF_TEST_GOOD)
    if bad is None or good is None:
        print('SELF-TEST UNKNOWN: registry unreachable. Reporting UNKNOWN, not PASS.')
        return 2
    if bad is not False or good is not True:
        print('SELF-TEST FAILED: resolver said bad=%r good=%r (expected False / True).' % (bad, good))
        print('A resolver that cannot tell a real tag from a nonexistent one proves nothing.')
        return 1
    print('self-test ok: %s:%s resolves, %s:%s does not' %
          (SELF_TEST_GOOD[0], SELF_TEST_GOOD[1], SELF_TEST_BAD[0], SELF_TEST_BAD[1]))
    return 0


def main():
    st = self_test()
    if st:
        return st

    code = find_images([WORKFLOWS])
    docs = find_images(DOCS)

    print('\n=== pinned images in workflows ===')
    failed, unknown = [], []
    for (repo, tag), where in sorted(code.items()):
        r = resolves(repo, tag)
        mark = {True: 'ok  ', False: 'FAIL', None: '????'}[r]
        print('  %s %s:%-12s %s' % (mark, repo, tag, where[0]))
        if r is False:
            failed.append((repo, tag, where))
        elif r is None:
            unknown.append((repo, tag, where))

    print('\n=== version claims in documentation vs workflows ===')
    drift = []
    code_tags = {}
    for repo, tag in code:
        code_tags.setdefault(repo, set()).add(tag)
    for (repo, tag), where in sorted(docs.items()):
        actual = code_tags.get(repo)
        if actual and tag not in actual:
            drift.append((repo, tag, sorted(actual), where))
            print('  DRIFT %s: docs say %s, workflows use %s  (%s)'
                  % (repo, tag, ', '.join(sorted(actual)), where[0]))
    if not drift:
        print('  no documented version contradicts the workflows')

    print('\n' + '=' * 72)
    if failed:
        for repo, tag, where in failed:
            print('FAIL: %s:%s DOES NOT RESOLVE  -> %s' % (repo, tag, ', '.join(where)))
        print('An unresolvable pin is worse than a stale one: a stale scanner still runs.')
        return 1
    if drift:
        print('FAIL: documentation names versions the workflows do not use.')
        print('A roadmap is an instruction. Reconcile it, or somebody will reconcile it wrongly.')
        return 1
    if unknown:
        for repo, tag, _ in unknown:
            print('UNKNOWN: %s:%s could not be checked (non-Docker-Hub registry or network).' % (repo, tag))
        print('Reported as UNKNOWN. Failure to observe is not an observation.')
        return 2
    print('PASS: every pinned image resolves; documentation agrees with the workflows.')
    return 0


if __name__ == '__main__':
    sys.exit(main())

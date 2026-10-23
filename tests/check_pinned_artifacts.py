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

TWO THINGS THIS COULD NOT SEE UNTIL 2026-10-14 (gap ledger L23)

      3  A TAG STARTING WITH `v`.      `zricethezav/gitleaks:v8.21.2` is pinned in two workflows and
                                      the image regex required a leading digit, so the gitleaks pin
                                      was exempt by regex -- the scanner whose acquisition path this
                                      checker was written for, never checked.
      4  ACTION REFERENCES.            `uses: owner/repo@ref` is a pin. `trivy-action@0.28.0` never
                                      existed either (FUTURE_WORK §9). Resolved here against the
                                      GitHub API: a tag through git/ref/tags, a 40-hex sha through
                                      commits, anything else through git/ref/heads. `./` and `$/`
                                      resolve to this repository at the running commit and are
                                      pinned by construction; `docker://` is an image.

    Action refs are NOT compared against documentation. The design documents quote third-party
    workflows verbatim as evidence of a defect (`actions/download-artifact@v4` with no run-id), and
    a quoted defect is not an instruction to this kit. Images stay compared, as before.

    No token is needed. GITHUB_TOKEN (or GH_TOKEN) is used for the REST fallback ONLY when its
    issuer -- $GITHUB_API_URL, and $PIN_CHECK_TOKEN_HOST when set -- is api.github.com; a token
    from `api.<tenant>.ghe.com` is never sent to api.github.com (KDEC-027). Unreachable is UNKNOWN,
    never PASS.

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

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import _github_refs  # noqa: E402 - after the path insert

WORKFLOWS = '.github/workflows/*.yml'
# Composites are code too. Decomposition Phase 2 moves scanner steps -- and the images they pin --
# into `.github/actions/**`; a checker that reads only workflows would lose every one of them in the
# move (plan §6.4, §7 step 9; tests/prove_pin_scope_covers_composites.py).
COMPOSITES = '.github/actions/**/*.yml'
CODE_PATTERNS = [WORKFLOWS, COMPOSITES]
DOCS = ['docs/**/*.md', 'README.md']

# `owner/name:tag` where the tag looks like a version. Deliberately narrow: matching every colon in
# a workflow finds YAML keys, not images. The optional `v` is the 2026-10-14 fix: without it the
# gitleaks pin (`:v8.21.2`) was never a match.
IMAGE = re.compile(r'\b([a-z0-9][a-z0-9._-]*/[a-z0-9][a-z0-9._-]*):(v?\d+\.\d+[\w.-]*)\b')

# `uses: owner/repo[/path]@ref`. The repository is the first two segments; a path inside it does not
# change which ref has to exist. `./`, `$/` and `docker://` start differently and never match.
ACTION = re.compile(r'uses:\s*([A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+)(?:/[A-Za-z0-9_./-]+)?@([A-Za-z0-9_./-]+)')
SHA40 = re.compile(r'^[0-9a-f]{40}$')

# A self-test tag that must NOT resolve. Without this the checker cannot distinguish "everything
# resolves" from "the resolver is broken and returns True for everything" -- which is precisely the
# class of defect it exists to catch.
SELF_TEST_BAD = ('securego/gosec', '2.28.0')
SELF_TEST_GOOD = ('securego/gosec', '2.24.6')
# The same pair for action refs. The bad one is a tag nobody will ever cut.
SELF_TEST_ACTION_BAD = ('actions/checkout', 'v0.0.0-this-tag-must-not-exist')
SELF_TEST_ACTION_GOOD = ('actions/checkout', 'v4')

GITHUB_API = _github_refs.GITHUB_API


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


def find_actions(patterns):
    """-> {(owner/repo, ref): [locations]} for every third-party `uses:` in code."""
    out = {}
    for pat in patterns:
        for f in glob.glob(pat, recursive=True):
            if not os.path.isfile(f):
                continue
            for lineno, line in uncommented(f):
                for repo, ref in ACTION.findall(line):
                    out.setdefault((repo, ref), []).append('%s:%d' % (f, lineno))
    return out


def ref_kind(ref):
    """'sha' for a full commit id, else 'tag'. A tag that is really a branch is tried as a branch
    only after the tag lookup says no, so a floating ref still counts as resolving -- whether it
    SHOULD float is the pinning policy's question (scripts/pin-actions.sh), not this one's."""
    return 'sha' if SHA40.match(ref) else 'tag'


def _github(path, timeout=15):
    """-> (status, json-or-None). Only with a token api.github.com issued (KDEC-027); otherwise
    (None, None) and the REST path is not taken. Network/auth trouble is None, never a verdict."""
    return _github_refs.api_get(path, 'secure-cicd-kit-pin-check', timeout)


def _action_resolves_api(repo, ref, timeout=15):
    """The REST path, secondary: True / False / None."""
    if ref_kind(ref) == 'sha':
        status, _ = _github('/repos/%s/commits/%s' % (repo, ref), timeout)
        if status == 200:
            return True
        # 404: no such commit. 422: not a commit id at all. Both mean the pin cannot resolve.
        if status in (404, 422):
            return False
        return None
    for kind in ('tags', 'heads'):
        status, body = _github('/repos/%s/git/ref/%s/%s' % (repo, kind, ref), timeout)
        if status == 200 and isinstance(body, dict) and body.get('ref') == 'refs/%s/%s' % (kind, ref):
            return True
        if status != 404:
            # 403 is the rate limit or a private repository; 401 a bad token. Not an observation.
            return None
    return False


def action_resolves(repo, ref, timeout=15):
    """True / False / None(unknown). An exact match on the ref, never a prefix.

    Git first (no token, no REST rate limit); the REST API only when git could not see and the run
    holds a token api.github.com issued. A ref git would read as an option is None, never run."""
    if not _github_refs.valid(repo, ref):
        return None
    if ref_kind(ref) == 'sha':
        r = _github_refs.commit_exists(repo, ref)
    else:
        r = _github_refs.ref_resolves(repo, ref)
    if r is not None:
        return r
    return _action_resolves_api(repo, ref, timeout)


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
    abad = action_resolves(*SELF_TEST_ACTION_BAD)
    agood = action_resolves(*SELF_TEST_ACTION_GOOD)
    if abad is None or agood is None:
        print('SELF-TEST UNKNOWN: github.com unreachable by git, and the REST API unusable (no '
              'token api.github.com issued, or rate-limited). Reporting UNKNOWN, not PASS.')
        return 2
    if abad is not False or agood is not True:
        print('SELF-TEST FAILED: action resolver said bad=%r good=%r (expected False / True).'
              % (abad, agood))
        print('A resolver that cannot tell a real ref from a nonexistent one proves nothing.')
        return 1
    print('self-test ok: %s@%s resolves, %s@%s does not' %
          (SELF_TEST_ACTION_GOOD[0], SELF_TEST_ACTION_GOOD[1],
           SELF_TEST_ACTION_BAD[0], SELF_TEST_ACTION_BAD[1]))
    return 0


def main():
    st = self_test()
    if st:
        return st

    code = find_images(CODE_PATTERNS)
    docs = find_images(DOCS)
    actions = find_actions(CODE_PATTERNS)

    print('\n=== pinned images in workflows and composites ===')
    failed, unknown = [], []
    for (repo, tag), where in sorted(code.items()):
        r = resolves(repo, tag)
        mark = {True: 'ok  ', False: 'FAIL', None: '????'}[r]
        print('  %s %s:%-12s %s' % (mark, repo, tag, where[0]))
        if r is False:
            failed.append((repo, tag, where))
        elif r is None:
            unknown.append((repo, tag, where))

    print('\n=== action references in workflows and composites ===')
    for (repo, ref), where in sorted(actions.items()):
        r = action_resolves(repo, ref)
        mark = {True: 'ok  ', False: 'FAIL', None: '????'}[r]
        print('  %s %s@%-42s %s (%d site%s)' % (mark, repo, ref, where[0], len(where),
                                                 '' if len(where) == 1 else 's'))
        if r is False:
            failed.append((repo, '@' + ref, where))
        elif r is None:
            unknown.append((repo, '@' + ref, where))

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
            sep = '' if tag.startswith('@') else ':'
            print('FAIL: %s%s%s DOES NOT RESOLVE  -> %s' % (repo, sep, tag, ', '.join(where)))
        print('An unresolvable pin is worse than a stale one: a stale scanner still runs.')
        return 1
    if drift:
        print('FAIL: documentation names versions the workflows do not use.')
        print('A roadmap is an instruction. Reconcile it, or somebody will reconcile it wrongly.')
        return 1
    if unknown:
        for repo, tag, _ in unknown:
            sep = '' if tag.startswith('@') else ':'
            print('UNKNOWN: %s%s%s could not be checked (other registry, rate limit or network).'
                  % (repo, sep, tag))
        print('Reported as UNKNOWN. Failure to observe is not an observation.')
        return 2
    print('PASS: every pinned image and every action ref resolves; documentation agrees with the '
          'workflows on image versions.')
    return 0


if __name__ == '__main__':
    sys.exit(main())

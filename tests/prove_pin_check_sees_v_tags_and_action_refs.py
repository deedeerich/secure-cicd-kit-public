#!/usr/bin/env python3
"""Prove the pin checker SEES a `v`-prefixed image tag and every third-party action ref.

WHY THIS EXISTS

    `tests/check_pinned_artifacts.py` exists because `securego/gosec:2.28.0` -- a tag that never
    existed -- sat pinned for two weeks behind a green job. It resolves every image it can see.

    It could not see two things (gap ledger L23, review G1-file38):

      1  A TAG THAT STARTS WITH `v`.   `zricethezav/gitleaks:v8.21.2` is pinned in two workflows.
                                       The image regex required the tag to start with a digit, so
                                       the gitleaks pin was never checked -- the exact scanner whose
                                       acquisition failure the checker was written to catch, exempt
                                       by regex.
      2  ACTION REFERENCES.            `uses: owner/repo@ref` is a pin too. `trivy-action@0.28.0`
                                       never existed either (FUTURE_WORK §9), and nothing checked
                                       the forty-odd `uses:` lines any more than it checked gosec.

    This proves both are now in scope, against a sandbox tree, with NO network: finding a pin and
    resolving a pin are different acts, and this file is about the first. The resolver's own
    negative control lives in the checker's self-test.

WHAT MUST NOT BE IN SCOPE
    `./` and `$/` references resolve to this repository at the running commit -- pinned by
    construction (tests/prove_pin_scope_covers_composites.py). `docker://` is an image, found by the
    image regex. A commented-out line is prose.

EXIT
    0  both classes are found, and the out-of-scope forms are not
    1  a class is still invisible
"""
import io
import os
import shutil
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

WORKFLOW = """name: sandbox
on: push
jobs:
  j:
    runs-on: ubuntu-latest
    steps:
      - uses: ./.github/actions/local
      - uses: $/.github/actions/self
      - uses: actions/checkout@v7
      - uses: github/codeql-action/upload-sarif@v4
      - uses: owner/repo@0123456789abcdef0123456789abcdef01234567
      - uses: docker://alpine:3.19
      # - uses: commented/out@v1
      - run: |
          IMG=zricethezav/gitleaks:v8.21.2
          docker run --rm securego/gosec:2.24.6 -version
"""


def main():
    import check_pinned_artifacts as cpa
    failures = []
    work = tempfile.mkdtemp(prefix='pin-see-')
    cwd = os.getcwd()
    try:
        wf = os.path.join(work, '.github', 'workflows')
        os.makedirs(wf)
        io.open(os.path.join(wf, 'ci.yml'), 'w', encoding='utf-8', newline='\n').write(WORKFLOW)
        os.chdir(work)

        images = cpa.find_images(cpa.CODE_PATTERNS)
        if ('zricethezav/gitleaks', 'v8.21.2') not in images:
            failures.append('a v-prefixed image tag (zricethezav/gitleaks:v8.21.2) is invisible '
                            'to find_images -- the gitleaks pin has never been checked')
        if ('securego/gosec', '2.24.6') not in images:
            failures.append('the control image (securego/gosec:2.24.6) is no longer found')
        if ('alpine', '3.19') in images:
            pass  # a bare image has no owner/ prefix; whether it is found is not asserted here

        if not hasattr(cpa, 'find_actions'):
            failures.append('check_pinned_artifacts has no find_actions -- action refs are not '
                            'in scope at all')
        else:
            actions = cpa.find_actions(cpa.CODE_PATTERNS)
            want = {('actions/checkout', 'v7'),
                    ('github/codeql-action', 'v4'),
                    ('owner/repo', '0123456789abcdef0123456789abcdef01234567')}
            got = set(actions)
            for ref in sorted(want - got):
                failures.append('action ref %s@%s not found' % ref)
            for repo, ref in sorted(got):
                if repo.startswith('./') or repo.startswith('$/') or repo == 'commented/out' \
                        or repo.startswith('docker:'):
                    failures.append('out-of-scope reference reported as an action pin: %s@%s'
                                    % (repo, ref))
            if hasattr(cpa, 'ref_kind'):
                if cpa.ref_kind('0123456789abcdef0123456789abcdef01234567') != 'sha':
                    failures.append('a 40-hex ref is not classified as a sha')
                if cpa.ref_kind('v7') != 'tag':
                    failures.append('v7 is not classified as a tag')
            else:
                failures.append('check_pinned_artifacts has no ref_kind -- a sha and a tag resolve '
                                'through different endpoints and must be told apart')
    finally:
        os.chdir(cwd)
        shutil.rmtree(work, ignore_errors=True)

    for f in failures:
        print('FAIL: %s.' % f)
    if failures:
        return 1
    print('PASS: v-prefixed image tags and third-party action refs are both in the pin checker\'s '
          'scope; ./, $/, docker:// and comments are not.')
    return 0


if __name__ == '__main__':
    sys.exit(main())

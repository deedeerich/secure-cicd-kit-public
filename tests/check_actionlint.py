#!/usr/bin/env python3
"""Run the pinned actionlint over every workflow; any finding it reports is a load-time defect.

WHY THIS EXISTS

    The first hosted milestone run (2026-10-15, KDEC-006) found four workflows GitHub would not even
    start -- zero jobs, "This run likely failed because of a workflow file issue" -- while every local
    proof was green, because the proofs run STEPS and GitHub refuses whole FILES first:

      self-test.yml                 a `run:` comment held a literal empty expression, which GitHub
                                    parses (expressions are evaluated inside shell comments too)
      reusable-deploy-*.yml (x2)    a job output read `steps.resolve` after that step was removed,
                                    and `cancelled()` was called inside a step's env: (not allowed)
      reusable-security.yml         a 23,414-character template (see check_expression_length.py)

    actionlint reports exactly this class. It is pinned (version and checksum) in self-test.

WHAT IS EXCLUDED, AND WHY
    shellcheck findings     style inside scripts; a separate concern, and noisy on generated blocks
    `$/` action references  the kit's composite form, proven to resolve on GitHub (decomposition
                            step 8, run on the private consumer repository); actionlint 1.7.7 does
                            not know the syntax. Excluded BY EXACT MESSAGE, nothing broader.

EXIT
    0  actionlint reports nothing outside the exclusions
    1  it reports at least one finding
    2  actionlint is not installed -- UNKNOWN, never PASS
"""
import glob
import os
import shutil
import subprocess
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DOLLAR_SLASH = 'specifying action "$/'
# actionlint 1.7.7 still enforces 10 workflow_dispatch inputs; the kit's decomposition plan (section
# 8.3) records this as a stale rule (GitHub's documented limit is higher). Excluded by exact text.
STALE_DISPATCH = 'maximum number of inputs for "workflow_dispatch" event is 10'


def main():
    exe = os.environ.get('ACTIONLINT') or shutil.which('actionlint')
    if not exe:
        print('UNKNOWN: actionlint is required (set ACTIONLINT or put it on PATH).')
        return 2
    # Overlay workflows ship in a consumer's copy and are loaded by GitHub exactly as these are;
    # a load-time defect there is the same startup failure, in someone else's repository. A
    # neutral copy has no overlays/, so this adds nothing there.
    files = sorted(glob.glob(os.path.join(ROOT, '.github', 'workflows', '*.yml')) +
                   glob.glob(os.path.join(ROOT, 'overlays', '*', 'workflows', '*.yml')))
    p = subprocess.run([exe, '-no-color', '-shellcheck=', '-format', '{{range $err := .}}'
                        '{{$err.Filepath}}:{{$err.Line}}:{{$err.Column}}: {{$err.Message}} [{{$err.Kind}}]\n'
                        '{{end}}'] + files,
                       capture_output=True, text=True, encoding='utf-8', errors='replace', cwd=ROOT)
    lines = [l for l in (p.stdout or '').splitlines() if l.strip()]
    findings = [l for l in lines if DOLLAR_SLASH not in l and STALE_DISPATCH not in l]
    excluded = len(lines) - len(findings)
    if p.returncode not in (0, 1):
        print('UNKNOWN: actionlint exited %d: %s' % (p.returncode, (p.stderr or '')[-300:]))
        return 2
    if findings:
        for f in findings:
            print('FAIL: ' + os.path.relpath(f, ROOT) if os.path.isabs(f.split(':')[0]) else 'FAIL: ' + f)
        return 1
    print('PASS: actionlint reports nothing across %d workflow(s) (%d `$/` reference(s) excluded by '
          'exact message).' % (len(files), excluded))
    return 0


if __name__ == '__main__':
    sys.exit(main())

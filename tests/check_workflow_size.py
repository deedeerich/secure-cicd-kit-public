#!/usr/bin/env python3
"""A workflow file over GitHub's size limit does not fail. It never starts.

WHY THIS EXISTS
    On 2026-09-16 `reusable-security.yml` crossed 500 KB. GitHub's response is not a failing job:

        Workflow file exceeds the maximum allowed size of 500 KB

    ZERO JOBS. A startup failure on every push, for six days, on the kit's flagship security
    workflow -- and every gate in the repository reported green the entire time.

    It went 472.1 KB -> 506.8 KB in commit 412ed634, which was itself a fix for a control that had
    crashed and decided a security verdict. The commit that repaired a control broke the workflow
    containing it, and nothing noticed because nothing was looking at size.

WHY NOTHING CAUGHT IT, WHICH IS THE PART WORTH KEEPING
    Every check READS the file. None of them RUNS it.

      self-test           parses and lints it. A 608 KB file parses perfectly.
      actionlint          lints it. Green.
      validate-scanners   proves the TOOLS directly -- it never invokes the workflow.
      consumer-path-test  WOULD invoke it, and is dispatch-only and weekly.

    So the single job that would have exposed it is the one that does not run automatically.
    EXISTS != CALLED != IN THE PIPELINE, with the kit's own centrepiece on the wrong side of it.

    A parseable file is not a runnable file. That is the whole lesson, and it is the same shape as
    a scanner that exits zero having parsed nothing.

THE THRESHOLD IS DELIBERATELY BELOW THE LIMIT
    Failing at 500 KB means failing at the moment the workflow is already dead. The warning
    threshold exists so somebody hears about it while there is still room to act, and the failure
    threshold sits under the real ceiling so a single commit cannot step from "fine" to "dead".

    475 KB is the owner's number, raised from 450. It leaves 25 KB of headroom rather than 50 --
    a deliberate trade: less room to react, fewer files failing a gate they are nowhere near
    breaking. The warning stays at 350 KB, which is where the useful signal lives.

SCOPE AND UNIT (completion ledger L66, lane L-E, 2026-10-21)
    The scope was `.github/workflows/*.yml` and nothing else, so the decomposition was moving bytes
    OUT of the measured file INTO files nobody measured: the resolve composite is ~100 KB, and the
    overlay workflows were never read at all. Composites and overlay workflows are now in scope at
    the same thresholds. GitHub documents no size limit for a composite action; applying the
    workflow limit to them is this kit's choice, not a platform fact.

    The unit was on-disk bytes, and on a Windows checkout (autocrlf) every line costs one byte more
    than the blob GitHub reads -- on 2026-10-21 the flagship measured 457.7 KB on a Windows disk and
    450.1 KB as GitHub reads it, 7.6 KB of phantom weight against a 25 KB headroom. The size is now
    measured as GitHub reads it: line endings normalised to LF.

EXIT
    0  every workflow is comfortably runnable
    1  a workflow is over the fail threshold, or over GitHub's hard limit
    2  could not be checked -- reported as UNKNOWN, never as PASS
"""
import argparse
import glob
import os
import sys

# GitHub's documented hard limit for a single workflow file.
HARD_LIMIT = 512000          # 500 KB, exactly
FAIL_AT = 486400             # 475 KB -- the owner's number. 25 KB of headroom left
WARN_AT = 358400             # 350 KB -- say something while acting is still cheap

WORKFLOWS = '.github/workflows/*.yml'
# L66: everything GitHub loads as workflow or action text, not only the top-level workflows.
SCOPE = (
    '.github/workflows/*.yml',
    '.github/workflows/*.yaml',
    '.github/actions/*/action.yml',
    '.github/actions/*/action.yaml',
    'overlays/*/workflows/*.yml',
    'overlays/*/.github/workflows/*.yml',
    'overlays/*/.github/actions/*/action.yml',
)


def human(n):
    return '%.1f KB' % (n / 1024.0)


def lf_size(path):
    """Bytes as GitHub reads the committed file: CRLF counted as LF."""
    with open(path, 'rb') as fh:
        return len(fh.read().replace(b'\r\n', b'\n'))


def in_scope(root):
    out = []
    for g in SCOPE:
        out.extend(p for p in glob.glob(os.path.join(root, g)) if os.path.isfile(p))
    return sorted(set(out))


def main(argv=None):
    ap = argparse.ArgumentParser(description='A workflow over the size limit never starts.')
    ap.add_argument('--root', default='.', help='repository root to measure (default: cwd)')
    a = ap.parse_args(sys.argv[1:] if argv is None else argv)
    root = a.root
    files = in_scope(root)
    rels = [os.path.relpath(f, root).replace('\\', '/') for f in files]
    if not any(r.startswith('.github/workflows/') for r in rels):
        print('UNKNOWN: no workflows found at %s.' % os.path.join(root, WORKFLOWS))
        print('Nothing inspected is not nothing wrong.')
        return 2

    rows = sorted(((lf_size(f), os.path.relpath(f, root).replace('\\', '/')) for f in files),
                  reverse=True)
    print('=== workflow, composite and overlay sizes as GitHub reads them (LF), hard limit %s ==='
          % human(HARD_LIMIT))
    dead, failing, warning = [], [], []
    for size, f in rows:
        if size > HARD_LIMIT:
            mark, bucket = 'WILL NOT START', dead
        elif size > FAIL_AT:
            mark, bucket = 'OVER FAIL LIMIT', failing
        elif size > WARN_AT:
            mark, bucket = 'approaching', warning
        else:
            mark, bucket = 'ok', None
        print('  %-9s %-16s %s' % (human(size), mark, f))
        if bucket is not None:
            bucket.append((size, f))

    print('\n' + '=' * 72)
    for size, f in dead:
        print('FAIL: %s is %s, OVER GITHUB\'S %s LIMIT.' % (f, human(size), human(HARD_LIMIT)))
        print('      This workflow DOES NOT RUN. Not a failing job -- zero jobs, a startup')
        print('      failure on every trigger. Every other check in this repository can pass')
        print('      while this file is dead, because they read it and do not run it.')
    for size, f in failing:
        print('FAIL: %s is %s, over the %s fail threshold.' % (f, human(size), human(FAIL_AT)))
        print('      Still runnable today. The threshold sits below GitHub\'s limit so that one')
        print('      commit cannot take a file from "fine" to "will not start".')
    for size, f in warning:
        print('::warning title=Workflow approaching the size limit::%s is %s. GitHub refuses a '
              'workflow over %s, and a file that crosses it stops starting entirely.'
              % (f, human(size), human(HARD_LIMIT)))

    if dead or failing:
        print('\nA PARSEABLE FILE IS NOT A RUNNABLE FILE.')
        return 1
    print('PASS: %d workflow, composite and overlay file(s); largest is %s, %s under GitHub\'s '
          'limit.' % (len(rows), human(rows[0][0]), human(HARD_LIMIT - rows[0][0])))
    if warning:
        print('      %d approaching the threshold -- warned above, not failed.' % len(warning))
    return 0


if __name__ == '__main__':
    sys.exit(main())

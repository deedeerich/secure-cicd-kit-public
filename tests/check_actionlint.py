#!/usr/bin/env python3
"""Run the pinned actionlint over every workflow; every finding must be CLASSIFIED, and every classification must still occur.

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

WHY A CLASSIFIED BASELINE, NOT AN EXCLUSION (2026-11-13, lane actionlint-pair, KDEC-058)

    Until 2026-11-13 this check dropped every line CONTAINING two strings (`specifying action "$/`
    and the 10-input workflow_dispatch rule). 89 raw findings (87 on the pinned 1.7.12) were
    therefore invisible, and a reviewer asked that they be CLASSIFIED, not grandfathered. Each is
    now a row of docs/assurance/ACTIONLINT_BASELINE.md: file, rule kind, exact message, how many
    times, which actionlint versions report it, and a class with a cited reason:

        1  actionlint does not model a pattern GitHub accepts (parser limitation)
        2  a genuine defect -- REFUSED here: a defect is fixed, never baselined
        3  style, no runtime effect

    The comparison is EXACT on (file, kind, message) and on the COUNT. So:
        UNCLASSIFIED   a finding (or one more occurrence of a known one) that no row covers   -> FAIL
        STALE          a row for this version that no longer occurs as often as it says      -> FAIL
        DEFECT_BASELINED  a class-2 row                                                        -> FAIL
    Line numbers are recorded for the reader and only NOTED when they drift: a line moves with every
    edit above it, and a count does not.

    A row whose workflow is absent from the tree (an export profile withholds it) is NOTED and not
    compared. An actionlint version the baseline was not verified with is UNKNOWN: the classification
    is per version (1.7.7 still reports the 10-input rule; 1.7.12 does not).

WHAT IS STILL NOT READ
    shellcheck findings     style inside scripts; a separate concern, and noisy on generated blocks
                            (`-shellcheck=` disables the integration; the baseline says so)

EXIT
    0  every finding is classified and every applicable row still occurs
    1  an unclassified finding, a stale row, or a baselined defect
    2  actionlint is not installed, the baseline cannot be read, or the version is not one the
       baseline was verified with -- UNKNOWN, never PASS
"""
import collections
import glob
import io
import os
import re
import shutil
import subprocess
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
BASELINE = os.path.join(ROOT, 'docs', 'assurance', 'ACTIONLINT_BASELINE.md')
FMT = '{{range $err := .}}{{$err.Filepath}}\t{{$err.Line}}\t{{$err.Kind}}\t{{$err.Message}}\n{{end}}'
CLASSES = {'1': 'parser limitation', '2': 'genuine defect', '3': 'style, no impact'}
ROW_RX = re.compile(r'^\|\s*(AL-\d{3})\s*\|\s*([0-9])\s*\|\s*(R\d+)\s*\|\s*`([^`]+)`\s*\|\s*([a-z-]+)\s*\|'
                    r'\s*(\d+)\s*\|\s*([0-9., ]+)\s*\|\s*([0-9, ]*)\s*\|\s*`(.+)`\s*\|\s*$')
VERIFIED_RX = re.compile(r'^Verified with actionlint:\s*(.+)$', re.M)


class BaselineError(Exception):
    pass


def read_baseline(path=BASELINE):
    """-> (verified versions, [row dict]). Raises BaselineError on any malformed row."""
    try:
        text = io.open(path, encoding='utf-8').read()
    except OSError as e:
        raise BaselineError('cannot read %s: %s' % (path, e))
    m = VERIFIED_RX.search(text)
    if not m:
        raise BaselineError('the baseline names no "Verified with actionlint:" line')
    verified = [v.strip() for v in m.group(1).split(',') if v.strip()]
    rows, seen = [], set()
    for line in text.splitlines():
        if not line.startswith('| AL-'):
            continue
        r = ROW_RX.match(line)
        if not r:
            raise BaselineError('malformed baseline row: %s' % line[:120])
        rid, cls, why, f, kind, n, vers, lines, msg = r.groups()
        if rid in seen:
            raise BaselineError('duplicate baseline id %s' % rid)
        seen.add(rid)
        if cls not in CLASSES:
            raise BaselineError('%s has class %s; the classes are %s' % (rid, cls, sorted(CLASSES)))
        rows.append({'id': rid, 'class': cls, 'reason': why, 'file': f, 'kind': kind, 'count': int(n),
                     'versions': [v.strip() for v in vers.split(',') if v.strip()],
                     'lines': [int(x) for x in lines.split(',') if x.strip()], 'message': msg})
    if not rows:
        raise BaselineError('the baseline has no rows')
    keys = collections.Counter((r['file'], r['kind'], r['message'], tuple(r['versions'])) for r in rows)
    dup = [k for k, c in keys.items() if c > 1]
    if dup:
        raise BaselineError('two rows classify the same finding: %s' % (dup[0],))
    return verified, rows


def parse_findings(stdout, root=ROOT):
    """actionlint -format FMT output -> {(file, kind, message): [line, ...]} with repo-relative paths."""
    got = collections.OrderedDict()
    for line in (stdout or '').splitlines():
        if not line.strip():
            continue
        parts = line.split('\t', 3)
        if len(parts) != 4:
            got.setdefault(('?', 'unparsed', line), []).append(0)
            continue
        f, ln, kind, msg = parts
        if os.path.isabs(f):
            f = os.path.relpath(f, root)
        f = f.replace('\\', '/')
        got.setdefault((f, kind, msg), []).append(int(ln) if ln.isdigit() else 0)
    return got


def evaluate(findings, rows, version, verified, present_files):
    """-> (problems, notes, counts). The whole decision, with no I/O, so the proof can drive it."""
    problems, notes = [], []
    if version not in verified:
        return (['ACTIONLINT_VERSION_UNCLASSIFIED: actionlint %s is not a version the baseline was verified with (%s); '
                 'classify its findings and add it to "Verified with actionlint:"' % (version, ', '.join(verified))],
                notes, {})
    counts = {'classified': 0, 'rows': 0, 'withheld': 0}
    applicable = {}
    for r in rows:
        if r['class'] == '2':
            problems.append('DEFECT_BASELINED: %s (%s %s) is class 2, a genuine defect; fix it, never baseline it'
                            % (r['id'], r['file'], r['kind']))
        if version not in r['versions']:
            continue
        if r['file'] not in present_files:
            counts['withheld'] += 1
            notes.append('NOTE: %s names %s, which is not in this tree (withheld by an export profile?)'
                         % (r['id'], r['file']))
            continue
        applicable[(r['file'], r['kind'], r['message'])] = r
    counts['rows'] = len(applicable)
    for key, lines in findings.items():
        r = applicable.get(key)
        if r is None:
            problems.append('UNCLASSIFIED: %s:%s [%s] %s -- add a classified row to %s'
                            % (key[0], ','.join(map(str, lines)), key[1], key[2],
                               os.path.relpath(BASELINE, ROOT).replace('\\', '/')))
            continue
        if len(lines) > r['count']:
            problems.append('UNCLASSIFIED: %s expects %d occurrence(s) of [%s] %s in %s; actionlint reports %d '
                            '(lines %s)' % (r['id'], r['count'], key[1], key[2], key[0], len(lines),
                                            ','.join(map(str, lines))))
        elif len(lines) < r['count']:
            problems.append('STALE: %s expects %d occurrence(s) in %s; actionlint reports %d -- lower the count '
                            'or delete the row' % (r['id'], r['count'], key[0], len(lines)))
        else:
            counts['classified'] += len(lines)
            if sorted(lines) != sorted(r['lines']):
                notes.append('NOTE: %s moved (recorded lines %s, now %s); the count holds'
                             % (r['id'], ','.join(map(str, r['lines'])), ','.join(map(str, lines))))
    for key, r in applicable.items():
        if key not in findings:
            problems.append('STALE: %s (%s [%s]) no longer occurs -- delete the row' % (r['id'], key[0], key[1]))
    return problems, notes, counts


def actionlint_version(exe):
    p = subprocess.run([exe, '-version'], capture_output=True, text=True, encoding='utf-8', errors='replace')
    first = (p.stdout or '').strip().splitlines()
    return first[0].strip().lstrip('v') if first else ''


def main():
    exe = os.environ.get('ACTIONLINT') or shutil.which('actionlint')
    if not exe:
        print('UNKNOWN: actionlint is required (set ACTIONLINT or put it on PATH).')
        return 2
    try:
        verified, rows = read_baseline()
    except BaselineError as e:
        print('UNKNOWN: %s' % e)
        return 2
    # Overlay workflows ship in a consumer's copy and are loaded by GitHub exactly as these are;
    # a load-time defect there is the same startup failure, in someone else's repository. A
    # neutral copy has no overlays/, so this adds nothing there.
    files = sorted(glob.glob(os.path.join(ROOT, '.github', 'workflows', '*.yml')) +
                   glob.glob(os.path.join(ROOT, 'overlays', '*', 'workflows', '*.yml')))
    rel = [os.path.relpath(f, ROOT).replace('\\', '/') for f in files]
    version = actionlint_version(exe)
    p = subprocess.run([exe, '-no-color', '-shellcheck=', '-format', FMT] + rel,
                       capture_output=True, text=True, encoding='utf-8', errors='replace', cwd=ROOT)
    if p.returncode not in (0, 1):
        print('UNKNOWN: actionlint exited %d: %s' % (p.returncode, (p.stderr or '')[-300:]))
        return 2
    findings = parse_findings(p.stdout)
    problems, notes, counts = evaluate(findings, rows, version, verified, set(rel))
    for n in notes:
        print(n)
    if any(x.startswith('ACTIONLINT_VERSION_UNCLASSIFIED') for x in problems):
        print('UNKNOWN: ' + problems[0])
        return 2
    if problems:
        for x in problems:
            print('FAIL: ' + x)
        return 1
    print('PASS: actionlint %s over %d workflow(s): %d finding(s), every one classified by %d baseline row(s) of '
          '%s; no stale row (%d row(s) for withheld files not compared).'
          % (version, len(files), counts['classified'], counts['rows'],
             os.path.relpath(BASELINE, ROOT).replace('\\', '/'), counts['withheld']))
    return 0


if __name__ == '__main__':
    sys.exit(main())

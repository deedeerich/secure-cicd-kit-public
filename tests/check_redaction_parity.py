#!/usr/bin/env python3
"""The two redaction pattern sets must be byte-identical. Fail the build if they drift.

WHY THERE ARE TWO COPIES AT ALL
    scan_report.py redacts what it PRINTS. redact_sarif.py redacts what gets UPLOADED. Each is
    inlined into the workflow separately, and a reusable workflow cannot reach the kit's own
    scripts/ at consumer runtime, so neither can import the other. The duplication is forced.

WHY THAT IS ACCEPTABLE ONLY WITH THIS FILE
    Unenforced duplication is how this kit lost fourteen Azure gitleaks rules and a flawfinder
    fix -- a change applied to one copy and not the other. Here the failure would be quieter and
    worse: someone adds a pattern for a new token format to the printer, the artifact redactor
    never learns it, and the value ships in a downloadable file while the summary looks clean.

    So the duplication is an ENFORCED invariant. Add a pattern in one place and the build fails
    until it exists in both.

USAGE  python3 tests/check_redaction_parity.py
EXIT   0 identical      1 drifted
"""
import io
import os
import re
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
A = os.path.join(ROOT, 'scripts', 'scan_report.py')
B = os.path.join(ROOT, 'scripts', 'redact_sarif.py')

BLOCK = re.compile(r'SECRET_PATTERNS = \[(.*?)\]\n', re.S)
MASK = re.compile(r'def _mask\(value, label\):(.*?)\n\n', re.S)
REDACT = re.compile(r'def redact\(text\):(.*?)\n\n', re.S)


def grab(path, rx, what):
    txt = io.open(path, encoding='utf-8').read()
    m = rx.search(txt)
    if not m:
        print('::error title=Redaction parity::%s has no %s block -- it was renamed or removed, '
              'and this check cannot compare what it cannot find. A parity check with nothing '
              'to compare is not a pass.' % (os.path.basename(path), what))
        return None
    return m.group(1).strip()


def check_order():
    """Every job that uploads an artifact must redact FIRST.

    Order is the entire control. The per-job status block is appended at the END of a job, which
    is right for printing a count and useless for redaction -- by then the artifact exists. A
    redactor placed after the upload protects nothing while looking exactly like protection.

    Also fails a job that uploads with no redaction step at all, which is the state thirteen of
    them were in: gitleaks stripped its snippets, and every other scanner shipped raw SARIF.
    """
    import yaml
    wf = os.path.join(ROOT, '.github', 'workflows', 'reusable-security.yml')
    doc = yaml.safe_load(io.open(wf, encoding='utf-8'))
    problems, checked = [], 0
    for job, v in (doc.get('jobs') or {}).items():
        steps = v.get('steps') or []
        # BOTH publication paths. The artifact is downloadable by anyone with repo read; the
        # Security tab is narrower but still a publication, and gitleaks was stripped before both
        # from the start. Checking only upload-artifact would have left ten upload-sarif steps
        # unguarded while the gate reported clean -- a denominator quietly missing a modality.
        ups = [i for i, s in enumerate(steps)
               if 'upload-artifact' in str(s.get('uses') or '')
               or 'upload-sarif' in str(s.get('uses') or '')]
        if not ups:
            continue
        reds = [i for i, s in enumerate(steps)
                if 'Redact credential' in str(s.get('name') or '')]
        if not reds:
            problems.append('%s publishes scanner output (artifact or Security tab) and never '
                            'redacts it' % job)
        elif min(reds) > min(ups):
            problems.append('%s redacts at step %d, AFTER uploading at step %d -- the artifact '
                            'is already published' % (job, min(reds), min(ups)))
        else:
            checked += 1
    if problems:
        for p in problems:
            print('::error title=Redaction order::%s' % p)
        return False
    print('  %-18s %d job(s) publish scanner output, all redact first'
          % ('upload ordering', checked))
    return True


def main():
    bad = False
    if not check_order():
        bad = True
    for rx, what in ((BLOCK, 'SECRET_PATTERNS'), (MASK, '_mask'), (REDACT, 'redact')):
        a = grab(A, rx, what)
        b = grab(B, rx, what)
        if a is None or b is None:
            bad = True
            continue
        if a != b:
            bad = True
            print('::error title=Redaction drift::%s differs between scan_report.py and '
                  'redact_sarif.py. One redacts what is PRINTED and the other what is '
                  'UPLOADED; a pattern present in only one means the value is masked in the '
                  'summary and shipped intact in the artifact.' % what)
            la, lb = a.split('\n'), b.split('\n')
            for i in range(max(len(la), len(lb))):
                x = la[i] if i < len(la) else '(absent)'
                y = lb[i] if i < len(lb) else '(absent)'
                if x != y:
                    print('    scan_report  : %s' % x.strip())
                    print('    redact_sarif : %s' % y.strip())
        else:
            print('  %-18s identical in both' % what)
    if bad:
        return 1
    print('redaction parity: printer and artifact redactor use the same patterns')
    return 0


if __name__ == '__main__':
    sys.exit(main())

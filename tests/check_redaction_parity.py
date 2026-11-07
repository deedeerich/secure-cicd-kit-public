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


def _expand(doc):
    """The workflow with every `$/` composite step expanded into its job, as the runner sees it.

    Scanner job bodies live in `.github/actions/<scanner>/` (ledger L64); this reads the steps a
    job actually runs. One rule, tests/_composite_expand.py, for every reader.
    """
    sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
    import _composite_expand
    return _composite_expand.expanded_doc(doc)


def grab(path, rx, what):
    txt = io.open(path, encoding='utf-8').read()
    m = rx.search(txt)
    if not m:
        print('::error title=Redaction parity::%s has no %s block -- it was renamed or removed, '
              'and this check cannot compare what it cannot find. A parity check with nothing '
              'to compare is not a pass.' % (os.path.basename(path), what))
        return None
    return m.group(1).strip()


def is_upload(step):
    """A step that publishes what is on disk: an artifact, the Security tab, or CodeQL's analyze,
    which uploads by itself unless told `upload: never`. Missing the third is how CodeQL's SARIF
    reached the Security tab before any redactor ran (N24)."""
    uses = str(step.get('uses') or '')
    if 'upload-artifact' in uses or 'upload-sarif' in uses:
        return True
    if 'codeql-action/analyze' in uses:
        return str((step.get('with') or {}).get('upload', 'always')).lower() != 'never'
    return False


def is_redaction(step):
    return 'Redact credential' in str(step.get('name') or '')


def order_problems(job, steps):
    """EVERY upload must be clean, not only the first.

    Walk the job. A redaction step cleans the workspace; any other step that is not itself an
    upload may write new output, and so TAINTS it again. An upload over a tainted workspace
    publishes whatever was written since the last redaction. The old rule -- "redact before the
    FIRST upload" -- passed jobs that produced a second report after redacting and then uploaded
    it raw (Trivy IaC, flawfinder: N24/WP19).
    """
    problems = []
    tainted = True
    seen_redaction = False
    for i, s in enumerate(steps):
        if is_redaction(s):
            tainted = False
            seen_redaction = True
        elif is_upload(s):
            if tainted:
                what = str(s.get('name') or s.get('uses'))
                if not seen_redaction:
                    problems.append('%s step %d (%s) publishes before ANY redaction' % (job, i, what))
                else:
                    problems.append('%s step %d (%s) publishes output written AFTER the last '
                                    'redaction' % (job, i, what))
        else:
            tainted = True
    return problems


def order_self_test():
    """The rule must fail each shape it claims to catch, or it proves nothing."""
    R = {'name': 'Redact credential material before upload'}
    U = {'uses': 'actions/upload-artifact@v7'}
    S = {'uses': 'github/codeql-action/upload-sarif@v4'}
    W = {'run': 'scanner > out.sarif'}
    good = [W, R, U, S]
    cases = [
        ('upload with no redaction', [W, U]),
        ('second report after redaction, uploaded raw', [W, R, U, W, S]),
        ('codeql analyze uploads by default', [W, {'uses': 'github/codeql-action/analyze@v4'}, R, U]),
        ('codeql analyze with upload: always', [W, {'uses': 'github/codeql-action/analyze@v4',
                                                     'with': {'upload': 'always'}}, R, U]),
    ]
    if order_problems('control', good):
        return 'the control failed'
    if order_problems('codeql-never', [W, {'uses': 'github/codeql-action/analyze@v4',
                                           'with': {'upload': 'never'}}, R, U]):
        return 'analyze with upload: never was flagged'
    for label, steps in cases:
        if not order_problems('case', steps):
            return 'did not catch: %s' % label
    return None


def check_order():
    """Every upload in every job must be preceded by a redaction with nothing written in between."""
    import yaml
    err = order_self_test()
    if err:
        print('::error title=Redaction order::self-test failed: %s' % err)
        return False
    wf = os.path.join(ROOT, '.github', 'workflows', 'reusable-security.yml')
    doc = _expand(yaml.safe_load(io.open(wf, encoding='utf-8')))
    problems, checked, uploads = [], 0, 0
    for job, v in (doc.get('jobs') or {}).items():
        steps = v.get('steps') or []
        n = sum(1 for s in steps if is_upload(s))
        if not n:
            continue
        uploads += n
        p = order_problems(job, steps)
        if p:
            problems.extend(p)
        else:
            checked += 1
    if problems:
        for p in problems:
            print('::error title=Redaction order::%s' % p)
        return False
    print('  %-18s %d upload step(s) in %d job(s), every one over a freshly redacted workspace'
          % ('upload ordering', uploads, checked))
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

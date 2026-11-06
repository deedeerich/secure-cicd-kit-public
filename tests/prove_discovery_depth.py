#!/usr/bin/env python3
"""A bounded search that found nothing has not shown absence beyond its bound (W4K-120).

WHY THIS EXISTS

    Discovery's presence probes stop at 8 directory levels and reported a language with no match
    as NOT_APPLICABLE ("searched, none found") -- including a language whose only project sits
    deeper than 8 levels, where nothing searched. NOT_APPLICABLE's registered rule is that it
    MUST be backed by a search that found nothing; a search that could not reach the code is not
    that search. Separately, the scanner jobs' root enumerations (Node, .NET, Go) stopped at 6
    levels, so a root at depth 7 or 8 was DISCOVERED (its job ran) and never ENUMERATED (never
    scanned), with nothing saying so.

WHAT IT PROVES (the discovery shell run AS SHIPPED, over synthetic trees)
    D1  a tree whose only go.mod is 10 levels deep does NOT report go NOT_APPLICABLE: go is
        enabled as UNDETERMINED, the summary names the depth gap, and coverage_gaps carries
        BeyondSearchDepth
    D2  CONTROL: a shallow tree with no Go reports go NOT_APPLICABLE and declares no depth gap,
        so D1 is caused by the depth and not by the probe refusing everything
    D3  every scanner job's root enumeration in the flagship searches the same depth discovery
        does (read from both files), and declares what lies deeper

EXIT  0 all hold, 1 any does not, 2 could not run
"""
import io
import os
import re
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, HERE)
import test_discovery as td  # noqa: E402

FLAGSHIP = os.path.join(ROOT, '.github', 'workflows', 'reusable-security.yml')
COMPOSITE = os.path.join(ROOT, '.github', 'actions', 'discover', 'action.yml')
DEEP_GO = 'a/b/c/d/e/f/g/h/i/svc/go.mod'


def _shipped(path):
    """The flagship's text plus the scanner composites it calls through `$/` (ledger L64): a
    scanner's commands live there now, and reading the workflow alone would count fewer sites."""
    sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
    import _composite_expand
    return _composite_expand.shipped_text(path)


def main():
    try:
        shell = td.extract_discovery_shell()
    except SystemExit as e:
        print('UNKNOWN: %s' % e)
        return 2
    bad = []
    deep = td.run_case(shell, ['app/main.py', DEEP_GO])
    print('  D1 deep-only go: go=%s coverage_gaps=%s' % (deep.get('go'), deep.get('coverage_gaps')))
    if deep.get('go') != 'true':
        bad.append('D1 a go.mod 10 levels deep left go=%r (NOT_APPLICABLE over code never '
                   'searched)' % deep.get('go'))
    if '| go | NOT_APPLICABLE' in deep.get('__summary__', ''):
        bad.append('D1 the summary reports go NOT_APPLICABLE over a tree it did not search')
    if 'BeyondSearchDepth' not in (deep.get('coverage_gaps') or ''):
        bad.append('D1 coverage_gaps does not declare BeyondSearchDepth')
    shallow = td.run_case(shell, ['app/main.py'])
    print('  D2 shallow, no go: go=%s coverage_gaps=%s'
          % (shallow.get('go'), shallow.get('coverage_gaps')))
    if shallow.get('go') != 'false' or '| go | NOT_APPLICABLE' not in shallow.get('__summary__', ''):
        bad.append('D2 CONTROL: a shallow tree with no Go did not report go NOT_APPLICABLE')
    if 'BeyondSearchDepth' in (shallow.get('coverage_gaps') or ''):
        bad.append('D2 CONTROL: a shallow tree declared a depth gap')

    comp = io.open(COMPOSITE, encoding='utf-8').read()
    disc = set(re.findall(r'find "\$scope" -maxdepth (\d+)', comp))
    flag = _shipped(FLAGSHIP)
    enum = re.findall(r'find "\$scope" -maxdepth (\d+)[^\n]*-name (package\.json|go\.mod|\'\*\.sln\')',
                      flag)
    print('  D3 discovery depth(s) %s; enumeration %s' % (sorted(disc), enum))
    if len(disc) != 1:
        bad.append('D3 discovery uses more than one depth: %s' % sorted(disc))
    if len(enum) != 3:
        bad.append('D3 expected the Node, .NET and Go root enumerations, found %d' % len(enum))
    for depth, what in enum:
        if {depth} != disc:
            bad.append('D3 the %s enumeration searches %s levels, discovery %s'
                       % (what, depth, sorted(disc)))
    gaps = len(re.findall(r'-mindepth (\d+)', flag))
    if gaps < 3:
        bad.append('D3 only %d enumeration(s) declare what lies beyond the bound' % gaps)
    for b in bad:
        print('FAIL ' + b)
    if bad:
        return 1
    print('PASS: a language beyond the search bound is UNDETERMINED and declared, never')
    print('      NOT_APPLICABLE; enumeration searches the depth discovery does and declares deeper.')
    return 0


if __name__ == '__main__':
    sys.exit(main())

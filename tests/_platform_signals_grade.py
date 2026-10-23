#!/usr/bin/env python3
"""Grade one report against the planted-finding contract (fixture/PLATFORM_SIGNALS.json).

Not a test: the leading underscore keeps tests/prove_tests_leave_tree_clean.py from running it.
validate-scanners.yml calls it from the mobile, semgrep-kotlin, cppcheck-build and dotnet-solution
legs (lane L-SCAN-B, KDEC-026). A row passes only when THAT tool's report names a rule containing the
row's fragment on THAT file -- never "something somewhere".

Usage: _platform_signals_grade.py --signals fixture/PLATFORM_SIGNALS.json --tool mobsfscan
           --tree android --root fixture/android REPORT [REPORT ...]
REPORT is SARIF (runs[].results[]) or Semgrep JSON (results[]). Paths in a report are matched after
removing the --root prefix (absolute or relative). Exit 0 all rows found, 1 any missing, 2 unreadable.
"""
import argparse
import json
import os
import sys


def norm(p, root):
    p = p.replace('\\', '/')
    for pre in (os.path.abspath(root).replace('\\', '/') + '/', root.replace('\\', '/').rstrip('/') + '/'):
        if p.startswith(pre):
            return p[len(pre):]
    i = p.find('/' + os.path.basename(root.rstrip('/')) + '/')
    return p[i + len(os.path.basename(root.rstrip('/'))) + 2:] if i >= 0 else p.lstrip('./')


def hits(report, root):
    doc = json.load(open(report, encoding='utf-8'))
    got = {}
    for run in doc.get('runs') or []:
        for r in run.get('results') or []:
            for loc in r.get('locations') or []:
                uri = ((loc.get('physicalLocation') or {}).get('artifactLocation') or {}).get('uri', '')
                got.setdefault(norm(uri, root), set()).add(r.get('ruleId', ''))
    for r in doc.get('results') or [] if isinstance(doc.get('results'), list) else []:
        got.setdefault(norm(r.get('path', ''), root), set()).add(r.get('check_id', ''))
    return got


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--signals', required=True)
    ap.add_argument('--tool', required=True)
    ap.add_argument('--tree', required=True)
    ap.add_argument('--root', required=True)
    ap.add_argument('reports', nargs='+')
    a = ap.parse_args()
    try:
        rows = [r for r in json.load(open(a.signals, encoding='utf-8'))
                if r['tool'] == a.tool and r['tree'] == a.tree]
        got = {}
        for rep in a.reports:
            for k, v in hits(rep, a.root).items():
                got.setdefault(k, set()).update(v)
    except (OSError, ValueError, KeyError) as e:
        print('UNREADABLE: %s' % e)
        return 2
    if not rows:
        print('NO ROWS for tool %s in tree %s -- a contract with nothing in it proves nothing' % (a.tool, a.tree))
        return 1
    missing = [r for r in rows if not any(r['rule'] in x for x in got.get(r['path'], set()))]
    for r in rows:
        print('  %s %-58s %s' % ('MISSED  ' if r in missing else 'DETECTED', r['path'], r['rule']))
    print('%d of %d planted %s signal(s) in %s detected' % (len(rows) - len(missing), len(rows), a.tool, a.tree))
    return 1 if missing else 0


if __name__ == '__main__':
    sys.exit(main())

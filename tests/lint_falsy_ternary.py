#!/usr/bin/env python3
"""Fail on `cond && <falsy> || <other>` in workflow expressions: it can never yield <falsy>.

WHY THIS EXISTS (H2 / N16)

    GitHub expressions have no ternary, so `cond && a || b` is the idiom -- and it silently breaks
    when `a` is falsy. `false`, `0`, `-0`, `''` and `null` are falsy, so `cond && 0 || 1` evaluates
    to 1 whether or not `cond` holds. The kit shipped exactly that:

        fetch-depth: ${{ inputs.scan_git_history && 0 || 1 }}

    so the full-history secret scan a caller asked for never fetched the history, and the scan read
    one commit while the input said it read all of them. Quote the value (`'0'` is a non-empty string,
    so truthy) or invert the condition.

EXIT  0 none found   1 found (each printed with file:line)   2 could not be checked
"""
import glob
import io
import os
import re
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
PATTERNS = ['.github/workflows/*.yml', '.github/actions/**/*.yml', 'templates/*.yml',
            'overlays/**/*.yml']
EXPR = re.compile(r'\$\{\{(.*?)\}\}')
FALSY_THEN = re.compile(r"&&\s*(false|0|-0|''|\"\"|null)\s*\|\|")


def findings(text):
    out = []
    for i, line in enumerate(text.split('\n'), 1):
        if line.lstrip().startswith('#'):
            continue
        for m in EXPR.finditer(line):
            if FALSY_THEN.search(m.group(1)):
                out.append((i, line.strip()))
    return out


def self_test():
    bad = 'fetch-depth: ${{ inputs.x && 0 || 1 }}'
    good = "fetch-depth: ${{ inputs.x && '0' || '1' }}"
    if not findings(bad):
        return 'missed `&& 0 ||`'
    if findings(good):
        return "flagged the quoted form `&& '0' ||`, which is correct"
    for v in ('false', "''", 'null'):
        if not findings('x: ${{ a && %s || b }}' % v):
            return 'missed `&& %s ||`' % v
    return None


def main():
    err = self_test()
    if err:
        print('SELF-TEST FAILED: %s' % err)
        return 1
    hits = []
    n = 0
    for pat in PATTERNS:
        for f in sorted(glob.glob(os.path.join(ROOT, pat), recursive=True)):
            n += 1
            for line, text in findings(io.open(f, encoding='utf-8', errors='replace').read()):
                hits.append('%s:%d  %s' % (os.path.relpath(f, ROOT), line, text))
    if not n:
        print('UNKNOWN: no workflow files found.')
        return 2
    for h in hits:
        print('FAIL: %s' % h)
    if hits:
        print('`cond && <falsy> || x` always yields x. Quote the value or invert the condition.')
        return 1
    print('PASS: %d file(s), no `&& <falsy> ||` expression.' % n)
    return 0


if __name__ == '__main__':
    sys.exit(main())

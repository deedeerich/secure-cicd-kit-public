#!/usr/bin/env python3
"""A composite action's manifest must load on GitHub's parser, not only on PyYAML.

GitHub's runner refused .github/actions/known-exploited/action.yml ("Unexpected type '' encountered while
reading 'action manifest root'", hosted run 40007007260) while every local check passed: an unquoted
flow-mapping value `{description: CVE@job:fingerprint ...}` holds a colon, which PyYAML reads as text and the
runner reads as a mapping indicator. This check refuses an unquoted scalar inside a `{...}` flow mapping that
contains `:` anywhere other than the key separator.

Exit 0: every manifest is clean. Exit 1: at least one offending line. Self-test first.
"""
import glob
import io
import os
import re
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
PATTERNS = ['.github/actions/*/action.yml', '.github/actions/*/action.yaml',
            'overlays/*/actions/*/action.yml', 'overlays/*/actions/*/action.yaml']
# key: {k: value, k2: value} on one line; values split on ', <key>:' boundaries.
FLOW = re.compile(r'^\s*[A-Za-z0-9_-]+:\s*\{(.*)\}\s*(#.*)?$')
FIELD = re.compile(r'(?:^|,)\s*([A-Za-z0-9_-]+):\s*')


def offending(line):
    m = FLOW.match(line)
    if not m:
        return None
    body = m.group(1)
    starts = [(f.start(), f.end()) for f in FIELD.finditer(body)]
    for i, (_s, e) in enumerate(starts):
        end = starts[i + 1][0] if i + 1 < len(starts) else len(body)
        value = body[e:end].strip()
        if not value or value[0] in '"\'':
            continue
        if ':' in value:
            return value
    return None


def self_test():
    bad = '  x: {description: CVE@job:fingerprint for each, value: "${{ steps.k.outputs.x }}"}'
    good = '  x: {description: "CVE@job:fingerprint for each", value: "${{ steps.k.outputs.x }}"}'
    plain = '  x: {description: the day it was read, value: "${{ steps.k.outputs.x }}"}'
    return offending(bad) is not None and offending(good) is None and offending(plain) is None


def main():
    if not self_test():
        print('SELF-TEST FAILED: the check cannot tell an unquoted colon from a quoted one.')
        return 1
    files = sorted(f for p in PATTERNS for f in glob.glob(os.path.join(ROOT, p)))
    if not files:
        print('UNKNOWN: no action manifests found -- nothing was examined.')
        return 2
    bad = []
    for f in files:
        for n, line in enumerate(io.open(f, encoding='utf-8'), 1):
            v = offending(line)
            if v is not None:
                bad.append('%s:%d  %s' % (os.path.relpath(f, ROOT), n, v[:80]))
    for b in bad:
        print('FAIL: unquoted colon in a flow-mapping value  ' + b)
    if bad:
        print('Quote the value: GitHub\'s manifest parser rejects it where PyYAML accepts it.')
        return 1
    print('PASS: %d action manifest(s), no unquoted colon in a flow-mapping value.' % len(files))
    return 0


if __name__ == '__main__':
    sys.exit(main())

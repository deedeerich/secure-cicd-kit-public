#!/usr/bin/env python3
"""Every export deny pattern carries a sample it MUST match, and is proven to match it.

WHY THIS EXISTS

    scripts/export-deny.txt is the export gate's whole knowledge of what must not leave. A pattern
    that cannot match anything blocks nothing, and nothing said so: on 2026-10-16 a shell-escaped
    edit turned a regex word boundary into a literal backspace byte (0x08), so the new pattern
    matched a backspace and never the name it was written for. It compiled, it loaded, the gate
    reported CLEAN -- and it was caught only by an unrelated control-byte check. A deny pattern is
    a claim ("this name cannot leave"), and a claim with no positive control is unfalsifiable.

THE CONTRACT (checked here for every pattern in the file)
    S1  the pattern line holds no control byte (anything below 0x20 except tab)
    S2  the pattern compiles, case-insensitively, exactly as the exporter compiles it
    S3  the lines directly after it carry at least one `#+ <sample>` -- a text the pattern MUST
        match -- and a pattern with none fails by name
    S4  it matches every `#+` sample, and matches no `#- <sample>` (an optional NEGATIVE sample:
        text it must leave alone, e.g. the public service name a lookbehind exists to spare)

    The samples sit beside the pattern in the file that never ships (the exporter excludes it by
    name), so they disclose nothing the pattern does not. They start with '#', so the exporter and
    check_export_safety read them as comments and nothing about the gate itself changes.

SELF-TEST (the proof that this check can fail)
    Before checking the real file, three corrupted copies are run through the same function and
    each must be refused: one pattern's sample removed (S3), one pattern's `\\b` replaced by the
    0x08 byte that caused the incident (S1, and S4 -- it no longer matches its sample), and one
    sample swapped for text the pattern does not match (S4).

USAGE  python3 tests/prove_deny_samples.py [path-to-deny-file]
EXIT   0 every pattern proven, 1 any is not, 2 the file could not be read
"""
import os
import re
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DENY = os.path.join(ROOT, 'scripts', 'export-deny.txt')
NEVER_LIFT = '!'


def check(text):
    """-> (patterns checked, list of failures) for the deny-file TEXT."""
    lines = text.splitlines()
    fails, n = [], 0
    for i, raw in enumerate(lines):
        line = raw.strip()
        if not line or line.startswith('#'):
            continue
        n += 1
        pat = line.partition('||')[0].strip()
        if pat.startswith(NEVER_LIFT):
            pat = pat[len(NEVER_LIFT):].strip()
        where = 'line %d (%r)' % (i + 1, pat[:40])
        bad = [c for c in raw if ord(c) < 0x20 and c != '\t']
        if bad:
            fails.append('S1 %s holds control byte(s) %s' % (
                where, ', '.join('0x%02x' % ord(c) for c in bad)))
        try:
            rx = re.compile(pat, re.I)
        except re.error as e:
            fails.append('S2 %s does not compile: %s' % (where, e))
            continue
        pos, neg = [], []
        for nxt in lines[i + 1:]:
            s = nxt.strip()
            if s.startswith('#+'):
                pos.append(s[2:].strip())
            elif s.startswith('#-'):
                neg.append(s[2:].strip())
            else:
                break
        if not pos:
            fails.append('S3 %s has no `#+` sample it must match' % where)
        for s in pos:
            if not rx.search(s):
                fails.append('S4 %s does not match its own sample %r' % (where, s))
        for s in neg:
            if rx.search(s):
                fails.append('S4 %s matches %r, which it must leave alone' % (where, s))
    return n, fails


def self_test(text):
    """Each corruption must be refused, or this check proves nothing."""
    lines = text.splitlines()
    plus = [i for i, l in enumerate(lines) if l.strip().startswith('#+')]
    bound = [i for i, l in enumerate(lines)
             if l.strip() and not l.strip().startswith('#') and '\\b' in l]
    problems = []
    if not plus or not bound:
        return ['the file has no sample or no \\b pattern to corrupt; the self-test cannot run']
    # 1. remove every sample of the first pattern that has exactly one
    first = plus[0]
    dropped = '\n'.join(l for j, l in enumerate(lines) if j != first)
    if not any(f.startswith('S3') for f in check(dropped)[1]):
        problems.append('a pattern with its only sample removed was not refused (S3)')
    # 2. the incident: a word boundary turned into the backspace byte
    corrupt = list(lines)
    corrupt[bound[0]] = corrupt[bound[0]].replace('\\b', '\x08', 1)
    got = check('\n'.join(corrupt))[1]
    if not any(f.startswith('S1') for f in got) or not any(f.startswith('S4') for f in got):
        problems.append('a \\b replaced by 0x08 was not refused as both S1 and S4: %r' % got[:3])
    # 3. a sample the pattern does not match
    swapped = list(lines)
    swapped[first] = '#+ zz-nothing-matches-this-zz'
    if not any(f.startswith('S4') for f in check('\n'.join(swapped))[1]):
        problems.append('a sample the pattern does not match was not refused (S4)')
    return problems


def main(argv):
    path = argv[1] if len(argv) > 1 else DENY
    try:
        text = open(path, encoding='utf-8').read()
    except OSError as e:
        print('UNKNOWN: cannot read %s: %s' % (path, e))
        return 2
    n, fails = check(text)
    if n == 0:
        print('FAIL: %s holds no pattern; a deny list with nothing in it checks nothing' % path)
        return 1
    problems = [] if fails else self_test(text)
    for f in fails:
        print('FAIL ' + f)
    for p in problems:
        print('SELF-TEST FAILED: ' + p)
    if fails or problems:
        return 1
    print('PASS: %d deny pattern(s); each is free of control bytes, compiles, and matches its own'
          % n)
    print('      sample(s) and none of its negative samples. Self-test: a missing sample, a \\b')
    print('      turned into 0x08 and a non-matching sample are each refused.')
    return 0


if __name__ == '__main__':
    sys.exit(main(sys.argv))

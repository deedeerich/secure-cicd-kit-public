#!/usr/bin/env python3
"""Every kit variable and secret has a row in docs/adoption/SETTINGS_PRECEDENCE.md. (owner 2026-11-07)

WHY THIS EXISTS
    GitHub resolves a variable or secret at its lowest level (environment > repository > organisation), so a
    repository can shadow an organisation value. The owner asked for an explicit table of every kit secret and
    variable: the level it belongs at, what wins, and what the kit does when it is shadowed. A table that misses
    a name a workflow reads is a setting nobody placed. This holds the table to the tree:

    S1  every `vars.NAME` and `secrets.NAME` read in .github/, templates/ and overlays/*/ appears in the table
        (by its exact name, or by a listed prefix such as KIT_API_EXTENSION_*)
    S2  the governed names (KIT_APPROVER_POOLS, KIT_APP_TEAM, KIT_SMALL_TEAM_SELF_APPROVAL, KIT_CLOUD) say
        "org overlay" or "never set it" in their row
    S3  the document quotes GitHub's precedence rule and cites the pages with a retrieval date
    --self-test  a name missing from the table, and a governed row without its level, are each refused

EXIT 0 holds   1 a rule refused   2 the document is missing
"""
import glob
import io
import os
import re
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
DOC = os.path.join('docs', 'adoption', 'SETTINGS_PRECEDENCE.md')
NAME_RX = re.compile(r'\b(?:vars|secrets)\.([A-Z][A-Z0-9_]*[A-Z0-9])\b')
GOVERNED = {'KIT_APPROVER_POOLS': 'org overlay', 'KIT_APP_TEAM': 'org overlay',
            'KIT_SMALL_TEAM_SELF_APPROVAL': 'never set it', 'KIT_CLOUD': 'org overlay'}


def names(root):
    out = set()
    for pat in ('.github/**/*.yml', 'templates/*.yml', 'overlays/*/**/*.yml'):
        for p in glob.glob(os.path.join(root, pat), recursive=True):
            out |= set(NAME_RX.findall(io.open(p, encoding='utf-8', errors='replace').read()))
    return out


def problems(root, doc_text):
    probs = []
    rows = [ln for ln in doc_text.splitlines() if ln.startswith('| `')]
    table = '\n'.join(rows)
    prefixes = re.findall(r'`([A-Z][A-Z0-9_]*_)\*`', table)
    for n in sorted(names(root)):
        if '`%s`' % n in table or any(n.startswith(p) for p in prefixes):
            continue
        probs.append('S1 %s is read by the kit and has no row in %s' % (n, DOC))
    for n, level in GOVERNED.items():
        row = next((r for r in rows if r.startswith('| `%s`' % n)), '')
        if level not in row:
            probs.append('S2 the row for %s does not say %r' % (n, level))
    for need in ('the variable at the lowest level takes precedence', 'docs.github.com', 'retrieved 2026-11-07'):
        if need not in ' '.join(doc_text.split()):
            probs.append('S3 the document does not carry %r' % need)
    return probs


def self_test():
    text = io.open(os.path.join(ROOT, DOC), encoding='utf-8').read()
    bad = 0
    # The S1 mutant hides a name THIS tree reads (an overlay-free release tree does not read ZAP_TARGET).
    read = sorted(names(ROOT))
    victim = 'ZAP_TARGET' if 'ZAP_TARGET' in read else (read[0] if read else None)
    if victim is None:
        bad += 1
    else:
        m1 = text.replace('`%s`' % victim, '`%sX`' % victim)
        bad += not any(('S1 %s ' % victim) in p for p in problems(ROOT, m1))
    m2 = text.replace('| `KIT_APP_TEAM` | variable | **org overlay**', '| `KIT_APP_TEAM` | variable | repository')
    bad += not any(p.startswith('S2 the row for KIT_APP_TEAM') for p in problems(ROOT, m2))
    print('check_settings_precedence selftest %s' % ('ok: 2 mutants refused' if not bad else 'FAILED'))
    return 0 if not bad else 1


def main(argv):
    p = os.path.join(ROOT, DOC)
    if not os.path.exists(p):
        print('UNKNOWN: %s is missing' % DOC)
        return 2
    if '--self-test' in argv:
        return self_test()
    probs = problems(ROOT, io.open(p, encoding='utf-8').read())
    for x in probs:
        print('FAIL: ' + x)
    if probs:
        return 1
    print('PASS: every kit variable and secret (%d names) has its level, what wins and what happens when it is '
          'shadowed in %s.' % (len(names(ROOT)), DOC))
    return 0


if __name__ == '__main__':
    sys.exit(main(sys.argv[1:]))

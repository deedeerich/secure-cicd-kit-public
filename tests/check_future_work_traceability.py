#!/usr/bin/env python3
"""Every section of the roadmap must be tracked by the completion ledger, or say why it is not.

WHY THIS EXISTS

    The owner asked for Dependabot auto-merge more than twice. It is designed, in full, in
    docs/roadmap/FUTURE_WORK.md section 6. The completion ledger (docs/assurance/COMPLETION_LEDGER.md)
    is the list release lanes are planned from, and it had no row for it, so no lane was ever given
    it and it was never built. A numeric check on 2026-10-22 (commit 2cd078e) found that sections 2
    (cost), 3 (findings management), 4 (presentation), 6 (auto-merge) and 8 (distribution and IP)
    were never cited by any ledger row, and that D6 was cited by none either.

    Nothing compared the two documents, so a design could be written, agreed and then fall out of
    the plan without any check turning red. A roadmap the plan does not read is not a roadmap.

WHAT THIS CHECKS

    1. Every `## N <middle dot> Title` section and every `### Dn <middle dot> Title` subsection of
       FUTURE_WORK is cited in the DESIGNED column (the second cell) of at least one ledger row, as
       `FW \u00a7N` / `FW-\u00a7N` / `FUTURE_WORK \u00a7N` or `FW Dn`, OR is listed in the exemption table of
       docs/assurance/FUTURE_WORK_TRACEABILITY.md with a reason of at least 20 characters. A
       subsection citation does NOT cover its parent section: D5 being tracked said nothing about
       D1-D4, which is exactly how section 3 went untracked.
    2. A citation anywhere else in a row (the built or closes column, the D-01 stale-document list)
       does not count. Naming a section as stale is not tracking its work.
    3. Reverse direction: a ledger DESIGNED citation of a section or subsection that does not exist
       in FUTURE_WORK fails (a row pointing at nothing).
    4. An exemption for a section a ledger row now cites fails (delete it), as does an exemption
       for a section that does not exist.
    5. The traceability file must exist and name every section and subsection in its table, so a
       new roadmap section cannot be added without a traceability decision.

    The seeded cases in self_test() run first on every invocation; a matcher that stopped matching
    turns this red before the real check can report clean.

USAGE
    python -I tests/check_future_work_traceability.py [--root <repo>]

EXIT
    0  every section is tracked or exempted with a reason
    1  a section is untracked, a citation points at nothing, or an exemption is stale
    2  the seeded self-test failed
"""
import argparse
import io
import os
import re
import sys

FW_PATH = 'docs/roadmap/FUTURE_WORK.md'
LEDGER_PATH = 'docs/assurance/COMPLETION_LEDGER.md'
TRACE_PATH = 'docs/assurance/FUTURE_WORK_TRACEABILITY.md'

MIDDOT = '\u00b7'
SECTION_RX = re.compile(r'^##\s+(\d+)\s*' + MIDDOT + r'\s*\S', re.M)
SUBSECTION_RX = re.compile(r'^###\s+(D\d+)\s*' + MIDDOT + r'\s*\S', re.M)
# A citation inside a DESIGNED cell. `FW \u00a73`, `FW-\u00a73`, `FW \u00a73.2`, `FUTURE_WORK \u00a73`, `FW D5`.
CITE_SECTION_RX = re.compile(r'\b(?:FW|FUTURE_WORK)\s*-?\s*\u00a7\s*(\d+)')
CITE_SUB_RX = re.compile(r'\b(?:FW|FUTURE_WORK)\s*-?\s*(D\d+)\b')
EXEMPT_HEADING = 'Sections not tracked by a ledger row'
MIN_REASON = 20


def _read(root, rel):
    p = os.path.join(root, rel)
    if not os.path.exists(p):
        return None
    return io.open(p, encoding='utf-8', errors='replace').read().replace('\r\n', '\n')


def _cells(line):
    s = line.strip()
    if not (s.startswith('|') and s.endswith('|')):
        return None
    return [c.strip() for c in s[1:-1].split('|')]


def fw_ids(fw_text):
    """-> ordered list of ids: '\u00a7N' for sections, 'Dn' for subsections."""
    found = []
    for m in re.finditer(r'(?m)^#{2,3}\s.*$', fw_text):
        line = m.group(0)
        s = SECTION_RX.match(line)
        d = SUBSECTION_RX.match(line)
        if s and line.startswith('## '):
            found.append('\u00a7' + s.group(1))
        elif d:
            found.append(d.group(1))
    return found


def ledger_citations(ledger_text):
    """-> {id: [row ids]} from the DESIGNED (second) cell of every table row with an id cell.

    Only the ledger proper counts: when the text has a `## 2 ` section (the ledger's tables), rows
    outside it -- the lane plan, the design candidates, the owner decisions -- are not rows that
    track work, and a section named there is not tracked."""
    cites = {}
    m = re.search(r'(?m)^## 2 .*$', ledger_text)
    if m:
        rest = ledger_text[m.end():]
        n = re.search(r'(?m)^## ', rest)
        ledger_text = rest[:n.start()] if n else rest
    for line in ledger_text.split('\n'):
        cells = _cells(line)
        if not cells or len(cells) < 3:
            continue
        row_id, designed = cells[0], cells[1]
        if not row_id or set(row_id) <= set('-: ') or row_id.lower() in ('id', '#', 'state', 'lane'):
            continue
        for m in CITE_SECTION_RX.finditer(designed):
            cites.setdefault('\u00a7' + m.group(1), []).append(row_id)
        for m in CITE_SUB_RX.finditer(designed):
            cites.setdefault(m.group(1), []).append(row_id)
    return cites


def trace_table(trace_text):
    """-> (ids named in any first table cell, {exempt id: reason})."""
    named, exempt = set(), {}
    in_exempt = False
    for line in trace_text.split('\n'):
        if line.startswith('#'):
            in_exempt = EXEMPT_HEADING.lower() in line.lower()
            continue
        cells = _cells(line)
        if not cells:
            continue
        first = cells[0].replace('*', '').replace('`', '').strip()
        m = re.match(r'^(\u00a7\d+|D\d+)\b', first)
        if not m:
            continue
        named.add(m.group(1))
        if in_exempt:
            exempt[m.group(1)] = cells[1] if len(cells) > 1 else ''
    return named, exempt


def check(fw_text, ledger_text, trace_text):
    problems = []
    ids = fw_ids(fw_text)
    if not ids:
        return ['FUTURE_WORK has no `## N %s` section: the matcher or the document changed' % MIDDOT]
    cites = ledger_citations(ledger_text)
    if trace_text is None:
        problems.append('%s does not exist: every roadmap section needs a traceability decision' % TRACE_PATH)
        named, exempt = set(), {}
    else:
        named, exempt = trace_table(trace_text)
    for i in ids:
        tracked = i in cites
        if not tracked and i not in exempt:
            problems.append('FUTURE_WORK %s is cited by no ledger row\'s designed column and is not '
                            'exempted with a reason in %s' % (i, TRACE_PATH))
        if i in exempt:
            if tracked:
                problems.append('%s is exempted but ledger row(s) %s now track it: delete the exemption'
                                % (i, ', '.join(cites[i])))
            elif len(exempt[i]) < MIN_REASON:
                problems.append('%s is exempted without a reason (at least %d characters)' % (i, MIN_REASON))
        if trace_text is not None and i not in named:
            problems.append('%s is not named in the traceability table of %s' % (i, TRACE_PATH))
    for c, rows in sorted(cites.items()):
        if c not in ids:
            problems.append('ledger row(s) %s cite FUTURE_WORK %s, which does not exist' % (', '.join(rows), c))
    for e in sorted(exempt):
        if e not in ids:
            problems.append('exemption %s names a section FUTURE_WORK does not have' % e)
    return problems


def self_test():
    fw = ('# t\n\n## 1 \u00b7 One\n\ntext\n\n## 2 \u00b7 Two\n\n### D5 \u00b7 Five\n\n'
          '### Not a sub\n\n## 3 \u00b7 Three\n')
    hdr = '| id | designed | built |\n|---|---|---|\n'
    trace_all = '| \u00a71 | a |\n| \u00a72 | b |\n| D5 | c |\n| \u00a73 | d |\n'
    full = hdr + '| A-1 | FW \u00a71 | x |\n| A-2 | FW-\u00a72; other | x |\n| A-3 | FW D5 | x |\n| A-4 | FUTURE_WORK \u00a73 | x |\n'
    cases = [
        ('every section cited passes', fw, full, trace_all, 0),
        ('a missing section fails', fw, hdr + '| A-1 | FW \u00a71 | x |\n| A-2 | FW \u00a72 | x |\n| A-3 | FW D5 | x |\n',
         trace_all, 1),
        ('a citation outside ledger section 2 does not count', fw,
         '## 2 \u00b7 The ledger\n\n' + hdr + '| A-1 | FW \u00a71 | x |\n| A-2 | FW \u00a72 | x |\n| A-3 | FW D5 | x |\n'
         '\n## 6 \u00b7 Owner decisions\n\n| O-1 | FW \u00a73 | x |\n', trace_all, 1),
        ('section 2 rows count when the ledger has sections', fw,
         '## 2 \u00b7 The ledger\n\n' + full + '\n## 6 \u00b7 Owner decisions\n\n| O-1 | FW \u00a79 | x |\n', trace_all, 0),
        ('a subsection does not cover its parent', fw,
         hdr + '| A-1 | FW \u00a71 | x |\n| A-3 | FW D5 | x |\n| A-4 | FW \u00a73 | x |\n', trace_all, 1),
        ('a citation outside the designed column does not count', fw,
         hdr + '| A-1 | FW \u00a71 | FW \u00a72 |\n| A-3 | FW D5 | x |\n| A-4 | FW \u00a73 | x |\n', trace_all, 1),
        ('an untracked subsection fails', fw,
         hdr + '| A-1 | FW \u00a71 | x |\n| A-2 | FW \u00a72 | x |\n| A-4 | FW \u00a73 | x |\n', trace_all, 1),
        ('an exemption with a reason passes', fw,
         hdr + '| A-1 | FW \u00a71 | x |\n| A-3 | FW D5 | x |\n| A-4 | FW \u00a73 | x |\n',
         trace_all + '\n## Sections not tracked by a ledger row\n\n| id | reason |\n|---|---|\n'
         '| \u00a72 | doctrine only, no build obligation; see the summary |\n', 0),
        ('an exemption without a reason fails', fw,
         hdr + '| A-1 | FW \u00a71 | x |\n| A-3 | FW D5 | x |\n| A-4 | FW \u00a73 | x |\n',
         trace_all + '\n## Sections not tracked by a ledger row\n\n| \u00a72 | tbd |\n', 1),
        ('a stale exemption fails', fw, full,
         trace_all + '\n## Sections not tracked by a ledger row\n\n| \u00a72 | doctrine only, no build obligation |\n', 1),
        ('a citation of a missing section fails', fw, full + '| A-5 | FW \u00a79 | x |\n', trace_all, 1),
        ('a missing traceability file fails', fw, full, None, 1),
        ('a section absent from the traceability table fails', fw, full,
         '| \u00a71 | a |\n| \u00a72 | b |\n| D5 | c |\n', 1),
        ('no sections at all fails (matcher drift)', '# t\n## One\n', full, trace_all, 1),
    ]
    bad = []
    for name, f, l, t, want in cases:
        got = 1 if check(f, l, t) else 0
        if got != want:
            bad.append('%s: expected %s, got %s (%s)' % (name, want, got, check(f, l, t)))
    return bad


def _out(s):
    # Windows consoles mangle the section sign; the report is read there too.
    print(s.replace('\u00a7', 'sec. '))


def main():
    ap = argparse.ArgumentParser(description=__doc__.split('\n')[0])
    ap.add_argument('--root', default=os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    a = ap.parse_args()
    bad = self_test()
    if bad:
        for b in bad:
            _out('SELF-TEST FAIL: ' + b)
        return 2
    print('self-test: 14 seeded cases held')
    fw = _read(a.root, FW_PATH)
    ledger = _read(a.root, LEDGER_PATH)
    if fw is None or ledger is None:
        print('FAIL: %s or %s is missing' % (FW_PATH, LEDGER_PATH))
        return 1
    problems = check(fw, ledger, _read(a.root, TRACE_PATH))
    ids = fw_ids(fw)
    if problems:
        for p in problems:
            _out('FAIL: ' + p)
        print('%d problem(s) over %d FUTURE_WORK sections and subsections' % (len(problems), len(ids)))
        return 1
    print('OK: %d FUTURE_WORK sections and subsections, each tracked by a ledger row or exempted with '
          'a reason' % len(ids))
    return 0


if __name__ == '__main__':
    sys.exit(main())

#!/usr/bin/env python3
"""Every register entry carries suggested mitigations; none is marked done without evidence and an approver.

WHY THIS EXISTS (owner, 2026-11-06)
    "Put a mitigations piece to the risk; do not assign them as completed yet, but make it part of our risk
    and decisions registers that we always have suggestions on what could fix/mitigate it."

THE REGISTERS (REGISTERS below)
    .context/products/secure-cicd-kit/decisions.md   ## KDEC-NNN entries
    .context/products/secure-cicd-kit/risks.md       ## R-NN entries
    docs/KNOWN_DEFECTS.md                            ## D-NN entries

THE FIELD, in each entry's section (before the next `## ` heading)
    **Suggested mitigations** (...free text...):
    - M1 PROPOSED — a concrete option
    - M2 COMPLETED — what was done — evidence: <run id, commit or document> — approved by: <role or login> — 2026-11-30

RULES
    R1  an entry with no `**Suggested mitigations**` block, or a block with no `- M<n> <STATUS> — text`
        line, is refused (a new entry cannot land without the field)
    R2  STATUS is one of PROPOSED, ACCEPTED, IN_PROGRESS, COMPLETED, DECLINED
    R3  COMPLETED needs a non-empty `evidence:` and a non-empty `approved by:`
    R4  the approver of a COMPLETED mitigation is a person or a role, never an automation (an agent, a bot,
        github-actions, dependabot): nothing is auto-marked complete
    R5  mitigation ids are unique within an entry

USAGE  python3 scripts/check_register_mitigations.py [--root DIR]   |   --self-test
EXIT   0 every entry holds   1 a rule refused (each named)   2 a register could not be read
"""
import argparse
import io
import os
import re
import sys

REGISTERS = [
    ('.context/products/secure-cicd-kit/decisions.md', r'KDEC-\d{3}'),
    ('.context/products/secure-cicd-kit/risks.md', r'R-\d{2}'),
    ('docs/KNOWN_DEFECTS.md', r'D-\d{1,3}'),
]
STATUSES = ('PROPOSED', 'ACCEPTED', 'IN_PROGRESS', 'COMPLETED', 'DECLINED')
FIELD = '**Suggested mitigations**'
LINE = re.compile(r'^\s*-\s+(M\d+)\s+([A-Z_]+)\s+[—-]+\s+(.+)$')
AUTOMATION = re.compile(r'(?i)\b(claude|agent|bot|github-actions|dependabot|automation|automated|copilot|ai|llm|script)\b')


def sections(text, id_rx):
    """-> [(entry id, heading line no, section lines)] for each `## <id>` heading."""
    lines = text.splitlines()
    head = re.compile(r'^##\s+(%s)\b' % id_rx)
    out, cur = [], None
    for n, ln in enumerate(lines, 1):
        if ln.startswith('## '):
            if cur:
                out.append(cur)
            m = head.match(ln)
            cur = (m.group(1), n, []) if m else None
            continue
        if cur:
            cur[2].append(ln)
    if cur:
        out.append(cur)
    return out


def entry_problems(eid, body):
    probs = []
    try:
        i = next(k for k, ln in enumerate(body) if ln.strip().startswith(FIELD))
    except StopIteration:
        return ['%s has no %s field (R1)' % (eid, FIELD)]
    items, seen = [], set()
    for ln in body[i + 1:]:
        if not ln.strip():
            if items:
                break
            continue
        m = LINE.match(ln)
        if not m:
            if items and ln.startswith('  '):
                items[-1] = (items[-1][0], items[-1][1], items[-1][2] + ' ' + ln.strip())
                continue
            break
        items.append((m.group(1), m.group(2), m.group(3)))
    if not items:
        return ['%s: its %s block lists no `- M<n> <STATUS> — text` line (R1)' % (eid, FIELD)]
    for mid, status, text in items:
        if mid in seen:
            probs.append('%s %s: the id is used twice (R5)' % (eid, mid))
        seen.add(mid)
        if status not in STATUSES:
            probs.append('%s %s: status %s is not one of %s (R2)' % (eid, mid, status, ', '.join(STATUSES)))
            continue
        if status == 'COMPLETED':
            ev = re.search(r'evidence:\s*([^—]+?)\s*(?:—|$)', text)
            ap = re.search(r'approved by:\s*([^—]+?)\s*(?:—|$)', text)
            if not ev or not ev.group(1).strip():
                probs.append('%s %s: COMPLETED with no evidence reference (R3)' % (eid, mid))
            if not ap or not ap.group(1).strip():
                probs.append('%s %s: COMPLETED with no approver (R3)' % (eid, mid))
            elif AUTOMATION.search(ap.group(1)):
                probs.append('%s %s: COMPLETED approved by %r, an automation; a person or role approves (R4)'
                             % (eid, mid, ap.group(1).strip()))
    return probs


def check(root):
    problems, counts = [], {}
    for rel, rx in REGISTERS:
        p = os.path.join(root, *rel.split('/'))
        try:
            text = io.open(p, encoding='utf-8').read()
        except OSError as e:
            return None, ['%s could not be read (%s)' % (rel, e)]
        secs = sections(text, rx)
        counts[rel] = len(secs)
        if not secs:
            problems.append('%s holds no entry matching %s' % (rel, rx))
        for eid, _n, body in secs:
            problems += ['%s: %s' % (rel, x) for x in entry_problems(eid, body)]
    return counts, problems


def self_test():
    ok = 'body\n\n**Suggested mitigations** (x):\n- M1 PROPOSED — do a thing\n'
    cases = [
        ('a proposed mitigation', ok, []),
        ('a completed one with evidence and a person', ok.replace('- M1 PROPOSED — do a thing',
         '- M1 COMPLETED — did it — evidence: run 123 — approved by: security-lead — 2026-11-30'), []),
        ('no field', 'body\n', ['R1']),
        ('an empty block', 'body\n\n**Suggested mitigations**:\n\nnext\n', ['R1']),
        ('an unknown status', ok.replace('PROPOSED', 'DONE'), ['R2']),
        ('completed without evidence', ok.replace('- M1 PROPOSED — do a thing',
         '- M1 COMPLETED — did it — approved by: security-lead'), ['R3']),
        ('completed without an approver', ok.replace('- M1 PROPOSED — do a thing',
         '- M1 COMPLETED — did it — evidence: run 1'), ['R3']),
        ('completed by an agent', ok.replace('- M1 PROPOSED — do a thing',
         '- M1 COMPLETED — did it — evidence: run 1 — approved by: claude'), ['R4']),
        ('a duplicate id', ok + '- M1 PROPOSED — again\n', ['R5']),
    ]
    bad = []
    for label, body, want in cases:
        got = entry_problems('X-1', body.splitlines())
        rules = sorted(set(re.findall(r'\((R\d)\)', ' '.join(got))))
        if rules != sorted(set(want)):
            bad.append('%s: wanted %s, got %s %s' % (label, want, rules, got))
    for b in bad:
        print('SELF-TEST FAIL: %s' % b)
    print('self-test %s: %d cases' % ('FAILED' if bad else 'ok', len(cases)))
    return 1 if bad else 0


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.split('\n')[0])
    ap.add_argument('--root', default=os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    ap.add_argument('--self-test', action='store_true')
    a = ap.parse_args(argv)
    if a.self_test:
        return self_test()
    counts, problems = check(a.root)
    if counts is None:
        print('UNKNOWN: %s' % problems[0])
        return 2
    for p in problems:
        print('REFUSED: %s' % p)
    if problems:
        print('FAIL: %d problem(s). Every entry needs suggested mitigations; none is COMPLETED without '
              'evidence and a human approver.' % len(problems))
        return 1
    print('PASS: %s -- every entry carries suggested mitigations, none completed without evidence and an approver.'
          % ', '.join('%s %d' % (os.path.basename(k), v) for k, v in counts.items()))
    return 0


if __name__ == '__main__':
    sys.exit(main())

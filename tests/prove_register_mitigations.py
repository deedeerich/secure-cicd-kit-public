#!/usr/bin/env python3
"""Every decision, risk and defect entry carries suggested mitigations; none is completed by silence.

WHY THIS EXISTS (owner, 2026-11-06): "put a mitigations piece to the risk; do not assign them as completed yet,
but make it part of our risk and decisions registers that we always have suggestions on what could
fix/mitigate it." scripts/check_register_mitigations.py holds the three registers to that.

  POSITIVE
    G1  the real registers pass: every KDEC, R and D entry has at least one PROPOSED mitigation
    G2  a mitigation moved to COMPLETED with an evidence reference and a human approver is accepted
  NEGATIVE (each on a copy of the real registers)
    G3  a new decision entry without the field is refused (R1)
    G4  a mitigation moved to COMPLETED without evidence is refused (R3); without an approver (R3)
    G5  a mitigation COMPLETED with an automation as approver is refused (R4)
    G6  the checker's own self-test (nine cases, one per rule and its control)

EXIT 0 all hold   1 any does not   2 a register could not be read
"""
import io
import os
import shutil
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
CHECK = os.path.join(ROOT, 'scripts', 'check_register_mitigations.py')
DEC = '.context/products/secure-cicd-kit/decisions.md'
FAILS = []


def check(cond, label, detail=''):
    print('  %s %s%s' % ('ok  ' if cond else 'FAIL', label, ('  -- ' + str(detail)[-400:]) if detail and not cond else ''))
    if not cond:
        FAILS.append(label)


def run(root, *extra):
    p = subprocess.run([sys.executable, CHECK, '--root', root] + list(extra), capture_output=True, text=True,
                       encoding='utf-8', errors='replace')
    return p.returncode, p.stdout + p.stderr


def copy_tree():
    d = tempfile.mkdtemp(prefix='regmit-')
    for rel in ('.context/products/secure-cicd-kit/decisions.md', '.context/products/secure-cicd-kit/risks.md',
                'docs/KNOWN_DEFECTS.md'):
        t = os.path.join(d, *rel.split('/'))
        os.makedirs(os.path.dirname(t), exist_ok=True)
        shutil.copyfile(os.path.join(ROOT, *rel.split('/')), t)
    return d


def edit(d, rel, old, new):
    p = os.path.join(d, *rel.split('/'))
    s = io.open(p, encoding='utf-8').read()
    assert old in s, old
    io.open(p, 'w', encoding='utf-8', newline='\n').write(s.replace(old, new, 1))


def main():
    # SOURCE-ONLY CONTROL (2026-11-06, public run 42317591967): the registers live under .context/, which
    # a neutral export never carries (prove_export_scope.py E2). In an exported copy -- its watermark
    # present and .context/ absent -- there is nothing to check: said by name, never a pass. E9.
    if (os.path.isfile(os.path.join(ROOT, '.neutral-export-watermark.json'))
            and not os.path.isdir(os.path.join(ROOT, '.context'))):
        print('SOURCE-ONLY CONTROL: prove_register_mitigations.py guards the source repository registers '
              'under .context/. This is an exported copy (.neutral-export-watermark.json present) '
              'and, by design, carries no .context/; the source ran it at the commit the watermark records. '
              'Nothing was checked here, and nothing passed.')
        return 0
    print('Register mitigations (scripts/check_register_mitigations.py):')
    rc, out = run(ROOT)
    check(rc == 0, 'G1 the real registers pass', out)
    rc, out = run(ROOT, '--self-test')
    check(rc == 0, 'G6 the checker\'s self-test', out)
    first = '- M1 PROPOSED — Keep a design-to-code trace table'
    for label, new, want_rc, want in [
        ('G2 COMPLETED with evidence and a human approver is accepted',
         '- M1 COMPLETED — Keep a design-to-code trace table — evidence: commit abc1234 — approved by: kit owner — 2026-11-30 —', 0, ''),
        ('G4 COMPLETED without evidence is refused', '- M1 COMPLETED — Keep a design-to-code trace table — approved by: kit owner —', 1, '(R3)'),
        ('G4 COMPLETED without an approver is refused', '- M1 COMPLETED — Keep a design-to-code trace table — evidence: run 42 —', 1, '(R3)'),
        ('G5 COMPLETED approved by an automation is refused',
         '- M1 COMPLETED — Keep a design-to-code trace table — evidence: run 42 — approved by: github-actions —', 1, '(R4)'),
    ]:
        d = copy_tree()
        try:
            edit(d, DEC, first, new)
            rc, out = run(d)
            check(rc == want_rc and want in out, label, out)
        finally:
            shutil.rmtree(d, ignore_errors=True)
    d = copy_tree()
    try:
        p = os.path.join(d, *DEC.split('/'))
        io.open(p, 'a', encoding='utf-8').write('\n## KDEC-999 — A new decision\n**Status:** PROPOSED\n**Decision:** something.\n')
        rc, out = run(d)
        check(rc == 1 and 'KDEC-999 has no **Suggested mitigations** field (R1)' in out, 'G3 a new entry without the field is refused', out)
    finally:
        shutil.rmtree(d, ignore_errors=True)
    if FAILS:
        print('FAIL: %d claim(s)' % len(FAILS))
        return 1
    print('PASS: every register entry suggests mitigations, and none is completed without evidence and a person.')
    return 0


if __name__ == '__main__':
    sys.exit(main())

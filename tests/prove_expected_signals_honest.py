#!/usr/bin/env python3
"""verify_expected_signals.py must not grade a fixture file that was never in the scanned tree.

WHY THIS EXISTS

    tests/consumer-fixture/full/secrets/ is GENERATED (tests/make_fixture.py) and git-ignored,
    on purpose: a credential shape must not be committed. The consumer path, though, scans a
    CHECKOUT -- so those files are not on the runner at all. Hosted run 38779788549 then said:

        CLEAN-OK    negative:no-false-positive     secrets/negative_controls.md
        MISSED      secret:azure-storage-connection-string   secrets/azure_storage.txt

    Both lines are false in the same way. The negative control did not pass -- nothing was there
    to be flagged. The three secret signals were not missed by gitleaks -- gitleaks was never
    shown them (its log: "scan completed in 10.6ms ... no leaks found" over 21 committed files).
    "MISSED" sent the investigation into the gitleaks rules; "CLEAN-OK" counted a vacuous pass.
    A verifier that cannot tell "the scanner did not see it" from "it was never there" grades
    the fixture's delivery as the scanner's detection.

THE RULE
    An expectation whose file is absent from --fixture is ABSENT: never DETECTED, MISSED or
    CLEAN-OK. ABSENT fails the run (a planted condition that was not planted proves nothing) and
    is reported apart from MISSED, naming the cause.

EXIT
    0  absent files are reported as ABSENT, present ones are graded as before
    1  the verifier graded an absent file
    2  could not be checked -- UNKNOWN, never PASS
"""
import json
import os
import shutil
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
VERIFY = os.path.join(HERE, 'verify_expected_signals.py')


def write(p, text):
    os.makedirs(os.path.dirname(p), exist_ok=True)
    open(p, 'w', encoding='utf-8', newline='\n').write(text)


def main():
    if not os.path.isfile(VERIFY):
        print('UNKNOWN: %s is missing.' % VERIFY)
        return 2
    d = tempfile.mkdtemp(prefix='expected-signals-')
    bad = []
    try:
        fx, sd = os.path.join(d, 'fixture'), os.path.join(d, 'sarif', 'sarif-probe-1')
        write(os.path.join(fx, 'present/vuln.py'), 'x = 1\n')
        write(os.path.join(fx, 'present/quiet.md'), 'nothing\n')
        write(os.path.join(fx, 'EXPECTED_SIGNALS.json'), json.dumps([
            {'path': 'present/vuln.py', 'expected_signal': 'sast:present'},
            {'path': 'present/quiet.md', 'expected_signal': 'negative:present-quiet'},
            {'path': 'gone/secret.txt', 'expected_signal': 'secret:gone'},
            {'path': 'gone/negative.md', 'expected_signal': 'negative:gone'},
        ]))
        write(os.path.join(sd, 'probe.sarif'), json.dumps({'runs': [{'results': [
            {'ruleId': 'r', 'locations': [{'physicalLocation': {'artifactLocation': {
                'uri': 'fixture/present/vuln.py'}}}]}]}]}))
        p = subprocess.run([sys.executable, VERIFY, '--fixture', fx, '--sarif-dir',
                            os.path.join(d, 'sarif')], capture_output=True, text=True,
                           encoding='utf-8', errors='replace', cwd=d)
        out = p.stdout + p.stderr
        rows = {}
        for line in out.splitlines():
            parts = line.split()
            if len(parts) >= 2 and parts[0].isupper() and ':' in parts[1]:
                rows[parts[1]] = parts[0]
        print('\n'.join('  %-10s %s' % (v, k) for k, v in sorted(rows.items())))
        want = {'sast:present': 'DETECTED', 'negative:present-quiet': 'CLEAN-OK',
                'secret:gone': 'ABSENT', 'negative:gone': 'ABSENT'}
        for sig, st in want.items():
            if rows.get(sig) != st:
                bad.append('%s graded %r, expected %s' % (sig, rows.get(sig), st))
        if p.returncode != 1:
            bad.append('exit %d with absent fixture files; expected 1' % p.returncode)
        if 'never in the scanned tree' not in out:
            bad.append('the ABSENT rows are not explained as a delivery defect')
    finally:
        shutil.rmtree(d, ignore_errors=True)
    if bad:
        for b in bad:
            print('FAIL: %s' % b)
        return 1
    print('PASS: an expectation whose file was never in the scanned tree is ABSENT -- not a miss '
          'by the scanner, and not a clean negative control.')
    return 0


if __name__ == '__main__':
    sys.exit(main())

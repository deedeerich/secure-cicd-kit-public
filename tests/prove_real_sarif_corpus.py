#!/usr/bin/env python3
"""Real scanner SARIF, stored, read by the kit's own validity code (ledger L18).

WHY THIS EXISTS

    KNOWN_DEFECTS' "first thing to check": the validity code was written against SARIF the author
    imagined, and L01 (a clean bandit run read as hollow) was a disagreement with what the tool
    really writes. tests/corpora/sarif/ holds REAL output -- checkov 3.3.30 and trivy 0.71.2 over
    three Terraform directories, produced 2026-10-21. Trivy's local base URI is normalised to
    file:///corpus/<kind>/, and every file went through scripts/redact_sarif.py, as SARIF does on
    its way out of a job; the `expected-` prefix is the name .gitignore admits for test fixtures:

        clean    a file with nothing to report
        seeded   the corpus family 1.5 file (tests/corpora/terraform_corpus.py): one known finding
        hollow   the corpus control: an unparseable file holding the same seed

WHAT IS PROVED, against the shipped scripts/sarif_validity.py and scan_report.examination_of
    R1  every stored file is the named tool's real output (driver name and version)
    R2  seeded: VALID, EXAMINED, and the seeded rule is among the results -- a real finding counts
    R3  clean:  VALID and EXAMINED -- never EXAMINED_NOTHING (the L01 class: a clean run is not hollow)

WHAT IS RECORDED, NOT ASSERTED -- the measured blind spot
    hollow: both tools DROP the unparseable file and write SARIF that differs from the clean run's
    by nothing a reader can use (no notification, no executionSuccessful, no artifact list), so
    the SARIF channel reads it VALID and EXAMINED. Only a side channel (ledger L03: checkov's parse
    error log, trivy's file count) can tell. Printed every run; asserted when L03 lands.

EXIT 0 R1-R3 hold; 1 one does not; 2 could not be checked.
"""
import io
import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
CORPUS = os.path.join(HERE, 'corpora', 'sarif')
sys.path.insert(0, os.path.join(ROOT, 'scripts'))

# tool -> (driver name, driver version, the seeded rule in lower case)
TOOLS = {'checkov': ('Checkov', '3.3.30', 'ckv_aws_24'),
         'trivy': ('Trivy', '0.71.2', 'aws-0107')}


def main():
    try:
        import sarif_validity as V
        import scan_report as S
    except ImportError as e:
        print('UNKNOWN: %s' % e)
        return 2
    bad = []
    for tool, (name, version, rule) in sorted(TOOLS.items()):
        seen = {}
        for kind in ('clean', 'seeded', 'hollow'):
            path = os.path.join(CORPUS, 'expected-%s-%s.sarif' % (tool, kind))
            if not os.path.isfile(path):
                bad.append('%s %s: %s is missing' % (tool, kind, path))
                continue
            doc = json.load(io.open(path, encoding='utf-8'))
            driver = ((doc.get('runs') or [{}])[0].get('tool') or {}).get('driver') or {}
            if driver.get('name') != name or driver.get('version') != version:
                bad.append('R1 %s %s: driver %r %r, want %s %s' % (tool, kind, driver.get('name'),
                                                                   driver.get('version'), name, version))
            state, why, n = V.verdict(path)
            exam = S.examination_of(doc, scanner=tool)[0]
            rules = sorted(set(str(r.get('ruleId') or '').lower() for run in doc['runs']
                               for r in run.get('results') or []))
            seen[kind] = (state, exam, n)
            print('  %-8s %-7s validity=%-17s examination=%-16s results=%s %s'
                  % (tool, kind, state, exam, n, rules))
            if kind == 'seeded' and not (state == 'VALID' and exam == S.EXAMINED and rule in rules):
                bad.append('R2 %s seeded: %s / %s / %s -- a real finding must count' % (tool, state, exam, rules))
            if kind == 'clean' and not (state == 'VALID' and exam == S.EXAMINED):
                bad.append('R3 %s clean: %s / %s -- a clean run read as hollow or failed (the L01 class)'
                           % (tool, state, exam))
        if seen.get('hollow') and seen.get('hollow')[:2] == seen.get('clean', (None, None))[:2]:
            print('  KNOWN LIMIT %s: the hollow run (unparseable file dropped) reads %s / %s, the same '
                  'as clean -- only a side channel can tell (ledger L03)' % (tool, *seen['hollow'][:2]))
    print()
    if bad:
        for b in bad:
            print('FAIL: %s' % b)
        return 1
    print('PASS: real checkov and trivy SARIF -- a real finding counts and a real clean run is not '
          'read as hollow. A real hollow run is indistinguishable in SARIF, as recorded above.')
    return 0


if __name__ == '__main__':
    sys.exit(main())

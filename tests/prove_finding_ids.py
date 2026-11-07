#!/usr/bin/env python3
"""ONE id normaliser for every source: each tool's CWE and CVE spelling is one id; an unknown form is refused.

WHY THIS EXISTS (owner, 2026-11-06): "most security suites/scanners have their own way that they label the
different CWEs and CVEs, and syntax can be different." scripts/finding_ids.py holds the format table (its
docstring cites each source); this proves every reader goes through it.

  POSITIVE
    P1  the format table: every listed CWE and vulnerability-id spelling normalises to its canonical form
        (the module's self-test, 33 cases)
    P2  one weakness, three tools, one CWE: the report's own reader (scan_report.what_of) gives CWE-79 for a
        CodeQL relationship to the CWE taxonomy, a Semgrep tag `external/cwe/cwe-079` and Bandit's
        `{"id": 79}`; the SAST family resolver (code_finding_key) places `cwe-079`, `CWE-79` and
        `{"id": 79}` in one family
    P3  the external intake: Aikido `cwe_classes` ["079"] and ["CWE-79"], SonarQube `cwe:79`, and a CVE
        written `cve-2026-12345` all reach the finding as CWE-79 / CVE-2026-12345
    P4  aliases: a GHSA with an advisory record naming a CVE resolves to that CVE, keeping both; with no
        record the GHSA stands and the basis says no alias was established
  NEGATIVE
    N1  unknown forms are refused BY NAME (CWE_FORM_UNKNOWN, VULN_ID_FORM_UNKNOWN), never guessed: a bare
        number in a field not declared numeric, `OWASP A03`, `CWE-XYZ`, a CVE in a CWE field, `CVE-21-1`,
        a GHSA with letters outside its alphabet, an un-namespaced vendor id
    N2  a number in a tag (`line 79`) is not read as a CWE by the report
    N3  an Aikido issue whose cve_id is malformed keeps its vendor identifier and lists the refusal
    N4  the old reader (the first digits anywhere) took `OWASP A03:2021` as a CWE; the shared one refuses it

EXIT 0 all hold   1 any does not
"""
import io
import os
import re
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, os.path.join(ROOT, 'scripts'))
FAILS = []


def check(cond, label, detail=''):
    print('  %s %s%s' % ('ok  ' if cond else 'FAIL', label, ('  -- ' + str(detail)[:300]) if detail and not cond else ''))
    if not cond:
        FAILS.append(label)


def main():
    import finding_ids as F
    import scan_report as SR
    import code_finding_key as CFK
    import external_findings_pull as EFP
    print('One id normaliser (scripts/finding_ids.py):')
    p = subprocess.run([sys.executable, os.path.join(ROOT, 'scripts', 'finding_ids.py'), '--self-test'],
                       capture_output=True, text=True)
    check(p.returncode == 0, 'P1 the format table normalises every listed spelling (module self-test)', p.stdout)

    codeql = SR.what_of({'id': 'py/reflective-xss', 'relationships': [
        {'target': {'id': '79', 'toolComponent': {'name': 'CWE'}}}]}, {}, 'py/reflective-xss', 'xss', 'codeql', 'CodeQL')[0]
    semgrep = SR.what_of({'id': 'python.flask.xss', 'properties': {'tags': ['security', 'external/cwe/cwe-079']}},
                         {}, 'python.flask.xss', 'xss', 'semgrep', 'Semgrep')[0]
    bandit = SR.what_of({'id': 'B703', 'properties': {'cwe': {'id': 79, 'link': 'https://cwe.mitre.org/data/definitions/79.html'}}},
                        {}, 'B703', 'xss', 'bandit', 'Bandit')[0]
    got = [codeql.get('cwe_reported') or codeql.get('cwe'), semgrep.get('cwe_reported') or semgrep.get('cwe'),
           bandit.get('cwe_reported') or bandit.get('cwe')]
    check(got == ['CWE-79'] * 3, 'P2 CodeQL, Semgrep and Bandit spellings are one CWE-79 in the report (%s)' % got)
    fams = {CFK.cwe_number(x) for x in ('cwe-079', 'CWE-79', {'id': 79}, 'external/cwe/cwe-079')}
    check(fams == {79}, 'P2 the SAST family resolver reads every spelling as CWE 79 (%s)' % fams)

    def ak(**over):
        r = {'id': 7, 'type': 'sast', 'severity': 'high', 'status': 'open', 'code_repo_name': 'app',
             'affected_file': 'a.py', 'start_line': 3, 'rule_id': 'X1'}
        r.update(over)
        refs = []
        items, _c, _u = EFP.aikido_items([r], {'app': 'example-org/app'}, 'code', id_refusals=refs)
        return (items[0] if items else {}), refs
    a1, _ = ak(cwe_classes=['079'])
    a2, _ = ak(cwe_classes=['CWE-79'])
    a3, _ = ak(type='open_source', cve_id='cve-2026-12345')
    check(a1.get('cwe') == a2.get('cwe') == 'CWE-79' and a3.get('identifier') == 'CVE-2026-12345',
          'P3 Aikido "079", "CWE-79" and "cve-2026-12345" reach the finding canonically')
    check(F.normalize_cwes(['cwe:79', 'owaspTop10:a3'][:1])[0] == ['CWE-79'], 'P3 SonarQube cwe:79 is CWE-79')

    r = F.resolve_aliases(['ghsa-x84v-xcm2-53pg'], {'GHSA-X84V-XCM2-53PG': {'aliases': ['CVE-2018-18074']}})
    check(r['primary'] == 'CVE-2018-18074' and 'GHSA-X84V-XCM2-53PG' in r['aliases'],
          'P4 a GHSA resolves to its CVE through the advisory aliases, both kept')
    r = F.resolve_aliases(['GHSA-x84v-xcm2-53pg'])
    check(r['primary'] == 'GHSA-X84V-XCM2-53PG' and 'no alias was established' in ' '.join(r['basis']),
          'P4 with no advisory record the GHSA stands, and says so')

    refused = [F.normalize_cwe('79'), F.normalize_cwe('OWASP A03'), F.normalize_cwe('CWE-XYZ'),
               F.normalize_cwe('CVE-2021-44228'), F.normalize_vuln_id('CVE-21-1'),
               F.normalize_vuln_id('GHSA-aaaa-bbbb-cccc'), F.normalize_vuln_id('javasecurity:S3649')]
    check(all(c is None and re.search(r'(CWE_FORM_UNKNOWN|VULN_ID_FORM_UNKNOWN)', why) for c, why in refused),
          'N1 every unknown form is refused by name', refused)
    tag = SR.what_of({'id': 'r', 'properties': {'tags': ['line 79', 'size 120']}}, {}, 'r', 'm', 'semgrep', 'Semgrep')[0]
    check(not tag.get('cwe'), 'N2 a number in a tag is not a CWE (%r)' % tag.get('cwe'))
    a4, refs = ak(type='open_source', cve_id='CVE-21-1')
    check(a4.get('identifier', '').startswith('aikido:') and refs and 'VULN_ID_FORM_UNKNOWN' in refs[0]['why'],
          'N3 a malformed Aikido cve_id keeps the vendor identifier and the refusal is listed', refs)
    old = re.search(r'(\d{1,5})', 'OWASP A03:2021')
    check(old is not None and CFK.cwe_number('OWASP A03:2021') is None,
          'N4 the old first-digits reader took OWASP A03:2021 as a CWE; the shared normaliser refuses it')
    if FAILS:
        print('FAIL: %d claim(s)' % len(FAILS))
        return 1
    print('PASS: every source spelling of a CWE or a vulnerability id is one id, and an unknown form is refused.')
    return 0


if __name__ == '__main__':
    sys.exit(main())

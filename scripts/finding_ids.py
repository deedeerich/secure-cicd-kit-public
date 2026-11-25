#!/usr/bin/env python3
"""ONE normaliser for weakness (CWE) and vulnerability (CVE, GHSA, OSV, vendor) identifiers, for every source.

WHY THIS EXISTS (the owner, 2026-11-06)
    "Most security suites/scanners have their own way that they label the different CWEs and CVEs, and
    syntax can be different." Two tools naming one weakness in two spellings were two identities: CodeQL
    and Semgrep tag `external/cwe/cwe-079`, Bandit reports `{"id": 79}`, SonarQube `cwe:79`, Semgrep
    metadata `CWE-79: Improper Neutralization ...`. The report kept `CWE-079` for one and `CWE-79` for the
    other. Every reader of an id (scripts/scan_report.py, scripts/code_finding_key.py,
    scripts/external_findings_pull.py) now goes through this module, and a form it does not know is
    REFUSED with a named reason -- never guessed (a stray number is not a CWE).

THE FORMAT TABLE (FORMATS below; sources read 2026-11-06)
    CWE  canonical `CWE-<n>`, n a positive integer without leading zeros
         CWE-79 / cwe-079 / CWE79 / CWE 79 / CWE_79   MITRE ids, any case, separator or zero padding
                                                       (https://cwe.mitre.org/data/definitions/79.html)
         external/cwe/cwe-079                         CodeQL query tags and Semgrep SARIF tags
                                                       (https://codeql.github.com/codeql-query-help/)
         cwe:79                                       SonarQube security standards (UNVERIFIED field,
                                                       docs/adoption/EXTERNAL_FINDINGS_SONAR_AIKIDO.md)
         CWE-89: Improper Neutralization ...          Semgrep rule `metadata.cwe` strings and lists
                                                       (https://github.com/semgrep/semgrep-rules)
         {"id": 79, "link": ...} / 79                 Bandit `issue_cwe` (bandit/core/issue.py), and a
                                                       field the source DECLARES numeric (numeric_ok);
                                                       a bare number anywhere else is refused
         lists and mixed lists                        each member normalised; refusals listed
    VULNERABILITY ids
         CVE-2021-44228 / cve-2021-44228 / CVE 2021-44228 / CVE_2021_44228   canonical CVE-YYYY-N
                                                       (https://www.cve.org/ResourcesSupport/FAQs, the
                                                       CVE ID syntax: year, then four or more digits)
         GHSA-xxxx-xxxx-xxxx                           GitHub advisory ids: three groups of four from
                                                       23456789cfghjmpqrvwx; kept UPPER-CASE, the form
                                                       the kit's identities already carry
                                                       (https://docs.github.com/en/code-security/security-advisories)
         PYSEC-, GO-, RUSTSEC-, OSV-, MAL-, GSD-, DSA-, DLA-, USN-   OSV database prefixes
                                                       (https://ossf.github.io/osv-schema/, "id")
         sonar:<issue key>, sonar-hotspot:<key>, sonar-rule:<repo:rule>, aikido:<id>
                                                       vendor ids, namespaced by the source; a vendor id
                                                       without a known namespace is refused
    ALIASES: GHSA and OSV ids resolve to their CVE when the advisory record's `aliases` names one
    (the OSV schema's `aliases` field); with no alias data the id stands, said in the basis.

USAGE   from finding_ids import normalize_cwe, normalize_cwes, normalize_vuln_id, resolve_aliases
        python3 scripts/finding_ids.py --self-test
EXIT    0 self-test ok   1 a case failed
"""
import json
import re
import sys

CWE_FORM_UNKNOWN = 'CWE_FORM_UNKNOWN'
VULN_ID_FORM_UNKNOWN = 'VULN_ID_FORM_UNKNOWN'

_CWE_TEXT = re.compile(r'^\s*(?:external/cwe/)?cwe\s*[-_: ]?\s*0*([1-9][0-9]{0,4})\s*(?::\s*\S.*)?$', re.I)
_CWE_IN_TEXT = re.compile(r'(?<![A-Za-z0-9])(?:external/cwe/)?cwe[-_: ]?0*([1-9][0-9]{0,4})(?![0-9])', re.I)
_DIGITS = re.compile(r'^\s*0*([1-9][0-9]{0,4})\s*$')
_CVE = re.compile(r'^\s*CVE[-_ ]?(\d{4})[-_ ](\d{4,7})\s*$', re.I)
_GHSA = re.compile(r'^\s*GHSA((?:-[23456789cfghjmpqrvwx]{4}){3})\s*$', re.I)
OSV_PREFIXES = ('PYSEC', 'GO', 'RUSTSEC', 'OSV', 'MAL', 'GSD', 'DSA', 'DLA', 'USN')
_OSV = re.compile(r'^\s*(%s)-([0-9]{4}-[0-9A-Za-z]{1,12}|[0-9]{3,6}-[0-9]{1,3})\s*$' % '|'.join(OSV_PREFIXES), re.I)
VENDOR_NAMESPACES = ('sonar', 'sonar-hotspot', 'sonar-rule', 'aikido')
_VENDOR = re.compile(r'^\s*(%s):([A-Za-z0-9][A-Za-z0-9._:/-]{0,120})\s*$' % '|'.join(VENDOR_NAMESPACES))


_REVIEWED = {}


def reviewed(kind):
    """{raw: canonical} a PERSON mapped for a form this table does not know (id-mappings.json at the kit root;
    author, date and review reference required: scripts/unknown_ids.py load_mappings). Never a guess."""
    if kind not in _REVIEWED:
        import os
        import unknown_ids
        applied, _r = unknown_ids.load_mappings(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
        _REVIEWED[kind] = dict((str(m['raw']), str(m['canonical'])) for m in applied if m.get('kind') == kind)
    return _REVIEWED[kind]


def normalize_cwe(value, numeric_ok=False):
    """-> ('CWE-<n>', basis) or (None, refusal naming CWE_FORM_UNKNOWN)."""
    if isinstance(value, bool):
        return None, '%s: %r is a boolean, not a CWE' % (CWE_FORM_UNKNOWN, value)
    if isinstance(value, dict):
        if 'id' in value:
            return normalize_cwe(value['id'], numeric_ok=True)
        return None, '%s: an object with no `id` (%s)' % (CWE_FORM_UNKNOWN, json.dumps(value)[:80])
    if isinstance(value, int):
        if numeric_ok and 0 < value < 100000:
            return 'CWE-%d' % value, 'a number in a field declared to hold a CWE'
        return None, '%s: the number %r in a field not declared to hold a CWE' % (CWE_FORM_UNKNOWN, value)
    s = str(value or '')
    m = _CWE_TEXT.match(s)
    if m:
        return 'CWE-%d' % int(m.group(1)), 'the CWE form %r' % s.strip()[:40]
    m = _DIGITS.match(s)
    if m and numeric_ok:
        return 'CWE-%d' % int(m.group(1)), 'a number in a field declared to hold a CWE'
    mapped = reviewed('cwe-form').get(s.strip())
    if mapped and _CWE_TEXT.match(mapped):
        return 'CWE-%d' % int(_CWE_TEXT.match(mapped).group(1)), 'a reviewed mapping of %r (id-mappings.json)' % s.strip()
    return None, '%s: %r is not a CWE form this kit knows (scripts/finding_ids.py FORMAT TABLE)' % (
        CWE_FORM_UNKNOWN, s[:60])


def normalize_cwes(value, numeric_ok=False):
    """-> (sorted unique canonical CWEs, refusals). Takes one value, a list, or a dict with `id`."""
    vals = value if isinstance(value, (list, tuple)) else [value]
    out, bad = set(), []
    for v in vals:
        if v in (None, ''):
            continue
        c, why = normalize_cwe(v, numeric_ok)
        if c:
            out.add(c)
        else:
            bad.append(why)
    return sorted(out, key=lambda c: int(c[4:])), bad


def cwes_in_text(text):
    """Every CWE named in free text in a KNOWN form (CWE-79, cwe-079, external/cwe/cwe-079, cwe:79),
    canonical and in order of first appearance. A bare number in text is never read as a CWE."""
    seen = []
    for m in _CWE_IN_TEXT.finditer(str(text or '')):
        c = 'CWE-%d' % int(m.group(1))
        if c not in seen:
            seen.append(c)
    return seen


def normalize_vuln_id(value, source=''):
    """-> (canonical id, kind) with kind cve | ghsa | osv | vendor, or (None, refusal naming
    VULN_ID_FORM_UNKNOWN). `source` (sonar, aikido) admits that vendor's own namespaced ids."""
    s = str(value or '')
    m = _CVE.match(s)
    if m:
        return 'CVE-%s-%s' % (m.group(1), m.group(2)), 'cve'
    m = _GHSA.match(s)
    if m:
        return 'GHSA' + m.group(1).upper(), 'ghsa'
    m = _OSV.match(s)
    if m:
        return '%s-%s' % (m.group(1).upper(), m.group(2).upper()), 'osv'
    m = _VENDOR.match(s)
    if m:
        return '%s:%s' % (m.group(1), m.group(2)), 'vendor'
    mapped = reviewed('vuln-id-form').get(s.strip())
    if mapped and mapped != s.strip():
        c, kind = normalize_vuln_id(mapped, source)
        if c:
            return c, kind
    if source == 'sonar' and re.match(r'^[a-z][a-z0-9-]{1,40}:[A-Za-z0-9_-]{1,40}$', s.strip()):
        return 'sonar-rule:%s' % s.strip(), 'vendor'
    return None, '%s: %r is not a CVE, GHSA, OSV or namespaced vendor id (scripts/finding_ids.py FORMAT TABLE)' % (
        VULN_ID_FORM_UNKNOWN, s[:60])


def resolve_aliases(ids, advisories=None, source=''):
    """-> {'primary', 'kind', 'aliases', 'basis', 'refused'}. The primary is a CVE when one is named or an
    advisory record's `aliases` (OSV schema) gives one; otherwise the GHSA, then the OSV id, then a vendor
    id. More than one CVE: the lowest is primary, every one is kept, and the basis says so."""
    canon, refused = [], []
    for v in ids or []:
        c, kind = normalize_vuln_id(v, source)
        if c:
            canon.append((c, kind))
        else:
            refused.append(kind)
    basis = []
    for c, kind in list(canon):
        if kind in ('ghsa', 'osv'):
            rec = (advisories or {}).get(c)
            if rec is None:
                basis.append('%s: no advisory record, so no alias was established' % c)
                continue
            for a in rec.get('aliases') or []:
                ac, ak = normalize_vuln_id(a)
                if ac and (ac, ak) not in canon:
                    canon.append((ac, ak))
                    basis.append('%s resolves to %s through the advisory aliases' % (c, ac))
                elif not ac:
                    refused.append(ak)
    order = {'cve': 0, 'ghsa': 1, 'osv': 2, 'vendor': 3}
    canon = sorted(set(canon), key=lambda t: (order[t[1]], t[0]))
    cves = [c for c, k in canon if k == 'cve']
    if len(cves) > 1:
        basis.append('%d CVEs named; the lowest is primary and every one is kept' % len(cves))
    primary = canon[0] if canon else (None, None)
    return {'primary': primary[0], 'kind': primary[1], 'aliases': [c for c, _ in canon], 'basis': basis,
            'refused': refused}


def self_test():
    cases = [
        (normalize_cwe('CWE-79'), 'CWE-79'), (normalize_cwe('cwe-079'), 'CWE-79'), (normalize_cwe('CWE79'), 'CWE-79'),
        (normalize_cwe('cwe:79'), 'CWE-79'), (normalize_cwe('external/cwe/cwe-079'), 'CWE-79'),
        (normalize_cwe('CWE 79'), 'CWE-79'), (normalize_cwe('CWE-89: Improper Neutralization of SQL'), 'CWE-89'),
        (normalize_cwe({'id': 78, 'link': 'https://cwe.mitre.org/data/definitions/78.html'}), 'CWE-78'),
        (normalize_cwe(79, numeric_ok=True), 'CWE-79'), (normalize_cwe('89', numeric_ok=True), 'CWE-89'),
        (normalize_cwe('79'), None), (normalize_cwe(79), None), (normalize_cwe('CWE-XYZ'), None),
        (normalize_cwe('CVE-2021-44228'), None), (normalize_cwe('OWASP A03'), None), (normalize_cwe('CWE-0'), None),
        (normalize_cwe(''), None), (normalize_cwe(True), None),
        (normalize_vuln_id('cve-2021-44228'), 'CVE-2021-44228'), (normalize_vuln_id(' CVE 2021-44228 '), 'CVE-2021-44228'),
        (normalize_vuln_id('CVE_2021_44228'), 'CVE-2021-44228'), (normalize_vuln_id('ghsa-x84v-xcm2-53pg'), 'GHSA-X84V-XCM2-53PG'),
        (normalize_vuln_id('PYSEC-2021-59'), 'PYSEC-2021-59'), (normalize_vuln_id('go-2022-0969'), 'GO-2022-0969'),
        (normalize_vuln_id('aikido:12345'), 'aikido:12345'), (normalize_vuln_id('javasecurity:S3649', 'sonar'), 'sonar-rule:javasecurity:S3649'),
        (normalize_vuln_id('javasecurity:S3649'), None), (normalize_vuln_id('CVE-21-1'), None),
        (normalize_vuln_id('GHSA-aaaa-bbbb-cccc'), None), (normalize_vuln_id('SNYK-JS-LODASH-1'), None),
    ]
    bad = []
    for i, ((got, _why), want) in enumerate(cases):
        if got != want:
            bad.append('case %d: got %r want %r (%s)' % (i, got, want, _why))
    r = resolve_aliases(['GHSA-x84v-xcm2-53pg'], {'GHSA-X84V-XCM2-53PG': {'aliases': ['CVE-2018-18074']}})
    if r['primary'] != 'CVE-2018-18074' or 'GHSA-X84V-XCM2-53PG' not in r['aliases']:
        bad.append('alias resolution: %r' % r)
    r = resolve_aliases(['GHSA-x84v-xcm2-53pg'])
    if r['primary'] != 'GHSA-X84V-XCM2-53PG' or 'no advisory record' not in ' '.join(r['basis']):
        bad.append('no alias data: %r' % r)
    if cwes_in_text('tags external/cwe/cwe-079 and CWE-89, line 79') != ['CWE-79', 'CWE-89']:
        bad.append('cwes_in_text: %r' % cwes_in_text('tags external/cwe/cwe-079 and CWE-89, line 79'))
    for b in bad:
        print('SELF-TEST FAIL: %s' % b)
    print('self-test %s: %d cases' % ('FAILED' if bad else 'ok', len(cases) + 3))
    return 1 if bad else 0


if __name__ == '__main__':
    sys.exit(self_test() if '--self-test' in sys.argv else 0)

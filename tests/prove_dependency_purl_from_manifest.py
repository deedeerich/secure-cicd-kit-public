#!/usr/bin/env python3
"""A dependency finding is keyed when its MANIFEST names the registry. NO NETWORK.

FOUND HOSTED (Release 4 end-to-end, public run 41945270732, 2026-11-04)
    The kit scanned a requirements.txt with three known-vulnerable pins and ticketed NOTHING:
    every Trivy dependency finding was UNFINGERPRINTABLE / WHERE_UNDERIVABLE ("subject
    SOURCE_DEPENDENCY requires purl; missing: purl"). Trivy's SARIF carries no purl -- only
    "Package: PyYAML / Installed Version: 5.1" in the message and the manifest's path. The kit
    refused, correctly, to assemble a purl from a package name plus a GUESSED ecosystem
    (`pkg:npm/requests` and `pkg:pypi/requests` are different packages).

    A manifest is not a guess. `requirements.txt` can only name PyPI packages, `package-lock.json`
    only npm ones. So: when the SARIF has no purl, the purl is built from the labelled Package and
    Installed Version lines AND an ecosystem read from the manifest's file name through a FIXED
    table -- and a manifest the table does not know still refuses, exactly as before.

WHAT IT PROVES
    P1  requirements.txt + "Package: PyYAML / Installed Version: 5.1" -> pkg:pypi/pyyaml@5.1
        (PyPI names normalised as PEP 503 does), FINGERPRINTED, basis says tier 3 and the manifest.
    P2  package-lock.json with a scoped package -> pkg:npm/%40scope/name@1.2.3; go.mod -> golang;
        pom.xml "group:artifact" -> pkg:maven/group/artifact@v; Gemfile.lock -> gem; Cargo.lock ->
        cargo; composer.lock -> composer; packages.lock.json -> nuget.
    P3  a manifest the table does not know (build.gradle) still refuses WHERE_UNDERIVABLE; so does a message
        missing the version, and a maven name without its group.
    P4  a purl the SARIF DOES carry still wins (tier 1/2 unchanged).
    P5  the same finding from two runs keys to ONE identity, and two packages in one manifest to two.
    P6  mutant: a table that also maps build.gradle keys it, so P3's refusal is the real table's.

EXIT  0 proven   1 a case failed (named)   2 could not be checked
"""
import io
import json
import os
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, os.path.join(ROOT, 'scripts'))

FAILS = []


def check(cond, msg):
    print('  %s %s' % ('ok  ' if cond else 'FAIL', msg))
    if not cond:
        FAILS.append(msg)


def sarif(results, tool='Trivy'):
    rules = [{'id': r['rid'], 'properties': {'tags': ['vulnerability', 'security', 'CRITICAL']}}
             for r in results]
    out = []
    for i, r in enumerate(results):
        res = {'ruleId': r['rid'], 'ruleIndex': i, 'level': 'error',
               'message': {'text': r['msg']},
               'locations': [{'physicalLocation': {'artifactLocation': {'uri': r['uri']},
                                                   'region': {'startLine': 3}},
                              'message': {'text': r['uri']}}]}
        if r.get('props'):
            res['properties'] = r['props']
        out.append(res)
    return {'version': '2.1.0', 'runs': [{'tool': {'driver': {'name': tool, 'version': '0.71.2', 'rules': rules}},
                                           'results': out}]}


def msg(pkg, ver, cve='CVE-2019-20477'):
    lines = ['Package: %s' % pkg] if pkg else []
    if ver:
        lines.append('Installed Version: %s' % ver)
    lines += ['Vulnerability %s' % cve, 'Severity: CRITICAL', 'Fixed Version: 9.9']
    return '\n'.join(lines)


def parse(results, scanner='trivy'):
    import scan_report as sr
    d = tempfile.mkdtemp(prefix='purl-')
    p = os.path.join(d, 'trivy-deps.sarif')
    io.open(p, 'w', encoding='utf-8').write(json.dumps(sarif(results)))
    found, state, _ex = sr.parse_sarif(p, scanner)
    for f in found:      # the purl is reported in the locus basis; lift it for the checks
        m = __import__('re').search(r'purl (pkg:\S+) from', f.get('locus_basis') or '')
        f['purl'] = m.group(1) if m else ''
        f['state'], f['reason'] = f.get('identity_state'), f.get('identity_reason')
    return found


def one(uri, pkg, ver, **kw):
    f = parse([dict(rid=kw.get('cve', 'CVE-2019-20477'), uri=uri, msg=msg(pkg, ver, kw.get('cve', 'CVE-2019-20477')),
                    props=kw.get('props'))])
    return f[0] if f else {}


def main():
    try:
        import scan_report  # noqa: F401
    except Exception as exc:                      # noqa: BLE001
        print('UNKNOWN: scan_report could not be imported: %s' % exc)
        return 2
    r = one('app/requirements.txt', 'PyYAML', '5.1')
    check(r.get('purl') == 'pkg:pypi/pyyaml@5.1', 'P1 requirements.txt -> %r' % r.get('purl'))
    check(r.get('state') == 'FINGERPRINTED', 'P1 the finding is FINGERPRINTED (%s %s)' % (r.get('state'), r.get('reason')))
    check('manifest' in (r.get('what_basis', '') + r.get('identity_basis', '') + json.dumps(r)).lower(),
          'P1 the basis names the manifest tier')
    cases = [('web/package-lock.json', '@scope/name', '1.2.3', 'pkg:npm/%40scope/name@1.2.3'),
             ('svc/go.mod', 'golang.org/x/net', 'v0.17.0', 'pkg:golang/golang.org/x/net@v0.17.0'),
             ('java/pom.xml', 'org.yaml:snakeyaml', '1.33', 'pkg:maven/org.yaml/snakeyaml@1.33'),
             ('rb/Gemfile.lock', 'rack', '2.2.3', 'pkg:gem/rack@2.2.3'),
             ('rs/Cargo.lock', 'hyper', '0.14.1', 'pkg:cargo/hyper@0.14.1'),
             ('php/composer.lock', 'guzzlehttp/guzzle', '7.4.0', 'pkg:composer/guzzlehttp/guzzle@7.4.0'),
             ('cs/packages.lock.json', 'Newtonsoft.Json', '12.0.1', 'pkg:nuget/Newtonsoft.Json@12.0.1')]
    for uri, pkg, ver, want in cases:
        r = one(uri, pkg, ver)
        check(r.get('purl') == want and r.get('state') == 'FINGERPRINTED',
              'P2 %s -> %r (%s)' % (os.path.basename(uri), r.get('purl'), r.get('state')))
    for uri, pkg, ver, why in (('app/build.gradle', 'org.yaml:snakeyaml', '1.33', 'a manifest the table does not know'),
                               ('app/requirements.txt', 'PyYAML', '', 'no Installed Version'),
                               ('java/pom.xml', 'snakeyaml', '1.33', 'a maven name without its group')):
        r = one(uri, pkg, ver)
        check(not r.get('purl') and r.get('state') == 'UNFINGERPRINTABLE' and r.get('reason') == 'WHERE_UNDERIVABLE',
              'P3 %s still refuses WHERE_UNDERIVABLE (%s %s)' % (why, r.get('state'), r.get('reason')))
    r = one('app/requirements.txt', 'PyYAML', '5.1', props={'purl': 'pkg:pypi/pyyaml@5.1.2'})
    check(r.get('state') == 'FINGERPRINTED' and ('tier 1' in (r.get('locus_basis') or '') or 'tier 2' in (r.get('locus_basis') or '')) and 'tier 3' not in (r.get('locus_basis') or ''), 'P4 a purl the SARIF carries wins (%s)' % (r.get('locus_basis') or '')[:80])
    a = one('app/requirements.txt', 'PyYAML', '5.1')
    b = one('app/requirements.txt', 'PyYAML', '5.1')
    f2 = parse([dict(rid='CVE-2019-20477', uri='app/requirements.txt', msg=msg('PyYAML', '5.1')),
                dict(rid='CVE-2019-11324', uri='app/requirements.txt', msg=msg('urllib3', '1.24.1', 'CVE-2019-11324'))])
    check(a.get('identity') and a.get('identity') == b.get('identity'), 'P5 one finding, two runs: one identity')
    check(len(set(x.get('identity') for x in f2)) == 2 and all(x.get('identity') for x in f2),
          'P5 two packages in one manifest: two identities')
    import scan_report as sr
    saved = dict(sr.manifest_ecosystems)
    try:
        sr.manifest_ecosystems['build.gradle'] = 'maven'
        r = one('app/build.gradle', 'org.yaml:snakeyaml', '1.33')
        check(bool(r.get('purl')), 'P6 mutant: a table that also maps build.gradle keys it -- so P3 bites on the real table')
    finally:
        sr.manifest_ecosystems.clear()
        sr.manifest_ecosystems.update(saved)
    print()
    if FAILS:
        print('FAIL: %d check(s): a dependency finding with no purl in its SARIF is not yet keyed from its manifest.'
              % len(FAILS))
        return 1
    print('PASS: a dependency finding is keyed from its manifest\'s registry (a fixed table), never a guessed one.')
    return 0


if __name__ == '__main__':
    sys.exit(main())

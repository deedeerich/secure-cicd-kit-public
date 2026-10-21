#!/usr/bin/env python3
"""Correlation above the observations: only the ANCHORED tier acts (L48; ETFB section 9.1-9.4).

WHY THIS EXISTS

    Enforcement counts clusters, not observations -- otherwise a well-covered repository is punished
    for having more scanners, which is a direct incentive to remove one (ETFB section 9.2). But a
    correlation layer that merges unrelated findings is worse than five tickets: the merged-away
    finding leaves no trace (section 9.3). So section 9.4 has three tiers and only one acts:

        anchored   a shared external identifier plus matching package coordinates -> one cluster
        proposed   heuristic agreement (same CWE family, overlapping locus) -> RECORDED, never applied
        singleton  nothing else agrees

    The reporter's only correlation today is `seen[(uri, rule)]` in scan_report.batch -- a rule id
    shared across two different tools almost never matches, and when it does it is a heuristic, not
    an anchor. This proves the anchored tier as a library, on identities computed by identify().

THE FOUR CASES

    allowed           two scanners, one vulnerable package, overlapping advisory aliases -> ONE
                      anchored cluster naming BOTH scanners; enforcement counts 1
    attack            the same advisory in two different packages -> two clusters; the same alias
                      across subject classes -> never merged; an alias CHAIN whose ends share
                      nothing -> not anchored (each acts alone; the chain is a proposal); CWE plus
                      path agreement -> a proposal that changes no count
    missing-evidence  an observation with no durable identity is its own acting unit, never
                      merged and never dropped; every observation appears in exactly one acting
                      cluster
    agreement         on a fixture with no alias chain, the anchored partition equals the one
                      scripts/reconcile_tickets.build_clusters computes for ticketing

EXIT  0 proven   1 a case failed (named)   2 could not be checked (UNKNOWN, never PASS)
"""
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, os.path.join(ROOT, 'scripts'))


def main():
    try:
        from finding_identity import identify
    except ImportError as exc:
        print('UNKNOWN: %s' % exc)
        return 2
    try:
        import finding_correlation as fc
    except ImportError as exc:
        print('FAIL: no anchored correlation tier exists (%s). The reporter correlates on '
              '(uri, rule), which section 9.4 calls a heuristic, and enforcement has nothing to count '
              'but observations.' % exc)
        return 1

    fails = []

    def check(cond, msg):
        if not cond:
            fails.append(msg)

    def obs(scanner, subject, purl=None, pkg=None, ver=None, **what):
        rec = {'finding_subject': subject}
        rec.update(what)
        if purl:
            rec['purl'] = purl
        if pkg:
            rec['package_name'], rec['package_version'] = pkg, ver
        out = dict(identify(rec))
        out['scanner'] = scanner
        return out

    trivy = obs('trivy', 'SOURCE_DEPENDENCY', purl='pkg:pypi/requests@2.19.1',
                cve='CVE-2018-18074', ghsa='GHSA-x84v-xcm2-53pg')
    grype = obs('grype', 'SOURCE_DEPENDENCY', purl='pkg:pypi/requests@2.19.1',
                ghsa='GHSA-x84v-xcm2-53pg')
    for o in (trivy, grype):
        check(o.get('identity') and o.get('where'), 'fixture did not fingerprint: %r' % o)
    check(trivy['identity'] != grype['identity'],
          'fixture: the two scanners produced one identity, so the alias tier is not exercised')

    # ── allowed ──────────────────────────────────────────────────────────────
    r = fc.correlate([trivy, grype])
    check(r['summary']['acting_clusters'] == 1 and r['clusters'][0]['tier'] == fc.ANCHORED,
          'allowed: two scanners on one package with overlapping aliases gave %r' % r['summary'])
    check(sorted(r['clusters'][0]['scanners']) == ['grype', 'trivy'],
          'allowed: the anchored cluster does not name every contributing scanner (%r) -- a dead '
          'detector could hide behind a live one' % r['clusters'][0]['scanners'])

    # ── attack: same advisory, different package coordinates ────────────────
    other_pkg = obs('trivy', 'SOURCE_DEPENDENCY', purl='pkg:pypi/requests@2.20.0',
                    cve='CVE-2018-18074')
    r = fc.correlate([trivy, other_pkg])
    check(r['summary']['acting_clusters'] == 2,
          'attack: one advisory in two package coordinates was merged (%r)' % r['summary'])
    # ── attack: across subject classes ───────────────────────────────────────
    img = obs('trivy-image', 'IMAGE', pkg='requests', ver='2.19.1', cve='CVE-2018-18074')
    r = fc.correlate([trivy, img])
    check(r['summary']['acting_clusters'] == 2,
          'attack: an IMAGE and a SOURCE_DEPENDENCY finding were correlated -- nothing correlates '
          'across subject classes')
    # ── attack: an alias chain whose ends share nothing ──────────────────────
    a = obs('s1', 'SOURCE_DEPENDENCY', purl='pkg:npm/x@1.0.0', cve='CVE-2024-0001', osv='PYSEC-2024-1')
    b = obs('s2', 'SOURCE_DEPENDENCY', purl='pkg:npm/x@1.0.0', osv='PYSEC-2024-1', ghsa='GHSA-aaaa-bbbb-cccc')
    c = obs('s3', 'SOURCE_DEPENDENCY', purl='pkg:npm/x@1.0.0', ghsa='GHSA-aaaa-bbbb-cccc')
    r = fc.correlate([a, b, c])
    check(r['summary']['acting_clusters'] == 3,
          'attack: an alias chain with no identifier common to all members was anchored (%r) -- '
          'alias sets are not transitive in practice' % r['summary'])
    check(any(p['basis'] == 'alias chain' for p in r['proposals']),
          'attack: the chain was not recorded as a proposal for a human')
    # ── attack: heuristic agreement only ─────────────────────────────────────
    s1 = obs('semgrep', 'SOURCE', cwe='CWE-89', rule_family='sqli', canonical_path='db.py',
             symbol_path='db.q', construct='execute("x" + v)')
    s2 = obs('codeql', 'SOURCE', cwe='CWE-89', rule_family='py/sql-injection',
             canonical_path='db.py', symbol_path='db.q2', construct='cursor.execute(q)')
    s1['cwe'], s1['canonical_path'] = 'CWE-89', 'db.py'
    s2['cwe'], s2['canonical_path'] = 'CWE-89', 'db.py'
    r = fc.correlate([s1, s2])
    check(r['summary']['acting_clusters'] == 2 and len(r['proposals']) == 1
          and r['proposals'][0]['tier'] == fc.PROPOSED,
          'attack: CWE-plus-path agreement either merged or went unrecorded (%r, %d proposal(s))'
          % (r['summary'], len(r['proposals'])))

    # ── missing evidence ─────────────────────────────────────────────────────
    refused = dict(identify({'finding_subject': 'SOURCE', 'cwe': 'CWE-89', 'rule_family': 'sqli',
                             'canonical_path': 'db.py'}), scanner='bandit')
    r = fc.correlate([trivy, grype, refused, dict(refused, scanner='semgrep')])
    members = sorted(i for cl in r['clusters'] for i in cl['members'])
    check(members == [0, 1, 2, 3],
          'missing-evidence: observations were dropped or double-counted: %r' % members)
    unid = [cl for cl in r['clusters'] if not cl['identity_established']]
    check(len(unid) == 2 and all(len(cl['members']) == 1 for cl in unid),
          'missing-evidence: observations with no durable identity were merged or lost (%r)' % unid)
    check(r['summary']['acting_clusters'] == 3,
          'missing-evidence: acting count %r, expected 1 anchored + 2 unidentified'
          % r['summary']['acting_clusters'])

    # ── agreement with the ticketing clusterer, where both should agree ──────
    try:
        import io
        import contextlib
        import reconcile_tickets as rt
        recs = []
        for o in (trivy, grype, other_pkg):
            recs.append({'identity': o['identity'], 'identity_state': o['state'],
                         'finding_subject': o['finding_subject'], 'what_aliases': o['what_aliases'],
                         'where': o['where'], 'scanner': o['scanner'], 'severity': 'HIGH'})
        with contextlib.redirect_stderr(io.StringIO()):
            tclusters, _w = rt.build_clusters(recs)
        theirs = sorted(sorted(cl['member_identities']) for cl in tclusters)
        mine_r = fc.correlate([trivy, grype, other_pkg])
        mine = sorted(sorted(set(cl['member_identities'])) for cl in mine_r['clusters'])
        check(theirs == mine, 'agreement: ticketing clusters %r, correlation clusters %r'
              % (theirs, mine))
    except ImportError as exc:
        fails.append('agreement: reconcile_tickets could not be imported: %s' % exc)

    if fails:
        for f in fails:
            print('FAIL: ' + f)
        return 1
    print('PASS: two scanners on one package with overlapping aliases form ONE anchored cluster '
          'naming both; different coordinates, different subjects and an alias chain with no '
          'common identifier do not merge; CWE-plus-path agreement is recorded as a proposal and '
          'changes no count; unidentified observations act alone and none is dropped; the '
          'anchored partition matches the ticketing clusterer where both apply.')
    return 0


if __name__ == '__main__':
    sys.exit(main())

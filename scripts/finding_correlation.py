#!/usr/bin/env python3
"""Correlation ABOVE the observations: anchored / proposed / singleton, and only anchored acts.

(ETFB section 9.1-9.4; SINGLE_PIPELINE_TARGET.md section 6.1 item 4; L48.)

WHAT THIS IS FOR

    Five scanners finding one issue must not raise five tickets or count as five blocking findings
    -- a well-covered repository would be punished for coverage, which is an incentive to remove a
    scanner. But corroboration is not duplication: no observation is ever removed, every
    contributing scanner is named, and a cluster that a heuristic proposed never suppresses what it
    clustered (section 9.1, section 9.4).

        observations  ->  correlation  ->  clusters  ->  what enforcement counts
        (kept forever)    (adds a key)     (one obligation each)

THE THREE TIERS, AND WHICH ONE ACTS

    anchored   identical durable identity, OR -- within ONE subject class and ONE locus (for a
               package subject the locus IS the package coordinate) -- advisory alias sets that
               share an identifier COMMON TO EVERY MEMBER. Clustered automatically. Acts.
    proposed   heuristic agreement only: an alias CHAIN whose ends share nothing (alias sets are
               not transitive in practice, section 5.6), or the same CWE in the same file with no
               shared identifier (SAST engines have no shared id at all, section 9.3). RECORDED for a
               human to confirm or split; NEVER applied -- each member keeps acting on its own.
    singleton  nothing else agrees. Its own obligation. An observation with no durable identity
               is always a singleton: it cannot be correlated, and it is never dropped.

    Nothing correlates across subject classes. A SOURCE finding and a RESOURCE finding about "the
    same problem" are two obligations with two owners.

DIFFERENCE FROM scripts/reconcile_tickets.build_clusters, STATED RATHER THAN HIDDEN

    The ticketing clusterer unions alias intersections transitively, so A{x,y}, B{y,z}, C{z}
    becomes one cluster although A and C share nothing; it then anchors that cluster on an identity
    rather than an identifier. Here that shape is a PROPOSAL, not an anchor. On every fixture with
    no such chain the two agree, and tests/prove_anchored_correlation.py asserts that they do. The
    two should become one implementation; that belongs to whoever owns the ticketing scripts.

    Tier names are lower-case, as reconcile_tickets spells them and as ETFB section 9.4 writes them
    in prose: minting upper-case state words for a distinction the design already names would be
    the vocabulary inflation reconcile_taxonomy.py exists to catch.

USAGE
    from finding_correlation import correlate
    python3 finding_correlation.py --self-test
"""
import hashlib
import sys

ANCHORED = 'anchored'
PROPOSED = 'proposed'
SINGLETON = 'singleton'


def _s(v):
    return v.strip() if isinstance(v, str) else ''


def _established(o):
    return (isinstance(o, dict) and _s(o.get('identity'))
            and _s(o.get('state') or o.get('identity_state')) == 'FINGERPRINTED')


def _aliases(o):
    vals = o.get('what_aliases') or []
    if isinstance(vals, str):
        vals = [vals]
    return frozenset(_s(str(v)).upper() for v in vals if _s(str(v)))


def _key(subject, anchor):
    return hashlib.sha256(('CORRELATION/%s/%s' % (subject, anchor)).encode('utf-8')).hexdigest()[:32]


def correlate(observations):
    """-> {clusters, proposals, summary}. Every observation index appears in exactly one cluster."""
    observations = list(observations or [])
    clusters, proposals = [], []

    by_identity = {}
    for i, o in enumerate(observations):
        if _established(o):
            by_identity.setdefault(_s(o['identity']), []).append(i)
        else:
            clusters.append({
                'tier': SINGLETON, 'identity_established': False,
                'subject': _s((o or {}).get('finding_subject')) if isinstance(o, dict) else '',
                'anchor': None, 'cluster_key': None, 'members': [i], 'member_identities': [],
                'scanners': [_s((o or {}).get('scanner'))] if isinstance(o, dict) else [],
                'why': 'no durable identity (%s): cannot be correlated, acts alone, never dropped'
                       % (_s((o or {}).get('reason')) or 'no identity') if isinstance(o, dict)
                       else 'not a mapping'})

    # Bucket identity groups by (subject, locus). WHERE is the subject-scaled locus; for a package
    # subject it is the coordinate, so "same bucket" is "matching package coordinates".
    buckets = {}
    for ident, idx in by_identity.items():
        o = observations[idx[0]]
        buckets.setdefault((_s(o.get('finding_subject')), _s(o.get('where'))), []).append(ident)

    for (subject, locus), idents in sorted(buckets.items()):
        parent = dict((k, k) for k in idents)

        def find(x):
            while parent[x] != x:
                parent[x] = parent[parent[x]]
                x = parent[x]
            return x

        for ai in range(len(idents)):
            for bi in range(ai + 1, len(idents)):
                aa = _aliases(observations[by_identity[idents[ai]][0]])
                ab = _aliases(observations[by_identity[idents[bi]][0]])
                if locus and aa and ab and (aa & ab):
                    ra, rb = find(idents[ai]), find(idents[bi])
                    if ra != rb:
                        parent[rb] = ra
        groups = {}
        for k in idents:
            groups.setdefault(find(k), []).append(k)
        for _root, members in sorted(groups.items()):
            common = None
            for k in members:
                al = _aliases(observations[by_identity[k][0]])
                common = al if common is None else (common & al)
            if len(members) > 1 and not common:
                # A CHAIN. Proposed, never applied: each identity acts on its own.
                proposals.append({'tier': PROPOSED, 'basis': 'alias chain', 'subject': subject,
                                  'member_identities': sorted(members),
                                  'members': sorted(i for k in members for i in by_identity[k]),
                                  'why': 'aliases link these pairwise, but no identifier is common to '
                                         'all of them. Alias sets are not transitive in practice; a '
                                         'human confirms or splits'})
                split = [[k] for k in members]
            else:
                split = [members]
            for part in split:
                idx = sorted(i for k in part for i in by_identity[k])
                shared = None
                for k in part:
                    al = _aliases(observations[by_identity[k][0]])
                    shared = al if shared is None else (shared & al)
                anchor = min(shared) if shared else part[0]
                tier = ANCHORED if len(idx) > 1 else SINGLETON
                clusters.append({
                    'tier': tier, 'identity_established': True, 'subject': subject,
                    'anchor': anchor, 'cluster_key': _key(subject, '%s@%s' % (anchor, locus)),
                    'members': idx, 'member_identities': sorted(_s(observations[i]['identity'])
                                                                for i in idx),
                    'scanners': sorted(set(_s(observations[i].get('scanner')) for i in idx)),
                    'why': ('identical durable identity' if len(part) == 1 and len(idx) > 1 else
                            'shared identifier %s at one locus within %s' % (anchor, subject)
                            if len(part) > 1 else 'nothing else agrees')})

    # The heuristic tier over the ACTING clusters: same subject, same CWE, same file, no anchor.
    index_of = {}
    for n, cl in enumerate(clusters):
        for i in cl['members']:
            index_of[i] = n
    heur = {}
    for i, o in enumerate(observations):
        if not isinstance(o, dict):
            continue
        cwe, path = _s(o.get('cwe')).upper(), _s(o.get('canonical_path'))
        if cwe and path:
            heur.setdefault((_s(o.get('finding_subject')), cwe, path), set()).add(index_of[i])
    for (subject, cwe, path), cl_ids in sorted(heur.items()):
        if len(cl_ids) > 1:
            proposals.append({'tier': PROPOSED, 'basis': 'same CWE and file', 'subject': subject,
                              'clusters': sorted(cl_ids),
                              'members': sorted(i for n in cl_ids for i in clusters[n]['members']),
                              'why': '%s in %s from different clusters with no shared identifier. '
                                     'A heuristic, not an identity: two defects in one function '
                                     'must not become one ticket' % (cwe, path)})

    acting = len(clusters)
    return {'clusters': clusters, 'proposals': proposals,
            'summary': {'observations': len(observations), 'acting_clusters': acting,
                        'anchored': sum(1 for c in clusters if c['tier'] == ANCHORED),
                        'singletons': sum(1 for c in clusters if c['tier'] == SINGLETON),
                        'unidentified': sum(1 for c in clusters if not c['identity_established']),
                        'proposals': len(proposals)}}


def _selftest():
    fails = []

    def o(ident, aliases, where='L', subject='SOURCE_DEPENDENCY', scanner='s', state='FINGERPRINTED'):
        return {'identity': ident, 'state': state, 'what_aliases': aliases, 'where': where,
                'finding_subject': subject, 'scanner': scanner}

    r = correlate([o('i1', ['CVE-1'], scanner='a'), o('i1', ['CVE-1'], scanner='b')])
    if r['summary']['acting_clusters'] != 1 or r['clusters'][0]['scanners'] != ['a', 'b']:
        fails.append('identical identity from two scanners: %r' % r['summary'])
    r = correlate([o('i1', ['CVE-1']), o('i2', ['CVE-1'], where='')])
    if r['summary']['acting_clusters'] != 2:
        fails.append('an empty locus anchored a merge')
    r = correlate([o('i1', ['CVE-1']), o('i2', [])])
    if r['summary']['acting_clusters'] != 2:
        fails.append('an observation with no aliases merged')
    r = correlate([o('', [], state='UNFINGERPRINTABLE'), None])
    if sorted(i for c in r['clusters'] for i in c['members']) != [0, 1]:
        fails.append('unidentified or malformed observations were dropped')
    if fails:
        for f in fails:
            sys.stderr.write('FAIL: %s\n' % f)
        return 2
    print('finding_correlation selftest ok: one identity from two scanners is one cluster naming '
          'both; an empty locus or an alias-less observation never anchors a merge; nothing is '
          'dropped. The tier cases run in tests/prove_anchored_correlation.py.')
    return 0


if __name__ == '__main__':
    if len(sys.argv) == 2 and sys.argv[1] in ('--self-test', '--selftest'):
        sys.exit(_selftest())
    print('usage: finding_correlation.py --self-test   (library)', file=sys.stderr)
    sys.exit(2)

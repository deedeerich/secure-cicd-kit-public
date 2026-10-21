#!/usr/bin/env python3
"""The baseline MATCHING CASCADE. Is this finding NEW, or was it here before? (ETFB section 5.3, L44)

A PURE FUNCTION over observations and a ledger. It reads nothing, writes nothing, calls nothing:
the ledger is handed to it already read (scripts/baseline_ledger.py reads it from the protected
default branch), and its answer goes to whoever enforces. That separation is deliberate -- the
cascade is the part that has to be right, and a function with no I/O is the part that can be
proven right in isolation.

THE CASCADE (ETFB section 5.3, verbatim in intent)

    exact match    WHAT, WHERE and CONTENT all agree           the same finding; first_seen carried
    moved          WHAT and CONTENT agree, WHERE differs, and   one finding that moved; the move is
                   exactly one unmatched entry and exactly      an EVENT; first_seen carried
                   one unmatched observation hold that pair
    ambiguous      the (WHAT, CONTENT) pair is held by more     resolved by CARDINALITY, never by
                   than one entry or more than one observation  guessing
    unmatched      no entry holds the (WHAT, CONTENT) pair      NEW
    uncomputable   a component could not be derived             neither a match nor NEW:
                                                                EVIDENCE_UNTRUSTED

THE CARDINALITY RULE. For a group of N ledger entries and M observations sharing (WHAT, CONTENT):
min(N, M) are continuations, any surplus M - N is NEW, any deficit N - M is POTENTIALLY_ABSENT.
Which observation continues which entry is genuinely undecidable in the hard cases, so it is
RECORDED as ambiguous and enforcement depends only on the counts, which are known.

THREE THINGS THIS ADDS THAT THE TABLE LEAVES IMPLICIT, EACH A WAY THE TABLE COULD BE MISREAD

    1  THE GROUP KEY CARRIES THE SUBJECT. An IMAGE finding and a SOURCE_DEPENDENCY finding for the
       same CVE share WHAT and share the declared not-applicable CONTENT. Grouping on (WHAT,
       CONTENT) alone would read a container finding as a lockfile finding that "moved", and
       section 9.3 is explicit that nothing correlates across subject classes.
    2  THE LEDGER IS FILTERED TO ONE ENVIRONMENT. Section 8.8 rule 4: a finding cannot be
       grandfathered into an environment it was never present in.
    3  OBSERVATIONS WITH ONE IDENTITY ARE ONE FINDING, NOT TWO. Identity excludes the scanner, so
       two scanners seeing one defect produce one identity. Counting them as two would make
       corroboration look like a duplicated defect and invent a NEW finding. Every observation is
       still listed -- corroboration is not duplication, and nothing here drops one.

A LEDGER THAT CANNOT BE READ IS NOT A LEDGER WITH NOTHING IN IT (ETFB section 3). Absent, tampered,
unparseable or malformed -> every finding is BASELINE_UNAVAILABLE and the run routes to
EVIDENCE_UNTRUSTED. Not "everything pre-existing" (a one-line bypass of `run`) and not "everything
new" (which blocks the world and gets the gate switched off). LEDGER_EMPTY is different: a ledger
that exists and holds nothing makes every finding NEW, correctly.

USAGE
    from finding_match import match
    result = match(observations, ledger_entries, ledger_state, environment='prod')
    python3 finding_match.py --self-test
"""
import sys

# Registered vocabulary (assurance-taxonomy.yaml). Spelled once, here.
IDENTITY_MATCHED_EXACT = 'IDENTITY_MATCHED_EXACT'
IDENTITY_MATCHED_MOVED = 'IDENTITY_MATCHED_MOVED'
IDENTITY_AMBIGUOUS = 'IDENTITY_AMBIGUOUS'
IDENTITY_UNMATCHED = 'IDENTITY_UNMATCHED'
IDENTITY_UNCOMPUTABLE = 'IDENTITY_UNCOMPUTABLE'

NEW = 'NEW'
PRE_EXISTING_BASELINED = 'PRE_EXISTING_BASELINED'
PRE_EXISTING_AGE_NOT_ESTABLISHED = 'PRE_EXISTING_AGE_NOT_ESTABLISHED'
PRE_EXISTING_BY_DETECTION_CHANGE = 'PRE_EXISTING_BY_DETECTION_CHANGE'
BASELINE_UNAVAILABLE = 'BASELINE_UNAVAILABLE'

POTENTIALLY_ABSENT = 'POTENTIALLY_ABSENT'      # finding_classification
EVIDENCE_UNTRUSTED = 'EVIDENCE_UNTRUSTED'      # routing_result

# lineage_ledger_integrity, reused for the baseline ledger: the same five facts about any
# governance ledger, and a second spelling of them would be the drift the registry exists to stop.
LEDGER_ABSENT = 'LEDGER_ABSENT'
LEDGER_EMPTY = 'LEDGER_EMPTY'
LEDGER_INTACT = 'LEDGER_INTACT'
LEDGER_TAMPERED = 'LEDGER_TAMPERED'
LEDGER_LINE_UNPARSEABLE = 'LEDGER_LINE_UNPARSEABLE'
USABLE_LEDGER_STATES = (LEDGER_INTACT, LEDGER_EMPTY)

DURABLE = 'DURABLE_ACROSS_RUNS_AND_UPGRADES'
COMPONENTS = ('what', 'where', 'content')
ENTRY_REQUIRED = ('identity', 'what', 'where', 'content', 'finding_subject', 'environment')


def _s(value):
    return value.strip() if isinstance(value, str) else ''


def _computable(obs):
    """-> '' when the observation carries a usable durable identity, else the reason it does not."""
    if not isinstance(obs, dict):
        return 'the observation is not a mapping'
    if _s(obs.get('state')) != 'FINGERPRINTED':
        return 'identity state is %r (%s)' % (obs.get('state'), obs.get('reason') or 'no reason given')
    missing = [c for c in COMPONENTS + ('identity', 'finding_subject') if not _s(obs.get(c))]
    if missing:
        # The label says FINGERPRINTED and a component is empty. Trusting the label over the value
        # is how an inference overwrites an observation.
        return 'state FINGERPRINTED but %s empty' % ', '.join(missing)
    scope = _s(obs.get('identity_scope'))
    if scope and scope != DURABLE:
        return ('identity scope is %s: computable and worthless as a ledger key -- a RELEASE-scoped '
                'identity is lost at the next deploy' % scope)
    return ''


def _baseline_state_of(entry):
    """The PRE-EXISTING flavour an entry licenses. An absent age flag is NOT an established age."""
    if entry.get('detection_change') is True:
        return PRE_EXISTING_BY_DETECTION_CHANGE
    if entry.get('age_established') is True:
        return PRE_EXISTING_BASELINED
    return PRE_EXISTING_AGE_NOT_ESTABLISHED


def _weakest(states):
    """For a group whose correspondence is undecidable, report the age claim nobody can overstate."""
    order = (PRE_EXISTING_AGE_NOT_ESTABLISHED, PRE_EXISTING_BY_DETECTION_CHANGE,
             PRE_EXISTING_BASELINED)
    for s in order:
        if s in states:
            return s
    return PRE_EXISTING_AGE_NOT_ESTABLISHED


def _ledger_faults(entries):
    faults = []
    seen = set()
    for i, e in enumerate(entries):
        if not isinstance(e, dict):
            faults.append('entry %d is not a mapping' % i)
            continue
        missing = [k for k in ENTRY_REQUIRED if not _s(e.get(k))]
        if missing:
            faults.append('entry %d lacks %s' % (i, ', '.join(missing)))
            continue
        key = (_s(e['identity']), _s(e['environment']))
        if key in seen:
            faults.append('entry %d duplicates the key (identity, environment) %r' % (i, key))
        seen.add(key)
    return faults


def _unavailable(observations, why):
    findings = []
    for i, obs in enumerate(observations):
        reason = _computable(obs)
        findings.append({
            'index': i, 'identity': _s((obs or {}).get('identity')) if isinstance(obs, dict) else '',
            'match': IDENTITY_UNCOMPUTABLE if reason else None,
            'baseline_state': BASELINE_UNAVAILABLE, 'routes_to': EVIDENCE_UNTRUSTED,
            'first_seen': None, 'ledger_identity': None,
            'why': ('baseline unavailable: %s' % why) + ('; also: %s' % reason if reason else ''),
        })
    return {'baseline': BASELINE_UNAVAILABLE, 'routes_to': EVIDENCE_UNTRUSTED, 'why': why,
            'findings': findings, 'ledger_unobserved': [], 'moves': [], 'groups': [],
            'summary': {'observations': len(observations), 'new': 0, 'continuations': 0,
                        'potentially_absent': 0, 'evidence_untrusted': len(observations),
                        'ambiguous_groups': 0}}


def match(observations, ledger_entries, ledger_state, environment):
    """-> result dict. See the module docstring for the cascade.

    `observations`   a list of identify() outputs, optionally with extra keys (scanner, ...).
    `ledger_entries` a list of ledger entries, as read by baseline_ledger.read_*.
    `ledger_state`   the reader's integrity state. Only LEDGER_INTACT and LEDGER_EMPTY are usable.
    `environment`    the environment being evaluated. Entries for any other environment are
                     invisible to this evaluation.
    """
    observations = list(observations or [])
    env = _s(environment)
    if not env:
        return _unavailable(observations, 'no environment was named, and the ledger is keyed by '
                                          '(identity, environment): there is no default to fall '
                                          'back to')
    if ledger_state not in USABLE_LEDGER_STATES:
        return _unavailable(observations, 'the ledger state is %r. Unreadable is not empty: NEW '
                                          'and PRE-EXISTING cannot be told apart' % (ledger_state,))
    entries = list(ledger_entries or [])
    if ledger_state == LEDGER_EMPTY and entries:
        return _unavailable(observations, 'the reader said LEDGER_EMPTY and handed over %d '
                                          'entries; the two disagree' % len(entries))
    faults = _ledger_faults(entries)
    if faults:
        return _unavailable(observations, 'the ledger is malformed: %s' % '; '.join(faults[:5]))

    entries = [e for e in entries if _s(e['environment']) == env]
    triple = lambda x: (_s(x['what']), _s(x['where']), _s(x['content']))  # noqa: E731
    group_of = lambda x: (_s(x['finding_subject']), _s(x['what']), _s(x['content']))  # noqa: E731

    findings = [None] * len(observations)
    by_identity = {}      # triple -> [observation indices]; one distinct finding per triple
    for i, obs in enumerate(observations):
        reason = _computable(obs)
        if reason:
            findings[i] = {'index': i, 'identity': _s(obs.get('identity')) if isinstance(obs, dict)
                           else '', 'match': IDENTITY_UNCOMPUTABLE, 'baseline_state': None,
                           'routes_to': EVIDENCE_UNTRUSTED, 'first_seen': None,
                           'ledger_identity': None,
                           'why': 'not a match and not NEW: %s' % reason}
            continue
        by_identity.setdefault((_s(obs['finding_subject']),) + triple(obs), []).append(i)

    ledger_by_triple = {}
    for e in entries:
        ledger_by_triple[(_s(e['finding_subject']),) + triple(e)] = e

    def stamp(indices, **fields):
        for i in indices:
            rec = {'index': i, 'identity': _s(observations[i]['identity']), 'routes_to': None,
                   'first_seen': None, 'ledger_identity': None}
            rec.update(fields)
            findings[i] = rec

    # Pass 1: exact.
    left_obs, used = {}, set()
    for key, idx in by_identity.items():
        e = ledger_by_triple.get(key)
        if e is not None:
            used.add(key)
            stamp(idx, match=IDENTITY_MATCHED_EXACT, baseline_state=_baseline_state_of(e),
                  first_seen=e.get('first_seen'), ledger_identity=_s(e['identity']),
                  why='WHAT, WHERE and CONTENT all agree with a ledger entry')
        else:
            left_obs[key] = idx
    left_ledger = {k: e for k, e in ledger_by_triple.items() if k not in used}

    # Pass 2: group the leftovers by (subject, WHAT, CONTENT).
    groups = {}
    for key, idx in left_obs.items():
        groups.setdefault((key[0], key[1], key[3]), ([], []))[0].append((key, idx))
    for key, e in left_ledger.items():
        groups.setdefault((key[0], key[1], key[3]), ([], []))[1].append(e)

    moves, unobserved, group_records = [], [], []
    counts = {'new': 0, 'continuations': len(used), 'potentially_absent': 0}
    for gkey in sorted(groups):
        obs_list, led_list = groups[gkey]
        n, m = len(led_list), len(obs_list)
        if n == 0:
            for _key, idx in obs_list:
                stamp(idx, match=IDENTITY_UNMATCHED, baseline_state=NEW,
                      why='no ledger entry in environment %s shares WHAT and CONTENT' % env)
            counts['new'] += m
            continue
        if m == 0:
            for e in led_list:
                unobserved.append({'identity': _s(e['identity']), 'classification': POTENTIALLY_ABSENT,
                                   'first_seen': e.get('first_seen'),
                                   'why': 'in the ledger and not observed. NOT fixed: absence of '
                                          'the scope is not absence of the thing, until coverage '
                                          'of where it lived is shown'})
            counts['potentially_absent'] += n
            continue
        if n == 1 and m == 1:
            e = led_list[0]
            key, idx = obs_list[0]
            stamp(idx, match=IDENTITY_MATCHED_MOVED, baseline_state=_baseline_state_of(e),
                  first_seen=e.get('first_seen'), ledger_identity=_s(e['identity']),
                  why='WHAT and CONTENT agree with exactly one unmatched entry; WHERE differs')
            moves.append({'ledger_identity': _s(e['identity']), 'observed_identity':
                          _s(observations[idx[0]]['identity']), 'from_where': _s(e['where']),
                          'to_where': key[2], 'first_seen': e.get('first_seen'),
                          'observations': list(idx)})
            counts['continuations'] += 1
            continue
        # AMBIGUOUS. Counts are known; correspondence is not, and is not invented.
        cont = min(n, m)
        surplus = max(m - n, 0)
        deficit = max(n - m, 0)
        gid = len(group_records)
        state = _weakest([_baseline_state_of(e) for e in led_list])
        for _key, idx in obs_list:
            stamp(idx, match=IDENTITY_AMBIGUOUS, baseline_state=None, group=gid,
                  why='one of %d observation(s) sharing WHAT and CONTENT with %d ledger entr(y/ies); '
                      'which continues which is undecidable, so enforcement uses the counts'
                      % (m, n))
        group_records.append({
            'group': gid, 'finding_subject': gkey[0], 'ledger_identities':
            sorted(_s(e['identity']) for e in led_list),
            'observations': sorted(i for _k, idx in obs_list for i in idx),
            'continuations': cont, 'new': surplus, 'potentially_absent': deficit,
            'continuation_baseline_state': state,
            'earliest_first_seen': min((e.get('first_seen') or '9999') for e in led_list)})
        counts['continuations'] += cont
        counts['new'] += surplus
        counts['potentially_absent'] += deficit

    untrusted = sum(1 for f in findings if f and f['routes_to'] == EVIDENCE_UNTRUSTED)
    return {
        'baseline': None, 'routes_to': EVIDENCE_UNTRUSTED if untrusted else None,
        'why': ('%d observation(s) have no computable durable identity' % untrusted) if untrusted
               else 'every observation was matched against a readable ledger',
        'findings': findings, 'ledger_unobserved': unobserved, 'moves': moves,
        'groups': group_records,
        'summary': {'observations': len(observations), 'new': counts['new'],
                    'continuations': counts['continuations'],
                    'potentially_absent': counts['potentially_absent'],
                    'evidence_untrusted': untrusted, 'ambiguous_groups': len(group_records)},
    }


# ─────────────────────────────────────────────────────────────────────────────
def _selftest():
    fails = []

    def check(cond, msg):
        if not cond:
            fails.append(msg)

    def obs(w, wh, c, subject='SOURCE', **extra):
        o = {'state': 'FINGERPRINTED', 'finding_subject': subject, 'what': w, 'where': wh,
             'content': c, 'identity': '%s|%s|%s|%s' % (subject, w, wh, c),
             'identity_scope': DURABLE}
        o.update(extra)
        return o

    def ent(o, env='prod', **extra):
        e = {k: o[k] for k in ('identity', 'what', 'where', 'content', 'finding_subject')}
        e.update({'environment': env, 'first_seen': '2026-01-01', 'age_established': True})
        e.update(extra)
        return e

    x, y = obs('W1', 'L1', 'C1'), obs('W2', 'L2', 'C2')
    led = [ent(x), ent(y)]
    r = match([x, y], led, LEDGER_INTACT, 'prod')
    check([f['match'] for f in r['findings']] == [IDENTITY_MATCHED_EXACT] * 2, 'exact: %r' % r)
    # Corroboration: two scanners, one identity -> one finding, both observations listed.
    r = match([dict(x, scanner='a'), dict(x, scanner='b')], [ent(x)], LEDGER_INTACT, 'prod')
    check(r['summary']['new'] == 0 and all(f['match'] == IDENTITY_MATCHED_EXACT for f in r['findings'])
          and len(r['findings']) == 2,
          'corroboration was read as duplication or an observation was dropped: %r' % r['summary'])
    r = match([dict(x, scanner='a'), dict(x, scanner='b')], [], LEDGER_EMPTY, 'prod')
    check(r['summary']['new'] == 1, 'two scanners on one NEW defect counted %d NEW' % r['summary']['new'])
    # Cross-subject: same WHAT and CONTENT sentinel, different subject -> never a move.
    img = obs('CVE', 'pkgA', 'NA', subject='IMAGE')
    dep = obs('CVE', 'purlA', 'NA', subject='SOURCE_DEPENDENCY')
    r = match([dep], [ent(img)], LEDGER_INTACT, 'prod')
    check(r['findings'][0]['match'] == IDENTITY_UNMATCHED,
          'a dependency finding "moved" from an image entry: %r' % r['findings'][0]['match'])
    # Moved, N=1 M=1
    r = match([obs('W1', 'L9', 'C1')], [ent(x)], LEDGER_INTACT, 'prod')
    check(r['findings'][0]['match'] == IDENTITY_MATCHED_MOVED and len(r['moves']) == 1, 'moved: %r' % r)
    # Ambiguous N=2 M=1 -> 1 continuation, 1 potentially absent
    x2 = obs('W1', 'L2b', 'C1')
    r = match([obs('W1', 'L9', 'C1')], [ent(x), ent(x2)], LEDGER_INTACT, 'prod')
    check(r['findings'][0]['match'] == IDENTITY_AMBIGUOUS
          and r['groups'][0]['continuations'] == 1 and r['groups'][0]['potentially_absent'] == 1,
          'N=2,M=1 ambiguity: %r' % r['groups'])
    # Age: missing flag is not established; detection change is its own flavour.
    r = match([x], [dict(ent(x), age_established=None)], LEDGER_INTACT, 'prod')
    check(r['findings'][0]['baseline_state'] == PRE_EXISTING_AGE_NOT_ESTABLISHED,
          'an absent age flag read as established')
    r = match([x], [ent(x, detection_change=True)], LEDGER_INTACT, 'prod')
    check(r['findings'][0]['baseline_state'] == PRE_EXISTING_BY_DETECTION_CHANGE,
          'a detection-change entry lost its flavour')
    # Unusable ledgers, malformed ledgers, no environment.
    for state in (LEDGER_ABSENT, LEDGER_TAMPERED, LEDGER_LINE_UNPARSEABLE, None, 'SOMETHING'):
        r = match([x], led, state, 'prod')
        check(r['baseline'] == BASELINE_UNAVAILABLE, 'ledger state %r was used' % (state,))
    r = match([x], [dict(ent(x), what='')], LEDGER_INTACT, 'prod')
    check(r['baseline'] == BASELINE_UNAVAILABLE, 'a malformed entry was matched against')
    r = match([x], [ent(x), ent(x)], LEDGER_INTACT, 'prod')
    check(r['baseline'] == BASELINE_UNAVAILABLE, 'a duplicated ledger key was accepted')
    r = match([x], led, LEDGER_INTACT, '')
    check(r['baseline'] == BASELINE_UNAVAILABLE, 'no environment fell back to a default')
    r = match([x], led, LEDGER_EMPTY, 'prod')
    check(r['baseline'] == BASELINE_UNAVAILABLE, 'EMPTY with entries was believed')
    # An empty but readable ledger: everything NEW, correctly.
    r = match([x, y], [], LEDGER_EMPTY, 'prod')
    check(r['summary']['new'] == 2 and r['routes_to'] is None, 'empty ledger: %r' % r['summary'])
    # A label that says FINGERPRINTED over an empty component, and a RELEASE scope.
    r = match([dict(x, content='')], led, LEDGER_INTACT, 'prod')
    check(r['findings'][0]['match'] == IDENTITY_UNCOMPUTABLE, 'empty component trusted over label')
    r = match([dict(x, identity_scope='VALID_WITHIN_ONE_RELEASE_ONLY')], led, LEDGER_INTACT, 'prod')
    check(r['findings'][0]['match'] == IDENTITY_UNCOMPUTABLE, 'a release-scoped identity was matched')

    if fails:
        for f in fails:
            sys.stderr.write('FAIL: %s\n' % f)
        return 2
    print('finding_match selftest ok: exact, moved, ambiguous-by-cardinality, unmatched and '
          'uncomputable each land where ETFB section 5.3 says; corroboration is one finding with every '
          'observation kept; nothing moves across subjects or environments; an unreadable, '
          'malformed or self-contradicting ledger is BASELINE_UNAVAILABLE for every finding.')
    return 0


if __name__ == '__main__':
    if len(sys.argv) == 2 and sys.argv[1] in ('--self-test', '--selftest'):
        sys.exit(_selftest())
    print('usage: finding_match.py --self-test   (library: from finding_match import match)',
          file=sys.stderr)
    sys.exit(2)

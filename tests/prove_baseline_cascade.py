#!/usr/bin/env python3
"""The baseline matching cascade, proven by forced failure (L44; ETFB section 5.3, section 4.3 item 5).

WHY THIS EXISTS

    `run` blocks every NEW high finding and lets a PRE-EXISTING one proceed on a track. Without a
    defensible answer to "have I seen this before?" the day the rung turns on, every inherited HIGH
    blocks every deployment and the gate is switched off within a week. ETFB section 4.3 item 5 says
    what promotion to `run` needs: "a deliberately relocated finding is shown to survive as the same
    finding; a deliberately introduced one is shown to appear as NEW; a deliberately removed one is
    shown to appear as POTENTIALLY_ABSENT rather than as fixed." This is that demonstration, run on
    identities computed by the real `identify()` from real-shaped records -- not on hand-made hashes.

THE FOUR CASES (docs/PROOF_RULE.md)

    allowed           an unchanged finding matches EXACT and keeps its first_seen
    attack            a finding introduced into a file full of baselined findings is NEW (section 8.8 rule 3);
                      a finding baselined in one environment is NEW in another (rule 4); a ledger
                      written for a different subject cannot grandfather this one
    missing-evidence  an unreadable ledger is BASELINE_UNAVAILABLE -> EVIDENCE_UNTRUSTED, never "all
                      pre-existing" and never "all new" (section 3); an uncomputable identity is
                      EVIDENCE_UNTRUSTED, neither matched nor NEW (section 5.3 last row)
    recovery          after the ledger is readable again, the same observations match as before

    plus the cardinality rule: a duplicated defect is one continuation and one NEW; a vanished one
    is POTENTIALLY_ABSENT; with two candidates and one observation nobody pretends to know which.

EXIT  0 proven   1 a case failed (named)   2 could not be checked (UNKNOWN, never PASS)
"""
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, os.path.join(ROOT, 'scripts'))


def main():
    try:
        from finding_identity import identify, FINGERPRINTED
    except ImportError as exc:
        print('UNKNOWN: cannot import finding_identity: %s' % exc)
        return 2
    try:
        import finding_match as fm
    except ImportError as exc:
        print('FAIL: no matching cascade exists (%s). ETFB section 5.3 is designed and not built: '
              'NEW and PRE-EXISTING cannot be told apart, so `run` is unreachable.' % exc)
        return 1

    fails = []

    def check(cond, msg):
        if not cond:
            fails.append(msg)

    def src(path, symbol, construct, cwe='CWE-78', family='os-command'):
        rec = {'finding_subject': 'SOURCE', 'cwe': cwe, 'rule_family': family,
               'canonical_path': path, 'symbol_path': symbol, 'construct': construct,
               'language_family': 'hash'}
        out = identify(rec)
        check(out['state'] == FINGERPRINTED and out.get('identity'),
              'fixture did not fingerprint: %r' % out)
        out = dict(out)
        out['scanner'] = 'semgrep'
        return out

    def entry(obs, env='prod', first_seen='2026-01-10', age=True):
        return {'identity': obs['identity'], 'what': obs['what'], 'where': obs['where'],
                'content': obs['content'], 'finding_subject': obs['finding_subject'],
                'environment': env, 'first_seen': first_seen, 'age_established': age}

    a = src('svc/worker.py', 'worker.run', 'subprocess.run(cmd, shell=True)')
    b = src('svc/db.py', 'db.query', 'cursor.execute("SELECT " + q)', cwe='CWE-89', family='sqli')
    ledger = [entry(a), entry(b, first_seen='2025-03-01', age=False)]

    # Non-empty first: every assertion below compares identities, and two empty ones are equal.
    check(all(x.get('identity') for x in (a, b)), 'fixture identities are empty')
    check(a['identity'] != b['identity'], 'two different fixtures share one identity')

    # ── allowed: unchanged ───────────────────────────────────────────────────
    r = fm.match([a, b], ledger, fm.LEDGER_INTACT, environment='prod')
    states = [f['match'] for f in r['findings']]
    check(states == [fm.IDENTITY_MATCHED_EXACT] * 2, 'allowed: unchanged findings matched %r' % states)
    check(r['findings'][0]['first_seen'] == '2026-01-10', 'allowed: first_seen not carried')
    check(r['findings'][1]['baseline_state'] == fm.PRE_EXISTING_AGE_NOT_ESTABLISHED,
          'allowed: an entry with no claimable age was reported as %r -- it must never read as an '
          'established age' % r['findings'][1]['baseline_state'])
    check(r['summary']['new'] == 0 and r['summary']['evidence_untrusted'] == 0,
          'allowed: %r' % r['summary'])

    # ── relocated: the file moved, the symbol and construct did not ──────────
    a_moved = src('services/worker/main.py', 'worker.run', 'subprocess.run(cmd,  shell=True)')
    check(a_moved['identity'] != a['identity'], 'relocation fixture did not move WHERE')
    r = fm.match([a_moved, b], ledger, fm.LEDGER_INTACT, environment='prod')
    f0 = r['findings'][0]
    check(f0['match'] == fm.IDENTITY_MATCHED_MOVED,
          'relocated: a moved finding was %r, not MOVED -- a refactor would manufacture NEW '
          'criticals' % f0['match'])
    check(f0['first_seen'] == '2026-01-10', 'relocated: first_seen was not carried across the move')
    check(len(r['moves']) == 1 and r['moves'][0]['ledger_identity'] == a['identity'],
          'relocated: the move was not recorded as an event naming the ledger entry')

    # ── attack: introduced beside baselined findings ─────────────────────────
    c = src('svc/worker.py', 'worker.run', 'os.system(user_input)')
    r = fm.match([a, b, c], ledger, fm.LEDGER_INTACT, environment='prod')
    check(r['findings'][2]['baseline_state'] == fm.NEW,
          'attack: a finding introduced into a file of baselined findings was %r -- grandfather '
          'status attached to a file rather than an identity' % r['findings'][2]['baseline_state'])
    # ── attack: another environment ──────────────────────────────────────────
    r = fm.match([a], ledger, fm.LEDGER_INTACT, environment='dev')
    check(r['findings'][0]['baseline_state'] == fm.NEW,
          'attack: a finding baselined in prod was %r in dev -- pre-existing in one environment '
          'is not pre-existing in another' % r['findings'][0]['baseline_state'])

    # ── removed ──────────────────────────────────────────────────────────────
    r = fm.match([a], ledger, fm.LEDGER_INTACT, environment='prod')
    gone = [e['identity'] for e in r['ledger_unobserved']]
    check(gone == [b['identity']], 'removed: the vanished entry was not reported (%r)' % gone)
    check(all(e['classification'] == fm.POTENTIALLY_ABSENT for e in r['ledger_unobserved']),
          'removed: a vanished finding was not POTENTIALLY_ABSENT -- a scanner that stopped '
          'looking would read as a fix')

    # ── cardinality: one defect duplicated by a file split ───────────────────
    a_copy = src('svc/worker_split.py', 'worker.run', 'subprocess.run(cmd, shell=True)')
    a_copy2 = src('svc/worker_other.py', 'worker.run', 'subprocess.run(cmd, shell=True)')
    r = fm.match([a_copy, a_copy2, b], ledger, fm.LEDGER_INTACT, environment='prod')
    check(r['summary']['new'] == 1 and r['summary']['continuations'] == 2,
          'cardinality: 1 ledger entry and 2 relocated observations must give 1 continuation and '
          '1 NEW (plus b exact), got %r' % r['summary'])
    check(r['findings'][0]['match'] == fm.IDENTITY_AMBIGUOUS,
          'cardinality: which observation continues the entry is undecidable and was not recorded '
          'as ambiguous (%r)' % r['findings'][0]['match'])

    # ── missing evidence: the ledger could not be read ──────────────────────
    for bad in (fm.LEDGER_ABSENT, fm.LEDGER_LINE_UNPARSEABLE, fm.LEDGER_TAMPERED, '', None):
        r = fm.match([a, b], ledger, bad, environment='prod')
        check(r['baseline'] == fm.BASELINE_UNAVAILABLE and r['routes_to'] == fm.EVIDENCE_UNTRUSTED,
              'missing-evidence: ledger state %r gave baseline %r / %r' % (bad, r['baseline'],
                                                                         r['routes_to']))
        check(all(f['baseline_state'] == fm.BASELINE_UNAVAILABLE for f in r['findings']),
              'missing-evidence: with ledger %r a finding was classified anyway -- the one-line '
              'total bypass of `run`' % bad)
    # ── missing evidence: an uncomputable identity ──────────────────────────
    refused = identify({'finding_subject': 'SOURCE', 'cwe': 'CWE-89', 'rule_family': 'sqli',
                        'canonical_path': 'svc/db.py', 'symbol_path': 'db.query'})
    r = fm.match([refused], ledger, fm.LEDGER_INTACT, environment='prod')
    f0 = r['findings'][0]
    check(f0['match'] == fm.IDENTITY_UNCOMPUTABLE and f0['routes_to'] == fm.EVIDENCE_UNTRUSTED
          and f0['baseline_state'] is None,
          'missing-evidence: an uncomputable identity resolved to %r / %r -- it must be neither a '
          'match nor NEW' % (f0['match'], f0['baseline_state']))

    # ── recovery ─────────────────────────────────────────────────────────────
    r = fm.match([a, b], ledger, fm.LEDGER_INTACT, environment='prod')
    check([f['match'] for f in r['findings']] == [fm.IDENTITY_MATCHED_EXACT] * 2
          and r['routes_to'] is None, 'recovery: a readable ledger did not restore matching')

    if fails:
        for f in fails:
            print('FAIL: ' + f)
        return 1
    print('PASS: on identities computed by identify(): unchanged -> EXACT with first_seen carried; '
          'relocated -> MOVED with the move recorded; introduced -> NEW; other environment -> NEW; '
          'removed -> POTENTIALLY_ABSENT; duplicated -> 1 continuation + 1 NEW by cardinality; '
          'unreadable ledger -> BASELINE_UNAVAILABLE / EVIDENCE_UNTRUSTED for every finding; '
          'uncomputable identity -> EVIDENCE_UNTRUSTED, neither matched nor NEW; recovery restores '
          'matching.')
    print('      THIS PROVES THE CASCADE OVER A LEDGER HANDED TO IT. Reading that ledger from the '
          'protected branch is tests/prove_ledger_read_authority.py.')
    return 0


if __name__ == '__main__':
    sys.exit(main())

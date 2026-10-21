#!/usr/bin/env python3
"""A scanner upgrade is a declared event, absorbed by an alias table, never a baseline reset (L46).

WHY THIS EXISTS (ETFB section 5.5)

    "A fingerprint scheme that survives no upgrade is a baseline that resets annually." Rule ids are
    the field a scanner upgrade renames, so WHAT never embeds one: it carries a rule FAMILY, and a
    reviewed alias table maps (scanner, version range, rule id) onto the family. Adding an alias is
    how an upgrade is absorbed; NOT adding one is how a baseline silently resets. And an upgrade is
    a declared event: the pinned generation changes, a reconciliation report compares the identity
    sets before and after, and the new generation is not authoritative for enforcement until a named
    approver accepts that report -- once, dated, inside a bounded window.

THE FOUR CASES

    allowed           a rule renamed across versions resolves to one family through the table,
                      so the identity computed by the real identify() is unchanged
    attack            no alias for the renamed rule -> no family -> WHAT_UNDERIVABLE, never a bare
                      rule id; conflicting aliases refuse; a changed generation with no accepted
                      reconciliation is not authoritative (DECISION_REQUIRED); a finding that
                      appears only after the upgrade is never NEW (it is admitted as
                      PRE_EXISTING_BY_DETECTION_CHANGE); one that disappears is POTENTIALLY_ABSENT,
                      never fixed; acceptance without an approver, after the window, or a second
                      time is refused -- the window is not a standing right
    missing-evidence  an observed scanner version that cannot be established -> EVIDENCE_UNTRUSTED;
                      an unparseable alias table refuses rather than resolving nothing
    recovery          after acceptance the new generation is authoritative

EXIT  0 proven   1 a case failed (named)   2 could not be checked (UNKNOWN, never PASS)
"""
import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, os.path.join(ROOT, 'scripts'))


def main():
    try:
        from finding_identity import identify
        import finding_match as fm
    except ImportError as exc:
        print('UNKNOWN: %s' % exc)
        return 2
    try:
        import rule_family as rf
    except ImportError as exc:
        print('FAIL: no rule-family alias table exists (%s). ETFB section 5.5 is designed and not '
              'built: every scanner upgrade that renames a rule resets the baseline for it.' % exc)
        return 1

    fails = []

    def check(cond, msg):
        if not cond:
            fails.append(msg)

    table_doc = {
        'schema_version': 1,
        'generations': {'semgrep': {'pinned': '1.45'}},
        'aliases': [
            {'scanner': 'semgrep', 'versions': '>=1.40,<1.90',
             'rule_id': 'python.lang.security.audit.subprocess-shell-true', 'family': 'os-command-shell'},
            {'scanner': 'semgrep', 'versions': '>=1.90,<2.0',
             'rule_id': 'python.lang.security.audit.dangerous-subprocess-use', 'family': 'os-command-shell'},
        ],
    }
    table, state, notes = rf.parse_table(json.dumps(table_doc))
    check(state == rf.USABLE and table, 'allowed: a well-formed alias table read as %r %r'
          % (state, notes))

    old_fam, old_basis = rf.resolve(table, 'semgrep', '1.45.0',
                                    'python.lang.security.audit.subprocess-shell-true')
    new_fam, new_basis = rf.resolve(table, 'semgrep', '1.92.1',
                                    'python.lang.security.audit.dangerous-subprocess-use')
    check(bool(old_fam) and old_fam == new_fam,
          'allowed: the renamed rule resolved to %r then %r (%s / %s)' % (old_fam, new_fam, old_basis,
                                                                          new_basis))

    def ident(family):
        rec = {'finding_subject': 'SOURCE', 'cwe': 'CWE-78', 'canonical_path': 'app.py',
               'symbol_path': 'app.run', 'construct': 'subprocess.run(cmd, shell=True)',
               'language_family': 'hash'}
        if family:
            rec['rule_family'] = family
        return identify(rec)

    before, after = ident(old_fam), ident(new_fam)
    check(before.get('identity') and before['identity'] == after.get('identity'),
          'allowed: the identity moved across an aliased rename -- the upgrade reset the baseline')

    # ── attack: a rename with no alias ───────────────────────────────────────
    none_fam, why = rf.resolve(table, 'semgrep', '1.92.1', 'python.lang.security.audit.brand-new-name')
    check(none_fam is None and why, 'attack: an unaliased rule resolved to %r' % none_fam)
    check(ident(none_fam).get('reason') == 'WHAT_UNDERIVABLE',
          'attack: with no family the identity was not refused -- a bare rule id must never stand '
          'in for a family')
    # Version outside every range: the alias does not apply.
    fam, _ = rf.resolve(table, 'semgrep', '3.0.0', 'python.lang.security.audit.dangerous-subprocess-use')
    check(fam is None, 'attack: an alias applied outside its version range')
    # Conflict
    clash = dict(table_doc, aliases=table_doc['aliases'] + [
        {'scanner': 'semgrep', 'versions': '>=1.90,<2.0',
         'rule_id': 'python.lang.security.audit.dangerous-subprocess-use', 'family': 'something-else'}])
    t2, st2, _n = rf.parse_table(json.dumps(clash))
    fam = rf.resolve(t2, 'semgrep', '1.92.1', 'python.lang.security.audit.dangerous-subprocess-use')[0] \
        if st2 == rf.USABLE else None
    check(fam is None, 'attack: two aliases naming different families for one rule resolved to %r' % fam)

    # ── the declared event ───────────────────────────────────────────────────
    g = rf.generation_check(table, 'semgrep', '1.92.1', accepted=[])
    check(g['changed'] and not g['authoritative'] and g['routes_to'] == 'DECISION_REQUIRED',
          'attack: an unreconciled generation change was treated as %r' % g)
    g_same = rf.generation_check(table, 'semgrep', '1.45.3', accepted=[])
    check(not g_same['changed'] and g_same['authoritative'], 'allowed: the pinned generation was '
                                                             'not authoritative: %r' % g_same)
    g_unknown = rf.generation_check(table, 'semgrep', '', accepted=[])
    check(not g_unknown['authoritative'] and g_unknown['routes_to'] == 'EVIDENCE_UNTRUSTED',
          'missing-evidence: an unknown scanner version gave %r' % g_unknown)

    # Reconciliation report over identity sets.
    stay = ident('os-command-shell')
    gone = identify({'finding_subject': 'SOURCE', 'cwe': 'CWE-89', 'rule_family': 'sqli',
                     'canonical_path': 'db.py', 'symbol_path': 'db.q', 'construct': 'q(x)'})
    appeared = identify({'finding_subject': 'SOURCE', 'cwe': 'CWE-22', 'rule_family': 'path',
                         'canonical_path': 'fs.py', 'symbol_path': 'fs.o', 'construct': 'open(p)'})
    report = rf.reconciliation_report([stay, gone], [stay, appeared], scanner='semgrep',
                                      from_generation='1.45', to_generation='1.92',
                                      opened_on='2026-10-14', window_days=14)
    check(report['continued'] == [stay['identity']], 'report: continued %r' % report['continued'])
    check([x['identity'] for x in report['disappeared']] == [gone['identity']]
          and all(x['classification'] == fm.POTENTIALLY_ABSENT for x in report['disappeared']),
          'attack: a finding that disappeared across the upgrade was not POTENTIALLY_ABSENT -- a '
          'scanner that stopped looking reads as a fix')
    check([x['identity'] for x in report['appeared']] == [appeared['identity']]
          and all(x['baseline_state'] == fm.PRE_EXISTING_BY_DETECTION_CHANGE for x in report['appeared']),
          'attack: a finding that appeared only because detection improved was not '
          'PRE_EXISTING_BY_DETECTION_CHANGE')
    check(report['acceptance'] is None and report['window_expires'] == '2026-10-28',
          'report: acceptance pre-filled or window wrong: %r / %r' % (report['acceptance'],
                                                                     report['window_expires']))
    for args, label in (((report, '', '2026-10-15'), 'no approver'),
                        ((report, 'security-lead', '2026-11-30'), 'after the window'),
                        ((report, 'security-lead', '2026-10-13'), 'before the report existed')):
        problems = rf.validate_acceptance(*args)
        check(bool(problems), 'attack: acceptance with %s was allowed' % label)
    ok = rf.validate_acceptance(report, 'security-lead', '2026-10-20')
    check(not ok, 'allowed: a valid acceptance was refused: %r' % ok)
    accepted = rf.accept(report, 'security-lead', '2026-10-20')
    check(rf.validate_acceptance(accepted, 'security-lead', '2026-10-21'),
          'attack: an already-accepted reconciliation was accepted again -- the window is one dated '
          'decision, not a standing right')

    # After acceptance: the generation is authoritative, and the appeared finding is never NEW.
    g2 = rf.generation_check(table, 'semgrep', '1.92.1', accepted=[accepted])
    check(g2['authoritative'], 'recovery: an accepted reconciliation did not make the generation '
                               'authoritative: %r' % g2)
    adm = rf.ledger_admissions(accepted, environment='prod', run_id='77',
                               observed_at='2026-10-20T00:00:00Z')
    check(adm and all(e['detection_change'] is True and e['age_established'] is False for e in adm),
          'admissions: detection-change entries asserted an age or lost their flag')
    r = fm.match([appeared], adm, fm.LEDGER_INTACT, environment='prod')
    check(r['findings'][0]['baseline_state'] == fm.PRE_EXISTING_BY_DETECTION_CHANGE,
          'attack: after the upgrade a newly-detected finding was %r -- an upgrade may never by '
          'itself create a NEW finding' % r['findings'][0]['baseline_state'])
    check(rf.ledger_admissions(report, environment='prod', run_id='77',
                               observed_at='2026-10-20T00:00:00Z') == [],
          'attack: an UNACCEPTED report produced ledger admissions')

    # ── missing evidence: an unparseable table ───────────────────────────────
    for text in ('', '{nope', json.dumps({'schema_version': 1, 'aliases': [{'scanner': 'x'}]})):
        _t, st, nt = rf.parse_table(text)
        check(st != rf.USABLE and nt, 'missing-evidence: alias table %r was usable' % text[:20])

    if fails:
        for f in fails:
            print('FAIL: ' + f)
        return 1
    print('PASS: an aliased rename keeps the identity; an unaliased one refuses as WHAT_UNDERIVABLE; '
          'out-of-range and conflicting aliases refuse; a changed generation is DECISION_REQUIRED '
          'until a reconciliation is accepted once, dated, by an approver inside its window; '
          'disappeared findings are POTENTIALLY_ABSENT and appeared ones are admitted as '
          'PRE_EXISTING_BY_DETECTION_CHANGE, never NEW; an unknown version is EVIDENCE_UNTRUSTED.')
    return 0


if __name__ == '__main__':
    sys.exit(main())

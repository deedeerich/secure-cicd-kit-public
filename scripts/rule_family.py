#!/usr/bin/env python3
"""The rule-family ALIAS TABLE, and the scanner upgrade as a DECLARED EVENT (ETFB section 5.5, L46).

WHY

    "A fingerprint scheme that survives no upgrade is a baseline that resets annually." The rule id
    is the field a scanner upgrade renames or splits, so finding_identity never puts one in WHAT:
    a CWE-only WHAT needs a `rule_family`, and the rule family comes from HERE -- a reviewed table on
    the protected branch, beside the ledger, mapping (scanner, version range, rule id) onto a stable
    family key. Adding an alias is how an upgrade is absorbed; NOT adding one is how a baseline
    silently resets. So an unaliased rule resolves to NOTHING, and the identity then refuses as
    WHAT_UNDERIVABLE rather than reaching for the bare rule id the identity exists to survive.

THE TABLE (.security/rule-family-aliases.json, protected branch, CODEOWNERS)

    {"schema_version": 1,
     "generations": {"<scanner>": {"pinned": "<major.minor>"}},
     "aliases": [{"scanner", "versions": ">=1.40,<1.90", "rule_id", "family"}]}

    Two aliases that match one (scanner, version, rule id) and name different families make that
    rule unresolvable: the table cannot be trusted to answer it, so it answers nothing.

AN UPGRADE IS A DECLARED EVENT

    The pinned generation is major.minor. When the observed scanner version's generation differs
    from the pin, `generation_check` says the new generation is NOT AUTHORITATIVE for enforcement
    and routes the scanner to DECISION_REQUIRED -- a reconciliation is owed -- until a
    reconciliation report for exactly that (from, to) pair has been accepted. A version that cannot
    be established is EVIDENCE_UNTRUSTED: a tool that cannot say what it is cannot be reconciled.

    `reconciliation_report` compares the identity sets before and after:

        continued     in both
        disappeared   POTENTIALLY_ABSENT -- never "fixed". A scanner that stopped looking and a
                      defect that stopped existing look the same in a report and are opposite
                      facts about the world.
        appeared      PRE_EXISTING_BY_DETECTION_CHANGE -- never NEW. Real findings, not the
                      author's doing; their age is NOT established and is never asserted as the
                      upgrade date.

    The window is BOUNDED and the acceptance is ONE dated decision by a named approver role: an
    acceptance with no approver, before the report existed, after its window, or a second time is
    refused. It is not a device for re-baselining a repository by upgrading something. Only an
    ACCEPTED report yields ledger admissions, and those go through propose-ledger's pull request
    like everything else -- this module writes nothing.

    The window length is a parameter, never a constant here: ETFB section 13 says every number in the
    design is a placeholder for an owner's decision.

USAGE
    python3 rule_family.py --self-test
    from rule_family import parse_table, resolve, generation_check, reconciliation_report
"""
import datetime
import json
import re
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

SCHEMA_VERSION = 1
default_table_path = '.security/rule-family-aliases.json'
USABLE = 'usable'
UNUSABLE = 'unusable'

POTENTIALLY_ABSENT = 'POTENTIALLY_ABSENT'
PRE_EXISTING_BY_DETECTION_CHANGE = 'PRE_EXISTING_BY_DETECTION_CHANGE'
DECISION_REQUIRED = 'DECISION_REQUIRED'
EVIDENCE_UNTRUSTED = 'EVIDENCE_UNTRUSTED'

_OPS = ('>=', '<=', '==', '>', '<')


def _s(v):
    return v.strip() if isinstance(v, str) else ''


def _vtuple(text):
    """'1.92.1' -> (1, 92, 1). None if no leading numeric component."""
    m = re.match(r'^\s*v?(\d+(?:\.\d+)*)', text or '')
    if not m:
        return None
    return tuple(int(x) for x in m.group(1).split('.'))


def generation(version):
    t = _vtuple(version)
    if not t:
        return ''
    return '.'.join(str(x) for x in (t + (0,))[:2])


def _parse_range(spec):
    """'>=1.40,<1.90' -> [(op, tuple)]. None if any clause is unparseable."""
    out = []
    for clause in (spec or '').split(','):
        clause = clause.strip()
        if not clause:
            return None
        op = next((o for o in _OPS if clause.startswith(o)), None)
        if not op:
            return None
        v = _vtuple(clause[len(op):])
        if v is None:
            return None
        out.append((op, v))
    return out or None


def _cmp(a, b):
    n = max(len(a), len(b))
    a, b = a + (0,) * (n - len(a)), b + (0,) * (n - len(b))
    return (a > b) - (a < b)


def _in_range(version, clauses):
    v = _vtuple(version)
    if v is None:
        return False
    for op, ref in clauses:
        c = _cmp(v, ref)
        if not {'>=': c >= 0, '<=': c <= 0, '==': c == 0, '>': c > 0, '<': c < 0}[op]:
            return False
    return True


def parse_table(text):
    """-> (table, state, notes). Any malformed alias makes the whole table UNUSABLE."""
    if not _s(text):
        return (None, UNUSABLE, ['the alias table is empty'])
    try:
        doc = json.loads(text)
    except ValueError as exc:
        return (None, UNUSABLE, ['not valid JSON: %s' % exc])
    notes = []
    if not isinstance(doc, dict) or doc.get('schema_version') != SCHEMA_VERSION:
        return (None, UNUSABLE, ['not a schema_version %d alias table' % SCHEMA_VERSION])
    gens = doc.get('generations') or {}
    if not isinstance(gens, dict):
        notes.append('generations is not an object')
        gens = {}
    for scanner, g in gens.items():
        if not isinstance(g, dict) or not generation(_s(g.get('pinned'))):
            notes.append('generation for %r has no parseable pinned version' % scanner)
    aliases = doc.get('aliases')
    if not isinstance(aliases, list):
        notes.append('aliases is not a list')
        aliases = []
    parsed = []
    for i, a in enumerate(aliases):
        if not isinstance(a, dict):
            notes.append('alias %d is not an object' % i)
            continue
        missing = [k for k in ('scanner', 'versions', 'rule_id', 'family') if not _s(a.get(k))]
        if missing:
            notes.append('alias %d lacks %s' % (i, ', '.join(missing)))
            continue
        clauses = _parse_range(a['versions'])
        if clauses is None:
            notes.append('alias %d: version range %r does not parse' % (i, a['versions']))
            continue
        parsed.append({'scanner': _s(a['scanner']).lower(), 'versions': a['versions'],
                       'clauses': clauses, 'rule_id': _s(a['rule_id']), 'family': _s(a['family'])})
    if notes:
        return (None, UNUSABLE, notes)
    return ({'generations': gens, 'aliases': parsed}, USABLE, ['%d alias(es)' % len(parsed)])


def read_table_at_ref(repo, ref, path=default_table_path):
    """The alias table, read the way the ledger is read: from a git ref, never a working tree."""
    import baseline_ledger as bl
    rc, out, err = bl._git(repo, 'show', '%s:%s' % (ref, path))
    if rc != 0:
        return (None, UNUSABLE, ['cannot read %s:%s: %s' % (ref, path, err)])
    return parse_table(out.decode('utf-8', 'replace'))


def resolve(table, scanner, version, rule_id):
    """-> (family, basis) or (None, why). Never falls back to the rule id."""
    if not table:
        return (None, 'no usable alias table')
    sc, rid = _s(scanner).lower(), _s(rule_id)
    if not _vtuple(version):
        return (None, 'scanner version %r cannot be established, so no version-ranged alias can be '
                      'applied' % (version,))
    hits = [a for a in table['aliases'] if a['scanner'] == sc and a['rule_id'] == rid
            and _in_range(version, a['clauses'])]
    families = sorted(set(a['family'] for a in hits))
    if not families:
        return (None, 'no alias for %s %s rule %r. Add one: that is how an upgrade is absorbed, '
                      'and a bare rule id is never a substitute' % (sc, version, rid))
    if len(families) > 1:
        return (None, 'aliases disagree for %s %s rule %r (%s). A table that answers two ways '
                      'answers nothing' % (sc, version, rid, ', '.join(families)))
    return (families[0], 'alias table: %s %s %r -> %s' % (sc, hits[0]['versions'], rid, families[0]))


def generation_check(table, scanner, observed_version, accepted=()):
    """-> {changed, authoritative, routes_to, pinned, observed, why}."""
    sc = _s(scanner).lower()
    observed = generation(observed_version)
    pin = generation(_s(((table or {}).get('generations') or {}).get(sc, {}).get('pinned')))
    out = {'changed': False, 'authoritative': False, 'routes_to': None, 'pinned': pin,
           'observed': observed, 'why': ''}
    if not observed:
        out.update(routes_to=EVIDENCE_UNTRUSTED,
                   why='the running %s version cannot be established; a tool that cannot say what '
                       'it is cannot be reconciled' % sc)
        return out
    if not pin:
        out.update(routes_to=DECISION_REQUIRED,
                   why='no generation is pinned for %s, so no upgrade can be declared against it' % sc)
        return out
    if observed == pin:
        out.update(authoritative=True, why='running the pinned generation %s' % pin)
        return out
    out['changed'] = True
    for rep in accepted or ():
        if (rep.get('scanner') == sc and rep.get('from_generation') == pin
                and rep.get('to_generation') == observed and rep.get('acceptance')):
            out.update(authoritative=True,
                       why='generation %s -> %s reconciled and accepted by %s on %s; update the pin'
                           % (pin, observed, rep['acceptance']['approver_role'],
                              rep['acceptance']['accepted_on']))
            return out
    out.update(routes_to=DECISION_REQUIRED,
               why='%s moved from the pinned generation %s to %s. The new generation is NOT '
                   'authoritative for enforcement until a reconciliation report for exactly this '
                   'change is accepted by a named approver' % (sc, pin, observed))
    return out


def _date(text):
    try:
        return datetime.date(*[int(x) for x in _s(text)[:10].split('-')])
    except (TypeError, ValueError):
        return None


def _keep(ident):
    return dict((k, ident.get(k)) for k in ('identity', 'what', 'where', 'content',
                                            'finding_subject', 'what_aliases'))


def reconciliation_report(before, after, scanner, from_generation, to_generation, opened_on,
                          window_days):
    """Compare identity sets across a generation change. Only FINGERPRINTED identities count; the
    rest are listed as not comparable, never silently dropped."""
    opened = _date(opened_on)
    if opened is None or not isinstance(window_days, int) or window_days <= 0:
        raise ValueError('a reconciliation needs an opening date and a positive window in days')

    def ids(items):
        good, bad = {}, []
        for x in items or []:
            if x.get('state') == 'FINGERPRINTED' and _s(x.get('identity')):
                good[x['identity']] = x
            else:
                bad.append(x.get('reason') or 'no identity')
        return good, bad

    b, bad_b = ids(before)
    a, bad_a = ids(after)
    return {
        'scanner': _s(scanner).lower(), 'from_generation': from_generation,
        'to_generation': to_generation, 'opened_on': opened.isoformat(),
        'window_expires': (opened + datetime.timedelta(days=window_days)).isoformat(),
        'continued': sorted(set(b) & set(a)),
        'disappeared': [dict(_keep(b[k]), classification=POTENTIALLY_ABSENT)
                        for k in sorted(set(b) - set(a))],
        'appeared': [dict(_keep(a[k]), baseline_state=PRE_EXISTING_BY_DETECTION_CHANGE)
                     for k in sorted(set(a) - set(b))],
        'not_comparable': {'before': bad_b, 'after': bad_a},
        'acceptance': None,
    }


def validate_acceptance(report, approver_role, accepted_on):
    problems = []
    if report.get('acceptance'):
        problems.append('this reconciliation was already accepted on %s. One generation change '
                        'grants ONE dated reconciliation; it is not a standing right'
                        % report['acceptance'].get('accepted_on'))
    if not _s(approver_role):
        problems.append('no approver role. An upgrade is a declared event with a named approver')
    when = _date(accepted_on)
    if when is None:
        problems.append('acceptance date %r does not parse' % (accepted_on,))
    else:
        if when < _date(report['opened_on']):
            problems.append('accepted before the report was opened')
        if when > _date(report['window_expires']):
            problems.append('accepted on %s, after the window closed on %s. A lapsed window is a '
                            'new decision, not a late signature' % (when, report['window_expires']))
    return problems


def accept(report, approver_role, accepted_on):
    problems = validate_acceptance(report, approver_role, accepted_on)
    if problems:
        raise ValueError('; '.join(problems))
    out = dict(report)
    out['acceptance'] = {'approver_role': _s(approver_role), 'accepted_on': _s(accepted_on)[:10]}
    return out


def ledger_admissions(report, environment, run_id, observed_at, observed_at_source='SIDECAR'):
    """Ledger entries for the findings that appeared because detection improved. ONLY from an
    accepted report; every entry is a detection change with NO established age."""
    import baseline_ledger as bl
    if not report.get('acceptance'):
        return []
    acc = report['acceptance']
    out = []
    for ident in report['appeared']:
        out.append(bl.entry_from_identity(
            ident, environment, _s(observed_at)[:10],
            {'run_id': run_id, 'observed_at': observed_at, 'observed_at_source': observed_at_source},
            False, detection_change=True,
            admitted_by='reconciliation %s %s -> %s, accepted by %s on %s' % (
                report['scanner'], report['from_generation'], report['to_generation'],
                acc['approver_role'], acc['accepted_on'])))
    return out


def _selftest():
    fails = []
    if generation('1.92.1') != '1.92' or generation('v2') != '2.0' or generation('x') != '':
        fails.append('generation() parsing')
    if not _in_range('1.45.0', _parse_range('>=1.40,<1.90')) or _in_range('1.90', _parse_range('<1.90')):
        fails.append('range evaluation')
    if _parse_range('~1.4') is not None or _parse_range('') is not None:
        fails.append('an unparseable range was accepted')
    t, st, _n = parse_table(json.dumps({'schema_version': 1, 'generations': {},
                                        'aliases': [{'scanner': 's', 'versions': '>=1', 'rule_id': 'r',
                                                     'family': 'f'}]}))
    if st != USABLE or resolve(t, 's', '', 'r')[0] is not None:
        fails.append('an unknown version resolved an alias')
    if fails:
        for f in fails:
            sys.stderr.write('FAIL: %s\n' % f)
        return 2
    print('rule_family selftest ok: versions, generations and ranges parse; an unparseable range '
          'and an unknown version refuse. The upgrade cases run in tests/prove_rule_family_upgrade.py.')
    return 0


if __name__ == '__main__':
    if len(sys.argv) == 2 and sys.argv[1] in ('--self-test', '--selftest'):
        sys.exit(_selftest())
    print('usage: rule_family.py --self-test   (library)', file=sys.stderr)
    sys.exit(2)

#!/usr/bin/env python3
"""A finding whose IDENTITY CHANGES keeps its disposition -- proven on identities a scanner produced.

WHY THIS FILE EXISTS, AND WHY `finding_lineage.py --self-test` DOES NOT COVER IT

    `finding_lineage.py --self-test` is thorough and it is green. It builds events out of
    hand-written hex strings -- 'a'*64 superseded by 'b'*64 -- and proves the resolver, the
    cardinality rules, the cycle refusal and the tamper detection. What it cannot establish is
    whether the identities a real scanner produces ever MOVE in the ways the ledger is built to
    record, or whether a disposition keyed on one of them survives the move.

    That is the same gap `tests/prove_identity_durability.py` exists to close one layer down, and
    it is the gap that matters: a ledger whose events nothing ever produces is a filing cabinet.

    So every identity in this file comes out of `scan_report.parse_sarif` -- the real entry
    point -- and the events are written with the CAUSE that actually moved them.

THE VACUOUS PASS THIS REFUSES, AND IT IS A DIFFERENT ONE FROM THE SIBLING FILE'S

    `prove_identity_durability.py` refuses `'' == ''`. This file's equivalent trap is the
    opposite shape: every assertion below would be satisfied by a pipeline where the identity
    NEVER MOVES, because then the old identity and the new one are the same string, the
    disposition is found by exact match, and `disposition_for` reports a cheerful
    DISPOSITION_KEYED_DIRECTLY having followed nothing at all. A test written that way would
    report working lineage over a ledger that was never consulted.

    THEREFORE, ASSERTED FIRST AND SEPARATELY, before any lineage claim:

      1  both identities are NON-EMPTY           -- or there is no identity to track
      2  they are DIFFERENT                      -- or there is no move to carry across
      3  the carry is reported as DISPOSITION_CARRIED_BY_LINEAGE, never as
         DISPOSITION_KEYED_DIRECTLY

    and the failure message for each says something different from the others, because "nothing
    computes an identity", "nothing ever moves" and "the ledger was not followed" have three
    different fixes.

WHAT THIS FILE DOES NOT ESTABLISH

    That anything in the pipeline WRITES these events today. Nothing does: detection requires
    comparing two scans against a stored record, and that comparison does not exist yet. This
    proves the record and the resolver are correct and sufficient for the four events the kit
    can already name -- it does not prove the kit notices when one of them happens.

    It also does not use real Semgrep or Trivy output. The SARIF builders are imported from
    `prove_identity_durability.py` so there is one fixture rather than two that drift, and they
    carry that file's stated limitation with them.

USAGE
    python tests/prove_lineage_durability.py
    python tests/prove_lineage_durability.py --self-test

EXIT
    0  identity moved, the move was recorded, and the disposition followed it
    1  a disposition was orphaned, a chain did not resolve, a cycle was followed, or a merge and
       a split collapsed into each other -- the message says which
    2  could not be checked -- reported as UNKNOWN, never as PASS
"""
import argparse
import io
import json
import os
import shutil
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, os.path.join(ROOT, 'scripts'))
sys.path.insert(0, HERE)

# Five failure vocabularies, kept apart for the same reason the sibling file keeps two: these
# have five different fixes and reporting them under one word sends the next reader to the wrong
# file.
NO_IDENTITY = 'IDENTITY_NEVER_COMPUTED'
NO_MOVEMENT = 'IDENTITY_NEVER_MOVED'
ORPHANED = 'DISPOSITION_ORPHANED'
CHAIN_BROKEN = 'LINEAGE_CHAIN_BROKEN'
RELATIONS_COLLAPSED = 'MERGE_AND_SPLIT_COLLAPSED'


def _pipeline(doc, scanner, workdir, tag):
    """-> (identity, finding) from the real reporter, or (None, reason)."""
    import scan_report
    path = os.path.join(workdir, '%s.sarif' % tag)
    with io.open(path, 'w', encoding='utf-8') as fh:
        json.dump(doc, fh)
    try:
        findings, state, _examination = scan_report.parse_sarif(path, scanner)
    except Exception as exc:                                       # noqa: BLE001
        return (None, 'parse_sarif RAISED %s: %s' % (type(exc).__name__, exc))
    if state != 'COMPLETE' or len(findings) != 1:
        return (None, 'parse_state=%s with %d finding(s)' % (state, len(findings)))
    return (findings[0]['identity'], findings[0])


def _event(src, dst, relation, cause, detail, actor, actor_class, when):
    from finding_lineage import _mkevent
    return _mkevent(src, dst, relation=relation, cause=cause, detail=detail,
                    actor=actor, actor_class=actor_class, when=when)


def _preamble(label, before, after, bad):
    """(1) non-empty, (2) actually different. ORDER IS THE POINT -- see the docstring."""
    if not before or not after:
        bad.append((NO_IDENTITY,
                    '%s: an identity is EMPTY (%r -> %r). There is nothing for a lineage ledger '
                    'to track, and every assertion below would pass over a pipeline that '
                    'computes no identity at all.' % (label, before, after)))
        return False
    if before == after:
        bad.append((NO_MOVEMENT,
                    '%s: the identity did NOT move (%s). This file exists to prove a disposition '
                    'survives a move; with no move, the register is matched by exact key and the '
                    'ledger is never consulted -- so a pass here would mean nothing. Either the '
                    'fixture no longer changes what it claims to change, or identity has stopped '
                    'depending on it.' % (label, before[:16])))
        return False
    return True


def scenario_move(workdir):
    """A FILE MOVED. One hop, and the exception approved before the move must still apply.

    This is the event an operator meets most often and understands least: nobody changed the
    code, a directory was reorganised, and every finding under it became NEW.
    """
    from prove_identity_durability import sast_sarif
    from finding_lineage import (append_event, load, disposition_for, LEDGER_INTACT,
                                 DISPOSITION_CARRIED_BY_LINEAGE, DISPOSITION_KEYED_DIRECTLY,
                                 SUPERSEDES, PATH_MOVED, OPERATOR)
    bad = []
    old, rec_old = _pipeline(sast_sarif('1.92.3', 'SQL built by concatenation',
                                        'python.lang.security.audit.sqli.sql-injection'),
                             'semgrep', workdir, 'move-before')
    new, rec_new = _pipeline(sast_sarif('1.92.3', 'SQL built by concatenation',
                                        'python.lang.security.audit.sqli.sql-injection',
                                        path='services/api/db/queries.py'),
                             'semgrep', workdir, 'move-after')
    if old is None or new is None:
        return [('UNPARSED', 'move: no comparable finding (%r / %r)' % (rec_old, rec_new))], None
    print('  %-30s old=%s' % ('a file moved', old[:16] or '(empty)'))
    print('  %-30s new=%s' % ('', new[:16] or '(empty)'))
    if not _preamble('move', old, new, bad):
        return bad, None

    ledger = os.path.join(workdir, 'move.jsonl')
    eid, refused = append_event(ledger, _event(
        old, new, SUPERSEDES, PATH_MOVED,
        'app/db/queries.py moved to services/api/db/queries.py in the monorepo split; the '
        'symbol and the construct are unchanged',
        'security-lead', OPERATOR, '2026-10-08T09:00:00Z'))
    if refused:
        return bad + [(CHAIN_BROKEN, 'move: the event was refused: %s' % '; '.join(refused))], None
    events, integrity, notes = load(ledger)
    if integrity != LEDGER_INTACT:
        bad.append((CHAIN_BROKEN, 'move: the ledger is %s (%s)' % (integrity, '; '.join(notes))))

    register = {old: {'state': 'ACCEPTED_RISK', 'expires': '2026-12-31',
                      'approver_role': 'security-lead',
                      'rationale': 'parameterisation is scheduled for the Q4 data-access rework'}}
    got = disposition_for(events, register, new)
    print('  %-30s %s via %s' % ('', got['basis'],
                                 (got['identity_keyed'] or '(none)')[:16]))
    if got['basis'] == DISPOSITION_KEYED_DIRECTLY:
        bad.append((NO_MOVEMENT,
                    'move: the approval matched DIRECTLY, which means the new identity equals the '
                    'old one and no lineage was followed. The scenario proved nothing.'))
    elif got['basis'] != DISPOSITION_CARRIED_BY_LINEAGE:
        bad.append((ORPHANED,
                    'move: the approval is %s. The finding was risk-accepted, a directory was '
                    'renamed, and it now reads as NEW and UNTRIAGED -- which is the silent '
                    'orphaning this ledger exists to end. (%s)' % (got['basis'], got['why'])))
    else:
        if got['identity_keyed'] != old:
            bad.append((ORPHANED, 'move: the carry names %r as the approved key, not the old '
                                  'identity' % got['identity_keyed']))
        if not got['requires_reaffirmation']:
            bad.append((ORPHANED,
                        'move: a CARRIED approval was not flagged for reaffirmation. An inference '
                        'never overwrites an observation: the approver approved the old key, and '
                        'a consumer must be able to see that the extension was machine-made.'))
        hop = (got['through'] or [{}])[0]
        if hop.get('cause') != PATH_MOVED:
            bad.append((CHAIN_BROKEN,
                        'move: the carry reports cause %r. Without the cause an operator cannot '
                        'tell a directory rename from the kit changing its own mind about how it '
                        'computes identity, and those deserve different amounts of trust.'
                        % hop.get('cause')))
        if not (hop.get('asserted_by') or {}).get('actor'):
            bad.append((CHAIN_BROKEN,
                        'move: the carry hop has no asserter. An unattributed alias is not '
                        'evidence -- it is a claim with nobody behind it.'))
        if hop.get('event_id') != eid:
            bad.append((CHAIN_BROKEN,
                        'move: the carry does not cite the event that authorised it (%r vs %r)'
                        % (hop.get('event_id'), eid)))
    return bad, (old, new, ledger)


def scenario_two_hops(workdir):
    """TWO MOVES. A directory split, then a refactor renamed the function.

    One hop is the easy case and the resolver that only does one hop looks correct until the
    second event lands. After a scanner upgrade followed by a refactor -- which is a normal
    quarter -- a one-hop resolver orphans everything it was built to protect.
    """
    from prove_identity_durability import sast_sarif
    from finding_lineage import (append_event, load, disposition_for, resolve,
                                 DISPOSITION_CARRIED_BY_LINEAGE, LINEAGE_RESOLVED,
                                 SUPERSEDES, PATH_MOVED, EXTRACTION_CORRECTED, TOOL, OPERATOR)
    bad = []
    first, _a = _pipeline(sast_sarif('1.45.0', 'm', 'python.lang.security.audit.sqli.sql-injection'),
                          'semgrep', workdir, 'h0')
    second, _b = _pipeline(sast_sarif('1.45.0', 'm', 'python.lang.security.audit.sqli.sql-injection',
                                      path='services/api/db/queries.py'),
                           'semgrep', workdir, 'h1')
    third, _c = _pipeline(sast_sarif('1.45.0', 'm', 'python.lang.security.audit.sqli.sql-injection',
                                     path='services/api/db/queries.py',
                                     symbol='app.db.queries.load_user'),
                          'semgrep', workdir, 'h2')
    if None in (first, second, third):
        return [('UNPARSED', 'two-hops: no comparable findings')]
    print('  %-30s %s -> %s -> %s' % ('two hops', first[:10], second[:10], third[:10]))
    if not _preamble('two-hops/first', first, second, bad):
        return bad
    if not _preamble('two-hops/second', second, third, bad):
        return bad
    if first == third:
        bad.append((NO_MOVEMENT, 'two-hops: the first and third identities are equal, so the '
                                 'chain is a loop rather than a chain'))

    ledger = os.path.join(workdir, 'two-hops.jsonl')
    append_event(ledger, _event(first, second, SUPERSEDES, PATH_MOVED,
                                'monorepo split moved the data-access package',
                                'security-lead', OPERATOR, '2026-10-01T09:00:00Z'))
    append_event(ledger, _event(second, third, SUPERSEDES, EXTRACTION_CORRECTED,
                                'fetch_user was renamed load_user by the Q4 refactor and the '
                                'symbol-path extraction now reports the new name',
                                'scripts/scan_report.py', TOOL, '2026-10-08T09:00:00Z'))
    events, _integrity, _notes = load(ledger)

    got = resolve(events, first)
    if not (got['state'] == LINEAGE_RESOLVED and got['current'] == third and got['hops'] == 2):
        bad.append((CHAIN_BROKEN,
                    'two-hops: resolution gave state=%s current=%s hops=%s. A resolver that stops '
                    'at the first hop loses every identity that moved twice.'
                    % (got['state'], (got['current'] or '')[:16], got['hops'])))
    register = {first: {'state': 'FALSE_POSITIVE', 'expires': '2027-01-31',
                        'approver_role': 'app-owner',
                        'rationale': 'the concatenated value is a validated enum, not user input'}}
    carried = disposition_for(events, register, third)
    if carried['basis'] != DISPOSITION_CARRIED_BY_LINEAGE:
        bad.append((ORPHANED,
                    'two-hops: the approval is %s after TWO moves (%s). One hop of tolerance is '
                    'not continuity.' % (carried['basis'], carried['why'])))
    elif len(carried['through']) != 2:
        bad.append((CHAIN_BROKEN,
                    'two-hops: the carry reports %d hop(s), not 2, so the operator cannot see '
                    'both causes' % len(carried['through'])))
    elif [h['cause'] for h in carried['through']] != [PATH_MOVED, EXTRACTION_CORRECTED]:
        bad.append((CHAIN_BROKEN,
                    'two-hops: the carry reports causes %r, in the wrong order or wrong set -- '
                    'the route is evidence and it has to be the route actually taken'
                    % [h['cause'] for h in carried['through']]))
    return bad


def scenario_alias(workdir):
    """AN ADVISORY GAINED AN ALIAS. The dependency case, and the one nobody sees coming.

    WHAT for a dependency finding is the alias SET. A feed adding a GHSA id beside an existing
    CVE changes the set, so the identity moves -- without any scanner upgrade, any code change,
    or anything at all happening inside the repository. The asserter here is the FEED, and
    recording that is the difference between an auditable carry and an anonymous one.
    """
    from prove_identity_durability import dep_sarif
    from finding_lineage import (append_event, load, disposition_for,
                                 DISPOSITION_CARRIED_BY_LINEAGE, SUPERSEDES,
                                 ADVISORY_ALIAS_ADDED, ADVISORY_FEED)
    bad = []
    before = dep_sarif('0.56.1', 'requests: Authorization header leak on redirect',
                       'CVE-2018-18074')
    after = dep_sarif('0.56.1', 'requests: Authorization header leak on redirect',
                      'CVE-2018-18074')
    # The feed added the GHSA alias. It arrives in the rule metadata, which is where a scanner
    # puts an advisory's aliases, and `what_of` lifts it into the alias set.
    after['runs'][0]['tool']['driver']['rules'][0]['properties']['aliases'] = \
        ['GHSA-x84v-xcm2-53pg']
    old, _a = _pipeline(before, 'trivy', workdir, 'alias-before')
    new, _b = _pipeline(after, 'trivy', workdir, 'alias-after')
    if old is None or new is None:
        return [('UNPARSED', 'alias: no comparable finding')]
    print('  %-30s old=%s new=%s' % ('advisory alias added', old[:12] or '(empty)',
                                     new[:12] or '(empty)'))
    if not _preamble('alias', old, new, bad):
        return bad

    ledger = os.path.join(workdir, 'alias.jsonl')
    append_event(ledger, _event(
        old, new, SUPERSEDES, ADVISORY_ALIAS_ADDED,
        'osv.dev added GHSA-x84v-xcm2-53pg as an alias of CVE-2018-18074, so the alias set that '
        'composes WHAT is no longer the same set',
        'osv.dev', ADVISORY_FEED, '2026-10-08T09:00:00Z'))
    events, _i, _n = load(ledger)
    register = {old: {'state': 'MITIGATED', 'expires': '2027-03-31',
                      'approver_role': 'platform-owner',
                      'compensating_control': 'egress proxy strips Authorization on cross-origin '
                                              'redirects'}}
    carried = disposition_for(events, register, new)
    if carried['basis'] != DISPOSITION_CARRIED_BY_LINEAGE:
        bad.append((ORPHANED,
                    'alias: the approval is %s. Nothing in the repository changed and nothing in '
                    'the scanner changed -- an upstream feed re-aliased an advisory -- and the '
                    'mitigation stopped applying. (%s)' % (carried['basis'], carried['why'])))
    else:
        hop = carried['through'][0]
        if (hop.get('asserted_by') or {}).get('actor_class') != ADVISORY_FEED:
            bad.append((CHAIN_BROKEN,
                        'alias: the carry records actor_class %r, not ADVISORY_FEED. A human '
                        'decision, a tool\'s output and a feed re-aliasing an advisory are not '
                        'interchangeable evidence.'
                        % (hop.get('asserted_by') or {}).get('actor_class')))
    return bad


def scenario_cycle(workdir):
    """A CYCLE IS REFUSED. Somebody will record one; the resolver must not spin on it."""
    from finding_lineage import (append_event, load, resolve, disposition_for,
                                 LINEAGE_CYCLE_REFUSED, DISPOSITION_NOT_FOUND,
                                 SUPERSEDES, PATH_MOVED, SUBJECT_SPEC_CHANGED, OPERATOR)
    from prove_identity_durability import sast_sarif
    bad = []
    one, _a = _pipeline(sast_sarif('1.45.0', 'm', 'a.b.sqli'), 'semgrep', workdir, 'c0')
    two, _b = _pipeline(sast_sarif('1.45.0', 'm', 'a.b.sqli', path='b/x.py'),
                        'semgrep', workdir, 'c1')
    if one is None or two is None or not one or not two or one == two:
        return [('UNPARSED', 'cycle: could not build two distinct identities')]
    ledger = os.path.join(workdir, 'cycle.jsonl')
    append_event(ledger, _event(one, two, SUPERSEDES, PATH_MOVED, 'moved',
                                'security-lead', OPERATOR, '2026-10-01T00:00:00Z'))
    append_event(ledger, _event(two, one, SUPERSEDES, SUBJECT_SPEC_CHANGED,
                                'recorded in error -- this closes a loop on purpose',
                                'security-lead', OPERATOR, '2026-10-02T00:00:00Z'))
    events, _i, _n = load(ledger)
    got = resolve(events, one)
    print('  %-30s %s' % ('a cycle', got['state']))
    if got['state'] != LINEAGE_CYCLE_REFUSED:
        bad.append((CHAIN_BROKEN,
                    'cycle: resolution returned %s instead of refusing. A resolver that loops '
                    'turns a data error into a hung job; one that returns the last identity it '
                    'saw reports a guess as an answer.' % got['state']))
    if got['current'] is not None:
        bad.append((CHAIN_BROKEN,
                    'cycle: a refusal still produced a current identity %r' % got['current']))
    carry = disposition_for(events, {one: {'state': 'ACCEPTED_RISK'}}, two)
    if carry['basis'] != DISPOSITION_NOT_FOUND:
        bad.append((CHAIN_BROKEN,
                    'cycle: a disposition was carried across a cyclic ancestry as %s. The '
                    'nearest ancestor found before the loop is a guess, and a guessed approval '
                    'is worse than a missing one.' % carry['basis']))
    return bad


def scenario_merge_and_split(workdir):
    """A MERGE AND A SPLIT MUST NOT COLLAPSE. Two findings turning out to be one is not one
    finding becoming two.

    Built over the SAME three identities in both directions, which is the only construction that
    can catch a resolver that treats the relation as a symmetric edge: if merge and split were
    interchangeable, these two ledgers would answer identically.
    """
    from prove_identity_durability import sast_sarif, dep_sarif
    from finding_lineage import (append_event, load, resolve, describe, disposition_for,
                                 LINEAGE_RESOLVED, LINEAGE_TERMINAL, LINEAGE_SPLIT_UNRESOLVED,
                                 DISPOSITION_CARRIED_BY_LINEAGE, DISPOSITION_NOT_FOUND,
                                 MERGED_INTO, SPLIT_INTO, CORRELATION_ESTABLISHED,
                                 SUBJECT_SPEC_CHANGED, TOOL, OPERATOR)
    bad = []
    a, _1 = _pipeline(sast_sarif('1.45.0', 'm', 'a.b.sqli'), 'semgrep', workdir, 'm0')
    b, _2 = _pipeline(dep_sarif('0.56.1', 'requests advisory', 'CVE-2018-18074'),
                      'trivy', workdir, 'm1')
    c, _3 = _pipeline(sast_sarif('1.45.0', 'm', 'a.b.sqli', path='c/y.py'),
                      'semgrep', workdir, 'm2')
    if not (a and b and c) or len({a, b, c}) != 3:
        return [('UNPARSED', 'merge/split: could not build three distinct identities')]

    merge_ledger = os.path.join(workdir, 'merge.jsonl')
    split_ledger = os.path.join(workdir, 'split.jsonl')
    append_event(merge_ledger, _event(
        [a, b], c, MERGED_INTO, CORRELATION_ESTABLISHED,
        'semgrep and trivy were reporting one condition; correlation established they are one',
        'correlator', TOOL, '2026-10-08T09:00:00Z'))
    append_event(split_ledger, _event(
        c, [a, b], SPLIT_INTO, SUBJECT_SPEC_CHANGED,
        'one aggregate entry was in fact two separate conditions once the subject spec '
        'distinguished them',
        'security-lead', OPERATOR, '2026-10-08T09:00:00Z'))
    merged, _mi, _mn = load(merge_ledger)
    splitd, _si, _sn = load(split_ledger)

    for member in (a, b):
        got = resolve(merged, member)
        if not (got['state'] == LINEAGE_RESOLVED and got['current'] == c):
            bad.append((CHAIN_BROKEN,
                        'merge: resolving source %s gave %s/%s. Every source of a merge must '
                        'reach the survivor: each was an approval of the SAME condition, so each '
                        'must still apply to it.'
                        % (member[:10], got['state'], (got['current'] or '')[:10])))
    if resolve(merged, c)['state'] != LINEAGE_TERMINAL:
        bad.append((CHAIN_BROKEN, 'merge: the survivor is not terminal'))

    got = resolve(splitd, c)
    print('  %-30s merge(%s) split(%s)' % ('merge vs split', resolve(merged, a)['state'],
                                           got['state']))
    if got['state'] != LINEAGE_SPLIT_UNRESOLVED:
        bad.append((RELATIONS_COLLAPSED,
                    'split: the source resolved as %s. A split must REFUSE -- picking one '
                    'successor hands this finding\'s approval to a condition nobody approved and '
                    'silently drops the others.' % got['state']))
    if sorted(got['candidates'] or []) != sorted([a, b]):
        bad.append((RELATIONS_COLLAPSED,
                    'split: the refusal did not name both candidates, so an operator cannot go '
                    'and triage them (%r)' % [x[:10] for x in (got['candidates'] or [])]))

    # THE DISCRIMINATOR. Same three identities, opposite relation, and the answers must differ.
    merge_answers = (resolve(merged, a)['state'], resolve(merged, c)['state'])
    split_answers = (resolve(splitd, a)['state'], resolve(splitd, c)['state'])
    if merge_answers == split_answers:
        bad.append((RELATIONS_COLLAPSED,
                    'merge and split over the same three identities answered identically %r. The '
                    'relation is being treated as a symmetric edge, so "two findings turned out '
                    'to be one" and "one finding became two" are the same record.'
                    % (merge_answers,)))
    if describe(merged, c)['merged_from'] and describe(splitd, c)['merged_from']:
        bad.append((RELATIONS_COLLAPSED,
                    'the split source describes itself as having been MERGED FROM something'))
    if describe(splitd, c)['split_into'] and describe(merged, c)['split_into']:
        bad.append((RELATIONS_COLLAPSED,
                    'the merge survivor describes itself as having been SPLIT INTO something'))

    # A disposition on one source of a MERGE carries to the survivor. The reverse does not: a
    # disposition on a SPLIT source must NOT be handed to one of the products.
    carried = disposition_for(merged, {a: {'state': 'ACCEPTED_RISK'}}, c)
    if carried['basis'] != DISPOSITION_CARRIED_BY_LINEAGE:
        bad.append((ORPHANED, 'merge: an approval on a merged source did not reach the survivor '
                              '(%s)' % carried['basis']))
    # THE SPLIT'S PRODUCTS, AND THE JUDGEMENT THIS LOCKS IN.
    #
    # Looking FORWARD from a split source refuses: there is no single successor. Looking BACKWARD
    # from a product finds the aggregate's approval, and this asserts it is carried AND flagged
    # for reaffirmation rather than either dropped or applied silently.
    #
    # Dropping it would re-raise, as brand-new, conditions somebody has already accepted -- the
    # orphaning this ledger exists to end. Applying it silently would be worse: an approval given
    # to an aggregate nobody re-examined would suppress each of its parts. Carried-and-flagged is
    # the only answer that is neither, and it is only available because the two bases are
    # separate states.
    handed = disposition_for(splitd, {c: {'state': 'ACCEPTED_RISK'}}, a)
    if handed['basis'] != DISPOSITION_CARRIED_BY_LINEAGE:
        bad.append((ORPHANED,
                    'split: a product of a split reported %s for the aggregate\'s approval. '
                    'Dropping it re-raises an already-accepted condition as brand-new work.'
                    % handed['basis']))
    elif not handed['requires_reaffirmation']:
        bad.append((RELATIONS_COLLAPSED,
                    'split: a product inherited the aggregate approval WITHOUT being flagged for '
                    'reaffirmation. The approval was given to something nobody re-examined after '
                    'it turned out to be several things, and suppressing each part on that '
                    'authority is the permissive direction.'))
    else:
        print('  %-30s split product carries the aggregate approval, flagged for reaffirmation'
              % '')
    return bad


def scenario_unknown_vs_terminal(workdir):
    """"NOT KNOWN" AND "NO SUCCESSOR" ARE DIFFERENT ANSWERS.

    The cheap resolver returns the input identity for both, and then a finding with a recorded
    history is indistinguishable from one the estate has never seen. One of those is triaged and
    tracked; the other is new work.
    """
    from prove_identity_durability import sast_sarif
    from finding_lineage import (append_event, load, resolve, LINEAGE_UNKNOWN, LINEAGE_TERMINAL,
                                 SUPERSEDES, PATH_MOVED, OPERATOR)
    bad = []
    known_old, _a = _pipeline(sast_sarif('1.45.0', 'm', 'a.b.sqli'), 'semgrep', workdir, 'u0')
    known_new, _b = _pipeline(sast_sarif('1.45.0', 'm', 'a.b.sqli', path='u/x.py'),
                              'semgrep', workdir, 'u1')
    stranger, _c = _pipeline(sast_sarif('1.45.0', 'm', 'a.b.sqli', path='never/seen.py'),
                             'semgrep', workdir, 'u2')
    if not (known_old and known_new and stranger):
        return [('UNPARSED', 'unknown/terminal: could not build identities')]
    ledger = os.path.join(workdir, 'known.jsonl')
    append_event(ledger, _event(known_old, known_new, SUPERSEDES, PATH_MOVED, 'moved',
                                'security-lead', OPERATOR, '2026-10-08T09:00:00Z'))
    events, _i, _n = load(ledger)
    terminal = resolve(events, known_new)
    unknown = resolve(events, stranger)
    print('  %-30s terminal=%s unknown=%s' % ('unknown vs terminal', terminal['state'],
                                              unknown['state']))
    if terminal['state'] != LINEAGE_TERMINAL:
        bad.append((CHAIN_BROKEN,
                    'the live end of a recorded chain reported %s, not LINEAGE_TERMINAL'
                    % terminal['state']))
    if unknown['state'] != LINEAGE_UNKNOWN:
        bad.append((CHAIN_BROKEN,
                    'an identity the ledger has never seen reported %s, not LINEAGE_UNKNOWN'
                    % unknown['state']))
    if terminal['state'] == unknown['state']:
        bad.append((CHAIN_BROKEN,
                    'LINEAGE_TERMINAL and LINEAGE_UNKNOWN collapsed into one answer, so a '
                    'tracked finding reads exactly like untracked new work'))
    if unknown['current'] is not None:
        bad.append((CHAIN_BROKEN,
                    'an unknown identity was resolved to %r. Returning the input makes a failure '
                    'read as a successful resolution, which is how the collapse happens in '
                    'practice.' % unknown['current']))
    return bad


def prove():
    workdir = tempfile.mkdtemp(prefix='lineage-')
    try:
        print('=== an identity that MOVED, and what happened to its approval ===')
        print('')
        bad, _handle = scenario_move(workdir)
        print('')
        bad += scenario_two_hops(workdir)
        print('')
        bad += scenario_alias(workdir)
        print('')
        print('=== the refusals, which are not failures ===')
        print('')
        bad += scenario_cycle(workdir)
        print('')
        bad += scenario_merge_and_split(workdir)
        print('')
        bad += scenario_unknown_vs_terminal(workdir)
        return bad
    finally:
        # ONLY the exact path mkdtemp returned.
        shutil.rmtree(workdir, ignore_errors=True)


def self_test():
    """Prove this file can fail, and prove it cannot pass vacuously.

    Three things are asserted, and the second is the one that matters: that the preamble REFUSES
    a pair of identities that did not move. Without it every scenario here would pass over a
    pipeline whose identities never change, by exact-matching the register and never opening the
    ledger.
    """
    from finding_lineage import (append_event, load, resolve, disposition_for, validate_event,
                                 LEDGER_ABSENT, LINEAGE_UNKNOWN, DISPOSITION_NOT_FOUND,
                                 SUPERSEDES, PATH_MOVED, OPERATOR)
    fails = []
    work = tempfile.mkdtemp(prefix='lineage-st2-')
    try:
        # 1. The preamble refuses an EMPTY identity, and says so under its own name.
        bad = []
        if _preamble('st', '', 'b' * 64, bad) or not any(c == NO_IDENTITY for c, _ in bad):
            fails.append('an EMPTY identity was accepted as something to track. Every lineage '
                         'claim below would then pass over a pipeline that computes no identity.')

        # 2. THE LOAD-BEARING ONE. The preamble refuses a pair that did not move.
        bad = []
        if _preamble('st', 'a' * 64, 'a' * 64, bad) or not any(c == NO_MOVEMENT for c, _ in bad):
            fails.append('two IDENTICAL identities were accepted as a move. This is the vacuous '
                         'pass this file exists to refuse: with no move, the register matches by '
                         'exact key, the ledger is never consulted, and every scenario reports '
                         'working lineage over a ledger nothing read.')
        if any(c == NO_IDENTITY for c, _ in bad):
            fails.append('a non-empty pair that did not move was reported as NO_IDENTITY -- the '
                         'failure vocabularies have collapsed and a reader cannot tell "nothing '
                         'computes an identity" from "nothing ever moves"')

        # 3. An ABSENT ledger answers UNKNOWN for everything, and that must not read as a carry.
        missing = os.path.join(work, 'does-not-exist.jsonl')
        events, state, _notes = load(missing)
        if state != LEDGER_ABSENT:
            fails.append('a missing ledger reported %r rather than LEDGER_ABSENT' % state)
        if resolve(events, 'a' * 64)['state'] != LINEAGE_UNKNOWN:
            fails.append('an absent ledger did not answer LINEAGE_UNKNOWN')
        got = disposition_for(events, {'a' * 64: {'state': 'ACCEPTED_RISK'}}, 'b' * 64)
        if got['basis'] != DISPOSITION_NOT_FOUND:
            fails.append('an absent ledger produced a disposition carry (%s). A ledger nobody is '
                         'keeping must not be able to extend an approval.' % got['basis'])

        # 4. The event validator refuses an unattributed event, so the scenarios above cannot be
        #    recording anonymous links and reporting them as evidence.
        if not validate_event(dict(_event('a' * 64, 'b' * 64, SUPERSEDES, PATH_MOVED, 'd',
                                          'who', OPERATOR, '2026-01-01T00:00:00Z'),
                                   asserted_by=None)):
            fails.append('an event with no asserter was accepted as valid')

        # 5. The scenarios must actually RUN. A proof whose scenarios all return UNPARSED exits 0
        #    on an empty failure list, which is the other way this file could lie.
        probe = tempfile.mkdtemp(prefix='lineage-st3-')
        try:
            bad, handle = scenario_move(probe)
            if handle is None:
                fails.append('scenario_move produced no identities at all, so its empty failure '
                             'list means "it did not run" rather than "it passed"')
            eid, refused = append_event(os.path.join(probe, 'x.jsonl'),
                                        _event('a' * 64, 'b' * 64, SUPERSEDES, PATH_MOVED, 'd',
                                               'who', OPERATOR, '2026-01-01T00:00:00Z'))
            if refused or not eid:
                fails.append('a valid event could not be appended: %r' % refused)
        finally:
            shutil.rmtree(probe, ignore_errors=True)
    finally:
        shutil.rmtree(work, ignore_errors=True)

    if fails:
        for f in fails:
            sys.stderr.write('FAIL: %s\n' % f)
        return 2
    print('self-test ok: an EMPTY identity is refused as untrackable; two IDENTICAL identities '
          'are refused as a non-move, which is the vacuous pass this file exists to prevent -- '
          'without it every scenario would exact-match the register and never open the ledger; '
          'the two failure vocabularies stay apart, so "nothing computes an identity" cannot be '
          'read as "nothing ever moves"; an ABSENT ledger answers LINEAGE_UNKNOWN and cannot '
          'extend an approval; an unattributed event is refused; and scenario_move genuinely '
          'produces identities, so an empty failure list means it passed rather than that it '
          'never ran.')
    return 0


def main():
    ap = argparse.ArgumentParser(
        description='A finding whose identity changes keeps its disposition -- proven on '
                    'identities the reporter actually produced, through an append-only ledger.')
    ap.add_argument('--self-test', action='store_true',
                    help='prove this proof can fail, including on the identity-never-moved pass')
    a = ap.parse_args()
    if a.self_test:
        return self_test()

    try:
        import scan_report            # noqa: F401
        import finding_lineage        # noqa: F401
        import prove_identity_durability  # noqa: F401
    except ImportError as exc:
        print('UNKNOWN: cannot import the reporter, the ledger or the SARIF fixtures (%s). A '
              'check that could not execute is not a pass.' % exc)
        return 2

    bad = prove()
    print('')
    print('=' * 74)
    if not bad:
        print('PASS: an identity that MOVED -- by a file move, by a refactor two hops later, and')
        print('      by an upstream feed adding an advisory alias -- kept its disposition, which')
        print('      is reported as CARRIED and flagged for reaffirmation rather than as a direct')
        print('      approval. A cycle is refused. A merge resolves and a split does not, and the')
        print('      two do not collapse. "Not known" and "no successor" stay different answers.')
        print('')
        print('      THIS DOES NOT PROVE ANYTHING WRITES THESE EVENTS. Detection needs two scans')
        print('      compared against a stored record and that comparison does not exist yet.')
        return 0

    groups = (
        ('IDENTITY NEVER COMPUTED', NO_IDENTITY),
        ('IDENTITY NEVER MOVED -- THE SCENARIO PROVED NOTHING', NO_MOVEMENT),
        ('DISPOSITION ORPHANED', ORPHANED),
        ('LINEAGE CHAIN BROKEN', CHAIN_BROKEN),
        ('MERGE AND SPLIT COLLAPSED', RELATIONS_COLLAPSED),
        ('NO COMPARABLE FINDING', 'UNPARSED'),
    )
    for label, code in groups:
        rows = [m for c, m in bad if c == code]
        if not rows:
            continue
        sys.stderr.write('\n-- %s --\n' % label)
        for m in rows:
            sys.stderr.write('::error::%s\n' % m)
    sys.stderr.write('\nLINEAGE_NOT_DURABLE -- %d failure(s).\n' % len(bad))
    return 1


if __name__ == '__main__':
    sys.exit(main())

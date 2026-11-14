#!/usr/bin/env python3
"""The lineage ledger's CONSUMERS: the report, the ticket binding and the run record (R03, P1).

WHY THIS FILE EXISTS

    External Product Assurance Review 2026-11-07, finding R03, reproduced against e26f683:
    `scripts/finding_lineage.py` correctly answers DISPOSITION_CARRIED_BY_LINEAGE, with
    requires_reaffirmation, for a finding whose identity moved from A to B with an intact ledger
    between them. And then nothing asked it. `scripts/scan_report.py disposition_for(B)` looked
    up only B's durable key and the temporary legacy fingerprint, so the report on B showed no
    record, no basis and no explanation -- the approval on A was orphaned exactly as if the ledger
    did not exist. `scripts/reconcile_tickets.py rebind` bound only identities already written in
    the ticket ledger or a swept ticket body, so B opened a second ticket beside A's.

    `tests/prove_lineage_durability.py` proves the RESOLVER. This proves the resolver is USED.

WHAT IT PROVES

  POSITIVE
    P1  a scanner result whose PATH moved (A -> B, SUPERSEDES / PATH_MOVED, intact ledger): the
        report on B names A's decision with its basis (claim, rationale, approver role, expiry),
        marks it DISPOSITION_CARRIED_BY_LINEAGE, names the cause and the event, and surfaces a
        PENDING decision; it does NOT suppress until reaffirmed on B
    P2  a two-hop move whose second hop is an EXTRACTION correction carries the same way
    P3  a decision keyed DIRECTLY on B is reported as `durable`, never as carried, and suppresses
    P4  ticket continuity: B binds to A's ticket (no second ticket), and the ticket ledger entry
        records that the binding was carried by lineage, from which identity, by which event
    P5  the command lines take `--lineage` (scan_report single and batch, reconcile_tickets),
        and the batch report states the lineage ledger it read
    P6  the exported history: the batch findings file (projected by evidence_export) records
        disposition_basis -- DISPOSITION_CARRIED_BY_LINEAGE for B, durable for a direct decision
  NEGATIVE
    N1  SPLIT: A SPLIT_INTO B, C -- the report on B carries A's decision PENDING and names the
        split; the tickets for B and C are BINDING_AMBIGUOUS (nothing created, nothing bound)
    N2  MERGE: A1, A2 MERGED_INTO B with separate tickets -- the report names BOTH prior decisions,
        pending; the ticket is BINDING_AMBIGUOUS and NOT auto-merged (no ticket absorbed)
    N3  CYCLE: the report refuses the carry by name (lineage-refused); the ticket is ambiguous
    N4  MISSING LEDGER: the report states LEDGER_ABSENT; nothing is carried, nothing suppressed
        N4b (finding 8) with A approved and not reported this run, and B the same scanner and rule
        at a new path: B carries LINEAGE_RECONCILIATION_UNRESOLVED naming A's decision, pending,
        never suppressing; N4c A still reported: nothing indicated; N4d unrelated: nothing
        N4e (finding 8, ticket side) ledger absent, coverage established, A gone and B (same scanner
        and rule) new: A's ticket is NOT closed as a clearance; held POTENTIALLY_ABSENT under
        LINEAGE_RECONCILIATION_UNRESOLVED naming A, B and B's ticket. N4f an old ticket ledger with
        no rule recorded: held, basis LINEAGE_RULE_NOT_RECORDED, never a silent close
    N5  TAMPERED LEDGER: the report refuses the carry naming LEDGER_TAMPERED and the ancestor's
        decision it would have carried; the ticket is ambiguous, never bound, never created
    N6  EXPIRED approval on A: carried, shown EXPIRED, pending, never suppressing
    N7  DIRECTLY BOUND + SPLIT (review 2026-11-09 finding 7): B already has its own ticket and the
        ledger says ticketed A was SPLIT INTO B, C -- B is BINDING_AMBIGUOUS naming the split, A's
        ticket and B's own; nothing bound, created, merged or closed; keyed on B's direct binding
    N8  DIRECTLY BOUND + MERGE: A1, A2 (each ticketed) MERGED INTO a directly bound B -- the same
    N9  DIRECTLY BOUND + MOVE: ticketed A SUPERSEDES a directly bound B with another ticket -- held
        ('direct:'), A's obligation named, never absorbed or dropped
    P8  a genuine clearance still closes with the ledger absent: nothing new, a different rule, a
        different scanner; and with an intact ledger recording no move
    P7  a direct binding that CONTINUES the lineage obligation (the run after a carry) binds
        normally: the direct binding stays authoritative for its own identity
  MUTANTS (each must be caught by the cases above)
    M1  carried-suppresses       a carried decision suppresses like a direct one
    M2  lineage-not-consulted    the report never asks the resolver (the reviewer's defect)
    M3  split-binds              a ticket binding is carried across a split
    M4  tampered-trusted         a carry is made from a ledger that is not intact
    M5  skip-lineage-when-bound  lineage is not evaluated for a directly bound cluster (finding 11)
    M6  absent-ledger-no-relationship  an absent ledger is read as no prior relationship (finding 8)
    M7  clear-despite-newcomer   the ticket-side hold is skipped (finding 8, ticket side)
    M8  alias-first-only         ingestion keeps only the first advisory id (finding 9)
    M9  extraction-generation-ignored  ingestion never reads the checkout (finding 9)
    M10 clear-on-partial-population   a partial population clears (review round 2 F14)
    M11 scanner-rule-only-correlation  scanner + rule alone holds (F15)
    M12 hold-lasts-one-run            a PLAUSIBLE hold is forgotten by the next run (F14/F15)
  REVIEW ROUND 2: N14/P14 (F14 partial population over two runs); N15a-e, P15a-d (F15 tiers,
    a hold is not an active finding, persistence and the SoD human resolution)
  FINDING 9 (real scanner output through scan_report.parse_sarif -> identify -> observation_of,
  then the report and the tickets), each mechanism alone and all three combined:
    P9  PATH (file moved), ALIAS (CVE -> CVE + GHSA), EXTRACTION (SARIF-only -> KDEC-038 checkout
        read), COMBINED (three recorded hops): the identity moves at every hop; with the lineage
        events recorded the report carries A's decision to B (pending, naming every cause) and B
        keeps A's ticket; nothing closes
    N10 the same scanner output with NO event recorded: nothing is carried to B on the report,
        and B opens its own ticket -- EXCEPT a VERIFIED ADDITIVE alias (review round 2 F17, the
        owner's alias policy): continuity is established automatically by
        finding_lineage.alias_continuity, the report carries A's decision (pending) and the ticket
        keeps A, and BOTH record the same decision_id. (Before F17 this asserted the asymmetry:
        ticket kept, report not carried. Changed by policy decision, not weakened.)
  REVIEW ROUND 2 F17: N17a-d CONTRADICTORY, REMOVAL, REPLACEMENT, UNVERIFIED alias changes from
    scanner output stay UNRESOLVED on both sides (nothing carried or suppressed on the report; the
    ticket held LINEAGE_RECONCILIATION_UNRESOLVED with the alias state, never continued silently or
    closed); N17e a second id of one namespace is CONTRADICTORY; P17 the verified addition is not held
    M13 any-alias-change-continues   every alias change is decided VERIFIED (F17)
  REVIEW ROUND 3 F19: N19a-g unknown / non-True sweep, a declared scanner job with no row, an
    unregistered row, unvalidated NOT_APPLICABLE, no inventory, interrupted twice -- never cleared;
    P19a-c a complete whole-repo run and validated NOT_APPLICABLE still clear, naming the inventory
    M14 sweep-is-false-only   M15 drop-inventory-binding   M16 trust-not-applicable
  REVIEW ROUND 3 F20 (KDEC-047): N20a-b same subject + locus with disjoint advisory ids is held on
    ADVISORY_ID_CONFLICT across runs; P20a the second-person path resolves it; P20b other locus /
    subject stay UNRELATED   M17 disjoint-before-subject-locus
  REVIEW ROUND 3 F21: P21/N21 (inside P17) the continuity is SCANNER_ATTESTED_ALIAS_CONTINUITY with its
    provenance on the report and the ticket record, never read as verified   M18 attestation-dropped

EXIT  0 all hold   1 a case failed (named)   2 could not be checked
"""
import io
import json
import os
import shutil
import subprocess
import sys
import tempfile
import datetime

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, HERE)
sys.path.insert(0, os.path.join(ROOT, 'scripts'))

TODAY = datetime.date(2026, 11, 7)
CARRIED = 'DISPOSITION_CARRIED_BY_LINEAGE'


def _disp(key, claim='ACCEPTED_RISK', **over):
    d = {'schema_version': 1, 'fingerprint': key, 'scanner': 'semgrep',
         'rule': 'python.lang.security.audit.sqli.sql-injection', 'scope_path': 'app/db/queries.py',
         'disposition_type': claim,
         'rationale': 'Parameterisation is scheduled for the Q4 data-access rework (change-record-7).',
         'evidence_ref': 'change-record-7', 'approver_role': 'security-lead',
         'created': '2026-09-01', 'expires': '2099-01-01', 'state': 'approved',
         'ticket': 'SEC-41'}
    d.update(over)
    return dict((k, v) for k, v in d.items() if v is not None)


def _ev(src, dst, relation, cause, detail):
    import finding_lineage as fl
    return fl._mkevent(src, dst, relation=relation, cause=cause, detail=detail,
                       actor='security-lead', actor_class=fl.OPERATOR,
                       when='2026-11-01T09:00:00Z')


def _ledger(work, name, events):
    import finding_lineage as fl
    path = os.path.join(work, name + '.jsonl')
    for e in events:
        _eid, refused = fl.append_event(path, e)
        if refused:
            raise RuntimeError('fixture event refused: %s' % '; '.join(refused))
    return path


def _finding(work, tag, **kw):
    """-> (identity, finding) from the REAL reporter (scan_report.parse_sarif)."""
    import scan_report
    from prove_identity_durability import sast_sarif
    doc = sast_sarif('1.92.3', 'SQL built by concatenation',
                     'python.lang.security.audit.sqli.sql-injection', **kw)
    path = os.path.join(work, '%s.sarif' % tag)
    with io.open(path, 'w', encoding='utf-8') as fh:
        json.dump(doc, fh)
    findings, state, _ex = scan_report.parse_sarif(path, 'semgrep')
    if state != 'COMPLETE' or len(findings) != 1 or not findings[0].get('identity'):
        raise RuntimeError('fixture %s: parse_state=%s, %d finding(s)' % (tag, state, len(findings)))
    return findings[0]['identity'], findings[0], path


def _context(fl, path):
    """The consumer's view of the ledger. Built from `finding_lineage.load` when the shared loader
    is absent, so this proof runs against a base that has no consumer wiring at all and fails AT
    THE GUARD (the orphaned approval, the second ticket) rather than on a missing name."""
    if hasattr(fl, 'consumer_context'):
        return fl.consumer_context(path)
    events, integrity, notes = fl.load(path)
    return {'path': path, 'events': events, 'integrity': integrity, 'notes': list(notes)}


def _lin(sr, fl, path):
    return sr.load_lineage(path) if hasattr(sr, 'load_lineage') else _context(fl, path)


def _call(fn, *args, **kw):
    """Call with `lineage=` when the consumer takes it; without it when it does not (the base)."""
    try:
        return fn(*args, **kw)
    except TypeError as exc:
        if 'lineage' not in str(exc):
            raise
        kw.pop('lineage', None)
        return fn(*args, **kw)


def _render(sr, f, reg, lineage):
    cfg = dict(scanner='semgrep', applicability='APPLICABLE', execution='COMPLETE', scope='.',
               artifact='-', upload='-', gate='-', sarif='', run_url='', max_detail=10)
    return _call(sr.render, cfg, [f], 'COMPLETE', reg, 'LOADED', (sr.EXAMINED, []), TODAY,
                 lineage=lineage)


# ── the report ──────────────────────────────────────────────────────────────────────────

def report_carried(sr, fl, work, fails, label='P1'):
    a, fa, _pa = _finding(work, label + '-a')
    b, fb, _pb = _finding(work, label + '-b', path='services/api/db/queries.py')
    if not a or a == b:
        fails.append('%s: the fixture identity did not move (%s)' % (label, a[:12]))
        return
    path = _ledger(work, label, [_ev(a, b, fl.SUPERSEDES, fl.PATH_MOVED,
                                     'app/db moved to services/api/db in the monorepo split')])
    reg = {a: _disp(a)}
    lin = _lin(sr, fl, path)
    # PRECONDITION: the resolver itself carries A's decision to B. Without this a red result
    # could be a broken fixture rather than a consumer that never asked.
    said = fl.disposition_for(lin['events'], reg, b, integrity=lin['integrity'])
    if said['basis'] != CARRIED:
        fails.append('%s: fixture: finding_lineage itself answers %s for B' % (label, said['basis']))
        return
    rec, basis, note = _call(sr.disposition_for, fb, reg, TODAY, lineage=lin)
    if basis != CARRIED or rec is not reg[a]:
        fails.append('%s: the report on B found %r (basis %r) for the decision approved on A -- '
                     'the approval is orphaned (R03)' % (label, rec and rec.get('fingerprint'), basis))
        return
    for need in (a, 'PATH_MOVED', 'pending', b):
        if need not in note:
            fails.append('%s: the carry note does not name %r: %s' % (label, need, note[:300]))
    if _call(sr.is_suppressed, fb, reg, TODAY, lineage=lin):
        fails.append('%s: a CARRIED decision suppressed B. An inference never overwrites an '
                     'observation: it is pending reaffirmation on B' % label)
    txt = _render(sr, fb, reg, lin)
    for need in (CARRIED, 'PENDING DECISION', 'security-lead', 'Parameterisation is scheduled',
                 a, b, 'ACCEPTED_RISK', '2099-01-01'):
        if need not in txt:
            fails.append('%s: the rendered report on B does not show %r' % (label, need))
    if '-- honoured' in txt:
        fails.append('%s: the report renders the carried decision as honoured' % label)


def report_two_hops(sr, fl, work, fails):
    a, _fa, _ = _finding(work, 'p2-a')
    m, _fm, _ = _finding(work, 'p2-m', path='services/api/db/queries.py')
    b, fb, _ = _finding(work, 'p2-b', path='services/api/db/queries.py',
                        symbol='app.db.queries.load_user')
    if len(set([a, m, b])) != 3:
        fails.append('P2: the fixture identities did not move twice')
        return
    path = _ledger(work, 'p2', [
        _ev(a, m, fl.SUPERSEDES, fl.PATH_MOVED, 'directory moved'),
        _ev(m, b, fl.SUPERSEDES, fl.EXTRACTION_CORRECTED, 'symbol extraction now reports load_user')])
    rec, basis, note = _call(sr.disposition_for, fb, {a: _disp(a)}, TODAY, lineage=_lin(sr, fl, path))
    if basis != CARRIED or 'EXTRACTION_CORRECTED' not in note or 'PATH_MOVED' not in note:
        fails.append('P2: a two-hop carry (path, then extraction) was %r: %s' % (basis, note[:200]))


def report_direct(sr, fl, work, fails):
    a, _fa, _ = _finding(work, 'p3-a')
    b, fb, _ = _finding(work, 'p3-b', path='services/api/db/queries.py')
    path = _ledger(work, 'p3', [_ev(a, b, fl.SUPERSEDES, fl.PATH_MOVED, 'moved')])
    lin = _lin(sr, fl, path)
    reg = {a: _disp(a), b: _disp(b)}
    rec, basis, _note = _call(sr.disposition_for, fb, reg, TODAY, lineage=lin)
    if basis != 'durable' or rec is not reg[b]:
        fails.append('P3: a decision keyed directly on B reported basis %r' % basis)
    if not _call(sr.is_suppressed, fb, reg, TODAY, lineage=lin):
        fails.append('P3: a direct, approved, unexpired decision on B did not suppress')
    txt = _render(sr, fb, reg, lin)
    if CARRIED in txt or 'PENDING DECISION' in txt:
        fails.append('P3: a DIRECT approval is rendered as carried or pending')


def report_split(sr, fl, work, fails):
    a, _fa, _ = _finding(work, 'n1-a')
    b, fb, _ = _finding(work, 'n1-b', path='services/api/db/queries.py')
    c, _fc, _ = _finding(work, 'n1-c', path='services/web/db/queries.py')
    path = _ledger(work, 'n1', [_ev(a, [b, c], fl.SPLIT_INTO, fl.SUBJECT_SPEC_CHANGED,
                                    'one finding was two conditions')])
    lin = _lin(sr, fl, path)
    reg = {a: _disp(a)}
    _rec, basis, note = _call(sr.disposition_for, fb, reg, TODAY, lineage=lin)
    if basis != CARRIED or 'SPLIT' not in note or c not in note:
        fails.append('N1: a split product did not carry A pending, naming the split and its '
                     'sibling (%r): %s' % (basis, note[:300]))
    if _call(sr.is_suppressed, fb, reg, TODAY, lineage=lin):
        fails.append('N1: a split product was suppressed by the aggregate\'s approval')


def report_merge(sr, fl, work, fails):
    a1, _f1, _ = _finding(work, 'n2-a1')
    a2, _f2, _ = _finding(work, 'n2-a2', path='lib/db/queries.py')
    b, fb, _ = _finding(work, 'n2-b', path='services/api/db/queries.py')
    path = _ledger(work, 'n2', [_ev([a1, a2], b, fl.MERGED_INTO, fl.CORRELATION_ESTABLISHED,
                                    'two tools reported one condition')])
    lin = _lin(sr, fl, path)
    reg = {a1: _disp(a1), a2: _disp(a2, claim='FALSE_POSITIVE', evidence_ref=None)}
    _rec, basis, note = _call(sr.disposition_for, fb, reg, TODAY, lineage=lin)
    if basis != CARRIED or a1 not in note or a2 not in note:
        fails.append('N2: a merge survivor does not name BOTH prior decisions (%r): %s'
                     % (basis, note[:300]))
    if _call(sr.is_suppressed, fb, reg, TODAY, lineage=lin):
        fails.append('N2: a merge survivor was suppressed by a carried decision')


def report_cycle(sr, fl, work, fails):
    a, _fa, _ = _finding(work, 'n3-a')
    b, fb, _ = _finding(work, 'n3-b', path='services/api/db/queries.py')
    path = _ledger(work, 'n3', [_ev(a, b, fl.SUPERSEDES, fl.PATH_MOVED, 'moved'),
                                _ev(b, a, fl.SUPERSEDES, fl.PATH_MOVED, 'moved back, a mistake')])
    lin = _lin(sr, fl, path)
    rec, basis, note = _call(sr.disposition_for, fb, {a: _disp(a)}, TODAY, lineage=lin)
    if rec is not None or basis != 'lineage-refused' or 'CYCLE' not in note:
        fails.append('N3: a cyclic ledger was %r (%s), not refused by name' % (basis, note[:200]))
    if _call(sr.is_suppressed, fb, {a: _disp(a)}, TODAY, lineage=lin):
        fails.append('N3: a cycle suppressed B')


def report_missing(sr, fl, work, fails):
    _a, fb, _ = _finding(work, 'n4-b', path='services/api/db/queries.py')
    lin = _lin(sr, fl, os.path.join(work, 'no-such-ledger.jsonl'))
    if (lin or {}).get('integrity') != fl.LEDGER_ABSENT:
        fails.append('N4: an absent ledger loaded as %r' % (lin or {}).get('integrity'))
    rec, _basis, _note = _call(sr.disposition_for, fb, {}, TODAY, lineage=lin)
    if rec is not None:
        fails.append('N4: a decision appeared from an absent ledger')
    if 'LEDGER_ABSENT' not in _render(sr, fb, {}, lin):
        fails.append('N4: the report does not say the lineage ledger is LEDGER_ABSENT')
    # N4b (review 2026-11-09 finding 8): A was approved, A is gone this run, the same weakness is
    # reported at a new path as B, and the ledger is ABSENT. The register indicates a prior
    # relationship (same scanner and rule, on a key this run did not report), so B carries an
    # explicit unresolved reconciliation obligation naming A's decision -- never "no relationship".
    a, fa, _ = _finding(work, 'n4b-a')
    reg = {a: _disp(a)}
    rec, basis, note = _call(sr.disposition_for, fb, reg, TODAY,
                             lineage=_call(sr.with_observed, lin, [fb]) if hasattr(sr, 'with_observed') else lin)
    if basis != 'LINEAGE_RECONCILIATION_UNRESOLVED' or rec is not None:
        fails.append('N4b: with the ledger ABSENT, A approved and gone, and B the same rule at a new '
                     'path, the report on B gave basis %r -- absence was read as no prior '
                     'relationship (finding 8)' % (basis,))
        return
    for need in (a, 'security-lead', '2099-01-01', 'PENDING DECISION', 'LEDGER_ABSENT'):
        if need not in note:
            fails.append('N4b: the reconciliation obligation does not name %r: %s' % (need, note[:300]))
    if _call(sr.is_suppressed, fb, reg, TODAY, lineage=lin):
        fails.append('N4b: an unresolved reconciliation suppressed B')
    txt = _render(sr, fb, reg, lin)
    if 'LINEAGE_RECONCILIATION_UNRESOLVED' not in txt or a not in txt:
        fails.append('N4b: the rendered report on B does not show the unresolved obligation on A')
    # N4c: A is STILL REPORTED this run -- its decision is its own finding's, not orphaned, and
    # nothing is indicated about B (no false obligation).
    rec, basis, _n = _call(sr.disposition_for, fb, reg, TODAY, lineage=sr.with_observed(lin, [fa, fb]))
    if basis:
        fails.append('N4c: a decision on a finding still reported this run was indicated as B\'s '
                     'prior relationship (%r)' % basis)
    # N4d: a different rule at a different path: nothing indicated.
    c, fc, _ = _finding(work, 'n4d-c', path='web/other.py')
    rec, basis, _n = _call(sr.disposition_for, fc, {a: _disp(a, rule='other.rule', scope_path='x/y.py')},
                           TODAY, lineage=sr.with_observed(lin, [fc]))
    if basis:
        fails.append('N4d: an unrelated orphaned decision was indicated (%r)' % basis)


def report_tampered(sr, fl, work, fails):
    a, _fa, _ = _finding(work, 'n5-a')
    b, fb, _ = _finding(work, 'n5-b', path='services/api/db/queries.py')
    path = _ledger(work, 'n5', [_ev(a, b, fl.SUPERSEDES, fl.PATH_MOVED, 'moved')])
    _tamper(path)
    lin = _lin(sr, fl, path)
    if lin['integrity'] != fl.LEDGER_TAMPERED:
        fails.append('N5: the tampered fixture loaded as %s' % lin['integrity'])
    reg = {a: _disp(a)}
    rec, basis, note = _call(sr.disposition_for, fb, reg, TODAY, lineage=lin)
    if rec is not None or basis != 'lineage-refused' or 'LEDGER_TAMPERED' not in note \
            or a not in note:
        fails.append('N5: a tampered ledger gave %r (%s); it must refuse the carry and name the '
                     'decision it would have carried' % (basis, note[:200]))
    if _call(sr.is_suppressed, fb, reg, TODAY, lineage=lin):
        fails.append('N5: a tampered ledger suppressed B')


def report_expired(sr, fl, work, fails):
    a, _fa, _ = _finding(work, 'n6-a')
    b, fb, _ = _finding(work, 'n6-b', path='services/api/db/queries.py')
    path = _ledger(work, 'n6', [_ev(a, b, fl.SUPERSEDES, fl.PATH_MOVED, 'moved')])
    lin = _lin(sr, fl, path)
    reg = {a: _disp(a, expires='2026-10-01')}
    _rec, basis, note = _call(sr.disposition_for, fb, reg, TODAY, lineage=lin)
    if basis != CARRIED or 'EXPIRED' not in note:
        fails.append('N6: an expired decision on A was carried as %r without saying EXPIRED: %s'
                     % (basis, note[:200]))
    if _call(sr.is_suppressed, fb, reg, TODAY, lineage=lin):
        fails.append('N6: an expired, carried decision suppressed B')
    if 'EXPIRED' not in _render(sr, fb, reg, lin):
        fails.append('N6: the report does not show the carried decision as EXPIRED')


def _tamper(path):
    lines = io.open(path, encoding='utf-8').read().splitlines()
    body = json.loads(lines[0])
    body['cause_detail'] = 'rewritten after the fact'
    lines[0] = json.dumps(body, sort_keys=True)
    with io.open(path, 'w', encoding='utf-8') as fh:
        fh.write('\n'.join(lines) + '\n')


# ── the tickets ─────────────────────────────────────────────────────────────────────────

def obs(ident, path, fp):
    """One observation as scan_report observation_of() writes it."""
    return {'scanner': 'semgrep', 'tool': 'semgrep', 'scanner_version': '', 'rule_id': 'sqli',
            'severity': 'HIGH', 'line': 3, 'canonical_path': path,
            'finding_subject': 'SOURCE', 'state': 'FINGERPRINTED', 'identity': ident,
            'what': 'sqli', 'where': path, 'content': '', 'identity_scope': '', 'what_aliases': [],
            'cwe': '', 'reason': '', 'detail': '', 'fp': fp, 'job': 'sast',
            'row_established': True}


def _tickets(rt, fl, work, name, events, first_runs, second_run, tamper=False):
    """Run 1 raises a ticket per record list in `first_runs`; run 2 reconciles `second_run`
    with the lineage ledger. -> (backend, ledger, result of run 2)."""
    be = rt.RecordingBackend()
    ledger = {}
    for recs in first_runs:
        cl, w = rt.build_clusters(recs)
        rt.reconcile(cl, w, be, ledger, True, today='2026-11-01', context={})
    path = _ledger(work, name, events) if events is not None else os.path.join(work, name + '.jsonl')
    if tamper:
        _tamper(path)
    cl, w = rt.build_clusters(second_run)
    res = rt.reconcile(cl, w, be, ledger, True, today='2026-11-07',
                       context={'lineage': _context(fl, path)})
    return be, ledger, res


A, B, C, A2 = 'a' * 64, 'b' * 64, 'c' * 64, 'd' * 64


def tickets_carried(rt, fl, work, fails):
    be, ledger, res = _tickets(rt, fl, work, 'p4', [_ev(A, B, fl.SUPERSEDES, fl.PATH_MOVED, 'moved')],
                               [[obs(A, 'app/q.py', 'f1')]], [obs(B, 'svc/q.py', 'f2')])
    if len(be.created) != 1:
        fails.append('P4: B opened a second ticket beside A\'s (%d created) -- continuity lost'
                     % len(be.created))
        return
    if res['outcomes'].get('LEDGER_BOUND') != 1:
        fails.append('P4: B did not bind to A\'s ticket: %r' % res['outcomes'])
    entries = [e for e in ledger.values() if isinstance(e, dict) and e.get('ref') == be.created[0]['ref']]
    carry = (entries[0].get('carried_by_lineage') or []) if entries else []
    if not any(x.get('identity') == B and A in (x.get('carried_from') or []) and x.get('events')
               for x in carry):
        fails.append('P4: the ticket ledger does not record that B was carried by lineage from A, '
                     'by which event: %r' % carry)
    if not any(x.get('identity') == B for x in res.get('carried_by_lineage') or []):
        fails.append('P4: the run record does not list the lineage-carried binding')
    if B not in (entries[0].get('member_identities') if entries else []):
        fails.append('P4: B is not a member of A\'s ticket after the carry')


def tickets_split(rt, fl, work, fails):
    be, _ledger_, res = _tickets(rt, fl, work, 'n1t',
                                 [_ev(A, [B, C], fl.SPLIT_INTO, fl.SUBJECT_SPEC_CHANGED, 'split')],
                                 [[obs(A, 'app/q.py', 'f1')]],
                                 [obs(B, 'svc/q.py', 'f2'), obs(C, 'web/q.py', 'f3')])
    if len(be.created) != 1 or res['outcomes'].get('LEDGER_BOUND'):
        fails.append('N1: a split created or bound tickets (%d created, %r)'
                     % (len(be.created), res['outcomes']))
    if res['outcomes'].get('BINDING_AMBIGUOUS') != 2:
        fails.append('N1: a split is not BINDING_AMBIGUOUS for both products: %r' % res['outcomes'])
    if not any('lineage' in str(x.get('detail')) and 'split:' in str(x.get('detail'))
               for x in res['needs_decision']):
        fails.append('N1: the decision owed does not say it is a LINEAGE split')
    if be.closed:
        fails.append('N1: a split closed a ticket')
    # ONE PRODUCT SEEN. Only B is observed this run (C is not yet scanned). Nothing else makes this
    # ambiguous -- no second cluster inherits the key -- so only the lineage split guard stands
    # between B and the aggregate's ticket.
    be1, _l1, res1 = _tickets(rt, fl, work, 'n1t-one',
                              [_ev(A, [B, C], fl.SPLIT_INTO, fl.SUBJECT_SPEC_CHANGED, 'split')],
                              [[obs(A, 'app/q.py', 'f1')]], [obs(B, 'svc/q.py', 'f2')])
    if res1['outcomes'].get('LEDGER_BOUND') or res1['outcomes'].get('BINDING_AMBIGUOUS') != 1:
        fails.append('N1: one split product alone was bound to the aggregate\'s ticket, or not '
                     'held for a decision: %r' % res1['outcomes'])


def tickets_merge(rt, fl, work, fails):
    be, _ledger_, res = _tickets(rt, fl, work, 'n2t',
                                 [_ev([A, A2], B, fl.MERGED_INTO, fl.CORRELATION_ESTABLISHED, 'merge')],
                                 [[obs(A, 'app/q.py', 'f1')], [obs(A2, 'lib/q.py', 'f4')]],
                                 [obs(B, 'svc/q.py', 'f2')])
    if len(be.created) != 2 or res['outcomes'].get('LEDGER_BOUND'):
        fails.append('N2: a lineage merge created or bound a ticket (%d, %r)'
                     % (len(be.created), res['outcomes']))
    if res['outcomes'].get('BINDING_AMBIGUOUS') != 1:
        fails.append('N2: a lineage merge is not BINDING_AMBIGUOUS: %r' % res['outcomes'])
    if be.closed or res.get('merged'):
        fails.append('N2: a lineage merge auto-merged or closed a ticket')


def _key_of(ledger, ident):
    return [k for k, e in ledger.items() if isinstance(e, dict) and ident in (e.get('member_identities') or [])]


def _direct_and_lineage(rt, fl, work, fails, label, events, first_runs, second_run, kind,
                        ancestors):
    """A cluster DIRECTLY bound to its own ticket that ALSO takes part in a lineage event whose
    ancestors are ticketed separately (review 2026-11-09 findings 7 and 11). The direct binding
    stays authoritative for its own identity; the ancestors' obligations are not erased."""
    be, ledger, res = _tickets(rt, fl, work, label, events, first_runs, second_run)
    tb = _key_of(ledger, B)
    tas = sorted(set(k for a in ancestors for k in _key_of(ledger, a)) - set(tb))
    # PRECONDITION -- the fixture reaches the guard: B has a REAL direct binding, and the lineage
    # resolver itself names an ancestor obligation that binding does not continue.
    bindings = rt.identity_bindings(ledger, {})
    got = rt.lineage_binding(B, bindings, _context(fl, os.path.join(work, label + '.jsonl')))
    if len(tb) != 1 or not tas or not got or not (set(got['keys']) - set(tb)) \
            or (kind != 'direct:' and not got['conflict'].startswith(kind)):
        fails.append('%s: fixture: B direct %r, ancestors %r, lineage_binding %r' % (label, tb, tas, got))
        return
    if res['outcomes'].get('LEDGER_BOUND'):
        fails.append('%s: B bound to its direct ticket and the lineage obligation(s) %s were '
                     'dropped -- lineage was not evaluated for a bound cluster (finding 7): %r'
                     % (label, ', '.join(t[:12] for t in tas), res['outcomes']))
        return
    held = [x for x in res['needs_decision'] if kind in str(x.get('detail'))]
    if res['outcomes'].get('BINDING_AMBIGUOUS', 0) < 1 or not held:
        fails.append('%s: no BINDING_AMBIGUOUS decision names the lineage %s conflict: %r'
                     % (label, kind, res['outcomes']))
        return
    detail = ' '.join(str(x.get('detail')) for x in held)
    refs = ' '.join(str(r) for x in held for r in (x.get('refs') or x.get('candidates') or []))
    for t in tas:
        if t not in detail and t not in refs and str((ledger.get(t) or {}).get('ref', t)) not in refs:
            fails.append('%s: the decision owed does not name the ancestor obligation %s -- it was '
                         'lost: %s' % (label, t[:12], detail[:300]))
    if tb[0] not in detail and tb[0] not in refs and str((ledger.get(tb[0]) or {}).get('ref', tb[0])) not in refs:
        fails.append('%s: the decision owed does not name B\'s direct ticket %s' % (label, tb[0][:12]))
    if any(x.get('cluster_key') != tb[0] for x in held if 'direct' in str(x.get('detail'))):
        fails.append('%s: the held cluster is not keyed on the DIRECT binding of B %s (the direct '
                     'binding is authoritative for its own identity): %r'
                     % (label, tb[0][:12], [x.get('cluster_key') for x in held]))
    if be.closed or res.get('merged'):
        fails.append('%s: a ticket was closed or auto-merged on a lineage conflict' % label)
    if len(be.created) != len(first_runs):
        fails.append('%s: a ticket was created on a lineage conflict (%d)' % (label, len(be.created)))


def tickets_direct_split(rt, fl, work, fails):
    _direct_and_lineage(rt, fl, work, fails, 'n7t',
                        [_ev(A, [B, C], fl.SPLIT_INTO, fl.SUBJECT_SPEC_CHANGED, 'split')],
                        [[obs(A, 'app/q.py', 'f1')], [obs(B, 'svc/q.py', 'f2')]],
                        [obs(B, 'svc/q.py', 'f2'), obs(C, 'web/q.py', 'f3')], 'split:', [A])


def tickets_direct_merge(rt, fl, work, fails):
    _direct_and_lineage(rt, fl, work, fails, 'n8t',
                        [_ev([A, A2], B, fl.MERGED_INTO, fl.CORRELATION_ESTABLISHED, 'merge')],
                        [[obs(A, 'app/q.py', 'f1')], [obs(A2, 'lib/q.py', 'f4')],
                         [obs(B, 'svc/q.py', 'f2')]],
                        [obs(B, 'svc/q.py', 'f2')], 'merge:', [A, A2])


def tickets_direct_move(rt, fl, work, fails):
    _direct_and_lineage(rt, fl, work, fails, 'n9t',
                        [_ev(A, B, fl.SUPERSEDES, fl.PATH_MOVED, 'moved')],
                        [[obs(A, 'app/q.py', 'f1')], [obs(B, 'svc/q.py', 'f2')]],
                        [obs(B, 'svc/q.py', 'f2')], 'direct:', [A])


def tickets_direct_continues(rt, fl, work, fails):
    """P7: the DIRECT BINDING STAYS AUTHORITATIVE when it continues the lineage obligation -- the
    run after a carry (B is now a member of A's ticket) binds, creates nothing, holds nothing."""
    be, ledger, _res = _tickets(rt, fl, work, 'p7t', [_ev(A, B, fl.SUPERSEDES, fl.PATH_MOVED, 'moved')],
                                [[obs(A, 'app/q.py', 'f1')]], [obs(B, 'svc/q.py', 'f2')])
    if _key_of(ledger, B) != _key_of(ledger, A) or len(_key_of(ledger, B)) != 1:
        fails.append('P7: fixture: B is not directly bound to A\'s ticket after the carry')
        return
    cl, w = rt.build_clusters([obs(B, 'svc/q.py', 'f2')])
    res = rt.reconcile(cl, w, be, ledger, True, today='2026-11-08',
                       context={'lineage': _context(fl, os.path.join(work, 'p7t.jsonl'))})
    if res['outcomes'].get('LEDGER_BOUND') != 1 or res['outcomes'].get('BINDING_AMBIGUOUS') \
            or len(be.created) != 1:
        fails.append('P7: a direct binding that continues the lineage obligation was not bound '
                     '(%r, %d created)' % (res['outcomes'], len(be.created)))


def tickets_cycle(rt, fl, work, fails):
    be, _l, res = _tickets(rt, fl, work, 'n3t',
                           [_ev(A, B, fl.SUPERSEDES, fl.PATH_MOVED, 'moved'),
                            _ev(B, A, fl.SUPERSEDES, fl.PATH_MOVED, 'back')],
                           [[obs(A, 'app/q.py', 'f1')]], [obs(B, 'svc/q.py', 'f2')])
    if len(be.created) != 1 or res['outcomes'].get('BINDING_AMBIGUOUS') != 1:
        fails.append('N3: a lineage cycle was not BINDING_AMBIGUOUS (%d, %r)'
                     % (len(be.created), res['outcomes']))


def tickets_tampered(rt, fl, work, fails):
    be, _l, res = _tickets(rt, fl, work, 'n5t', [_ev(A, B, fl.SUPERSEDES, fl.PATH_MOVED, 'moved')],
                           [[obs(A, 'app/q.py', 'f1')]], [obs(B, 'svc/q.py', 'f2')], tamper=True)
    if len(be.created) != 1 or res['outcomes'].get('LEDGER_BOUND') \
            or res['outcomes'].get('BINDING_AMBIGUOUS') != 1:
        fails.append('N5: a tampered ledger bound, or created, instead of a decision owed (%d, %r)'
                     % (len(be.created), res['outcomes']))
    if not any('LEDGER_TAMPERED' in str(x.get('detail')) for x in res['needs_decision']):
        fails.append('N5: the decision owed does not name LEDGER_TAMPERED')


def tickets_missing(rt, fl, work, fails):
    be, _l, res = _tickets(rt, fl, work, 'n4t', None, [[obs(A, 'app/q.py', 'f1')]],
                           [obs(B, 'svc/q.py', 'f2')])
    if not any('LEDGER_ABSENT' in n for n in res['notes']):
        fails.append('N4: the run does not say the lineage ledger is LEDGER_ABSENT')
    if be.closed:
        fails.append('N4: a missing lineage ledger closed a ticket')


# ── finding 8, the ticket side: an absent ledger is not a verified clearance ───────────────

def _declared_jobs():
    """The scanner jobs the kit's scanner-registry.yaml DECLARES (review round 3 F19: the population
    denominator), read independently of the reconciler's own loader where a YAML library exists."""
    try:
        import yaml
        doc = yaml.safe_load(io.open(os.path.join(ROOT, 'scanner-registry.yaml'), encoding='utf-8'))
        return sorted(k for k, v in (doc.get('jobs') or {}).items() if (v or {}).get('class') == 'scanner')
    except ImportError:
        import reconcile_tickets as _rt
        return sorted(_rt.load_scanner_inventory()['jobs'])


def _row(job, **kw):
    return dict({'established': True, 'gate': 'PASS', 'execution': 'COMPLETE', 'scope': '.',
                 'scanner_version': '1', 'job': job, 'applicability': 'APPLICABLE'}, **kw)


# Review round 3 F19: a whole-repo run establishes a row for EVERY declared scanner job.
DECLARED = dict(('declared-' + j, _row(j)) for j in _declared_jobs())
COVERED = dict(DECLARED, semgrep=_row('sast-semgrep'))
HOLD = 'LINEAGE_RECONCILIATION_UNRESOLVED'
HOLD_NO_RULE = 'LINEAGE_RULE_NOT_RECORDED'
HOLD_CONFLICT = 'LINEAGE_CONFLICT_UNRESOLVED'


def _clearance(rt, fl, work, name, events, second_run, strip_rule=False, lineage=True, coverage=None):
    """Run 1 tickets A (semgrep, sqli, app/q.py); run 2 reconciles `second_run` WITH coverage that
    establishes semgrep over the whole tree, so a clearance is otherwise fully evidenced.
    -> (backend, ledger, result of run 2, A's ticket ref)."""
    be = rt.RecordingBackend()
    ledger = {}
    cl, w = rt.build_clusters([obs(A, 'app/q.py', 'f1')])
    rt.reconcile(cl, w, be, ledger, True, today='2026-11-01', context={'coverage': COVERED})
    ref_a = be.created[0]['ref']
    if strip_rule:
        # A ledger written before rule_id was recorded in its members.
        for e in ledger.values():
            for seen in (e.get('members') or {}).values():
                for x in seen:
                    x.pop('rule', None)
    path = _ledger(work, name, events) if events is not None else os.path.join(work, name + '.jsonl')
    cl, w = rt.build_clusters(second_run)
    ctx = {'coverage': coverage or COVERED}
    if lineage:
        ctx['lineage'] = _context(fl, path)
    res = rt.reconcile(cl, w, be, ledger, True, today='2026-11-07', context=ctx)
    return be, ledger, res, ref_a


def _held(res, ref):
    # Review round 2: a held reconciliation is a TICKET state, recorded apart from the finding-state
    # list (potentially_absent). Read where the reconciler writes it.
    return [p for p in res.get('reconciliation_held') or [] if str(p.get('ref')) == str(ref)]


def tickets_missing_newcomer(rt, fl, work, fails):
    """N4e (review 2026-11-09 finding 8, ticket side). Ledger ABSENT, coverage established: A is
    gone and B -- same scanner, same rule, new path -- is new this run. A's ticket is NOT closed as
    a verified clearance; it is held POTENTIALLY_ABSENT under LINEAGE_RECONCILIATION_UNRESOLVED,
    naming A and B (and B's ticket), and B's obligation is ticketed (nothing lost either way)."""
    be, ledger, res, ref_a = _clearance(rt, fl, work, 'n4e', None, [obs(B, 'svc/q.py', 'f2')])
    if str(ref_a) in [str(x) for x in be.closed] or any(str(c.get('ref')) == str(ref_a)
                                                       for c in res.get('cleared') or []):
        fails.append('N4e: with the lineage ledger absent, A\'s ticket %s was closed as a verified '
                     'clearance while B (same scanner and rule) is new this run -- the guard '
                     '%s did not hold it' % (ref_a, HOLD))
    held = _held(res, ref_a)
    if not held or held[0].get('state') != HOLD:
        fails.append('N4e: A\'s ticket is not held POTENTIALLY_ABSENT with state %s: %r' % (HOLD, held))
        return
    why = ' '.join(held[0].get('why') or [])
    if A[:12] not in why or B[:12] not in why or 'LEDGER_ABSENT' not in why:
        fails.append('N4e: the hold does not name both A and B and LEDGER_ABSENT: %s' % why[:300])
    if len(be.created) != 2:
        fails.append('N4e: B\'s obligation was not ticketed (%d created)' % len(be.created))
    new_ref = [c['ref'] for c in be.created if str(c['ref']) != str(ref_a)]
    if new_ref and str(new_ref[0]) not in why:
        fails.append('N4e: the hold does not name B\'s ticket %s: %s' % (new_ref[0], why[:300]))
    if not held[0].get('newcomers'):
        fails.append('N4e: the hold record carries no newcomers list')


def tickets_missing_rule_unrecorded(rt, fl, work, fails):
    """N4f: an OLD ticket ledger whose members carry no rule. Same scanner newcomer, ledger absent:
    whether the rule matches cannot be told, and it is said -- held under LINEAGE_RULE_NOT_RECORDED,
    never a silent close."""
    be, _l, res, ref_a = _clearance(rt, fl, work, 'n4f', None, [obs(B, 'svc/q.py', 'f2')],
                                    strip_rule=True)
    if str(ref_a) in [str(x) for x in be.closed]:
        fails.append('N4f: an old ledger without rule_id closed A\'s ticket silently (guard %s)'
                     % HOLD_NO_RULE)
    held = _held(res, ref_a)
    if not held or held[0].get('state') != HOLD or held[0].get('basis') != HOLD_NO_RULE:
        fails.append('N4f: A is not held under %s / %s: %r' % (HOLD, HOLD_NO_RULE, held))


def tickets_nonintact_newcomer(rt, fl, work, fails):
    """N4g (R03 acceptance: "missing ledgers and tampering must preserve unresolved obligations").
    The lineage ledger is NOT intact (tampered, or a line that does not parse): A is gone, coverage
    is established, and B -- same scanner, same rule, new path -- appears. B is held for a person;
    A's ticket must NOT close as a verified clearance either. Each state is reached for real: the
    precondition asserts the loader reports that state, and that B was held BINDING_AMBIGUOUS."""
    ev = [_ev(A, B, fl.SUPERSEDES, fl.PATH_MOVED, 'moved')]
    for state, name in ((fl.LEDGER_TAMPERED, 'n4g1'), (fl.LEDGER_LINE_UNPARSEABLE, 'n4g2')):
        path = _ledger(work, name, ev)
        if state == fl.LEDGER_TAMPERED:
            _tamper(path)
        else:
            with io.open(path, 'a', encoding='utf-8') as fh:
                fh.write('{this is not json' + chr(10))
        be = rt.RecordingBackend()
        ledger = {}
        cl, w = rt.build_clusters([obs(A, 'app/q.py', 'f1')])
        rt.reconcile(cl, w, be, ledger, True, today='2026-11-01', context={'coverage': COVERED})
        ref_a = be.created[0]['ref']
        lin = _context(fl, path)
        if lin.get('integrity') != state:
            fails.append('N4g: the fixture did not reach %s (the loader says %s)' % (state, lin.get('integrity')))
            continue
        cl, w = rt.build_clusters([obs(B, 'svc/q.py', 'f2')])
        res = rt.reconcile(cl, w, be, ledger, True, today='2026-11-07',
                           context={'coverage': COVERED, 'lineage': lin})
        if res['outcomes'].get('BINDING_AMBIGUOUS') != 1:
            fails.append('N4g %s: B was not held BINDING_AMBIGUOUS (precondition): %r' % (state, res['outcomes']))
        if str(ref_a) in [str(x) for x in be.closed] or any(str(c.get('ref')) == str(ref_a)
                                                           for c in res.get('cleared') or []):
            fails.append('N4g %s: the ticket %s closed as a verified clearance while B is held '
                         'for a person -- the guard %s did not hold it' % (state, ref_a, HOLD))
            continue
        held = _held(res, ref_a)
        if not held or held[0].get('state') != HOLD or held[0].get('basis') != state:
            fails.append('N4g %s: A is not held under %s with basis %s: %r' % (state, HOLD, state, held))
            continue
        why = ' '.join(held[0].get('why') or [])
        if A[:12] not in why or B[:12] not in why or state not in why:
            fails.append('N4g %s: the hold does not name A, B and the ledger state: %s' % (state, why[:300]))


def tickets_conflict_clearance(rt, fl, work, fails):
    """N4h (R03 acceptance: "Splits, merges, cycles ... must preserve unresolved obligations").
    The lineage ledger is INTACT and records a SPLIT (A -> B, C), a MERGE (A, X -> B) or a CYCLE
    (A -> B -> A). A (and X) are not reported this run, coverage is established, and the product
    that remains is held BINDING_AMBIGUOUS. The ancestor's ticket must NOT close as a verified
    clearance: the obligation it carries is unresolved."""
    X = A2
    cases = (('split', [_ev(A, [B, C], fl.SPLIT_INTO, fl.SUBJECT_SPEC_CHANGED, 'split')],
              [[obs(A, 'app/q.py', 'f1')]], [obs(B, 'svc/q.py', 'f2'), obs(C, 'web/q.py', 'f3')], 1),
             ('merge', [_ev([A, X], B, fl.MERGED_INTO, fl.CORRELATION_ESTABLISHED, 'merge')],
              [[obs(A, 'app/q.py', 'f1'), obs(X, 'lib/q.py', 'f4')]], [obs(B, 'svc/q.py', 'f2')], 2),
             ('cycle', [_ev(A, B, fl.SUPERSEDES, fl.PATH_MOVED, 'moved'),
                        _ev(B, A, fl.SUPERSEDES, fl.PATH_MOVED, 'back')],
              [[obs(A, 'app/q.py', 'f1')]], [obs(B, 'svc/q.py', 'f2')], 1))
    for kind, events, firsts, second, n_old in cases:
        be = rt.RecordingBackend()
        ledger = {}
        for recs in firsts:
            cl, w = rt.build_clusters(recs)
            rt.reconcile(cl, w, be, ledger, True, today='2026-11-01', context={'coverage': COVERED})
        old_refs = [c['ref'] for c in be.created]
        path = _ledger(work, 'n4h-' + kind, events)
        lin = _context(fl, path)
        if lin.get('integrity') != fl.LEDGER_INTACT or len(old_refs) != n_old:
            fails.append('N4h %s: fixture precondition (intact ledger, %d old tickets): %s, %d'
                         % (kind, n_old, lin.get('integrity'), len(old_refs)))
            continue
        cl, w = rt.build_clusters(second)
        res = rt.reconcile(cl, w, be, ledger, True, today='2026-11-07',
                           context={'coverage': COVERED, 'lineage': lin})
        if not res['outcomes'].get('BINDING_AMBIGUOUS'):
            fails.append('N4h %s: the remaining product was not held BINDING_AMBIGUOUS '
                         '(precondition): %r' % (kind, res['outcomes']))
        for ref in old_refs:
            if str(ref) in [str(x) for x in be.closed] or any(str(c.get('ref')) == str(ref)
                                                             for c in res.get('cleared') or []):
                fails.append('N4h %s: the ticket %s closed as a verified clearance while its '
                             'lineage obligation is unresolved -- the guard %s / %s did not hold it'
                             % (kind, ref, HOLD, HOLD_CONFLICT))
                continue
            held = _held(res, ref)
            if not held or held[0].get('state') != HOLD or held[0].get('basis') != HOLD_CONFLICT:
                fails.append('N4h %s: %s is not held under %s with basis %s: %r'
                             % (kind, ref, HOLD, HOLD_CONFLICT, held))


def tickets_intact_clears(rt, fl, work, fails):
    """P8e: an INTACT ledger with no newcomer still closes A (the hold is not a blanket)."""
    be, _l, res, ref_a = _clearance(rt, fl, work, 'p8e',
                                    [_ev(C, A2, fl.SUPERSEDES, fl.PATH_MOVED, 'unrelated')], [])
    if str(ref_a) not in [str(x) for x in be.closed]:
        fails.append('P8e: an intact ledger and no newcomer did not close A: %r'
                     % res.get('potentially_absent'))


def tickets_missing_clears(rt, fl, work, fails):
    """P8: the hold is narrow. A GENUINE clearance still closes: ledger absent and (a) nothing new,
    (b) a same-scanner newcomer on a DIFFERENT rule, (c) a same-rule newcomer from a DIFFERENT
    scanner; and (d) an intact ledger that records no move, with a same-rule newcomer."""
    other_rule = dict(obs(B, 'svc/q.py', 'f2'), rule_id='xss', what='xss')
    other_scanner = dict(obs(B, 'svc/q.py', 'f2'), scanner='codeql', tool='codeql')
    cases = (('P8a nothing new', 'p8a', None, []),
             ('P8b same scanner, different rule', 'p8b', None, [other_rule]),
             ('P8c same rule, different scanner', 'p8c', None, [other_scanner]),
             ('P8d intact ledger, no move recorded', 'p8d',
              [_ev(C, A2, fl.SUPERSEDES, fl.PATH_MOVED, 'unrelated')], [obs(B, 'svc/q.py', 'f2')]))
    # Every scanner that reports this run has its coverage row, as a real report writes one: the
    # population is complete (review round 2 F14 makes a missing row a provisional clearance).
    full = dict(COVERED, codeql=dict(COVERED['semgrep']))
    for label, name, events, second in cases:
        be, _l, res, ref_a = _clearance(rt, fl, work, name, events, second, coverage=full)
        if str(ref_a) not in [str(x) for x in be.closed]:
            fails.append('%s: a genuine clearance did not close A\'s ticket: %r'
                         % (label, res.get('potentially_absent')))


# ── finding 9: real scanner output, each identity mechanism, through production ingestion ──
#
# The cases above build observations by hand. These start from SCANNER OUTPUT (SARIF shaped as
# Semgrep and Trivy write it), go through the production ingestion and identity functions
# (scan_report.parse_sarif -> finding_identity.identify, and observation_of for the findings
# file), and then into BOTH consumers: the report (disposition_for / is_suppressed) and the
# tickets (build_clusters -> reconcile). Three mechanisms move an identity, each alone and all
# three combined:
#   PATH        the file moved (canonical_path is in SOURCE's WHERE)
#   ALIAS       the advisory feed re-aliased: CVE -> CVE + GHSA (WHAT hashes the alias SET)
#   EXTRACTION  the kit's extraction generation changed for the same SARIF: SARIF-only fields
#               (no checkout) -> KDEC-038 code location read from the checked-out commit
# PRECONDITION for each: both identities are computed (FINGERPRINTED) and DIFFER, so the case
# reaches the lineage consumers rather than passing on an identity that never moved.

SRC_RULE = 'python.lang.security.audit.sqli.sql-injection'
SRC_LINE = '    cursor.execute("SELECT * FROM users WHERE id = " + user_id)'


def _checkout(work):
    """The scanned commit, both layouts (before and after the move): the construct at line 42."""
    root = os.path.join(work, 'checkout')
    if not os.path.isdir(root):
        body = ''.join('# line %d\n' % i for i in range(1, 41)) + 'def fetch_user(user_id):\n' + \
            SRC_LINE + '\n    return cursor.fetchone()\n'
        for rel in ('app/db/queries.py', 'services/api/db/queries.py'):
            p = os.path.join(root, *rel.split('/'))
            os.makedirs(os.path.dirname(p))
            with io.open(p, 'w', encoding='utf-8', newline='\n') as fh:
                fh.write(body)
    return root


def _scan(sr, work, tag, scanner, doc, source_root=''):
    """Scanner output -> the production finding and its findings-file observation."""
    p = os.path.join(work, 'f9-%s.sarif' % tag)
    with io.open(p, 'w', encoding='utf-8') as fh:
        json.dump(doc, fh)
    findings, state, _ex = sr.parse_sarif(p, scanner, source_root=source_root)
    if state != 'COMPLETE' or len(findings) != 1:
        raise RuntimeError('F9 fixture %s: parse_state=%s, %d finding(s)' % (tag, state, len(findings)))
    f = findings[0]
    return f, sr.observation_of(f, 'sast' if scanner == 'semgrep' else 'sca', True)


def _source_doc(path, aliases=()):
    """A Semgrep SOURCE finding; `aliases` are the advisory ids its rule metadata carries."""
    from prove_identity_durability import sast_sarif
    doc = sast_sarif('1.92.3', 'SQL built by concatenation', SRC_RULE, path=path, line=42)
    if aliases:
        doc['runs'][0]['tool']['driver']['rules'][0]['properties']['references'] = list(aliases)
    return doc


def _dep_doc(aliases):
    """A Trivy dependency finding; the advisory feed's aliases in the rule's properties."""
    from prove_identity_durability import dep_sarif
    doc = dep_sarif('0.50.1', 'requests 2.19.1: Session leaks Authorization header',
                    'CVE-2018-18074')
    doc['runs'][0]['tool']['driver']['rules'][0]['properties']['aliases'] = list(aliases)
    return doc


CVE_ = 'CVE-2018-18074'
GHSA_ = 'GHSA-x84v-xcm2-53pg'


def _mechanism_states(sr, work):
    """-> {case: (scanner, [(finding, observation)...] in order, [cause per hop])}. Each hop is
    computed from scanner output by the production functions."""
    root = _checkout(work)
    old, new = 'app/db/queries.py', 'services/api/db/queries.py'
    return {
        'path': ('semgrep', [_scan(sr, work, 'p0', 'semgrep', _source_doc(old)),
                             _scan(sr, work, 'p1', 'semgrep', _source_doc(new))],
                 ['PATH_MOVED']),
        'alias': ('trivy', [_scan(sr, work, 'a0', 'trivy', _dep_doc([CVE_])),
                            _scan(sr, work, 'a1', 'trivy', _dep_doc([CVE_, GHSA_]))],
                  ['ADVISORY_ALIAS_ADDED']),
        'extraction': ('semgrep', [_scan(sr, work, 'e0', 'semgrep', _source_doc(old)),
                                   _scan(sr, work, 'e1', 'semgrep', _source_doc(old), root)],
                       ['EXTRACTION_CORRECTED']),
        # ALL THREE between two scans, on one SOURCE finding whose rule names an advisory. The
        # ledger records one cause per event, so the move is recorded as the three hops it is;
        # each intermediate identity is computed from scanner output too.
        'combined': ('semgrep', [_scan(sr, work, 'c0', 'semgrep', _source_doc(old, [CVE_])),
                                 _scan(sr, work, 'c1', 'semgrep', _source_doc(new, [CVE_])),
                                 _scan(sr, work, 'c2', 'semgrep', _source_doc(new, [CVE_, GHSA_])),
                                 _scan(sr, work, 'c3', 'semgrep', _source_doc(new, [CVE_, GHSA_]),
                                       root)],
                     ['PATH_MOVED', 'ADVISORY_ALIAS_ADDED', 'EXTRACTION_CORRECTED']),
    }


def mechanisms(sr, rt, fl, work, fails):
    """F9 P9a-d (positive, per mechanism) and N10a-d (negative: the same scanner output with no
    lineage event recorded)."""
    try:
        cases = _mechanism_states(sr, work)
    except RuntimeError as exc:
        fails.append('F9: %s' % exc)
        return
    for name in ('path', 'alias', 'extraction', 'combined'):
        scanner, hops, causes = cases[name]
        ids = [f['identity'] for f, _o in hops]
        # PRECONDITION: computed, and moved at every hop.
        if not all(ids) or any(f['identity_state'] != 'FINGERPRINTED' for f, _o in hops):
            fails.append('F9 %s: an identity was not computed (%r) -- the case never reaches the '
                         'consumers' % (name, [(f['identity_state'], f['identity_reason']) for f, _o in hops]))
            continue
        if len(set(ids)) != len(ids):
            fails.append('F9 %s: the identity did NOT move under %s (%s) -- the mechanism is not '
                         'exercised' % (name, '+'.join(causes), ' -> '.join(i[:12] for i in ids)))
            continue
        a, b = ids[0], ids[-1]
        fa, fb = hops[0][0], hops[-1][0]
        # THE TICKET KEY. An advisory alias ADDED keeps the shared-alias anchor (the earlier id is
        # common to both sets), so the ticket's cluster key does not move: ticket continuity under
        # an alias change needs no lineage event. That is asserted, not assumed -- the durable
        # identity (and so the report's decision lookup) DOES move, and only the ledger carries it.
        keys = [rt.build_clusters([o])[0][0]['cluster_key'] for _f, o in hops]
        key_stable = name == 'alias'
        if (keys[0] == keys[-1]) != key_stable:
            fails.append('F9 %s: the ticket cluster key %s under %s (%s), expected it to %s'
                         % (name, 'held' if keys[0] == keys[-1] else 'moved', '+'.join(causes),
                            ' -> '.join(k[:12] for k in keys), 'hold' if key_stable else 'move'))
        events = [_ev(ids[i], ids[i + 1], fl.SUPERSEDES, getattr(fl, causes[i]), 'F9 %s hop %d' % (name, i))
                  for i in range(len(causes))]
        reg = {a: _disp(a, scanner=scanner, rule=fa['rule'], scope_path=fa['uri'])}
        for label, evs in (('P9 ' + name, events),
                           ('N10 ' + name, [_ev(C, A2, fl.SUPERSEDES, fl.PATH_MOVED, 'unrelated')])):
            path = _ledger(work, 'f9-%s-%s' % (name, label[0]), evs)
            lin = _lin(sr, fl, path)
            rec, basis, note = _call(sr.disposition_for, fb, reg, TODAY, lineage=lin)
            suppressed = _call(sr.is_suppressed, fb, reg, TODAY, lineage=lin)
            be, ledger = rt.RecordingBackend(), {}
            cl, w = rt.build_clusters([hops[0][1]])
            rt.reconcile(cl, w, be, ledger, True, today='2026-11-01', context={})
            cl, w = rt.build_clusters([hops[-1][1]])
            res = rt.reconcile(cl, w, be, ledger, True, today='2026-11-07',
                               context={'lineage': _context(fl, path)})
            if be.closed:
                fails.append('%s: a ticket was closed (%r)' % (label, be.closed))
            if suppressed:
                fails.append('%s: the decision on A suppressed B' % label)
            if label.startswith('P9'):
                if basis != CARRIED or rec is not reg[a]:
                    fails.append('%s: the report on B (from scanner output) did not carry A\'s decision '
                                 '(basis %r)' % (label, basis))
                elif not all(c in note for c in causes) or a not in note:
                    fails.append('%s: the carry note does not name A and every cause %r: %s'
                                 % (label, causes, note[:300]))
                if len(be.created) != 1 or res['outcomes'].get('LEDGER_BOUND') != 1:
                    fails.append('%s: B did not keep A\'s ticket (%d created, %r)'
                                 % (label, len(be.created), res['outcomes']))
            elif key_stable:
                # N10 alias -- A POLICY CHANGE BY DECISION, NOT A WEAKENED ASSERTION. Before review
                # round 2 this asserted the asymmetry: the ticket kept A (stable cluster key) with no
                # lineage event while the report did NOT carry A's decision. The owner's alias policy
                # (relayed 2026-11-09, the round-2 review findings, "Alias continuity"; F17): a VERIFIED
                # ADDITIVE advisory alias -- CVE -> CVE + GHSA, co-declared by the scanner's own
                # advisory record -- ESTABLISHES CONTINUITY AUTOMATICALLY, and the report and the
                # ticket consume the SAME lineage decision (finding_lineage.alias_continuity).
                # Asserted now, and stronger than before: both sides carry, and both record the same
                # decision_id. The unresolved alias changes are proven separately (alias_policy).
                want = _decide(fl)(hops[0][1], hops[-1][1])
                if want['state'] != fl.SCANNER_ATTESTED_ALIAS_CONTINUITY:
                    fails.append('%s: the scanner-output alias addition was not decided %s (%s: %s)'
                                 % (label, fl.SCANNER_ATTESTED_ALIAS_CONTINUITY, want['state'], want['why']))
                    continue
                if basis != CARRIED or rec is not reg[a]:
                    fails.append('%s: under the alias policy the verified alias addition did not carry '
                                 'A\'s decision to B on the report (basis %r)' % (label, basis))
                elif want['decision_id'] not in note or 'ADVISORY_ALIAS_ADDED' not in note:
                    fails.append('%s: the report carry does not name the alias decision %s: %s'
                                 % (label, want['decision_id'][:16], note[:300]))
                if len(be.created) != 1 or res['outcomes'].get('LEDGER_BOUND') != 1:
                    fails.append('%s: a verified alias addition lost the ticket (%d created, %r)'
                                 % (label, len(be.created), res['outcomes']))
                got = [r.get('alias_decision') for r in res.get('carried_by_lineage') or []]
                if want['decision_id'] not in got:
                    fails.append('%s: the ticket did not record the SAME alias decision as the report '
                                 '(%s vs %r)' % (label, want['decision_id'][:16], got))
                if res.get('reconciliation_held'):
                    fails.append('%s: a verified alias addition was held: %r'
                                 % (label, res['reconciliation_held']))
            else:
                if basis == CARRIED or rec is not None:
                    fails.append('%s: with no lineage event recorded the report carried A\'s decision '
                                 'to B (basis %r) -- continuity must come from the ledger only'
                                 % (label, basis))
                if len(be.created) != 2 or res['outcomes'].get('LEDGER_BOUND'):
                    fails.append('%s: with no lineage event B bound to A\'s ticket (%d created, %r)'
                                 % (label, len(be.created), res['outcomes']))


def _mechanisms_entry(rt, fl, work, fails):
    import scan_report as sr
    mechanisms(sr, rt, fl, work, fails)


# ── review round 2 F17: the alias policy's UNRESOLVED side, from scanner output ─────────────
CVE2_ = 'CVE-2019-11324'
# The precondition reads the UNMUTATED decision (captured before any mutant), so a mutant of
# alias_continuity is caught by the consumers' behaviour, never by a precondition it broke.
_DECIDE = {}


def _decide(fl):
    return _DECIDE.get('alias') or fl.alias_continuity

TRIVY_COV = dict(DECLARED, trivy=_row('deps-scan', scanner_version='0.50.1'))


def _dep_doc2(rule_id, aliases, message='requests 2.19.1: Session leaks Authorization header'):
    from prove_identity_durability import dep_sarif
    doc = dep_sarif('0.50.1', message, rule_id)
    doc['runs'][0]['tool']['driver']['rules'][0]['properties']['aliases'] = list(aliases)
    return doc


def _scanner_attested(label, d, note, res, ob, fl, fails):
    """P21/N21 (review round 3 F21): the continuity is SCANNER-ATTESTED, never verified. The decision
    (precondition, unmutated) is named SCANNER_ATTESTED_ALIAS_CONTINUITY; the CONSUMER outputs -- the
    report's note and the ticket run record's carried_by_lineage -- say scanner-attested, carry the
    provenance the input holds (scanner, version; advisory source NOT_ESTABLISHED because the SARIF
    does not name its feed) and ALIAS_AUTHORITY_NOT_CONSULTED, and never read as verified."""
    import re
    if d.get('state') != 'SCANNER_ATTESTED_ALIAS_CONTINUITY':
        fails.append('P21 %s: the continuity decision is named %r, not SCANNER_ATTESTED_ALIAS_CONTINUITY'
                     % (label, d.get('state')))
    carried = [c for c in res.get('carried_by_lineage') or [] if c.get('cause') == fl.ADVISORY_ALIAS_ADDED]
    pv = (carried[0].get('provenance') or {}) if carried else {}
    if not carried or carried[0].get('assurance') != 'SCANNER_ATTESTED' or \
            carried[0].get('corroboration') != 'ALIAS_AUTHORITY_NOT_CONSULTED' or \
            pv.get('scanner') != 'trivy' or pv.get('scanner_version') != (ob.get('scanner_version') or 'NOT_ESTABLISHED') \
            or pv.get('advisory_source') != 'NOT_ESTABLISHED' or \
            not (pv.get('observation') or {}).get('alias_evidence'):
        fails.append('P21 %s: the ticket record does not carry the scanner attestation and its '
                     'provenance: %r' % (label, carried))
    if 'attested by the scanner' not in (note or '') or 'not independently verified' not in (note or ''):
        fails.append('P21 %s: the report note does not say the continuity is scanner-attested: %s'
                     % (label, (note or '')[:300]))
    blob = json.dumps([carried, note, d.get('event')], sort_keys=True)
    bad = [w for w in ('_'.join(('ALIAS', 'CONTINUITY', 'VERIFIED')), 'verified additive alias') if w in blob]
    bad += re.findall(r'(?<!not )independently verified', blob)
    if bad:
        fails.append('N21 %s: an output reads the scanner-attested continuity as verified: %r' % (label, bad))
    pv2 = getattr(fl, 'alias_provenance', lambda r: {})({'scanner': 'trivy'})
    if pv2.get('scanner_version') != 'NOT_ESTABLISHED' or pv2.get('advisory_source') != 'NOT_ESTABLISHED':
        fails.append('N21 %s: provenance absent from the input is not recorded NOT_ESTABLISHED: %r' % (label, pv2))


def alias_policy(sr, rt, fl, work, fails):
    """N17a-d: CONTRADICTORY (CVE-1+GHSA -> CVE-2+GHSA), REMOVAL (CVE+GHSA -> CVE), REPLACEMENT
    (CVE -> GHSA), UNVERIFIED (CVE -> CVE+GHSA where the GHSA is only in the message, not in the
    advisory record). Each from scanner output, with an INTACT ledger recording no move and coverage
    over the locus. PRECONDITION: finding_lineage.alias_continuity decides the named state (the
    fixture reaches the guard). Then: the report carries nothing to B and never suppresses (the
    unverified case names LINEAGE_RECONCILIATION_UNRESOLVED + ALIAS_UNVERIFIED); the ticket is NOT
    continued silently and NOT closed -- held LINEAGE_RECONCILIATION_UNRESOLVED with the alias state
    as its basis, persisted on A's ledger entry. P17: the verified addition with coverage is NOT held."""
    cases = (
        ('N17a contradictory', fl.ALIAS_CONTRADICTORY, (CVE_, [CVE_, GHSA_]), (CVE2_, [CVE2_, GHSA_]), None),
        ('N17b removal', fl.ALIAS_REMOVED, (CVE_, [CVE_, GHSA_]), (CVE_, [CVE_]), None),
        ('N17c replacement', fl.ALIAS_REPLACED, (CVE_, [CVE_]), (GHSA_, [GHSA_]), None),
        ('N17d unverified', fl.ALIAS_UNVERIFIED, (CVE_, [CVE_]), (CVE_, [CVE_]),
         'requests 2.19.1: Session leaks Authorization header (see %s)' % GHSA_.lower()),
        ('P17 verified addition', fl.SCANNER_ATTESTED_ALIAS_CONTINUITY, (CVE_, [CVE_]), (CVE_, [CVE_, GHSA_]), None))
    # N17e, record level: a PURE ADDITION of a second id in a namespace the old set already names
    # (CVE -> CVE + another CVE) is CONTRADICTORY, never VERIFIED -- even when co-declared. Scanner
    # ingestion keeps one id per namespace, so this is built from the identity composition directly.
    import finding_identity as fi
    loc, con = 'W' * 64, 'X' * 64
    old = {'identity': fi.identity_for_advisory_aliases('SOURCE_DEPENDENCY', [CVE_], loc, con),
           'finding_subject': 'SOURCE_DEPENDENCY', 'what_aliases': [CVE_], 'where': loc, 'content': con}
    new = dict(old, what_aliases=[CVE_, CVE2_], alias_evidence=[CVE_, CVE2_],
               identity=fi.identity_for_advisory_aliases('SOURCE_DEPENDENCY', [CVE_, CVE2_], loc, con))
    if _decide(fl)(old, new)['state'] != fl.ALIAS_CONTRADICTORY:
        fails.append('N17e: a second CVE added to a CVE was not ALIAS_CONTRADICTORY (%r)'
                     % _decide(fl)(old, new)['state'])
    for label, want, (ra, aa), (rb, ab), msg_b in cases:
        tag = label.split()[0].lower()
        fa, oa = _scan(sr, work, tag + 'a', 'trivy', _dep_doc2(ra, aa))
        fb, ob = _scan(sr, work, tag + 'b', 'trivy', _dep_doc2(rb, ab, msg_b) if msg_b else _dep_doc2(rb, ab))
        d = _decide(fl)(oa, ob)  # the UNMUTATED decision: the precondition
        if d['state'] != want:
            fails.append('%s: PRECONDITION -- alias_continuity decided %s, expected %s (%s; %r -> %r)'
                         % (label, d['state'], want, d['why'], oa['what_aliases'], ob['what_aliases']))
            continue
        a = fa['identity']
        reg = {a: _disp(a, scanner='trivy', rule=ra, scope_path='requirements.txt')}
        path = _ledger(work, 'f17-' + tag, [_ev(C, A2, fl.SUPERSEDES, fl.PATH_MOVED, 'unrelated')])
        lin = _lin(sr, fl, path)
        rec, basis, note = sr.disposition_for(fb, reg, TODAY, lineage=lin)
        if sr.is_suppressed(fb, reg, TODAY, lineage=lin):
            fails.append('%s: the decision on A suppressed B' % label)
        be, ledger = rt.RecordingBackend(), {}
        cl, w = rt.build_clusters([oa])
        rt.reconcile(cl, w, be, ledger, True, today='2026-11-01', context={'coverage': TRIVY_COV})
        ref_a = be.created[0]['ref']
        cl, w = rt.build_clusters([ob])
        res = rt.reconcile(cl, w, be, ledger, True, today='2026-11-07',
                           context={'lineage': _context(fl, path), 'coverage': TRIVY_COV})
        held = _held(res, ref_a)
        if want == fl.SCANNER_ATTESTED_ALIAS_CONTINUITY:
            if basis != CARRIED or held or _closed(be, ref_a) or len(be.created) != 1:
                fails.append('%s: the verified addition did not continue cleanly (basis %r, held %r, '
                             'closed %r, %d created)' % (label, basis, held, be.closed, len(be.created)))
            _scanner_attested(label, d, note, res, ob, fl, fails)
            continue
        if basis == CARRIED or rec is not None:
            fails.append('%s: the report carried A\'s decision to B (basis %r) across an unresolved '
                         'alias change' % (label, basis))
        if want == fl.ALIAS_UNVERIFIED and (basis != HOLD or fl.ALIAS_UNVERIFIED not in note):
            fails.append('%s: the report did not name the unresolved alias obligation (%r: %s)'
                         % (label, basis, note[:200]))
        if _closed(be, ref_a):
            fails.append('%s: A\'s ticket was CLOSED as a clearance across an unresolved alias change'
                         % label)
        if not held or held[0].get('state') != HOLD or held[0].get('basis') != want:
            fails.append('%s: A\'s ticket continued without a held reconciliation naming %s (held %r)'
                         % (label, want, held))
        persisted = [e for e in ledger.values() if isinstance(e, dict) and str(e.get('ref')) == str(ref_a)]
        rc = (persisted[0].get('reconciliation') or {}) if persisted else {}
        if rc.get('state') != HOLD or not rc.get('alias_decisions'):
            fails.append('%s: the hold is not persisted on A\'s ledger entry with its alias decision (%r)'
                         % (label, rc))


# ── wiring ──────────────────────────────────────────────────────────────────────────────

def wiring(sr, fl, work, fails):
    a, _fa, _ = _finding(work, 'p5-a')
    b, _fb, sarif_b = _finding(work, 'p5-b', path='services/api/db/queries.py')
    path = _ledger(work, 'p5', [_ev(a, b, fl.SUPERSEDES, fl.PATH_MOVED, 'moved')])
    reg = os.path.join(work, 'p5-register.json')
    with io.open(reg, 'w', encoding='utf-8') as fh:
        json.dump({a: _disp(a)}, fh)
    out = subprocess.run([sys.executable, os.path.join(ROOT, 'scripts', 'scan_report.py'),
                          '--scanner', 'semgrep', '--sarif', sarif_b, '--execution', 'COMPLETE',
                          '--applicability', 'APPLICABLE', '--dispositions', reg,
                          '--lineage', path, '--out', ''],
                         capture_output=True, text=True, cwd=ROOT)
    if out.returncode != 0 or CARRIED not in out.stdout:
        fails.append('P5: scan_report.py --lineage did not carry (rc %d): %s'
                     % (out.returncode, (out.stdout + out.stderr)[-400:]))
    import inspect
    if 'lineage_path' not in inspect.signature(sr.batch).parameters:
        fails.append('P5: scan_report.batch() takes no lineage ledger')
    text = io.open(os.path.join(ROOT, 'scripts', 'reconcile_tickets.py'), encoding='utf-8').read()
    if "'--lineage'" not in text:
        fails.append('P5: reconcile_tickets.py takes no --lineage')
    # AS SHIPPED: the scan-report action reads the ledger from the protected branch (never the PR
    # checkout) and passes it; the reconcile workflow passes the protected checkout's ledger.
    act = io.open(os.path.join(ROOT, '.github', 'actions', 'scan-report', 'action.yml'),
                  encoding='utf-8').read()
    for need in ('FETCH_HEAD:.security/finding-lineage.jsonl"',
                 'FETCH_HEAD:.security/finding-lineage.jsonl.head"', '--lineage "$lineage"'):
        if need not in act:
            fails.append('P5: the scan-report action does not carry %r' % need)
    wf = io.open(os.path.join(ROOT, '.github', 'workflows', 'reusable-ticket-reconcile.yml'),
                 encoding='utf-8').read()
    if 'args+=(--lineage .security/finding-lineage.jsonl)' not in wf:
        fails.append('P5: reusable-ticket-reconcile.yml does not pass the lineage ledger')


def exported(sr, fl, work, fails):
    """P6: the batch run's findings file -- which the evidence export projects -- records WHICH
    basis each decision rode in on, so the exported history keeps direct and carried apart."""
    a, _fa, _ = _finding(work, 'p6-a')
    b, _fb, _ = _finding(work, 'p6-b', path='services/api/db/queries.py')
    d, _fd, _ = _finding(work, 'p6-d', path='lib/other/queries.py')
    run = os.path.join(work, 'p6-batch')
    os.makedirs(run)
    from prove_identity_durability import sast_sarif
    doc = sast_sarif('1.92.3', 'SQL built by concatenation',
                     'python.lang.security.audit.sqli.sql-injection', path='services/api/db/queries.py')
    doc2 = sast_sarif('1.92.3', 'SQL built by concatenation',
                      'python.lang.security.audit.sqli.sql-injection', path='lib/other/queries.py')
    doc['runs'][0]['results'].extend(doc2['runs'][0]['results'])
    with io.open(os.path.join(run, 'semgrep.sarif'), 'w', encoding='utf-8') as fh:
        json.dump(doc, fh)
    with io.open(os.path.join(run, 'state-semgrep.json'), 'w', encoding='utf-8') as fh:
        json.dump({'scanner': 'semgrep', 'applicability': 'APPLICABLE', 'execution': 'COMPLETE',
                   'scope': 'x', 'sarif': 'semgrep.sarif', 'artifact': 'RETAINED',
                   'upload': 'COMPLETE', 'gate': 'FAIL', 'job': 'sast'}, fh)
    path = _ledger(work, 'p6', [_ev(a, b, fl.SUPERSEDES, fl.PATH_MOVED, 'moved')])
    reg = os.path.join(work, 'p6-register.json')
    with io.open(reg, 'w', encoding='utf-8') as fh:
        json.dump({a: _disp(a), d: _disp(d)}, fh)
    out = os.path.join(work, 'p6-gh-output')
    io.open(out, 'w').close()
    env = dict(os.environ, GITHUB_OUTPUT=out, GITHUB_STEP_SUMMARY='')
    p = subprocess.run([sys.executable, os.path.join(ROOT, 'scripts', 'scan_report.py'),
                        '--batch', run, '--max-detail', '5', '--expect', 'semgrep',
                        '--dispositions', reg, '--lineage', path],
                       capture_output=True, text=True, env=env, cwd=ROOT)
    fpath = os.path.join(run, 'findings.json')
    if not os.path.isfile(fpath):
        fails.append('P6: the batch wrote no findings.json (rc %d): %s'
                     % (p.returncode, (p.stdout + p.stderr)[-300:]))
        return
    rows = dict((r.get('identity'), r) for r in json.load(io.open(fpath, encoding='utf-8')))
    if (rows.get(b) or {}).get('disposition_basis') != CARRIED:
        fails.append('P6: the findings file does not record B\'s decision as %s: %r'
                     % (CARRIED, (rows.get(b) or {}).get('disposition_basis')))
    if (rows.get(d) or {}).get('disposition_basis') != 'durable':
        fails.append('P6: a direct decision is not recorded as durable in the findings file: %r'
                     % (rows.get(d) or {}).get('disposition_basis'))
    if 'Lineage ledger' not in (p.stdout or ''):
        fails.append('P6: the batch report does not state the lineage ledger it read')
    try:
        import evidence_export as ee
        if 'disposition_basis' not in ee.FINDING:
            fails.append('P6: the evidence export drops disposition_basis from the history')
    except ImportError as exc:
        fails.append('P6: evidence_export did not import: %s' % exc)


# ── review round 2 F14: separate runs, a partial population, cannot discharge a merge ancestor ──

PROVISIONAL = 'CLEARANCE_PROVISIONAL'
PRESERVED = 'LINEAGE_RELATIONSHIP_PRESERVED'


def _cov(scope='.', **extra):
    c = dict(COVERED, semgrep=dict(COVERED['semgrep'], scope=scope))
    c.update(extra)
    for k in [k for k, v in c.items() if v is None]:
        del c[k]                    # review round 3 F19: a None override removes the row
    return c


def _closed(be, ref):
    return str(ref) in [str(x) for x in be.closed]


def _merge_two_runs(rt, fl, work, name, run1_cov, x_scanner='semgrep', sweep_complete=True,
                    second=None, run2_cov=None, ctx1=None):
    """Tickets A (semgrep, app/q.py) and X (lib/q.py) in one run; the INTACT lineage ledger records
    A and X MERGED_INTO B. Run 1 sees part of the population (nothing reported; `run1_cov`, the
    sweep as given, `ctx1` merged into its context); run 2 sees `run2_cov` (default the whole
    population) and B. -> (be, ledger, ref_a, r1, r2)."""
    be = rt.RecordingBackend()
    ledger = {}
    xo = dict(obs(A2, 'lib/q.py', 'f4'), scanner=x_scanner, tool=x_scanner)
    full = _cov(**({x_scanner: dict(COVERED['semgrep'])} if x_scanner != 'semgrep' else {}))
    cl, w = rt.build_clusters([obs(A, 'app/q.py', 'f1'), xo])
    rt.reconcile(cl, w, be, ledger, True, today='2026-11-01', context={'coverage': full})
    refs = dict((c['cluster_key'], c['ref']) for c in be.created)
    ref_a = [refs[k] for k in refs if A in (ledger[k].get('member_identities') or [])][0]
    lin = _context(fl, _ledger(work, name, [_ev([A, A2], B, fl.MERGED_INTO,
                                                fl.CORRELATION_ESTABLISHED, 'merge')]))
    be._sweep_complete = sweep_complete
    cl, w = rt.build_clusters([])
    r1 = rt.reconcile(cl, w, be, ledger, True, today='2026-11-07',
                      context=dict({'coverage': run1_cov, 'lineage': lin}, **(ctx1 or {})))
    be._sweep_complete = True
    cl, w = rt.build_clusters([obs(B, 'svc/q.py', 'f2')] if second is None else second)
    r2 = rt.reconcile(cl, w, be, ledger, True, today='2026-11-08',
                      context={'coverage': full if run2_cov is None else run2_cov, 'lineage': lin})
    return be, ledger, ref_a, r1, r2


def tickets_partial_population(rt, fl, work, fails):
    """N14 (review round 2 F14). A and X merge into B, reconciled over two runs, the first seeing
    only part of the population: a scope that covers A's file but not B's, a scanner that FAILED,
    a scanner whose row never arrived (interrupted), a ticket sweep that was paged/capped. Run 1
    must NOT close A: the clearance is CLEARANCE_PROVISIONAL (RECONCILIATION_POPULATION_INCOMPLETE).
    Run 2 sees B held BINDING_AMBIGUOUS and A is still open and held on the conflict. Two
    separate runs never discharge A."""
    failed_row = {'established': False, 'gate': 'FAILED', 'execution': 'FAILED', 'scope': '.',
                  'scanner_version': '1'}
    cases = (('partial-scope', _cov(scope='app'), 'semgrep', True),
             ('scanner-failure', _cov(codeql=failed_row), 'codeql', True),
             ('interrupted', _cov(), 'codeql', True),
             ('paginated-sweep', _cov(), 'semgrep', False))
    for label, cov1, xs, sweep in cases:
        be, _l, ref_a, r1, r2 = _merge_two_runs(rt, fl, work, 'n14-' + label, cov1, xs, sweep)
        if any(str(c.get('ref')) == str(ref_a) for c in r1.get('cleared') or []) or _closed(be, ref_a):
            fails.append('N14 %s: run 1 saw part of the population and closed A (%s) as a verified '
                         'clearance -- the guard %s did not hold it' % (label, ref_a, PROVISIONAL))
            continue
        h1 = _held(r1, ref_a)
        if not h1 or h1[0].get('state') != PROVISIONAL or 'RECONCILIATION_POPULATION_INCOMPLETE' \
                not in ' '.join(h1[0].get('why') or []):
            fails.append('N14 %s: run 1 did not record A as %s naming the incomplete population: %r'
                         % (label, PROVISIONAL, h1))
        if r2['outcomes'].get('BINDING_AMBIGUOUS') != 1:
            fails.append('N14 %s: run 2 did not hold B BINDING_AMBIGUOUS (precondition): %r'
                         % (label, r2['outcomes']))
        h2 = _held(r2, ref_a)
        if _closed(be, ref_a) or not h2 or h2[0].get('basis') != HOLD_CONFLICT:
            fails.append('N14 %s: after two separate runs A is closed or not held on the merge '
                         '(%s): %r' % (label, HOLD_CONFLICT, h2))


def tickets_complete_population_clears(rt, fl, work, fails):
    """P14: provisional is not a blanket. Run 1 partial (provisional), run 2 the WHOLE population
    with neither B nor X reported: A (and X) clear, citing the run."""
    be, _l, ref_a, r1, r2 = _merge_two_runs(rt, fl, work, 'p14', _cov(scope='app'), second=[])
    if _closed(be, ref_a) and not any(str(c.get('ref')) == str(ref_a) for c in r2.get('cleared') or []):
        fails.append('P14: A closed in run 1, not on the complete run')
    if not _closed(be, ref_a):
        fails.append('P14: a complete population with the merge product absent did not clear A: %r'
                     % r2.get('reconciliation_held'))


# ── review round 3 F19: affirmative completeness, a declared denominator, validated N/A ──────

def _sha_registry():
    import hashlib
    return hashlib.sha256(io.open(os.path.join(ROOT, 'scanner-registry.yaml'), 'rb').read()).hexdigest()


def _provisional_naming(r, ref, needle):
    h = _held(r, ref)
    return bool(h and h[0].get('state') == PROVISIONAL and needle in ' '.join(h[0].get('why') or []))


def tickets_population_r3(rt, fl, work, fails):
    """N19/P19 (review round 3 F19), through reconcile() -- the consumer path -- with the INTACT
    ledger recording A's merge (the full-population gate applies). Run 1 must NOT clear A, and the
    hold must name the guard's own gap:
      N19a  the sweep returned a non-True value ('PARTIAL'): bool() read it as complete
      N19b  population_gaps itself with sweep_complete None (unknown) and absent
      N19c  a scanner job the declared inventory names has no coverage row (never seen / missing)
      N19d  a coverage row whose job the inventory does not declare (unregistered scanner)
      N19e  NOT_APPLICABLE with no evidence; on an `always` job; under a PARTIAL discovery
      N19f  no declared inventory available (None; unreadable; names no scanner job)
      N19g  interrupted (a declared job's row missing) in TWO separate runs: A is never cleared
    P19a  a complete whole-repo run clears, naming the inventory (source, sha256) it used
    P19b  NOT_APPLICABLE backed by the kit's own evidence (discovery:COMPLETE, input:image_ref)
          clears -- the binding does not block ordinary clearances
    P19c  the report's coverage row carries applicability_basis, and the workflow writes it."""
    sha = _sha_registry()
    # Base-tolerant, so on a tree without the round-3 names the proof still reaches the GUARD.
    load_inv = getattr(rt, 'load_scanner_inventory', None) or (lambda path=None: {'state': 'absent at base'})
    na_ok = getattr(rt, 'not_applicable_validated', None) or (lambda row, inv: False)

    def pop(*a, **kw):
        try:
            return rt.population_gaps(*a, **kw)
        except TypeError:
            kw.pop('inventory', None)
            return rt.population_gaps(*a, **kw)
    na = lambda job, basis='': _row(job, established=False, gate='UNDETERMINED', execution='NOT_RUN',
                                    applicability='NOT_APPLICABLE', applicability_basis=basis)
    reg_bad = os.path.join(work, 'r3-empty-registry.yaml')
    io.open(reg_bad, 'w', encoding='utf-8').write(u'jobs:\n  plan: {class: infrastructure}\n')
    cases = (
        ('N19a', _cov(), 'PARTIAL', None, 'not affirmatively complete'),
        ('N19c', _cov(**{'declared-sbom': None}), True, None, 'declared scanner job sbom'),
        ('N19d', _cov(mystery=_row('not-a-registered-job')), True, None,
         'not in the declared scanner inventory'),
        ('N19e-no-basis', _cov(**{'declared-sast-bandit': na('sast-bandit')}), True, None,
         'APPLICABILITY_NOT_ESTABLISHED'),
        ('N19e-always', _cov(**{'declared-secret-scan': na('secret-scan', 'discovery:COMPLETE')}),
         True, None, 'APPLICABILITY_NOT_ESTABLISHED'),
        ('N19e-partial-discovery', _cov(**{'declared-sast-go': na('sast-go', 'discovery:DISCOVERY_PARTIAL')}),
         True, None, 'APPLICABILITY_NOT_ESTABLISHED'),
        ('N19f-none', _cov(), True, {'scanner_inventory': None}, 'SCANNER_INVENTORY_NOT_ESTABLISHED'),
        ('N19f-unreadable', _cov(), True,
         {'scanner_inventory': load_inv(os.path.join(work, 'absent.yaml'))},
         'SCANNER_INVENTORY_NOT_ESTABLISHED'),
        ('N19f-no-scanner-job', _cov(), True,
         {'scanner_inventory': load_inv(reg_bad)}, 'SCANNER_INVENTORY_NOT_ESTABLISHED'))
    for label, cov1, sweep, ctx1, needle in cases:
        be, _l, ref_a, r1, _r2 = _merge_two_runs(rt, fl, work, 'n19-' + label, cov1, 'semgrep', sweep,
                                                 ctx1=ctx1)
        if any(str(c.get('ref')) == str(ref_a) for c in r1.get('cleared') or []):
            fails.append('%s: run 1 cleared A on an unestablished population (%s)' % (label, needle))
        elif not _provisional_naming(r1, ref_a, needle):
            fails.append('%s: A is not held %s naming %r: %r' % (label, PROVISIONAL, needle, _held(r1, ref_a)))
    # N19b: the predicate, unknown and absent.
    entry = {'member_identities': [A]}
    lin = _context(fl, os.path.join(work, 'n19b-absent.jsonl'))
    inv = load_inv()
    for label, kw in (('None', {'sweep_complete': None}), ('absent', {})):
        try:
            # 'absent': the caller never established it -- passed as None positionally.
            got = pop(entry, {}, lin, dict(COVERED), [], inventory=inv, **kw) if kw else \
                pop(entry, {}, lin, dict(COVERED), [], None, inventory=inv)
        except TypeError as exc:
            got = ['crash %s' % exc]
        if not got or 'not affirmatively complete' not in ' '.join(got):
            fails.append('N19b sweep_complete %s: no population gap: %r' % (label, got))
    if pop(entry, {}, lin, dict(COVERED), [], True, inventory=inv):
        fails.append('N19b precondition: a complete sweep over the declared population still gapped')
    # N19g: interrupted in two separate runs, then the whole population.
    gone = _cov(**{'declared-iac-scan': None})
    be, ledger, ref_a, r1, r2 = _merge_two_runs(rt, fl, work, 'n19g', gone, second=[], run2_cov=gone)
    if _closed(be, ref_a) or not _provisional_naming(r1, ref_a, 'declared scanner job iac-scan') \
            or not _provisional_naming(r2, ref_a, 'declared scanner job iac-scan'):
        fails.append('N19g: two interrupted runs discharged A or did not hold it provisional')
    cl, w = rt.build_clusters([])
    r3 = rt.reconcile(cl, w, be, ledger, True, today='2026-11-09',
                      context={'coverage': _cov(), 'lineage': _context(fl, os.path.join(work, 'n19g.jsonl'))})
    if not _closed(be, ref_a):
        fails.append('P19a (after N19g): the whole population did not clear A: %r' % _held(r3, ref_a))
    # P19a / P19b.
    for label, cov in (('P19a', _cov()),
                       ('P19b', _cov(**{'declared-sast-bandit': na('sast-bandit', 'discovery:COMPLETE'),
                                        'declared-sast-go': na('sast-go', 'discovery:COMPLETE'),
                                        'declared-image-scan': na('image-scan', 'input:image_ref')}))):
        be, _l, ref_a, r1, _r2 = _merge_two_runs(rt, fl, work, 'p19-' + label, cov, second=[])
        if not any(str(c.get('ref')) == str(ref_a) for c in r1.get('cleared') or []):
            fails.append('%s: a complete whole-repo run did not clear A: %r' % (label, _held(r1, ref_a)))
        pi = r1.get('population_inventory') or {}
        if pi.get('sha256') != sha or pi.get('source') != 'scanner-registry.yaml' or \
                pi.get('state') != 'SCANNER_INVENTORY_ESTABLISHED':
            fails.append('%s: the run record does not name the declared inventory it used: %r' % (label, pi))
    # P19c: the report writes the basis; the workflow's state builder supplies it.
    import scan_report as sr
    sd = os.path.join(work, 'p19c-states')
    os.makedirs(sd)
    with io.open(os.path.join(sd, 'state-bandit.json'), 'w', encoding='utf-8') as fh:
        json.dump({'scanner': 'bandit', 'applicability': 'NOT_APPLICABLE', 'execution': 'NOT_RUN',
                   'scope': 'python', 'artifact': 'NONE', 'upload': 'NONE', 'gate': 'UNDETERMINED',
                   'sarif': '', 'job': 'sast-bandit', 'applicability_basis': 'discovery:COMPLETE'}, fh)
    try:
        sr.batch(sd, '', 20, '')
    except SystemExit:
        pass
    cov, _n = rt.load_coverage(os.path.join(sd, 'findings-coverage.json'))
    if not cov or (cov.get('bandit') or {}).get('applicability_basis') != 'discovery:COMPLETE' \
            or not na_ok(cov['bandit'], inv):
        fails.append('P19c: the coverage row does not carry a validatable applicability_basis: %r' % cov)
    wf = io.open(os.path.join(ROOT, '.github', 'workflows', 'reusable-security.yml'), encoding='utf-8').read()
    if 'applicability_basis:$ab' not in wf or 'discovery:${D_STATE:-UNSTATED}' not in wf \
            or wf.count("image-scan input:image_ref") != 2:
        fails.append('P19c: the state builder (reusable-security.yml add) does not write applicability_basis')


# ── review round 2 F15 + the F8 policy: correlation tiers, not scanner + rule alone ───────────

def _dep(ident, purl_where, aliases, fp, path='requirements.txt'):
    return dict(obs(ident, path, fp), scanner='trivy', tool='trivy', rule_id='CVE-2024-1111',
                finding_subject='SOURCE_DEPENDENCY', where=purl_where, what_aliases=list(aliases))


def _absent_two(rt, fl, work, name, first, second, coverage=None):
    """Ledger ABSENT. Run 1 tickets `first`; run 2 reconciles `second` (coverage established for
    every scanner). -> (be, ledger, res, A's ref)."""
    cov = coverage or dict(COVERED, trivy=dict(COVERED['semgrep']), codeql=dict(COVERED['semgrep']))
    be = rt.RecordingBackend()
    ledger = {}
    cl, w = rt.build_clusters(first)
    rt.reconcile(cl, w, be, ledger, True, today='2026-11-01', context={'coverage': cov})
    ref_a = be.created[0]['ref']
    lin = _context(fl, os.path.join(work, name + '.jsonl'))
    cl, w = rt.build_clusters(second)
    res = rt.reconcile(cl, w, be, ledger, True, today='2026-11-07',
                       context={'coverage': cov, 'lineage': lin})
    return be, ledger, res, ref_a, lin, cov


def tickets_correlation_tiers(rt, fl, work, fails):
    """N15/P15 (review round 2 F15, the F8 policy), ledger ABSENT, A gone, coverage established.
      N15a same scanner + same rule and NOTHING else shared: INSUFFICIENT -- A clears, the gap is
           recorded (this was held at e521c81: the over-hold)
      N15b the same advisory scanner, disjoint advisory ids: UNRELATED -- A clears
      N15c another finding subject: UNRELATED -- A clears
      P15a same scanner + rule + a weaker shared attribute (file name, line): PLAUSIBLE -- held
           LINEAGE_RECONCILIATION_UNRESOLVED naming both tickets
      P15b same subject and the same locus (rule renamed at the same place): STRONG -- the
           relationship is PRESERVED, reaffirmation required, NOT closed
      P15c same package advisory id shared (CVE -> CVE + GHSA at another manifest): STRONG
    The tier is on the run record and on the ticket."""
    a_src = obs(A, 'app/q.py', 'f1')
    cases = (('N15a', [a_src], [dict(obs(B, 'other/zz.py', 'f9'), line=99)], None),
             ('N15b', [_dep(A, 'pkg:pypi/x@1', ['CVE-2024-1111'], 'f1')],
              [_dep(B, 'pkg:pypi/y@1', ['CVE-2024-2222'], 'f2')], None),
             ('N15c', [a_src], [dict(obs(B, 'app/q.py', 'f2'), finding_subject='IMAGE')], None),
             ('P15a', [a_src], [obs(B, 'svc/q.py', 'f2')], 'LINEAGE_RECONCILIATION_UNRESOLVED'),
             ('P15b', [dict(a_src, where='W-app-q')],
              [dict(obs(B, 'app/q.py', 'f2'), where='W-app-q', rule_id='sqli-v2')], PRESERVED),
             ('P15c', [_dep(A, 'pkg:pypi/x@1', ['CVE-2024-1111'], 'f1')],
              [_dep(B, 'pkg:pypi/x@1#b', ['CVE-2024-1111', 'GHSA-aaaa-bbbb-cccc'], 'f2',
                    path='svc/requirements.txt')], PRESERVED))
    for label, first, second, want in cases:
        be, ledger, res, ref_a, _lin_, _c = _absent_two(rt, fl, work, 'tier-' + label, first, second)
        held = _held(res, ref_a)
        if want is None:
            if not _closed(be, ref_a):
                fails.append('%s: no relationship by the tiers, yet A was not cleared: %r'
                             % (label, held))
            if label == 'N15a' and not any(str(g.get('ref')) == str(ref_a) and
                                           g.get('tier') == 'CORRELATION_INSUFFICIENT'
                                           for g in res.get('reconciliation_gaps') or []):
                fails.append('N15a: the evidence gap (CORRELATION_INSUFFICIENT) is not on the run record')
            continue
        if _closed(be, ref_a):
            fails.append('%s: A was closed as a verified clearance despite %s evidence' % (label, want))
            continue
        if not held or held[0].get('state') != want:
            fails.append('%s: A is not held %s: %r' % (label, want, held))
            continue
        tier = 'CORRELATION_STRONG' if want == PRESERVED else 'CORRELATION_PLAUSIBLE'
        if held[0].get('tier') != tier:
            fails.append('%s: the run record does not carry the tier %s: %r' % (label, tier, held[0].get('tier')))
        if want == PRESERVED and not held[0].get('reaffirmation_required'):
            fails.append('%s: a preserved relationship does not require reaffirmation' % label)
        new_ref = [c['ref'] for c in be.created if str(c['ref']) != str(ref_a)]
        if not new_ref or str(new_ref[0]) not in ' '.join(held[0].get('why') or []):
            fails.append('%s: the hold does not name the new ticket %r' % (label, new_ref))
        on_ticket = [t for r, t in be.comments if str(r) == str(ref_a) and tier in t and want in t]
        if not on_ticket:
            fails.append('%s: the tier and state are not said on A\'s ticket' % label)
        key_a = [k for k, e in ledger.items() if str(e.get('ref')) == str(ref_a)][0]
        if (ledger[key_a].get('reconciliation') or {}).get('tier') != tier:
            fails.append('%s: the ticket ledger does not record the tier' % label)


def tickets_advisory_conflict(rt, fl, work, fails):
    """N20/P20 (review round 3 F20, KDEC-047), ledger ABSENT, A gone, coverage established.
      N20a same subject + same locus (purl), both alias sets present and DISJOINT, reported by
           another scanner: was UNRELATED, so A cleared. Now CORRELATION_CONFLICT, held
           LINEAGE_RECONCILIATION_UNRESOLVED on ADVISORY_ID_CONFLICT, finding state VERIFIED_ABSENT
           (not an active finding), persisted on the ticket ledger
      N20b the next run (B now bound to its own ticket) still holds A
      P20a the existing second-person path resolves it: `separate` releases it and the rescan clears A
      P20b disjoint ids with ANOTHER locus stay UNRELATED and A clears (N15b), another subject too (N15c)."""
    cov = dict(COVERED, trivy=_row('deps-scan'), osv=_row('malicious-deps'))
    a = _dep(A, 'pkg:pypi/x@1', ['CVE-2024-1111'], 'f1')
    b = dict(_dep(B, 'pkg:pypi/x@1', ['GHSA-zzzz-yyyy-xxxx'], 'f2', path='svc/requirements.txt'),
             scanner='osv', tool='osv', rule_id='GHSA-zzzz-yyyy-xxxx')
    be, ledger, res, ref_a, lin, _c = _absent_two(rt, fl, work, 'n20', [a], [b], coverage=cov)
    held = _held(res, ref_a)
    if _closed(be, ref_a):
        fails.append('N20a: same subject and locus with disjoint advisory ids read as UNRELATED: A '
                     'was closed as a verified clearance (want ADVISORY_ID_CONFLICT)')
        return
    if not held or held[0].get('state') != HOLD or held[0].get('basis') != 'ADVISORY_ID_CONFLICT' \
            or held[0].get('tier') != 'CORRELATION_CONFLICT':
        fails.append('N20a: A is not held %s on ADVISORY_ID_CONFLICT (CORRELATION_CONFLICT): %r' % (HOLD, held))
        return
    if held[0].get('finding_state') != 'VERIFIED_ABSENT' or \
            any(str(p.get('ref')) == str(ref_a) for p in res.get('potentially_absent') or []):
        fails.append('N20a: the conflict hold is read as an active / potentially absent finding: %r' % held[0])
    key_a = [k for k, e in ledger.items() if str(e.get('ref')) == str(ref_a)][0]
    if (ledger[key_a].get('reconciliation') or {}).get('basis') != 'ADVISORY_ID_CONFLICT':
        fails.append('N20a: the conflict is not persisted on the ticket ledger')
    cl, w = rt.build_clusters([b])
    r3 = rt.reconcile(cl, w, be, ledger, True, today='2026-11-08', context={'coverage': cov, 'lineage': lin})
    if _closed(be, ref_a) or not _held(r3, ref_a):
        fails.append('N20b: the run after the conflict hold discharged A')
        return
    approval = rt.tm.Approval(actor='appsec-reviewer', reason='both advisories read: separate')
    err, _rec = rt.resolve_reconciliation(ledger, str(ref_a), 'separate', 'security-lead', approval, '2026-11-08')
    if err:
        fails.append('P20a: the second-person resolution of the conflict was refused: %s' % err)
        return
    cl, w = rt.build_clusters([b])
    rt.reconcile(cl, w, be, ledger, True, today='2026-11-09', context={'coverage': cov, 'lineage': lin})
    if not _closed(be, ref_a):
        fails.append('P20a: a resolved conflict (separate) did not let the rescan clear A')
    # P20b: the tier function itself, for the two UNRELATED shapes and the conflict.
    seen = {'subject': 'SOURCE_DEPENDENCY', 'where': 'pkg:pypi/x@1', 'aliases': ['CVE-2024-1111'],
            'scanner': 'trivy'}
    for label, m, want in (
            ('conflict', {'finding_subject': 'SOURCE_DEPENDENCY', 'where': 'pkg:pypi/x@1',
                          'what_aliases': ['GHSA-zzzz-yyyy-xxxx'], 'scanner': 'osv'}, 'CORRELATION_CONFLICT'),
            ('other-locus', {'finding_subject': 'SOURCE_DEPENDENCY', 'where': 'pkg:pypi/y@1',
                             'what_aliases': ['GHSA-zzzz-yyyy-xxxx'], 'scanner': 'osv'}, 'CORRELATION_UNRELATED'),
            ('other-subject', {'finding_subject': 'IMAGE', 'where': 'pkg:pypi/x@1',
                               'what_aliases': ['GHSA-zzzz-yyyy-xxxx'], 'scanner': 'osv'}, 'CORRELATION_UNRELATED'),
            ('shared-id', {'finding_subject': 'SOURCE_DEPENDENCY', 'where': 'pkg:pypi/x@1',
                           'what_aliases': ['CVE-2024-1111'], 'scanner': 'osv'}, 'CORRELATION_STRONG')):
        got = rt.correlation_tier(seen, m)[0]
        if got != want:
            fails.append('P20b %s: correlation_tier is %s, want %s' % (label, got, want))


def tickets_hold_not_active(rt, fl, work, fails):
    """N15d (the F8 policy, CRITICAL): a held reconciliation is a TICKET state. It does not change
    the finding's state or count as an active finding: the held ticket is in reconciliation_held
    with finding_state VERIFIED_ABSENT, NOT in the finding-state list potentially_absent, the run
    counts only the findings reported (clusters 1 = B), and the summary keeps the two apart."""
    be, _l, res, ref_a, _lin_, _c = _absent_two(rt, fl, work, 'n15d', [obs(A, 'app/q.py', 'f1')],
                                                [obs(B, 'svc/q.py', 'f2')])
    held = _held(res, ref_a)
    if not held:
        fails.append('N15d: fixture precondition: A is not held')
        return
    if held[0].get('finding_state') != 'VERIFIED_ABSENT':
        fails.append('N15d: the held ticket\'s finding state is %r, not VERIFIED_ABSENT'
                     % held[0].get('finding_state'))
    if any(str(p.get('ref')) == str(ref_a) for p in res.get('potentially_absent') or []):
        fails.append('N15d: the held reconciliation is counted in the finding-state list potentially_absent')
    if res['clusters'] != 1:
        fails.append('N15d: the run counts %d findings; only B was reported' % res['clusters'])
    text = rt.render_summary(res)
    row = [l for l in text.splitlines() if 'ticket reconciliation held' in l]
    if not row or 'not an active finding' not in row[0] or 'VERIFIED_ABSENT 1' not in row[0]:
        fails.append('N15d: the summary does not keep the ticket state apart from the finding: %r' % row)
    if any(l.startswith('| POTENTIALLY_ABSENT') for l in text.splitlines()):
        fails.append('N15d: the summary counts the held ticket as POTENTIALLY_ABSENT')


def tickets_hold_persists_and_resolves(rt, fl, work, fails):
    """N15e/P15d (F14 + F8 policy: an auditable human resolution). The PLAUSIBLE hold must survive
    the next run (B is then bound to its own ticket, no longer new) -- else the second run clears
    A. The resolution is ticket.triage_merge with separation of duties: a triager decides, a second
    person approves; self-approval and no approval are refused and change nothing. `separate`
    releases the hold and the next run's rescan clears A; `same` keeps A open while B is open."""
    for decision in ('separate', 'same'):
        be, ledger, res, ref_a, lin, cov = _absent_two(rt, fl, work, 'n15e-' + decision,
                                                       [obs(A, 'app/q.py', 'f1')],
                                                       [obs(B, 'svc/q.py', 'f2')])
        if not _held(res, ref_a):
            fails.append('N15e: fixture precondition: A is not held after run 2')
            return
        cl, w = rt.build_clusters([obs(B, 'svc/q.py', 'f2')])
        r3 = rt.reconcile(cl, w, be, ledger, True, today='2026-11-08',
                          context={'coverage': cov, 'lineage': lin})
        if _closed(be, ref_a) or not _held(r3, ref_a):
            fails.append('N15e: the run after the hold (B now bound to its own ticket) discharged A')
            return
        for who, appr, why in (('security-lead', 'security-lead', 'self-approval'),
                               ('security-lead', None, 'no approval')):
            approval = rt.tm.Approval(actor=appr, reason='confirmed by reading both findings') if appr else None
            err, _rec = rt.resolve_reconciliation(ledger, str(ref_a), decision, who, approval, '2026-11-08')
            if not err:
                fails.append('N15e: a resolution with %s was accepted' % why)
        approval = rt.tm.Approval(actor='appsec-reviewer', reason='both findings read: %s' % decision)
        err, rec = rt.resolve_reconciliation(ledger, str(ref_a), decision, 'security-lead', approval,
                                             '2026-11-08')
        if err or (rec or {}).get('resolution', {}).get('approved_by') != 'appsec-reviewer':
            fails.append('P15d: a triager + second-person resolution was refused or not recorded: %s' % err)
            continue
        cl, w = rt.build_clusters([obs(B, 'svc/q.py', 'f2')])
        r4 = rt.reconcile(cl, w, be, ledger, True, today='2026-11-09',
                          context={'coverage': cov, 'lineage': lin})
        if decision == 'separate' and not _closed(be, ref_a):
            fails.append('P15d separate: the released hold did not let the rescan clear A: %r' % _held(r4, ref_a))
        if decision == 'same':
            h = _held(r4, ref_a)
            if _closed(be, ref_a) or not h or h[0].get('state') != PRESERVED:
                fails.append('P15d same: A is not preserved open beside the open B: %r' % h)
            cl, w = rt.build_clusters([])
            rt.reconcile(cl, w, be, ledger, True, today='2026-11-10',
                         context={'coverage': cov, 'lineage': lin})
            if not _closed(be, ref_a):
                fails.append('P15d same: once B cleared, A did not clear with it')


REPORT = (('P1 path moved: carried, pending, never suppressing', report_carried),
          ('P6 exported history: direct vs carried basis', exported),
          ('P2 two hops incl. extraction correction', report_two_hops),
          ('P3 direct approval distinct from carried', report_direct),
          ('N1 split: carried pending, names the split', report_split),
          ('N2 merge: names every prior decision', report_merge),
          ('N3 cycle: refused by name', report_cycle),
          ('N4 missing ledger: LEDGER_ABSENT stated', report_missing),
          ('N5 tampered ledger: carry refused, named', report_tampered),
          ('N6 expired approval: carried EXPIRED, pending', report_expired),
          ('P5 command-line wiring', wiring))
TICKETS = (('P4 ticket continuity carried by lineage', tickets_carried),
           ('N1 split: tickets ambiguous', tickets_split),
           ('N2 merge: ambiguous, not auto-merged', tickets_merge),
           ('N3 cycle: ticket ambiguous', tickets_cycle),
           ('N4 missing ledger: stated, nothing closed', tickets_missing),
           ('N4e missing ledger + newcomer: clearance held', tickets_missing_newcomer),
           ('N4f old ledger, no rule: held, said', tickets_missing_rule_unrecorded),
           ('N4g non-intact ledger + newcomer: clearance held', tickets_nonintact_newcomer),
           ('N4h split/merge/cycle ancestor: clearance held', tickets_conflict_clearance),
           ('P8 genuine clearance still closes', tickets_missing_clears),
           ('P8e intact ledger, no newcomer: closes', tickets_intact_clears),
           ('N5 tampered: ticket ambiguous', tickets_tampered),
           ('N7 directly bound + lineage split: held', tickets_direct_split),
           ('N8 directly bound + lineage merge: held', tickets_direct_merge),
           ('N9 directly bound + lineage move: held', tickets_direct_move),
           ('P7 direct binding continues the lineage', tickets_direct_continues),
           ('P9/N10 path, alias, extraction, combined (F9)', _mechanisms_entry),
           ('N17/P17 alias policy, unresolved alias changes (F17)',
            lambda rt, fl, work, fails: alias_policy(__import__('scan_report'), rt, fl, work, fails)),
           ('N14 partial population: provisional, two runs', tickets_partial_population),
           ('P14 complete population clears', tickets_complete_population_clears),
           ('N19/P19 affirmative, declared population (R3 F19)', tickets_population_r3),
           ('N15/P15 correlation tiers (F15, F8 policy)', tickets_correlation_tiers),
           ('N20/P20 advisory-id conflict held (R3 F20)', tickets_advisory_conflict),
           ('N15d held reconciliation is not an active finding', tickets_hold_not_active),
           ('N15e/P15d hold persists; SoD human resolution', tickets_hold_persists_and_resolves))


def run_all(sr, rt, fl, quiet=False):
    fails = []
    work = tempfile.mkdtemp(prefix='lineage-consumers-')
    try:
        for label, fn in REPORT:
            before = len(fails)
            try:
                fn(sr, fl, work, fails)
            except Exception as exc:                          # noqa: BLE001 - a crash is a failure
                fails.append('%s crashed: %s: %s' % (label, type(exc).__name__, exc))
            if not quiet:
                print('  %-52s %s' % (label, 'ok' if len(fails) == before else 'FAIL'))
        for label, fn in TICKETS:
            before = len(fails)
            try:
                fn(rt, fl, work, fails)
            except Exception as exc:                          # noqa: BLE001
                fails.append('%s crashed: %s: %s' % (label, type(exc).__name__, exc))
            if not quiet:
                print('  %-52s %s' % (label, 'ok' if len(fails) == before else 'FAIL'))
    finally:
        shutil.rmtree(work, ignore_errors=True)
    return fails


def mutants(sr, rt, fl):
    """-> list of mutants that SURVIVED (were not caught). Each is restored afterwards."""
    survived = []
    if hasattr(fl, 'alias_continuity'):
        _DECIDE['alias'] = fl.alias_continuity

    def attempt(name, target, attr, replacement):
        original = getattr(target, attr)
        setattr(target, attr, replacement(original))
        try:
            caught = bool(run_all(sr, rt, fl, quiet=True))
        finally:
            setattr(target, attr, original)
        print('  mutant %-24s %s' % (name, 'caught' if caught else 'SURVIVED'))
        if not caught:
            survived.append(name)

    def carried_suppresses(orig):
        def f(fi, disp, today=None, lineage=None):
            rec, basis, _n = _call(sr.disposition_for, fi, disp, today, lineage=lineage)
            return rec is not None and not sr.not_suppressed_because(rec, today)
        return f
    attempt('carried-suppresses', sr, 'is_suppressed', carried_suppresses)

    def not_consulted(orig):
        return lambda f, disp, lineage, today=None: None
    attempt('lineage-not-consulted', sr, 'lineage_disposition', not_consulted)

    def split_binds(orig):
        def f(ident, bindings, lineage):
            got = orig(ident, bindings, lineage)
            if got and got.get('conflict', '').startswith('split'):
                got = dict(got, conflict='')
            return got
        return f
    attempt('split-binds', rt, 'lineage_binding', split_binds)

    def tampered_trusted(orig):
        return tuple(orig) + (fl.LEDGER_TAMPERED,)
    attempt('tampered-trusted', fl, 'RESOLVABLE', tampered_trusted)

    # Review 2026-11-09 finding 11: the reviewer's named mutant. The defect as it stood at cd9698d.
    def skip_when_bound(orig):
        return lambda c, bound, bindings, lineage: False
    # Review 2026-11-09 finding 8: an absent ledger read as no prior relationship.
    if hasattr(sr, 'unresolved_reconciliation'):
        attempt('absent-ledger-no-relationship', sr, 'unresolved_reconciliation',
                lambda orig: (lambda f, disp, lineage, today=None: None))
    else:
        survived.append('absent-ledger-no-relationship (sr.unresolved_reconciliation absent)')
    # Review 2026-11-09 finding 9: the F9 cases exercise the REAL mechanisms, so breaking a
    # mechanism in production ingestion must turn them red (the precondition "the identity moved").
    def alias_first_only(orig):
        def f(*a, **kw):
            out, basis = orig(*a, **kw)
            if out.get('cve'):
                out = dict((k, v) for k, v in out.items() if k not in ('ghsa', 'osv'))
            return out, basis
        return f
    attempt('alias-first-only', sr, 'what_of', alias_first_only)
    attempt('extraction-generation-ignored', sr.code_finding_key, 'code_location',
            lambda orig: (lambda *a, **kw: {'refused': 'mutant: no checkout read'}))
    # Review 2026-11-09 R03 acceptance: a non-intact ledger must hold the clearance too.
    if hasattr(rt, 'lineage_clearance_hold'):
        def clear_when_tampered(orig):
            def f(entry, newcomers, lineage, created=None):
                if lineage and lineage.get('integrity') != fl.LEDGER_ABSENT:
                    return None
                return orig(entry, newcomers, lineage, created)
            return f
        attempt('clear-when-tampered', rt, 'lineage_clearance_hold', clear_when_tampered)
    else:
        survived.append('clear-when-tampered (rt.lineage_clearance_hold absent)')
    # Review 2026-11-09 finding 8, ticket side: the coordinator's named mutant.
    if hasattr(rt, 'lineage_clearance_hold'):
        attempt('clear-despite-newcomer', rt, 'lineage_clearance_hold',
                lambda orig: (lambda entry, newcomers, lineage, created=None: None))
    else:
        survived.append('clear-despite-newcomer (rt.lineage_clearance_hold absent)')
    if hasattr(rt, 'lineage_conflict_hold'):
        attempt('clear-during-split', rt, 'lineage_conflict_hold',
                lambda orig: (lambda key, entry, conflicts, lineage: None))
    else:
        survived.append('clear-during-split (rt.lineage_conflict_hold absent)')
    # Review round 2 F14 / F15: the coordinator's named mutant, and the lane's.
    if hasattr(rt, 'population_gaps'):
        attempt('clear-on-partial-population', rt, 'population_gaps',
                lambda orig: (lambda *a, **kw: []))
    else:
        survived.append('clear-on-partial-population (rt.population_gaps absent)')
    # Review round 3 F19: the coordinator's named mutants.
    if hasattr(rt, 'load_scanner_inventory'):
        def sweep_is_false_only(orig):          # revert `is True` to the old `is False` check
            def f(entry, ledger, lineage, coverage, withheld, sweep_complete, inventory=None):
                return orig(entry, ledger, lineage, coverage, withheld,
                            False if sweep_complete is False else True, inventory=inventory)
            return f
        attempt('sweep-is-false-only', rt, 'population_gaps', sweep_is_false_only)

        def drop_inventory_binding(orig):       # the denominator is whatever ran again
            def f(entry, ledger, lineage, coverage, withheld, sweep_complete, inventory=None):
                jobs = dict(((inventory or {}).get('jobs') or {}))
                seen = dict((str((r or {}).get('job') or ''), jobs.get(str((r or {}).get('job') or ''), 'discover.x'))
                            for r in (coverage or {}).values())
                return orig(entry, ledger, lineage, coverage, withheld, sweep_complete,
                            inventory={'state': 'SCANNER_INVENTORY_ESTABLISHED', 'jobs': seen})
            return f
        attempt('drop-inventory-binding', rt, 'population_gaps', drop_inventory_binding)
        attempt('trust-not-applicable', rt, 'not_applicable_validated',
                lambda orig: (lambda row, inventory: True))
    else:
        survived.append('sweep-is-false-only / drop-inventory-binding (rt.load_scanner_inventory absent)')
    if hasattr(rt, 'correlation_tier'):
        def scanner_rule_only(orig):
            def f(seen, m):
                if seen.get('scanner') and seen.get('scanner') == m.get('scanner') and                         seen.get('rule') and seen.get('rule') == (m.get('rule') or m.get('rule_id')):
                    return rt.CORRELATION_PLAUSIBLE, ['mutant: scanner and rule alone']
                return orig(seen, m)
            return f
        attempt('scanner-rule-only-correlation', rt, 'correlation_tier', scanner_rule_only)

        def disjoint_first(orig):           # review round 3 F20: the disjoint check back on top
            def f(seen, m):
                sa = set(seen.get('aliases') or [])
                ma = set(str(x) for x in m.get('what_aliases') or [] if x)
                if sa and ma and not (sa & ma):
                    return rt.CORRELATION_UNRELATED, ['mutant: disjoint advisory ids first']
                return orig(seen, m)
            return f
        attempt('disjoint-before-subject-locus', rt, 'correlation_tier', disjoint_first)
        attempt('hold-lasts-one-run', rt, 'prior_reconciliation_hold',
                lambda orig: (lambda *a, **kw: None))
    else:
        survived.append('scanner-rule-only-correlation (rt.correlation_tier absent)')
    # Review round 2 F17: the coordinator's named mutant -- ANY alias change continues identity.
    if hasattr(fl, 'alias_continuity'):
        def any_alias_change_continues(orig):
            def f(old, new):
                d = orig(old, new)
                if d['state'] in fl.ALIAS_UNRESOLVED_STATES:
                    v = fl._alias_view(new)
                    d = dict(d, state=fl.SCANNER_ATTESTED_ALIAS_CONTINUITY, decision_id='mutant',
                             why='mutant: any alias change continues',
                             event={'relation': fl.SUPERSEDES, 'from_identities': [d['from_identity']],
                                    'to_identities': [v['identity']], 'cause': fl.ADVISORY_ALIAS_ADDED,
                                    'event_id': 'mutant'})
                return d
            return f
        attempt('any-alias-change-continues', fl, 'alias_continuity', any_alias_change_continues)

        def attestation_dropped(orig):      # review round 3 F21: the claim reads as verified again
            def f(old, new):
                d = dict(orig(old, new))
                for k in ('assurance', 'corroboration', 'provenance'):
                    d.pop(k, None)
                d['why'] = d.get('why', '').replace('as attested by the scanner', 'as verified').replace(
                    'not independently verified', 'verified')
                return d
            return f
        attempt('attestation-dropped', fl, 'alias_continuity', attestation_dropped)
    else:
        survived.append('any-alias-change-continues (fl.alias_continuity absent)')
    if hasattr(rt, 'lineage_outstanding'):
        attempt('skip-lineage-when-bound', rt, 'lineage_outstanding', skip_when_bound)
    else:
        survived.append('skip-lineage-when-bound (rt.lineage_outstanding absent)')
    return survived


def main():
    try:
        import scan_report as sr
        import reconcile_tickets as rt
        import finding_lineage as fl
    except Exception as exc:                                  # noqa: BLE001
        print('UNKNOWN: could not import: %s' % exc)
        return 2
    print('=== R03: the lineage ledger reaches the report, the ticket and the record ===')
    fails = run_all(sr, rt, fl)
    if fails:
        print('')
        for i, f in enumerate(fails, 1):
            print('  %d. %s' % (i, f))
        print('::error title=Lineage consumers unproven::%d failure(s)' % len(fails))
        return 1
    survived = mutants(sr, rt, fl)
    if survived:
        print('::error title=Lineage consumer mutants survived::%s' % ', '.join(survived))
        return 1
    print('lineage consumers proven: a moved finding\'s prior decision is reported as '
          'DISPOSITION_CARRIED_BY_LINEAGE with its basis and a pending decision, never '
          'suppressing; a direct approval stays distinct; the ticket binding follows the approved '
          'lineage and records it; split, merge, cycle, missing and tampered ledgers and an '
          'expired approval leave the obligation visible and undecided; a directly bound cluster in a '
          'conflicting lineage event is held, never erasing the ancestor obligation; an absent ledger '
          'holds a clearance a same-rule newcomer may be; path, alias, extraction and combined moves from '
          'real scanner output reach both consumers; a partial population only ever clears '
          'provisionally; correlation is tiered (strong, plausible, unrelated, insufficient) and a held '
          'reconciliation is a ticket state, never an active finding; mutants '
          'caught.')
    return 0


if __name__ == '__main__':
    sys.exit(main())

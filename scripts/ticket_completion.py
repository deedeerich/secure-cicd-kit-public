#!/usr/bin/env python3
"""TWO COMPLETION LEVELS, THE QUALIFYING RESCAN, RECURRENCE AFTER FINAL, AND THE TAG TAXONOMY (KDEC-062, owner 2026-11-16).

THE OWNER'S RULINGS (2026-11-16)

    Level 1 "done/closed" may be set by the person who triaged or fixed the finding. It records THEIR
    disposition; it is not an independent verification.
    Level 2 "archived/final" may NEVER be set by the level-1 actor. It needs either a QUALIFYING kit rescan or a
    distinct, authorised person.
    Both are KIT LOGICAL STATES. The tracker word for each is configuration (`ticket_taxonomy.completion_statuses`
    in the policy register, per tracker); the kit hard-codes no tracker status name. An unmapped level is
    projected the way the kit always projected it (labels and a comment for level 1, the tracker's done state for
    level 2) and the row says COMPLETION_STATUS_UNMAPPED.

THE RECORD IS THE AUTHORITY, NEVER A LABEL

    The completion level lives in the ticket ledger entry (`completion`, history in `completion_history`) -- the
    register merged to the protected default branch by a reviewed pull request (reusable-propose-ledger). A
    label is its projection. A person can add any label to a tracker ticket, so a protected `<stamp>-*` label the
    kit's record does not attest (SYSTEM_LABEL_UNATTESTED) is reported and IGNORED for every state decision; it
    is never removed either (the kit removes no label it did not write -- and it writes none away).

THE QUALIFYING RESCAN (absence is not remediation unless ...)

    For every affected instance (every member identity, every scanner that saw it):
        the same instance identity is not reported by the rescan          else RESCAN_INSTANCE_STILL_PRESENT
        the ledger recorded which scanner saw it and where                 else RESCAN_INSTANCE_NOT_RECORDED
        the rescan's coverage record exists                                else RESCAN_OUTPUT_MISSING
        that scanner has a row                                             else RESCAN_SCANNER_NOT_RUN
        the row is ESTABLISHED (ran, completed, report read, not PARTIAL) else RESCAN_SCANNER_NOT_COMPLETED
        the rescan says which files exist (path_inventory ESTABLISHED)     else RESCAN_PATH_STATE_NOT_ESTABLISHED
        the file still exists                                              else RESCAN_PATH_REMOVED
        the file is not excluded by the scanner's row                      else RESCAN_PATH_EXCLUDED
        the scanner's scope covers the file                                else RESCAN_PATH_OUT_OF_SCOPE
        the scope the scanner ran with is the scope recorded when it saw it else RESCAN_SCOPE_CHANGED
            (not recorded at all: RESCAN_BASIS_NOT_RECORDED)
        a config digest, when either side declares one, is the same        else RESCAN_CONFIG_CHANGED
        no finding without an identity at that scanner and file           else RESCAN_UNIDENTIFIED_AT_PATH
    All hold -> RESCAN_QUALIFYING. Any fails -> RESCAN_NOT_VERIFIED with every reason named; no automatic level 2.

RECURRENCE AFTER LEVEL 2: A NEW LINKED RECURRENCE TICKET (never a reopen)

    A final record is final: reopening it would rewrite the verified history it carries, and an archived status
    is one many tracker workflows offer no transition out of. So the same finding observed again after level 2
    gets a NEW ticket that names its predecessor (reference and key), and the ledger keeps the predecessor's
    completion in `completion_history` and the chain in `recurrences`. Deterministic: recurrence number n is the
    count already recorded + 1; the same run seen twice records one recurrence.
"""
import os
import re
import sys

# ── the logical levels ────────────────────────────────────────────────────────────────────
COMPLETION_OPEN = 'COMPLETION_OPEN'
COMPLETION_L1_DONE = 'COMPLETION_L1_DONE'
COMPLETION_L2_FINAL = 'COMPLETION_L2_FINAL'
LEVELS = (COMPLETION_OPEN, COMPLETION_L1_DONE, COMPLETION_L2_FINAL)
# The config keys a tracker's status map uses (ticket_taxonomy.completion_statuses.<backend>.<key>).
STATUS_KEYS = {COMPLETION_L1_DONE: 'level1', COMPLETION_L2_FINAL: 'level2'}

# ── refusals and projection states ─────────────────────────────────────────────────────────
COMPLETION_L2_SAME_ACTOR = 'COMPLETION_L2_SAME_ACTOR'
COMPLETION_L2_NOT_AUTHORISED = 'COMPLETION_L2_NOT_AUTHORISED'
COMPLETION_L1_NOT_RECORDED = 'COMPLETION_L1_NOT_RECORDED'
COMPLETION_ALREADY_FINAL = 'COMPLETION_ALREADY_FINAL'
COMPLETION_RESCAN_NOT_QUALIFYING = 'COMPLETION_RESCAN_NOT_QUALIFYING'
COMPLETION_CONTINUITY_NOT_ESTABLISHED = 'COMPLETION_CONTINUITY_NOT_ESTABLISHED'
COMPLETION_STATUS_MAPPED = 'COMPLETION_STATUS_MAPPED'
COMPLETION_STATUS_UNMAPPED = 'COMPLETION_STATUS_UNMAPPED'

# ── the rescan ─────────────────────────────────────────────────────────────────────────────
RESCAN_QUALIFYING = 'RESCAN_QUALIFYING'
RESCAN_NOT_VERIFIED = 'RESCAN_NOT_VERIFIED'
RESCAN_INSTANCE_STILL_PRESENT = 'RESCAN_INSTANCE_STILL_PRESENT'
RESCAN_INSTANCE_NOT_RECORDED = 'RESCAN_INSTANCE_NOT_RECORDED'
RESCAN_OUTPUT_MISSING = 'RESCAN_OUTPUT_MISSING'
RESCAN_SCANNER_NOT_RUN = 'RESCAN_SCANNER_NOT_RUN'
RESCAN_SCANNER_NOT_COMPLETED = 'RESCAN_SCANNER_NOT_COMPLETED'
RESCAN_PATH_STATE_NOT_ESTABLISHED = 'RESCAN_PATH_STATE_NOT_ESTABLISHED'
RESCAN_PATH_REMOVED = 'RESCAN_PATH_REMOVED'
RESCAN_PATH_EXCLUDED = 'RESCAN_PATH_EXCLUDED'
RESCAN_PATH_OUT_OF_SCOPE = 'RESCAN_PATH_OUT_OF_SCOPE'
RESCAN_SCOPE_CHANGED = 'RESCAN_SCOPE_CHANGED'
RESCAN_BASIS_NOT_RECORDED = 'RESCAN_BASIS_NOT_RECORDED'
RESCAN_CONFIG_CHANGED = 'RESCAN_CONFIG_CHANGED'
RESCAN_UNIDENTIFIED_AT_PATH = 'RESCAN_UNIDENTIFIED_AT_PATH'
# KDEC-069: the scanner that saw it is RETIRED (scanner-obligations.json provider_lifecycle) and no replacement's
# clean result shows equivalence (issue type, location, version, detection capability). Never auto-closed:
# it waits for a verifier who is not the fixer, or an authorised disposition.
RESCAN_PROVIDER_RETIRED_NO_EQUIVALENCE = 'RESCAN_PROVIDER_RETIRED_NO_EQUIVALENCE'
PATH_INVENTORY_ESTABLISHED = 'PATH_INVENTORY_ESTABLISHED'
PATH_INVENTORY_NOT_ESTABLISHED = 'PATH_INVENTORY_NOT_ESTABLISHED'

# ── recurrence ─────────────────────────────────────────────────────────────────────────────
RECURRENCE_LINKED_TICKET = 'RECURRENCE_LINKED_TICKET'
RECURRENCE_ALREADY_RECORDED = 'RECURRENCE_ALREADY_RECORDED'

# ── continuity (the register) ──────────────────────────────────────────────────────────────
REGISTER_READ = 'REGISTER_READ'

# ── tags ───────────────────────────────────────────────────────────────────────────────────
TAG_SYSTEM = 'system'
TAG_SOURCE = 'source'
TAG_METADATA = 'metadata'
TAG_USER = 'user'
SYSTEM_LABEL_UNATTESTED = 'SYSTEM_LABEL_UNATTESTED'
TAXONOMY_LABEL_INVALID = 'TAXONOMY_LABEL_INVALID'
TAXONOMY_LABEL_PROTECTED = 'TAXONOMY_LABEL_PROTECTED'
# The kit's own projection labels of the two levels (suffixes under the stamp). A person adding one changes nothing.
LEVEL_LABEL_SUFFIX = {COMPLETION_L1_DONE: 'completion-level1', COMPLETION_L2_FINAL: 'completion-level2'}
LABEL_TOKEN = re.compile(r'^[^\s,;]{1,100}$')


def _s(v):
    return str(v or '').strip()


def _same_actor(a, b):
    return bool(_s(a)) and _s(a).lower() == _s(b).lower()


# ═════════════════════════════════════════════════════════════════════════════════════════
# THE LEVELS
# ═════════════════════════════════════════════════════════════════════════════════════════

def level_of(entry):
    """-> the kit logical level, read from the LEDGER record only (never from a label)."""
    c = (entry or {}).get('completion') if isinstance(entry, dict) else None
    lv = (c or {}).get('level') if isinstance(c, dict) else None
    return lv if lv in LEVELS else COMPLETION_OPEN


def level1_actor(entry):
    c = (entry or {}).get('completion') or {}
    return _s((c.get('level1') or {}).get('actor')) if isinstance(c, dict) else ''


def set_level1(entry, actor, role, disposition, today, evidence=None):
    """Level 1: the triager's or fixer's own disposition. -> (refusal or None, entry). Never independent."""
    if level_of(entry) == COMPLETION_L2_FINAL:
        return {'state': COMPLETION_ALREADY_FINAL,
                'detail': 'the record is already final (level 2); a level-1 disposition does not reopen or '
                          'rewrite it'}, entry
    if not _s(actor):
        return {'state': COMPLETION_L1_NOT_RECORDED, 'detail': 'a level-1 disposition names no actor'}, entry
    e = dict(entry or {})
    l1 = {'actor': _s(actor), 'role': _s(role) or 'fixer', 'disposition': _s(disposition) or 'resolved',
          'on': _s(today), 'independent': False}
    if evidence:
        l1['evidence'] = evidence
    e['completion'] = {'level': COMPLETION_L1_DONE, 'level1': l1}
    return None, e


def set_level2(entry, by, today, actor='', authorised=None, rescan=None, continuity=REGISTER_READ,
               fallback_l1_actor=''):
    """Level 2: archived/final. `by` is 'person' or 'rescan'.

    person: a level-1 record must exist (else COMPLETION_L1_NOT_RECORDED); the person must not be the level-1
            actor (COMPLETION_L2_SAME_ACTOR -- also compared with `fallback_l1_actor`, the item's own fixer, so a
            missing record never lets the fixer through); and must be in `authorised` when a list is given
            (COMPLETION_L2_NOT_AUTHORISED).
    rescan: `rescan` must be a RESCAN_QUALIFYING verdict (COMPLETION_RESCAN_NOT_QUALIFYING, every reason kept),
            and the register must have been read (COMPLETION_CONTINUITY_NOT_ESTABLISHED): no automatic clearance
            while continuity cannot be established.
    -> (refusal or None, entry)."""
    if level_of(entry) == COMPLETION_L2_FINAL:
        return {'state': COMPLETION_ALREADY_FINAL, 'detail': 'already final'}, entry
    c = dict((entry or {}).get('completion') or {})
    if by == 'person':
        l1a = level1_actor(entry)
        if _same_actor(actor, l1a) or _same_actor(actor, fallback_l1_actor):
            return {'state': COMPLETION_L2_SAME_ACTOR,
                    'detail': '%s set (or claims) level 1 on this record and may never set level 2: a distinct '
                              'authorised person or a qualifying kit rescan finalises it' % _s(actor)}, entry
        if not l1a and not _s(fallback_l1_actor):
            return {'state': COMPLETION_L1_NOT_RECORDED,
                    'detail': 'no level-1 disposition is recorded, so the person finalising it cannot be shown to '
                              'be distinct from the one who set it'}, entry
        if authorised is not None and _s(actor).lower() not in set(_s(a).lower() for a in authorised):
            return {'state': COMPLETION_L2_NOT_AUTHORISED,
                    'detail': '%s is not on the authorised list for a level-2 finalisation' % _s(actor)}, entry
        basis = {'by': 'person', 'actor': _s(actor), 'on': _s(today)}
    elif by == 'rescan':
        if continuity != REGISTER_READ:
            return {'state': COMPLETION_CONTINUITY_NOT_ESTABLISHED,
                    'detail': 'the register state is %s: continuity with the recorded finding cannot be '
                              'established, so no automatic clearance is made' % continuity}, entry
        if not isinstance(rescan, dict) or rescan.get('verdict') != RESCAN_QUALIFYING:
            return {'state': COMPLETION_RESCAN_NOT_QUALIFYING,
                    'detail': 'the rescan is not qualifying: %s' % '; '.join(
                        '%s (%s)' % (r['reason'], r.get('detail') or '') for r in (rescan or {}).get('reasons') or [])
                    or 'no verdict', 'reasons': list((rescan or {}).get('reasons') or [])}, entry
        basis = {'by': 'rescan', 'run': _s(rescan.get('run')), 'commit': _s(rescan.get('commit')), 'on': _s(today),
                 'instances': rescan.get('instances') or 0, 'limits': list(rescan.get('limits') or [])}
    else:
        return {'state': COMPLETION_L2_NOT_AUTHORISED, 'detail': 'unknown level-2 basis %r' % by}, entry
    e = dict(entry or {})
    c.update(level=COMPLETION_L2_FINAL, level2=basis)
    e['completion'] = c
    return None, e


def tracker_status(level, backend_name, taxonomy):
    """-> (status name or None, state). The tracker's own word for a logical level is CONFIGURATION."""
    m = ((taxonomy or {}).get('completion_statuses') or {}).get(_s(backend_name)) or {}
    name = _s(m.get(STATUS_KEYS.get(level, ''))) if isinstance(m, dict) else ''
    return (name, COMPLETION_STATUS_MAPPED) if name else (None, COMPLETION_STATUS_UNMAPPED)


# ═════════════════════════════════════════════════════════════════════════════════════════
# THE QUALIFYING RESCAN
# ═════════════════════════════════════════════════════════════════════════════════════════

def _norm(p):
    return _s(p).replace('\\', '/').lstrip('./')


def path_excluded(excluded, path):
    p = _norm(path)
    for x in excluded or []:
        x = _norm(x).rstrip('/')
        if x and (p == x or p.startswith(x + '/')):
            return True
    return False


def _obligations_policy(obligations):
    """The kit's scanner-obligations.json (KDEC-069) beside this script, or the one given. None when absent."""
    if obligations is not None:
        return obligations or None
    import scanner_obligations as so
    pol, _ = so.load_policy(os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                                         'scanner-obligations.json'))
    return pol


def retired_replacement(obs, ident, rows, paths, present, commit, pol):
    """-> (row, decision) for a finding whose scanner is RETIRED: the first replacement row whose clean result
    shows equivalence, else (None, the last decision). (None, None) when the scanner is not retired."""
    import scanner_obligations as so
    import reconcile_tickets as rt
    sc = _s(obs.get('scanner'))
    if not pol or so.lifecycle(pol, sc, 'external' if sc.startswith('ext-') else 'core')[0] != so.RETIRED:
        return None, None
    finding = {'identity': ident, 'scanner': sc, 'issue_type': _s(obs.get('issue_type')), 'cwe': _s(obs.get('cwe')),
               'path': _s(obs.get('path')), 'seen_at_digest': _s(obs.get('artifact_digest'))}
    last = None
    for name, row in sorted((rows or {}).items()):
        if name == sc:
            continue
        view = {'scanner': name, 'established': rt.row_established(row), 'scope': row.get('scope'),
                'commit': _s(row.get('commit')) or _s(commit), 'artifact_digest': _s(row.get('artifact_digest')),
                'path_inventory': sorted(paths or []), 'present_identities': sorted(present),
                'issue_types': list(row.get('issue_types') or []), 'cwes': list(row.get('cwes') or [])}
        d = so.closure_decision(finding, view, pol)
        if d['decision'] == so.CLOSE_EQUIVALENT:
            return row, d
        if not any(m.startswith('capability: %s is not a provider' % name) for m in d['missing']):
            last = d
    return None, last or {'decision': so.PENDING_VERIFICATION, 'missing': ['no replacement for %s ran' % sc],
                          'pending_route': so.PENDING_ROUTE}


def qualify_rescan(entry, present_identities, coverage_doc, withheld=(), run='', commit='', obligations=None):
    """-> {verdict, reasons [{identity, scanner, path, reason, detail}], instances, limits, run, commit}.

    `coverage_doc` is the rescan's findings-coverage.json document ({rows, path_inventory}) or None."""
    import reconcile_tickets as rt
    reasons, limits, n = [], [], 0

    def no(ident, scanner, path, reason, detail):
        reasons.append({'identity': ident, 'scanner': scanner, 'path': path, 'reason': reason, 'detail': detail})

    present = set(present_identities or [])
    obl_policy = _obligations_policy(obligations)
    rows = None
    inv = None
    if isinstance(coverage_doc, dict) and isinstance(coverage_doc.get('rows'), list):
        rows = dict((r.get('scanner'), r) for r in coverage_doc['rows'] if isinstance(r, dict) and r.get('scanner'))
        inv = coverage_doc.get('path_inventory') if isinstance(coverage_doc.get('path_inventory'), dict) else None
    paths = None
    if inv and inv.get('state') == PATH_INVENTORY_ESTABLISHED and isinstance(inv.get('paths'), list):
        paths = set(_norm(p) for p in inv['paths'])
    members = (entry or {}).get('members') or {}
    ids = list((entry or {}).get('member_identities') or [])
    if not ids:
        no('', '', '', RESCAN_INSTANCE_NOT_RECORDED, 'the record names no affected instance')
    for ident in ids:
        n += 1
        if ident in present:
            no(ident, '', '', RESCAN_INSTANCE_STILL_PRESENT, 'the rescan still reports this instance')
            continue
        seen = [o for o in members.get(ident) or [] if isinstance(o, dict)]
        if not seen:
            no(ident, '', '', RESCAN_INSTANCE_NOT_RECORDED, 'the ledger does not record which scanner saw it, or where')
            continue
        for obs in seen:
            sc, path = _s(obs.get('scanner')), _s(obs.get('path'))
            if rows is None:
                no(ident, sc, path, RESCAN_OUTPUT_MISSING, 'the rescan has no readable coverage record')
                continue
            row = rows.get(sc)
            # KDEC-069: a finding from a RETIRED provider keeps its identity and never closes on its own tool's
            # absence; a replacement closes it only with shown equivalence, and is then judged as that row.
            repl, decision = retired_replacement(obs, ident, rows, paths, present, commit, obl_policy)
            if decision is not None and repl is None:
                no(ident, sc, path, RESCAN_PROVIDER_RETIRED_NO_EQUIVALENCE,
                   '%s is retired; no replacement shows equivalence (%s); pending %s'
                   % (sc, '; '.join(decision.get('missing') or []), decision.get('pending_route')))
                continue
            if repl is not None:
                limits.append('%s is retired: closed through %s under shown equivalence (%s)' % (
                    sc, decision['replacement'], ', '.join('%s=%s' % kv for kv in sorted(decision['equivalence'].items()))))
                row, sc = repl, decision['replacement']
                obs = dict(obs, scanner=sc, scan_scope=repl.get('scope'))
            if not row:
                no(ident, sc, path, RESCAN_SCANNER_NOT_RUN, '%s has no row in the rescan' % sc)
                continue
            if not rt.row_established(row):
                no(ident, sc, path, RESCAN_SCANNER_NOT_COMPLETED, '%s did not complete: execution %s, gate %s, '
                   'established %s' % (sc, row.get('execution'), row.get('gate'), row.get('established')))
                continue
            if paths is None:
                no(ident, sc, path, RESCAN_PATH_STATE_NOT_ESTABLISHED,
                   'the rescan does not say which files exist (path_inventory %s)'
                   % ((inv or {}).get('state') or 'absent'))
            elif path and _norm(path) not in paths:
                no(ident, sc, path, RESCAN_PATH_REMOVED, '%s no longer exists: a deleted file is not a fix' % path)
            if path_excluded(row.get('excluded'), path):
                no(ident, sc, path, RESCAN_PATH_EXCLUDED, '%s is excluded from %s in the rescan' % (path, sc))
            elif not rt.scope_covers(row.get('scope'), path):
                no(ident, sc, path, RESCAN_PATH_OUT_OF_SCOPE, '%s scanned %r, which does not cover %s'
                   % (sc, row.get('scope'), path))
            if 'scan_scope' not in obs:
                no(ident, sc, path, RESCAN_BASIS_NOT_RECORDED,
                   'the scope %s ran with when it saw the instance was not recorded, so comparability is unknown' % sc)
            elif _norm(obs.get('scan_scope')) != _norm(row.get('scope')):
                no(ident, sc, path, RESCAN_SCOPE_CHANGED, '%s scope was %r when it saw it and is %r now'
                   % (sc, obs.get('scan_scope'), row.get('scope')))
            was, now = _s(obs.get('config_sha256')), _s(row.get('config_sha256'))
            if (was or now) and was != now:
                no(ident, sc, path, RESCAN_CONFIG_CHANGED, '%s configuration digest was %r and is %r'
                   % (sc, was[:16] or 'undeclared', now[:16] or 'undeclared'))
            elif not was and not now:
                limits.append('%s declared no configuration digest at either scan; scope was compared' % sc)
            if _s(obs.get('scanner_version')) and _s(row.get('scanner_version')) and \
                    _s(obs.get('scanner_version')) != _s(row.get('scanner_version')):
                limits.append('%s version %s -> %s' % (sc, obs.get('scanner_version'), row.get('scanner_version')))
            if any(_s(w.get('scanner')) == sc and _norm(w.get('uri')) == _norm(path) for w in withheld or []):
                no(ident, sc, path, RESCAN_UNIDENTIFIED_AT_PATH,
                   '%s reported a finding with no durable identity at %s; it may be this one' % (sc, path))
    return {'verdict': RESCAN_NOT_VERIFIED if reasons else RESCAN_QUALIFYING, 'reasons': reasons,
            'instances': n, 'limits': sorted(set(limits)), 'run': _s(run), 'commit': _s(commit)}


# ═════════════════════════════════════════════════════════════════════════════════════════
# RECURRENCE AFTER LEVEL 2
# ═════════════════════════════════════════════════════════════════════════════════════════

def plan_recurrence(entry, run='', commit=''):
    """-> None (not final: the existing reopen policy applies) or {decision, number, predecessor, ...}."""
    if level_of(entry) != COMPLETION_L2_FINAL:
        return None
    prior = [r for r in (entry or {}).get('recurrences') or [] if isinstance(r, dict)]
    if run and any(_s(r.get('run')) == _s(run) and r.get('after_final') for r in prior):
        return {'decision': RECURRENCE_ALREADY_RECORDED, 'number': len(prior)}
    return {'decision': RECURRENCE_LINKED_TICKET, 'number': len(prior) + 1,
            'predecessor': _s((entry or {}).get('ref')), 'predecessor_key': _s((entry or {}).get('key')),
            'run': _s(run), 'commit': _s(commit)}


def apply_recurrence(entry, plan, new_ref, new_key, today):
    """The history is kept whole: the predecessor's completion moves to `completion_history`, the chain grows."""
    e = dict(entry or {})
    hist = list(e.get('completion_history') or [])
    if e.get('completion'):
        hist.append(dict(e['completion'], ref=_s(e.get('ref')), key=_s(e.get('key')), superseded_on=_s(today)))
    e['completion_history'] = hist
    e.pop('completion', None)
    e['predecessors'] = sorted(set([_s(p) for p in e.get('predecessors') or []] + [plan['predecessor']]))
    e['recurrences'] = list(e.get('recurrences') or []) + [{
        'number': plan['number'], 'after_final': True, 'predecessor': plan['predecessor'],
        'predecessor_key': plan.get('predecessor_key') or '', 'ticket': _s(new_ref), 'recurred_on': _s(today),
        'run': plan.get('run') or '', 'commit': plan.get('commit') or ''}]
    e['ref'] = _s(new_ref)
    e['key'] = _s(new_key) or _s(new_ref)
    return e


# ═════════════════════════════════════════════════════════════════════════════════════════
# THE TAG TAXONOMY
# ═════════════════════════════════════════════════════════════════════════════════════════

def taxonomy_problems(taxonomy, stamp):
    """-> [(state, detail)] for a configured taxonomy the kit refuses. Config only: the kit invents no names."""
    out = []
    t = taxonomy if isinstance(taxonomy, dict) else {}
    p = _s(stamp) or 'secure-cicd-kit'
    for name, lab in sorted((t.get('source_labels') or {}).items()):
        if not isinstance(lab, str) or not LABEL_TOKEN.match(lab):
            out.append((TAXONOMY_LABEL_INVALID, 'source_labels.%s %r is not one label token' % (name, lab)))
        elif lab == p or lab.startswith(p + '-'):
            out.append((TAXONOMY_LABEL_PROTECTED, 'source_labels.%s %r is in the kit\'s protected %s-* namespace'
                        % (name, lab, p)))
    for name, val in sorted((t.get('metadata') or {}).items()):
        if not isinstance(val, str) or not LABEL_TOKEN.match(_slug(name) + '-' + _slug(val)):
            out.append((TAXONOMY_LABEL_INVALID, 'metadata.%s %r is not a label value' % (name, val)))
    for be, m in sorted((t.get('completion_statuses') or {}).items()):
        if not isinstance(m, dict) or set(m) - set(STATUS_KEYS.values()) or \
                not all(isinstance(v, str) and v.strip() for v in m.values()):
            out.append((TAXONOMY_LABEL_INVALID, 'completion_statuses.%s must map only level1/level2 to status '
                        'names' % be))
    return out


def _slug(v):
    return re.sub(r'[^a-z0-9._-]+', '-', _s(v).lower()).strip('-')[:60] or 'unknown'


def kit_labels(taxonomy, stamp, source_keys=()):
    """-> the labels the taxonomy's CONFIG adds to a kit-written ticket: the configured source label of each
    source key it names, and one `<stamp>-meta-<name>-<value>` per configured metadata pair (protected)."""
    t = taxonomy if isinstance(taxonomy, dict) else {}
    if taxonomy_problems(t, stamp):
        return []
    p = _s(stamp) or 'secure-cicd-kit'
    out = set()
    src = t.get('source_labels') or {}
    for k in source_keys or ():
        if _s(k) in src:
            out.add(src[_s(k)])
    for name, val in (t.get('metadata') or {}).items():
        out.add('%s-meta-%s-%s' % (p, _slug(name), _slug(val)))
    return sorted(out)


def classify_labels(labels, stamp, taxonomy=None):
    """-> {system, source, metadata, user}: the four classes. `<stamp>` and `<stamp>-*` are protected (system or,
    under `<stamp>-meta-`, metadata); a configured source label is source; everything else is a person's."""
    p = _s(stamp) or 'secure-cicd-kit'
    srcs = set(((taxonomy or {}).get('source_labels') or {}).values())
    out = {TAG_SYSTEM: [], TAG_SOURCE: [], TAG_METADATA: [], TAG_USER: []}
    for lab in labels or []:
        lab = _s(lab)
        if not lab:
            continue
        if lab.startswith(p + '-meta-'):
            out[TAG_METADATA].append(lab)
        elif lab == p or lab.startswith(p + '-'):
            out[TAG_SYSTEM].append(lab)
        elif lab in srcs:
            out[TAG_SOURCE].append(lab)
        else:
            out[TAG_USER].append(lab)
    return dict((k, sorted(set(v))) for k, v in out.items())


def user_labels(labels, stamp, taxonomy=None):
    return classify_labels(labels, stamp, taxonomy)[TAG_USER]


def unattested_level_labels(entry, labels, stamp):
    """-> [{label, state}] for every level projection label on the ticket the LEDGER does not attest. They are
    reported and ignored: the level is read from the record (level_of), never from the label."""
    p = _s(stamp) or 'secure-cicd-kit'
    lv = level_of(entry)
    out = []
    for level, suffix in LEVEL_LABEL_SUFFIX.items():
        lab = '%s-%s' % (p, suffix)
        attested = (lv == level) or (level == COMPLETION_L1_DONE and lv == COMPLETION_L2_FINAL)
        if lab in set(labels or []) and not attested:
            out.append({'label': lab, 'state': SYSTEM_LABEL_UNATTESTED, 'recorded_level': lv})
    return out


def level_label(level, stamp):
    suffix = LEVEL_LABEL_SUFFIX.get(level)
    return ('%s-%s' % (_s(stamp) or 'secure-cicd-kit', suffix)) if suffix else ''


def _selftest():
    fails = []
    _r, e = set_level1({}, 'dev-one', 'fixer', 'fixed', '2026-11-16')
    r2, _e2 = set_level2(e, 'person', '2026-11-16', actor='DEV-ONE', authorised=['dev-one', 'sec-two'])
    if not r2 or r2['state'] != COMPLETION_L2_SAME_ACTOR:
        fails.append('the level-1 actor reached level 2')
    r3, e3 = set_level2(e, 'person', '2026-11-16', actor='sec-two', authorised=['sec-two'])
    if r3 or level_of(e3) != COMPLETION_L2_FINAL:
        fails.append('a distinct authorised person was refused')
    if classify_labels(['secure-cicd-kit-triage', 'mine'], 'secure-cicd-kit')[TAG_USER] != ['mine']:
        fails.append('a person\'s label was not classified as theirs')
    if unattested_level_labels({}, ['secure-cicd-kit-completion-level2'], 'secure-cicd-kit') == []:
        fails.append('a hand-added level-2 label was attested')
    for f in fails:
        print('FAIL: %s' % f)
    print('ticket_completion self-test: %s' % ('FAIL' if fails else 'PASS'))
    return 1 if fails else 0


if __name__ == '__main__':
    if '--self-test' in sys.argv[1:]:
        sys.exit(_selftest())
    print(__doc__)
    sys.exit(0)

#!/usr/bin/env python3
"""CANONICAL finding LINEAGE. When an identity changes, what happened to everything keyed on it?

THIS FILE IS THE SINGLE SOURCE OF TRUTH for the CONTINUITY side of finding matching.

THE GAP THIS CLOSES, AND WHY IT IS NOT THE SAME GAP `finding_identity.py` CLOSES
--------------------------------------------------------------------------------
`finding_identity.py` makes an identity that survives the things a vendor does to a finding --
a rule rename, a version bump, a reworded message, a line move. It is the right answer to
"is this the same finding I saw before?" and it is not an answer to the question underneath it:

    THE IDENTITY ITSELF SOMETIMES CHANGES ANYWAY.

    A package is renamed upstream and the purl moves. A file moves and the canonical path moves
    with it. An advisory gains a GHSA alias and the alias SET that composes WHAT is no longer the
    same set. A subject specification is corrected. And -- the case this kit just lived through --
    AN EXTRACTION BUG IS FIXED, and every finding in the estate acquires the identity it should
    have had all along.

    At that moment every disposition, every exception and every ticket keyed on the old identity
    is ORPHANED. Silently. Nothing errors. The operator sees a finding they resolved last month
    reappear as NEW, or an approved exception simply stop applying, with nothing anywhere saying
    why. A reviewer facing a wall of re-raised findings approves in bulk or stops reading, and
    the register stops meaning anything -- which is the same end state as having no register.

    THE SILENCE IS THE DEFECT. A finding whose identity moved and a finding that is genuinely new
    look identical to every consumer, because the only thing that could tell them apart is a
    record of the move, and nothing was keeping one.

WHAT A LINEAGE RECORD IS
------------------------
An append-only sequence of EVENTS. Each event says: these identities became these identities, at
this time, because of THIS, and SOMETHING ASSERTED IT.

    old identity -> new identity        the link
    when                                 the time, from a source that knew it
    cause                                scanner version, rule rename, advisory alias added,
                                         extraction corrected, subject spec changed, package
                                         renamed, path moved, correlation established
    asserted_by                          WHO OR WHAT SAYS SO. An unattributed alias is not
                                         evidence -- it is a claim with nobody behind it, and a
                                         ledger of those is a ledger that cannot be audited.
    provenance                           the repository, commit, ref and run it was written from,
                                         using provenance_identity's own field names

FIVE RULES, EACH OF WHICH EXISTS BECAUSE ITS ABSENCE IS A SPECIFIC FAILURE
--------------------------------------------------------------------------
1.  APPEND-ONLY, AND PROVABLY SO. A superseded identity is never deleted -- it is how an
    operator asked "what happened to the finding I accepted in March?" gets an answer at all.
    Enforced rather than promised: each event carries the id of the one before it and an
    `event_id` that hashes its own content TOGETHER WITH that link, so removing, editing or
    reordering a line breaks the chain and `--verify` reports LEDGER_TAMPERED. The chain is
    anchored at its FIRST event, so it cannot see the LAST one removed: the writer therefore also
    records a HEAD anchor (event count + last event id) beside the ledger, and the reader requires
    the chain to end there (L51). A promise of append-only that nothing checks is a comment.

2.  RESOLUTION FOLLOWS THE CHAIN, AND REFUSES A CYCLE. Identities move more than once -- an
    extraction fix in one release and a package rename in the next. Resolution walks to the end.
    It also keeps every identity it has visited and REFUSES rather than looping: a cycle in a
    lineage ledger is a mistake somebody made, and a resolver that spins on it turns a data
    error into an outage. Termination is structural, not a hop budget: the visited set cannot
    grow past the number of identities the ledger mentions.

3.  A MERGE AND A SPLIT ARE DIFFERENT EVENTS. Two findings turning out to be one is not one
    finding becoming two, and they must not be representable as each other:

        MERGED_INTO   N -> 1   two tools were reporting one condition. Resolution of ANY of the
                               N yields the one. Dispositions on all N converge on it, which is
                               the correct behaviour: each was an approval of the same condition.
        SPLIT_INTO    1 -> N   one entry was actually several conditions. Resolution of the one
                               is LINEAGE_SPLIT_UNRESOLVED and names the candidates. It does NOT
                               pick one, because picking one would hand that finding's approval
                               to a condition nobody approved -- and silently drop the others.

    Recording a split as two SUPERSEDES events would collapse them, so appending a second
    SUPERSEDES for an identity that already has a successor is REFUSED by name.

4.  "NOT KNOWN" AND "NO SUCCESSOR" ARE DIFFERENT ANSWERS. LINEAGE_UNKNOWN means this ledger has
    never heard of the identity. LINEAGE_TERMINAL means it has, and the identity is current. One
    of those says the finding is new to the estate; the other says it is the live form of
    something with a history. Collapsing them -- returning the input unchanged for both, which
    is what a one-line resolver does -- is the four-state collapse this kit refuses everywhere
    else, and it is the version of it that makes a tracked finding read as untracked.

5.  A CARRIED DISPOSITION IS NOT A DIRECT ONE. An exception found by following lineage is
    reported as DISPOSITION_CARRIED_BY_LINEAGE with the chain and the causes that produced it,
    never as though it had been approved against this identity. AN INFERENCE NEVER OVERWRITES AN
    OBSERVATION: the approver approved a key, and this says "that key became this one, because of
    X, asserted by Y" so a human can agree or refuse. Rendering it as a direct approval would let
    a chain of machine-asserted aliases silently extend a human decision.

WHAT THIS FILE DOES NOT DO
--------------------------
It does not DETECT that an identity moved. Detection needs two scans and the old record, and it
belongs with whatever compares them. This is the record and the resolver: the thing that was
missing was somewhere to write it down and a defined way to read it back.

It does not correlate. `finding_identity.py` says why: correlation asks whether two TOOLS saw one
thing in THIS run, identity asks whether this is the finding from before, and they stack rather
than merge. A correlation that concludes two findings are one is an INPUT here -- it arrives as a
MERGED_INTO event with `cause: CORRELATION_ESTABLISHED` and the correlator as the asserter.

USAGE
    python3 finding_lineage.py --self-test
    python3 finding_lineage.py --explain
    python3 finding_lineage.py --ledger <path> --verify
    python3 finding_lineage.py --ledger <path> --resolve <identity>
    python3 finding_lineage.py --ledger <path> --append <event.json>

    from finding_lineage import load, resolve, disposition_for, append_event

EXIT
    0  the operation completed, INCLUDING a resolution that correctly refused
    1  the ledger is tampered with or has an unparseable line, an append was refused, or
       `--resolve` was refused because the ledger is not LEDGER_INTACT or LEDGER_EMPTY
    2  self-test failed, or the request could not be carried out at all (including `--verify`
       of a ledger that does not exist)
"""

import argparse
import hashlib
import io
import json
import os
import sys

schema_version = 1

# ─────────────────────────────────────────────────────────────────────────────
# RELATION. How one set of identities relates to another. The cardinality is part of the
# definition, and it is CHECKED -- see rule 3 above.
SUPERSEDES = 'SUPERSEDES'
MERGED_INTO = 'MERGED_INTO'
SPLIT_INTO = 'SPLIT_INTO'

# (relation -> (from_min, from_max_or_None, to_min, to_max_or_None)). The table is the guard:
# a SUPERSEDES with two sources is a merge wearing the wrong word, and a merge recorded as a
# supersession loses the fact that the other source existed.
_cardinality = {
    SUPERSEDES: (1, 1, 1, 1),
    MERGED_INTO: (2, None, 1, 1),
    SPLIT_INTO: (1, 1, 2, None),
}

# ─────────────────────────────────────────────────────────────────────────────
# RESOLUTION OUTCOME. Five answers, none of which may be rendered as another. See rule 4.
LINEAGE_UNKNOWN = 'LINEAGE_UNKNOWN'
LINEAGE_TERMINAL = 'LINEAGE_TERMINAL'
LINEAGE_RESOLVED = 'LINEAGE_RESOLVED'
LINEAGE_CYCLE_REFUSED = 'LINEAGE_CYCLE_REFUSED'
LINEAGE_SPLIT_UNRESOLVED = 'LINEAGE_SPLIT_UNRESOLVED'

# ─────────────────────────────────────────────────────────────────────────────
# CAUSE. What moved the identity. Not decoration: an operator reading "this finding is the same
# one you accepted in March" needs to know whether that is because a file moved or because the
# kit changed its own mind about how to compute identity, and those warrant different amounts of
# trust. An event with no cause is REFUSED, so there is no "cause unknown" value to hide behind:
# the four-state rule is kept by making the weak state unwritable rather than by registering it.
SCANNER_VERSION_CHANGE = 'SCANNER_VERSION_CHANGE'
RULE_RENAMED = 'RULE_RENAMED'
ADVISORY_ALIAS_ADDED = 'ADVISORY_ALIAS_ADDED'
PACKAGE_RENAMED = 'PACKAGE_RENAMED'
PATH_MOVED = 'PATH_MOVED'
EXTRACTION_CORRECTED = 'EXTRACTION_CORRECTED'
SUBJECT_SPEC_CHANGED = 'SUBJECT_SPEC_CHANGED'
CORRELATION_ESTABLISHED = 'CORRELATION_ESTABLISHED'

CAUSES = (SCANNER_VERSION_CHANGE, RULE_RENAMED, ADVISORY_ALIAS_ADDED, PACKAGE_RENAMED,
          PATH_MOVED, EXTRACTION_CORRECTED, SUBJECT_SPEC_CHANGED, CORRELATION_ESTABLISHED)

# ─────────────────────────────────────────────────────────────────────────────
# ATTRIBUTION. An alias is an ASSERTION BY SOMETHING. The class matters because the three are
# worth different amounts: a human decision, a tool's output, and an upstream feed's re-aliasing
# are not interchangeable evidence, and a ledger that recorded only "an alias exists" could not
# tell them apart afterwards.
OPERATOR = 'OPERATOR'
TOOL = 'TOOL'
ADVISORY_FEED = 'ADVISORY_FEED'
# Reading, never writing. An event that arrives with no asserter is refused at append time; this
# exists so a ledger produced elsewhere can be NAMED as unattributed rather than read as trusted.
ATTRIBUTION_ABSENT = 'ATTRIBUTION_ABSENT'

ATTRIBUTION_CLASSES = (OPERATOR, TOOL, ADVISORY_FEED)

# ─────────────────────────────────────────────────────────────────────────────
# LEDGER INTEGRITY. Five states, and the first two are the ones a tired implementation collapses:
# a ledger that does not exist and a ledger with nothing in it answer the same way to every
# question and mean completely different things about whether anybody is keeping one.
LEDGER_ABSENT = 'LEDGER_ABSENT'
LEDGER_EMPTY = 'LEDGER_EMPTY'
LEDGER_INTACT = 'LEDGER_INTACT'
LEDGER_TAMPERED = 'LEDGER_TAMPERED'
LEDGER_LINE_UNPARSEABLE = 'LEDGER_LINE_UNPARSEABLE'

# ─────────────────────────────────────────────────────────────────────────────
# HOW A DISPOSITION REACHED A FINDING. See rule 5.
DISPOSITION_KEYED_DIRECTLY = 'DISPOSITION_KEYED_DIRECTLY'
DISPOSITION_CARRIED_BY_LINEAGE = 'DISPOSITION_CARRIED_BY_LINEAGE'
DISPOSITION_NOT_FOUND = 'DISPOSITION_NOT_FOUND'

# The provenance envelope, by `provenance_identity`'s own field names. THE LEDGER IS EVIDENCE, so
# it carries provenance the way the rest of this kit does rather than inventing a private shape.
# Absent fields are listed as absent by --verify; they are never filled in with a default, which
# is the FILE_MTIME error -- a value that looks authoritative and is systematically wrong in the
# direction that makes a weak claim read as a strong one.
provenance_fields = ('organization', 'repository', 'commit_sha', 'ref', 'run_id')

default_ledger = os.path.join('.security', 'finding-lineage.jsonl')


# ─────────────────────────────────────────────────────────────────────────────
def _canonical(payload):
    """The bytes an event_id is computed over. Sorted keys and separators fixed, so two writers
    that agree about the content agree about the id."""
    return json.dumps(payload, sort_keys=True, separators=(',', ':'),
                      ensure_ascii=True).encode('utf-8')


def _event_id(payload, prev_event_id):
    """The event's own identity, hashed TOGETHER WITH its link to the previous event.

    Hashing the content alone would make each line independently verifiable and the SEQUENCE
    unverifiable -- a line could be deleted and every remaining line would still check out. The
    link is what makes removal and reordering detectable, which is what "append-only" has to
    mean if it is going to be a control rather than a convention.
    """
    body = dict(payload)
    body.pop('event_id', None)
    body['prev_event_id'] = prev_event_id or ''
    return hashlib.sha256(_canonical(body)).hexdigest()


def _as_list(value):
    if value is None:
        return []
    if isinstance(value, (list, tuple)):
        return [str(v).strip() for v in value if str(v).strip()]
    text = str(value).strip()
    return [text] if text else []


def validate_event(event):
    """-> list of refusal reasons. Empty means the event may be appended.

    Everything here refuses rather than normalising. A ledger is evidence, and an evidence store
    that silently repairs its inputs is a store whose contents nobody can reason about.
    """
    bad = []
    if not isinstance(event, dict):
        return ['the event is not a mapping']

    relation = str(event.get('relation') or '').strip()
    if relation not in _cardinality:
        bad.append('relation %r is not one of %s. A MERGE and a SPLIT are different events and '
                   'there is no generic "changed" relation to fall back to -- see rule 3.'
                   % (relation or None, ', '.join(sorted(_cardinality))))
    src = _as_list(event.get('from_identities'))
    dst = _as_list(event.get('to_identities'))
    if not src:
        bad.append('from_identities is empty: an event with no antecedent records nothing')
    if not dst:
        bad.append('to_identities is empty: an identity that went away has not been superseded, '
                   'it has been RESOLVED or REMEDIATED, and that is a disposition rather than a '
                   'lineage event')
    if relation in _cardinality:
        fmin, fmax, tmin, tmax = _cardinality[relation]
        if len(src) < fmin or (fmax is not None and len(src) > fmax):
            bad.append('%s requires %s source identity/identities, got %d. Cardinality is part '
                       'of the relation: a SUPERSEDES with two sources is a merge wearing the '
                       'wrong word, and the word is what a reader trusts.'
                       % (relation, fmin if fmax == fmin else '%s or more' % fmin, len(src)))
        if len(dst) < tmin or (tmax is not None and len(dst) > tmax):
            bad.append('%s requires %s target identity/identities, got %d'
                       % (relation, tmin if tmax == tmin else '%s or more' % tmin, len(dst)))
    if set(src) & set(dst):
        bad.append('identity/identities %s appear on BOTH sides of one event. A finding did not '
                   'become itself, and writing it down would seed a cycle that every later '
                   'resolution has to refuse.' % ', '.join(sorted(set(src) & set(dst))))
    if len(set(src)) != len(src) or len(set(dst)) != len(dst):
        bad.append('an identity is repeated within one side of the event, which would make a '
                   'merge of two findings look like a merge of three')

    cause = str(event.get('cause') or '').strip()
    if cause not in CAUSES:
        bad.append('cause %r is not one of %s. "Something changed" is not a cause, and an event '
                   'without one cannot be weighed: a file moving and the kit correcting its own '
                   'extraction warrant different amounts of trust in the same link.'
                   % (cause or None, ', '.join(CAUSES)))
    if not str(event.get('cause_detail') or '').strip():
        bad.append('cause_detail is empty. The cause is the CLASS; the detail is what actually '
                   'happened, and it is the only part a human reading this in six months can '
                   'check against anything.')

    asserted = event.get('asserted_by')
    if not isinstance(asserted, dict):
        bad.append('asserted_by is missing. AN UNATTRIBUTED ALIAS IS NOT EVIDENCE: it is a claim '
                   'with nobody behind it, and it would let a chain of anonymous links extend a '
                   'human approval to a finding no human ever saw.')
    else:
        if not str(asserted.get('actor') or '').strip():
            bad.append('asserted_by.actor is empty -- name the tool, the feed or the role. A '
                       'ROLE, never a person: nothing orphans at handoff.')
        cls = str(asserted.get('actor_class') or '').strip()
        if cls not in ATTRIBUTION_CLASSES:
            bad.append('asserted_by.actor_class %r is not one of %s. A human decision, a tool\'s '
                       'output and an upstream feed re-aliasing an advisory are not '
                       'interchangeable evidence, and the class is what records which one this '
                       'was.' % (cls or None, ', '.join(ATTRIBUTION_CLASSES)))

    if not str(event.get('observed_at') or '').strip():
        bad.append('observed_at is empty. Without it the ledger cannot say WHEN an approval '
                   'stopped applying, which is the one thing an operator looking at a re-raised '
                   'finding needs. A filesystem timestamp is not a substitute -- it records the '
                   'last copy.')
    if not isinstance(event.get('provenance'), dict):
        bad.append('provenance is missing. The ledger is evidence; evidence that cannot say '
                   'which repository, commit and run produced it is an assertion.')
    return bad


def append_event(ledger_path, event):
    """Append one validated event. -> (event_id, []) or (None, [reasons]).

    Refuses rather than writing a doubtful record, and NEVER rewrites or removes an existing one.
    The only filesystem operation is an append.
    """
    bad = validate_event(event)
    if bad:
        return (None, bad)

    events, integrity, notes = load(ledger_path)
    if integrity in (LEDGER_TAMPERED, LEDGER_LINE_UNPARSEABLE):
        return (None, ['refusing to append to a ledger whose integrity is %s: %s'
                       % (integrity, '; '.join(notes))])

    # RULE 3, ENFORCED AT WRITE TIME. An identity that already has a successor cannot acquire a
    # second one as a supersession. If it genuinely became several things, that is ONE SPLIT_INTO
    # event -- and the difference is not cosmetic: resolution of a split refuses and names the
    # candidates, where resolution of two supersessions would silently pick whichever was written
    # first and drop the other.
    successors = _successor_map(events)
    relation = str(event.get('relation')).strip()
    if relation in (SUPERSEDES, MERGED_INTO):
        for ident in _as_list(event.get('from_identities')):
            existing = successors.get(ident) or []
            if existing:
                return (None, [
                    'identity %s already has successor(s) %s in this ledger. Appending another '
                    '%s would record a SPLIT as two supersessions, and the two must not collapse '
                    'into each other: one finding becoming several is a SPLIT_INTO event whose '
                    'resolution REFUSES and names the candidates, where two supersessions would '
                    'silently resolve to the first one written and lose the rest.'
                    % (ident, ', '.join(existing), relation)])

    prev = events[-1]['event_id'] if events else ''
    payload = {}
    for key in ('relation', 'finding_subject', 'cause', 'cause_detail', 'observed_at',
                'observed_at_source'):
        if str(event.get(key) or '').strip():
            payload[key] = str(event[key]).strip()
    payload['schema_version'] = schema_version
    payload['from_identities'] = _as_list(event.get('from_identities'))
    payload['to_identities'] = _as_list(event.get('to_identities'))
    payload['asserted_by'] = dict(event.get('asserted_by') or {})
    payload['provenance'] = dict(event.get('provenance') or {})
    payload['prev_event_id'] = prev
    payload['event_id'] = _event_id(payload, prev)

    directory = os.path.dirname(os.path.abspath(ledger_path))
    if directory and not os.path.isdir(directory):
        os.makedirs(directory)
    with io.open(ledger_path, 'a', encoding='utf-8') as fh:
        fh.write(json.dumps(payload, sort_keys=True) + '\n')
    _write_head(ledger_path, len(events) + 1, payload['event_id'])
    return (payload['event_id'], [])


# ─────────────────────────────────────────────────────────────────────────────
# HEAD ANCHORING (L51, G1-7 / T6).
#
# The chain is anchored at its FIRST event (prev_event_id ''), so it proves that no line was
# removed, inserted or reordered BEFORE the last one -- and proves nothing about the last one.
# Delete the final N events and what remains is a perfectly valid, shorter chain. That was read as
# LEDGER_INTACT, which made "append-only" false for exactly the events most likely to matter: the
# newest supersession, the one a carried approval depends on.
#
# So the writer records the HEAD beside the ledger -- the event count and the last event id -- and
# the reader requires the chain to end exactly there. A missing head over a non-empty ledger is
# TAMPERED, not intact: a ledger that cannot exclude truncation cannot claim completeness.
#
# The head file is in the same directory and the same commit, so someone who rewrites both can
# hide a truncation from this file alone. That is what `expected_head` is for: the head event id as
# recorded OUTSIDE the ledger -- read from the protected branch, or from the run record of the last
# accepted write -- and a disagreement is TAMPERED whatever the local head says. On the protected
# branch the review of the diff is the other anchor: a removed line is visible in it.
def head_path(ledger_path):
    return ledger_path + '.head'


def _write_head(ledger_path, count, head_event_id):
    tmp = head_path(ledger_path) + '.tmp'
    with io.open(tmp, 'w', encoding='utf-8', newline='\n') as fh:
        fh.write(json.dumps({'schema_version': schema_version, 'event_count': count,
                             'head_event_id': head_event_id}, sort_keys=True) + '\n')
    os.replace(tmp, head_path(ledger_path))


def _read_head(ledger_path):
    """-> (head dict or None, problem or '')."""
    path = head_path(ledger_path)
    if not os.path.exists(path):
        return (None, '')
    try:
        head = json.loads(io.open(path, encoding='utf-8').read())
    except (IOError, OSError, ValueError) as exc:
        return (None, 'the head anchor %s cannot be read: %s' % (path, exc))
    if (not isinstance(head, dict) or not isinstance(head.get('event_count'), int)
            or not str(head.get('head_event_id') or '').strip()):
        return (None, 'the head anchor %s is not {event_count, head_event_id}' % path)
    return (head, '')


def load(ledger_path, expected_head=None):
    """-> (events, integrity_state, notes).

    A LEDGER THAT DOES NOT EXIST AND AN EMPTY ONE ARE DIFFERENT STATES, and both are different
    from a readable one. The first says nobody is keeping a lineage record, which is a finding in
    itself; the second says somebody is and nothing has moved yet.

    A line that cannot be parsed is REPORTED, never skipped. Skipping is how an evidence store
    comes to answer confidently from a subset of itself.

    `expected_head` is the head event id as recorded OUTSIDE this ledger (see HEAD ANCHORING). When
    given, the chain must end exactly there.
    """
    expected_head = str(expected_head or '').strip()
    head, head_problem = _read_head(ledger_path) if ledger_path else (None, '')
    if ledger_path and not os.path.exists(ledger_path) and (head or head_problem or expected_head):
        return ([], LEDGER_TAMPERED,
                ['no ledger at %r, but a head anchor says one was written (%s). A deleted ledger is '
                 'not a ledger nobody keeps' % (ledger_path, head_problem or 'head %s'
                                                % (head or {}).get('head_event_id') or expected_head)])
    if not ledger_path or not os.path.exists(ledger_path):
        return ([], LEDGER_ABSENT,
                ['no ledger at %r. Nothing is recording what happened to identities that moved, '
                 'so an orphaned approval is indistinguishable from a new finding.' % ledger_path])
    events, notes, unparseable = [], [], False
    try:
        raw = io.open(ledger_path, encoding='utf-8').read()
    except (IOError, OSError) as exc:
        return ([], LEDGER_LINE_UNPARSEABLE, ['cannot read %r: %s' % (ledger_path, exc)])
    for number, line in enumerate(raw.splitlines(), start=1):
        if not line.strip():
            continue
        try:
            item = json.loads(line)
        except ValueError as exc:
            unparseable = True
            notes.append('line %d is not JSON (%s). It is NOT skipped: a ledger that answers from '
                         'the lines it could read is a ledger that answers confidently from a '
                         'subset of itself.' % (number, exc))
            continue
        if not isinstance(item, dict):
            unparseable = True
            notes.append('line %d is valid JSON but not an event object' % number)
            continue
        events.append(item)
    if unparseable:
        return (events, LEDGER_LINE_UNPARSEABLE, notes)
    if head_problem:
        return (events, LEDGER_LINE_UNPARSEABLE, [head_problem])
    if not events:
        if (head and head['event_count'] > 0) or expected_head:
            return ([], LEDGER_TAMPERED,
                    ['the ledger holds no events, but its head anchor records %s. The ledger was '
                     'emptied after it was written'
                     % ('%d event(s) ending at %s' % (head['event_count'], head['head_event_id'])
                        if head else 'head %s' % expected_head)])
        return ([], LEDGER_EMPTY,
                ['the ledger exists and holds no events. Somebody is keeping one and no identity '
                 'has moved yet -- which is a different statement from LEDGER_ABSENT.'])

    # CHAIN VERIFICATION. This is what makes append-only a control.
    prev = ''
    for index, item in enumerate(events):
        recorded_prev = str(item.get('prev_event_id') or '')
        if recorded_prev != prev:
            notes.append('event %d links to prev_event_id %r but the preceding event is %r. A '
                         'line has been removed, inserted or reordered.'
                         % (index + 1, recorded_prev or None, prev or None))
            return (events, LEDGER_TAMPERED, notes)
        expected = _event_id(item, prev)
        if str(item.get('event_id') or '') != expected:
            notes.append('event %d has event_id %r but its content hashes to %r. The line has '
                         'been edited after it was written.'
                         % (index + 1, item.get('event_id'), expected))
            return (events, LEDGER_TAMPERED, notes)
        prev = expected
    # THE CHAIN PROVES EVERYTHING BUT ITS END. The head anchor proves the end.
    if head is None:
        notes.append('the chain re-derives, but the head anchor %s is ABSENT, so a truncated tail '
                     'cannot be excluded. A ledger that cannot rule out losing its newest events '
                     'is not intact' % head_path(ledger_path))
        return (events, LEDGER_TAMPERED, notes)
    if head['event_count'] != len(events) or head['head_event_id'] != prev:
        notes.append('the head anchor records %d event(s) ending at %s; the ledger holds %d ending '
                     'at %s. The tail was truncated or rewritten after it was written'
                     % (head['event_count'], head['head_event_id'], len(events), prev))
        return (events, LEDGER_TAMPERED, notes)
    if expected_head and expected_head != prev:
        notes.append('the external head anchor is %s and the ledger ends at %s. The ledger and its '
                     'local head were rewritten together; only the anchor recorded elsewhere saw it'
                     % (expected_head, prev))
        return (events, LEDGER_TAMPERED, notes)
    notes.append('%d event(s), chain intact from the first to the last, ending at the recorded head'
                 % len(events))
    return (events, LEDGER_INTACT, notes)


def _successor_map(events):
    """identity -> [identities it became]. A SPLIT contributes several; a MERGE contributes one
    FOR EACH of its sources, which is why resolving any member of a merge finds the survivor."""
    out = {}
    for item in events:
        for ident in _as_list(item.get('from_identities')):
            out.setdefault(ident, [])
            for target in _as_list(item.get('to_identities')):
                if target not in out[ident]:
                    out[ident].append(target)
    return out


def _predecessor_map(events):
    out = {}
    for item in events:
        for target in _as_list(item.get('to_identities')):
            out.setdefault(target, [])
            for ident in _as_list(item.get('from_identities')):
                if ident not in out[target]:
                    out[target].append(ident)
    return out


def _event_for(events, source, target):
    for item in events:
        if source in _as_list(item.get('from_identities')) \
                and target in _as_list(item.get('to_identities')):
            return item
    return None


def known_identities(events):
    out = set()
    for item in events:
        out.update(_as_list(item.get('from_identities')))
        out.update(_as_list(item.get('to_identities')))
    return out


def resolve(events, identity):
    """-> {state, current, chain, hops, candidates, why}.

    `state` is one of the five LINEAGE_* outcomes and is the ONLY thing a caller should branch
    on. `current` is populated for TERMINAL and RESOLVED and is None for the other three -- a
    resolver that returned the input identity on failure would make "not known", "split" and
    "cycle" all read as "this identity is current", which is the collapse rule 4 forbids.
    """
    identity = str(identity or '').strip()
    if not identity:
        return {'state': LINEAGE_UNKNOWN, 'current': None, 'chain': [], 'hops': 0,
                'candidates': [], 'why': 'no identity was supplied'}
    if identity not in known_identities(events):
        return {'state': LINEAGE_UNKNOWN, 'current': None, 'chain': [identity], 'hops': 0,
                'candidates': [],
                'why': 'this ledger has never heard of %s. That is NOT the same answer as "it '
                       'has no successor": one says the finding is new to the estate, the other '
                       'says it is the live form of something with a history.' % identity}

    successors = _successor_map(events)
    chain = [identity]
    visited = set(chain)
    hops = 0
    cursor = identity
    while True:
        nxt = successors.get(cursor) or []
        if not nxt:
            state = LINEAGE_TERMINAL if hops == 0 else LINEAGE_RESOLVED
            return {'state': state, 'current': cursor, 'chain': chain, 'hops': hops,
                    'candidates': [],
                    'why': ('%s is in the ledger and has no successor, so it is current'
                            % cursor) if hops == 0 else
                           ('followed %d hop(s) to %s' % (hops, cursor))}
        if len(nxt) > 1:
            # A SPLIT. Refuse, and say what it split into. Choosing would hand this finding's
            # approval to one of several conditions and silently drop the others.
            return {'state': LINEAGE_SPLIT_UNRESOLVED, 'current': None, 'chain': chain,
                    'hops': hops, 'candidates': list(nxt),
                    'why': '%s was SPLIT into %d identities (%s). There is no single successor, '
                           'and picking one would transfer an approval to a condition nobody '
                           'approved while losing the others entirely. A merge resolves; a split '
                           'does not, and that asymmetry is the point.'
                           % (cursor, len(nxt), ', '.join(nxt))}
        step = nxt[0]
        if step in visited:
            # Termination is guaranteed by this set, not by a hop budget: it cannot grow past the
            # number of identities the ledger mentions. A budget would also report a long honest
            # chain as a cycle, which is a different fault with a different fix.
            return {'state': LINEAGE_CYCLE_REFUSED, 'current': None, 'chain': chain + [step],
                    'hops': hops, 'candidates': [],
                    'why': 'following %s returns to %s, which is already in this chain (%s). A '
                           'lineage cycle is a mistake somebody recorded; a resolver that looped '
                           'on it would turn a data error into a hung job, and one that returned '
                           'the last identity it saw would report a guess as a resolution.'
                           % (cursor, step, ' -> '.join(chain + [step]))}
        chain.append(step)
        visited.add(step)
        cursor = step
        hops += 1


def ancestors(events, identity):
    """-> (ordered list of ancestors nearest-first, cycle_detail or '').

    Breadth-first over predecessors, so a MERGE target reaches all of its sources. Refuses a
    cycle the same way `resolve` does: the question "where did this come from" has no answer in a
    ledger that says it came from itself.
    """
    identity = str(identity or '').strip()
    preds = _predecessor_map(events)
    order, seen, frontier = [], set([identity]), [identity]
    while frontier:
        nxt = []
        for node in frontier:
            for parent in preds.get(node) or []:
                if parent == identity:
                    return (order, 'ancestry of %s reaches %s itself' % (identity, identity))
                if parent in seen:
                    continue
                seen.add(parent)
                order.append(parent)
                nxt.append(parent)
        frontier = nxt
    return (order, '')


def describe(events, identity):
    """-> {merged_from, split_into, superseded, supersedes}. The four relationships kept APART.

    A consumer that only has a successor map cannot tell a merge target from a split source, and
    the two mean opposite things about whether this identity's history is one thread or several.
    """
    identity = str(identity or '').strip()
    out = {'merged_from': [], 'split_into': [], 'superseded': [], 'supersedes': []}
    for item in events:
        relation = str(item.get('relation') or '')
        src = _as_list(item.get('from_identities'))
        dst = _as_list(item.get('to_identities'))
        if relation == MERGED_INTO and identity in dst:
            out['merged_from'] = [s for s in src]
        if relation == SPLIT_INTO and identity in src:
            out['split_into'] = [d for d in dst]
        if relation == SUPERSEDES and identity in dst:
            out['superseded'] = [s for s in src]
        if relation == SUPERSEDES and identity in src:
            out['supersedes'] = [d for d in dst]
    return out


RESOLVABLE = (LEDGER_INTACT, LEDGER_EMPTY)


def disposition_for(events, dispositions, identity, integrity=None):
    """Which approved exception applies to this identity, and HOW it got here.

    -> {basis, disposition, identity_keyed, through, lineage_state, requires_reaffirmation, why}

    `basis` is DISPOSITION_KEYED_DIRECTLY, DISPOSITION_CARRIED_BY_LINEAGE or
    DISPOSITION_NOT_FOUND. The disposition itself is returned UNMODIFIED -- this reads the
    register, it does not write to it, and it never re-keys an approval onto a new identity. AN
    INFERENCE NEVER OVERWRITES AN OBSERVATION: the approver approved the key they approved, and
    `through` plus `requires_reaffirmation` is what lets a human agree with the carry rather than
    inherit it silently.

    `integrity` is the state the events were loaded under. When it is given and is not
    LEDGER_INTACT or LEDGER_EMPTY, NO CARRY is made (L51): a carry is a human decision extended by
    the ledger's links, and links from a ledger nobody can verify extend nothing. A disposition
    keyed DIRECTLY on the identity does not depend on the ledger and still applies.
    """
    identity = str(identity or '').strip()
    dispositions = dispositions or {}
    state = resolve(events, identity)['state']
    if identity in dispositions:
        return {'basis': DISPOSITION_KEYED_DIRECTLY, 'disposition': dispositions[identity],
                'identity_keyed': identity, 'through': [], 'lineage_state': state,
                'requires_reaffirmation': False,
                'why': 'approved against this identity directly'}
    if integrity is not None and integrity not in RESOLVABLE:
        return {'basis': DISPOSITION_NOT_FOUND, 'disposition': None, 'identity_keyed': None,
                'through': [], 'lineage_state': None, 'requires_reaffirmation': False,
                'why': 'the lineage ledger is %s, so no carry can be established from it. A link '
                       'read from a record nobody can verify extends no approval' % integrity}

    chain, cycle = ancestors(events, identity)
    if cycle:
        return {'basis': DISPOSITION_NOT_FOUND, 'disposition': None, 'identity_keyed': None,
                'through': [], 'lineage_state': LINEAGE_CYCLE_REFUSED,
                'requires_reaffirmation': False,
                'why': 'the ancestry of this identity contains a cycle (%s), so no carry can be '
                       'established from it. REFUSED rather than returning the nearest ancestor '
                       'found before the loop, which would be a guess.' % cycle}

    for ancestor in chain:
        if ancestor in dispositions:
            hops = []
            cursor = ancestor
            # Walk FORWARD from the approved ancestor so the reported path is the direction the
            # identity actually moved, and each hop carries the cause and the asserter that moved
            # it. A path without causes is a claim that the carry is legitimate with nothing
            # supporting it.
            guard = set([cursor])
            forward = _successor_map(events)
            while cursor != identity:
                nxt = (forward.get(cursor) or [None])[0]
                if nxt is None or nxt in guard:
                    break
                event = _event_for(events, cursor, nxt) or {}
                hops.append({
                    'from': cursor, 'to': nxt,
                    'relation': event.get('relation'),
                    'cause': event.get('cause'),
                    'cause_detail': event.get('cause_detail'),
                    'asserted_by': event.get('asserted_by') or {'actor_class': ATTRIBUTION_ABSENT},
                    'observed_at': event.get('observed_at'),
                    'event_id': event.get('event_id'),
                })
                guard.add(nxt)
                cursor = nxt
            return {'basis': DISPOSITION_CARRIED_BY_LINEAGE,
                    'disposition': dispositions[ancestor], 'identity_keyed': ancestor,
                    'through': hops, 'lineage_state': state,
                    # The flag is the whole point of distinguishing the two bases. A carried
                    # approval is a human decision extended by machine assertions, and the
                    # consumer gets to decide whether it accepts that extension.
                    'requires_reaffirmation': True,
                    'why': 'approved against %s, which this identity descends from through %d '
                           'recorded hop(s). Reported as CARRIED rather than direct: the approver '
                           'approved that key, not this one.' % (ancestor, len(hops))}

    return {'basis': DISPOSITION_NOT_FOUND, 'disposition': None, 'identity_keyed': None,
            'through': [], 'lineage_state': state, 'requires_reaffirmation': False,
            'why': 'no disposition is keyed on this identity or on any identity it descends '
                   'from. lineage_state is %s, which says whether the ledger knows this identity '
                   'at all -- "untriaged and new" and "untriaged with a history" are different '
                   'answers.' % state}


# ─────────────────────────────────────────────────────────────────────────────
def _mkevent(src, dst, relation=SUPERSEDES, cause=EXTRACTION_CORRECTED, detail='test event',
             actor='tests/prove_lineage_durability.py', actor_class=TOOL, when='2026-10-08T00:00:00Z'):
    """A complete, valid event. Used by the self-test and by the proof beside it, so a change to
    the required shape fails in one place rather than in two copies that drift."""
    return {
        'relation': relation,
        'from_identities': src if isinstance(src, (list, tuple)) else [src],
        'to_identities': dst if isinstance(dst, (list, tuple)) else [dst],
        'cause': cause,
        'cause_detail': detail,
        'observed_at': when,
        'observed_at_source': 'DECLARED_IN_CONTENT',
        'finding_subject': 'SOURCE',
        'asserted_by': {'actor': actor, 'actor_class': actor_class,
                        'method': 'constructed by the self-test'},
        'provenance': {'repository': 'secure-cicd-kit', 'commit_sha': '0' * 40,
                       'ref': 'refs/heads/test', 'run_id': 'self-test'},
    }


def _selftest():
    """Exercises the SUCCESS path, every refusal, and the vacuous pass.

    THE VACUOUS PASS THIS REFUSES: every assertion in a lineage test can be satisfied by a ledger
    that resolves nothing, because "no disposition applies" and "the chain was followed and found
    none" produce the same answer to a sloppy question. So the first thing asserted is that the
    resolver DISTINGUISHES an unknown identity from a terminal one -- if those two collapse,
    nothing else here means anything.
    """
    import shutil
    import tempfile

    fails = []

    def check(condition, message):
        if not condition:
            fails.append(message)

    work = tempfile.mkdtemp(prefix='lineage-st-')
    try:
        path = os.path.join(work, 'lineage.jsonl')

        # ── 1. ABSENT is not EMPTY is not INTACT ─────────────────────────────
        _events, state, _notes = load(path)
        check(state == LEDGER_ABSENT, 'a missing ledger reported %r, not LEDGER_ABSENT' % state)
        with io.open(path, 'w', encoding='utf-8') as fh:
            fh.write('')
        _events, state, _notes = load(path)
        check(state == LEDGER_EMPTY,
              'an existing but empty ledger reported %r. LEDGER_ABSENT says nobody is keeping a '
              'lineage record; LEDGER_EMPTY says somebody is and nothing has moved. They answer '
              'every question identically and mean opposite things.' % state)

        # ── 2. THE DISCRIMINATOR, ASSERTED FIRST. See the docstring ──────────
        eid, bad = append_event(path, _mkevent('a' * 64, 'b' * 64, cause=RULE_RENAMED,
                                               detail='semgrep renamed sqli.sql-injection'))
        check(bool(eid) and not bad, 'a complete valid event was refused: %r' % bad)
        events, state, notes = load(path)
        check(state == LEDGER_INTACT, 'a freshly written ledger is %r: %s' % (state, notes))
        unknown = resolve(events, 'z' * 64)
        terminal = resolve(events, 'b' * 64)
        check(unknown['state'] == LINEAGE_UNKNOWN,
              'an identity absent from the ledger resolved as %r' % unknown['state'])
        check(terminal['state'] == LINEAGE_TERMINAL,
              'an identity present with no successor resolved as %r' % terminal['state'])
        check(unknown['state'] != terminal['state'],
              'LINEAGE_UNKNOWN and LINEAGE_TERMINAL collapsed into one answer, so "new to the '
              'estate" and "current form of something with a history" are indistinguishable and '
              'every other assertion in this file is vacuous')
        check(unknown['current'] is None,
              'an unknown identity was resolved to %r instead of None. Returning the input makes '
              'a failure read as a successful resolution.' % unknown['current'])

        # ── 3. A ONE-HOP AND A TWO-HOP CHAIN BOTH RESOLVE ────────────────────
        one = resolve(events, 'a' * 64)
        check(one['state'] == LINEAGE_RESOLVED and one['current'] == 'b' * 64 and one['hops'] == 1,
              'a one-hop chain resolved as %r' % one)
        append_event(path, _mkevent('b' * 64, 'c' * 64, cause=PATH_MOVED,
                                    detail='queries.py moved under db/'))
        events, _state, _notes = load(path)
        two = resolve(events, 'a' * 64)
        check(two['state'] == LINEAGE_RESOLVED and two['current'] == 'c' * 64 and two['hops'] == 2,
              'a TWO-hop chain did not resolve to the far end: %r. A resolver that stops at the '
              'first hop loses every identity that moved twice, which is the normal case after a '
              'scanner upgrade followed by a refactor.' % two)
        check(two['chain'] == ['a' * 64, 'b' * 64, 'c' * 64],
              'the reported chain is %r, so an operator cannot see the route taken' % two['chain'])

        # ── 4. A CYCLE IS REFUSED, NOT FOLLOWED ──────────────────────────────
        append_event(path, _mkevent('c' * 64, 'a' * 64, cause=SUBJECT_SPEC_CHANGED,
                                    detail='a mistake, deliberately: this closes the loop'))
        events, _state, _notes = load(path)
        cyc = resolve(events, 'a' * 64)
        check(cyc['state'] == LINEAGE_CYCLE_REFUSED,
              'a cyclic chain resolved as %r instead of being refused' % cyc['state'])
        check(cyc['current'] is None,
              'a cycle was refused and still produced a current identity %r, which is the '
              'resolver reporting a guess as an answer' % cyc['current'])
        check('a' * 64 in (cyc['why'] or ''), 'the cycle refusal does not name the cycle')

        # ── 5. MERGE AND SPLIT DO NOT COLLAPSE ───────────────────────────────
        merge_path = os.path.join(work, 'merge.jsonl')
        split_path = os.path.join(work, 'split.jsonl')
        append_event(merge_path, _mkevent(['1' * 64, '2' * 64], '3' * 64, relation=MERGED_INTO,
                                          cause=CORRELATION_ESTABLISHED,
                                          detail='trivy and checkov were reporting one condition'))
        append_event(split_path, _mkevent('3' * 64, ['1' * 64, '2' * 64], relation=SPLIT_INTO,
                                          cause=SUBJECT_SPEC_CHANGED,
                                          detail='one entry was two conditions'))
        merged, _s, _n = load(merge_path)
        splitd, _s2, _n2 = load(split_path)
        for member in ('1' * 64, '2' * 64):
            got = resolve(merged, member)
            check(got['state'] == LINEAGE_RESOLVED and got['current'] == '3' * 64,
                  'merge: resolving member %s gave %r. Every source of a merge must reach the '
                  'survivor -- each was an approval of the same condition.' % (member[:4], got))
        check(resolve(merged, '3' * 64)['state'] == LINEAGE_TERMINAL,
              'merge: the survivor is not terminal')
        got = resolve(splitd, '3' * 64)
        check(got['state'] == LINEAGE_SPLIT_UNRESOLVED,
              'split: the source resolved as %r. A split MUST refuse: picking one successor hands '
              'this finding\'s approval to a condition nobody approved and drops the rest.'
              % got['state'])
        check(sorted(got['candidates']) == sorted(['1' * 64, '2' * 64]),
              'split: the refusal did not name the candidates (%r)' % got['candidates'])
        check(got['current'] is None, 'split: a refusal still produced a current identity')
        check(describe(merged, '3' * 64)['merged_from'] and not describe(merged, '3' * 64)['split_into'],
              'the merge survivor does not describe itself as merged')
        check(describe(splitd, '3' * 64)['split_into'] and not describe(splitd, '3' * 64)['merged_from'],
              'the split source does not describe itself as split')
        check(describe(merged, '3' * 64)['merged_from'] != describe(splitd, '3' * 64)['split_into']
              or resolve(merged, '1' * 64)['state'] != resolve(splitd, '1' * 64)['state'],
              'a merge of {1,2}->3 and a split of 3->{1,2} are indistinguishable, so "two '
              'findings turned out to be one" reads the same as "one finding became two"')

        # A SPLIT RECORDED AS TWO SUPERSESSIONS IS REFUSED AT WRITE TIME.
        two_path = os.path.join(work, 'two-supersede.jsonl')
        append_event(two_path, _mkevent('9' * 64, '8' * 64))
        _eid, bad = append_event(two_path, _mkevent('9' * 64, '7' * 64))
        check(bool(bad), 'a second SUPERSEDES for one identity was accepted, which records a '
                         'SPLIT as two supersessions and collapses the two relations')
        check(any('SPLIT' in b for b in bad),
              'the refusal does not explain that a split is the relation being asked for: %r'
              % bad)

        # ── 6. A DISPOSITION SURVIVES THE CHAIN, AND SAYS IT WAS CARRIED ─────
        disp_path = os.path.join(work, 'disp.jsonl')
        append_event(disp_path, _mkevent('a' * 64, 'b' * 64, cause=EXTRACTION_CORRECTED,
                                         detail='D-2: scan_report now populates CONTENT'))
        append_event(disp_path, _mkevent('b' * 64, 'c' * 64, cause=ADVISORY_ALIAS_ADDED,
                                         detail='GHSA alias added to CVE-2018-18074',
                                         actor='osv.dev', actor_class=ADVISORY_FEED))
        dev, _s3, _n3 = load(disp_path)
        register = {'a' * 64: {'state': 'ACCEPTED_RISK', 'expires': '2026-12-31',
                               'approver_role': 'security-lead'}}
        carried = disposition_for(dev, register, 'c' * 64)
        check(carried['basis'] == DISPOSITION_CARRIED_BY_LINEAGE,
              'a disposition two hops back was reported as %r, so the approval is orphaned'
              % carried['basis'])
        check(carried['disposition'] is register['a' * 64],
              'the carried disposition was copied or rewritten rather than returned as approved')
        check(carried['identity_keyed'] == 'a' * 64,
              'the carry does not say WHICH identity was actually approved')
        check(carried['requires_reaffirmation'] is True,
              'a carried disposition was not flagged for reaffirmation. A human approved one key; '
              'machine assertions extended it to another, and the consumer must get to see that.')
        check(len(carried['through']) == 2,
              'the carry reports %d hop(s), not the 2 it travelled' % len(carried['through']))
        check(all(h.get('cause') for h in carried['through']),
              'a hop in the carry chain has no cause, so nothing supports the claim that the '
              'carry is legitimate')
        check(all((h.get('asserted_by') or {}).get('actor') for h in carried['through']),
              'a hop in the carry chain has no asserter. An unattributed alias is not evidence.')
        direct = disposition_for(dev, {'c' * 64: register['a' * 64]}, 'c' * 64)
        check(direct['basis'] == DISPOSITION_KEYED_DIRECTLY,
              'an approval keyed on the identity itself was reported as %r' % direct['basis'])
        check(direct['requires_reaffirmation'] is False,
              'a direct approval was flagged as needing reaffirmation')
        none_found = disposition_for(dev, {}, 'c' * 64)
        check(none_found['basis'] == DISPOSITION_NOT_FOUND,
              'an empty register produced %r' % none_found['basis'])
        # 'c' is the live end of a->b->c, so its own lineage state is TERMINAL. The point is that
        # DISPOSITION_NOT_FOUND still CARRIES a lineage state, so "untriaged and new to the
        # estate" and "untriaged but the live form of something with a history" stay apart.
        check(none_found['lineage_state'] == LINEAGE_TERMINAL,
              'a finding with no approval reported lineage_state %r instead of LINEAGE_TERMINAL, '
              'so "untriaged and new" and "untriaged with a history" collapse'
              % none_found['lineage_state'])
        unheard = disposition_for(dev, {}, 'q' * 64)
        check(unheard['lineage_state'] == LINEAGE_UNKNOWN,
              'an identity the ledger has never seen reported lineage_state %r'
              % unheard['lineage_state'])

        # ── 7. VALIDATION REFUSES EVERY INCOMPLETE EVENT ─────────────────────
        refusals = [
            (dict(_mkevent('a' * 64, 'b' * 64), asserted_by=None), 'asserted_by',
             'an unattributed alias'),
            (dict(_mkevent('a' * 64, 'b' * 64), asserted_by={'actor': 'x'}), 'actor_class',
             'an asserter with no class'),
            # Deliberately lower-case. A rejected fixture value written in upper-case snake case
            # reads as this kit's own vocabulary to every reader and to the taxonomy gate, and
            # registering it would assert that "something changed" is an acceptable cause --
            # the opposite of what this assertion exists to establish.
            (dict(_mkevent('a' * 64, 'b' * 64), cause='something-changed'), 'cause',
             'an unregistered cause'),
            (dict(_mkevent('a' * 64, 'b' * 64), cause_detail=''), 'cause_detail',
             'a cause with no detail'),
            (dict(_mkevent('a' * 64, 'b' * 64), observed_at=''), 'observed_at',
             'an event with no time'),
            (dict(_mkevent('a' * 64, 'b' * 64), provenance=None), 'provenance',
             'an event with no provenance'),
            (dict(_mkevent('a' * 64, 'b' * 64), relation='CHANGED'), 'relation',
             'a generic "changed" relation'),
            (_mkevent(['a' * 64, 'b' * 64], 'c' * 64, relation=SUPERSEDES), 'Cardinality',
             'a SUPERSEDES with two sources, which is a merge wearing the wrong word'),
            (_mkevent('a' * 64, ['b' * 64, 'c' * 64], relation=SUPERSEDES), 'requires',
             'a SUPERSEDES with two targets, which is a split wearing the wrong word'),
            (_mkevent('a' * 64, 'b' * 64, relation=MERGED_INTO), 'or more',
             'a MERGED_INTO with one source, which has nothing to merge'),
            (_mkevent('a' * 64, 'b' * 64, relation=SPLIT_INTO), 'or more',
             'a SPLIT_INTO with one target, which has nothing to split into'),
            (_mkevent('a' * 64, 'a' * 64), 'BOTH sides', 'an identity that became itself'),
        ]
        for event, needle, label in refusals:
            reasons = validate_event(event)
            check(bool(reasons), '%s was accepted' % label)
            check(any(needle in r for r in reasons),
                  '%s was refused without naming %r: %r' % (label, needle, reasons))

        # ── 8. TAMPERING IS DETECTED. This is what makes append-only a control ──
        tamper = os.path.join(work, 'tamper.jsonl')
        append_event(tamper, _mkevent('a' * 64, 'b' * 64))
        append_event(tamper, _mkevent('b' * 64, 'c' * 64))
        append_event(tamper, _mkevent('c' * 64, 'd' * 64))
        lines = io.open(tamper, encoding='utf-8').read().splitlines()
        check(len(lines) == 3, 'the tamper fixture is not three lines')

        edited = os.path.join(work, 'edited.jsonl')
        body = json.loads(lines[1])
        body['cause_detail'] = 'rewritten after the fact'
        with io.open(edited, 'w', encoding='utf-8') as fh:
            fh.write(lines[0] + '\n' + json.dumps(body, sort_keys=True) + '\n' + lines[2] + '\n')
        # Each tampered copy carries the ORIGINAL head anchor, so it is refused by the CHAIN and
        # not merely for lacking a head -- a refusal for the wrong reason is a coincidence, and
        # the reason is asserted (docs/PROOF_RULE.md).
        shutil.copyfile(head_path(tamper), head_path(edited))
        _e, state, notes = load(edited)
        check(state == LEDGER_TAMPERED,
              'an EDITED event was reported as %r. A ledger whose contents can be changed '
              'without detection is not evidence.' % state)
        check(any('edited after' in n for n in notes),
              'the EDITED event was refused for another reason: %r' % notes)

        removed = os.path.join(work, 'removed.jsonl')
        with io.open(removed, 'w', encoding='utf-8') as fh:
            fh.write(lines[0] + '\n' + lines[2] + '\n')
        shutil.copyfile(head_path(tamper), head_path(removed))
        _e, state, notes = load(removed)
        check(state == LEDGER_TAMPERED,
              'a REMOVED event was reported as %r. Hashing each line independently detects '
              'edits and not deletions, which is the half an append-only claim actually needs.'
              % state)
        check(any('removed, inserted or reordered' in n for n in notes),
              'the REMOVED event was refused for another reason: %r' % notes)

        reordered = os.path.join(work, 'reordered.jsonl')
        with io.open(reordered, 'w', encoding='utf-8') as fh:
            fh.write(lines[1] + '\n' + lines[0] + '\n' + lines[2] + '\n')
        shutil.copyfile(head_path(tamper), head_path(reordered))
        _e, state, notes = load(reordered)
        check(state == LEDGER_TAMPERED, 'a REORDERED ledger was reported as %r' % state)
        check(any('removed, inserted or reordered' in n for n in notes),
              'the REORDERED ledger was refused for another reason: %r' % notes)

        # THE LAST LINE, which the chain alone cannot see (L51). Head anchor kept.
        truncated = os.path.join(work, 'truncated.jsonl')
        with io.open(truncated, 'w', encoding='utf-8') as fh:
            fh.write(lines[0] + '\n' + lines[1] + '\n')
        shutil.copyfile(head_path(tamper), head_path(truncated))
        _e, state, notes = load(truncated)
        check(state == LEDGER_TAMPERED and any('truncated' in n for n in notes),
              'a TRUNCATED tail was reported as %r (%r). The chain is anchored at its first '
              'event; only the head anchor sees the last one go.' % (state, notes))

        garbage = os.path.join(work, 'garbage.jsonl')
        with io.open(garbage, 'w', encoding='utf-8') as fh:
            fh.write(lines[0] + '\nnot json at all\n')
        _e, state, notes = load(garbage)
        check(state == LEDGER_LINE_UNPARSEABLE,
              'an unparseable line was reported as %r rather than named. Skipping it is how a '
              'store comes to answer confidently from a subset of itself.' % state)
        check(any('line 2' in n for n in notes),
              'the unparseable line was not identified by number: %r' % notes)
        _eid, bad = append_event(garbage, _mkevent('x' * 64, 'y' * 64))
        check(bool(bad),
              'an append to a ledger with an unreadable line was accepted, so the new event '
              'would sit on a chain nobody can verify')

        # ── 9. A SUPERSEDED IDENTITY IS NEVER REMOVED ────────────────────────
        events, _s4, _n4 = load(tamper)
        for ident in ('a' * 64, 'b' * 64, 'c' * 64):
            check(ident in known_identities(events),
                  'superseded identity %s is no longer in the ledger, so "what happened to the '
                  'finding I accepted in March" has no answer' % ident[:4])
    finally:
        # ONLY the exact path mkdtemp returned. Never a path derived from anything else.
        shutil.rmtree(work, ignore_errors=True)

    if fails:
        sys.stderr.write('finding_lineage selftest FAILED (%d):\n' % len(fails))
        for f in fails:
            sys.stderr.write('  - %s\n' % f)
        return 2
    print('finding_lineage selftest ok: LEDGER_ABSENT, LEDGER_EMPTY and LEDGER_INTACT stay '
          'distinct; LINEAGE_UNKNOWN is distinguishable from LINEAGE_TERMINAL (asserted first, '
          'because every other claim here is vacuous if it is not); one-hop and TWO-hop chains '
          'resolve to the far end and report the route; a cycle is REFUSED by name and yields no '
          'current identity; a merge resolves from every source to the survivor while a split '
          'REFUSES and names its candidates, and recording a split as two supersessions is '
          'refused at write time; a disposition two hops back is carried, flagged for '
          'reaffirmation, attributed at every hop and returned unmodified; %d incomplete events '
          'are each refused with the missing field named; and an edited, removed, reordered or '
          'unparseable line is detected rather than absorbed.' % len(refusals))
    return 0


def _explain():
    print('finding lineage -- what happens to everything keyed on an identity when the identity '
          'changes')
    print('')
    print('RELATIONS (cardinality is part of the definition and is enforced)')
    for relation in (SUPERSEDES, MERGED_INTO, SPLIT_INTO):
        fmin, fmax, tmin, tmax = _cardinality[relation]
        print('  %-12s %s -> %s' % (relation,
                                    '%d' % fmin if fmax == fmin else '%d+' % fmin,
                                    '%d' % tmin if tmax == tmin else '%d+' % tmin))
    print('')
    print('RESOLUTION OUTCOMES (branch on these and nothing else)')
    print('  %-26s the ledger has never heard of this identity' % LINEAGE_UNKNOWN)
    print('  %-26s known, and has no successor: it is current' % LINEAGE_TERMINAL)
    print('  %-26s followed one or more hops to a current identity' % LINEAGE_RESOLVED)
    print('  %-26s the chain returns on itself. Refused, never followed' % LINEAGE_CYCLE_REFUSED)
    print('  %-26s split into several; no single successor exists' % LINEAGE_SPLIT_UNRESOLVED)
    print('')
    print('CAUSES')
    for cause in CAUSES:
        print('  ' + cause)
    print('')
    print('ATTRIBUTION CLASSES  ' + ', '.join(ATTRIBUTION_CLASSES))
    print('  %s is read, never written: an event with no asserter is refused.'
          % ATTRIBUTION_ABSENT)
    print('')
    print('LEDGER INTEGRITY     ' + ', '.join((LEDGER_ABSENT, LEDGER_EMPTY, LEDGER_INTACT,
                                               LEDGER_TAMPERED, LEDGER_LINE_UNPARSEABLE)))
    print('')
    print('PROVENANCE FIELDS    ' + ', '.join(provenance_fields))
    return 0


def main(argv=None):
    ap = argparse.ArgumentParser(
        description='Append-only lineage for finding identities: old identity -> new identity, '
                    'when, what caused it, and what asserted it.')
    ap.add_argument('--self-test', action='store_true')
    ap.add_argument('--selftest', action='store_true', help=argparse.SUPPRESS)
    ap.add_argument('--explain', action='store_true')
    ap.add_argument('--ledger', default=default_ledger)
    ap.add_argument('--verify', action='store_true',
                    help='report the ledger integrity state and the absent provenance fields')
    ap.add_argument('--resolve', default='', metavar='IDENTITY')
    ap.add_argument('--expect-head', default='', metavar='event-id',
                    help='the head event id as recorded outside the ledger (protected branch or '
                         'run record); the chain must end there')
    ap.add_argument('--append', default='', metavar='event.json')
    a = ap.parse_args(argv)

    if a.self_test or a.selftest:
        return _selftest()
    if a.explain:
        return _explain()

    if a.append:
        try:
            event = json.load(io.open(a.append, encoding='utf-8'))
        except (IOError, ValueError) as exc:
            sys.stderr.write('cannot read %s as an event: %s\n' % (a.append, exc))
            return 2
        eid, bad = append_event(a.ledger, event)
        if bad:
            sys.stderr.write('REFUSED -- nothing was written:\n')
            for b in bad:
                sys.stderr.write('  - %s\n' % b)
            return 1
        print('appended %s' % eid)
        return 0

    events, state, notes = load(a.ledger, expected_head=a.expect_head)
    if a.resolve and state not in RESOLVABLE:
        # A RESOLUTION FROM A LEDGER NOBODY CAN VERIFY IS AN ANSWER MANUFACTURED FROM A BROKEN
        # RECORD (L51, G1-7 defect 2). `--resolve` used to skip this check and exit 0. LEDGER_EMPTY
        # is resolvable -- it is a verified ledger in which nothing has moved, and every identity is
        # truthfully LINEAGE_UNKNOWN there. LEDGER_ABSENT is not: "nobody keeps a lineage record"
        # answered as "never heard of it" would read as new-to-the-estate.
        print('REFUSED: %s is %s -- no resolution is given from it' % (a.ledger, state))
        for n in notes:
            print('  ' + n)
        return 1
    if a.verify or not a.resolve:
        print('%s: %s' % (a.ledger, state))
        for n in notes:
            print('  ' + n)
        thin = []
        for index, item in enumerate(events):
            absent = [f for f in provenance_fields
                      if not str((item.get('provenance') or {}).get(f) or '').strip()]
            if absent:
                thin.append('  event %d does not state %s -- recorded as absent, never defaulted'
                            % (index + 1, ', '.join(absent)))
        if thin:
            print('provenance fields not stated (a weaker record, not an invalid one):')
            for t in thin:
                print(t)
        # THE EXIT CODE IS THE ONLY THING A SCHEDULER READS (L51, G1-7 defect 3). Only TAMPERED
        # used to exit 1, so an unparseable ledger and a missing one "verified" with exit 0.
        if state in (LEDGER_TAMPERED, LEDGER_LINE_UNPARSEABLE):
            return 1
        if state == LEDGER_ABSENT and a.verify:
            # Nothing to verify is not a verified ledger. 2: the request could not be carried out.
            return 2
        if not a.resolve:
            return 0

    if a.resolve:
        got = resolve(events, a.resolve)
        print('%s' % got['state'])
        print('  current   : %s' % (got['current'] or '(none -- see why)'))
        print('  hops      : %d' % got['hops'])
        if got['chain']:
            print('  chain     : ' + ' -> '.join(c[:16] for c in got['chain']))
        if got['candidates']:
            print('  candidates: ' + ', '.join(c[:16] for c in got['candidates']))
        print('  why       : %s' % got['why'])
        # A REFUSAL IS NOT A TOOL FAILURE. Exit 0 and let the caller branch on the state --
        # exiting non-zero would make a correctly-refused cycle indistinguishable from a broken
        # run, which is the conflation this whole kit exists to prevent.
        return 0
    return 0


if __name__ == '__main__':
    sys.exit(main())

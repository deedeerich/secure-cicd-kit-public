#!/usr/bin/env python3
"""Derive what a reversal may do to ONE object, from what live state said about it.

WHY THIS EXISTS (L98; docs/architecture/DEPLOYMENT_CONTRACT_RECONCILIATION.md section 8)

    A change manifest is a record of the past. A reversal acts on the present. Release R1 creates
    X; another onboarding process later modifies X or takes a dependency on it; R1's manifest
    still truthfully says "I created X", and that is no longer sufficient AUTHORITY to delete X.
    So every manifest entry is a PROPOSAL, and this script turns a proposal plus the live reads
    an adapter made into exactly one `reversal_disposition` (assurance-taxonomy.yaml).

THE RULE IT EXISTS TO HOLD
    THE UNKNOWN BRANCH AND THE DESTRUCTIVE BRANCH ARE NOT THE SAME BRANCH. Exactly one value
    removes anything -- REVERSAL_REMOVE -- and it is reachable only when every one of P1-P6 was
    POSITIVELY established. "No conflict was found" is also what a failed conflict query returns,
    so an input that is absent is unknown, never empty: every flag below defaults to unknown.

THE PRECONDITIONS (section 8.1), each read by the ADAPTER from live state and passed in here
    P1  ownership    the RELEASE_OWNERSHIP_STAMP on the live object (--stamp); other claims on it
    P2  version      the object's current version handle against the recorded post-state
    P3  later        releases that wrote this object since (the release graph)
    P4  external     P2 differs AND no release claims the difference -- derived, never observed,
                     and only once P3 itself succeeded
    P5  dependents   anything introduced later that depends on the object
    P6  ancestry     descendant releases still standing, whether or not they touched the object

    For ENTRY actions (a release-owned entry on a shared surface, section 8.1 "the unit of
    conflict is the mutation"), a moved parent version is a trigger to look closer, not a
    verdict: is OUR entry still byte-identical, does removing it alter anything another actor
    owns, can the surface address it independently.

WHAT IT CANNOT ESTABLISH
    Whether the adapter's reads were TRUE. It decides correctly from the facts it is given; a
    stamp an external actor forged, or a dependency read that missed an edge, is an adapter and
    acceptance-matrix question (section 8.6, 7.8). The stamp is evidence, not proof (section 8.3
    rule 4).

USAGE
    Single entry (key=value lines on stdout, for `>> "$GITHUB_OUTPUT"`):
      derive_reversal_disposition.py --release R --stamp S --current-version V
          [--action CREATED|MODIFIED|REDIRECTED|ENTRY] [--recorded-post-version P]
          [--stamp-unreadable] [--current-version-unreadable]
          [--later-releases none|unknown|a,b] [--descendants none|unknown|a,b]
          [--dependents none|unknown|a,b] [--other-claims none|unknown|a,b]
          [--classification EXCLUSIVE|OWNED_BINDING|SHARED_CONFIGURATION_ENTRY|PLATFORM_OWNED_SHARED]
          [--entry-unchanged yes|no|unknown] [--entry-side-effect-free yes|no|unknown]
          [--entry-independent yes|no|unknown]
    Batch (a JSON list of entries in, a JSON list of derivations out):
      derive_reversal_disposition.py --release R --entries entries.json
      Entry keys mirror the flags; null means unknown, [] means positively none.
    derive_reversal_disposition.py --self-test

EXIT  0 derived (whatever the disposition)   2 the input could not be read, or the self-test failed
"""
import argparse
import io
import json
import sys

REMOVE = 'REVERSAL_REMOVE'
RESTORE = 'REVERSAL_RESTORE_PRIOR'
DEFER = 'REVERSAL_DEFERRED_TO_SUCCESSOR'
SCOPED = 'REVERSAL_ENTRY_SCOPED'
CONFLICT = 'REVERSAL_REFUSED_CONFLICT'
DEPENDENCY = 'REVERSAL_WITHHELD_DEPENDENCY'
UNTRUSTED = 'REVERSAL_WITHHELD_UNTRUSTED'

ACTIONS = ('CREATED', 'MODIFIED', 'REDIRECTED', 'ENTRY')
FALSE, UNEVALUABLE = 'established-false', 'unevaluable'


def parse_stamp(raw):
    """-> dict, or None when unreadable. '' (read, nothing there) -> {}."""
    if raw is None:
        return None
    raw = str(raw).strip()
    if not raw:
        return {}
    fields = {}
    for part in raw.split(';'):
        if '=' in part:
            k, v = part.split('=', 1)
            fields[k.strip()] = v.strip()
    if not fields:
        fields = {'release_id': raw}
    return fields


def result(entry, disposition, ownership, conflict, precondition, status, reason):
    return {'object': entry.get('object', ''), 'action': entry.get('action', ''),
            'reversal_disposition': disposition, 'release_ownership': ownership,
            'reversal_conflict': conflict or 'none', 'deciding_precondition': precondition,
            'precondition_status': status, 'reason': reason}


def derive(entry, release):
    """The section 8 derivation. Every unknown resolves somewhere non-destructive."""
    action = entry.get('action') or 'CREATED'
    classification = entry.get('classification') or 'EXCLUSIVE'
    stamp = parse_stamp(entry.get('stamp'))
    later = entry.get('later_releases')
    descendants = entry.get('descendants')
    dependents = entry.get('dependents')
    claims = entry.get('other_claims')
    current = entry.get('current_version')
    post = entry.get('recorded_post_version')

    if action not in ACTIONS:
        return result(entry, UNTRUSTED, 'OWNERSHIP_UNESTABLISHED', 'PRECONDITION_UNESTABLISHED',
                      'P1', UNEVALUABLE, 'unrecognised manifest action %r; nothing destructive'
                      % action)
    if classification == 'PLATFORM_OWNED_SHARED':
        return result(entry, DEPENDENCY, 'PLATFORM_OWNED_SHARED', None, 'classification',
                      FALSE, 'the platform owns this resource; an application rollback cannot act '
                      'on it whatever its manifest says (section 8.3a)')
    if classification == 'REFERENCE_ONLY':
        return result(entry, DEPENDENCY, 'REFERENCE_ONLY', None, 'classification', FALSE,
                      'consumption left no trace to reverse; the referenced resource belongs to '
                      'somebody else (section 8.3a)')

    # P1 -- ownership, read off the live object.
    if stamp is None:
        return result(entry, UNTRUSTED, 'OWNERSHIP_UNESTABLISHED', None, 'P1', UNEVALUABLE,
                      'the ownership stamp could not be read')
    owner = stamp.get('release_id', '')
    if not owner:
        return result(entry, UNTRUSTED, 'OWNERSHIP_UNESTABLISHED', None, 'P1', UNEVALUABLE,
                      'the live object carries no ownership stamp')
    if owner != release:
        if later is None:
            return result(entry, UNTRUSTED, 'OWNED_BY_ANOTHER_RELEASE', 'PRECONDITION_UNESTABLISHED',
                          'P3', UNEVALUABLE, 'the stamp names %s and the release graph could not '
                          'be read to say whether it is a later release' % owner)
        if owner in later:
            return result(entry, DEFER, 'OWNED_BY_ANOTHER_RELEASE', 'SUPERSEDED_BY_LATER_RELEASE',
                          'P3', FALSE, 'later release %s wrote the current state; reverse it '
                          'first' % owner)
        return result(entry, CONFLICT, 'OWNED_BY_ANOTHER_RELEASE', None, 'P1', FALSE,
                      'OWNED_BY_ANOTHER_RELEASE: the stamp names %s, not %s; the manifest and live '
                      'state disagree about who made this' % (owner, release))
    if claims is None:
        return result(entry, UNTRUSTED, 'OWNERSHIP_UNESTABLISHED', None, 'P1', UNEVALUABLE,
                      'other ownership claims on the object could not be read')
    if claims:
        return result(entry, DEPENDENCY, 'OWNED_SHARED', None, 'P1', FALSE,
                      'co-owned by %s; shared ownership withdraws the removal branch'
                      % ', '.join(map(str, claims)))
    ownership = 'OWNED_BINDING' if classification == 'OWNED_BINDING' else (
        'SHARED_CONFIGURATION_ENTRY' if classification == 'SHARED_CONFIGURATION_ENTRY'
        else 'OWNED_EXCLUSIVE')

    # P6 -- reverse-ancestry order, about the graph rather than the object.
    if descendants is None:
        return result(entry, UNTRUSTED, ownership, 'PRECONDITION_UNESTABLISHED', 'P6', UNEVALUABLE,
                      'the release graph could not be traversed for descendants')
    if descendants:
        return result(entry, DEFER, ownership, 'REVERSE_ORDER_VIOLATED', 'P6', FALSE,
                      'descendant release(s) %s still stand; reverse them first'
                      % ', '.join(map(str, descendants)))

    # P3 -- has a later release written it (needed before P4 can be derived at all).
    if later is None:
        return result(entry, UNTRUSTED, ownership, 'PRECONDITION_UNESTABLISHED', 'P3', UNEVALUABLE,
                      'the release graph could not be read for later writers')
    if later:
        # The stamp still names us, yet the graph records a later writer of this object. Either
        # the later release did not re-stamp or the stamp was restored; both say the current
        # state is not solely ours, and the later release is reversed first.
        return result(entry, DEFER, ownership, 'SUPERSEDED_BY_LATER_RELEASE', 'P3', FALSE,
                      'later release(s) %s wrote this object since; reverse them first'
                      % ', '.join(map(str, later)))

    # P2 -- is it still the post-state this release left behind?
    if current is None or post is None:
        return result(entry, UNTRUSTED, ownership, 'PRECONDITION_UNESTABLISHED', 'P2', UNEVALUABLE,
                      'the %s could not be read' % ('current version handle' if current is None
                                                    else 'recorded post-state version'))
    if str(current) != str(post):
        if action != 'ENTRY':
            # P4 -- the difference no release in the graph claims.
            return result(entry, CONFLICT, ownership, 'MODIFIED_BY_EXTERNAL_ACTOR', 'P4', FALSE,
                          'MODIFIED_BY_EXTERNAL_ACTOR: current version %s is not the recorded '
                          'post-state %s and no release claims the change' % (current, post))
        unchanged = entry.get('entry_unchanged')
        if unchanged is None:
            return result(entry, UNTRUSTED, ownership, 'PRECONDITION_UNESTABLISHED', 'P4',
                          UNEVALUABLE, 'the parent moved and our entry could not be compared')
        if not unchanged:
            return result(entry, CONFLICT, ownership, 'MODIFIED_BY_EXTERNAL_ACTOR', 'P4', FALSE,
                          'this release\'s own entry was altered by someone else')
        free = entry.get('entry_side_effect_free')
        if free is None:
            return result(entry, UNTRUSTED, ownership, 'PRECONDITION_UNESTABLISHED', 'P5',
                          UNEVALUABLE, 'whether removing the entry changes the evaluation '
                          'outcome for other entries could not be established')
        if not free:
            return result(entry, DEPENDENCY, ownership, 'DEPENDENT_INTRODUCED_LATER', 'P5', FALSE,
                          'removing this entry alters the effective behaviour of entries another '
                          'actor owns')
        if entry.get('entry_independent') is not True:
            return result(entry, UNTRUSTED, ownership, 'PRECONDITION_UNESTABLISHED', 'P4',
                          UNEVALUABLE, 'the surface cannot be shown to address this entry '
                          'independently -- granularity unestablished')

    # P5 -- does anything introduced later depend on it?
    if dependents is None:
        return result(entry, UNTRUSTED, ownership, 'PRECONDITION_UNESTABLISHED', 'P5', UNEVALUABLE,
                      'the dependency read failed or the adapter cannot read dependents')
    if dependents:
        return result(entry, DEPENDENCY, ownership, 'DEPENDENT_INTRODUCED_LATER', 'P5', FALSE,
                      'preserved because %s depends on it' % ', '.join(map(str, dependents)))

    if action == 'ENTRY':
        if str(current) != str(post):
            return result(entry, SCOPED, ownership, None, 'all', 'all-established',
                          'the parent changed, this release\'s entry did not; the entry alone is '
                          'reversed')
        return result(entry, RESTORE, ownership, None, 'all', 'all-established',
                      'entry unchanged since this release wrote it; restore the recorded prior')
    if action == 'CREATED':
        return result(entry, REMOVE, ownership, None, 'all', 'all-established',
                      'created by this release, unchanged since, exclusively owned, nothing '
                      'depends on it, no descendant stands')
    return result(entry, RESTORE, ownership, None, 'all', 'all-established',
                  'still the post-state this release recorded; restore the captured prior')


def tri(v):
    if v is None:
        return None
    v = str(v).strip().lower()
    return True if v in ('yes', 'true') else False if v in ('no', 'false') else None


def listish(v):
    if v is None or str(v).strip().lower() == 'unknown':
        return None
    v = str(v).strip()
    if v.lower() in ('none', ''):
        return []
    return [x.strip() for x in v.split(',') if x.strip()]


def self_test():
    rel = 'r1'
    base = {'object': 'o', 'action': 'CREATED', 'stamp': 'release_id=r1', 'current_version': 'v',
            'recorded_post_version': 'v', 'later_releases': [], 'descendants': [],
            'dependents': [], 'other_claims': []}
    cases = [({}, REMOVE), ({'stamp': None}, UNTRUSTED), ({'current_version': 'w'}, CONFLICT),
             ({'dependents': None}, UNTRUSTED), ({'dependents': ['d']}, DEPENDENCY),
             ({'descendants': ['r2']}, DEFER), ({'action': 'MODIFIED'}, RESTORE),
             ({'stamp': 'release_id=r2', 'later_releases': ['r2']}, DEFER),
             ({'stamp': 'release_id=r9'}, CONFLICT)]
    bad = []
    for over, want in cases:
        e = dict(base, **over)
        got = derive(e, rel)['reversal_disposition']
        if got != want:
            bad.append('%r -> %s, wanted %s' % (over, got, want))
    # Unset keys are UNKNOWN: an entry that says nothing must never be removable.
    if derive({'object': 'o', 'action': 'CREATED', 'stamp': 'release_id=r1'}, rel)[
            'reversal_disposition'] == REMOVE:
        bad.append('an entry with no P2-P6 evidence derived REMOVE')
    if bad:
        for b in bad:
            print('SELF-TEST FAILED: ' + b)
        return 2
    print('self-test ok: %d derivations, and an entry with unasked preconditions is not removable'
          % (len(cases) + 1))
    return 0


def main(argv):
    ap = argparse.ArgumentParser(description=__doc__.split('\n')[0])
    ap.add_argument('--self-test', action='store_true')
    ap.add_argument('--release', default='')
    ap.add_argument('--entries')
    ap.add_argument('--object', default='')
    ap.add_argument('--action', default='CREATED')
    ap.add_argument('--stamp')
    ap.add_argument('--stamp-unreadable', action='store_true')
    ap.add_argument('--current-version')
    ap.add_argument('--current-version-unreadable', action='store_true')
    ap.add_argument('--recorded-post-version')
    ap.add_argument('--later-releases')
    ap.add_argument('--descendants')
    ap.add_argument('--dependents')
    ap.add_argument('--other-claims')
    ap.add_argument('--classification', default='EXCLUSIVE')
    ap.add_argument('--entry-unchanged')
    ap.add_argument('--entry-side-effect-free')
    ap.add_argument('--entry-independent')
    a = ap.parse_args(argv)
    if a.self_test:
        return self_test()
    if not a.release:
        print('::error::--release is required: a disposition is relative to the release being '
              'reversed.', file=sys.stderr)
        return 2
    if a.entries:
        try:
            entries = json.load(io.open(a.entries, encoding='utf-8'))
            if not isinstance(entries, list):
                raise ValueError('not a JSON list')
        except (OSError, ValueError) as e:
            print('::error::entries unreadable (%s). Nothing is derived from an unread manifest.'
                  % e, file=sys.stderr)
            return 2
        print(json.dumps([derive(e if isinstance(e, dict) else {}, a.release) for e in entries],
                         indent=1))
        return 0
    entry = {
        'object': a.object, 'action': a.action, 'classification': a.classification,
        'stamp': None if a.stamp_unreadable else a.stamp,
        'current_version': None if a.current_version_unreadable else a.current_version,
        'recorded_post_version': a.recorded_post_version,
        'later_releases': listish(a.later_releases), 'descendants': listish(a.descendants),
        'dependents': listish(a.dependents), 'other_claims': listish(a.other_claims),
        'entry_unchanged': tri(a.entry_unchanged),
        'entry_side_effect_free': tri(a.entry_side_effect_free),
        'entry_independent': tri(a.entry_independent),
    }
    r = derive(entry, a.release)
    for k in ('reversal_disposition', 'release_ownership', 'reversal_conflict',
              'deciding_precondition', 'precondition_status'):
        print('%s=%s' % (k, r[k]))
    print('reason=%s' % r['reason'].replace('\n', ' '))
    return 0


if __name__ == '__main__':
    sys.exit(main(sys.argv[1:]))

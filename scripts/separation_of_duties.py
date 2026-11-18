#!/usr/bin/env python3
"""Separation of duties for review-driven tickets (KDEC-037, owner ruling 2026-11-04).

THE OWNER'S WORDS

    "The submitter of the review doesn't get to do the triage review, the fix, and then sign off on
    their own work... They can submit the review and identify what needs to be triaged; they could
    even be talked into doing the work; they just can't be the authority that approves their own
    work, or approves their review after they've completed it. They can move the tickets to closed
    if their task is complete, and it's someone else's responsibility to come behind them and
    double-check."

THE ROLES, PER ITEM (docs/ticketing/SEPARATION-OF-DUTIES.md)

    submitter        submitted the review (a person, or the automation that ran it)
    run_started_by   the person who started an AI run whose output is under review
    triager          decided the triage (link / new, merge / separate)
    fixer            did the fix (the assignee)
    requester        asked for an exception, an exemption, an extension or a closure
    verifier         concurs with the review / verifies the fix / approves the request

    ONE PERSON MAY HOLD submitter, triager and fixer. NOBODY MAY BE THE VERIFIER OF ANYTHING THEY
    AUTHORED -- their review, their triage decision, their fix, their request, or an AI run they
    started. A fixer MAY move their own ticket to resolved-pending-verification; it is closed only by
    someone else (or by the kit's own rescan).

    A bot is never a verifier: an automation does not concur with itself.
"""
import sys

SOD_SELF_APPROVAL = 'SOD_SELF_APPROVAL'
AUTHOR_ROLES = ('submitter', 'run_started_by', 'triager', 'fixer', 'requester', 'caller', 'on_behalf_of')


def _norm(who):
    w = str(who or '').strip().lower()
    if w.endswith('[bot]'):
        w = w[:-len('[bot]')]
    return w.split('@')[0] if '@' in w else w


def violations(roles, verifier):
    """-> [(role, who)] the verifier would be approving their own work in. Empty: allowed."""
    v = _norm(verifier)
    if not v:
        return [('verifier', 'nobody')]
    out = []
    for role in AUTHOR_ROLES:
        vals = roles.get(role)
        for who in (vals if isinstance(vals, (list, tuple, set)) else [vals]):
            if who and _norm(who) == v:
                out.append((role, who))
    if str(verifier).strip().lower().endswith('[bot]'):
        out.append(('bot', verifier))
    return out


def describe(viol):
    return '; '.join('%s is the %s' % (who, role.replace('_', ' ')) for role, who in viol)


def _selftest():
    roles = {'submitter': 'a', 'run_started_by': 'b', 'triager': 'c', 'fixer': 'd', 'requester': 'e'}
    bad = [w for w in 'abcde' if not violations(roles, w)]
    if bad or violations(roles, 'f') or not violations(roles, 'x[bot]'):
        sys.stderr.write('FAIL: separation of duties: %r\n' % bad)
        return 2
    print('separation_of_duties selftest ok: no author role may verify; a non-author may; a bot never may.')
    return 0


if __name__ == '__main__':
    sys.exit(_selftest() if sys.argv[1:] == ['--self-test'] else 2)

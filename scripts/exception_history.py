#!/usr/bin/env python3
"""An exception's HISTORY and its RENEWAL CAP: "endless exemptions/exceptions are not a thing."
(KDEC-018 item 4, owner 2026-10-22; lane L-FX.)

WHAT AN EXCEPTION'S HISTORY IS

    Every dated exception the kit honours may carry `renews`: the PRIOR GRANTS of the same exception
    (the same secret finding, the same register entry's softening, the same deploy acceptance), one
    object per grant, oldest first or in any order:

        "renews": [{"ticket": "SEC-1200", "approver": "Named Person", "from": "2026-01-10",
                    "expires": "2026-04-10"},
                   {"ticket": "SEC-1311", "approver": "Other Person", "from": "2026-04-10",
                    "expires": "2026-07-10"}]

    `ticket` is a work-item key <PROJECT>-<digits>; `approver` the named person who approved that
    grant; `from` the date it was granted; `expires` the date it lapsed. The number of renewals is
    the number of prior grants. No `renews` (or an empty list) is a FIRST exception and says so.

    The history is shown wherever the exception is applied or resurfaced:
        "previously excepted 2 time(s) since 2026-01-10, tickets SEC-1200, SEC-1311,
         approvers Named Person, Other Person"
    or "first exception".

    A history the kit cannot read is not "no history": the caller refuses the exception as
    unattributed (it cannot be shown to be under the cap).

THE CAP

    `numbers.max_exception_renewals` in the CENTRAL register (the authority's scope; a repository
    file may not set it). Kit default 2: a first grant and two renewals, then the exception is
    refused by name -- EXCEPTION_RENEWAL_LIMIT -- and the finding reverts to its normal routing (a
    secret BLOCKS). The cap is an integer from 0 to 5 and can never be "unlimited": 0 means no
    exception is ever renewed; 5 bounds the life of one exception at six grants (about eighteen
    months at the quarterly expiries the kit's examples use), past which a recurring exception is a
    standing policy and belongs in the register as one -- or, for a secret, removed.

USAGE (the deploy reusables' verdict step re-implements the same rules in jq; this CLI is for people)
    python3 exception_history.py --renews-json '[...]' [--cap N]
    python3 exception_history.py --self-test
EXIT  0 within the cap   1 over the cap or unreadable   2 usage, or self-test failed
"""
import argparse
import datetime
import json
import re
import sys

kit_default_max_renewals = 2
max_renewals_ceiling = 5
number_key = 'max_exception_renewals'
EXCEPTION_RENEWAL_LIMIT = 'EXCEPTION_RENEWAL_LIMIT'
GRANT_KEYS = ('ticket', 'approver', 'from', 'expires')
TICKET_RE = re.compile(r'^[A-Z][A-Z0-9_]*-[0-9]+$')
ISO_DATE = re.compile(r'^\d{4}-\d{2}-\d{2}$')


def _date(s):
    if not isinstance(s, str) or not ISO_DATE.match(s):
        return None
    try:
        return datetime.date.fromisoformat(s)
    except ValueError:
        return None


def parse_renews(value):
    """-> (grants, problem). `grants` is a list ([] for a first exception); `problem` names why the
    history cannot be read (then `grants` is None)."""
    if value is None:
        return [], ''
    if not isinstance(value, list):
        return None, 'renews is not a list of prior grants'
    out = []
    for i, g in enumerate(value):
        if not isinstance(g, dict):
            return None, 'renews[%d] is not an object {ticket, approver, from, expires}' % i
        extra = [k for k in g if k not in GRANT_KEYS]
        if extra:
            return None, 'renews[%d] carries unknown field(s) %s' % (i, ', '.join(sorted(extra)))
        if not TICKET_RE.match(str(g.get('ticket') or '').strip()):
            return None, 'renews[%d].ticket %r is not a work-item key <PROJECT>-<digits>' % (i, g.get('ticket'))
        if not str(g.get('approver') or '').strip():
            return None, 'renews[%d] names no approver' % i
        for k in ('from', 'expires'):
            if _date(g.get(k)) is None:
                return None, 'renews[%d].%s %r is not a YYYY-MM-DD calendar date' % (i, k, g.get(k))
        out.append(dict((k, str(g[k]).strip()) for k in GRANT_KEYS))
    return out, ''


def cap_from_numbers(numbers):
    """-> (cap, problem). Absent -> the kit default."""
    v = (numbers or {}).get(number_key)
    if v is None:
        return kit_default_max_renewals, ''
    if isinstance(v, bool) or not isinstance(v, int) or not 0 <= v <= max_renewals_ceiling:
        return kit_default_max_renewals, ('numbers.%s is %r; it must be an integer from 0 to %d -- a renewal '
                                          'cap can never be unlimited' % (number_key, v, max_renewals_ceiling))
    return v, ''


def summary(grants):
    """-> {'renewals', 'history', 'since', 'prior_tickets', 'prior_approvers'} for display."""
    grants = grants or []
    if not grants:
        return {'renewals': 0, 'history': 'first exception', 'since': '', 'prior_tickets': [],
                'prior_approvers': []}
    since = min(g['from'] for g in grants)
    tickets = [g['ticket'] for g in sorted(grants, key=lambda g: g['from'])]
    approvers = []
    for g in sorted(grants, key=lambda g: g['from']):
        if g['approver'] not in approvers:
            approvers.append(g['approver'])
    return {'renewals': len(grants), 'since': since, 'prior_tickets': tickets, 'prior_approvers': approvers,
            'history': 'previously excepted %d time(s) since %s, tickets %s, approvers %s'
                       % (len(grants), since, ', '.join(tickets), ', '.join(approvers))}


def verdict(grants, cap):
    """-> (code or None, why) for an exception whose readable history is `grants`."""
    n = len(grants or [])
    if n > cap:
        return (EXCEPTION_RENEWAL_LIMIT, 'renewed %d time(s); the cap is %d (numbers.%s). Endless exceptions are '
                'not a thing: fix the cause, or the authority raises the cap (at most %d)'
                % (n, cap, number_key, max_renewals_ceiling))
    return (None, '')


def _selftest():
    fails = []
    g, p = parse_renews(None)
    if g != [] or p or summary(g)['history'] != 'first exception':
        fails.append('no history is not a first exception')
    two = [{'ticket': 'SEC-2', 'approver': 'B', 'from': '2026-04-01', 'expires': '2026-07-01'},
           {'ticket': 'SEC-1', 'approver': 'A', 'from': '2026-01-01', 'expires': '2026-04-01'}]
    g, p = parse_renews(two)
    s = summary(g)
    if p or s['renewals'] != 2 or s['since'] != '2026-01-01' or 'SEC-1, SEC-2' not in s['history']:
        fails.append('a two-grant history did not read: %r %r' % (p, s))
    if verdict(g, 2)[0] or verdict(g, 1)[0] != EXCEPTION_RENEWAL_LIMIT:
        fails.append('the cap is not applied as renewals > cap')
    for bad in ('x', [1], [{'ticket': 'nope', 'approver': 'A', 'from': '2026-01-01', 'expires': '2026-02-01'}],
                [{'ticket': 'SEC-1', 'approver': ' ', 'from': '2026-01-01', 'expires': '2026-02-01'}],
                [{'ticket': 'SEC-1', 'approver': 'A', 'from': 'never', 'expires': '2026-02-01'}]):
        if parse_renews(bad)[0] is not None:
            fails.append('an unreadable history %r was read' % (bad,))
    for v, ok in ((None, True), (0, True), (5, True), (6, False), (-1, False), (True, False), ('2', False)):
        if (not cap_from_numbers({number_key: v} if v is not None else {})[1]) != ok:
            fails.append('cap %r accepted=%s' % (v, not ok))
    if fails:
        for f in fails:
            sys.stderr.write('FAIL: %s\n' % f)
        return 2
    print('exception_history selftest ok: no history is a first exception; a history reads, is summarised '
          'and counted; renewals over the cap are EXCEPTION_RENEWAL_LIMIT; an unreadable history is not '
          'read; the cap is an integer 0..5, never unlimited.')
    return 0


def main(argv=None):
    ap = argparse.ArgumentParser(description='Read an exception history and apply the renewal cap.')
    ap.add_argument('--self-test', action='store_true')
    ap.add_argument('--renews-json', default='')
    ap.add_argument('--cap', type=int, default=kit_default_max_renewals)
    a = ap.parse_args(argv)
    if a.self_test:
        return _selftest()
    try:
        value = json.loads(a.renews_json) if a.renews_json.strip() else None
    except ValueError:
        print('history unreadable: --renews-json is not JSON')
        return 1
    grants, problem = parse_renews(value)
    if grants is None:
        print('history unreadable: %s' % problem)
        return 1
    s = summary(grants)
    code, why = verdict(grants, a.cap)
    print('renewals=%d' % s['renewals'])
    print('history=%s' % s['history'])
    if code:
        print('%s: %s' % (code, why))
        return 1
    return 0


if __name__ == '__main__':
    sys.exit(main())

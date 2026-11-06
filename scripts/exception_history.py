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

THE HISTORY COMES FROM GIT (KDEC-022 item 2, owner 2026-10-23: option D, "B plus C")

    A register can say anything about itself, including a shorter `renews` than happened. So the
    renewal history of every register exception -- a secret_exceptions or known_exploited_exceptions
    item (keyed by its finding), and an entry's decision (keyed by the entry id) -- is DERIVED from
    the git history of the protected register file: `git log --follow` of the file on the default
    branch, every version read, every distinct (ticket, expiry) the exception ever had collected
    (read_git_history, derive_grants). Then (check_history):

        the declared `renews` lists every prior grant git shows   -> verified; the count is the
                                                                     larger of the two (a longer
                                                                     declared history only tightens)
        it lists fewer (the history was erased)                    -> EXCEPTION_HISTORY_TAMPERED
        git cannot show the history (a shallow clone, no git, a    -> EXCEPTION_HISTORY_UNVERIFIED:
        file that differs from its committed version, a blob the      refused exactly as an
        fetch cannot supply)                                           unreadable history is --
                                                                       never read as zero renewals
    The cap (numbers.max_exception_renewals) binds that DERIVED count. The weekly Jira cross-check
    (scripts/exception_due.py --cross-check) is the second half, C; the gate never depends on Jira.

USAGE (the deploy reusables' verdict step re-implements the same rules in jq; this CLI is for people)
    python3 exception_history.py --renews-json '[...]' [--cap N]
    python3 exception_history.py --self-test
EXIT  0 within the cap   1 over the cap or unreadable   2 usage, or self-test failed
"""
import argparse
import datetime
import io
import json
import os
import re
import subprocess
import sys

kit_default_max_renewals = 2
max_renewals_ceiling = 5
number_key = 'max_exception_renewals'
EXCEPTION_RENEWAL_LIMIT = 'EXCEPTION_RENEWAL_LIMIT'
# KDEC-022 item 2: the history as git shows it.
EXCEPTION_HISTORY_TAMPERED = 'EXCEPTION_HISTORY_TAMPERED'
EXCEPTION_HISTORY_UNVERIFIED = 'EXCEPTION_HISTORY_UNVERIFIED'
history_verified = 'VERIFIED'
history_unverified = 'UNVERIFIED'
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


def verdict_count(n, cap):
    """verdict() for a count rather than a list of grants (the derived count, KDEC-022)."""
    return verdict([None] * int(n or 0), cap)


# ── the history from git (KDEC-022 item 2, B) ─────────────────────────────────────────────────

def _git(repo, *args):
    p = subprocess.run(['git', '-C', repo, '-c', 'core.quotepath=off'] + list(args), capture_output=True)
    return p.returncode, p.stdout.decode('utf-8', 'replace'), p.stderr.decode('utf-8', 'replace').strip()


def unverified(why):
    return {'state': history_unverified, 'why': why, 'versions': [], 'source': 'none'}


def history_from_texts(texts, source='supplied'):
    """A history made of the given versions, oldest first (a fixture, or 'the register as committed
    once'). -> a VERIFIED history."""
    return {'state': history_verified, 'why': '%d version(s) supplied' % len(texts), 'source': source,
            'versions': [{'sha': '', 'date': '', 'text': t} for t in texts]}


def read_git_history(repo, ref, path):
    """Every committed version of `path` reachable from `ref`, oldest first, following renames.
    -> a history dict: state VERIFIED, or UNVERIFIED with the reason. A shallow repository, an
    unresolvable ref, or a version whose blob cannot be read is UNVERIFIED -- the history git
    cannot show is not an empty one."""
    rc, out, err = _git(repo, 'rev-parse', '--verify', '--quiet', '%s^{commit}' % ref)
    if rc != 0:
        return unverified('ref %r cannot be resolved in %s (%s)' % (ref, repo, err or 'no such ref'))
    sha = out.strip()
    rc, out, _e = _git(repo, 'rev-parse', '--is-shallow-repository')
    if rc != 0 or out.strip() != 'false':
        return unverified('the repository is a shallow clone: git cannot show the register\'s whole history, so '
                          'no renewal count can be verified (fetch it with history -- the workflow uses a '
                          'blob-less partial clone)')
    rc, out, err = _git(repo, 'log', '--follow', '--format=%x00%H%x09%cs', '--name-only', sha, '--', path)
    if rc != 0:
        return unverified('git log --follow of %s failed: %s' % (path, err))
    commits = []
    for block in out.split('\x00')[1:]:
        lines = [x for x in block.split('\n') if x.strip()]
        if not lines:
            continue
        head = lines[0].split('\t')
        commits.append((head[0], head[1] if len(head) > 1 else '', lines[-1].strip() if len(lines) > 1 else path))
    versions = []
    for c_sha, date, p in reversed(commits):
        rc, _o, _e = _git(repo, 'cat-file', '-e', '%s:%s' % (c_sha, p))
        if rc != 0:
            # The commit deleted the file (or renamed it away): no version at this commit.
            continue
        rc, text, err = _git(repo, 'show', '%s:%s' % (c_sha, p))
        if rc != 0:
            return unverified('version %s of %s cannot be read: %s' % (c_sha[:12], p, err))
        versions.append({'sha': c_sha, 'date': date, 'text': text})
    return {'state': history_verified, 'why': '%d committed version(s) of %s at %s' % (len(versions), path, sha[:12]),
            'source': 'git', 'versions': versions}


def history_for_file(path, extra_text=None):
    """The git history of a register FILE in a working tree (the central register, --validate).
    The committed versions at HEAD; the file as it stands must equal the newest of them, unless
    `extra_text` is given (a proposed version being validated), which is appended as the newest.
    -> a history dict."""
    if not path or not os.path.isfile(path):
        return unverified('no file at %s' % (path or '(none)'))
    d, base = os.path.dirname(os.path.abspath(path)), os.path.basename(path)
    rc, out, _e = _git(d, 'ls-files', '--full-name', '--', base)
    rel = out.strip().split('\n')[0].strip() if rc == 0 else ''
    if not rel:
        return unverified('%s is not a committed file in any git history: its exceptions\' renewals cannot be '
                          'verified' % path)
    rc, top, _e = _git(d, 'rev-parse', '--show-toplevel')
    h = read_git_history(top.strip(), 'HEAD', rel)
    if h['state'] != history_verified:
        return h
    if extra_text is not None:
        h['versions'].append({'sha': 'proposed', 'date': '', 'text': extra_text})
        return h
    try:
        current = io.open(path, encoding='utf-8').read()
    except (OSError, UnicodeDecodeError) as exc:
        return unverified('%s cannot be read: %s' % (path, exc))
    newest = h['versions'][-1]['text'] if h['versions'] else None
    if newest is None or newest.replace('\r\n', '\n') != current.replace('\r\n', '\n'):
        return unverified('%s differs from its committed version: git does not show the history of what is being '
                          'read' % path)
    return h


def exception_key(kind, ident):
    return '%s:%s' % (kind, ident)


def derive_grants(history):
    """-> {key: [grant, ...]} oldest first, one per distinct (ticket, expires) the exception ever had,
    each {ticket, approver, from, expires}. Keys: secret:<finding>, kev:<finding>, decision:<entry id>.
    A version that does not parse contributes nothing (its neighbours still do)."""
    out = {}
    for v in (history or {}).get('versions') or []:
        try:
            doc = json.loads(v.get('text') or '')
        except ValueError:
            continue
        for e in (doc.get('policies') if isinstance(doc, dict) else None) or []:
            if not isinstance(e, dict):
                continue
            found = []
            for kind, field in (('secret', 'secret_exceptions'), ('kev', 'known_exploited_exceptions')):
                for item in e.get(field) or []:
                    if isinstance(item, dict) and str(item.get('finding') or '').strip():
                        found.append((exception_key(kind, str(item['finding']).strip()), item.get('ticket'),
                                      item.get('expires'), item.get('approver')))
            dec = e.get('decision')
            if isinstance(dec, dict) and str(e.get('id') or '').strip():
                found.append((exception_key('decision', str(e['id']).strip()), dec.get('exception_ref'),
                              dec.get('expires'), dec.get('authority')))
            for key, ticket, expires, approver in found:
                g = {'ticket': str(ticket or '').strip(), 'expires': str(expires or '').strip(),
                     'approver': str(approver or '').strip(), 'from': v.get('date') or ''}
                seen = out.setdefault(key, [])
                if not any(x['ticket'] == g['ticket'] and x['expires'] == g['expires'] for x in seen):
                    seen.append(g)
    return out


def check_history(history, key, ticket, expires, declared):
    """-> (code or None, why, derived_prior_count). `declared` is the parsed `renews` (a list)."""
    if not history or history.get('state') != history_verified:
        return (EXCEPTION_HISTORY_UNVERIFIED, 'its renewal history cannot be verified from git (%s); a history git '
                'cannot show is not "no renewals"' % ((history or {}).get('why') or 'no history was read'), None)
    grants = history.setdefault('_grants', None) or derive_grants(history)
    history['_grants'] = grants
    cur = (str(ticket or '').strip(), str(expires or '').strip())
    prior = [g for g in grants.get(key) or [] if (g['ticket'], g['expires']) != cur]
    have = set((g['ticket'], g['expires']) for g in declared or [])
    have_exp = set(g['expires'] for g in declared or [])
    missing = [g for g in prior if (g['ticket'], g['expires']) not in have
               and not (not g['ticket'] and g['expires'] in have_exp)]
    if missing:
        return (EXCEPTION_HISTORY_TAMPERED,
                'git shows %d prior grant(s) of this exception and its declared renews lists %d; missing: %s. A '
                'history shorter than git shows was erased' % (
                    len(prior), len(declared or []),
                    ', '.join('%s until %s (first committed %s)' % (g['ticket'] or '(no ticket)', g['expires'],
                                                                     g['from'] or '?') for g in missing)), len(prior))
    return (None, '', len(prior))


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

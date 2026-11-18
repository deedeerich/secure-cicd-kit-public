#!/usr/bin/env python3
"""The review-finalize gate: a review's tickets are written only after a RECORDED HUMAN CONCURRENCE
with the finalized review. (KDEC-037; KDEC-035 O-35g as the owner amended it, 2026-11-03.)

THE OWNER'S WORDS

    "tines runs it and I go yay verily I concur with your findings and your evidence. And then it
    finalizes the review and writes the tickets."

WHAT A FINALIZED REVIEW IS (api/v1/tickets/review-record.schema.json)

    A record at `.security/reviews/<review_id>.json` on the PROTECTED DEFAULT BRANCH:
        status FINALIZED, submitted_by, concurred_by (a GitHub login), concurred_on (a date),
        evidence_set_sha256 (the exact set of tickets the concurrence covers), statement.

    THE AUTHORITY IS NEVER WHERE THE AUTOMATION CAN WRITE. An automation may PROPOSE the record (a
    pull request through its own sync path); it becomes a concurrence only when the concurring
    reviewer APPROVES that pull request and it is merged. So the gate holds, all of:

      R1  the record exists on the checkout of the default branch and is schema-valid
      R2  status is FINALIZED
      R3  evidence_set_sha256 equals the evidence set of THIS call (a byte changed after the
          concurrence is another set)
      R4  concurred_by is on the review approver list (the central register's
          approver_lists[<list>], or .security/reviews/approvers.json beside the records -- both on
          the protected branch); an unreadable list is not an empty one
      R5  SEPARATION OF DUTIES (scripts/separation_of_duties.py): concurred_by is NOT the
          submitter, the person who started the AI run, the triager, the API caller (GitHub's actor
          and triggering actor), the declared on_behalf_of, or a bot (SOD_SELF_APPROVAL)
      R6  concurred_on is a real date, not in the future, and not older than the owner's maximum
      R7  READ BACK FROM GITHUB: the newest commit that touched the record on the default branch
          came from a merged pull request into it, which concurred_by APPROVED and did not author.
          A history that cannot be read is not a concurrence.

    Anything else is REVIEW_NOT_FINALIZED, with every reason named; the caller reads it as
    API_REVIEW_NOT_FINALIZED and nothing is read from or written to the tracker.

    CONCURRENCE IS AGREE OR DISAGREE (owner, 2026-11-04). `decision` DISAGREE (with an `alternative`)
    sends every item back, recorded as dissent; `item_decisions` may DISAGREE with single items, which
    alone go back. A DISAGREE is a finalized answer -- not a refusal -- and writes nothing it covers.

    THE APPROVER LIST IS THE WHOLE SECURITY TEAM (owner, O-37b): a list (`list:<name>`, the central
    register's approver_lists or .security/reviews/approvers.json) or a GitHub team
    (`team:<org>/<slug>`, read through the API host: it needs a token that can read the
    organisation's members; one that cannot is "not readable", never an empty team). Any member
    except the author of the work may concur -- including on the AI's work that ran for another
    engineer.

WHAT IT CANNOT DO, PLAINLY

    It cannot tell whether the person read the evidence. It establishes that a named person on the
    approver list, who is not the automation, approved exactly this set on the protected branch.
    Group membership (a team on the list) is not resolved: the run's token cannot read an
    organisation's teams, so the list names logins.
"""
import datetime
import io
import json
import os
import re
import urllib.parse

REVIEW_FINALIZED = 'REVIEW_FINALIZED'
REVIEW_NOT_FINALIZED = 'REVIEW_NOT_FINALIZED'
REVIEW_ID_RE = re.compile(r'^[A-Za-z0-9][A-Za-z0-9._-]{2,79}$')
LIST_NAME_RE = re.compile(r'^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$')
RECORD_DIR = '.security/reviews'


def _s(v):
    return v.strip() if isinstance(v, str) else ''


def load_approvers_source(source, central_path='', reviews_dir='', client=None):
    """-> (logins or None, note). `source` is list:<name> (the default) or team:<org>/<slug>."""
    src = (source or 'list:review-concurrence').strip()
    if src.startswith('team:'):
        org, _sep, slug = src[len('team:'):].partition('/')
        if not (LIST_NAME_RE.match(org or '') and LIST_NAME_RE.match(slug or '')):
            return None, 'the approver source %r is not team:<org>/<slug>' % src
        if client is None:
            return None, 'the team %s/%s could not be read: no GitHub client' % (org, slug)
        members, page = [], 1
        while page <= 10:
            st, doc, _h, err = client.get('/orgs/%s/teams/%s/members?per_page=100&page=%d' % (org, slug, page))
            if err or not isinstance(doc, list):
                return None, ("the team %s/%s could not be read (%s): the token needs the organisation's Members: "
                              "read; an unreadable team is not an empty one" % (org, slug, err or st))
            members += [_s(m.get('login')).lower() for m in doc if isinstance(m, dict) and m.get('login')]
            if len(doc) < 100:
                break
            page += 1
        if not members:
            return None, 'the team %s/%s has no members: nobody may concur' % (org, slug)
        return sorted(set(members)), 'GitHub team %s/%s (%d member(s))' % (org, slug, len(set(members)))
    name = src[len('list:'):] if src.startswith('list:') else src
    return load_approvers(name, central_path, reviews_dir)


def load_approvers(list_name, central_path='', reviews_dir=''):
    """-> (logins or None, source note). The central register's approver_lists[list_name] first
    (K-9: one list, named once); else approvers.json beside the review records. None: no list."""
    if not LIST_NAME_RE.match(list_name or ''):
        return None, 'the review approver list name %r is not a plain name' % list_name
    for label, path in (('the central register', central_path),
                        ('the review approvers file', os.path.join(reviews_dir, 'approvers.json') if reviews_dir else '')):
        if not path or not os.path.isfile(path):
            continue
        try:
            doc = json.load(io.open(path, encoding='utf-8'))
        except (OSError, ValueError) as exc:
            return None, '%s %s could not be read (%s): an unreadable list is not an empty one' % (
                label, path, type(exc).__name__)
        if label == 'the central register' and isinstance(doc, dict) and isinstance(doc.get('approver_lists_source'), str):
            # ONE MECHANISM with KDEC-036 (the AppSec list): the register's approver_lists, or the shared file its
            # approver_lists_source names, read by the same loader the landing zone's hand-off uses.
            import policy_registration as pr
            probs, _note = pr.load_approver_lists(doc, os.path.dirname(os.path.abspath(path)))
            if probs:
                return None, "the central register's approver lists could not be read: %s" % '; '.join(
                    str(x[1]) for x in probs)
        lists = doc.get('approver_lists') if isinstance(doc, dict) else None
        if isinstance(lists, dict) and list_name in lists:
            names = lists[list_name]
            if not isinstance(names, list) or not names or any(not _s(n) for n in names):
                return None, '%s holds approver_lists[%s], and it is not a non-empty list of logins' % (label, list_name)
            return sorted(set(_s(n).lower() for n in names)), '%s: approver_lists[%s]' % (label, list_name)
    return None, ('no approver list %r was found (the central register\'s approver_lists, or %s/approvers.json): '
                  'nobody is named who may concur' % (list_name, RECORD_DIR))


def _pr_approval(client, repo, branch, rel_path, concurrer):
    """R7. -> (ok, why, facts)."""
    if client is None:
        return False, 'no GitHub API client: the pull request behind the record cannot be read', {}
    st, commits, _h, err = client.get('/repos/%s/commits?path=%s&sha=%s&per_page=1' % (
        repo, urllib.parse.quote(rel_path), urllib.parse.quote(branch)))
    if err or not isinstance(commits, list):
        return False, 'the record\'s commit history could not be read (%s)' % (err or st), {}
    if not commits:
        return False, 'no commit on %s touched %s: the record is not on the protected branch' % (branch, rel_path), {}
    sha = commits[0].get('sha') or ''
    st, pulls, _h, err = client.get('/repos/%s/commits/%s/pulls' % (repo, sha))
    if err or not isinstance(pulls, list):
        return False, 'the pull request of commit %s could not be read (%s)' % (sha[:12], err or st), {}
    merged = [p for p in pulls if isinstance(p, dict) and p.get('merged_at')
              and ((p.get('base') or {}).get('ref') == branch)]
    if not merged:
        return False, ('commit %s that wrote the record came from no merged pull request into %s: a record pushed '
                       'past review is not a concurrence' % (sha[:12], branch)), {'commit': sha}
    pr = merged[0]
    n = pr.get('number')
    author = _s((pr.get('user') or {}).get('login')).lower()
    st, reviews, _h, err = client.get('/repos/%s/pulls/%s/reviews?per_page=100' % (repo, n))
    if err or not isinstance(reviews, list):
        return False, 'the reviews of pull request #%s could not be read (%s)' % (n, err or st), {}
    approvers = sorted(set(_s((r.get('user') or {}).get('login')).lower() for r in reviews
                           if isinstance(r, dict) and r.get('state') == 'APPROVED'))
    facts = {'commit': sha, 'pull_request': n, 'pr_author': author, 'pr_approvers': approvers}
    if concurrer not in approvers:
        return False, ('%s did not APPROVE pull request #%s that merged the record (approved by: %s)'
                       % (concurrer, n, ', '.join(approvers) or 'nobody')), facts
    if author == concurrer:
        return False, '%s authored pull request #%s: a concurrence is not self-approved' % (concurrer, n), facts
    return True, '', facts


def check(review_id, evidence_sha, reviews_dir, approvers, approvers_note, excluded, today, max_age_days,
          client=None, repo='', branch='', schema=None):
    """-> {'state', 'reasons', 'record', 'concurred_by', 'facts', 'decision', 'item_decisions', 'roles'}.
    Every reason named; never partial. `excluded` is the API caller's identities (actor, triggering
    actor, declared on_behalf_of)."""
    import kit_api as ka
    import separation_of_duties as sod
    out = {'state': REVIEW_NOT_FINALIZED, 'reasons': [], 'record': None, 'concurred_by': '', 'facts': {},
           'review_id': review_id or '', 'approvers_source': approvers_note, 'decision': None,
           'item_decisions': {}, 'roles': {}}
    why = out['reasons']
    if not REVIEW_ID_RE.match(review_id or ''):
        why.append('no review id was given, or it is malformed: a review\'s tickets need its finalized record')
        return out
    path = os.path.join(reviews_dir or '', '%s.json' % review_id)
    if not reviews_dir or not os.path.isfile(path):
        why.append('R1: no record %s/%s.json on the default branch' % (RECORD_DIR, review_id))
        return out
    try:
        rec = json.load(io.open(path, encoding='utf-8'))
    except (OSError, ValueError) as exc:
        why.append('R1: the record could not be read (%s)' % type(exc).__name__)
        return out
    errs = ka.validate(rec, schema) if schema else []
    if errs:
        why.append('R1: the record breaks review-record.schema.json: %s %s' % errs[0])
        return out
    out['record'] = {k: rec.get(k) for k in ('review_id', 'status', 'submitted_by', 'run_started_by', 'triaged_by',
                                             'concurred_by', 'concurred_on', 'decision', 'alternative',
                                             'evidence_set_sha256', 'title')}
    if rec.get('decision') == 'DISAGREE' and not _s(rec.get('alternative')):
        why.append('R1: a DISAGREE names no alternative: a dissent is recorded with what the reviewer would do instead')
    for d in rec.get('item_decisions') or []:
        if d.get('decision') == 'DISAGREE' and not _s(d.get('alternative')):
            why.append('R1: the DISAGREE on item %s names no alternative' % d.get('item'))
    out['decision'] = rec.get('decision')
    out['item_decisions'] = dict((int(d['item']), d) for d in rec.get('item_decisions') or [])
    if rec.get('review_id') != review_id:
        why.append('R1: the record at %s.json names review %r' % (review_id, rec.get('review_id')))
    if rec.get('status') != 'FINALIZED':
        why.append('R2: the review is %s, not FINALIZED' % rec.get('status'))
    if rec.get('evidence_set_sha256') != evidence_sha:
        why.append('R3: the concurrence covers evidence set %s and this call is %s: what will be written is not what '
                   'was concurred with' % (str(rec.get('evidence_set_sha256'))[:16], evidence_sha[:16]))
    who = _s(rec.get('concurred_by')).lower()
    out['concurred_by'] = who
    if approvers is None:
        why.append('R4: %s' % approvers_note)
    elif who not in approvers:
        why.append('R4: %s is not on the review approver list (%s)' % (who, approvers_note))
    roles = {'submitter': rec.get('submitted_by'), 'run_started_by': rec.get('run_started_by'),
             'triager': rec.get('triaged_by'), 'caller': list(excluded or [])}
    out['roles'] = dict((k, v) for k, v in roles.items() if v)
    viol = sod.violations(roles, rec.get('concurred_by'))
    if viol:
        why.append('R5 %s: %s -- nobody approves their own work, review or triage' % (sod.SOD_SELF_APPROVAL,
                                                                                      sod.describe(viol)))
    d = None
    try:
        d = datetime.date.fromisoformat(rec.get('concurred_on') or '')
    except ValueError:
        pass
    td = datetime.date.fromisoformat(today) if today else datetime.date.today()
    if d is None:
        why.append('R6: concurred_on %r is not a calendar date' % rec.get('concurred_on'))
    elif d > td:
        why.append('R6: concurred_on %s is in the future' % d)
    elif (td - d).days > max_age_days:
        why.append('R6: the concurrence of %s is %d day(s) old; the maximum is %d' % (d, (td - d).days, max_age_days))
    if not why:
        ok, w, facts = _pr_approval(client, repo, branch, '%s/%s.json' % (RECORD_DIR, review_id), who)
        out['facts'] = facts
        if not ok:
            why.append('R7: %s' % w)
    if not why:
        out['state'] = REVIEW_FINALIZED
    return out

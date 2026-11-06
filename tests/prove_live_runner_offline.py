#!/usr/bin/env python3
"""The live R-1/R-2 runner, proven OFFLINE: it refuses to start when it should, blocks writes in
R-1, and never puts a credential in its transcript.

tests/live_ticketing_run.py is run by a person against a PERSONAL tracker. Its safety properties
must not wait for that run to be discovered, so this drives its real main() in-process with
urllib.request.urlopen replaced by the stateful Jira stand-in from tests/prove_ticket_backends.py.
No request can leave the machine. Placeholder values only.

    refuse   a required value missing -> exit 2, named, ZERO requests
             no --confirm-live        -> exit 2, ZERO requests
    R-1      wrong host, bad token, missing project, missing stamp field, missing reopen
             transition (T-24): each refused BY NAME; every write the runner saw was blocked
             before it left
    R-2      two runs then a join then a narrowing: creations [1, 0, 0, 0]
    redact   the transcript holds neither the token nor the account email

EXIT  0 proven  1 a case failed  2 could not be checked
"""
import base64
import io
import os
import shutil
import sys
import tempfile
import urllib.request

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, HERE)
sys.path.insert(0, os.path.join(ROOT, 'scripts'))

TOKEN = 'placeholder-live-token-0123'
EMAIL = 'owner@personal.invalid'
ENV = dict(TICKET_BACKEND='jira', JIRA_HOST='https://example.atlassian.net', JIRA_EMAIL=EMAIL,
           JIRA_TOKEN=TOKEN, JIRA_PROJECT='KIT', JIRA_STAMP_FIELD='customfield_10001',
           JIRA_EPIC_ID='10000', JIRA_CALIBRATION_ISSUE='10002', TICKET_CREATE_CEILING='25',
           # The other tracker's values sit in the same .env, as on the owner's machine.
           AZDO_PAT='placeholder-other-pat', AZDO_ORG='https://dev.azure.com/example',
           AZDO_PROJECT='kit')


def write_env(d, values):
    p = os.path.join(d, '.env')
    io.open(p, 'w', encoding='utf-8').write(''.join('%s=%s\n' % kv for kv in values.items()))
    return p


def main():
    try:
        import prove_ticket_backends as P
        import live_ticketing_run as L
        import reconcile_tickets as rt
    except Exception as exc:                          # noqa: BLE001
        print('UNKNOWN: could not import: %s' % exc)
        return 2
    real = urllib.request.urlopen
    fails = []
    tmp = tempfile.mkdtemp(prefix='live-runner-offline-')
    rt._sleep = lambda s: None
    try:
        # REFUSALS, with zero requests.
        for label, values, args, needle in (
                ('a required value missing', dict((k, v) for k, v in ENV.items()
                                                  if k != 'JIRA_EPIC_ID'),
                 ['--confirm-live'], 'JIRA_EPIC_ID'),
                ('no --confirm-live', ENV, [], '--confirm-live')):
            r = P.install(P.Replay())
            d = tempfile.mkdtemp(dir=tmp)
            rc = L.main(['--backend', 'jira', '--env-file', write_env(d, values)] + args)
            if rc != 2 or r.requests:
                fails.append('%s: exit %d with %d request(s); expected 2 and none'
                             % (label, rc, len(r.requests)))

        # R-1: a stand-in that checks the credential, so a bad token is refused like the real one.
        good = 'Basic ' + base64.b64encode(('%s:%s' % (EMAIL, TOKEN)).encode()).decode()
        r = P.install(P.Replay())
        P.JiraTracker(r)
        inner = P.Replay.__call__

        def authed(self, req, timeout=None, **kw):
            import urllib.error
            # Another host does not exist here, exactly as a wrong host does not resolve live.
            if not req.full_url.startswith(ENV['JIRA_HOST'] + '/'):
                raise urllib.error.URLError('host does not resolve')
            if dict(req.header_items()).get('Authorization') != good:
                raise urllib.error.HTTPError(req.full_url, 401, 'unauthorized', {}, io.BytesIO(b''))
            try:
                return inner(self, req, timeout, **kw)
            except urllib.error.HTTPError:
                raise
            except urllib.error.URLError:
                # On the right host, an unscripted path is what Jira answers 404 to.
                raise urllib.error.HTTPError(req.full_url, 404, 'not found', {}, io.BytesIO(b''))
        P.Replay.__call__ = authed
        d = tempfile.mkdtemp(dir=tmp)
        rc = L.main(['--backend', 'jira', '--env-file', write_env(d, ENV), '--confirm-live',
                     '--phase', 'r1', '--run-dir', d])
        P.Replay.__call__ = inner
        if rc != 0:
            fails.append('R-1 offline: the four broken values were not all refused by name '
                         '(exit %d)' % rc)
        writes = [q for q in r.requests if q['method'] in ('PUT', 'PATCH') or (
            q['method'] == 'POST' and not q['url'].endswith('/search/jql'))]
        if writes:
            fails.append('R-1 offline: %d write(s) reached the tracker' % len(writes))
        transcripts = [os.path.join(d, f) for f in os.listdir(d) if f.startswith('transcript')]
        # T-24 / TICKETING_BACKENDS.md R-1: FIVE breaks, the fifth a missing reopen transition.
        # The live runner used to break four settings and never the transition, so a site with
        # no transition of that name was first discovered on a real closed ticket.
        r1_text = ''.join(io.open(p, encoding='utf-8').read() for p in transcripts)
        for var in ('JIRA_HOST', 'JIRA_TOKEN', 'JIRA_PROJECT', 'JIRA_STAMP_FIELD',
                    'JIRA_TRANSITION_REOPEN'):
            if not any(ln.strip().startswith('R-1  %s ' % var) and 'REFUSED (named)' in ln
                       for ln in r1_text.splitlines()):
                fails.append('R-1 offline: %s was not broken and refused by name (T-24)' % var)

        # R-2: two runs, a join, a narrowing -> [1, 0, 0, 0].
        r = P.install(P.Replay())
        t = P.JiraTracker(r)
        d2 = tempfile.mkdtemp(dir=tmp)
        rc = L.main(['--backend', 'jira', '--env-file', write_env(d2, ENV), '--confirm-live',
                     '--phase', 'r2', '--run-dir', d2])
        stories = [i for i in t.issues.values() if i['type'] == 'Story']
        if rc != 0 or len(stories) != 1:
            fails.append('R-2 offline: exit %d with %d ticket(s); expected 0 and exactly 1'
                         % (rc, len(stories)))
        r2_transcripts = [os.path.join(d2, f) for f in os.listdir(d2)
                          if f.startswith('transcript')]
        # T-02: the runner put a person's note before and after the block, the joined run
        # updated the block, and the runner read the notes back intact -- and said so.
        r2_text = ''.join(io.open(p, encoding='utf-8').read() for p in r2_transcripts)
        for after in ('T-2 joined', 'T-2 narrowed'):
            if 'T-02 check   HELD after %s' % after not in r2_text:
                fails.append('R-2 offline: the transcript does not record the T-02 human-text '
                             'check as HELD after %s' % after)
        # T-13: the narrowing is a delta -- the departed member is marked on the ticket.
        if stories and 'POTENTIALLY_ABSENT' not in P.adf_text(stories[0].get('description')):
            fails.append('R-2 offline: after the narrowing the ticket does not mark the departed '
                         'member POTENTIALLY_ABSENT (T-13)')
        if stories and 'Human note BEFORE the block' not in P.adf_text(
                stories[0].get('description')):
            fails.append('R-2 offline: the human note is not on the ticket after the joined run')
        transcripts += r2_transcripts

        # R-3 (KDEC-024): the lifecycle on one ticket -- NEW, escalation, clearance close,
        # RECURRED, close again -- ends with exactly one ticket, CLOSED.
        r = P.install(P.Replay())
        t = P.JiraTracker(r)
        d3 = tempfile.mkdtemp(dir=tmp)
        rc = L.main(['--backend', 'jira', '--env-file', write_env(
            d3, dict(ENV, JIRA_TRANSITION_REOPEN='Reopen')), '--confirm-live', '--phase', 'r3',
                     '--run-dir', d3])
        stories = [i for i in t.issues.values() if i['type'] == 'Story']
        if rc != 0 or len(stories) != 1 or (stories[0]['fields']['status'].get(
                'statusCategory') or {}).get('key') != 'done':
            fails.append('R-3 offline: exit %d with %d ticket(s); expected 0 and exactly one, '
                         'closed' % (rc, len(stories)))
        transcripts += [os.path.join(d3, f) for f in os.listdir(d3) if f.startswith('transcript')]

        # REDACTION: no credential, in any transcript.
        if not transcripts:
            fails.append('no transcript was written')
        for p in transcripts:
            text = io.open(p, encoding='utf-8').read()
            for what, val in (('the token', TOKEN), ('the account email', EMAIL),
                              ('the OTHER tracker\'s PAT', 'placeholder-other-pat')):
                if val in text:
                    fails.append('%s appears in %s' % (what, os.path.basename(p)))
    finally:
        urllib.request.urlopen = real
        shutil.rmtree(tmp, ignore_errors=True)
    if fails:
        for i, f in enumerate(fails, 1):
            print('  %d. %s' % (i, f))
        print('::error title=Live runner unsafe::%d failure(s)' % len(fails))
        return 1
    print('live runner, offline: refuses without a required value or --confirm-live (no request '
          'made); R-1 refuses all five broken values by name, the missing reopen transition '
          'included, with every write blocked; R-2 makes one ticket over four runs and keeps a '
          'person\'s note around the block (T-02); no transcript holds a credential.')
    return 0


if __name__ == '__main__':
    sys.exit(main())

#!/usr/bin/env python3
"""TICKETING_BACKENDS.md R-1 and R-2, against the OWNER'S PERSONAL Jira or Azure DevOps. Run by a
person, with a transcript. Never against a consumer's tracker; never in CI.

WHAT IT DOES

    R-1  live REFUSALS. The configuration is broken one value at a time -- wrong host, bad token,
         missing project, missing stamp field, missing reopen transition (Jira) or state (Azure
         DevOps) -- and each must be refused BY NAME. The transition is tried on the calibration
         ticket (reads only), since Jira offers transitions per issue, not at run start.
         Every write is BLOCKED in this phase by the runner itself, so a refusal that failed to
         happen cannot write anything.
    R-2  live BEHAVIOUR on real tickets, with a ledger kept beside the transcript:
           T-1  two runs over the same synthetic finding: the second creates nothing
           T-2  a narrowed membership: nothing new
           T-02 before the "joined" run the RUNNER, standing in for a person, writes a note
                before and after the machine-owned block; after it, both notes must still be
                there with the block updated between them (completion ledger row T-02)
         and, after a PERSON acts on the ticket the run printed (the bridge has no delete and no
         way to duplicate or close by itself -- by design):
           T-6  a person duplicates the ticket with the stamp     -> BINDING_AMBIGUOUS
           T-7  a person closes it with nothing backing it        -> reopened
           T-8  a person makes the reopen refusable               -> successor, predecessor kept
         Cleanup is by a person: the bridge cannot delete, and the transcript lists every ticket.

SAFETY

    * It refuses to start unless EVERY required variable for the chosen backend is present
      (scripts/check_env.py's list), naming each missing one.
    * It refuses to touch the network without --confirm-live.
    * Only the chosen backend's values are passed to the bridge, so a .env holding both trackers
      is not refused as two backends (C-2) and the other credential is never in reach.
    * The transcript never contains a credential: every value of a *TOKEN*, *PAT*, *EMAIL* or
      *PASSWORD* variable is replaced before anything is printed or written.
    * The synthetic findings carry a per-run marker, so its tickets are recognisable for cleanup.

USAGE
    python tests/live_ticketing_run.py --backend jira --env-file .env --confirm-live --phase r1
    python tests/live_ticketing_run.py --backend azdo --env-file .env --confirm-live --phase r2
    python tests/live_ticketing_run.py --backend jira --env-file .env --confirm-live \
        --phase r2-after-human --run-dir <dir printed by the r2 run>

EXIT  0 every check held   1 a check failed   2 refused to start (missing value, no
      --confirm-live, misuse)
"""
import argparse
import io
import json
import os
import sys
import tempfile
import time
import urllib.error
import urllib.request

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, os.path.join(ROOT, 'scripts'))

SECRET_MARKERS = ('TOKEN', 'PAT', 'EMAIL', 'PASSWORD', 'SECRET')
SHARED = ('TICKET_BACKEND', 'TICKET_STAMP_LABEL', 'TICKET_CREATE_CEILING', 'TICKET_RETRY_CEILING',
          'TICKET_INSTANCE_THRESHOLD', 'TICKET_DEGRADED_RUN_THRESHOLD')
PREFIX = {'jira': 'JIRA_', 'azdo': 'AZDO_'}


class Transcript(object):
    def __init__(self, path, secrets):
        self.path = path
        self.secrets = sorted((s for s in secrets if s), key=len, reverse=True)
        self.lines = []

    def clean(self, text):
        text = str(text)
        for s in self.secrets:
            text = text.replace(s, '<redacted>')
        return text

    def say(self, text=''):
        line = self.clean(text)
        self.lines.append(line)
        print(line)

    def save(self):
        io.open(self.path, 'w', encoding='utf-8').write('\n'.join(self.lines) + '\n')


class WriteBlocker(object):
    """Wraps urlopen. In R-1 every non-read request is refused BEFORE it leaves the machine."""

    def __init__(self, inner):
        self.inner = inner
        self.block_writes = False
        self.blocked = []
        self.calls = 0

    def __call__(self, req, *a, **kw):
        self.calls += 1
        method = req.get_method()
        reads = method == 'GET' or (method == 'POST' and any(
            p in req.full_url for p in ('/search/jql', '/_apis/wit/wiql', '/workitemsbatch')))
        if self.block_writes and not reads:
            self.blocked.append('%s %s' % (method, req.full_url))
            raise urllib.error.URLError('R-1 write blocked by the runner')
        return self.inner(req, *a, **kw)


def backend_env(values, backend):
    env = dict((k, v) for k, v in values.items()
               if k.startswith(PREFIX[backend]) or k in SHARED)
    if backend == 'azdo' and not env.get('AZDO_ORG_URL') and values.get('AZDO_ORG'):
        env['AZDO_ORG_URL'] = values['AZDO_ORG']
    env['TICKET_BACKEND'] = backend
    return env


def synthetic(marker, members):
    import reconcile_tickets as rt
    recs = {'a': rt._rec('kit-live-test', 'LIVE-%s' % marker, 'live/%s/a.txt' % marker,
                         'live-%s-a' % marker, aliases=['live-%s' % marker, 'live-%s-b' % marker],
                         severity='low'),
            'b': rt._rec('kit-live-test-2', 'LIVE-%s-B' % marker, 'live/%s/a.txt' % marker,
                         'live-%s-b' % marker, aliases=['live-%s-b' % marker, 'live-%s' % marker],
                         severity='low')}
    return [recs[m] for m in members]


def r1(rt, env, backend, tr, blocker):
    """Each broken value is refused BY NAME, with writes blocked."""
    blocker.block_writes = True
    breaks = {
        'jira': [('JIRA_HOST', 'https://kit-r1-wrong-host.invalid', 'JIRA_HOST'),
                 ('JIRA_TOKEN', 'r1-not-a-token', 'JIRA_TOKEN'),
                 ('JIRA_PROJECT', 'ZZR1NOPE', 'JIRA_PROJECT'),
                 ('JIRA_STAMP_FIELD', 'customfield_1', 'JIRA_STAMP_FIELD'),
                 # T-24: the FIFTH break. Jira's transitions are per issue and per status, so a
                 # missing reopen transition cannot be established at run start; it is exercised
                 # on the calibration ticket, reads only, with every write blocked.
                 ('JIRA_TRANSITION_REOPEN', 'kit-r1-no-such-transition',
                  'JIRA_TRANSITION_REOPEN')],
        'azdo': [('AZDO_ORG_URL', 'https://dev.azure.com/kit-r1-no-such-org', 'AZDO_ORG_URL'),
                 ('AZDO_PAT', 'r1-not-a-pat', 'AZDO_PAT'),
                 ('AZDO_PROJECT', 'zz-r1-nope', 'AZDO_PROJECT'),
                 ('AZDO_STAMP_FIELD', 'Custom.KitR1NoSuchField', 'AZDO_STAMP_FIELD'),
                 # T-24: the fifth break. Azure DevOps states are per type, so run start refuses.
                 ('AZDO_STATE_REOPEN', 'kit-r1-no-such-state', 'AZDO_STATE_REOPEN')],
    }[backend]
    ok = True
    for var, bad, named in breaks:
        e = dict(env, **{var: bad})
        b, note = rt.choose_backend(e)
        if b is None:
            refused, detail = True, note
        else:
            good, detail = b.validate()
            refused = not good
            if good and var == 'JIRA_TRANSITION_REOPEN':
                # The shape is fine; the reopen is what must refuse, by name, and write nothing.
                cal = (e.get('JIRA_CALIBRATION_ISSUE') or '').strip()
                reopened, detail = b.reopen(cal) if cal else (
                    False, 'JIRA_CALIBRATION_ISSUE is unset, so the reopen could not be tried')
                refused = not reopened
        by_name = named in detail
        tr.say('R-1  %-18s broken -> %s %s' % (var, 'REFUSED' if refused else 'ACCEPTED',
                                                 '(named)' if by_name else '(NOT named)'))
        tr.say('       %s' % detail)
        ok = ok and refused and by_name
    tr.say('R-1  writes attempted and blocked by the runner: %d' % len(blocker.blocked))
    blocker.block_writes = False
    return ok and not blocker.blocked


HUMAN_BEFORE = 'Human note BEFORE the block (kit live test %s): must survive every kit update.'
HUMAN_AFTER = 'Human note AFTER the block (kit live test %s): must survive every kit update.'


def add_human_text(rt, b, ref, marker):
    """T-02 live: the RUNNER, standing in for a person and saying so in the transcript, writes a
    note before and after the machine-owned block. -> (ok, detail). The bridge never does this;
    it is the fixture the next run's members-added update must not erase."""
    desc, ok, detail = b.read_description(ref)
    if not ok:
        return False, 'could not read ticket %s to add the human note: %s' % (ref, detail)
    before, after = HUMAN_BEFORE % marker, HUMAN_AFTER % marker
    if b.name == 'jira':
        para = lambda t: {'type': 'paragraph', 'content': [{'type': 'text', 'text': t}]}  # noqa
        doc = dict(desc or {'type': 'doc', 'version': 1})
        doc['content'] = [para(before)] + list(doc.get('content') or []) + [para(after)]
        new = doc
    else:
        new = dict(desc or {}, html='<p>%s</p>%s<p>%s</p>' % (before, (desc or {}).get(
            'html') or '', after))
    good, detail = b.write_description(ref, new, desc)
    return good, detail


def human_text_held(rt, b, ref, marker, joined_identity):
    """-> (held, detail): both human notes still there, and the joined member in the block."""
    desc, ok, detail = b.read_description(ref)
    if not ok:
        return False, 'could not read ticket %s back: %s' % (ref, detail)
    text = b.description_text(desc)
    lines = [ln.strip() for ln in text.split('\n')]
    missing = [w for w, t in (('before', HUMAN_BEFORE % marker), ('after', HUMAN_AFTER % marker))
               if t not in lines]
    if missing:
        return False, 'the human note(s) %s were ERASED by the kit update' % ', '.join(missing)
    if joined_identity not in text:
        return False, 'the joined member %s is not in the block' % joined_identity
    # The block's first and last lines both name the machine-owned block.
    edges = [n for n, ln in enumerate(lines) if 'machine-owned block' in ln]
    if not edges or lines.index(HUMAN_BEFORE % marker) > edges[0] or \
            lines.index(HUMAN_AFTER % marker) < edges[-1]:
        return False, 'the human notes are no longer before and after the block'
    return True, 'both human notes intact, the block updated between them'


def r2(rt, env, tr, run_dir):
    marker = time.strftime('%Y%m%d%H%M%S')
    ledger_path = os.path.join(run_dir, 'ledger.json')
    io.open(os.path.join(run_dir, 'marker'), 'w').write(marker)
    ledger = {}
    ok = True
    counts = []
    for label, members in (('T-1 run 1', 'a'), ('T-1 run 2', 'a'), ('T-2 joined', 'ab'),
                           ('T-2 narrowed', 'b')):
        b, note = rt.choose_backend(env)
        if b is None:
            tr.say('R-2 refused: %s' % note)
            return False
        ref = next((e.get('ref') for e in ledger.values() if e.get('ref')), None)
        if label == 'T-2 joined':
            # T-02: human text around the block BEFORE the members-added update.
            good, detail = add_human_text(rt, b, ref, marker) if ref else (False, 'no ticket')
            tr.say('R-2  T-02 setup   the runner, standing in for a person, wrote a note before '
                   'and after the block of ticket %s: %s' % (ref, detail))
            ok = ok and good
        res = rt.reconcile(*rt.build_clusters(synthetic(marker, members)), backend=b,
                           ledger=ledger, apply_changes=True, today=time.strftime('%Y-%m-%d'))
        made = [c for c in res['created'] if c.get('ref')]
        counts.append(len(made))
        tr.say('R-2  %-14s created %d, outcomes %s, claim %s, calls %s, throttles %d'
               % (label, len(made), json.dumps(res['outcomes'], sort_keys=True),
                  (res.get('ticketing_claim') or {}).get('routing_result'), res.get('calls'),
                  len(res.get('throttles') or [])))
        for c in made:
            tr.say('       ticket %s  (cleanup by a person: the bridge has no delete)' % c['ref'])
        if label in ('T-2 joined', 'T-2 narrowed') and ref:
            # After the join (a members-added write) AND after the narrowing (a T-13 write that
            # marks the departed member POTENTIALLY_ABSENT), the person's notes are intact.
            held, detail = human_text_held(rt, b, ref, marker, 'live-%s-b' % marker)
            tr.say('R-2  T-02 check   %s after %s: %s' % ('HELD' if held else 'FAILED', label,
                                                         detail))
            ok = ok and held
    rt.save_ledger(ledger_path, ledger)
    if counts != [1, 0, 0, 0]:
        tr.say('R-2  FAIL: creations per run %r, expected [1, 0, 0, 0] (T-1, T-2)' % counts)
        ok = False
    ref = next((e.get('ref') for e in ledger.values() if e.get('ref')), None)
    tr.say('')
    tr.say('NEXT, BY A PERSON, on ticket %s, then rerun with --phase r2-after-human --run-dir %s:'
           % (ref, run_dir))
    tr.say('  T-6  duplicate it WITH its stamp (or set the stamp on another ticket)')
    tr.say('  T-7  or: close it with nothing backing it -> the rerun must reopen it')
    tr.say('  T-8  or: close it where no reopen transition/state is permitted -> successor')
    return ok


def r2_after_human(rt, env, tr, run_dir):
    marker = io.open(os.path.join(run_dir, 'marker')).read().strip()
    ledger_path = os.path.join(run_dir, 'ledger.json')
    ledger, note = rt.load_ledger(ledger_path)
    if not ledger:
        tr.say('no ledger at %s: run --phase r2 first' % ledger_path)
        return False
    b, note = rt.choose_backend(env)
    if b is None:
        tr.say('refused: %s' % note)
        return False
    res = rt.reconcile(*rt.build_clusters(synthetic(marker, 'b')), backend=b, ledger=ledger,
                       apply_changes=True, today=time.strftime('%Y-%m-%d'))
    rt.save_ledger(ledger_path, ledger)
    tr.say('R-2  after the human act: outcomes %s' % json.dumps(res['outcomes'], sort_keys=True))
    tr.say('     ambiguous candidates: %s' % [d.get('candidates') for d in res['needs_decision']])
    tr.say('     reopened: %s' % res.get('reopened'))
    tr.say('     successors: %s' % res.get('successors'))
    tr.say('     A PERSON records which of T-6 / T-7 / T-8 this exercised and whether it held.')
    return bool(res['outcomes'].get(rt.BINDING_AMBIGUOUS) or res.get('reopened')
                or res.get('successors'))


def main(argv=None):
    ap = argparse.ArgumentParser(description='Live R-1/R-2 against a PERSONAL tracker.')
    ap.add_argument('--backend', choices=['jira', 'azdo'], required=True)
    ap.add_argument('--env-file', default=os.path.join(ROOT, '.env'))
    ap.add_argument('--phase', choices=['r1', 'r2', 'r2-after-human'], default='r1')
    ap.add_argument('--run-dir', default='')
    ap.add_argument('--confirm-live', action='store_true',
                    help='required: this contacts the tracker the .env names')
    args = ap.parse_args(argv)

    import check_env
    if not os.path.exists(args.env_file):
        print('REFUSED: no env file at %s' % args.env_file)
        return 2
    values = check_env.load(args.env_file)
    alias = check_env.ALIASES
    missing = [k for k in check_env.REQUIRED[args.backend]
               if not (values.get(k) or values.get(alias.get(k, '')))]
    if missing:
        print('REFUSED: required for %s and missing: %s' % (args.backend, ', '.join(missing)))
        return 2
    if not args.confirm_live:
        print('REFUSED: --confirm-live not given. This contacts the tracker the env file names; '
              'say so explicitly.')
        return 2

    import reconcile_tickets as rt
    env = backend_env(values, args.backend)
    secrets = [v for k, v in values.items() if any(m in k for m in SECRET_MARKERS)]
    run_dir = args.run_dir or tempfile.mkdtemp(prefix='kit-live-%s-' % args.backend)
    tr = Transcript(os.path.join(run_dir, 'transcript-%s-%s.txt'
                                 % (args.phase, time.strftime('%Y%m%dT%H%M%S'))), secrets)
    blocker = WriteBlocker(urllib.request.urlopen)
    urllib.request.urlopen = blocker
    try:
        tr.say('live ticketing run: backend %s, phase %s, %s' % (args.backend, args.phase,
                                                                time.strftime('%Y-%m-%dT%H:%M:%S')))
        tr.say('effective configuration (credentials redacted):')
        for k in sorted(env):
            tr.say('  %-26s %s' % (k, env[k]))
        if args.phase == 'r1':
            ok = r1(rt, env, args.backend, tr, blocker)
        elif args.phase == 'r2':
            ok = r2(rt, env, tr, run_dir)
        else:
            ok = r2_after_human(rt, env, tr, run_dir)
        tr.say('RESULT: %s' % ('HELD' if ok else 'FAILED'))
        tr.say('transcript: %s' % tr.path)
    finally:
        urllib.request.urlopen = blocker.inner
        tr.save()
    return 0 if ok else 1


if __name__ == '__main__':
    sys.exit(main())

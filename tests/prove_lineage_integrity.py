#!/usr/bin/env python3
"""The lineage ledger's integrity claim, tested at the edges the chain alone cannot see (L51).

WHY THIS EXISTS (G1-7 / T6, confirmed by reading; N34)

    scripts/finding_lineage.py says removing, editing or reordering a line breaks the chain and
    `--verify` reports LEDGER_TAMPERED. That is true for every line but the LAST: the chain is
    anchored only at its first event, so deleting the final N events leaves a perfectly valid
    shorter chain and the ledger reads LEDGER_INTACT. The operator deletes the last SUPERSEDES
    event, the carried approval it enabled silently disappears -- or, run the other way, a rewritten
    tail carries an approval nobody made -- and verification says all is well.

    So this asserts, on ledgers written by the real append_event and read by the real load():

      HEAD ANCHORING
        a truncated tail is LEDGER_TAMPERED and says the tail was truncated
        a removed head anchor is LEDGER_TAMPERED (a ledger that cannot exclude truncation is not
          intact)
        a ledger emptied, or deleted, under a head that says it had events is LEDGER_TAMPERED
        an EXTERNAL anchor (the head event id as recorded on the protected branch) that disagrees
          with the ledger is LEDGER_TAMPERED even when the local head file was rewritten to match
        and the allowed case: a ledger written only by append_event is LEDGER_INTACT

      RESOLUTION REFUSES WHAT IT CANNOT TRUST
        `--resolve` on a tampered, truncated, unparseable or absent ledger exits non-zero and
          prints no resolution (it used to skip the integrity check and exit 0)
        disposition_for(..., integrity=<not intact>) carries no approval through the ledger

EXIT  0 proven   1 a case failed (named)   2 could not be checked (UNKNOWN, never PASS)
"""
import io
import json
import os
import shutil
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
SCRIPT = os.path.join(ROOT, 'scripts', 'finding_lineage.py')
sys.path.insert(0, os.path.join(ROOT, 'scripts'))


def main():
    try:
        import finding_lineage as fl
    except ImportError as exc:
        print('UNKNOWN: cannot import finding_lineage: %s' % exc)
        return 2

    fails = []

    def check(cond, msg):
        if not cond:
            fails.append(msg)

    work = tempfile.mkdtemp(prefix='lineage-integrity-')
    try:
        def fresh(name, n=3):
            path = os.path.join(work, name, 'lineage.jsonl')
            ids = ['%x' % (i + 10) * 64 for i in range(n + 1)]
            for i in range(n):
                eid, bad = fl.append_event(path, fl._mkevent(ids[i][:64], ids[i + 1][:64]))
                if bad:
                    raise RuntimeError('fixture append refused: %r' % bad)
            return path

        def lines_of(path):
            return io.open(path, encoding='utf-8').read().splitlines()

        def write_lines(path, lines):
            with io.open(path, 'w', encoding='utf-8', newline='\n') as fh:
                fh.write(''.join(l + '\n' for l in lines))

        # allowed
        ok = fresh('ok')
        _e, state, notes = fl.load(ok)
        check(state == fl.LEDGER_INTACT, 'allowed: an append_event-only ledger is %r (%s)'
              % (state, notes))
        events, _s, _n = fl.load(ok)
        head_id = events[-1]['event_id'] if events else ''
        check(bool(head_id), 'allowed: the fixture has no head event id, so nothing below is real')

        # tail truncation, head file left in place
        trunc = fresh('trunc')
        write_lines(trunc, lines_of(trunc)[:-1])
        _e, state, notes = fl.load(trunc)
        check(state == fl.LEDGER_TAMPERED,
              'tail truncation: deleting the LAST event left the ledger %r -- the chain is anchored '
              'only at its first event' % state)
        check(any('trunc' in n.lower() or 'head' in n.lower() for n in notes),
              'tail truncation was refused without naming the head anchor or the truncation: %r'
              % notes)

        # head anchor removed
        nohead = fresh('nohead')
        head_file = fl.head_path(nohead) if hasattr(fl, 'head_path') else nohead + '.head'
        if os.path.exists(head_file):
            os.remove(head_file)
        _e, state, notes = fl.load(nohead)
        check(state == fl.LEDGER_TAMPERED,
              'head anchor removed: the ledger read %r. Without an anchor a truncated tail cannot '
              'be excluded, so it is not intact' % state)

        # emptied under a head that says otherwise
        emptied = fresh('emptied')
        write_lines(emptied, [])
        _e, state, _n = fl.load(emptied)
        check(state == fl.LEDGER_TAMPERED, 'a ledger emptied under its head read %r' % state)
        deleted = fresh('deleted')
        os.remove(deleted)
        _e, state, _n = fl.load(deleted)
        check(state == fl.LEDGER_TAMPERED,
              'a ledger deleted under its head read %r -- that is not "nobody keeps one"' % state)

        # truncation with the local head rewritten to match: only an external anchor sees it
        forged = fresh('forged')
        full_events, _s2, _n2 = fl.load(forged)
        external = full_events[-1]['event_id']
        write_lines(forged, lines_of(forged)[:-1])
        short, _s3, _n3 = fl.load(forged)
        if short:
            with io.open(fl.head_path(forged) if hasattr(fl, 'head_path') else forged + '.head',
                         'w', encoding='utf-8') as fh:
                json.dump({'schema_version': 1, 'event_count': len(short),
                           'head_event_id': short[-1]['event_id']}, fh)
        _e, state, notes = fl.load(forged, expected_head=external) \
            if 'expected_head' in fl.load.__code__.co_varnames else (None, None, [])
        check(state == fl.LEDGER_TAMPERED,
              'a truncation with a forged local head was %r against the protected-branch anchor'
              % state)
        _e, state, _n = fl.load(ok, expected_head=head_id) \
            if 'expected_head' in fl.load.__code__.co_varnames else (None, None, [])
        check(state == fl.LEDGER_INTACT, 'allowed: a matching external anchor read %r' % state)

        # ── RESOLVE REFUSES A LEDGER IT CANNOT TRUST (G1-7 defect 2) ──────────
        # `--resolve` used to skip the integrity check entirely: on a TAMPERED or UNPARSEABLE
        # ledger it resolved anyway and exited 0. A resolution read from a ledger nobody can verify
        # is an answer manufactured from a broken record.
        def cli(*args):
            p = subprocess.run([sys.executable, SCRIPT] + list(args), capture_output=True,
                               text=True)
            return p.returncode, p.stdout + p.stderr

        first = events[0]['from_identities'][0] if events else ''
        check(bool(first), 'resolve fixture has no identity to resolve')
        rc, out = cli('--ledger', ok, '--resolve', first)
        check(rc == 0 and 'LINEAGE_RESOLVED' in out,
              'allowed: --resolve on an intact ledger gave rc=%s: %s' % (rc, out[-200:]))
        edited = fresh('edited-for-resolve')
        ls = lines_of(edited)
        body = json.loads(ls[1])
        body['cause_detail'] = 'rewritten after the fact'
        ls[1] = json.dumps(body, sort_keys=True)
        write_lines(edited, ls)
        garbage = fresh('garbage-for-resolve')
        write_lines(garbage, lines_of(garbage)[:1] + ['not json'])
        for label, path in (('a TAMPERED (edited) ledger', edited), ('a truncated tail', trunc),
                            ('an UNPARSEABLE ledger', garbage),
                            ('an ABSENT ledger', os.path.join(work, 'none', 'lineage.jsonl'))):
            rc, out = cli('--ledger', path, '--resolve', first)
            check(rc != 0, 'attack: --resolve on %s exited %s -- it resolved against a record '
                           'nobody can verify' % (label, rc))
            check('LINEAGE_RESOLVED' not in out and 'LINEAGE_TERMINAL' not in out,
                  'attack: --resolve on %s still printed a resolution: %s' % (label, out[-200:]))
        # The library carry refuses too, when told the integrity it was read under.
        reg = {first: {'disposition_type': 'ACCEPTED_RISK'}}
        tampered_events, tstate, _tn = fl.load(edited)
        got = fl.disposition_for(tampered_events, reg, events[-1]['to_identities'][0],
                                 integrity=tstate) \
            if 'integrity' in fl.disposition_for.__code__.co_varnames else {'basis': None}
        check(got['basis'] == fl.DISPOSITION_NOT_FOUND,
              'attack: a disposition was carried through a %s ledger (%r)' % (tstate, got['basis']))

        # ── VERIFY'S EXIT CODE IS THE ONLY THING A SCHEDULER READS (G1-7 defect 3) ──
        # `--verify` returned 1 for LEDGER_TAMPERED only. An unparseable ledger, and one that does
        # not exist, "verified" with exit 0 -- corruption and absence read as clean by any caller
        # that checks the exit code.
        empty_path = os.path.join(work, 'empty', 'lineage.jsonl')
        os.makedirs(os.path.dirname(empty_path))
        write_lines(empty_path, [])
        for label, path, want_zero in (('an intact ledger', ok, True),
                                       ('an empty ledger', empty_path, True),
                                       ('an UNPARSEABLE ledger', garbage, False),
                                       ('an ABSENT ledger', os.path.join(work, 'nope', 'l.jsonl'), False),
                                       ('a TAMPERED ledger', edited, False)):
            rc, out = cli('--ledger', path, '--verify')
            check((rc == 0) == want_zero,
                  '--verify on %s exited %s, expected %s' % (label, rc, '0' if want_zero else
                                                            'non-zero'))
    except RuntimeError as exc:
        print('UNKNOWN: %s' % exc)
        return 2
    finally:
        shutil.rmtree(work, ignore_errors=True)

    if fails:
        for f in fails:
            print('FAIL: ' + f)
        return 1
    print('PASS: a ledger written by append_event is INTACT; a truncated tail, a removed head '
          'anchor, an emptied or deleted ledger under its head, and a truncation hidden by a forged '
          'local head (seen through the protected-branch anchor) are all LEDGER_TAMPERED; '
          '--resolve refuses a tampered, truncated, unparseable or absent ledger with a non-zero '
          'exit and no resolution, and no disposition is carried through one.')
    return 0


if __name__ == '__main__':
    sys.exit(main())

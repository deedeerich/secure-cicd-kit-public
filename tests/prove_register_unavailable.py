#!/usr/bin/env python3
"""THE REGISTER STATE TRAVELS (lane ticket-defaults, 2026-11-13; reviewer concern on KDEC-049 R1).

When the ticket ledger (the register) is missing or unreadable, the condition must stay EXPLICIT through every
consumer of the external-findings pull -- the receipt, every item (`baseline.register`), the batches the review
concurs with, the ticket text, tickets.submit's routing and the reusable workflow's output -- never a log line.
A missing register is not an empty one: no unmatched item is classified as definitively new without it.

    P1  readable ledger: REGISTER_READ on the receipt and every item; a bound cluster MATCHES (the register is
        really used); no item is listed new_not_established; submit adds no register label
    N1  --register names a path with no file: REGISTER_NOT_ESTABLISHED on the receipt and every item; every
        unmatched item is listed new_not_established; the output says so; submit routes to triage
    N2  no --register at all: REGISTER_NOT_ESTABLISHED, the same
    N3  an unreadable ledger: REGISTER_UNREADABLE and BASELINE_UNAVAILABLE on the receipt and every item
    C1  the batches (the review's evidence set) and the ticket facts carry the register state
    W1  reusable-external-findings.yml exposes register_state and annotates anything but REGISTER_READ
    Mutants (each must be caught at its own claim):
    MU1 a missing register read as an empty, read one          -> caught at N1
    MU2 an item with no register state stamped as read          -> caught at N2
    MU3 tickets.submit ignores the register state               -> caught at N1-submit
    MU4 the reader does not name an unreadable register  -> caught at N3

USAGE: python3 tests/prove_register_unavailable.py   (no network; exit 0 PASS, 1 FAIL)
"""
import contextlib
import io
import json
import os
import shutil
import sys
import tempfile

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, 'scripts'))

import external_findings_baseline as EFB  # noqa: E402
import external_findings_pull as EFP      # noqa: E402
import ticket_submit as TS                # noqa: E402
import ticket_templates as TT             # noqa: E402

REPO = 'example-org/app-a'
CK = 'c' * 32


def _issue(n, line, rule, path):
    return {'key': 'AY%04d' % n, 'rule': rule, 'component': 'proj-a:%s' % path, 'project': 'proj-a', 'line': line,
            'message': 'injection %d' % n, 'issueStatus': 'OPEN', 'status': 'OPEN', 'severity': 'MAJOR',
            'impacts': [{'softwareQuality': 'SECURITY', 'severity': 'HIGH'}], '_project': 'proj-a'}


ISSUES = [_issue(1, 10, 'javasecurity:S3649', 'src/Db.java'), _issue(2, 20, 'javasecurity:S2076', 'src/Run.java')]
CWE = {'javasecurity:S3649': 'CWE-89', 'javasecurity:S2076': 'CWE-78'}
# The ledger binds the src/Run.java CWE-78 finding (line 20): with the register read, AY0002 MATCHES it.
LEDGER = {'schema': 1, 'clusters': {CK: {'ref': '42', 'key': 'SEC-42', 'members': [
    {'identity': 'id-run', 'scanner': 'semgrep', 'rule_id': 'cmdi', 'canonical_path': 'src/Run.java', 'line': 20,
     'cwe': 'CWE-78', 'severity': 'high'}]}}}


class _NoHttp(object):
    def __init__(self, *a, **k):
        self.auth = ''


def pull(work, extra):
    """One sonar pull through EFP.main with the source stubbed (no network). -> (rc, stdout, doc)."""
    out = os.path.join(work, 'pulled.json')
    rmap = os.path.join(work, 'map.json')
    io.open(rmap, 'w', encoding='utf-8').write(json.dumps({'proj-a': REPO}))
    real_http, real_pull = EFP.Http, EFP.sonar_pull
    EFP.Http = _NoHttp
    EFP.sonar_pull = lambda *a, **k: (list(ISSUES), [], {}, dict(CWE))
    os.environ['SONAR_TOKEN'] = 'squ_fixture'
    buf = io.StringIO()
    try:
        with contextlib.redirect_stdout(buf):
            rc = EFP.main(['sonar', '--host', 'https://sonar.example.com', '--project', 'proj-a', '--repo-map', rmap,
                           '--repository', REPO, '--out', out] + extra)
    finally:
        EFP.Http, EFP.sonar_pull = real_http, real_pull
        os.environ.pop('SONAR_TOKEN', None)
    doc = json.load(io.open(out, encoding='utf-8')) if os.path.exists(out) else {}
    return rc, buf.getvalue(), doc


def submit_labels(item):
    """tickets.submit's routing of one unmatched item -> its template labels."""
    grp = [{'baseline': dict(item.get('baseline') or {}), 'match_review': None, 'template_labels': []}]

    class Plan(object):
        post = []
    TS._route_review(Plan(), grp, 'k', 'secure-cicd-kit')
    return set(grp[0]['template_labels'])


def claims(work):
    """-> [(label, ok, detail)] for every case. Mutants run this same function and must fail their claim."""
    out = []
    ledger = os.path.join(work, 'ticket-ledger.json')
    io.open(ledger, 'w', encoding='utf-8').write(json.dumps(LEDGER))
    bad = os.path.join(work, 'bad-ledger.json')
    io.open(bad, 'w', encoding='utf-8').write('{"clusters": {not json')

    rc, so, d = pull(work, ['--register', ledger])
    its = d.get('items') or []
    enh = [i for i in its if 'sonar:AY0002' in i.get('aliases', [])]
    out.append(('P1 a readable ledger is REGISTER_READ on the receipt and every item',
                rc == 0 and ((d.get('baseline') or {}).get('register') or {}).get('state') == EFB.REGISTER_READ and its
                and all(i['baseline'].get('register') == EFB.REGISTER_READ for i in its), (rc, d.get('baseline'))))
    out.append(('P1 the register is really used: the bound cluster is matched (enhances %s)' % CK,
                len(enh) == 1 and (enh[0].get('enhances') or {}).get('correlation_key') == CK, enh))
    out.append(('P1 nothing is listed new_not_established and submit adds no register label',
                d.get('new_not_established') == [] and all('secure-cicd-kit-register-review' not in submit_labels(i)
                                                           for i in its), d.get('new_not_established')))

    for tag, extra in (('N1', ['--register', os.path.join(work, 'absent', 'ticket-ledger.json')]), ('N2', [])):
        rc, so, d = pull(work, extra)
        its = d.get('items') or []
        st = EFB.REGISTER_NOT_ESTABLISHED
        out.append(('%s %s on the receipt and on every item' % (tag, st),
                    rc == 0 and ((d.get('baseline') or {}).get('register') or {}).get('state') == st and its and
                    all(i['baseline'].get('register') == st for i in its) and d.get('register') == st,
                    (d.get('baseline'), [i.get('baseline') for i in its])))
        out.append(('%s no unmatched item is classified new: every one is listed %s' % (tag, st),
                    len(d.get('new_not_established') or []) == len(its) == 2 and
                    all(r.get('state') == st for r in d['new_not_established']) and
                    (d.get('counts') or {}).get('new_not_established') == 2 and st in so, d.get('new_not_established')))
        out.append(('%s-submit tickets.submit routes each item to triage (register-review)' % tag,
                    its and all({'secure-cicd-kit-register-review', 'secure-cicd-kit-triage'} <= submit_labels(i)
                                for i in its), [sorted(submit_labels(i)) for i in its]))
        if tag == 'N1':
            # C1: the batches the review concurs with, and the ticket text, carry the state.
            rows = EFP.batches(d, 'review-0001')
            out.append(('C1 every batched item carries baseline.register %s' % st,
                        rows and all(i['baseline'].get('register') == st for p, _h in rows for i in p['items']), rows[:1]))
            rec = TT.normalize('finding', its[0], {}, 0)
            out.append(('C1 the ticket facts name the register state',
                        any(k == 'register' and st in str(v) for k, v in rec.get('template_facts') or rec.get('facts') or []),
                        rec.get('template_facts')))
            out.append(('C1 every item still passes the finding template',
                        all(TT.validate_item('finding', i) is None for i in its),
                        [TT.validate_item('finding', i) for i in its]))

    rc, so, d = pull(work, ['--register', bad])
    its = d.get('items') or []
    out.append(('N3 an unreadable ledger: %s and %s on the receipt and every item'
                % (EFB.REGISTER_UNREADABLE, EFB.UNAVAILABLE),
                rc == 0 and (d.get('baseline') or {}).get('state') == EFB.UNAVAILABLE and
                ((d.get('baseline') or {}).get('register') or {}).get('state') == EFB.REGISTER_UNREADABLE and its and
                all(i['baseline'].get('register') == EFB.REGISTER_UNREADABLE and i['baseline'].get('state') ==
                    EFB.UNAVAILABLE for i in its), (d.get('baseline'), [i.get('baseline') for i in its])))

    wf = io.open(os.path.join(ROOT, '.github', 'workflows', 'reusable-external-findings.yml'), encoding='utf-8').read()
    out.append(('W1 the reusable workflow exposes register_state and annotates anything but REGISTER_READ',
                'value: ${{ jobs.pull.outputs.register_state }}' in wf and 'register_state: ${{ steps.pull.outputs.register_state }}' in wf and
                'echo "register_state=$register" >> "$GITHUB_OUTPUT"' in wf and
                '[ "$register" = REGISTER_READ ] || echo "::warning title=$register::' in wf, ''))
    return out


def failing(work, prefix):
    return [c for c in claims(work) if c[0].startswith(prefix) and not c[1]]


def main():
    work = tempfile.mkdtemp(prefix='kit-register-')
    fails = []
    try:
        for label, ok, detail in claims(work):
            print('  %s %s' % ('ok  ' if ok else 'FAIL', label))
            if not ok:
                fails.append('%s -- %s' % (label, json.dumps(detail, default=str)[:600]))

        mutants = []
        real_read = EFB.read_register
        mutants.append(('MU1 a missing register read as an empty, read one', 'N1 ',
                        lambda: setattr(EFB, 'read_register', lambda p: (
                            ({}, EFB.REGISTER_READ, 'empty') if p and not os.path.exists(p) else real_read(p))),
                        lambda: setattr(EFB, 'read_register', real_read)))
        real_stamp = EFP._receipt_stamp

        def stamp_read(r):
            b = real_stamp(r)
            if not (isinstance((r or {}).get('register'), dict) and (r or {})['register'].get('state')):
                b['register'] = EFB.REGISTER_READ
            return b
        real_read2 = EFB.read_register
        mutants.append(('MU2 an item with no register state stamped as read', 'N2 ',
                        lambda: (setattr(EFP, '_receipt_stamp', stamp_read),
                                 setattr(EFB, 'read_register', lambda p: (None, None, 'x') if not p else real_read2(p))),
                        lambda: (setattr(EFP, '_receipt_stamp', real_stamp), setattr(EFB, 'read_register', real_read2))))
        real_rr = TS.REGISTER_READ
        mutants.append(('MU3 tickets.submit ignores the register state', 'N1-submit',
                        lambda: setattr(TS, 'REGISTER_READ', EFB.REGISTER_NOT_ESTABLISHED),
                        lambda: setattr(TS, 'REGISTER_READ', real_rr)))
        real_read3 = EFB.read_register
        mutants.append(('MU4 the reader does not name an unreadable register', 'N3 ',
                        lambda: setattr(EFB, 'read_register', lambda p: (
                            (None, 'not-a-register-state', 'x') if p and os.path.basename(p) == 'bad-ledger.json'
                            else real_read3(p))),
                        lambda: setattr(EFB, 'read_register', real_read3)))
        for label, prefix, apply, undo in mutants:
            apply()
            try:
                got = failing(work, prefix)
            except Exception as exc:                   # noqa: BLE001 - a crash is not a catch
                got = []
                print('  mutant %s crashed: %s' % (label, exc))
            finally:
                undo()
            print('  mutant %-58s %s' % (label, 'caught at %s' % got[0][0] if got else 'NOT CAUGHT'))
            if not got:
                fails.append('mutant %s was not caught at %s' % (label, prefix))
    finally:
        shutil.rmtree(work, ignore_errors=True)
    if fails:
        for f in fails:
            print('FAIL: %s' % f)
        print('::error title=Register state not carried::%d failure(s)' % len(fails))
        return 1
    print('PASS: a missing or unreadable register is named on the receipt, every item, the batches, the ticket and '
          'the workflow output; no item is classified new without it; every mutant is caught.')
    return 0


if __name__ == '__main__':
    sys.exit(main())

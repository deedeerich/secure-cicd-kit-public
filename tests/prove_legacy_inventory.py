#!/usr/bin/env python3
"""The READ-ONLY legacy-key inventory (scripts/legacy_inventory.py; review 2026-11-09 finding 10).

WHY THIS FILE EXISTS

    The key migration window closes 2026-11-13. After it, every disposition keyed on the legacy
    fingerprint stops suppressing. The owner must run an inventory of each consumer register
    before that day, and the inventory must never write or re-key anything.

    The findings file it resolves identities from is written HERE by the production path:
    scan_report.parse_sarif (the real SARIF walk and identify()) and scan_report.observation_of
    (the row the batch report writes). No identity is hand-built.

WHAT IT PROVES

  POSITIVE
    P1  an approved, in-date decision keyed on a finding's legacy fingerprint is listed
        REKEY_REQUIRED with the durable identity the report computed for that finding, its owner
        (approver_role), expiry and reaffirmation YES; the text names all of them; counts agree
    P2  --json through main(): the same row, machine-readable, exit 0
    P3  a legacy key whose durable identity is already keyed in the register: ALREADY_REKEYED,
        reaffirmation no; a durable-shaped key is never listed as legacy
  NEGATIVE
    N1  no findings file: REKEY_REQUIRED_IDENTITY_UNRESOLVED, no identity guessed
    N2  an EXPIRED legacy record: NOT_SUPPRESSING naming EXPIRED, reaffirmation no
    N3  an absent register: exit 2 and register_state NOT CONFIGURED, never "0 legacy keys"
    N4  a legacy key matching two different durable identities: unresolved, both named
  READ-ONLY
    R1  sha256 of the register and the findings file, and the directory listing, are identical
        before and after a text run and a --json run
  MUTANTS (each must be caught)
    M1  rekeys-register     the inventory rewrites the register onto the durable key (R1)
    M2  guesses-identity    an unresolved key is given an identity anyway (N1)
    M3  expiry-ignored      the suppression rule ignores expiry (N2)
    M4  absent-is-empty     an unreadable register reports LOADED with zero rows (N3)
    M5  existence-is-effective  a durable-key record counts as the migration merely because it
                            exists (N5a-c, P4)
  REPLACEMENT EFFECTIVENESS (finding: ALREADY_REKEYED required only that a record EXISTS)
    P4  an effective (approved, in-date) durable-key replacement stays ALREADY_REKEYED
    N5a the replacement is EXPIRED: REKEYED_REPLACEMENT_NOT_EFFECTIVE naming EXPIRED, action yes
    N5b the replacement is rejected / not approved: same state, naming the state
    N5c the replacement is otherwise non-suppressing under scan_report's own rule (rationale
        too short): same state; the summary counts it as needing reaffirmation

EXIT  0 all hold   1 a case failed (named)   2 could not be checked
"""
import contextlib
import datetime
import hashlib
import io
import json
import os
import shutil
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, HERE)
sys.path.insert(0, os.path.join(ROOT, 'scripts'))

TODAY = datetime.date(2026, 11, 10)      # inside the window, so suppression is not the variable


def _disp(key, **over):
    d = {'schema_version': 1, 'fingerprint': key, 'scanner': 'semgrep',
         'rule': 'python.lang.security.audit.sqli.sql-injection', 'scope_path': 'app/db/queries.py',
         'disposition_type': 'ACCEPTED_RISK',
         'rationale': 'Parameterisation is scheduled for the Q4 data-access rework (change-record-7).',
         'evidence_ref': 'change-record-7', 'approver_role': 'security-lead',
         'created': '2026-09-01', 'expires': '2099-01-01', 'state': 'approved'}
    d.update(over)
    return d


def _finding(sr, work, tag, **kw):
    """-> the finding the REAL reporter builds from a Semgrep-shaped SARIF result."""
    from prove_identity_durability import sast_sarif
    doc = sast_sarif('1.92.3', 'SQL built by concatenation',
                     'python.lang.security.audit.sqli.sql-injection', **kw)
    path = os.path.join(work, '%s.sarif' % tag)
    with io.open(path, 'w', encoding='utf-8') as fh:
        json.dump(doc, fh)
    findings, state, _ex = sr.parse_sarif(path, 'semgrep')
    if state != 'COMPLETE' or len(findings) != 1 or not findings[0].get('identity'):
        raise RuntimeError('fixture %s: parse_state=%s, %d finding(s)' % (tag, state, len(findings)))
    return findings[0]


def _write(path, obj):
    with io.open(path, 'w', encoding='utf-8') as fh:
        json.dump(obj, fh, indent=1, sort_keys=True)
    return path


def _findings_file(sr, work, name, fs):
    return _write(os.path.join(work, name), [sr.observation_of(f, 'sast-semgrep', True) for f in fs])


def _main(li, argv):
    buf = io.StringIO()
    with contextlib.redirect_stdout(buf):
        rc = li.main(argv)
    return rc, buf.getvalue()


def _hashes(d):
    out = {}
    for n in sorted(os.listdir(d)):
        p = os.path.join(d, n)
        if os.path.isfile(p):
            out[n] = hashlib.sha256(open(p, 'rb').read()).hexdigest()
    return out


def run_all(li, sr):
    fails = []
    work = tempfile.mkdtemp(prefix='legacy-inv-')
    try:
        fa = _finding(sr, work, 'a')
        fb = _finding(sr, work, 'b', path='services/api/db/queries.py')
        fc = _finding(sr, work, 'c', path='app/db/other.py')
        if len(set([fa['identity'], fb['identity'], fc['identity']])) != 3 or \
                len(set([fa['fp'], fb['fp'], fc['fp']])) != 3:
            return ['fixture: the three findings did not get distinct keys']
        fpath = _findings_file(sr, work, 'findings.json', [fa, fb, fc])
        reg = {
            fa['fp']: _disp(fa['fp']),                                    # P1: re-key required
            fb['fp']: _disp(fb['fp']),                                    # P3: already re-keyed
            fb['identity']: _disp(fb['identity']),
            fc['fp']: _disp(fc['fp'], expires='2026-11-01'),              # N2: expired
        }
        rpath = _write(os.path.join(work, 'dispositions.json'), {'dispositions': list(reg.values())})
        # N4 fixture. The legacy hash ignores the symbol, so two functions in one file with the
        # same rule and message share it while the durable identity tells them apart -- both rows
        # from the real reporter.
        f_alt = _finding(sr, work, 'd', symbol='app.db.queries.other_fn')
        if f_alt['fp'] != fa['fp'] or f_alt['identity'] == fa['identity']:
            raise RuntimeError('fixture N4: the two-symbol findings did not share a legacy key')
        dup = _write(os.path.join(work, 'dup-findings.json'),
                     [sr.observation_of(fa, 'sast-semgrep', True),
                      sr.observation_of(f_alt, 'sast-semgrep', True)])
        reg4 = _write(os.path.join(work, 'reg4.json'), {fa['fp']: _disp(fa['fp'])})

        # P4 / N5a-c: four more findings, each with a legacy entry (approved, in date) AND a
        # replacement on the durable key whose effectiveness is the variable.
        extra = [_finding(sr, work, 'e%d' % i, path='svc%d/db/q.py' % i) for i in range(4)]
        fe = _findings_file(sr, work, 'findings-e.json', extra)
        regE = {}
        for f, over in zip(extra, ({}, {'expires': '2026-11-01'}, {'state': 'rejected'},
                                    {'rationale': 'too short'})):
            regE[f['fp']] = _disp(f['fp'])
            regE[f['identity']] = _disp(f['identity'], **over)
        rE = _write(os.path.join(work, 'regE.json'), {'dispositions': list(regE.values())})

        # R1 baseline, before anything runs
        before = _hashes(work)

        # P1
        inv = li.inventory(rpath, [fpath], TODAY)
        rows = dict((r['legacy_key'], r) for r in inv['rows'])
        r1 = rows.get(fa['fp'])
        if not r1 or r1['inventory_state'] != 'REKEY_REQUIRED' \
                or r1['durable_identities'] != [fa['identity']] or not r1['reaffirmation_required'] \
                or r1['owner'] != 'security-lead' or r1['expires'] != '2099-01-01':
            fails.append('P1: the legacy-keyed approved decision was not listed REKEY_REQUIRED with '
                         'its durable identity, owner and expiry: %r' % (r1,))
        txt = li.render_text(inv)
        for need in (fa['fp'], fa['identity'], 'security-lead', '2099-01-01', 'REKEY_REQUIRED',
                     inv['window_closes'], 'reaffirmation required: YES'):
            if need not in txt:
                fails.append('P1: the text inventory does not name %r' % need)
        s = inv['summary']
        if (s['legacy_keys'], s['REKEY_REQUIRED'], s['ALREADY_REKEYED'], s['NOT_SUPPRESSING'],
                s['durable_keys'], s['reaffirmation_required']) != (3, 1, 1, 1, 1, 1):
            fails.append('P1: the counts do not match the register: %r' % s)

        # P2
        rc, out = _main(li, ['--register', rpath, '--findings', fpath, '--today', TODAY.isoformat(),
                             '--json'])
        try:
            j = json.loads(out)
        except ValueError:
            j = None
        if rc != 0 or not j or [r['inventory_state'] for r in j['rows']
                                if r['legacy_key'] == fa['fp']] != ['REKEY_REQUIRED']:
            fails.append('P2: --json did not report the REKEY_REQUIRED row (rc %r): %s' % (rc, out[:300]))
        rc_t, out_t = _main(li, ['--register', rpath, '--findings', fpath, '--today', TODAY.isoformat()])
        if rc_t != 0 or fa['identity'] not in out_t:
            fails.append('P2: the text run did not name the durable identity (rc %r)' % rc_t)

        # P3
        r3 = rows.get(fb['fp'])
        if not r3 or r3['inventory_state'] != 'ALREADY_REKEYED' or r3['reaffirmation_required']:
            fails.append('P3: a legacy key already re-keyed was %r' % (r3 and r3['inventory_state'],))
        if fb['identity'] in rows:
            fails.append('P3: a durable-keyed record was listed as legacy')

        # N1
        inv0 = li.inventory(rpath, [], TODAY)
        n1 = dict((r['legacy_key'], r) for r in inv0['rows']).get(fa['fp'])
        if not n1 or n1['inventory_state'] != 'REKEY_REQUIRED_IDENTITY_UNRESOLVED' \
                or n1['durable_identities'] or not n1['reaffirmation_required']:
            fails.append('N1: with no findings file the row was %r -- an identity cannot be read '
                         'from a hash' % (n1,))

        # N2
        n2 = rows.get(fc['fp'])
        if not n2 or n2['inventory_state'] != 'NOT_SUPPRESSING' or 'EXPIRED' not in \
                n2['not_suppressing_because'] or n2['reaffirmation_required']:
            fails.append('N2: an expired legacy record was %r' % (n2 and (n2['inventory_state'],
                                                                          n2['not_suppressing_because']),))

        # N3
        missing = os.path.join(work, 'no-such-register.json')
        rc3, out3 = _main(li, ['--register', missing, '--json'])
        try:
            j3 = json.loads(out3)
        except ValueError:
            j3 = {}
        if rc3 != 2 or j3.get('register_state') != 'NOT CONFIGURED':
            fails.append('N3: an absent register gave rc %r state %r -- absence is not "no legacy keys"'
                         % (rc3, j3.get('register_state')))

        # N4: one legacy key, two identities. The legacy hash ignores the symbol, so two functions
        # in one file with the same rule and message share it while the durable identity tells
        # them apart -- both rows from the real reporter.
        n4 = li.inventory(reg4, [dup], TODAY)['rows']
        if len(n4) != 1 or n4[0]['inventory_state'] != 'REKEY_REQUIRED_IDENTITY_UNRESOLVED' \
                or len(n4[0]['durable_identities']) != 2:
            fails.append('N4: a legacy key matching two identities was %r' % (n4,))

        # P4 / N5a-c
        invE = li.inventory(rE, [fe], TODAY)
        rowsE = [dict((r['legacy_key'], r) for r in invE['rows'])[f['fp']] for f in extra]
        want = (('P4', 'ALREADY_REKEYED', None, False),
                ('N5a', 'REKEYED_REPLACEMENT_NOT_EFFECTIVE', 'EXPIRED', True),
                ('N5b', 'REKEYED_REPLACEMENT_NOT_EFFECTIVE', 'rejected', True),
                ('N5c', 'REKEYED_REPLACEMENT_NOT_EFFECTIVE', 'rationale', True))
        for (tag, st, why, act), r in zip(want, rowsE):
            if r['inventory_state'] != st or r['reaffirmation_required'] != act or                     (why and why not in r['action']):
                fails.append('%s: expected %s (action %s, naming %r), got %s: %s'
                             % (tag, st, act, why, r['inventory_state'], r['action'][:200]))
        sE = invE['summary']
        if (sE['ALREADY_REKEYED'], sE.get('REKEYED_REPLACEMENT_NOT_EFFECTIVE'),
                sE['reaffirmation_required']) != (1, 3, 3):
            fails.append('N5: the summary does not count the not-effective replacements as needing '
                         'action: %r' % sE)
        if 'REKEYED_REPLACEMENT_NOT_EFFECTIVE' not in li.render_text(invE):
            fails.append('N5: the text inventory does not show the new state')

        # R1
        after = _hashes(work)
        if after != before:
            changed = sorted(set(k for k in set(before) | set(after) if before.get(k) != after.get(k)))
            fails.append('R1: the inventory changed or created files: %s -- it must be read-only' % changed)
    finally:
        shutil.rmtree(work, ignore_errors=True)
    return fails


def mutants(li, sr):
    survived = []

    def m_rekey():
        real = li.inventory

        def inv(register_path, findings_paths=(), today=None):
            out = real(register_path, findings_paths, today)
            if not os.path.exists(register_path):
                return out
            d = json.load(io.open(register_path, encoding='utf-8'))
            recs = d['dispositions'] if isinstance(d, dict) and 'dispositions' in d else d
            if isinstance(recs, list):
                for r in out['rows']:
                    if r['durable_identities']:
                        recs.append(dict(_disp(r['durable_identities'][0])))
                with io.open(register_path, 'w', encoding='utf-8') as fh:
                    json.dump({'dispositions': recs}, fh)
            return out
        return [('inventory', inv)]

    def m_guess():
        real = li.load_findings

        def lf(paths):
            by_fp, refused, notes = real(paths)
            return _Guess(by_fp), refused, notes
        return [('load_findings', lf)]

    def m_expiry():
        real = sr.not_suppressed_because

        def ns(d, today=None):
            r = real(d, today)
            return '' if r.startswith('EXPIRED') else r
        return [('_sr_not_suppressed_because', ns)]

    def m_absent():
        real = sr.load_dispositions

        def ld(path):
            d, state = real(path)
            return d, 'LOADED'
        return [('_sr_load_dispositions', ld)]

    def m_exists():
        real = sr.not_suppressed_because

        def ns(d, today=None):
            if isinstance(d, dict) and len(str(d.get('fingerprint', ''))) == 64:
                return ''                      # a durable-key record "suppresses" because it exists
            return real(d, today)
        return [('_sr_not_suppressed_because', ns)]

    for name, make in (('rekeys-register', m_rekey), ('guesses-identity', m_guess),
                       ('expiry-ignored', m_expiry), ('absent-is-empty', m_absent),
                       ('existence-is-effective', m_exists)):
        saved = []
        for attr, fn in make():
            tgt, a = (sr, attr[4:]) if attr.startswith('_sr_') else (li, attr)
            saved.append((tgt, a, getattr(tgt, a)))
            setattr(tgt, a, fn)
        try:
            caught = bool(run_all(li, sr))
        finally:
            for tgt, a, v in saved:
                setattr(tgt, a, v)
        print('  mutant %-24s %s' % (name, 'caught' if caught else 'SURVIVED'))
        if not caught:
            survived.append(name)
    return survived


class _Guess(dict):
    """A mutant's identity map: every unknown legacy key 'resolves' to a made-up identity."""
    def get(self, k, default=None):
        return dict.get(self, k) or set(['0' * 64])


def main():
    try:
        import scan_report as sr
        import legacy_inventory as li
    except Exception as exc:                                  # noqa: BLE001
        print('UNKNOWN: could not import: %s' % exc)
        return 2
    print('=== finding 10: the read-only legacy-key inventory ===')
    try:
        fails = run_all(li, sr)
    except RuntimeError as exc:
        print('UNKNOWN: %s' % exc)
        return 2
    if fails:
        for i, f in enumerate(fails, 1):
            print('  %d. %s' % (i, f))
        print('::error title=Legacy inventory unproven::%d failure(s)' % len(fails))
        return 1
    survived = mutants(li, sr)
    if survived:
        print('::error title=Legacy inventory mutants survived::%s' % ', '.join(survived))
        return 1
    print('legacy inventory proven: each legacy-keyed decision is listed with the durable identity '
          'the production report computed, owner, expiry and whether reaffirmation is required; '
          'unresolved, expired, ambiguous and absent cases are named; inputs are byte-identical '
          'after a run; five mutants caught; a durable-key replacement counts only when it is itself effective.')
    return 0


if __name__ == '__main__':
    sys.exit(main())

#!/usr/bin/env python3
"""A scanner upgrade is a DECLARED event on the write path: propose-ledger runs the generation check (L46).

WHY THIS EXISTS

    ETFB section 5.5: "An upgrade is a declared event ... the new generation is not authoritative for
    enforcement until that report is reviewed and accepted by a named approver", and "an upgrade may
    never, by itself, create a NEW finding". scripts/rule_family.py built generation_check,
    reconciliation_report and accept as a library, and the audit (L46) found nothing ran them: the
    ledger's only write path admitted whatever a new scanner generation reported as NEW, with a
    claimable first_seen, as though the author had introduced it that day.

WHAT IT PROVES (against throwaway git repositories, through propose_ledger.propose)

    held        the alias table pins semgrep 1.90; a run observes semgrep 1.95. Findings that
                generation reports which the ledger does not hold are NOT admitted; the proposal
                carries a reconciliation report at .security/reconciliations/semgrep-1.90-1.95.json
                (appeared = those identities, acceptance null, a bounded window), and the body names
                DECISION_REQUIRED.
    reopened    the report already exists unaccepted at the tip: it is not re-opened (its window
                runs from the first opening) and nothing is admitted.
    accepted    the report at the tip carries an acceptance (approver role, date, inside the window):
                the held findings are admitted as detection changes -- age NOT established, never
                NEW-with-a-date.
    untrusted   a pinned scanner whose running version cannot be established holds its findings
                (EVIDENCE_UNTRUSTED: a tool that cannot say what it is cannot be reconciled).
    unpinned    no table, or a scanner the table does not pin: admitted as before, and said.

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
sys.path.insert(0, os.path.join(ROOT, 'scripts'))
PATH = '.security/finding-baseline.json'
TABLE = '.security/rule-family-aliases.json'
REPORT = '.security/reconciliations/semgrep-1.90-1.95.json'


def git(repo, *args):
    p = subprocess.run(['git', '-c', 'user.name=t', '-c', 'user.email=t@example.invalid',
                        '-c', 'commit.gpgsign=false', '-c', 'init.defaultBranch=main'] + list(args),
                       cwd=repo, capture_output=True, text=True)
    if p.returncode != 0:
        raise RuntimeError('git %s: %s' % (' '.join(args), p.stderr.strip()[:300]))
    return p.stdout


def main():
    try:
        from finding_identity import identify
        import baseline_ledger as bl
        import propose_ledger as pl
    except ImportError as exc:
        print('UNKNOWN: %s' % exc)
        return 2
    fails = []

    def check(cond, msg):
        if not cond:
            fails.append(msg)

    def obs(path, sym, construct, tool='semgrep', version='1.95.0'):
        o = identify({'finding_subject': 'SOURCE', 'cwe': 'CWE-78', 'rule_family': 'cmd',
                      'canonical_path': path, 'symbol_path': sym, 'construct': construct,
                      'language_family': 'hash'})
        o.update(scanner=tool, tool=tool, scanner_version=version)
        return o

    a = obs('app.py', 'm.a', 'run(a)', version='1.90.0')
    prov = {'run_id': '41', 'observed_at': '2026-01-05T00:00:00Z', 'observed_at_source': 'SIDECAR'}
    header = {'established_on': '2026-01-05', 'established_commit': 'e' * 40, 'approver_role': 'security-lead'}
    ledger = bl.serialise(bl.new_ledger(header, [bl.entry_from_identity(a, 'prod', '2026-01-05', prov, True)]))
    table = json.dumps({'schema_version': 1, 'generations': {'semgrep': {'pinned': '1.90'}}, 'aliases': []})
    ctx = dict(event='push', ref='refs/heads/main', default_branch='main', default_ref='main',
               environment='prod', run_id='900', commit='f' * 40,
               observed_at='2026-10-14T00:00:00Z', observed_at_source='SIDECAR')
    a95 = obs('app.py', 'm.a', 'run(a)')
    c95 = obs('new.py', 'm.c', 'run(c)')
    work = tempfile.mkdtemp(prefix='propose-generation-')

    def repo_with(files):
        repo = os.path.join(work, 'r%d' % len(os.listdir(work)))
        os.makedirs(repo)
        git(repo, 'init', '-q')
        for rel, text in files.items():
            dest = os.path.join(repo, *rel.split('/'))
            if not os.path.isdir(os.path.dirname(dest)):
                os.makedirs(os.path.dirname(dest))
            with io.open(dest, 'w', encoding='utf-8', newline='\n') as fh:
                fh.write(text)
        git(repo, 'add', '-A')
        git(repo, 'commit', '-qm', 'seed')
        return repo

    def entries_of(p):
        files = dict((f['path'], f['content']) for f in (p.get('files') or []))
        ents, _s, _n, _h = bl.parse_ledger(files.get(PATH) or ledger)
        return dict((e['identity'], e) for e in ents), files

    try:
        # ── held ─────────────────────────────────────────────────────────────
        p = pl.propose(repo_with({PATH: ledger, TABLE: table}), [a95, c95], PATH, **ctx)
        ents, files = entries_of(p)
        check(c95['identity'] not in ents,
              'held: a finding first reported by an UNRECONCILED scanner generation (1.90 -> 1.95) was '
              'admitted to the baseline -- an upgrade created a NEW finding (ETFB 5.5)')
        rep = json.loads(files.get(REPORT) or 'null')
        check(bool(rep) and rep.get('acceptance') is None
              and [x['identity'] for x in rep.get('appeared') or []] == [c95['identity']]
              and rep.get('window_expires'),
              'held: no open reconciliation report for semgrep 1.90 -> 1.95 travels in the proposal '
              '(files %r)' % sorted(files))
        check('DECISION_REQUIRED' in (p.get('body') or ''),
              'held: the proposal body does not say a reconciliation decision is owed')

        # ── reopened: an unaccepted report at the tip is not re-opened ────────
        if rep:
            opened = dict(rep, opened_on='2026-10-10',
                          window_expires='2026-11-09')
            p2 = pl.propose(repo_with({PATH: ledger, TABLE: table, REPORT: json.dumps(opened)}),
                            [a95, c95], PATH, **ctx)
            ents2, files2 = entries_of(p2)
            check(c95['identity'] not in ents2 and REPORT not in files2,
                  'reopened: an open report at the tip was re-opened (%r) or the finding admitted'
                  % sorted(files2))

            # ── accepted: admitted as a detection change, age not established ──
            acc = dict(opened, acceptance={'approver_role': 'security-lead', 'accepted_on': '2026-10-12'})
            p3 = pl.propose(repo_with({PATH: ledger, TABLE: table, REPORT: json.dumps(acc)}),
                            [a95, c95], PATH, **ctx)
            ents3, _f3 = entries_of(p3)
            e = ents3.get(c95['identity'])
            check(bool(e) and e.get('detection_change') is True and e.get('age_established') is False,
                  'accepted: after an accepted reconciliation the finding was not admitted as a '
                  'detection change with no established age (%r)' % (e,))

        # ── untrusted: a pinned scanner with no stated version ────────────────
        cx = obs('x.py', 'm.x', 'run(x)', version='')
        p4 = pl.propose(repo_with({PATH: ledger, TABLE: table}), [a95, cx], PATH, **ctx)
        ents4, _f4 = entries_of(p4)
        check(cx['identity'] not in ents4
              and 'EVIDENCE_UNTRUSTED' in (p4.get('body') or '') + (p4.get('why') or ''),
              'untrusted: a finding from a pinned scanner with no established version was admitted, '
              'or the body does not say why it was held')

        # ── unpinned: no table / a scanner the table does not pin ─────────────
        cb = obs('b.py', 'm.b', 'run(b)', tool='bandit', version='1.7.9')
        p5 = pl.propose(repo_with({PATH: ledger, TABLE: table}), [a95, cb], PATH, **ctx)
        check(cb['identity'] in entries_of(p5)[0], 'unpinned: an unpinned scanner\'s finding was held')
        p6 = pl.propose(repo_with({PATH: ledger}), [a, c95], PATH, **ctx)
        check(c95['identity'] in entries_of(p6)[0], 'unpinned: with no alias table a finding was held')
    except RuntimeError as exc:
        print('UNKNOWN: fixture repository could not be built: %s' % exc)
        return 2
    finally:
        shutil.rmtree(work, ignore_errors=True)

    if fails:
        for f in fails:
            print('FAIL: ' + f)
        return 1
    print('PASS: propose-ledger runs the generation check: a finding first reported by an unreconciled '
          'scanner generation is held, not admitted, and an open reconciliation report travels in the '
          'proposal (never re-opened); once a named approver accepts it the findings enter as detection '
          'changes with no established age; an unversioned pinned scanner is held as EVIDENCE_UNTRUSTED; '
          'an unpinned scanner, or no table, admits as before.')
    return 0


if __name__ == '__main__':
    sys.exit(main())

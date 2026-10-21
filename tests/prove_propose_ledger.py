#!/usr/bin/env python3
"""propose-ledger is the only write authority, and what it writes is a pull request (L45).

WHY THIS EXISTS

    SINGLE_PIPELINE_TARGET.md section 6.1 and section 9.3: "the ledger write is the one genuine
    write path in the whole design". The run does not push to the protected branch; it opens a pull
    request carrying the proposed delta, and branch protection plus CODEOWNERS is what enforces the
    review. If that path ever grows to include the protected branch, "the ledger has stopped being a
    governance artifact and the whole baseline becomes a scanner output."

    So this proves, against a throwaway git repository:

    allowed           on the protected branch's post-merge run, a NEW finding is proposed with a
                      claimable first_seen; a MOVED finding keeps first_seen and gains a move
                      record; the proposed ledger parses under the same reader that will read it
    attack            a pull_request (or pull_request_target) run, or a run on any ref but the
                      default branch, is REFUSED and produces nothing; no proposal ever changes an
                      existing entry's first_seen (ETFB section 8.8 rule 1); a POTENTIALLY_ABSENT entry
                      is never removed; an uncomputable identity is never admitted; the script
                      never writes the ledger path or commits -- the repository is unchanged
    missing-evidence  an unreadable ledger REFUSES (proposing against it would re-baseline the
                      repository); an absent ledger refuses unless establishment is explicitly
                      requested with an approver, and establishment never asserts an age
    recovery          once the proposal is merged, the same observations propose nothing new

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
LINEAGE = '.security/finding-lineage.jsonl'
fl = None


def load_lineage(files):
    """Write the payload's lineage files to a scratch directory and load them as the reader would."""
    d = tempfile.mkdtemp(prefix='lineage-read-')
    try:
        for rel, text in files.items():
            dest = os.path.join(d, rel)
            if not os.path.isdir(os.path.dirname(dest)):
                os.makedirs(os.path.dirname(dest))
            with io.open(dest, 'w', encoding='utf-8', newline='\n') as fh:
                fh.write(text)
        return fl.load(os.path.join(d, LINEAGE))
    finally:
        shutil.rmtree(d, ignore_errors=True)


def git(repo, *args):
    p = subprocess.run(['git', '-c', 'user.name=t', '-c', 'user.email=t@example.invalid',
                        '-c', 'commit.gpgsign=false', '-c', 'init.defaultBranch=main'] + list(args),
                       cwd=repo, capture_output=True, text=True)
    if p.returncode != 0:
        raise RuntimeError('git %s: %s' % (' '.join(args), p.stderr.strip()[:300]))
    return p.stdout


def main():
    global fl
    try:
        from finding_identity import identify
        import baseline_ledger as bl
        import finding_lineage as fl
    except ImportError as exc:
        print('UNKNOWN: %s' % exc)
        return 2
    try:
        import propose_ledger as pl
    except ImportError as exc:
        print('FAIL: no propose-ledger exists (%s). The design\'s only write authority is not built, '
              'so nothing can ever establish or extend a baseline.' % exc)
        return 1

    fails = []

    def check(cond, msg):
        if not cond:
            fails.append(msg)

    def finding(path, sym, construct):
        out = identify({'finding_subject': 'SOURCE', 'cwe': 'CWE-78', 'rule_family': 'cmd',
                        'canonical_path': path, 'symbol_path': sym, 'construct': construct,
                        'language_family': 'hash'})
        if not out.get('identity'):
            raise RuntimeError('fixture did not fingerprint')
        return out

    a = finding('app.py', 'm.a', 'run(a)')
    b = finding('lib.py', 'm.b', 'run(b)')
    prov = {'run_id': '41', 'observed_at': '2026-01-05T00:00:00Z', 'observed_at_source': 'SIDECAR'}
    base_entries = [bl.entry_from_identity(a, 'prod', '2026-01-05', prov, True),
                    bl.entry_from_identity(b, 'prod', '2025-06-01', dict(prov, observed_at_source='UNKNOWN'),
                                           False)]
    header = {'established_on': '2025-06-01', 'established_commit': 'e' * 40,
              'approver_role': 'security-lead'}
    ctx = dict(event='push', ref='refs/heads/main', default_branch='main', default_ref='main',
               environment='prod', run_id='900', commit='f' * 40,
               observed_at='2026-10-14T00:00:00Z', observed_at_source='SIDECAR')

    work = tempfile.mkdtemp(prefix='propose-ledger-')
    try:
        repo = os.path.join(work, 'repo')
        os.makedirs(os.path.join(repo, '.security'))
        git(repo, 'init', '-q')
        with io.open(os.path.join(repo, PATH), 'w', encoding='utf-8', newline='\n') as fh:
            fh.write(bl.serialise(bl.new_ledger(header, base_entries)))
        git(repo, 'add', '-A')
        git(repo, 'commit', '-qm', 'baseline')
        head_before = git(repo, 'rev-parse', 'HEAD').strip()
        tree_before = io.open(os.path.join(repo, PATH), encoding='utf-8').read()

        a_moved = finding('src/app.py', 'm.a', 'run(a)')
        c = finding('new.py', 'm.c', 'run(c)')
        refused_ident = identify({'finding_subject': 'SOURCE', 'cwe': 'CWE-78',
                                  'rule_family': 'cmd', 'canonical_path': 'x.py',
                                  'symbol_path': 'm.x'})
        observations = [a_moved, c, refused_ident]      # b is not observed

        # ── allowed ──────────────────────────────────────────────────────────
        p = pl.propose(repo, observations, PATH, **ctx)
        check(p['status'] == pl.PROPOSED, 'allowed: status %r (%s)' % (p['status'], p.get('why')))
        doc = json.loads(p.get('content') or '{}')
        entries, state, notes, _h = bl.parse_ledger(p.get('content') or '')
        check(state == bl.LEDGER_INTACT, 'allowed: the proposed ledger does not parse under the '
                                         'reader that will read it: %r' % notes)
        by_id = dict((e['identity'], e) for e in entries)
        check(c['identity'] in by_id, 'allowed: the NEW finding was not proposed')
        if c['identity'] in by_id:
            ce = by_id[c['identity']]
            check(ce['first_seen'] == '2026-10-14' and ce['age_established'] is True,
                  'allowed: a NEW finding seen by a claimable source got first_seen %r / age %r'
                  % (ce['first_seen'], ce['age_established']))
        check(a_moved['identity'] in by_id and a['identity'] not in by_id,
              'allowed: the MOVED finding was not re-keyed to its new identity')
        if a_moved['identity'] in by_id:
            me = by_id[a_moved['identity']]
            check(me['first_seen'] == '2026-01-05', 'attack: the move reset first_seen to %r'
                  % me['first_seen'])
            # L51 / B-08: ONE move record. The move is a lineage event (finding_lineage, hash-chained,
            # head-anchored) carried in the same pull request, never a second copy in the entry.
            check('move_history' not in me,
                  'one record: the moved entry still carries move_history -- a second move record '
                  'beside the lineage ledger, which the two can disagree with')
            files = dict((f['path'], f['content']) for f in (p.get('files') or []))
            lin = files.get(LINEAGE)
            check(bool(lin) and LINEAGE + '.head' in files,
                  'one record: the proposal carries no lineage event (and head anchor) for the move '
                  '(files: %r)' % sorted(files))
            if lin and LINEAGE + '.head' in files:
                events, integ, lnotes = load_lineage({LINEAGE: lin, LINEAGE + '.head': files[LINEAGE + '.head']})
                check(integ == fl.LEDGER_INTACT and len(events) == 1
                      and events[0]['relation'] == fl.SUPERSEDES and events[0]['cause'] == fl.PATH_MOVED
                      and events[0]['from_identities'] == [a['identity']]
                      and events[0]['to_identities'] == [a_moved['identity']],
                      'one record: the lineage carried is %s with %r (%r)' % (integ, events, lnotes))
                if events:
                    check(fl.resolve(events, a['identity'])['current'] == a_moved['identity'],
                          'one record: the old identity does not resolve to the moved one')
                    check((events[0].get('asserted_by') or {}).get('actor_class') == fl.TOOL,
                          'one record: the move event is not attributed to the tool that asserted it')
            check(files.get(PATH) == p.get('content'),
                  'the payload files do not carry the proposed ledger itself')
        check(b['identity'] in by_id and by_id[b['identity']]['first_seen'] == '2025-06-01',
              'attack: an unobserved (POTENTIALLY_ABSENT) entry was removed or re-dated')
        check(refused_ident.get('identity') is None and not any(
              e['identity'] in ('', None) for e in entries),
              'attack: an uncomputable identity was admitted')
        check(any(u for u in p['delta']['evidence_untrusted']),
              'missing-evidence: the uncomputable finding is not reported in the proposal')
        check(p['branch'] and p['branch'] != 'main' and p['base'] == 'main',
              'the proposal targets %r from %r; it must be a new branch into the default branch'
              % (p.get('base'), p.get('branch')))
        check(p['path'] == PATH and p['title'] and p['body'], 'the PR payload is incomplete')
        # The script wrote nothing and committed nothing.
        check(git(repo, 'rev-parse', 'HEAD').strip() == head_before
              and io.open(os.path.join(repo, PATH), encoding='utf-8').read() == tree_before
              and not git(repo, 'status', '--porcelain').strip(),
              'attack: propose() changed the repository. Its only output is a payload')

        # ── attack: PR context and wrong refs ────────────────────────────────
        for bad in (dict(ctx, event='pull_request'), dict(ctx, event='pull_request_target'),
                    dict(ctx, ref='refs/heads/feature'), dict(ctx, ref='refs/pull/7/merge'),
                    dict(ctx, event=''), dict(ctx, default_branch='')):
            r = pl.propose(repo, observations, PATH, **bad)
            check(r['status'] == pl.REFUSED and not r.get('content'),
                  'attack: a run with event=%r ref=%r produced %r -- a PR run may only read'
                  % (bad['event'], bad['ref'], r['status']))

        # ── anti-laundering: an entry's first_seen can never move ────────────
        later = [bl.entry_from_identity(a, 'prod', '2026-09-01', prov, True)]
        problems = pl.first_seen_violations(base_entries, later)
        check(bool(problems), 'attack: re-dating an existing entry\'s first_seen was not detected')

        # ── missing evidence ─────────────────────────────────────────────────
        with io.open(os.path.join(repo, PATH), 'w', encoding='utf-8', newline='\n') as fh:
            fh.write('{broken')
        git(repo, 'commit', '-qam', 'corrupt')
        r = pl.propose(repo, observations, PATH, **ctx)
        check(r['status'] == pl.REFUSED and 'BASELINE_UNAVAILABLE' in (r.get('why') or ''),
              'missing-evidence: an unreadable ledger produced %r -- proposing against it would '
              're-baseline the repository' % r['status'])
        git(repo, 'rm', '-q', PATH)
        git(repo, 'commit', '-qm', 'remove')
        r = pl.propose(repo, observations, PATH, **ctx)
        check(r['status'] == pl.REFUSED, 'missing-evidence: an absent ledger was silently established')
        r = pl.propose(repo, observations, PATH, establish_approver_role='security-lead', **ctx)
        check(r['status'] == pl.REFUSED and 'CODEOWNERS' in (r.get('why') or ''),
              'missing-evidence: establishment with no CODEOWNERS over the ledger was %r -- nothing '
              'would make the named role the one who merges' % r['status'])
        with io.open(os.path.join(repo, 'CODEOWNERS'), 'w', encoding='utf-8', newline='\n') as fh:
            fh.write('/.security/ @example-org/security-leads\n')
        git(repo, 'add', '-A')
        git(repo, 'commit', '-qm', 'codeowners')
        r = pl.propose(repo, observations, PATH, establish_approver_role='security-lead', **ctx)
        check(r['status'] == pl.PROPOSED, 'establishment with an approver was refused: %r'
              % r.get('why'))
        est, st, nt, hdr = bl.parse_ledger(r.get('content') or '')
        check(st == bl.LEDGER_INTACT and all(e['age_established'] is False for e in est),
              'missing-evidence: establishment asserted an age -- "first observed by us on <date>; '
              'the finding may be older" is all it may say (%r)' % nt)
        check(hdr.get('approver_role') == 'security-lead', 'establishment recorded no approver')

        # ── ETFB section 8.8 rule 4: presence in an environment is a DECLARED, DATED assumption ──
        pres = (hdr.get('environment_presence') or {}).get('prod') or {}
        check(pres.get('evidence') == 'merge' and pres.get('assumption') is True
              and pres.get('declared_on') == '2026-10-14' and pres.get('run_id') == '900',
              'rule 4: the established ledger does not declare that presence in `prod` is an '
              'assumption of inheritance from a default-branch (merge) scan, dated -- it is a silent '
              'inheritance (%r)' % (hdr.get('environment_presence'),))
        for label, bad_pres in (('an assumption-free claim from a source scan',
                                 {'evidence': 'merge', 'assumption': False, 'declared_on': '2026-10-14',
                                  'run_id': '1'}),
                                ('an unregistered evidence depth',
                                 {'evidence': 'prod-guess', 'assumption': True, 'declared_on': '2026-10-14',
                                  'run_id': '1'}),
                                ('an undated declaration',
                                 {'evidence': 'merge', 'assumption': True, 'run_id': '1'})):
            d = json.loads(r['content'])
            d['header']['environment_presence'] = {'prod': bad_pres}
            _e, st, nt, _h = bl.parse_ledger(json.dumps(d))
            check(st == bl.LEDGER_LINE_UNPARSEABLE,
                  'rule 4: the reader accepted %s (%s, %r)' % (label, st, nt))
        d = json.loads(r['content'])
        d['header']['environment_presence'] = {'prod': {'evidence': 'revalidate', 'assumption': False,
                                                        'declared_on': '2026-10-14', 'run_id': '1'}}
        _e, st, nt, _h = bl.parse_ledger(json.dumps(d))
        check(st in bl.USABLE, 'rule 4: a deployed-artefact (revalidate) presence claim was refused (%r)' % nt)
        nightly = pl.propose(repo, observations, PATH, establish_approver_role='security-lead',
                             **dict(ctx, event='schedule'))
        _e, _s, _n, nh = bl.parse_ledger(nightly.get('content') or '')
        check(((nh.get('environment_presence') or {}).get('prod') or {}).get('evidence') == 'nightly',
              'rule 4: a scheduled run did not record its evidence as the nightly depth (%r)' % (nh,))

        # ── one record: the reader refuses a second move record in an entry ──
        legacy = json.loads(r['content'])
        if legacy['entries']:
            legacy['entries'][0]['move_history'] = [{'from_identity': 'x'}]
            _e, st, nt, _h = bl.parse_ledger(json.dumps(legacy))
            check(st == bl.LEDGER_LINE_UNPARSEABLE and any('lineage' in n for n in nt),
                  'one record: a ledger entry carrying move_history was read as %s -- moves are '
                  'recorded once, in the lineage ledger (%r)' % (st, nt))

        # ── recovery: merge the proposal, run again, nothing to propose ──────
        if not os.path.isdir(os.path.join(repo, '.security')):
            os.makedirs(os.path.join(repo, '.security'))   # `git rm` took the empty directory
        with io.open(os.path.join(repo, PATH), 'w', encoding='utf-8', newline='\n') as fh:
            fh.write(r['content'])
        git(repo, 'add', '-A')
        git(repo, 'commit', '-qm', 'merge proposal')
        again = pl.propose(repo, observations, PATH, **ctx)
        check(again['status'] == pl.UNCHANGED,
              'recovery: the merged proposal re-proposed %r (%s)' % (again['status'], again.get('why')))

        # ── one record, over time: merge the first proposal's files, move the finding again ──
        repo2 = os.path.join(work, 'repo2')
        os.makedirs(os.path.join(repo2, '.security'))
        git(repo2, 'init', '-q')
        for f in p.get('files') or [{'path': PATH, 'content': p.get('content') or ''}]:
            with io.open(os.path.join(repo2, f['path']), 'w', encoding='utf-8', newline='\n') as fh:
                fh.write(f['content'])
        git(repo2, 'add', '-A')
        git(repo2, 'commit', '-qm', 'merge the first proposal')
        a_again = finding('lib/app.py', 'm.a', 'run(a)')
        r2 = pl.propose(repo2, [a_again, c], PATH, **dict(ctx, run_id='901'))
        files2 = dict((f['path'], f['content']) for f in (r2.get('files') or []))
        if LINEAGE in files2 and LINEAGE + '.head' in files2:
            ev2, integ2, n2 = load_lineage({LINEAGE: files2[LINEAGE], LINEAGE + '.head': files2[LINEAGE + '.head']})
            check(integ2 == fl.LEDGER_INTACT and len(ev2) == 2
                  and fl.resolve(ev2, a['identity'])['current'] == a_again['identity'],
                  'one record: a second move did not extend the merged chain (%s, %d event(s), %r)'
                  % (integ2, len(ev2), n2))
        else:
            check(False, 'one record: a second move carried no lineage (%s: %s)'
                  % (r2['status'], r2.get('why')))
        # A lineage ledger nobody can verify is never extended: the proposal refuses.
        lpath = os.path.join(repo2, LINEAGE)
        if os.path.exists(lpath):
            text = io.open(lpath, encoding='utf-8').read().replace('PATH_MOVED', 'RULE_RENAMED', 1)
            with io.open(lpath, 'w', encoding='utf-8', newline='\n') as fh:
                fh.write(text)
            git(repo2, 'commit', '-qam', 'tamper with the lineage')
            r3 = pl.propose(repo2, [a_again, c], PATH, **dict(ctx, run_id='902'))
            check(r3['status'] == pl.REFUSED and 'lineage' in (r3.get('why') or '').lower(),
                  'one record: a move proposed on top of a TAMPERED lineage ledger gave %r (%s)'
                  % (r3['status'], r3.get('why')))
        else:
            check(False, 'one record: no lineage ledger was ever merged, so tampering cannot be tested')
    except RuntimeError as exc:
        print('UNKNOWN: fixture repository could not be built: %s' % exc)
        return 2
    finally:
        shutil.rmtree(work, ignore_errors=True)

    if fails:
        for f in fails:
            print('FAIL: ' + f)
        return 1
    print('PASS: propose-ledger produces a pull-request payload and nothing else; NEW is admitted '
          'with a claimable first_seen, MOVED keeps first_seen and records the move, unobserved '
          'entries are kept, uncomputable identities are reported and never admitted; PR events and '
          'non-default refs are refused; re-dating first_seen is detected; an unreadable ledger '
          'refuses; establishment needs an approver and asserts no age; a merged proposal re-runs '
          'to unchanged. A move is ONE record: a lineage event in the same proposal (none in the '
          'entry, which the reader now refuses), extended by the next move, never on top of a '
          'tampered chain. Presence in an environment is a declared, dated assumption in the header '
          '(merge or nightly depth), and the reader refuses one claimed without an assumption.')
    return 0


if __name__ == '__main__':
    sys.exit(main())

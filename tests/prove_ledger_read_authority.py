#!/usr/bin/env python3
"""The baseline ledger is read from the protected default branch, never from the PR (L45, ETFB 5.4).

WHY THIS EXISTS

    "A baseline read from the PR head is not a weaker baseline; it is a self-signed certificate."
    If a pull request can add its own finding to the ledger and have that ledger read back during
    its own evaluation, it grandfathers the thing it just introduced -- identical in shape to
    exempting the secret it introduces. ETFB section 5.4 therefore fixes three rules, and this proves
    each by running the reader against a real throwaway git repository:

      1  READ FROM THE PROTECTED BRANCH. An entry the PR branch added -- committed on the branch,
         or sitting in the working tree -- is not in the ledger the PR is evaluated against.
      2  GRANDFATHERING FROM THE MERGE BASE. An entry merged to the default branch AFTER the PR
         branched does not grandfather anything in the PR: nothing can be added underneath a PR.
      3  REMOVALS FROM THE TIP. An entry removed on the default branch after the PR branched stops
         grandfathering at once: strengthening takes effect immediately.

    And the missing-evidence half: a ref that does not exist, a ledger that does not parse, an
    entry carrying matched material, an entry whose identity does not derive from its components,
    and no computable merge base are all UNUSABLE -- and the cascade then answers
    BASELINE_UNAVAILABLE, never "everything new" and never "everything pre-existing".

    Everything runs in a mkdtemp directory; the kit's own repository is never touched.

EXIT  0 proven   1 a rule failed (named)   2 could not be checked (UNKNOWN, never PASS)
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

LEDGER_PATH = '.security/finding-baseline.json'


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
        import finding_match as fm
    except ImportError as exc:
        print('UNKNOWN: %s' % exc)
        return 2
    try:
        import baseline_ledger as bl
    except ImportError as exc:
        print('FAIL: no baseline ledger reader exists (%s). ETFB section 5.4 is designed and not '
              'built: there is nothing that reads first_seen from the protected branch.' % exc)
        return 1

    fails = []
    usable = (fm.LEDGER_INTACT, fm.LEDGER_EMPTY)

    def check(cond, msg):
        if not cond:
            fails.append(msg)

    def finding(sym, construct):
        out = identify({'finding_subject': 'SOURCE', 'cwe': 'CWE-78', 'rule_family': 'cmd',
                        'canonical_path': 'app.py', 'symbol_path': sym, 'construct': construct,
                        'language_family': 'hash'})
        if not out.get('identity'):
            raise RuntimeError('fixture did not fingerprint: %r' % out)
        return out

    def entry(f):
        return bl.entry_from_identity(f, environment='prod', first_seen='2026-02-01',
                                      first_seen_provenance={'run_id': '1', 'observed_at':
                                                             '2026-02-01T00:00:00Z',
                                                             'observed_at_source': 'SIDECAR'},
                                      age_established=True)

    def write(repo, entries, header=None):
        doc = bl.new_ledger(header or {'established_on': '2026-02-01', 'established_commit':
                                       'a' * 40, 'approver_role': 'security-lead'}, entries)
        path = os.path.join(repo, LEDGER_PATH)
        if not os.path.isdir(os.path.dirname(path)):
            os.makedirs(os.path.dirname(path))
        with io.open(path, 'w', encoding='utf-8', newline='\n') as fh:
            fh.write(bl.serialise(doc))

    a, b, c = finding('m.a', 'run(a)'), finding('m.b', 'run(b)'), finding('m.c', 'run(c)')
    check(len({a['identity'], b['identity'], c['identity']}) == 3, 'fixtures collide')

    work = tempfile.mkdtemp(prefix='ledger-authority-')
    try:
        repo = os.path.join(work, 'repo')
        os.makedirs(repo)
        git(repo, 'init', '-q')
        write(repo, [entry(a), entry(b)])
        git(repo, 'add', '-A')
        git(repo, 'commit', '-qm', 'baseline')
        git(repo, 'checkout', '-qb', 'pr')
        # THE ATTACK: the PR grandfathers the finding it introduces, in a commit AND in the tree.
        write(repo, [entry(a), entry(b), entry(c)])
        git(repo, 'commit', '-qam', 'pr adds its own finding to the ledger')
        git(repo, 'checkout', '-q', 'main')
        # After the PR branched: main removes b (a remediation merged by someone else) ...
        write(repo, [entry(a)])
        git(repo, 'commit', '-qam', 'main removes b')
        git(repo, 'checkout', '-q', 'pr')

        ev = bl.read_for_evaluation(repo, 'main', 'pr', LEDGER_PATH)
        keys = sorted(e['identity'] for e in ev['entries'])
        check(ev['state'] == fm.LEDGER_INTACT, 'allowed: a well-formed ledger read as %r (%s)'
              % (ev['state'], ev['notes']))
        check(bool(keys), 'allowed: the effective ledger is empty, so every check below is vacuous')
        check(c['identity'] not in keys,
              'rule 1: the entry the PR added to its OWN branch is in the ledger it is evaluated '
              'against -- a self-signed baseline')
        check(b['identity'] not in keys,
              'rule 3: an entry removed on the default branch after the PR branched still '
              'grandfathers -- a removal must strengthen at once')
        check(keys == [a['identity']], 'effective ledger is %r, expected only a' % keys)
        r = fm.match([a, b, c], ev['entries'], ev['state'], environment='prod')
        got = [f['baseline_state'] for f in r['findings']]
        check(got == [fm.PRE_EXISTING_BASELINED, fm.NEW, fm.NEW],
              'cascade over the effective ledger gave %r; expected a pre-existing, b and c NEW' % got)

        # Rule 2: an addition to main after the PR branched does not grandfather the PR.
        git(repo, 'checkout', '-q', 'main')
        write(repo, [entry(a), entry(c)])
        git(repo, 'commit', '-qam', 'main admits c after the PR branched')
        git(repo, 'checkout', '-q', 'pr')
        ev = bl.read_for_evaluation(repo, 'main', 'pr', LEDGER_PATH)
        check(c['identity'] not in [e['identity'] for e in ev['entries']],
              'rule 2: an entry merged underneath the open PR grandfathered it')

        # The working tree is never read.
        write(repo, [entry(a), entry(b), entry(c)])
        ev = bl.read_for_evaluation(repo, 'main', 'pr', LEDGER_PATH)
        check(sorted(e['identity'] for e in ev['entries']) == [a['identity']],
              'rule 1: an uncommitted working-tree ledger was read')
        git(repo, 'checkout', '-q', '--', '.')

        # ── missing evidence ─────────────────────────────────────────────────
        ev = bl.read_for_evaluation(repo, 'no-such-branch', 'pr', LEDGER_PATH)
        check(ev['state'] not in usable,
              'a default ref that does not exist read as %r' % ev['state'])
        r = fm.match([a], ev['entries'], ev['state'], environment='prod')
        check(r['baseline'] == fm.BASELINE_UNAVAILABLE,
              'an unreadable ref did not make the baseline unavailable')
        ev = bl.read_for_evaluation(repo, 'main', 'pr', 'no/such/ledger.json')
        check(ev['state'] == fm.LEDGER_ABSENT, 'a ledger absent at the ref read as %r' % ev['state'])

        orphan = os.path.join(work, 'orphan')
        os.makedirs(orphan)
        git(orphan, 'init', '-q')
        write(orphan, [entry(a)])
        git(orphan, 'add', '-A')
        git(orphan, 'commit', '-qm', 'x')
        git(orphan, 'checkout', '-q', '--orphan', 'unrelated')
        git(orphan, 'commit', '-qm', 'unrelated history', '--allow-empty')
        ev = bl.read_for_evaluation(orphan, 'main', 'unrelated', LEDGER_PATH)
        check(ev['state'] not in usable,
              'no merge base (a shallow clone looks like this) read as %r' % ev['state'])

        def bad_doc(mutator, label):
            doc = json.loads(bl.serialise(bl.new_ledger(
                {'established_on': '2026-02-01', 'established_commit': 'a' * 40,
                 'approver_role': 'security-lead'}, [entry(a)])))
            mutator(doc)
            entries, state, notes, _h = bl.parse_ledger(json.dumps(doc))
            check(state not in usable,
                  '%s was accepted as a usable ledger' % label)
            check(bool(notes), '%s was refused without saying why' % label)

        bad_doc(lambda d: d['entries'][0].update(snippet='password = "hunter2"'),
                'an entry carrying a matched snippet')
        bad_doc(lambda d: d['entries'][0].update(partial_fingerprints={'x': 'y'}),
                'an entry carrying a scanner partialFingerprint')
        bad_doc(lambda d: d['entries'][0].update(where='0' * 64),
                'an entry whose identity does not derive from its components')
        bad_doc(lambda d: d['entries'][0].update(age_established='yes'),
                'an entry whose age flag is not a boolean')
        bad_doc(lambda d: d['entries'].append(dict(d['entries'][0])), 'a duplicated key')
        bad_doc(lambda d: d['header'].pop('approver_role'), 'a ledger with no establishing approver')
        bad_doc(lambda d: d['entries'][0].update(finding_subject='RELEASE'),
                'a RELEASE-scoped entry')
        for text, label in (('', 'an empty file'), ('{not json', 'invalid JSON'),
                            ('[]', 'a JSON list')):
            _e, state, _n, _h = bl.parse_ledger(text)
            check(state == fm.LEDGER_LINE_UNPARSEABLE, '%s read as %r' % (label, state))
        _e, state, _n, _h = bl.parse_ledger(bl.serialise(bl.new_ledger(
            {'established_on': '2026-02-01', 'established_commit': 'a' * 40,
             'approver_role': 'security-lead'}, [])))
        check(state == fm.LEDGER_EMPTY, 'an established ledger with no entries read as %r' % state)
    except RuntimeError as exc:
        print('UNKNOWN: the fixture repository could not be built: %s' % exc)
        return 2
    finally:
        shutil.rmtree(work, ignore_errors=True)

    if fails:
        for f in fails:
            print('FAIL: ' + f)
        return 1
    print('PASS: against a real git repository, the PR\'s own ledger edits (committed or in the '
          'working tree) are never read; an entry merged underneath an open PR does not grandfather '
          'it; a removal on the default branch takes effect at once; a missing ref, a missing merge '
          'base, an unparseable ledger, matched material, a non-deriving identity, a non-boolean age, '
          'a duplicate key, a RELEASE entry and a ledger with no approver are all unusable, and the '
          'cascade then answers BASELINE_UNAVAILABLE.')
    return 0


if __name__ == '__main__':
    sys.exit(main())

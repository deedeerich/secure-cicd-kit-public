#!/usr/bin/env python3
"""The paths that decide what the kit's controls do have ONE protected owner, and a change to the
files that decide "Self-test required" and the floor carries a decision record (KE-05, KDEC-050).

WHY THIS EXISTS

    The self-test runs on `pull_request`, so GitHub runs the PULL REQUEST'S copy of self-test.yml,
    scripts/selftest_required.py, scripts/capability_floor.py and every validator. A pull request
    that edits the `required` job (or adds any workflow with a job named "Self-test required") makes
    that check pass while weakening it. Nothing inside the repository can stop that alone: whatever
    check a pull request runs, the same pull request can rewrite. What stops it is a REVIEWER the
    pull request cannot choose: CODEOWNERS on those paths, with the ruleset requiring code-owner
    review and allowing no bypass. This file makes the first half true and checkable:

      --check-codeowners  every protected path (below), and a probe file under each protected
                          directory, is owned -- by GitHub's last-matching-rule semantics, in the
                          CODEOWNERS file GitHub actually reads -- by exactly the protected owner the
                          file declares on its `# kit-protected-owner:` line. GitHub accepts approval
                          from ANY one owner on a line, so a second owner on a protected line would be
                          a second, weaker door. In an ADOPTED copy (scripts/export_for_adoption.py
                          left its watermark, or --adopted) any placeholder owner (YOUR_ORG,
                          replace-me) is refused: a placeholder team owns nothing.
      --check-change      against the base, a change to a CHANGE_GUARDED file needs lines ADDED to
                          docs/assurance/PROTECTED_CHANGE_LOG.md that name a decision id and every
                          guarded path changed; a line removed from the log is refused (append-only).
                          This is visibility, not authority: the pull request can rewrite this check
                          too. Its authority is the code-owner review above.

EXIT  0 holds   1 refused (each named)   2 could not be checked
"""
import argparse
import fnmatch
import io
import os
import re
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
PLACEHOLDER_OWNER = '@YOUR_ORG/replace-me-kit-control-owners'
PLACEHOLDER = re.compile(r'YOUR_ORG|replace-me', re.I)
WATERMARK = '.neutral-export-watermark.json'
CHANGE_LOG = 'docs/assurance/PROTECTED_CHANGE_LOG.md'
# The floor, the registry, the policy register, the workflows and actions, the validators, and the
# owners file itself. A directory entry is checked on every tracked file under it plus a probe.
PROTECTED = ('CODEOWNERS', '.github/CODEOWNERS', 'docs/CODEOWNERS', 'capability-floor.json',
             'scanner-registry.yaml', 'assurance-taxonomy.yaml', 'rollback-resource-classes.yaml',
             'id-mappings.json', 'policy/policy-registration.json', 'governance-profile.json', '.github/', 'scripts/', 'tests/',
             'profiles/', 'policy/', 'schemas/', 'templates/', 'api/')
# Deliberately security-approvers only (the separation of duties CODEOWNERS states): exceptions.
EXEMPT = ('schemas/disposition.schema.json', 'schemas/disposition-request.schema.json')
# The files that decide whether "Self-test required" and the floor mean what they say.
CHANGE_GUARDED = ('.github/workflows/self-test.yml', 'scripts/selftest_required.py',
                  'scripts/capability_floor.py', 'scripts/protected_paths.py', 'capability-floor.json',
                  'scanner-registry.yaml', 'CODEOWNERS', '.github/CODEOWNERS', 'docs/CODEOWNERS',
                  '.github/actions/capability-floor/', 'tests/prove_selftest_required.py',
                  'tests/prove_capability_floor.py', 'tests/prove_scanner_floor_shrink.py',
                  # The governance gate (KDEC-059): the merge decision, its profile and its workflow.
                  'scripts/governance_gate.py', 'governance-profile.json', '.github/workflows/governance-gate.yml',
                  'tests/prove_governance_profiles.py')


def codeowners_file(root):
    """GitHub reads the FIRST of these it finds; a later one is ignored entirely."""
    for rel in ('.github/CODEOWNERS', 'CODEOWNERS', 'docs/CODEOWNERS'):
        if os.path.isfile(os.path.join(root, rel)):
            return rel
    return None


def parse(text):
    """-> (declared protected owner or None, [(pattern, [owners])]) in file order."""
    declared, rules = None, []
    for ln in text.splitlines():
        m = re.match(r'^#\s*kit-protected-owner:\s*(\S+)\s*$', ln)
        if m:
            declared = m.group(1)
            continue
        s = ln.split('#', 1)[0].strip() if not ln.lstrip().startswith('#') else ''
        if s:
            parts = s.split()
            rules.append((parts[0], parts[1:]))
    return declared, rules


def matches(pattern, path):
    """GitHub CODEOWNERS (gitignore-style) for the shapes this kit uses: `*`, `/dir/`, `/file`,
    `dir/`, `*.ext`, and globs."""
    anchored = pattern.startswith('/')
    p = pattern.lstrip('/')
    if p in ('*', '**'):
        return True
    if p.endswith('/'):
        if anchored:
            return path.startswith(p)
        return path.startswith(p) or ('/' + p) in ('/' + path)
    if anchored or '/' in p:
        return fnmatch.fnmatchcase(path, p) or path.startswith(p.rstrip('/') + '/')
    return any(fnmatch.fnmatchcase(seg, p) for seg in path.split('/')) or fnmatch.fnmatchcase(path, p)


def owners_of(rules, path):
    hit = None
    for pat, owners in rules:
        if matches(pat, path):
            hit = (pat, owners)
    return hit


def tracked(root):
    try:
        r = subprocess.run(['git', '-C', root, 'ls-files'], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        if r.returncode == 0:
            return [x for x in r.stdout.decode('utf-8', 'replace').splitlines() if x]
    except OSError:
        pass
    out = []
    for d, _dirs, files in os.walk(root):
        if '.git' in d.split(os.sep):
            continue
        for f in files:
            out.append(os.path.relpath(os.path.join(d, f), root).replace(os.sep, '/'))
    return out


def probe_paths(files):
    out = set()
    for p in PROTECTED:
        if p.endswith('/'):
            out.add(p + '__kit_protected_probe__/x.yml')
            out.update(f for f in files if f.startswith(p))
        else:
            out.add(p)
    return sorted(x for x in out if x not in EXEMPT)


def check_codeowners(root, adopted=None):
    rel = codeowners_file(root)
    if not rel:
        return ['no CODEOWNERS file (looked in .github/, the root and docs/): nothing is owned']
    text = io.open(os.path.join(root, rel), encoding='utf-8').read()
    declared, rules = parse(text)
    probs = []
    if not declared:
        return ['%s declares no `# kit-protected-owner: @org/team` line: the protected owner is unknown' % rel]
    if adopted is None:
        adopted = os.path.isfile(os.path.join(root, WATERMARK))
    if adopted:
        bad = sorted({o for _p, owners in rules for o in owners if PLACEHOLDER.search(o)}
                     | ({declared} if PLACEHOLDER.search(declared) else set()))
        if bad:
            probs.append('%s still names placeholder owner(s) %s in an adopted copy: a placeholder team owns '
                         'nothing, so code-owner review is not required for those paths. Replace them '
                         '(the kit-protected-owner line too) with real teams' % (rel, ', '.join(bad)))
    for path in probe_paths(tracked(root)):
        hit = owners_of(rules, path)
        if not hit:
            probs.append('protected path %s matches no rule in %s (unowned)' % (path, rel))
        elif hit[1] != [declared]:
            probs.append('protected path %s is owned by %s (rule %r), not solely by the protected owner %s: '
                         'GitHub accepts approval from ANY one owner on the matching line'
                         % (path, ' '.join(hit[1]) or '(nobody)', hit[0], declared))
    return probs


def git(root, *args):
    r = subprocess.run(['git', '-C', root] + list(args), stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    return r.returncode, r.stdout.decode('utf-8', 'replace')


def guarded(path):
    return any(path == g or (g.endswith('/') and path.startswith(g)) for g in CHANGE_GUARDED)


def check_change(changed, added_log, removed_log):
    """-> problems for one change: its guarded paths, and the log lines it added and removed."""
    probs = []
    if removed_log:
        probs.append('%s lost %d line(s): the log is append-only' % (CHANGE_LOG, len(removed_log)))
    hit = sorted(p for p in changed if guarded(p))
    if not hit:
        return probs
    text = '\n'.join(added_log)
    if not re.search(r'\b[A-Z]{2,}-\d+\b', text):
        probs.append('this change edits %s, which decide what "Self-test required" and the floor mean, and adds '
                     'no decision record to %s (a line naming a decision id and each path)'
                     % (', '.join(hit), CHANGE_LOG))
        return probs
    for p in hit:
        if p not in text:
            probs.append('%s: the decision record added to %s does not name %s' % (p, CHANGE_LOG, p))
    return probs


def change_from_git(root, base):
    rc, _ = git(root, 'cat-file', '-e', '%s^{commit}' % base)
    if rc != 0:
        return None
    rc, out = git(root, 'diff', '--name-only', base, 'HEAD')
    if rc != 0:
        return None
    changed = [x for x in out.splitlines() if x]
    rc, diff = git(root, 'diff', '-U0', base, 'HEAD', '--', CHANGE_LOG)
    added = [ln[1:] for ln in diff.splitlines() if ln.startswith('+') and not ln.startswith('+++')]
    removed = [ln[1:] for ln in diff.splitlines() if ln.startswith('-') and not ln.startswith('---')]
    return changed, added, removed


def self_test():
    import shutil
    import tempfile
    fails = []
    good = ('# kit-protected-owner: @o/control\n* @o/control\n/schemas/disposition.schema.json @o/sec\n'
            '/schemas/disposition-request.schema.json @o/sec\n')
    d = tempfile.mkdtemp(prefix='owners-')
    try:
        io.open(os.path.join(d, 'CODEOWNERS'), 'w').write(good)
        if check_codeowners(d, adopted=True):
            fails.append('a fully owned file was refused: %s' % check_codeowners(d, adopted=True))
        io.open(os.path.join(d, 'CODEOWNERS'), 'w').write(good + '/scanner-registry.yaml @o/control @o/other\n')
        if not any('scanner-registry.yaml' in p for p in check_codeowners(d)):
            fails.append('a second owner on a protected line was accepted')
        io.open(os.path.join(d, 'CODEOWNERS'), 'w').write(good.replace('* @o/control\n', '/scripts/ @o/control\n'))
        if not any('.github/' in p and 'unowned' in p for p in check_codeowners(d)):
            fails.append('an unowned .github/ path was accepted')
        io.open(os.path.join(d, 'CODEOWNERS'), 'w').write(good.replace('@o/control', PLACEHOLDER_OWNER))
        if check_codeowners(d, adopted=False) or not check_codeowners(d, adopted=True):
            fails.append('the placeholder must pass the template and be refused in an adopted copy')
    finally:
        shutil.rmtree(d, ignore_errors=True)
    if check_change(['README.md'], [], []):
        fails.append('an unguarded change was refused')
    if not check_change(['scripts/selftest_required.py'], [], []):
        fails.append('a guarded change with no record was accepted')
    if check_change(['scripts/selftest_required.py'], ['| 2026-11-11 | KDEC-050 | scripts/selftest_required.py |'], []):
        fails.append('a guarded change with a record was refused')
    if not check_change(['README.md'], [], ['| old |']):
        fails.append('a log line removed was accepted')
    if fails:
        print('SELF-TEST FAILED: ' + '; '.join(fails))
        return 1
    print('self-test ok: 8 cases (owned, second owner, unowned, placeholder template/adopted, change record)')
    return 0


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.split('\n')[0])
    ap.add_argument('--root', default=ROOT)
    ap.add_argument('--check-codeowners', action='store_true')
    ap.add_argument('--adopted', action='store_true', help='refuse placeholder owners (implied by the watermark)')
    ap.add_argument('--check-change', action='store_true')
    ap.add_argument('--base-ref')
    ap.add_argument('--self-test', action='store_true')
    a = ap.parse_args(argv)
    if a.self_test:
        return self_test()
    probs = []
    if a.check_codeowners:
        probs += check_codeowners(a.root, True if a.adopted else None)
    if a.check_change:
        got = change_from_git(a.root, a.base_ref or 'HEAD^1')
        if got is None:
            print('UNKNOWN: base %r could not be read: the change was NOT checked' % a.base_ref)
            return 2
        probs += check_change(*got)
    for p in probs:
        print('REFUSED: ' + p)
    if probs:
        return 1
    print('protected paths: hold')
    return 0


if __name__ == '__main__':
    sys.exit(main())

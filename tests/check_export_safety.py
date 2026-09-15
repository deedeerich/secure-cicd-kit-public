#!/usr/bin/env python3
"""Fail the build if the neutral core names anyone. The deny list existed; nothing ran it.

WHY THIS EXISTS
    `scripts/export-deny.txt` has listed account identities, private repository names and a former
    engagement since it was written. Exactly one thing read it: `export_for_adoption.py`, which a
    human runs by hand when preparing a copy for somebody else.

    So the protection was real and entirely deferred. The names sat in the tree, and the only thing
    standing between them and disclosure was somebody remembering to run an export script. That is
    DOCUMENTED, not ENFORCED -- two rungs of the maturation ladder apart, and the gap is invisible
    because nothing fails while the names simply sit there.

    A sweep on 2026-09-15 found 89 line hits across 19 neutral files naming one employer's tooling
    and a second engagement's repositories, in a kit whose whole premise is being employer-neutral.

WHAT NEUTRAL MAY AND MAY NOT KNOW
    Direction of knowledge is one-way:

        overlay  ──knows──>  neutral
        neutral  ──MUST NOT know──>  overlay

    The neutral core may know that an EXTENSION POINT exists. It may not know who fills it. A
    neutral kit that reports "SonarCloud: absent" is not merely inaccurate about its own contract --
    it is telling every future consumer what a previous consumer used.

        ABSENT BY DESIGN != MISSING CAPABILITY

    The lessons stay. A defect found while working somewhere else is engineering knowledge and
    belongs in the comments that prevent it recurring. WHOSE estate it was found in is not.

SCOPE: TRACKED FILES ONLY, AND NOT THE OVERLAY
    Only files git actually tracks can be published, so only those are scanned -- which also means
    an ignored file that someone force-adds starts failing immediately, which is the point.

    `overlays/*` is EXCLUDED. An overlay is allowed to know its own name; that is what makes it an
    overlay. Export-time filtering still applies to it, and is a separate control.

    `scripts/export-deny.txt` is excluded from its own scan. It names the things being protected --
    that is its function, and it is marked never-export.

USAGE
    python3 tests/check_export_safety.py [--deny scripts/export-deny.txt]
    python3 tests/check_export_safety.py --self-test

EXIT
    0  neutral core names nobody      1  a denied pattern reached a tracked neutral file
    2  self-test failed or the deny list is missing/empty
"""
import argparse
import io
import os
import re
import subprocess
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DEFAULT_DENY = os.path.join('scripts', 'export-deny.txt')

# Excluded from the scan, each for a stated reason rather than because it was noisy.
EXCLUDE_PREFIXES = (
    'overlays/',              # an overlay may know its own identity; that is what it is
)
EXCLUDE_EXACT = (
    'scripts/export-deny.txt',  # names what it protects, by design; marked never-export
)
# Binary-ish extensions where a regex hit means nothing useful.
SKIP_EXT = {'.png', '.jpg', '.jpeg', '.gif', '.ico', '.pdf', '.zip', '.gz', '.pyc', '.woff',
            '.woff2', '.ttf', '.class', '.jar', '.so', '.dll', '.exe'}


def load_deny(path):
    """-> [(compiled, why, raw)]. Format: <regex> || <why>. Blank lines and # comments ignored."""
    out = []
    with io.open(path, encoding='utf-8', errors='replace') as fh:
        for line in fh:
            s = line.strip()
            if not s or s.startswith('#'):
                continue
            raw, why = (s.split('||', 1) + [''])[:2]
            raw, why = raw.strip(), why.strip()
            if not raw:
                continue
            try:
                out.append((re.compile(raw, re.I), why, raw))
            except re.error as e:
                # A pattern that does not compile protects NOTHING while looking like it does.
                raise SystemExit('deny pattern %r does not compile: %s' % (raw, e))
    return out


def tracked_files(root):
    """Only what git would publish. An ignored file that gets force-added starts failing at once."""
    try:
        out = subprocess.check_output(['git', '-C', root, 'ls-files', '-z'],
                                      stderr=subprocess.DEVNULL)
    except (OSError, subprocess.CalledProcessError):
        return None
    return [p for p in out.decode('utf-8', 'replace').split('\0') if p]


def in_scope(rel):
    if rel in EXCLUDE_EXACT:
        return False
    for p in EXCLUDE_PREFIXES:
        if rel.startswith(p):
            return False
    return os.path.splitext(rel)[1].lower() not in SKIP_EXT


def scan(root, deny, files):
    hits = []
    for rel in files:
        if not in_scope(rel):
            continue
        full = os.path.join(root, rel.replace('/', os.sep))
        try:
            with io.open(full, encoding='utf-8', errors='replace') as fh:
                for n, line in enumerate(fh, 1):
                    for rx, why, raw in deny:
                        m = rx.search(line)
                        if m:
                            hits.append((rel, n, raw, why, m.group(0), line.strip()[:110]))
        except (OSError, ValueError):
            continue
    return hits


def self_test():
    import tempfile
    fails = []
    d = tempfile.mkdtemp()
    dn = os.path.join(d, 'deny.txt')
    io.open(dn, 'w', encoding='utf-8').write(
        '# comment\n\nacmecorp\\s*global   || former engagement\n'
        'secretproject       || private repository name\n'
        '[unclosed          || deliberately fine, see below\n'.replace('[unclosed', 'goodpattern'))
    deny = load_deny(dn)
    if len(deny) != 3:
        fails.append('deny list parsing wrong (%d patterns, expected 3)' % len(deny))
    if deny and deny[0][1] != 'former engagement':
        fails.append('the WHY column was not captured, so a failure cannot explain itself')

    os.makedirs(os.path.join(d, 'overlays', 'someone'), exist_ok=True)
    os.makedirs(os.path.join(d, 'scripts'), exist_ok=True)
    io.open(os.path.join(d, 'clean.md'), 'w', encoding='utf-8').write('nothing to see\n')
    io.open(os.path.join(d, 'dirty.md'), 'w', encoding='utf-8').write(
        'built during the AcmeCorp Global engagement\n')
    io.open(os.path.join(d, 'overlays', 'someone', 'x.md'), 'w', encoding='utf-8').write(
        'AcmeCorp Global overlay\n')
    io.open(os.path.join(d, 'scripts', 'export-deny.txt'), 'w', encoding='utf-8').write(
        'acmecorp\\s*global || former engagement\n')

    files = ['clean.md', 'dirty.md', 'overlays/someone/x.md', 'scripts/export-deny.txt']
    hits = scan(d, deny, files)
    got = sorted(set(h[0] for h in hits))

    if 'dirty.md' not in got:
        fails.append('a denied name in a tracked neutral file was NOT caught')
    if 'clean.md' in got:
        fails.append('a clean file was reported')
    # AN OVERLAY MAY KNOW ITS OWN NAME. Flagging it would make the boundary unusable.
    if 'overlays/someone/x.md' in got:
        fails.append('an overlay was flagged for naming itself -- that is what an overlay is')
    # THE DENY LIST NAMES WHAT IT PROTECTS. Scanning it would fail every build forever.
    if 'scripts/export-deny.txt' in got:
        fails.append('the deny list flagged itself')
    # Case-insensitive: "AcmeCorp Global" must match the lowercase pattern.
    if not any(h[4].lower().startswith('acmecorp') for h in hits):
        fails.append('matching is not case-insensitive, so any capitalisation evades it')
    # VACUITY GUARD: a scan that inspected zero eligible files cannot establish safety.
    if not [f for f in files if in_scope(f)]:
        fails.append('no file was in scope; a vacuous pass is not a pass')

    if fails:
        print('SELF-TEST FAILED:')
        for f in fails:
            print('  - %s' % f)
        return False
    print('self-test ok: a denied name in neutral fails, a clean file does not, an overlay may')
    print('              name itself, the deny list does not flag itself, matching ignores case,')
    print('              and a scan with nothing in scope is not treated as a pass')
    return True


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--deny', default=DEFAULT_DENY)
    ap.add_argument('--self-test', action='store_true')
    a = ap.parse_args()
    if a.self_test:
        return 0 if self_test() else 2
    if not self_test():
        print('ABORTING -- a control that cannot prove it detects anything proves nothing.')
        return 2

    dpath = a.deny if os.path.isabs(a.deny) else os.path.join(ROOT, a.deny)
    if not os.path.exists(dpath):
        print('::error title=No deny list::%s is missing. This control cannot run, which is a '
              'FAILURE and not a skip -- absence of a list is not absence of names.' % dpath)
        return 2
    deny = load_deny(dpath)
    if not deny:
        print('::error title=Empty deny list::%s compiled to zero patterns. A check that '
              'inspects nothing reports success forever (LM-017).' % dpath)
        return 2

    files = tracked_files(ROOT)
    if files is None:
        print('::error title=Not a git repository::cannot determine which files would be '
              'published. Unknown scope is not empty scope.')
        return 2
    scoped = [f for f in files if in_scope(f)]
    if not scoped:
        print('::error title=Nothing in scope::%d tracked file(s), none eligible. A vacuous pass '
              'is not a pass.' % len(files))
        return 2

    hits = scan(ROOT, deny, scoped)
    print('')
    print('EXPORT SAFETY -- does the neutral core name anyone?')
    print('-' * 92)
    print('  deny patterns            %d' % len(deny))
    print('  tracked files            %d' % len(files))
    print('  scanned (neutral only)   %d   overlays/ excluded: an overlay may know its own name'
          % len(scoped))
    print('')
    if not hits:
        print('  CLEAN -- no denied pattern appears in any tracked neutral file.')
        print('')
        print('  This proves the NAMES are absent. It does not prove the lessons were kept, which')
        print('  is the other half and belongs to review.')
        return 0
    byfile = {}
    for rel, n, raw, why, got, line in hits:
        byfile.setdefault(rel, []).append((n, raw, why, got, line))
    print('  %d hit(s) in %d file(s):' % (len(hits), len(byfile)))
    print('')
    for rel in sorted(byfile):
        print('  %s' % rel)
        for n, raw, why, got, line in byfile[rel][:6]:
            print('    :%-5d %-28s  %s' % (n, got[:28], why))
            print('           %s' % line)
        if len(byfile[rel]) > 6:
            print('    ... %d more' % (len(byfile[rel]) - 6))
        print('')
    print('::error title=Neutral core names someone::%d denied pattern hit(s). Keep the LESSON, '
          'remove the NAME. A kit that is employer-neutral by intent and not by construction '
          'discloses one consumer to the next.' % len(hits))
    return 1


if __name__ == '__main__':
    sys.exit(main())

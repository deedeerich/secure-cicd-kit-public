#!/usr/bin/env python3
"""A neutral export ships the KIT, not the workshop it was built in.

WHY THIS EXISTS

    The first export to the public mirror after the release to main (2026-10-16) was prepared and
    read before it was pushed, and three things in it were not the kit:

      .context/          the agents' continuity records: the owner's personal trackers by project
                         key, which builder platform receives the explainer, private commit ids it
                         was reconciled against. Working memory for this repository's sessions,
                         meaningless to a reader of the public copy and not theirs to read.
      an employer slug   the deny pattern for one employer's name matched it with a space or none,
                         and missed it with a hyphen -- the form an overlay directory takes.
      a private repo     the Level 2 consumer repository was named in an architecture document.

    The last two are deny-list entries (export-deny.txt, which never ships, so the names are not
    repeated here). The first is SCOPE, and scope is asserted by running the export as shipped.

WHAT IT PROVES
    E1  the export runs to completion on this tree with the neutral profile (its deny gate passes)
    E2  nothing under .context/, overlays/ or scripts/export-profiles/ is shipped, and neither is
        scripts/export-deny.txt nor the kit's own internal consumer-path test workflow
    E3  the kit itself is shipped: the reusable workflows, the scripts and this test

    And, against a throwaway source repository built here (the exporter copied into it, so the
    real tree and its deny list are never touched), the three places the exporter's behaviour and
    its documentation disagreed (review findings, 2026-10-16):
    E4  NO DENY LIST IS A REFUSAL. With export-deny.txt absent, or present with no pattern in it,
        the export exits non-zero and writes nothing. It used to print a warning and export with
        nothing checked -- and since the deny list never ships, every recipient running the
        shipped script onward was in exactly that state.
    E5  THE PROFILE IS BOUND TO THE DESTINATION. The watermark records the profile a copy was
        taken under, and an incremental under a different profile (or none, or into a copy whose
        watermark predates the field) is refused by name. The profile README promised this; the
        watermark had no such field and nothing compared one. A same-profile incremental still
        runs (the positive control).
    E7  THE WATERMARK KEEPS THE COMMIT AND DROPS THE BRANCH (owner's choice for the public copy,
        2026-10-16). It records the source commit -- the three-way incremental needs nothing
        else -- and a neutral source label, never the private branch name; an incremental from
        the commit alone still runs and advances it.
    E9  THE COPY PASSES ITS OWN CHECKS. The capability inventory is regenerated from the copy (it
        named a workflow the export withholds), and the copy's proof census passes (a tool only
        the withheld workflow runs looked unwired). Both failed the first public Release 2 PR.
    E8  WHAT GIT DOES NOT TRACK IS NOT THE KIT. An untracked file that is not gitignored (a scanner
        tarball an earlier CI step downloaded) is neither scanned nor shipped.
    E6  THE EXCLUDED PATH IS EXCLUDED. A path list defined for exclusion was never read, so the
        file it named shipped in every full export and every incremental.
    E10 THE ZIP HOLDS WHAT WAS EXPORTED, AND NOTHING A CHECK LEFT BEHIND (2026-10-26). The work
        package for 4060290 carried 32 compiled .pyc files under __pycache__: the copy's own checks
        were run inside the exported tree, and the tree was then zipped by hand. The copy step
        excluded __pycache__; nothing guarded the step after it. `--zip` now packs a tree and
        REFUSES, writing no zip, when the tree holds __pycache__, *.pyc/*.pyo, .pytest_cache,
        .git, .context, .claude, export profiles, the deny list or an overlay the copy's profile
        did not include. A clean export zips (the positive control), `--out ... --zip` packs the
        copy it has just written, and an existing zip is never overwritten.

USAGE  python3 tests/prove_export_scope.py
EXIT   0 scope holds, 1 it does not, 2 the export could not be run
"""
import json
import os
import shutil
import subprocess
import sys
import tempfile

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
EXPORT = os.path.join(ROOT, 'scripts', 'export_for_adoption.py')

INTERNAL_WORKFLOW = '.github/workflows/consumer-path-test.yml'
NEVER_SHIPPED_TREES = ('.context/', 'overlays/', 'scripts/export-profiles/')
NEVER_SHIPPED_FILES = ('scripts/export-deny.txt', INTERNAL_WORKFLOW)
WATERMARK = '.neutral-export-watermark.json'
# A branch name the synthetic source works on; it must never reach a written watermark (E7).
PRIVATE_BRANCH = 'zzq-private-branch'

# A made-up recipient for the synthetic source. Nothing here names anybody real.
RECIPIENT = 'recipient-x'
RECIPIENT_TOKEN = 'zzqrecipientname'
DENY_TEXT = ('# synthetic deny list for the proof\n'
             + RECIPIENT_TOKEN + '   || the synthetic recipient\'s name\n'
             + '!zzqownername     || the synthetic owner identity, never liftable\n')
PROFILE_TEXT = ('INCLUDE_OVERLAY ' + RECIPIENT + '\n'
                'LIFT ' + RECIPIENT_TOKEN + '   || this copy is for them\n')


def _git(args, cwd):
    return subprocess.run(['git', '-c', 'user.name=proof', '-c', 'user.email=proof@example.invalid',
                           '-c', 'core.autocrlf=false'] + args, cwd=cwd, capture_output=True,
                          text=True, encoding='utf-8', errors='replace')


def _write(path, text):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, 'w', encoding='utf-8', newline='\n') as f:
        f.write(text)


def make_source(work, deny_text):
    """A minimal committed source repository holding the exporter as shipped."""
    src = os.path.join(work, 'src')
    os.makedirs(os.path.join(src, 'scripts'))
    shutil.copyfile(EXPORT, os.path.join(src, 'scripts', 'export_for_adoption.py'))
    if deny_text is not None:
        _write(os.path.join(src, 'scripts', 'export-deny.txt'), deny_text)
    _write(os.path.join(src, 'scripts', 'export-profiles', RECIPIENT + '.txt'), PROFILE_TEXT)
    _write(os.path.join(src, 'README.md'), 'a kit\n')
    _write(os.path.join(src, INTERNAL_WORKFLOW.replace('/', os.sep)), 'name: internal\n')
    _write(os.path.join(src, 'overlays', RECIPIENT, 'notes.md'), 'for ' + RECIPIENT_TOKEN + '\n')
    for args in (['init', '-q'], ['checkout', '-q', '-b', PRIVATE_BRANCH], ['add', '-A'],
                 ['commit', '-qm', 'base']):
        p = _git(args, src)
        if p.returncode != 0:
            raise RuntimeError('git %s failed: %s' % (args[0], p.stderr[:300]))
    return src


def run_export(src, *args):
    env = dict(os.environ, PYTHONIOENCODING='utf-8')
    return subprocess.run([sys.executable, os.path.join(src, 'scripts', 'export_for_adoption.py')]
                          + list(args), cwd=src, capture_output=True, text=True, encoding='utf-8',
                          errors='replace', env=env)


def prove_no_deny_list_refuses(fails):
    for label, deny in (('absent', None), ('empty', '# only a comment\n\n')):
        work = tempfile.mkdtemp(prefix='export-nodeny-')
        try:
            src = make_source(work, deny)
            out = os.path.join(work, 'copy')
            p = run_export(src, '--out', out)
            if p.returncode == 0:
                fails.append('E4 deny list %s: the export exited 0 with nothing checked' % label)
            if os.path.exists(out):
                fails.append('E4 deny list %s: the export wrote %s' % (label, out))
        finally:
            shutil.rmtree(work, ignore_errors=True)


def prove_profile_bound(fails):
    work = tempfile.mkdtemp(prefix='export-profile-')
    try:
        src = make_source(work, DENY_TEXT)
        dest = os.path.join(work, 'copy')
        p = run_export(src, '--out', dest, '--profile', RECIPIENT)
        if p.returncode != 0:
            fails.append('E5 setup: the profiled full export failed: %s' % (p.stdout + p.stderr)[-600:])
            return
        raw = open(os.path.join(dest, WATERMARK), encoding='utf-8').read()
        wm = json.loads(raw)
        if PRIVATE_BRANCH in raw:
            fails.append('E7 the watermark names the private source branch')
        if not wm.get('source_commit'):
            fails.append('E7 the watermark does not record the source commit')
        if wm.get('profile') != RECIPIENT:
            fails.append('E5 the watermark does not record the profile (got %r)' % wm.get('profile'))
        _write(os.path.join(src, 'README.md'), 'a kit, changed\n')
        _git(['commit', '-qam', 'change'], src)
        p = run_export(src, '--into', dest)
        if p.returncode == 0:
            fails.append('E5 an incremental with NO profile into a profiled copy was not refused')
        p = run_export(src, '--into', dest, '--profile', RECIPIENT, '--apply')
        if p.returncode != 0:
            fails.append('E5 control: a same-profile incremental was refused: %s'
                         % (p.stdout + p.stderr)[-600:])
        else:
            # E7: the three-way check ran from the commit alone, and the advanced watermark
            # still names no branch.
            raw = open(os.path.join(dest, WATERMARK), encoding='utf-8').read()
            if PRIVATE_BRANCH in raw:
                fails.append('E7 the incremental watermark names the private source branch')
            if json.loads(raw).get('source_commit') != _git(['rev-parse', 'HEAD'], src).stdout.strip():
                fails.append('E7 the incremental did not advance the watermark to the source commit')
        # A neutral copy, then an incremental that tries to bring a profile into it.
        dest2 = os.path.join(work, 'copy2')
        p = run_export(src, '--out', dest2)
        if p.returncode != 0:
            fails.append('E5 setup: the neutral full export failed: %s' % (p.stdout + p.stderr)[-600:])
            return
        _write(os.path.join(src, 'README.md'), 'a kit, changed again\n')
        _git(['commit', '-qam', 'change2'], src)
        p = run_export(src, '--into', dest2, '--profile', RECIPIENT)
        if p.returncode == 0:
            fails.append('E5 a profiled incremental into a NEUTRAL copy was not refused')
        # A watermark written before the field existed says nothing about its rules.
        wp = os.path.join(dest2, WATERMARK)
        legacy = json.load(open(wp, encoding='utf-8'))
        legacy.pop('profile', None)
        with open(wp, 'w', encoding='utf-8') as f:
            json.dump(legacy, f)
        p = run_export(src, '--into', dest2)
        if p.returncode == 0:
            fails.append('E5 an incremental into a copy whose watermark records no profile was '
                         'not refused')
    finally:
        shutil.rmtree(work, ignore_errors=True)


def prove_excluded_path(fails):
    work = tempfile.mkdtemp(prefix='export-exclude-')
    try:
        src = make_source(work, DENY_TEXT)
        dest = os.path.join(work, 'copy')
        p = run_export(src, '--out', dest)
        if p.returncode != 0:
            fails.append('E6 setup: the full export failed: %s' % (p.stdout + p.stderr)[-600:])
            return
        if os.path.exists(os.path.join(dest, INTERNAL_WORKFLOW.replace('/', os.sep))):
            fails.append('E6 the full export shipped %s' % INTERNAL_WORKFLOW)
            # Reset so the incremental is tested on its own: as though it had never shipped.
            os.remove(os.path.join(dest, INTERNAL_WORKFLOW.replace('/', os.sep)))
            wp = os.path.join(dest, WATERMARK)
            wm = json.load(open(wp, encoding='utf-8'))
            wm.get('files', {}).pop(INTERNAL_WORKFLOW, None)
            with open(wp, 'w', encoding='utf-8') as f:
                json.dump(wm, f)
        _write(os.path.join(src, INTERNAL_WORKFLOW.replace('/', os.sep)), 'name: internal v2\n')
        _git(['commit', '-qam', 'touch internal'], src)
        p = run_export(src, '--into', dest, '--apply')
        if os.path.exists(os.path.join(dest, INTERNAL_WORKFLOW.replace('/', os.sep))):
            fails.append('E6 the incremental export shipped %s' % INTERNAL_WORKFLOW)
    finally:
        shutil.rmtree(work, ignore_errors=True)
def prove_untracked_not_kit(fails):
    """E8: a file git does not track is not the kit, ignored or not.

    Self-test run 39618329392 (2026-10-21) went red because an earlier step downloaded a scanner
    tarball into the checkout. It was untracked but not gitignored, so the exporter scanned it --
    a denied short name matched three bytes of compressed data -- and would have copied it. The
    exporter excluded only IGNORED files, though its own rule is that the kit is what git tracks.
    """
    work = tempfile.mkdtemp(prefix='export-untracked-')
    try:
        src = make_source(work, DENY_TEXT)
        stray_bin = os.path.join(src, 'scanner_9.9.9_linux_x64.tar.gz')
        with open(stray_bin, 'wb') as f:
            f.write(b'\x1f\x8b\x08\x00' + b'\x00\x07' + RECIPIENT_TOKEN.encode() + b'\x00\xff')
        _write(os.path.join(src, 'downloads', 'notes.txt'), 'fetched for ' + RECIPIENT_TOKEN + '\n')
        out = os.path.join(work, 'copy')
        p = run_export(src, '--out', out, '--allow-dirty')
        if p.returncode != 0:
            fails.append('E8 an untracked, non-ignored file blocked the export: %s'
                         % (p.stdout + p.stderr)[-400:])
        for rel in ('scanner_9.9.9_linux_x64.tar.gz', 'downloads/notes.txt'):
            if os.path.exists(os.path.join(out, rel.replace('/', os.sep))):
                fails.append('E8 the export shipped the untracked file %s' % rel)
        if not os.path.isfile(os.path.join(out, 'README.md')) and p.returncode == 0:
            fails.append('E8 control: the tracked README.md was not shipped')
    finally:
        shutil.rmtree(work, ignore_errors=True)


def _zip_names(path):
    import zipfile
    with zipfile.ZipFile(path) as zf:
        return zf.namelist()


# Leftovers a check run inside an exported tree can create, plus what must never ship at all.
ZIP_LEFTOVERS = (('scripts/__pycache__/helper.cpython-311.pyc', 'scripts/__pycache__'),
                 ('scripts/stray.pyc', 'scripts/stray.pyc'),
                 ('scripts/stray.pyo', 'scripts/stray.pyo'),
                 ('.pytest_cache/v/cache/nodeids', '.pytest_cache'),
                 ('.git/HEAD', '.git'),
                 ('.context/CONTINUATION.md', '.context'),
                 ('.claude/settings.json', '.claude'),
                 ('scripts/export-profiles/x.txt', 'scripts/export-profiles'),
                 ('scripts/export-deny.txt', 'scripts/export-deny.txt'),
                 ('overlays/someone-else/notes.md', 'overlays/someone-else'))


def prove_zip_refuses_leftovers(fails):
    """E10: --zip packs only a clean exported tree, and refuses anything a check left behind."""
    work = tempfile.mkdtemp(prefix='export-zip-')
    try:
        src = make_source(work, DENY_TEXT)
        _write(os.path.join(src, 'scripts', 'helper.py'), 'X = 1\n')
        _git(['add', '-A'], src)
        _git(['commit', '-qm', 'helper'], src)
        out = os.path.join(work, 'copy')
        zp = os.path.join(work, 'copy.zip')
        p = run_export(src, '--out', out, '--profile', RECIPIENT, '--zip', zp)
        if p.returncode != 0 or not os.path.isfile(zp):
            fails.append('E10 --out with --zip did not produce a zip (exit %d): %s'
                         % (p.returncode, (p.stdout + p.stderr)[-400:]))
            return
        names = _zip_names(zp)
        if not all(n.startswith('copy/') for n in names):
            fails.append('E10 zip entries are not under one top folder named for the copy: %s'
                         % names[:3])
        for must in ('README.md', 'scripts/helper.py', WATERMARK,
                     'overlays/' + RECIPIENT + '/notes.md'):
            if 'copy/' + must not in names:
                fails.append('E10 control: the zip is missing %s' % must)
        for rel, root_of in ZIP_LEFTOVERS:
            path = os.path.join(out, rel.replace('/', os.sep))
            os.makedirs(os.path.dirname(path), exist_ok=True)
            with open(path, 'wb') as f:
                f.write(b'\x00leftover\n')
            bad = os.path.join(work, 'bad.zip')
            q = run_export(src, '--zip-tree', out, '--zip', bad)
            said = q.stdout + q.stderr
            if q.returncode == 0:
                fails.append('E10 --zip-tree packed a tree holding %s' % rel)
            if os.path.exists(bad):
                fails.append('E10 --zip-tree wrote a zip although the tree holds %s' % rel)
                os.remove(bad)
            if root_of not in said.replace('\\', '/'):
                fails.append('E10 the refusal for %s did not name %s: %s'
                             % (rel, root_of, said.strip()[-200:]))
            target = os.path.join(out, root_of.replace('/', os.sep))
            if os.path.isdir(target):
                shutil.rmtree(target)
            elif os.path.exists(target):
                os.remove(target)
        again = os.path.join(work, 'again.zip')
        r = run_export(src, '--zip-tree', out, '--zip', again)
        if r.returncode != 0 or not os.path.isfile(again):
            fails.append('E10 control: a clean exported tree did not zip: %s'
                         % (r.stdout + r.stderr)[-300:])
        elif sorted(_zip_names(again)) != sorted(names):
            fails.append('E10 control: re-zipping the clean tree changed the entry list')
        if os.path.isfile(again) and run_export(src, '--zip-tree', out, '--zip',
                                                again).returncode == 0:
            fails.append('E10 --zip overwrote an existing zip')
    finally:
        shutil.rmtree(work, ignore_errors=True)


MUST_SHIP = ('.github/workflows/reusable-security.yml',
             '.github/workflows/reusable-ticket-reconcile.yml',
             'scripts/export_for_adoption.py',
             'tests/prove_export_scope.py')


def main():
    work = tempfile.mkdtemp(prefix='export-scope-')
    out = os.path.join(work, 'copy')
    try:
        env = dict(os.environ, PYTHONIOENCODING='utf-8')
        # --allow-dirty: a developer's uncommitted edits must not stop the SCOPE being checked;
        # the watermark it writes lives in a temp directory and is discarded.
        p = subprocess.run([sys.executable, EXPORT, '--out', out, '--allow-dirty'], cwd=ROOT,
                           capture_output=True, text=True, encoding='utf-8', errors='replace',
                           env=env)
        if p.returncode != 0 or not os.path.isdir(out):
            print('FAIL E1: the neutral export did not complete (exit %d):' % p.returncode)
            print((p.stdout + p.stderr)[-2500:])
            return 1
        shipped = []
        for dp, _dn, fns in os.walk(out):
            for fn in fns:
                shipped.append(os.path.relpath(os.path.join(dp, fn), out).replace(os.sep, '/'))
        fails = []
        for rel in shipped:
            if rel.startswith(NEVER_SHIPPED_TREES) or rel in NEVER_SHIPPED_FILES:
                fails.append('E2 shipped %s' % rel)
        for rel in MUST_SHIP:
            if rel not in shipped:
                fails.append('E3 did not ship %s' % rel)
        print('exported %d file(s)' % len(shipped))
        # E9 THE COPY PASSES ITS OWN SELF-TEST CHECKS. The first public PR of Release 2 failed
        # twice in "Normalizer drift": the generated capability inventory named the internal
        # consumer-path workflow the export withholds, and a tool only that workflow runs then
        # looked unwired to the proof census. Run both against the exported tree, as shipped.
        inv = os.path.join(out, 'docs', 'assurance', 'CAPABILITY_INVENTORY_GENERATED.csv')
        before = open(inv, 'rb').read() if os.path.isfile(inv) else None
        subprocess.run([sys.executable, os.path.join(out, 'tests', 'capability_inventory.py')],
                       cwd=out, capture_output=True, text=True, env=env)
        after = open(inv, 'rb').read() if os.path.isfile(inv) else None
        if before is None or before.replace(b'\r\n', b'\n') != (after or b'').replace(b'\r\n', b'\n'):
            fails.append('E9 the exported capability inventory is not what the exported tree '
                         'generates: it describes the source, not the copy')
        cov = subprocess.run([sys.executable, os.path.join(out, 'tests', 'check_selftest_coverage.py')],
                             cwd=out, capture_output=True, text=True, encoding='utf-8',
                             errors='replace', env=env)
        if cov.returncode != 0:
            fails.append('E9 the exported tree fails its own proof census: %s'
                         % ' | '.join(l for l in cov.stdout.splitlines() if 'FAIL' in l)[:400])
        # The deny list never ships (E2), so in a copy the controls that guard the SOURCE have
        # nothing to read. Each must say so by name -- not fail the copy's self-test (third
        # failure of the first public Release 2 PR), and not pretend to have checked anything.
        # check_context_current.py joined 2026-10-22: the export ships no .context (E2), and once
        # the sweep refused any exit 1 the copy's self-test went red on it (public run 39840692734).
        for tool in ('check_export_safety.py', 'prove_deny_samples.py', 'prove_export_scope.py',
                     'check_context_current.py'):
            q = subprocess.run([sys.executable, os.path.join(out, 'tests', tool)], cwd=out,
                               capture_output=True, text=True, encoding='utf-8', errors='replace',
                               env=env)
            said = q.stdout + q.stderr
            if q.returncode != 0 or 'SOURCE-ONLY CONTROL' not in said:
                fails.append('E9 in the exported copy tests/%s exited %d without naming itself a '
                             'source-only control: %s' % (tool, q.returncode, said.strip()[-200:]))
        try:
            prove_no_deny_list_refuses(fails)
            prove_profile_bound(fails)
            prove_excluded_path(fails)
            prove_untracked_not_kit(fails)
            prove_zip_refuses_leftovers(fails)
        except RuntimeError as e:
            print('UNKNOWN: the synthetic source could not be built: %s' % e)
            return 2
        if fails:
            for f in fails[:40]:
                print('FAIL ' + f)
            if len(fails) > 40:
                print('... %d more' % (len(fails) - 40))
            return 1
        print('PASS: the neutral export completes, ships the kit, and ships no continuity record,')
        print('      no overlay, no export profile, no deny list and no internal test workflow;')
        print('      no deny list is a refusal; the profile is bound to the destination.')
        return 0
    finally:
        shutil.rmtree(work, ignore_errors=True)



# SOURCE-ONLY CONTROL (2026-10-21). This control guards the SOURCE before anything leaves it. A
# neutral export never carries the deny list (tests/prove_export_scope.py E2), so in an exported
# copy -- recognised by its export watermark AND the list's absence -- there is nothing for it to
# read. It says so by name and does not fail the copy's own self-test; the source's gate checked
# this tree at export, at the commit the watermark records. An explicit list or a self-test run
# still runs normally. tests/prove_export_scope.py E9.
def _exported_copy_without_list(root, argv):
    if any(a.startswith('--deny') or a == '--self-test' for a in argv[1:]) or len(
            [a for a in argv[1:] if not a.startswith('-')]) > 0:
        return False
    wm = os.path.join(root, '.neutral-export-watermark.json')
    return os.path.isfile(wm) and not os.path.isfile(os.path.join(root, 'scripts',
                                                                  'export-deny.txt'))


def _say_source_only(name):
    print('SOURCE-ONLY CONTROL: %s guards the source repository before export. This is an '
          'exported copy (.neutral-export-watermark.json present) and, by design, carries no '
          'scripts/export-deny.txt, so there is nothing here for it to check; the source ran it '
          'at the commit the watermark records. Nothing was checked here, and nothing passed.'
          % name)
    return 0

if __name__ == '__main__':
    if _exported_copy_without_list(ROOT, sys.argv):
        sys.exit(_say_source_only('prove_export_scope.py'))
    sys.exit(main())

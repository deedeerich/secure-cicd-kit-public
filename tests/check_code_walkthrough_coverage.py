#!/usr/bin/env python3
"""Every tracked file is in the code walkthrough, and the walkthrough names no file that is gone (2026-11-07).

WHY THIS EXISTS
    The owner: "I need to intimately understand every drop of code." docs/architecture/code-walkthrough/
    has one page per area, a row per file: what it does in plain words, who calls it, its inputs and
    outputs, and the tests that prove it. A walkthrough kept by hand drifts the day a lane adds a file,
    and a walkthrough that silently misses a file reads as complete -- the same false clean the kit
    refuses everywhere else. So the coverage is a check, not an intention.

SCOPE (what must have a row)
    Every tracked file EXCEPT documents (docs/**, .context/**, which are indexed by their own READMEs
    and docs/architecture/INDEX.md), the walkthrough files themselves, and the two files the neutral
    export writes into its copy (the watermark and EXPORT_MANIFEST.md). Where a row lives:

      core            a file the neutral export ships: a row in a page under docs/architecture/code-walkthrough/,
                      first cell the path in backticks: | `scripts/kit_api.py` | ...
      overlay         a file under overlays/NAME/: a row in overlays/NAME/CODE_WALKTHROUGH.md, path relative
                      to the overlay, so the neutral core never names an overlay's owner
      export profiles a file under scripts/export-profiles/: a row in scripts/export-profiles/CODE_WALKTHROUGH.md
      other withheld  a file the neutral export withholds by exact path or name (export-deny.txt, the internal
                      consumer-path test): a core row, which a neutral copy tolerates as absent

RULES
    W1  every in-scope file has a row in the right place
    W2  every row names a file that exists (a file the neutral export withholds may be absent: that is
        the public copy, not a stale row)
    W3  every row's "what it does" cell is a sentence (at least four words, not TODO or TBD)
    W4  every overlay directory, and scripts/export-profiles/ when present, has its CODE_WALKTHROUGH.md
    W5  no path has two rows

    --self-test builds trees that break each rule, and one that holds, and requires each verdict.

EXIT  0 the walkthrough covers the tree   1 a rule refused (each named)   2 could not be read
"""
import importlib.util
import os
import re
import shutil
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
PAGES = 'docs/architecture/code-walkthrough'
LOCAL = 'CODE_WALKTHROUGH.md'
PROFILES = 'scripts/export-profiles'
ROW = re.compile(r'^\|\s*`([^`]+)`\s*\|(.*)$')
WEAK = re.compile(r'^(?:todo|tbd|\?|-|n/?a)?\.?$', re.I)


def tracked(root):
    """Tracked files plus untracked, unignored ones (a new file counts before it is committed)."""
    try:
        res = subprocess.run(['git', '-C', root, 'ls-files', '--cached', '--others', '--exclude-standard'],
                             capture_output=True, text=True, timeout=60)
        if res.returncode == 0 and res.stdout.strip():
            return sorted(set(p.strip() for p in res.stdout.splitlines()
                              if p.strip() and os.path.isfile(os.path.join(root, p.strip()))))
    except (OSError, ValueError):
        pass
    out = []
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in ('.git', '__pycache__', '.pytest_cache')]
        for f in filenames:
            out.append(os.path.relpath(os.path.join(dirpath, f), root).replace('\\', '/'))
    return sorted(out)


def exporter(root):
    """The neutral export's own `exportable` rule, so the two cannot drift; a fallback when absent."""
    p = os.path.join(root, 'scripts', 'export_for_adoption.py')
    if os.path.exists(p):
        try:
            spec = importlib.util.spec_from_file_location('_kit_export_rule', p)
            mod = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(mod)
            return mod.exportable
        except Exception:  # an exporter that cannot load must not silence this check
            pass

    def fallback(rel):
        parts = rel.split('/')
        return not (parts[0] in ('overlays', '.context') or 'export-profiles' in parts[:2]
                    or os.path.basename(rel) == 'export-deny.txt'
                    or rel == '.github/workflows/consumer-path-test.yml')
    return fallback


# Written BY the neutral export into the copy it makes (scripts/export_for_adoption.py: the watermark and
# the manifest), so a public copy carries them and the source tree never does.
EXPORT_WRITTEN = ('.neutral-export-watermark.json', 'EXPORT_MANIFEST.md')


def in_scope(rel):
    if rel.startswith(('docs/', '.context/')) or rel in EXPORT_WRITTEN:
        return False
    if os.path.basename(rel) == LOCAL:
        return False
    return True


def read_rows(path):
    """-> [(line, path, what)] for every table row whose first cell is a backticked path."""
    rows = []
    try:
        text = open(path, encoding='utf-8').read()
    except OSError:
        return None
    for n, ln in enumerate(text.splitlines(), 1):
        m = ROW.match(ln.strip())
        if not m:
            continue
        rest = [c.strip() for c in m.group(2).split('|')]
        what = rest[0] if rest else ''
        rows.append((n, m.group(1).strip(), what))
    return rows


def check(root):
    probs = []
    files = tracked(root)
    exportable = exporter(root)
    present = set(files)
    seen = {}

    def add_rows(page, prefix):
        rows = read_rows(os.path.join(root, page))
        if rows is None:
            return
        for n, rel, what in rows:
            full = prefix + rel
            if full in seen:
                probs.append('W5 %s has two rows: %s:%d and %s' % (full, page, n, seen[full]))
                continue
            seen[full] = '%s:%d' % (page, n)
            if full not in present and not os.path.isfile(os.path.join(root, full)):
                if exportable(full) or prefix:
                    probs.append('W2 %s:%d names %s, which does not exist' % (page, n, full))
            if WEAK.match(what) or len(what.split()) < 4:
                probs.append('W3 %s:%d: the row for %s does not say what it does in a sentence' % (page, n, full))

    pages_dir = os.path.join(root, PAGES)
    core_pages = sorted(f for f in os.listdir(pages_dir) if f.endswith('.md')) if os.path.isdir(pages_dir) else []
    for f in core_pages:
        add_rows(os.path.join(PAGES, f).replace('\\', '/'), '')
    overlays = sorted({f.split('/')[1] for f in files if f.startswith('overlays/') and f.count('/') >= 2})
    for name in overlays:
        page = 'overlays/%s/%s' % (name, LOCAL)
        if not os.path.isfile(os.path.join(root, page)):
            probs.append('W4 overlay %s has no %s' % (name, LOCAL))
        else:
            add_rows(page, 'overlays/%s/' % name)
    if any(f.startswith(PROFILES + '/') for f in files):
        page = '%s/%s' % (PROFILES, LOCAL)
        if not os.path.isfile(os.path.join(root, page)):
            probs.append('W4 %s has no %s' % (PROFILES, LOCAL))
        else:
            add_rows(page, PROFILES + '/')
    if not core_pages:
        probs.append('W4 %s has no pages' % PAGES)
    for rel in files:
        if not in_scope(rel):
            continue
        if rel not in seen:
            if rel.startswith('overlays/'):
                where = 'overlays/%s/%s' % (rel.split('/')[1], LOCAL)
            elif rel.startswith(PROFILES + '/'):
                where = '%s/%s' % (PROFILES, LOCAL)
            else:
                where = PAGES + '/'
            probs.append('W1 %s has no row (add one to %s)' % (rel, where))
    return probs, len(seen)


def _tree(d, files, pages):
    for rel, body in list(files.items()) + list(pages.items()):
        p = os.path.join(d, rel)
        os.makedirs(os.path.dirname(p), exist_ok=True)
        with open(p, 'w', encoding='utf-8') as h:
            h.write(body)


def self_test():
    ok = True
    good = '| `scripts/a.py` | Turns one input into one output. | x | y |\n| `tools/b.sh` | Runs the local checks in order. | x | y |\n'
    base_files = {'scripts/a.py': 'x\n', 'tools/b.sh': 'x\n', 'docs/readme.md': 'doc\n',
                  'overlays/org1/actions/x.yml': 'x\n'}
    overlay_page = {'overlays/org1/CODE_WALKTHROUGH.md': '| `actions/x.yml` | Adds one scanner for this organisation. | a | b |\n'}
    cases = [
        ('control: every file covered', base_files, dict({PAGES + '/s.md': good}, **overlay_page), None),
        ('W1 a file with no row', dict(base_files, **{'scripts/c.py': 'x\n'}),
         dict({PAGES + '/s.md': good}, **overlay_page), 'W1 scripts/c.py'),
        ('W2 a row for a missing file', base_files,
         dict({PAGES + '/s.md': good + '| `scripts/gone.py` | Did something once upon a time. | x | y |\n'}, **overlay_page),
         'W2'),
        ('W3 a row with no sentence', base_files,
         dict({PAGES + '/s.md': good.replace('Runs the local checks in order.', 'TODO')}, **overlay_page), 'W3'),
        ('W4 an overlay with no walkthrough', base_files, {PAGES + '/s.md': good}, 'W4 overlay org1'),
        ('W5 a path with two rows', base_files,
         dict({PAGES + '/s.md': good, PAGES + '/t.md': '| `scripts/a.py` | Turns one input into one output. | x | y |\n'},
              **overlay_page), 'W5'),
        ('W2 control: a withheld file may be absent', base_files,
         dict({PAGES + '/s.md': good + '| `scripts/export-deny.txt` | Names what the export must refuse. | x | y |\n'},
              **overlay_page), None),
    ]
    for name, files, pages, want in cases:
        d = tempfile.mkdtemp()
        try:
            _tree(d, files, pages)
            probs, _ = check(d)
        finally:
            shutil.rmtree(d, ignore_errors=True)
        if want is None:
            if probs:
                print('FAIL %s: refused %s' % (name, probs))
                ok = False
            else:
                print('PASS %s' % name)
        elif any(p.startswith(want) for p in probs):
            print('PASS %s refused: %s' % (name, [p for p in probs if p.startswith(want)][0]))
        else:
            print('FAIL %s was not refused (%s)' % (name, probs))
            ok = False
    return 0 if ok else 1


def main(argv):
    if '--self-test' in argv:
        return self_test()
    root = argv[argv.index('--root') + 1] if '--root' in argv else ROOT
    try:
        probs, n = check(root)
    except OSError as e:
        print('UNKNOWN could not read the tree: %s' % e)
        return 2
    for p in probs:
        print('FAIL ' + p)
    if probs:
        print('%d problem(s); %d row(s) read' % (len(probs), n))
        return 1
    print('PASS every in-scope file has exactly one walkthrough row (%d rows), each a sentence, none stale' % n)
    return 0


if __name__ == '__main__':
    sys.exit(main(sys.argv[1:]))

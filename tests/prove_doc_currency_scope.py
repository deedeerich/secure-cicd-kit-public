#!/usr/bin/env python3
"""The document-currency gate reads the whole estate, with claims read from the code (L81 / B-11).

WHY THIS EXISTS

    tests/check_doc_currency.py read three assurance tables and the consumer documents. The
    completion ledger's D-01 row lists stale lines in the architecture and assurance documents, the
    roadmap and the continuity record -- "deploy never executed", "nothing is ENFORCED", "defaults to
    11" -- and the gate passed over every one, because it never opened those files (B-11: it "did
    not catch any of the stale prose listed in D-01").

WHAT IT PROVES (a constructed tree: the real workflows and registries, seeded documents only)
    D1  an ARCHITECTURE document calling the deploy workflows unexercised fails the gate, by name
    D2  a document saying `fail_on_cvss` defaults to 11, while the reusable ships 9.0, fails
    D3  a document saying nothing is ENFORCED, while the stage register records an ENFORCED stage,
        fails
    D4  a known_stale entry accounts for its document until its date (rc 0, reported), fails after
        it, and fails when the document no longer contradicts anything (a stale entry)
    D5  CONTROL: the same tree with true documents passes

EXIT  0 all hold   1 any does not   2 could not be checked
"""
import contextlib
import importlib
import io
import os
import shutil
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, HERE)

TRUE_DOC = 'The deploy workflows are proven live (runs 38878189985, 38858033863).\n'
SEEDS = {
    'D1': ('docs/architecture/SEEDED.md', 'Both deploy workflows are provisional and have never run.\n',
           'deploy workflows'),
    'D2': ('docs/architecture/SEEDED.md', '- **`fail_on_cvss` defaults to 11** in the reusable.\n',
           'nvd-cvss-default'),
    'D3': ('docs/assurance/SEEDED.md', 'Across this entire file, **nothing is ENFORCED**.\n',
           'nothing-enforced'),
}


def tree(work, name, docs):
    root = os.path.join(work, name)
    shutil.copytree(os.path.join(ROOT, '.github', 'workflows'),
                    os.path.join(root, '.github', 'workflows'))
    os.makedirs(os.path.join(root, 'tests'))
    shutil.copyfile(os.path.join(ROOT, 'tests', 'prove_secrets_always_block.py'),
                    os.path.join(root, 'tests', 'prove_secrets_always_block.py'))
    for rel, text in dict({'docs/START-HERE.md': TRUE_DOC}, **docs).items():
        p = os.path.join(root, rel)
        os.makedirs(os.path.dirname(p), exist_ok=True)
        io.open(p, 'w', encoding='utf-8').write(text)
    return root


def run(root, today, known=None):
    C = importlib.import_module('check_doc_currency')
    importlib.reload(C)
    C.ROOT = root
    if known is not None:
        C.known_stale = known
    out = io.StringIO()
    saved = sys.argv
    sys.argv = ['check_doc_currency.py', '--today', today]
    try:
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(out):
            rc = C.main()
    finally:
        sys.argv = saved
    return rc, out.getvalue()


def main():
    try:
        import yaml  # noqa: F401
    except ImportError:
        print('UNKNOWN: PyYAML unavailable.')
        return 2
    bad = []
    work = tempfile.mkdtemp(prefix='doc-scope-')
    try:
        for key, (rel, text, named) in sorted(SEEDS.items()):
            rc, out = run(tree(work, key, {rel: text}), '2026-10-21', known={})
            ok = rc == 1 and named in out and rel in out
            print('  %s %-46s rc=%s %s' % (key, rel + ' (' + named + ')', rc, 'ok' if ok else 'WRONG'))
            if not ok:
                bad.append('%s: a seeded contradiction in %s was not refused by name (rc=%s)'
                           % (key, rel, rc))
        rel, text, _n = SEEDS['D1']
        known = {rel: 'seeded known-stale entry'}
        for label, docs, today, want in (
                ('D4 known stale, before its date', {rel: text}, '2026-10-21', 0),
                ('D4 known stale, after its date', {rel: text}, '2099-01-01', 1),
                ('D4 entry left after the fix', {rel: TRUE_DOC}, '2026-10-21', 1)):
            rc, out = run(tree(work, label.replace(' ', '_').replace(',', ''), docs), today, known)
            print('  %-50s rc=%s %s' % (label, rc, 'ok' if rc == want else 'WRONG'))
            if rc != want:
                bad.append('%s: rc=%s, want %s' % (label, rc, want))
        rc, out = run(tree(work, 'D5', {'docs/architecture/TRUE.md': TRUE_DOC}), '2026-10-21', known={})
        print('  %-50s rc=%s' % ('D5 CONTROL true documents', rc))
        if rc != 0:
            bad.append('D5 a tree of true documents failed: %s' % out[-500:])
    finally:
        shutil.rmtree(work, ignore_errors=True)
        sys.modules.pop('check_doc_currency', None)
    for b in bad:
        print(('FAIL ' + b).encode('ascii', 'replace').decode('ascii'))
    if bad:
        return 1
    print('PASS: architecture and assurance documents are read; "defaults to 11" and "nothing is')
    print('      ENFORCED" are refused against the code; a known-stale entry holds until its date.')
    return 0


if __name__ == '__main__':
    sys.exit(main())

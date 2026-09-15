#!/usr/bin/env python3
"""Find untrusted input interpolated into shell or JS. The ticket-reference gate's defect, swept for.

WHY THIS EXISTS
    the ticket-reference gate did this:

        run: |
          PR_BODY="${{ github.event.pull_request.body }}"

    GitHub substitutes that into the SCRIPT TEXT before bash sees it. Two consequences:

      1. INJECTION. A PR body containing $(...) or backticks executes on the runner with the
         job's token. Anyone who can open a pull request can run code.
      2. SILENT TRUNCATION. The assignment ends at the first `"` in the body, so text after it
         is parsed as shell instead of stored. That is how the gate reported a ticket reference absent
         from a description that contained one -- a FALSE NEGATIVE manufactured by the harness.

    It was found by reading one file. Nothing swept the other seventy. Finding a defect and not
    looking for its siblings is how one instance gets fixed and five survive.

THE RULE
    Any value that is not constrained by GitHub must reach a script through `env:`, never
    through `${{ }}` inside `run:` or a `github-script` body. In env: it is DATA. In the script
    it is CODE.

THREE CLASSES, NOT TWO, AND NOT ONE ACCEPTED PILE
    UNTRUSTED_CONTEXT_INTERPOLATION
        anyone who can open an issue, PR, comment or push a branch controls the value.
        Remote code execution on the runner with the job's token.

    CALLER_CONTROLLED_INPUT_INTERPOLATION
        a reusable workflow's own inputs, or workflow_dispatch inputs. Setting them needs write
        access to the CALLING repository, so the exposure is smaller -- and it is not nothing.
        A trusted input can still be a MALFORMED input: it truncates on a quote, it can be
        interpreted as shell, and a kit consumed by many repositories should not let one
        misconfigured caller execute code in the workflow the others share. Reported with its
        own severity rather than filed away as "accepted".

    SAFE_ENV_TRANSPORT
        the value arrives through env:. This is the FIX and is never reported. A linter that
        flags the remedy teaches people to ignore it.

    TRUSTED
        repository, run id, sha, actor, job status -- constrained by GitHub. Ignored.

WHAT IT CANNOT ESTABLISH
    Static. It proves an interpolation EXISTS in a script body. It cannot prove exploitability,
    which depends on the trigger and on who can reach it. A `pull_request_target` or
    `issue_comment` trigger makes an UNTRUSTED hit reachable by strangers; on `push` to a
    protected branch the same hit needs write access first. Both are reported; the trigger is
    shown so a reader can tell which they are looking at.

USAGE
    python3 tests/lint_injection.py [path ...]      default: the repo this file sits in
    python3 tests/lint_injection.py --self-test

EXIT
    0 clean      1 untrusted interpolation found      2 self-test failed
"""
import io
import os
import re
import sys

import yaml

EXPR = re.compile(r'\$\{\{([^}]*)\}\}')

# Attacker-controlled in a public or multi-contributor repository.
UNTRUSTED = [
    r'github\.event\.issue\.(title|body)',
    r'github\.event\.pull_request\.(title|body)',
    r'github\.event\.pull_request\.head\.(ref|label|sha)',
    r'github\.event\.pull_request\.head\.repo\.',
    r'github\.event\.comment\.body',
    r'github\.event\.review\.body',
    r'github\.event\.review_comment\.body',
    r'github\.event\.discussion\.(title|body)',
    r'github\.event\.discussion_comment\.body',
    r'github\.event\.commits',
    r'github\.event\.head_commit\.(message|author)',
    r'github\.event\.workflow_run\.head_(branch|commit)',
    r'github\.event\.pages',
    r'github\.head_ref',
    r'github\.event\.release\.(body|tag_name|name)',
    r'github\.event\.milestone\.(title|description)',
    r'github\.event\.issue\.user\.login',
    r'github\.event\.pull_request\.user\.login',
]
SEMI = [r'github\.event\.inputs\.', r'inputs\.']

# Triggers that let someone with NO write access reach the job.
HOSTILE_TRIGGERS = {'pull_request_target', 'issue_comment', 'issues', 'pull_request_review',
                    'pull_request_review_comment', 'discussion', 'discussion_comment',
                    'workflow_run', 'fork', 'watch', 'public'}

UNTRUSTED_RE = [re.compile(p) for p in UNTRUSTED]
SEMI_RE = [re.compile(p) for p in SEMI]


def tier(expr):
    for r in UNTRUSTED_RE:
        if r.search(expr):
            return 'UNTRUSTED'
    for r in SEMI_RE:
        if r.search(expr):
            return 'SEMI'
    return 'TRUSTED'


def triggers_of(doc):
    on = doc.get('on', doc.get(True))
    if isinstance(on, str):
        return {on}
    if isinstance(on, list):
        return set(on)
    if isinstance(on, dict):
        return set(on)
    return set()


def scan_file(path):
    """-> (findings, error). A file that cannot be parsed is reported, never skipped."""
    try:
        doc = yaml.safe_load(io.open(path, encoding='utf-8', errors='replace'))
    except Exception as e:
        return ([], '%s: %s' % (type(e).__name__, str(e)[:120]))
    if not isinstance(doc, dict):
        return ([], 'not a workflow mapping')
    trig = triggers_of(doc)
    hostile = sorted(trig & HOSTILE_TRIGGERS)
    out = []
    for jname, job in (doc.get('jobs') or {}).items():
        if not isinstance(job, dict):
            continue
        for i, step in enumerate(job.get('steps') or []):
            if not isinstance(step, dict):
                continue
            bodies = []
            if isinstance(step.get('run'), str):
                bodies.append(('run', step['run']))
            uses = str(step.get('uses') or '')
            with_ = step.get('with') or {}
            if 'github-script' in uses and isinstance(with_.get('script'), str):
                bodies.append(('github-script', with_['script']))
            for kind, body in bodies:
                for m in EXPR.finditer(body):
                    e = m.group(1).strip()
                    t = tier(e)
                    if t == 'TRUSTED':
                        continue
                    line = body[:m.start()].count('\n') + 1
                    out.append(dict(file=path, job=jname, step=step.get('name') or '#%d' % (i + 1),
                                    kind=kind, expr=e, tier=t, line=line,
                                    triggers=sorted(trig), hostile=hostile))
    return (out, '')


def self_test():
    import tempfile
    d = tempfile.mkdtemp()
    bad = os.path.join(d, 'bad.yml')
    io.open(bad, 'w', encoding='utf-8').write(
        'on:\n  pull_request_target:\njobs:\n  j:\n    steps:\n'
        '      - run: |\n          BODY="${{ github.event.pull_request.body }}"\n')
    good = os.path.join(d, 'good.yml')
    io.open(good, 'w', encoding='utf-8').write(
        'on:\n  pull_request:\njobs:\n  j:\n    steps:\n'
        '      - env:\n          BODY: ${{ github.event.pull_request.body }}\n'
        '        run: |\n          echo "$BODY"\n')
    trusted = os.path.join(d, 'trusted.yml')
    io.open(trusted, 'w', encoding='utf-8').write(
        'on: push\njobs:\n  j:\n    steps:\n'
        '      - run: echo "${{ github.repository }} ${{ github.run_id }}"\n')

    f_bad, _ = scan_file(bad)
    f_good, _ = scan_file(good)
    f_trust, _ = scan_file(trusted)
    fails = []
    if len(f_bad) != 1 or f_bad[0]['tier'] != 'UNTRUSTED':
        fails.append('did not flag a PR body interpolated into run:')
    if f_bad and not f_bad[0]['hostile']:
        fails.append('did not notice pull_request_target is reachable without write access')
    # THE CENTRAL ASSERTION: env: is the fix, so env: must NOT be flagged.
    if f_good:
        fails.append('flagged a value passed safely through env: -- the fix would look broken')
    if f_trust:
        fails.append('flagged github.repository, which GitHub constrains')
    # A file that cannot be parsed must be reported, never silently skipped.
    broken = os.path.join(d, 'broken.yml')
    io.open(broken, 'w', encoding='utf-8').write('jobs: [unclosed\n')
    _, err = scan_file(broken)
    if not err:
        fails.append('an unparseable workflow was skipped silently')
    if fails:
        print('SELF-TEST FAILED:')
        for f in fails:
            print('  - %s' % f)
        return False
    print('self-test ok: run: interpolation flagged, env: NOT flagged, trusted contexts ignored, '
          'unparseable files reported')
    return True


def main():
    args = [a for a in sys.argv[1:] if not a.startswith('-')]
    if '--self-test' in sys.argv:
        return 0 if self_test() else 2
    if not self_test():
        return 2
    roots = args or [os.path.dirname(os.path.dirname(os.path.abspath(__file__)))]

    files, findings, errors = [], [], []
    for root in roots:
        for dp, _dn, fn in os.walk(root):
            if os.sep + '.git' + os.sep in dp + os.sep:
                continue
            if not dp.replace('\\', '/').endswith('.github/workflows'):
                continue
            for f in sorted(fn):
                if f.endswith(('.yml', '.yaml')):
                    files.append(os.path.join(dp, f))
    for p in files:
        got, err = scan_file(p)
        findings.extend(got)
        if err:
            errors.append((p, err))

    print('')
    print('scanned %d workflow file(s) under %d root(s)' % (len(files), len(roots)))
    if errors:
        print('')
        print('UNPARSEABLE -- not scanned, and therefore NOT established as clean:')
        for p, e in errors:
            print('  %s  %s' % (p, e))

    un = [f for f in findings if f['tier'] == 'UNTRUSTED']
    semi = [f for f in findings if f['tier'] == 'SEMI']
    print('')
    print('%-42s %s' % ('UNTRUSTED_CONTEXT_INTERPOLATION', len(un)))
    print('%-42s %s' % ('CALLER_CONTROLLED_INPUT_INTERPOLATION', len(semi)))
    print('%-42s %s' % ('unparseable (state NOT established)', len(errors)))
    print('')
    if un:
        print('UNTRUSTED INPUT IN A SCRIPT BODY -- %d site(s)' % len(un))
        print('-' * 100)
        for f in un:
            print('  %s' % f['file'])
            print('    job %s / step %s (%s line %d)' % (f['job'], f['step'], f['kind'], f['line']))
            print('    ${{ %s }}' % f['expr'])
            print('    triggers: %s%s' % (', '.join(f['triggers']),
                                          '   <-- REACHABLE WITHOUT WRITE ACCESS: %s'
                                          % ', '.join(f['hostile']) if f['hostile'] else ''))
    else:
        print('no untrusted input interpolated into any script body')
    if semi:
        print('')
        print('CALLER_CONTROLLED_INPUT_INTERPOLATION -- %d site(s) in %d file(s)'
              % (len(semi), len(set(f['file'] for f in semi))))
        print('  Setting these needs write access to the CALLING repository, so this is not the')
        print('  remote-code-execution case. It is also not nothing: a trusted input can still be')
        print('  a malformed one. It truncates on a quote, it can be read as shell, and a kit')
        print('  consumed by many repositories should not let one misconfigured caller execute')
        print('  code in the workflow the others share.')
        print('')
        # Grouped by file so this is a work list, not a wall. 158 individually-printed lines is
        # how a real finding class becomes something everyone scrolls past.
        byfile = {}
        for f in semi:
            byfile.setdefault(f['file'], []).append(f)
        print('  %-52s %5s  %s' % ('file', 'sites', 'jobs'))
        for p in sorted(byfile, key=lambda k: -len(byfile[k])):
            g = byfile[p]
            jobs = sorted(set(x['job'] for x in g))
            print('  %-52s %5d  %s' % (os.path.basename(p)[:52], len(g), ','.join(jobs)[:34]))

    print('')
    print('STATIC. This proves an interpolation exists in a script body. Exploitability depends')
    print('on the trigger and on who can reach it -- both shown above, neither decided here.')
    return 1 if un else 0


if __name__ == '__main__':
    sys.exit(main())

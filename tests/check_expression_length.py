#!/usr/bin/env python3
"""No `run:` (or other string) that contains a `${{ }}` expression may approach GitHub's 21,000 limit.

WHY THIS EXISTS

    GitHub evaluates any workflow string that contains a `${{ }}` expression as a template, and refuses
    the WHOLE WORKFLOW at load time when such a string is longer than 21,000 characters:

        (Line: 6773, Col: 14): Exceeded max expression length 21000

    That is a startup failure -- zero jobs run -- and it is invisible to every local check: the YAML
    parses, the steps run under bash, every proof passes. It was found by the first hosted milestone
    run (2026-10-15, KDEC-006) on the security gate's `run:` block, 23,414 characters with 28
    expressions, which had grown past the limit one honest comment at a time.

    A string with NO expression is not a template and is not subject to the limit, so the fix is the
    kit's existing rule (L38): values reach a script through `env:`, never `${{ }}` inside `run:`.

RULE
    Every string value in every workflow, composite action and overlay workflow that contains `${{`
    must be at most LIMIT characters (a margin below GitHub's 21,000, so growth is caught early).

EXIT
    0  every expression-bearing string is under the limit
    1  at least one is not (named, with its length)
    2  could not be checked -- UNKNOWN, never PASS
"""
import glob
import io
import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
GITHUB_LIMIT = 21000
LIMIT = 18000
GLOBS = ['.github/workflows/*.yml', '.github/actions/*/action.yml', 'overlays/*/workflows/*.yml']


def strings(node, path=''):
    """Yield (path, string) for every string value in a parsed YAML document."""
    if isinstance(node, dict):
        for k, v in node.items():
            for x in strings(v, '%s.%s' % (path, k)):
                yield x
    elif isinstance(node, list):
        for i, v in enumerate(node):
            name = v.get('name') or v.get('id') if isinstance(v, dict) else None
            for x in strings(v, '%s[%s]' % (path, name or i)):
                yield x
    elif isinstance(node, str):
        yield path, node


def offenders(doc, limit=LIMIT):
    return [(p, len(s)) for p, s in strings(doc) if '${{' in s and len(s) > limit]


def self_test(yaml):
    long_body = 'echo "${{ inputs.x }}"\n' + ('# padding\n' * 2500)
    bad = yaml.safe_load('jobs:\n  a:\n    steps:\n      - name: big\n        run: |\n' +
                         ''.join('          %s\n' % l for l in long_body.splitlines()))
    clean = yaml.safe_load('jobs:\n  a:\n    steps:\n      - name: big\n        env:\n'
                           '          X: ${{ inputs.x }}\n        run: |\n' +
                           ''.join('          %s\n' % l for l in ('echo "$X"\n' + '# padding\n' * 2500).splitlines()))
    if not offenders(bad):
        return 'a long run: with an expression was not refused'
    if offenders(clean):
        return 'a long run: with NO expression was refused (it is not a template)'
    return None


def main():
    try:
        import yaml
    except ImportError:
        print('UNKNOWN: PyYAML unavailable.')
        return 2
    why = self_test(yaml)
    if why:
        print('SELF-TEST FAILED: %s' % why)
        return 2
    files = sorted(f for g in GLOBS for f in glob.glob(os.path.join(ROOT, g)))
    if not files:
        print('UNKNOWN: no workflows found. Nothing inspected is not nothing wrong.')
        return 2
    bad = []
    for f in files:
        doc = yaml.safe_load(io.open(f, encoding='utf-8'))
        for p, n in offenders(doc):
            bad.append('%s %s: %d characters with a ${{ }} expression (limit %d; GitHub refuses the '
                       'whole workflow above %d)' % (os.path.relpath(f, ROOT).replace('\\', '/'), p, n,
                                                       LIMIT, GITHUB_LIMIT))
    if bad:
        for b in bad:
            print('FAIL: ' + b)
        print('Move the expressions into `env:` (ledger L38); a string with no expression is not a '
              'template and has no length limit.')
        return 1
    print('PASS: %d file(s); every expression-bearing string is under %d characters.'
          % (len(files), LIMIT))
    return 0


if __name__ == '__main__':
    sys.exit(main())

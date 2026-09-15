#!/usr/bin/env python3
"""Static check: a line continuation must never be followed by a comment.

WHY THIS EXISTS
    In bash, `\` at end of line escapes the NEWLINE. If the next line is a comment, the two join
    and everything after `#` is discarded -- silently deleting whatever was supposed to follow.

    On 2026-09-02 four scanner invocations in reusable-security.yml carried this shape:

        semgrep scan --config p/csharp --config p/security-audit \
          # suppression: EXPECTED_NEGATIVE_RESULT -- ...
          --sarif --output dotnet-semgrep.sarif --metrics=off "$scope" || true

    The scanner ran WITHOUT its output flags and WITHOUT "$scope" -- unscoped over the whole
    checkout, writing no report -- while the orphaned flag line became a bogus command that
    `|| true` swallowed. Exit 0. Job green. Nothing detected.

    gosec was the worst case: `docker run <image>` with no arguments whatsoever.

    This is the second instance of the same family. The first was a literal two-character `\n`
    inside an apt-get command (2026-09-01), which resolved to the package name `n`. Both share a
    root: THE LINE CONTINUATION IS A FRAGILE CONSTRUCT AND NOTHING WAS CHECKING IT.

    A defect found twice by accident is a defect that gets mechanized.

EXIT
    0 -- clean
    1 -- at least one violation (prints file:line and both lines)
"""
import glob
import io
import os
import re
import sys

# Everything that can carry shell. Workflow YAML holds it inside `run:` blocks; .sh files are shell
# outright. Both are checked -- a defect class does not respect file extensions.
PATTERNS = [
    '.github/workflows/*.yml',
    '.github/workflows/*.yaml',
    '.github/actions/**/*.yml',
    '.github/actions/**/*.yaml',
    'scripts/**/*.sh',
    'tests/**/*.sh',
]

# THE FAMILY, NOT THE INSTANCE.
#
# Two members of this class shipped before anyone looked for the third: a literal two-character
# `\n` inside an apt-get command (2026-09-01), and a continuation followed by a comment in four
# scanner invocations (2026-09-02). Fixing only the shape most recently observed is how a class
# gets rediscovered a third time. Every known form of "line joining that silently discards what
# follows" is checked here, each with a seeded fixture case proving the detector works.

CONTINUATION = re.compile(r'\\$')                # a REAL continuation: backslash IMMEDIATELY at EOL
                                                 # (not `\\[ \t]*$` -- that also matches the
                                                 # trailing-whitespace form and double-counts it)
COMMENT = re.compile(r'^[ \t]*#')
BLANK = re.compile(r'^[ \t]*$')

# `\` followed by trailing whitespace is NOT a continuation -- bash escapes the space, not the
# newline, and the next line becomes a separate command. Invisible in every editor.
TRAILING_WS_BACKSLASH = re.compile(r'\\[ \t]+$')

# A literal two-character backslash-n where a newline or continuation was intended. This is the
# 2026-09-01 defect: `install -y \n --no-install-recommends` became the package name `n`.
LITERAL_BACKSLASH_N = re.compile(r'[^\\]\\n(?![a-zA-Z0-9_"\'/])')

FORMS = [
    ('continuation followed by a comment',
     'the `\\` joins the COMMENT line; everything after `#` is discarded'),
    ('continuation followed by a blank line',
     'the `\\` joins an empty line, silently ending the command early'),
    ('backslash followed by trailing whitespace',
     'escapes the SPACE, not the newline -- the next line becomes a separate command'),
    ('literal two-character \\n',
     'not a newline and not a continuation -- resolves to the character `n` as an argument'),
]


def collect():
    seen, files = set(), []
    for pat in PATTERNS:
        for f in glob.glob(pat, recursive=True):
            rp = os.path.realpath(f)
            if rp not in seen and os.path.isfile(f):
                seen.add(rp)
                files.append(f)
    return sorted(files)


def scan(path):
    """Return [(lineno, form, offending_line, following_line_or_note)] for every form."""
    lines = io.open(path, encoding='utf-8', errors='replace').read().split('\n')
    out = []
    for i, line in enumerate(lines):
        nxt = lines[i + 1] if i + 1 < len(lines) else ''

        if CONTINUATION.search(line) and COMMENT.match(nxt):
            out.append((i + 1, FORMS[0][0], line, nxt))
        elif CONTINUATION.search(line) and BLANK.match(nxt) and i + 1 < len(lines) - 1:
            out.append((i + 1, FORMS[1][0], line, '(blank line)'))

        if TRAILING_WS_BACKSLASH.search(line):
            out.append((i + 1, FORMS[2][0], line, '(trailing whitespace after `\\`)'))

        # Only meaningful inside shell; a `\n` in a Python or jq string is legitimate. Restrict to
        # lines that look like shell invocation rather than quoted program text.
        if LITERAL_BACKSLASH_N.search(line) and not re.match(r'^[ \t]*(#|[a-z_]+\s*=)', line):
            if re.search(r'\b(apt-get|apt|yum|dnf|pip|npm|docker|curl|wget|install)\b', line):
                out.append((i + 1, FORMS[3][0], line, '(literal backslash-n)'))

    return out


SELF_TEST_FIXTURE = os.path.join('tests', 'fixtures', 'bad_continuation.sample')
# Every FORM must be represented, or the fixture proves less than it appears to. The self-test
# asserts coverage per form, not just a total -- a total can be reached while one detector is dead.
SELF_TEST_FORMS = {FORMS[0][0]: 2, FORMS[1][0]: 1, FORMS[2][0]: 1, FORMS[3][0]: 1}


def self_test():
    """A checker that cannot detect its own defect class is decoration.

    The first version of this file reported PASS on a clean tree while being unable to find a
    seeded violation -- a failed observation rendered as a positive result, which is the exact
    defect this repository exists to refuse. The fixture is committed so the claim is checkable
    by anyone, not just by whoever wrote the regex.
    """
    if not os.path.isfile(SELF_TEST_FIXTURE):
        print('SELF-TEST FAIL: fixture missing at %s' % SELF_TEST_FIXTURE)
        return 1

    found = {}
    for _lineno, form, _line, _note in scan(SELF_TEST_FIXTURE):
        found[form] = found.get(form, 0) + 1

    bad = False
    for form, expected in SELF_TEST_FORMS.items():
        got = found.get(form, 0)
        mark = 'ok  ' if got == expected else 'DEAD'
        print('  self-test %s %-44s expected %d, found %d' % (mark, form, expected, got))
        if got != expected:
            bad = True

    extra = set(found) - set(SELF_TEST_FORMS)
    if extra:
        print('  self-test DEAD unexpected form(s) reported: %s' % ', '.join(sorted(extra)))
        bad = True

    return 1 if bad else 0


def main():
    if self_test() != 0:
        print('\nABORTING: the checker cannot detect its own defect class, so a PASS would')
        print('be meaningless. Fix the checker before trusting any result from it.')
        return 1

    files = collect()
    violations = []
    for f in files:
        for lineno, form, line, note in scan(f):
            violations.append((f, lineno, form, line, note))

    print('shell line-joining check -- %d file(s) scanned, %d form(s) checked'
          % (len(files), len(FORMS)))

    if not violations:
        print('PASS: no fragile line-joining construct found.')
        return 0

    why = dict((name, expl) for name, expl in FORMS)
    print('\nFAIL: %d violation(s).\n' % len(violations))
    for f, lineno, form, line, note in violations:
        print('%s:%d  [%s]' % (f, lineno, form))
        print('    %s' % line.strip()[:100])
        print('    %s' % note.strip()[:100])
        print('    why: %s' % why.get(form, ''))
        print()
    print('Fix: put comments ABOVE the command, never inside a continued line; use a real')
    print('newline rather than the two characters `\\n`; and never leave whitespace after `\\`.')
    return 1


if __name__ == '__main__':
    sys.exit(main())

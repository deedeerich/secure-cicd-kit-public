#!/usr/bin/env python3
"""Fail the build on control bytes in source. Prose guidance failed four times; this is the ratchet.

WHY THIS EXISTS
    A shell heredoc silently converts `\\b` in a Python string literal into a literal 0x08
    BACKSPACE byte. The result compiles, runs, and is invisible:

        re.compile(r'(?i)\\x08priorclient\\x08')

    That pattern matches a literal backspace character and therefore matches NOTHING, EVER. It
    renders as `\\b` in an editor, in a terminal, and in every file-reading tool. Ten of them were
    written into a provenance gate in one edit. The gate's self-test reported "former-engagement
    material was not refused" and reading the source could not show why, because there was nothing
    to see.

    A refusal that cannot fire AND cannot be seen is strictly worse than a wrong one. A wrong
    pattern can be read and argued with.

    Same session, same mechanism: `.split("\\0")` became a literal NUL and the file stopped
    compiling, and two patch anchors had their escapes eaten. Four incidents. At that point the
    problem is not memory, it is that the failure is undetectable by reading -- so it needs a
    detector, not another reminder.

THE LADDER THIS MOVES ALONG
    DOCUMENTED -> DETECTABLE -> ENFORCED -> TESTED -> REVALIDATED

    This file is the DETECTABLE rung. It is honest about what that means: it catches the CLASS of
    damage, not the habit that causes it. Someone can still write a bad regex by hand; what they can
    no longer do is ship one whose text lies about its own contents.

WHAT COUNTS AS A CONTROL BYTE
    Everything below 0x20 except tab, line feed and carriage return, plus DEL. Those three are
    legitimate whitespace in source; the rest arrive by accident, and in a regex or a policy string
    they arrive as silent behaviour changes.

    C0 controls are also invisible in a code review, a diff and a terminal -- which is the whole
    reason they need a machine to find them.

USAGE
    python3 tests/check_source_hygiene.py [path ...]      default: the repo this file sits in
    python3 tests/check_source_hygiene.py --self-test

EXIT
    0 clean      1 a control byte reached tracked source      2 self-test failed
"""
import io
import os
import subprocess
import sys

# Legitimate in text. Everything else below 0x20, plus DEL, is not.
ALLOWED = {0x09, 0x0A, 0x0D}
CONTROL = set(range(0x00, 0x20)) - ALLOWED | {0x7F}

NAMES = {0x00: 'NUL', 0x07: 'BEL', 0x08: 'BACKSPACE', 0x0B: 'VT', 0x0C: 'FF',
         0x1B: 'ESC', 0x7F: 'DEL'}

# Text formats where a control byte is always a defect. Binary is excluded by extension rather
# than by sniffing, so the decision is visible here rather than buried in a heuristic.
TEXT_EXT = {'.py', '.yml', '.yaml', '.sh', '.json', '.md', '.txt', '.csv', '.cfg', '.ini',
            '.toml', '.ps1', '.cmd', '.tf', '.example', '.sample', '.gitignore'}

# Its own fixtures necessarily contain the bytes it hunts for.
SKIP_BASENAMES = {'check_source_hygiene.py'}


def tracked(root):
    """Only files git would publish. An untracked scratch file is not the repo's problem."""
    try:
        out = subprocess.check_output(['git', '-C', root, 'ls-files', '-z'],
                                      stderr=subprocess.DEVNULL)
    except (OSError, subprocess.CalledProcessError):
        return None
    return [p for p in out.decode('utf-8', 'replace').split('\0') if p]


def in_scope(rel):
    if os.path.basename(rel) in SKIP_BASENAMES:
        return False
    ext = os.path.splitext(rel)[1].lower()
    return ext in TEXT_EXT or os.path.basename(rel).startswith('.')


def scan_bytes(data):
    """-> [(line, col, byte)]. Line and column are 1-based, counted over the raw bytes."""
    hits = []
    line = col = 1
    for b in data:
        if b in CONTROL:
            hits.append((line, col, b))
        if b == 0x0A:
            line += 1
            col = 1
        else:
            col += 1
    return hits


def scan_file(path):
    try:
        data = io.open(path, 'rb').read()
    except OSError:
        return []
    return scan_bytes(data)


def self_test():
    fails = []
    # THE EXACT DAMAGE THIS EXISTS FOR: a regex literal whose \b became 0x08.
    poisoned = b"re.compile(r'(?i)\x08priorclient\x08')\n"
    hits = scan_bytes(poisoned)
    if not hits or hits[0][2] != 0x08:
        fails.append('a literal BACKSPACE inside a regex was not detected')
    if len(hits) != 2:
        fails.append('expected 2 control bytes, got %d' % len(hits))
    if hits and hits[0][0] != 1:
        fails.append('line number wrong (%s)' % hits[0][0])

    # The other two shapes from the same session.
    if not scan_bytes(b'x = "a\x00b"\n'):
        fails.append('a literal NUL was not detected')
    if not scan_bytes(b'esc\x1b[0m\n'):
        fails.append('a literal ESC was not detected')

    # Clean source with every legitimate whitespace byte must pass.
    clean = b'def f():\n\treturn 1\r\n\n# a comment with \\b and \\0 written properly\n'
    if scan_bytes(clean):
        fails.append('clean source with tab/CR/LF was reported: %s' % scan_bytes(clean))

    # Line accounting across multiple lines.
    multi = b'line one\nline two\x08here\nline three\n'
    h = scan_bytes(multi)
    if len(h) != 1 or h[0][0] != 2:
        fails.append('multi-line position wrong: %s' % h)

    # VACUITY: a scan that inspected nothing must not read as clean.
    if in_scope('logo.png') or in_scope('font.woff2'):
        fails.append('a binary extension was brought into scope')
    if not in_scope('scripts/thing.py') or not in_scope('.github/workflows/a.yml'):
        fails.append('a text file was excluded from scope')

    if fails:
        print('SELF-TEST FAILED:')
        for f in fails:
            print('  - %s' % f)
        return False
    print('self-test ok: a BACKSPACE inside a regex literal is caught with its line and column,')
    print('              NUL and ESC are caught, tab/CR/LF are not reported, positions are right')
    print('              across lines, and binary extensions stay out of scope')
    return True


def main():
    args = [a for a in sys.argv[1:] if not a.startswith('--')]
    if '--self-test' in sys.argv:
        return 0 if self_test() else 2
    if not self_test():
        print('ABORTING -- a hygiene check that cannot prove it detects anything proves nothing.')
        return 2

    root = os.path.abspath(args[0]) if args else os.path.dirname(os.path.dirname(
        os.path.abspath(__file__)))
    files = tracked(root)
    if files is None:
        print('::error title=Not a git repository::cannot determine which files would be '
              'published. Unknown scope is not empty scope.')
        return 2
    scoped = [f for f in files if in_scope(f)]
    if not scoped:
        print('::error title=Nothing in scope::%d tracked file(s), none eligible. A vacuous pass '
              'is not a pass.' % len(files))
        return 2

    hits = []
    for rel in scoped:
        for line, col, b in scan_file(os.path.join(root, rel.replace('/', os.sep))):
            hits.append((rel, line, col, b))

    print('')
    print('SOURCE HYGIENE -- control bytes in tracked text')
    print('-' * 88)
    print('  tracked files      %d' % len(files))
    print('  scanned            %d' % len(scoped))
    print('')
    if not hits:
        print('  CLEAN -- no control byte in any tracked text file.')
        print('')
        print('  This detects the CLASS, not the habit. A hand-written bad regex still gets')
        print('  through; what cannot get through is one whose text lies about its contents.')
        return 0
    for rel, line, col, b in hits[:40]:
        print('  %s:%d:%d  0x%02X %s' % (rel, line, col, b, NAMES.get(b, 'control')))
    if len(hits) > 40:
        print('  ... %d more' % (len(hits) - 40))
    print('')
    print('::error title=Control byte in source::%d found. These are INVISIBLE in an editor, a '
          'diff and a terminal. In a regex or a policy string they silently change behaviour -- a '
          'pattern containing 0x08 matches a backspace and therefore nothing. Almost always a '
          'shell heredoc eating a backslash escape; write the edit with an editor instead.'
          % len(hits))
    return 1


if __name__ == '__main__':
    sys.exit(main())

#!/usr/bin/env python3
"""Inline scripts/dependabot_config.py into the reusable check workflow, once, and hold the copy equal.

A reusable workflow cannot reach `scripts/` in the CALLER's checkout (inline_normalizer.py explains
the history), and a consumer should not need the kit checked out to have its Dependabot file
checked. So .github/workflows/reusable-dependabot-config-check.yml carries the script between two
marker lines, written to $RUNNER_TEMP by a heredoc. This writes that region; `--check` fails when the
copy differs from the canonical script by one byte.

USAGE  python3 scripts/inline_dependabot_config.py [--check]
EXIT   0 in sync (or rewritten)   1 --check found drift   2 the markers are missing
"""
import io
import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CANON = os.path.join(ROOT, 'scripts', 'dependabot_config.py')
WF = os.path.join(ROOT, '.github', 'workflows', 'reusable-dependabot-config-check.yml')
BEGIN = "cat > \"$RUNNER_TEMP/dependabot_config.py\" <<'DEPENDABOT_CONFIG_PY'"
END = 'DEPENDABOT_CONFIG_PY'
PAD = ' ' * 10


def region(text):
    lines = text.split('\n')
    for i, ln in enumerate(lines):
        if ln.strip() == BEGIN:
            for j in range(i + 1, len(lines)):
                if lines[j].strip() == END:
                    return lines, i, j
    return lines, None, None


def body():
    src = io.open(CANON, encoding='utf-8').read().replace('\r\n', '\n').rstrip('\n').split('\n')
    return [(PAD + ln) if ln else '' for ln in src]


def main(argv):
    text = io.open(WF, encoding='utf-8').read().replace('\r\n', '\n')
    lines, i, j = region(text)
    if i is None:
        print('UNKNOWN: the inline markers are missing from %s' % WF)
        return 2
    want = lines[:i + 1] + body() + lines[j:]
    new = '\n'.join(want)
    if '--check' in argv:
        if new != text:
            print('FAIL: the copy of scripts/dependabot_config.py inside reusable-dependabot-config-check.yml '
                  'differs from the script. Run: python3 scripts/inline_dependabot_config.py')
            return 1
        print('OK: the inlined dependabot_config.py is byte-equal to the canonical script.')
        return 0
    io.open(WF, 'w', encoding='utf-8', newline='\n').write(new)
    print('rewrote the inlined copy in %s' % os.path.relpath(WF, ROOT))
    return 0


if __name__ == '__main__':
    sys.exit(main(sys.argv[1:]))

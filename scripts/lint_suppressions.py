#!/usr/bin/env python3
"""Every error suppression must state WHY it is safe.

WHY ANNOTATION RATHER THAN PROHIBITION

`|| true`, `2>/dev/null` and `continue-on-error` are not defects. Some are correct and necessary:
cleanup must run after failure, noisy stderr can be suppressed without losing exit status, a
nonzero exit sometimes genuinely means "nothing found".

Outlawing the syntax produces a lint everybody disables. Requiring a stated reason produces a
RECORD -- so that six months from now, somebody who sees `continue-on-error: true` and tidies it
away has to first read why it exists. That has already happened once here in reverse: a publication
failure killed an entire deep scan because nobody had recorded that publication and detection are
different concerns.

THE ADVERSARIAL QUESTION each annotation must survive:

    If this command fails in a way DIFFERENT from the failure the author expected, what happens?

`grep -c` is the worked example. The author meant "exit 1 = zero matches". `grep` also exits 2 when
it cannot read the file. `|| echo 0` collapsed both, so an unreadable file counted as zero hits --
a multi-state dependency projected into a boolean before its states were understood.

REASONS (see assurance-taxonomy.yaml : suppression_reason)

    PRESENTATION_ONLY                     noise suppressed; exit status and failure state survive
    EXPECTED_NEGATIVE_RESULT              nonzero means "nothing found", and the distinction from
                                          "something broke" is handled explicitly
    FAILURE_ISOLATION_WITH_STATE_CAPTURE  execution continues AND the error becomes propagated data
    CLEANUP_AFTER_FAILURE                 must run after failure; makes no new assurance claim
    UNSAFE                                the signal that determines truth is destroyed -- fix it

USAGE
    # suppression: PRESENTATION_ONLY -- stderr is noisy; rc is checked on the next line
    some-command 2>/dev/null

    python3 scripts/lint_suppressions.py            report
    python3 scripts/lint_suppressions.py --check    fail on unannotated suppressions
"""

import io
import os
import re
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SCAN = [".github/workflows", "scripts", "tests"]
EXT = (".yml", ".yaml", ".sh")

REASONS = {
    "PRESENTATION_ONLY",
    "EXPECTED_NEGATIVE_RESULT",
    "FAILURE_ISOLATION_WITH_STATE_CAPTURE",
    "CLEANUP_AFTER_FAILURE",
    "UNSAFE",
}

IDIOMS = [
    (re.compile(r"\|\|\s*true\b"), "|| true"),
    (re.compile(r"\|\|\s*echo\s+0\b"), "|| echo 0"),
    (re.compile(r"2>\s*/dev/null"), "2>/dev/null"),
    (re.compile(r"continue-on-error:\s*true"), "continue-on-error"),
    (re.compile(r"\bset\s+\+e\b"), "set +e"),
]

ANNOT = re.compile(r"#\s*suppression:\s*([A-Z_]+)")
# STATING A REASON IS NOT SUFFICIENT. Suppression is permissible only when the suppressed signal is
# non-semantic for every relevant consumer, or its meaning survives through another explicit
# channel. So the annotation must name WHAT IS DISCARDED and WHERE IT SURVIVES.
DISCARDS = re.compile(r"#\s*discards:\s*(\S.*)")
PRESERVED = re.compile(r"#\s*preserved[_-]by:\s*(\S.*)")
# How far above a suppression its annotation may sit. Widened from 6 after completing the
# annotations pushed the `suppression:` marker out of range -- the count then dropped and looked
# like a regression when nothing had changed but the lookback. A measuring instrument's own limits
# must not present as a property of the thing measured.
WINDOW = 16


def files():
    for d in SCAN:
        for dp, _, fns in os.walk(os.path.join(ROOT, d)):
            for f in fns:
                if f.endswith(EXT):
                    yield os.path.join(dp, f)


def main(argv):
    check = "--check" in argv
    unannotated, annotated, unsafe, incomplete = [], [], [], []

    for p in files():
        if os.path.basename(p) == "lint_suppressions.py":
            continue
        try:
            lines = io.open(p, encoding="utf-8", errors="ignore").read().split("\n")
        except OSError:
            continue
        rel = os.path.relpath(p, ROOT).replace("\\", "/")

        for i, line in enumerate(lines):
            if line.lstrip().startswith("#"):
                continue                      # the doc-comment describing an idiom is not one
            for rx, label in IDIOMS:
                if not rx.search(line):
                    continue
                window = lines[max(0, i - WINDOW):i + 1]
                m = None
                for w in window:
                    m = ANNOT.search(w) or m
                if not m:
                    unannotated.append((rel, i + 1, label, line.strip()[:70]))
                elif m.group(1) not in REASONS:
                    unannotated.append((rel, i + 1, label,
                                        "unknown reason '%s'" % m.group(1)))
                elif m.group(1) == "UNSAFE":
                    unsafe.append((rel, i + 1, label))
                else:
                    blob = "\n".join(window)
                    if not (DISCARDS.search(blob) and PRESERVED.search(blob)):
                        incomplete.append((rel, i + 1, label, m.group(1)))
                    else:
                        annotated.append((rel, i + 1, label, m.group(1)))

    print("suppressions: %d complete, %d reason-only, %d unannotated, %d UNSAFE"
          % (len(annotated), len(incomplete), len(unannotated), len(unsafe)))

    if incomplete:
        print("\n-- REASON GIVEN, BUT NOT WHAT IS DISCARDED OR WHERE IT SURVIVES --")
        for rel, ln, label, reason in sorted(incomplete)[:12]:
            print("   %-34s:%-5d %-18s %s" % (rel, ln, label, reason))
        if len(incomplete) > 12:
            print("   ... and %d more" % (len(incomplete) - 12))
        print("   A reason explains the syntax. It does not establish that the discarded")
        print("   distinction is irrelevant to EVERY consumer, or preserved somewhere else.")

    if unsafe:
        print("\n-- MARKED UNSAFE (known defect, must be fixed) --")
        for rel, ln, label in unsafe:
            print("   %s:%d  %s" % (rel, ln, label))

    if unannotated:
        print("\n== UNANNOTATED SUPPRESSIONS ==")
        for rel, ln, label, src in sorted(unannotated):
            print("   %-34s:%-5d %-18s %s" % (rel, ln, label, src))
        print("\n::error title=Unannotated suppression::%d site(s) swallow an error without stating"
              " why that is safe. Add `# suppression: <REASON>` and answer: if this fails in a way"
              " DIFFERENT from the one you expected, what happens?" % len(unannotated))
        return 1 if check else 0

    print("\nevery suppression states why it is safe")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))

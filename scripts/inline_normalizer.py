#!/usr/bin/env python3
"""Inject the canonical SARIF normalizer into every workflow that needs it.

WHY A GENERATOR AND NOT A SHARED ACTION

A reusable workflow resolves `uses: ./...` against the CALLER's checkout, so anything under
`scripts/` does not exist at consumer runtime. The kit already learned this the expensive way —
14 Azure gitleaks rules that silently never loaded while its own CI stayed green. Three of its
workflow headers say so outright: *"Logic is INLINED (not `uses: ./`) so it resolves correctly when
called cross-repo."*

Referencing the kit's own repo by full path (`owner/secure-cicd-kit/.github/actions/...@v1`) would
hardcode an owner, which is its own portability defect.

So inlining is the only mechanism that works. But three hand-maintained copies is precisely the
drift that produced the flawfinder fix that never reached the workflow, the trivy tag bumped in one
place and not another, and the Azure rules. Therefore the copies are GENERATED from one canonical
file and CHECKED: `self-test` re-runs this in --check mode and fails if any inlined block has
diverged. Duplication becomes an enforced invariant rather than a hope.

USAGE
    python3 scripts/inline_normalizer.py           # rewrite the inlined blocks
    python3 scripts/inline_normalizer.py --check   # fail if any copy has drifted
"""

import io
import os
import re
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CANON = os.path.join(ROOT, "scripts", "normalize_sarif.py")
WF = os.path.join(ROOT, ".github", "workflows")

# ONE GENERATOR, N CANONICAL SCRIPTS.
#
# scan_report.py joined normalize_sarif.py under the same constraint for the same reason: a
# reusable workflow cannot reach the kit's own scripts/ directory at consumer runtime. Adding a
# second bespoke generator would have re-created, at the level of the tooling, precisely the
# duplication the tooling exists to police.
#
# Each entry is (canonical file, marker token, heredoc tag, /tmp destination).
SCRIPTS = [
    ("normalize_sarif.py", "NORMALIZE_SARIF", "NORMALIZE_PY", "/tmp/normalize_sarif.py"),
    ("scan_report.py", "SCAN_REPORT", "SCAN_REPORT_PY", "/tmp/scan_report.py"),
    ("scan_status.sh", "SCAN_STATUS", "SCAN_STATUS_SH", "/tmp/scan_status.sh"),
    ("redact_sarif.py", "REDACT_SARIF", "REDACT_SARIF_PY", "/tmp/redact_sarif.py"),
    ("sbom_licenses.py", "SBOM_LICENSES", "SBOM_LICENSES_PY",
     "/tmp/sbom_licenses.py"),
]

TARGETS = ["reusable-security.yml"]

# Per-job result block. job -> (display name, sarif path or '', scope).
#
# Every scanner job gets one. The consolidated `report` job owns severity, remediation, gate
# impact and disposition; this is only what the job itself knows, so that someone debugging a
# scanner does not have to leave its own log to find out whether it found anything.
# sonar and zap were removed 2026-09-14: they are the overlay capabilities and no
# longer live in the neutral core. A generator that still targeted them would silently
# place nothing, and "0 blocks placed" reads identically to "nothing needed placing".
STATUS_JOBS = [
    ("secret-scan",   "Secret scan",        "gitleaks.sarif",     "whole repository"),
    ("code-quality",  "Code quality",       "",                   "linters"),
    ("sast-semgrep",  "SAST (Semgrep)",     "semgrep.sarif",      "source"),
    ("sast-bandit",   "SAST (Bandit)",      "bandit.sarif",       "python"),
    ("deps-scan",     "Dependencies",       "trivy-deps.sarif",   "dependencies + CVE feeds"),
    # checkov-action writes into a DIRECTORY named by output_file_path; the report is the file
    # inside it. Passing "" here meant the IaC job printed "findings NOT ESTABLISHED" on every
    # run, including runs where it had just counted sixteen.
    ("iac-scan",      "Infrastructure",     "checkov.sarif/results_sarif.sarif",
     "terraform / bicep / docker"),
    ("sast-dotnet",   "SAST (.NET)",        "",                   "dotnet"),
    ("sast-java",     "SAST (Java)",        "",                   "java / kotlin"),
    ("sast-go",       "SAST (Go)",          "",                   "go"),
    ("sast-cpp",      "SAST (C/C++)",       "",                   "c / c++"),
    ("malicious-deps", "Malicious packages", "",                  "dependency provenance"),
    ("sbom",          "SBOM",               "",                   "components"),
]
STATUS_TOKEN = "SCAN_STATUS"
STATUS_TAG = "SCAN_STATUS_SH"


def status_step(job, display, sarif, scope):
    """A complete generated STEP, not just a heredoc, appended to one scanner job."""
    body = io.open(os.path.join(ROOT, "scripts", "scan_status.sh"), encoding="utf-8").read()
    begin, end = markers(STATUS_TOKEN, "scan_status.sh")
    pad = " " * 6
    out = [pad + begin,
           pad + "- name: Result summary",
           pad + "  if: always()",
           pad + "  shell: bash",
           pad + "  env:",
           # job.status is a controlled enum and could not carry shell syntax. It goes through
           # env: anyway -- deciding case by case which inputs are "safe enough" to interpolate
           # is exactly what put a PR body into a run: block in the ticket-reference gate.
           pad + "    JOB_STATUS: ${{ job.status }}",
           pad + "  run: |",
           pad + "    cat > /tmp/scan_status.sh <<'" + STATUS_TAG + "'"]
    inner = pad + "    "
    out += [(inner + line).rstrip() if line.strip() else "" for line in body.split("\n")]
    out += [inner + STATUS_TAG,
            inner + ". /tmp/scan_status.sh",
            inner + 'if [ "$JOB_STATUS" = "success" ]; then _e=COMPLETE; else _e=FAILED; fi',
            inner + 'scan_status "%s" "$_e" "%s" "%s"' % (display, sarif, scope),
            pad + end]
    return "\n".join(out)


def markers(token, canon_name):
    # The em dash is load-bearing: the blocks already inlined in the workflow carry it. Emitting a
    # hyphen here would make `extract` match nothing, and a check that finds no copies would then
    # report success -- a drift detector passing because it looked for the wrong string. `main`
    # treats "no copies found" as a failure for the same reason.
    return (u"# BEGIN %s — generated from scripts/%s. DO NOT EDIT HERE." % (token, canon_name),
            "# END %s" % token)


def block(indent, canon_name, token, tag, dest):
    """The inlined heredoc, indented to sit inside a workflow `run:` step."""
    body = io.open(os.path.join(ROOT, "scripts", canon_name), encoding="utf-8").read()
    begin, end = markers(token, canon_name)
    pad = " " * indent
    out = [pad + begin, pad + "cat > %s <<'%s'" % (dest, tag)]
    # Heredoc body must NOT be indented relative to the block scalar, or the content changes.
    # YAML strips the common indent, so emit the body at the same indent as the terminator.
    out += [(pad + line).rstrip() if line.strip() else "" for line in body.split("\n")]
    out += [pad + tag, pad + end]
    return "\n".join(out)


def extract(text, token, canon_name, tag):
    """Return every inlined body found, as it would be written to /tmp."""
    begin, end = markers(token, canon_name)
    found = []
    idx = 0
    while True:
        b = text.find(begin, idx)
        if b == -1:
            return found
        e = text.find(end, b)
        seg = text[b:e]
        catline = seg.index("<<'%s'\n" % tag)
        start = catline + len("<<'%s'\n" % tag)
        body = seg[start:seg.rindex(tag)]
        # INDENT COMES FROM THE `cat >` LINE, NOT THE BEGIN MARKER.
        #
        # For a block inlined inside an existing run:, the two are identical. For a block that
        # generates a whole STEP, the marker sits at step indent and the heredoc body four spaces
        # deeper -- so measuring from the marker left four spaces on every line and every one of
        # the fourteen copies reported DRIFTED against a file they matched exactly. A drift
        # detector that cries wolf on correct output gets switched off, which is worse than not
        # having one.
        line_start = seg.rfind("\n", 0, catline) + 1
        catline_text = seg[line_start:catline]
        indent = len(catline_text) - len(catline_text.lstrip(" "))
        lines = [ln[indent:] if len(ln) >= indent else ln for ln in body.split("\n")]
        found.append("\n".join(lines).rstrip("\n"))
        idx = e + 1


def inject(text, canon_name, token, tag, dest):
    """Replace every BEGIN/END region with a freshly generated block. Returns (text, n).

    The write half of this generator was documented from the start and never implemented --
    `block()` existed and nothing called it, so the three inlined copies were placed by hand and
    only the CHECK half ever ran. That is the same "written but not plugged in" shape the kit
    keeps finding elsewhere, sitting inside the tool built to police duplication.
    """
    begin, end = markers(token, canon_name)
    out, idx, n = [], 0, 0
    while True:
        b = text.find(begin, idx)
        if b == -1:
            out.append(text[idx:])
            return ("".join(out), n)
        line_start = text.rfind("\n", 0, b) + 1
        indent = b - line_start
        e = text.find(end, b)
        if e == -1:
            raise ValueError("%s: BEGIN marker without a matching END" % canon_name)
        out.append(text[idx:line_start])
        out.append(block(indent, canon_name, token, tag, dest))
        idx = e + len(end)
        n += 1


REDACT_TOKEN = "REDACT_SARIF"
REDACT_TAG = "REDACT_SARIF_PY"


def redact_step():
    """A generated step that scrubs every SARIF in the workspace before it becomes an artifact."""
    body = io.open(os.path.join(ROOT, "scripts", "redact_sarif.py"), encoding="utf-8").read()
    begin, end = markers(REDACT_TOKEN, "redact_sarif.py")
    pad = " " * 6
    out = [pad + begin,
           pad + "- name: Redact credential material before upload",
           pad + "  if: always()",
           pad + "  shell: bash",
           pad + "  run: |",
           pad + "    cat > /tmp/redact_sarif.py <<'" + REDACT_TAG + "'"]
    inner = pad + "    "
    out += [(inner + line).rstrip() if line.strip() else "" for line in body.split("\n")]
    out += [inner + REDACT_TAG,
            inner + "shopt -s nullglob globstar",
            inner + "# A PATH ENDING .sarif IS NOT ALWAYS A SARIF FILE.",
            inner + "#",
            inner + "# checkov-action treats `output_file_path` as a DIRECTORY and writes",
            inner + "# checkov.sarif/results_sarif.sarif inside it. `*.sarif` therefore matched the",
            inner + "# DIRECTORY, the redactor raised IsADirectoryError and exited 1, and a job whose",
            inner + "# scan had SUCCEEDED went red -- taking the second IaC scanner behind it with it,",
            inner + "# because that step had no if: always(). A housekeeping step decided a security",
            inner + "# verdict. Keep regular files only; **/*.sarif still finds the real report inside.",
            inner + "files=()",
            inner + "for _f in *.sarif **/*.sarif; do",
            inner + '  if [ -f "$_f" ]; then files+=( "$_f" ); fi',
            inner + "done",
            inner + 'if [ ${#files[@]} -eq 0 ]; then',
            inner + '  echo "no SARIF produced by this job -- nothing to redact"',
            inner + "else",
            inner + '  python3 /tmp/redact_sarif.py "${files[@]}"',
            inner + "fi",
            pad + end]
    return "\n".join(out)


def place_redaction_steps(text):
    """Insert the redactor immediately BEFORE the first upload-artifact step of each job.

    ORDER IS THE WHOLE POINT. The per-job status block is appended at the END of a job, which is
    fine for printing a count and useless for redaction -- by then the artifact is already
    uploaded. A redactor that runs after the upload protects nothing.

    Idempotent: an existing generated block is removed before re-inserting, so re-running the
    generator cannot stack copies.
    """
    begin, end = markers(REDACT_TOKEN, "redact_sarif.py")
    n = 0
    for m in list(re.finditer(r"(?ms)^  ([a-z][\w-]*):\n.*?(?=^  [a-z][\w-]*:\s*$|\Z)", text)):
        pass
    # Re-scan each time, because every insertion shifts later offsets.
    jobs = [mm.group(1) for mm in
            re.finditer(r"(?m)^  ([a-z][\w-]*):\s*$", text)]
    for job in jobs:
        m = re.search(r"(?ms)^  %s:\n.*?(?=^  [a-z][\w-]*:\s*$|\Z)" % re.escape(job), text)
        if not m:
            continue
        seg = m.group(0)
        seg_clean = re.sub(r"(?ms)^ *%s.*?^ *%s\n?" % (re.escape(begin), re.escape(end)), "", seg)
        if "upload-artifact" not in seg_clean:
            if seg != seg_clean:
                text = text[:m.start()] + seg_clean + text[m.end():]
            continue
        # Split into steps at the 6-space list marker and find the first upload.
        parts = re.split(r"(?m)^(?=      - )", seg_clean)
        idx = next((i for i, p in enumerate(parts) if "upload-artifact" in p), None)
        if idx is None:
            continue
        parts.insert(idx, redact_step() + "\n")
        new_seg = "".join(parts)
        text = text[:m.start()] + new_seg + text[m.end():]
        n += 1
    return (text, n)


def place_status_steps(text):
    """Append the generated Result-summary step to each scanner job. Returns (text, n).

    Inserted at the END of a job, immediately before the next job header. Idempotent: an existing
    generated block is replaced, never stacked, so re-running cannot accumulate copies.
    """
    begin, end = markers(STATUS_TOKEN, "scan_status.sh")
    n = 0
    for job, display, sarif, scope in STATUS_JOBS:
        m = re.search(r"(?ms)^  %s:\n.*?(?=^  [a-z][\w-]*:\s*$|\Z)" % re.escape(job), text)
        if not m:
            continue
        seg = m.group(0)
        # drop any previous generated block before re-inserting
        seg_clean = re.sub(r"(?ms)^ *%s.*?^ *%s\n?" % (re.escape(begin), re.escape(end)), "", seg)
        seg_clean = seg_clean.rstrip("\n")
        new_seg = seg_clean + "\n\n" + status_step(job, display, sarif, scope) + "\n\n"
        text = text[:m.start()] + new_seg + text[m.end():]
        n += 1
    return (text, n)


def main(argv):
    check = "--check" in argv
    if not check:
        written = 0
        for canon_name, token, tag, dest in SCRIPTS:
            for name in TARGETS:
                p = os.path.join(WF, name)
                t = io.open(p, encoding="utf-8").read()
                new, n = inject(t, canon_name, token, tag, dest)
                if n and new != t:
                    io.open(p, "w", encoding="utf-8", newline="\n").write(new)
                written += n
                print("  %-20s %s: %d block(s) regenerated" % (canon_name, name, n))
        for name in TARGETS:
            p = os.path.join(WF, name)
            t = io.open(p, encoding="utf-8").read()
            new, n = place_redaction_steps(t)
            if n and new != t:
                io.open(p, "w", encoding="utf-8", newline=chr(10)).write(new)
            written += n
            print("  %-20s %s: %d pre-upload redaction step(s)" % ("redact_sarif.py", name, n))

        for name in TARGETS:
            p = os.path.join(WF, name)
            t = io.open(p, encoding="utf-8").read()
            new, n = place_status_steps(t)
            if n and new != t:
                io.open(p, "w", encoding="utf-8", newline=chr(10)).write(new)
            written += n
            print("  %-20s %s: %d per-job status step(s)" % ("scan_status.sh", name, n))
        print("regenerated %d inlined block(s); re-run with --check to verify" % written)
        return 0
    drift, missing, total = [], [], 0
    for canon_name, token, tag, dest in SCRIPTS:
        canon = io.open(os.path.join(ROOT, "scripts", canon_name),
                        encoding="utf-8").read().rstrip("\n")
        for name in TARGETS:
            t = io.open(os.path.join(WF, name), encoding="utf-8").read()
            copies = extract(t, token, canon_name, tag)
            if not copies:
                # NOT a pass. A drift check that finds nothing to compare and reports success is
                # the vacuous-truth failure: every claim about an empty set is satisfied. This is
                # how a renamed marker, a deleted block or a typo'd heredoc tag would turn the
                # guard off while leaving it green.
                missing.append("%s in %s" % (canon_name, name))
                print("  %-20s %s: NO INLINED BLOCK FOUND" % (canon_name, name))
                continue
            bad = [i + 1 for i, c in enumerate(copies) if c.rstrip("\n") != canon]
            total += len(copies)
            for i in bad:
                drift.append("%s in %s block %d" % (canon_name, name, i))
            print("  %-20s %s: %d inlined copy/copies, %s"
                  % (canon_name, name, len(copies),
                     "DRIFTED" if bad else "identical to canonical"))
    if check:
        if drift:
            print("::error title=Inlined script drift::" + ", ".join(drift) +
                  " differ from their canonical file under scripts/. The inlined copies are "
                  "GENERATED; edit the canonical file and re-run scripts/inline_normalizer.py.")
            return 1
        if missing:
            print("::error title=Inlined block missing::" + ", ".join(missing) +
                  " -- the canonical script is registered in SCRIPTS but no inlined copy exists "
                  "in the workflow. Either the block was removed, the marker was renamed, or the "
                  "script was never wired in. A check with nothing to compare is not a pass.")
            return 1
        print("inlined scripts: all %d copy/copies match their canonical source" % total)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))

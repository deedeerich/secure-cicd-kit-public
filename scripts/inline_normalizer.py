#!/usr/bin/env python3
"""Put the canonical scripts into the workflow ONCE, and fetch them everywhere else.

WHY THE SCRIPTS CANNOT SIMPLY BE `uses: ./`

A reusable workflow resolves `uses: ./...` against the CALLER's checkout, so anything under
`scripts/` does not exist at consumer runtime. The kit already learned this the expensive way --
14 Azure gitleaks rules that silently never loaded while its own CI stayed green. Three of its
workflow headers say so outright: *"Logic is INLINED (not `uses: ./`) so it resolves correctly when
called cross-repo."*

Referencing the kit's own repo by full path (`owner/secure-cicd-kit/.github/actions/...@v1`) would
hardcode an owner, which is its own portability defect.

WHY THE ANSWER IS NO LONGER "INLINE IT INTO EVERY JOB"

It was, and that answer killed the workflow. Each script was inlined at every CALL SITE: thirteen
byte-identical copies of redact_sarif.py, twelve of scan_status.sh, three of normalize_sarif.py.
On 2026-09-16 the file crossed GitHub's 500 KB ceiling at 608.8 KB and GitHub stopped STARTING it
-- zero jobs, a startup failure on every push, for six days, while every check in this repository
reported green because they all READ the file and none of them RAN it.

Duplication was never the requirement. REACHABILITY was. So the scripts are written out ONCE, by a
bootstrap job (`kit-scripts`), and published as a RUN-SCOPED ARTIFACT that every other job in the
same run downloads into /tmp. Every call site still invokes `/tmp/<script>` exactly as before.

WHY AN ARTIFACT CAME FIRST, AND WHY `$/` NOW CARRIES THE JOB BODIES

GitHub shipped self-repository `uses:` syntax (`$/.github/actions/...`) on 2026-07-30. When this
generator was written, how it resolved inside a reusable workflow called from ANOTHER repository was
unestablished, so the bundle went out as a run-scoped artifact, which belongs to the RUN and needs
nothing new. `$/` was then proven cross-repository (decomposition plan step 8; Level 2 runs
38434823833, 38468728084) and discover, resolve, the report and, since ledger L64, scanner job
bodies (COMPOSITES below) run through it. It needs github.com and runner >= 2.336.0, so no GitHub
Enterprise Server (OD-8, ledger O-22, an open owner decision). The artifact remains while job bodies
still call /tmp/<script>; it is retired when the last one has moved (ledger L64, B-01).

WHAT IS STILL GENERATED, AND WHY IT IS STILL CHECKED

One copy is still a copy. `--check` re-derives the entire generated surface and fails if the file
on disk differs -- and fails if a canonical script has MORE THAN ONE inlined copy, because that is
exactly how 623 KB happened the first time.

USAGE
    python3 scripts/inline_normalizer.py           # rewrite the generated regions
    python3 scripts/inline_normalizer.py --check   # fail if anything has drifted
"""

import hashlib
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
# Each entry is (canonical file, marker token, heredoc tag, /tmp destination). Every one of these
# is written by the bootstrap job and by nothing else; the destination is what every call site in
# every other job already invokes, which is why moving the WRITE did not move the CALL.
SCRIPTS = [
    ("normalize_sarif.py", "NORMALIZE_SARIF", "NORMALIZE_PY", "/tmp/normalize_sarif.py"),
    # scan_report.py LEFT THE BUNDLE at decomposition step 11. The report job now runs it through
    # the scan-report composite (`$/`), beside the identity modules it imports and this bundle never
    # shipped (C1, KDEC-002). Nothing else invokes /tmp/scan_report.py.
    ("scan_status.sh", "SCAN_STATUS", "SCAN_STATUS_SH", "/tmp/scan_status.sh"),
    ("redact_sarif.py", "REDACT_SARIF", "REDACT_SARIF_PY", "/tmp/redact_sarif.py"),
    ("sbom_licenses.py", "SBOM_LICENSES", "SBOM_LICENSES_PY",
     "/tmp/sbom_licenses.py"),
    # THE WRAPPER IS A SCRIPT TOO. The pre-upload sweep used to be shell emitted into every job
    # that uploads -- fourteen byte-identical copies, 47 KB of one wrapper, inside the file that
    # had just been rescued from GitHub's size limit for exactly that reason. Duplicated prose
    # drifts the same way duplicated code does.
    ("redact_all.sh", "REDACT_ALL", "REDACT_ALL_SH", "/tmp/redact_all.sh"),
    # Validity rows 1-6 before publication (ledger L02). One copy here, called at every count
    # site, rather than six rows re-implemented in jq ten times.
    ("sarif_validity.py", "SARIF_VALIDITY", "SARIF_VALIDITY_PY", "/tmp/sarif_validity.py"),
]

TARGETS = ["reusable-security.yml"]

# SCANNER COMPOSITES (completion ledger L64; decomposition plan section 7 step 12). A scanner job
# whose body moved into `.github/actions/<name>/` keeps only the composite call and its Result
# summary (which reads `job.status`, a JOB fact). The fetch + verify pair and every pre-upload
# redaction move WITH the body, to the same positions relative to the same steps: the fetch is the
# composite's first steps, and the redaction walk below runs over the composite's step list exactly
# as it runs over a job's. The composite is the job's FIRST step, so "first step of the job" and
# "first step of the composite" are the same moment on the runner.
# tests/prove_composite_move_equivalence.py expands each call back into its job and compares it
# with the job as it stood before the move.
COMPOSITES = ["secret-scan", "sast-cpp", "iac-scan", "deps-scan", "sast-dotnet", "sast-java",
              # lane L-SCAN-B (KDEC-026): born a composite, never inline.
              "sast-mobile"]
ACTIONS = os.path.join(ROOT, ".github", "actions")

# The one job that materialises the scripts. It is excluded from the fetch step for the obvious
# reason, and included in the redaction step for a less obvious one: it uploads an artifact, and
# "every job that uploads redacts first" is a stronger invariant than one with a carve-out in it.
BOOTSTRAP_JOB = "kit-scripts"
ARTIFACT = "kit-scripts-${{ github.run_attempt }}"

# Jobs that invoke at least one of the scripts. Anything here gets the download step as its FIRST
# step, before checkout, because a later step cannot fetch what an earlier step already needed.
#
# A job missing from this list does not fail quietly: every call site checks that its script is
# present and says so loudly if it is not. A MISSING TOOL IS NOT A CLEAN RESULT -- that conflation
# is the kit's founding defect (gosec pinned to a tag that never existed, `|| true`, "the scanner
# could not be acquired" recorded as "the scanner found nothing").
FETCH_JOBS = [
    # A job listed in COMPOSITES fetches INSIDE its composite (COMPOSITES above).
    "code-quality", "sast-semgrep", "sast-bandit", "codeql", 
    "sast-go", "malicious-deps",
    "sbom", "report",
    # image-scan joined when its reports stopped dying with the runner (ledger L12): it now
    # redacts before uploading, and the redactor lives in this bundle.
    "image-scan",
]

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
    ("sast-mobile",   "SAST (mobile)",      "",                   "android / ios"),
    ("sast-go",       "SAST (Go)",          "",                   "go"),
    ("sast-cpp",      "SAST (C/C++)",       "",                   "c / c++"),
    ("malicious-deps", "Malicious packages", "",                  "dependency provenance"),
    ("sbom",          "SBOM",               "",                   "components"),
    ("image-scan",    "Container image",    "trivy-image.sarif",  "image vulnerabilities"),
]
STATUS_TOKEN = "SCAN_STATUS"
STATUS_TAG = "SCAN_STATUS_SH"

# Tokens for the GENERATED STEPS. Deliberately distinct from the SCRIPTS tokens above: a step
# marker and a script marker that shared a name would make `extract` match a wrapper and compare
# it against a canonical file it was never meant to equal -- and a drift detector that cries wolf
# on correct output gets switched off, which is worse than not having one.
FETCH_STEP_TOKEN = "FETCH_KIT_SCRIPTS"
REDACT_STEP_TOKEN = "REDACT_STEP"
STATUS_STEP_TOKEN = "STATUS_STEP"
# The producer-side step: build the digest manifest and assert it against the value pinned in
# this file. Separate token from the consumer-side verification for the same reason the step
# markers are separate from the script markers -- one region, one meaning.
PIN_STEP_TOKEN = "PIN_KIT_SCRIPTS"
# The step the pin block must follow. Anchored on the step NAME rather than on a position,
# because a position moves and a name is the thing a reader actually looks for.
PIN_ANCHOR = "- name: Write the canonical scripts"
MANIFEST = "/tmp/kit-scripts.sha256"


def materialised(canon_name):
    """The EXACT bytes the bootstrap job's heredoc writes to /tmp for one canonical script.

    NOT the canonical file's bytes. `block()` right-strips every line and YAML strips the block
    scalar's common indent, so what lands on the runner is a deterministic FUNCTION of the
    canonical file rather than a copy of it. A digest computed over the source file would
    therefore mismatch on the runner for any script carrying trailing whitespace or a final
    newline -- and a pinned digest that fails on correct output is worse than none, because the
    first thing anyone does with an integrity check that cries wolf is switch it off.

    Reproduced here from the generator's own emission rules so the two cannot drift: the same
    function produces the workflow text and the digest that vouches for it.
    """
    body = io.open(os.path.join(ROOT, "scripts", canon_name), encoding="utf-8").read()
    lines = [line.rstrip() if line.strip() else "" for line in body.split("\n")]
    # Each emitted line is written by the heredoc followed by a newline.
    return ("".join(ln + "\n" for ln in lines)).encode("utf-8")


def manifest_body():
    """`sha256sum` manifest text for the six scripts, in the order they are written."""
    return "".join(
        "%s  %s\n" % (hashlib.sha256(materialised(canon)).hexdigest(), os.path.basename(dest))
        for canon, _token, _tag, dest in SCRIPTS)


def manifest_digest():
    """The single value pinned at every call site. A commitment to all six digests at once.

    ONE PINNED VALUE, NOT SIX PER JOB. The manifest lists every script's digest; pinning the
    manifest's own digest is cryptographically the same assertion and costs one line per call
    site instead of six. Fourteen call sites x six lines is how this file crossed GitHub's size
    limit the first time, and an integrity check that reintroduces the failure it is guarding
    against has not helped anyone.
    """
    return hashlib.sha256(manifest_body().encode("utf-8")).hexdigest()


def markers(token, canon_name):
    # The em dash is load-bearing: the blocks already inlined in the workflow carry it. Emitting a
    # hyphen here would make `extract` match nothing, and a check that finds no copies would then
    # report success -- a drift detector passing because it looked for the wrong string. `main`
    # treats "no copies found" as a failure for the same reason.
    return (u"# BEGIN %s \u2014 generated from scripts/%s. DO NOT EDIT HERE." % (token, canon_name),
            "# END %s" % token)


def step_markers(token):
    """Markers for a generated STEP (as opposed to a generated script body)."""
    return (u"# BEGIN %s \u2014 generated by scripts/inline_normalizer.py. DO NOT EDIT HERE."
            % token,
            "# END %s" % token)


def drop_region(text, begin, end):
    """Remove every BEGIN..END region, markers included, at any indent. Idempotence lives here."""
    return re.sub(r"(?ms)^[ ]*%s.*?^[ ]*%s[ ]*\n?" % (re.escape(begin), re.escape(end)), "", text)


def fetch_step(pad_n=6, where="the top of this file"):
    """Download the run-scoped script bundle AND verify it. FIRST steps of the job.

    THE DOWNLOAD AND THE VERIFICATION ARE ONE REGION ON PURPOSE. They are two steps because a
    `uses:` step cannot also run shell, but they are a single control: a download whose bytes
    nobody checked is a supply-chain step with no integrity check, and anything that could place
    the verification somewhere other than immediately after the fetch -- a hand edit, a
    reordering, a job that copied the download and not the check -- would leave that gap open
    while the workflow still read as protected.
    """
    begin, end = step_markers(FETCH_STEP_TOKEN)
    pad = " " * pad_n
    inner = pad + "    "
    return "\n".join([
        pad + begin,
        pad + "- name: Fetch the kit's own scripts",
        pad + "  # A RUN-SCOPED ARTIFACT, NOT `uses: ./` and NOT a copy per call site. Why, at",
        pad + "  # length, in the `kit-scripts` job at %s." % where,
        pad + "  if: always()",
        # SHA-pinned like every remote `uses:` in the kit (ledger L82; tests/check_action_pins.py).
        pad + "  uses: actions/download-artifact@9000827ccba6bdab643e8b6fd33ac0654aef8333 # v8.0.2",
        pad + "  with:",
        pad + "    name: " + ARTIFACT,
        pad + "    path: /tmp",
        pad + "- name: Verify the kit scripts against their pinned digest",
        pad + "  # A DOWNLOADED SCRIPT NOBODY VERIFIED IS A SUPPLY CHAIN STEP WITH NO INTEGRITY",
        pad + "  # CHECK. Why this digest and not a manifest fetched beside it: `kit-scripts`.",
        pad + "  if: always()",
        pad + "  shell: bash",
        pad + "  run: |",
        inner + "set -euo pipefail",
        inner + "cd /tmp",
        inner + 'echo "%s  kit-scripts.sha256" | sha256sum -c -' % manifest_digest(),
        inner + "sha256sum -c kit-scripts.sha256",
        pad + end,
    ])


def pin_step():
    """Producer side: write the manifest, and assert it against the digest pinned in this file.

    WHY THE PRODUCER VERIFIES TOO, WHEN IT JUST WROTE THE FILES ITSELF

    It is not checking the download -- there was none. It is checking the ROUND TRIP. What lands
    in /tmp is not the canonical file: the generator right-strips every line and YAML strips the
    block scalar's indent, so the bytes on the runner are a function of the source, and a change
    to either end of that function would silently produce a different script. Asserting it HERE
    means a mismatch surfaces in the one job that can explain it, before thirteen consumers each
    discover it separately as "sha256sum: WARNING: 1 computed checksum did NOT match".

    It also closes the obvious hole in the consumer check: without this, a manifest built at run
    time from whatever was written would faithfully describe the wrong thing, and every consumer
    would verify the bundle against its own corruption.
    """
    begin, end = step_markers(PIN_STEP_TOKEN)
    pad = " " * 6
    inner = pad + "    "
    out = [pad + begin,
           pad + "- name: Pin what was written, and assert it is what this file promises",
           pad + "  shell: bash",
           pad + "  run: |",
           inner + "set -euo pipefail",
           inner + "cd /tmp",
           # -t IS NOT DECORATION. GNU coreutils prints `<hash>  name` in text mode and
           # `<hash> *name` in binary mode, and binary is the DEFAULT on Windows builds. The
           # pinned digest is over the manifest BYTES, so a separator that changes with the
           # platform changes the digest -- and the local proof that runs this step could
           # never agree with the runner. Force text mode and the format is a fact, not a
           # property of whoever executed it.
           #
           # EVERY LINE HERE ENDS IN A CONTINUATION UNTIL THE REDIRECT, DELIBERATELY. Dropping
           # the backslash before `> kit-scripts.sha256` makes the redirect a SEPARATE command
           # that truncates the manifest to zero bytes while sha256sum's output goes to the
           # log -- a manifest that looks written, reads empty, and certifies nothing. Caught
           # by tests/prove_kit_script_digests.py running this step rather than reading it.
           inner + "sha256sum -t \\"]
    names = [os.path.basename(dest) for _c, _t, _g, dest in SCRIPTS]
    for n in names:
        out.append(inner + "  " + n + " \\")
    out += [
        inner + "  > kit-scripts.sha256",
        inner + "cat kit-scripts.sha256",
        inner + "# THE ROUND TRIP, ASSERTED. The digest below is derived by",
        inner + "# scripts/inline_normalizer.py from scripts/*, so a mismatch means the bytes",
        inner + "# that reached this runner are not the bytes this repository holds. That is",
        inner + "# not a warning: every downstream job is about to execute these files.",
        inner + 'if ! echo "%s  kit-scripts.sha256" | sha256sum -c -; then' % manifest_digest(),
        inner + '  echo "::error title=Kit scripts do not match their pinned digest::What this"',
        inner + '  echo "job wrote to /tmp differs from what scripts/inline_normalizer.py"',
        inner + '  echo "derived from scripts/. Publishing it would hand every scanner a"',
        inner + '  echo "script this repository cannot vouch for. Re-run the generator."',
        inner + "  exit 1",
        inner + "fi",
        pad + end]
    return "\n".join(out)


def place_pin_step(text):
    """Insert the producer-side pin block immediately after the step that writes the scripts.

    Anchored on the step NAME, not an offset: the manifest must describe files that exist, and
    must exist before the upload publishes it. Both facts are true of "right after the write"
    and of nowhere else.
    """
    begin, end = step_markers(PIN_STEP_TOKEN)
    m = job_segment(text, BOOTSTRAP_JOB)
    if not m:
        return (text, 0)
    seg = drop_region(m.group(0), begin, end)
    anchor = re.search(r"(?m)^      %s[ ]*\n" % re.escape(PIN_ANCHOR), seg)
    if not anchor:
        raise ValueError("%s: no step named %r to anchor the pin block to"
                         % (BOOTSTRAP_JOB, PIN_ANCHOR))
    # The anchored step ends where the next 6-space list item begins -- OR where the next
    # generated region's BEGIN marker does. Matching only on `- ` put this block BETWEEN a
    # `# BEGIN REDACT_STEP` marker and its own step, so the next regenerate() dropped the
    # redaction region and took this block out with it. A generated block that silently
    # deletes itself is worse than one that was never placed.
    nxt = re.search(r"(?m)^      (?:- |# BEGIN )", seg[anchor.end():])
    cut = anchor.end() + (nxt.start() if nxt else len(seg) - anchor.end())
    seg = seg[:cut] + pin_step() + "\n" + seg[cut:]
    return (text[:m.start()] + seg + text[m.end():], 1)


def status_step(job, display, sarif, scope):
    """A complete generated STEP, appended to one scanner job."""
    begin, end = step_markers(STATUS_STEP_TOKEN)
    pad = " " * 6
    inner = pad + "    "
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
           inner + "# A SUMMARY IS NOT A VERDICT. If the script did not arrive, say so and stop;",
           inner + "# never fail the job for it. A housekeeping step deciding a security verdict",
           inner + "# is how a scan that had SUCCEEDED went red twice in this file's history.",
           inner + "if [ ! -s /tmp/scan_status.sh ]; then",
           inner + '  echo "::warning title=Result summary unavailable::'
           + '/tmp/scan_status.sh did not reach this job."',
           inner + '  echo "No per-job summary was printed. The scan\'s own verdict stands."',
           inner + "  exit 0",
           inner + "fi",
           inner + ". /tmp/scan_status.sh",
           inner + 'if [ "$JOB_STATUS" = "success" ]; then _e=COMPLETE; else _e=FAILED; fi',
           inner + 'scan_status "%s" "$_e" "%s" "%s"' % (display, sarif, scope),
           pad + end]
    return "\n".join(out)


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


def redact_step(pad_n=6):
    """A generated step that scrubs every SARIF in the workspace before it becomes an artifact."""
    begin, end = step_markers(REDACT_STEP_TOKEN)
    pad = " " * pad_n
    inner = pad + "    "
    out = [pad + begin,
           pad + "- name: Redact credential material before upload",
           pad + "  if: always()",
           pad + "  shell: bash",
           pad + "  run: |",
           inner + "# ORDER IS THE WHOLE CONTROL: this runs immediately before an upload, and",
           inner + "# again before every later upload that follows a step which may have written",
           inner + "# output -- a redactor after the upload protects nothing while looking exactly",
           inner + "# like protection (N24/WP19). The sweep itself is ONE canonical script --",
           inner + "# scripts/redact_all.sh, written by the `kit-scripts` job and fetched into",
           inner + "# /tmp by every other -- because fourteen copies of one wrapper are how this",
           inner + "# file reached 608.8 KB and stopped starting.",
           inner + "#",
           inner + "# A MISSING TOOL IS NOT A CLEAN RESULT. If the bundle did not arrive,",
           inner + "# publication must not proceed on the strength of a scrub that never ran.",
           inner + "if [ ! -s /tmp/redact_all.sh ]; then",
           inner + '  echo "::error title=Redaction could not be guaranteed::'
           + '/tmp/redact_all.sh is absent."',
           inner + '  echo "The kit-scripts artifact did not reach this job, so no SARIF was'
           + ' scrubbed"',
           inner + '  echo "and none may be published. A MISSING TOOL IS NOT A CLEAN RESULT."',
           inner + "  exit 1",
           inner + "fi",
           inner + "bash /tmp/redact_all.sh",
           pad + end]
    return "\n".join(out)


def job_segment(text, job):
    """The full text of one job, header line to the next job header (or EOF)."""
    return re.search(r"(?ms)^  %s:\n.*?(?=^  [a-z][\w-]*:\s*$|\Z)" % re.escape(job), text)


def place_fetch_steps(text):
    """Insert the artifact download as the FIRST step of every consuming job. Returns (text, n).

    First, not merely present: `report` normalises before it renders, `deps-scan` before it
    uploads, and a step cannot fetch what a step above it already needed. The bootstrap job is
    excluded by construction -- it is the producer.
    """
    begin, end = step_markers(FETCH_STEP_TOKEN)
    n = 0
    for job in FETCH_JOBS:
        m = job_segment(text, job)
        if not m:
            continue
        seg = drop_region(m.group(0), begin, end)
        mm = re.search(r"(?m)^    steps:[ ]*\n", seg)
        if not mm:
            continue
        seg = seg[:mm.end()] + fetch_step() + "\n" + seg[mm.end():]
        text = text[:m.start()] + seg + text[m.end():]
        n += 1
    return (text, n)


def _publishes(step_text):
    """Does this step publish what is on disk? Text-level twin of tests/check_redaction_parity.py
    is_upload(): upload-artifact, upload-sarif, or CodeQL analyze unless it says `upload: never`."""
    # The `uses:` LINE decides, not any mention: a comment explaining an upload is not an upload.
    m = re.search(r"(?m)^[ ]*(?:- )?uses:[ ]*([^\s#]+)", step_text)
    uses = m.group(1) if m else ""
    if "upload-artifact" in uses or "upload-sarif" in uses:
        return True
    if "codeql-action/analyze" in uses:
        return not re.search(r"(?m)^[ ]+upload:[ ]*['\"]?never", step_text)
    return False


def redaction_walk(seg, pad_n):
    """The walk itself, over one step list whose items sit at `pad_n` spaces. -> (text, placed)."""
    begin, end = step_markers(REDACT_STEP_TOKEN)
    seg_clean = drop_region(seg, begin, end)
    parts = re.split(r"(?m)^(?=%s- )" % (" " * pad_n), seg_clean)
    out, tainted, placed = [parts[0]], True, 0
    for part in parts[1:]:
        if _publishes(part):
            if tainted:
                out.append(redact_step(pad_n) + "\n")
                placed += 1
                tainted = False
        else:
            tainted = True
        out.append(part)
    return ("".join(out), placed)


def regenerate_composite(text):
    """The generated regions of one scanner composite. -> (text, counts).

    The composite's steps sit at 4 spaces under `runs: steps:`. The fetch pair goes FIRST, and the
    redaction walk is the job walk at that indent: one rule, two step lists.
    """
    counts = {"fetch": 0, "redact": 0}
    begin, end = step_markers(FETCH_STEP_TOKEN)
    text = drop_region(text, begin, end)
    mm = re.search(r"(?m)^  steps:[ ]*\n", text)
    if not mm:
        raise ValueError("composite has no `runs: steps:` list")
    text = (text[:mm.end()] + fetch_step(4, "the top of .github/workflows/reusable-security.yml")
            + "\n" + text[mm.end():])
    counts["fetch"] = 1
    head, steps = text[:mm.end()], text[mm.end():]
    steps, counts["redact"] = redaction_walk(steps, 4)
    return (head + steps, counts)


def place_redaction_steps(text):
    """Insert the redactor before EVERY upload that follows a step which may have written output.

    ORDER IS THE WHOLE POINT, AND "BEFORE THE FIRST UPLOAD" WAS NOT ENOUGH. Jobs that run two
    scanners redacted once, uploaded the first scanner's report, then RAN THE SECOND SCANNER and
    uploaded its report raw: Trivy IaC after Checkov, flawfinder after cppcheck (N24/WP19). So the
    rule is a walk: a redaction cleans the workspace, an upload keeps it clean, and ANY other step
    taints it again. Every upload over a tainted workspace gets a redaction immediately before it.
    tests/check_redaction_parity.py enforces the same walk on the result.

    Idempotent: every generated block is removed before re-inserting, so re-running cannot stack.
    """
    begin, end = step_markers(REDACT_STEP_TOKEN)
    n = 0
    jobs = [mm.group(1) for mm in
            re.finditer(r"(?m)^  ([a-z][\w-]*):\s*$", text)]
    for job in jobs:
        m = job_segment(text, job)
        if not m:
            continue
        seg = m.group(0)
        new_seg, placed = redaction_walk(seg, 6)
        if new_seg != seg:
            text = text[:m.start()] + new_seg + text[m.end():]
        n += placed
    return (text, n)


def place_status_steps(text):
    """Append the generated Result-summary step to each scanner job. Returns (text, n).

    Inserted at the END of a job, immediately before the next job header. Idempotent: an existing
    generated block is replaced, never stacked, so re-running cannot accumulate copies.
    """
    begin, end = step_markers(STATUS_STEP_TOKEN)
    n = 0
    for job, display, sarif, scope in STATUS_JOBS:
        m = job_segment(text, job)
        if not m:
            continue
        seg = drop_region(m.group(0), begin, end)
        seg_clean = seg.rstrip("\n")
        new_seg = seg_clean + "\n\n" + status_step(job, display, sarif, scope) + "\n\n"
        text = text[:m.start()] + new_seg + text[m.end():]
        n += 1
    return (text, n)


def regenerate(text):
    """Every generated region, re-derived from the canonical sources. Returns (text, counts).

    ONE FUNCTION FOR BOTH HALVES. The write path and the check path used to be different code,
    which is how a generator can pass its own check while emitting something nobody ships.
    """
    counts = {}
    for canon_name, token, tag, dest in SCRIPTS:
        text, n = inject(text, canon_name, token, tag, dest)
        counts[canon_name] = n
    text, counts["fetch"] = place_fetch_steps(text)
    # BEFORE the redaction step is placed, because the manifest must be written while the only
    # steps after the writer are the redactor and the upload -- and `place_pin_step` anchors on
    # the step that ends at the next list item, whichever that turns out to be.
    text, counts["pin"] = place_pin_step(text)
    text, counts["redact"] = place_redaction_steps(text)
    text, counts["status"] = place_status_steps(text)
    return (text, counts)


def import_closure():
    """-> [problem] for every import in a bundled Python script that the bundle cannot satisfy.

    THE BUNDLE IS ALL A CONSUMER'S JOB HAS (completion ledger L61, DECOMP section 1.5). A bundled
    script runs from /tmp in a job that has only the bundle and the runner's Python: an import of a
    kit module that is not in the bundle, or of a third-party package, fails at consumer runtime and
    nowhere else -- every local proof imports from scripts/, where the module sits beside it. This
    is C1's shape (scan_report imported two identity modules the bundle never shipped), and until
    2026-10-21 nothing checked it: the four bundled .py files happened to import only the standard
    library. A closure that holds by coincidence is a closure nobody will notice breaking.

    Allowed: the standard library (sys.stdlib_module_names), `__future__`, and another script in
    this bundle (by module name). Everything else, including a relative import, is refused --
    wherever it sits in the file, because a function-level import fails just as hard when it runs.
    """
    import ast
    bundled = {os.path.splitext(c)[0] for c, _t, _g, _d in SCRIPTS if c.endswith(".py")}
    stdlib = set(getattr(sys, "stdlib_module_names", ())) | {"__future__"}
    problems = []
    if not stdlib - {"__future__"}:
        return ["the standard-library module list is unavailable (Python < 3.10), so the import "
                "closure cannot be established -- UNKNOWN is not a pass"]
    for canon_name, _token, _tag, _dest in SCRIPTS:
        if not canon_name.endswith(".py"):
            continue
        path = os.path.join(ROOT, "scripts", canon_name)
        try:
            tree = ast.parse(io.open(path, encoding="utf-8").read(), filename=canon_name)
        except SyntaxError as e:
            problems.append("%s does not parse (%s)" % (canon_name, e))
            continue
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                names = [a.name for a in node.names]
            elif isinstance(node, ast.ImportFrom):
                if node.level:
                    problems.append("%s:%d relative import -- the bundle is flat files in /tmp"
                                    % (canon_name, node.lineno))
                    continue
                names = [node.module or ""]
            else:
                continue
            for n in names:
                top = n.split(".")[0]
                if top not in stdlib and top not in bundled:
                    problems.append("%s:%d imports `%s`, which is neither the standard library "
                                    "nor a script in this bundle -- it fails at consumer runtime "
                                    "and nowhere a local proof runs" % (canon_name, node.lineno, n))
    return problems


def main(argv):
    check = "--check" in argv
    drift, missing, extra, stale, total = [], [], [], [], 0

    for name in TARGETS:
        p = os.path.join(WF, name)
        raw = io.open(p, "rb").read()
        original = raw.decode("utf-8").replace("\r\n", "\n")
        new, counts = regenerate(original)
        if not check:
            if new != original:
                # The working tree's line endings are kept (CRLF under core.autocrlf on Windows);
                # git stores LF either way.
                nl = "\r\n" if b"\r\n" in raw else "\n"
                io.open(p, "w", encoding="utf-8", newline=nl).write(new)
            for canon_name, token, tag, dest in SCRIPTS:
                print("  %-20s %s: %d block(s) regenerated" % (canon_name, name,
                                                               counts[canon_name]))
            print("  %-20s %s: %d fetch + verify step(s)" % ("kit-scripts artifact", name,
                                                             counts["fetch"]))
            print("  %-20s %s: %d producer pin step(s), manifest %s"
                  % ("kit-scripts digest", name, counts["pin"], manifest_digest()[:16]))
            print("  %-20s %s: %d pre-upload redaction step(s)" % ("redact_sarif.py", name,
                                                                   counts["redact"]))
            print("  %-20s %s: %d per-job status step(s)" % ("scan_status.sh", name,
                                                             counts["status"]))
            print("%s regenerated; re-run with --check to verify" % name)
            continue

        # A REGENERATED FILE THAT DIFFERS FROM THE SHIPPED ONE IS DRIFT, whatever caused it. This
        # covers the generated STEPS as well as the script bodies -- the wrappers are now the
        # repeated thing, and an unchecked repeated thing is how the kit lost 14 gitleaks rules.
        if new != original:
            stale.append(name)

        for canon_name, token, tag, dest in SCRIPTS:
            canon = io.open(os.path.join(ROOT, "scripts", canon_name),
                            encoding="utf-8").read().rstrip("\n")
            copies = extract(original, token, canon_name, tag)
            if not copies:
                # NOT a pass. A drift check that finds nothing to compare and reports success is
                # the vacuous-truth failure: every claim about an empty set is satisfied. This is
                # how a renamed marker, a deleted block or a typo'd heredoc tag would turn the
                # guard off while leaving it green.
                missing.append("%s in %s" % (canon_name, name))
                print("  %-20s %s: NO INLINED BLOCK FOUND" % (canon_name, name))
                continue
            # MORE THAN ONE COPY IS THE DEFECT THAT KILLED THIS WORKFLOW, not a style preference.
            # Thirteen copies of redact_sarif.py were 45% of a 608.8 KB file that GitHub refused
            # to start. One copy, in the bootstrap job, fetched everywhere else.
            if len(copies) > 1:
                extra.append("%s in %s (%d copies)" % (canon_name, name, len(copies)))
            bad = [i + 1 for i, c in enumerate(copies) if c.rstrip("\n") != canon]
            total += len(copies)
            for i in bad:
                drift.append("%s in %s block %d" % (canon_name, name, i))
            print("  %-20s %s: %d inlined copy/copies, %s"
                  % (canon_name, name, len(copies),
                     "DRIFTED" if bad else "identical to canonical"))

    for comp in COMPOSITES:
        p = os.path.join(ACTIONS, comp, "action.yml")
        rel = os.path.relpath(p, ROOT).replace(os.sep, "/")
        if not os.path.isfile(p):
            # A registered composite with no file is a job that fails on the runner.
            missing.append("composite %s" % rel)
            print("  %-20s %s: COMPOSITE MISSING" % (comp, rel))
            continue
        raw = io.open(p, "rb").read()
        original = raw.decode("utf-8").replace("\r\n", "\n")
        new, counts = regenerate_composite(original)
        if not check:
            if new != original:
                nl = "\r\n" if b"\r\n" in raw else "\n"
                io.open(p, "w", encoding="utf-8", newline=nl).write(new)
            print("  %-20s %s: %d fetch + verify, %d pre-upload redaction step(s)"
                  % (comp, rel, counts["fetch"], counts["redact"]))
            continue
        if new != original:
            stale.append(rel)
        for canon_name, token, tag, dest in SCRIPTS:
            if extract(original, token, canon_name, tag):
                extra.append("%s in %s (a composite fetches the bundle; it never inlines it)"
                             % (canon_name, rel))
        print("  %-20s %s: generated steps %s" % (comp, rel,
                                                 "STALE" if new != original else "match"))

    if not check:
        return 0

    closure = import_closure()
    if closure:
        print("::error title=Bundle import closure broken::" + "; ".join(closure) +
              ". The bundle is all a consumer's job has (L61).")
        return 1
    print("bundle import closure: every import in the bundled scripts is the standard library "
          "or another bundled script")

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
    if extra:
        print("::error title=Duplicated inlined script::" + ", ".join(extra) +
              " -- a canonical script is inlined more than once. It belongs in the `%s` job and "
              "nowhere else; every other job fetches the run-scoped artifact. Per-call-site "
              "inlining is what took this file to 608.8 KB, past GitHub's 500 KB limit, after "
              "which it did not fail -- it never started." % BOOTSTRAP_JOB)
        return 1
    if stale:
        print("::error title=Generated regions are stale::" + ", ".join(stale) +
              " differs from what scripts/inline_normalizer.py would emit. The blocks AND the "
              "generated steps around them are generated; re-run the generator rather than "
              "editing the workflow by hand.")
        return 1
    print("inlined scripts: all %d copy/copies match their canonical source, and every "
          "generated step matches the generator" % total)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))

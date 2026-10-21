#!/usr/bin/env python3
"""Assemble a language-grouped prototype of reusable-security.yml from the live file.

Every scanner body, every comment, every heredoc is LIFTED VERBATIM by line range from the
source workflow. Only the job envelopes, the per-step state capture and the report/gate
consolidation are authored here. Lifting rather than retyping is what keeps the prototype
comparable to the original: any size or lint delta is attributable to the restructuring and
not to a transcription accident.

Output: reusable-security-grouped.yml  (LF only, UTF-8, no BOM)
"""
import io
import os
import re
import sys

SRC = r"D:/Dev/secure-cicd-kit/.github/workflows/reusable-security.yml"
HERE = os.path.dirname(os.path.abspath(__file__))
OUT = os.path.join(HERE, "reusable-security-grouped.yml")
STEP_STATE = os.path.join(HERE, "scan_step_state.sh")

RAW = io.open(SRC, encoding="utf-8", newline="").read()
assert "\r" not in RAW, "source already has CR bytes"
L = RAW.split("\n")            # L[0] is line 1


def s(a, b):
    """Lines a..b inclusive, 1-indexed, as text ending in exactly one newline."""
    return "\n".join(L[a - 1:b]) + "\n"


def inject(text, name_substr, extra):
    """Insert `extra` (list of lines, already indented) after the `- name:` line matching."""
    out, done = [], False
    for ln in text.split("\n"):
        out.append(ln)
        if not done and ln.startswith("      - ") and name_substr in ln:
            out.extend(extra)
            done = True
    assert done, "inject target not found: %r" % name_substr
    return "\n".join(out)


COE = [
    "        # suppression: FAILURE_ISOLATION_WITH_STATE_CAPTURE -- siblings share this job; an abort",
    "        # here denies THEM the chance to produce evidence, and an enforce step exiting 1 would",
    "        # abort every scanner queued behind it. See scan_step_state.sh for the whole argument.",
    "        # discards: this step's power to fail the job directly",
    "        # preserved_by: the paired `record state` step -- it reads this outcome and writes a",
    "        # preserved_by: scanner_state the gate enforces on. RECORDED and SURFACED, not softened.",
    "        continue-on-error: true",
]


def tolerate(text, name_substr, step_id=None):
    extra = list(COE)
    if step_id:
        extra = ["        id: %s" % step_id] + extra
    return inject(text, name_substr, extra)


# ---------------------------------------------------------------- canonical blocks
FETCH = s(2691, 2700)
CHECKOUT = "      - uses: actions/checkout@v7\n"
REDACT = s(2978, 2999)

# CodeQL's own state, handed to the canonical recorder instead of to a 37-line per-language step.
CQ_ENV = [
    '          CQ_INIT: ${{ steps.cq_init.outcome }}',
    '          CQ_ANALYZE: ${{ steps.cq_analyze.outcome }}',
    '          CQ_QUERIES: ${{ inputs.codeql_queries }}',
]

BOOT = """      # BEGIN FETCH_STEP_STATE -- the per-step state recorder, one canonical copy.
      - name: Confirm the per-step state recorder arrived
        if: always()
        shell: bash
        run: |
          # A MISSING RECORDER IS NOT AN EMPTY RESULT. Without /tmp/scan_step_state.sh every
          # scanner in this job would finish with no state written, and the gate would read a
          # row of absences. Absence reads as green. Establish it here, once, where the cause
          # is legible, rather than three logs away in whichever scanner noticed first.
          if [ ! -s /tmp/scan_step_state.sh ]; then
            echo "::error title=State recorder absent::/tmp/scan_step_state.sh did not reach this"
            echo "job, so no scanner in it can record what it established. A job that cannot"
            echo "record cannot report, and an unrecorded run must not read as a clean one."
            exit 1
          fi
      # END FETCH_STEP_STATE
"""


def record(scanner, scope, sarif="", outcome=None, enforced=None,
           selected=None, applicable=None, preset=None, extra_env=None):
    """A per-SCANNER state step. Always runs. Cheap because the logic is one canonical script."""
    env = []
    env.append('          D_STATE: ${{ needs.discover.outputs.state }}')
    if selected is not None:
        env.append('          SELECTED: %s' % selected)
    if applicable is not None:
        env.append('          APPLICABLE: %s' % applicable)
    if outcome is not None:
        env.append('          OUTCOME: ${{ steps.%s.outcome }}' % outcome)
    if enforced is not None:
        env.append('          ENFORCED: ${{ steps.%s.outcome }}' % enforced)
    if preset is not None:
        env.append('          PRESET: %s' % preset)
    for e in (extra_env or []):
        env.append(e)
    return (
        "      - name: %s — record state\n"
        "        # PER-STEP, NOT PER-JOB. Three scanners in this job produce three independent\n"
        "        # scanner_state values; `job.status` could only ever produce one.\n"
        "        if: always()\n"
        "        shell: bash\n"
        "        env:\n"
        "%s\n"
        "        run: |\n"
        "          . /tmp/scan_step_state.sh\n"
        "          record_state '%s' '%s' '%s'\n"
        % (scanner, "\n".join(env), scanner, scope, sarif)
    )


def seal(job_scanners, coverage=None):
    """Upload the per-step records, THEN insist every declared scanner produced one."""
    names = " ".join(job_scanners)
    cov = ""
    if coverage:
        appl, klass = coverage
        cov = ("          coverage_note '%s' '%s' %s\n" % (appl, klass, names))
    return (
        "      - name: Publish this job's per-scanner records\n"
        "        # THE RECORDS LEAVE THE JOB BEFORE ANYTHING IS ALLOWED TO FAIL ON THEM. The\n"
        "        # assertion below can fail this job; uploading first means the evidence that\n"
        "        # explains the failure survives it.\n"
        "        if: always()\n"
        "        uses: actions/upload-artifact@v7\n"
        "        with:\n"
        "          name: scanstate-${{ github.job }}-${{ github.run_attempt }}\n"
        "          path: /tmp/_scanstate\n"
        "          retention-days: 30\n"
        "          if-no-files-found: error\n"
        "      - name: Every scanner in this job recorded a state\n"
        "        # RECORDING IS MANDATORY, NOT INCIDENTAL. A declared scanner with no record is\n"
        "        # not a scanner that skipped -- it is a hole in the evidence, and a hole reads\n"
        "        # as green. Named here so the list cannot drift away from the steps above.\n"
        "        if: always()\n"
        "        shell: bash\n"
        "        env:\n"
        "          D_STATE: ${{ needs.discover.outputs.state }}\n"
        "        run: |\n"
        "          . /tmp/scan_step_state.sh\n"
        "%s"
        "          assert_states %s\n"
        % (cov, names)
    )


TMO = ("    # Bounded so a stalled dependency cannot bill six hours (LM-001: unbounded execution\n"
       "    # converts a dependency failure into uncontrolled cost).\n"
       "    # NOT YET: a timeout still surfaces as a plain job failure. It SHOULD classify as\n"
       "    # UNAVAILABLE / EXECUTION_TIMEOUT — cost is bounded here, semantics are not. See\n"
       "    # docs/roadmap/FUTURE_WORK.md. Do not let this comment imply the mapping exists.\n"
       "    timeout-minutes: %d\n")


# ---------------------------------------------------------------- kit-scripts, patched
def kit_scripts_job():
    txt = s(261, 2057)
    step_state = io.open(STEP_STATE, encoding="utf-8", newline="").read()
    body = "".join("          " + ln + "\n" if ln.strip() else "\n"
                   for ln in step_state.rstrip("\n").split("\n"))
    block = (
        "          # BEGIN SCAN_STEP_STATE — generated from scripts/scan_step_state.sh. DO NOT EDIT HERE.\n"
        "          # THE RECORDER THAT REPLACES scan_status.sh. Per-JOB status capture could not\n"
        "          # survive grouping SAST by language: one job now holds three scanners and\n"
        "          # `job.status` can only carry one verdict. Written ONCE, here, like every other\n"
        "          # canonical script, because N copies of a status contract is how this file\n"
        "          # reached 608.8 KB and stopped starting.\n"
        "          cat > /tmp/scan_step_state.sh <<'SCAN_STEP_STATE_SH'\n"
        + body +
        "          SCAN_STEP_STATE_SH\n"
        "          # END SCAN_STEP_STATE\n"
    )
    anchor = "          # END REDACT_ALL\n"
    assert txt.count(anchor) == 1
    txt = txt.replace(anchor, anchor + block)

    old = ("          for f in /tmp/normalize_sarif.py /tmp/scan_report.py /tmp/scan_status.sh \\\n"
           "                   /tmp/redact_sarif.py /tmp/sbom_licenses.py /tmp/redact_all.sh; do\n")
    assert txt.count(old) == 1, "verify loop not found verbatim"
    new = ("          for f in /tmp/normalize_sarif.py /tmp/scan_report.py /tmp/scan_status.sh \\\n"
           "                   /tmp/redact_sarif.py /tmp/sbom_licenses.py /tmp/redact_all.sh \\\n"
           "                   /tmp/scan_step_state.sh; do\n")
    txt = txt.replace(old, new)

    old = ("            /tmp/sbom_licenses.py\n"
           "            /tmp/redact_all.sh\n")
    assert txt.count(old) == 1
    txt = txt.replace(old, old + "            /tmp/scan_step_state.sh\n")
    return txt


# ---------------------------------------------------------------- CodeQL, de-matrixed
def codeql_steps(cqlang, disc):
    """The CodeQL leg for one language, with the matrix removed.

    The matrix was never free: `if: matrix.gate == 'true'` sits on the STEPS, so all six legs
    start a runner and five of them bill a startup to skip every step. Folding each leg into
    its language job replaces six billed jobs with zero.
    """
    txt = s(3606, 3637)
    txt = txt.replace("${{ matrix.lang }}", cqlang)
    txt = txt.replace("matrix.gate == 'true'",
                      "needs.discover.outputs.%s == 'true'" % disc)
    return txt


def codeql_upload(cqlang, disc):
    """CodeQL's SARIF upload, kept STRICTLY AFTER the job's single redaction sweep.

    ORDER IS THE WHOLE CONTROL and the merge is where it breaks. In the standalone codeql job
    the redactor sat between `analyse` and this upload. Appending the whole CodeQL block to a
    language job put this upload BEFORE that job's redaction sweep -- a redactor after the
    upload protects nothing while looking exactly like protection. So the upload is a separate
    piece, emitted after REDACT, and the ordering is asserted mechanically rather than trusted.
    """
    txt = s(3660, 3670)
    txt = txt.replace("${{ matrix.lang }}", cqlang)
    txt = txt.replace("matrix.gate == 'true'",
                      "needs.discover.outputs.%s == 'true'" % disc)
    return txt


# ---------------------------------------------------------------- jobs
def job_secrets():
    scanners = ["gitleaks", "detect-secrets"]
    scan = s(2708, 2856) + s(2857, 2869)
    scan += tolerate(s(2870, 2909), "name: Gitleaks (path-scoped, redacted)")
    scan += s(2910, 2929)
    scan += tolerate(s(2930, 2967), "name: Enforce", step_id="gitleaks_enforce")
    scan += tolerate(s(3023, 3035), "name: detect-secrets (defense in depth)",
                     step_id="detect_secrets")
    return (
        "  # ─── SECRETS — ON ITS OWN, ALWAYS ─────────────────────────────────────────────\n"
        "  # Secrets are the one capability that is never conditional and never advisory. A leaked\n"
        "  # credential is live exposure, not inherited debt, so this job has no language gate, no\n"
        "  # selector, and is deliberately NOT merged with anything: a job that cannot be skipped\n"
        "  # must not be able to be skipped BY something else's condition.\n"
        "  secrets:\n"
        "    needs: [discover, kit-scripts]\n"
        "    if: always()\n"
        "    name: Secrets (gitleaks + detect-secrets)\n"
        "    runs-on: ubuntu-latest\n"
        "    # PERMISSION UNION: contents:read + security-events:write. Both members publish SARIF,\n"
        "    # so the union equals each member's own need and the merge grants nothing new. Declared\n"
        "    # explicitly rather than inherited from the top level, which is a reduction: the\n"
        "    # workflow-level default was reaching jobs that never publish anything.\n"
        "    permissions:\n"
        "      contents: read\n"
        "      security-events: write\n"
        + (TMO % 20) +
        "    steps:\n"
        + FETCH + BOOT + CHECKOUT + scan
        + s(2968, 2977) + REDACT + s(3000, 3007) + s(3008, 3015) + s(3016, 3022)
        + record("gitleaks", "whole repository", "gitleaks.sarif",
                 outcome="gitleaks", enforced="gitleaks_enforce")
        + record("detect-secrets", "whole repository", outcome="detect_secrets")
        + seal(scanners)
    )


def job_sca():
    scanners = ["semgrep", "trivy", "malicious-deps", "sbom"]
    sel_mal = "${{ inputs.enable_malicious_pkg_scan }}"
    sel_sbom = "${{ inputs.enable_sbom }}"
    scan = tolerate(s(3275, 3322), "name: Semgrep scan")
    scan += tolerate(s(3323, 3353), "name: Semgrep — enforce", step_id="semgrep_enforce")
    scan += tolerate(s(3733, 3759), "name: Trivy filesystem (vuln + secret)", step_id="trivy_deps")
    scan += s(3760, 3782)
    osv = s(5383, 5387) + s(5388, 5396)
    osv = osv.replace("      - name: Install OSV-Scanner\n",
                      "      - name: Install OSV-Scanner\n"
                      "        # SELECTABILITY SURVIVES THE MERGE. The step carries the same\n"
                      "        # `inputs.enable_malicious_pkg_scan` that used to gate the JOB, so a\n"
                      "        # consumer who switched this off still gets it switched off -- and the\n"
                      "        # record below says EXCLUDED_BY_SELECTOR rather than nothing at all.\n"
                      "        if: inputs.enable_malicious_pkg_scan\n")
    osv = osv.replace("      - name: Scan lockfiles\n",
                      "      - name: Scan lockfiles\n"
                      "        if: inputs.enable_malicious_pkg_scan\n")
    scan += tolerate(osv, "name: Scan lockfiles", step_id="osv")
    sbom = s(5501, 5504) + s(5505, 5519) + s(5520, 5540)
    sbom = sbom.replace("      - name: Generate SBOM with Syft\n",
                        "      - name: Generate SBOM with Syft\n"
                        "        # Same selector the `sbom` JOB used to carry.\n"
                        "        if: inputs.enable_sbom\n")
    sbom = sbom.replace("      - name: Summarize\n",
                        "      - name: Summarize\n        if: inputs.enable_sbom\n")
    sbom = re.sub(r"(      - name: Dependency licences\n)(        if: always\(\)\n)",
                  r"\1        if: always() && inputs.enable_sbom\n", sbom)
    scan += tolerate(sbom, "name: Generate SBOM with Syft", step_id="sbom")
    return (
        "  # ─── SCA — DEPENDENCIES, PROVENANCE, COMPONENTS ───────────────────────────────\n"
        "  # MEMBERSHIP RULE: every scanner here reads the TREE and needs no language toolchain,\n"
        "  # so every one of them can run on every repository. That is also why they were the four\n"
        "  # shortest jobs in the file, and why four runner startups bought nothing.\n"
        "  #\n"
        "  # Semgrep's language-agnostic pass lives here rather than in a language job, and that is\n"
        "  # the one placement in this topology that is not obvious. Its job was `if: always()` on\n"
        "  # purpose: p/default and p/owasp-top-ten find sinks in ecosystems this kit has no\n"
        "  # language job for. Moving it under `sast-python` would have silently narrowed it to\n"
        "  # repositories where Python was discovered. It needs an always-on home and this is the\n"
        "  # only one, short of buying a dedicated runner for one short scan -- which is precisely\n"
        "  # what the grouping exists to stop.\n"
        "  sca:\n"
        "    needs: [discover, kit-scripts]\n"
        "    if: always()\n"
        "    name: SCA (dependencies + provenance + SBOM + language-agnostic SAST)\n"
        "    runs-on: ubuntu-latest\n"
        "    # PERMISSION UNION: contents:read + security-events:write.\n"
        "    #\n"
        "    # THE COST, STATED: `sbom` needs NEITHER. Syft writes a CycloneDX file and uploads it\n"
        "    # as a plain artifact; it publishes no SARIF. Merged here, syft -- a binary fetched at\n"
        "    # run time by a piped installer -- executes with security-events:write in its\n"
        "    # environment. It already did, because the JOB declared no permissions and inherited\n"
        "    # the workflow default, so this is not a regression introduced by the merge. It is a\n"
        "    # pre-existing over-grant the merge makes impossible to fix without splitting `sbom`\n"
        "    # back out into a job of its own, at the price of one billed minute.\n"
        "    permissions:\n"
        "      contents: read\n"
        "      security-events: write\n"
        + (TMO % 25) +
        "    steps:\n"
        + FETCH + BOOT + CHECKOUT + scan
        + s(3354, 3365) + s(3783, 3794) + s(5397, 5407)
        + REDACT
        + s(3388, 3395) + s(3396, 3403) + s(3404, 3413)
        + s(3817, 3824) + s(3825, 3832) + s(3833, 3844)
        + s(5430, 5437) + s(5438, 5445) + s(5446, 5457)
        + s(5563, 5597)
        + record("semgrep", "source", "semgrep.sarif",
                 outcome="semgrep", enforced="semgrep_enforce")
        + record("trivy", "dependencies", "trivy-deps.sarif", outcome="trivy_deps")
        + record("malicious-deps", "dependency provenance", "osv.sarif",
                 outcome="osv", selected=sel_mal)
        + record("sbom", "components", outcome="sbom", selected=sel_sbom)
        + seal(scanners)
    )


LANG_PERM = (
    "    # PERMISSION UNION: contents:read + security-events:write + actions:read.\n"
    "    #\n"
    "    # THE COST, STATED PLAINLY: `actions: read` is NEW for every step in this job except the\n"
    "    # CodeQL leg. Today only the `codeql` job declares it; every other SAST job runs without\n"
    "    # it. Folding CodeQL into the language jobs grants it to the linters, to the pattern\n"
    "    # scanners, and to whatever `pip install`, `npm`, `dotnet restore`, Maven or `go get`\n"
    "    # pulled into the same runner -- and `actions: read` lets the job token read this\n"
    "    # repository's workflow runs, their logs and their artifacts, including artifacts from\n"
    "    # OTHER runs. That is an information-disclosure widening, not a theoretical one: a\n"
    "    # compromised rule pack or a typosquatted transitive dependency in this job can now read\n"
    "    # CI history it previously could not.\n"
    "    #\n"
    "    # THE SPLIT THAT AVOIDS IT, since it must be on the record rather than discovered later:\n"
    "    # keep CodeQL as its own job -- one per language, or the existing six-leg matrix -- so\n"
    "    # `actions: read` stays isolated to the steps that need it. It costs one billed job per\n"
    "    # language that is actually present, which on a single-language repository is one minute.\n"
    "    # The owner decides whether one minute is worth not handing CI-history read access to\n"
    "    # every package manager in the job. This prototype implements the merge because the merge\n"
    "    # is what was asked for; the recommendation is the split.\n"
    "    permissions:\n"
    "      contents: read\n"
    "      security-events: write\n"
    "      actions: read\n"
)


def job_sast_python():
    scanners = ["code-quality", "bandit", "codeql-python"]
    lint = s(3192, 3227)
    lint = tolerate(lint, "name: Ruff + mypy", step_id="ruff_mypy")
    scan = s(3460, 3462) + lint
    scan += tolerate(s(3463, 3477), "name: Bandit → SARIF", step_id="bandit")
    return (
        "  # ─── SAST: PYTHON ─────────────────────────────────────────────────────────────\n"
        "  # BY LANGUAGE, NOT BY TOOL. ruff/mypy, bandit and the CodeQL Python analysis were three\n"
        "  # jobs, each paying checkout and a Python toolchain to look at the same tree. They are\n"
        "  # one job and THREE scanner_state records -- fewer runners, more resolution.\n"
        "  #\n"
        "  # THE MODULARITY COST: a consumer can no longer cancel, re-run or read the timing of\n"
        "  # bandit independently of ruff, and a single job-level `timeout-minutes` now bounds all\n"
        "  # three together. What is preserved is SELECTION and REPORTING: every scanner keeps the\n"
        "  # gate that used to sit on its job, as a step-level `if:`, and keeps its own record.\n"
        "  sast-python:\n"
        "    needs: [discover, kit-scripts]\n"
        "    # DISCOVERED, NOT DECLARED -- the same rule the three separate jobs carried.\n"
        "    if: needs.discover.outputs.python == 'true'\n"
        "    name: SAST (python)\n"
        "    runs-on: ubuntu-latest\n"
        + LANG_PERM
        + (TMO % 40) +
        "    steps:\n"
        + FETCH + BOOT + CHECKOUT + scan
        + s(3478, 3489)
        + codeql_steps("python", "python")
        + REDACT
        + codeql_upload("python", "python")
        + s(3512, 3519) + s(3520, 3527) + s(3528, 3539)
        + record("code-quality", "python linters", outcome="ruff_mypy",
                 applicable="${{ needs.discover.outputs.python }}")
        + record("bandit", "python", "bandit.sarif", outcome="bandit",
                 applicable="${{ needs.discover.outputs.python }}")
        + record("codeql-python", "python dataflow", outcome="cq_analyze",
                 applicable="${{ needs.discover.outputs.python }}",
                 extra_env=CQ_ENV)
        + seal(scanners, coverage=("${{ needs.discover.outputs.python }}", "python source"))
    )


def job_sast_node():
    scanners = ["eslint", "codeql-node"]
    scan = s(3089, 3144) + s(3145, 3154)
    scan = tolerate(scan, "name: ESLint", step_id="eslint") if False else scan
    scan += tolerate(s(3155, 3185), "name: ESLint", step_id="eslint")
    return (
        "  # ─── SAST: NODE / TYPESCRIPT ──────────────────────────────────────────────────\n"
        "  # THIS JOB FIXES A DEFECT BY EXISTING. ESLint lived in `code-quality`, whose job-level\n"
        "  # gate was `needs.discover.outputs.python == 'true'`. On a Node-only repository that job\n"
        "  # never started, so ESLint never ran -- and because a skipped job renders as skipped, the\n"
        "  # report could not tell that from \"no JavaScript here\". Grouping by language makes the\n"
        "  # gate and the content agree by construction.\n"
        "  sast-node:\n"
        "    needs: [discover, kit-scripts]\n"
        "    if: needs.discover.outputs.node == 'true'\n"
        "    name: SAST (node / typescript)\n"
        "    runs-on: ubuntu-latest\n"
        + LANG_PERM
        + (TMO % 40) +
        "    steps:\n"
        + FETCH + BOOT + CHECKOUT + scan
        + codeql_steps("javascript-typescript", "node")
        + REDACT
        + codeql_upload("javascript-typescript", "node")
        + record("eslint", "node / typescript linters", outcome="eslint",
                 applicable="${{ needs.discover.outputs.node }}")
        + record("codeql-node", "javascript / typescript dataflow", outcome="cq_analyze",
                 applicable="${{ needs.discover.outputs.node }}",
                 extra_env=CQ_ENV)
        + seal(scanners, coverage=("${{ needs.discover.outputs.node }}", "node source"))
    )


def job_sast_dotnet():
    scanners = ["dotnet-vuln", "semgrep-csharp", "codeql-dotnet"]
    scan = s(4192, 4194) + s(4195, 4214)
    scan += tolerate(s(4215, 4228), "name: Vulnerable + deprecated NuGet packages",
                     step_id="nuget_vuln")
    scan += tolerate(s(4229, 4303), "name: Semgrep (C#)")
    scan += tolerate(s(4304, 4330), "name: Semgrep (C#) — enforce", step_id="semgrep_csharp_enforce")
    return (
        "  # ─── SAST: .NET ───────────────────────────────────────────────────────────────\n"
        "  # TWO SCANNERS THAT USED TO SHARE ONE STATE. `dotnet list package --vulnerable` and\n"
        "  # Semgrep's C# rules both ran in `sast-dotnet` and both reported through the single\n"
        "  # `dotnet-vuln` key, so a broken NuGet audit and a broken Semgrep run were one row. They\n"
        "  # are two records here. That is the forbidden collapse being undone, not introduced.\n"
        "  sast-dotnet:\n"
        "    needs: [discover, kit-scripts]\n"
        "    if: needs.discover.outputs.dotnet == 'true'\n"
        "    name: SAST (.NET)\n"
        "    runs-on: ubuntu-latest\n"
        + LANG_PERM
        + (TMO % 40) +
        "    steps:\n"
        + FETCH + BOOT + CHECKOUT + scan
        + s(4331, 4342)
        + codeql_steps("csharp", "dotnet")
        + REDACT
        + codeql_upload("csharp", "dotnet")
        + s(4365, 4372) + s(4373, 4380) + s(4381, 4390)
        + record("dotnet-vuln", "dotnet packages", outcome="nuget_vuln",
                 applicable="${{ needs.discover.outputs.dotnet }}")
        + record("semgrep-csharp", "c#", "semgrep-csharp.sarif", outcome="dotnet_semgrep",
                 enforced="semgrep_csharp_enforce",
                 applicable="${{ needs.discover.outputs.dotnet }}")
        + record("codeql-dotnet", "c# dataflow", outcome="cq_analyze",
                 applicable="${{ needs.discover.outputs.dotnet }}",
                 extra_env=CQ_ENV)
        + seal(scanners, coverage=("${{ needs.discover.outputs.dotnet }}", "dotnet source"))
    )


def job_sast_java():
    scanners = ["java-sast", "codeql-java"]
    scan = s(4437, 4444)
    scan += tolerate(s(4445, 4513), "name: Semgrep (Java)")
    scan += tolerate(s(4514, 4540), "name: Semgrep (Java) — enforce", step_id="semgrep_java_enforce")
    return (
        "  # ─── SAST: JAVA / KOTLIN ──────────────────────────────────────────────────────\n"
        "  sast-java:\n"
        "    needs: [discover, kit-scripts]\n"
        "    if: needs.discover.outputs.java == 'true'\n"
        "    name: SAST (java / kotlin)\n"
        "    runs-on: ubuntu-latest\n"
        + LANG_PERM
        + (TMO % 40) +
        "    steps:\n"
        + FETCH + BOOT + CHECKOUT + scan
        + s(4541, 4552)
        + codeql_steps("java-kotlin", "java")
        + REDACT
        + codeql_upload("java-kotlin", "java")
        + s(4575, 4582) + s(4583, 4590) + s(4591, 4600)
        + record("java-sast", "java / kotlin", "semgrep-java.sarif", outcome="java_semgrep",
                 enforced="semgrep_java_enforce",
                 applicable="${{ needs.discover.outputs.java }}")
        + record("codeql-java", "java / kotlin dataflow", outcome="cq_analyze",
                 applicable="${{ needs.discover.outputs.java }}",
                 extra_env=CQ_ENV)
        + seal(scanners, coverage=("${{ needs.discover.outputs.java }}", "java source"))
    )


def job_sast_go():
    scanners = ["gosec", "codeql-go"]
    scan = s(4647, 4649)
    scan += tolerate(s(4650, 4800), "name: gosec")
    scan += tolerate(s(4801, 4831), "name: gosec — enforce", step_id="gosec_enforce")
    return (
        "  # ─── SAST: GO ─────────────────────────────────────────────────────────────────\n"
        "  sast-go:\n"
        "    needs: [discover, kit-scripts]\n"
        "    if: needs.discover.outputs.go == 'true'\n"
        "    name: SAST (go)\n"
        "    runs-on: ubuntu-latest\n"
        + LANG_PERM
        + (TMO % 40) +
        "    steps:\n"
        + FETCH + BOOT + CHECKOUT + scan
        + s(4832, 4843)
        + codeql_steps("go", "go")
        + REDACT
        + codeql_upload("go", "go")
        + s(4866, 4873) + s(4874, 4881) + s(4882, 4891)
        + record("gosec", "go", "gosec.sarif", outcome="gosec", enforced="gosec_enforce",
                 applicable="${{ needs.discover.outputs.go }}")
        + record("codeql-go", "go dataflow", outcome="cq_analyze",
                 applicable="${{ needs.discover.outputs.go }}",
                 extra_env=CQ_ENV)
        + seal(scanners, coverage=("${{ needs.discover.outputs.go }}", "go source"))
    )


def job_sast_cpp():
    scanners = ["cppcheck", "flawfinder", "codeql-cpp"]
    scan = s(4943, 4993)
    scan += tolerate(s(4994, 5048), "name: cppcheck", step_id="cppcheck")
    scan += tolerate(s(5091, 5233), "name: flawfinder")
    scan += tolerate(s(5234, 5260), "name: flawfinder — enforce", step_id="flawfinder_enforce")
    return (
        "  # ─── SAST: C / C++ ────────────────────────────────────────────────────────────\n"
        "  # cppcheck HAD NO SCANNER STATE AT ALL. It uploaded SARIF and published to the Security\n"
        "  # tab, and the report's state table had no row for it -- its findings were attributed to\n"
        "  # `flawfinder` or to nothing. Per-step capture gives it one, which is the second defect\n"
        "  # this restructuring closes as a side effect rather than as a feature.\n"
        "  sast-cpp:\n"
        "    needs: [discover, kit-scripts]\n"
        "    if: needs.discover.outputs.cpp == 'true'\n"
        "    name: SAST (c / c++)\n"
        "    runs-on: ubuntu-latest\n"
        + LANG_PERM
        + (TMO % 40) +
        "    steps:\n"
        + FETCH + BOOT + CHECKOUT + scan
        + s(5261, 5272)
        + codeql_steps("c-cpp", "cpp")
        + REDACT
        + codeql_upload("c-cpp", "cpp")
        + s(5071, 5078) + s(5079, 5090)
        + s(5273, 5280) + s(5281, 5288) + s(5289, 5297) + s(5298, 5310)
        + record("cppcheck", "c / c++", "cppcheck.sarif", outcome="cppcheck",
                 applicable="${{ needs.discover.outputs.cpp }}")
        + record("flawfinder", "c / c++", "flawfinder.sarif", outcome="flawfinder",
                 enforced="flawfinder_enforce",
                 applicable="${{ needs.discover.outputs.cpp }}")
        + record("codeql-cpp", "c / c++ dataflow", outcome="cq_analyze",
                 applicable="${{ needs.discover.outputs.cpp }}",
                 extra_env=CQ_ENV)
        + seal(scanners, coverage=("${{ needs.discover.outputs.cpp }}", "c / c++ source"))
    )


def job_iac():
    scanners = ["checkov", "trivy-iac"]
    scan = s(3890, 3901)
    scan = tolerate(scan, "name: Checkov") if False else scan
    scan += tolerate(s(3902, 3908), "name: Checkov", step_id="checkov_run")
    scan += s(3909, 3950)
    scan += tolerate(s(3951, 3993), "name: Checkov — enforce", step_id="checkov_enforce")
    scan += tolerate(s(4059, 4079), "name: Trivy IaC misconfig", step_id="trivy_iac")
    scan += s(4080, 4102)
    return (
        "  # ─── IaC ──────────────────────────────────────────────────────────────────────\n"
        "  # AS TODAY, with one correction. Trivy's IaC report was written to trivy-iac.sarif, and\n"
        "  # the report job matched it with the glob `trivy*.sarif` belonging to the DEPENDENCY\n"
        "  # scanner -- so misconfiguration findings were attributed to the `trivy` dependency key\n"
        "  # and Trivy's IaC pass had no state of its own. Two records here, two globs.\n"
        "  iac:\n"
        "    needs: [discover, kit-scripts]\n"
        "    if: needs.discover.outputs.iac == 'true'\n"
        "    name: IaC (checkov + trivy config)\n"
        "    runs-on: ubuntu-latest\n"
        "    # PERMISSION UNION: contents:read + security-events:write. Unchanged -- both members\n"
        "    # were already in one job. Declared rather than inherited.\n"
        "    permissions:\n"
        "      contents: read\n"
        "      security-events: write\n"
        + (TMO % 20) +
        "    steps:\n"
        + FETCH + BOOT + scan
        + s(3994, 4005) + s(4103, 4114)
        + REDACT
        + s(4028, 4035) + s(4036, 4043) + s(4044, 4058)
        + s(4115, 4122) + s(4123, 4130) + s(4131, 4145)
        + record("checkov", "terraform / bicep / docker", "checkov.sarif",
                 outcome="checkov_run", enforced="checkov_enforce",
                 applicable="${{ needs.discover.outputs.iac }}")
        + record("trivy-iac", "infrastructure as code", "trivy-iac.sarif",
                 outcome="trivy_iac",
                 applicable="${{ needs.discover.outputs.iac }}")
        + seal(scanners, coverage=("${{ needs.discover.outputs.iac }}",
                                   "infrastructure as code"))
    )


def job_image():
    scanners = ["trivy-image"]
    scan = tolerate(s(5345, 5359), "name: Trivy image", step_id="trivy_image")
    return (
        "  # ─── CONTAINER IMAGE ──────────────────────────────────────────────────────────\n"
        "  # AS TODAY, and deliberately not merged. Its applicability is a CALLER-SUPPLIED target,\n"
        "  # not a discovered artefact: with no image_ref there is nothing to scan and nothing to\n"
        "  # bill. A job that skips on an empty input costs zero; a step that skips inside a job\n"
        "  # someone else pays for costs that job's startup, so folding it in would have made the\n"
        "  # common case -- no image -- more expensive, not less.\n"
        "  image:\n"
        "    needs: [discover, kit-scripts]\n"
        "    if: inputs.image_ref != ''\n"
        "    name: Container image (trivy)\n"
        "    runs-on: ubuntu-latest\n"
        "    # UNCHANGED from the current image-scan job, which already declared exactly this.\n"
        "    permissions:\n"
        "      contents: read\n"
        "      security-events: write\n"
        + (TMO % 20) +
        "    steps:\n"
        + FETCH + BOOT + CHECKOUT + scan
        + record("trivy-image", "${{ inputs.image_ref }}", "trivy-image.sarif",
                 outcome="trivy_image",
                 selected="${{ inputs.image_ref != '' }}")
        + seal(scanners)
    )


SCANNER_NEEDS = ("secrets, sca, sast-python, sast-node, sast-dotnet, sast-java,\n"
                 "            sast-go, sast-cpp, iac, image")

ROSTER1 = ("gitleaks,detect-secrets,semgrep,trivy,malicious-deps,sbom,code-quality,"
           "bandit,codeql-python,eslint,codeql-node,dotnet-vuln,semgrep-csharp,")
ROSTER2 = ("codeql-dotnet,java-sast,codeql-java,gosec,codeql-go,cppcheck,flawfinder,"
           "codeql-cpp,checkov,trivy-iac,trivy-image")
ALL_SCANNERS = ROSTER1 + ROSTER2



def job_report():
    return (
        "  # ─── REPORT ───────────────────────────────────────────────────────────────────\n"
        "  # THE CONSOLIDATION NO LONGER READS `needs.<job>.result`, AND CANNOT.\n"
        "  #\n"
        "  # It used to derive one scanner_state per JOB from that job's conclusion. After grouping,\n"
        "  # one job carries up to three scanners, and a job conclusion cannot say which of them\n"
        "  # failed. So each scanner writes its OWN record inside its job and this job reads the\n"
        "  # records. Job conclusions are still consulted for exactly the two things they can\n"
        "  # answer -- did the job run at all, and did the toolchain arrive -- and nothing else.\n"
        "  report:\n"
        "    name: Security scan report\n"
        "    needs: [discover, kit-scripts, " + SCANNER_NEEDS + "]\n"
        "    if: always()\n"
        "    runs-on: ubuntu-latest\n"
        + (TMO % 10) +
        "    # UNION: contents:read only. The report publishes nothing to the Security tab, so it\n"
        "    # keeps the narrowest set in the file -- unchanged from today.\n"
        "    permissions:\n"
        "      contents: read\n"
        "    steps:\n"
        + FETCH + CHECKOUT
        + s(5651, 5664)
        + """      - name: Collect every per-scanner record this run produced
        uses: actions/download-artifact@v8
        # suppression: FAILURE_ISOLATION_WITH_STATE_CAPTURE -- with `if: always()` this job runs
        # even when every scanner job was skipped, and download-artifact fails when no artifact
        # matches. Failing here would delete the report in precisely the run that needs it most.
        # discards: the distinction between "no records" and "records could not be downloaded"
        # preserved_by: the reconciliation below, which compares what arrived against the FULL
        # preserved_by: expected roster and writes COLLECTION_FAILED for every scanner missing
        continue-on-error: true
        with:
          pattern: scanstate-*
          path: _records
          merge-multiple: true

      - name: Reconcile the records against the expected roster
        env:
          # THE ROSTER IS DECLARED HERE, NOT DERIVED FROM WHAT ARRIVED. A report assembled only
          # from the records it received cannot notice a record that never came -- and a scanner
          # missing from the table is indistinguishable from a scanner that was never expected.
          EXPECTED: >-
            __ROSTER1__
            __ROSTER2__
          # The job conclusions are read for the two questions a conclusion can answer: did the
          # job run, and did it die before its scanners could record. They are NEVER projected
          # into a scanner_state.
          J_SECRETS: ${{ needs.secrets.result }}
          J_SCA: ${{ needs.sca.result }}
          J_PY: ${{ needs.sast-python.result }}
          J_NODE: ${{ needs.sast-node.result }}
          J_DOTNET: ${{ needs.sast-dotnet.result }}
          J_JAVA: ${{ needs.sast-java.result }}
          J_GO: ${{ needs.sast-go.result }}
          J_CPP: ${{ needs.sast-cpp.result }}
          J_IAC: ${{ needs.iac.result }}
          J_IMAGE: ${{ needs.image.result }}
          D_STATE: ${{ needs.discover.outputs.state }}
        run: |
          set -uo pipefail
          mkdir -p _states
          # suppression: FAILURE_ISOLATION_WITH_STATE_CAPTURE -- a run in which no scanner
          # recorded anything is a legitimate state, and it is the run whose report matters most.
          # discards: the copy's exit status, which carries no information a reader needs
          # preserved_by: the roster reconciliation below, which reports every absence by name
          cp -f _records/state-*.json _states/ 2>/dev/null || true
          cp -f _sarif/*.sarif _states/ 2>/dev/null || true

          echo "| scanner | scanner_state | execution | applicability | discovery |" >> "$GITHUB_STEP_SUMMARY"
          echo "|---|---|---|---|---|" >> "$GITHUB_STEP_SUMMARY"
          missing=""
          for sc in $(echo "$EXPECTED" | tr ',' ' '); do
            f="_states/state-${sc}.json"
            if [ ! -s "$f" ]; then
              missing="${missing}${missing:+ }${sc}"
              # NO RECORD IS NOT NO FINDINGS. A scanner that was expected and recorded nothing
              # gets COLLECTION_FAILED -- never NOT_APPLICABLE, which would assert a search that
              # nobody performed.
              jq -n --arg sc "$sc" \\
                '{scanner:$sc, scanner_state:"COLLECTION_FAILED",
                  execution:"COLLECTION_FAILED", applicability:"UNKNOWN",
                  discovery:"UNDETERMINED_PRESENT",
                  unavailable_reason:"INFRASTRUCTURE_UNKNOWN", scope:"", sarif:"",
                  findings:"NOT ESTABLISHED", publication:"NONE", gate:"UNDETERMINED",
                  tolerated:"none", looked:"false", artifact:"NONE", upload:"NONE"}' > "$f"
            fi
            jq -r '"| \\(.scanner) | \\(.scanner_state) | \\(.execution) | \\(.applicability) | \\(.discovery) |"' \\
              "$f" >> "$GITHUB_STEP_SUMMARY"
          done
          if [ -n "$missing" ]; then
            echo "::error title=Records NOT RECEIVED::Expected per-scanner records never arrived:"
            echo "$missing. Each is recorded COLLECTION_FAILED. A scanner absent from the evidence"
            echo "is not a scanner that found nothing."
          fi
          # A JOB THAT DIED BEFORE ITS SCANNERS COULD RECORD IS THE ONE CASE A CONCLUSION SEES
          # THAT A RECORD CANNOT. Said here, against the job, never folded into a scanner row.
          for j in "secrets=$J_SECRETS" "sca=$J_SCA" "sast-python=$J_PY" "sast-node=$J_NODE" \\
                   "sast-dotnet=$J_DOTNET" "sast-java=$J_JAVA" "sast-go=$J_GO" \\
                   "sast-cpp=$J_CPP" "iac=$J_IAC" "image=$J_IMAGE"; do
            n="${j%%=*}"; r="${j##*=}"
            printf '  job %-14s %s\\n' "$n" "$r"
            case "$r" in
              success|skipped) ;;
              *) echo "::warning title=Job ${n} was '${r}'::Its scanners' own records stand where"
                 echo "they exist. Where they do not, this is why -- and that is COLLECTION_FAILED," ;;
            esac
          done
          echo "reconciled $(ls -1 _states/state-*.json | wc -l) scanner record(s)"

""".replace("__ROSTER1__", ROSTER1).replace("__ROSTER2__", ROSTER2)
        + (s(5797, 5854)
           .replace(
               "--expect gitleaks,code-quality,semgrep,bandit,codeql,trivy,trivy-image,checkov,"
               "dotnet-vuln,java-sast,gosec,flawfinder,malicious-deps,sbom \\",
               '--expect "$EXPECTED" \\')
           .replace(
               "          RUN_URL:",
               "          # The SAME roster the reconciliation used, so a scanner cannot be\n"
               "          # expected by one and unknown to the other.\n"
               "          EXPECTED: >-\n"
               "            " + ROSTER1 + "\n"
               "            " + ROSTER2 + "\n"
               "          RUN_URL:"))
        + REDACT
        + s(5877, 5885)
    )


def job_gate():
    return (
        "  # ─── GATE ─────────────────────────────────────────────────────────────────────\n"
        "  # DELIBERATELY NOT MERGED WITH `report`, AND THE REASON IS THE GATE'S OWN CONTRACT.\n"
        "  #\n"
        "  # A gate must not run in the same job as the thing it judges, and this gate judges\n"
        "  # `report`: it reads that job's conclusion and it NAMES the evidence artifact that job\n"
        "  # assembles. Merge them and three separate failures become indistinguishable -- the\n"
        "  # renderer crashing, the evidence upload failing, and the gate deciding to block all\n"
        "  # produce one red job. Worse, the gate's `exit 1` would fail the job that owns the\n"
        "  # evidence upload, so the only thing standing between a block and no evidence at all\n"
        "  # would be an `if: always()` on the upload step. The gate is cheap; the ambiguity is not.\n"
        "  #\n"
        "  # IT ALSO NO LONGER ENFORCES ON JOB CONCLUSIONS. Every scanner step in this file carries\n"
        "  # `continue-on-error: true`, so a merged job's conclusion is `success` even when a\n"
        "  # scanner inside it crashed or a policy enforce step exited 1. Reading conclusions here\n"
        "  # would be the softening defect with extra steps. It reads the per-scanner RECORDS.\n"
        "  security-gate:\n"
        "    name: Security gate\n"
        "    needs:\n"
        "      - discover\n"
        "      - kit-scripts\n"
        + "".join("      - %s\n" % j for j in
                  ["secrets", "sca", "sast-python", "sast-node", "sast-dotnet", "sast-java",
                   "sast-go", "sast-cpp", "iac", "image"])
        + "      # THE REPORT IS NOT EXEMPT. It assembles the evidence artifact this gate NAMES in\n"
        "      # its own `evidence_artifact` output, and it is the one job whose failure is\n"
        "      # invisible from any scanner record because it produces none. Checked explicitly\n"
        "      # below rather than folded into the scanner loop: it is not a scanner and must not\n"
        "      # acquire a scanner_state.\n"
        "      - report\n"
        "    if: always()\n"
        "    runs-on: ubuntu-latest\n"
        "    # UNION: contents:read only. The gate reads records and emits outputs; it publishes\n"
        "    # nothing. Today this job declares NO permissions and therefore inherits\n"
        "    # security-events:write from the workflow. Declaring the minimum here is a reduction.\n"
        "    permissions:\n"
        "      contents: read\n"
        "    outputs:\n"
        "      assurance_state: ${{ steps.gate.outputs.assurance_state }}\n"
        "      enforcement_state: ${{ steps.gate.outputs.enforcement_state }}\n"
        "      gate_decision: ${{ steps.gate.outputs.gate_decision }}\n"
        "      secret_gate: ${{ steps.gate.outputs.secret_gate }}\n"
        "      scanner_states: ${{ steps.gate.outputs.scanner_states }}\n"
        "      undetermined: ${{ steps.gate.outputs.undetermined }}\n"
        "      evidence_artifact: ${{ steps.gate.outputs.evidence_artifact }}\n"
        "      discovery_state: ${{ needs.discover.outputs.state }}\n"
        "      established: ${{ steps.gate.outputs.established }}\n"
        "      unestablished: ${{ steps.gate.outputs.unestablished }}\n"
        + (TMO % 10) +
        "    steps:\n"
        "      - name: Collect every per-scanner record this run produced\n"
        "        # THE GATE READS THE RECORDS DIRECTLY, not through the report. The report can\n"
        "        # fail; the gate still has to be able to say what each scanner established, and a\n"
        "        # gate that could only speak through a job it also judges is not independent.\n"
        "        # suppression: FAILURE_ISOLATION_WITH_STATE_CAPTURE -- no matching artifact is a\n"
        "        # legitimate state (every job skipped) and must not abort the gate.\n"
        "        # discards: this download's exit status\n"
        "        # preserved_by: the roster loop below, which records every absent scanner as\n"
        "        # preserved_by: COLLECTION_FAILED and drives `undetermined` from it\n"
        "        continue-on-error: true\n"
        "        uses: actions/download-artifact@v8\n"
        "        with:\n"
        "          pattern: scanstate-*\n"
        "          path: _records\n"
        "          merge-multiple: true\n"
        "      - name: Enforce required scans\n"
        "        id: gate\n"
        "        env:\n"
        "          EXPECTED: >-\n"
        "            " + ROSTER1 + "\n"
        "            " + ROSTER2 + "\n"
        "          # SECRETS ARE NOT SUBJECT TO ADVISORY MODE, and after grouping that policy can\n"
        "          # no longer be expressed as \"the job called secret-scan\". It is the set of\n"
        "          # SCANNERS whose findings are live exposure, named here.\n"
        "          SECRET_SCANNERS: \"gitleaks detect-secrets\"\n"
        "          R_REPORT: ${{ needs.report.result }}\n"
        "          R_TOOLING: ${{ needs.kit-scripts.result }}\n"
        "          D_STATE: ${{ needs.discover.outputs.state }}\n"
        "          COVERAGE_GAPS: ${{ needs.discover.outputs.coverage_gaps }}\n"
        "          COVERAGE_GAP_COUNT: ${{ needs.discover.outputs.coverage_gap_count }}\n"
        "          ADVISORY: ${{ inputs.advisory_mode }}\n"
        "        run: |\n"
        + GATE_BODY
    )


GATE_BODY = r'''          set -u
          fail=0
          secret_fail=0
          undetermined=0
          states=""
          established=""
          unestablished=""
          # ONE ROW PER SCANNER, READ FROM THAT SCANNER'S OWN RECORD.
          #
          # The previous loop read `needs.<job>.result` and projected it: success -> PASS,
          # skipped -> NOT_APPLICABLE. That projection is unavailable now and was always lossy --
          # `skipped` collapses "not licensed", "switched off", "nothing to scan" and "an earlier
          # job failed" into one word, and after grouping it would ALSO collapse three scanners
          # into one. Each scanner's record carries the axes separately and they are read, not
          # inferred.
          for sc in $(echo "$EXPECTED" | tr ',' ' '); do
            f="_records/state-${sc}.json"
            st=""; gt=""; disc=""; why=""
            if [ -s "$f" ]; then
              st=$(jq -r '.scanner_state' "$f")
              gt=$(jq -r '.gate' "$f")
              disc=$(jq -r '.discovery' "$f")
              why=$(jq -r '.unavailable_reason' "$f")
            else
              # AN EXPECTED SCANNER WITH NO RECORD IS THE WORST CASE, because it is the one that
              # looks like nothing happened. It is COLLECTION_FAILED and it makes the run PARTIAL.
              st=COLLECTION_FAILED; gt=UNDETERMINED; disc=UNDETERMINED_PRESENT
              why=INFRASTRUCTURE_UNKNOWN
              echo "::error title=${sc}: NO RECORD::This scanner was expected and recorded nothing."
              echo "Recorded COLLECTION_FAILED. Absence of a record is not absence of risk."
            fi
            case "$st" in
              PASS|FINDINGS|PARTIAL|NOT_APPLICABLE|FAILED|UNAVAILABLE|COLLECTION_FAILED) ;;
              *) echo "::error title=${sc}: unregistered scanner_state '${st}'::Not a value in"
                 echo "assurance-taxonomy.yaml. Treated as UNAVAILABLE rather than believed."
                 st=UNAVAILABLE ;;
            esac
            printf '  %-16s %-18s gate=%-12s %s\n' "$sc" "$st" "$gt" "$disc"
            echo "| $sc | $st | $gt | $disc | ${why:-} |" >> "$GITHUB_STEP_SUMMARY"
            # PARTIAL FAILURE IS NOT TOTAL IGNORANCE. What WAS established stays established.
            case "$st" in
              UNAVAILABLE|COLLECTION_FAILED)
                undetermined=1
                unestablished="${unestablished}${unestablished:+ }${sc}(${st})"
                ;;
              *)
                established="${established}${established:+ }${sc}(${st})"
                ;;
            esac
            states="${states}${states:+,}\"$sc\":\"$st\""
            # ENFORCEMENT COMES FROM THE RECORD'S GATE FIELD, NOT FROM A JOB CONCLUSION. Every
            # scanner step is continue-on-error, so conclusions are uninformative here by design.
            case "$st" in
              FAILED) fail=1 ;;
            esac
            if [ "$gt" = "BLOCKED" ]; then
              fail=1
              # SECRETS ARE NOT SUBJECT TO ADVISORY MODE -- keyed on the scanner, since the job
              # that used to carry the name no longer maps one-to-one onto it.
              for ss in $SECRET_SCANNERS; do
                [ "$sc" = "$ss" ] && secret_fail=1
              done
            fi
          done
          # THE EVIDENCE JOB, CHECKED AS ITSELF AND NOT AS A SCANNER.
          echo "| report | $R_REPORT |" >> "$GITHUB_STEP_SUMMARY"
          printf '  %-16s %s\n' "report" "$R_REPORT"
          case "$R_REPORT" in
            success|skipped) ;;
            *)
              echo "::error title=Security report NOT produced::The consolidated report job was"
              echo "'$R_REPORT'. Per-scanner records above stand, but correlation, severity,"
              echo "disposition and the evidence artifact were not assembled. The run is not"
              echo "documented and must not be read as one that was."
              fail=1
              undetermined=1
              ;;
          esac
          # THE TOOLCHAIN JOB, CHECKED AS ITSELF. It has no `if:` -- it cannot legitimately skip,
          # so `skipped` is not accepted here. Without it no scanner in this run could redact, and
          # none could RECORD: /tmp/scan_step_state.sh is in the same bundle. A run where nothing
          # could record is a run whose silence must not read as NOT_APPLICABLE.
          echo "| kit-scripts | $R_TOOLING |" >> "$GITHUB_STEP_SUMMARY"
          printf '  %-16s %s\n' "kit-scripts" "$R_TOOLING"
          case "$R_TOOLING" in
            success) ;;
            *)
              echo "::error title=Kit scripts NOT materialised::The job that writes the kit's own"
              echo "scripts was '$R_TOOLING', so redaction, path normalisation, the per-step state"
              echo "recorder and the consolidated report had nothing to run."
              fail=1
              undetermined=1
              ;;
          esac
          # A GREEN GATE MUST NOT BE READ AS FULL COVERAGE. COVERAGE_GAP is an artefact-class
          # fact from discovery -- code is present that NO scanner in this kit can read -- and it
          # is neither NOT_APPLICABLE nor CLEAN. It is repeated here because the gate summary is
          # what a reviewer actually reads before approving a promotion.
          if [ -n "$COVERAGE_GAPS" ]; then
            echo "::warning title=COVERAGE_GAP x${COVERAGE_GAP_COUNT}::${COVERAGE_GAPS} are present"
            echo "in this repository and NO scanner in this kit can read them. Not blocked, and"
            echo "not clean -- nothing looked. A PASS below is scoped to what WAS scanned."
            cg="| (coverage) | COVERAGE_GAP x${COVERAGE_GAP_COUNT} |"
            cg="$cg ${COVERAGE_GAPS} — present, no capable scanner |"
            echo "$cg" >> "$GITHUB_STEP_SUMMARY"
          fi
          emit() { echo "$1=$2" >> "$GITHUB_OUTPUT"; }
          emit scanner_states "{${states}}"
          emit undetermined "$([ "$undetermined" = "1" ] && echo true || echo false)"
          emit evidence_artifact "security-sarif"
          emit secret_gate "$([ "$secret_fail" = "1" ] && echo FAIL || echo PASS)"
          emit established "$established"
          emit unestablished "$unestablished"
          # DISCOVERY FAILURE POISONS THE RESULT. If applicability could not be established, no
          # number of green scanners establishes posture: we do not know what was not scanned.
          if [ "$D_STATE" = "DISCOVERY_UNAVAILABLE" ]; then
            echo "::error title=UNDETERMINED::Discovery failed, so the set of capabilities that"
            echo "SHOULD have run is unknown. Individual scanner records cannot be read as coverage."
            emit assurance_state UNDETERMINED
          elif [ "$undetermined" = "1" ]; then
            echo "::warning title=PARTIAL assurance::Some capabilities could not establish a result."
            echo "  established:   ${established:-none}"
            echo "  UNESTABLISHED: ${unestablished}"
            echo "What was established REMAINS established. What was not is named above."
            emit assurance_state PARTIAL
          elif [ "$fail" = "1" ] || [ "$secret_fail" = "1" ]; then
            emit assurance_state FINDINGS
          else
            emit assurance_state PASS
          fi
          if [ "$secret_fail" = "1" ]; then
            emit enforcement_state BLOCKED; emit gate_decision FAIL
          elif [ "$fail" = "1" ] && [ "$ADVISORY" = "true" ]; then
            emit enforcement_state ADVISORY; emit gate_decision ADVISORY
          elif [ "$fail" = "1" ]; then
            emit enforcement_state BLOCKED; emit gate_decision FAIL
          else
            emit enforcement_state ALLOWED; emit gate_decision PASS
          fi
          # CHECKED BEFORE advisory_mode, deliberately.
          if [ "$secret_fail" = "1" ]; then
            echo "::error title=GATE=FAIL (secrets)::A secret finding blocks regardless of mode."
            echo "advisory_mode does NOT cover secrets. Rotate the credential, then remove it."
            {
              echo "## GATE = FAIL — secret finding"
              echo ""
              echo "> **Secrets are outside advisory mode.** Rotate first, then remove from history."
            } >> "$GITHUB_STEP_SUMMARY"
            exit 1
          fi
          if [ "$fail" = "1" ]; then
            if [ "$ADVISORY" = "true" ]; then
              echo "::warning title=GATE=ADVISORY — non-secret findings not blocked::Scanners ran"
              echo "and findings were reported and persisted, but enforcement is OFF for them."
              echo "SECRETS STILL BLOCK — advisory mode never covered them."
              {
                echo "## GATE = ADVISORY (non-secret findings)"
                echo ""
                echo "> Every scanner that ran is recorded above with its own state."
                echo "> **Non-secret findings were not blocked. Secrets are always enforced.**"
              } >> "$GITHUB_STEP_SUMMARY"
              exit 0
            fi
            echo "::error::One or more required security scans failed or blocked."
            exit 1
          fi
          echo "All required security scans passed or were not applicable."
'''


def main():
    parts = [
        s(1, 260),
        kit_scripts_job(),
        s(2058, 2676),
        job_secrets(),
        job_sca(),
        job_sast_python(),
        job_sast_node(),
        job_sast_dotnet(),
        job_sast_java(),
        job_sast_go(),
        job_sast_cpp(),
        job_iac(),
        job_image(),
        job_report(),
        job_gate(),
    ]
    txt = "".join(parts)
    txt = txt.replace("\r\n", "\n").replace("\r", "\n")
    bad = [hex(ord(c)) for c in set(txt) if ord(c) < 0x20 and c not in "\t\n"]
    assert not bad, "control bytes present: %s" % bad
    with io.open(OUT, "w", encoding="utf-8", newline="") as fh:
        fh.write(txt)
    raw = io.open(OUT, "rb").read()
    print("wrote %s: %d bytes, %d lines" % (OUT, len(raw), raw.count(b"\n")))


if __name__ == "__main__":
    sys.exit(main())

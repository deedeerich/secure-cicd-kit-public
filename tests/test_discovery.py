#!/usr/bin/env python3
"""Prove the discovery job's applicability logic without spending CI minutes.

Discovery is now control-plane input for every scanner, which makes it the highest-leverage place
in the kit for a lie. A discovery job that silently under-reports produces a tidy row of
NOT_APPLICABLE and a green run over code nobody scanned -- strictly worse than a red one.

So it is tested the way everything else here is tested: by EXERCISING THE REAL THING. The shell is
extracted from the workflow itself rather than reimplemented, because a test that reimplements the
logic proves only that the author can write the same bug twice.

Cases, per the agreed contract:
  1. monorepo          Go + Java + Terraform discovered independently; unrelated scanners stay off
  2. single language   a Python-only repo must not wake five other language jobs
  3. narrowing         explicit `language:` CONSTRAINS discovery, never fabricates applicability
  4. iac required, absent   -> MISSING_BUT_REQUIRED (absence is the finding)
  5. iac auto, absent       -> NOT_APPLICABLE (legitimately nothing there)
  6. iac disabled           -> DISABLED, reported loudly
  7. discovery failure      -> DISCOVERY_UNAVAILABLE and EVERYTHING ON
"""

import io
import os
import re
import shutil
import subprocess
import sys
import tempfile

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
WF = os.path.join(ROOT, ".github", "workflows", "reusable-security.yml")
REG = os.path.join(ROOT, "scanner-registry.yaml")
# WHERE THE STEPS SHIP. Since 2026-10-15 the survey and the platform probe run from this
# composite, reached through `$/` (inline, they held the flagship over the 475 KB fail line in
# tests/check_workflow_size.py). The job invokes it once per part, with the ids it always had,
# so this reads the job, requires that it USES the composite (a composite nobody uses is a file
# nobody ships), and runs the steps from the composite -- as tests/test_resolve.py does.
ACTION = os.path.join(ROOT, ".github", "actions", "discover", "action.yml")
USES = "$/.github/actions/discover"
# job step id -> the composite part it must run, and the composite step id that part runs.
PARTS = {"d": ("survey", "d"), "platform": ("platform", "platform")}

# THE JOB'S OUTPUTS CONTRACT, AS IT STOOD INLINE (2bf2e49, before the move). Every consumer reads
# needs.discover.outputs.<name>; the move must not rename one, drop one, or re-source one. Pinned
# here as data rather than read from history, because a CI checkout is shallow.
BASE_OUTPUTS = dict(
    [(k, "${{ steps.d.outputs.%s }}" % k) for k in
     ("python", "node", "go", "dotnet", "java", "cpp", "iac", "state", "unsupported",
      "coverage_gaps", "coverage_gap_count")] +
    [(k, "${{ steps.platform.outputs.%s }}" % k) for k in
     ("ghas_available", "code_scanning", "secret_scanning", "push_protection",
      "dependabot_alerts", "dependabot_updates", "dependabot_config", "visibility",
      "platform_source")])


def load_job_and_composite():
    """-> (discover job, composite document). Fails unless the job uses the composite for
    both parts under the ids its outputs read."""
    import yaml
    doc = yaml.safe_load(io.open(WF, encoding="utf-8"))
    job = (doc.get("jobs") or {}).get("discover")
    if not job:
        raise SystemExit("FAIL: no job named discover in reusable-security.yml")
    by_id = {s.get("id"): s for s in job.get("steps") or [] if s.get("id")}
    for sid, (part, _) in PARTS.items():
        s = by_id.get(sid) or {}
        if s.get("uses") != USES or str((s.get("with") or {}).get("part")) != part:
            raise SystemExit("FAIL: discover step %r does not use %s with part %s (uses=%r with=%r) "
                             "-- its body ships nowhere this proof can run it"
                             % (sid, USES, part, s.get("uses"), s.get("with")))
    if not os.path.isfile(ACTION):
        raise SystemExit("FAIL: the discover job uses %s but %s does not exist" % (USES, ACTION))
    return job, (yaml.safe_load(io.open(ACTION, encoding="utf-8")) or {})


def composite_step(comp, step_id):
    for step in (comp.get("runs") or {}).get("steps") or []:
        if step.get("id") == step_id:
            return step
    raise SystemExit("FAIL: composite %s has no step with id %r" % (ACTION, step_id))


def extract_discovery_shell():
    """The survey step's `run` body, from the composite the job ships it in."""
    _, comp = load_job_and_composite()
    return composite_step(comp, PARTS["d"][1])["run"]


def wiring_checks():
    """The move changed WHERE the steps run and nothing a consumer can observe.

    1. the job's outputs are exactly the base contract: names and expression sources
    2. each output's invocation runs the part whose composite step emits it, and the composite
       output of that name reads that step
    3. each composite run step is gated to exactly its part, and declares shell: bash
    4. an unknown part fails loudly; the job passes every declared input and nothing else
    5. the registry names the composite (tests/check_scanner_registry.py enforces the use)
    """
    import yaml
    job, comp = load_job_and_composite()
    ok = True
    outputs = {k: str(v).strip() for k, v in (job.get("outputs") or {}).items()}
    added = sorted(set(outputs) - set(BASE_OUTPUTS))
    dropped = sorted(set(BASE_OUTPUTS) - set(outputs))
    changed = sorted(k for k in set(outputs) & set(BASE_OUTPUTS) if outputs[k] != BASE_OUTPUTS[k])
    ok &= check_bool("job outputs == base (names + sources)", not (added or dropped or changed),
                     "added=%s dropped=%s re-sourced=%s" % (added, dropped, changed))
    cout = comp.get("outputs") or {}
    bad = []
    for k, expr in BASE_OUTPUTS.items():
        sid = expr.split("steps.", 1)[1].split(".", 1)[0]
        part, inner = PARTS[sid]
        want = "${{ steps.%s.outputs.%s }}" % (inner, k)
        if str((cout.get(k) or {}).get("value", "")).strip() != want:
            bad.append("%s: composite value %r, want %r" % (k, (cout.get(k) or {}).get("value"), want))
    # That each step really WRITES its outputs is asserted by running it: see emitted_checks.
    bad += ["%s: composite output nothing maps" % k for k in sorted(set(cout) - set(BASE_OUTPUTS))]
    ok &= check_bool("each output read from its own part", not bad, "\n".join(bad))
    steps = (comp.get("runs") or {}).get("steps") or []
    gated = []
    for sid, (part, inner) in PARTS.items():
        s = composite_step(comp, inner)
        if str(s.get("if", "")).replace('"', "'").strip() != "inputs.part == '%s'" % part:
            gated.append("%s: if=%r" % (inner, s.get("if")))
    gated += ["%s: shell=%r" % (s.get("id") or s.get("name"), s.get("shell"))
              for s in steps if s.get("run") and s.get("shell") != "bash"]
    ok &= check_bool("each part gated; every step shell: bash", not gated, "\n".join(gated))
    guard = [s for s in steps if not s.get("id") and "exit 1" in str(s.get("run", ""))
             and all("inputs.part != '%s'" % p in str(s.get("if", "")) for p, _ in PARTS.values())]
    ok &= check_bool("an unknown part fails loudly", bool(guard), "no guard step found")
    passed = set()
    for s in job.get("steps") or []:
        if s.get("uses") == USES:
            passed |= set(s.get("with") or {})
    declared = set(comp.get("inputs") or {})
    ok &= check_bool("job passes every input, nothing extra", passed == declared,
                     "missing=%s extra=%s" % (sorted(declared - passed), sorted(passed - declared)))
    reg = yaml.safe_load(io.open(REG, encoding="utf-8")) or {}
    row = (reg.get("jobs") or {}).get("discover") or {}
    ok &= check_bool("registry names the composite", row.get("composite") == "discover",
                     "row=%s" % row)
    return ok


def check_bool(name, ok, detail=""):
    print("  %-38s %s" % (name, "PASS" if ok else "FAIL"))
    if not ok and detail:
        for line in str(detail).splitlines()[:12]:
            print("      %s" % line)
    return bool(ok)


def run_platform_unreachable():
    """The platform step, as shipped, with the API unreachable: every answer must be an
    UNKNOWN that says nobody asked successfully -- never a fabricated false."""
    _, comp = load_job_and_composite()
    body = "gh() { return 1; }\n" + composite_step(comp, PARTS["platform"][1])["run"]
    return run_case(body, ["app/main.py"])


def _bash():
    """Resolve a REAL bash.

    On Windows, `subprocess` resolves a bare "bash" to WSL, which cannot see the Windows filesystem
    and fails with mount errors that look nothing like a shell problem. This kit has already lost
    time to that once, diagnosing a WSL startup failure as a syntax error. Prefer Git Bash
    explicitly; fall back to whatever is on PATH elsewhere (CI, Linux, macOS).
    """
    gitbash = os.path.join("C:" + os.sep, "Program Files", "Git", "bin", "bash.exe")
    gitbash86 = os.path.join("C:" + os.sep, "Program Files (x86)", "Git", "bin", "bash.exe")
    for c in (gitbash, gitbash86):
        if os.path.exists(c):
            return c
    return shutil.which("bash") or "bash"


def make_tree(spec, base):
    for rel in spec:
        p = os.path.join(base, rel)
        os.makedirs(os.path.dirname(p), exist_ok=True)
        io.open(p, "w", encoding="utf-8").write("x\n")


def big_tree(n, ext="py", prefix="bulk"):
    """A tree large enough that a match stream does not fit in one pipe write.

    The original probe piped find into `head -1`. Under `pipefail`, head closing the pipe kills
    find with SIGPIPE and the pipeline reports 141 -- which the survey read as "could not look".
    Every synthetic tree in this file was 1-3 files, so the stream always fit and the suite was
    green while the real behaviour on any real repository was DISCOVERY_UNAVAILABLE. The tests
    were not wrong about what they asserted; they were wrong about what they SAMPLED.
    """
    return ["%s/f%d.%s" % (prefix, i, ext) for i in range(n)]


def run_case(shell, files, language="auto", iac_mode="auto", scope=".", break_find=False,
             break_probes=None, break_all_soft=False):
    """Execute the real discovery shell against a synthetic tree; return its outputs."""
    tmp = tempfile.mkdtemp(prefix="disc-")
    rundir = tempfile.mkdtemp(prefix="disc-run-")
    outfile = os.path.join(tmp, "gh_output")
    summary = os.path.join(tmp, "gh_summary")
    try:
        make_tree(files, tmp)
        io.open(outfile, "w").close()
        io.open(summary, "w").close()

        # THE HARNESS MUST FEED THE STEP THE WAY THE RUNNER DOES.
        #
        # Caller input stopped being interpolated as `${{ inputs.* }}` inside the script -- it is
        # passed as ENV, deliberately, so a caller cannot inject shell. These substitutions then
        # matched nothing, every case silently ran with the defaults (language=auto,
        # iac_mode=auto), and four assertions about SELECTORS were being answered by a shell that
        # had never seen a selector. Kept below for older revisions; the env below is what works.
        body = shell
        body = body.replace("${{ inputs.paths }}", scope)
        body = body.replace("${{ inputs.language }}", language)
        body = body.replace("${{ inputs.iac_mode }}", iac_mode)
        if break_find:
            # Simulate the dangerous failure: the survey itself cannot run. The contract says this
            # must NOT resolve to a tidy row of NOT_APPLICABLE.
            body = "find() { return 1; }\n" + body.replace("set -uo pipefail", "set -uo pipefail\nset -e")
        elif break_all_soft:
            # Every probe fails, but the STEP does not abort -- exercises the per-probe counting
            # path rather than the catastrophic ERR trap. Both must reach the same verdict.
            body = "find() { return 1; }\n" + body
        elif break_probes:
            # Break SOME probes. What the surviving probes established must still be reported.
            pats = "|".join("*%s*" % p for p in break_probes)
            body = ("find() { case \"$*\" in %s) return 1;; *) command find \"$@\";; esac; }\n"
                    % pats) + body

        # OUTSIDE the tree under test. The harness previously wrote d.sh into the very directory it
        # was surveying, so the coverage probe reported `sh` for every fixture -- the instrument
        # showing up in its own measurement. A mechanism's limits must not present as a property of
        # the thing being measured.
        script = os.path.join(rundir, "d.sh")
        io.open(script, "w", encoding="utf-8", newline="\n").write(body)
        env = dict(os.environ, GITHUB_OUTPUT=outfile, GITHUB_STEP_SUMMARY=summary,
                   IN_PATHS=scope, IN_LANGUAGE=language, IN_IAC_MODE=iac_mode,
                   IN_ENABLE_IAC="false")
        p = subprocess.run([_bash(), script], cwd=tmp, env=env, capture_output=True, text=True)

        out = {}
        for line in io.open(outfile, encoding="utf-8"):
            if "=" in line:
                k, v = line.strip().split("=", 1)
                out[k] = v
        # A COVERAGE GAP THAT NOBODY CAN SEE IS THE DEFECT, NOT THE FIX. The step OUTPUT is what a
        # consumer binds to; the SUMMARY and the ::warning are what a human reads, and the
        # requirement is that all three carry it. Surfaced under reserved keys so `check` can
        # assert on outputs exactly as before.
        out["__summary__"] = io.open(summary, encoding="utf-8").read()
        out["__log__"] = (p.stdout or "") + (p.stderr or "")
        return out
    finally:
        shutil.rmtree(tmp, ignore_errors=True)
        shutil.rmtree(rundir, ignore_errors=True)


def check(name, got, expect):
    bad = {k: (expect[k], got.get(k)) for k in expect if got.get(k) != expect[k]}
    status = "PASS" if not bad else "FAIL"
    print("  %-38s %s" % (name, status))
    for k, (want, actual) in bad.items():
        print("      %-8s want=%-24s got=%s" % (k, want, actual))
    return not bad


def check_text(name, got, key, must, must_not=()):
    """Assert on the human-facing channels: the step summary and the annotation log."""
    blob = got.get(key, "")
    missing = [s for s in must if s not in blob]
    present = [s for s in must_not if s in blob]
    ok = not missing and not present
    print("  %-38s %s" % (name, "PASS" if ok else "FAIL"))
    for s in missing:
        print("      MISSING  %r" % s)
    for s in present:
        print("      FORBIDDEN %r" % s)
    return ok


def main():
    shell = extract_discovery_shell()
    ok = True

    # THE MOVE INTO THE COMPOSITE CHANGED NOTHING A CONSUMER CAN OBSERVE.
    ok &= wiring_checks()

    # COULD NOT LOOK IS NOT ABSENT, on the platform axis too.
    plat = run_platform_unreachable()
    ok &= check("platform API unreachable -> UNKNOWN", plat,
                {"ghas_available": "unknown", "code_scanning": "UNKNOWN",
                 "secret_scanning": "unknown", "push_protection": "unknown",
                 "dependabot_alerts": "unknown", "dependabot_updates": "unknown",
                 "dependabot_config": "ABSENT", "visibility": "unknown",
                 "platform_source": "none"})
    ok &= check_text("platform unknown -> summary says why", plat, "__summary__",
                     must=["was not readable by this token", "| GitHub Advanced Security | unknown | none |"])

    # EVERY JOB OUTPUT IS WRITTEN BY THE STEP IT IS READ FROM -- established by running both
    # steps as shipped, not by reading their text (the survey writes most of its answers in a loop).
    surveyed = run_case(shell, ["app/main.py", "ops/deploy.sh"])
    for sid, got in (("d", surveyed), ("platform", plat)):
        want = sorted(k for k, v in BASE_OUTPUTS.items() if "steps.%s." % sid in v)
        missing = [k for k in want if k not in got]
        ok &= check_bool("step %s writes all %d of its outputs" % (sid, len(want)), not missing,
                         "never written: %s" % missing)

    ok &= check("monorepo: go+java+terraform",
                run_case(shell, ["svc/go.mod", "api/pom.xml", "infra/main.tf"]),
                {"go": "true", "java": "true", "iac": "true",
                 "python": "false", "dotnet": "false", "cpp": "false",
                 "state": "COMPLETE"})

    ok &= check("single language: python only",
                run_case(shell, ["app/main.py", "requirements.txt"]),
                {"python": "true", "go": "false", "java": "false",
                 "dotnet": "false", "cpp": "false", "iac": "false"})

    ok &= check("narrowing constrains, never fabricates",
                run_case(shell, ["svc/go.mod", "app/main.py"], language="go"),
                {"go": "true", "python": "false"})

    ok &= check("narrowing cannot invent applicability",
                run_case(shell, ["app/main.py"], language="go"),
                {"go": "false", "python": "false"})

    ok &= check("iac required + absent -> partial",
                run_case(shell, ["app/main.py"], iac_mode="required"),
                {"iac": "false", "state": "DISCOVERY_PARTIAL"})

    ok &= check("iac required + present -> run",
                run_case(shell, ["infra/main.tf"], iac_mode="required"),
                {"iac": "true", "state": "COMPLETE"})

    ok &= check("iac auto + absent -> not applicable",
                run_case(shell, ["app/main.py"], iac_mode="auto"),
                {"iac": "false", "state": "COMPLETE"})

    ok &= check("iac disabled -> off, loudly",
                run_case(shell, ["infra/main.tf"], iac_mode="disabled"),
                {"iac": "false"})

    ok &= check("dockerfile counts as iac",
                run_case(shell, ["build/Dockerfile"]),
                {"iac": "true"})

    # THE ONE THAT MATTERS MOST.
    ok &= check("discovery failure -> everything ON",
                run_case(shell, ["app/main.py"], break_find=True),
                {"state": "DISCOVERY_UNAVAILABLE", "python": "true", "go": "true",
                 "java": "true", "dotnet": "true", "cpp": "true", "iac": "true"})

    ok &= check("all probes fail (no abort) -> unavailable",
                run_case(shell, ["app/main.py"], break_all_soft=True),
                {"state": "DISCOVERY_UNAVAILABLE", "python": "true", "go": "true",
                 "java": "true", "dotnet": "true", "cpp": "true", "iac": "true"})

    # PARTIAL IS NOT TOTAL. One probe failing must not discard six good answers.
    ok &= check("one probe fails -> others survive",
                run_case(shell, ["svc/go.mod", "app/main.py"], break_probes=["csproj"]),
                {"state": "DISCOVERY_PARTIAL",
                 "dotnet": "true",     # undetermined -> enabled
                 "go": "true",         # established, preserved
                 "python": "true",     # established, preserved
                 "java": "false", "cpp": "false", "iac": "false"})

    ok &= check("undetermined outranks the selector",
                run_case(shell, ["app/main.py"], language="python", break_probes=["go.mod"]),
                {"python": "true", "go": "true", "state": "DISCOVERY_PARTIAL"})

    # ABSENCE IS ONLY A FINDING IF ABSENCE WAS ESTABLISHED.
    ok &= check("iac required + probe failed -> not a finding",
                run_case(shell, ["app/main.py"], iac_mode="required", break_probes=["*.tf"]),
                {"iac": "true", "state": "DISCOVERY_PARTIAL"})

    # COVERAGE IS NOT APPLICABILITY. Discovery asking seven closed questions and hearing "no"
    # seven times is not the same as understanding the repository.
    ok &= check("unsupported languages are declared",
                run_case(shell, ["src/main.rs", "app/h.rb", "web/i.php"]),
                {"state": "COMPLETE", "unsupported": "php,rb,rs",
                 "python": "false", "go": "false"})

    ok &= check("supported + unsupported coexist",
                run_case(shell, ["app/main.py", "native/core.rs"]),
                {"python": "true", "unsupported": "rs", "state": "COMPLETE"})

    ok &= check("fully supported repo declares no gap",
                run_case(shell, ["app/main.py", "svc/go.mod", "infra/main.tf"]),
                {"python": "true", "go": "true", "iac": "true", "unsupported": ""})

    # ─────────────────────────────────────────────────────────────────────────
    # COVERAGE_GAP — absence of evidence, published as such
    # ─────────────────────────────────────────────────────────────────────────
    #
    #   ARTIFACT_PRESENT + CAPABILITY_REQUIRED + SCANNER_UNAVAILABLE = COVERAGE_GAP
    #
    # Three states that must never appear collapsed:
    #   NOT_APPLICABLE   the artifact is not here            nothing to find
    #   CLEAN            a scanner ran and found nothing     evidence of absence
    #   COVERAGE_GAP     the artifact is here, nothing scans it   ABSENCE OF EVIDENCE
    #
    # The failure being pinned: discovery answered its seven closed questions, found no Python
    # and no Go, and published a tidy survey over a repository of shell scripts, PowerShell and
    # workflow YAML that nothing in this kit can read. Silence is the defect. A gap must be
    # NAMED, COUNTED, WARNED and put in the summary.
    shell_ps = run_case(shell, ["ops/deploy.sh", "ops/build.ps1"])
    ok &= check("shell + powershell -> counted gaps",
                shell_ps,
                # Order follows the sorted EXTENSION (ps1 before sh), not the display name.
                {"coverage_gaps": "PowerShell,Shell", "coverage_gap_count": "2",
                 "python": "false", "go": "false", "state": "COMPLETE"})
    ok &= check_text("shell + powershell -> summary rows", shell_ps, "__summary__",
                     must=["| Shell | COVERAGE_GAP |", "| PowerShell | COVERAGE_GAP |",
                           "**COVERAGE_GAP x2**"],
                     must_not=["| Shell | NOT_APPLICABLE |", "| PowerShell | NOT_APPLICABLE |"])
    ok &= check_text("shell + powershell -> ::warning each", shell_ps, "__log__",
                     must=["::warning title=COVERAGE_GAP: Shell::",
                           "::warning title=COVERAGE_GAP: PowerShell::"])

    # THE PIPELINE'S OWN DEFINITION FILES. No probe asked about them at all, so a repo whose only
    # unscanned artifact was .github/workflows/*.yml produced a completely silent survey. This kit
    # ships no actionlint; incidental CKV_GHA_* coverage from Checkov is not a declared capability.
    gha = run_case(shell, [".github/workflows/ci.yml", ".github/workflows/release.yaml"])
    ok &= check("workflow YAML is a declared gap", gha,
                {"coverage_gaps": "GitHubActionsWorkflow", "coverage_gap_count": "1",
                 "unsupported": "", "state": "COMPLETE"})
    ok &= check_text("workflow gap names the missing scanner", gha, "__summary__",
                     must=["| GitHubActionsWorkflow | COVERAGE_GAP |", "actionlint"])

    # Swift, Kotlin, Ruby, PHP, Rust are in this estate and nothing here scans them.
    est = run_case(shell, ["ios/App.swift", "android/Main.kt", "app/h.rb",
                           "web/i.php", "native/core.rs"])
    ok &= check("swift/kotlin/ruby/php/rust all named", est,
                {"coverage_gap_count": "5"})
    ok &= check_text("each class named, not spelled as an extension", est, "__summary__",
                     must=["| Swift | COVERAGE_GAP |", "| Kotlin | COVERAGE_GAP |",
                           "| Ruby | COVERAGE_GAP |", "| PHP | COVERAGE_GAP |",
                           "| Rust | COVERAGE_GAP |"])

    # A GAP IS NOT AN APPLICABILITY ANSWER. Supported code still runs; the gap sits beside it.
    ok &= check("gap coexists with a real scanner",
                run_case(shell, ["app/main.py", "ops/deploy.sh"]),
                {"python": "true", "coverage_gaps": "Shell", "coverage_gap_count": "1"})

    # ZERO IS ONLY PRINTED WHEN SOMEONE LOOKED. A fully covered repo declares no gap, and that
    # claim has to be distinguishable from the silence this test exists to forbid.
    ok &= check("fully covered repo -> zero gaps",
                run_case(shell, ["app/main.py", "svc/go.mod", "infra/main.tf"]),
                {"coverage_gaps": "", "coverage_gap_count": "0"})

    # REGRESSION: `find | head -1` reported 141 on any repo with a second match, so discovery
    # claimed DISCOVERY_UNAVAILABLE on essentially every real repository. It failed SAFE, which
    # is exactly why it survived -- over-scanning is quiet.
    ok &= check("large tree still resolves COMPLETE",
                run_case(shell, big_tree(400, "py") + big_tree(400, "go", "gosrc")
                         + ["svc/go.mod", "infra/main.tf"]),
                {"state": "COMPLETE", "python": "true", "go": "true", "iac": "true",
                 "java": "false", "dotnet": "false", "cpp": "false"})

    print()
    if not ok:
        print("::error title=Discovery contract violated::Applicability logic does not match the "
              "agreed contract. A discovery defect is not one scanner being wrong -- it decides "
              "what gets scanned at all.")
        return 1
    print("discovery: all cases hold")
    return 0


if __name__ == "__main__":
    sys.exit(main())

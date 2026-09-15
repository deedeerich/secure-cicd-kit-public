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


def extract_discovery_shell():
    """Pull the discover step's `run` body straight out of the workflow."""
    import yaml
    doc = yaml.safe_load(io.open(WF, encoding="utf-8"))
    for step in doc["jobs"]["discover"]["steps"]:
        if step.get("id") == "d":
            return step["run"]
    raise SystemExit("discover step not found -- did the job get renamed?")


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
        env = dict(os.environ, GITHUB_OUTPUT=outfile, GITHUB_STEP_SUMMARY=summary)
        subprocess.run([_bash(), script], cwd=tmp, env=env, capture_output=True, text=True)

        out = {}
        for line in io.open(outfile, encoding="utf-8"):
            if "=" in line:
                k, v = line.strip().split("=", 1)
                out[k] = v
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


def main():
    shell = extract_discovery_shell()
    ok = True

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

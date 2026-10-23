#!/usr/bin/env python3
"""The seeded corpus for the pipeline linters (lane L-SCAN-A, KDEC-025).

    actionlint + zizmor   over GitHub Actions workflows       (deps-scan)
    shellcheck            over *.sh / *.bash                  (deps-scan)
    PSScriptAnalyzer      over *.ps1 / *.psm1 / *.psd1        (deps-scan)
    hadolint              over Dockerfiles                    (iac-scan)

WHY A GENERATOR AND NOT FILES IN THE TREE

    A seeded workflow committed under tests/ would sit at */.github/workflows/*, which is exactly what
    discovery looks for -- so the kit's own dogfood scan would carry the seeds as real findings. The
    corpus is written into a throwaway directory by the proof that needs it, the way
    tests/corpora/terraform_corpus.py writes its Terraform families. Nothing seeded is ever tracked.

WHAT EACH SEED IS FOR

    SEEDS     path -> content. Every file carries at least one known finding.
    EXPECTED  tool -> rule ids that MUST appear (a scanner that runs and misses them is not a pass),
              and the subset that must arrive at error level (the level the jobs hand to the gate).
    REFUSED   tool -> files the job must NOT claim to have read: a shell dialect shellcheck cannot
              parse, a PowerShell script that #Requires a newer PowerShell than the runner's. Each
              must be NAMED as a VERSION_GAP and must not be counted as clean.

Measured 2026-10-23 with the releases the jobs pin (actionlint 1.7.12, zizmor 1.30.1, shellcheck
0.11.0, PSScriptAnalyzer 1.25.0 on pwsh 7.4, hadolint 2.15.1) by tests/prove_pipeline_lint.py.

USAGE
    python3 tests/corpora/pipeline_lint_corpus.py --write DIR    # materialise the corpus in DIR
"""
import io
import os
import re
import sys

WORKFLOW = """name: seeded
on:
  pull_request_target:
jobs:
  build:
    runs-on: ubuntu-latest
    permissions: write-all
    needs: [does-not-exist]
    steps:
      - uses: actions/checkout@v4
        with:
          ref: ${{ github.event.pull_request.head.sha }}
      - name: echo the title
        run: echo "${{ github.event.pull_request.title }}"
      - name: unquoted
        run: echo $HOME/$RUNNER_TEMP
"""

SHELL = """#!/bin/bash
# seeded: unquoted expansions, cd without a guard, rm over an unquoted variable
cd $1
rm -rf $TARGET/*
for f in $(ls *.txt); do echo $f; done
"""

# zsh: shellcheck refuses the dialect (SC1071). The job must NAME it, not pass it as clean.
ZSH = """#!/bin/zsh
print -P "%F{red}seeded%f"
"""

POWERSHELL = """# seeded: plain-text secure string, Invoke-Expression, Write-Host
param([string]$Command)
$password = ConvertTo-SecureString "P@ssw0rd!" -AsPlainText -Force
Invoke-Expression $Command
Write-Host "done"
"""

# A script that #Requires a PowerShell newer than any runner carries. The job must refuse it.
PS_FUTURE = """#Requires -Version 99.0
Write-Output "needs a PowerShell that does not exist"
"""

DOCKERFILE = """FROM ubuntu:latest
WORKDIR app
ADD ./src /app
RUN apt-get update && apt-get install -y curl
USER root
"""

SEEDS = {
    ".github/workflows/seeded.yml": WORKFLOW,
    "scripts/deploy.sh": SHELL,
    "scripts/fancy.sh": ZSH,
    "ops/run.ps1": POWERSHELL,
    "ops/future.ps1": PS_FUTURE,
    "build/Dockerfile": DOCKERFILE,
}

# tool -> (rule ids that must appear, rule ids that must be at error level). Rule ids are as the
# job's SARIF writes them.
EXPECTED = {
    "actionlint": ({"actionlint/expression", "actionlint/job-needs",
                    "actionlint/shellcheck/SC2086"},
                   {"actionlint/expression", "actionlint/job-needs"}),
    "zizmor": ({"zizmor/template-injection", "zizmor/dangerous-triggers",
                "zizmor/excessive-permissions", "zizmor/unpinned-uses"},
               {"zizmor/template-injection", "zizmor/dangerous-triggers",
                "zizmor/excessive-permissions"}),
    "shellcheck": ({"SC2086", "SC2164", "SC2045"}, {"SC2045"}),
    "psscriptanalyzer": ({"PSAvoidUsingConvertToSecureStringWithPlainText",
                          "PSAvoidUsingInvokeExpression", "PSAvoidUsingWriteHost"},
                         {"PSAvoidUsingConvertToSecureStringWithPlainText"}),
    "hadolint": ({"DL3007", "DL3000", "DL3020", "DL3008", "DL3002"}, {"DL3000", "DL3020"}),
}

REFUSED = {
    "shellcheck": ["scripts/fancy.sh"],
    "psscriptanalyzer": ["ops/future.ps1"],
}

# Which seeds each tool reads, so a proof can build a tree holding only one class.
CLASS_OF = {
    ".github/workflows/seeded.yml": "workflows",
    "scripts/deploy.sh": "shell",
    "scripts/fancy.sh": "shell",
    "ops/run.ps1": "powershell",
    "ops/future.ps1": "powershell",
    "build/Dockerfile": "dockerfile",
}


def write(dest, only=None):
    """Write the seeds (or only those of the classes named) under dest. -> list of paths."""
    out = []
    for rel, text in sorted(SEEDS.items()):
        if only and CLASS_OF[rel] not in only:
            continue
        p = os.path.join(dest, *rel.split("/"))
        os.makedirs(os.path.dirname(p), exist_ok=True)
        io.open(p, "w", encoding="utf-8", newline="\n").write(text)
        out.append(rel)
    return out


def rules_in(tool, path):
    """Rule ids in a tool's NATIVE report, named as the jobs' SARIF names them -- so the weekly
    probe (validate-scanners.yml), which runs the bare tool, asserts the same EXPECTED set."""
    import json
    doc = json.load(io.open(path, encoding="utf-8-sig"))
    if tool == "actionlint":
        out = set()
        for e in doc or []:
            m = re.search(r"\b(SC\d+):", e.get("message", ""))
            if e.get("kind") == "shellcheck" and m:
                out.add("actionlint/shellcheck/" + m.group(1))
            else:
                out.add("actionlint/" + e.get("kind", "unknown"))
        return out
    if tool == "shellcheck":
        return {"SC%s" % c.get("code") for c in doc.get("comments") or []}
    if tool == "psscriptanalyzer":
        return {d.get("RuleName") for d in (doc if isinstance(doc, list) else [doc])}
    return {r.get("ruleId") for run in doc.get("runs") or [] for r in run.get("results") or []}


def check(tool, path):
    """0 when every seeded rule for `tool` is in its report, else 1 (2 if unreadable)."""
    try:
        got = rules_in(tool, path)
    except (OSError, ValueError) as exc:
        print("UNKNOWN: %s report %s unreadable (%s) -- not zero findings" % (tool, path, exc))
        return 2
    missing = sorted(EXPECTED[tool][0] - got)
    print("%s: %d rule(s) found; seeded and missing: %s" % (tool, len(got), missing or "none"))
    return 1 if missing else 0


if __name__ == "__main__":
    if len(sys.argv) == 3 and sys.argv[1] == "--write":
        for rel in write(sys.argv[2]):
            print(rel)
        sys.exit(0)
    if len(sys.argv) == 4 and sys.argv[1] == "--check" and sys.argv[2] in EXPECTED:
        sys.exit(check(sys.argv[2], sys.argv[3]))
    print(__doc__)
    sys.exit(2)

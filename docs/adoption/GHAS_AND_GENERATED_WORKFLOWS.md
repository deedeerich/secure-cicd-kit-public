# Enabling GHAS from the GitHub UI, and what this kit does about it

## The failure this document exists to prevent

A consumer enables code scanning the documented one-click way — **Security > Code scanning >
Set up > Advanced** — and GitHub opens a pull request adding `.github/workflows/codeql.yml`.

On 2026-09-22 that pull request went red on `secure-cicd-kit-public`. **CodeQL itself passed.**
All seven `Analyze` jobs succeeded and published. What failed were four of this kit's own checks,
against a file GitHub generated and that no human wrote.

That is the worst possible defect for an adoption path: the platform's supported route produces a
red build, and every red is ours.

## What was actually wrong, and what changed

| check | cause | status |
|---|---|---|
| YAML lint | yamllint's `default` preset rejects `branches: [ "main" ]` (`brackets`) and sequences written at the parent indent (`indentation`) | **fixed** — see below |
| Normalizer drift | an older copy globbed every workflow and called `os.stat(None)` on one it had no mapping for | **fixed** — `TARGETS` names one file; the public mirror was stale |
| actionlint | linted the generated file | tracked |
| Validation coverage | counted `codeql.yml` as a third orchestration workflow, changing a denominator | tracked |

**The yamllint change, and why it is not a weakening.** Two rules were relaxed:

```yaml
brackets:    {max-spaces-inside: 1}
indentation: {spaces: consistent, indent-sequences: whatever}
```

Both are whitespace preferences inherited from `extends: default`. Neither expresses a security
property, a correctness property, or anything this kit has an opinion about. And GitHub regenerates
that file byte-identically every time, so a consumer **cannot fix it once** — they would be
reformatting the same generated file forever.

A linter that fails the platform's own supported output is the linter that is wrong.

Everything the kit does care about is untouched: `truthy`, `comments`, `line-length`, key
duplication, trailing whitespace, and every non-style rule in the default preset still apply, and
the kit's own workflows still pass unchanged.

## If you want the kit's CodeQL instead of GitHub's

GitHub's generated workflow is a reasonable default and **you do not have to replace it.** It runs,
it publishes, and this kit no longer objects to it.

Replace it only if you want what the kit's version adds:

- **language selection from discovery, not from a hand-edited matrix.** The generated file lists
  languages a human chose once. The kit derives them from what is actually in the tree, so a new
  language is scanned the day it appears and a removed one stops billing a runner.
- **a typed scanner state per language**, so `NOT_APPLICABLE` (with evidence), `PASS`,
  `FINDINGS` and a present-but-unscannable language (`COVERAGE_GAP` in discovery) stay different
  answers rather than collapsing into a green tick. CodeQL renders one report row per language
  (`codeql-python`, `codeql-javascript-typescript`, … six in all).
- **publication failure separated from scan failure.** Where code scanning is unavailable — a
  private repository without GitHub Code Security — the generated workflow fails. The kit warns that
  the SARIF was NOT published (`ANALYSIS=COMPLETE`), keeps it as a redacted artifact, and the gate
  still enforces on the findings. A scan that ran and could not publish is not a scan that did not
  run. Proven on a private consumer repository with no licence: publication refused, analysis ran,
  the gate read 5 Python and 4 JavaScript results (runs 38817782084, 38820564939).

**How to swap.** CodeQL is already a job inside `reusable-security.yml`, so a consumer calling that
workflow has it. If you are calling this kit at all:

1. Delete `.github/workflows/codeql.yml` — the generated one.
2. Confirm your caller invokes `reusable-security.yml` (see `templates/security.yml`).
3. If a branch ruleset required the `CodeQL` check by name, update it to the kit's check before
   deleting (the caller job's `Security gate`, e.g. `security / Security gate`), or the branch
   becomes unmergeable.

Step 3 is the one that bites. **A required status check naming a job that no longer exists blocks
every pull request forever**, and the error does not say which check is missing.

## What is still not solved

- **Private repositories without GitHub Code Security cannot publish to the Security tab.** That is
  a licensing boundary, not a defect, and it renders as a publication warning rather than as a
  missing scan. Semgrep and the language-specific scanners continue regardless. One known defect
  remains: the `resolve` position still withdraws CodeQL on the platform pre-flight
  (`docs/KNOWN_DEFECTS.md` D-10), which caps the job `PARTIAL` although the analysis runs.
- **Dependabot** fails separately on the public mirror and is not diagnosed here.
- **GHAS is not one switch.** Dependency graph, Dependabot alerts, Dependabot security updates, code
  scanning, secret scanning and push protection have different availability and enablement states.
  A single `ghas_available` boolean loses most of that, and the kit currently carries four of them.

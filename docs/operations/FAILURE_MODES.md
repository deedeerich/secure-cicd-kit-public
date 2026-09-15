# Failure modes — how this breaks, and how to fix it

Every entry here happened for real, in this kit, and was found by a test rather than by a user.
They are written down because the expensive ones all share a shape: **the pipeline reported success
while analysing nothing.** A scanner that crashes is cheap — you know immediately. A scanner that
runs against the wrong directory, loads no rules, or writes its report to a filename nobody reads
exits **zero** and buys you a green checkmark you did not earn.

> **The governing rule.** Silence is never a correct outcome. Every scanner either produces findings,
> produces an explicit "nothing to scan and here is the path I searched", or fails loudly. If you see
> none of those three, that is a defect in the kit — please report it rather than assuming clean.

---

## 1 · Silent no-op — the worst class

### Semgrep reports success and finds nothing

**Symptom:** Semgrep job green, zero findings, on code you know contains issues. Meanwhile Bandit or
another scanner finds things in the same tree.

**Cause A — default ignore list.** Semgrep skips `tests/`, `test/`, `fixtures/`, `vendor/` and similar
**by default**. If your code lives under a path matching those, Semgrep silently skips all of it.

**Cause B — `--config` not repeated.** Semgrep takes scan targets *positionally*. Writing
`--config p/default p/owasp-top-ten` loads **one** ruleset and treats the other as a **path to scan**.
Half your rules never run, with no warning.

**Fix:** the kit writes its own `.semgrepignore` (replacing the default) and builds one `--config` per
ruleset. If you customise the Semgrep invocation, preserve both. **Caller scope must outrank a
scanner's convenience defaults** — if someone asks to scan `tests/security-fixture`, the scanner does
not get to decide that directory looks test-ish and skip it.

### A job that installs a tool and never runs it

**Symptom:** job green, no findings ever, and no SARIF artifact produced.

**Cause:** the job has setup steps and publish steps but no analysis step between them. Three jobs in
this kit shipped that way — `sast-java` ran no scanner at all, `sast-dotnet` had dependency auditing
and zero static analysis, and `sast-cpp` ran `cppcheck` while publishing a `flawfinder` report that
nothing generated.

**How to detect it yourself:** an unexplained **absent SARIF artifact** is the tell. If a job claims a
capability, it should either produce a report or say "no applicable source under `<path>`".

**Fix:** `tests/verify_expected_signals.py` compares *expected* against *observed* on a fixture with
deliberately planted flaws. Counting green jobs cannot catch this; a signal contract can.

---

## 2 · Scope and discovery

### "Dependencies lock file is not found" / scanner reads the repo root

**Symptom:** `setup-node` hard-fails; or a scanner reports findings from files far outside the `paths`
you asked for; or a monorepo consumer gets one service scanned and the rest ignored.

**Cause:** root assumptions. Tools default to the repository root and ignore your scope. This kit hit
it in **three** places — Node (`package-lock.json` at root), Go (`gosec ./...` from root), and .NET
(`ls **/*.sln` from root).

**Fix:** project roots are **discovered under `paths`**, and **every** discovered root is scanned, not
the first one. If you add a language, do the same — and print what you found.

### gitleaks scanned my whole history when I asked for one directory

**Cause:** history scanning is repo-wide by nature and ignores `paths` entirely.

**Fix:** `scan_git_history` defaults **false**. Turn it on deliberately; it is slow and its scope is
the whole repository regardless of what you asked for.

---

## 3 · Prerequisites — coverage you never had

Some scanners cannot operate without a specific artifact. Missing it is not a vulnerability; it is an
**`ASSURANCE_PREREQUISITE_GAP`** — a condition preventing a security *claim* from being established.

| Missing | Consequence | Remediation |
|---|---|---|
| **npm lockfile** (`package-lock.json`/`npm-shrinkwrap.json`/`yarn.lock`) | **Trivy cannot resolve npm dependencies at all.** Reported as `NODE_SCA_PARTIAL` naming the root | Commit a lockfile if the project is meant to have deterministic resolution |
| `go.mod` | gosec skips the module | expected for non-Go trees |
| `.csproj` / `.sln` | `dotnet restore` resolves nothing, so the audit finds nothing | expected for non-.NET trees |

> **The workflow will never create these for you.** Generating a lockfile so a scanner stops
> complaining converts *"we cannot establish this"* into *"we quietly changed the project until we
> could."* Three cases, and they are different: the project genuinely should have the artifact
> (add it); a scanner-specific prerequisite (adapt the scanner, or use another); or a legacy layout
> where the artifact makes no sense (scan what can be scanned and **state the coverage boundary**).

---

## 4 · Publication ≠ detection

### "Resource not accessible by integration" on SARIF upload

**Symptom:** scanners succeed, then every job fails on `github/codeql-action/upload-sarif`.

**Cause:** code scanning is free on **public** repos and otherwise requires GitHub Advanced Security,
which is sold to organisations on Enterprise plans. **A personal account cannot buy it for private
repos.** Treating upload as mandatory turned ten successful scans into ten failed jobs.

**Fix:** publication is optional and never decides whether a scan passed. The order is fixed:

```
scanner executes → result evaluated → gate derived → findings persisted → publication attempted
```

When publication is unavailable you get `ANALYSIS=COMPLETE`, `GATE=PASS|FAIL`,
`PUBLICATION=DEGRADED` — **never** `SCAN=FAILED`. Findings are always written as a
`sarif-<category>` build artifact, so an absent Security tab costs you triage convenience, not
evidence.

### A job that fails with ZERO steps

Not a workflow bug. Something refused to start it:

- **environment protection rule** — *"Branch X is not allowed to deploy to Y"*
- **billing** — *"recent account payments have failed or your spending limit needs to be increased"*

They look identical at a glance and both read like flaky CI. **Read the run's annotation, not the
logs** — there are no logs, because nothing ran.

---

## 5 · References that were never valid

### "Unable to resolve action …"

**Cause:** a `uses:` ref that does not exist. This kit shipped `aquasecurity/trivy-action@0.28.0` in
**six** places for weeks — upstream tags are `v`-prefixed. Tool-level probes never caught it because
they install the Trivy *binary* and never resolve the action reference.

**Fix:** **resolve every ref against upstream, never write one from memory.** The rule `PINNING.md`
already stated for SHAs applies to tags.

```bash
gh api repos/<owner>/<repo>/git/refs/tags/<tag> --jq .object.sha   # exists?
```

### "requires go >= 1.25.8 (running go 1.22)"

**Cause:** installing a scanner with `go install …@latest` couples the **scanner** to the
**consumer's** language toolchain. Nobody should have to upgrade Go to run a security scanner.

**Fix:** scanners run from pinned containers, decoupled from the application runtime. The toolchain
used to scan must not silently redefine the supported runtime of the application.

### "workflow not found" when calling the kit from another repo

**Cause:** a private repo's reusable workflows are invisible to every other repo until the
**providing** repo opts in. The error blames the path, never the setting.

**Fix:** on the **kit** repo — Settings → Actions → General → Access, or:

```bash
gh api -X PUT repos/<ORG>/secure-cicd-kit/actions/permissions/access -f access_level='organization'
```

There is **no cross-organisation sharing of a private kit**. Each org hosts its own instance — which
is why every environment-specific value is an input.

---

## 6 · Azure OIDC

| Error | Meaning | First thing to check |
|---|---|---|
| `AADSTS70025` | **Zero** federated credentials on the app | creating the app registration does not create a credential |
| `AADSTS700213` | A credential exists, no subject matches | **`Entity type` FIRST.** A `Branch` credential can never match a job declaring `environment:` |

**Editing a federated credential replaces it.** Repointing one from `dev` to `prod` leaves you with a
working `prod` and a broken `dev`. You need **one credential per environment**.

**Never trust ambient cloud context.** `az account show` reports whatever profile is cached locally —
possibly a former client's, possibly years stale, possibly unreachable. Assert observed tenant /
subscription / identity against declared values *before* any mutation. `verify-azure-oidc.yml` is the
reference implementation.

---

## 7 · Fixtures rot

The `clean` control fixture pins current, non-vulnerable dependencies. **It is expected to go stale
and start failing** — `urllib3 2.2.3` acquired four HIGH advisories within hours of being pinned as
clean.

When that happens: **bump the pin.** Never raise `fail_on_severity`, never point the clean control
somewhere quieter, never mark it soft-fail. Each of those converts a true positive into a silent one,
in the file whose only job is proving the gate does not fire on clean input.

**Clean fixtures are time-sensitive evidence, not static truth. A newly discovered true positive
invalidates the fixture, not the scanner.**

---

## 8 · When the kit reports red on YOUR repository

**Workflow correctness and security posture are different questions.** A run that correctly finds
real vulnerabilities is a **successful test of the kit** and a failed security assessment of the
repository. Classify before changing anything — see
[`FINDING_CLASSIFICATION.md`](FINDING_CLASSIFICATION.md).

Only `KIT_DEFECT` is fixed by changing the kit. Never adjust scanner configuration merely to make a
real run green.

## The run that never ends

Observed 2026-08-18: two jobs stalled during dependency acquisition and sat `in_progress` for three
hours while every other job in the run completed normally.

- **Signature:** everything green except one job pinned at `in_progress`, its current step never
  completing. Check `started_at` on the incomplete job — a long run is not necessarily a slow run.
- **Cost:** an unbounded job runs to GitHub's **360-minute** default. Estimated ~386 billed minutes
  from that single incident.
- **Classification:** `EXECUTION_UNAVAILABLE`. The scanner never produced a result, so the security
  posture cannot be determined from that run. It is **not** a finding and **not** clean.
- **Now bounded:** every non-mutating job carries `timeout-minutes`. Mutating jobs deliberately do
  not — see `ROLLBACK_CONTRACT.md`.
- **Still open:** the bound stops the cost; it does not yet produce the right *state*. A timeout
  currently reads as a plain job failure.

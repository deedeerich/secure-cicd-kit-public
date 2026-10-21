# Pipeline ordering, and what makes a scan valid

**The sequence a run must execute in, and the two checks that bracket the scanners: can this tool
read this code, and did this report come from a tool that read anything.**

```
Phase: design — a written contract, not an implementation
Truth State: modelled 2026-09-23 from the owner's handwritten ordering notes, against the
             workflows as they stand in this tree and the registered vocabulary in
             secure-cicd-kit/assurance-taxonomy.yaml (v1)
Audience: whoever builds the ordering, and whoever has to explain a zero-finding scan
Decision Supported: what runs before what and why; what discovery must establish beyond
             presence; what makes a SARIF trustworthy as evidence of coverage; what a
             coverage figure is allowed to claim; how a run without Advanced Security
             reports in the same words as one with it
Deferred Depth: the job topology and its cost · the ticketing contract · the finding
             baseline · the rung ladder
```

> **Nothing described here is built.** Not the version probe, not the capability table, not the
> validity check, not the file-level denominator, not the parity normaliser. This document exists
> so that when they are built they are built once, and in the right order relative to each other.
> The kit's own rule applies to this file first: **registering a term is not implementing it, and
> writing it down does not make it so.**
>
> **No vocabulary is coined here.** Every enforcement word used below is already registered in
> `assurance-taxonomy.yaml`. Where the design needed a word the registry did not have, the design
> was changed rather than the registry — see §7.

---

## 0 · What this settles, and what it deliberately does not

**Settled here:** the order of the run and the reason each position is where it is; which half of
the owner's ordering the kit currently inverts and which of the two is right; what `discover` must
establish beyond presence and how each language's version is detected; what happens when a version
cannot be detected; what a capable-tool-absent answer is and when it must be declared; what makes a
SARIF trustworthy as evidence that something was looked at; what state a zero-finding,
zero-artefact SARIF is in; what a file-level coverage denominator would cost and what weaker claim
is affordable instead; and how a run without GitHub Advanced Security reports in the same
vocabulary as one with it while the provenance still records which produced it.

**Settled by measurement rather than by argument, which is the part of this document to trust most:**
§3 reproduces the defect on the scanner this kit actually invokes, and establishes from vendor
documentation and source what each of the other scanners does with input it cannot read. Six of eight
tool groups can report a clean zero having parsed nothing.

**Not settled here, and named as unsettled in §8:** CodeQL's behaviour above its declared language
ceiling, which is documented only negatively; whether a version probe can be made cheap enough to run
where it needs to run; whether requesting a second output format from every scanner is affordable,
which §3's findings make unavoidable and which belongs to the topology work; the landing-zone
deployment mapping, which lives outside both repositories; and every number.

**Deliberately out of scope, because three other pieces of work own them:** the job topology and
its cost model; the ticketing contract; and the enforcement rung and finding baseline, which
`ENFORCEMENT_TIERS_AND_FINDING_BASELINE.md` already settles. This document is the sequence and the
validity of a scan. Where it touches enforcement it defers to that document rather than restating
it.

---

## 1 · The ordering contract

### 1.1 The owner's order, as written

```
1  discovery
2  validation of toolsets as well as code versions
     -- code versions FIRST and then toolsets, to ensure the tool is capable of
        scanning what is required
3  identification of exactly what tools to run
4  the harness, guardrails, hooks and other files for developers and security/governance
5  per team size and environment
6  true SARIF files, checked for content befitting and not just error methods
7  gates based on environment; deployment method
```

### 1.2 The first correction: this is two orderings, not one

Positions 4 and 5 are not run-time positions. The harness — `developer-safety/hooks/`,
`developer-safety/branch-protection/{solo,small-team,critical-service}.json`,
`developer-safety/codeowners/`, the pull-request template, the baseline gitignore — is **emitted at
adoption and executes at commit time**, on the developer's machine, before a run exists. Sizing it
by team pattern and environment tier is real and is exactly what those three branch-protection
profiles already do; it just does not happen between "pick the tools" and "check the SARIF".

So the list resolves into two sequences that meet at one point:

```
ADOPTION SEQUENCE  (once per repository, re-run when the shape changes)
  A1  establish team pattern and environment set
  A2  emit the harness sized to them -- hooks, branch protection, CODEOWNERS, templates
  A3  register the policy: rung per (repo, environment), cherry-picks, profile

RUN SEQUENCE  (every run)
  R1  applicability -- what artefact classes are here
  R2  applicability, version half -- what version each is written for
  R3  capability -- for each (class, version), is a configured tool able to read it
  R4  selection and depth -- exactly which tools run, how hard
  R5  execution
  R6  validity -- did each report come from a tool that read something
  R7  enforcement -- gate by environment tier, under the registered rung

  MEETING POINT: A3's registration is read at R7, from the protected default branch.
```

**Why this split matters and is not pedantry.** The hooks are the only control in the kit that runs
*before* material reaches a remote. The owner's separate note — *"Secrets need to continue to be
handled redacted and cannot be pushed up ever. No matter environment etc."* — is a requirement on
A2, not on R5. A secret that reaches the run has already defeated it; the run's job is then
detection, redaction and refusal to publish, which is a second line and must be described as one.
Placing the harness inside the run sequence would make it look like a scanner, and a scanner is
exactly what it is not.

### 1.3 The run sequence, with the reason for each position

Named against the axis vocabulary already in `AXES_AND_PHASES.md`, which defines six axes and
warns that contaminating one with another is the defect.

| # | phase | axis it settles | why it cannot move earlier | why it cannot move later |
|---|---|---|---|---|
| **R1** | **applicability — presence** | APPLICABILITY | nothing to point a tool at until the scope is surveyed | every later phase is scoped by it; a tool chosen before presence is a tool chosen by configuration |
| **R2** | **applicability — version** | APPLICABILITY | a version is a property *of* a discovered class; nothing to version before R1 | R3 cannot ask "does the tool support it" without an "it". **This is the position the kit does not have.** |
| **R3** | **capability** | APPLICABILITY | needs R2's answer | putting it after R5 is the defect: it turns a pre-declarable gap into a zero that looks clean |
| **R4** | **selection and depth** | APPLICABILITY x DEPTH | needs R3 so an incapable tool is not selected as though it were capable | a tool selected after it ran is not a selection |
| **R5** | **execution** | — | — | — |
| **R6** | **validity** | — | the evidence does not exist until R5 finishes | enforcing on an unvalidated report is enforcing on an unread file |
| **R7** | **enforcement** | ENVIRONMENT CONSEQUENCE x TEAM PATTERN | needs R6, or it gates on evidence of unknown standing | it is the last thing in the run by construction |

Two properties of the table are load-bearing.

**R2 and R3 are inside APPLICABILITY, not beside it.** `AXES_AND_PHASES.md` says discovery decides
applicability, and the version question is an applicability question: a Python 3.13 file is not
applicable to an analyser that stops at 3.12 in exactly the sense the axis means — there is nothing
that tool can establish about it. Making version a fourth axis would have been the easy move and
the wrong one; it would put two decisions in one knob, which that document forbids.

**R6 is not an axis at all.** It is a property of the evidence, and it sits between the scanners and
the gate for the same structural reason the redaction step sits before the upload step in every
scanner job in `reusable-security.yml`: **order is the whole control.** A validity check after the
gate validates nothing while looking exactly like validation.

### 1.4 Where the owner's order and the kit's invert, and which is right

There is one genuine inversion, and it is not subtle once located.

**The kit fixes the toolset version first, as a caller input, and never establishes the code
version at all.**

`reusable-security.yml:119-153` declares `python_version` (default `3.12`), `node_version` (`20`),
`dotnet_version` (`8.0.x`), `go_version` (`1.22`) and `java_version` (`17`) as `workflow_call`
inputs. They are consumed by `actions/setup-python@v7` at `:3188` and `:3460`,
`actions/setup-node@v7` at `:3147`, `actions/setup-dotnet@v6` at `:4192`, `actions/setup-java@v5` at
`:4437` and `actions/setup-go@v7` at `:4647`. The `discover` job does not receive any of them — its
`env:` block at `:2110-2125` carries `${IN_PATHS}`, `${IN_LANGUAGE}`, `${IN_IAC_MODE}` and `${IN_ENABLE_IAC}`
and nothing else — and nothing anywhere compares an input against anything the repository declares.

That is the owner's order run backwards. The toolset version is settled by a default a caller
probably never changed, the code version is never asked, and the comparison that would connect them
does not exist. `version_applicability` already says so in the registry, in its own rule:

> **A SCANNER THAT RAN IS NOT A SCANNER THAT COULD READ THE INPUT.** Version support is established
> or it is a gap; it is never assumed from the scanner having exited zero.

**Her order is right.** The reason is not preference. A toolset version chosen before the code
version is known can only be chosen from a default or a guess, and a default that turns out to be
wrong is wrong *silently* — the interpreter installs, the scanner installs, the scan runs, and the
mismatch surfaces, if at all, as an absence. A code version established first constrains the
toolset choice to something that can be checked, and a check that fails is loud. **Ordering is what
converts a silent wrong answer into a noisy one**, which is the only thing ordering is ever for
here.

### 1.5 The second correction: "validation of toolsets" is two questions

The owner's position 2 says *validation of toolsets*. The kit has something called that, and it is
only one of the two things the phrase means. They must not collapse.

| | (a) does this tool work at all | (b) can this tool read THIS code |
|---|---|---|
| question | does the scanner detect what it claims to detect | does the scanner support the version in front of it |
| where it lives today | `validate-scanners.yml` | **nowhere** |
| when it runs | weekly, on dispatch, and on push to the kit's own paths (`validate-scanners.yml:17-33`) | — |
| what it runs against | a synthetic fixture the kit generates — `tests/make_fixture.py`, invoked at `validate-scanners.yml:64` | — |
| whose repository | the kit's | the consumer's |
| registered vocabulary | `capability_maturity.DETECTION_PROVEN`, `selftest_reach.EXERCISED_ON_SCHEDULE` | `version_applicability` |

**The fixture cannot answer (b), by construction.** `tests/make_fixture.py` writes the corpus, so
the corpus is written in whatever language version the kit chose — it declares no target version
for any ecosystem. A weekly green from that fixture establishes that bandit detects a hardcoded
password in code bandit can parse. It establishes nothing whatsoever about a consumer repository
targeting a newer Python. Reading (a) as (b) is the same class of error as reading a passing
self-test as coverage, which `a_node_is_not_a_path` already names.

**And (a) does not reach a consumer's run at all.** `validate-scanners.yml` is a workflow in the
kit's repository on the kit's schedule. A consumer calling `reusable-security.yml` never executes
it. So the strongest honest statement available to a consumer today is *the kit's maintainer proved
these detectors against the kit's fixture at some point in the last week* — which is worth having,
is `PRODUCER_UNVERIFIED_EXTERNALLY_DECLARED` from the consumer's side, and is not a per-run
capability claim.

### 1.6 What the kit does today, position by position

| owner's position | kit today | verdict |
|---|---|---|
| 1 discovery | `discover` job, `reusable-security.yml:2058-2676`. Seven closed presence probes plus an unsupported-language sweep plus a platform probe. | **MEETS**, for presence |
| 2a code versions | nothing | **MISSES** |
| 2b toolsets, meaning (b) | nothing | **MISSES** |
| 2b toolsets, meaning (a) | `validate-scanners.yml`, out of band, against a fixture | **PARTIAL** — real, and not the consumer's run |
| 3 which tools to run | per-job `if:` expressions reading `needs.discover.outputs.*` (`:3061`, `:3439`, `:3564-3567`, `:3870`, `:4171`, `:4416`, `:4626`, `:4917`) | **MEETS** |
| 4 the harness | `developer-safety/` exists and is emitted at adoption | **MEETS**, at A2 |
| 5 per team size and environment | branch-protection profiles exist; nothing in a run reads a team pattern or an environment tier. `AXES_AND_PHASES.md` says so plainly: "No environment tier concept exists anywhere in the kit… No team-pattern concept exists." | **PARTIAL** |
| 6 true SARIF checked for content | file non-empty plus one `jq` expression. §3. | **PARTIAL**, and this is the weakest link |
| 7 gates by environment | `security-gate` reads job results only; no tier input exists | **MISSES** |

**The ordering itself is also absent.** Every scanner job carries `needs: [discover, kit-scripts]`
and nothing else — grep the file and the dependency graph is one fan-out and one fan-in.
`AXES_AND_PHASES.md` already recorded this: *"This kit currently has no stage model at all — every
scanner hangs off `discover` and runs in parallel."* That is a cost and topology matter and it
belongs to the topology work, not here. What belongs here is the consequence: **R2, R3 and R6 have
nowhere to attach**, because there is no position between `discover` and the scanners and no
position between the scanners and the gate. The sequence has to exist before the checks can be put
in it.

---

## 2 · The pre-scan capability check

> `ARTIFACT_PRESENT` + `CAPABILITY_REQUIRED` + a tool that cannot read the version =
> **`COVERAGE_GAP`, declared before the scan.**

### 2.1 What discovery must additionally establish

`discover` currently emits seven booleans — `python`, `node`, `go`, `dotnet`, `java`, `cpp`, `iac`
(`:2073-2079`). It must additionally emit, per discovered class, a **target version** and **the
evidence it came from**. Not the version the runner installed: `version_applicability` is explicit
that these are different facts, and the registry's own example is this kit's exact configuration —

> Distinct from the version the runner installed. A repo can target 3.13 while the workflow sets up
> 3.11, and then every scanner is reading code written for a version it was never handed.

The kit's defaults make that the *likely* case, not a hypothetical: `python_version` defaults to
`3.12` and `go_version` to `1.22`, values a consumer inherits by saying nothing.

### 2.2 How each version is detected, and at what strength

Detection is not one mechanism. Each ecosystem declares its target in a different place, with a
different degree of authority, and the difference has to survive into the record — a version read
from a lockfile is a stronger claim than one read from a loose range in a manifest.

| class | ordered sources, strongest first | what the source proves | weakest case |
|---|---|---|---|
| **python** | `.python-version`; `pyproject.toml` `requires-python`; `setup.cfg` / `setup.py` `python_requires`; `tox.ini` envlist; a `Dockerfile` base image tag; `runtime.txt` | an exact pin proves the target; `requires-python = ">=3.9"` proves only a **floor**, and a floor is not a target | only a floor, or nothing |
| **node** | `package.json` `engines.node`; `.nvmrc`; `.node-version`; `volta.node`; `package.json` `type` and the TypeScript `compilerOptions.target` in `tsconfig.json` for syntax level | `engines` is advisory in npm and frequently absent or stale; `tsconfig` target is the better syntax-level signal for TypeScript | nothing, which is common |
| **go** | `go.mod` `go` directive; `go.mod` `toolchain` directive | the `go` directive is a **language version** declaration and is mandatory in a module — the strongest signal of any ecosystem here | absent only if there is no module |
| **dotnet** | `*.csproj` / `Directory.Build.props` `TargetFramework(s)`; `global.json` `sdk.version`; `LangVersion` | `TargetFramework` is mandatory and exact; `LangVersion` may be `latest`, which is a moving target and must be recorded as one | `LangVersion: latest` |
| **java** | `pom.xml` `maven.compiler.release` / `source` / `target`; `build.gradle` `sourceCompatibility` / `toolchain`; `.sdkmanrc` | usually present and exact | a Gradle toolchain resolved at build time, not statically readable |
| **cpp** | `CMakeLists.txt` `${CMAKE_CXX_STANDARD}` / `target_compile_features`; `-std=` in a `Makefile` or `compile_commands.json` | varies wildly; a mixed tree can hold several standards at once | very often nothing |
| **iac** | `terraform` block `required_version`; provider `required_providers` constraints; `Chart.yaml` `apiVersion`; Bicep target scope | `required_version` is a constraint, not a pin | a constraint range |

Three rules govern the table.

**A constraint is not a version.** `">=3.9"`, `"^20"`, `"~> 5.0"` each name a set. The set's
**lower bound** is the only thing established, and a capability answer computed against a lower
bound establishes that the tool can read the *oldest* permitted version — which is precisely the
version the code is least likely to be written in. A constraint therefore yields
`VERSION_SUPPORT_UNDETERMINED`, not a satisfied check, unless the whole constraint set is inside
the tool's supported range.

**Multiple answers do not average.** A monorepo with three `TargetFramework` values has three
target versions. The capability question is asked per root, and a repository where one root is
supported and another is not is `VERSION_UNSUPPORTED` for that root and supported for the other.
Collapsing to a single repository-wide version is how the unsupported root disappears — the same
shape as the `gosec` two-files-one-identity defect already in this kit's record.

**The probe obeys the same rule every other probe in `discover` already obeys.** "Found nothing" and
"could not look" are different answers, and `discover`'s `probe()` function at `:2164-2191` is built
around exactly that distinction, with per-probe sentinel files because an earlier version threw the
answer away at a subshell boundary. A version probe that cannot read a manifest must set its own
sentinel, not return an empty string.

### 2.3 What happens when a version cannot be detected

**It resolves to `VERSION_SUPPORT_UNDETERMINED`, and that is a gap.** Not "assume supported", and
not "assume unsupported" either.

The registry already fixes this and the wording is not negotiable:

> Treated as a gap, never as support. Could-not-establish is not established-absent and is
> certainly not established-present — the same rule as a failed discovery probe.

The governing invariant is `defaults_are_suspicious_at_assurance_boundaries`: *"there is NO implicit
default from unknown to known."*

What a gap means operationally, and this is the part that keeps the design usable:

- **The scanner still runs.** `UNDETERMINED_PRESENT` already establishes the precedent — a failed
  presence probe force-enables the scanner rather than skipping it, because over-scanning is a cost
  problem and under-scanning reported green is not. The same logic applies one level down.
- **Its result may not be reported as evidence of coverage.** The scanner contributes
  `scanner_state.PARTIAL` — *"Executed, but a prerequisite was missing so the security CLAIM is NOT
  established"*, whose registered `forbidden` clause is exactly the failure mode here: it **MUST
  NOT** be projected, summarised or rounded into `PASS`.
- **The repository is told which file to add.** A `VERSION_SUPPORT_UNDETERMINED` on Python because
  no `.python-version` and no `requires-python` exists is closed by the repository adding one. That
  is a cheap, actionable, one-line remediation, and saying so is the difference between a control
  and an obstacle.

**Assume-supported is the one answer that is forbidden**, because it is the answer that reproduces
the defect. It converts an unasked question into a satisfied one and leaves no trace that anything
was assumed.

### 2.4 The matching step, and the four answers it can give

For each discovered `(class, version, root)`, against each **configured** tool for that class:

| answer | condition | state | run the tool? | reported as |
|---|---|---|---|---|
| supported | the target version is inside the tool's declared range | `SCANNER_SUPPORTS` | yes | ordinary coverage |
| unsupported | the target version is outside it | `VERSION_UNSUPPORTED` | **yes, and its output is not coverage** | `COVERAGE_GAP`, declared **before** the scan |
| undetermined | the tool's range is unknown, or the target version is unknown, or the target is a constraint spanning the boundary | `VERSION_SUPPORT_UNDETERMINED` | yes | a gap, `scanner_state.PARTIAL` |
| no tool at all | no configured tool claims this class | `SCANNER_UNAVAILABLE` | — | `COVERAGE_GAP`, as today |

**Each tool declares its own range. There is no kit-wide table.** The registry says why, and it is
the right reason:

> Declared PER SCANNER, never kit-wide. bandit, semgrep, CodeQL, gosec and trivy each have their
> own range, and a single shared table would be a convenient fiction whose first exception is
> silently wrong.

**Why `VERSION_UNSUPPORTED` still runs the tool.** Because a tool outside its range is not
guaranteed to find nothing — a lexical scanner may still work perfectly, and even a parser-based one
may handle most of a tree. Suppressing it discards real findings. What changes is not whether it
runs but **what its silence is allowed to mean**: a `VERSION_UNSUPPORTED` scanner reporting zero
contributes findings if it has them and contributes **no coverage claim** if it does not. Findings
from it are still findings. Absence from it is not absence.

**Why the gap is declared before the scan and not after.** This is the whole point of the position
in the sequence. After the scan, the gap has to be *inferred* from a zero — and a zero has three
causes (clean, unsupported, broken) that the number cannot distinguish. Before the scan, it is a
**derived fact from two established values**, needing no inference at all. The same move
`discover`'s `coverage_gaps` already makes for artefact classes, applied one level finer.

### 2.5 The four states, and the fourth thing

`NOT_APPLICABLE`, `CLEAN` and `COVERAGE_GAP` never collapse. The version work does not add a fourth
member to that set — `VERSION_UNSUPPORTED` is a **cause** of `COVERAGE_GAP`, not a peer of it, and
the registry says so: *"a member of the same family as `COVERAGE_GAP`."*

The genuine fourth thing is the turned-off scanner, and it is already registered twice over because
the two ways of turning one off are different acts:

| state | what it is | whose action | may it read as `CLEAN`? |
|---|---|---|---|
| `NOT_APPLICABLE` | searched, none found | nobody's | no — it is a different claim |
| `CLEAN` | a capable tool ran over it and found nothing | — | it **is** the claim |
| `COVERAGE_GAP` | the artefact is here and nothing capable looked | platform's | **never** |
| `discovery_state.DISABLED` | switched off for this run by configuration | the caller's | **never** — *"an exception, reported loudly, never a default"* |
| `platform_applicability.NOT_CONFIGURED` | available at the platform and switched off there | the platform owner's | **never** |

A turned-off scanner is a fourth thing again, and the kit already refuses to let it wear any of the
other three's clothes. `control_weakening.CONTROL_DISABLED` is what records the act of turning it
off, and `WEAKENING_UNATTRIBUTED` is what it becomes when nobody attached a reason.

---

## 3 · Is the version-capability defect real? Yes — demonstrated, not assumed

The hypothesis was: **a scanner can run, exit 0, emit structurally valid SARIF with zero results, and
have parsed nothing** — reporting `CLEAN` where the truth is `COVERAGE_GAP`.

**Verdict: REAL.** It was reproduced on this machine, on 2026-09-23, with the scanner this kit
actually invokes, and the reproduction is worse than the hypothesis in one respect and better in
another. Both matter.

### 3.1 The experiment, so it can be repeated

```
bandit 1.9.4 under CPython 3.11.9, invoked exactly as the kit invokes it:
    bandit -r <dir> -f sarif -o out.sarif

Corpus A  one file, parseable, containing a hardcoded password and shell=True
Corpus B  one file using PEP 695 syntax -- `type UserId = int` and `def identity[T](x: T)`
          -- which is Python 3.12+ and a SyntaxError under 3.11, containing the SAME
          hardcoded password and the SAME shell=True
Corpus C  one file, parseable, genuinely clean
```

The version gap is the point: PEP 695 is valid Python that a 3.11 interpreter cannot parse. Bandit
builds its AST with the `ast` module of the interpreter it runs under, so its language-version
ceiling **is** that interpreter's. This kit's `python_version` input defaults to `3.12`
(`reusable-security.yml:123`), so the same experiment against a repository targeting 3.13 or 3.14 is
the identical situation one minor version along — and CodeQL's documented Python support runs to
**3.14** ([Supported languages and frameworks](https://codeql.github.com/docs/codeql-overview/supported-languages-and-frameworks/)),
so the two scanners pointed at the same file have different ceilings. That is the registry's reason
for insisting the range is declared per scanner, arriving as a measurement.

### 3.2 What corpus B produced

```
exit code                                   0
runs[].results                              []          (empty array, not null)
runs[].invocations[].executionSuccessful    true
runs[].tool.driver.rules                    []          (zero rules)
runs[].artifacts                            ABSENT
file non-empty                              yes
jq '[.runs[].results[]] | length'           0
```

Console output, in full: `No issues identified.` … `Total lines of code: 7` …
`Files skipped (1): modern.py (syntax error while parsing AST from file)`

**Every check the kit performs passes.** `[ -s bandit.sarif ]` is true, so the publication step sets
`exists=true` (`:3478-3489`). The `jq` expression succeeds, so `scan_status.sh` prints
`Findings: 0` and `SARIF: GENERATED`. The job exits 0, so `security-gate` maps `success` to `PASS`
(`:5996`). **The run is green over a file containing a hardcoded credential and a shell injection,
and the credential was never looked at.**

Corpus A, for contrast, produced three findings and `rules` of length 3. Corpus C — genuinely clean —
produced `results: []`, `rules: []`, `executionSuccessful: true`, no `artifacts`.

**A fourth corpus makes the loss concrete rather than structural.** Two files in one directory, each
holding the same pair of secret-shaped literals — an access key id and a secret access key — one file
parseable and one using PEP 695. Bandit reported **one** finding, from the parseable file only, plus
the notification. The identical secret material in the second file was not reported, and the run
exited 0. **The thing the scanner missed was a credential**, which is the one finding class the owner's
notes make unconditional, and nothing in the report said a file had been skipped except the
notification nobody reads.

### 3.3 The two corrections the experiment forces

**Correction one: a rules count does not discriminate, at least not for this scanner.** Corpus B and
corpus C both produced a rules array of length **zero**. Bandit populates `tool.driver.rules` only
with rules that actually fired, so for bandit the rule count is a function of findings and carries no
information about coverage at all. A validity rule that required a non-zero rules count would fail
every genuinely clean bandit run and would therefore be switched off. This is why §4.4 of this
document declares the validity profile per tool: the same check is informative for one producer and
actively wrong for another.

**Correction two — and this is the better news — the skip IS disclosed, in SARIF, naming the file.**
Corpus B's invocation object carried:

```
"toolConfigurationNotifications": [
  { "message": { "text": "syntax error while parsing AST from file" },
    "level": "error",
    "locations": [ { "physicalLocation": {
       "artifactLocation": { "uri": "vtest2/modern.py" } } } ] } ]
```

That is exactly the mechanism §4.2 identified: a notification object, at `level` error, with
`notification.locations` (SARIF §3.58.4) naming the artefact. It is present, it is precise, and
**nothing in this kit reads it.**

Three details of that disclosure change the design and none of them is obvious:

**It is in `toolConfigurationNotifications`, not `toolExecutionNotifications`.** A check written
against the obvious array — the one the owner's note names — would have missed it entirely. Both must
be read. SARIF §3.20.22 gives them the identical `level` error rule, so reading both is correct and
not a concession.

**`executionSuccessful` is `true` while an error-level notification is present, and that is
self-contradictory under the spec.** SARIF §3.20.21-22 say the presence of an error-level notification
**SHALL** mean the run failed; SARIF §3.20.14 has bandit asserting it succeeded. A consumer reading
only `executionSuccessful` — the format's one mandatory success assertion — is told the run was fine.
**So `executionSuccessful` alone is not a sufficient check, and the notification arrays are the
authority where they disagree**, because the spec's `SHALL` is on the notification side.

**`properties.metrics` is an enumeration manifest and must never be mistaken for a coverage
manifest.** Bandit publishes a per-file record in `runs[].properties.metrics`, keyed by path — corpus
C shows `{"clean.py": {"loc": 2, ...}}`. It looks exactly like the artefact inventory §5.2 wants. It
is not: **corpus B's metrics list the skipped file, with `loc: 7`.** Bandit counted the lines of a file
it could not parse and reported them in the same structure as the file it did parse. Using
`properties.metrics` as proof of coverage would report the unread file as read — a fabricated
positive, produced by the one structure that looked like the answer.

### 3.4 Semgrep, tested the same way, behaves differently in every respect that matters

`semgrep 1.178.0`, invoked as the kit invokes it —
`semgrep scan --config … --sarif --output … --metrics=off <scope>` (`:3302-3303`, `:4489-4490`).

**Semgrep parses PEP 695 fine.** On corpus B it reported `Parsed lines: ~100.0%`, `Targets scanned: 1`
and found the hardcoded token. It has its own parser rather than CPython's, so its Python ceiling is
independent of the interpreter it is installed under. **Two scanners, one file, opposite answers** —
and neither answer is wrong, which is the entire case for a per-scanner range.

**On genuinely unparseable code it loses the finding and says so only at `warning` level.** A fourth
corpus — a file whose line 2 holds the same hardcoded password and whose line 4 is not Python at all
— produced:

```
console        Findings: 0 · Rules run: 151 · Targets scanned: 1 · Parsed lines: ~75.0%
SARIF          results: []
               invocations[].executionSuccessful: true
               invocations[].toolExecutionNotifications:
                 [{ descriptor.id: "Syntax error", level: "WARNING",
                    message: "Syntax error at line broken.py:4 ..." }]
               artifacts: ABSENT
```

**The password on line 2 was not reported.** A partial parse silently dropped a finding the tool
would otherwise have made, and the only trace in the SARIF is a **`warning`**, which under
SARIF §3.20.21 does **not** mean the run failed. So a validity rule that escalates on `level` error
alone would read this as a clean scan — and §4.3's UNVERIFIED note about which level a tool should use
is not a theoretical gap. **It is the live behaviour of the kit's highest-yield scanner.**

**`--strict` is the lever, and the kit does not use it.** Semgrep's documented exit codes give `3` for
*"Invalid syntax of the scanned language"* **only with `--strict`**
([CLI reference](https://docs.semgrep.dev/cli-reference/)); `--error` raises the code on *findings*
and does nothing for parse failures. That matches the source: parse errors are assigned
`` `Warning `` severity in `src/core/Core_error.ml`, and `output.py`'s `_final_raise` re-raises a
warning-level error only when `--strict` is set. **`--strict` is absent from every Semgrep invocation
in this kit** (`:3302-3303`, `:4489-4490`, and the C# and Java jobs) — so every parse failure in every
Semgrep run is currently a silent zero.

**A correction to my own experiment, and it makes the kit's position worse rather than better.** The
run above was Semgrep **1.178.0**. The kit pins **`semgrep/semgrep:1.90.0`** (`:3262`). The
`Targets scanned:` and `Parsed lines: ~N%` summary lines **do not exist at 1.90.0** — they were added
later. At the pinned version the only console trace is the sentence *"Some files were skipped or only
partially analyzed."* with a partially-scanned fragment, printed to stderr, **which a SARIF-only
pipeline discards entirely.** So the parse-rate evidence I measured is not evidence available to this
kit today, and reporting it as though it were would have been the same error the document is about.

**The richer evidence exists at both versions and the kit throws it away.** Semgrep's JSON output
carries `errors[].type: ["PartialParsing", [spans]]` with exact line and column, and `paths.skipped`
**when `--verbose` is set**. The kit requests only `--sarif`. Three additions — `--strict`,
`--json-output` alongside `--sarif`, and `--verbose` — would convert every silent Semgrep parse
failure into a loud one and put a real skip list in reach. **That is the cheapest unbuilt thing in
this document.**

**One trap to avoid while doing it: `paths.scanned` is not a parsed-file list.** My corpus-four run
showed the unparseable file listed under `paths.scanned`, and Semgrep's own source carries the
maintainers' comment on that field — *"This is incorrect when some rules are skipped by
semgrep-core"*, with a `TODO` to use what the core actually returns. The one honest number, a
per-language parse rate computed in `metrics.py`, is sent to Semgrep's telemetry endpoint and reaches
neither the JSON nor the SARIF. **A file listed as scanned was not necessarily parsed**, which is the
same false-coverage shape as bandit's `properties.metrics`, in a second tool.

### 3.5 CodeQL: documented at the edges, undocumented exactly in the middle

**Declared version support is published and current**
([Supported languages and frameworks](https://codeql.github.com/docs/codeql-overview/supported-languages-and-frameworks/)),
though only for the *latest* CodeQL, with per-release deltas in the
[changelog](https://codeql.github.com/docs/codeql-overview/codeql-changelog/):

| language | declared support, as fetched 2026-09-23 |
|---|---|
| Python | "Python 2.7, 3.5 … 3.13, 3.14"; "The extractor requires Python 3 to run" |
| JavaScript | "ECMAScript 2022 or lower" |
| TypeScript | "2.6-7.0", standard TypeScript compiler |
| Java | "Java 7 to 26" (javac, ECJ) |
| C# | "C# up to 14"; .NET up to 10 |
| Go | "Go up to 1.27"; requires "Go 1.11 or more recent" |
| C/C++ | "C89 … C23, C++98 … C++23"; Clang up to 22, GCC up to 16. Footnote: "C++20 modules are _not_ supported"; "C23 and C++23 support is currently in beta" |

**Total extraction failure fails loudly.** Documented, with the exact strings:
`Error: "No source code was seen during the build"` and `failed with exit code 32`, across six named
causes
([No source code seen during build](https://docs.github.com/en/code-security/reference/code-scanning/troubleshoot-analysis-errors/no-source-code-seen-during-build)).
The CLI has a counterpart string — `CodeQL detected code written in Go but could not process any of
it`, exit 32, from `database finalize` — which appears in GitHub's own issue tracker
([codeql-action#2186](https://github.com/github/codeql-action/issues/2186)) and **not** in the
documentation. So: if CodeQL extracts nothing at all, the kit's `cq_analyze` step fails and
`cq_state` correctly emits `COLLECTION_FAILED` (`:3683-3686`). That path is sound.

**Partial extraction is documented as tolerated, with no threshold, and that is the hole.**
[Extraction errors in the database](https://docs.github.com/en/code-security/reference/code-scanning/troubleshoot-analysis-errors/extraction-errors-in-the-database):
*"A small number of extractor errors is healthy and typically indicates a good state of analysis."*
The guidance is to investigate only on *"extractor errors in the overwhelming majority of files."*
**There is no documented point at which CodeQL escalates**, and the documented error catalogue — some
twenty entries — contains **no** entry for an unsupported language version. So the state where most
of a tree was skipped and the analysis exited 0 with few alerts is, by design, not an error. **The
scanner will not fail the build for it, and a capability layer must therefore measure coverage
itself.**

**UNVERIFIED: what CodeQL does with syntax above its declared ceiling.** No GitHub or CodeQL page
states it. There is no `--max-errors` and no `--fail-on-extraction-errors` in the
[`database create`](https://docs.github.com/en/code-security/reference/code-scanning/codeql/codeql-cli-manual/database-create)
manual. The nearest documented analogue is Kotlin in a no-build scan, where files are *excluded*
rather than erroring:
[Kotlin detected in no-build](https://docs.github.com/en/code-security/code-scanning/troubleshooting-code-scanning/kotlin-detected-in-no-build).
**The experiment that settles it:** build a database over a file using syntax above the ceiling, then
compare `codeql database print-baseline` and the `src.zip` in the analysis artifact against the source
tree. Until someone runs it, the design assumes the quiet-skip behaviour, which is the non-permissive
direction.

**CodeQL is the one scanner here that does expose a coverage figure, and it is not in the SARIF.**
Three documented mechanisms, all outside the report:

- **The tool status page** publishes *"File coverage percentages by programming language"*, and defines
  the measure: *"CodeQL reports a file as scanned if some lines of code in that file were processed"*
  ([Tool status page](https://docs.github.com/en/code-security/concepts/code-scanning/tool-status-page)).
  Zero coverage is documented as meaning *"You may have code in languages not currently being
  analyzed."* **This is the strongest coverage signal available to this kit from any scanner** — and it
  lives in the GitHub UI, so it exists only where code scanning is licensed, which §6 shows is not
  everywhere.
- **`codeql database print-baseline`**, whose documentation draws precisely the distinction this design
  needs: the baseline counts lines *"seen within the source root"* and *"is different from the lines
  of code counted by CodeQL metrics queries, which only counts code that is passed to the CodeQL
  evaluator."* **Enumerated minus analysed is the skip count**, from the tool's own two numbers.
- **`src.zip`**, an archived copy of the source files CodeQL actually scanned, shipped in the analysis
  artifact, with the documented technique of diffing it against the repository
  ([Fewer lines scanned than expected](https://docs.github.com/en/code-security/code-scanning/troubleshooting-code-scanning/fewer-lines-scanned-than-expected)).
  An exact extracted-file manifest.

**A defect in this kit's CodeQL job, found while checking, and it is one line.** The autobuild step
carries `id: cq_build` (`:3623`) and **its outcome is read nowhere.** `cq_analyze` requires only
`cq_init` to have succeeded (`:3630`), and `cq_state` branches on `cq_init` and `cq_analyze` only
(`:3675`, `:3683`). A partially successful autobuild — some modules compiled, others failed on a
toolchain mismatch, which is exactly what `java_version` defaulting to `17` against code targeting a
newer JDK would produce — leaves a partial database, an analysis that succeeds, and
`state=COMPLETE`. The step that knows is captured into an identifier and never consulted. **That is
`CONTROL_SURFACE_DEAD`'s shape applied to a step rather than an input**, and it is the documented
tolerated-partial-extraction case arriving through the kit's own wiring.

### 3.6 The rest of the suite, established from source and vendor documentation

Six of the eight tool groups can produce a silent zero. The verdicts below are from vendor
documentation and from the tools' own source, cited by file and line so each is checkable; what
remains genuinely open is marked and carries its experiment.

| scanner | silent zero on input it cannot read? | default exit on parse failure | the lever that hard-fails | coverage signal in its SARIF |
|---|---|---|---|---|
| **bandit** (`:3465`) | **yes — reproduced, §3.2** | **0** | **none exists** | notification, misfiled in the configuration array |
| **semgrep** 1.90.0 (`:3262`) | **yes — reproduced, §3.4** | **0** | **`--strict` → 3**, unused here | notification at `warning`, which is non-failing |
| **gosec** 2.24.6 (`:4683`) | **yes, as this kit invokes it** | 1 by default, **0 under `-no-fail`** | remove `-no-fail` | **nothing at all** |
| **Trivy** 0.36.0 (`:3734`, `:4061`, `:5346`) | **yes** | **0** | **none exists** | **nothing at all** |
| **Checkov** v12 (`:3903`) | **yes, twice over** | **0** | `${CKV_PARSE_ERROR_FAIL}`, env-only | **nothing** — parsing errors dropped |
| **cppcheck** (`:4974`) | **yes** | **0** | `--error-exitcode=N`, unset here | UNVERIFIED |
| **flawfinder** (`:5123`) | no parse, so version-immune — **yes via its extension list** | 0 | none that helps | **nothing**, and `--sarif` suppresses its line count |
| **ruff / mypy** (`:3215`) | **no — both fail loudly** | ruff **1**, mypy **2** | default is already correct | ruff carries it as a result; mypy emits no SARIF |
| **gitleaks / detect-secrets** (`:2885`, `:3026`) | no parse, so version-immune — **but both exit 0 having read nothing** | 0 | findings-only flags | gitleaks none; detect-secrets **has no SARIF support** |

Five of those rows say something this kit needs to act on rather than merely note.

**gosec: the kit's own invocation is what makes this one silent.** gosec's exit code covers findings
**and** processing errors in a single number — its `computeExitCode` returns failure when
`len(issues) > 0 || len(errors) > 0` — and package-load failures land in that `errors` map. The kit
runs it with **`-no-fail`** (`:4722`), which suppresses both. The comment above it (`:4699`) says
`-no-fail` *"keeps DETECTION separate from ENFORCEMENT"*, and for findings that is exactly right. For
**load errors it is not a separation, it is a deletion** — because gosec's SARIF formatter emits only
`data.Issues` and never populates the `Invocations` field its own type declares, so a Go module that
failed to load leaves **no trace in the report at all.** The kit's own note at `:4696-4698` already
records the live version skew — *"gosec now requires Go >= 1.25.8, this kit defaults go_version 1.22"*
— and Go's toolchain rule makes the failure real: *"The Go toolchain refuses to load a module or
workspace that declares a minimum required Go version greater than the toolchain's own version"*
([Go toolchains](https://go.dev/doc/toolchain)). Whether it is loud depends on a variable nobody set
deliberately: the official `golang` images ship `GOTOOLCHAIN=local`, which gosec's image inherits, so
the refusal happens rather than silently self-upgrading — and then `-no-fail` swallows it. **The fix is
to stop discarding the errors map while continuing to discard the findings exit code**, which means
reading gosec's JSON `"Golang errors"` map rather than relying on its exit status.

**Trivy: an unrecognised lockfile version yields zero packages at debug level.** The pnpm parser
returns `-1` for an unknown lock version with a `Debug` log and the caller then returns no packages;
`--exit-code` is documented as findings-only — *"By default, Trivy exits with code 0 even when
security issues are detected. Use the `--exit-code` option if you want to exit with a non-zero exit
code"* ([configuration](https://trivy.dev/docs/latest/guide/configuration/others/)) — and its
`Failed()` predicate counts only vulnerabilities, misconfigurations, secrets and licences. So the kit's
`exit-code: 1` (`:3745`) cannot fire on a zero-parse run. Trivy's SARIF writer emits only findings plus
a `ROOTPATH` base id, so **a forty-lockfile scan and a zero-lockfile scan differ by nothing in the
report.** The one tripwire exists and is on stderr: an `INFO` line reading
`Number of language-specific files num=0`. **That string is the cheapest single assertion available to
this kit for dependency coverage**, and nothing reads it.

**Checkov: two skip modes, and the dangerous one records nothing.** A hard HCL failure is collected
into `parsing_errors` by a function named, in the source, `load_or_die_quietly`. But blocks that parse
and do not match the shape Checkov expects are **filtered out with no error, no log and no
`parsing_errors` entry** — which is precisely the newer-Terraform case. Exit code ignores parsing
errors unless `${CKV_PARSE_ERROR_FAIL}` is set true — an environment variable with **no CLI flag and no
mention in Checkov's documentation** — and the kit sets `soft_fail: true` (`:3907`) besides. Checkov's SARIF writer
emits only failed and skipped checks — **not passed checks and not parsing errors** — so 500 passing
resources and 0 parsed resources produce identical SARIF. The only honest channel is JSON's
`summary.resource_count`, which the kit does not request.

**flawfinder is version-immune and blind for a different reason, and `--sarif` is what blinds it.** It
*"works by doing simple lexical tokenization"* and can *"find vulnerabilities in programs that cannot
be built"*, so no language standard can break it — but it *"only opens and examines regular files that
have C/C++ filename extensions"* from a fixed list that excludes `.cppm`, `.ixx`, `.hh`, `.hxx`,
`.tcc` and `.cu`. A C++20 module interface is silently not a C++ file. Its `Lines analyzed = N`
summary would catch that, and in the source the `--sarif` branch returns before
`show_final_results()` is reached — **so the one number that would have shown zero coverage is exactly
the number a SARIF pipeline throws away.**

**ruff and mypy are the two that get it right, and they are the two that are not security controls.**
Ruff exits 1 on a syntax error and carries it into SARIF as an `invalid-syntax` result; mypy exits **2**
— distinguishable from a type error's 1 — with a targeted hint naming the interpreter version needed.
Worth knowing anyway: on a hard parse error ruff runs only its token-based rules and skips the
AST-based ones, so a ruff run can be simultaneously loud about the syntax and quiet about everything
the AST rules would have found.

**The secret scanners: the version question is settled; a worse question replaces it.**
`detect-secrets` contains no use of Python's `ast` module anywhere in its codebase — its design
document describes plugins as *"codified rules to scan an arbitrary string / line"* — and gitleaks is
regex plus Shannon entropy with a keyword prefilter. **So the §5.4 premise holds: neither is gated by
language version.** But both exit 0 having read nothing, in ways this kit is exposed to:
`detect-secrets scan` returns 0 unconditionally; its default scope is git-tracked files and a failed
`git ls-files` is swallowed to an empty set, producing `"results": {}` with no log; and its baseline
output records only files **with** findings, so fifty thousand clean files and zero files are
bit-identical. gitleaks exits 0 when zero bytes were scanned and prints `scanned ~0 bytes` — a real
signal, on stderr, that nothing reads. **`detect-secrets` also has no SARIF output at all**, which
means §4's validity rule cannot apply to it even in principle.

**My own earlier attempt at this row failed and the failure is worth keeping.** `detect-secrets` 1.5.0
reported zero over every corpus here, including a parseable file holding a well-known example access
key id and secret access key that bandit found in the same directory on the same run — and it emitted
`fatal: not a git repository`, which is very likely the swallowed-`git ls-files` path described above
walking into my own experiment. So the experiment had **no positive control** and could not have
discriminated anything. The mechanism question is now settled from source; **the invocation question is
not, and it is the more alarming of the two**, because the kit runs `detect-secrets` inside a checkout
where that path is reachable. An experiment that returns zero for the wrong reason is the same defect
as a scanner that does.

**Still genuinely open:** whether cppcheck's `checkersReport` and `noValidConfiguration` messages —
the ones that render as `Active checkers: There was critical errors` — survive into its SARIF output
(`--output-format=sarif`, added in 2.16.0). The experiment is one command: run it over a file with a
deliberate `syntaxError` at `--enable=information` and grep the SARIF for `checkersReport`. Also open:
whether a Go package that fails **type-checking only** is dropped by gosec before its error is
recorded, which would make even the JSON errors map insufficient.

### 3.7 What the evidence changes

**The defect is not a family resemblance to the founding defect. It is the same defect.** The kit's own
record names the shape — *"17 sites where a parse failure produced `n=0` → read as clean"* — and every
one of those was fixed by refusing to turn an absent or malformed report into zero. What corpus B shows
is a **well-formed, honestly-produced, fully conformant report** whose zero means nothing, which the
existing fixes do not reach and cannot reach, because there is nothing wrong with the file.

**Every scanner discloses it somewhere different, and four do not disclose it at all:**

| | where the skip is disclosed | at what level | coverage figure, and where |
|---|---|---|---|
| bandit | `toolConfigurationNotifications` — the **wrong array** for a runtime condition | `error`, beside `executionSuccessful: true` | none usable; `properties.metrics` counts skipped files as though read |
| semgrep | `toolExecutionNotifications` | **`warning`**, which is non-failing | only in JSON `errors[]`; the parse rate goes to telemetry alone |
| CodeQL | extraction diagnostics, outside the SARIF | not applicable | yes — three ways, all outside the report |
| gosec | **nowhere in the SARIF** | — | JSON `"Golang errors"` map and `Stats` only |
| Trivy | **nowhere in the SARIF** | — | one stderr `INFO` line |
| Checkov | **nowhere in the SARIF** | — | JSON `summary.resource_count` only |
| flawfinder | **nowhere in the SARIF** | — | `Lines analyzed`, which `--sarif` suppresses |

**And one cross-cutting fact settles the shape of §4: not one of these tools populates
`runs[].artifacts[]`.** Checked across bandit, semgrep, gosec, Trivy and Checkov — the property is
absent from every SARIF writer in all five. So the artefact inventory that SARIF §3.14.15 makes
optional is, in this suite, **universally unpopulated**, which means §4.5's row 9 is not an exception
to be handled but the **only** outcome any of them can reach from the SARIF alone. §4.4 is revised
accordingly.

**That table is the argument for the profile in §4.4, made by measurement rather than by assertion** —
and the measurement's verdict is harsher than the design first assumed. No single rule reads all
seven, four of them put nothing in the report, and the honest per-tool declaration has to name a
**non-SARIF** channel for most of the suite.

**And it settles what `discover` must do first.** Every one of these behaviours is invisible unless the
version question was asked beforehand. Bandit's corpus-B report is indistinguishable from corpus C's
on every field the kit reads; the only thing that separates them is a notification nobody looks at and
a version comparison nobody makes. **Ask the version first, and the zero becomes readable. Ask it
never, and no amount of care downstream recovers the answer.**

---

## 4 · The post-scan validity check

> "True SARIF files that are checked for content befitting, and not just error methods."

### 4.1 What the kit checks today, exactly

One expression, in three places.

`scripts/scan_status.sh:36` — the per-job summary every scanner calls:

```
jq '[.runs[].results[]] | length'
```

`reusable-security.yml:2894-2906` (gitleaks) and `:3308-3320` (Semgrep) wrap the same shape in the
right guards: absent file is `COLLECTION_FAILED`, a `jq` failure is `COLLECTION_FAILED`, and neither
is permitted to become `n=0`. The comments say why, and they are correct as far as they go: *"This
was `jq ... 2>/dev/null || echo 0`, so a missing, truncated or malformed report produced n=0 — which
the gate reads as CLEAN."*

So the current check establishes exactly two of the four claims `publication_state` already
separates:

| claim | registered term | checked today? |
|---|---|---|
| the scanner executed and finished | `ANALYSIS_COMPLETE` | inferred from the job result, not from the report |
| an output file exists and is non-empty | `REPORT_PRODUCED` | **yes** — `[ -s file ]` |
| the output parses as the format it claims to be | `REPORT_STRUCTURALLY_VALID` | **yes** — the `jq` expression succeeding |
| retained independently of any publication channel | `PERSISTED` | yes — `upload-artifact` before `upload-sarif` |

**That is the "error methods" check.** It asks whether the file is broken. It never asks whether the
file is *about anything*. A report from a tool that parsed zero files satisfies both boxes it
checks, and `scan_report.py`'s own header already says what follows: **"A clean SARIF from a scanner
pointed at an empty directory is a clean SARIF."**

### 4.2 What SARIF normatively guarantees — and the answer is: much less than one would hope

All citations are to the OASIS standard, *Static Analysis Results Interchange Format (SARIF) Version
2.1.0 Plus Errata 01*, OASIS Standard incorporating Approved Errata, 28 August 2023 —
https://docs.oasis-open.org/sarif/sarif/v2.1.0/sarif-v2.1.0.html — by section.

| property | § | conformance | absent same as empty? | usable as proof something was read? |
|---|---|---|---|---|
| `runs[].results` | 3.14.23 | **SHALL**, conditionally | **no** — absent defaults to null | **partly** — see below |
| `runs[].invocations[].executionSuccessful` | 3.20.14 | **SHALL**, *inside* an optional parent | n/a | weakly — self-asserted |
| `runs[].invocations[]` | 3.14.11 | MAY | yes | — |
| `runs[].invocations[].exitCode` | 3.20.9 | SHOULD, conditionally | n/a | no |
| `toolExecutionNotifications` at `level` error | 3.20.21 | MAY, but presence **SHALL** mean the run failed | yes | **negative proof only** |
| `toolConfigurationNotifications` at `level` error | 3.20.22 | same | yes | negative proof only |
| `runs[].artifacts[]` | 3.14.15 | **MAY** | **yes** (SARIF §3.7.2) | **no** |
| `artifacts[].roles` value `analysisTarget` | 3.24.6 | MAY | yes | **no — it records intent** |
| `runs[].tool.driver.rules[]` | 3.19.23 | MAY | yes | **no — a catalogue, not a log** |
| `runs[].versionControlProvenance` | 3.14.13 | MAY | yes | **best available** |
| `results[].baselineState` value `absent` | 3.27.24 | MAY | yes | yes, indirectly |
| `invocations[].startTimeUtc` / `endTimeUtc` | 3.20.7-8 | MAY | yes | heuristic only |
| a way to say "this file was not analysed" | — | **does not exist** | — | — |

Five of those rows overturn something one would reasonably have assumed, and each changes the
design.

**`runs[].artifacts[]` being non-empty cannot be a conformance check.** SARIF §3.14.15 is `MAY`, and its
only `SHOULD` is narrower than the question: the array *"**SHOULD** contain elements representing at
least those artifacts in which results were detected, but it **MAY** contain elements representing
all artifacts examined by the tool (whether or not results were detected in those artifacts), **or
any subset of those artifacts**."* The empty set is a subset, and with zero results the `SHOULD` is
vacuously satisfied. Worse for detection purposes, SARIF §3.7.2 makes an absent array-valued property
default to empty, so **absent and empty are the same thing here** — there is no signal to read. And
SARIF §3.4.5 closes the loop: where `run.artifacts` does not describe an artefact, `artifactLocation.index`
**SHALL NOT** be present, so a tool that lists nothing produces a fully self-consistent log with no
dangling references. **A tool that discloses nothing about what it read is not producing defective
SARIF. It is producing conformant SARIF.**

**`runs[].tool.driver.rules[]` is a capability catalogue, not an execution record.** SARIF §3.19.23's
wording is *"an analysis rule **supported by** the tool component"*. A rule count says what the tool
could have run. Nothing in the spec ties array membership to evaluation. A non-zero rule count is
therefore reassuring and proves nothing, and a rules array is the one thing GitHub *does* require —
see §4.6.

**`invocations` is optional, so the one mandatory success assertion is evadable.**
`executionSuccessful` is a `SHALL` (SARIF §3.20.14) — *"true if the engineering system that started the
process knows that the analysis tool succeeded"* — but only if an invocation object exists at all.
Omit `invocations` and the obligation vanishes. Note also the spec's own example pairs
`exitCode: 1` with `executionSuccessful: true`, so **the two are independent and neither may be
inferred from the other.**

**`results` is the one place null and empty are normatively different, and it is the strongest
primitive in the format.** SARIF §3.14.23, and it is worth quoting because it is the whole basis of the
rule below:

> If the tool failed to start… `results` **MAY** be present. If it is present, its value **SHALL**
> be null. … If the tool started but failed to begin its analysis… again `results` **MAY** be
> present, and if present **SHALL** be null. In all other circumstances, `results` **SHALL** be
> present and **SHALL** contain all results detected by the tool. If the tool did not detect any
> results, `results` **SHALL** be an empty array. … **If `results` is absent, it SHALL default to
> null.**

So `null` or absent means *did not attempt*; `[]` means *attempted and found nothing*. The same
idiom appears at SARIF §3.13.4 for `sarifLog.runs` and at SARIF §3.27.23 for `result.suppressions`, which also
carries the only run-wide structural consistency `SHALL` in the format. **But `[]` guarantees only
that analysis *began*** — a tool that started, analysed two files of two thousand and then died
falls under "all other circumstances" and emits a short array, indistinguishable from a complete
one at this level.

**The spec says outright that a consumer must not assume completeness on failure**, and this is the
sentence the whole check is built around. SARIF §3.20.21:

> The presence within this array of any notification object whose `level` property is "error"
> **SHALL** mean that the run failed. **A SARIF consumer SHALL NOT assume that a failed run contains
> a complete set of analysis results.**
>
> NOTE: This is important in compliance scenarios, where, for example, a corporate policy might
> require that a project's entire code base be analyzed with a specified set of rules.

The committee understood this exact use case. Note the direction of the guarantee, though: it says
when completeness **must not** be assumed. It never says when completeness **may** be assumed.

### 4.3 What the spec leaves to the tool, and it is the load-bearing gap

**There is no normative rule for which `level` a tool uses to report that it failed to analyse a
file.** SARIF §3.58.6's definitions support either:

- `error` — *"The condition encountered by the tool resulted in the analysis being halted or caused
  the results to be **incorrect or incomplete**."*
- `warning` — *"the analysis might be **incomplete** but the results that were generated are
  probably valid."*

Only `error` triggers the run-failed `SHALL`. So **a scanner that failed to analyse most of a tree
can emit `warning` notifications, or `note`, or none at all, and produce a log no conformance
checker will flag.** `artifacts[].roles` does not close it either: the value `analysisTarget` means
*"The analysis tool was instructed to scan this artifact"* (SARIF §3.24.6) — an instruction, not an
outcome. An artefact can carry that role and have been skipped.

**That is the seam.** The format can express *what was touched* and cannot express *what was
skipped*, and the one property that would bridge it — `notification.locations` (SARIF §3.58.4), the only
way to name the file a tool failed on — is `MAY`.

### 4.4 So the validity check is a profile, not a conformance test

This is the design decision that follows, and it is not a compromise. It is the same move GitHub
itself makes: `tool.driver.rules[]` is `MAY` in OASIS and **required** by GitHub's ingestion
([SARIF support for code scanning](https://docs.github.com/en/code-security/code-scanning/integrating-with-code-scanning/sarif-support-for-code-scanning)).
A consuming platform may profile SARIF upward, and this kit is a consuming platform.

**The profile is declared per producing tool, exactly as the version range in §2.4 is.** For each
scanner the kit invokes, one declaration:

```
does this tool populate runs[].invocations[]                       yes / no / unknown
does it set executionSuccessful honestly                           yes / no / unknown
does it list artifacts it EXAMINED, not only those with findings   yes / no / unknown
does it report per-file analysis failures, in WHICH array,
                                          and at what level       error / warning / note / none / unknown
where, outside the SARIF, does it expose a parsed-or-skipped count named channel, or no
the lever that turns its quiet skip into a loud one                named flag or env var, or none
```

**Why per tool and not one rule for all.** The registry already argues this for version ranges and
the argument transfers without change: *"a single shared table would be a convenient fiction whose
first exception is silently wrong."* §3.6 is that argument as a measurement: bandit discloses in one
notification array, semgrep in the other at a non-failing level, and four tools in neither.

**And `unknown` is a gap, not a pass.** `defaults_are_suspicious_at_assurance_boundaries` applies
here identically to §2.3.

#### 4.4.1 The measurement changes this section's conclusion, and the honest version is less tidy

The profile above was written expecting a **spread** of answers — some tools evidencing examined
scope, others not. §3.6 measured it instead, and the answer to the third line is **no, for every tool
in the suite**: not one of bandit, semgrep, gosec, Trivy or Checkov populates `runs[].artifacts[]` at
all.

Two consequences, and neither is what the design wanted.

**§4.5 row 8 is currently unreachable, so row 9 is not an exception — it is the whole of the
suite.** A rule whose outcome is `PARTIAL` on every scanner on every run is not a control; it is a
permanently amber check, and this kit's own record says what happens to those: *"A permanently red
check is not a control, it is training: people learn red means 'known backlog', stop reading it, and a
real regression arrives wearing the same colour."* **Shipping §4.5 as written would produce exactly
that**, and saying so is more useful than leaving the rule looking usable.

**So the profile's authoritative field is the fifth line, not the third.** The channel that can
actually discriminate a clean scan from a blind one is, for most of this suite, **outside the SARIF**:

| scanner | the assertion that discriminates | where it lives |
|---|---|---|
| bandit | `errors[]` is empty | `-f json` — a second output, alongside the SARIF |
| semgrep | exit code is not 3; `errors[]` has no `PartialParsing` | **`--strict`**, plus `--json-output` |
| gosec | the `"Golang errors"` map is empty | `-fmt json`, and stop passing `-no-fail` |
| Trivy | the `Results` key is present, and stderr carries no `num=0` | JSON output plus the log line |
| Checkov | `summary.resource_count > 0` | `-o json` |
| cppcheck | `--error-exitcode=N` fires; `Active checkers` is not the critical-error form | exit code plus `--enable=information` |
| flawfinder | `Lines analyzed` is greater than zero | its text output — **which `--sarif` suppresses** |
| CodeQL | tool-status coverage percentage, or `print-baseline` against `src.zip` | the GitHub UI, or the CLI |
| detect-secrets | — | **no SARIF at all**; needs its own contract |

**Every row is a second output or a changed flag, not a new analysis.** That is the good news in an
otherwise unwelcome finding: the evidence exists in every case, it is cheap in every case, and in four
cases the kit already runs the tool and asks for the one format that cannot carry the answer.

**And it revises §4.5 in one specific way:** row 8's "the tool's profile says it evidences examined
scope, and that evidence is present" must be read as *evidence from the channel the profile names*,
which may be a sidecar file rather than the SARIF. The validated object stops being one SARIF and
becomes **the SARIF plus the sidecar the profile names for that tool** — which is more machinery than
this document wanted to propose, and is what the measurement requires. A rule that only ever reads the
SARIF cannot reach a clean verdict for any scanner in this kit, and a rule that always says `PARTIAL`
will be switched off.

### 4.5 The rule

Evaluated per report, on the runner, before any publication attempt — where "report" means the SARIF
**plus whatever sidecar channel that tool's profile names**, per §4.4.1. Rows 1-7 read the SARIF
alone; rows 8-10 cannot.

| # | condition | verdict | why |
|---|---|---|---|
| 1 | file absent or empty | `COLLECTION_FAILED` | already enforced; unchanged |
| 2 | does not parse, or is not SARIF | `COLLECTION_FAILED` | already enforced; unchanged |
| 3 | `runs` is null | `COLLECTION_FAILED` | SARIF §3.13.4 — the producer tried to populate it and failed |
| 4 | `results` is absent or null | `COLLECTION_FAILED` | SARIF §3.14.23 — normatively *did not attempt*. **This is the single highest-value addition, because it is a conformance-guaranteed reading and today it counts as zero.** |
| 5 | any `toolExecutionNotifications` or `toolConfigurationNotifications` entry at `level` error | `COLLECTION_FAILED` | SARIF §3.20.21-22 — the run failed, and completeness may not be assumed |
| 6 | `invocations[].executionSuccessful` is false | `COLLECTION_FAILED` | SARIF §3.20.14 |
| 7 | `results` is non-empty | `FINDINGS`, and the coverage question is answered by the findings themselves | a tool that found something read something |
| 8 | `results` is `[]`, and the channel the profile names says scope was examined and nothing was skipped | `PASS` — and only here is this run's zero a clean zero | the claim is established, by whichever channel actually carries it |
| 9 | `results` is `[]`, and the profile names **no** channel, or names one and it says `unknown` | **`PARTIAL`** | see §4.5.1 |
| 10 | `results` is `[]`, the profile names a channel, and the channel is absent or unreadable | **`PARTIAL`**, and the divergence is itself reported | the tool or the wiring did not do what it was declared to do — a declaration defect or a collection defect, and both need a human |

Rows 7 and 8 are the only two that yield a clean or a findings result. **Everything else is either a
collection failure or an unestablished claim, and none of it is zero.**

**As the kit stands, row 8 is reachable for no scanner**, because the sidecar channels §4.4.1 names are
not requested anywhere. That is not an argument for softening the rule; it is the size of the gap,
stated once, so nobody implements rows 1-7, sees green, and concludes the coverage question was
answered. **Rows 1-6 are worth building immediately and on their own merits** — row 4 especially, since
`results` being null is a conformance-guaranteed "did not attempt" that today counts as zero. Rows
8-10 should not ship until at least one tool has its channel wired, or the kit acquires a check whose
only possible answer is amber.

### 4.5.1 A SARIF that reports no findings and no artefacts is not CLEAN. It is `PARTIAL`.

Stated as the owner's rule requires, and reusing the registered term rather than coining one:

> **`scanner_state.PARTIAL`** — *"Executed, but a prerequisite was missing so the security CLAIM is
> NOT established."*
>
> `forbidden`: *"MUST NOT be projected, summarised or rounded into PASS by any downstream consumer.
> 'Not established' is not 'clean'."*

That is exactly the situation. The scanner executed — `results: []` proves analysis began (SARIF §3.14.23).
What is missing is the **prerequisite for the coverage claim**: a record of what was read. So the
findings half of the result stands at full strength (there were none reported) and the coverage half
is not established, which is precisely the split `PARTIAL` exists to carry.

**Why not `COLLECTION_FAILED`.** Because nothing failed. A tool that conformantly declines to list
clean artefacts has collected its results correctly; the kit simply cannot verify the scope from the
artefact. `COLLECTION_FAILED`'s registered definition is *"gathering its results failed — producing
an EMPTY BUT WELL-FORMED output"*, and using it here would assert a malfunction that did not occur.
It would also blur the distinction the cascade above depends on: rows 3-6 are positive evidence of
failure, row 9 is absence of evidence about scope, and those are different facts with different
owners — one is a defect to fix, the other a capability limit to record.

**And the coverage-side state has its own registered word.** Alongside the scanner's `PARTIAL`, the
scope that scanner was pointed at is `coverage_state.COVERAGE_UNDETERMINED` — *"The coverage probe
itself could not run. Unknown, not absent… That is a weaker claim than FULL and must not be reported
as one."*

**Enforcement.** `PARTIAL` *"warns; does not block"* by its registered enforcement, and that is
right and must not be quietly upgraded here. The gate consequence belongs to the environment tier,
where `environment_tier` already sets it: *"'Scanner did not run' MUST block at production tiers."*
A claim that was not established is on the same side of that line as a scanner that did not run, and
`ENFORCEMENT_TIERS_AND_FINDING_BASELINE.md` §3 owns the rung mechanics. This document does not
restate them.

**A caution this section's own title now needs.** "No findings and no artefacts" turned out to
describe **every** scanner in the suite on every run (§3.7), not an unusual case — so the rule as
stated would fire universally. `PARTIAL` is still the correct *state* for a report that cannot evidence
its scope, and that verdict is unchanged. What changed is that the state has to be reached from the
channel §4.4.1 names rather than from `artifacts[]`, because `artifacts[]` is empty for reasons that
have nothing to do with whether the scan was blind. **An honest state assigned universally is
indistinguishable, in practice, from no state at all** — and a check every scanner fails will be
switched off long before it catches anything.

### 4.6 Where the check runs, and why it cannot be the Security tab

**On the runner, on the local file, before `upload-sarif`.** Not afterwards, and not by reading
anything back from GitHub.

The reason is documented and decisive: **GitHub does not ingest the properties the check depends
on.** Its
[SARIF support page](https://docs.github.com/en/code-security/code-scanning/integrating-with-code-scanning/sarif-support-for-code-scanning)
states *"code scanning will only use the following supported properties"* and *"note that the rest
of the supported fields are ignored"*, and the supported list contains exactly one invocation
property — `invocation.workingDirectory.uri`, optional, used only to rebase absolute URIs. It
contains **no** `executionSuccessful`, **no** `exitCode`, **no** `toolExecutionNotifications`, and
**no** run-level `artifacts[]` at all.

So: GitHub does not read SARIF's only mandatory success assertion, and does not read the error-level
notifications that SARIF §3.20.21 says **SHALL** mean the run failed. **A failed run uploads cleanly and
presents as a successful scan with zero alerts.** That is the founding defect of this kit reproduced
inside the platform's own ingestion, and it means the Security tab can never be the place validity
is established.

**Precisely stated, because the strong form is UNVERIFIED and the weak form is enough.** What is
documented is that those properties are not in the supported list and that unsupported fields are
ignored. Whether an upload carrying `executionSuccessful: false` plus an error-level notification is
**rejected, warned on, or silently dropped** is stated nowhere — not on the SARIF-support page, the
about-SARIF page, or the upload page. There is partial counter-evidence that the ingest path
understands the fields *for CodeQL*: the CodeQL Action uploads a payload with
`executionSuccessful: false` on failure, and has its own check asserting on
`invocations[0].toolExecutionNotifications` for status-page notifications. That proves the machinery
exists for GitHub's own producer; it does not establish anything about the third-party path.
**The experiment that settles it** is one API round trip: `POST` a SARIF whose run carries
`executionSuccessful: false`, one error-level notification and `results: []`, then `GET
/repos/{owner}/{repo}/code-scanning/sarifs/{sarif_id}` and read `processing_status` together with the
`errors[]` and `warnings[]` arrays that response is documented to carry. Until someone runs it, the
design assumes the notifications are dropped, which is the non-permissive direction — and the
conclusion is unaffected either way, because a check that depended on GitHub reading them would still
be running after publication rather than before.

Two further documented facts constrain the design and belong in the record:

**Truncation is silent.** The same page's limits table caps results per run at 25,000 with *"Only
the top 5,000 results will be included, prioritized by severity"*, and locations per result at 1,000
with *"Only 100 locations will be included"*. Those are **not** rejections. A run at the top of the
range uploads successfully and displays a subset, so **a count read from the Security tab is not the
count the scanner produced.** The kit's existing decision to persist every SARIF as an artifact
before publishing is what makes this survivable, and it is one more reason the local file is the
authority.

**GitHub synthesises a property.** *"If you upload a SARIF file using the `upload-sarif` action and
this data is missing, GitHub attempts to populate the `partialFingerprints` field from the source
files."* Ingestion mutates the artefact. Another reason the validated object must be the local one.

This puts the validity check in the same structural position as the redaction step, for the same
reason, and the comment already in the file states the principle: **"ORDER IS THE WHOLE CONTROL…
a redactor after the upload protects nothing while looking exactly like protection."** A validity
check after publication validates nothing while looking exactly like validation.

### 4.7 What the check cannot establish, named so nobody assumes it does

- **It cannot produce a file-level coverage figure from SARIF alone.** The format has no way to
  express what was not analysed. §5 is the honest treatment of that.
- **It cannot detect a partial run that reported no error.** A tool that analysed two files of two
  thousand and exited cleanly emits `results: []`, and rows 8 and 9 cannot tell it from a complete
  clean run unless the tool disclosed a scope record. This is the residual, it is real, and the only
  thing that reduces it is a per-tool count from outside SARIF — which for one scanner exists and is
  the subject of §3.
- **A near-zero invocation duration is a smell, not a violation.** `startTimeUtc` and `endTimeUtc`
  are both `MAY` (SARIF §3.20.7-8), there is no `SHALL` that the second follows the first, and a heuristic
  threshold would be a number nobody can defend. Worth logging; not worth gating.
- **`versionControlProvenance` is the strongest scope anchor available and it is optional.**
  SARIF §3.14.13 defines each entry as specifying *"a revision in a repository containing files that were
  scanned during the run"*, with the stated rationale that it lets an engineering system *"reproduce
  a scan"*. It pins the claim to an immutable revision rather than to a self-asserted file list, and
  requiring it in the profile costs a producer almost nothing. Recommended, not sufficient.

---

## 5 · File-level accounting

> "None of the files or workstreams are skipped unless they don't apply."

### 5.1 What the kit counts today, and what it does not

`discover`'s `coverage_gaps` output counts **artefact classes**, not files. The evidence is in the
code: `declare_gap()` at `:2442-2448` appends a class name to a comma list and increments
`gap_count`, and `gap_class()` at `:2411-2438` maps a file extension onto a human class name —
`rs` becomes `Rust`, `ps1` becomes `PowerShell`. A per-class file count *is* computed and put in the
warning text (`_n` at `:2482`, from `grep -c`), but it is neither emitted as an output nor summed.
So a consumer receives `coverage_gaps=Rust,Shell` and `coverage_gap_count=2` and cannot tell whether
that is four files or four thousand.

That is the right granularity for the question `coverage_gaps` was built to answer — *where does this
platform's assurance stop* is a question about capability classes. It is the wrong granularity for
the owner's question, which is about **files**.

And the denominator is missing on the other side too. Nothing in the kit establishes how many files
exist in scope. `discover`'s presence probes use `find … -print -quit` (`:2180-2182`) — deliberately,
because an earlier version piped to `head -1` and `pipefail` turned a large repository into a
declared survey failure. `-print -quit` stops at the **first** match. A probe designed to stop
counting cannot produce a count, and that is a correct design decision for the question it answers.

### 5.2 What a file-level denominator would actually take

Four things, and each is a separate piece of work.

**(1) The denominator itself — the set of files in scope.** One full `find` over the scope with no
early exit, classified by extension, minus the exclusions `discover` already applies
(`node_modules`, `vendor`, `.git`). Cheap: one directory walk, and `discover` already performs two
full walks without early exit for the unsupported-language sweep (`:2451-2458`) and the workflow
sweep (`:2501-2504`). This is the affordable part.

**(2) The unreadable scope.** Files the walk could not enumerate — permission denied, a broken
symlink, a path too long, a submodule not checked out. `discover`'s sweeps send `find`'s stderr to
`/dev/null` and capture only the **exit status** (`unsup_rc` at `:2459`, `gha_rc` at `:2505`), which
is the right instinct and too coarse: a walk that failed on one subtree exits non-zero exactly like
one that failed on all of them, and the current code turns either into a single `COVERAGE_UNDETERMINED`.
A real unreadable-scope figure needs `find`'s diagnostics kept and counted, not discarded.

**(3) The definition of covered, per scanner.** This is the expensive one and it is not a counting
problem. "Covered" has to mean *this named tool read this named file*, and the only place that can
come from is the tool's own output — which lands us in §4, because `runs[].artifacts[]` is the SARIF
property that would carry it and §4 establishes how unevenly it is populated. A definition of
covered that a tool cannot evidence is a definition that has to be taken on trust, and a coverage
figure resting on trust is the thing this kit exists to refuse.

**(4) How coverage was proven.** Per (file, scanner) pair, the mechanism that established it, at the
strength that mechanism actually has. Three strengths, and they are already distinguishable with
registered vocabulary:

| strength | mechanism | registered as |
|---|---|---|
| strong | the tool named the file in its own output | `observation_quality.VERIFIED`, `evidence_confidence.observed_tool_attributed` |
| weak | the tool was pointed at a scope containing the file and exited cleanly | inference, not observation — `PRODUCER_UNVERIFIED_EXTERNALLY_DECLARED` is the closest honest label |
| none | neither | `COVERAGE_GAP` |

The middle row is where the trouble is. It is what almost every scanner invocation in this kit can
support today, and it is **not** a coverage proof: `scan_report.py`'s own header says it —
*"A clean SARIF from a scanner pointed at an empty directory is a clean SARIF."*

### 5.3 The honest answer: a full per-file denominator is disproportionate, and here is what is not

**Cost, stated plainly.** For `S` scanners over `F` files, a complete accounting is an `S x F`
matrix. On a monorepo with 40,000 files and fourteen scanners that is over half a million cells,
recomputed every run, most of them `NOT_APPLICABLE` because a Python scanner has nothing to say
about a `.tf` file. The matrix is mostly structural zeroes, it is expensive to produce, it is
expensive to store, and — the decisive objection — **no consumer has a question whose answer needs
it.** Nobody asks "was `src/util/parse.py` read by bandit". They ask "is there Python here that
nothing read".

**So the affordable claim is the class-and-count claim, and it must be stated as the weaker claim it
is.** Three figures per artefact class, per scanner, per run:

```
class            the artefact class, as gap_class() already names it
files_in_scope   the denominator -- a full walk, no early exit
enumeration      COMPLETE or partial, with the count of paths the walk could not read
covered_by       the scanners that claim this class AND whose version check passed
coverage_basis   how the claim is supported -- named-in-output, or scope-inference
```

What that supports, precisely: *"this class holds N files; these scanners were pointed at it; their
version capability was established or was not; coverage was proven by output attribution for these
and by scope inference for those."*

What it does **not** support, and must never be written as though it did: *"96% of files were
scanned."* A percentage over a class-level denominator is a number whose units nobody can name, and
it is exactly the shape `FUTURE_WORK.md` already flags — *"A real search with the wrong denominator,
recorded as an absence."* A wrong denominator that produces a reassuring percentage is worse than no
percentage, because a percentage invites comparison across runs and repositories, and two figures
computed over different denominators are not comparable at all.

### 5.4 The one place a full per-file denominator IS proportionate

**Secrets.** The owner's requirement is unconditional — *"cannot be pushed up ever. No matter
environment etc. And still any gaps are identified"* — and the cost objection in §5.3 does not apply,
because the secret scanners are the ones that should genuinely read every file: they are lexical, so
their applicability ought not to be gated by artefact class or by language version at all. One
denominator, two scanners (`gitleaks` and `detect-secrets`), and an enumeration failure inside that
scope is a first-class finding rather than a footnote.

**The premise is now established, and a worse one replaces it.** §3.6 settles the version half:
`detect-secrets` uses no Python AST anywhere, and gitleaks is regex plus entropy with a keyword
prefilter — **so neither is gated by language version, and the class-and-language objection genuinely
does not apply to secrets.** The denominator is therefore as cheap as §5.2 hoped.

**What replaces it is a scope problem, and it is sharper.** Both secret scanners exit 0 having read
nothing, by paths this kit is exposed to:

- `detect-secrets scan` **returns 0 unconditionally** — the exit code carries no information at all.
- Its default scope is git-tracked files, and a failing `git ls-files` is swallowed to an empty set
  with no log, producing `"results": {}` and exit 0. **This is not hypothetical here: the attempt in
  §3.6 hit exactly that path**, emitting `fatal: not a git repository` while reporting zero.
- Its baseline output records only files **with** findings, so fifty thousand clean files and zero
  files are bit-identical. There is no file count anywhere in it.
- It has **no SARIF output at all**, so §4's validity rule cannot apply to it even in principle.
- gitleaks exits 0 when zero bytes were scanned, and prints `scanned ~0 bytes` — a real signal, on
  stderr, that nothing reads.

**So the secret denominator is affordable and it is also the most load-bearing one in the kit**, which
is an uncomfortable combination. The enumeration count is not a refinement here; it is the only thing
standing between "no secrets found" and "no files read", because neither tool's exit code and neither
tool's report can tell those apart. **`scanned ~0 bytes` and an empty `results` map are the two
assertions worth wiring before anything else in this document**, and they are each one line.

This is also the only place where a file the walk could not read is unambiguously serious. A `.rs`
file nobody could enumerate is a coverage gap in a class that was already a coverage gap. A file
nobody could enumerate in a secret sweep is a file that might hold a live credential, and the
registered rule from `WHY_THESE_KEEP_HAPPENING.md` applies without modification: **failure to
establish the secret result can never become permission to merge.**

### 5.5 "Unless they don't apply" needs the evidence attached

The owner's clause carries its own proof obligation. "Does not apply" is a claim, and
`scanner_state.NOT_APPLICABLE` already states what backs it:

> **MUST** be backed by a search that found nothing. **MUST NOT** be produced by a toggle being off,
> by a selector excluding it, or by discovery failing.

So a skip is admissible only with the search that justifies it attached — which is why `discover`
already emits `NOT_APPLICABLE` rows with the pattern it searched for ("searched, none found", and
the literal glob list at `:2332-2337`). The file-level version of the same rule: a file omitted from
a scanner's scope is recorded with **which** rule omitted it, and the four reasons are already
separately registered and must not merge:

| reason a file was not scanned | registered as | acceptable? |
|---|---|---|
| no scanner in the kit claims its class | `SCANNER_UNAVAILABLE` → `COVERAGE_GAP` | declared, not acceptable-and-silent |
| a scanner claims it but cannot read the version | `VERSION_UNSUPPORTED` → `COVERAGE_GAP` | same |
| the caller's selector excluded it | `EXCLUDED_BY_SELECTOR` | **must be reported** — *"Narrowing scope must never silently reduce VISIBILITY"* |
| the depth for this trigger context narrowed scope | `scan_depth.DEPTH_REDUCED` | must be reported — *"we looked less hard this time" is not "there was nothing to look at"* |

The fourth row is the one a file-level report makes newly visible. A pull-request run scanning
changed paths only is `DEPTH_REDUCED` over every unchanged file, and a file-level denominator would
say so for the first time — which is useful and will be unwelcome, because it makes the cheapest run
look the least covered. It **is** the least covered. That is the correct reading and the reason not
to hide it.

---

## 6 · The parity requirement when Advanced Security is off

> "GHAS accepted immediately but otherwise free codeql and dependabot scans turned on and report
> the same way as the others when it's off."

### 6.1 What the kit already establishes once

`discover`'s `platform` step (`reusable-security.yml:2566-2676`) establishes nine values and emits
them as job outputs: `ghas_available`, `code_scanning`, `secret_scanning`, `push_protection`,
`dependabot_alerts`, `dependabot_updates`, `dependabot_config`, `visibility`, `platform_source`.
It does so **once**, with the reason written in the file: *"Every downstream job previously answered
this for itself, which meant sixteen jobs could hold sixteen different beliefs about the same
organisation setting."*

Three properties of that step are already right and must be preserved by anything built on it.

**`UNKNOWN` is a real value.** The `security_and_analysis` block is returned only to callers with
admin permission, so a read-scoped `GITHUB_TOKEN` legitimately cannot see it, and the comment at
`:2562-2565` is explicit that reporting `false` there "would be a fabricated negative… and it would
silently disable scanners on repositories that are fully licensed."

**There is a behavioural probe behind the settings read.** When the settings object is invisible,
`:2604-2614` asks the code-scanning API and classifies the answer. That is the
`DISTINCTION_OBSERVABLE` discipline applied to a platform capability — establishing the distinction
by probing rather than assuming it from a field it cannot read.

**Dependabot alerts and Dependabot updates are two outputs, not one.** `:2624-2627`, with the reason
stated: *"collapsing them is how 'we have Dependabot' came to mean four different things."* That
separation is load-bearing for §6.3 and the documentation below confirms it was the right cut.

**What is missing is the consumption.** Only the `report` job reads any of it, and only two values —
`${P_CODESCAN}` and `${P_SOURCE}` at `:5698-5699` — and only to render them. Nothing switches anything on.
`ghas_available` is consumed by no job at all. The CodeQL job does not read it: it attempts `init`
with `continue-on-error: true` (`:3610-3614`) and infers `UNAVAILABLE` from the outcome
(`:3675-3682`). That inference is defensible and is not the same thing as acting on the established
value, and no job anywhere enables Dependabot in response to it.

### 6.2 What the free tier actually permits — established, with citations

The entitlement model changed: Advanced Security is now **two separately purchasable products**,
GitHub Code Security and GitHub Secret Protection, each licensed per unique active committer, and
either may be enabled without the other.
[About GitHub Advanced Security](https://docs.github.com/en/get-started/learning-about-github/about-github-advanced-security) ·
[GHAS billing](https://docs.github.com/en/billing/concepts/product-billing/github-advanced-security):
*"A subset of Advanced Security features are available to all public repositories on GitHub.com free
of charge."*

| capability | public repository | private repository, no licence | source |
|---|---|---|---|
| dependency graph | free | **free** | [GitHub security features](https://docs.github.com/en/code-security/getting-started/github-security-features) — listed under "Available for all GitHub plans" |
| Dependabot **alerts** | free | **free** | same; and [GitHub's plans](https://docs.github.com/en/get-started/learning-about-github/githubs-plans): *"With GitHub Free, your personal account includes: Dependabot alerts"* |
| Dependabot **security updates** | free | **free** | same section |
| Dependabot **version updates** | free | **free** | same section |
| Dependabot custom auto-triage rules | paid | paid | under Code Security |
| secret scanning, partner patterns | free | free | [GitHub security features](https://docs.github.com/en/code-security/getting-started/github-security-features) |
| secret scanning, **user** alerts | **free** | **requires Secret Protection** | same; and [About secret scanning](https://docs.github.com/en/code-security/secret-scanning/introduction/about-secret-scanning) |
| push protection, repository level | **free** | **requires Secret Protection** | same |
| **code scanning / CodeQL** | **free** | **requires Code Security** | [About code scanning](https://docs.github.com/en/code-security/code-scanning/introduction-to-code-scanning/about-code-scanning): *"If you want to use code scanning on private repositories, you need a GitHub Code Security license."* |
| **any SARIF upload**, including third-party | free | **refused** | [Uploading a SARIF file to GitHub](https://docs.github.com/en/code-security/code-scanning/integrating-with-code-scanning/uploading-a-sarif-file-to-github): *"For private and internal repositories, code scanning is available when GitHub Code Security features are enabled for the repository."* |

**CodeQL default setup versus advanced setup**, from
[Configure code scanning](https://docs.github.com/en/code-security/how-tos/find-and-fix-code-vulnerabilities/configure-code-scanning/configure-code-scanning):

- Eligibility, verbatim: *"Your repository is eligible for default setup for code scanning if:
  GitHub Actions is enabled. It is publicly visible, or GitHub Code Security is enabled."*
- **They do not coexist.** Verbatim: *"default setup will override existing code scanning
  configurations… default setup will disable the existing workflow file and block any CodeQL
  analysis API uploads."* There is a dedicated rejection page for it:
  [Upload was rejected because CodeQL default setup is enabled](https://docs.github.com/en/code-security/code-scanning/troubleshooting-sarif-uploads/default-setup-enabled).
- And a documented dormant state, verbatim: *"If the analyses fail for all CodeQL-supported
  languages in a repository, default setup will still be enabled, but it will not run any scans or
  use any GitHub Actions minutes until another CodeQL-supported language is added… and the analysis
  of a CodeQL-supported language succeeds."*

### 6.3 The consequence the requirement has to absorb

**On a public repository the owner's requirement is fully achievable.** Free CodeQL, free secret
scanning, free push protection, free Dependabot. Nothing to design around.

**On a private repository with no licence, half of it is not achievable, and the half that fails is
the CodeQL half.** Three separate documented walls, and each would have to fall for "free CodeQL
turned on" to be possible there:

1. **Default setup is ineligible** — it requires public visibility *or* Code Security.
2. **Code scanning as a feature requires a licence** — so there is no alerts surface, and by
   extension no tool status page.
3. **The SARIF upload path is refused for every tool**, not only CodeQL. The documented error is
   `GitHub Code Security or GitHub Advanced Security must be enabled for this repository to use
   code scanning`.

The kit already behaves correctly in the face of (3) and says why: every scanner job persists its
SARIF as an artifact *before* attempting publication, and the upload step is
`continue-on-error: true` with an explicit degraded-publication warning — bandit's is at `:3528-3536`.
`publication_state.PUBLICATION_DEGRADED` is the registered word, and its registered rule is exactly
this situation: *"MUST NOT fail the scan. An unreachable dashboard cancelled an entire deep scan
once. An empty Security tab is indistinguishable from a clean codebase — say which it is."*

**So the design must not promise free CodeQL on a private repository, and this document will not.**
What it says instead:

| tier | code analysis actually available | what the run must say |
|---|---|---|
| Code Security enabled | CodeQL, advanced setup, results in the Security tab | ordinary coverage |
| public, no licence | CodeQL free, either setup, results in the Security tab | ordinary coverage |
| private, no licence | **no CodeQL.** Semgrep, bandit, gosec and the rest, results in artifacts only | coverage **at the strength those tools have**, and `code_scanning` = `UNAVAILABLE`, which is a **platform** action and never a developer one |

**Substitution is not equivalence and must never be reported as it.** The kit already runs Semgrep on
every run, and `AXES_AND_PHASES.md` states the difference in one line: *"SEMGREP FINDS THE SINK;
CODEQL FOLLOWS THE FLOW. Pattern matching says the dangerous call is present. Only taint tracking
says attacker-controlled input REACHES it."* A private unlicensed repository is therefore missing
interprocedural dataflow, and a parity design that let its report read identically to a licensed
one would be manufacturing the reassurance this kit exists to refuse. `COVERAGE_GAP` is the right
answer for the taint-tracking capability on that tier — the code is here, a control is owed, and
nothing capable of it looked.

**The Dependabot half of the requirement is achievable everywhere and is genuinely not built.**
`dependabot_alerts`, `dependabot_updates` and `dependabot_config` are established and consumed by
nothing. Turning them on needs the repository-level toggle (repository administrators or
organization owners, per
[About Dependabot alerts](https://docs.github.com/en/code-security/dependabot/dependabot-alerts/about-dependabot-alerts))
plus the dependency graph, plus a `.github/dependabot.yml` for version updates — and the kit already
detects the config file's presence at `:2628-2632` and does nothing with the answer. A run cannot
flip an organization setting from inside a job with a read-scoped token; what it **can** do is emit
`NOT_CONFIGURED` against a named owner and a named action, which is the registered meaning of that
value: *"Available and switched off. PLATFORM action — a decision was made, or never made."*

### 6.4 The normalisation: same words, and the provenance still says which

Two different questions, and the whole design is keeping them apart.

**Question one — what did this control establish?** Answered in `scanner_state`, and the answer set
does not vary by tier:

```
PASS · FINDINGS · PARTIAL · NOT_APPLICABLE · FAILED · COLLECTION_FAILED · UNAVAILABLE
```

A consumer branching on `scanner_state` must not be able to tell which entitlement produced it,
because the entitlement is not what it is asking about. `scanner_state`'s own rule already forces
this: *"Every scanner reports its OWN state."* Dependabot alerts read from the alerts API and Trivy
findings read from a SARIF are both observations of dependency risk, and both land as `FINDINGS`
with their severity, their package coordinates and their advisory identifiers — not as "Dependabot
said so" versus "a scanner said so". The normalisation is therefore a **mapping into the existing
vocabulary**, per source:

| source | how it is read | maps to |
|---|---|---|
| Dependabot alerts (any tier) | `GET /repos/{owner}/{repo}/dependabot/alerts` | `FINDINGS` or `PASS`; `UNAVAILABLE` if the endpoint refuses; **never** `PASS` on a refusal |
| Dependabot not switched on | `dependabot_alerts` = `NOT_CONFIGURED` | `platform_applicability.NOT_CONFIGURED`, and the scanner contributes `UNAVAILABLE` |
| CodeQL, licensed or public | the job's own outcome, as today | `PASS` / `FINDINGS` / `COLLECTION_FAILED` / `UNAVAILABLE` |
| CodeQL, private unlicensed | not attempted, or `init` refused | `UNAVAILABLE` plus `COVERAGE_GAP` for the dataflow capability |
| every other scanner | its SARIF, through §4's validity check | as §4 defines |

**Question two — where did this evidence come from?** Answered in provenance, and it must remain
answerable. It needs **no new field**: the run already carries everything required.

- `provenance_identity` already lists `scanner` and `scanner_version` among its bound fields, so the
  producing tool is named at capture. `evidence_confidence.observed_tool_attributed` is the
  registered reason that matters: *"Overlapping coverage cannot hide a dead detector behind a live
  one."*
- `discover` already emits `visibility` and `platform_source`, and `platform_source` records **how**
  the platform answer was established — `security_and_analysis`, a code-scanning probe, or `none`.
- The per-capability `platform_applicability` value records the entitlement's **effect**.

Those three together answer "which tier produced this" without a fourth thing to keep in sync. And
`platform_source` = `none` is itself information the record must keep: it means the token could not
see the settings object, so every platform value in that run is a probe result rather than a read —
weaker, and not to be reported as equal.

**One asymmetry cannot be normalised away and must be stated rather than smoothed.** A finding from
the Dependabot alerts API has no SARIF, so §4's validity check does not apply to it and cannot; its
trustworthiness rests on the API having answered at all. That is a different evidence basis from a
scanner's own report, it is weaker in a specific way — nothing external corroborates the alert set's
completeness — and pretending otherwise would be the platform equivalent of trusting an empty SARIF.
Where a tier's evidence has a different basis, the **state** is the same word and the **basis** is
recorded beside it.

---

## 7 · Vocabulary reused, by name

Everything in this column is registered in `secure-cicd-kit/assurance-taxonomy.yaml` v1 and is used
here with its registered meaning. **Nothing in this document redefines any of it, and nothing new is
proposed.** Where the design wanted a word that did not exist, the design was changed.

| reused | where and how |
|---|---|
| `version_applicability` — `VERSION_DISCOVERED`, `SCANNER_SUPPORTS`, `VERSION_UNSUPPORTED`, `VERSION_SUPPORT_UNDETERMINED`, and its rule | the whole of §2. This namespace was registered and used nowhere outside `FUTURE_WORK.md`; §2 is its first consumer |
| `discovery_state` — `ARTIFACT_PRESENT`, `CAPABILITY_REQUIRED`, `SCANNER_UNAVAILABLE`, `COVERAGE_GAP`, `UNDETERMINED_PRESENT`, `EXCLUDED_BY_SELECTOR`, `DISABLED`, `NOT_APPLICABLE` | §2.4, §2.5, §5.5 |
| `coverage_state` — `FULL`, `UNSUPPORTED_PRESENT`, `COVERAGE_UNDETERMINED` | §4.5.1, §5.2 |
| `scanner_state` — `PASS`, `FINDINGS`, `PARTIAL` and its `forbidden` clause, `NOT_APPLICABLE` and its `forbidden` clause, `FAILED`, `COLLECTION_FAILED`, `UNAVAILABLE` | §2.3, §4.5, §4.5.1, §5.5, §6.4 |
| `publication_state` — `ANALYSIS_COMPLETE`, `REPORT_PRODUCED`, `REPORT_STRUCTURALLY_VALID`, `PERSISTED`, `PUBLICATION_DEGRADED` | §4.1 as the four claims the current check does and does not make; §6.3 for the upload |
| `platform_applicability` — `APPLICABLE`, `NOT_APPLICABLE`, `UNAVAILABLE`, `NOT_CONFIGURED`, `UNKNOWN` | §2.5, §6.3, §6.4 |
| `observation_quality` — `VERIFIED`, `PRODUCER_UNVERIFIED_EXTERNALLY_DECLARED`, `DISTINCTION_OBSERVABLE` | §1.5, §5.2, §6.1 |
| `evidence_confidence.observed_tool_attributed` and its tool-attribution warning | §5.2, §6.4 |
| `capability_maturity.DETECTION_PROVEN` · `selftest_reach.EXERCISED_ON_SCHEDULE` | §1.5 — what `validate-scanners.yml` actually establishes |
| `control_weakening` — `CONTROL_DISABLED`, `WEAKENING_UNATTRIBUTED`, `CONTROL_SURFACE_DEAD`, `NOT_A_CONTROL_SURFACE` and its escape-hatch rule | §2.5, §3.4 |
| `scan_depth` — `DEPTH_REDUCED`, `revalidate`, and the rule that reduced depth is not `NOT_APPLICABLE` | §1.3, §5.5 |
| `environment_tier` — sandbox / dev / test / uat / prod, and "scanner did not run MUST block at production tiers" | §1.3, §4.5.1 |
| `team_pattern` — solo_dev / pair_devs / small_team / full_team | §1.2 — what the harness is sized by |
| `provenance_identity` field list, including `scanner` and `scanner_version` | §6.4 |
| `finding_classification` — `ASSURANCE_PREREQUISITE_GAP`, `EXECUTION_UNAVAILABLE`, `POTENTIALLY_ABSENT` | §3, §5.5 |
| `toolchain_currency` — `UNSUPPORTED`, `VERSION_UNKNOWN`, `UPDATE_BLOCKED_BY_COMPATIBILITY`, and "newer exists is not upgrade now" | §3 — the question D7 owns, kept apart from D6's |
| `routing_result` — `EVIDENCE_UNTRUSTED`, `DECISION_REQUIRED`, `PROCEED_WITH_ADVISORY` | §4.5.1 by reference to the rung document, which owns the lattice |
| `iac_mode` — auto / disabled / required | §2.2 |
| `suppression_reason` — `EXPECTED_NEGATIVE_RESULT`, `PRESENTATION_ONLY`, `FAILURE_ISOLATION_WITH_STATE_CAPTURE` | §5.2 where `find`'s exit status is discussed |
| invariants `absence_is_not_a_negative_observation`, `defaults_are_suspicious_at_assurance_boundaries`, `partial_is_not_total_ignorance`, `a_node_is_not_a_path` | throughout; §2.3, §1.5 and §4.5.1 most directly |

**Seven registered terms stopped being orphans when this document landed.** `reconcile_taxonomy.py`
reported `ANALYSIS_COMPLETE`, `REPORT_PRODUCED`, `REPORT_STRUCTURALLY_VALID`, `PUBLICATION_DEGRADED`,
`OBSERVED_TOOL_ATTRIBUTED`, `SCANNER_VERSION` and `UNDETERMINED_PRESENT` as registered and used
nowhere when this work began. §4 is what uses the first four, and it uses them for exactly the
distinction `publication_state` was registered to protect: *"A scanner running, a report existing, a
report being valid, and a report being published are not the same event."*

**That is worth exactly as much as it sounds like and no more.** A term used in a design document is
still not a term any code branches on, and the orphan report cannot tell the difference — which is
the same caution `TAXONOMY_DRIFT.md` applies to registration itself. Clearing an orphan by writing
prose about it moves a promise from one column to another. It does not implement anything, and it
would be a poor reason to consider any of §4 done.

**One registered classification becomes wrong if this is built, and that is worth saying out loud.**
`control_weakening.NOT_A_CONTROL_SURFACE` gives *"a language version"* as its own example of an input
that changes no control's strength, and `reusable-nvd-cve.yml:833` records `python_version` under it.
That classification is correct **today**, precisely because nothing compares the version against a
scanner's range. The moment §2.4 exists, a language version decides whether a control can see, which
is the definition of a control surface — and the classification has to move. `NOT_A_CONTROL_SURFACE`'s
own rule anticipates the danger: *"THE ESCAPE HATCH, AND THEREFORE THE THING TO GUARD."*

**A note for the maintainer, found while checking and outside this document's scope.**
`tests/check_weakening_record.py`'s exemption for `reusable-security.yml` rests on the file being
"623 KB", over the 500 KB limit at which GitHub refuses to start a workflow. The file is now
340.8 KB. The premise of the exemption has expired ahead of its 2026-10-31 date, so the posture step
it defers can land — and when it does, the five version inputs must each be classified. They are not
currently in that exemption's `weakening_inputs_unrecorded` list at all.

---

## 8 · What could not be settled

Named because a document that answered everything about a mechanism nobody has built would be lying.

**~~What most scanners do with a language version they do not support.~~ LARGELY SETTLED — see §3.6.**
Six of eight tool groups can produce a silent zero, two reproduced directly and the rest established
from vendor documentation and source. What remains open is narrower and named in §3.6: whether
cppcheck's critical-error report survives into its SARIF, and whether gosec drops a
type-check-only failure before recording it. **The residual UNVERIFIED that matters most is CodeQL's
behaviour above its declared ceiling**, which is documented only negatively — GitHub states that *"A
small number of extractor errors is healthy"* and gives **no threshold at which CodeQL escalates**.
§3.5 names the experiment. Each remaining experiment is a seeded-corpus run the kit already has the
machinery for, and they are what turn §2 from a design into a table of real ranges.

**Whether a version probe is cheap enough to run where it needs to run.** §2.2 proposes reading up to
six files per ecosystem. In `discover` that is trivial. Per root in a large monorepo it may not be,
and the cost has not been measured. The topology work owns whether it is a step, a job, or part of
`discover`; this document only says it must happen before selection.

**The threshold at which a partially-extracted analysis stops being trustworthy.** §4.7 admits the
residual: a tool that read two files of two thousand and exited cleanly is indistinguishable from a
complete run at the SARIF level. CodeQL's tool status page publishes a per-language file-coverage
percentage, so for that one scanner a threshold is expressible — and **what the threshold should be is
a policy decision nobody has made**, and it must not be implemented as a constant. For every other
scanner there is no coverage percentage to threshold at all.

**~~Whether the artefact-disclosure profile in §4.4 is satisfiable by enough tools.~~ SETTLED, and the
answer is none of them — see §3.7 and §4.4.1.** Not one scanner in this suite populates
`runs[].artifacts[]`. So §4.5 row 9 is not the normal case, it is the **only** case reachable from the
SARIF, and a rule whose sole outcome is `PARTIAL` is the permanently-amber check this kit warns about
rather than a control. §4.4.1 revises the profile onto per-tool non-SARIF channels in response.
**What is now unsettled is downstream of that revision:** whether requesting a second output format
from every scanner is acceptable in run time and artefact size — that is the topology work's
question, not this document's — and whether the resulting sidecar-plus-SARIF pair can be validated
without the validator becoming a second place the contract lives, which is the drift this kit catches
everywhere else.

**Whether GitHub rejects, warns on, or silently drops an error-level notification from a third-party
SARIF.** §4.6 names the one-round-trip experiment. The conclusion there does not depend on the answer,
but the answer is worth having, because if uploads carrying a failed run were *rejected* then the kit
would be discovering validity failures at publication time as job failures, which is a different
operational shape from discovering them at the check.

**Whether the free-tier substitution in §6.3 is acceptable to the owner.** The documentation is
clear that free CodeQL on a private unlicensed repository is not available, so the honest position is
a declared `COVERAGE_GAP` for interprocedural dataflow on that tier. Whether that is tolerable, or
whether it means private repositories must hold a licence to be in scope at all, is a governance
decision and not this document's to make.

**Whether a locally-run CodeQL is available at all on a private unlicensed repository.** The upload
path is definitively refused, and GitHub lists the CodeQL CLI under GitHub Code Security in its
feature table — but whether the CLI's own licence permits running it against a private repository and
keeping the SARIF in an artifact was not established here. **UNVERIFIED.** What would settle it: the
CodeQL CLI terms and conditions, read directly. Until then the design assumes it is not available,
which is the non-permissive direction.

**The landing zones, and the deployment-method mapping the owner's last line names.** *"Gates based on
environment. Deployment method closer to the better ones which I believe is in the landing zones that
I created."* Those landing zones are in neither repository — a full-text search of this kit finds no
reference to a landing zone of any kind — so the mapping from environment tier to deployment method
cannot be reconciled against anything here. `DEPLOYMENT_CONTRACT_RECONCILIATION.md` holds the deploy
surface's own reconciliation and `environment_tier` holds the gating stringency; what is missing is
the third column joining a tier to a deployment mechanism. **That is a real dependency on an external
artefact and it is the reason §1's R7 is specified as a position rather than as a table.**

**The relationship between R2 and the toolchain-currency question.** §3 keeps them apart, as
`FUTURE_WORK.md` D6 and D7 already do. What is not settled is whether they share an implementation:
both need a per-tool version table, and maintaining two would be the drift this kit catches
everywhere else. Whether one table can serve a coverage question and a maintenance question without
one of them being silently wrong is not established.

**Every number.** There are almost none in this document, deliberately. The ones implied — how many
version sources to try before declaring `VERSION_SUPPORT_UNDETERMINED`, what fraction of a class's
files must be evidenced before a zero counts as `PASS`, what near-zero invocation duration means — are
all placeholders awaiting an owner's decision, and none of them should be implemented as a constant.

---

## 9 · The one-paragraph version

A run establishes what is here, then what version it is written for, then whether each configured
tool can read that version, and only then picks the tools — because a toolset version chosen before
the code version is known can only be chosen from a default, and a wrong default is wrong silently.
A version that cannot be established is a gap and never an assumption of support; a capable tool that
is absent, or present and unable to read the version, is a `COVERAGE_GAP` **declared before the
scan** rather than inferred afterwards from a zero that has three causes. After the scanners run, and
before anything is published or gated, each report is checked for content and not only for
parseability: a `results` property that is null or absent means the tool did not attempt, an
error-level notification means the run failed and completeness may not be assumed, and a report with
no findings and no record of what was read is `PARTIAL` — not `CLEAN` — because the scanner executed
and the prerequisite for the coverage claim is missing. That check runs on the local report before
upload, because GitHub ingests neither the success assertion nor the artefact inventory, so a failed
run uploads cleanly and presents as a clean scan — and "the local report" has to mean the SARIF plus a
sidecar, because measurement showed that no scanner in this kit discloses its examined scope in SARIF
at all, so a rule reading only SARIF could never return a clean verdict and would be switched off for
saying `PARTIAL` about everything. Coverage is reported per artefact class with its
denominator, its unreadable scope and the basis of the claim, because a per-file matrix across
fourteen scanners is mostly structural zeroes and answers a question nobody asks — except for
secrets, where the denominator is every file and an enumeration failure is a finding. Where Advanced
Security is absent, Dependabot is turned on and reports in the same words as every other scanner
while the provenance still records the tier; where it is absent on a private repository, CodeQL is
not available at all, and that is a declared gap rather than a substitution presented as parity.

# Known defects — things that are wrong, not things that are missing

**Established 2026-10-08 by adversarial testing of the scanner and normalisation path.** Every
entry below was observed by running code, not by reading it. Where something could not be
observed, it says `NOT ESTABLISHED` rather than an estimate.

## What belongs here, and what does not

Three registers already exist and this is not a fourth copy of any of them. *One truth in three
places* is a named hazard in this repository, so the boundary is stated rather than assumed:

| Register | Holds |
|---|---|
| `docs/assurance/KNOWN_GAPS.md` | **coverage** gaps — a control that does not exist, or exists and reaches nothing |
| `docs/assurance/VALIDATION_DEBT.md` + `tests/reconcile_validation.py` | **unproven** claims — dated, owned, expiring, build-enforced |
| `.context/products/secure-cicd-kit/risks.md` | **risks** — conditions that may cause harm, with a truth state |
| **this file** | **defects** — code that is wrong in a way a test can demonstrate, with the reproduction attached |

A defect that is also a risk appears in both, and the risk entry is the one that carries the
truth state. Cross-references are given where they exist; two entries below sharpen a risk that
was recorded more narrowly than the evidence supports.

## Severity, and what the words mean here

| | |
|---|---|
| **CATASTROPHIC** | ships a false assurance claim to a consumer. Someone reads a clean verdict over code nothing examined, and acts on it. |
| **SEVERE** | silently loses governance state — approvals, dispositions, baselines — so decisions already taken stop being honoured. |
| **MODERATE** | loud failure, wrong diagnosis. Work is lost or misdirected but nobody is told something false about their security posture. |
| **MINOR** | cosmetic, or confined to a developer's own machine. |

Severity is assigned on **blast radius if it ships unfixed**, not on how hard it is to hit.

---

## D-1 · A scan that examined nothing renders as a clean scope — **CATASTROPHIC** · **FIXED**

**What it is.** `scripts/scan_report.py` decides whether a finding count may be printed from
three inputs: the SARIF's parse state, and the `applicability` and `execution` values **supplied
by the caller**. It never reads the SARIF's own account of its run. Five hollow-scan shapes
therefore render the sentence `Findings: **NONE** in the scanned scope.`

The reporter has the vocabulary to refuse all five. `NO_COUNT_STATES` and `NO_COUNT_APPLIC` exist
for exactly this, and the source argues the case for `COVERAGE_GAP` joining the second list at
length. The lists are correct; they are consulted on values nothing validates.

**Reproduction.**

```
python tests/prove_hollow_scan.py        # exits 1, prints all five
```

Observed 2026-10-08, five scenarios, each independently sufficient:

| Shape | What the SARIF says | Rendered |
|---|---|---|
| `declared_failure` | `invocations[0].executionSuccessful: false`, `exitCode: 0`, a FATAL `toolExecutionNotifications` entry | clean |
| `zero_rules` | `tool.driver.rules: []` | clean |
| `zero_artifacts` | `artifacts: []`, `properties.files_scanned: 0` | clean |
| `no_runs` | `runs: []` — no tool name, no rules, no results | clean |
| `permissive_default` | a state file naming only `scanner` and `sarif` | clean, with `0` in the Blocking and Total columns |

The fields the reporter does not read are `runs[].invocations[].executionSuccessful`,
`runs[].invocations[].toolExecutionNotifications`, `runs[].tool.driver.rules` and
`runs[].artifacts`. All four are in the document it already parsed.

**Why the workflow does not save it.** `reusable-security.yml` computes `execution` in shell, out
of band, and that shell can catch a scanner whose process exit code is non-zero. The
`declared_failure` shape is chosen specifically to defeat it: the scanner exits **0** and declares
its failure only inside the SARIF, so the shell sees success and the only witness is the field
nobody reads. `zero_rules` and `zero_artifacts` are invisible to that shell as well — it observes
the process, not the rule set or the denominator.

`permissive_default` needs no scanner failure at all. `batch()` substitutes
`applicability='APPLICABLE'` and `execution='COMPLETE'` for any state file that omits them, so an
**omission produces the strongest claim the vocabulary can express**. That is the opposite of
fail-closed, and it is the shape a consumer wiring their own job is most likely to produce —
`roster_faults` does not catch it, because a state file that exists and names a scanner is not a
missing one.

**Blast radius if it shipped.** A consumer enables the kit, a scanner's vulnerability database
download times out, and the step summary reports a clean scope. There is no warning, no
`COVERAGE_GAP`, no `NOT ESTABLISHED` — the output is identical to a genuinely clean repository,
and it is the strongest-looking output the reporter can emit. `nothing was looked at` printed as
`nothing found` is the single collapse this kit's governing rule names first, and the deliverable
would be shipping it in its own reporter.

### State: FIXED

`tests/prove_hollow_scan.py` went from **exit 1 to exit 0**, all five shapes refused, with its
`--self-test` at exit 0 and the proof itself unweakened — it matches the same literal sentence and
asserts the same five shapes.

| Shape | Before | After |
|---|---|---|
| `declared_failure` | clean | `NOT ESTABLISHED` |
| `zero_rules` | clean | `NOT ESTABLISHED` |
| `zero_artifacts` | clean | `NOT ESTABLISHED` |
| `no_runs` | clean | `NOT ESTABLISHED` |
| `permissive_default` | `\| trivy \| APPLICABLE \| COMPLETE \| 0 \| 0 \| 0 \|` | `\| trivy \| UNKNOWN \| NOT_DECLARED \| NOT ESTABLISHED \| -- \| -- \|` + 1 roster fault |

**Revised 2026-10-16 (KDEC-008 OD-2).** `zero_rules` was the wrong shape to call hollow: an empty
`rules` array is exactly what a CLEAN bandit run emits (bandit lists only rules that fired), and the
owner ruled that a clean bandit run is not hollow. The empty-rules witness is now per tool (no profile
enables it); the slot is `bandit_unparsed` (an error in `toolConfigurationNotifications`, which the
reporter now reads alongside the execution array), and a clean bandit run is a control that must read
clean. The proof is wired into self-test.

**The control still works, which is the half that makes the fix a fix rather than a refusal to
answer.** A run that declared itself successful, loaded rules, examined 128 artifacts and found
nothing still renders `Findings: **NONE** in the scanned scope.` A reporter that refused every
verdict would have satisfied every assertion above.

**What was built.** A **second axis**, not a fourth value on the existing one.
`scan_examination` — `EXAMINED` / `EXAMINED_NOTHING` / `NOT_DECLARED` — is registered in
`assurance-taxonomy.yaml` and **derived from the SARIF**, never supplied by the caller.
`execution_state` is *declared* by the job that ran the scanner, and that job is the thing being
checked: a scanner that crashes and exits 0 produces a job that **truthfully** declares
`COMPLETE`. Folding the two together would mean asking the caller whether the caller was right.

`examination_of(doc)` reads the four witnesses the reporter previously ignored, **any one of
which is sufficient alone** — they describe different ways of reading nothing and do not
corroborate each other, so requiring agreement would mean a scanner has to fail in two ways
before anyone is told. `render` now takes the verdict as a **required** parameter with no default,
because a default here would be this same defect one layer up.

**Two places the care actually went, both of which the self-test caught or pinned:**

- **Absent is not empty.** `rules` and `artifacts` are *optional* in SARIF. Only an array that is
  **present and empty** is a witness. The first draft of `examination_of` did not count
  `executionSuccessful: true` as an affirmative witness, so a conforming scanner declaring success
  and omitting both optional arrays was read as having examined nothing — `NOT ESTABLISHED` would
  have become the ordinary result of a healthy scan. **The self-test caught it before it was
  committed.** A false-failure flood gets a gate muted and is no safer than a false pass; that is
  D-4's lesson, and it applied here within the hour.
- **A finding outranks every witness.** A result is itself proof that something was read, and
  stronger proof than any metadata, so a scanner reporting findings while omitting its
  `invocations` is not punished for the omission.

**The default direction is inverted.** `--applicability` now defaults to `UNKNOWN` (already
registered, and its own taxonomy entry says *"Run anyway and say so; never report a clean
result"* — it was the one value in that namespace carrying that instruction and the one value
`NO_COUNT_APPLIC` omitted). `--execution` and `batch()`'s substitution now default to
`NOT_DECLARED`, newly registered for exactly this position. **Silence now degrades a verdict
instead of strengthening it**, and a state file declaring neither field is also a **roster
fault** — degrading the row keeps the report honest, and the fault is what stops the wiring
defect being permanently absorbed by an honest-looking `NOT ESTABLISHED` row.

**Fails closed on an unrecognised state.** `COUNTABLE_EXAMINATION` is a membership test over an
allowed set, not an inequality with one bad value, so a value added to the namespace later and not
to the allowed set refuses rather than passes. Asserted by a deliberately unregistered
`SOME_FUTURE_VALUE` in `scan_report.py`'s self-test — listed in `reconcile_taxonomy.py`'s
`NOT_VOCABULARY` with the reasoning, following the `GATE_RELAXED` precedent, because registering
it would make the rogue value legitimate and silently disarm the assertion.

**The axis is printed on every row, green ones included.** A caveat that appears only when it is
bad teaches a reader that its absence means nothing was checked.

**Workflow regenerated cleanly.** `scripts/inline_normalizer.py` → all 6 inlined copies identical
to canonical, `--check` exit 0. `reusable-security.yml` grew **373.4 KB → 409.3 KB (+35.9 KB)**.
`check_workflow_size.py` exits 0: **65.7 KB under the 475 KB fail threshold and 90.7 KB under
GitHub's 500 KB hard limit.** The *"approaching the size limit"* warning was already present
before this change at 373.4 KB (the warn threshold is 350 KB), so the warning is not new, but the
headroom is now smaller and worth saying so. **Nothing was trimmed to fit.**

**Residual, stated rather than hidden.** A scanner that declares `executionSuccessful: true`,
omits both optional arrays, and genuinely read nothing is still `EXAMINED`. This axis cannot see
that case — only a denominator could. It is the weakest row in `examination_of` and the first to
revisit against real scanner output.

**Suggested mitigations** (each PROPOSED until an approver records evidence; `scripts/check_register_mitigations.py` refuses a COMPLETED one without evidence and a human approver):
- M1 PROPOSED — Keep prove_hollow_scan.py and the hollow-scan witness required; add any new scanner to the hollow fixtures when it is added.

---

## D-2 · The durable finding identity is empty for every finding, from every scanner — **SEVERE** · **FIXED**

**What it is.** `scripts/finding_identity.py` is correct. `scripts/scan_report.py` calls it on
every finding. The record it passes cannot satisfy **any** registered subject's specification, so
`identify()` refuses every time and `identity` is the empty string on 100% of findings.

`parse_sarif` populates three identity fields — `purl`, `canonical_path`, `symbol_path`. The eight
subject specifications between them require `construct`, `package_name`, `package_version`,
`module_path`, `resource_type`, `resource_name`, `attribute_path`, `resource_id`, `observed_value`,
`target_host`, `target_path`, `observed_condition`, `policy_definition_id`, `principal_id`,
`role_definition_id`, `assignment_scope` and `release_id`. **None of those names appears anywhere
in `scan_report.py`.**

**Reproduction.**

```
python tests/prove_identity_durability.py    # exits 1
```

Observed 2026-10-08. The control — `identify()` called directly on a complete record — **HELD**
across a scanner swap, a version bump, a rule rename, a reworded message and a line move. Every
end-to-end scenario produced an empty identity:

| Scenario | `identity_state` | reason | legacy `fp` |
|---|---|---|---|
| Semgrep 1.45 → 1.92, message reworded | `UNFINGERPRINTABLE` | `CONTENT_UNDERIVABLE` | **MOVED** |
| the same, plus the rule renamed | `UNFINGERPRINTABLE` | `CONTENT_UNDERIVABLE` | **MOVED** |
| Trivy dependency finding with CVE **and** purl present | `UNFINGERPRINTABLE` | `CONTENT_UNDERIVABLE` | **MOVED** |

The control passing is what localises the defect: the identity model is sound and nothing feeds
it. Those are different bugs with different fixes, and a test that reported one word for both
would have sent the next reader to the wrong file.

**The trap this nearly hid behind.** The obvious assertion is
`identity_before == identity_after`, and it **passes today** — both sides are `''`. A test written
that way reports durable identity over a pipeline that computes none. `tests/prove_identity_durability.py`
therefore asserts non-emptiness first and separately, keeps two failure vocabularies apart
(`IDENTITY_NEVER_COMPUTED` vs `IDENTITY_MOVED`), and its `--self-test` asserts that two identical
empty identities are reported as the former rather than as stability.

**Blast radius if it shipped.** The legacy key is
`fingerprint(scanner, rule_id, uri, message)`, and all four inputs are on `finding_identity.py`'s
own FORBIDDEN list with the reason for each. Dispositions — false positives, mitigations, risk
acceptances, deferrals — are keyed on it. So a vendor rewording one sentence in a string table
orphans every approval against that rule, and the findings reappear as NEW. A reviewer facing a
wall of re-raised findings approves in bulk or stops reading, and the register stops meaning
anything. The failure is silent, arrives on a routine scanner upgrade, and the register looks
healthy throughout — nothing reports an orphan rate because nothing knows the old key existed.

**Relationship to `risks.md` R-10.** R-10 records this and is correct, with one understatement
this pass corrected. R-10 attributes it to one cause — `SOURCE` needs a `construct`, which is the
SARIF snippet, and the kit redacts snippets. The observed scope is wider: **seven of the eight
subjects fail on `where`, not on content**, and `where` has nothing to do with redaction.
`IMAGE` needs `package_name` and `package_version`; `IAC_PLAN` needs a resource address;
`RESOURCE`, `RUNTIME_OBSERVATION`, `POLICY`, `IDENTITY_ASSIGNMENT` and `RELEASE` each need
platform identifiers. None is extracted. Lifting the redaction constraint alone would fix nothing.

### State: FIXED

`scripts/scan_report.py` gained the per-subject extraction layer the entry above said it needed
(`locus_of`, `construct_of`, `language_family_of`, `purl_parts`, `_url_locus`), and
`tests/prove_identity_durability.py` went **1 → 0**.

| Scenario | before | after |
|---|---|---|
| Semgrep 1.45 → 1.92, message reworded **and snippet reformatted** | `UNFINGERPRINTABLE` / `CONTENT_UNDERIVABLE` | **FINGERPRINTED, identity HELD** |
| the same, plus the rule renamed | `UNFINGERPRINTABLE` / `CONTENT_UNDERIVABLE` | **FINGERPRINTED, identity HELD** |
| Trivy dependency finding with CVE **and** purl | `UNFINGERPRINTABLE` / `CONTENT_UNDERIVABLE` | **FINGERPRINTED, identity HELD** (via D-3's new subject) |
| two findings in one file, different symbols | both empty — collision untestable | **two distinct identities** |
| a SAST finding with the construct **removed** | *not tested* | `UNFINGERPRINTABLE` / `CONTENT_UNDERIVABLE`, no hash |

The legacy `fp` **MOVED in all three** vendor-change scenarios, before and after. That contrast
is the whole value of the fix and it is printed by the proof on every run.

**What was populated, and what deliberately was not.** Twelve of the fourteen missing names are
now derived: `construct`, `language_family`, `package_name`, `package_version`,
`package_source`, `module_path`, `resource_type`, `resource_name`, `attribute_path`,
`target_host`, `target_path`, `observed_port`, `observed_condition`. **`dependency_scope` and
`manifest_role` are deliberately left unpopulated**, and that is a decision rather than an
omission: they are OPTIONAL locus fields, and an optional locus field a scanner reports in one
run and omits in the next moves the identity between runs — the defect the module exists to
prevent, arriving through its own fix. Nothing the kit's scanners emit states either reliably.

`RESOURCE`, `IDENTITY_ASSIGNMENT`, `POLICY` and `RELEASE` have **no extractor and say so by
name**. No scanner in this kit maps to them, so the refusal reads *"no extraction was attempted"*
rather than *"the fields were absent"* — which are different states and must not collapse.

**Extraction is tiered, and the tier is recorded** in a new `locus_basis` field on every finding,
on the same discipline as `provenance_identity.observation_time`: a structured purl (tier 1), a
structured field under one of the several names scanners disagree about (tier 2), a labelled
value inside a rendered message (tier 3). Tier 3's capture is constrained to a coordinate-shaped
token so a reworded label **misses** — which refuses — rather than capturing a sentence, which
would move an identity silently.

**Secret findings now refuse under their own name.** `parse_sarif` sets `is_secret_finding` for
gitleaks, detect-secrets, trufflehog and any secret/credential rule namespace, so `identify()`
refuses them with `SECRET_SUBJECT_NOT_BASELINEABLE` instead of `CONTENT_UNDERIVABLE`. This is
both a better sentence and the precondition for hashing constructs at all — see D-8.

**Suggested mitigations** (each PROPOSED until an approver records evidence; `scripts/check_register_mitigations.py` refuses a COMPLETED one without evidence and a human approver):
- M1 PROPOSED — Keep prove_report_emits_findings.py and the identity proofs required; alert when identity is empty on more than a set share of findings.

---

## D-3 · `SOURCE` requires a construct, so no dependency finding can ever be fingerprinted — **SEVERE** · **FIXED**

**What it is.** A design defect in the specification table, separate from D-2 and not fixed by
fixing it. `SPEC['SOURCE']['content'] = 'construct'` — **mandatory**, no `?` prefix. A dependency
vulnerability has no matched construct: the package coordinate is the whole finding. The module
has a declared sentinel for exactly this state, `CONTENT_NOT_APPLICABLE_FOR_SUBJECT`, and uses it
for `IMAGE`, where `content` is `None`. `SOURCE` cannot express it.

`finding_subject.BY_SCANNER` routes `pip-audit`, `npm-audit` and `dotnet-vuln` to `SOURCE`, and
`subject_for` routes Trivy pointed at a dependency manifest to `SOURCE` as well. So every
dependency finding in the kit lands on the one subject that cannot represent it.

**Reproduction.** Observed 2026-10-08:

```
identify({'finding_subject': 'SOURCE', 'cve': 'CVE-2018-18074',
          'purl': 'pkg:pypi/requests@2.19.1', 'canonical_path': 'requirements.txt'})
  -> UNFINGERPRINTABLE / CONTENT_UNDERIVABLE
     "subject SOURCE requires `construct` and it is absent or empty"

identify({'finding_subject': 'IMAGE', 'cve': 'CVE-2018-18074',
          'package_name': 'requests', 'package_version': '2.19.1'})
  -> FINGERPRINTED
```

A perfect record — a real advisory id and a real purl, the two strongest inputs the model accepts
— is refused on the source path and accepted on the image path. The same vulnerability in the
same package is fingerprintable in a container and not in a lockfile.

**Blast radius if it shipped.** Dependency findings are the highest-volume class in most
repositories and the one whose approvals are most often time-boxed ("accept until the upstream fix
lands"). None of them can hold a durable key, so this is D-2's consequence concentrated on the
category that can least afford it — and unlike D-2, it would survive a complete and correct
extraction layer, which makes it the easier of the two to leave behind by accident.

### State: FIXED — by splitting the subject, not by loosening the requirement

**The decision: a ninth registered `finding_subject`, `SOURCE_DEPENDENCY`.** Its locus is the
package coordinate (`purl` **required**, not optional) and its `content` is `None`, so CONTENT is
the declared `CONTENT_NOT_APPLICABLE_FOR_SUBJECT` sentinel read from the specification table —
the same shape as `IMAGE`, for the same reason, because it is the same kind of fact about a
different artifact. `SPEC['SOURCE']['content']` is **unchanged and still mandatory**.

Registered in `assurance-taxonomy.yaml` under `finding_subject`, with a `forbidden:` clause
naming `SOURCE` and `SOURCE_DEPENDENCY` as the pair that must not collapse.
`finding_subject.BY_SCANNER` routes `pip-audit`, `npm-audit`, `dotnet-vuln` and
`dependency-check` there, and `subject_for` routes any multi-modal scanner pointed at a
dependency manifest there.

**Why not `'?construct'`, which is one character and would also have passed the proof.** Because
`_derive_content` returns the not-applicable sentinel for an absent **optional** key. A Semgrep
finding whose scanner merely failed to carry its construct — or whose construct the kit's own
pre-upload redactor stripped (D-8) — would then hash as though no construct had ever existed.
Two different injections in one function would share one identity and the second would inherit
the first's risk acceptance. That is the permissive direction, and a security gate does not get
to make those errors. The deeper objection is the four-state rule: *"this subject has no matched
construct"* and *"this finding has one and we could not read it"* are two states, and an optional
key answers both with one sentinel.

**The fix also delivers something `SPEC['SOURCE']['why_stable']` had already promised and the
table did not implement:** *"When the finding is a dependency, the PURL replaces the path
entirely."* Under `SOURCE` that sentence was false — `?purl` was optional and `canonical_path`
was required — so the lockfile path went into every dependency locus and every dependency finding
in a repository shared most of its WHERE with every other, and all of them would have been
orphaned at once by a monorepo re-layout.

**Both halves are asserted, because the cheap fix stays one character away forever.**
`finding_identity.py --self-test` now checks that the D-3 reproduction record fingerprints under
the new subject, that its CONTENT is the sentinel and not a hash, that the manifest path does
**not** reach the locus, that a version change **does** change the identity, that
`SPEC['SOURCE']['content'] == 'construct'` literally, and that a SAST finding with no construct
still refuses with `CONTENT_UNDERIVABLE` carrying no hash.

**Reproduction, after:**

```
identify({'finding_subject': 'SOURCE_DEPENDENCY', 'cve': 'CVE-2018-18074',
          'purl': 'pkg:pypi/requests@2.19.1', 'canonical_path': 'requirements.txt'})
  -> FINGERPRINTED, content = CONTENT_NOT_APPLICABLE_FOR_SUBJECT

identify({'finding_subject': 'SOURCE', 'cwe': 'CWE-89', 'rule_family': 'f',
          'canonical_path': 'a.py', 'symbol_path': 'm.f'})
  -> UNFINGERPRINTABLE / CONTENT_UNDERIVABLE      # still refuses, by design
```

**Suggested mitigations** (each PROPOSED until an approver records evidence; `scripts/check_register_mitigations.py` refuses a COMPLETED one without evidence and a human approver):
- M1 PROPOSED — Keep the split subject (SOURCE_DEPENDENCY) proven; review the subject table when a new finding kind is added.

---

## D-8 · The redactor strips the only carrier of CONTENT before the reporter reads it — **SEVERE** · **FIXED IN CODE (KDEC-038), PROVEN LOCALLY; HOSTED RUN OWED**

**2026-11-06, lane kit-sast-export (KDEC-038).** The report no longer depends on the snippet. The security-gate job
checks out the scanned commit, and `scan_report` (with `--source-root`, passed by the scan-report composite) reads
a SOURCE finding's reported line from the file: the construct, the enclosing symbol and a code anchor (the
normalised line and its ordinal -- never the line number), through `scripts/code_finding_key.py`. Every tool reads
the same text, so bandit and semgrep on one line are one identity. A path outside the checkout is never read
(SOURCE_PATH_REFUSED); a file not in the checkout leaves the old behaviour, said in the basis. Proven by
`tests/prove_sast_secret_tickets.py` on SARIF that carries NO snippet; not yet observed in a hosted report job.
The rest of this entry is the record as it stood.


**What it is.** Two controls in this kit are in direct conflict, and fixing D-2 is what made the
conflict visible rather than academic.

`SPEC['SOURCE']['content']` is `construct`, and the only place a SARIF document carries a matched
construct is `locations[].physicalLocation.region.snippet.text` (or `contextRegion.snippet`).
`scripts/redact_sarif.py` **removes both**, correctly — for a secret scanner the snippet *is* the
secret — and `scripts/redact_all.sh` runs that sweep **before the first upload step of every job
that uploads**, which is also correct: a redactor that runs after the upload protects nothing.

The consolidated `report` job then reads those **uploaded, already-redacted** artifacts
(`scan_report.batch` opens the SARIF named in each per-job state file). So on the real pipeline
the construct is gone by the time the reporter sees it, and every SAST finding refuses with
`CONTENT_UNDERIVABLE`.

**Status of the evidence.** Established by reading the generated workflow and the two scripts.
`tests/prove_identity_durability.py` passes because it calls `parse_sarif` directly on an
unredacted document, which is the pre-redaction position — so the extraction is proven and the
*pipeline placement* is not. **`reusable-security.yml` has never been run end to end**, so the
production behaviour is NOT ESTABLISHED by execution.

**Why the honest outcome is a refusal and not a weaker hash.** `CONTENT_UNDERIVABLE` on a
redacted SAST finding is the correct state: the construct exists and could not be read. Making
`content` optional to make those findings fingerprint is D-3's rejected fix wearing a different
hat, and it would hand one identity to every finding in a symbol.

**The fix, not taken here because it is a workflow change rather than a script change.** Compute
the identity **in the scanner job, before redaction**, and carry the three component hashes
forward in the per-job state file. The hashes are safe to carry where the raw snippet is not: the
`LITERALS_PLACEHOLDERED` policy replaces every string and numeric literal before hashing, so a
credential is destroyed before the hash exists. That is also why hashing a construct at all is
defensible — and why `parse_sarif` now sets `is_secret_finding` for secret scanners, so a secret
finding refuses outright and no secret-derived material can reach a ledger under any ordering.

**Blast radius if it ships unfixed.** D-2's symptom returns for the SAST half of the estate while
the gate reports a fixed identity model — the worst combination, because the proof is green.
Dependency and image findings are unaffected: neither has a construct to strip.

**Suggested mitigations** (each PROPOSED until an approver records evidence; `scripts/check_register_mitigations.py` refuses a COMPLETED one without evidence and a human approver):
- M1 PROPOSED — Keep tests/prove_sast_secret_tickets.py required (the line read from the checkout replaces the redacted snippet), and run it hosted once on the public mirror.

---

## D-9 · The advisory alias SET had exactly one member by construction — **MODERATE** · **FIXED**

**What it is.** `finding_identity._derive_what` composes WHAT from an alias **set** and says why
in its own comment: *"carried as a SET because advisories re-alias; §5.6 matches on INTERSECTION,
which needs the members."* `scan_report.what_of` searched for a CVE, then a GHSA, then an OSV id —
and `break` on the first hit. A finding whose SARIF carried both `CVE-2018-18074` and
`GHSA-x84v-xcm2-53pg` produced the single-element set `{CVE-2018-18074}`.

So the alias machinery existed, was wired, and was fed one alias forever. Set intersection
against a one-element set is equality with extra steps, which means §5.6's re-aliasing tolerance
was unreachable.

**Reproduction (before).** `tests/prove_lineage_durability.py::scenario_alias` added
`rule.properties.aliases = ['GHSA-x84v-xcm2-53pg']` to a Trivy SARIF already carrying
`CVE-2018-18074` and observed the identity **unchanged** — `05013d6bef5d4693` before and after.
After removing the `break`: `05013d6bef5d` → `75eb072434e0`.

**State: FIXED.** The `break` is gone and the basis line records every alias found.

**The consequence, stated rather than hidden.** WHAT hashes the sorted alias set, so a feed adding
an alias to an existing advisory now **moves** the identity. That is not introduced by this
change — it was always going to happen the first time two aliases appeared in one document — and
the honest answer to it is a lineage event, not a smaller set. It is registered as
`ADVISORY_ALIAS_ADDED` and it is the one cause where nothing in the repository and nothing in the
scanner changed.

**Suggested mitigations** (each PROPOSED until an approver records evidence; `scripts/check_register_mitigations.py` refuses a COMPLETED one without evidence and a human approver):
- M1 PROPOSED — Keep the alias-set proof required; add advisories with three or more aliases to its fixtures.

---

## D-4 · A harness that could not run reported the gate it tests as broken — **MODERATE** · **FIXED**

**What it is.** `tests/prove_bootstrap_failure.py` resolved its shell with
`shutil.which('bash')`. On Windows that returns `C:\Windows\system32\bash.exe` — the WSL launcher
stub, which exists, is executable, and fails every invocation when no distribution is installed or
its mounts are broken. All four scenarios got exit 1 and an empty `$GITHUB_OUTPUT`, and the file
reported `FAIL: all_green — the CONTROL did not go green` with exit 1.

**Reproduction (before the fix).** On a Windows host with the WSL stub first on `PATH`:

```
python tests/prove_bootstrap_failure.py
  -> all four scenarios exit=1, assurance=(none), enforcement=(none)
  -> "FAIL: all_green -- the CONTROL did not go green"   exit 1

# the same file, with Git Bash first on PATH
  -> all_green  exit=0  PASS/ALLOWED/false
  -> the three failure scenarios  BLOCKED/true
  -> PASS, exit 0
```

**Blast radius.** No false assurance claim — this direction is a *false failure*. That is not the
safe direction either. A gate that cries wolf gets muted, and the next real failure arrives in a
file nobody reads any more; the person who muted it was being reasonable at the time. And the
collapse is the kit's own: *nothing was looked at* rendered as *the control is broken*, inside the
file that exists to enforce the distinction. Its header already promised exit 2 for "could not be
checked — reported as UNKNOWN, never as PASS"; it honoured the never-as-PASS half and dropped the
report-as-UNKNOWN half.

**State: FIXED** in `862d92d`. Shell selection is now a **capability probe** rather than a path
lookup: a candidate must run a script that exits 7 **and** appends a known line to
`$GITHUB_OUTPUT`, and both must be observed. A stub that exits non-zero for its own reasons cannot
satisfy it, and neither can a shell that runs but cannot write the file the harness reads its
results from. Git for Windows' bash is named explicitly as a fallback candidate. Both branches
observed: with only the stub reachable the probe rejects it and names the WSL error and the file
exits 2; with Git Bash present the gate proves itself and exits 0.

**Suggested mitigations** (each PROPOSED until an approver records evidence; `scripts/check_register_mitigations.py` refuses a COMPLETED one without evidence and a human approver):
- M1 PROPOSED — Use the shared usable_bash() probe in every harness; the battery puts Git for Windows bash ahead of the WSL stub (tools/battery.ps1).

---

## D-5 · Structurally malformed SARIF raises out of the parser instead of returning `UNPARSEABLE` — **MODERATE**

**What it is.** `parse_sarif` documents three states — `COMPLETE`, `ABSENT`, `UNPARSEABLE` — and
its own comment says *"UNPARSEABLE is not zero findings. It is a collection failure wearing a
report's clothes."* A fourth state exists undeclared. The `try/except` covers `json.load` only, so
valid JSON whose SARIF structure is wrong reaches `run.get('tool')` on a non-mapping and raises.

**Reproduction.** Observed 2026-10-08 while writing `tests/prove_identity_durability.py`:

```
echo '{"runs": ["a-string-not-an-object"]}' > bad.sarif
python -c "import sys; sys.path.insert(0,'scripts'); import scan_report; \
           scan_report.parse_sarif('bad.sarif','trivy')"
  -> AttributeError: 'str' object has no attribute 'get'
```

**Blast radius.** `batch()` calls `parse_sarif` for every scanner with no exception handling, so
one malformed document destroys the whole report — fifteen scanners that worked included. The
failure is **loud**, which is why this is MODERATE and not worse: nobody is told anything false.
But a truncated upload or a scanner emitting a non-conforming document costs the entire run's
reporting rather than one row reading `UNPARSEABLE`, and the traceback points at the reporter
rather than at the scanner that wrote the bad file. The caller is misdirected, not misled.

**State: DOCUMENTED, NOT FIXED** — same inlining constraint as D-1 and D-2; it belongs in the same
change. `tests/prove_identity_durability.py --self-test` asserts the condition is reported by name
rather than swallowed, so the behaviour is pinned and a future fix will be visible.

**To close it.** Widen the `except` in `parse_sarif` to `(ValueError, IOError, AttributeError,
TypeError)` returning `UNPARSEABLE`, and have `batch()` isolate each scanner so one bad document
costs one row.

**Suggested mitigations** (each PROPOSED until an approver records evidence; `scripts/check_register_mitigations.py` refuses a COMPLETED one without evidence and a human approver):
- M1 PROPOSED — Keep prove_malformed_sarif_isolated.py required and add each new malformed shape found in the wild to its fixtures.

---

## D-6 · Five validation deferrals expired 8 days ago and the gate is RED — **MODERATE** · **DELIBERATELY NOT "FIXED"**

**What it is.** `tests/reconcile_validation.py` exits 1 with 6 BLOCKING items. Observed
2026-10-08:

```
! deferral for `nvd-trivy`         EXPIRED 2026-09-30 (8d ago)
! deferral for `nvd-dockerfile`    EXPIRED 2026-09-30 (8d ago)
! deferral for `code-quality`      EXPIRED 2026-09-30 (8d ago)
! deferral for `sast-java`         EXPIRED 2026-09-30 (8d ago)
! deferral for `context-integrity` EXPIRED 2026-09-30 (8d ago)
! 12 capabilities are proven at TOOL level only — reusable-security.yml has never been
  invoked end-to-end — and no deferral in DEFERRALS
10/15 of the debt ratchet used.
```

**Why it is left RED.** The gate's own message is *"Prove it, or make a fresh dated decision —
silence must not renew a deferral."* Editing five dates forward is the precise failure that gate
was built to catch, and it would convert a visible, dated, owned debt into an invisible one while
turning the build green — a strictly worse state than the red one, arrived at by the action that
most looks like fixing it. No new evidence was produced for any of the five in this pass, so there
is nothing to prove them with, and the decision is the owner's (`kit-maintainer`) and not a
passing worker's.

**Blast radius.** The debt is correctly recorded and correctly loud. The risk is **ratchet
exhaustion**: 10 of 15 slots are used, and a red gate that stays red for weeks is one somebody
eventually works around. That is the same muting dynamic as D-4, on a longer clock.

**State: REPORTED, UNCHANGED.** Needs a dated decision by the owner, not a worker's edit.

**Suggested mitigations** (each PROPOSED until an approver records evidence; `scripts/check_register_mitigations.py` refuses a COMPLETED one without evidence and a human approver):
- M1 PROPOSED — Keep the expired-deferral gate red until each deferral is closed by evidence or re-dated by the owner with a reason.

---

## D-7 · The export-safety gate flags a file the exporter does not ship — **MINOR** · ANOTHER WORKER'S SURFACE

**What it is.** `tests/check_export_safety.py` exits 1 with two denied-pattern hits in
`scripts/export-profiles/consumer-am.txt`, introduced by `da6a1ac` *("A copy going TO someone
should not be gated as though it were going past them")* — in-flight work on the export surface
by another worker, landed partway through this pass.

The gate scans the neutral core and excludes `overlays/` only. The exporter excludes
`export-profiles` as well, via `EXCLUDE_TOP`. So the two scopes have diverged, and the gate is
reporting on a file that no export carries.

**Reproduction.** Observed 2026-10-08, using the exporter's **own** predicate rather than reading
its exclusion list:

```
python tests/check_export_safety.py
  -> 2 hit(s) in scripts/export-profiles/consumer-am.txt   exit 1

python -c "import sys; sys.path.insert(0,'scripts'); import export_for_adoption as e; \
           print(e.exportable('scripts/export-profiles/consumer-am.txt'))"
  -> False
```

**Blast radius.** No disclosure: the named file does not leave the repository through either the
full or the incremental export, and the two paths share one predicate by construction. The cost is
a red gate that is a false positive — the D-4 muting dynamic a third time, and the one direction
where it matters most, because this is the gate that guards against naming one consumer to the
next. A reader who learns to expect two hits here will not notice the third.

**State: REPORTED, NOT FIXED.** `scripts/export_for_adoption.py` and `scripts/export-deny.txt`
are owned by another worker mid-change and were not touched. The fix is to give
`check_export_safety.py` the exporter's exclusion predicate rather than its own copy of part of
it — **the same "one truth in two places" failure the exporter's own `exportable()` docstring
warns about**, one layer out — and it belongs with whoever owns that surface.

**Suggested mitigations** (each PROPOSED until an approver records evidence; `scripts/check_register_mitigations.py` refuses a COMPLETED one without evidence and a human approver):
- M1 PROPOSED — Keep the export profile excluded from the export it governs, and prove it in prove_export_scope.py.

---

## D-10 · The resolve position caps CodeQL on a platform pre-flight the analysis contradicts — **MODERATE** · **DOCUMENTED, NOT FIXED**

**What it is.** `.github/actions/resolve/action.yml` withdraws the `codeql` job whenever discovery's
platform probe reads code scanning `UNAVAILABLE` or `NOT_CONFIGURED`, labelling every CodeQL
candidate `PLATFORM_UNAVAILABLE` with the reason *"code scanning is UNAVAILABLE on this repository,
so codeql cannot run here (PO 6.3)"*, and the gate and report then cap the job at `PARTIAL`.

**Observed (first Level 2 dispatch, private consumer repository, run 38817782084, kit at
`1a5f6f9`).** The platform probe read `UNAVAILABLE` — there is no licence — and the CodeQL job
nonetheless initialised, analysed and wrote five Python and four JavaScript results to the
evidence bundle. Only `upload-sarif` was refused (*"Code scanning is not enabled for this
repository"*). The licence governs **publication** to the Security tab, not whether the analysis
runs. The same premise sat in the gate's CodeQL rows and is fixed there (`f7a7ed1`,
`tests/prove_codeql_rows_read_sarif.py`): a discovered language whose SARIF arrived is applicable
and its row follows the evidence.

**Why it is a defect and not a conservative default.** The report told a reader that CodeQL
"cannot run here" over nine retained findings it had just run and found. That is "the control
could not be acquired" written over "the control found something" — a wrong diagnosis, loud
rather than silent, which is why it is MODERATE and not CATASTROPHIC.

**State: DOCUMENTED, NOT FIXED.** The fix is the resolve composite's: withdraw CodeQL on
`PLATFORM_UNAVAILABLE` only from *publication*, and let the capability verdict read the job's own
`cq_state` (COMPLETE / COLLECTION_FAILED / UNAVAILABLE) rather than the pre-flight. It touches
`tests/test_resolve.py`'s platform rows and was deliberately not folded into the gate fix.

**Suggested mitigations** (each PROPOSED until an approver records evidence; `scripts/check_register_mitigations.py` refuses a COMPLETED one without evidence and a human approver):
- M1 PROPOSED — Let CodeQL run when the analysis can read the code even if the platform probe says UNAVAILABLE, recording the probe and the result separately.

---

## D-11 · A rejected job token was reported five different ways, none naming it — **MODERATE** · **FIXED**

**Observed (owner's work copy, GHE.com data-residency host, GitHub-hosted runners, 2026-11-02;
screenshots only).** Every API call with the job's own `github.token` was answered 401 "Bad
credentials", at `https://api.github.com/...`: resolve "Consume the platform-probe values" crashed on
`Invalid format '  "message": "Bad credentials",'`; the consumer path's dispatch and collect steps
printed a raw `HTTP 401` with `gh auth login` advice; the self-test pin step said *"rate-limited ...
(set GITHUB_TOKEN to lift the unauthenticated limit)"* with GITHUB_TOKEN set; every Trivy scan was
COLLECTION_FAILED after setup-trivy's checkout of `aquasecurity/trivy`; Dependabot Updates failed
`dependency_file_not_found` on `/Dockerfile`.

**Root cause, traced.** Those messages are KDEC-027's defects, and they are not in the kit the owner
exported (`82e95a7`): the unsanitised `dependabot_basis=...${body:0:160}` write was fixed in
`8b64f97`, the "lift the unauthenticated limit" text removed in `686431b`, trivy-action/setup-trivy
removed in `3fdb59f` (all 2026-10-23, all ancestors of `82e95a7`). `tests/prove_job_token_named.py`
run against the `c7e1ea9` tree (`KIT_PROOF_ROOT`) reproduces the crash (6 unparseable output lines)
and the 8 setup-trivy sites; against `82e95a7` the output parses and Trivy is the pinned binary. So
the runs executed a pre-KDEC-027 revision -- scheduled runs use the DEFAULT branch's workflow files --
on a ghe.com host, where a token sent to github.com is always 401. The kit fixed the crash then; what
it still lacked was the NAME: nothing said "GitHub refused this job's token, on which host, whose
setting". Separately, `.github/dependabot.yml` listed eight ecosystems at `/` where the kit has no
manifest; Dependabot fails such a job instead of skipping it (the file's comment said otherwise).

**Fixed (2026-11-02).**
1. **A job token preflight**, in a step that already ran: the discover platform step's repository GET
   classifies its answer (`scripts/api_token_cause.sh`, taxonomy `api_token_preflight`):
   `JOB_TOKEN_REJECTED`, `ORG_IP_ALLOW_LIST_BLOCKS_RUNNER`, `ORG_SSO_BLOCKS_TOKEN`, `RATE_LIMITED`,
   `API_UNREACHABLE`, `TOKEN_PREFLIGHT_UNCLASSIFIED`; output `token_preflight`, one summary row with
   the owner role and the checklist, one annotation titled with the cause. No new job, no new check.
2. **Downstream reports the same word**: resolve's Dependabot basis and owner row; the consumer
   path's three gh jobs run the same preflight first and fail on it, named; the pin checkers' UNKNOWN
   names the cause per path (git: `API_UNREACHABLE`; REST: `JOB_TOKEN_REJECTED (HTTP 401)` /
   `RATE_LIMITED (HTTP 403)` / "no token api.github.com issued"). Exit codes unchanged (2).
3. **The host is written, never defaulted**: every `GH_REPO` and `-R`/`--repo` naming this run's
   repository is `${GH_HOST}/OWNER/REPO`; `gh attestation verify` passes `--hostname`
   (`tests/prove_ghe_host.py` H8 static, H9 under bash on a simulated ghe.com host).
4. **Trivy**: the self-test tool composite's `install.sh` (unpinned script, run as root) is the same
   pinned, sha256-verified release binary as every scan job (T8 refuses setup-trivy, a checkout of
   aquasecurity/trivy, or install.sh).
5. **Dependabot**: entries only where a manifest is (github-actions; terraform at
   `/infra/feed-mirrors`; the held fixture directories); `tests/check_action_pins.py` P7 refuses an
   entry whose directory has no manifest of its ecosystem.

**Follow-up (2026-11-02): the proof failed in every exported copy.** The exporter leaves
`.github/workflows/consumer-path-test.yml` out by design (`EXCLUDE_PATHS`), so T3's consumer-path
part and T6 failed on the `91d4e73` work package, and would have turned Normalizer drift and
`Self-test required` red at work. In a tree carrying `.neutral-export-watermark.json` whose exporter
excludes the file, both now report `SOURCE-ONLY` by name (as `prove_export_scope.py` E9 does);
without the watermark, or when the exporter does not exclude it, a missing file still fails (T9,
four cases, two failing before the rule).

**Proof.** `tests/prove_job_token_named.py` T1..T9 (31 failures before the fix on this tree),
`tests/prove_ghe_host.py` H8/H9, `tests/check_action_pins.py` P7 (8 refusals before). Local only;
a hosted run on a ghe.com host is owed.

**Suggested mitigations** (each PROPOSED until an approver records evidence; `scripts/check_register_mitigations.py` refuses a COMPLETED one without evidence and a human approver):
- M1 PROPOSED — Keep the job-token preflight in every job that calls the API, and prove_job_token_named.py required.

---

## D-12 · A kit host's copy had no pre-flight, and a licence could pass the grade — **MODERATE** · **FIXED**

**Observed (owner ruling, 2026-11-03).** *"If the consumer path test is no longer good why is it
still in the package, or why haven't you fixed it so that it runs and tests things out before a true
run of the pipeline?"* The exporter withheld `.github/workflows/consumer-path-test.yml` from every
export (`EXCLUDE_PATHS`: "tests the kit where it is developed; in a recipient's copy it is a scheduled
job billing their minutes"). The consumer-am copy is not a mere recipient: it is that organisation's
private kit HOST, which their other repositories call, on a GHE.com host with GitHub-hosted runners
and GitHub Advanced Security off. It kept a pre-2026-10-16 copy of the workflow that failed with 401s,
and no package replaced it; the documents told the owner to disable it.

**Two defects behind it.** (1) Scope: the one run that proves caller → reusable → scanners → finding →
gate → caller fails, on the host's own platform, could not reach the host. (2) Grading: the
expected-vs-observed grade counted CodeQL's SARIF as detection, so on a host where CodeQL analyses a
signal the open-source scanner missed read DETECTED, and on a GHAS-off host the same tree could read
MISSED — a licence deciding the grade (`tests/prove_consumer_path_preflight.py` C4 reproduced the
first on `60506ad`: a Semgrep signal flagged only by CodeQL graded 24/24).

**Fixed (2026-11-03).**
1. **A profile may send a withheld path**: `INCLUDE_PATH <path> || <reason>` in
   `scripts/export-profiles/*.txt`, only for an `EXCLUDE_PATHS` entry and only with a reason. The full
   export, the incremental (a never-received included path arrives as new; an older file at that path
   is a CONFLICT, left alone), the zip and the watermark (`included_paths`) all honour it. consumer-am
   includes the consumer path test; the neutral export still withholds it.
2. **Dispatch-only by default**: every job of the workflow is conditioned on
   `github.event_name != 'schedule' || vars.KIT_CONSUMER_PATH_SCHEDULE == 'true'`, so its weekly cron
   starts no job unless a repository opts in. The owner's use: run it by hand until green, disable
   it, re-enable it to troubleshoot or after a kit import.
3. **GHAS off is a supported host**: `assert-contract` records Security-tab publication and each CodeQL
   leg in "GHAS-dependent rows (recorded, never graded)" — `UNAVAILABLE` when the platform says so,
   never a pass, never failing the job (it reads the code-scanning API with `security-events: read`);
   the grade runs `verify_expected_signals.py --not-graded codeql`, which lists CodeQL's SARIF as NOT
   GRADED (or UNAVAILABLE when absent), makes a CodeQL-pinned signal UNAVAILABLE outside the
   denominator, and fails a run left with nothing to grade.
4. **`prove_job_token_named.py` checks the file where it was sent**: T3/T6 are SOURCE-ONLY only in a
   copy whose watermark records neither shipping nor including the file; in a kit host's copy the
   shipped file is checked, and an older work-side file left at that path fails.
5. The proof census counts a schedule that starts nothing unless opted in as dispatch-only.

**Proof.** `tests/prove_consumer_path_preflight.py` C1..C4 (18 failures on `60506ad`), including the
three assertion jobs run step by step as shipped on a simulated GHE.com host with GHAS off;
`tests/prove_export_scope.py` E11 (synthetic kit-host profile) and E12 (the real consumer-am copy
carries the workflow, the negative workflow, every fixture file, the generator and the verifier, and
its `prove_job_token_named.py` checks the shipped file); `prove_job_token_named.py` T9 (seven cases).
Local only; the first hosted run on a GHE.com host is the owner's dispatch after import.

**Suggested mitigations** (each PROPOSED until an approver records evidence; `scripts/check_register_mitigations.py` refuses a COMPLETED one without evidence and a human approver):
- M1 PROPOSED — Keep the pre-flight in every kit-host export profile and its GHAS-off proof (prove_consumer_path_preflight.py) required.

---

## D-13 · AKS, VMs and code-packaged Functions have no deploy adapter -- **MODERATE** · **NAMED, ADAPTER PLAN SIZED**

**What it is.** The kit releases Azure App Service (Linux container), Azure Container Apps, Azure Static Web
Apps and -- since KDEC-036 -- Azure Functions hosted as a Linux custom container on a Premium or Dedicated
plan (the App Service reusable with `site_kind: functionapp`). An application on AKS, on virtual machines
(or scale sets), or a Functions app packaged as code (zip, run-from-package, Flex Consumption) is scanned by
the kit and deployed by something else. Until 2026-11-03 nothing said so at run time: the gap was a line in
the hand-off contract, and a reviewer reading a green run saw no sign that the release path was outside
the kit (the security-review lane's G10).

**State: NAMED (KDEC-036 G10).** Discovery now reports `NO_KIT_ADAPTER:aks`, `NO_KIT_ADAPTER:vm` and
`NO_KIT_ADAPTER:function_app_code` from the repository (Kubernetes manifests, a Helm chart or kustomization,
a workflow step deploying to AKS; VM infrastructure or `az vm` in a workflow; a `host.json` with no
Dockerfile beside it, or the functions action), in the security gate's summary, `kit-security-record.json`
and the workflow output `no_kit_adapter`. A deploy whose environment vends a `KIT_HOSTING_KIND` its adapter
does not serve is refused before login, by name. Proof: `tests/prove_reviewer_signals.py` R3, R7, R8. This
is a missing capability, not wrong code; it is recorded here because the owner asked for the build plan
beside the defect it leaves (and `docs/assurance/KNOWN_GAPS.md` is the coverage register).

**Blast radius while it stands.** No deployment governance from the kit for those workloads: no verdict
before login, no digest binding, no release approval bound to the digest, no readiness, no promotion, no
verified reversal. The review sheets mark them `MOD-OUTSIDE-KIT`, and a sign-off may not claim deployment
governance for them.

**The adapter plan (each on the contract the other adapters keep: verdict and gates before login, by
digest, staged first, verified from live state, reversed on failure, every step recorded).** Estimates are
working days for one engineer, built test-first against the stub cloud as K-8 was, plus the live run.

| adapter | how it keeps the contract | new pieces | estimate |
|---|---|---|---|
| **AKS** (`reusable-deploy-aks.yml`) | the deploy identity gets a kubeconfig through `az aks get-credentials` with Entra (no admin credentials, a namespace-scoped Kubernetes RBAC role); capture reads the Deployment's current image digest and revision (`kubectl get deploy -o json`, `rollout history`); deploy sets the image BY DIGEST (`kubectl set image ...@sha256:`) into a staging Deployment or a canary (a second Deployment behind the same Service at weight 0, or Gateway API weights), verifies `rollout status` and the health endpoint from inside the cluster, then promotes; reversal is `rollout undo` to the captured revision, verified by reading the digest back; ownership stamp as an annotation; the lease keyed on the cluster/namespace/deployment id | a `kubectl` stand-in for the stub cloud (Deployments, ReplicaSets, rollouts, Services), new hand-off items naming the cluster, the namespace and the Deployment, Helm-managed releases refused until a Helm path is built (Helm owns the manifest) | **12-15 days** (+3 for a Helm path) |
| **VM / VM scale set** (`reusable-deploy-vmss.yml`) | releases an IMAGE, never a mutable host: a scale set whose model points at a Compute Gallery image version built by the kit (digest = the gallery version's id and its source image hash); capture reads the scale set's model and each instance's `latestModelApplied`; deploy updates the model and rolls a canary batch (`az vmss update-instances` on one instance, or a rolling upgrade policy with a max batch of one), verifies health through the load balancer probe, then rolls the rest; reversal points the model back to the captured image version and rolls again | an image-build reusable (Packer or `az image builder`) with SBOM and provenance like `reusable-build-docker.yml`, the gallery hand-off items, a stub for the scale set and the gallery | **15-20 days** (single VMs by script or SSH: out of scope -- there is no digest to bind, and the owner's rule is build once, promote the same digest) |
| **Functions, code-packaged** (`site_kind: functionapp-zip`, or `reusable-deploy-functions-zip.yml`) | the static site's pattern: the package is an artefact with a content digest (`static-site-package`-style), deployed to the staging slot by `az functionapp deployment source config-zip` (Premium, Dedicated, Consumption) and verified by a marker endpoint returning the digest; swap; reversal redeploys the prior artefact (kept for the retention period). Flex Consumption has no slots: refused at uat/prod (no pre-traffic check), as `preview_environment: ''` is for a static site | the packaging composite and the marker, the zip-deploy calls in the fake az | **6-8 days** |

**Owner decision owed (O-36i):** which of the three to build, in what order. Default: none until asked;
the gap is named on every run in the meantime.

**Suggested mitigations** (each PROPOSED until an approver records evidence; `scripts/check_register_mitigations.py` refuses a COMPLETED one without evidence and a human approver):
- M1 PROPOSED — Size and build an AKS adapter first (the most likely target), then VMs; until then name NO_KIT_ADAPTER in every run.

---

## D-14 · A weakening could be approved by the person who asked for it, and need never end -- **SEVERE** · **FIXED**

**What it was.** Every reusable's posture step called a weakening `WEAKENING_ATTRIBUTED` when a reason and
an authority were present, and checked an expiry only if one was given. `weakening_authority` was free
text: it could name the requester, or the team itself, and an exception with no `weakening_expires` stood
forever. A reviewer reading `WEAKENING_ATTRIBUTED` read "a person who may decide has decided, until a
date"; the kit had established neither.

**Why the expiry was optional.** The weakening record was added (2026-09) to make softened controls
VISIBLE without breaking a single existing caller: every governance input was optional, so a caller that
supplied none got identical behaviour plus a record saying it was unattributed. The expiry was treated as
the one OPTIONAL refinement of an attribution ("any stated expiry is in the future"), because the first
users were the kit's own dogfood runs and early adopters recording standing adoption-baseline decisions.
The cost of that compatibility was never revisited once the record started to route releases (KDEC-014,
KDEC-029): optional-until-reviewed became optional forever.

**Removed (owner rulings 2026-11-03, KDEC-036).** An exception with no expiry is never approved, in any
mode. A weakening is approved only with an evidence reference, a reason, a named owner, an expiry within
the ceiling (default 90 days) and an approver on a registered approver list who is not the requester; a
missing field is `WEAKENING_NOT_APPROVED`, named (proceeds at crawl, the control still counted weakened;
refused at uat/prod); the requester, the actor or the released commit's author as owner or approver is
`WEAKENING_SELF_APPROVED`, BLOCKED by the gate and refused by every deploy. Proof:
`tests/prove_reviewer_signals.py` R2, R3 (seen failing on `1567af2`). **Consequence for adopters:** a caller
with an attributed weakening and no `weakening_approver` or `weakening_exception_ref` now reads
`WEAKENING_NOT_APPROVED`, and its uat/prod deploys refuse until the record is completed.

**Suggested mitigations** (each PROPOSED until an approver records evidence; `scripts/check_register_mitigations.py` refuses a COMPLETED one without evidence and a human approver):
- M1 PROPOSED — Keep the five-field rule and the self-approval refusal proven (prove_reviewer_signals.py); audit approved weakenings monthly.

---

## Verified NOT defects

Recorded so the next pass does not re-litigate them.

- **16 flags quoted in documentation that `argparse` does not define.** All 16 are **false
  positives** of an `argparse`-only audit, each verified by reading the script: `finding_identity.py`
  accepts `--self-test` and `--selftest` at `main()` line 1005 (both spellings deliberately, with
  the reason in a comment); `inline_normalizer.py --check` at line 570; `redact_sarif.py --self-test`
  at line 302; `lint_suppressions.py --check` at line 88. One apparent `check_stage_phase.py --check`
  is a line-attribution artefact — that documentation line is about
  `build_pipeline_overlays.py --check`, which does define it. **Genuine stale flags in
  documentation: 0.**
- **`tests/prove_kit_script_digests.py` exits 2 on this host.** `sha256sum` is not on `PATH`, and
  the file reports `UNKNOWN: ... A check that could not execute is not a pass.` That is the correct
  behaviour and is the fix D-4 applied to its sibling. Environmental, not a defect.
- **`tests/make_fixture.py` and `tests/verify_expected_signals.py` exit 2 when run with no
  arguments.** Both require arguments and say so in a usage line. They are tools, not gates.
- **The legacy `fp` moving on a reworded message.** Real, consequential, and a *deliberate,
  documented* migration state — both keys are carried so that swapping in one step does not orphan
  every existing approval at once. It is the consequence of D-2 rather than a defect of its own,
  and it closes when D-2 does.

---

## Observed gate state, 2026-10-08

28 files in `tests/`, each executed individually on this host and its exit code observed:

| | |
|---|---|
| | before D-1 fix | after D-1 fix |
|---|---|---|
| exit 0 | 21 | **22** |
| exit 1 — a real defect, loudly reported | 4 | **3** — `prove_identity_durability.py` (D-2/D-3), `reconcile_validation.py` (D-6), `check_export_safety.py` (D-7, a false positive) |
| exit 2 — UNKNOWN, correctly refusing to pass | 1 | **1** — `prove_kit_script_digests.py`, no `sha256sum` on this host |
| exit 2 — usage, argument-taking tools not gates | 2 | **2** — `make_fixture.py`, `verify_expected_signals.py` |

`prove_hollow_scan.py` is the one that moved, 1 → 0. `prove_bootstrap_failure.py` exited 1 before
D-4 was fixed and exits 0 now; the gate it tests was never broken. `check_export_safety.py` exited
0 at the start of this pass and exits 1 after `da6a1ac`.

**`scripts/` is not in that sweep, and one gate there is red.** `scripts/reconcile_taxonomy.py`
exits 1 with taxonomy-drift terms. It was **already red before any of this work** — measured at
**25** terms on `3b4ed68` using a detached worktree, so the baseline is established and not
inferred. **Reporting it here because the earlier sweep in this pass covered
only `tests/` and therefore missed it** — a floor presented as a total, which is the error this
file's own rules forbid.

### Observed again after the D-2 / D-3 / lineage pass

29 files in `tests/`, each executed individually on this host and its exit code observed:

| | before this pass | after |
|---|---|---|
| exit 0 | 22 | **24** |
| exit 1 — a real defect, loudly reported | 3 | **2** — `reconcile_validation.py` (D-6), `check_export_safety.py` (D-7, a false positive) |
| exit 2 — usage, argument-taking tools not gates | 2 | **2** — `make_fixture.py`, `verify_expected_signals.py` |
| exit 2 — environmental, see below | 1 | **1** — `prove_kit_script_digests.py` |
| total | 28 | **29** |

`prove_identity_durability.py` is the one that moved, 1 → 0. `prove_lineage_durability.py` is the
new file and exits 0.

**`prove_kit_script_digests.py` exits 0 when run alone and 2 inside the sweep, before and after
this pass.** It materialises `/tmp/scan_report.py` and friends, and concurrent sessions in other
worktrees on this host write the same paths. **The exit 2 is a `/tmp` collision, not a defect in
the thing it tests** — established by running it standalone, which passes and prints the matching
manifest digest. The earlier entry above attributed it to a missing `sha256sum`; on this host
`sha256sum` is present and the standalone run uses it.

**Taxonomy drift: 25 → 7, measured on this host.** The entry above says 24 on the then-current
commit; the reading taken at the start of this pass on `0ac1a4a` was **25**, and that
discrepancy is reported rather than reconciled because nothing here can establish which run the
24 came from. What changed:

- `SOURCE_DEPENDENCY` registered (D-3).
- Three namespaces registered for the identity model's own words — `identity_refusal`,
  `identity_scope`, `content_normalisation_policy`. These were driving `finding_identity.py` and
  defined nowhere.
- Seven namespaces registered for the lineage ledger — `lineage_relation`, `lineage_resolution`,
  `lineage_cause`, `lineage_attribution`, `lineage_ledger_integrity`, `disposition_carry`,
  `lineage_proof_failure` — plus `identity_proof_failure` for the two proofs' error vocabularies.
- **One reader defect in the gate itself, fixed.** `registered_terms()` read `values`,
  `artifacts`, `required_fields` and `fields`, but not
  `provenance_identity.observation_time.sources` — which registers `DECLARED_IN_CONTENT`,
  `SIDECAR`, `FILENAME`, `FILE_MTIME` and `UNKNOWN`, each with a definition, a tier and a
  `claimable` flag. `FILE_MTIME` was on the drift list for that reason alone: the gate was
  telling a correct author to register a term the registry already held.

The remaining 7 belong to other surfaces: `INCLUDE_OVERLAY` and `NEVER_LIFT` (the export
profiles), `NO_COUNT_APPLIC` and `NO_COUNT_STATES` (`prove_hollow_scan.py`), and `BY_SCANNER`,
`COUNTABLE_EXAMINATION` and `EXCLUDE_TOP` (identifiers and region markers quoted in this file's
own prose). **The orphan list is unchanged at 10**, so nothing was registered that nothing uses.

**`reusable-security.yml` regenerated cleanly and grew.** `inline_normalizer.py --check` passes,
`prove_kit_script_digests.py` confirms the shipped bootstrap shell writes exactly the manifest the
workflow pins (`7ccf57b5…`, regenerated), and the file went **416.4 KB → 436.3 KB** — +19.9 KB,
almost all of it the extraction layer's comments. The fail threshold is 475 KB and GitHub's hard
limit is 500 KB, so **38.7 KB of headroom remains against the fail threshold**, down from 58.6 KB.
`check_workflow_size.py` passes with its `approaching` warning, which it also emitted before.
Nothing was trimmed to make room. The next person to add an inlined script should expect to have
to make room first.

**`scripts/finding_lineage.py` is deliberately NOT inlined into the workflow.** Nothing in the
pipeline writes lineage events yet — detection requires comparing two scans against a stored
record, and that comparison does not exist — so inlining it would add roughly 25 KB to a file
already warned as approaching the limit in exchange for a script no job calls.

**The stage ladder did not move, and that is correct.**
`ABSENT 2 · DESIGNED 4 · BUILT 8 · EXERCISED 0 · PROVEN 1 · ENFORCED 0`, unchanged. Stage 7
*evidence validity* is the stage that owns this defect — its declared guardrail is verbatim *"a
zero-finding zero-artifact report reading as clean"* — and it is `BUILT`. `BUILT → EXERCISED`
costs **a run id against a named commit**, and nothing here ran in CI. Stage 14 *reporting* is
`BUILT` for the same reason, and stage 6 *scanning* is `PROVEN` and would need a recorded refusal
of a real prohibited operation to move. **The ladder deliberately gives no credit for writing a
test**, which is the property that makes it worth having: the fix is real, the gate is green, and
the stage has still not been exercised.

**This count is from a complete collection, so it is a total and not a floor** — the directory was
enumerated and every `.py` in it was run. It establishes nothing about the workflows: nothing here
was run on GitHub, and `tests/check_selftest_coverage.py` reports 3 of 12 workflows exercised on
the commit that could break them, 3 on a schedule only, 4 on dispatch only and 2 by nothing.

## What this pass could NOT establish

- **That any of this behaves the same on GitHub.** Every observation above is from local
  execution. `reusable-security.yml` has never been invoked end-to-end — that is the sixth
  BLOCKING item in D-6. **This applies to the D-1 fix as much as to the defect:** the regenerated
  workflow was verified byte-identical to the canonical script and under the size limit, and it
  has not been *run*. The reporter's behaviour is established; the workflow's is not.
- **That the four witnesses are populated by the scanners this kit actually runs.** The fix
  establishes what the reporter decides when they are present or present-and-empty. Whether
  Trivy, Semgrep, Checkov, CodeQL and the rest emit `invocations`, `rules` and `artifacts` in
  practice is **NOT ESTABLISHED**. If a scanner emits none of them, its scans land on
  `NOT_DECLARED` and read as unmeasured — correct by this file's rules and possibly noisy in
  practice. **This is the first thing to check against real scanner output**, and it is the risk
  the fix carries in the false-failure direction.
- **That real scanners emit the SARIF shapes used in D-1 and D-2.** Both reproductions use
  constructed documents, built to be *generous* to the kit — CWE where Semgrep puts it, a
  `logicalLocations` symbol, a CVE and a purl on the dependency case. If an identity cannot be
  computed from those it cannot be computed from a real one, but a corpus of real scanner output
  would be stronger evidence and this is not one.
- **Whether the five expired deferrals in D-6 are still the right calls.** No evidence was
  produced for or against any of them.
- **That the SAST construct survives to the reporter in production.** It does not — that is D-8,
  and it was found by fixing D-2 rather than refuted by it. `prove_identity_durability.py` calls
  `parse_sarif` directly, which is the pre-redaction position; the `report` job reads
  post-redaction artifacts. The extraction is proven; its placement in the pipeline is wrong and
  **NOT ESTABLISHED by execution** either way, because the workflow has still never run.
- **That one field in `prove_identity_durability.py`'s SAST fixture was not there before.** It
  was not. The documents carried no `region.snippet`, so they could not satisfy `SOURCE`'s
  CONTENT however the extraction was written — the file's own claim to be *generous* to the kit
  was wrong in exactly the place that mattered. Semgrep does emit
  `region.snippet.text`, so it is now in the fixture at that key, the "after" document
  **reformats** it so the scenario also proves formatter-immunity, and a new scenario feeds the
  same document with the snippet **removed** and asserts the identity refuses with
  `CONTENT_UNDERIVABLE` carrying no hash. Without that scenario the fixture change would be
  indistinguishable from loosening CONTENT to turn a red file green. The `--self-test` separately
  asserts the two cases *differ*, so the refusal it checks cannot be passing merely because
  nothing fingerprints at all.
- **That anything writes a lineage event.** Nothing does. `scripts/finding_lineage.py` is the
  record and the resolver; detection — noticing that an identity moved, which needs two scans and
  the stored record — does not exist, and `tests/prove_lineage_durability.py` says so in its own
  PASS banner rather than leaving it to be inferred.
- **That the kit's own identity change was recorded in the ledger it just gained.** It was not.
  Fixing D-2 and D-3 moved the identity of **every finding in every consuming repository** — the
  `EXTRACTION_CORRECTED` and `SUBJECT_SPEC_CHANGED` causes exist for exactly this event — and no
  migration ledger was written, because the old identities were all the empty string and there is
  nothing to supersede. A consumer that had somehow keyed dispositions on the empty identity has
  no lineage to follow. **This is the one case where the ledger cannot help retroactively**, and
  it is worth stating because it is the last moment at which that will be true.

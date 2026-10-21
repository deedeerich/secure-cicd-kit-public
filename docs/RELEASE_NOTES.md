# Release notes

Each release of `main` is built from a release-candidate branch, never directly from the development
trunk: the candidate merges the trunk and keeps every consumer overlay off `main`, so the neutral kit,
and the public export generated from it, carry no consumer-specific material. Each entry names the
trunk commit that brought the change.

## Release 2

Built on `release/main-candidate-2` from Release 1 (`ef4b15d`) and the trunk through `25f14d3`.
`overlays/` stays removed, as in Release 1; a consumer's own ticket-number range for the Jira
reference gate stays in that consumer's overlay, and the core gate ships with no range.

### Deploy and release

- **The starter template hands deploy the combined verdict** (security and policy together) instead
  of the security verdict alone; the deploy binds to the GitHub environment's `KIT_*` values and
  refuses a mismatched target; attestation verification runs inside both deploy reusables; NOW SERVING
  is read from production's own start record; a staging-slot swap stamps which run owns it; live
  acceptance enablers. Proven on a sandbox subscription: a healthy Container Apps deploy with
  provenance tags, a production deploy refused before any change when rollback was disabled, and a
  healthy direct App Service deploy. (`11d1d56`, live runs recorded in `25f14d3`)
- **Version gaps at uat and prod (KDEC-014).** The security gate names the cause of every advisory
  (`advisory_causes`). At uat and prod a deploy refuses an advisory caused by a proven version gap,
  unless a named person accepts it through the existing weakening record (authority, reason, an
  unexpired date) and the environment's required reviewers approve. The deploy's verdict step always
  writes one ruling, and an absent ruling routes the deploy `EVIDENCE_UNTRUSTED`. (`3830edb`,
  `078ef90`)
- **Version-gap enforcement is on for infrastructure as code.** Seeded Terraform corpora establish
  the ranges Checkov and Trivy-config can read; a gap counts as proven only when every candidate's
  established range answers that it cannot read the version. A hosted corpus probe re-measures on
  change, and the registry cites its run. (`272fe71`, `37e4e77`, `939cfc3`)

### Findings, ledger and ticketing

- **A finding baseline is established only by an approved pull request** under code ownership; one
  move record; the ticket ledger persists; a scanner-generation check; per-environment presence.
  (`a0e8b16`)
- **Ticket updates never erase human-written text**; reopen classes; least-privilege sweep; a
  degraded-streak signal; delta updates. Proven against a personal Jira site. (`85bd33d`)

### Scan validity

- **Hollow-scan handling follows per-tool profiles**: a clean Bandit run is not hollow. Semgrep runs
  with `--strict`, and its exit 3 is `COLLECTION_FAILED`. The CodeQL autobuild outcome is read and
  reported. Discovery searches to depth 8 and names what lies beyond it. (`a279f5a`)
- **The assurance dataflow trace reads `env:` and `needs`** (31 to 120 hand-offs traced); ten real
  defects it then found are fixed, including a silent rollback-capability step that both deploy
  reusables read as "rollback available" (now `UNAVAILABLE`). (`a279f5a`)
- **Scanner registry hygiene; NVD `fail_on_cvss` defaults to 9.0** with the decimal comparison
  fixed; the proof census and stage register are checked; size and bundle gates measure what GitHub
  actually loads; validate-scanners fails on a missing probe and runs as a matrix; workflow policy
  checks job-level `uses:` and images; branch-protection profiles require the gate and policy checks.
  (`58dce0d`)
- **Real SARIF fixtures**; Dependabot paging; toolchain advice. (`272fe71`) Dependabot no longer
  touches the deliberately vulnerable test fixtures. (`754f80d`)

### Export and neutrality

- **The export gate and the safety check agree**; every deny pattern carries its own positive and
  negative samples (`tests/prove_deny_samples.py`); the export profile is bound to its destination;
  the export watermark keeps the commit and drops the branch name; the proof census runs outside the
  kit. (`a279f5a`)
- **Untracked files are never scanned or exported**, ignored or not. (`904bc7a`)

### Documentation

- `docs/assurance/COMPLETION_LEDGER.md`: the designed-versus-built map, 202 rows. (`d107fe9`)
- `docs/assurance/RELEASE_1_EVIDENCE_MANIFEST.md` and its two further parts: what Release 1 proved,
  with run ids. Consumer documents made true to the code. (`f01ef04`)
- The builder explainer to v1.12, in parts each under 20 KB, with part 12 listing every change since
  v1.10. (`f01ef04`, `6feaf82`, `8ca6bb0`)

### Still owed

Unchanged by this release and carried as dated deferrals: attestation signing, change detection and
the Terraform toolchain (2026-12-31). Not yet run: a real gate verdict feeding a deploy in one
pipeline, a hosted establish-then-propose ledger run, Azure DevOps ticketing live, and SHA-pinned
actions (the self-use weakening expires 2026-10-31). The rung ladder is not yet wired into the gate
(`wiring/gate-rung.patch.md` unapplied; `tests/prove_gate_reads_rung.py` still fails by design and
is accounted for in `tests/check_selftest_coverage.py`); nor are the SLA and cost-packing work that
KDEC-007 also scheduled after Release 1.

## Release 1

`ef4b15d` (pull request #3): a correct scan, gate and verdict; finding identity and the ledger; Jira
and Azure DevOps ticketing with the Jira reference gate in the core; provenance; and deploy with
rollback, proven end to end. No consumer overlay.

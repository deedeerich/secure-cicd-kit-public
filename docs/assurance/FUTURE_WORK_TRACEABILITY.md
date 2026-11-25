# Future-work traceability: every roadmap item, and the ledger row that tracks it

```
Phase:              1
Truth State:        audit at 2cd078e (lane L-FWA, 2026-10-22). FUTURE_WORK.md (592 lines) and
                    COMPLETION_LEDGER.md were read in full; decisions.md, continuation.md, risks.md and
                    AXES_AND_PHASES.md were read in full for owner-stated requirements
Audience:           whoever plans release lanes from the completion ledger
Decision Supported: what the roadmap asks for that the plan did not carry, and in what order to close it
Deferred Depth:     the designs themselves (FUTURE_WORK.md); the rows' evidence (COMPLETION_LEDGER.md)
```

## Summary

**Why this exists.** The owner asked for Dependabot auto-merge more than twice. It is designed in
FUTURE_WORK §6, but the completion ledger, which release lanes are planned from, had no row for it, so
no lane built it. A section-by-section check found the same gap for §2, §3 (D1–D4), §4, §7 and §8, and
for D6. Some of that work was tracked under other labels (the ledger cites "FW D5", "FW D7", and uses
`FW:line` for the flagship workflow). None of §2, §4, §6 or §8 was.

| measure | count |
|---|---|
| FUTURE_WORK sections and subsections (`## N ·`, `### Dn ·`) | 16 (§1–§13, D5, D6, D7) |
| sections cited by a ledger row's designed column at `2cd078e` | 9 (§1, §5, §9–§13, D5, D7) |
| distinct requirements, capabilities or commitments in FUTURE_WORK (rows of the table below) | 58 |
| tracked by an existing ledger row (under any label) | 43 |
| resolved by a recorded decision or run, no row needed | 2 |
| tracked only by a row this lane added | 12 |
| left to lane L-DB (FW §6 auto-merge) | 1 |
| ledger rows added | 15: 11 from FUTURE_WORK (K-03 is also KDEC-013) and 4 from owner statements; listed in ledger section 3 |
| owner decisions added | 3 (O-24, O-25, O-26) |

**Top 5 by risk.**

1. **FW §6, Dependabot auto-merge: covered by lane L-DB.** Asked for repeatedly, designed in full, and
   never built. It is the reason this check exists. Its eligibility depends on team pattern (AX-TEAM).
2. **AX-CRAWL (O-24).** The owner's "crawl: only secrets block" can be read two ways. Read one way, a
   scan that did not run would pass at crawl. The library's crawl row is right for findings, and the
   ruling must say that untrusted evidence still stops a run.
3. **FW-§10-M.** Neither deploy reusable has a time bound. A hang bills up to GitHub's 6-hour job limit,
   and a kill at that limit mid-mutation has no designed rollback outcome.
4. **FW-§3a.** Correlation records no confidence and no disagreement. Two scanners that disagree are
   clustered, not escalated, which is the averaging-away FW §3 forbids.
5. **FW-§8a.** Moving to an organisation breaks every federated credential, because the OIDC subjects
   contain the owner name. Azure reports it as an authentication failure (AADSTS700213) and never
   mentions the move. Nothing lists what will break.

**Reverse direction.** Every ledger row that cites FUTURE_WORK points at a section that exists. Two
rows cite loosely:

- L74 cites FW §12, but it tracks the contract's assertions, not §12's owed decision (now FW-§12).
- L76 cites FW §9, the assurance model, for validate-scanners.

The ledger's abbreviation `FW` also meant both the flagship workflow and this roadmap. Its legend now
says which column means which.

**Stale roadmap text found (for lane L-G; not changed here).**

- §8 says the export gate "cannot cover history". The exporter writes a fresh tree with no history
  (FW-§8b).
- §5 says context-integrity's refusal path has no evidence. A wrong tenant was refused live after a
  real login (run 38826929579, ledger section 7).
- §1's table is dated 2026-08-18. It already appears in D-01.

## Traceability table

Line numbers are FUTURE_WORK.md at `2cd078e`. "added" means the row was added by this lane.

| § | line | item (short quote) | ledger row(s) | note |
|---|---|---|---|---|
| §1 | 18–20 | validate-scanners and the consumer contract green on `main`; "Re-verify at current `main`" | S-06, L26, L30, L76 | hosted re-run on the trunk owed (L-Z) |
| §1 | 21 | "Reconcile `sast-java`" | none needed | resolved by run evidence; KDEC-005 closed it locally |
| §1 | 22 | "`code-quality` detection assertion" | L13 | seeded lint fixture proven (KDEC-005) |
| §1 | 23 | "Trivy path normalization … one file, two identities" | FW-§1 | UNKNOWN, not re-traced |
| §2 | 40–42 | "Report before/after billed minutes per class" (small, monorepo, IaC-heavy) | **FW-§2 (added)** | no measurement exists |
| §2 | 47 | "Consolidate sub-minute jobs + re-gate" | L65 | OD-3 |
| §2 | 48 | "Changed-path intelligence" | **FW-§2 (added)** | `determine-changes` held by deferral `change-detection` |
| §2 | 49 | "Developer mode vs assurance mode" | AX-DEPTH, S-05 | EP-1..EP-4 |
| §3 | 58–62 | correlation doctrine; "Never destructive deduplication" | S-11, L48 | |
| §3 | 237 | "OSV and Trivy independently flagged the same lockfile" | S-11 | corroboration is clustered |
| §3 | 239–246 | calibration, independence, "Disagreement should escalate, never average away" | **FW-§3a (added)** | NOT BUILT |
| §3 | 248–250 | "There is no correlation `SKILL.md` anywhere" | **FW-§3b (added)** | NOT BUILT |
| D5 | 66–85 | NEW, RECURRED, REOPENED_BY_LAPSE; "D5 needs a clock, not a diff" | T-08, T-17, T-21 | no schedule exists (T-17) |
| D5 | 100–102 | idempotence: key on the fingerprint, reopen, never duplicate | T-01, T-16 | |
| D5 | 104–108 | "must never auto-close because a scanner did not run" | T-09, T-13 | POTENTIALLY_ABSENT is built (T-13) |
| D5 | 110–113 | "`RECURRED` must not be silently re-dispositioned" | T-08 | `falsified` reopen class |
| D5 | 115–118 | "The issue is a projection, not the record" | T-14 | never-list |
| D5 | 120–121 | tracker custody; other trackers are extension points | T-12, TKT-WORK (added) | KDEC-004 made Jira authoritative |
| D5 | 123 | depends on D1–D4 | L48 | |
| D6 | 147–155 | VERSION_DISCOVERED, SCANNER_SUPPORTS, VERSION_UNSUPPORTED | S-03, L19, L20 | now cite FW D6 |
| D6 | 157–159 | VERSION_UNSUPPORTED "must never collapse into NOT_APPLICABLE or CLEAN" | L20, S-04, V-04 | |
| D6 | 161–164 | the repository target vs the runner's toolchain | V-03 | |
| D6 | 166–169 | "Each scanner must declare its own supported range" | L20, V-02 | |
| D6 | 171–173 | VERSION_SUPPORT_UNDETERMINED is a gap | L20 | built in `resolve` |
| D7 | 191–198 | inventory of everything whose version changes detection | L23 | |
| D7 | 200–210 | CURRENT … UPDATE_BLOCKED_BY_COMPATIBILITY | L23 | |
| D7 | 212–224 | "AN UPGRADE IS A CHANGE TO DETECTION"; regression against the seeded corpus | L23, V-02 | weekly corpus probe exists |
| D7 | 229–233 | toolchain composites report what was actually installed | L23 | `setup-python` reports `installed`; no inventory |
| §4 | 260–264 | Tier 1 HTML artifact, Tier 2 trend JSON, Tier 3 Pages off by default | **FW-§4 (added)** | NOT BUILT |
| §4 | 266–268 | the engineer's view: "what was not scanned and why", redacted | **FW-§4 (added)** | |
| §5 | 276–281 | Swift, Kotlin/Android, .NET real repo, build-aware C/C++, shell, workflows | FW-§5 | O-14 |
| §5 | 282 | five composite actions, expiry 2026-09-15 | G-01 | registry; `toolchain-terraform` held to 2026-12-31 |
| §5 | 283 | `reusable-nvd-cve.yml` warm path | NVD-§6 | lane L-N measured the cache path |
| §5 | 284 | `context-integrity` negative fixture | none needed | refusal observed live, 38826929579 |
| §5 | 285 | image build and push; ACR behind Azure identity | L85 | cloud registry push live |
| §6 | 301–366 | smart Dependabot auto-merge: risk-tiered conditions, human escalation | **lane L-DB** | not added here, by instruction |
| §6 | 313–325 | GHAS applicability by probe, not a secret | L25 | |
| §6 | 327–342 | the reference-estate census: ten workflows | S-11, L48, S-13, F-01, FW-§4, FW-§5, L110-1, S-05, L25, **FW-§6b (added)** | two map to nothing until FW-§6b |
| §6 | 351–352 | CodeQL invoked | S-06, L75 | |
| §7 | 372 | ROLLBACK_CONTRACT: "Reversible ≠ safe to reverse" | L94 | now cites FW §7 |
| §7 | 373–374 | Landing Zone reconciliation | DCR-GATE2 | O-09; now cites FW §7 |
| §8 | 386 | organisation and Enterprise migration; "OIDC subjects contain the owner name" | **FW-§8a (added)** | NOT BUILT |
| §8 | 387 | export gate "cannot cover history" | **FW-§8b (added)** | built by construction, unproven |
| §8 | 388 | promotion path personal → portable → organisation | **FW-§8c (added)** | first hop only |
| §9 | 394–408 | tool ≠ workflow ≠ consumer ≠ publication | L76, L71 | doctrine; the proof-rule document |
| §10 | 424–428 | "A timeout must not read as a scanner failure" | L10 | |
| §10 | 429–433 | bounded dependency acquisition | L11 | |
| §10 | 434–436 | a hung-scanner test with sibling states intact | L10 | |
| §10 | 437–439 | re-size `reusable-nvd-cve` from evidence | NVD-§6 | |
| §10 | 440–447 | mutating pipelines need their own bound | **FW-§10-M (added)** | NOT BUILT |
| §11 | 489–493 | compare every pin against upstream; verify each pin resolves | L23 | `check_pinned_artifacts` |
| §11 | 494–496 | decide on the unpinned tools | L84 | |
| §12 | 525–528 | decide the negative control's shape; share the two legs | **FW-§12 (added)** | O-26 |
| §13 | 539–561 | employer-neutral custody; one-way direction | L107, OVL-A | |
| §13 | 573–576 | the one-way dependency is checked | L107 | `check_custody`, `prove_custody_overlays` |
| §13 | 583–587 | reference gate neutral, "enforcement OFF and no default range" | **K-03 (added)** | KDEC-013 |
| §13 | 589–591 | DAST and external quality: a neutral requirement first | OVL-A | |
| §13 | — | export cannot leak | L106 | |

## Owner-stated requirements not in the ledger before this lane

Read from `decisions.md`, `continuation.md` and `risks.md`, and from the coordinator's relay of
2026-10-22.

| requirement | source | row added |
|---|---|---|
| KDEC-013: the Jira reference gate is core, with no default range | decisions.md | K-03 (DONE-PROVEN-LOCAL) |
| team-type-driven settings (solo dev, pair, team), including auto-merge eligibility | owner 2026-10-22; AXES "enforcement by team pattern" | AX-TEAM (PARTIAL) |
| a crawl phase where only secrets block | owner 2026-10-22 | AX-CRAWL (O-24) |
| finer policy per organisation, team, product and environment | owner 2026-10-22 (lane L-A) | POL-SCOPE (NOT BUILT) |
| Jira only at work; Azure DevOps out of scope for work | owner 2026-10-22 | TKT-WORK (O-25) |

Already tracked: KDEC-010 (V-01), KDEC-014 (K-01), KDEC-015 (K-02), KDEC-016 (PHP-1, PHP-2), and
KDEC-011 (B-16). KDEC-005, KDEC-006 and KDEC-012 are process rulings, held by the registry and lane
L-Z, and need no row. No KDEC entry records the 2026-10-22 rulings yet; that record is lane L-G's.

## Sections not tracked by a ledger row

None at this commit. Every section and subsection is cited by at least one ledger row's designed
column. To exempt one, add a row here as `| §N | reason |`, with a reason of at least 20 characters.
`tests/check_future_work_traceability.py` fails on an exemption that a ledger row also covers.

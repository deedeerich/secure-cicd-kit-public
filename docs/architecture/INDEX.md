# The architecture suite: reading order

```
Kept:      2026-11-07, drawn against the trunk at c1420ea (fix/normalization-and-discovery).
Audience:  the owner, a security reviewer, a new maintainer: anyone who must understand every part.
Rule:      one document per file, each at most about 25 KB; every diagram is Mermaid and parses
           (tests/check_mermaid_diagrams.py); every file in the tree is in the code walkthrough
           (tests/check_code_walkthrough_coverage.py). Where the code and a document disagree,
           the code wins and the document is fixed.
```

Read in this order. Each layer assumes the one before it.

## 1 · Notation

| # | Document | What it gives you |
|---|---|---|
| 00 | [00_NOTATION_AND_LEGEND.md](00_NOTATION_AND_LEGEND.md) | every shape, line, colour, boundary mark, STRIDE letter and data class used below |

## 2 · Architecture, outside in (C4)

| # | Document | Level |
|---|---|---|
| 01 | [01_CONTEXT.md](01_CONTEXT.md) | L1 context: people by role, every outside system |
| 02 | [02_CONTAINERS.md](02_CONTAINERS.md) | L2 containers: templates, reusable workflows, actions, scripts, registries |
| 03a | [03a_COMPONENTS_GATE.md](03a_COMPONENTS_GATE.md) | L3: the security run and its gate |
| 03b | [03b_COMPONENTS_DEPLOY.md](03b_COMPONENTS_DEPLOY.md) | L3: build, verdict, deploy, promotion |
| 03c | [03c_COMPONENTS_TICKETING.md](03c_COMPONENTS_TICKETING.md) | L3: ticketing |
| 03d | [03d_COMPONENTS_DEPENDABOT.md](03d_COMPONENTS_DEPENDABOT.md) | L3: Dependabot triage, keep-current, config check |
| 03e | [03e_COMPONENTS_KIT_API.md](03e_COMPONENTS_KIT_API.md) | L3: the kit API |
| 03f | [03f_COMPONENTS_EVIDENCE_EXPORT.md](03f_COMPONENTS_EVIDENCE_EXPORT.md) | L3: evidence export |
| 03g | [03g_COMPONENTS_KIT_INIT.md](03g_COMPONENTS_KIT_INIT.md) | L3: kit init |
| 04 | [04_DEPLOYMENT_VIEW.md](04_DEPLOYMENT_VIEW.md) | where each part runs, and as whom |

## 3 · Boundaries, data and identity

| # | Document | What it holds |
|---|---|---|
| 05 | [05_TRUST_BOUNDARIES.md](05_TRUST_BOUNDARIES.md) | every trust boundary TB-1..TB-14: what crosses, the control, the proof file |
| 06 | [06_DATA_FLOWS.md](06_DATA_FLOWS.md) | findings, SBOMs, evidence, tickets, tokens, secrets (names only), logs, with classification |
| 07 | [07_IDENTITY_AND_ACCESS.md](07_IDENTITY_AND_ACCESS.md) | every identity, its scope per job, the rulings it follows |

## 4 · Threats and security architecture

| # | Document | What it holds |
|---|---|---|
| 08 | [08_SECURITY_ARCHITECTURE.md](08_SECURITY_ARCHITECTURE.md) | the security architecture in one place: layers of defence, what holds each |
| 09 | [09_THREAT_MODEL.md](09_THREAT_MODEL.md) | method, assets, STRIDE per element, summary, the residuals to act on first |
| 09b | [09b_THREATS_BY_BOUNDARY.md](09b_THREATS_BY_BOUNDARY.md) | every threat by boundary: control, proof, state, residual, suggested mitigation (PROPOSED) |

## 5 · Design documents, one per subsystem

| # | Document | Subsystem |
|---|---|---|
| 10a | [10a_DESIGN_SECURITY_GATE.md](10a_DESIGN_SECURITY_GATE.md) | discovery, resolve, scanners, report, gate |
| 10b | [10b_DESIGN_BUILD_AND_DEPLOY.md](10b_DESIGN_BUILD_AND_DEPLOY.md) | build, verdict, deploy, promotion, rollback, deployed scan |
| 10c | [10c_DESIGN_TICKETING.md](10c_DESIGN_TICKETING.md) | reconciler, trackers, ledger, exceptions due |
| 10d | [10d_DESIGN_DEPENDABOT.md](10d_DESIGN_DEPENDABOT.md) | Dependabot triage, keep-current, config check |
| 10e | [10e_DESIGN_KIT_API.md](10e_DESIGN_KIT_API.md) | the kit API |
| 10f | [10f_DESIGN_EVIDENCE_EXPORT.md](10f_DESIGN_EVIDENCE_EXPORT.md) | evidence export |
| 10g | [10g_DESIGN_KIT_INIT.md](10g_DESIGN_KIT_INIT.md) | kit init |
| 10h | [10h_DESIGN_POLICY_AND_EXCEPTIONS.md](10h_DESIGN_POLICY_AND_EXCEPTIONS.md) | the policy register, rungs, weakenings, exceptions |
| 10i | [10i_DESIGN_FEEDS_AND_EXTERNAL_INTAKE.md](10i_DESIGN_FEEDS_AND_EXTERNAL_INTAKE.md) | feed mirrors, KEV, NVD, SonarQube and Aikido intake |
| 10j | [10j_DESIGN_EXPORT_AND_SELF_ASSURANCE.md](10j_DESIGN_EXPORT_AND_SELF_ASSURANCE.md) | neutral export, public mirror, self-test, battery, the checks on the kit itself |

## 6 · The code, every file

| # | Document | What it holds |
|---|---|---|
| 11 | [code-walkthrough/README.md](code-walkthrough/README.md) | one page per area; every tracked file, what it does, who calls it, its inputs and outputs, the tests that prove it |

## 7 · The earlier documents (kept, and linked from the suite)

The single-page diagrams ARCH-01..ARCH-07 and the long design and contract documents are indexed in
[README.md](README.md). The suite cites them where they hold more detail; where the suite and one of them
disagree, the suite was drawn later against the code, and the earlier document has been fixed to match.

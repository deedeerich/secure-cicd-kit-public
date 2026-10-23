# How the secure CI/CD kit works — READ ME FIRST

```
Audience:     a builder or automation platform that will run, extend or integrate this kit, with no
              prior context and a short reading window
Authority:    the kit's own design documents (docs/architecture/*, docs/PIPELINE_STATE_AND_DIRECTION.md,
              docs/roadmap/FUTURE_WORK.md, docs/KNOWN_DEFECTS.md) and the code on the trunk branch.
              Where this explainer and those disagree, THEY win and this file is wrong.
Truth labels: VERIFIED = a proof, check or run executed (or a run read back) at the commit named
              in 10-CHANGE-LOG.md, or the code read at that commit for a fact the code states.
              READ = taken from a commit message, merge record or registry comment and not
              re-run for this version (from v1.12; earlier parts folded READ into VERIFIED).
              DESIGNED = written in a design document, not (yet) built.
              Anything else is said plainly ("not established", "owner decision").
Kept current: every change landed on the trunk updates the affected part and appends to 10-CHANGE-LOG.md.
```

## What this is, in one paragraph

A reusable GitHub Actions security pipeline that a repository calls with one `uses:` line. It finds
out what is actually in the repository, runs the scanners that apply, refuses to treat "could not
look" as "nothing found", keeps findings and their evidence, and ends in a **gate** that emits a
**verdict** — `routing_result` — that a deployment step reads before it is allowed to deploy. Around
that core the design adds durable finding identity, a findings ledger, ticketing (Jira first),
build provenance, and deployment with rollback. Some of that is built and proven; some is designed
and not built. Part 09 says exactly which.

## Read in this order. Each part stands alone and is under 20 KB.

| # | file | read it for | must not be skipped because |
|---|---|---|---|
| 01 | `01-PURPOSE-AND-PRINCIPLES.md` | why the kit exists and the rules every part obeys | every later rule is one of these applied |
| 02 | `02-RUN-FLOW.md` | what happens, job by job, in one run | the order is load-bearing (redaction before publication, discovery before scanning) |
| 03 | `03-VOCABULARY-AND-VERDICT.md` | the exact states and the gate/routing contract | a consumer integrates against these words, and a sixth spelling is a defect |
| 04 | `04-SCANNERS.md` | each scanner job: tool, trigger, what it enforces, its known gaps | each one has a different failure shape |
| 05 | `05-WEAKENINGS-AND-POSTURE.md` | every input, how weakening one is recorded, how routing decides | a softened control that is not recorded reads as a clean run |
| 06 | `06-FINDINGS-LIFECYCLE-AND-TICKETING.md` | identity, ledger, dispositions, Jira and Azure DevOps | a ticket is a REQUEST, never a disposition |
| 07 | `07-BUILD-PROVENANCE-DEPLOY-ROLLBACK.md` | build once, provenance, deploy gated on the verdict, rollback | deploy is the stage with the most design and the least build |
| 08 | `08-HOW-THE-KIT-PROVES-ITSELF.md` | the proofs, validation debt, deferrals, and what "proven" means | "it compiles" and "a test exists" are not proof here |
| 09 | `09-STATUS-BUILT-VS-DESIGNED.md` | what is built and proven, what is designed only, what needs a hosted run | building on a designed-only part as if it ran is the failure this kit exists to stop |
| 10 | `10-CHANGE-LOG.md` | what changed since the last version you read (v1.11 onward) | read this first on every later delivery |
| 10b | `10b-CHANGE-LOG-EARLIER.md` | the change log for v1.10 back to v1 | history only; read it to trace why a rule exists |
| 11 | `11-INTEGRATING-WITH-THE-KIT.md` | **wiring another product to the kit**: who deploys what, what the landing zone hands over, the workflow shape, reading the verdict | it is the only part written for integration rather than understanding |
| 12 | `12-CHANGES-SINCE-A907DC8.md` | every behavioural change since explainer v1.10 (`a907dc8`), grouped by what an integrator must do differently | a builder working from v1.10 is otherwise wiring against outdated behaviour |

**If your last copy was v1.10** (trunk `a907dc8`), read 12, then replace every part 12 says changed.

Evidence for every claim of "proven", with run ids, is the Release 1 evidence manifest in three parts
under `docs/assurance/`: `RELEASE_1_EVIDENCE_MANIFEST.md` (scan, gate, NVD, provenance),
`RELEASE_1_EVIDENCE_MANIFEST_PART2.md` (identity, build, deploy, ticketing) and
`RELEASE_1_EVIDENCE_MANIFEST_PART3.md` (what a consumer can and cannot read; what the trunk added
since main). Each is under 20 KB and stands alone.

## If you can read only three

01, 03 and 09 — the rules, the contract, and what is real. If you are WIRING a product to the kit, add 11.

## Four things to get right before anything else

1. **The verdict, not the job result.** Deploy reads `routing_result`. A job that "succeeded" can carry
   findings, softened enforcement, or missing evidence. Part 03.
2. **Absence is not a negative.** "Nothing found", "nothing exists", "nothing was looked at" and "the
   control is off" are four different states, and the kit never lets a tool collapse them. Part 01.
3. **Secrets block in every mode.** Advisory mode softens inherited findings. It never softens a leaked
   credential — in source, in history, or baked into an image. The one way past a found secret is a
   ticketed exception for that ONE finding in the policy register, renewed only under a cap. Parts 03–05.
4. **A ticket is a request.** Closing, editing or approving a ticket changes nothing the gate reads. Only
   a disposition merged to the protected default branch does. Part 06.

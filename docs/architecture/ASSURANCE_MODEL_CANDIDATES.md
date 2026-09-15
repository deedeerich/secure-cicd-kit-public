# Assurance model — design candidates

```
Status: CANDIDATES. Nothing here is built. Recorded so the design survives, and so that when it is
built the record shows what was intended versus what shipped.
```

**The narrow question this addresses:**

> How do we make safe change flow continuously when independent human reviewers are scarce?

Answer shape: mechanized constraints + independent AI challenge + evidence-backed risk classification
+ bounded authority + runtime verification + selective human escalation. That gives separation of
*function* without requiring separate *people* in serialized queues.

---

## C-1 · Drift catcher — code-to-cloud reconciliation

**Ancestry check: absent from the corpus — but CORRECTED 2026-08-12, and the correction matters.**

The search found no dedicated drift or reconciliation capability. The only `drift` in code is
`line_drift` in the AGHAS correlator, scoring whether a finding matches a line that *moved between
commits* — finding-identity-across-change, not infrastructure reconciliation. Adjacent, not an
ancestor.

An earlier draft called that "genuinely new." **That was wrong.** Owner context: drift reconciliation
was the **platform team's responsibility** at the prior organization, and they had a solution in
progress. It is absent from her corpus because it **was not in her role's scope**, not because nobody
thought of it.

**This is a fourth absence class** — see the reconstruction's §22.11, which distinguishes
*org-boundary* · *lost-to-event* · *deliberately-withheld*. Add **out-of-scope-of-prior-role**. Like
the withheld class, it carries information: absence here says something about *organizational
boundaries*, and nothing whatsoever about *novelty in the field*.

**Why it is live now, and this is the actual pressure:** the motivating context is a security
engineer embedded in a **very small team responsible for the cloud and everything operating in
it**. The boundary that made this someone else's problem no longer exists. `Known pressure` — role scope
changed, not a new idea arriving.

**Consequence for how this gets built.** An earlier draft said "adopt the detection; build the
disposition model." **AMENDED — that assumed wheels exist.** Don't-reinvent-the-wheel is not
assume-somebody-installed-wheels. The principle is:

> **Reuse trustworthy detection where it exists. Implement missing detection where necessary.
> Normalize the evidence. Build the differentiated reasoning, reconciliation and disposition layer
> above it.**

Detection is a **capability dependency, not a product assumption**. For every signal the model needs,
ask: *do we have a trustworthy detector for this condition — configured, enforced where appropriate,
observable, and producing evidence we can consume?* If yes, integrate. If no, prefer an established
tool, and build only where there is a genuine capability gap.

Still true: **the differentiated layer is the governance above detection** — consequence
classification, evidence production, authority for mutation, exception-as-state, reverse drift as
legitimate. In any framing, "I built drift detection" invites a fair comparison to mature tooling;
"I built the layer that decides what drift *means* and who may act on it" does not.

### Two layers, and the seam between them is the portable part

| Layer | Contents |
|---|---|
| **Detection / adapters** | Azure Policy · Terraform/OpenTofu plan and state comparison · Defender · GitHub/CodeQL · dependency and container scanners · identity/RBAC checks · configuration scanners · resource inventory · telemetry freshness · FinOps signals. Each adapter **normalizes** what its native tool produces **without pretending all signals mean the same thing**. |
| **Assurance / disposition** | Correlates observations against declared intent, controls, exceptions, ownership, consequence, evidence quality and authority — then decides what deserves attention. |

Portability lives in the seam. The upper layer must not care whether one organization gets
configuration drift from Terraform + Azure Policy + Resource Graph while another uses OpenTofu, AWS
Config, and a feral shell script from 2019 that inexplicably runs the company. It cares about the
**observation contract, provenance, freshness, and claim entitlement**.

### Missing detection is itself a finding

If the model asks *"has production network configuration drifted from declared state?"* and no
mechanism can establish that, the answer is **not** `NO_DRIFT`:

```
DRIFT_STATE   = UNKNOWN
REASON        = NO_TRUSTWORTHY_DETECTION_CAPABILITY
ASSURANCE_GAP = NETWORK_CONFIGURATION_DRIFT
```

Typed absence applied outside its origin — and the same shape as the M-07 entitlement failure, where
an empty fallback control set was indistinguishable from a clean result. **"A control failed" and "we
lack the coverage to know whether the control is effective" must never produce the same dashboard
state.**

### Detection capability ladder

Discovering that Azure Policy or Defender *exists* establishes almost nothing about whether it can
support the claim being made. Assess each detector:

```
Available -> Configured -> Producing evidence -> Evidence trustworthy & current -> Coverage sufficient
```

Structurally identical to `designed -> configured -> enforced -> observed -> effective`, applied to
detectors rather than controls — and subject to the same rule: **each rung needs its own evidence and
cannot be inferred from the one below.**

### Implementation order

1. **Inventory** what detection already exists in the target environment.
2. **Map** it against the signals the assurance model requires.
3. **Reuse** adequate capabilities.
4. **Repair** badly configured ones — usually cheaper than adding tools.
5. **Add commodity tooling** where a capability is absent.
6. **Write custom detectors only for genuine gaps.**
7. The disposition layer consumes all of them through **normalized contracts**.

### Job

> Compare declared intent against deployed reality, detect meaningful divergence, classify
> consequence, and produce **evidence** — not automatically "fix" everything.

### Loop

```
repo / IaC / pipeline intent
   → deployed cloud state
   → policy & control expectations
   → observed telemetry
   → diff → classify → disposition
```

### Drift types — "drift" alone is too coarse to act on

| Type | Divergence |
|---|---|
| **Configuration** | Deployed state differs from IaC/config |
| **Policy** | Resource still deployed but no longer meets *current* controls |
| **Identity / permission** | RBAC, PIM, service identities changed outside intended state |
| **Dependency / version** | Images, packages, modules differ from approved versions |
| **Observability** | Expected telemetry stopped arriving, or became stale |
| **Governance** | Required approvals, evidence, or metadata disappeared or expired |
| **Reverse** | Production carries a legitimate emergency/manual change **not reflected back into code** |

**Reverse drift is the one most tools ignore.** Reconciliation is bidirectional. A system that only
says "Terraform says prod is wrong" treats every emergency fix as a violation and trains people to
route around it.

### Required behavior

```
detect → explain → classify → propose reconciliation → REQUIRE AUTHORITY for consequential mutation
```

Not `agent saw diff → agent rewrote prod`. Auto-remediation is permitted only where remediation is
deterministic, reversible, and bounded — the **auto-correct** treatment class, not the default.

### Why it is the glue

It answers, continuously: what did we intend · what did we deploy · what changed outside the pipeline ·
what evidence says the control is still effective · what drift is harmless, what is material, and what
requires a human. That is materially more useful than a dashboard that reddens whenever Terraform
sneezes.

---

## C-2 · Risk-tiered independent assurance

**The governing principle:**

> **Human review is reserved for consequential uncertainty, not every change.**

"AI review plus ceremonial human blessing on every PR" is still a bottleneck — it just moves the queue.

| Tier | Required |
|---|---|
| **Low** — reversible, bounded, non-sensitive paths | Deterministic CI · scanners · tests · policy checks · **AI adversarial review**. No second human if evidence is strong. |
| **Medium** | All of the above · independent architect review (separate agent context) · non-prod deployment · smoke/integration/security evidence · deferred peer review if solo-staffed |
| **High** — life-safety, identity, network boundary, production data, irreversible | Human platform/security/architect approval before prod · rollback and recovery evidence · explicit blast-radius review · two-person approval where feasible |

**Change classification happens at PR creation**, so the system selects the assurance path rather than
a human deciding how much process to apply after the fact.

---

## C-3 · Compensating mechanisms for thin staffing

Grouped by what they buy:

**Prevent by construction** — policy-as-code for mechanically forbiddable things · golden/paved-road
templates so secure defaults are *inherited* rather than re-reviewed · change-budget and blast-radius
limits bounding what agents may auto-approve.

**Preserve integrity across stages** — environment promotion of the *same immutable artifact*
(dev → test → prod, no rebuilding between stages) · deploy by digest and signature, so what was tested
is what ships.

**Generate evidence automatically** — an evidence bundle per PR/release: tests, scans, SBOM,
provenance, policy results, drift diff, rollback plan. Assembled by machinery, not by a person writing
a summary.

**Make review independent** — the reviewing model must not be the one that authored the change ·
falsification prompts requiring the reviewer to state what would make the implementation wrong and
then check for it.

**Move assurance into runtime** — canary/slot deployment with health gates and automatic rollback ·
continuous post-deploy verification, because pre-prod review cannot establish production
effectiveness · telemetry integrity checks **before** trusting "healthy" or "no findings."

**Handle what can't be resolved now** — exception-as-state, never bypass: expiry, owner, rationale,
compensating control, revisit trigger · deferred-review queue for low-risk self-approved changes,
sampled later · random/sample deep review rather than exhaustive review of every trivial change.

**Include cost** — FinOps checks in the same pipeline. Infrastructure drift includes accidental spend,
not only security.

**Make it visible** — reconciliation view showing code intent, cloud reality, unresolved drift,
exceptions, evidence freshness, and owners.

---

## C-4 · Assurance profiles

Staffing changes the **mechanism**; it must not change the **objective**.

| Profile | Shape |
|---|---|
| **Solo engineer** | PR required · AI independent review required · deterministic checks required · author merge allowed for low-risk · high-risk escalates to a human · post-merge sample audit |
| **Small team** | Independent human review where available · AI review still required · CODEOWNERS on sensitive paths · stronger environment protections |
| **Critical service** | No direct merge or deploy · platform/security approval · rollback and recovery evidence · canary or slot promotion · post-deploy verification mandatory |

Implemented today at the branch level in `developer-safety/branch-protection/` — `solo.json`,
`small-team.json`, `critical-service.json`. The profiles above are the fuller operating model those
JSON files are a first slice of.

---

## Relationship to already-recovered doctrine

These are extensions, not inventions, and the lineage should be stated whenever they are presented:

| Candidate element | Recovered ancestor |
|---|---|
| Treatment classes (prevent / auto-correct / challenge / defer / block) | Findings as *states requiring disposition* |
| Exception-as-state with expiry and owner | Supersession with lineage and controlled reason enum |
| Evidence bundle per release | Claim entitlement — what permits reliance on the output |
| Telemetry integrity before trusting "healthy" | Freshness and fail-open findings; "silent services are untriageable" |
| Reviewer must not be the author | No self-approval; no agent validates its own work |
| Risk-tiered escalation | Escalate conflict / consequential uncertainty / exception / novelty / irreversibility / risk acceptance |
| Baseline always runs, overlays are selected | Baseline Core Profile + applicable overlays |

**Not established as new — and the distinction matters.** The drift *catcher* is absent from her
corpus for role-scope reasons, and detection itself is a mature commodity. What has no clear ancestor
either in the corpus or in the common tooling: **reverse drift as a first-class legitimate type**,
**consequence classification driving disposition** rather than binary compliant/non-compliant, and
**change classification at PR creation selecting the assurance path**. Those three are where any
novelty claim should be made, narrowly, and only after checking the tooling landscape rather than
only the corpus.

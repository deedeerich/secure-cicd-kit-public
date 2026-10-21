# Work item hierarchy — three tiers, and why it is not four

```
Status: DECIDED 2026-09-24. Constrained by both backends, not chosen on merit.
Preferred design: FOUR tiers. Adopted design: THREE. See "If the option appears".
```

## The decision

| tier | what it is | Azure DevOps (Basic) | Jira (team-managed) |
|---|---|---|---|
| 1 | **product** | `Epic` | `Epic` |
| 0 | **vulnerability, or vulnerability class** — the correlation cluster | `Issue` | `Story` |
| −1 | **instance** — one observation at one locus | `Task` | `Subtask` |

The mapping between backends is a **rename, not a redesign**. Same depth, same parent/child
semantics, same place for every field. That is what makes the adapter an adapter.

## Why not four

The preferred design was `Epic → Feature → Story → Task`: product, then scanner family or
capability area, then the vulnerability class, then each instance. Fewer tickets carrying more
taskings, and a rollup tier that answers "how is SCA doing" without a saved filter.

Neither backend supports it on the plans in use, and the reasons are different:

**Azure DevOps** — the project runs the **Basic** process, whose only work item types are
`Epic`, `Issue` and `Task`. The four-tier shape exists in the **Agile** process
(`Epic → Feature → User Story → Task`), but the process is fixed **at project creation and cannot
be changed on an existing project**.

**Jira** — the test project is team-managed, and its hierarchy is `Epic` (level 1), then `Bug`/`Feature`/
`Story`/`Task` (level 0), then `Subtask` (level −1). **`Feature` exists as a type but sits at
level 0 — a sibling of `Story`, not a tier above it.** Having the word does not give the depth.
A tier above `Epic` requires Premium and Advanced Roadmaps.

So four tiers would mean a new Azure DevOps project **and** a Jira plan upgrade, and would still
leave the two backends at different depths — which is the one thing a backend-agnostic contract
cannot absorb, because it changes where a field lives rather than what it is called.

## What is lost, stated plainly

The scanner-family rollup. It moves from a hierarchy tier to a **label or component**
(`sca`, `sast`, `secrets`, `iac`, `container`) on the level-0 item.

That is a real loss and it is a query loss, not a data loss: grouping by family becomes a filter
rather than a parent. Nothing about correlation, SLA, disposition or closure depends on it.

## If the option appears, take it

**Go to four tiers** when both backends can carry it — a new Azure DevOps project on the Agile
process, and a Jira plan with Advanced Roadmaps. Expanding three into four is a reparent;
collapsing four into three is a merge, and the merge is the lossy direction.

Until then this is a **technical constraint recorded as one**, not a preference. Anyone reading
the three-tier shape later should know it was forced, so they do not defend it on merit.

## The invariants that do not change with tier count

- **The SLA clock lives on the INSTANCE**, never the class. Severity varies within a class, and a
  single class-level deadline lets one low-severity member extend a critical's clock.
- **Closure is one-way.** A class item may close when every instance beneath it closes. An
  instance must **never** close because its parent did — only the scanner failing to reproduce it
  clears a finding, and both backends will happily cascade the wrong way if asked.
- **Volume is a deliberate trade.** One instance item per observation means item count equals
  finding count. Above a per-class threshold the class carries a count and an evidence artifact
  instead of N children, because both tools degrade badly past a few hundred children on one
  parent.
- **The correlation key is stamped on the level-0 item**, which is the unit check-before-create
  looks up. The Jira test project is team-managed, so custom fields are project-scoped — one project means one
  field with one id, and the stamped key format stays stable. Project-per-product would give a
  different field id per project and break it.

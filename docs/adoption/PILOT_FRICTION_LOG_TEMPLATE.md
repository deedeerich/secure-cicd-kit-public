# Pilot friction log

The owner's question was how painful adoption will be. The honest answer is "heavy in week one without help,
light afterwards if it is rolled out well", and this log is how we find out which, per team, instead of
guessing. Every pilot team keeps one while it adopts the kit; the platform team summarises all of them each
week with `scripts/friction_summary.py`. The rollout plan's wave gates read the summary
([ROLLOUT_PLAN.md](ROLLOUT_PLAN.md)).

**The target:** a new repository goes from nothing to its **first green security run at crawl in one hour or
less** (kit init, the checklist, the first run). Every minute past that is friction we owe a fix for.

## How to keep it (two minutes a day)

Copy [`pilot-friction-log.template.csv`](pilot-friction-log.template.csv) to your team's share (one file per
team, or one per repository) and add a row whenever one of these happens. Delete the example rows.

| `kind` | when | what to fill in |
|---|---|---|
| `first_green` | once per repository: the first time `security / Security gate` is green at crawl | `minutes` = from starting kit init to that green run, wall clock |
| `stuck` | every time you were stuck for 5 minutes or more | `step` (where: kit init, the checklist step, the first run, a deploy ...), `error_state` (the name in brackets after the plain sentence, as `namespace.STATE` if you have it, e.g. `environment_protection.ENVIRONMENT_REVIEWERS_ABSENT`), `minutes` lost, `fix` (what worked), `fixed_by` (`self`, `docs`, `platform`, `security`, `other`) |
| `satisfaction` | at the end of week one, and again at week four | `satisfaction` 1 (painful) to 5 (easy), and a `note` in your own words |

Every row also carries `team`, `repository`, `date` (YYYY-MM-DD), and where you know them `stack`,
`deploy_shape` (`container`, `static`, `none`) and `rung` (`crawl` while piloting).

**Write the state name exactly as the run printed it.** The summary joins each one to its plain-English
entry in [docs/errors/ERRORS.md](../errors/ERRORS.md); a state with no entry there is reported as a gap in
the catalogue, which is a fix we owe, not a mistake you made.

## What we do with it

- **Each stuck point** with a state name: if the plain sentence did not get you unstuck, the entry is
  rewritten. If several teams hit the same step, the step is automated (kit init) or removed.
- **Time to first green over 60 minutes**: the platform team pairs with that team for its next repository,
  and the slowest step becomes the next kit-init or checklist change.
- **Satisfaction of 2 or less**: a 15-minute conversation that week.

## The summary

```bash
python3 scripts/friction_summary.py path/to/logs/            # every *.csv in the folder
python3 scripts/friction_summary.py team-a.csv team-b.csv --json summary.json
```

It prints, per team and overall: time to first green against the 60-minute target (met, missed, or not yet),
minutes lost and where (the steps and the error states, worst first, each with its plain sentence), who
fixed them, and the satisfaction scores. A row it cannot read is listed with the reason and never silently
dropped; the summary exits 1 when there is one, so a broken log is fixed rather than half-counted.

Nothing in the log may be a secret, a customer name or a person's performance note: it is about the kit's
friction, not about people.

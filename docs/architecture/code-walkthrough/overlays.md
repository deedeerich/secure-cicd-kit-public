# Code walkthrough: overlays and export profiles

```
Kept:      2026-11-07. Held by tests/check_code_walkthrough_coverage.py (rule W4).
```

[Back to the walkthrough index](README.md)

An **overlay** (`overlays/NAME/`) is one organisation's additions to the kit: its own scanners, its
pipeline template, its settings and its threat notes. The rules (`docs/architecture/THREAT_MODEL.md`
section 6, KDEC-003):

- an overlay adds and never relaxes a core rule;
- the core never depends on an overlay (`tests/check_custody.py`);
- the neutral export withholds every overlay a profile does not name (`scripts/export_for_adoption.py`);
- the neutral core never names an overlay's owner (`tests/check_export_safety.py`).

So each overlay's walkthrough lives **inside the overlay**, as `overlays/NAME/CODE_WALKTHROUGH.md`, with
paths relative to the overlay. This page names no overlay. In a neutral copy of the kit there are no
overlays at all, and this page is the whole of this section.

The **export profiles** (`scripts/export-profiles/`) say who a copy of the kit is for. They are withheld
from the neutral export too, and their rows live in `scripts/export-profiles/CODE_WALKTHROUGH.md`.

| Where | What it lists |
|---|---|
| `overlays/NAME/CODE_WALKTHROUGH.md` | every file of that overlay: its actions, scripts, template, workflows, docs, tests and fixtures |
| `scripts/export-profiles/CODE_WALKTHROUGH.md` | the profiles' README and each profile |

How an overlay is wired to the core is drawn in [../02_CONTAINERS.md](../02_CONTAINERS.md) section 3.6 and
[../05_TRUST_BOUNDARIES.md](../05_TRUST_BOUNDARIES.md) TB-10.

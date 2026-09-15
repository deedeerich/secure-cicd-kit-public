#!/usr/bin/env python3
"""Assert every job in a reusable workflow is enumerated by its gate job.

A scanner that runs but cannot fail the gate is reporting, not gating. This kit
shipped exactly that defect once; this check exists so it cannot ship again.
"""
import sys, yaml

WF, GATE = ".github/workflows/reusable-security.yml", "security-gate"
d = yaml.safe_load(open(WF, encoding="utf-8"))
jobs = set(d["jobs"]) - {GATE}
needs = set(d["jobs"][GATE].get("needs") or [])
missing = sorted(jobs - needs)
print(f"jobs={len(jobs)} gate_needs={len(needs)}")
if missing:
    print("::error::Jobs run but CANNOT fail the gate: " + ", ".join(missing))
    print("A scanner that cannot block is reporting, not gating.")
    sys.exit(1)
print("OK: every job is enumerated by the gate")

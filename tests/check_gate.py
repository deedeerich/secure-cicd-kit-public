#!/usr/bin/env python3
"""Assert every job in a reusable workflow is enumerated by its gate job.

A scanner that runs but cannot fail the gate is reporting, not gating. This kit
shipped exactly that defect once; this check exists so it cannot ship again.

ONE REGISTERED EXCEPTION, AND IT IS THE INVERSE RULE, NOT A HOLE. A job registered in
scanner-registry.yaml with class `governance` runs AFTER the gate (propose-ledger: its only
authority is a pull request, and a proposal must never be able to fail a verdict). The gate
cannot wait for a job that runs after it, so such jobs are read from the registry and left out
of this comparison -- and tests/check_scanner_registry.py fails the build if the gate ever DOES
wait for one. Nothing is exempt by name here; the class is the decision, in a reviewed file.
"""
import sys, yaml

WF, GATE = ".github/workflows/reusable-security.yml", "security-gate"
REG = "scanner-registry.yaml"
d = yaml.safe_load(open(WF, encoding="utf-8"))
reg = yaml.safe_load(open(REG, encoding="utf-8")) or {}
after_gate = sorted(n for n, r in (reg.get("jobs") or {}).items()
                    if isinstance(r, dict) and r.get("class") == "governance")
jobs = set(d["jobs"]) - {GATE} - set(after_gate)
# `needs:` is a STRING when a job has one dependency. set() over a string is a set of
# CHARACTERS, which would report every real job missing and pass only by accident.
_needs = d["jobs"][GATE].get("needs") or []
needs = set([_needs] if isinstance(_needs, str) else _needs)
missing = sorted(jobs - needs)
print(f"jobs={len(jobs)} gate_needs={len(needs)} after_gate={after_gate}")
if missing:
    print("::error::Jobs run but CANNOT fail the gate: " + ", ".join(missing))
    print("A scanner that cannot block is reporting, not gating.")
    sys.exit(1)
print("OK: every job is enumerated by the gate (governance jobs run after it, by class)")

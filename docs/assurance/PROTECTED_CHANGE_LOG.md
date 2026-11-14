# Protected change log

A pull request that changes a file deciding what "Self-test required" and the capability floor mean
(`scripts/protected_paths.py` CHANGE_GUARDED) adds a row here naming a decision id and every guarded
path it changes. Rows are never edited or removed: the self-test contract job refuses a removed line.

This log is VISIBILITY, not authority. The same pull request could rewrite the check that reads it.
The authority is code-owner review by the protected owner (CODEOWNERS `kit-protected-owner`), with
the ruleset requiring code-owner review, the "Self-test required" check, and no bypass actors
(KDEC-050).

| date | decision | guarded paths changed | what |
|---|---|---|---|
| 2026-11-11 | KDEC-050 | `.github/workflows/self-test.yml`, `scripts/capability_floor.py`, `scripts/protected_paths.py`, `capability-floor.json`, `CODEOWNERS`, `tests/prove_capability_floor.py`, `tests/prove_scanner_floor_shrink.py` | Append-only tombstones and base comparison on every event (KE-04), the tombstone policy seam (KE-03, PROPOSED), the protected owner (KE-05), this log and its check. |
| 2026-11-13 | KDEC-059 | `.github/workflows/self-test.yml`, `scripts/protected_paths.py`, `CODEOWNERS`, `scripts/governance_gate.py`, `governance-profile.json`, `.github/workflows/governance-gate.yml`, `tests/prove_governance_profiles.py` | The governance profiles (KDEC-052 item 11, KE-02): a base-side gate reads the PR as data; the new files are guarded and owned; the self-test runs their proofs. |

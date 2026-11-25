# Scanner obligations: what a repository must be scanned for, and who may provide it

```
Status:    KDEC-069, PROPOSED (owner direction 2026-11-18, approved 2026-11-24). Built and proven offline.
Policy:    scanner-obligations.json (kit root; protected: governance-profile.json scanner_floor class)
Evaluator: scripts/scanner_obligations.py, run by .github/actions/scanner-obligations in the security gate
Proof:     tests/prove_scanner_obligations.py
```

## 1. The rule

**Discovery decides what is owed. A token decides only whether a provider can run.**

- **Obligation.** What the repository contains and what the run pushes or deploys (the plan's discovery, the image
  it scans, WordPress found in the tree), matched against `required_when` in the versioned policy. No token, secret
  or environment variable is read to decide it.
- **Providers.** Each obligation lists the scanners that may satisfy it, and the coverage aspects each one gives. A
  partial replacement shows the exact aspects it leaves uncovered (`PARTIAL`).
- **Lifecycle.** Core providers are adopted by default. An external one (`ext-<name>`, the KDEC-028 row name) is an
  option until a record adopts it. An adopted provider that did not run, with no retirement record, is
  **UNAVAILABLE**, whatever its token says.
- **Satisfaction.** A required aspect no adopted provider covers is a visible **COVERAGE_GAP**. It needs a
  time-bound acceptance by the risk owner, or a control retirement.

## 2. What the gate does with it

| state | crawl | walk, run, or no resolved policy |
|---|---|---|
| SATISFIED, NOT_REQUIRED, CONTROL_RETIRED, REMOVED_BY_EXCEPTION | proceed | proceed |
| UNAVAILABLE (adopted provider did not run) | advisory, cause SCANNER_DID_NOT_RUN | refused |
| COVERAGE_GAP, PARTIAL | advisory, cause SCANNER_DID_NOT_RUN | refused until accepted or retired |
| GAP_ACCEPTED | advisory, cause COVERAGE_PARTIAL, assurance PARTIAL | the same: never PASS |
| not evaluated (the composite crashed, the policy was refused) | refused | refused |

DAST is a promotion-phase obligation: it is judged against the deploy evidence, not at the pull-request gate.

## 3. The records (each is one entry in `scanner-obligations.json`, merged to `main` with its approval)

**Adopt an external provider** (your organisation connected it and expects it to run):

```json
{"provider": "ext-sonar", "state": "ADOPTED", "on": "2026-11-25", "by": "<login>"}
```

**Retire a provider** (the licence was not renewed, the tool was replaced). One line; it never retires the control:

```json
{"provider": "ext-sonar", "state": "RETIRED", "on": "2026-11-25", "by": "<login>", "reason": "not renewed", "replaced_by": "semgrep"}
```

Both go in `provider_lifecycle`, which is history: append, never edit. The last record per provider wins.

**Accept a coverage gap for a time.** `accepted_by` must be the `risk_owner`. It lives at most
`acceptance_max_days` (90) from `decided_on`:

```json
{"obligation": "wordpress-components", "aspects": ["wordpress-themes"], "accepted_by": "<risk owner>",
 "risk_owner": "<risk owner>", "decided_on": "2026-11-25", "expires": "2027-02-20", "reference": "RISK-12"}
```

**Retire a control.** This is a security decision. The `main` approval authorises the change, but the residual risk
is accepted by the risk owner named in the record:

```json
{"obligation": "...", "decided_by": "<security approver>", "risk_owner": "<risk owner>",
 "residual_risk_accepted_by": "<risk owner>", "decided_on": "2026-11-25", "reference": "SEC-DEC-3"}
```

**Remove an obligation from one repository.** The exception lives in the governed policy (`obligation_exceptions`,
approved by someone other than its requester, never a bot, with an expiry). The repository's own
`.kit/obligations.json` only names it:

```json
{"remove": [{"obligation": "image-scan", "exception_ref": "SEC-41"}]}
```

A repository may also **add** an obligation for itself (`{"declare": [{"obligation": "dast", "why": "..."}]}`). It can
never remove one by its own word: that is `REMOVAL_REFUSED`, and the obligation stays.

## 4. Findings from a retired tool

A finding keeps its identity. The retired tool's absence never closes it. A replacement's clean result closes it
**only with shown equivalence**:

- the same issue type;
- the same location (in the replacement's scope and its path inventory);
- the relevant version (the replacement completed, on a recorded commit or artifact digest);
- detection capability (the policy says the replacement detects that issue type).

Otherwise it is `RESCAN_PROVIDER_RETIRED_NO_EQUIVALENCE`. It waits for a verifier who is not the fixer, or an
authorised disposition (`docs/ticketing/SEPARATION-OF-DUTIES.md` section 5).

## 5. Limits (stated, not hidden)

- The core policy names `ext-sonar`, `ext-wp-vulns` and `ext-zap` as options, never adopted. An organisation that
  runs them adds the adoption records in its own copy of the kit.
- WordPress discovery is a bounded tree read (`wp-includes/version.php`, `wp-config.php`, `wp-content/plugins`,
  `wp-content/themes`, a WordPress Composer package). Neutral discovery does not compute it yet.
- Coverage aspects are coarse: one `source-flaws` aspect for SAST. Per-language fitness stays with the capability
  selection (`scanner-registry.yaml`).
- The ticket path compares issue types only when a coverage row or the ledger observation declares them. Where
  neither does, equivalence is not shown, and the finding waits for a person.

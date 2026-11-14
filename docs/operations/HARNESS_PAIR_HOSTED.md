# The hosted kit-harness pair: owner setup

**Status:** the job is built (`.github/workflows/kit-harness-pair.yml`, KDEC-058; accepted direction KDEC-052
item 9). It is NOT established: until the four settings below exist, every run ends **HARNESS_LEG_NOT_RUN**, red,
with each missing piece named. That is the intended outcome, not a fault.

## What it does

`tests/prove_kit_harness_pair.py` (KREQ-302) runs the kit's export leg and the evidence harness's import leg on one
shared fixture and fails when either leg did not run or a vendored copy differs. Locally it needs
`--harness-root`. The hosted job:

1. decides, in `scripts/harness_pair_gate.py plan`, whether it may run: the event is a push to the default branch
   or a dispatch from it; the App key and client id are present; the harness repository is `OWNER/REPO`; the pin in
   `.github/harness-pair.json` is a full 40-hex commit;
2. only then mints a GitHub App installation token with `permission-contents: read`, for the harness repository
   alone (`actions/create-github-app-token`, SHA-pinned at v3.3.0);
3. checks the harness out at the pinned commit with that token and `persist-credentials: false`;
4. in `scripts/harness_pair_gate.py run`, checks the checkout's HEAD is the pin and runs the pair proof. Any
   missing piece is `HARNESS_LEG_NOT_RUN` with its reasons, an `::error` annotation and a step-summary line.
   It never exits 0 without the pair passing.

| Reason | Meaning |
|---|---|
| CREDENTIAL_ABSENT | the App private-key secret or the client-id variable is missing |
| EVENT_NOT_TRUSTED | not a push to, or a dispatch from, the default branch (a pull request never gets the token) |
| HARNESS_REPOSITORY_NOT_SET | `KIT_HARNESS_REPOSITORY` is empty or not `OWNER/REPO` |
| PIN_NOT_SET | `.github/harness-pair.json` names no commit |
| PIN_NOT_A_COMMIT | the pin is a branch, tag, short SHA or `HEAD`, not a full 40-hex commit |
| HARNESS_CHECKOUT_MISSING | the mint or checkout step failed, so there is no harness checkout |
| HARNESS_PIN_MISMATCH | the checkout's HEAD is not the pinned commit |

## Why it never sits beside pull-request code

- The workflow has no `pull_request` or `pull_request_target` trigger.
- The key lives in the environment `kit-harness-pair`, which (step 2 below) admits only the default branch. A
  pull request that edits the workflow to reference it runs from its own ref and is refused the environment.
- The gate refuses every other event and ref before the mint step can run (third layer, proven offline).
- The token goes only to `actions/checkout` for the harness; no later step receives it. The action revokes it
  when the job ends.

The job is its own workflow rather than a self-test job: self-test's `required` verdict needs every self-test
job, and this one is red on purpose until the credential exists.

## Owner setup (on the SAME host as the kit run)

The token is minted at `github.api_url` and the checkout reads `github.server_url`, so on a GHE.com tenant both stay
on `<tenant>.ghe.com` (KDEC-027, `tests/prove_ghe_host.py`). Create the App on the host where the kit and the
harness live; a github.com App cannot read a ghe.com repository.

1. **GitHub App.** Settings > Developer settings > GitHub Apps > New. Webhook off. Repository permissions:
   **Contents: Read-only**; leave every other permission at No access (Metadata: Read-only is added automatically).
   No organization or account permissions. Generate a private key. Install it on the harness repository **only**
   ("Only select repositories").
2. **Environment.** In the kit repository: Settings > Environments > New environment `kit-harness-pair`.
   Deployment branches and tags: **Selected branches**, the default branch only. Add the environment secret
   `KIT_HARNESS_APP_PRIVATE_KEY` (the private key's full PEM text) and the environment variable
   `KIT_HARNESS_APP_CLIENT_ID` (the App's client id).
3. **Repository variable.** `KIT_HARNESS_REPOSITORY` = `OWNER/REPO` of the harness, with no host.
4. **Pin.** A reviewed pull request sets `commit` in `.github/harness-pair.json` to the merged harness commit
   that carries the KDEC-051 reader (full 40-hex). Change it only by a reviewed pull request.

Then dispatch "Kit-harness pair" from the default branch. When it shows the pair PASS, delete the
`prove_kit_harness_pair.py` UNWIRED entry in `tests/check_selftest_coverage.py` (it expires 2026-12-31).

5. **Push trigger back.** Until setup the workflow is `workflow_dispatch` only (integration 2026-11-13,
   KDEC-058 M6): with no App every run is HARNESS_LEG_NOT_RUN, and a check that is red on every push to main
   trains people to ignore red. After setup, add `push: branches: [main]` back to
   `.github/workflows/kit-harness-pair.yml` (a protected change, reviewed). `tests/prove_harness_pair_gate.py`
   W1 enforces both states: dispatch only while the pin is null, push(main) and dispatch once it is set, so the
   pin pull request (step 4) and this one land together.

Note: GitHub creates an environment the first time a job names one. If the workflow reaches the default branch
before step 2, `kit-harness-pair` appears with no branch rule and no secret; the run is still HARNESS_LEG_NOT_RUN
(no key), and step 2 adds the rule.

## Proofs

- `tests/prove_harness_pair_gate.py` (self-test): the decision, the run, the workflow's shape, nine mutants
  (an unpinned ref, a trusted pull_request, an absent credential read as 0, and four workflow edits).
- Locally, through the gate, against a harness checkout at its pinned commit: rc 0 on 2026-11-13 (lane
  actionlint-pair). That is a local run, not hosted acceptance.

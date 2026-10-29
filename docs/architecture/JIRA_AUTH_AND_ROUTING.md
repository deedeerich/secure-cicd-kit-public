# Jira auth, ticket routing and test ticketing

KDEC-028 (lane L-AM, owner 2026-10-23). This page covers three things:

- how the kit authenticates to Jira without a person's account;
- how a finding's ticket reaches the right project or board;
- how test runs write tickets without any risk to the real project.

Every variable and secret is listed in section 5.

**Truth labels.**

- VERIFIED means run here: against fakes (`tests/prove_jira_auth_and_routing.py`) or live against the owner's personal Jira site.
- READ means taken from a cited source and not run.
- OWED means it needs a run nobody has done yet.

---

## 1. Authentication

### 1.1 Two modes

| Mode | Selected by | What is sent | Where |
|---|---|---|---|
| `basic` (default) | `JIRA_EMAIL` is set, or `JIRA_AUTH_MODE` unset/`basic` | `Authorization: Basic base64(JIRA_EMAIL:JIRA_TOKEN)` | the site (`JIRA_HOST`); the gateway when `JIRA_CLOUD_ID` is set |
| `bearer` | `JIRA_AUTH_MODE=bearer` **and** no `JIRA_EMAIL` | `Authorization: Bearer JIRA_TOKEN` | always the gateway `https://api.atlassian.com/ex/jira/<cloudId>` |

**Basic always wins when `JIRA_EMAIL` is set.** If `JIRA_AUTH_MODE=bearer` is also set, the backend note says so: "JIRA_AUTH_MODE=bearer is not honoured while JIRA_EMAIL is present". The kit never changes mode silently.

Configurations that are refused, each naming the variable to fix:

- an unknown `JIRA_AUTH_MODE`;
- bearer without `JIRA_TOKEN`;
- basic without `JIRA_EMAIL`;
- a malformed `JIRA_CLOUD_ID`.

Any `401` or `403` names the credential in use. In bearer mode that is `JIRA_TOKEN` alone, never `JIRA_EMAIL`.

### 1.2 The cloud id

The gateway addresses a site by its cloud id.

- If `JIRA_CLOUD_ID` is set, it is used.
- If it is unset, the kit looks it up once at `https://<JIRA_HOST>/_edge/tenant_info`. That request carries **no** credential.
- If the lookup fails, or returns no well-formed cloud id, the run refuses and names `JIRA_CLOUD_ID`. Nothing is sent to the gateway and nothing is written.

You can also read the cloud id in admin.atlassian.com: it is the string after `/s/` in the site's admin URL [5].

### 1.3 Why bearer: service accounts

A token belongs to the account that created it, and so does an email. With basic auth that account is usually a person's. When the person leaves, ticketing breaks, and until then tickets look as if that person filed them [3][4].

An Atlassian **service account** solves this:

- An organisation admin creates it under admin.atlassian.com, Directory, Service accounts.
- It gets access to the project or projects.
- The admin creates a **scoped** API token for it, valid for 1 to 365 days and shown once [5].

Behaviour of these tokens, from the sources:

- **Gateway only.** Service-account tokens and scoped tokens must use the `api.atlassian.com` gateway; the site URL does not work with them [1][2][5].
- **Bearer works without an email.** The token can be sent as a Bearer token with no email [1][2]. Atlassian's support page says "You can use Bearer token authentication or basic authentication in the HTTP header" [5].
- **Scoped tokens with basic auth.** A *personal* scoped token is used with basic auth (email plus token) against the gateway [6]. That is why basic mode with `JIRA_CLOUD_ID` set also goes through the gateway.

The scopes the reconciler needs:

- read the project, issue types, create metadata and the user;
- search with JQL;
- create and edit issues;
- comment;
- transition.

These correspond to the classic `read:jira-work`, `write:jira-work` and `read:jira-user` scopes. That mapping is READ, not verified.

### 1.4 What was verified, and what is owed

Live checks against the owner's personal site, 2026-10-23:

| Check | Result |
|---|---|
| `_edge/tenant_info` with no credential | returned a well-formed cloud id (VERIFIED) |
| basic, site URL | run-start validation established the project, issue types, stamp field and epic (VERIFIED, regression) |
| basic, gateway (`JIRA_CLOUD_ID` set) | the same validation, through `api.atlassian.com/ex/jira/<cloudId>` (VERIFIED) |
| bearer with a *person's classic* API token | `401`, refused naming `JIRA_TOKEN` (VERIFIED). This is expected: a classic personal token is not a bearer credential |
| test-mode create through the gateway, then a rerun | one ticket, `PP-8`, summary starting `[TEST] [low]` (a live-test rule id on `infra/lam-live.tf`), labels `iac, kit-test, secure-cicd-kit`. The rerun was `LEDGER_BOUND` and created nothing (VERIFIED) |

**OWED: a live bearer success.** The personal site has no service account, and none was created. Atlassian's sources also warn that "some endpoints still only work with Basic Auth and not with Bearer" [1]. The first service-account run must therefore confirm each endpoint the reconciler calls:

- `/myself`
- `/project`
- `createmeta`
- `search/jql`
- `issue` create and edit
- `comment`
- `transitions`

If one of them refuses bearer, use basic with the service account's own address in `JIRA_EMAIL`, plus `JIRA_CLOUD_ID`. No person's identity is involved in either mode.

### 1.5 Every Jira caller

| Caller | Jira API? | Auth |
|---|---|---|
| `scripts/reconcile_tickets.py` (both reusable workflows) | yes | both modes, through `choose_backend` |
| `scripts/exception_due.py` | yes | both modes: it builds its backend with `reconcile_tickets.choose_backend` |
| `.github/workflows/reusable-ticket-reference.yml` (the PR reference gate) | **no**: it reads the pull-request text only | none needed. The proof asserts it carries no Jira credential |
| an overlay's `run_jira_step.py` | no: it runs the gate step | none |
| `scripts/check_env.py` | no (it reads `.env`) | does not require `JIRA_EMAIL` when `JIRA_AUTH_MODE=bearer` |

## 2. Routing tickets to projects and boards

### 2.1 The rule

`ticket_routing` lives on any policy-register entry, at any scope (`scripts/ticket_routing.py`; schema `schemas/policy-registration.schema.json`). It is an ordered list of rules plus a default:

```json
"ticket_routing": {
  "rules": [
    {"id": "cloud", "match": {"scanner_family": ["iac"], "category": ["IAC_PLAN", "RESOURCE", "POLICY"]},
     "project": "AZSEC", "issue_type": "Bug", "components": ["Azure"], "labels": ["cloud-security"]},
    {"id": "dast", "match": {"scanner_family": ["dast"]}, "project": "SEC"}
  ],
  "default": {"project": "SEC"}
}
```

**Match keys.** Every key given must hold; a list means "any of these".

| Key | Values |
|---|---|
| `class` | `secret`, `kev`, `malicious`, `finding` |
| `scanner_family` | `secrets`, `sca`, `sast`, `iac`, `container`, `dast` |
| `scanner` | a scanner name |
| `category` | the `finding_subject` |
| `severity` | a list of severities |
| `min_severity` | one severity: that one or worse |
| `repository` | `owner/name` globs |

**Targets.** Each rule names a `project`. It may also set:

- `issue_type`, which otherwise is `JIRA_TYPE_CLUSTER`;
- `epic`, the numeric id of an epic in *that* project;
- `components`;
- `labels`.

A routed project never inherits `JIRA_EPIC_ID`, because that epic belongs to `JIRA_PROJECT`.

### 2.2 Precedence

Repository, then org+team+product, org+product, org+team, org, enterprise, and finally the kit default, which is `JIRA_PROJECT`.

**Routing is not a security floor.** A narrower scope overrides a broader one freely, in either direction. Compare the rung, where a narrower scope may only tighten.

- Rules are tried most-specific scope first, and the first match wins.
- A scope's rules are followed by its parent's, unless the scope says `"inherit": false`. That drops broader rules but keeps a broader default.
- The default comes from the most specific scope that sets one.

**The simple case needs no register.** Set `JIRA_PROJECT` as an organisation variable and override it with a repository variable where a repository has its own board. GitHub already resolves a repository variable over an organisation variable of the same name [7].

### 2.3 The one exception: TICKET_ROUTING_BELOW_FLOOR

A rule or default with `"project": "none"` creates no ticket. That is allowed for ordinary findings.

It is never allowed for a secret, a KEV-listed vulnerability or a known-malicious package:

- **In the register.** A `none` rule whose `match.class` names one of those classes is refused as `TICKET_ROUTING_BELOW_FLOOR`, which routes BLOCKED like every other below-floor register.
- **At run time.** A `none` rule or default that happens to match such a finding is skipped for it, and the run notes name the refusal. The finding is ticketed by the next rule, the default, or `JIRA_PROJECT`.

All of this is VERIFIED with fakes.

### 2.4 A rule change never moves or duplicates a ticket

Routing is consulted only when a ticket is **created**.

The sweep covers:

- `JIRA_PROJECT`;
- every project the routing names;
- every project the ledger records a ticket in. The ledger stores each ticket's `project`.

So after a rule changes, the next run finds the existing ticket where it is, updates it as usual, and creates nothing. It adds **one** comment saying that routing now names another project and the ticket stays put. A rerun does not repeat that comment. VERIFIED with fakes.

**Residual.** If the ledger is lost, and the old project is no longer named anywhere in the routing, the sweep cannot see the old ticket. A new one can then be created in the new project. Keep a retired project in a rule until its tickets are closed.

## 3. Test ticketing: chosen by the branch, never by a variable

There is **no variable to swap** (owner, 2026-10-23). A variable that someone sets to "test" and forgets to put back sends real findings to a sandbox. There are two GitHub Environments instead, and the reusable workflow picks between them from the **ref**:

| Run | Mode | Environment | Holds |
|---|---|---|---|
| push or dispatch on the **default branch** | real | `ticketing`: deployment branches = default branch only | the real `JIRA_PROJECT`, routing, token |
| push or dispatch on **any other branch** | test, and only if the caller names `test_environment` | `ticketing-test`: deployment branches = dev and feature branches | a SANDBOX `JIRA_PROJECT` (e.g. `SECTEST`) and its own token |

How it works:

- The callers name both environments: `environment: ticketing` and `test_environment: ticketing-test` (templates `ticket-reconcile.yml` and `exception-due.yml`).
- The guard derives `TICKETING_MODE` and the job's environment from the ref. Schedules and pull requests never arm a test run.

What test mode does:

- **Every test ticket is marked.** It carries the label `kit-test` and a `[TEST]` summary prefix.
- **The register's routing is not followed.** It names real projects, so everything goes to the sandbox.
- **Ledger bindings are kept apart, in both directions.** Test bindings are stored as `test:<cluster key>`. A test run never sees or touches a real ticket, and a real run never binds to a test one. A test run's ledger is never proposed.

Guard `TICKETING_TEST_TARGETS_REAL_PROJECT` refuses before anything is sent when any of these holds:

- `JIRA_REAL_PROJECTS` is unset;
- the sandbox is one of `JIRA_REAL_PROJECTS`;
- the sandbox is a project the register's routing names.

Set the `JIRA_REAL_PROJECTS` organisation or repository variable to the real keys.

All of the above is VERIFIED with fakes. The live `PP-8` row in 1.4 is a test-mode run.

## 4. What only a hosted run can prove

- That GitHub honours each environment's deployment-branch policy, including that a feature-branch run cannot obtain the `ticketing` environment.
- That the environment expression resolves as written.
- A bearer run with a real service-account token (1.4).

## 5. Every variable and secret

| Name | Kind | Where | Needed |
|---|---|---|---|
| `JIRA_HOST` | variable | env `ticketing` / `ticketing-test` (or org) | yes: `https://<site>.atlassian.net` |
| `JIRA_PROJECT` | variable | org, overridden per repo; **the sandbox key in `ticketing-test`** | yes: the kit-default project |
| `JIRA_TOKEN` | secret | each ticketing environment | yes: the service account's token |
| `JIRA_EMAIL` | secret | each ticketing environment | basic only; never a person's address |
| `JIRA_AUTH_MODE` | variable | each ticketing environment | `bearer` for a service-account token; unset = basic |
| `JIRA_CLOUD_ID` | variable | each ticketing environment | optional: looked up when unset |
| `JIRA_REAL_PROJECTS` | variable | org or repo | required for test runs: the real project keys |
| `JIRA_STAMP_FIELD` | variable | each ticketing environment | yes: `customfield_<id>`, provisioned once, on every routed project's screens |
| `JIRA_EPIC_ID` | variable | each ticketing environment | yes: numeric, in `JIRA_PROJECT` |
| `JIRA_CALIBRATION_ISSUE` | variable | each ticketing environment | yes: numeric, a ticket the credential did not create |
| `JIRA_TYPE_CLUSTER` / `JIRA_TYPE_INSTANCE` | variable | each ticketing environment | optional: Story / Subtask |
| `JIRA_TRANSITION_REOPEN` / `JIRA_TRANSITION_DONE` | variable | each ticketing environment | optional |
| `JIRA_PRIORITY_LADDER` | variable | each ticketing environment | optional |
| `TICKET_CREATE_CEILING` | variable | each ticketing environment | yes |
| `TICKET_CALL_BUDGET`, `TICKET_RETRY_CEILING`, `TICKET_INSTANCE_THRESHOLD`, `TICKET_DEGRADED_RUN_THRESHOLD`, `TICKET_STAMP_LABEL` | variable | each ticketing environment | optional |
| `ticket_routing` | register entry field | `policy/policy-registration.json` (central) or `.security/policy-registration.json` | optional |
| `TICKETING_MODE` | **derived**, never set | the reusable workflow, from the ref | none to set |

Each routed project must:

- carry the issue types its rules name;
- have the stamp field on the create screen;
- have its epic, if a rule names one, in that project.

Run-start validation checks all of this before anything is written, and refuses by naming the rule.

## Sources

Read on 2026-10-23.

1. Atlassian Community, "A Guide to Service Accounts in Atlassian Cloud - Part 3: Service Accounts in Practice". Says: the gateway URL; cloud id from `_edge/tenant_info`; "The API Token can usually be sent in the Header as Bearer Token ... you don't need the Service Account Email"; "some endpoints still only work with Basic Auth". [link](https://community.atlassian.com/forums/Jira-Cloud-Admins-articles/A-Guide-to-Service-Accounts-in-Atlassian-Cloud-Part-3-Service/bc-p/3186443)
2. Atlassian Community, "Jira API with Basic Auth and Service Account". The accepted answer: service accounts need `api.atlassian.com`; "You can use them but not with Basic Auth, however if you sent it as a Bearer token it should work". [link](https://community.atlassian.com/forums/Jira-questions/Jira-API-with-Basic-Auth-and-Service-Account/qaq-p/3119645)
3. unified.to, "Jira API key: how to get it and use it". Says: credentials are user-linked; prefer service accounts; the `api.atlassian.com` base URL. [link](https://unified.to/blog/jira_api_key_how_to_get_it_and_use_it_api_token_guide_for_developers)
4. Knit, "How to Get a Jira API Token". Says: basic auth is email:token; tokens last 1–365 days; scoped tokens route through `api.atlassian.com/ex/jira/{cloudId}`. [link](https://getknit.dev/blog/jira-api-key)
5. Atlassian Support, "Manage API tokens for service accounts". Says: "You can use Bearer token authentication or basic authentication"; tokens must use `api.atlassian.com`; the Jira URL form; scopes; expiry; cloud id after `/s/`. [link](https://support.atlassian.com/user-management/docs/manage-api-tokens-for-service-accounts/)
6. Atlassian Support, "Manage API tokens for your Atlassian account". Says: scoped tokens call `https://api.atlassian.com/ex/jira/{cloudId}` with basic auth (`--user me@example.com:my-api-token`). [link](https://support.atlassian.com/atlassian-account/docs/manage-api-tokens-for-your-atlassian-account/)
7. GitHub Docs, "Variables reference". On precedence: "If a variable with the same name exists at multiple levels, the variable at the lowest level takes precedence" (environment over repository over organisation). [link](https://docs.github.com/en/actions/reference/workflows-and-actions/variables)

Sources 1 and 2 render with JavaScript. They were read from the page HTML with curl, because the fetch tool returned only the title. Sources 3 to 7 were read with the fetch tool.

# SonarQube and Aikido findings in the kit's intake

Status: built and proven against stand-in HTTP servers (2026-11-06). No call to a real SonarQube or
Aikido yet: the first one is the owner's, at work, with the checklist at the end.

## What it does

`scripts/external_findings_pull.py` pulls findings from **SonarQube** (Server or Cloud) and **Aikido**,
read-only, and turns each open one into a `finding` ticket-template item (KDEC-037,
`api/v1/tickets/finding.schema.json`) with its provenance. It checks every item against the template,
removes the ones the kit's own scan already holds, and writes one file. It writes nothing to either
vendor and nothing to a tracker.

`.github/workflows/reusable-external-findings.yml` runs it in two separate modes:

| mode | when | what it may do |
|---|---|---|
| **pull** | a schedule or a dispatch | read the source (`contents: read`), keep the result as the artifact `external-findings-<source>`; with `review_id` set, cut batches of at most 20 items and print each batch's `evidence_sha256` |
| **submit** | a dispatch with `submit: true`, `review_id` and `from_run_id` | wait in the environment `external-findings-review` until its required reviewers approve, then send each batch **of that pull, unchanged**, to the kit API as `tickets.submit` |

The kit API then applies KDEC-037 in full: the review must be finalized, with a concurrence bound
to that exact evidence set; separation of duties applies; every ticket in the tracker, manual ones
included, is searched before one is created. Submit never pulls again, because the review concurred
with the pull it read.

Starter: `templates/external-findings.yml`. The kit's own copy, `.github/workflows/external-findings.yml`,
runs only on dispatch, because this repository holds neither secret.

## Secrets (the owner sets them; never printed, masked before anything runs)

| secret | what it is |
|---|---|
| `SONAR_TOKEN` | a SonarQube user token with Browse on the projects, sent as `Authorization: Bearer` |
| `SONAR_HOST_URL` | `https://sonarcloud.io`, or your SonarQube Server URL (https only) |
| `AIKIDO_CLIENT_ID`, `AIKIDO_CLIENT_SECRET` | client credentials an Aikido workspace admin creates on the integrations page (scope `issues:read`) |

## The vendor APIs, as read on 2026-11-06

| what | source | confirmed |
|---|---|---|
| Sonar auth: `Authorization: Bearer <token>` | docs.sonarsource.com/sonarqube-server/extension-guide/web-api/ ("we recommend that you use the bearer authentication scheme") | Server: yes. Cloud: **UNVERIFIED** by a live call |
| `GET /api/issues/search`: `componentKeys`, `organization`, `impactSoftwareQualities`, `issueStatuses`, `p` (1-based), `ps` (at most 500) | sonarcloud.io/api/webservices/list | yes |
| issues answer: `paging{pageIndex,pageSize,total}`, `issues[]{key, rule, component, line, textRange, message, issueStatus, impacts[{softwareQuality, severity}]}`, `components[]{key, path}` | sonarcloud.io/api/webservices/response_example?controller=api/issues&action=search | yes |
| `GET /api/hotspots/search`: `projectKey`, `status=TO_REVIEW`, `p`, `ps`; `hotspots[]{key, component, securityCategory, vulnerabilityProbability, status, line, message, ruleKey}` | the same two pages | yes; Cloud marks it "deprecated as of 16 June, 2026", and its replacement is **UNVERIFIED** |
| CWE per issue | not in the issues or hotspots answer; optional `GET /api/rules/show` field `securityStandards` (`cwe:89`) | **UNVERIFIED**: that field is not in the documented example. Without it the CWE is left empty |
| a 10,000-result search depth | not stated in the pages read | **UNVERIFIED**; the pull refuses past it as `SOURCE_TRUNCATED` |
| Aikido token: `POST https://app.aikido.dev/api/oauth/token`, `grant_type=client_credentials`, HTTP Basic with id and secret | apidocs.aikido.dev/reference/authorization | yes; the answer's `access_token` name is the OAuth 2.0 standard's (**UNVERIFIED** on the page). The US token URL is **UNVERIFIED** (derived from the US API base) |
| `GET <base>/issues/export`: `format=json`, `filter_status=open`, `page` (0-based), `per_page` (10 to 5000); base EU `https://app.aikido.dev/api/public/v1`, US `https://app.us.aikido.dev/api/public/v1` | apidocs.aikido.dev/reference/exportissues | yes; the end of paging (a page shorter than `per_page`) is **UNVERIFIED** |
| issue fields: `id, group_id, type, severity, status, rule, rule_id, affected_package, affected_file, cve_id, cwe_classes, start_line, code_repo_name, patched_versions` | the same page | yes; the exact form of `cwe_classes` entries is **UNVERIFIED** (both `CWE-79` and `79` are read) |

## How each field is mapped

| finding field | SonarQube | Aikido |
|---|---|---|
| `identifier` | the rule key (`javasecurity:S3649`) | the CVE when there is one, else `aikido:<type>:<rule_id>` |
| `severity` | the SECURITY impact: BLOCKER critical, HIGH high, MEDIUM medium, LOW low, INFO info (else the old severity: BLOCKER critical, CRITICAL high, MAJOR medium, MINOR low); a hotspot's probability | as given (critical, high, medium, low) |
| `cwe` | from the rule lookup only (UNVERIFIED field), through `scripts/finding_ids.py` | every `cwe_classes` member through `scripts/finding_ids.py`; an unknown form is listed in `id_refusals` |
| `asset` | `repo-path`: the repository from the map, the file, the line | the same, from `code_repo_name`, `affected_file`, `start_line` |
| `finding_subject` | `SOURCE` | open_source/license `SOURCE_DEPENDENCY`, sast and secrets `SOURCE`, iac `IAC_PLAN`, container `IMAGE` |
| `fix_status` | `FIX_AVAILABILITY_NOT_ESTABLISHED` | `FIX_AVAILABLE` when `patched_versions` lists one |
| status | OPEN/CONFIRMED become items; ACCEPTED and FALSE_POSITIVE are listed under `source_closed` | `open` becomes an item; anything else is `source_closed` |
| `aliases`, `evidence` | `sonar:<key>`; the sha256 of the record as received | `aikido:<id>` and the CVE; the same |

A finding that cannot be mapped (no repository in the map, no file, a cloud or container finding,
which need their own asset scheme) is listed `NOT_MAPPED` with the reason. It is never dropped.

**Code findings and the SAST identity.** The SAST/evidence-export lane is building a code-finding
identity on the trunk. Until it lands, a code finding matches a kit finding by path, line and CWE,
and a dependency finding by CVE and path (`kit_duplicate()`, the one function to replace). Two Sonar
issues of one rule in one file are one identity until then; both vendor keys are kept as aliases.

## One normaliser for every id

Every CWE and vulnerability id, from every source, goes through `scripts/finding_ids.py` (the format
table is its docstring, with sources): `CWE-79`, `cwe-079`, `CWE79`, `cwe:79`, `external/cwe/cwe-079`,
Semgrep's `CWE-89: ...` strings, Bandit's `{"id": 79}`; `CVE` in any case and separator, `GHSA`, OSV ids,
and namespaced vendor ids (`sonar:`, `sonar-rule:`, `aikido:`). A GHSA resolves to its CVE when the
advisory's `aliases` name one. An unknown form is refused (`CWE_FORM_UNKNOWN`, `VULN_ID_FORM_UNKNOWN`),
never guessed. The kit's own report and the SAST family resolver use the same module
(`tests/prove_finding_ids.py`).

**Unknown ids are never lost** (owner ruling, 2026-11-06). Every id the kit cannot read -- here, in the
kit's own report, and an unknown SAST rule (`RULE_FAMILY_UNKNOWN`) -- is written to `unknown-ids.json`
(tool, rule, raw id, source, count) beside the output, printed as `NEEDS_MAPPING`, and turned by the
ticket reconciler into ONE review item per (kind, tool, rule, raw id), labelled `needs-mapping` and
`needs-human-review`. A person maps it in `id-mappings.json` (author, date and review reference
required; CODEOWNERS); until then it stays unknown, never guessed (`tests/prove_unknown_ids.py`).

## States (assurance-taxonomy.yaml `external_findings_pull`)

`SOURCE_PULLED` (every page read, items listed; zero items is a result) · `SOURCE_NOT_CONFIGURED` ·
`SOURCE_AUTH_REFUSED` (401/403: never "no findings") · `SOURCE_UNREACHABLE` · `SOURCE_RESPONSE_INVALID` ·
`SOURCE_TRUNCATED` · `SOURCE_HOST_REFUSED` (not https). Every state but the first fails the run.

## Testing at work: the owner's checklist

1. Copy `templates/external-findings.yml` into the repository that holds the secrets; pin the kit by
   commit SHA; set `sonar_projects`, `sonar_organization` (Cloud only) and `repo_map`.
2. Confirm the secrets exist with those exact names: `SONAR_TOKEN`, `SONAR_HOST_URL`,
   `AIKIDO_CLIENT_ID`, `AIKIDO_CLIENT_SECRET` (organisation secrets must be visible to that repository).
3. Create the environment `external-findings-review` with **required reviewers** (the security team,
   self-review prevented). Owner command, not run by this lane:
   `gh api -X PUT repos/<org>/<repo>/environments/external-findings-review --input env.json`, with
   `env.json` = `{"reviewers":[{"type":"Team","id":<team id>}],"prevent_self_review":true}`.
4. Dispatch **External findings** with nothing set. Expect `SOURCE_PULLED` for each source and
   read the summary: items, duplicates of kit findings, closed at the source, not mapped (with why).
5. Negative check: temporarily point `SONAR_HOST_URL` at the right host with a wrong token in a
   scratch repository. Expect `SOURCE_AUTH_REFUSED`, a red run, no items.
6. Note anything the summary says is `NOT_MAPPED` and extend `repo_map`; record the first real
   answers against each UNVERIFIED row above (the CWE field, the US token URL, the page end).
7. To write tickets: dispatch again with `review_id`; finalize that review over the printed
   `evidence_sha256` values (KDEC-037); then dispatch with `submit: true`, the same `review_id` and
   `from_run_id` set to the pull's run id; approve in the environment. Read each answer with
   `scripts/kit_api.py status --correlation-id <id>`. Test on the owner's personal tracker first.

Proofs: `tests/prove_external_findings_pull.py`, `tests/prove_external_findings_workflow.py`.

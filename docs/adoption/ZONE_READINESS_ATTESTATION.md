# Zone readiness when there is no landing zone — the AppSec attestation

```
Truth State:  BUILT and proven locally (KDEC-036 G1, owner ruling 2026-11-03;
              tests/prove_reviewer_signals.py R9). No hosted run yet.
Audience:     AppSec, and the team that owns an application's repository
```

## What this is, and why

Before a release to **uat** or **prod**, the kit asks one question about the platform the app runs
on: *is this zone ready to take a production release?* (`KIT_ZONE_READINESS`: `READY`,
`READY_WITH_EXCEPTIONS`, `NOT_READY`). Only `READY` and `READY_WITH_EXCEPTIONS` release there.

**Who may answer it** (owner ruling, 2026-11-03):

- **Inside a connected landing zone**, the landing zone answers. Its vend writes `KIT_ZONE_READINESS`
  and its marker `KIT_HANDOFF_ISSUER: landing-zone` into each GitHub environment. Nothing below applies.
- **Outside one**, **AppSec** answers, with a signed-off file in the application repository:
  `.kit/zone-readiness.json`. The app or deploy team never answers it for itself.

A readiness value the repository set on its own (`KIT_ZONE_READINESS` with no landing-zone marker and
no attestation) is **self-set**: the deploy refuses it at uat and prod
(`READINESS_SOURCE_SELF_SET_REFUSED`). Letting the deploy side certify the platform's readiness to
itself is exactly what this closes.

## The file

Copy `templates/zone-readiness.example.json` to `.kit/zone-readiness.json` on the default branch:

| field | what it holds |
|---|---|
| `environment` | the GitHub environment it is for (`"prod"`), or a list of them |
| `state` | `READY`, `READY_WITH_EXCEPTIONS` or `NOT_READY` |
| `issuer_role` | `appsec` |
| `issued_by` | the AppSec reviewer who issued it (their GitHub login) |
| `issued_on` | `YYYY-MM-DD`, not in the future |
| `expires_on` | `YYYY-MM-DD`; after it the attestation is refused |
| `evidence_ref` | the review record, ticket or assessment it rests on |
| `exceptions` | a list; `READY_WITH_EXCEPTIONS` must name at least one |

## Who can change it

Put `developer-safety/codeowners/CODEOWNERS.zone-readiness` in `.github/CODEOWNERS`, and protect the
default branch: a pull request, code-owner review required, no administrator bypass. List the AppSec
reviewers' GitHub **logins** in the central policy register's approver list `appsec`
(`approver_lists.appsec`; another name with `numbers.appsec_approver_list`).

## What the deploy checks, at uat and prod, before it logs in

With the job's own token (`contents: read`, `pull-requests: read`), cheaply:

1. the file on the default branch is a valid attestation for **this** environment, not expired, with
   evidence;
2. its latest change on the default branch arrived through a **merged pull request**;
3. that pull request was **approved** by someone on the `appsec` list who is **not its author**.

Any of these failing is `READINESS_ATTESTATION_REFUSED`, with the reason, and the release is refused.
Passing, the release reads `readiness_source` `READINESS_SOURCE_APPSEC_ATTESTATION` and the
attested state decides, exactly as a landing zone's value would. Below uat nothing is read: readiness
is recorded, never required.

## Test fixtures

A personal sandbox or a test repository may set `KIT_ZONE_READINESS: READY` itself **only** with the
variable `KIT_ZONE_READINESS_TEST_FIXTURE: true`. The release then reads
`READINESS_SOURCE_TEST_FIXTURE`, with a warning: a test fixture, never an issued readiness. A reviewer
seeing it on an environment that serves real users stops and asks (S7).

## What the kit cannot see

Team membership (it matches logins against the list), and who wrote a GitHub variable (the audit log
shows it). See `docs/security-review/OBTAIN-SEPARATELY.md`.

# Questions for app teams — a short interview sheet

```
Truth State:  Authored, not field-tested (2026-11-03).
Use:          at the first meeting, before reading runs. Ask for links, not descriptions. Record
              each answer as Observed, Read or Stated (SIGN-OFF.md).
```

## The app

1. What does the app do, for whom, and who owns it (by role)?
2. Where does it run: App Service, Container Apps, Static Web Apps, Functions (as a container, or as a
   code package), AKS, VMs, or something else? Which
   environments (dev, test, uat, prod), and which of them serve real users?
3. Is it inside a landing zone that vends its target and deploy identity, or outside one?
4. What data does it store, process or send on? Does any of it go to another team's system?
5. Who can reach it: the internet, internal users only, other services only?

## The pipeline

6. Which workflow calls the kit, and at which commit SHA? Please send the file.
7. Send the latest security run id on the commit you want reviewed, and the latest deploy run id
   per tier.
8. Is any scanner narrowed, softened or switched off (`language`, `paths`, `advisory_mode`,
   `soft_fail_sast`, `iac_mode`, `enable_sbom`)? Who decided, where is it recorded, and when does it
   end?
9. Is the `Security gate` check required on the default branch? Who can change branch protection?
10. Are there secret or known-exploited exceptions in the policy register? Is each secret rotated?

## Identity and deploy

11. Which identity deploys each environment, what roles does it hold, and at what scope?
12. Who approves uat and prod releases? Does the approver quote the digest in the approval comment?
13. Who set `KIT_ZONE_READINESS`, `KIT_ENVIRONMENT_TIER` and `KIT_HANDOFF_ISSUER` on each environment?
    (The readiness value must come from the landing zone, or from AppSec as a recorded attestation —
    never from the app team. The deploy records `readiness_source` and `tier_source` from the
    landing zone's marker; the audit log says who wrote it.)
14. Is `KIT_TARGET_LEASE_ACCOUNT` set? If not, what else could change the target during a release?
15. Has a rollback ever been run? Send the run id if so.

## Around the app

16. What third parties does it use (SaaS, APIs, vendor actions or images)? Are any new?
17. Does any AI agent or automation hold a token that writes to the repository, the tracker or the
    cloud target?
18. Has anything security-relevant happened to it recently (a leaked secret, an alert, an outage
    caused by a change)? If yes, that is a conversation for incident response first.
19. What is changing in this release, and is any of it new data, new exposure, new privilege, a new
    third party or a new environment?
20. Who should we talk to for anything the team cannot answer?

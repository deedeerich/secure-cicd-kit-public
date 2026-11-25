# Cloud checks — one list, by what each check is for (read-only)

```
Truth State:  Authored, not field-tested (2026-11-03; merged by intent 2026-11-04). Commands follow
              the Azure CLI and Microsoft Graph v1.0, the AWS CLI v2 and the GitHub REST API v3 as
              documented; run them on a non-production subscription, account or repository first and
              correct this sheet where an output differs.
Use with:     CAB-CHANGE-SAFETY-STEPS.md steps 4 and 5. Run only the checks for the boundary rows
              that are yes, and only on the platforms the change touches.
Read-only:    every command is a list, show, get, describe, lookup, validate or simulate, or a GET.
              None creates, edits or deletes. A reader role is enough for almost all of them (Azure
              Reader on the scope, plus the Graph read permission named; AWS SecurityAudit or
              ReadOnlyAccess; a GitHub read token). Where it is not, the check says so: ask the
              platform role to run it and send you the output. Never take a write role to review.
Replaces:     CLOUD-CHECKS-AZURE.md, CLOUD-CHECKS-AWS.md and CLOUD-CHECKS-GITHUB.md. Every old id
              (Z1..Z14, W1..W12, H1..H8) is kept as an alias on the check that now holds it; the
              alias table is at the end. Those three files remain as pointers to this one.
```

**How each check reads.** Each check is stated **once, by what it is for**, in words that are true
on any cloud: the question, then what is **safe**, what to **ask** about and what is a **stop**. Below
it, an **implementation table** says where that answer lives on Azure, on AWS and on GitHub, and, for
any other cloud, **how to find the equivalent**: the kind of setting or log to look for, so a reviewer
on a platform this sheet does not name can still do the check. Then the exact read commands per
platform, unchanged from the platform sheets they came from.

**A sovereign or government cloud** (any provider's separate partition for a government or a
jurisdiction) uses the same checks. Point the CLI at that cloud's own endpoints and sign-in first
(on Azure, `az cloud set` to that cloud; on AWS, a profile for that partition, whose accounts and
credentials are separate), use that cloud's Graph or API host, and expect some features to be absent
there: an absent feature is a gap to record, never "off" and never "clean".

**Placeholders.** Azure: `<sub>` subscription id, `<rg>` resource group, `<name>` resource name,
`<id>` full resource id, `<principalId>` an identity's object id, `<appId>` an app registration's
client id, `<spId>` its service principal's object id. AWS: `<role>`, `<policyArn>`, `<bucket>`,
`<keyId>`, `<fn>` (Lambda), `<apiId>`, `<sg>`, `<vpc>`, `<arn>`; add `--region <region>` where the
resource is regional. GitHub: `<owner>/<repo>`, `<org>`, `<env>`, `<branch>` (the default branch),
`<id>`; on a GHE.com tenant add `--hostname <tenant>.ghe.com` to every `gh` call (KDEC-027: the token
goes only to the host that issued it).

**New to a platform?** Use the console path first and the command second. A few AWS words: an **IAM
role** is an identity a service or pipeline assumes; its **permissions policy** says what it may do
and its **trust policy** who may assume it; a **security group** is a firewall around one resource, a
**network ACL** one around a subnet; **S3 Block Public Access** stops a bucket being public;
**CloudTrail** records API calls and **Config** how resources looked over time. The Azure words map
across: role assignment, managed identity and federated credential; NSG; private endpoint;
Activity log; Policy. If an output does not make sense, ask the platform team to walk you through it:
that is part of the review. The kit has no AWS deploy adapter: an AWS release is outside the kit
(`modules/MOD-OUTSIDE-KIT.md`), so on AWS these reads are the only cloud evidence there is.

---

## C0 · What changed, who changed it, and when? (every review; the "before and after" of each platform sheet)

**Intent.** For each check, read the state **before** the change (production now, or the IaC plan's
"before") and **after** it (a lower environment where it already ran, or the plan's "after"), and the
change history between them. Write both on the ticket.
- **Safe:** the history shows only the change the ticket names. **Stop:** a resource the ticket does
  not name changed in a boundary that matters (CAB-CHANGE-SAFETY-STEPS 4.0).

| | Azure | AWS | GitHub | Other cloud: how to find the equivalent |
|---|---|---|---|---|
| Look at | the resource's **Activity log** | **CloudTrail → Event history**; **Config → Resources → Resource timeline** | the organisation audit log (owners; Enterprise Cloud for the API); otherwise **Settings** pages show current state only, so read them before and after | the provider's control-plane audit log (every management API call, with caller and time) and, if it has one, its resource configuration history |

```sh
# Azure
az monitor activity-log list --resource-id <id> --offset 7d \
  --query "[].{when:eventTimestamp, op:operationName.localizedValue, who:caller, status:status.value}" -o table
# AWS
aws cloudtrail lookup-events --lookup-attributes AttributeKey=ResourceName,AttributeValue=<name> --max-results 50 \
  --query "Events[].{when:EventTime, event:EventName, who:Username}" --output table
aws configservice get-resource-config-history --resource-type <AWS::IAM::Role|AWS::EC2::SecurityGroup|AWS::S3::Bucket|...> --resource-id <id> --limit 5
# GitHub
gh api "orgs/<org>/audit-log?phrase=repo:<owner>/<repo>"
```

## C1 · Who holds which access, and is any of it wider than the change needs? (was Z1, W1)

**Intent.** A diff of permissions, not a list: the grants added are exactly the ones the change
names, at the narrowest scope that works.
- **Safe:** named actions on named resources; the one app, not its group; the group, not the
  subscription or account; the deploy identity holds a deploy role on its app and read on its group;
  the build identity can push only.
- **Ask:** a group-scope grant where a resource scope would do; a service wildcard on one named
  resource; a custom role or policy you have not read.
- **Stop:** an owner, user-access-administrator or role-assignment-administrator role, or a
  contributor role, at subscription, management-group or account-wide scope for a workload identity;
  `*` in the actions; a right to write role assignments or policies (privilege escalation); a grant the
  change does not name (E3); an IAM user with an access key created for a workload (gotcha G2).

| | Azure (Z1) | AWS (W1) | GitHub | Other cloud: how to find the equivalent |
|---|---|---|---|---|
| Look at | the resource (group, subscription) → **Access control (IAM)** → **Role assignments**; **Check access** for one identity | **IAM → Roles →** the role **→ Permissions**; **Policies →** the policy **→ Policy versions** (compare); **IAM Access Analyzer → Findings** | collaborators and teams with admin (C20); app permissions (C20) | the provider's role bindings on the resource and on every parent scope (inherited), and the definition of each custom role; its policy simulator or validator if it has one |
| Platform stop | `Owner`, `User Access Administrator`, `Role Based Access Control Administrator` or `Contributor` at subscription or management-group scope; a custom role with `"*"` in `actions` or `Microsoft.Authorization/*/write` | `"Action": "*"` or `"iam:*"`; `iam:PassRole` on `"*"`; `iam:CreatePolicyVersion`, `iam:AttachRolePolicy` or `iam:PutRolePolicy` on its own role; `validate-policy` returns a `SECURITY_WARNING` | — | the same three classes: full control, grant-others, wildcard |
| Platform safe | deploy identity: `Website Contributor` or `Container Apps Contributor` on its app, `Reader` on its group; build identity `AcrPush` only | conditions that narrow (`aws:SourceAccount`, `aws:PrincipalOrgID`) | — | — |

```sh
# Azure (Z1)
az role assignment list --scope <id> --include-inherited -o table          # who holds what ON this resource
az role assignment list --assignee <principalId> --all --include-inherited \
  --query "[].{role:roleDefinitionName, scope:scope}" -o table             # what this identity holds EVERYWHERE
az role definition list --name "<role name>" --query "[].permissions" -o json   # a custom role's actions
# AWS (W1)
aws iam list-attached-role-policies --role-name <role>
aws iam list-role-policies --role-name <role>                                   # inline policy names
aws iam get-role-policy --role-name <role> --policy-name <name>
aws iam get-policy --policy-arn <policyArn> --query Policy.DefaultVersionId --output text
aws iam list-policy-versions --policy-arn <policyArn>
aws iam get-policy-version --policy-arn <policyArn> --version-id <vN>           # read the new AND the previous version: that is the diff
aws accessanalyzer validate-policy --policy-type IDENTITY_POLICY --policy-document file://policy.json   # wildcards, PassRole to *, ...
aws iam simulate-principal-policy --policy-source-arn <roleArn> --action-names iam:PassRole s3:GetObject --resource-arns <arn>
```

## C2 · Who may become, or assume, this identity? (was W2; the federated-credential lines of Z10)

**Intent.** Trust is a grant too: whoever may assume a role or present a token to an identity holds
everything that identity holds.
- **Safe:** the principal is one named service, one named role, or a CI OIDC trust pinned to one
  repository **and** one environment (`repo:<owner>/<repo>:environment:<env>`, or the id-qualified
  form), with the expected audience.
- **Ask:** another account, subscription or tenant as principal: whose is it, and does a third party
  carry an external-id condition (E5)?
- **Stop:** "anyone" as principal without a narrowing condition; a CI trust pinned to `repo:<owner>/*`,
  matched with a wildcard, or with no subject condition at all (any repository on the host could
  assume it); a branch subject for an environment job.

| | Azure | AWS (W2) | GitHub | Other cloud: how to find the equivalent |
|---|---|---|---|---|
| Look at | **Entra ID → App registrations →** the app **→ Certificates & secrets → Federated credentials**; a managed identity's **Federated credentials** (commands in C11) | **IAM → Roles →** the role **→ Trust relationships** | the repository's OIDC subject template (what it emits) | the identity's trust or workload-identity-federation configuration: issuer, subject, audience |
| Platform safe | one federated credential per environment; audience `api://AzureADTokenExchange` | GitHub OIDC (`token.actions.githubusercontent.com`, or the tenant's own issuer on GHE.com) with `sub` pinned and `aud` `sts.amazonaws.com` | — | — |
| Platform stop | a subject with a wildcard or a branch form for an environment job | `"Principal": {"AWS": "*"}` without a narrowing condition; `StringLike` on `*` | — | — |

```sh
# AWS (W2)
aws iam get-role --role-name <role> --query Role.AssumeRolePolicyDocument
# Azure: az ad app federated-credential list (C11); GitHub: gh api repos/<owner>/<repo>/actions/oidc/customization/sub
```

## C3 · Is anything newly reachable over the network? (was Z2, W3)

**Intent.** Every new opening is a new way in; "temporary" openings are the ones most often forgotten.
- **Safe:** the new rule names a specific source and specific ports; it does not shadow a deny the
  platform relies on.
- **Ask:** a large private range, or a whole virtual network, where one subnet would do.
- **Stop:** inbound from anywhere (`*`, `Internet`, `0.0.0.0/0`, `::/0`) to a management port (22,
  3389, 5985/5986) or a data or cache port (1433, 3306, 5432, 6379, 9200, 27017); all ports from
  anywhere; a rule described as temporary with no removal step (gotcha G1). Shared entries belong to
  the platform (E1).

| | Azure (Z2) | AWS (W3) | GitHub | Other cloud: how to find the equivalent |
|---|---|---|---|---|
| Look at | **Network security groups →** the NSG **→ Inbound security rules**; **Firewall Policies →** the policy **→ Rule collections** | **EC2 → Security Groups →** the group **→ Inbound rules**; **VPC → Network ACLs** | N/A | the per-resource firewall (security group, firewall rule, network policy), the per-subnet ACL, and the **effective** rules on one network interface |
| Platform detail | the `Internet` service tag and `VirtualNetwork` count as wide | all ports is `-1` | — | — |

```sh
# Azure (Z2)
az network nsg rule list -g <rg> --nsg-name <nsg> --include-default -o table
az network nic list-effective-nsg -g <rg> -n <nic>                       # what actually applies to one NIC
az network firewall policy rule-collection-group list -g <rg> --policy-name <policy> -o json   # needs the azure-firewall extension
# AWS (W3)
aws ec2 describe-security-group-rules --filters Name=group-id,Values=<sg> \
  --query "SecurityGroupRules[?IsEgress==\`false\`].{port:FromPort, to:ToPort, cidr:CidrIpv4, cidr6:CidrIpv6, src:ReferencedGroupInfo.GroupId}" --output table
aws ec2 describe-network-acls --filters Name=vpc-id,Values=<vpc> --query "NetworkAcls[].Entries"
```

## C4 · Is a service or data store newly public, or no longer private? (was Z3, Z4, W4)

**Intent.** A store or service reached privately should stay private; public access, anonymous
reads, weak transport and the wrong region are each a boundary change.
- **Safe:** reached through an approved private connection whose DNS resolves privately from the
  caller's network; public network access off where a private connection exists; TLS 1.2 or higher,
  HTTPS only, plain FTP off, remote debugging off; no anonymous or public read on non-public data; the
  region is one the data may sit in (DB-6); retention rules do not delete audit data early (DB-5).
- **Ask:** public access on but restricted to named ranges: who reads it from where? A private
  connection from another subscription, account or tenant: who approved it? A policy granting another
  account: whose, and what data?
- **Stop:** a private connection removed and public access turned on in its place; public access
  newly on for a data store with no network restriction; anonymous read on for non-public data;
  insecure transport allowed on external ingress; "anyone" in a store's policy with no narrowing
  condition.

| | Azure (Z3, Z4) | AWS (W4) | GitHub | Other cloud: how to find the equivalent |
|---|---|---|---|---|
| Look at | the resource **→ Networking → Private endpoint connections**; storage **→ Configuration**; App Service **→ Configuration → General settings** | **S3 →** the bucket **→ Permissions** (Block public access, Bucket policy, Object Ownership); **Management** (lifecycle) | N/A | the service's private-connectivity attachments and their approval state; its "public network access" switch; the store's public/anonymous-access setting, its resource policy, its region and its lifecycle or retention rules |
| Platform safe | `publicNetworkAccess` `Disabled`; storage `allowBlobPublicAccess` false and shared key off where Entra auth is used; network rules `defaultAction` `Deny` with named ranges | all four Block Public Access settings true at account and bucket; `IsPublic` false; ownership `BucketOwnerEnforced` (ACLs off) | — | — |
| Platform stop | `defaultAction` `Allow` with public access `Enabled`; `allowInsecure` true on external ingress | Block Public Access off for a bucket holding non-public data; `"Principal": "*"` | — | — |
| Kit note | the kit's promotion posture check reads the App Service and Container Apps settings back (`POSTURE_PASSED`); a store's are yours to read | no kit read on AWS | — | — |

```sh
# Azure (Z3)
az network private-endpoint list -g <rg> -o table
az network private-endpoint-connection list --id <id> -o table          # on the target resource: Approved / Pending / Rejected
# Azure (Z4)
az resource show --ids <id> --query "{publicNetworkAccess:properties.publicNetworkAccess, location:location}"
az storage account show -g <rg> -n <name> --query "{public:publicNetworkAccess, defaultAction:networkRuleSet.defaultAction, blobPublic:allowBlobPublicAccess, sharedKey:allowSharedKeyAccess, minTls:minimumTlsVersion, httpsOnly:enableHttpsTrafficOnly}"
az webapp show -g <rg> -n <name> --query "{httpsOnly:httpsOnly, public:publicNetworkAccess}"
az webapp config show -g <rg> -n <name> --query "{minTls:minTlsVersion, ftps:ftpsState, remoteDebugging:remoteDebuggingEnabled}"
az webapp config access-restriction show -g <rg> -n <name>
az containerapp show -g <rg> -n <name> --query "properties.configuration.ingress.{external:external, insecure:allowInsecure, ipRules:ipSecurityRestrictions}"
# AWS (W4)
aws s3control get-public-access-block --account-id <account>
aws s3api get-public-access-block --bucket <bucket>
aws s3api get-bucket-policy-status --bucket <bucket>                     # PolicyStatus.IsPublic
aws s3api get-bucket-policy --bucket <bucket> --query Policy --output text
aws s3api get-bucket-ownership-controls --bucket <bucket>
aws s3api get-bucket-location --bucket <bucket>                           # residency (DB-6)
aws s3api get-bucket-lifecycle-configuration --bucket <bucket>            # retention (DB-5)
```

## C5 · Is the data encrypted at rest with the key the data class requires? (was W5)

**Intent.** Encryption at rest is usually on by default; the review question is **whose key**, and
whether the change moved it.
- **Safe:** a customer-managed key where the data class requires one; otherwise the platform's key.
- **Stop:** encryption changed to a key in another account, subscription or tenant, or a key feature
  disabled with no reason given.

| | Azure | AWS (W5) | GitHub | Other cloud: how to find the equivalent |
|---|---|---|---|---|
| Look at | the store's **Encryption** blade (platform-managed or customer-managed key, and which vault); transport is in C4 | the bucket's default encryption (SSE-KMS with a customer-managed key, or SSE-S3; bucket keys) | N/A | the store's encryption-at-rest setting and the key it names: provider-managed or customer-managed, and where that key lives |
| Platform stop | — | encryption changed to a key in another account, or bucket keys disabled with no reason given | — | — |

```sh
# AWS (W5)
aws s3api get-bucket-encryption --bucket <bucket>
```

## C6 · Who can use, administer or destroy keys and secrets stores? (was Z5, W6)

**Intent.** The app uses a key or reads a secret; a separate role administers it; nobody routine can
destroy it.
- **Safe:** the app's identity uses only what it needs (read one secret; encrypt and decrypt with one
  key); administrators are a separate role; deletion protection on for production keys; rotation on;
  no new human with standing access.
- **Ask:** list rights where only get is used.
- **Stop:** full control, all permissions or purge/schedule-deletion granted to a workload identity;
  "anyone" in a key policy without a narrowing condition; deletion protection off on a vault holding
  production keys; a key scheduled for deletion by the change with data still under it (irreversible:
  step 6.3).

| | Azure (Z5) | AWS (W6) | GitHub | Other cloud: how to find the equivalent |
|---|---|---|---|---|
| Look at | the vault **→ Access control (IAM)** or **Access policies**; **Networking**; **Properties** | **KMS → Customer managed keys →** the key **→ Key policy, Key rotation, Grants** | N/A | the key store's access model (role-based or policy), who may use vs administer keys, its deletion protection, and rotation |
| Platform safe | `Key Vault Secrets User` on the vault or on the one secret; purge protection on | key users (`Encrypt`, `Decrypt`, `GenerateDataKey`) = the app's role only; administrators (`kms:Put*`, `kms:ScheduleKeyDeletion`) separate; rotation on | — | — |
| Platform stop | `Key Vault Administrator`, `all`, or `purge` to a workload identity | `kms:*` to a workload role | — | — |

```sh
# Azure (Z5)
az keyvault show -n <vault> --query "{rbac:properties.enableRbacAuthorization, public:properties.publicNetworkAccess, defaultAction:properties.networkAcls.defaultAction, softDelete:properties.enableSoftDelete, purgeProtection:properties.enablePurgeProtection}"
az keyvault show -n <vault> --query "properties.accessPolicies[].{objectId:objectId, keys:permissions.keys, secrets:permissions.secrets}"   # access-policy model
az role assignment list --scope <vault id> --include-inherited -o table                                    # RBAC model
az keyvault key list --vault-name <vault> --query "[].{name:name, enabled:attributes.enabled}" -o table    # needs a data-plane read role
# AWS (W6)
aws kms describe-key --key-id <keyId> --query "KeyMetadata.{state:KeyState, manager:KeyManager, spec:KeySpec}"
aws kms get-key-policy --key-id <keyId> --policy-name default --output text
aws kms get-key-rotation-status --key-id <keyId>
aws kms list-grants --key-id <keyId>
```

## C7 · Will we still see what happens: logging, recording and audit streams? (was Z6, W7, H8)

**Intent.** Logs are the evidence for every later investigation and review; turning them down is
invisible until the day they are needed.
- **Safe:** after the change the same categories go to the same destination; retention at least the
  organisation's audit period; API recording and configuration recording on; secret scanning and push
  protection unchanged where licensed (the push ruleset `active` where they are not; `leak_gates` in
  the run shows each layer).
- **Ask:** a category removed "to reduce noise", or a destination changed.
- **Stop:** a log setting deleted, every category off, a trail stopped, its data events removed or the
  recorder stopped, to cut cost or "during the change" (gotcha G4); audit logs of a store or vault
  holding regulated data reduced (E6); secret scanning, push protection or audit-log streaming switched
  off by the change (SB-5, SB-6).

| | Azure (Z6) | AWS (W7) | GitHub (H8) | Other cloud: how to find the equivalent |
|---|---|---|---|---|
| Look at | the resource **→ Diagnostic settings** | **CloudTrail → Trails**; **Config → Settings** | the enterprise **→ Settings → Audit log → Log streaming** (Enterprise Cloud); the repository's security features | the provider's per-resource log export settings, its account-wide API audit trail and configuration recorder, and their retention |
| Platform safe | — | `IsLogging` true, multi-region, log file validation on; recorder `recording` true and `lastStatus` `SUCCESS`; event selectors unchanged | — | — |

```sh
# Azure (Z6)
az monitor diagnostic-settings list --resource <id> -o json
# AWS (W7)
aws cloudtrail describe-trails --query "trailList[].{name:Name, multiRegion:IsMultiRegionTrail, org:IsOrganizationTrail, validation:LogFileValidationEnabled}"
aws cloudtrail get-trail-status --name <trail> --query "{logging:IsLogging, latest:LatestDeliveryTime}"
aws cloudtrail get-event-selectors --trail-name <trail>
aws configservice describe-configuration-recorder-status --query "ConfigurationRecordersStatus[].{name:name, recording:recording, last:lastStatus}"
# GitHub (H8)
gh api repos/<owner>/<repo> --jq '.security_and_analysis'
```

## C8 · Does the platform's own posture or threat detection flag the resource? (was Z7, W11)

**Intent.** The cloud's security service already judges the resource; read what it says about what
the change touches.
- **Safe:** no new unhealthy High (or Critical) finding introduced by the change.
- **Ask:** an existing High finding the change touches: fixed by this change, or made worse?
- **Stop:** a new High finding on a boundary the change opens (public access, missing encryption, a
  management port open); an active threat finding (credential misuse, unusual API calls): that is
  incident response first (E7), not a review; the security service disabled in the account (SB-5).

| | Azure (Z7) | AWS (W11) | GitHub | Other cloud: how to find the equivalent |
|---|---|---|---|---|
| Look at | **Microsoft Defender for Cloud → Recommendations**, filtered to the resource; or the resource **→ Microsoft Defender for Cloud** | **Security Hub → Findings** (filter Resource ID); **GuardDuty → Findings** | code scanning and Dependabot alerts where licensed (C7) | the provider's posture-management recommendations and its threat-detection findings, filtered to the resource |

```sh
# Azure (Z7)
az graph query -q "securityresources | where type == 'microsoft.security/assessments' | where tolower(id) startswith tolower('<id>') | project name=tostring(properties.displayName), status=tostring(properties.status.code), severity=tostring(properties.metadata.severity)" -o table   # needs the resource-graph extension
# AWS (W11)
aws securityhub get-findings --filters '{"ResourceId":[{"Value":"<arn>","Comparison":"EQUALS"}],"RecordState":[{"Value":"ACTIVE","Comparison":"EQUALS"}]}' \
  --query "Findings[].{title:Title, severity:Severity.Label, status:Workflow.Status}" --output table
aws guardduty list-detectors
aws guardduty list-findings --detector-id <detector> --finding-criteria '{"Criterion":{"service.archived":{"Eq":["false"]}}}'
aws guardduty get-findings --detector-id <detector> --finding-ids <id> ... --query "Findings[].{type:Type, severity:Severity, resource:Resource.ResourceType}"
```

## C9 · Do the guardrail policies still hold, and is there a new exemption? (was Z8)

**Intent.** Organisation-wide policies are the controls that hold whatever an account admin grants;
an exemption is an exception like any other.
- **Safe:** compliant, or non-compliant only on assignments unrelated to the change.
- **Ask:** a new non-compliance the ticket does not explain.
- **Stop:** a new exemption with no expiry, or one the requester approved (gotchas G6, G7).

| | Azure (Z8) | AWS | GitHub | Other cloud: how to find the equivalent |
|---|---|---|---|---|
| Look at | **Policy → Compliance**, filtered to the resource group; the resource **→ Policies** | **Config → Rules** compliance for the resource; the organisation's service control policies on its account (read by the organisation's administrator) | organisation rulesets (C16) | the provider's policy engine compliance for the resource, its deny guardrails at the organisation level, and any exemption or exception object with its expiry |

```sh
# Azure (Z8)
az policy state list --resource <id> --filter "complianceState eq 'NonCompliant'" \
  --query "[].{policy:policyDefinitionName, assignment:policyAssignmentName}" -o table
az policy exemption list --scope <id> -o table                    # an exemption added for this change?
```

## C10 · What can the workload's own runtime identity reach? (was Z9; the execution-role lines of W8)

**Intent.** The identity a running app uses should reach only that app's own resources, and belong
to that app alone (KDEC-015: one identity per workload).
- **Safe:** roles only on what the app uses: pull from its registry, a data role on its own store,
  read on its own secrets.
- **Stop:** any role at subscription or account-wide scope or above (gotcha G3); one identity or
  execution role shared by several apps or unrelated functions.

| | Azure (Z9) | AWS | GitHub | Other cloud: how to find the equivalent |
|---|---|---|---|---|
| Look at | the app **→ Identity**; then C1 for that principal | the Lambda function's or task's execution role (C14 shows how to find it), then C1 on that role | N/A | the identity attached to the compute resource, then C1 on that identity |
| Platform safe | `AcrPull` on its registry; `Key Vault Secrets User` on its vault | — | — | — |

```sh
# Azure (Z9)
az webapp identity show -g <rg> -n <name>                            # or: az containerapp identity show, az functionapp identity show
az role assignment list --assignee <principalId> --all --include-inherited \
  --query "[].{role:roleDefinitionName, scope:scope}" -o table
```

## C11 · What API permissions, consents and credentials does an app identity hold? (was Z10)

**Intent.** Directory and API permissions are access too, and application (app-only) permissions are
not limited by any person's role.
- **Safe:** only the permissions the change names; delegated and user-consented where possible; one
  federated credential per environment (C2); no client secret where OIDC is the design.
- **Ask:** an application permission where a delegated one would do.
- **Stop:** directory-wide write, role-management write, app-role-assignment write or
  all-applications write, or mailbox write, granted to a workload; admin consent to a third-party
  multi-tenant app nobody cleared (E5); a new client secret on a deploy identity.

| | Azure (Z10) | AWS | GitHub | Other cloud: how to find the equivalent |
|---|---|---|---|---|
| Look at | **Entra ID → App registrations →** the app **→ API permissions, Certificates & secrets** (incl. **Federated credentials**), **Owners**; **Enterprise applications →** the app **→ Permissions** | N/A (an AWS workload's permissions are its role: C1, C2) | GitHub App permissions and installations (C20) | the directory's app registrations: requested vs granted permissions, consent type, credentials (secrets, certificates, federation) and owners |
| Platform stop | `Directory.ReadWrite.All`, `RoleManagement.ReadWrite.Directory`, `AppRoleAssignment.ReadWrite.All`, `Application.ReadWrite.All` or `Mail.ReadWrite` (application) | — | — | — |
| Needs | `Application.Read.All` (or a directory reader role) | — | — | — |

```sh
# Azure (Z10)
az ad app permission list --id <appId> -o json                                     # what it ASKS for
az rest --method get --url "https://graph.microsoft.com/v1.0/servicePrincipals/<spId>/appRoleAssignments"     # application permissions GRANTED
az rest --method get --url "https://graph.microsoft.com/v1.0/servicePrincipals/<spId>/oauth2PermissionGrants" # delegated grants; consentType AllPrincipals = admin consent
az ad app federated-credential list --id <appId> --query "[].{name:name, subject:subject, issuer:issuer}" -o table
az ad app credential list --id <appId> -o table                                     # client secrets and certificates
az ad app owner list --id <appId> --query "[].userPrincipalName" -o tsv
```

## C12 · Are sign-in protections unchanged: MFA, Conditional Access, SSO? (was Z11, H7)

**Intent.** An exclusion added "temporarily" is how an account ends up with no second factor; these
are identity-architecture decisions, not an app ticket's (E2, E3).
- **Safe:** no policy disabled or switched to report-only; no exclusion added; organisation 2FA and
  SSO enforcement unchanged.
- **Stop:** an exclusion added for a person or a service account with no end; MFA off for an
  administrative role; the organisation's 2FA requirement or SSO enforcement removed as part of an app
  change.

| | Azure (Z11) | AWS | GitHub (H7) | Other cloud: how to find the equivalent |
|---|---|---|---|---|
| Look at | **Entra ID → Protection → Conditional Access → Policies**; each policy's **Audit logs** (needs `Policy.Read.All`) | the identity source's sign-in policy (IAM Identity Center settings, or the external identity provider, usually Entra); root-user MFA in the credential report | the organisation **→ Settings → Authentication security** (2FA; SAML SSO on Enterprise Cloud) | the identity provider's sign-in policies, their exclusions and their change log |

```sh
# Azure (Z11)
az rest --method get --url "https://graph.microsoft.com/v1.0/identity/conditionalAccess/policies" \
  --query "value[].{name:displayName, state:state, excludeUsers:conditions.users.excludeUsers, excludeGroups:conditions.users.excludeGroups}"
# GitHub (H7)
gh api orgs/<org> --jq '{two_factor_requirement_enabled}'       # organisation owners
```

## C13 · Are secrets kept out of configuration and code paths? (was Z12, W9, H4)

**Intent.** A secret in plain configuration is readable by everyone who can read the configuration.
**Do not paste values into the ticket:** look at a value only to tell a reference from a literal.
- **Safe:** every credential-like setting is a reference to the platform's secret store, read by the
  app's own identity; cloud access from CI is OIDC (no client secret, no long-lived key); a credential
  that grants access to an environment lives in that environment's secrets, behind its reviewers
  (`docs/adoption/SETUP.md` section 2.1).
- **Ask:** a new organisation-wide CI secret visible to every repository.
- **Stop:** a literal password, token or connection string with a key in a setting or an environment
  variable (gotcha G5): the secret is compromised as far as its readers reach, and rotation is owed; a
  new long-lived cloud key or a personal access token added as a CI secret for a workload; a deploy
  credential moved from environment scope to repository or organisation scope.

| | Azure (Z12) | AWS (W9) | GitHub (H4) | Other cloud: how to find the equivalent |
|---|---|---|---|---|
| Look at | App Service **→ Configuration** (Key Vault references `@Microsoft.KeyVault(...)`); Container Apps secrets sourced from Key Vault | Lambda environment variable names; ECS task definitions (`secrets` from Secrets Manager or SSM Parameter Store) | repository, organisation and Dependabot secrets: names, scope, visibility | the compute service's environment variables or settings, and whether each credential is a reference to the provider's secret manager |
| Needs | listing App Service settings needs `Microsoft.Web/sites/config/list/action` (Reader does not have it) | — | `visibility` `all` on an organisation secret means every workflow in every repository can read it | — |

```sh
# Azure (Z12)
az webapp config appsettings list -g <rg> -n <name> --query "[].name" -o tsv       # names first
az containerapp show -g <rg> -n <name> --query "properties.template.containers[].env[].{name:name, secretRef:secretRef}"
az containerapp secret list -g <rg> -n <name> --query "[].name" -o tsv            # names only, without --show-values
# AWS (W9)
aws lambda get-function-configuration --function-name <fn> --query "keys(Environment.Variables)"     # names only
aws ecs describe-task-definition --task-definition <td> --query "taskDefinition.containerDefinitions[].{env:environment[].name, secrets:secrets[].name}"
# GitHub (H4)
gh api repos/<owner>/<repo>/actions/secrets --jq '.secrets[] | {name, updated_at}'
gh api orgs/<org>/actions/secrets --jq '.secrets[] | {name, visibility, updated_at}'
gh api orgs/<org>/actions/secrets/<name>/repositories --jq '.repositories[].full_name'    # who can read a "selected" org secret
gh api repos/<owner>/<repo>/dependabot/secrets --jq '.secrets[].name'
```

## C14 · Does the app or API check who is calling? (was Z13, W8, W10)

**Intent.** An endpoint without authentication is open to anyone who finds it, and they will.
- **Safe:** every new route requires the same authentication as the existing ones, or is named as
  deliberately public on the ticket; CORS lists named origins; an API key is not the only control;
  an invoke permission names the calling service and its source.
- **Ask:** anonymous access allowed on an app holding non-public data: where does the app check the
  caller itself?
- **Stop:** ingress switched to external for an internal service; CORS `*` with credentials allowed; a
  function URL or route with no authorization that the ticket does not name as public; a resource
  policy admitting anyone, or invoke rights to anyone with no source condition.

| | Azure (Z13) | AWS (W8, W10) | GitHub | Other cloud: how to find the equivalent |
|---|---|---|---|---|
| Look at | App Service or Container Apps **Authentication**; ingress and CORS | **Lambda →** the function **→ Configuration → Permissions** (execution role and resource-based policy), **Function URL**; **API Gateway →** the API **→ Resources →** each method **→ Method request** (Authorization), **Authorizers**; HTTP APIs **Routes → Authorization** | N/A | the platform's built-in authentication for the compute service, its gateway's per-route authorizers, CORS, and any invoke or resource policy |
| Platform detail | `unauthenticatedClientAction` `AllowAnonymous` is the ask | function URL `AuthType` `AWS_IAM` is safe, `NONE` a stop unless public (gotcha G8); routes with `authorizationType` / `AuthorizationType` `NONE`; the execution role is checked with C1 and must not be shared by unrelated functions | — | — |

```sh
# Azure (Z13)
az webapp auth show -g <rg> -n <name>
az containerapp auth show -g <rg> -n <name>
az containerapp show -g <rg> -n <name> --query "properties.configuration.ingress.{external:external, targetPort:targetPort, cors:corsPolicy}"
# AWS (W8)
aws lambda get-policy --function-name <fn> --query Policy --output text
aws lambda get-function-url-config --function-name <fn> --query "{auth:AuthType, cors:Cors}"
aws lambda get-function-configuration --function-name <fn> --query "{role:Role, kms:KMSKeyArn, vpc:VpcConfig.SubnetIds}"
# AWS (W10)
aws apigateway get-authorizers --rest-api-id <apiId>
aws apigateway get-resources --rest-api-id <apiId> --embed methods \
  --query "items[].{path:path, methods:resourceMethods}"                  # look for authorizationType NONE
aws apigateway get-rest-api --rest-api-id <apiId> --query "{policy:policy, endpoint:endpointConfiguration.types}"
aws apigatewayv2 get-routes --api-id <apiId> --query "Items[].{route:RouteKey, auth:AuthorizationType}" --output table   # HTTP APIs
aws apigatewayv2 get-authorizers --api-id <apiId>
```

## C15 · Does every DNS name point only at something we own? (was Z14, W12)

**Intent.** A name left pointing at something deleted can be claimed by someone else (subdomain
takeover).
- **Safe:** each new record points at a resource the change creates or the team owns.
- **Stop:** a CNAME or alias to a name that does not exist or that others could claim (a deleted app,
  a bucket, a distribution, an environment name); a record in a shared zone changed by the app team
  (E1).

| | Azure (Z14) | AWS (W12) | GitHub | Other cloud: how to find the equivalent |
|---|---|---|---|---|
| Look at | public and private DNS zones' record sets | **Route 53 →** the hosted zone's records (including alias targets) | Pages custom domains, if used | the provider's DNS zones, and for each CNAME or alias whether its target still exists and is ours |
| Platform stop | a CNAME to a resource name that is deleted or deletable by others | a CNAME or alias to an S3 bucket, CloudFront distribution or Elastic Beanstalk name that does not exist or that another account could claim | — | — |

```sh
# Azure (Z14)
az network dns record-set list -g <rg> -z <zone> -o table
az network private-dns record-set list -g <rg> -z <zone> -o table
# AWS (W12)
aws route53 list-resource-record-sets --hosted-zone-id <zone> \
  --query "ResourceRecordSets[].{name:Name, type:Type, target:ResourceRecords[].Value, alias:AliasTarget.DNSName}" --output table
```

---

The checks below are about the **source-control and CI platform**, where the kit's own gates live: a
change to these settings is a change to the gate (step 5.1). GitHub is the platform the kit runs on;
for another platform, the right-hand column says what to look for. Several answers are admin-only
(classic branch protection, push protection on a private repository, the audit log): a non-admin
token gets 403 or 404, which is `UNKNOWN`, never "off". Ask the admin role for the answer instead of
taking admin to review.

## C16 · Is the default branch's gate intact? (was H1)

- **Safe:** the default branch requires a pull request and the `Security gate` check (for example
  `security / Security gate`); `enforcement` `active`; bypass actors limited to a named admin role;
  the push ruleset refusing secret-file paths is `active` (`docs/adoption/LEAK_GATES.md`).
- **Ask:** a new bypass actor; a required review count lowered.
- **Stop:** a ruleset moved to `evaluate` or `disabled`; the `Security gate` requirement removed or
  renamed so nothing reports it (a required check naming no job blocks forever; one renamed away
  silently stops being required); a bypass for the requester. In the same change as code, this is the
  change editing its own gate (step 5.1).

| | Azure | AWS | GitHub (H1) | Other platform: how to find the equivalent |
|---|---|---|---|---|
| Look at | N/A | N/A | the repository **→ Settings → Rules → Rulesets**; **Branches** for classic protection | the branch protection or merge policy on the default branch: required checks, required reviews, who may bypass |

```sh
gh api repos/<owner>/<repo>/rulesets --jq '.[] | {id, name, target, enforcement}'
gh api repos/<owner>/<repo>/rulesets/<id> --jq '{enforcement, bypass_actors, conditions, rules: [.rules[].type]}'
gh api repos/<owner>/<repo>/rules/branches/<branch> --jq '.[] | {type, parameters}'     # the rules that actually apply
gh api orgs/<org>/rulesets --jq '.[] | {id, name, target, enforcement}'
gh api repos/<owner>/<repo>/branches/<branch>/protection                                # classic protection; admin only
```

## C17 · Do deployment environments still require an independent approver? (was H2)

- **Safe:** at uat and prod, required reviewers from the approver list, `prevent_self_review` true,
  deployment branches limited to the default branch; `KIT_ENVIRONMENT_TIER` matches reality;
  `KIT_ZONE_READINESS` issued by the landing zone or by AppSec as a recorded attestation (S7).
- **Ask:** `can_admins_bypass` true (an admin bypass leaves no approval: `RELEASE_APPROVAL_ABSENT`).
- **Stop:** reviewers removed, self-review allowed, or the branch policy opened (`404` on the policies
  call means no custom policy: every branch may deploy); `KIT_ZONE_READINESS` set to `READY` by the app
  or deploy team (a test fixture only); a production environment re-tiered below uat (S6).

| | Azure | AWS | GitHub (H2) | Other platform: how to find the equivalent |
|---|---|---|---|---|
| Look at | N/A (the cloud side of the deploy identity is C1, C2) | N/A (same) | **Settings → Environments →** the environment | the deployment stage's approval gate: who approves, whether the author can, which branches may deploy |

```sh
gh api repos/<owner>/<repo>/environments/<env> \
  --jq '{protection_rules, deployment_branch_policy, can_admins_bypass}'
gh api repos/<owner>/<repo>/environments/<env>/deployment-branch-policies --jq '.branch_policies[] | {name, type}'
gh api repos/<owner>/<repo>/environments/<env>/variables --jq '.variables[] | {name, value}'   # KIT_ENVIRONMENT_TIER, KIT_ZONE_READINESS, ...
gh api repos/<owner>/<repo>/environments/<env>/secrets --jq '.secrets[] | {name, updated_at}' # names only
```

## C18 · Are the CI token defaults and allowed actions unchanged? (was H3)

- **Safe:** `default_workflow_permissions` `read`; `can_approve_pull_request_reviews` false; allowed
  actions limited (selected, or the organisation's list), and the kit's own pins are full SHAs.
- **Stop:** the default token switched to `write`; Actions allowed to approve pull requests (a
  workflow could then approve its own change: separation of duties). In the workflow diff of this
  change, also stop on: `permissions: write-all` or a new `contents: write` / `id-token: write` at
  workflow level (rule R3); `pull_request_target` that checks out the pull request head; a new
  `secrets: inherit` (R8); a `uses:` on a branch or tag outside `trusted_orgs`; a kit pin moved with no
  reason (S9).

| | Azure | AWS | GitHub (H3) | Other platform: how to find the equivalent |
|---|---|---|---|---|
| Look at | N/A | N/A | **Settings → Actions → General** | the CI system's default job-token rights, whether a job may approve or merge, and which external steps or images it may run |

```sh
gh api repos/<owner>/<repo>/actions/permissions                       # enabled, allowed_actions
gh api repos/<owner>/<repo>/actions/permissions/selected-actions      # when allowed_actions is "selected"
gh api repos/<owner>/<repo>/actions/permissions/workflow              # default_workflow_permissions, can_approve_pull_request_reviews
gh api orgs/<org>/actions/permissions
```

## C19 · Can anything push around review? (was H5)

- **Safe:** no deploy keys, or read-only keys with a named owner.
- **Stop:** a new key with `read_only` false (it can push, around pull requests unless a ruleset stops
  it) that the ticket does not name.

| | Azure | AWS | GitHub (H5) | Other platform: how to find the equivalent |
|---|---|---|---|---|
| Look at | N/A | N/A | the repository's deploy keys | per-repository keys, tokens or service accounts that can push |

```sh
gh api repos/<owner>/<repo>/keys --jq '.[] | {id, title, read_only, created_at}'
```

## C20 · Which apps, webhooks and outside parties can act on the code? (was H6)

- **Safe:** each app's permissions match its stated job; `repository_selection` `selected`.
- **Ask:** a new app with `contents: write`, `administration`, `workflows` or `secrets` permission.
- **Stop:** a third party with write access nobody cleared (E5); an AI agent's app that can approve,
  merge or change environments (E9; `ai_review` is advisory only); a webhook to an external URL that
  receives repository content.

| | Azure | AWS | GitHub (H6) | Other platform: how to find the equivalent |
|---|---|---|---|---|
| Look at | third-party app consent is C11 | a third-party account in a trust policy is C2 | organisation app installations; repository webhooks; admin collaborators | the platform's installed integrations and their permission scopes, outbound webhooks, and who holds admin |

```sh
gh api orgs/<org>/installations --jq '.installations[] | {app_slug, repository_selection, permissions}'   # organisation owners
gh api repos/<owner>/<repo>/hooks --jq '.[] | {id, active, url: .config.url, events}'                      # repository admin
gh api repos/<owner>/<repo>/collaborators --jq '.[] | select(.permissions.admin) | .login'
```

---

## Aliases: every old id, and where it now lives

| Old id | Now | Old id | Now | Old id | Now |
|---|---|---|---|---|---|
| Z1 | C1 | W1 | C1 | H1 | C16 |
| Z2 | C3 | W2 | C2 | H2 | C17 |
| Z3 | C4 | W3 | C3 | H3 | C18 |
| Z4 | C4 | W4 | C4 | H4 | C13 |
| Z5 | C6 | W5 | C5 | H5 | C19 |
| Z6 | C7 | W6 | C6 | H6 | C20 |
| Z7 | C8 | W7 | C7 | H7 | C12 |
| Z8 | C9 | W8 | C14 (execution role: C10) | H8 | C7 |
| Z9 | C10 | W9 | C13 | | |
| Z10 | C11 (federated credentials: C2) | W10 | C14 | | |
| Z11 | C12 | W11 | C8 | | |
| Z12 | C13 | W12 | C15 | | |
| Z13 | C14 | | | | |
| Z14 | C15 | | | | |

A record or ticket that cites an old id stays valid: the old id names the platform, the new one the
intent.

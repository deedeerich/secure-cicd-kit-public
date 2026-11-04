# Cloud checks — Azure (read-only)

```
Truth State:  Authored, not field-tested (2026-11-03). Commands follow the Azure CLI and Microsoft
              Graph v1.0 as documented; run them on a non-production subscription first and correct
              this sheet where an output differs.
Use with:     CAB-CHANGE-SAFETY-STEPS.md step 4. Run only the checks for the boundary rows that are yes.
Read-only:    every command below is a list, show or GET. None creates, edits or deletes. A reader
              role is enough for most (Reader on the scope; for Graph, the read permission named).
              Where Reader is not enough, the check says so: ask the platform role to run it and
              send you the output, never take a write role to review.
Placeholders: <sub> subscription id, <rg> resource group, <name> resource name, <id> full ARM
              resource id, <principalId> the identity's object id, <appId> an app registration's
              client id, <spId> its service principal's object id.
```

**Before and after.** For each check, read the state before the change (the current production
state, or the IaC plan's "before") and after it (the lower environment where it already ran, or the
plan's "after"). Write both on the ticket. Who changed what, and when, for any resource:

```sh
az monitor activity-log list --resource-id <id> --offset 7d \
  --query "[].{when:eventTimestamp, op:operationName.localizedValue, who:caller, status:status.value}" -o table
```

Portal: the resource → **Activity log**.

---

## Z1 · Role assignments — a diff, not a list

```sh
az role assignment list --scope <id> --include-inherited -o table          # who holds what ON this resource
az role assignment list --assignee <principalId> --all --include-inherited \
  --query "[].{role:roleDefinitionName, scope:scope}" -o table             # what this identity holds EVERYWHERE
az role definition list --name "<role name>" --query "[].permissions" -o json   # a custom role's actions
```

Portal: the resource (or resource group, or subscription) → **Access control (IAM)** → **Role
assignments**; **Check access** for one identity.

- **Safe:** the assignments added are exactly the ones the change names, at the narrowest scope that
  works (the one app, not its resource group; the resource group, not the subscription); the deploy
  identity holds `Website Contributor` or `Container Apps Contributor` on its app and `Reader` on its
  group; the build identity `AcrPush` only.
- **Ask:** a role at resource-group scope where resource scope would do; a custom role you have not
  read.
- **Stop:** `Owner`, `User Access Administrator`, `Role Based Access Control Administrator` or
  `Contributor` at subscription or management-group scope for a workload identity; a custom role with
  `"*"` in `actions`, or `Microsoft.Authorization/*/write`; an assignment the change does not name (E3).

## Z2 · NSG and firewall rules

```sh
az network nsg rule list -g <rg> --nsg-name <nsg> --include-default -o table
az network nic list-effective-nsg -g <rg> -n <nic>                       # what actually applies to one NIC
az network firewall policy rule-collection-group list -g <rg> --policy-name <policy> -o json   # needs the azure-firewall extension
```

Portal: **Network security groups** → the NSG → **Inbound security rules**; **Firewall Policies** →
the policy → **Rule collections**.

- **Safe:** the new rule names a specific source range and specific ports; priority does not shadow a
  deny the platform relies on.
- **Ask:** a source of `VirtualNetwork` or a large private range where one subnet would do.
- **Stop:** inbound from `*`, `Internet` or `0.0.0.0/0` to a management port (22, 3389, 5985/5986) or a
  data port (1433, 3306, 5432, 6379, 9200, 27017); a rule described as temporary with no removal step.
  Shared entries belong to the platform (E1).

## Z3 · Private endpoints

```sh
az network private-endpoint list -g <rg> -o table
az network private-endpoint-connection list --id <id> -o table          # on the target resource: Approved / Pending / Rejected
```

Portal: the resource → **Networking** → **Private endpoint connections**.

- **Safe:** the store or service the change uses is reached through an approved private endpoint, and
  its DNS resolves to the private address from the caller's network.
- **Ask:** a private endpoint connection from another subscription or tenant (who approved it?).
- **Stop:** the change removes a private endpoint and turns public access on in its place.

## Z4 · Public network access, TLS and store settings

```sh
az resource show --ids <id> --query "{publicNetworkAccess:properties.publicNetworkAccess, location:location}"
az storage account show -g <rg> -n <name> --query "{public:publicNetworkAccess, defaultAction:networkRuleSet.defaultAction, blobPublic:allowBlobPublicAccess, sharedKey:allowSharedKeyAccess, minTls:minimumTlsVersion, httpsOnly:enableHttpsTrafficOnly}"
az webapp show -g <rg> -n <name> --query "{httpsOnly:httpsOnly, public:publicNetworkAccess}"
az webapp config show -g <rg> -n <name> --query "{minTls:minTlsVersion, ftps:ftpsState, remoteDebugging:remoteDebuggingEnabled}"
az webapp config access-restriction show -g <rg> -n <name>
az containerapp show -g <rg> -n <name> --query "properties.configuration.ingress.{external:external, insecure:allowInsecure, ipRules:ipSecurityRestrictions}"
```

Portal: the resource → **Networking**; storage → **Configuration**; App Service → **Configuration**
→ **General settings**.

- **Safe:** `publicNetworkAccess` `Disabled` where a private endpoint exists; TLS 1.2 or higher; HTTPS
  only; FTP off (or FTPS only); remote debugging off; storage `allowBlobPublicAccess` false and shared
  key off where Entra auth is used; the region is one the data may sit in (DB-6).
- **Ask:** public access on with network rules (`defaultAction` `Deny` plus named ranges): who reads
  it from where?
- **Stop:** public access newly `Enabled` on a data store with `defaultAction` `Allow`; anonymous blob
  access on for non-public data; `allowInsecure` true on external ingress. The kit's promotion posture
  check reads the App Service and Container Apps settings back (`POSTURE_PASSED`); a store's are yours
  to read.

## Z5 · Key Vault access

```sh
az keyvault show -n <vault> --query "{rbac:properties.enableRbacAuthorization, public:properties.publicNetworkAccess, defaultAction:properties.networkAcls.defaultAction, softDelete:properties.enableSoftDelete, purgeProtection:properties.enablePurgeProtection}"
az keyvault show -n <vault> --query "properties.accessPolicies[].{objectId:objectId, keys:permissions.keys, secrets:permissions.secrets}"   # access-policy model
az role assignment list --scope <vault id> --include-inherited -o table                                    # RBAC model
az keyvault key list --vault-name <vault> --query "[].{name:name, enabled:attributes.enabled}" -o table    # needs a data-plane read role
```

Portal: the vault → **Access control (IAM)** or **Access policies**; **Networking**; **Properties**.

- **Safe:** the app's identity reads only the secrets it needs (`Key Vault Secrets User` on the vault
  or on the one secret); purge protection on; no new human with standing access.
- **Ask:** `get` and `list` on secrets where only `get` is used.
- **Stop:** `Key Vault Administrator`, `all` permissions, or `purge` granted to a workload identity;
  purge protection off on a vault holding production keys.

## Z6 · Diagnostic settings and retention

```sh
az monitor diagnostic-settings list --resource <id> -o json
```

Portal: the resource → **Diagnostic settings**.

- **Safe:** after the change the same log categories go to the same destination as before; retention
  at least the organisation's audit period.
- **Ask:** a category removed "to reduce noise", or a destination changed.
- **Stop:** a diagnostic setting deleted or every category off to cut cost (gotcha G4); audit logs of a
  Key Vault or store holding regulated data reduced (E6).

## Z7 · Defender for Cloud recommendations for the resource

```sh
az graph query -q "securityresources | where type == 'microsoft.security/assessments' | where tolower(id) startswith tolower('<id>') | project name=tostring(properties.displayName), status=tostring(properties.status.code), severity=tostring(properties.metadata.severity)" -o table   # needs the resource-graph extension
```

Portal: **Microsoft Defender for Cloud** → **Recommendations**, filtered to the resource; or the
resource → **Microsoft Defender for Cloud**.

- **Safe:** no `Unhealthy` High recommendation introduced by the change.
- **Ask:** an existing `Unhealthy` recommendation the change touches.
- **Stop:** a new High recommendation on a boundary the change opens (public access, missing
  encryption, a management port open).

## Z8 · Azure Policy compliance

```sh
az policy state list --resource <id> --filter "complianceState eq 'NonCompliant'" \
  --query "[].{policy:policyDefinitionName, assignment:policyAssignmentName}" -o table
az policy exemption list --scope <id> -o table                    # an exemption added for this change?
```

Portal: **Policy** → **Compliance**, filtered to the resource group; the resource → **Policies**.

- **Safe:** compliant, or non-compliant only on assignments unrelated to the change.
- **Ask:** a new non-compliance the ticket does not explain.
- **Stop:** a new policy exemption with no expiry, or one the requester approved (gotchas G6, G7).

## Z9 · Managed identity scope

```sh
az webapp identity show -g <rg> -n <name>                            # or: az containerapp identity show, az functionapp identity show
az role assignment list --assignee <principalId> --all --include-inherited \
  --query "[].{role:roleDefinitionName, scope:scope}" -o table
```

- **Safe:** the identity holds roles only on the resources the app uses (`AcrPull` on its registry, a
  data role on its own store, `Key Vault Secrets User` on its vault).
- **Stop:** any role at `/subscriptions/<sub>` or above (gotcha G3); one identity shared by several
  apps (KDEC-015: one identity per workload).

## Z10 · Entra app permissions, consent and federated credentials (Microsoft Graph)

```sh
az ad app permission list --id <appId> -o json                                     # what it ASKS for
az rest --method get --url "https://graph.microsoft.com/v1.0/servicePrincipals/<spId>/appRoleAssignments"     # application permissions GRANTED
az rest --method get --url "https://graph.microsoft.com/v1.0/servicePrincipals/<spId>/oauth2PermissionGrants" # delegated grants; consentType AllPrincipals = admin consent
az ad app federated-credential list --id <appId> --query "[].{name:name, subject:subject, issuer:issuer}" -o table
az ad app credential list --id <appId> -o table                                     # client secrets and certificates
az ad app owner list --id <appId> --query "[].userPrincipalName" -o tsv
```

Reading service principals needs `Application.Read.All` (or a directory reader role). Portal:
**Entra ID** → **App registrations** → the app → **API permissions**, **Certificates & secrets**
(including **Federated credentials**), **Owners**; **Enterprise applications** → the app →
**Permissions**.

- **Safe:** only the permissions the change names; delegated, user-consented where possible; one
  federated credential per environment with subject `repo:<owner>/<repo>:environment:<env>` (or the
  id-qualified form); no client secret where OIDC is the design.
- **Ask:** an application permission (app-only) where a delegated one would do.
- **Stop:** `Directory.ReadWrite.All`, `RoleManagement.ReadWrite.Directory`, `AppRoleAssignment.ReadWrite.All`,
  `Application.ReadWrite.All` or `Mail.ReadWrite` (application) granted to a workload; admin consent to
  a third-party multi-tenant app nobody cleared (E5); a federated subject with a wildcard or a branch
  form for an environment job; a new client secret on a deploy identity.

## Z11 · Conditional Access and MFA (Microsoft Graph)

```sh
az rest --method get --url "https://graph.microsoft.com/v1.0/identity/conditionalAccess/policies" \
  --query "value[].{name:displayName, state:state, excludeUsers:conditions.users.excludeUsers, excludeGroups:conditions.users.excludeGroups}"
```

Needs `Policy.Read.All`. Portal: **Entra ID** → **Protection** → **Conditional Access** → **Policies**;
each policy's **Audit logs**.

- **Safe:** no policy disabled or switched to report-only; no exclusion added.
- **Stop:** an exclusion added for a person or a service account "temporarily", with no end; MFA off for
  an administrative role. Identity architecture owns this (E3).

## Z12 · Secrets in application settings

```sh
az webapp config appsettings list -g <rg> -n <name> --query "[].name" -o tsv       # names first
az containerapp show -g <rg> -n <name> --query "properties.template.containers[].env[].{name:name, secretRef:secretRef}"
az containerapp secret list -g <rg> -n <name> --query "[].name" -o tsv            # names only, without --show-values
```

Listing App Service settings needs `Microsoft.Web/sites/config/list/action` (Reader does not have
it). **Do not paste values into the ticket.** Look at each value only to see whether it is a Key Vault
reference (`@Microsoft.KeyVault(...)`) or a literal.

- **Safe:** every credential-like setting is a Key Vault reference, or a Container Apps secret sourced
  from Key Vault, and the app's identity reads it.
- **Stop:** a literal password, connection string with a key, or token in an app setting or a plain
  `env` value (gotcha G5). The secret is then compromised as far as its readers reach: rotation is owed.

## Z13 · Authentication and ingress of the app itself

```sh
az webapp auth show -g <rg> -n <name>
az containerapp auth show -g <rg> -n <name>
az containerapp show -g <rg> -n <name> --query "properties.configuration.ingress.{external:external, targetPort:targetPort, cors:corsPolicy}"
```

- **Safe:** the change's new routes require the same authentication as the existing ones; CORS lists
  named origins.
- **Ask:** `unauthenticatedClientAction` `AllowAnonymous` on an app that holds non-public data: where
  does the app check the caller itself?
- **Stop:** ingress switched to external for an internal service; CORS `*` with credentials allowed.

## Z14 · DNS records

```sh
az network dns record-set list -g <rg> -z <zone> -o table
az network private-dns record-set list -g <rg> -z <zone> -o table
```

- **Safe:** each new record points at a resource in this subscription that the change creates or owns.
- **Stop:** a CNAME to a resource name that is deleted or deletable by others (dangling: subdomain
  takeover); a record in a shared zone changed by the app team (E1).

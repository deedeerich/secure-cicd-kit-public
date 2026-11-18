# Non-human identities in Microsoft Entra and Azure: what works and what doesn't

*Written 2026-10-23 and grounded in Microsoft Learn (sources at the end). Entra features change, so re-check a
row before relying on it for a control.*

## The four things people mix up

| Term | What it actually is |
|---|---|
| **App registration** (application object) | The global *definition* of an app: its name, credentials (secrets, certificates, federated credentials) and the permissions it asks for. It lives in its home tenant. |
| **Service principal** ("Enterprise application") | The *instance* of an app in one tenant. Roles, consent and sign-in logs attach to this. One app registration can have service principals in many tenants. |
| **Managed identity** | A service principal that Azure creates and rotates for you. It has **no application object** and no secret you can see. **System-assigned:** tied to one resource's life. **User-assigned:** standalone and reusable. |
| **Workload identity** | The umbrella term for all of the above, i.e. any non-human identity. "Workload ID Premium" is the licence that unlocks extra controls for them. |

## What applies to each

✅ = works. ❌ = not supported. ◐ = partly, see the note.

| Control | User (human) | App reg / service principal | Managed identity |
|---|---|---|---|
| **Azure RBAC role assignments** | ✅ | ✅ | ✅ |
| **Entra directory roles** (e.g. Application Administrator) | ✅ | ✅ | ✅ |
| **PIM *eligible* (just-in-time) assignment** | ✅ | ❌ It can't perform activation. | ❌ |
| **PIM *active* assignment with an end date** | ✅ | ✅ | ✅ |
| **MFA** | ✅ | ❌ (not applicable) | ❌ |
| **Conditional Access** | ✅ | ◐ Single-tenant SPs only, **with Workload ID Premium**. Blocks by location or risk only (no device or MFA conditions). The SP must be **assigned directly**: a CA policy aimed at a group that contains the SP is **not enforced** for it. | ❌ Not covered at all. |
| **Continuous access evaluation** | ✅ | ◐ Single-tenant SPs, Microsoft Graph only. | ❌ |
| **ID Protection (risk detection)** | ✅ | ◐ Single- and multi-tenant SPs, with Premium. | ❌ |
| **Access reviews of privileged role assignments** | ✅ | ◐ SPs in privileged roles, with Premium. | ◐ Yes, and licensed per managed identity. |
| **Group membership** | ✅ | ✅ Can be a member of a security group, and RBAC through the group works. **But CA through a group does not.** | ✅ Same as SPs. |
| **Dynamic groups** | ✅ | ❌ | ❌ |
| **Administrative unit *member*** | ✅ | ❌ (members are users, groups and devices) | ❌ |
| **Administrative unit-scoped *admin*** | ✅ | ✅ Can hold a role scoped to an AU. | ✅ |
| **Secrets / certificates** | n/a | ✅ (avoid secrets) | ❌ Azure manages them; nothing to leak. |
| **Federated identity credentials** (e.g. GitHub OIDC) | n/a | ✅ Up to 20 per app. | ✅ **User-assigned only**, up to 20. ❌ Not on system-assigned. |
| **Owners** | n/a | ✅ App reg and SP have owners. Owners can add credentials. | ❌ No owners; managed through the Azure resource. |
| **Delegated (on behalf of a user) permissions** | n/a | ✅ | ❌ App permissions only. |
| **Usable outside Azure** | ✅ | ✅ | ◐ Only from the Azure resource, or by acting as the trusted credential on an app via a federated credential. |
| **Sign-in logs** | User sign-ins | "Service principal sign-ins" tab | "Managed identity sign-ins" tab |

## What this means in practice

1. **There is no just-in-time access for non-humans.** Any role a service principal or managed identity holds is
   standing access. The controls you have instead:
   - **Least privilege and narrow scope:** a resource group, not a subscription; owned apps, not the directory.
   - **Federated credentials instead of secrets,** so there is nothing to steal.
   - **Time-bound active assignments** where the need is temporary.
   - **Alerting** on its sign-ins and on credentials added to apps.
   - **Access reviews** (Premium).
2. **Don't rely on group-targeted Conditional Access for service principals.** Target the workload identity
   directly, and buy Workload ID Premium if you want that control at all. A 90-day trial exists.
3. **Managed identities can't be put behind Conditional Access.** Their protection is that the credential never
   leaves Azure. So who can *attach* a user-assigned identity to a resource (the Managed Identity Operator role)
   is the thing to guard.
4. **Owners of an app registration can add credentials to it.** Treat ownership like a privileged role, and audit
   it.
5. **Application Administrator / Cloud Application Administrator** can add credentials to *any* app, so they can
   become any app's permissions. Never give these tenant-wide to automation. Prefer `Application.ReadWrite.OwnedBy`,
   ownership of specific apps, or a role scoped to specific app objects.

## For this kit

- **GitHub → Azure:** use OIDC federated credentials on a **user-assigned managed identity** or app registration,
  **one per environment**. The `subject` names the repo and environment
  (`repo:<org>/<repo>:environment:prod`), so a dev run can never get the prod identity.
  - It has no secret, no PIM and no Conditional Access (for a managed identity).
  - Its safety comes from the exact `subject`, the GitHub environment's required reviewers and branch rule, and
    narrowly scoped RBAC.
- **The 20-credential limit:** at most 20 federated credentials per identity. A repo with many environments needs
  more than one identity, which is the better design anyway.
- **The `subject` must match exactly:** a mismatch fails silently at token exchange, not at setup.

## Sources (Microsoft Learn)

- [Eligible and time-bound role assignments in Azure RBAC](https://learn.microsoft.com/azure/role-based-access-control/pim-integration#pim-functionality): "you can't create eligible role assignments for applications, service principals, or managed identities because they can't perform the activation steps."
- [Conditional Access for workload identities](https://learn.microsoft.com/entra/identity/conditional-access/workload-identity): single-tenant SPs only; managed identities aren't covered; group-assigned policy isn't enforced for SPs; Premium licence required.
- [Continuous access evaluation for workload identities](https://learn.microsoft.com/entra/identity/conditional-access/concept-continuous-access-evaluation-workload)
- [Microsoft Entra Workload ID FAQ (licensing, access reviews)](https://learn.microsoft.com/entra/workload-id/workload-identities-faqs)
- [Securing workload identities with ID Protection](https://learn.microsoft.com/entra/id-protection/concept-workload-identity-risk)
- [Federated identity credential considerations (20 per app/UAMI, exact subject)](https://learn.microsoft.com/entra/workload-id/workload-identity-federation-considerations)
- [Federated credential on a user-assigned managed identity (not system-assigned)](https://learn.microsoft.com/entra/workload-id/workload-identity-federation-create-trust-user-assigned-managed-identity)
- [Managed identities glossary (no application object)](https://learn.microsoft.com/entra/identity/managed-identities-azure-resources/managed-identities-glossary)
- [Administrative units in Microsoft Entra ID](https://learn.microsoft.com/entra/identity/role-based-access-control/administrative-units)
- [Dynamic membership rules (service-principal-type identities not supported)](https://learn.microsoft.com/entra/identity/users/groups-dynamic-membership#overview)

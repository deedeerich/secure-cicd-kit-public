# SYNTHETIC IaC FIXTURE: TERRAFORM-HEAVY, INTENTIONALLY MISCONFIGURED

The **IaC-heavy cost class** for the cost-redesign acceptance test
(`docs/operations/COST_MEASUREMENT.md`). A repository that is almost all Terraform: one root, six
modules, no application code, no dependency manifests, no secrets. It exists so `iac-scan`
(Checkov + Trivy config) dominates the run, which no other fixture in this kit does.

Every misconfiguration is deliberate and listed in `EXPECTED_SIGNALS.json`. Nothing here is ever
applied: there is no provider configuration, no backend and no credential (passwords are
`sensitive` variables with no value). Do not "fix" it: a fixed resource silently stops proving that
the IaC path still detects.

| path | planted |
|---|---|
| `modules/storage/main.tf` | public blob access, TLS 1.0, HTTP allowed, an anonymous-read container |
| `modules/network/main.tf` | an NSG rule open to any source on any port; SSH open to the internet |
| `modules/compute/main.tf` | password authentication on a Linux VM, no encryption at host |
| `modules/database/main.tf` | SQL server public network access, TLS 1.0, a firewall rule for the whole internet |
| `modules/kubernetes/main.tf` | AKS with RBAC off and a public API server |
| `modules/keyvault/main.tf` | Key Vault without purge protection, public network access |
| `envs/prod/main.tf` | the root that wires the six modules (no finding of its own is expected) |

Dispatched on the public mirror as `consumer-path-negative.yml` with `scope: iac` (see
`docs/operations/COST_MEASUREMENT.md` for the patch that adds that scope). At crawl, the kit
default, IaC findings route `PROCEED_WITH_ADVISORY`; this class is measured for cost and for the
per-scanner invariants, not for a block.

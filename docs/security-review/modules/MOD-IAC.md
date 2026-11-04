# MOD-IAC — infrastructure code in the repository

```
Truth State: Authored, not field-tested (2026-11-03). One page. Tick only from evidence you saw;
             otherwise label the line Stated or Not established (../SIGN-OFF.md).
```

- [ ] `iac_mode` is `auto` or `required`, never `disabled` (a weakening); discovery found the IaC
      (Terraform, Bicep, ARM, Kubernetes, Helm, Dockerfile).
- [ ] `iac-scan` ran Checkov and Trivy IaC, neither `COLLECTION_FAILED`. A Terraform root above the
      measured read range is a proven `VERSION_GAP`, refused at uat/prod without a named acceptance.
- [ ] Who applies this IaC, and with which identity. The kit applies no infrastructure (KDEC-009: the
      landing zone vends, the kit releases); IaC that creates platform objects is the platform's (E1).
- [ ] IaC that manages a kit-deployed target ignores only the kit-owned fields, never
      `ignore_changes = all` (`docs/architecture/LZ_KIT_SEAM_CONTRACT.md`).
- [ ] No state file is committed (the baseline `.gitignore` and the push ruleset cover `*.tfstate`).
- [ ] New network exposure, a new identity or a new role in the IaC is a boundary change: a full
      review (`../CAB-CHANGE-SAFETY-STEPS.md` step 2, rows SB, AB, XB), with the plan's before and
      after read through the cloud checks (`../CLOUD-CHECKS-AZURE.md`, `../CLOUD-CHECKS-AWS.md`), and
      E3 for identity.

# Release 4 consumer fixture

What a consumer repository adds for Release 4 that the consumer path checks
(`scripts/consumer_surface_check.py`, row R3): the AppSec readiness attestation at
`.kit/zone-readiness.json` (KDEC-036 G1), for uat and prod, with one listed exception. A deploy
accepts it only when its latest change arrived through a pull request an AppSec approver approved;
that half needs a hosted run and is not exercised here. Holds no manifest and no seeded finding.

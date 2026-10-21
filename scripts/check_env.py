#!/usr/bin/env python3
"""Say which .env field is missing, by name, before a request fails with a bare 401.

WHY THIS EXISTS
    `.env.example` prefilled the host and project and left the credentials blank. Two of the
    three blanks read as secrets and were filled in. The third was JIRA_EMAIL, which reads as
    configuration -- and Jira Cloud basic auth is the PAIR email:token, so the omission
    surfaced as `Client must be authenticated to access this resource. HTTP 401`.

    That message names nothing. It is indistinguishable from a wrong token, a revoked token, a
    disabled account and a typo'd host. The operator was then told the field was empty, which
    the template is what caused.

    A required field that is blank is a KNOWN ABSENCE. Reporting it as an authentication
    failure is the same collapse this kit refuses everywhere else: a thing nobody supplied
    reported as a thing that was rejected.

ONE BACKEND, ITS VALUES ONLY (C-1, OD-5)
    This used to require Jira AND Azure DevOps credentials together. Exactly one backend is
    authoritative per (repo, environment) cell -- TICKETING_CONTRACT.md 4.6 calls two at once a
    policy defect -- so demanding both asked an operator to hold a credential the run must never
    use. Now `TICKET_BACKEND` selects the backend and only that backend's values are required
    (TICKETING_BACKENDS.md 3.1 / 4.1). An operator proving both backends checks each in turn:
    `python scripts/check_env.py --backend azdo`.

    Values with a documented default (issue types, transition and state names, the umbrella
    label) are not required here; the reconciler validates them at run start.

EXIT
    0  every required field for the selected backend is present
    1  the backend is unselected or unknown, or a required field is missing
    2  no .env at all -- reported as UNKNOWN, never as PASS
"""
import os
import sys

REQUIRED = {
    'jira': {
        'JIRA_HOST': 'https://<site>.atlassian.net',
        'JIRA_EMAIL': 'Jira Cloud basic auth is email:token. The token alone is a 401.',
        'JIRA_TOKEN': 'id.atlassian.com > Security > Create API token',
        'JIRA_PROJECT': 'project key',
        'JIRA_STAMP_FIELD': 'customfield_<id> of a single-line text field, provisioned once',
        'JIRA_EPIC_ID': 'numeric id of the product epic (tier 1), created once by a human',
        'JIRA_CALIBRATION_ISSUE': 'numeric id of a ticket this credential did NOT create',
        'TICKET_CREATE_CEILING': 'per-run creation ceiling; no default exists in code',
    },
    'azdo': {
        'AZDO_ORG_URL': 'https://dev.azure.com/<org> (or legacy https://<org>.visualstudio.com; '
                        'AZDO_ORG is accepted as the older name)',
        'AZDO_PROJECT': 'project name',
        'AZDO_PAT': 'User settings > Personal access tokens; Work Items read & write, one org',
        'AZDO_STAMP_FIELD': 'reference name of a custom single-line text field',
        'AZDO_EPIC_ID': 'the tier-1 work item id',
        'AZDO_CALIBRATION_ITEM': 'a work item this PAT did NOT create',
        'TICKET_CREATE_CEILING': 'per-run creation ceiling; no default exists in code',
    },
    'github': {
        'GH_TOKEN': 'a token with issues:write on ONE repository',
        'TICKET_REPO': 'owner/repo',
        'TICKET_STAMP_LABEL': 'the umbrella label, provisioned once by a human',
        'TICKET_CALIBRATION_REF': 'number of an issue this credential did NOT create',
    },
}
# The older spelling of a variable, accepted so a .env written before the design is not refused
# for a rename. The design's name wins when both are present.
ALIASES = {'AZDO_ORG_URL': 'AZDO_ORG'}


def load(path):
    vals = {}
    for raw in open(path, encoding="utf-8"):
        line = raw.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        k, v = line.split("=", 1)
        # A trailing `# comment` on a value line is a comment, not part of the value.
        v = v.split("#", 1)[0].strip().strip("'\"")
        vals[k.strip()] = v
    return vals


def is_secret(name):
    return any(m in name for m in ('TOKEN', 'PAT', 'PASSWORD', 'SECRET'))


def main(argv):
    path = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), ".env")
    if not os.path.exists(path):
        print("UNKNOWN: no .env found at %s" % path)
        print("Copy .env.example to .env and fill in the fields marked REQUIRED.")
        print("Nothing inspected is not nothing wrong.")
        return 2

    vals = load(path)
    backend = (vals.get('TICKET_BACKEND') or '').strip().lower()
    if len(argv) == 3 and argv[1] == '--backend':
        backend = argv[2].strip().lower()
    if backend not in REQUIRED:
        print("TICKET_BACKEND is %s. Set it to exactly one of: %s."
              % (repr(backend) if backend else 'unset', ', '.join(sorted(REQUIRED))))
        print("Exactly one backend is authoritative per repository and environment; the")
        print("values this checks depend on which one. (Or pass --backend <name>.)")
        return 1

    required = REQUIRED[backend]
    got = {}
    for k in required:
        got[k] = vals.get(k) or vals.get(ALIASES.get(k, ''), '')
    missing = [(k, why) for k, why in required.items() if not got[k]]

    print("backend: %s" % backend)
    for k in sorted(required):
        v = got[k]
        shown = ("set, %d chars" % len(v)) if (v and is_secret(k)) else (v or "")
        print("  %-24s %s" % (k, shown if v else "** MISSING **"))

    if missing:
        print("\n%d required field(s) missing for %s. This is why, by name:"
              % (len(missing), backend))
        for k, why in missing:
            print("  %-24s %s" % (k, why))
        print("\nA blank required field is a KNOWN ABSENCE, not an authentication failure.")
        return 1

    print("\nPASS: every required field for %s is present. Presence is not validity -- a wrong"
          % backend)
    print("      token still fails, and it fails differently, which is the point.")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))

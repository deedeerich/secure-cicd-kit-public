#!/usr/bin/env python3
"""The POLICY REGISTER (schema_version 2): who decided how hard each control bites, per org, team,
product, repository and environment tier -- and the only sanctioned way to read it. Stage 1. (L32, L33)

WHERE IT LIVES (two copies of ONE format; neither is ever read from the pull request's tree)

    central     policy/policy-registration.json inside the kit, delivered by `$/` at the caller's
                pinned kit commit. At work this is the private kit's copy, holding both orgs, every
                team and product, and the repository -> (team, product) map. A change reaches a
                repository when it moves its kit pin. The neutral kit ships none.
    repository  .security/policy-registration.json on the calling repository's PROTECTED DEFAULT
                BRANCH, read from a git ref, never the working tree (a registration read from the
                PR under evaluation is the PR choosing its own rung). Its scopes name only
                environment_tier: it IS the repository level. It may TIGHTEN, never soften.

    Neither present -> the KIT DEFAULT: crawl at every tier -- only secrets block, every other
    control routes PROCEED_WITH_ADVISORY (owner requirement 2026-10-22, the crawl phase). An
    UNREADABLE file is never the default: REGISTRATION_UNAVAILABLE, EVIDENCE_UNTRUSTED.

THE FORMAT (schemas/policy-registration.schema.json; templates/policy-register.central.example.json)

    {schema_version: 2, register_id, sign_off: {by, role, date, [reference]}, [proposed_by],
     [notes], [environment_names: {name: tier}], [orgs: {org: enterprise}],
     [repositories: {"owner/name": {[team], [product]}}], [numbers], policies: [
       {id, scope: {[enterprise] | [org], [team], [product], [repository], [environment_tier]},
        [rung], [controls: {control: routing_result}], [team_pattern], [merge_reaches_tier],
        [deploy_approval: {[approver_groups], [approvers_required], [self_review_prevented],
                           [ai_review]}],
        decision: {authority, reason, decided_on, expires, [approver_role], [exception_ref],
                   [environment_reviewers], [evidence_refs]}, [notes],
        [secret_exceptions: [{finding, ticket, explanation, approver, expires,
                              [environment_reviewers]}]]}]}
    secret_exceptions: ONE secret finding made advisory, ticketed and attributed (below, SECRET
    EXCEPTIONS). A defective item is refused by name (SECRET_EXCEPTION_*) and the secret blocks.

    A harness may PROPOSE a register (proposed_by); a person SIGNS IT OFF (sign_off). Nothing
    unsigned resolves.

PRECEDENCE (most specific wins; deterministic; ties are conflicts)

    kit default < enterprise < org < org+team < org+product < org+team+product < repository
    and, at each level, the scope without environment_tier < the same scope with it.
    The ENTERPRISE of a repository is its org's value in the central `orgs` map ({org: enterprise}).
    An enterprise scope names only `enterprise` (and optionally environment_tier). ONCE THE MAP
    DEFINES AN ENTERPRISE (it is non-empty), an org it does not name does not run at all:
    ORG_NOT_UNDER_ENTERPRISE, BLOCKED, even if it ran before the map existed (KDEC-019 item 1,
    owner 2026-10-22: "No run with the enterprise floor even if unmapped previously"). With no
    map, or an empty one, nothing changes. --validate names every org the register mentions that
    the map leaves out.

THE AUTHORITY FLOOR (KDEC-018, owner 2026-10-22: "if they say walk everyone is at walk")

    Each matching entry is applied in precedence order on top of what the run inherited. An entry
    that makes anything STRONGER is a tightening. An entry that leaves the rung or any control
    WEAKER than what a registered entry before it set is REFUSED -- POLICY_BELOW_AUTHORITY_FLOOR,
    BLOCKED, with or without a decision -- and only its non-weakening part is applied, so the floor
    holds in the record. That covers an org under its enterprise, every team, product,
    team+product and repository entry, and a tier-qualified entry beneath its tier-less one. The
    rung and the controls cannot be softer than crawl at all (crawl is the absolute floor), so the
    only softening left is of the KIT DEFAULT's deploy approval at uat/prod, and only the
    AUTHORITY (an enterprise or org scope) may make it: in force with its unexpired decision,
    recorded as an attributed weakening row (routes PROCEED_WITH_ADVISORY), and never honoured by
    the deploy (which holds the stronger of it and the kit default). Per-finding exceptions
    (secret_exceptions) are not rung changes and are unaffected. Every entry carries a decision.

WHAT RESOLUTION REFUSES, BY NAME (policy_resolution in assurance-taxonomy.yaml)

    POLICY_MODE_SUPPLIED          BLOCKED   the run received policy_mode; it is derived
    POLICY_REGISTER_CONFLICT      BLOCKED   two entries for one scope, a duplicated key or id,
                                            one environment name with two tiers, or the
                                            repository file and the central register both
                                            registering one repository tier
    POLICY_DECISION_UNATTRIBUTED  BLOCKED   an entry without authority, reason, decided_on or
                                            expires; a uat/prod departure without the
                                            environment's required reviewers; no sign_off
    CHERRY_PICK_BELOW_FLOOR       BLOCKED   a secret-class control below BLOCKED, or any control
                                            set to PROCEED (findings must never PASS-wash)
    REPOSITORY_FILE_SOFTENING     BLOCKED   the repository's own file softened what it inherited
    POLICY_BELOW_AUTHORITY_FLOOR  BLOCKED   a central entry left something weaker than the
                                            authority floor above it (THE AUTHORITY FLOOR)
    ORG_NOT_UNDER_ENTERPRISE      BLOCKED   an enterprise is defined and the run's org is not in
                                            the orgs map (KDEC-019)
    CELLS_NOT_MONOTONE           BLOCKED   sandbox <= dev <= test <= uat = prod violated
    POLICY_DECISION_EXPIRED       DECISION_REQUIRED  an applied decision expired; its tightening
                                            stays in force and its softening reverts
    REGISTRATION_UNAVAILABLE      EVIDENCE_UNTRUSTED unreadable, unparseable, schema violation
    CELL_NOT_REGISTERED           EVIDENCE_UNTRUSTED an environment name that maps to no tier

USAGE
    python3 policy_registration.py --self-test
    python3 policy_registration.py --validate FILE [--origin central|repository] [--today D]
    python3 policy_registration.py --repo . --default-ref FETCH_HEAD [--central PATH] \
        [--repository owner/name] [--environment NAME] [--event EVENT] [--supplied k=v ...] \
        [--out resolution.json] [--github-output "$GITHUB_OUTPUT"]

EXIT  0 resolved   1 refused (state printed)   2 usage, or self-test failed
"""
import argparse
import datetime
import io
import json
import os
import re
import subprocess
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import enforcement_axes as ax  # noqa: E402
import exception_history as eh  # noqa: E402
import rung_ladder as rl  # noqa: E402

SCHEMA_VERSION = 2
KIT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
default_registration_path = '.security/policy-registration.json'
default_central_path = os.path.join(KIT_ROOT, 'policy', 'policy-registration.json')

# Local names for the axes' vocabularies, so each is spelled once (rung_ladder, enforcement_axes).
TEAM_PATTERNS = ax.TEAM_PATTERNS
PRODUCTION_TIERS = rl.PRODUCTION_TIERS

ORIGIN_CENTRAL = 'central'
ORIGIN_REPOSITORY = 'repository'

# policy_resolution values introduced with the register (assurance-taxonomy.yaml).
POLICY_REGISTER_CONFLICT = 'POLICY_REGISTER_CONFLICT'
POLICY_DECISION_UNATTRIBUTED = 'POLICY_DECISION_UNATTRIBUTED'
POLICY_DECISION_EXPIRED = 'POLICY_DECISION_EXPIRED'
REPOSITORY_FILE_SOFTENING = 'REPOSITORY_FILE_SOFTENING'
POLICY_BELOW_AUTHORITY_FLOOR = 'POLICY_BELOW_AUTHORITY_FLOOR'
# An org outside the enterprise once one is defined (KDEC-019 item 1).
ORG_NOT_UNDER_ENTERPRISE = 'ORG_NOT_UNDER_ENTERPRISE'
# An exception renewed more often than the authority's cap (KDEC-018 item 4; scripts/exception_history.py).
EXCEPTION_RENEWAL_LIMIT = eh.EXCEPTION_RENEWAL_LIMIT
# Precedence levels. The AUTHORITY is the enterprise and the org: only they may soften the kit
# default (deploy approval), and nothing beneath a registered entry may soften it (KDEC-018).
LEVEL_ENTERPRISE = 0
LEVEL_ORG = 1
AUTHORITY_LEVELS = (LEVEL_ENTERPRISE, LEVEL_ORG)
# policy_source
KIT_DEFAULT = 'KIT_DEFAULT'
REGISTER = 'REGISTER'

ROUTE_OF = {
    rl.POLICY_MODE_SUPPLIED: 'BLOCKED', POLICY_REGISTER_CONFLICT: 'BLOCKED',
    POLICY_DECISION_UNATTRIBUTED: 'BLOCKED', rl.CHERRY_PICK_BELOW_FLOOR: 'BLOCKED',
    REPOSITORY_FILE_SOFTENING: 'BLOCKED', POLICY_BELOW_AUTHORITY_FLOOR: 'BLOCKED',
    ORG_NOT_UNDER_ENTERPRISE: 'BLOCKED', rl.CELLS_NOT_MONOTONE: 'BLOCKED',
    rl.REGISTRATION_UNAVAILABLE: 'EVIDENCE_UNTRUSTED', rl.CELL_NOT_REGISTERED: 'EVIDENCE_UNTRUSTED',
    POLICY_DECISION_EXPIRED: 'DECISION_REQUIRED', EXCEPTION_RENEWAL_LIMIT: 'DECISION_REQUIRED',
}
# When several refusals apply, the record names the first of these that fired.
REFUSAL_ORDER = (rl.POLICY_MODE_SUPPLIED, POLICY_REGISTER_CONFLICT, POLICY_DECISION_UNATTRIBUTED,
                 rl.CHERRY_PICK_BELOW_FLOOR, REPOSITORY_FILE_SOFTENING, POLICY_BELOW_AUTHORITY_FLOOR,
                 ORG_NOT_UNDER_ENTERPRISE, rl.CELLS_NOT_MONOTONE,
                 rl.REGISTRATION_UNAVAILABLE, rl.CELL_NOT_REGISTERED, EXCEPTION_RENEWAL_LIMIT,
                 POLICY_DECISION_EXPIRED)

# The flagship's scanner jobs: the named controls a register may set. secret-scan and
# malicious-deps are the secret class -- they block in every mode and never soften.
JOBS = ('secret-scan', 'code-quality', 'sast-semgrep', 'sast-bandit', 'sast-dotnet', 'sast-java',
        'sast-go', 'sast-cpp', 'deps-scan', 'iac-scan', 'malicious-deps', 'sbom', 'codeql', 'image-scan')
SECRET_JOBS = ('secret-scan', 'malicious-deps')
SECRET_CONTROLS = ('secrets',) + SECRET_JOBS
CONTROL_KEYS = rl.control_classes + JOBS
# A job's findings reach the gate as BLOCKING-SEVERITY counts (each scanner's own threshold), with
# no per-finding new/pre-existing class until the cascade's output reaches the gate (ledger L44).
# So a job is read at new_critical_high, the strictest non-secret class -- never a weaker one.
JOB_DEFAULT_CLASS = 'new_critical_high'

TOP_KEYS = ('schema_version', 'register_id', 'sign_off', 'proposed_by', 'notes', 'environment_names',
            'orgs', 'repositories', 'numbers', 'policies')
ORG_RE = re.compile(r'^[A-Za-z0-9][A-Za-z0-9._-]*$')
ENTRY_KEYS = ('id', 'scope', 'rung', 'controls', 'team_pattern', 'merge_reaches_tier', 'deploy_approval',
              'decision', 'notes', 'secret_exceptions')

# ── SECRET EXCEPTIONS (owner ruling 2026-10-22, lane L-S) ───────────────────────────────────────
#
# "There must be the possibility of exceptions ... but they must be requested and logged with tickets
# that have explanations." A secret blocks at every rung, and a class-wide or scanner-wide softening of
# secrets is still CHERRY_PICK_BELOW_FLOOR. ONE secret finding may be made advisory by an entry's
# `secret_exceptions` item naming ALL of:
#   finding                the finding's fingerprint as the security report computes it (`fp`: 12
#                          lowercase hex, scripts/scan_report.py fingerprint()). Secret findings carry
#                          no durable identity by design (identify() refuses them, section 5.7), so
#                          this is the one per-finding key the kit has; a scanner or rule change
#                          orphans it, which fails SAFE -- the secret blocks again.
#   ticket                 a work-item key, <PROJECT>-<digits> (scripts/ticket_reference.py, KDEC-013),
#                          within the register's numbers.ticket_min_digits..ticket_max_digits when set
#   explanation, approver  why, and the named person who approved it
#   expires                YYYY-MM-DD, not past
#   environment_reviewers  (on the item or the entry's decision) when it applies at uat/prod
#   renews                 (KDEC-018 item 4) the PRIOR grants of this exception, each {ticket,
#                          approver, from, expires} (scripts/exception_history.py). Shown wherever
#                          the exception is applied; renewed more than numbers.max_exception_renewals
#                          (central only; kit default 2, 0..5) -> EXCEPTION_RENEWAL_LIMIT; an
#                          unreadable history -> SECRET_EXCEPTION_UNATTRIBUTED. A decision may carry
#                          `renews` the same way; the cap binds a SOFTENING decision.
# Any element missing refuses THAT exception by name and the secret still BLOCKS; nothing else about
# the register changes. It lives only in the register (central, or the repository's file on its
# protected default branch) -- never a run input.
SECRET_EXCEPTION_KEYS = ('finding', 'ticket', 'explanation', 'approver', 'expires', 'environment_reviewers',
                         'renews')
SECRET_EXCEPTION_NOT_FINDING_SCOPED = 'SECRET_EXCEPTION_NOT_FINDING_SCOPED'
SECRET_EXCEPTION_UNTICKETED = 'SECRET_EXCEPTION_UNTICKETED'
SECRET_EXCEPTION_UNATTRIBUTED = 'SECRET_EXCEPTION_UNATTRIBUTED'
SECRET_EXCEPTION_EXPIRED = 'SECRET_EXCEPTION_EXPIRED'
SECRET_EXCEPTION_REFUSALS = (SECRET_EXCEPTION_NOT_FINDING_SCOPED, SECRET_EXCEPTION_UNTICKETED,
                             SECRET_EXCEPTION_UNATTRIBUTED, EXCEPTION_RENEWAL_LIMIT, SECRET_EXCEPTION_EXPIRED)
FINGERPRINT_RE = re.compile(r'^[0-9a-f]{12}$')
TICKET_RE = re.compile(r'^([A-Z][A-Z0-9_]*)-([0-9]+)$')
SCOPE_KEYS = ('enterprise', 'org', 'team', 'product', 'repository', 'environment_tier')
DECISION_REQUIRED_FIELDS = ('authority', 'reason', 'decided_on', 'expires')
DECISION_KEYS = DECISION_REQUIRED_FIELDS + ('approver_role', 'exception_ref', 'environment_reviewers',
                                            'evidence_refs', 'renews')
SIGN_OFF_KEYS = ('by', 'role', 'date', 'reference')
APPROVAL_KEYS = ('approver_groups', 'approvers_required', 'self_review_prevented', 'ai_review')
SELF_REVIEW = ('required', 'not_required')
# An AI review comments; it never approves and never gates (owner, 2026-10-22).
AI_REVIEW = ('advisory', 'none')
REPO_RE = re.compile(r'^[A-Za-z0-9][A-Za-z0-9._-]*/[A-Za-z0-9._-]+$')
ISO_DATE = re.compile(r'^\d{4}-\d{2}-\d{2}$')


def default_deploy_approval(tier):
    """uat and prod: one required reviewer, self-review prevented (KDEC-014's environment reviewers,
    now a setting the deploy reads back). Below them nothing is demanded."""
    prod = tier in PRODUCTION_TIERS
    return {'approver_groups': [], 'approvers_required': 1 if prod else 0,
            'self_review_prevented': 'required' if prod else 'not_required', 'ai_review': 'none'}


def _s(v):
    return v.strip() if isinstance(v, str) else ''


def _date(s):
    if not isinstance(s, str) or not ISO_DATE.match(s):
        return None
    try:
        return datetime.date.fromisoformat(s)
    except ValueError:
        return None


def _rank(route):
    return rl.PRECEDENCE.index(route)


# ── reading and validating ────────────────────────────────────────────────────────────────────

class _Dup(object):
    def __init__(self):
        self.keys = []

    def hook(self, pairs):
        seen = {}
        for k, v in pairs:
            norm = k.lower() if isinstance(k, str) else k
            if norm in seen:
                self.keys.append(k)
            seen[norm] = True
        return dict(pairs)


def parse_registration(text, origin=ORIGIN_CENTRAL):
    """-> (doc or None, problems [(code, message)]). Refuses the WHOLE file on any fault: a half-read
    policy is a policy somebody else wrote. A duplicated JSON key (which json.loads would silently
    let the last copy win) is a conflict, by name."""
    if not _s(text):
        return (None, [(rl.REGISTRATION_UNAVAILABLE, 'the registration file is empty')])
    dup = _Dup()
    try:
        doc = json.loads(text, object_pairs_hook=dup.hook)
    except ValueError as exc:
        return (None, [(rl.REGISTRATION_UNAVAILABLE, 'not valid JSON: %s' % exc)])
    problems = [(POLICY_REGISTER_CONFLICT, 'key %r appears twice in one object: the register says two '
                 'things and the reader would silently keep the last' % k) for k in dup.keys]
    problems += check_document(doc, origin)
    return (None if problems else doc, problems)


def check_document(doc, origin):
    """Structural, attribution and conflict checks over one parsed document. -> problems."""
    p = []
    bad = lambda m: p.append((rl.REGISTRATION_UNAVAILABLE, m))  # noqa: E731
    unattributed = lambda m: p.append((POLICY_DECISION_UNATTRIBUTED, m))  # noqa: E731
    if not isinstance(doc, dict):
        return [(rl.REGISTRATION_UNAVAILABLE, 'the registration is not a JSON object')]
    if doc.get('schema_version') != SCHEMA_VERSION:
        bad('schema_version is %r; this reader understands %d (schema_version 1, the per-repository '
            'cell format, is retired: rewrite it as a policies list)' % (doc.get('schema_version'), SCHEMA_VERSION))
    for k in doc:
        if k not in TOP_KEYS:
            bad('unknown top-level field %r: the register reads through an allowlist' % k)
    if not _s(doc.get('register_id')):
        bad('register_id is missing or empty')
    if 'proposed_by' in doc and not isinstance(doc['proposed_by'], str):
        bad('proposed_by is not a string')
    so = doc.get('sign_off')
    if not isinstance(so, dict):
        unattributed('no sign_off: a register nobody signed off is a proposal, not a policy')
    else:
        for k in so:
            if k not in SIGN_OFF_KEYS:
                bad('sign_off carries unknown field %r' % k)
        for k in ('by', 'role'):
            if not _s(so.get(k)):
                unattributed('sign_off lacks %s' % k)
        if not _s(so.get('date')):
            unattributed('sign_off lacks date')
        elif _date(so.get('date')) is None:
            bad('sign_off.date %r is not a YYYY-MM-DD calendar date' % so.get('date'))
    names = doc.get('environment_names', {})
    if not isinstance(names, dict):
        bad('environment_names is not an object')
    else:
        for n, t in names.items():
            if not _s(n) or t not in rl.tier_order:
                bad('environment_names[%r] = %r is not a registered environment_tier' % (n, t))
    orgs = doc.get('orgs', {})
    if origin == ORIGIN_REPOSITORY and 'orgs' in doc:
        bad('orgs belongs to the central register; a repository does not place its org in an enterprise')
    if not isinstance(orgs, dict):
        bad('orgs is not an object ({org: enterprise})')
        orgs = {}
    for oname, ent in orgs.items():
        if not ORG_RE.match(oname or ''):
            bad('orgs key %r is not an org name' % oname)
        if not _s(ent):
            bad('orgs[%r] must name its enterprise (a non-empty string)' % oname)
    enterprises = set(_s(v) for v in orgs.values() if _s(v))
    repos = doc.get('repositories', {})
    if origin == ORIGIN_REPOSITORY and 'repositories' in doc:
        bad('repositories belongs to the central register; a repository does not map itself to a team')
    if not isinstance(repos, dict):
        bad('repositories is not an object')
    else:
        for rname, m in repos.items():
            if not REPO_RE.match(rname or ''):
                bad('repositories key %r is not owner/name' % rname)
            if not isinstance(m, dict) or any(k not in ('team', 'product') for k in m) \
                    or any(not _s(v) for v in m.values()):
                bad('repositories[%r] must be {team, product} strings' % rname)
    if 'numbers' in doc and not isinstance(doc['numbers'], dict):
        bad('numbers is not an object')
    elif eh.number_key in (doc.get('numbers') or {}):
        # The renewal cap is the AUTHORITY's to set (KDEC-018 item 4), never a repository's.
        if origin == ORIGIN_REPOSITORY:
            bad('numbers.%s belongs to the central register: the renewal cap is set at the authority\'s '
                'scope' % eh.number_key)
        _cap, why = eh.cap_from_numbers(doc['numbers'])
        if why:
            bad(why)
    pols = doc.get('policies')
    if not isinstance(pols, list):
        bad('policies is missing or not a list')
        pols = []
    ids, scopes = {}, {}
    for i, e in enumerate(pols):
        where = 'policies[%d]' % i
        if not isinstance(e, dict):
            bad('%s is not an object' % where)
            continue
        eid = _s(e.get('id'))
        where = 'policies[%d] (%s)' % (i, eid or 'no id')
        if not eid:
            bad('%s has no id' % where)
        elif eid in ids:
            p.append((POLICY_REGISTER_CONFLICT, 'entry id %r appears twice' % eid))
        ids[eid] = True
        for k in e:
            if k not in ENTRY_KEYS:
                bad('%s carries unknown field %r' % (where, k))
        sc = e.get('scope')
        if not isinstance(sc, dict):
            bad('%s has no scope object' % where)
            sc = {}
        for k in sc:
            if k not in SCOPE_KEYS:
                bad('%s scope carries unknown dimension %r (enterprise, org, team, product, repository, '
                    'environment_tier)' % (where, k))
            elif not _s(sc[k]):
                bad('%s scope.%s is empty' % (where, k))
        tier = sc.get('environment_tier')
        if tier is not None and tier not in rl.tier_order:
            bad('%s scope.environment_tier %r is not a registered environment_tier' % (where, tier))
        if origin == ORIGIN_REPOSITORY:
            if any(k != 'environment_tier' for k in sc):
                bad('%s: a repository file is the repository level; its scope names only '
                    'environment_tier' % where)
        elif sc.get('enterprise'):
            # THE ENTERPRISE IS THE TOP AUTHORITY (KDEC-018). It names nothing narrower: which orgs
            # it binds is the `orgs` map's to say, never an entry's.
            if any(k not in ('enterprise', 'environment_tier') for k in sc):
                bad('%s scope names an enterprise together with %s; an enterprise scope names only the '
                    'enterprise (and optionally environment_tier), and the orgs map says which orgs are in it'
                    % (where, ', '.join(sorted(k for k in sc if k not in ('enterprise', 'environment_tier')))))
            if _s(sc['enterprise']) not in enterprises:
                bad('%s scope.enterprise %r is not the enterprise of any org in the orgs map, so it would '
                    'bind nobody' % (where, sc['enterprise']))
        else:
            if not sc.get('org') and not sc.get('repository'):
                bad('%s scope names neither enterprise, org nor repository' % where)
            if (sc.get('team') or sc.get('product')) and not sc.get('org'):
                bad('%s scope names a team or product without its org' % where)
            if sc.get('repository') and (sc.get('team') or sc.get('product')):
                bad('%s scope names a repository and a team or product; the repository map says '
                    'which team and product a repository belongs to' % where)
            if sc.get('repository'):
                if not REPO_RE.match(sc['repository']):
                    bad('%s scope.repository %r is not owner/name' % (where, sc['repository']))
                elif sc.get('org') and sc['repository'].split('/')[0].lower() != sc['org'].lower():
                    bad('%s scope.repository %r is outside scope.org %r' % (where, sc['repository'], sc['org']))
        key = scope_key(sc, origin)
        if key in scopes:
            p.append((POLICY_REGISTER_CONFLICT, 'entries %r and %r register the same scope %s; '
                      'which one governs would be an accident of order' % (scopes[key], eid, _scope_text(sc))))
        else:
            scopes[key] = eid
        if 'rung' in e and e['rung'] not in rl.RUNGS:
            bad('%s rung %r is not crawl, walk or run' % (where, e['rung']))
        ctl = e.get('controls', {})
        if not isinstance(ctl, dict):
            bad('%s controls is not an object' % where)
            ctl = {}
        for c, v in ctl.items():
            if c not in CONTROL_KEYS:
                bad('%s controls names %r, which is neither a control class nor a scanner job' % (where, c))
            elif v not in rl.PRECEDENCE:
                bad('%s controls[%s] = %r is not a registered routing_result' % (where, c, v))
            elif v == 'PROCEED':
                p.append((rl.CHERRY_PICK_BELOW_FLOOR, '%s sets %s to PROCEED: a finding must never read as '
                          'a pass; the weakest any control may be is PROCEED_WITH_ADVISORY' % (where, c)))
            elif c in SECRET_CONTROLS and v != 'BLOCKED':
                p.append((rl.CHERRY_PICK_BELOW_FLOOR, '%s sets %s to %s: a secret-class control blocks at '
                          'every rung and has no softer setting' % (where, c, v)))
        sx = e.get('secret_exceptions')
        if sx is not None:
            if not isinstance(sx, list):
                bad('%s secret_exceptions is not a list' % where)
            else:
                for j, item in enumerate(sx):
                    if not isinstance(item, dict):
                        bad('%s secret_exceptions[%d] is not an object' % (where, j))
                        continue
                    for k in item:
                        if k not in SECRET_EXCEPTION_KEYS:
                            bad('%s secret_exceptions[%d] carries unknown field %r' % (where, j, k))
                    rv_i = item.get('environment_reviewers')
                    if rv_i is not None and (not isinstance(rv_i, list) or any(not _s(x) for x in rv_i)):
                        bad('%s secret_exceptions[%d].environment_reviewers must be a list of reviewer '
                            'names' % (where, j))
        if 'team_pattern' in e and e['team_pattern'] not in TEAM_PATTERNS:
            bad('%s team_pattern %r is not registered' % (where, e['team_pattern']))
        if 'merge_reaches_tier' in e:
            if e['merge_reaches_tier'] not in rl.tier_order:
                bad('%s merge_reaches_tier %r is not a registered environment_tier' % (where, e['merge_reaches_tier']))
            if tier is not None:
                bad('%s declares merge_reaches_tier on a tier-qualified scope; how far a merge reaches '
                    'is a property of the scope, not of one tier' % where)
        da = e.get('deploy_approval', {})
        if not isinstance(da, dict):
            bad('%s deploy_approval is not an object' % where)
            da = {}
        for k, v in da.items():
            if k not in APPROVAL_KEYS:
                bad('%s deploy_approval carries unknown field %r' % (where, k))
            elif k == 'approver_groups' and (not isinstance(v, list) or any(not _s(g) for g in v)):
                bad('%s deploy_approval.approver_groups must be a list of group names' % where)
            elif k == 'approvers_required' and v not in (0, 1):
                bad('%s deploy_approval.approvers_required %r: GitHub environments admit on ONE listed '
                    'reviewer, so the register can say 0 or 1 and nothing it cannot enforce' % (where, v))
            elif k == 'self_review_prevented' and v not in SELF_REVIEW:
                bad('%s deploy_approval.self_review_prevented %r is not required | not_required' % (where, v))
            elif k == 'ai_review' and v not in AI_REVIEW:
                bad('%s deploy_approval.ai_review %r: an AI review comments, advisory only -- it is never '
                    'a gate or an approval (advisory | none)' % (where, v))
        dec = e.get('decision')
        if not isinstance(dec, dict):
            unattributed('%s has no decision: every registration is a decision a named person made' % where)
            continue
        for k in dec:
            if k not in DECISION_KEYS:
                bad('%s decision carries unknown field %r' % (where, k))
        for k in DECISION_REQUIRED_FIELDS:
            if not _s(dec.get(k)):
                unattributed('%s decision lacks %s' % (where, k))
        for k in ('decided_on', 'expires'):
            if _s(dec.get(k)) and _date(dec.get(k)) is None:
                bad('%s decision.%s %r is not a YYYY-MM-DD calendar date; an expiry nobody can read has '
                    'not "not arrived"' % (where, k, dec.get(k)))
        rv = dec.get('environment_reviewers')
        if rv is not None and (not isinstance(rv, list) or any(not _s(x) for x in rv)):
            bad('%s decision.environment_reviewers must be a list of reviewer names' % where)
        if 'renews' in dec:
            _g, why = eh.parse_renews(dec.get('renews'))
            if why:
                unattributed('%s decision.%s: a history the kit cannot read cannot be shown to be under the '
                             'renewal cap' % (where, why))
        departs = any(k in e for k in ('rung', 'controls', 'deploy_approval'))
        if departs and tier in (None,) + PRODUCTION_TIERS and not rv:
            unattributed('%s applies at uat/prod and changes enforcement there, so its decision must name '
                         'the environment\'s required reviewers (decision.environment_reviewers)' % where)
    return p


def scope_key(sc, origin):
    lower = lambda v: v.lower() if isinstance(v, str) else v  # noqa: E731
    return (origin == ORIGIN_REPOSITORY, sc.get('enterprise'), lower(sc.get('org')), sc.get('team'),
            sc.get('product'), lower(sc.get('repository')), sc.get('environment_tier'))


def _scope_text(sc):
    return '{%s}' % ', '.join('%s=%s' % (k, sc[k]) for k in SCOPE_KEYS if k in sc)


def renewal_cap(central):
    """The authority's renewal cap: the central register's numbers, else the kit default."""
    return eh.cap_from_numbers((central or {}).get('numbers'))[0]


def secret_exception_verdict(item, entry, today, numbers=None, cap=eh.kit_default_max_renewals):
    """-> (refusal code or None, why) for ONE secret_exceptions item, in the order a reader fixes
    them: what it covers, its ticket, who decided and why, how often it was renewed, whether it is
    still in force."""
    finding = _s(item.get('finding'))
    if not FINGERPRINT_RE.match(finding):
        return (SECRET_EXCEPTION_NOT_FINDING_SCOPED,
                'finding %r is not one finding\'s fingerprint (12 lowercase hex, the security report\'s '
                '`fp`). Secrets as a class, a scanner, a rule or a wildcard are never excepted -- that is '
                'CHERRY_PICK_BELOW_FLOOR' % (item.get('finding'),))
    ticket = _s(item.get('ticket'))
    m = TICKET_RE.match(ticket)
    if not m:
        return (SECRET_EXCEPTION_UNTICKETED,
                'ticket %r is not a work-item key <PROJECT>-<digits>: a secret exception must be requested '
                'and logged on a ticket' % (item.get('ticket') or '',))
    import ticket_reference as tr
    nums = numbers or {}
    lo, hi = nums.get('ticket_min_digits'), nums.get('ticket_max_digits')
    enforce = isinstance(lo, int) and isinstance(hi, int)
    seen = tr.examine(ticket, m.group(1), enforce=enforce, min_digits=lo if enforce else None,
                      max_digits=hi if enforce else None)
    if seen['outcome'] != tr.REFERENCE_FOUND or seen['key'] != ticket:
        return (SECRET_EXCEPTION_UNTICKETED, 'ticket %r does not satisfy the id-format policy (%s)'
                % (ticket, seen['detail']))
    missing = [k for k in ('explanation', 'approver', 'expires') if not _s(item.get(k))]
    if missing:
        return (SECRET_EXCEPTION_UNATTRIBUTED, 'the exception for %s lacks %s' % (finding, ', '.join(missing)))
    exp = _date(item.get('expires'))
    if exp is None:
        return (SECRET_EXCEPTION_UNATTRIBUTED, 'expires %r is not a YYYY-MM-DD calendar date; an expiry '
                'nobody can read has not "not arrived"' % item.get('expires'))
    tier = ((entry or {}).get('scope') or {}).get('environment_tier')
    reviewers = item.get('environment_reviewers') or ((entry or {}).get('decision') or {}).get('environment_reviewers')
    if tier in (None,) + PRODUCTION_TIERS and not reviewers:
        return (SECRET_EXCEPTION_UNATTRIBUTED, 'the exception for %s applies at uat/prod, so it must name the '
                'environment\'s required reviewers (environment_reviewers)' % finding)
    grants, why = eh.parse_renews(item.get('renews'))
    if grants is None:
        return (SECRET_EXCEPTION_UNATTRIBUTED, 'the exception for %s has a history the kit cannot read (%s), so '
                'it cannot be shown to be under the renewal cap' % (finding, why))
    code, why = eh.verdict(grants, cap)
    if code:
        return (code, 'the exception for %s (%s) was %s' % (finding, ticket, why))
    if exp < datetime.date.fromisoformat(today):
        return (SECRET_EXCEPTION_EXPIRED, 'the exception for %s (%s) expired on %s; the secret blocks again '
                'until someone re-decides it' % (finding, ticket, exp.isoformat()))
    dec_exp = _date(((entry or {}).get('decision') or {}).get('expires'))
    if dec_exp is None or dec_exp < datetime.date.fromisoformat(today):
        return (SECRET_EXCEPTION_EXPIRED, 'the entry %r carrying the exception for %s has an expired '
                'decision' % ((entry or {}).get('id'), finding))
    return (None, 'excepted: %s on %s, approved by %s until %s' % (finding, ticket, _s(item.get('approver')),
                                                                  exp.isoformat()))


def validate(doc, origin, today):
    """--validate: everything resolution would refuse anywhere, before any run meets it. -> problems."""
    problems = check_document(doc, origin)
    if problems:
        return problems
    for e in doc.get('policies') or []:
        exp = _date((e.get('decision') or {}).get('expires'))
        if exp and exp < datetime.date.fromisoformat(today):
            problems.append((POLICY_DECISION_EXPIRED, 'entry %r expired on %s; renew or remove it'
                             % (e.get('id'), exp.isoformat())))
        for item in e.get('secret_exceptions') or []:
            code, why = secret_exception_verdict(item, e, today, doc.get('numbers'),
                                                 renewal_cap(doc if origin == ORIGIN_CENTRAL else None))
            if code:
                problems.append((code, 'entry %r: %s' % (e.get('id'), why)))
    if origin == ORIGIN_CENTRAL:
        for o in unmapped_orgs(doc):
            problems.append((ORG_NOT_UNDER_ENTERPRISE, 'org %r appears in this register but not in its orgs map; '
                             'once an enterprise is defined every run in it is refused (KDEC-019). Name it in '
                             'the orgs map' % o))
        # Every mapped repository, and each org (named by an entry or the orgs map) with its
        # unmapped repositories.
        orgs = set(_s((e.get('scope') or {}).get('org')).lower()
                   for e in doc.get('policies') or [] if (e.get('scope') or {}).get('org'))
        orgs |= set(_s(o).lower() for o in (doc.get('orgs') or {}))
        idents = [('%s (unmapped repositories)' % o, _identity(doc, '%s/' % o)) for o in sorted(orgs)]
        idents += [(r, _identity(doc, r)) for r in sorted(doc.get('repositories') or {})]
        seen = set()
        for t, ident in idents:
            folds = {tier: _fold(doc, None, ident, tier, today) for tier in rl.tier_order}
            for d in rl.check_cells_monotone(dict((tier, {'tier': tier, 'rung': f['rung']})
                                                  for tier, f in folds.items())):
                problems.append((rl.CELLS_NOT_MONOTONE, '%s: %s' % (t, d)))
            # THE AUTHORITY FLOOR, for every repository and org it would reach (KDEC-018).
            for tier, f in sorted(folds.items()):
                for code, d in zip(f['refusals'], f['defects']):
                    if code in (POLICY_BELOW_AUTHORITY_FLOOR, EXCEPTION_RENEWAL_LIMIT) and (t, d) not in seen:
                        seen.add((t, d))
                        problems.append((code, '%s at %s: %s' % (t, tier, d)))
    return problems


# ── resolution ────────────────────────────────────────────────────────────────────────────────

def enterprise_defined(central):
    """True when the central register places any org in an enterprise (a non-empty `orgs` map; an
    enterprise entry cannot exist without one). From then on every org must be named (KDEC-019)."""
    orgs = (central or {}).get('orgs')
    return isinstance(orgs, dict) and any(_s(v) for v in orgs.values())


def unmapped_orgs(doc):
    """The orgs a central register mentions (an entry's org or repository, the repository map) that
    its orgs map does not name -- each would be refused at every run once an enterprise is defined."""
    if not enterprise_defined(doc):
        return []
    mapped = set(_s(o).lower() for o in doc['orgs'])
    seen = set()
    for e in doc.get('policies') or []:
        sc = e.get('scope') or {}
        if _s(sc.get('org')):
            seen.add(_s(sc['org']).lower())
        if _s(sc.get('repository')):
            seen.add(_s(sc['repository']).split('/')[0].lower())
    for rname in doc.get('repositories') or {}:
        seen.add(_s(rname).split('/')[0].lower())
    return sorted(o for o in seen if o and o not in mapped)


def _identity(doc, repository):
    owner, _sep, _name = (repository or '').partition('/')
    m = {}
    for rname, mapping in ((doc or {}).get('repositories') or {}).items():
        if rname.lower() == (repository or '').lower():
            m = mapping
    # The org's enterprise, from the central orgs map (org names compare case-insensitively).
    ent = None
    for oname, e in ((doc or {}).get('orgs') or {}).items():
        if isinstance(oname, str) and oname.lower() == owner.lower():
            ent = _s(e) or None
    return {'org': owner.lower(), 'repository': (repository or '').lower(),
            'team': m.get('team'), 'product': m.get('product'), 'enterprise': ent}


def _level(sc, origin):
    if origin == ORIGIN_REPOSITORY or sc.get('repository'):
        return 5
    if sc.get('team') and sc.get('product'):
        return 4
    if sc.get('product'):
        return 3
    if sc.get('team'):
        return 2
    if sc.get('enterprise'):
        return LEVEL_ENTERPRISE
    return LEVEL_ORG


def _matches(sc, ident, origin, tier):
    if sc.get('environment_tier') not in (None, tier):
        return False
    if origin == ORIGIN_REPOSITORY:
        return True
    if sc.get('enterprise'):
        return bool(ident.get('enterprise')) and sc['enterprise'] == ident.get('enterprise')
    if sc.get('repository'):
        return sc['repository'].lower() == ident['repository']
    if _s(sc.get('org')).lower() != ident['org']:
        return False
    if sc.get('team') and sc['team'] != ident['team']:
        return False
    if sc.get('product') and sc['product'] != ident['product']:
        return False
    return True


def _chain(central, repo_doc, ident, tier):
    out = []
    for origin, doc in ((ORIGIN_CENTRAL, central), (ORIGIN_REPOSITORY, repo_doc)):
        for e in (doc or {}).get('policies') or []:
            sc = e.get('scope') or {}
            if _matches(sc, ident, origin, tier):
                out.append(((_level(sc, origin), 'environment_tier' in sc), origin, e))
    out.sort(key=lambda x: x[0])
    return out


def _effective(rung, overrides):
    floor = rl.rung_floor(rung)
    eff = dict((c, overrides.get(c, floor[c])) for c in rl.control_classes)
    for j in JOBS:
        eff[j] = overrides.get(j, 'BLOCKED' if j in SECRET_JOBS else eff[JOB_DEFAULT_CLASS])
    return eff


def _approval_strength(da):
    return (da['approvers_required'], 1 if da['self_review_prevented'] == 'required' else 0)


def _fold(central, repo_doc, ident, tier, today):
    """Apply every matching entry, least specific first, at one tier."""
    chain = _chain(central, repo_doc, ident, tier)
    rung, over, team = 'crawl', {}, None
    da = default_deploy_approval(tier)
    weak, refusals, defects, applied = [], [], [], []
    ranks = {}
    sx_applied, sx_refused = {}, []
    nums = dict((central or {}).get('numbers') or {}, **((repo_doc or {}).get('numbers') or {}))
    cap = renewal_cap(central)
    # The deploy-approval fields a REGISTERED entry has set at this tier. The rung and the controls
    # cannot be softer than crawl's (the kit default), so any softening of them is a softening of
    # something registered; deploy approval is the one value the kit default sets above its weakest.
    da_registered = set()
    for key, origin, e in chain:
        if key in ranks:
            refusals.append(POLICY_REGISTER_CONFLICT)
            defects.append('entries %r and %r both match at the same precedence; which governs would be '
                           'an accident of order' % (ranks[key], e.get('id')))
            continue
        ranks[key] = e.get('id')
        dec = e.get('decision') or {}
        exp = _date(dec.get('expires'))
        expired = exp is None or exp < datetime.date.fromisoformat(today)
        before = _effective(rung, over)
        new_rung = e.get('rung', rung)
        new_over = dict(over)
        new_over.update(e.get('controls') or {})
        after = _effective(new_rung, new_over)
        rung_softer = rl.rung_index(new_rung) < rl.rung_index(rung)
        # RAISING THE RUNG IS A TIGHTENING, even where the ladder routes one class differently
        # (run's pre_existing_on_track is advisory: those findings are on a tracked SLA). A control
        # is softened by THIS entry only when it ends weaker than what it inherited AND weaker than
        # the entry's own rung gives it with the inherited overrides -- i.e. by an explicit control.
        by_rung = before if rung_softer else _effective(new_rung, over)
        softer = [c for c in sorted(after)
                  if _rank(after[c]) < _rank(before[c]) and _rank(after[c]) < _rank(by_rung[c])]
        new_da = dict(da)
        new_da.update(e.get('deploy_approval') or {})
        new_da['approver_groups'] = sorted(new_da.get('approver_groups') or [])
        da_soft_keys = [k for k, a, b in zip(('approvers_required', 'self_review_prevented'),
                                             _approval_strength(new_da), _approval_strength(da)) if a < b]
        da_softer = bool(da_soft_keys)
        any_softer = softer or rung_softer or da_softer
        softened = ', '.join(softer + (['rung'] if rung_softer else []) + (['deploy-approval'] if da_softer else []))
        if any_softer and origin == ORIGIN_REPOSITORY:
            refusals.append(REPOSITORY_FILE_SOFTENING)
            defects.append('the repository file entry %r softens what the repository inherited (%s); a '
                           'repository may tighten its own policy, never loosen it' % (e.get('id'), softened))
        # THE AUTHORITY FLOOR (KDEC-018). Below a registered value: refused at every scope, decision
        # or not. Below the kit default's deploy approval: only the authority (enterprise, org).
        authority = key[0] in AUTHORITY_LEVELS
        floor_breach = origin == ORIGIN_CENTRAL and (
            softer or rung_softer or (da_softer and (not authority or da_registered & set(da_soft_keys))))
        if floor_breach:
            refusals.append(POLICY_BELOW_AUTHORITY_FLOOR)
            defects.append('entry %r leaves %s weaker than the floor above it (%s); the highest authority\'s '
                           'rung and routing bind every narrower scope, which may only tighten -- with a '
                           'decision or without one (KDEC-018). Its tightening, if any, is applied; its '
                           'softening is not' % (e.get('id'), softened, ', '.join(applied) or 'the kit default'))
        may_soften = not expired and origin == ORIGIN_CENTRAL and not floor_breach
        # A SOFTENING decision is an exception: its renewals are counted and capped (KDEC-018 item 4).
        grants = eh.parse_renews(dec.get('renews'))[0] or []
        renew_code, renew_why = eh.verdict(grants, cap)
        if any_softer and may_soften and renew_code:
            refusals.append(renew_code)
            defects.append('entry %r softens %s on a decision %s; the softening does not apply'
                           % (e.get('id'), softened, renew_why))
            may_soften = False
        hist = eh.summary(grants)
        if expired:
            refusals.append(POLICY_DECISION_EXPIRED)
            defects.append('entry %r: its decision expired on %s. Its tightening stays in force and its '
                           'softening does not apply; silence never renews a decision'
                           % (e.get('id'), dec.get('expires')))
        if any_softer and not may_soften:
            # Apply only what does not weaken.
            if rl.rung_index(new_rung) > rl.rung_index(rung):
                rung = new_rung
            cur = _effective(rung, over)
            for c, v in (e.get('controls') or {}).items():
                if _rank(v) >= _rank(cur[c]):
                    over[c] = v
            merged = dict(da)
            for k, v in (e.get('deploy_approval') or {}).items():
                if k == 'approvers_required':
                    merged[k] = max(da[k], v)
                elif k == 'self_review_prevented':
                    merged[k] = 'required' if 'required' in (da[k], v) else 'not_required'
                elif k == 'approver_groups':
                    merged[k] = sorted(v)
                else:
                    merged[k] = v
            da = merged
        else:
            prev_rung, prev_da = rung, da
            rung, over, da = new_rung, new_over, new_da
            row = lambda control, base, value: weak.append({  # noqa: E731
                'input': 'policy entry %s' % e.get('id'), 'class': rl.GATE_SOFTENED, 'control': control,
                'baseline': base, 'value': value, 'state': rl.WEAKENING_IN_FORCE,
                'attribution': rl.WEAKENING_ATTRIBUTED, 'routes_to': rl.PROCEED_WITH_ADVISORY,
                'reason': _s(dec.get('reason')), 'authority': _s(dec.get('authority')),
                'expires': _s(dec.get('expires')), 'exception_ref': _s(dec.get('exception_ref')),
                'renewals': hist['renewals'], 'history': hist['history']})
            if rung_softer:
                row('rung', prev_rung, new_rung)
            for c in softer:
                row(c, before[c], after[c])
            if da_softer:
                row('deploy-approval', 'approvers_required=%s self_review_prevented=%s'
                    % (prev_da['approvers_required'], prev_da['self_review_prevented']),
                    'approvers_required=%s self_review_prevented=%s'
                    % (new_da['approvers_required'], new_da['self_review_prevented']))
        da_registered |= set(k for k in (e.get('deploy_approval') or {})
                             if k in ('approvers_required', 'self_review_prevented'))
        if 'team_pattern' in e:
            team = e['team_pattern']
        applied.append(e.get('id'))
        # SECRET EXCEPTIONS: each item judged alone. A refused one is named and changes nothing --
        # the secret still blocks; an applied one is keyed by its finding, the most specific entry
        # winning. The repository's own file may carry them (the owner's ruling names it).
        for item in e.get('secret_exceptions') or []:
            code, why = secret_exception_verdict(item, e, today, nums, cap)
            ih = eh.summary(eh.parse_renews(item.get('renews'))[0] or [])
            rec = {'finding': _s(item.get('finding')), 'ticket': _s(item.get('ticket')),
                   'entry': e.get('id'), 'origin': origin, 'renewals': ih['renewals'], 'history': ih['history']}
            if code:
                sx_refused.append(dict(rec, code=code, why=why))
            else:
                sx_applied[rec['finding']] = dict(rec, approver=_s(item.get('approver')),
                                                  expires=_s(item.get('expires')),
                                                  explanation=_s(item.get('explanation')))
    return {'rung': rung, 'overrides': over, 'team_pattern': team, 'deploy_approval': da, 'chain': applied,
            'weakenings': weak, 'refusals': refusals, 'defects': defects, 'identity': ident,
            'secret_exceptions': [sx_applied[k] for k in sorted(sx_applied)],
            'secret_exception_refusals': sx_refused}


def _merge_reach(central, repo_doc, ident):
    reach = None
    for (lvl, has_tier), origin, e in _chain(central, repo_doc, ident, None):
        if 'merge_reaches_tier' in e:
            reach = e['merge_reaches_tier']
    return reach


def _blank(state, why, notes=None, defects=None, **extra):
    out = {'state': state, 'axis': 'enforcement', 'routes_to': ROUTE_OF.get(state), 'why': why,
           'notes': list(notes or []), 'defects': list(defects or []), 'refusals': [state],
           'environment': None, 'environment_tier': None, 'team_pattern': None, 'rung_declared': None,
           'rung_effective': None, 'rung_divergence': None, 'policy_mode': None, 'policy_mode_source': None,
           'policy_source': None, 'chain': [], 'scope': {}, 'floor': {}, 'effective_minimum': {},
           'job_minimums': {}, 'divergences': [], 'weakenings': [], 'human_controls': {},
           'unvalidated_human_workflow_paths': [], 'breach_authority': {},
           'tier_behaviour': {'stops_on_evidence_untrusted': True}, 'deploy_approval': {},
           'numbers': {}, 'registration_ref': None, 'max_exception_renewals': None,
           'secret_exceptions': [], 'secret_exception_refusals': []}
    out.update(extra)
    return out


def _refusal_state(codes):
    for c in REFUSAL_ORDER:
        if c in codes:
            return c
    return None


def resolve(central, repo_doc, repository, environment, event, supplied_inputs, today):
    """Stage 1, pure over its arguments. `central` / `repo_doc` are parsed documents or None."""
    sup = rl.refuse_supplied_policy_mode(dict(supplied_inputs or {}))
    if sup['state'] == rl.POLICY_MODE_SUPPLIED:
        return _blank(sup['state'], sup['why'], defects=[sup['why']])
    problems = []
    for origin, doc in ((ORIGIN_CENTRAL, central), (ORIGIN_REPOSITORY, repo_doc)):
        if doc is not None:
            problems += [(c, '%s register: %s' % (origin, m)) for c, m in check_document(doc, origin)]
    if problems:
        state = _refusal_state([c for c, _m in problems])
        return _blank(state, 'the policy register is refused: %s' % problems[0][1],
                      notes=[m for _c, m in problems], defects=[m for _c, m in problems],
                      refusals=sorted(set(c for c, _m in problems)))
    names = {}
    for origin, doc in ((ORIGIN_CENTRAL, central), (ORIGIN_REPOSITORY, repo_doc)):
        for n, t in ((doc or {}).get('environment_names') or {}).items():
            if n in names and names[n] != t:
                why = 'environment name %r maps to %s and to %s' % (n, names[n], t)
                return _blank(POLICY_REGISTER_CONFLICT, why, defects=[why])
            names[n] = t
    ident = _identity(central, repository)
    # KDEC-019 item 1: once the central register defines an enterprise, an org it does not place
    # in one is outside the floor, and a run there is refused -- even if it ran before the map.
    if enterprise_defined(central) and not ident.get('enterprise'):
        why = ('org %r is not named in the central register\'s orgs map, which defines an enterprise (%s): '
               'a run outside the enterprise floor is refused. Add the org to the orgs map (KDEC-019)'
               % (ident['org'], ', '.join(sorted(set(_s(v) for v in central['orgs'].values())))))
        return _blank(ORG_NOT_UNDER_ENTERPRISE, why, defects=[why], environment=_s(environment) or None,
                      scope=ident)
    # A repository-file entry beside a central repository entry for one tier: two registrations.
    if repo_doc:
        mine = set((e.get('scope') or {}).get('environment_tier') for e in repo_doc.get('policies') or [])
        for e in (central or {}).get('policies') or []:
            sc = e.get('scope') or {}
            if sc.get('repository', '').lower() == ident['repository'] and sc.get('environment_tier') in mine:
                why = ('central entry %r and the repository file both register %s at tier %s'
                       % (e.get('id'), repository, sc.get('environment_tier') or '(every tier)'))
                return _blank(POLICY_REGISTER_CONFLICT, why, defects=[why])
    # Which tier.
    env = _s(environment)
    reach = _merge_reach(central, repo_doc, ident)
    basis = 'named environment'
    if event in ('pull_request', 'pull_request_target') or not env:
        tier = reach or 'prod'
        basis = ('the declared merge reach' if reach else
                 'no merge reach is declared, so the strictest tier') + ' (%s)' % (event or 'no environment named')
        env_name = env or None
    else:
        tier = names.get(env) or (env if env in rl.tier_order else None)
        env_name = env
        if tier is None:
            why = ('environment %r maps to no environment_tier: name it in environment_names or use a '
                   'tier name (%s)' % (env, ', '.join(rl.tier_order)))
            return _blank(rl.CELL_NOT_REGISTERED, why, environment=env)
    folds = dict((t, _fold(central, repo_doc, ident, t, today)) for t in rl.tier_order)
    if reach and env and event not in ('pull_request', 'pull_request_target') and \
            rl.rung_index(folds[reach]['rung']) > rl.rung_index(folds[tier]['rung']):
        basis = ('named %s sits below %s, which a merge reaches without a human gate; evaluated at %s'
                 % (tier, reach, reach))
        tier = reach
    f = folds[tier]
    mono = rl.check_cells_monotone(dict((t, {'tier': t, 'rung': folds[t]['rung']}) for t in rl.tier_order))
    refusals = list(f['refusals']) + ([rl.CELLS_NOT_MONOTONE] if mono else [])
    defects = list(f['defects']) + mono
    rung = f['rung']
    eff = _effective(rung, f['overrides'])
    floor = rl.rung_floor(rung)
    team = f['team_pattern']
    hc = ax.human_controls(team or 'solo_dev')
    state = _refusal_state(refusals) or rl.POLICY_RESOLVED
    routes = ROUTE_OF.get(state)
    if routes is None and f['weakenings']:
        routes = rl.PROCEED_WITH_ADVISORY
    return _blank(
        state, 'resolved at tier %s by %s; chain: %s' % (tier, basis, ', '.join(f['chain']) or 'kit default'),
        defects=defects, refusals=sorted(set(refusals)), routes_to=routes,
        environment=env_name, environment_tier=tier, team_pattern=team, rung_declared=rung,
        rung_effective=rung, policy_mode=rl.derive_policy_mode(rung), policy_mode_source='derived',
        policy_source=REGISTER if f['chain'] else KIT_DEFAULT, chain=f['chain'], scope=f['identity'],
        floor=floor, effective_minimum=dict((c, eff[c]) for c in rl.control_classes), job_minimums=dict((j, eff[j]) for j in JOBS),
        divergences=[{'control': c, 'floor': floor[c], 'effective': eff[c],
                      'direction': 'strengthening' if _rank(eff[c]) > _rank(floor[c]) else 'softening'}
                     for c in rl.control_classes if eff[c] != floor[c]],
        weakenings=f['weakenings'], human_controls=hc,
        unvalidated_human_workflow_paths=sorted(k for k, v in hc.items() if v == ax.HUMAN_CONTROL_UNVALIDATED),
        breach_authority=ax.breach_authority(team or 'solo_dev'), tier_behaviour=ax.tier_behaviour(tier),
        deploy_approval=dict((t, folds[t]['deploy_approval']) for t in rl.tier_order),
        secret_exceptions=f['secret_exceptions'], secret_exception_refusals=f['secret_exception_refusals'],
        max_exception_renewals=renewal_cap(central),
        numbers=dict((central or {}).get('numbers') or {}, **((repo_doc or {}).get('numbers') or {})))


# ── reading from git and from the kit ─────────────────────────────────────────────────────────

def _git(repo, *args):
    p = subprocess.run(['git', '-C', repo] + list(args), capture_output=True)
    return p.returncode, p.stdout, p.stderr.decode('utf-8', 'replace').strip()


def read_at_ref(repo, ref, path=default_registration_path):
    """-> (text or None, status 'readable'|'absent'|'unreadable', notes, sha). The BLOB at the ref."""
    rc, out, err = _git(repo, 'rev-parse', '--verify', '--quiet', '%s^{commit}' % ref)
    if rc != 0:
        return (None, 'unreadable', ['ref %r cannot be resolved (%s). Cannot read is not the default'
                                     % (ref, err or 'no such ref')], '')
    sha = out.decode().strip()
    rc, _o, _e = _git(repo, 'cat-file', '-e', '%s:%s' % (sha, path))
    if rc != 0:
        return (None, 'absent', ['no repository registration at %s:%s' % (ref, path)], sha)
    rc, out, err = _git(repo, 'show', '%s:%s' % (sha, path))
    if rc != 0:
        return (None, 'unreadable', ['cannot read %s:%s: %s' % (ref, path, err)], sha)
    return (out.decode('utf-8', 'replace'), 'readable', [], sha)


def read_central(path):
    if not path or not os.path.exists(path):
        return (None, 'absent', ['no central register at %s' % (path or '(none)')])
    try:
        return (io.open(path, encoding='utf-8').read(), 'readable', [])
    except (OSError, UnicodeDecodeError) as exc:
        return (None, 'unreadable', ['cannot read the central register %s: %s' % (path, exc)])


def resolve_from_ref(repo, default_ref, path, central_path, repository, environment, event,
                     supplied_inputs, today):
    sup = rl.refuse_supplied_policy_mode(dict(supplied_inputs or {}))
    if sup['state'] == rl.POLICY_MODE_SUPPLIED:
        return _blank(sup['state'], sup['why'], defects=[sup['why']])
    docs, notes = {}, []
    ctext, cstat, cnotes = read_central(central_path)
    rtext, rstat, rnotes, sha = read_at_ref(repo, default_ref, path)
    notes += cnotes + rnotes
    for origin, text, stat in ((ORIGIN_CENTRAL, ctext, cstat), (ORIGIN_REPOSITORY, rtext, rstat)):
        if stat == 'unreadable':
            return _blank(rl.REGISTRATION_UNAVAILABLE, 'the %s registration could not be read. Unreadable '
                          'is not the kit default: the input to enforcement is missing' % origin,
                          notes=notes, registration_ref=sha or None)
        if stat == 'readable':
            doc, problems = parse_registration(text, origin)
            if problems:
                state = _refusal_state([c for c, _m in problems])
                return _blank(state, 'the %s register is refused: %s' % (origin, problems[0][1]),
                              notes=notes + [m for _c, m in problems],
                              defects=[m for _c, m in problems], registration_ref=sha or None,
                              refusals=sorted(set(c for c, _m in problems)))
            docs[origin] = doc
    out = resolve(docs.get(ORIGIN_CENTRAL), docs.get(ORIGIN_REPOSITORY), repository, environment, event,
                  supplied_inputs, today)
    out['registration_ref'] = sha
    out['notes'] = notes + out['notes']
    return out


# ── CLI ───────────────────────────────────────────────────────────────────────────────────────

def github_output_lines(r):
    """Single-line values only; JSON is compact. Every key the gate's steps read."""
    v = lambda x: '' if x is None else str(x)  # noqa: E731
    out = []
    for k in ('state', 'routes_to', 'environment', 'environment_tier', 'team_pattern', 'rung_declared',
              'rung_effective', 'rung_divergence', 'policy_mode', 'policy_mode_source'):
        out.append('policy_%s=%s' % (k, v(r.get(k))))
    out.append('policy_effective_minimum=%s' % json.dumps(r['effective_minimum'], sort_keys=True))
    out.append('policy_divergences=%s' % json.dumps(r['divergences'], sort_keys=True))
    out.append('policy_weakenings=%s' % json.dumps(r['weakenings'], sort_keys=True))
    out.append('policy_unvalidated_human_workflow_paths=%s' % ','.join(r['unvalidated_human_workflow_paths']))
    out.append('policy_stops_on_evidence_untrusted=%s'
               % str(bool(r['tier_behaviour'].get('stops_on_evidence_untrusted', True))).lower())
    out.append('policy_source=%s' % v(r.get('policy_source')))
    out.append('policy_chain=%s' % ','.join(r.get('chain') or []))
    out.append('policy_job_minimums=%s' % ' '.join('%s=%s' % (j, r['job_minimums'][j])
                                                   for j in JOBS if j in r['job_minimums']))
    out.append('policy_refusals=%s' % ','.join(x for x in r.get('refusals') or [] if x != rl.POLICY_RESOLVED))
    out.append('policy_deploy_approval=%s' % json.dumps(r.get('deploy_approval') or {}, sort_keys=True))
    out.append('policy_registration_ref=%s' % v(r.get('registration_ref')))
    # The secret exceptions in force and the ones refused, by finding (owner ruling 2026-10-22).
    # Compact JSON of plain fields; the gate matches `finding` against the report's secret findings.
    # Each carries its history (KDEC-018 item 4): renewals and the "previously excepted ..." line.
    keep = ('finding', 'ticket', 'approver', 'expires', 'entry', 'renewals', 'history')
    out.append('policy_secret_exceptions=%s' % json.dumps(
        [dict((k, x.get(k, '')) for k in keep) for x in r.get('secret_exceptions') or []], sort_keys=True))
    out.append('policy_secret_exception_refusals=%s' % json.dumps(
        [dict((k, x.get(k, '')) for k in ('finding', 'ticket', 'entry', 'code', 'history'))
         for x in r.get('secret_exception_refusals') or []], sort_keys=True))
    # The authority's renewal cap, for the deploy's version-gap exception (it holds the stronger of
    # this and the kit default).
    out.append('policy_max_exception_renewals=%s' % v(r.get('max_exception_renewals')))
    return [line.replace('\n', ' ').replace('\r', ' ') for line in out]


def _selftest():
    fails = []
    r = resolve(None, None, 'o/r', 'prod', 'push', {}, '2026-10-22')
    if r['state'] != rl.POLICY_RESOLVED or r['policy_source'] != KIT_DEFAULT or r['rung_effective'] != 'crawl':
        fails.append('no register did not resolve to the kit default: %r' % r['why'])
    if r['job_minimums'].get('secret-scan') != 'BLOCKED' or r['job_minimums'].get('deps-scan') != 'PROCEED_WITH_ADVISORY':
        fails.append('the kit default is not "only secrets block"')
    if resolve(None, None, 'o/r', 'prod', 'push', {'policy_mode': 'x'}, '2026-10-22')['state'] != rl.POLICY_MODE_SUPPLIED:
        fails.append('a supplied policy_mode was not refused')
    _d, problems = parse_registration('{"schema_version": 2, "schema_version": 2}')
    if not any(c == POLICY_REGISTER_CONFLICT for c, _m in problems):
        fails.append('a duplicated key was not a conflict')
    if fails:
        for f in fails:
            sys.stderr.write('FAIL: %s\n' % f)
        return 2
    print('policy_registration selftest ok: no register is the kit default (only secrets block), a supplied '
          'policy_mode is refused, a duplicated key is a conflict. The full proof is '
          'tests/prove_policy_registration.py.')
    return 0


def main(argv=None):
    ap = argparse.ArgumentParser(description='Resolve, or validate, the enforcement policy register.')
    ap.add_argument('--self-test', action='store_true')
    ap.add_argument('--validate', default='', help='validate one register file and exit')
    ap.add_argument('--origin', default=ORIGIN_CENTRAL, choices=(ORIGIN_CENTRAL, ORIGIN_REPOSITORY))
    ap.add_argument('--repo', default='.')
    ap.add_argument('--default-ref', default='')
    ap.add_argument('--path', default=default_registration_path)
    ap.add_argument('--central', default=default_central_path)
    ap.add_argument('--repository', default=os.environ.get('GITHUB_REPOSITORY', ''))
    ap.add_argument('--environment', default='')
    ap.add_argument('--event', default='')
    ap.add_argument('--supplied', action='append', default=[],
                    help='key=value for every input the run RECEIVED (repeatable)')
    ap.add_argument('--supplied-json', default='',
                    help='toJSON(inputs): a JSON object of every input the run RECEIVED')
    ap.add_argument('--today', default='')
    ap.add_argument('--out', default='')
    ap.add_argument('--github-output', default='')
    a = ap.parse_args(argv)
    if a.self_test:
        return _selftest()
    today = a.today or datetime.date.today().isoformat()
    if a.validate:
        try:
            text = io.open(a.validate, encoding='utf-8').read()
        except (OSError, UnicodeDecodeError) as exc:
            print('REFUSED: cannot read %s: %s' % (a.validate, exc))
            return 1
        doc, problems = parse_registration(text, a.origin)
        if doc is not None:
            problems = validate(doc, a.origin, today)
        for c, m in problems:
            print('%s: %s' % (c, m))
        if problems:
            print('REFUSED: %d problem(s) in %s' % (len(problems), a.validate))
            return 1
        print('VALID: %s (%s register, %d entr%s, signed off by %s on %s)'
              % (a.validate, a.origin, len(doc['policies']), 'y' if len(doc['policies']) == 1 else 'ies',
                 doc['sign_off']['by'], doc['sign_off']['date']))
        return 0
    if not a.default_ref:
        print('--default-ref is required: the repository registration is read from the protected default '
              'branch, and there is no default for which branch that is', file=sys.stderr)
        return 2
    supplied = {}
    if a.supplied_json:
        try:
            obj = json.loads(a.supplied_json)
        except ValueError:
            obj = None
        if not isinstance(obj, dict):
            # The inputs could not be read, so whether policy_mode was among them is unknown.
            r = _blank(rl.REGISTRATION_UNAVAILABLE, '--supplied-json is not a JSON object: the inputs '
                       'this run received cannot be checked for a supplied policy_mode')
            if a.github_output:
                with io.open(a.github_output, 'a', encoding='utf-8') as fh:
                    for line in github_output_lines(r):
                        fh.write(line + '\n')
            print(r['state'] + '  ' + r['why'])
            return 1
        supplied.update(dict((str(k), '' if v is None else str(v)) for k, v in obj.items()))
    for kv in a.supplied:
        k, _sep, val = kv.partition('=')
        supplied[k.strip()] = val
    r = resolve_from_ref(a.repo, a.default_ref, a.path, a.central, a.repository, a.environment, a.event,
                         supplied, today)
    print('%s  routes_to=%s  source=%s tier=%s rung=%s policy_mode=%s chain=%s'
          % (r['state'], r['routes_to'], r['policy_source'], r['environment_tier'], r['rung_effective'],
             r['policy_mode'], ','.join(r['chain']) or '-'))
    print('  ' + r['why'])
    for n in r['notes'] + r['defects']:
        print('  ' + n)
    if a.out:
        with io.open(a.out, 'w', encoding='utf-8') as fh:
            json.dump(r, fh, indent=2, sort_keys=True)
    if a.github_output:
        with io.open(a.github_output, 'a', encoding='utf-8') as fh:
            for line in github_output_lines(r):
                fh.write(line + '\n')
    return 0 if r['state'] == rl.POLICY_RESOLVED else 1


if __name__ == '__main__':
    sys.exit(main())

#!/usr/bin/env python3
"""The organisation's governed kit settings: read from the org overlay inside the org's own kit copy.

WHY THIS EXISTS (owner rulings, 2026-11-07)
    GitHub resolves a secret or variable of the same name at the LOWEST level that has one: an
    environment value beats a repository value, which beats an organisation value (docs.github.com,
    "Variables reference" and "Secrets reference", retrieved 2026-11-07; docs/adoption/SETTINGS_PRECEDENCE.md).
    So a repository can SHADOW an organisation variable, and a job cannot tell which level a value came
    from. Settings that govern a production release -- who may approve it (the approver pools), whether a
    tiny team may approve its own deployment, the default adoption level, which Azure cloud each environment
    signs in to, and where tickets go -- must therefore come from a place a repository cannot write: the
    org overlay in the organisation's kit repository, read by the reusable workflow from its OWN checkout
    (the kit delivered by `$/`, or the kit checkout the rollback takes), at the commit the caller pins.
    A consumer's repository or environment value may only TIGHTEN a governed setting; one that loosens is
    refused by name (GOVERNED_SETTING_LOOSENED, in scripts/environment_protection.py).

WHERE THE OVERLAY LIVES
    overlays/<org>/kit-org-settings.json in the org's copy of the kit (schema `kit-org-settings/1`, below).
    The neutral kit ships none (a neutral fixture lives under tests/fixtures/org-overlay/ and a template at
    templates/kit-org-settings.example.json). The overlay whose `github_orgs` names the repository's owner
    applies; none is ORG_OVERLAY_ABSENT (the kit's behaviour without an overlay, unchanged); two is
    ORG_OVERLAY_AMBIGUOUS and an unreadable or invalid one ORG_OVERLAY_INVALID -- both refused at uat/prod.

THE FILE (every key but schema and github_orgs optional; unknown keys are refused)
    {"schema": "kit-org-settings/1",
     "github_orgs": ["example-org"],
     "host": "github.com" | "<tenant>.ghe.com",
     "approver_pools": {"platform": ["@example-org/platform-approvers"], "security": ["@example-org/security-approvers"]},
     "codeowners": {"governed_paths": ["/.github/workflows/", "/.kit/", "/id-mappings.json"], "owners": ["@example-org/..."]},
     "adoption": {"default_level": "crawl", "crawl_weeks_optimal": 4, "crawl_weeks_advisory": 8, "crawl_weeks_maximum": 26},
     "environment_classes": {"qa": "test"},
     "azure_clouds": {"declared": ["commercial", "gov"], "environments": {"prod": "gov", "example-org/app:uat": "gov"}},
     "ticket_routing": {"tracker": "jira", "project": "SEC", "tags": ["secure-cicd-kit"]},
     "escalation": {"owner_role": "platform on-call", "channel": "a ticket in the configured tracker, highest priority",
                    "service_level": "same business day"},   (KREQ-706: required at prod; deploy_contract.py)
     "app_teams": {"example-org/solo-app": {"team": "@example-org/solo-devs", "size": 1,
                   "small_team_self_approval": {"approved_by": "<role>", "ref": "SEC-1", "date": "YYYY-MM-DD",
                                                "reason": "...", "expires": "YYYY-MM-DD", "review_days": 90,
                                                "external_approver_group_available": false}}},
     "known_solo_developers": {"example-solo-account": ["example-solo-login"]},
     "repositories": {"example-org/app": {"adoption_level": "walk"}}}

SMALL-TEAM SELF-APPROVAL (a declared WEAKENING; owner 2026-11-07)
    For a team of two or fewer with no external approver group, uat/prod keep their required reviewers (the
    wait happens) but Prevent self-review may be off, so the developer approves their own deployment. Only
    the org overlay may declare it, with the five weakening fields (approved_by, ref, date, reason, expires),
    time-boxed by a review (review_days, default 90): SMALL_TEAM_SELF_APPROVAL in force; refused as
    _TEAM_TOO_LARGE (size > 2 or none), _POOLS_EXIST (the overlay names approver pools), _EXTERNAL_GROUP_AVAILABLE,
    _INCOMPLETE (a field missing or unreadable), _BEYOND_REVIEW (expires after date + review_days) or _EXPIRED.
    GitHub cannot let a pull request's author approve their own pull request ("Pull request authors cannot
    approve their own pull requests", docs.github.com, retrieved 2026-11-07), so this mode applies to
    DEPLOYMENTS only.
    NARROWED (owner 2026-11-07, same day): the mode is ONLY for KNOWN solo developers the org names, never inferred
    from a team size. `known_solo_developers` maps a GitHub account or org (the repository's owner) to the logins of
    its known solo developers; the app team must list `members`, every one of them a listed login of that owner.
    Anything else is SMALL_TEAM_SELF_APPROVAL_NOT_KNOWN_SOLO_DEVELOPER (refused).

AZURE CLOUD PER ENVIRONMENT (owner 2026-11-07; KIT_CLOUD is Azure-only)
    With an overlay that declares more than one Azure cloud, the cloud of a deploy's environment comes from
    the overlay's map (`<owner>/<repo>:<env>`, then `<env>`); an unmapped environment is
    AZURE_CLOUD_UNSET_FOR_ENVIRONMENT (refused), because an organisation-wide KIT_CLOUD would otherwise
    classify every tenant alike and the job cannot see which level a variable came from. The call's cloud
    and the environment's KIT_CLOUD (alias KIT_AZURE_CLOUD) must agree with it (AZURE_CLOUD_CONFLICTS_WITH_ORG).
    One declared cloud is the default for every environment. No overlay: the environment's KIT_CLOUD, else
    the call's input, else commercial. AWS jobs never read KIT_CLOUD (tests/check_kit_cloud_scope.py).

USAGE
    python3 org_settings.py resolve --kit-root DIR --repository O/R --environment ENV [--cloud C]
        [--bound-cloud B] [--azure] [--today YYYY-MM-DD] [--github-output FILE] [--github-env FILE]
    python3 org_settings.py validate FILE
    python3 org_settings.py --self-test           (the full proof: tests/prove_org_settings.py)
EXIT 0 resolved (or valid)   1 refused (a cloud the deploy must not sign in to, an invalid file)   2 usage
"""
import argparse
import datetime
import glob
import io
import json
import os
import re
import sys

SCHEMA = 'kit-org-settings/1'
OVERLAY_GLOB = os.path.join('overlays', '*', 'kit-org-settings.json')
APPLIED, ABSENT, INVALID, AMBIGUOUS = 'ORG_OVERLAY_APPLIED', 'ORG_OVERLAY_ABSENT', 'ORG_OVERLAY_INVALID', 'ORG_OVERLAY_AMBIGUOUS'
LOOSENED = 'GOVERNED_SETTING_LOOSENED'
LEVELS = ('crawl', 'walk', 'run')
TIERS = ('sandbox', 'dev', 'test', 'uat', 'prod')
CLOUDS = ('commercial', 'gov')
CLOUD_WORDS = {'commercial': 'commercial', 'public': 'commercial', 'azurecloud': 'commercial',
               'gov': 'gov', 'usgov': 'gov', 'government': 'gov', 'azureusgovernment': 'gov'}
ADOPTION_DEFAULTS = {'default_level': 'crawl', 'crawl_weeks_optimal': 4, 'crawl_weeks_advisory': 8,
                     'crawl_weeks_maximum': 26}
SMALL_TEAM_MAX = 2
REVIEW_DAYS_DEFAULT, REVIEW_DAYS_MAX = 90, 365
WEAKENING_FIELDS = ('approved_by', 'ref', 'date', 'reason', 'expires')

# small_team_self_approval (assurance-taxonomy.yaml)
ST_IN_FORCE = 'SMALL_TEAM_SELF_APPROVAL'
ST_NOT_DECLARED = 'SMALL_TEAM_SELF_APPROVAL_NOT_DECLARED'
ST_TOO_LARGE = 'SMALL_TEAM_SELF_APPROVAL_TEAM_TOO_LARGE'
ST_POOLS = 'SMALL_TEAM_SELF_APPROVAL_POOLS_EXIST'
ST_EXTERNAL = 'SMALL_TEAM_SELF_APPROVAL_EXTERNAL_GROUP_AVAILABLE'
ST_INCOMPLETE = 'SMALL_TEAM_SELF_APPROVAL_INCOMPLETE'
ST_BEYOND = 'SMALL_TEAM_SELF_APPROVAL_BEYOND_REVIEW'
ST_EXPIRED = 'SMALL_TEAM_SELF_APPROVAL_EXPIRED'
ST_NOT_ORG = 'SMALL_TEAM_SELF_APPROVAL_NOT_ORG_DECLARED'
ST_NOT_KNOWN_SOLO = 'SMALL_TEAM_SELF_APPROVAL_NOT_KNOWN_SOLO_DEVELOPER'
LOGIN_RX = re.compile(r'^@?[A-Za-z0-9](?:[A-Za-z0-9-]{0,38})$')

# azure_cloud (assurance-taxonomy.yaml)
AC_MAP = 'AZURE_CLOUD_FROM_ORG_MAP'
AC_SINGLE = 'AZURE_CLOUD_ORG_SINGLE'
AC_ENV = 'AZURE_CLOUD_FROM_ENVIRONMENT'
AC_INPUT = 'AZURE_CLOUD_FROM_INPUT'
AC_UNSET = 'AZURE_CLOUD_UNSET_FOR_ENVIRONMENT'
AC_CONFLICT = 'AZURE_CLOUD_CONFLICTS_WITH_ORG'
AC_UNKNOWN = 'AZURE_CLOUD_VALUE_UNKNOWN'
AC_NOT_ESTABLISHED = 'AZURE_CLOUD_NOT_ESTABLISHED'
AC_PERMITTED = (AC_MAP, AC_SINGLE, AC_ENV, AC_INPUT)

TOP_KEYS = {'schema', 'github_orgs', 'host', 'approver_pools', 'codeowners', 'adoption', 'environment_classes',
            'azure_clouds', 'ticket_routing', 'app_teams', 'known_solo_developers', 'repositories', 'dast',
            'escalation', 'note'}
DAST_REQUIRED, DAST_NOT_REQUIRED, DAST_NO_POLICY = 'DAST_REQUIRED', 'DAST_NOT_REQUIRED_BY_DECISION', 'DAST_NO_ORG_POLICY'
DAST_DECISION_FIELDS = ('approved_by', 'ref', 'date', 'reason')
PLACEHOLDER = re.compile(r'<[^>]*>|YOUR_ORG|your-org', re.I)
TEAM_RX = re.compile(r'^@?[A-Za-z0-9][A-Za-z0-9._-]*/[A-Za-z0-9][A-Za-z0-9._-]*$')
LOGIN_RX = re.compile(r'^@?[A-Za-z0-9][A-Za-z0-9-]{0,38}$')
DATE_RX = re.compile(r'^\d{4}-\d{2}-\d{2}$')


def norm(x):
    """A team or login as the kit compares it: no @, no org prefix, lower case."""
    return str(x or '').strip().lstrip('@').split('/')[-1].lower()


def cloud_word(v):
    """-> 'commercial' | 'gov' | '' (empty) | None (unrecognised)."""
    v = str(v or '').strip()
    if not v or v.lower() == 'auto':
        return ''
    return CLOUD_WORDS.get(v.lower())


def _date(s):
    if not isinstance(s, str) or not DATE_RX.match(s):
        return None
    try:
        return datetime.date(*[int(p) for p in s.split('-')])
    except ValueError:
        return None


def problems(doc):
    """-> [problem] for an overlay document (empty = valid). Never raises."""
    p = []
    if not isinstance(doc, dict):
        return ['the file is not a JSON object']
    if doc.get('schema') != SCHEMA:
        p.append('schema is %r, not %r' % (doc.get('schema'), SCHEMA))
    for k in sorted(set(doc) - TOP_KEYS):
        p.append('unknown key %r (the reader is an allowlist)' % k)
    orgs = doc.get('github_orgs')
    if not isinstance(orgs, list) or not orgs or any(not isinstance(o, str) or not o.strip() for o in orgs):
        p.append('github_orgs must be a non-empty list of organisation names')
    host = doc.get('host')
    if host is not None and not (host == 'github.com' or re.match(r'^[a-z0-9-]+\.ghe\.com$', str(host))):
        p.append('host %r is neither github.com nor <tenant>.ghe.com' % host)
    pools = doc.get('approver_pools')
    if pools is not None:
        if not isinstance(pools, dict) or set(pools) - {'platform', 'security'}:
            p.append('approver_pools must be {"platform": [...], "security": [...]}')
        else:
            for k, v in pools.items():
                if not isinstance(v, list) or any(not isinstance(t, str) or not TEAM_RX.match(t.strip()) for t in v):
                    p.append('approver_pools.%s must list GitHub team slugs (@org/team)' % k)
    co = doc.get('codeowners')
    if co is not None:
        if not isinstance(co, dict) or set(co) - {'governed_paths', 'owners'}:
            p.append('codeowners must be {"governed_paths": [...], "owners": [...]}')
        else:
            for t in co.get('owners') or []:
                if not isinstance(t, str) or not TEAM_RX.match(t.strip()):
                    p.append('codeowners.owners entry %r is not a team slug (@org/team)' % t)
            for g in co.get('governed_paths') or []:
                if not isinstance(g, str) or not g.startswith('/'):
                    p.append('codeowners.governed_paths entry %r must start with /' % g)
    ad = doc.get('adoption')
    if ad is not None:
        if not isinstance(ad, dict) or set(ad) - set(ADOPTION_DEFAULTS):
            p.append('adoption keys are %s' % ', '.join(sorted(ADOPTION_DEFAULTS)))
        else:
            if ad.get('default_level', 'crawl') not in LEVELS:
                p.append('adoption.default_level must be one of %s' % ', '.join(LEVELS))
            w = dict(ADOPTION_DEFAULTS, **{k: v for k, v in ad.items() if k != 'default_level'})
            if not all(isinstance(w[k], int) and w[k] > 0 for k in ('crawl_weeks_optimal', 'crawl_weeks_advisory',
                                                                      'crawl_weeks_maximum')):
                p.append('adoption crawl weeks must be positive integers')
            elif not (w['crawl_weeks_optimal'] <= w['crawl_weeks_advisory'] <= w['crawl_weeks_maximum'] <= 26):
                p.append('adoption crawl weeks must be optimal <= advisory <= maximum <= 26 (six months, the hard maximum)')
    ec = doc.get('environment_classes')
    if ec is not None and (not isinstance(ec, dict) or any(v not in TIERS for v in ec.values())):
        p.append('environment_classes values must be one of %s' % ', '.join(TIERS))
    ac = doc.get('azure_clouds')
    if ac is not None:
        if not isinstance(ac, dict) or set(ac) - {'declared', 'environments'}:
            p.append('azure_clouds must be {"declared": [...], "environments": {...}}')
        else:
            dec = ac.get('declared')
            if not isinstance(dec, list) or not dec or any(cloud_word(c) not in CLOUDS for c in dec):
                p.append('azure_clouds.declared must list commercial and/or gov')
            envs = ac.get('environments') or {}
            if not isinstance(envs, dict):
                p.append('azure_clouds.environments must map an environment to a cloud')
            else:
                for k, v in envs.items():
                    c = cloud_word(v)
                    if c not in CLOUDS:
                        p.append('azure_clouds.environments[%r] is %r, not commercial or gov' % (k, v))
                    elif isinstance(dec, list) and c not in [cloud_word(d) for d in dec]:
                        p.append('azure_clouds.environments[%r] names %s, which declared does not list' % (k, c))
    esc = doc.get('escalation')
    if esc is not None and (not isinstance(esc, dict) or set(esc) - {'owner_role', 'channel', 'service_level'} or
                            not all(isinstance(v, str) for v in esc.values())):
        p.append('escalation must be {"owner_role", "channel", "service_level"}, each a string (KREQ-706)')
    tr = doc.get('ticket_routing')
    if tr is not None:
        if not isinstance(tr, dict) or set(tr) - {'tracker', 'project', 'tags'}:
            p.append('ticket_routing must be {"tracker", "project", "tags"}')
        elif tr.get('tracker') not in (None, 'jira', 'azdo', 'github', 'freshservice'):
            p.append('ticket_routing.tracker %r is not jira, azdo, github or freshservice' % tr.get('tracker'))
        elif tr.get('tags') is not None and (not isinstance(tr['tags'], list) or
                                             any(not isinstance(t, str) or not t.strip() for t in tr['tags'])):
            p.append('ticket_routing.tags must be a list of strings')
    apps = doc.get('app_teams')
    if apps is not None:
        if not isinstance(apps, dict):
            p.append('app_teams must map owner/repo to an app team')
        else:
            for repo, e in apps.items():
                if not re.match(r'^[\w.-]+/[\w.-]+$', repo) or not isinstance(e, dict):
                    p.append('app_teams[%r] must be an owner/repo key with an object' % repo)
                    continue
                if set(e) - {'team', 'members', 'size', 'small_team_self_approval'}:
                    p.append('app_teams[%r] has unknown keys' % repo)
                if e.get('team') is not None and not TEAM_RX.match(str(e['team']).strip()):
                    p.append('app_teams[%r].team must be a team slug (@org/team)' % repo)
                if e.get('size') is not None and (not isinstance(e['size'], int) or e['size'] < 1):
                    p.append('app_teams[%r].size must be a positive integer' % repo)
    ksd = doc.get('known_solo_developers')
    if ksd is not None:
        if not isinstance(ksd, dict):
            p.append('known_solo_developers must map a GitHub account or org to a list of logins')
        else:
            for owner, logins in ksd.items():
                if not re.match(r'^[\w.-]+$', str(owner)) or not isinstance(logins, list) or not logins \
                        or any(not isinstance(x, str) or not LOGIN_RX.match(x.strip()) for x in logins):
                    p.append('known_solo_developers[%r] must be a non-empty list of GitHub logins' % owner)
    reps = doc.get('repositories')
    if reps is not None:
        if not isinstance(reps, dict):
            p.append('repositories must map owner/repo to settings')
        else:
            for repo, e in reps.items():
                if not isinstance(e, dict) or set(e) - {'adoption_level', 'dast_not_required'} or \
                        e.get('adoption_level', 'crawl') not in LEVELS:
                    p.append('repositories[%r] may hold only adoption_level (crawl, walk or run) and dast_not_required'
                             % repo)
                    continue
                dn = e.get('dast_not_required')
                if dn is not None and (not isinstance(dn, dict) or any(not str(dn.get(f) or '').strip()
                                                                      for f in DAST_DECISION_FIELDS)):
                    p.append('repositories[%r].dast_not_required needs approved_by, ref, date and reason' % repo)
    dp = doc.get('dast')
    if dp is not None and (not isinstance(dp, dict) or set(dp) - {'required'} or not isinstance(dp.get('required'), bool)):
        p.append('dast must be {"required": true | false}')
    return p


def placeholders(doc):
    """-> [where] a template placeholder (<...>, YOUR_ORG) is still in the overlay."""
    out = []

    def walk(x, path):
        if isinstance(x, dict):
            for k, v in x.items():
                if path == '' and k == 'note':   # free text about the file, never a setting
                    continue
                if isinstance(k, str) and PLACEHOLDER.search(k):
                    out.append(path + '/' + k)
                walk(v, path + '/' + str(k))
        elif isinstance(x, list):
            for i, v in enumerate(x):
                walk(v, '%s[%d]' % (path, i))
        elif isinstance(x, str) and PLACEHOLDER.search(x):
            out.append(path)
    walk(doc, '')
    return out


def load(kit_root, owner):
    """-> (doc or None, state, source path or '', why). Picks the overlay whose github_orgs names `owner`."""
    found = []
    bad = []
    for path in sorted(glob.glob(os.path.join(kit_root, OVERLAY_GLOB))):
        rel = os.path.relpath(path, kit_root).replace(os.sep, '/')
        try:
            with io.open(path, encoding='utf-8') as fh:
                doc = json.load(fh)
        except (OSError, ValueError) as exc:
            bad.append((rel, 'unreadable (%s)' % type(exc).__name__))
            continue
        orgs = doc.get('github_orgs') if isinstance(doc, dict) else None
        if isinstance(orgs, list) and any(str(o).strip().lower() == (owner or '').strip().lower() for o in orgs):
            found.append((rel, doc))
    if len(found) > 1:
        return None, AMBIGUOUS, ', '.join(r for r, _d in found), ('%d overlays name the organisation %r: %s; one '
                                                                   'organisation has one overlay' % (len(found), owner,
                                                                   ', '.join(r for r, _d in found)))
    if not found:
        if bad:
            return None, INVALID, bad[0][0], 'the overlay %s is %s, so whether it governs %r is unknown' % (bad[0][0], bad[0][1], owner)
        return None, ABSENT, '', 'no overlay in this kit copy names the organisation %r' % owner
    rel, doc = found[0]
    probs = problems(doc)
    if probs:
        return None, INVALID, rel, '%s: %s' % (rel, '; '.join(probs[:4]))
    return doc, APPLIED, rel, 'the org overlay %s governs %r' % (rel, owner)


def pools_of(doc):
    """-> sorted team slugs (normalised) of the overlay's approver pools, [] when none."""
    pools = (doc or {}).get('approver_pools') or {}
    return sorted({norm(t) for v in pools.values() for t in (v or []) if norm(t)})


def dast_policy(doc, repo):
    """-> {'state', 'why', 'record'}: whether a lower-environment DAST result is required before promotion."""
    per = (((doc or {}).get('repositories') or {}).get(repo) or {}).get('dast_not_required')
    if isinstance(per, dict) and all(str(per.get(f) or '').strip() for f in DAST_DECISION_FIELDS):
        return {'state': DAST_NOT_REQUIRED, 'record': {f: per[f] for f in DAST_DECISION_FIELDS},
                'why': 'DAST not required for %s: decided by %s (%s, %s): %s' % (
                    repo, per['approved_by'], per['ref'], per['date'], per['reason'])}
    if ((doc or {}).get('dast') or {}).get('required') is True:
        return {'state': DAST_REQUIRED, 'record': None,
                'why': 'the org overlay requires a lower-environment DAST result before promotion'}
    return {'state': DAST_NO_POLICY, 'record': None, 'why': 'no org overlay policy requires DAST (KDEC-029: where configured)'}


def adoption(doc, repo):
    """-> the adoption settings for `repo`: crawl unless the overlay says otherwise."""
    ad = dict(ADOPTION_DEFAULTS, **((doc or {}).get('adoption') or {}))
    per = ((doc or {}).get('repositories') or {}).get(repo) or {}
    if per.get('adoption_level'):
        ad['default_level'] = per['adoption_level']
        ad['source'] = 'org overlay repositories[%s]' % repo
    else:
        ad['source'] = 'org overlay adoption' if (doc or {}).get('adoption') else 'kit default (crawl)'
    return ad


def crawl_clock(started_on, today, ad=None):
    """-> (state, weeks). CRAWL_ON_TRACK < optimal <= CRAWL_PAST_OPTIMAL < advisory <= CRAWL_ADVISORY < maximum
    <= CRAWL_MAXIMUM_ESCALATE. Nothing promotes or extends by itself: past the maximum a person decides."""
    ad = dict(ADOPTION_DEFAULTS, **(ad or {}))
    s, t = _date(started_on), _date(today) if isinstance(today, str) else today
    if not s or not t or s > t:
        return 'CRAWL_START_UNKNOWN', None
    weeks = (t - s).days // 7
    if weeks >= ad['crawl_weeks_maximum']:
        return 'CRAWL_MAXIMUM_ESCALATE', weeks
    if weeks >= ad['crawl_weeks_advisory']:
        return 'CRAWL_ADVISORY', weeks
    if weeks >= ad['crawl_weeks_optimal']:
        return 'CRAWL_PAST_OPTIMAL', weeks
    return 'CRAWL_ON_TRACK', weeks


def app_team(doc, repo):
    e = ((doc or {}).get('app_teams') or {}).get(repo)
    if not isinstance(e, dict) or not e.get('team'):
        return None
    mem = e.get('members')
    return {'team': norm(e['team']), 'members': sorted(norm(m) for m in mem) if isinstance(mem, list) else None,
            'size': e.get('size')}


def small_team(doc, repo, today):
    """-> (state, record or None, why). Only an org overlay declares the mode."""
    e = ((doc or {}).get('app_teams') or {}).get(repo) or {}
    rec = e.get('small_team_self_approval') if isinstance(e, dict) else None
    if not rec:
        return ST_NOT_DECLARED, None, 'the org overlay declares no small-team self-approval for %s' % repo
    if not isinstance(rec, dict):
        return ST_INCOMPLETE, None, 'small_team_self_approval for %s is not an object' % repo
    ksd = (doc or {}).get('known_solo_developers')
    known = {str(k).strip().lower(): {str(x).strip().lstrip('@').lower() for x in v}
             for k, v in ksd.items() if isinstance(v, list)} if isinstance(ksd, dict) else {}
    listed = known.get(repo.split('/', 1)[0].strip().lower())
    mem = e.get('members')
    if not listed or not isinstance(mem, list) or not mem \
            or any(str(m).strip().lstrip('@').lower() not in listed for m in mem):
        return ST_NOT_KNOWN_SOLO, rec, ('self-approval is only for known solo developers the org names: %s is not under '
                                        'an account or org in known_solo_developers, or its app team members are not '
                                        'all listed developers of that owner' % repo)
    if pools_of(doc):
        return ST_POOLS, rec, ('the org overlay names approver pools (%s), so an external approver group exists and '
                               'the team may not approve itself' % ', '.join(pools_of(doc)))
    size = e.get('size')
    if not isinstance(size, int) or size < 1:
        return ST_INCOMPLETE, rec, 'the app team of %s declares no size' % repo
    if size > SMALL_TEAM_MAX:
        return ST_TOO_LARGE, rec, 'the app team of %s has %d people; the mode is for %d or fewer' % (repo, size, SMALL_TEAM_MAX)
    if rec.get('external_approver_group_available') is not False:
        return ST_EXTERNAL, rec, ('the declaration does not say external_approver_group_available: false, so an '
                                  'external approver is presumed available')
    missing = [f for f in WEAKENING_FIELDS if not str(rec.get(f) or '').strip() or PLACEHOLDER.search(str(rec.get(f)))]
    if missing:
        return ST_INCOMPLETE, rec, 'the weakening record lacks %s (all five are required)' % ', '.join(missing)
    d, x = _date(rec.get('date')), _date(rec.get('expires'))
    rd = rec.get('review_days', REVIEW_DAYS_DEFAULT)
    if not d or not x or not isinstance(rd, int) or not 1 <= rd <= REVIEW_DAYS_MAX or x < d:
        return ST_INCOMPLETE, rec, 'date, expires or review_days (1..%d) is unreadable' % REVIEW_DAYS_MAX
    t = _date(today) if isinstance(today, str) else today
    if t and d > t:
        return ST_INCOMPLETE, rec, 'the weakening is dated %s, in the future' % rec['date']
    if (x - d).days > rd:
        return ST_BEYOND, rec, ('it expires %s, %d days after it was approved; the review is due within %d days'
                                % (rec['expires'], (x - d).days, rd))
    if t and x < t:
        return ST_EXPIRED, rec, 'it expired on %s; renew it in the org overlay after a review' % rec['expires']
    return ST_IN_FORCE, rec, ('the developer may approve their own deployment of %s: a declared weakening approved '
                              'by %s (%s, %s), reason: %s; expires %s' % (repo, rec['approved_by'], rec['ref'],
                                                                         rec['date'], rec['reason'], rec['expires']))


def azure_cloud(doc, state, repo, environment, given, bound):
    """-> (cloud or '', state, why). `given` is the call's cloud input, `bound` the job's KIT_CLOUD."""
    g, b = cloud_word(given), cloud_word(bound)
    if g is None or b is None:
        return '', AC_UNKNOWN, ('the cloud %r is neither commercial nor gov' % (given if g is None else bound))
    if state in (INVALID, AMBIGUOUS):
        return '', AC_NOT_ESTABLISHED, 'the org overlay could not be read, so the clouds it declares are unknown'
    ac = (doc or {}).get('azure_clouds') if state == APPLIED else None
    if not ac:
        if b:
            return b, AC_ENV, 'the environment\'s KIT_CLOUD (no org overlay declares clouds)'
        return g or 'commercial', AC_INPUT, 'the call\'s cloud input%s (no org overlay declares clouds)' % (
            '' if g else ', empty: commercial')
    declared = sorted({cloud_word(c) for c in ac.get('declared') or []})
    envs = {k: cloud_word(v) for k, v in (ac.get('environments') or {}).items()}
    key = '%s:%s' % (repo, environment)
    mapped = envs.get(key) or envs.get(environment)
    src = key if envs.get(key) else environment
    if mapped:
        cloud, st, why = mapped, AC_MAP, 'the org overlay maps %s to %s' % (src, mapped)
    elif len(declared) == 1:
        cloud, st, why = declared[0], AC_SINGLE, 'the org overlay declares one Azure cloud, %s' % declared[0]
    else:
        return '', AC_UNSET, ('the org overlay declares %s, and maps neither %s nor %s, so this environment\'s cloud is '
                              'unknown; an organisation-wide KIT_CLOUD cannot decide it' % (' and '.join(declared), key,
                                                                                            environment))
    for what, v in (('the call\'s cloud input', g), ('the environment\'s KIT_CLOUD', b)):
        if v and v != cloud:
            return '', AC_CONFLICT, '%s is %s, and %s' % (what, v, why)
    return cloud, st, why


def resolve(kit_root, repo, environment, given='', bound='', today=None):
    """-> dict: everything the deploy reads from the org overlay for one repository and environment."""
    owner = (repo or '').split('/')[0]
    doc, state, source, why = load(kit_root, owner)
    today = today or datetime.date.today().isoformat()
    out = {'schema': 'kit-org-settings-resolved/1', 'state': state, 'source': source, 'why': why,
           'repository': repo, 'environment': environment}
    if state == APPLIED:
        out['pools'] = pools_of(doc)
        out['app_team'] = app_team(doc, repo)
        st, rec, swhy = small_team(doc, repo, today)
        out['small_team'] = {'state': st, 'why': swhy,
                             'record': {k: rec.get(k) for k in WEAKENING_FIELDS + ('review_days',)} if isinstance(rec, dict) else None}
        out['classes'] = dict(doc.get('environment_classes') or {})
        out['adoption'] = adoption(doc, repo)
        out['ticket_routing'] = doc.get('ticket_routing')
        out['dast'] = dast_policy(doc, repo)
        out['escalation'] = doc.get('escalation')
    cloud, cst, cwhy = azure_cloud(doc, state, repo, environment, given, bound)
    out['azure_cloud'] = {'cloud': cloud, 'state': cst, 'why': cwhy}
    return out


def _write(path, pairs):
    if path:
        with io.open(path, 'a', encoding='utf-8') as fh:
            for k, v in pairs:
                fh.write('%s=%s\n' % (k, str(v).replace('\n', ' ')))


def _emit(**kv):
    """One line per value to the step's GITHUB_OUTPUT file (--github-output); `_path` names the file."""
    _write(kv.pop('_path', ''), list(kv.items()))


def cmd_resolve(a):
    r = resolve(a.kit_root, a.repository, a.environment, a.cloud, a.bound_cloud, a.today)
    compact = json.dumps(r, sort_keys=True, separators=(',', ':'))
    ac = r['azure_cloud']
    st = (r.get('small_team') or {}).get('state', ST_NOT_DECLARED)
    print('org_settings=%s source=%s' % (r['state'], r['source'] or '-'))
    print('  ' + r['why'])
    print('azure_cloud=%s cloud=%s' % (ac['state'], ac['cloud'] or '-'))
    print('  ' + ac['why'])
    print('small_team_self_approval=%s' % st)
    _emit(_path=a.github_output, org_settings=compact, org_settings_state=r['state'], azure_cloud=ac['cloud'],
          azure_cloud_state=ac['state'], small_team_self_approval=st)
    refused = a.azure and ac['state'] not in AC_PERMITTED
    summ = os.environ.get('GITHUB_STEP_SUMMARY')
    if summ:
        lines = ['### Org governed settings (the org overlay in the kit copy)', '',
                 '`%s`: %s.' % (r['state'], r['why'])]
        if a.azure:
            lines.append('Azure cloud `%s` (`%s`): %s.' % (ac['cloud'] or 'none', ac['state'], ac['why']))
        if st == ST_IN_FORCE:
            lines.append('**SMALL_TEAM_SELF_APPROVAL**: %s. This is a declared weakening, time-boxed for review.'
                         % r['small_team']['why'])
        elif st != ST_NOT_DECLARED:
            lines.append('Small-team self-approval is declared but not in force (`%s`): %s.' % (st, r['small_team']['why']))
        with io.open(summ, 'a', encoding='utf-8') as fh:
            fh.write('\n'.join(lines) + '\n')
    if not refused and a.azure and a.github_env:
        _write(a.github_env, [('CLOUD', ac['cloud'])])
    if refused:
        print('::error title=Deploy refused before login (Azure cloud)::%s: %s. Map this environment to its cloud '
              'in the org overlay (azure_clouds.environments), or make the call and KIT_CLOUD agree with it '
              '(docs/adoption/SETTINGS_PRECEDENCE.md); nothing was deployed.' % (ac['state'], ac['why']))
        return 1
    return 0


def _selftest():
    fails = []
    base = {'schema': SCHEMA, 'github_orgs': ['o']}
    if problems(base):
        fails.append('a minimal overlay was refused: %r' % problems(base))
    if not problems(dict(base, surprise=1)):
        fails.append('an unknown key was accepted')
    rec = {'approved_by': 'security lead', 'ref': 'SEC-1', 'date': '2026-11-01', 'reason': 'two developers, no pool',
           'expires': '2027-01-30', 'external_approver_group_available': False}
    doc = dict(base, known_solo_developers={'o': ['dev1', 'dev2']},
               app_teams={'o/r': {'team': '@o/devs', 'size': 2, 'members': ['@dev1', 'dev2'],
                                  'small_team_self_approval': rec}})
    for got, want in ((small_team(doc, 'o/r', '2026-11-07')[0], ST_IN_FORCE),
                      (small_team(dict(doc, approver_pools={'security': ['@o/sec']}), 'o/r', '2026-11-07')[0], ST_POOLS),
                      (small_team(doc, 'o/r', '2027-02-01')[0], ST_EXPIRED),
                      (small_team(dict(doc, known_solo_developers={'x': ['dev1']}), 'o/r', '2026-11-07')[0],
                       ST_NOT_KNOWN_SOLO),
                      (azure_cloud(dict(base, azure_clouds={'declared': ['commercial', 'gov']}), APPLIED, 'o/r', 'prod',
                                   'gov', '')[1], AC_UNSET),
                      (azure_cloud(None, ABSENT, 'o/r', 'prod', '', '')[0], 'commercial')):
        if got != want:
            fails.append('%s, expected %s' % (got, want))
    for f in fails:
        sys.stderr.write('FAIL: %s\n' % f)
    if fails:
        return 2
    print('org_settings selftest ok. The full proof is tests/prove_org_settings.py.')
    return 0


def main(argv=None):
    argv = list(sys.argv[1:] if argv is None else argv)
    if argv[:1] == ['--self-test']:
        return _selftest()
    ap = argparse.ArgumentParser(description=__doc__.split('\n')[0])
    sub = ap.add_subparsers(dest='cmd', required=True)
    r = sub.add_parser('resolve')
    r.add_argument('--kit-root', required=True)
    r.add_argument('--repository', default=os.environ.get('GITHUB_REPOSITORY', ''))
    r.add_argument('--environment', default='')
    r.add_argument('--cloud', default='')
    r.add_argument('--bound-cloud', default='')
    r.add_argument('--azure', action='store_true', help='an Azure sign-in follows: refuse a cloud it must not use')
    r.add_argument('--today', default=None)
    r.add_argument('--github-output', default='')
    r.add_argument('--github-env', default='')
    v = sub.add_parser('validate')
    v.add_argument('file')
    a = ap.parse_args(argv)
    if a.cmd == 'validate':
        try:
            with io.open(a.file, encoding='utf-8') as fh:
                doc = json.load(fh)
        except (OSError, ValueError) as exc:
            print('ORG_OVERLAY_INVALID: %s is unreadable (%s)' % (a.file, exc))
            return 1
        probs = problems(doc) + ['a template placeholder is still at %s' % w for w in placeholders(doc)]
        for p in probs:
            print('ORG_OVERLAY_INVALID: %s' % p)
        if not probs:
            print('valid: %s is a readable org overlay' % a.file)
        return 1 if probs else 0
    return cmd_resolve(a)


if __name__ == '__main__':
    sys.exit(main())

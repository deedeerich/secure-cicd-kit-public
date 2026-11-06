#!/usr/bin/env python3
"""Read back the deployment protection of the GitHub environment a deploy runs in, and say whether
it is what the policy demands. Read-only; refuses before login at uat and prod. (owner, 2026-10-22)

WHY

    KDEC-014 made the uat/prod environment's REQUIRED REVIEWERS half of every exception, and the
    owner's single-developer rule makes them the control itself: a prod or uat deploy needs ONE
    approver from a named reviewer group (architect / security / platform) who is NOT the deploying
    developer -- GitHub environment required reviewers with self-review prevented. The kit cannot SET
    that, but it can READ it (GET /repos/{owner}/{repo}/environments/{name}, which anyone with read
    access may call). A deploy to an unprotected prod environment is a real gap, so it is refused.

WHAT IS DEMANDED (per tier)

    The security gate emits `deploy_approval` (the policy register's per-tier demand, or the kit
    default) and the caller passes it to the deploy. The deploy holds the STRONGER of that and the
    kit default for the tier, because it cannot tell a value the gate emitted from one a caller typed:
    uat and prod always demand at least one required reviewer with self-review prevented. Approver
    groups, when named, are a tightening and are honoured.

OUTCOMES (environment_protection in assurance-taxonomy.yaml)

    ENVIRONMENT_PROTECTION_VERIFIED        the environment's reviewer rule satisfies the demand
    ENVIRONMENT_PROTECTION_NOT_REQUIRED    nothing is demanded at this tier (below uat by default)
    ENVIRONMENT_REVIEWERS_ABSENT           no required-reviewer rule, or one with no reviewers
    ENVIRONMENT_SELF_REVIEW_ALLOWED        self-review must be prevented and is not
    ENVIRONMENT_APPROVER_GROUP_MISSING     named groups are demanded and a reviewer outside them
                                           (or no reviewer from them) could approve
    ENVIRONMENT_PROTECTION_NOT_ESTABLISHED the API could not be read, or the demand could not be

    At uat and prod anything but VERIFIED or NOT_REQUIRED refuses the deploy before login. Below
    uat it is recorded and warned, never refused.

USAGE
    python3 environment_protection.py --repository owner/name --environment NAME --tier TIER \
        [--demand-json JSON] [--api-url URL] [--github-output FILE]      (token: $GH_TOKEN)
    python3 environment_protection.py --self-test

EXIT 0 permitted   1 refused   2 usage or self-test failure
"""
import argparse
import json
import os
import sys
import urllib.parse
import urllib.request

PRODUCTION_TIERS = ('uat', 'prod')
TIERS = ('sandbox', 'dev', 'test', 'uat', 'prod')
VERIFIED = 'ENVIRONMENT_PROTECTION_VERIFIED'
NOT_REQUIRED = 'ENVIRONMENT_PROTECTION_NOT_REQUIRED'
REVIEWERS_ABSENT = 'ENVIRONMENT_REVIEWERS_ABSENT'
SELF_REVIEW_ALLOWED = 'ENVIRONMENT_SELF_REVIEW_ALLOWED'
GROUP_MISSING = 'ENVIRONMENT_APPROVER_GROUP_MISSING'
NOT_ESTABLISHED = 'ENVIRONMENT_PROTECTION_NOT_ESTABLISHED'
PERMITTED = (VERIFIED, NOT_REQUIRED)


def default_demand(tier):
    prod = tier in PRODUCTION_TIERS
    return {'approver_groups': [], 'approvers_required': 1 if prod else 0,
            'self_review_prevented': 'required' if prod else 'not_required'}


def demand_for(tier, demand_json):
    """-> (demand, note). The stronger of the supplied demand and the kit default; None when the
    supplied value cannot be read (the demand is then not established)."""
    base = default_demand(tier)
    if not (demand_json or '').strip():
        return base, 'no deploy_approval was passed; the kit default for %s applies' % tier
    try:
        doc = json.loads(demand_json)
    except ValueError:
        return None, 'deploy_approval is not JSON'
    if not isinstance(doc, dict):
        return None, 'deploy_approval is not a JSON object'
    sup = doc.get(tier, {}) if any(k in TIERS for k in doc) else doc
    if not isinstance(sup, dict):
        return None, 'deploy_approval[%s] is not an object' % tier
    groups = sup.get('approver_groups') or []
    if not isinstance(groups, list) or any(not isinstance(g, str) or not g.strip() for g in groups):
        return None, 'deploy_approval approver_groups is not a list of names'
    req = sup.get('approvers_required', 0)
    out = {'approver_groups': sorted(g.strip() for g in groups),
           'approvers_required': max(base['approvers_required'], 1 if req == 1 else 0),
           'self_review_prevented': 'required' if 'required' in (base['self_review_prevented'],
                                                                 sup.get('self_review_prevented')) else 'not_required'}
    if out['approver_groups'] and not out['approvers_required']:
        out['approvers_required'] = 1
    note = 'the stronger of the passed deploy_approval and the kit default for %s' % tier
    return out, note


def evaluate(env_doc, demand):
    """-> (outcome, why). `env_doc`: the parsed API answer, or None when it could not be read."""
    if demand is None:
        return NOT_ESTABLISHED, 'the policy\'s deploy approval could not be read, so what to verify is unknown'
    if not demand['approvers_required'] and demand['self_review_prevented'] != 'required':
        return NOT_REQUIRED, 'no required reviewer is demanded at this tier'
    if not isinstance(env_doc, dict):
        return NOT_ESTABLISHED, 'the environment\'s protection rules could not be read'
    rules = env_doc.get('protection_rules')
    if not isinstance(rules, list):
        return NOT_ESTABLISHED, 'the API answer carries no protection_rules list'
    rv = [r for r in rules if isinstance(r, dict) and (r.get('type') == 'required_reviewers' or 'reviewers' in r)]
    reviewers = [x for r in rv for x in (r.get('reviewers') or []) if isinstance(x, dict)]
    if not reviewers:
        return REVIEWERS_ABSENT, 'the environment has no required reviewers: anyone who can run the workflow deploys'
    if demand['self_review_prevented'] == 'required' and not all(r.get('prevent_self_review') is True for r in rv):
        return SELF_REVIEW_ALLOWED, ('the environment lets the person who started the deploy approve it '
                                     '(prevent_self_review is off)')
    groups = set(g.lower() for g in demand['approver_groups'])
    if groups:
        outside, inside = [], 0
        for x in reviewers:
            who = x.get('reviewer') or {}
            names = set(str(who.get(k, '')).lower() for k in ('slug', 'name')) - {''}
            if x.get('type') == 'Team' and names & groups:
                inside += 1
            else:
                outside.append(str(who.get('slug') or who.get('login') or who.get('name') or '?'))
        if outside or not inside:
            return GROUP_MISSING, ('a reviewer outside the named groups (%s) could approve: %s'
                                   % (', '.join(sorted(groups)), ', '.join(sorted(outside)) or 'none from them'))
    return VERIFIED, 'required reviewers%s, self-review %s' % (
        ' from %s' % ', '.join(sorted(groups)) if groups else '',
        'prevented' if all(r.get('prevent_self_review') is True for r in rv) else 'not demanded')


def fetch(api_url, repository, environment, token):
    url = '%s/repos/%s/environments/%s' % (api_url.rstrip('/'), repository, urllib.parse.quote(environment, safe=''))
    req = urllib.request.Request(url, headers={'Accept': 'application/vnd.github+json',
                                               'X-GitHub-Api-Version': '2022-11-28'})
    if token and url.startswith('https://'):
        req.add_header('Authorization', 'Bearer %s' % token)
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            return json.loads(resp.read().decode('utf-8')), None
    except Exception as exc:  # noqa: BLE001 -- any failure is "could not read", never a pass
        return None, 'GET %s failed: %s' % (url.split('?')[0], type(exc).__name__)


def _selftest():
    fails = []
    prot = {'protection_rules': [{'type': 'required_reviewers', 'prevent_self_review': True,
                                  'reviewers': [{'type': 'Team', 'reviewer': {'slug': 'security', 'name': 'Security'}}]}]}
    d, _n = demand_for('prod', '')
    if evaluate(prot, d)[0] != VERIFIED:
        fails.append('a protected prod environment was not VERIFIED')
    if evaluate({'protection_rules': []}, d)[0] != REVIEWERS_ABSENT:
        fails.append('an unprotected prod environment was not REVIEWERS_ABSENT')
    if evaluate(None, d)[0] != NOT_ESTABLISHED:
        fails.append('an unreadable answer was not NOT_ESTABLISHED')
    d, _n = demand_for('prod', json.dumps({'prod': {'approvers_required': 0, 'self_review_prevented': 'not_required'}}))
    if d['approvers_required'] != 1:
        fails.append('a passed demand weakened the prod default')
    if fails:
        for f in fails:
            sys.stderr.write('FAIL: %s\n' % f)
        return 2
    print('environment_protection selftest ok. The full proof is tests/prove_deploy_environment_protection.py.')
    return 0


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.split('\n')[0])
    ap.add_argument('--self-test', action='store_true')
    ap.add_argument('--repository', default=os.environ.get('GITHUB_REPOSITORY', ''))
    ap.add_argument('--environment', default='')
    ap.add_argument('--tier', default='')
    ap.add_argument('--demand-json', default='')
    ap.add_argument('--api-url', default=os.environ.get('GITHUB_API_URL', 'https://api.github.com'))
    ap.add_argument('--github-output', default='')
    a = ap.parse_args(argv)
    if a.self_test:
        return _selftest()
    tier = a.tier.strip()
    demand, note = demand_for(tier, a.demand_json)
    if tier not in TIERS:
        # A tier nobody can name cannot be shown to be below production.
        outcome, why = NOT_ESTABLISHED, 'environment_tier %r is not a registered tier' % tier
    elif demand is not None and not demand['approvers_required'] and demand['self_review_prevented'] != 'required':
        outcome, why = evaluate(None, demand)
    elif not a.environment.strip() or not a.repository.strip():
        outcome, why = NOT_ESTABLISHED, 'no GitHub environment (or repository) is named, so none can be read'
    else:
        doc, err = fetch(a.api_url, a.repository, a.environment, os.environ.get('GH_TOKEN', ''))
        outcome, why = evaluate(doc, demand)
        if err:
            why = '%s (%s)' % (why, err)
    refused = outcome not in PERMITTED and (tier in PRODUCTION_TIERS or tier not in TIERS)
    print('environment_protection=%s tier=%s refused=%s' % (outcome, tier or '(none)', str(refused).lower()))
    print('  ' + why)
    print('  demand: %s (%s)' % (json.dumps(demand, sort_keys=True), note))
    if a.github_output:
        with open(a.github_output, 'a', encoding='utf-8') as fh:
            fh.write('environment_protection=%s\n' % outcome)
            fh.write('environment_protection_refused=%s\n' % str(refused).lower())
            fh.write('environment_protection_why=%s\n' % why.replace('\n', ' '))
    return 1 if refused else 0


if __name__ == '__main__':
    sys.exit(main())

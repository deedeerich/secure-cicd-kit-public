#!/usr/bin/env python3
"""Read back the protection of the GitHub environment a deploy runs in; refuse an ungated uat or prod.

WHY (owner, 2026-10-22 and 2026-11-06: "never a prod deployment without a human approval")
    uat and prod are production environments. A person from the platform or security pool, never the
    deployer, approves every release there -- even when someone pushes straight to main. The kit cannot
    SET an environment's reviewers; it READS them (GET /repos/{o}/{r}/environments/{env} on the run's own
    API host, GITHUB_API_URL, so GHE.com is served: KDEC-027) and refuses before any cloud login. dev and
    test are not gated. docs/adoption/BRANCH_PROTECTION_SETTINGS.md section 6; KDEC-042.

CLASSING (which environments are gated)
    The class is the STRONGEST of: the bound tier (environment_tier, vended or passed), the explicit class
    in the caller's .kit/environments.json (read through the contents API at GITHUB_SHA), and the name
    (a uat/stage/staging/preprod/prod/production/prd word gates; dev/development/sandbox/test/testing do
    not). An explicit class names what the pattern cannot and may raise a name; it never lowers one,
    because a push to main can edit that file. No name, or a name nothing classes: ENVIRONMENT_UNCLASSED,
    refused at every tier until .kit/environments.json classes it. An unreadable file is NOT_ESTABLISHED.

AT uat AND prod THE ENVIRONMENT MUST (each a named refusal; environment_protection in the taxonomy)
    exist (NOT_FOUND); carry a required-reviewers rule (REVIEWERS_ABSENT) with reviewers in it
    (REVIEWERS_EMPTY); prevent self-review (SELF_REVIEW_ALLOWED); hold the deploy_approval groups when
    named (ENVIRONMENT_APPROVER_GROUP_MISSING); include a platform or security pool reviewer when pools are named in
    vars.KIT_APPROVER_POOLS or .kit/settings.json approver_pools (ENVIRONMENT_APPROVER_POOL_MISSING); and not be
    approvable by the app team alone when vars.KIT_APP_TEAM or .kit/settings.json app_team names it
    (ENVIRONMENT_APPROVERS_ALL_APP_TEAM). Membership the kit cannot read is app_team_check=NOT_ESTABLISHED: recorded,
    never invented, and the decision rests on the environment's rules. Unreadable rules: NOT_ESTABLISHED,
    refused. A variable wins over the settings file (a push cannot edit a variable).

USAGE
    python3 environment_protection.py --repository o/r --environment NAME --tier TIER [--demand-json J]
        [--ref SHA] [--api-url URL] [--github-output FILE]   (token $GH_TOKEN; $KIT_APPROVER_POOLS, $KIT_APP_TEAM)
    python3 environment_protection.py --self-test        (the full proof: tests/prove_uat_prod_gating.py)
EXIT 0 permitted   1 refused   2 usage or self-test failure
"""
import argparse
import base64
import json
import os
import re
import sys
import urllib.error
import urllib.parse
import urllib.request

PRODUCTION_TIERS = ('uat', 'prod')
TIERS = ('sandbox', 'dev', 'test', 'uat', 'prod')
RANK = dict((t, i) for i, t in enumerate(TIERS))
NAME_WORDS = {'uat': 'uat', 'stage': 'uat', 'staging': 'uat', 'preprod': 'uat', 'prod': 'prod',
              'production': 'prod', 'prd': 'prod', 'dev': 'dev', 'development': 'dev', 'sandbox': 'sandbox',
              'test': 'test', 'testing': 'test'}
VERIFIED = 'ENVIRONMENT_PROTECTION_VERIFIED'
NOT_REQUIRED = 'ENVIRONMENT_PROTECTION_NOT_REQUIRED'
NOT_FOUND = 'ENVIRONMENT_NOT_FOUND'
UNCLASSED = 'ENVIRONMENT_UNCLASSED'
REVIEWERS_ABSENT = 'ENVIRONMENT_REVIEWERS_ABSENT'
REVIEWERS_EMPTY = 'ENVIRONMENT_REVIEWERS_EMPTY'
SELF_REVIEW_ALLOWED = 'ENVIRONMENT_SELF_REVIEW_ALLOWED'
GROUP_MISSING = 'ENVIRONMENT_APPROVER_GROUP_MISSING'
POOL_MISSING = 'ENVIRONMENT_APPROVER_POOL_MISSING'
ALL_APP_TEAM = 'ENVIRONMENT_APPROVERS_ALL_APP_TEAM'
NOT_ESTABLISHED = 'ENVIRONMENT_PROTECTION_NOT_ESTABLISHED'
PERMITTED = (VERIFIED, NOT_REQUIRED)


def default_demand(tier):
    prod = tier in PRODUCTION_TIERS
    return {'approver_groups': [], 'approvers_required': 1 if prod else 0,
            'self_review_prevented': 'required' if prod else 'not_required'}


def demand_for(tier, demand_json):
    """-> (demand, note): the stronger of the passed deploy_approval and the kit default; None if unreadable."""
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
    return out, 'the stronger of the passed deploy_approval and the kit default for %s' % tier


def name_class(name):
    """The class a name's words give (the strongest word), or None."""
    words = [NAME_WORDS[w] for w in re.split(r'[^a-z0-9]+', (name or '').lower()) if w in NAME_WORDS]
    return max(words, key=lambda c: RANK[c]) if words else None


def explicit_class(spec, name):
    """-> (class or None, problem or ''). spec: .kit/environments.json (list or {"classes": {}} form)."""
    if spec is None:
        return None, ''
    found = None
    if isinstance(spec, dict) and isinstance(spec.get('classes'), dict):
        found = spec['classes'].get(name)
    elif isinstance(spec, dict) and isinstance(spec.get('environments'), list):
        for e in spec['environments']:
            if isinstance(e, dict) and e.get('name') == name:
                found = e.get('class', e.get('tier'))
    else:
        return None, '.kit/environments.json has neither an environments list nor a classes map'
    if found is None:
        return None, ''
    if found not in TIERS:
        return None, '.kit/environments.json classes %r as %r, not one of %s' % (name, found, ', '.join(TIERS))
    return found, ''


def classify(name, tier, spec, spec_err=''):
    """-> (effective class or None, source, refusal outcome or '', why)."""
    if spec_err:
        return None, 'unread', NOT_ESTABLISHED, '.kit/environments.json could not be read (%s)' % spec_err
    exp, prob = explicit_class(spec, name)
    if prob:
        return None, 'unread', NOT_ESTABLISHED, prob
    pat = name_class(name)
    if not (name or '').strip() or (exp is None and pat is None):
        return None, 'none', UNCLASSED, ('the environment %r is not classed: no .kit/environments.json class and '
                                         'no dev/test/uat/prod word in its name' % (name or ''))
    cands = [(c, s) for c, s in ((tier if tier in TIERS else None, 'tier'), (exp, '.kit/environments.json'),
                                 (pat, 'name')) if c]
    cls, src = max(cands, key=lambda cs: RANK[cs[0]])
    return cls, src, '', ''


def _norm(x):
    return str(x or '').strip().lstrip('@').split('/')[-1].lower()


def parse_pools(raw):
    """KIT_APPROVER_POOLS / settings approver_pools -> set of team slugs and logins (None when not named)."""
    if raw in (None, '', {}, []):
        return None
    if isinstance(raw, str):
        try:
            raw = json.loads(raw)
        except ValueError:
            raw = [p for p in raw.split(',')]
    vals = [v for k, vs in raw.items() if k in ('platform', 'security') for v in (vs if isinstance(vs, list) else [vs])] \
        if isinstance(raw, dict) else (raw if isinstance(raw, list) else [raw])
    out = set(_norm(v) for v in vals) - {''}
    return out or None


def parse_team(raw):
    """KIT_APP_TEAM / settings app_team -> {'team': slug, 'members': set or None} or None."""
    if raw in (None, '', {}):
        return None
    if isinstance(raw, str):
        try:
            raw = json.loads(raw)
        except ValueError:
            raw = {'team': raw}
    if isinstance(raw, str):
        raw = {'team': raw}
    if not isinstance(raw, dict):
        return None
    mem = raw.get('members')
    return {'team': _norm(raw.get('team')), 'members': set(_norm(m) for m in mem) if isinstance(mem, list) else None}


def _who(x):
    r = x.get('reviewer') or {}
    return x.get('type'), _norm(r.get('slug') or r.get('login') or r.get('name'))


def app_team_check(reviewers, team):
    """-> APP_TEAM_NOT_DECLARED | APP_TEAM_INDEPENDENT | APP_TEAM_ONLY | NOT_ESTABLISHED. Never guesses."""
    if not team:
        return 'APP_TEAM_NOT_DECLARED'
    seen = []
    for x in reviewers:
        kind, who = _who(x)
        if kind == 'Team':
            seen.append(who == team['team'])
        elif team['members'] is not None:
            seen.append(who in team['members'])
        else:
            seen.append(None)
    if False in seen:
        return 'APP_TEAM_INDEPENDENT'
    return 'APP_TEAM_ONLY' if seen and all(s is True for s in seen) else 'NOT_ESTABLISHED'


def evaluate(env_doc, demand, pools=None, team=None):
    """-> (outcome, why, app_team_check). env_doc: the API answer, None when unreadable, 404 when absent."""
    if demand is None:
        return NOT_ESTABLISHED, 'the policy\'s deploy approval could not be read, so what to verify is unknown', '-'
    if not demand['approvers_required'] and demand['self_review_prevented'] != 'required':
        return NOT_REQUIRED, 'no required reviewer is demanded at this tier', '-'
    if env_doc == 404:
        return NOT_FOUND, 'the environment does not exist, so no reviewer can be waited for', '-'
    if not isinstance(env_doc, dict) or not isinstance(env_doc.get('protection_rules'), list):
        return NOT_ESTABLISHED, 'the environment\'s protection rules could not be read', '-'
    rv = [r for r in env_doc['protection_rules'] if isinstance(r, dict) and r.get('type') == 'required_reviewers']
    if not rv:
        return REVIEWERS_ABSENT, 'the environment has no required-reviewers rule: anyone who can run the workflow deploys', '-'
    if any(not isinstance(r.get('reviewers'), list) for r in rv):
        return NOT_ESTABLISHED, 'the required-reviewers rule carries no readable reviewer list', '-'
    reviewers = [x for r in rv for x in r['reviewers'] if isinstance(x, dict)]
    if not reviewers:
        return REVIEWERS_EMPTY, 'the required-reviewers rule names nobody, so nobody is waited for', '-'
    if demand['self_review_prevented'] == 'required' and not all(r.get('prevent_self_review') is True for r in rv):
        return SELF_REVIEW_ALLOWED, 'the person who started the deploy may approve it (prevent_self_review is off)', '-'
    groups = set(g.lower() for g in demand['approver_groups'])
    if groups:
        outside = [w for k, w in map(_who, reviewers) if not (k == 'Team' and w in groups)]
        if outside or not reviewers:
            return GROUP_MISSING, ('a reviewer outside the named groups (%s) could approve: %s'
                                   % (', '.join(sorted(groups)), ', '.join(sorted(outside)))), '-'
    if pools is not None and not any(w in pools for _k, w in map(_who, reviewers)):
        return POOL_MISSING, ('no reviewer is in the platform or security pool (%s)' % ', '.join(sorted(pools))), '-'
    tc = app_team_check(reviewers, team)
    if tc == 'APP_TEAM_ONLY':
        return ALL_APP_TEAM, 'every reviewer is on the app team (%s): nobody outside it approves' % team['team'], tc
    return VERIFIED, 'required reviewers%s%s, self-review prevented' % (
        ' from %s' % ', '.join(sorted(groups)) if groups else '', ', a pool member among them' if pools else ''), tc


def get(api_url, path, token, raw=False):
    """-> (parsed JSON or text, error or ''); a 404 answers (404, '')."""
    url = '%s/%s' % (api_url.rstrip('/'), path.lstrip('/'))
    if url.startswith('file:'):  # a recorded API tree (the proofs): no query, and an absent path is a 404
        url = url.split('?')[0]
        if not os.path.exists(urllib.request.url2pathname(urllib.parse.urlsplit(url).path)):
            return 404, ''
    req = urllib.request.Request(url, headers={'Accept': 'application/vnd.github.raw+json' if raw else
                                               'application/vnd.github+json', 'X-GitHub-Api-Version': '2022-11-28'})
    if token and url.startswith('https://'):
        req.add_header('Authorization', 'Bearer %s' % token)
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            body = resp.read().decode('utf-8')
    except urllib.error.HTTPError as exc:
        return (404, '') if exc.code == 404 else (None, 'GET %s answered %s' % (url.split('?')[0], exc.code))
    except Exception as exc:  # noqa: BLE001 -- any failure is "could not read", never a pass
        return None, 'GET %s failed: %s' % (url.split('?')[0], type(exc).__name__)
    try:
        doc = json.loads(body)
    except ValueError:
        return None, 'GET %s did not answer JSON' % url.split('?')[0]
    if raw and isinstance(doc, dict) and doc.get('encoding') == 'base64' and 'content' in doc:
        try:
            doc = json.loads(base64.b64decode(doc['content']).decode('utf-8'))
        except ValueError:
            return None, 'the file at %s is not JSON' % path.split('?')[0]
    return doc, ''


def kit_file(api_url, repo, rel, ref, token):
    """-> (doc or None when absent, error)."""
    doc, err = get(api_url, 'repos/%s/contents/%s%s' % (repo, rel, '?ref=%s' % urllib.parse.quote(ref) if ref else ''),
                   token, raw=True)
    return (None, '') if doc == 404 else (doc, err)


def _selftest():
    fails = []
    prot = {'protection_rules': [{'type': 'required_reviewers', 'prevent_self_review': True,
                                  'reviewers': [{'type': 'Team', 'reviewer': {'slug': 'security'}}]}]}
    d, _n = demand_for('prod', '')
    for got, want in ((evaluate(prot, d)[0], VERIFIED), (evaluate({'protection_rules': []}, d)[0], REVIEWERS_ABSENT),
                      (evaluate(None, d)[0], NOT_ESTABLISHED), (evaluate(404, d)[0], NOT_FOUND),
                      (classify('qa-east', 'dev', None)[2], UNCLASSED), (classify('prod', 'dev', None)[0], 'prod'),
                      (classify('prod', 'dev', {'classes': {'prod': 'dev'}})[0], 'prod'),
                      (evaluate(prot, d, team={'team': 'security', 'members': None})[0], ALL_APP_TEAM),
                      (evaluate(prot, d, pools={'platform'})[0], POOL_MISSING)):
        if got != want:
            fails.append('%s, expected %s' % (got, want))
    if demand_for('prod', json.dumps({'prod': {'approvers_required': 0}}))[0]['approvers_required'] != 1:
        fails.append('a passed demand weakened the prod default')
    for f in fails:
        sys.stderr.write('FAIL: %s\n' % f)
    if fails:
        return 2
    print('environment_protection selftest ok. The full proof is tests/prove_uat_prod_gating.py.')
    return 0


def decide(a, environ):
    """-> (outcome, why, refused, effective class, class source, app team check, demand)."""
    tier, env, token = a.tier.strip(), a.environment.strip(), environ.get('GH_TOKEN', '')
    if tier not in TIERS:  # a tier nobody can name cannot be shown to be below production
        return NOT_ESTABLISHED, 'environment_tier %r is not a registered tier' % tier, True, '-', '-', '-', None
    if not a.repository.strip():
        return NOT_ESTABLISHED, 'no repository is named, so nothing can be read', True, '-', '-', '-', None
    spec, err = kit_file(a.api_url, a.repository, '.kit/environments.json', a.ref, token)
    cls, src, bad, why = classify(env, tier, spec, err)
    if bad:
        return bad, why, True, '-', src, '-', None
    demand, _note = demand_for(cls, a.demand_json)
    settings = None
    pools, team = parse_pools(environ.get('KIT_APPROVER_POOLS')), parse_team(environ.get('KIT_APP_TEAM'))
    if (pools is None or team is None) and cls in PRODUCTION_TIERS:
        settings, serr = kit_file(a.api_url, a.repository, '.kit/settings.json', a.ref, token)
        if serr or not isinstance(settings, (dict, type(None))):
            return (NOT_ESTABLISHED, '.kit/settings.json could not be read (%s), so its approver pools and app team '
                    'are unknown' % (serr or 'not a JSON object'), True, cls, src, '-', demand)
        settings = settings or {}
        pools = pools if pools is not None else parse_pools(settings.get('approver_pools'))
        team = team if team is not None else parse_team(settings.get('app_team'))
    doc = None
    if cls in PRODUCTION_TIERS or (demand or {}).get('approvers_required'):
        doc, err = get(a.api_url, 'repos/%s/environments/%s' % (a.repository, urllib.parse.quote(env, safe='')), token)
    if team and team['members'] is None and team['team'] and doc not in (None, 404):
        org = a.repository.split('/')[0]
        mem, _e = get(a.api_url, 'orgs/%s/teams/%s/members?per_page=100' % (org, team['team']), token)
        if isinstance(mem, list):
            team = dict(team, members=set(_norm(m.get('login')) for m in mem if isinstance(m, dict)))
    outcome, why, tc = evaluate(doc, demand, pools, team)
    if doc is None and err and outcome == NOT_ESTABLISHED:
        why = '%s (%s)' % (why, err)
    return outcome, why, outcome not in PERMITTED and cls in PRODUCTION_TIERS, cls, src, tc, demand


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.split('\n')[0])
    ap.add_argument('--self-test', action='store_true')
    ap.add_argument('--repository', default=os.environ.get('GITHUB_REPOSITORY', ''))
    ap.add_argument('--environment', default='')
    ap.add_argument('--tier', default='')
    ap.add_argument('--demand-json', default='')
    ap.add_argument('--ref', default=os.environ.get('GITHUB_SHA', ''))
    ap.add_argument('--api-url', default=os.environ.get('GITHUB_API_URL', 'https://api.github.com'))
    ap.add_argument('--github-output', default='')
    a = ap.parse_args(argv)
    if a.self_test:
        return _selftest()
    outcome, why, refused, cls, src, tc, demand = decide(a, os.environ)
    print('environment_protection=%s tier=%s refused=%s' % (outcome, a.tier.strip() or '(none)', str(refused).lower()))
    print('  ' + why)
    print('  environment %r classed %s (from %s); app_team_check=%s; demand %s'
          % (a.environment, cls, src, tc, json.dumps(demand, sort_keys=True)))
    if a.github_output:
        with open(a.github_output, 'a', encoding='utf-8') as fh:
            fh.write('environment_protection=%s\nenvironment_protection_refused=%s\nenvironment_class=%s\n'
                     'app_team_check=%s\nenvironment_protection_why=%s\n'
                     % (outcome, str(refused).lower(), cls, tc, why.replace('\n', ' ')))
    return 1 if refused else 0


if __name__ == '__main__':
    sys.exit(main())

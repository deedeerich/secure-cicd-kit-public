#!/usr/bin/env python3
"""Proof: scripts/kit_org_init.py checks the one-time organisation setup read-only and plans, never performs.

Against a 127.0.0.1 stand-in (tests/_survey_api_standin.py) in the documented GitHub REST shapes.

POSITIVE
  P1  a fully set-up organisation on github.com: every item PASS, the github.com OIDC issuer, nothing to do
  P2  the checklist says, for each ACTION_NEEDED item, WHAT, HOW (the exact gh command) and WHY, and lists the
      dry-run plan in order; the fill-out section names what only a person knows
  P3  a GHE.com organisation: the tenant's own issuer (token.actions.acme.ghe.com) and GH_HOST in every command
  P4  a user account: the organisation-only items are NOT_ESTABLISHED by name; the kit repository is still checked
  P5  every request was a GET
NEGATIVE
  N1  a kit repository that cannot be called (access none), no overlay, a missing team, no KIT_APPROVER_POOLS, a
      per-environment variable at the org level, an allow-list missing a kit action owner, a write-default token
      that may approve PRs, a customised OIDC subject, no kit init in the copy, Dependabot off: each ACTION_NEEDED
  N2  local-only Actions on the GHE.com org: ACTION_NEEDED, naming the kit's action owners
  N3  everything 403: NOT_ESTABLISHED, never PASS
  N4  the kit repository answering on another host -> SURVEY_HOST_MISMATCH
  N5  a variable's VALUE never reaches the checklist
  N6  an output directory inside the kit is refused
MUTANTS  M1 github.com's issuer everywhere  M2 no variable is "wrong at org"  M3 no kit action owners
         M4 access none accepted  M5 a write sent  M6 a user account read as an organisation

EXIT 0 every case held and every mutant was caught   1 otherwise
"""
import contextlib
import io
import os
import shutil
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, os.path.join(ROOT, 'scripts'))
sys.path.insert(0, HERE)

import kit_org_init as oi  # noqa: E402
import kit_survey as ks  # noqa: E402
from _survey_api_standin import StandIn  # noqa: E402

VALUE = 'FIXTURE-ORG-VARIABLE-VALUE-NEVER-IN-OUTPUT'


def routes(owner='octo-org', host='github.com', good=True, user=False, allowed='selected'):
    K = '/repos/%s/secure-cicd-kit' % owner
    owners = oi.kit_action_owners()
    R = {
        '/users/%s' % owner: (200, {'login': owner, 'type': 'User' if user else 'Organization'}),
        K: (200, {'name': 'secure-cicd-kit', 'full_name': '%s/secure-cicd-kit' % owner, 'private': True,
                  'visibility': 'private', 'html_url': 'https://%s/%s/secure-cicd-kit' % (host, owner)}),
        K + '/actions/permissions/access': (200, {'access_level': ('user' if user else 'organization') if good else 'none'}),
        K + '/contents/overlays/%s' % owner.lower(): (200, []) if good else (404, {}),
        K + '/contents/scripts/kit_init.py': (200, {}) if good else (404, {}),
        K + '/contents/templates/kit-init.yml': (200, {}),
        K + '/actions/permissions': (200, {'enabled': True, 'allowed_actions': 'all'}),
    }
    if user:
        return R
    O = '/orgs/%s' % owner
    R.update({
        O + '/teams/platform': (200, {'slug': 'platform'}),
        O + '/teams/appsec': (200, {'slug': 'appsec'}) if good else (404, {}),
        O + '/actions/variables': (200, {'variables': [{'name': 'KIT_APPROVER_POOLS', 'value': VALUE}]} if good else
                                   {'variables': [{'name': 'AZURE_CLIENT_ID', 'value': VALUE}]}),
        O + '/actions/permissions': (200, {'enabled_repositories': 'all', 'allowed_actions': allowed}),
        O + '/actions/permissions/selected-actions': (200, {
            'github_owned_allowed': True, 'patterns_allowed': ['%s/*' % o for o in (owners if good else owners[1:])]}),
        O + '/actions/permissions/workflow': (200, {'default_workflow_permissions': 'read' if good else 'write',
                                                    'can_approve_pull_request_reviews': not good}),
        O + '/actions/oidc/customization/sub': (404, {}) if good else (200, {'include_claim_keys': ['repository_owner', 'workflow']}),
        O: (200, {'login': owner, 'dependabot_alerts_enabled_for_new_repositories': good,
                  'dependabot_security_updates_enabled_for_new_repositories': good,
                  'advanced_security_enabled_for_new_repositories': False,
                  'secret_scanning_enabled_for_new_repositories': False}),
    })
    return R


class Fail(Exception):
    pass


def check(cond, what):
    if not cond:
        raise Fail(what)


def run(si, owner='octo-org', host='github.com', **kw):
    return oi.run_checks(owner, host=host, api_url=si.url, token='stand-in-not-a-credential', env={},
                         platform_team='platform', appsec_team='appsec', **kw)


def results(res):
    return [(i['id'], i['result']) for i in res['items']]


def case_p1(si):
    si.reset(routes())
    res = run(si)
    bad = [i for i in res['items'] if i['result'] != oi.PASS]
    check(not bad, 'P1 a set-up org has non-PASS items: %r' % [(i['id'], i['title']) for i in bad])
    check(any('token.actions.githubusercontent.com' in i['title'] for i in res['items']), 'P1 github.com issuer')
    check('Nothing to do.' in '\n'.join(oi.checklist_md(res)), 'P1 an empty plan')


def case_n1_p2_n5(si):
    si.reset(routes(good=False))
    res = run(si)
    need = dict((i['title'], i) for i in res['items'] if i['result'] == oi.ACTION_NEEDED)
    titles = ' / '.join(need)
    for want in ('cannot call the kit', 'overlay', 'appsec does not exist', 'KIT_APPROVER_POOLS is not set',
                 'AZURE_CLIENT_ID', 'allow-list misses', 'default workflow token is write', 'customised',
                 'lacks kit init', 'Dependabot is not on'):
        check(want in titles, 'N1 %r not ACTION_NEEDED (got %s)' % (want, titles))
    for i in need.values():
        check(i['what'] and i['how'] and i['why'], 'P2 %s lacks what/how/why' % i['title'])
    acc = [i for i in need.values() if 'cannot call' in i['title']][0]
    check("actions/permissions/access -f access_level='organization'" in acc['how'], 'P2 the exact access command')
    md = '\n'.join(oi.checklist_md(res))
    check('## Dry-run plan' in md and '**Why it matters:**' in md and 'What you need to fill out' in md, 'P2 checklist sections')
    check(VALUE not in md and VALUE not in str(res), 'N5 a variable value reached the output')


def case_p3_n2(si):
    si.reset(routes('acme', 'acme.ghe.com', allowed='local_only'))
    res = run(si, owner='acme', host='acme.ghe.com')
    check(any('token.actions.acme.ghe.com' in i['title'] for i in res['items']), 'P3 the tenant issuer')
    lo = [i for i in res['items'] if 'local actions only' in i['title']]
    check(lo and lo[0]['result'] == oi.ACTION_NEEDED and 'bridgecrewio' in lo[0]['why'], 'N2 local-only names the owners')
    check(all('GH_HOST=acme.ghe.com gh' in i['how'] for i in res['items'] if i['how']), 'P3 GH_HOST on every command')


def case_p4(si):
    si.reset(routes('solo', user=True))
    res = run(si, owner='solo')
    r = dict((i['id'], i['result']) for i in res['items'])
    check(res['owner_kind'] == 'user' and r['O5'] == oi.NOT_ESTABLISHED and r['O7'] == oi.NOT_ESTABLISHED, 'P4 org-only items')
    check(r['O1'] == oi.PASS and r['O2'] == oi.PASS, 'P4 the kit repository still checked (%r)' % r)


def case_p5(si):
    si.reset(routes(good=False))
    run(si)
    check(si.requests and not si.writes(), 'P5 only GET')


def case_n3(si):
    R = dict((k, (403, {'message': 'Must have admin rights'})) for k in routes())
    R['/users/octo-org'] = (200, {'login': 'octo-org', 'type': 'Organization'})
    si.reset(R)
    res = run(si)
    passed = [i['id'] for i in res['items'] if i['result'] == oi.PASS and i['id'] != 'O8']
    check(not passed, 'N3 unreadable items read as PASS: %r' % passed)


def case_n4(si):
    R = routes()
    R['/repos/octo-org/secure-cicd-kit'][1]['html_url'] = 'https://acme.ghe.com/octo-org/secure-cicd-kit'
    si.reset(R)
    try:
        run(si)
        raise Fail('N4 a kit repository on another host was accepted')
    except ks.Refusal as e:
        check(e.state == ks.SURVEY_HOST_MISMATCH, 'N4 %s' % e.state)


def case_n6():
    with contextlib.redirect_stdout(io.StringIO()):
        rc = oi.main(['--owner', 'o', '--host', 'github.com', '--out', os.path.join(ROOT, 'org-init-out')])
    check(rc == 1 and not os.path.exists(os.path.join(ROOT, 'org-init-out')), 'N6 inside the kit refused')


CASES = [('P1', case_p1), ('N1/P2/N5', case_n1_p2_n5), ('P3/N2', case_p3_n2), ('P4', case_p4), ('P5', case_p5),
         ('N3', case_n3), ('N4', case_n4)]


def run_all(si, quiet=False):
    failed = []
    for name, fn in CASES:
        try:
            fn(si)
            if not quiet:
                print('  PASS %s' % name)
        except Fail as e:
            failed.append('%s: %s' % (name, e))
        except Exception as e:  # noqa: BLE001
            failed.append('%s: crashed %r' % (name, e))
    try:
        case_n6()
        if not quiet:
            print('  PASS N6')
    except Fail as e:
        failed.append('N6: %s' % e)
    return failed


def mutants():
    o_transport, o_kind = ks._transport, ks.owner_kind

    def put_access(req, timeout):
        if req.full_url.endswith('/access'):
            req.method = 'PUT'
        return o_transport(req, timeout)

    M = [('M1 github.com issuer everywhere', oi, 'issuer_for', lambda h: 'https://token.actions.githubusercontent.com'),
         ('M2 nothing wrong at org', oi, 'WRONG_AT_ORG', ()),
         ('M3 no kit action owners', oi, 'kit_action_owners', lambda root=None: []),
         ('M4 access none accepted', oi, 'item', None),
         ('M5 a write sent', ks, '_transport', put_access),
         ('M6 user read as org', ks, 'owner_kind', lambda c, o: 'org' if o_kind(c, o) else 'org')]
    o_item = oi.item

    def item_accept_none(oid, title, result, *a, **k):
        if oid == 'O2' and result == oi.ACTION_NEEDED:
            result = oi.PASS
        return o_item(oid, title, result, *a, **k)
    survived = []
    with StandIn() as si:
        for name, mod, attr, repl in M:
            if attr == 'item':
                repl = item_accept_none
            orig = getattr(mod, attr)
            setattr(mod, attr, repl)
            try:
                got = run_all(si, quiet=True)
                if got:
                    print('  caught %s -- %s' % (name, got[0]))
                else:
                    survived.append(name)
            finally:
                setattr(mod, attr, orig)
    return survived


def main():
    with StandIn() as si:
        failed = run_all(si)
    survived = mutants()
    for f in failed:
        print('  FAIL %s' % f)
    for s in survived:
        print('  MUTANT SURVIVED %s' % s)
    ok = not failed and not survived
    print('prove_kit_org_init: %s' % ('PASS' if ok else 'FAIL'))
    return 0 if ok else 1


if __name__ == '__main__':
    sys.exit(main())

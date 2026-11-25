#!/usr/bin/env python3
"""The OIDC verifier signs in to either cloud and checks the identity from the directory side (2026-11-06).

WHY THIS EXISTS
    .github/workflows/verify-azure-oidc.yml passed no `environment` and no `audience` to azure/login,
    so it could not sign in to Azure Government, and it never looked at the identity from the
    directory side. The owner uses it to check the OIDC identity she created, so after sign-in it
    now runs five READ-ONLY checks, each PASS / FAIL / NOT_ESTABLISHED with the reason in plain words:
    no client secret, role assignments in exactly one subscription, the federated credential's
    issuer is this run's own host issuer, its subject is repo:<org>/<repo>:environment:<env>, and its
    audience is the cloud's.

    The step `directory` runs AS SHIPPED (tests/_step_harness.py) against a stub `az` answering from
    fixtures; the login's environment and audience are evaluated with the Gov-audience proof's
    evaluator (tests/prove_azure_gov_audience.py, which also holds this site to its table).

WHAT IT PROVES
  POSITIVE
    P1  public cloud, a clean identity on a GHE.com host: all five PASS, the step passes
    P2  gov cloud: the credential with api://AzureADTokenExchangeUSGov PASSES; with
        vars.KIT_AZURE_OIDC_AUDIENCE set to the global audience, a global-audience credential PASSES
    P3  a managed identity (no app registration): no_client_secret PASSES (it cannot hold one)
    P4  the login step: gov -> environment AzureUSGovernment and the Gov audience; public ->
        AzureCloud and the global audience; the directory step runs after login, before any probe
  NEGATIVE
    N1  a client secret on the app registration -> FAIL, the step fails
    N2  a role assignment at a management group -> FAIL
    N3  two subscriptions -> FAIL       N4  a subscription other than AZURE_SUBSCRIPTION_ID -> FAIL
    N5  no role assignment at all -> FAIL
    N6  a credential trusting the github.com issuer on a GHE.com run -> FAIL (never hard-coded)
    N7  only a branch-scoped credential (ref:refs/heads/main) -> subject FAIL
    N8  a gov run with a global-audience credential and no override -> audience FAIL
    N9  Graph unreadable -> NOT_ESTABLISHED with the reason (step passes); with
        require_directory_checks true -> the step fails
    N10 role assignments unreadable -> NOT_ESTABLISHED, never PASS
    N11 no expression inside the run: block; every value reaches it through env:

EXIT 0 all hold   1 any does not   2 bash or PyYAML unavailable
"""
import io
import json
import os
import shutil
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, HERE)

try:
    import yaml  # noqa: F401
except ImportError:
    print('UNKNOWN: PyYAML not available.')
    sys.exit(2)

import prove_azure_gov_audience as G  # noqa: E402

WF = '.github/workflows/verify-azure-oidc.yml'
SUB = '11111111-2222-3333-4444-555555555555'
SUB2 = '66666666-7777-8888-9999-000000000000'
CLIENT = 'aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee'
REPO = 'example-org/example-app'
ENVN = 'dev'
SERVER = 'https://example.ghe.com'
ISS = 'https://token.actions.example.ghe.com'
GLOBAL, GOV = G.GLOBAL, G.GOV
FAILS = []

AZ_SHIM = r'''
case "$*" in
  "ad app federated-credential list"*) f=fic ;;
  "ad app show"*) f=app ;;
  "ad sp show"*) f=sp ;;
  "account list"*) f=accounts ;;
  "role assignment list"*) f=roles ;;
  *) echo "unexpected az call: $*" >&2; exit 9 ;;
esac
if [ -f "$FIX/$f.json" ]; then cat "$FIX/$f.json"; else cat "$FIX/$f.err" >&2 2>/dev/null; exit 1; fi
'''


def check(cond, label, detail=''):
    print('  %s %s%s' % ('ok  ' if cond else 'FAIL', label, ('  -- ' + detail) if detail and not cond else ''))
    if not cond:
        FAILS.append(label)


def ident(pw=0, mi=False, roles=None, accounts=None, fic=None, unreadable=()):
    fx = {}
    if not mi:
        fx['app'] = {'appId': CLIENT, 'passwordCredentials': [{'keyId': 'k%d' % i} for i in range(pw)]}
    else:
        fx['app.err'] = 'Resource does not exist'
    fx['sp'] = {'appId': CLIENT, 'passwordCredentials': [],
                'servicePrincipalType': 'ManagedIdentity' if mi else 'Application'}
    fx['roles'] = roles if roles is not None else [
        {'scope': '/subscriptions/%s/resourceGroups/rg-app' % SUB, 'roleDefinitionName': 'Contributor'}]
    fx['accounts'] = accounts if accounts is not None else [{'id': SUB}]
    fx['fic'] = fic if fic is not None else [cred()]
    for u in unreadable:
        fx.pop(u, None)
        fx[u + '.err'] = 'Insufficient privileges to complete the operation.'
    return fx


def cred(subject=None, issuer=ISS, aud=GLOBAL):
    return {'name': 'gh', 'issuer': issuer, 'subject': subject or 'repo:%s:environment:%s' % (REPO, ENVN),
            'audiences': [aud]}


def run(H, bash, step, fx, cloud='public', override='', require=False):
    work = tempfile.mkdtemp(prefix='oidc-dir-')
    try:
        ws = os.path.join(work, 'ws'); os.makedirs(ws)
        fix = os.path.join(work, 'fix'); os.makedirs(fix)
        for k, v in fx.items():
            if k.endswith('.err'):
                io.open(os.path.join(fix, k), 'w', encoding='utf-8').write(v)
            else:
                io.open(os.path.join(fix, k + '.json'), 'w', encoding='utf-8').write(json.dumps(v))
        shims = os.path.join(work, 'bin')
        H.shim(shims, 'az', AZ_SHIM)
        aud_expr = str(step['env']['EXPECTED_AUDIENCE'])
        actx = {'inputs.cloud': cloud}
        if override:
            actx['vars.KIT_AZURE_OIDC_AUDIENCE'] = override
        inner = aud_expr.strip()[3:-2].strip()
        ctx = {'secrets.AZURE_CLIENT_ID': CLIENT, 'secrets.AZURE_SUBSCRIPTION_ID': SUB, 'inputs.cloud': cloud,
               inner: G.evaluate(aud_expr, actx),
               'steps.claims.outputs.subject': 'repo:%s:environment:%s' % (REPO, ENVN),
               'steps.claims.outputs.claim_issuer': ISS, 'steps.preflight.outputs.expect_repository': REPO,
               'inputs.environment': ENVN, 'inputs.require_directory_checks': require}
        r = H.run(bash, step, ctx, ws, shim_dir=shims,
                  extra_env={'FIX': fix, 'RUNNER_TEMP': ws, 'GITHUB_SERVER_URL': SERVER})
        checks = {}
        try:
            for c in json.loads(r['outputs'].get('directory_checks', '[]')):
                checks[c['check']] = c
        except ValueError:
            pass
        return r['rc'], r['outputs'].get('directory_verdict'), checks, r['log']
    finally:
        shutil.rmtree(work, ignore_errors=True)


def v(checks, name):
    return (checks.get(name) or {}).get('verdict')


def main():
    import _step_harness as H
    bash, why = H.usable_bash()
    if not bash:
        print('UNKNOWN: no usable bash (%s).' % why)
        return 2
    doc = H.load(WF)
    steps = doc['jobs']['verify']['steps']
    ids = [s.get('id') or s.get('name') for s in steps]
    step = dict(next(s for s in steps if s.get('id') == 'directory'))
    step['_job_env'] = {}
    print('OIDC directory-side checks (%s, step `directory`):' % WF)

    # P4: the login step and the order.
    login = next(s for s in steps if str(s.get('uses', '')).startswith('azure/login@'))
    w = login.get('with') or {}
    check(G.evaluate(w.get('environment'), {'inputs.cloud': 'gov'}) == 'AzureUSGovernment' and
          G.evaluate(w.get('audience'), {'inputs.cloud': 'gov'}) == GOV,
          'P4 gov signs in with AzureUSGovernment and the Gov audience')
    check(G.evaluate(w.get('environment'), {'inputs.cloud': 'public'}) == 'AzureCloud' and
          G.evaluate(w.get('audience'), {'inputs.cloud': 'public'}) == GLOBAL,
          'P4 public signs in with AzureCloud and the global audience')
    li = steps.index(login)
    check(li < ids.index('directory') < ids.index('probe'), 'P4 the directory checks run after login, before any probe')
    check('${{' not in str(step.get('run')), 'N11 no expression inside the run: block')

    rc, verdict, c, log = run(H, bash, step, ident())
    check(rc == 0 and verdict == 'PASS' and all(v(c, k) == 'PASS' for k in
          ('no_client_secret', 'one_subscription', 'issuer', 'subject', 'audience')),
          'P1 public, a clean identity on GHE.com: all five PASS', log[-500:])
    rc, verdict, c, log = run(H, bash, step, ident(fic=[cred(aud=GOV)]), cloud='gov')
    check(rc == 0 and v(c, 'audience') == 'PASS', 'P2 gov: the USGov-audience credential passes', log[-300:])
    rc, verdict, c, log = run(H, bash, step, ident(fic=[cred(aud=GLOBAL)]), cloud='gov', override=GLOBAL)
    check(rc == 0 and v(c, 'audience') == 'PASS', 'P2 gov with the override: a global-audience credential passes')
    rc, verdict, c, log = run(H, bash, step, ident(mi=True, fic=[cred()]))
    check(v(c, 'no_client_secret') == 'PASS', 'P3 a managed identity passes no_client_secret', log[-300:])

    rc, verdict, c, _ = run(H, bash, step, ident(pw=1))
    check(rc == 1 and v(c, 'no_client_secret') == 'FAIL', 'N1 a client secret is a FAIL and fails the step')
    rc, verdict, c, _ = run(H, bash, step, ident(roles=[{'scope': '/subscriptions/%s/resourceGroups/rg-app' % SUB}, {'scope': '/providers/Microsoft.Management/managementGroups/mg1'}]))
    check(rc == 1 and v(c, 'one_subscription') == 'FAIL', 'N2 a management-group role is a FAIL')
    rc, verdict, c, _ = run(H, bash, step, ident(accounts=[{'id': SUB}, {'id': SUB2}],
                                               roles=[{'scope': '/subscriptions/%s' % SUB}]))
    check(rc == 1 and v(c, 'one_subscription') == 'FAIL', 'N3 two subscriptions is a FAIL')
    rc, verdict, c, _ = run(H, bash, step, ident(accounts=[{'id': SUB2}], roles=[{'scope': '/subscriptions/%s/resourceGroups/x' % SUB2}]))
    check(rc == 1 and v(c, 'one_subscription') == 'FAIL', 'N4 a subscription other than AZURE_SUBSCRIPTION_ID is a FAIL')
    rc, verdict, c, _ = run(H, bash, step, ident(roles=[]))
    check(rc == 1 and v(c, 'one_subscription') == 'FAIL', 'N5 no role assignment is a FAIL')
    rc, verdict, c, _ = run(H, bash, step, ident(fic=[cred(issuer='https://token.actions.githubusercontent.com')]))
    check(rc == 1 and v(c, 'issuer') == 'FAIL', 'N6 a github.com issuer on a GHE.com run is a FAIL')
    rc, verdict, c, _ = run(H, bash, step, ident(fic=[cred(subject='repo:%s:ref:refs/heads/main' % REPO)]))
    check(rc == 1 and v(c, 'subject') == 'FAIL', 'N7 only a branch-scoped credential: subject FAIL')
    rc, verdict, c, _ = run(H, bash, step, ident(fic=[cred(aud=GLOBAL)]), cloud='gov')
    check(rc == 1 and v(c, 'audience') == 'FAIL', 'N8 gov with a global-audience credential and no override: FAIL')
    fx = ident(unreadable=('app', 'sp', 'fic'))
    rc, verdict, c, log = run(H, bash, step, fx)
    check(rc == 0 and verdict == 'NOT_ESTABLISHED' and v(c, 'no_client_secret') == 'NOT_ESTABLISHED'
          and 'Insufficient privileges' in (c.get('no_client_secret') or {}).get('reason', ''),
          'N9 Graph unreadable: NOT_ESTABLISHED with the reason, the step passes', log[-300:])
    rc, verdict, c, _ = run(H, bash, step, fx, require=True)
    check(rc == 1, 'N9 Graph unreadable with require_directory_checks true: the step fails')
    rc, verdict, c, _ = run(H, bash, step, ident(unreadable=('roles',)))
    check(v(c, 'one_subscription') == 'NOT_ESTABLISHED', 'N10 role assignments unreadable: NOT_ESTABLISHED, never PASS')

    if FAILS:
        print('FAIL: %d claim(s)' % len(FAILS))
        return 1
    print('PASS: both clouds sign in, and the identity is checked from the directory side with a named verdict per check.')
    return 0


if __name__ == '__main__':
    sys.exit(main())

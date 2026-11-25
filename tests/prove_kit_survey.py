#!/usr/bin/env python3
"""Proof: scripts/kit_survey.py surveys an organisation read-only, compares it with the kit, and finds turn-offs.

Against a 127.0.0.1 stand-in (tests/_survey_api_standin.py) serving two fixture organisations in the documented
GitHub REST shapes: `octo-org` on github.com and `acme` on a GHE.com tenant (acme.ghe.com), plus a user account.

POSITIVE
  P1  every adoption state from its evidence: ADOPTED (walk, from the repository's registration), PARTIAL (a
      moving kit ref and a declared weakening, its reason kept), TURNED_OFF three ways (a commit that removed the
      caller, with its message, PR body and pain point; a job `if: false`; a workflow disabled through the API,
      REASON_NOT_RECORDED), NEVER (whole history read), NOT_ESTABLISHED (403 everywhere), KIT_HOST
  P2  the percentages state their denominators; archived, forks and the kit are excluded and named
  P3  the comparison: ORG_BETTER with credit (CodeQL on a schedule, signed commits, a production wait timer, a
      Dependabot cooldown), ORG_ONLY with an overlay-only proposal (SonarQube, Snyk) and its by-hand steps,
      KIT_BETTER (an unpinned non-blocking Semgrep; a stored cloud key), KIT_ONLY, GAP (DAST: nobody)
  P4  the GHE.com shape surveys with host acme.ghe.com (KDEC-027)
  P5  all four outputs are written; secret and variable NAMES appear, no value does
  P6  every request was a GET (the stand-in answers anything else 405 and records it)
  P7  a user account's own private repositories are read through /user/repos
NEGATIVE
  N1  a repository the API answers for on another host -> SURVEY_HOST_MISMATCH, nothing written
  N2  an https API URL that is not the named host's API -> SURVEY_HOST_MISMATCH before any request
  N3  no host named anywhere -> SURVEY_HOST_NOT_NAMED (never a default github.com)
  N4  an output directory inside the kit -> SURVEY_OUT_IN_KIT
  N5  a history cut short (--history 1) never reads as NEVER: NOT_ESTABLISHED
  N6  a refused token -> SURVEY_AUTH_REFUSED
  N7  a next-page link to another host is refused, not followed
MUTANTS (each must make a case above fail)
  M1 names_only keeps values   M2 history finds nothing   M3 the repository host check passes anything
  M4 403 read as absent        M5 truncated history read as complete   M6 the schedule credit dropped
  M7 the kit counted in the denominator   M8 a cross-host next link silently dropped

EXIT 0 every case held and every mutant was caught   1 otherwise
"""
import io
import json
import os
import shutil
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, os.path.join(ROOT, 'scripts'))
sys.path.insert(0, HERE)

import kit_survey as ks  # noqa: E402
from _survey_api_standin import StandIn, content, listing, repo_obj  # noqa: E402

SHA = 'c1420eafe79481070963562cc31c1ec5aae12b7a'
PIN = 'b4ffde65f46336ab88eb53be808477a3936bae11'
SECRET_VALUE = 'FIXTURE-SECRET-VALUE-NEVER-IN-OUTPUT'
VAR_VALUE = 'FIXTURE-VARIABLE-VALUE-NEVER-IN-OUTPUT'
WF = '.github/workflows/'


def security_caller(owner, ref=SHA, extra_with='', job_if=''):
    return ('name: Security\non:\n  push: {branches: [main]}\n  pull_request: {branches: [main]}\npermissions: {}\n'
            'jobs:\n  security:\n%s    permissions: {contents: read, security-events: write, actions: read}\n'
            '    uses: %s/secure-cicd-kit/.github/workflows/reusable-security.yml@%s\n    with:\n      language: python\n%s'
            % (('    if: %s\n' % job_if) if job_if else '', owner, ref, extra_with))


def build_routes(owner='octo-org', host='github.com', user=False):
    R = {}
    repos = []

    def repo(name, files=None, wf_state=None, protection=(404, {'message': 'Branch not protected'}),
             rulesets=(200, []), envs=(200, {'environments': []}), secrets=(200, {'secrets': []}),
             variables=(200, {'variables': []}), commits=(200, []), extra=None, forbidden=False, **kw):
        repos.append(repo_obj(owner, name, host, **kw))
        b = '/repos/%s/%s' % (owner, name)
        if forbidden:
            for p in ('/actions/workflows', '/contents/.github/workflows', '/branches/main/protection', '/rulesets',
                      '/environments', '/contents/.github/CODEOWNERS', '/contents/CODEOWNERS', '/contents/docs/CODEOWNERS',
                      '/contents/.github/dependabot.yml', '/contents/.github/dependabot.yaml', '/actions/secrets',
                      '/actions/variables', '/commits'):
                R[b + p] = (403, {'message': 'Resource not accessible by integration'})
            return
        files = files or {}
        wfs = [p for p in files if p.startswith(WF)]
        R[b + '/actions/workflows'] = (200, {'total_count': len(wfs), 'workflows': [
            {'path': p, 'state': (wf_state or {}).get(p, 'active')} for p in wfs]})
        R[b + '/contents/.github/workflows'] = listing(wfs) if wfs else (404, {'message': 'Not Found'})
        for p, t in files.items():
            R[b + '/contents/' + p] = content(t)
        R[b + '/branches/main/protection'] = protection
        R[b + '/rulesets'] = rulesets
        R[b + '/environments'] = envs
        R[b + '/actions/secrets'] = secrets
        R[b + '/actions/variables'] = variables
        R[b + '/commits'] = commits
        for k, v in (extra or {}).items():
            R[b + k] = v

    sec_names = (200, {'total_count': 2, 'secrets': [
        {'name': 'AZURE_CLIENT_ID', 'value': SECRET_VALUE, 'created_at': '2026-01-01T00:00:00Z'},
        {'name': 'SONAR_TOKEN', 'created_at': '2026-01-01T00:00:00Z'}]})
    var_names = (200, {'total_count': 1, 'variables': [{'name': 'KIT_APP_TEAM', 'value': VAR_VALUE}]})

    # 1 ADOPTED at walk
    repo('app-adopted', files={
        WF + 'security.yml': security_caller(owner),
        WF + 'deploy.yml': 'on: {push: {branches: [main]}}\njobs:\n  deploy:\n    uses: %s/secure-cicd-kit/.github/'
                           'workflows/reusable-deploy-containerapp.yml@%s\n' % (owner, SHA),
        '.security/policy-registration.json': json.dumps({'policies': [{'id': 'p', 'rung': 'crawl'},
                                                                       {'id': 'q', 'rung': 'walk'}]}),
        '.github/CODEOWNERS': '* @octo-org/appsec\n',
        '.github/dependabot.yml': 'version: 2\nupdates:\n  - package-ecosystem: pip\n    directory: /\n'
                                  '    schedule: {interval: weekly}\n    groups: {all: {patterns: ["*"]}}\n'},
        secrets=sec_names, variables=var_names,
        commits=(200, [{'sha': 'a' * 40}]),
        extra={'/commits/' + 'a' * 40: (200, {'sha': 'a' * 40, 'commit': {'message': 'Wire the kit', 'committer': {'date': '2026-10-01T00:00:00Z'}},
                                              'parents': [], 'files': [{'filename': WF + 'security.yml', 'status': 'added',
                                              'patch': '+    uses: %s/secure-cicd-kit/.github/workflows/reusable-security.yml@%s' % (owner, SHA)}]})})
    # 2 PARTIAL: a moving ref and a declared weakening
    repo('app-partial', files={WF + 'security.yml': security_caller(
        owner, ref='v1', extra_with='      advisory_mode: true\n      weakening_reason: "noisy semgrep rules block every PR"\n')},
        commits=(200, []))
    # 3 TURNED_OFF by a commit that removed the caller (its reason in the message and the PR)
    c1, c2 = '1' * 40, '2' * 40
    repo('app-turned-off', files={WF + 'lint.yml': (
        'on: [pull_request]\njobs:\n  semgrep:\n    runs-on: ubuntu-latest\n    steps:\n'
        '      - uses: returntocorp/semgrep-action@v1\n        continue-on-error: true\n')},
        commits=(200, [{'sha': c2}, {'sha': c1}]),
        extra={'/commits/' + c2: (200, {'sha': c2, 'commit': {'message': 'Add lint', 'committer': {'date': '2026-09-02T00:00:00Z'}},
                                        'parents': [{'sha': c1}], 'files': [{'filename': WF + 'lint.yml', 'status': 'added',
                                                                              'patch': '+on: [pull_request]'}]}),
               '/commits/' + c1: (200, {'sha': c1, 'commit': {
                   'message': 'Remove kit security scan\n\nIt takes 40 minutes per PR and blocks releases.',
                   'committer': {'date': '2026-09-01T00:00:00Z'}}, 'parents': [{'sha': '0' * 40}],
                   'files': [{'filename': WF + 'security.yml', 'status': 'removed',
                              'patch': '-    uses: %s/secure-cicd-kit/.github/workflows/reusable-security.yml@%s' % (owner, SHA)}]}),
               '/commits/%s/pulls' % c1: (200, [{'number': 7, 'title': 'Drop the kit scan', 'body': 'Too slow for our release train.'}])})
    # 4 TURNED_OFF through the API (the workflow disabled in the UI)
    repo('app-disabled-api', files={WF + 'security.yml': security_caller(owner)},
         wf_state={WF + 'security.yml': 'disabled_manually'}, commits=(200, []))
    # 5 TURNED_OFF by `if: false`, committed with the UI's default message
    c3 = '3' * 40
    repo('app-if-false', files={WF + 'security.yml': security_caller(owner, job_if='false')},
         commits=(200, [{'sha': c3}]),
         extra={'/commits/' + c3: (200, {'sha': c3, 'commit': {'message': 'Update security.yml', 'committer': {'date': '2026-09-03T00:00:00Z'}},
                                         'parents': [{'sha': '0' * 40}], 'files': [{'filename': WF + 'security.yml', 'status': 'modified',
                                                                                     'patch': '+    if: false'}]})})
    # 6 NEVER, and the org's own practice
    repo('app-never', files={
        WF + 'codeql.yml': ('on:\n  pull_request: {}\n  schedule: [{cron: "0 3 * * 1"}]\njobs:\n  analyze:\n'
                            '    runs-on: ubuntu-latest\n    steps:\n      - uses: github/codeql-action/init@%s\n'
                            '        with: {queries: security-and-quality}\n      - uses: github/codeql-action/analyze@%s\n' % (PIN, PIN)),
        WF + 'sonar.yml': ('on: [push]\njobs:\n  sonar:\n    runs-on: ubuntu-latest\n    steps:\n'
                           '      - uses: SonarSource/sonarqube-scan-action@v5\n'),
        WF + 'snyk.yml': ('on: [pull_request]\njobs:\n  snyk:\n    runs-on: ubuntu-latest\n    steps:\n'
                          '      - uses: snyk/actions/node@%s\n' % PIN),
        WF + 'deploy.yml': ('on: {push: {branches: [main]}}\njobs:\n  deploy:\n    runs-on: ubuntu-latest\n'
                            '    environment: prod\n    steps:\n      - uses: step-security/harden-runner@%s\n'
                            '      - uses: aws-actions/configure-aws-credentials@%s\n        with:\n'
                            '          aws-secret-access-key: ${{ secrets.AWS_SECRET_ACCESS_KEY }}\n'
                            '      - run: aws s3 sync ./site s3://bucket\n' % (PIN, PIN)),
        '.github/dependabot.yml': ('version: 2\nupdates:\n  - package-ecosystem: npm\n    directory: /\n'
                                   '    schedule: {interval: weekly}\n    cooldown: {default-days: 5}\n')},
        protection=(200, {'required_pull_request_reviews': {'required_approving_review_count': 2},
                          'required_signatures': {'enabled': True}, 'enforce_admins': {'enabled': True},
                          'allow_force_pushes': {'enabled': False}}),
        envs=(200, {'environments': [{'name': 'prod', 'protection_rules': [
            {'type': 'required_reviewers', 'prevent_self_review': True, 'reviewers': [{'type': 'Team'}]},
            {'type': 'wait_timer', 'wait_timer': 30}], 'deployment_branch_policy': {'protected_branches': True}}]}),
        secrets=(200, {'secrets': [{'name': 'AWS_SECRET_ACCESS_KEY', 'value': SECRET_VALUE}]}),
        commits=(200, [{'sha': '6' * 40}]),
        extra={'/commits/' + '6' * 40: (200, {'sha': '6' * 40, 'commit': {'message': 'Add CodeQL', 'committer': {'date': '2026-08-01T00:00:00Z'}},
                                              'parents': [], 'files': [{'filename': WF + 'codeql.yml', 'status': 'added', 'patch': '+on:'}]})})
    # 7 nothing readable
    repo('app-unreadable', forbidden=True)
    # excluded from the denominator
    repo('old-archived', archived=True)
    repo('someone-fork', fork=True)
    repo('secure-cicd-kit', files={WF + 'reusable-security.yml': 'on: {workflow_call: {}}\njobs: {}\n'})

    if user:
        R['/users/%s' % owner] = (200, {'login': owner, 'type': 'User'})
        R['/user'] = (200, {'login': owner})
        R['/user/repos'] = (200, repos)
    else:
        R['/users/%s' % owner] = (200, {'login': owner, 'type': 'Organization'})
        R['/orgs/%s/repos' % owner] = (200, repos)
    return R


class Fail(Exception):
    pass


def check(cond, what):
    if not cond:
        raise Fail(what)


def survey(si, owner='octo-org', host='github.com', history=200, **kw):
    return ks.run_survey(owner, host=host, api_url=si.url, token='stand-in-token-not-a-credential',
                         history=history, env={}, **kw)


def rows_by(result):
    return dict((r['name'], r) for r in result['rows'])


def comp_by(result):
    return dict((c['id'], c) for c in result['comparison'])


def case_p1(si):
    si.reset(build_routes())
    r = rows_by(survey(si))
    check(r['app-adopted']['adoption'] == ks.ADOPTED and r['app-adopted']['adoption_level'] == 'walk', 'P1 adopted at walk')
    check(r['app-adopted']['kit_pin'] == SHA[:12], 'P1 the pinned kit commit')
    p = r['app-partial']
    check(p['adoption'] == ks.PARTIAL and 'noisy semgrep' in p['turn_off_reason'], 'P1 partial with its weakening reason')
    check(any('moving ref' in x for x in p['partial_because']), 'P1 partial names the moving ref')
    t = r['app-turned-off']
    check(t['adoption'] == ks.TURNED_OFF and t['turn_off_evidence'].startswith('commit 111111111111'), 'P1 removal commit is the evidence')
    check('40 minutes' in t['turn_off_reason'] and 'Too slow' in t['turn_off_reason'], 'P1 message and PR body are the reason')
    check('too slow' in t['pain_point'] and 'blocks delivery' in t['pain_point'], 'P1 pain point classified')
    d = r['app-disabled-api']
    check(d['adoption'] == ks.TURNED_OFF and 'disabled_manually' in d['turn_off_evidence']
          and d['turn_off_reason'] == ks.REASON_NOT_RECORDED, 'P1 API-disabled workflow, reason not recorded')
    f = r['app-if-false']
    check(f['adoption'] == ks.TURNED_OFF and 'if: false' in f['turn_off_evidence'] and '333333333333' in f['turn_off_evidence']
          and f['turn_off_reason'] == ks.REASON_NOT_RECORDED, 'P1 if: false with a UI-default message')
    check(r['app-never']['adoption'] == ks.NEVER, 'P1 never (whole history read)')
    u = r['app-unreadable']
    check(u['adoption'] == ks.NOT_ESTABLISHED, 'P1 unreadable is NOT_ESTABLISHED')
    check('branch_protection' in u['not_established'] and ks.csv_row(u)['branch_protection'] == ks.NOT_ESTABLISHED,
          'P1 a 403 on protection is NOT_ESTABLISHED, never none')
    check(r['secure-cicd-kit']['adoption'] == ks.KIT_HOST, 'P1 the kit itself')


def case_p2(si):
    si.reset(build_routes())
    t = survey(si)['totals']
    check(t['denominator'] == 7, 'P2 denominator 7 (got %s)' % t['denominator'])
    check(t['excluded'] == {'kit_host': 1, 'archived': 1, 'fork': 1}, 'P2 exclusions named %r' % t['excluded'])
    check(t['supported'] == 2 and t['supported_pct'] == '29%', 'P2 supported 2 of 7')
    check(t['secured'] == 1 and t['secured_pct'] == '14%', 'P2 secured 1 of 7')
    check(t['deploying_denominator'] == 2 and t['deploying_secured'] == 1, 'P2 deploying denominator %r' % t)


def case_p3(si):
    si.reset(build_routes())
    c = comp_by(survey(si))
    check(c['codeql']['verdict'] == ks.ORG_BETTER and any('schedule' in x and 'app-never' in x for x in c['codeql']['credit']),
          'P3 CodeQL on a schedule is credited')
    check(c['branch-protection']['verdict'] == ks.ORG_BETTER and any('signed commits' in x for x in c['branch-protection']['credit']),
          'P3 signed commits credited')
    check(c['environment-protection']['verdict'] == ks.ORG_BETTER and any('wait' in x for x in c['environment-protection']['credit']),
          'P3 a production wait timer credited')
    check(c['dependabot-config']['verdict'] == ks.ORG_BETTER, 'P3 Dependabot cooldown credited')
    s = c['sonarqube']
    check(s['verdict'] == ks.ORG_ONLY and not s['proposal']['native'] and 'ONLY' in s['proposal']['where']
          and len(s['proposal']['by_hand']) >= 5, 'P3 SonarQube ORG_ONLY, overlay only, by-hand steps')
    check(c['snyk']['verdict'] == ks.ORG_ONLY, 'P3 Snyk ORG_ONLY')
    check(c['runner-hardening']['verdict'] == ks.ORG_ONLY, 'P3 harden-runner ORG_ONLY')
    check(c['sast-semgrep']['verdict'] == ks.KIT_BETTER and c['sast-semgrep']['kit_better'], 'P3 semgrep unpinned and non-blocking: KIT_BETTER')
    check(c['oidc-cloud-login']['verdict'] == ks.KIT_BETTER, 'P3 a stored cloud key: KIT_BETTER')
    check(c['sbom']['verdict'] == ks.KIT_ONLY, 'P3 sbom KIT_ONLY')
    check(c['dast']['verdict'] == ks.GAP, 'P3 DAST nobody: GAP')
    check(c['codeql']['proposal']['native'] and 'KDEC' in c['codeql']['proposal']['where'], 'P3 a native practice may reach the kit by KDEC')
    check(any(x.startswith('[scheduled]') and 'cron' in x for x in c['codeql']['proposal']['by_hand']), 'P3 ORG_BETTER steps name the strength')


def case_p4(si):
    si.reset(build_routes('acme', 'acme.ghe.com'))
    res = survey(si, owner='acme', host='acme.ghe.com')
    check(res['host'] == 'acme.ghe.com' and rows_by(res)['app-adopted']['adoption'] == ks.ADOPTED, 'P4 GHE.com shape')


def case_p5_p6(si):
    si.reset(build_routes())
    res = survey(si)
    d = tempfile.mkdtemp(prefix='kit-survey-proof-')
    try:
        ks.write_outputs(res, d)
        names = sorted(os.listdir(d))
        check(names == ['KIT_ADOPTION_INVENTORY.md', 'KIT_SURVEY.csv', 'KIT_SURVEY.md', 'KIT_SURVEY_COMPARISON.md',
                        'kit-survey.json'], 'P5 outputs %r' % names)
        blob = ''.join(io.open(os.path.join(d, n), encoding='utf-8').read() for n in names)
        check(SECRET_VALUE not in blob and VAR_VALUE not in blob, 'P5 a secret or variable VALUE reached an output')
        check('AZURE_CLIENT_ID' in blob and 'KIT_APP_TEAM' in blob, 'P5 the names are kept')
        check('How to do it by hand' in blob and 'Denominator: **7**' in blob, 'P5 the by-hand steps and the denominator')
    finally:
        shutil.rmtree(d, ignore_errors=True)
    check(si.requests and not si.writes(), 'P6 only GET requests')


def case_p7(si):
    si.reset(build_routes('solo', user=True))
    res = survey(si, owner='solo')
    check(res['owner_kind'] == 'user' and any(r['path'] == '/user/repos' for r in si.requests), 'P7 /user/repos read')
    check(any(r['path'] == '/user/repos' and r['query'].get('visibility') == 'all' for r in si.requests), 'P7 private included')


def refused(fn, state):
    try:
        fn()
    except ks.Refusal as e:
        return e.state == state
    return False


def case_n1(si):
    si.reset(build_routes('acme', 'acme.ghe.com'))
    check(refused(lambda: survey(si, owner='acme', host='github.com'), ks.SURVEY_HOST_MISMATCH), 'N1 host mix-up refused')


def case_n2_n3(si):
    si.reset({})
    check(refused(lambda: ks.run_survey('o', host='acme.ghe.com', api_url='https://api.github.com', env={}),
                  ks.SURVEY_HOST_MISMATCH), 'N2 API URL of another host refused')
    check(not si.requests, 'N2 refused before any request')
    check(refused(lambda: ks.run_survey('o', env={}), ks.SURVEY_HOST_NOT_NAMED), 'N3 no host named')


def case_n4():
    import contextlib
    with contextlib.redirect_stdout(io.StringIO()):
        rc = ks.main(['--owner', 'o', '--host', 'github.com', '--out', os.path.join(ROOT, 'kit-survey-out')])
    check(rc == 1 and not os.path.exists(os.path.join(ROOT, 'kit-survey-out')), 'N4 output inside the kit refused')


def case_n5(si):
    si.reset(build_routes())
    r = rows_by(survey(si, history=1))
    check(r['app-turned-off']['adoption'] == ks.NOT_ESTABLISHED, 'N5 a cut history is NOT_ESTABLISHED, never NEVER (got %s)'
          % r['app-turned-off']['adoption'])


def case_n6(si):
    si.reset({'/users/octo-org': (401, {'message': 'Bad credentials'})})
    check(refused(lambda: survey(si), ks.SURVEY_AUTH_REFUSED), 'N6 refused token')


def case_n7(si):
    routes = build_routes()
    first = routes['/orgs/octo-org/repos']
    routes['/orgs/octo-org/repos'] = (200, first[1][:1], {'Link': '<https://elsewhere.example.invalid/orgs/octo-org/repos?page=2>; rel="next"'})
    si.reset(routes)
    check(refused(lambda: survey(si), ks.SURVEY_HOST_MISMATCH), 'N7 next link to another host refused')


CASES = [('P1', case_p1), ('P2', case_p2), ('P3', case_p3), ('P4', case_p4), ('P5/P6', case_p5_p6), ('P7', case_p7),
         ('N1', case_n1), ('N2/N3', case_n2_n3), ('N5', case_n5), ('N6', case_n6), ('N7', case_n7)]


def run_all(si, quiet=False):
    failed = []
    for name, fn in CASES:
        try:
            fn(si)
            if not quiet:
                print('  PASS %s' % name)
        except Fail as e:
            failed.append('%s: %s' % (name, e))
        except Exception as e:  # noqa: BLE001 -- a crash under a mutant is a caught mutant
            failed.append('%s: crashed %r' % (name, e))
    try:
        case_n4()
        if not quiet:
            print('  PASS N4')
    except Fail as e:
        failed.append('N4: %s' % e)
    return failed


def mutants():
    orig = {k: getattr(ks, k) for k in ('names_only', '_history', 'repo_host_matches', 'cell', 'adopt', 'CREDIT',
                                         'totals', '_next_link')}
    o_adopt, o_totals, o_next = orig['adopt'], orig['totals'], orig['_next_link']

    def adopt_trunc(row, client=None):
        row['history_truncated'] = False
        return o_adopt(row, client)

    def totals_kit(rows):
        return o_totals([dict(r, is_kit=False) for r in rows])

    def next_any(h):
        u = o_next(h)
        return None if u and 'elsewhere' in u else u
    M = [('M1 names_only keeps values', 'names_only', lambda items: sorted(json.dumps(i) for i in items)),
         ('M2 history finds nothing', '_history', lambda *a: ('READ', [], False)),
         ('M3 host check passes anything', 'repo_host_matches', lambda repo, host: True),
         ('M4 403 read as absent', 'cell', lambda s: 'READ' if s == 200 else 'ABSENT'),
         ('M5 truncated history read as complete', 'adopt', adopt_trunc),
         ('M6 schedule credit dropped', 'CREDIT', dict((k, v) for k, v in orig['CREDIT'].items() if k != 'scheduled')),
         ('M7 kit counted in the denominator', 'totals', totals_kit),
         ('M8 a cross-host next link silently dropped', '_next_link', next_any)]
    survived = []
    with StandIn() as si:
        for name, attr, repl in M:
            setattr(ks, attr, repl)
            try:
                got = run_all(si, quiet=True)
                if not got:
                    survived.append(name)
                else:
                    print('  caught %s -- %s' % (name, got[0]))
            finally:
                setattr(ks, attr, orig[attr])
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
    print('prove_kit_survey: %s' % ('PASS' if ok else 'FAIL'))
    return 0 if ok else 1


if __name__ == '__main__':
    sys.exit(main())

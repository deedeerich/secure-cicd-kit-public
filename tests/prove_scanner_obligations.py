#!/usr/bin/env python3
"""Obligation is decided by discovery and policy; a provider's token only says whether it can run.

WHY THIS EXISTS (owner, 2026-11-18, approved 2026-11-24, KDEC-069): "Required should be identified by the
discovery step based on what is in each of the repos and by what we are checking or have pushed." And:
removing a scanner token (we stopped paying, retired or replaced the tool) must neither leave its findings
impossible to close nor silently remove the control it served.

scripts/scanner_obligations.py over the kit's scanner-obligations.json is the authority. This file holds it:

  POSITIVE
    O1  discovery decides: a Python repository owes source SAST; a repository with no code owes none; an
        image pushed owes an image scan; WordPress found in the tree owes a WordPress component scan
    O2  a repository may DECLARE an extra obligation, and it becomes required (basis DECLARED)
    O3  a removal is honoured only with an exception the GOVERNED policy records for that repository,
        approved by someone other than the requester, unexpired
    P1  every provider is listed with its coverage; a partial replacement shows its exact gap (PARTIAL)
    L1  retiring a provider is a one-line record (date, who); a retired provider blocks nothing, and an
        optional unfunded tool (never adopted) blocks nothing
    S1  a required control with no provider left is a visible COVERAGE_GAP; a time-bound acceptance by the
        risk owner turns it into GAP_ACCEPTED (named, never clean); a control retirement whose residual
        risk the risk owner accepted makes it CONTROL_RETIRED
    R1  routing by stage: crawl ADVISORY, walk and run REFUSED (UNAVAILABLE) or DECISION_REQUIRED (gap)
    E1  outcome and cause are separate fields on every obligation
    C1  a finding from a retired tool keeps its identity and closes on a replacement's clean result ONLY
        with shown equivalence: same issue type and location, the relevant version, detection capability
    G1  the gate's outputs: an adopted external provider with no token and no retirement is handed to the
        gate as UNAVAILABLE (never NOT_CONFIGURED), a retired one is not
    T1  the ticket reconciler's rescan qualification applies the same rule: the retired tool's absence never
        qualifies; a replacement qualifies only with equivalence (RESCAN_PROVIDER_RETIRED_NO_EQUIVALENCE)
    G2  the SHIPPED security-gate step (KDEC-067 harness): the token removed reads UNAVAILABLE -- advisory at
        crawl (SCANNER_DID_NOT_RUN), refused at walk and run; a COVERAGE_GAP the same; an accepted gap
        proceeds with advisory (COVERAGE_PARTIAL, assurance PARTIAL), never PASS, at run too; a policy not evaluated is refused at every rung
  NEGATIVE
    N1  token presence never decides: a token with no discovery creates no obligation; discovery with no
        token keeps the obligation required and the adopted provider UNAVAILABLE
    N2  a repository cannot remove an obligation by its own word (REMOVAL_REFUSED), nor with an expired,
        self-approved or ungoverned exception
    N3  an expired gap acceptance, an acceptance without a risk owner, or one longer than the policy's
        maximum, does not hold: the gap is COVERAGE_GAP again
    N4  a control retirement whose residual risk was not accepted by the risk owner does not retire it
    N5  closure without equivalence stays PENDING_VERIFICATION, each missing element named; the retired
        tool's own absence never closes anything
    N6  an unreadable or malformed policy is a refusal (exit 3), never an empty obligation list
  MUTANTS (each must be caught): token decides; repo removal honoured; expired acceptance honoured; a
    partial provider counted as full coverage; closure without location match.
  The shipped scanner-obligations.json validates (K1), every core provider identity is a capability-floor
  identity (K2), and the composite wires the evaluator from the kit, not the checkout (K3).

EXIT 0 all hold   1 any does not   2 no usable bash for the shipped gate cases (UNKNOWN, never PASS)
"""
import copy
import io
import json
import os
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, os.path.join(ROOT, 'scripts'))
import scanner_obligations as SO  # noqa: E402

POLICY_PATH = os.path.join(ROOT, 'scanner-obligations.json')
FLOOR_PATH = os.path.join(ROOT, 'capability-floor.json')
COMPOSITE = os.path.join(ROOT, '.github', 'actions', 'scanner-obligations', 'action.yml')
TODAY = '2026-11-25'
FAILS = []


def check(cond, label, detail=''):
    print('  %s  %s%s' % ('PASS' if cond else 'FAIL', label, ('  -- %s' % detail) if (detail and not cond) else ''))
    if not cond:
        FAILS.append(label)


def policy():
    """A small, self-contained policy: the shipped one is checked separately (K1)."""
    return {
        'schema': SO.SCHEMA, 'policy_version': 'test.1', 'decision': 'KDEC-069',
        'acceptance_max_days': 90,
        'obligations': [
            {'obligation': 'secret-scan', 'phase': 'security-gate', 'required_when': ['always'],
             'coverage': ['repository-secrets'],
             'providers': [{'provider': 'gitleaks', 'kind': 'core', 'coverage': ['repository-secrets'],
                            'detects': ['secret']}]},
            {'obligation': 'source-sast', 'phase': 'security-gate',
             'required_when': ['discover.python', 'discover.php'], 'coverage': ['source-flaws', 'quality-gate'],
             'providers': [
                 {'provider': 'semgrep', 'kind': 'core', 'coverage': ['source-flaws'], 'detects': ['sast']},
                 {'provider': 'ext-sonar', 'kind': 'external', 'coverage': ['source-flaws', 'quality-gate'],
                  'detects': ['sast', 'code-quality']}]},
            {'obligation': 'image-scan', 'phase': 'security-gate', 'required_when': ['pushes.image'],
             'coverage': ['image-vulnerabilities'],
             'providers': [{'provider': 'trivy-image', 'kind': 'core', 'coverage': ['image-vulnerabilities'],
                            'detects': ['image-vulnerability']}]},
            {'obligation': 'wordpress-components', 'phase': 'security-gate', 'required_when': ['discover.wordpress'],
             'coverage': ['wordpress-core', 'wordpress-plugins'],
             'providers': [{'provider': 'ext-wpscan', 'kind': 'external', 'coverage': ['wordpress-core', 'wordpress-plugins'],
                            'detects': ['wordpress-vulnerability']},
                           {'provider': 'ext-wpcore', 'kind': 'external', 'coverage': ['wordpress-core'],
                            'detects': ['wordpress-vulnerability']}]},
            {'obligation': 'dast', 'phase': 'promotion', 'required_when': ['deploys.any'],
             'coverage': ['running-application'],
             'providers': [{'provider': 'ext-zap', 'kind': 'external', 'coverage': ['running-application'],
                            'detects': ['dast']}]},
        ],
        'provider_lifecycle': [
            {'provider': 'ext-sonar', 'state': 'ADOPTED', 'on': '2026-10-01', 'by': 'owner'},
        ],
        'coverage_gap_acceptances': [], 'control_retirements': [], 'obligation_exceptions': [],
    }


def st(identity, applicability='APPLICABLE', execution='COMPLETE'):
    return {'scanner': identity, 'applicability': applicability, 'execution': execution}


def ev(pol=None, signals=None, states=None, decl=None, repo='org/app', stage='walk', today=TODAY):
    return SO.evaluate(pol or policy(), signals or {}, states if states is not None else {}, decl, repo, today,
                       stage=stage)


def ob(res, name):
    return next((o for o in res['obligations'] if o['obligation'] == name), None)


def full_states():
    return {'gitleaks': st('gitleaks'), 'semgrep': st('semgrep'), 'ext-sonar': st('ext-sonar')}


# ----------------------------------------------------------------------------------- the cases
def obligations(fails):
    print('O: discovery decides what is required')
    r = ev(signals={'python': 'true'}, states=full_states())
    s = ob(r, 'source-sast')
    check(s['required'] and 'discover.python' in s['basis'], 'O1 a Python repository owes source SAST (basis discover.python)',
          s)
    r0 = ev(signals={}, states={'gitleaks': st('gitleaks')})
    check(not ob(r0, 'source-sast')['required'] and ob(r0, 'secret-scan')['required'],
          'O1 no code: no source SAST owed; secret scanning is always owed')
    ri = ev(signals={'image_ref': 'reg/app@sha256:' + 'a' * 64}, states={'gitleaks': st('gitleaks')})
    check(ob(ri, 'image-scan')['required'] and ob(ri, 'image-scan')['state'] == SO.UNAVAILABLE,
          'O1 an image pushed owes an image scan; the core provider that did not run is UNAVAILABLE',
          ob(ri, 'image-scan'))
    tmp = tempfile.mkdtemp()
    os.makedirs(os.path.join(tmp, 'site', 'wp-includes'))
    io.open(os.path.join(tmp, 'site', 'wp-includes', 'version.php'), 'w').write("<?php $wp_version = '6.4.1';\n")
    sig = SO.discover_extra(tmp)
    check(sig.get('wordpress') == 'true', 'O1 WordPress in the tree is discovered (wp-includes/version.php)', sig)
    check(SO.discover_extra(tempfile.mkdtemp()).get('wordpress') == 'false', 'O1 no WordPress in an empty tree')
    rw = ev(signals={'wordpress': 'true'}, states={'gitleaks': st('gitleaks')})
    check(ob(rw, 'wordpress-components')['required'], 'O1 WordPress found owes a WordPress component scan')

    rd = ev(signals={}, states={'gitleaks': st('gitleaks'), 'semgrep': st('semgrep'), 'ext-sonar': st('ext-sonar')},
            decl={'declare': [{'obligation': 'source-sast', 'why': 'generated code is shipped'}]})
    check(ob(rd, 'source-sast')['required'] and 'DECLARED' in ob(rd, 'source-sast')['basis'],
          'O2 a repository may declare an extra obligation (basis DECLARED)')
    rbad = ev(decl={'declare': [{'obligation': 'no-such-control'}]}, states={'gitleaks': st('gitleaks')})
    check(any('no-such-control' in p for p in rbad['declaration_problems']),
          'O2 a declaration of an obligation the policy does not define is named, not silently dropped')

    pol = policy()
    pol['obligation_exceptions'] = [{'obligation': 'source-sast', 'repository': 'org/app', 'exception_ref': 'SEC-41',
                                     'requested_by': 'dev1', 'approved_by': 'sec1', 'expires': '2026-12-31'}]
    rr = ev(pol=pol, signals={'python': 'true'}, states={'gitleaks': st('gitleaks')},
            decl={'remove': [{'obligation': 'source-sast', 'exception_ref': 'SEC-41'}]})
    s = ob(rr, 'source-sast')
    check(not s['required'] and s['cause'] == SO.CAUSE_REMOVED and s['state'] == SO.REMOVED_BY_EXCEPTION,
          'O3 a removal with a governed, independently approved, unexpired exception is honoured, and named', s)

    print('N2: a repository cannot remove an obligation by its own word')
    rn = ev(signals={'python': 'true'}, states={'gitleaks': st('gitleaks')},
            decl={'remove': [{'obligation': 'source-sast', 'exception_ref': 'SEC-41',
                              'approved_by': 'sec1', 'expires': '2026-12-31'}]})
    s = ob(rn, 'source-sast')
    check(s['required'] and any('REMOVAL_REFUSED' in p for p in rn['declaration_problems']),
          'N2 a removal the governed policy does not record is REMOVAL_REFUSED; the obligation stays', rn['declaration_problems'])
    for label, mut in (('expired', {'expires': '2026-11-01'}), ('self-approved', {'approved_by': 'dev1'}),
                       ('bot-approved', {'approved_by': 'dependabot[bot]'}), ('other repository', {'repository': 'org/other'}),
                       ('no expiry', {'expires': ''})):
        p2 = copy.deepcopy(pol)
        p2['obligation_exceptions'][0].update(mut)
        rx = ev(pol=p2, signals={'python': 'true'}, states={'gitleaks': st('gitleaks')},
                decl={'remove': [{'obligation': 'source-sast', 'exception_ref': 'SEC-41'}]})
        check(ob(rx, 'source-sast')['required'], 'N2 a removal with an %s exception is refused' % label)


def providers(fails):
    print('P/L: providers, coverage, lifecycle')
    r = ev(signals={'python': 'true'}, states=full_states())
    s = ob(r, 'source-sast')
    check(s['state'] == SO.SATISFIED and s['outcome'] == SO.OUT_SATISFIED and s['cause'] is None,
          'P1 semgrep + the adopted Sonar cover source SAST: SATISFIED, no cause', s)
    check(sorted(p['provider'] for p in s['providers']) == ['ext-sonar', 'semgrep'] and
          all('coverage' in p for p in s['providers']), 'P1 every provider is listed with its coverage')

    # Sonar's token removed WITHOUT a retirement record: UNAVAILABLE, never NOT_CONFIGURED.
    st2 = {'gitleaks': st('gitleaks'), 'semgrep': st('semgrep'),
           'ext-sonar': st('ext-sonar', 'NOT_CONFIGURED', 'NOT_RUN')}
    r = ev(signals={'python': 'true'}, states=st2)
    s = ob(r, 'source-sast')
    sonar = next(p for p in s['providers'] if p['provider'] == 'ext-sonar')
    check(sonar['status'] == SO.UNAVAILABLE and s['state'] == SO.UNAVAILABLE and s['cause'] == SO.CAUSE_UNAVAILABLE,
          'L1 an adopted provider whose token is missing with no retirement record is UNAVAILABLE', s)
    check('ext-sonar(UNAVAILABLE)' in r['gate']['unavailable'].split(),
          'G1 the gate is handed ext-sonar(UNAVAILABLE), not a NOT_CONFIGURED row', r['gate'])
    r2 = ev(signals={'python': 'true'}, states=st2, stage='crawl')
    check(ob(r2, 'source-sast')['route'] == SO.ROUTE_ADVISORY and ob(r, 'source-sast')['route'] == SO.ROUTE_REFUSED,
          'R1 UNAVAILABLE routes ADVISORY at crawl and REFUSED at walk')
    r3 = ev(signals={'python': 'true'}, states=st2, stage='run')
    check(ob(r3, 'source-sast')['route'] == SO.ROUTE_REFUSED, 'R1 UNAVAILABLE routes REFUSED at run')
    r4 = ev(signals={'python': 'true'}, states=st2, stage='')
    check(ob(r4, 'source-sast')['route'] == SO.ROUTE_REFUSED, 'R1 with no resolved stage it is read at its strictest')

    # Retire Sonar: one line. The quality gate it alone covered is now a PARTIAL coverage gap, named.
    pol = policy()
    pol['provider_lifecycle'].append({'provider': 'ext-sonar', 'state': 'RETIRED', 'on': '2026-11-20', 'by': 'owner',
                                      'reason': 'licence not renewed'})
    r = ev(pol=pol, signals={'python': 'true'}, states=st2)
    s = ob(r, 'source-sast')
    sonar = next(p for p in s['providers'] if p['provider'] == 'ext-sonar')
    check(sonar['status'] == SO.RETIRED and sonar.get('retired') == {'on': '2026-11-20', 'by': 'owner',
                                                                     'reason': 'licence not renewed'},
          'L1 a retirement is a one-line record (date, who) carried on the provider', sonar)
    check('ext-sonar' not in r['gate']['unavailable'], 'G1 a retired provider is not handed to the gate as not run')
    check(s['state'] == SO.PARTIAL and s['gap'] == ['quality-gate'] and s['covered'] == ['source-flaws'],
          'P1 the partial replacement shows its gap: PARTIAL, gap [quality-gate]', s)
    check(s['route'] == SO.ROUTE_DECISION and 'source-sast(PARTIAL:quality-gate)' in r['gate']['gaps'].split(),
          'S1 a gap at walk needs a decision, and the gate is told which aspect', r['gate'])

    # An optional, unfunded tool that was never adopted blocks nothing.
    pol = policy()
    pol['obligations'][1]['coverage'] = ['source-flaws']
    pol['provider_lifecycle'] = []
    r = ev(pol=pol, signals={'python': 'true'}, states={'gitleaks': st('gitleaks'), 'semgrep': st('semgrep')})
    s = ob(r, 'source-sast')
    check(s['state'] == SO.SATISFIED and not r['gate']['unavailable'],
          'L1 a provider never adopted (an optional, unfunded tool) blocks nothing', s)


def satisfaction(fails):
    print('S: coverage gaps, acceptance and control retirement')
    base = {'gitleaks': st('gitleaks')}
    r = ev(signals={'wordpress': 'true'}, states=base)
    w = ob(r, 'wordpress-components')
    check(w['state'] == SO.COVERAGE_GAP and w['outcome'] == SO.OUT_NOT_SATISFIED and w['cause'] == SO.CAUSE_GAP,
          'S1 a required control with no provider adopted or left is a visible COVERAGE_GAP', w)
    check(w['route'] == SO.ROUTE_DECISION and ev(signals={'wordpress': 'true'}, states=base, stage='crawl')
          ['obligations'][3]['route'] == SO.ROUTE_ADVISORY, 'R1 a COVERAGE_GAP needs a decision at walk, advisory at crawl')
    pol = policy()
    acc = {'obligation': 'wordpress-components', 'accepted_by': 'risk-owner-1', 'risk_owner': 'risk-owner-1',
           'decided_on': '2026-11-20', 'expires': '2027-01-31', 'reference': 'RISK-7'}
    pol['coverage_gap_acceptances'] = [acc]
    r = ev(pol=pol, signals={'wordpress': 'true'}, states=base)
    w = ob(r, 'wordpress-components')
    check(w['state'] == SO.GAP_ACCEPTED and w['route'] == SO.ROUTE_PROCEED_NAMED and w['outcome'] == SO.OUT_NOT_SATISFIED
          and w['cause'] == SO.CAUSE_ACCEPTED and w['acceptance']['reference'] == 'RISK-7',
          'S1 a time-bound acceptance by the risk owner: GAP_ACCEPTED, named, never SATISFIED', w)
    check('wordpress-components(GAP_ACCEPTED' in r['gate']['accepted'], 'S1 the gate names the accepted gap', r['gate'])
    for label, mut in (('expired', {'expires': '2026-11-24'}), ('no risk owner', {'risk_owner': ''}),
                       ('accepted by someone other than the risk owner', {'accepted_by': 'dev1'}),
                       ('longer than the policy maximum', {'expires': '2027-06-01'}), ('undated', {'decided_on': ''})):
        p2 = copy.deepcopy(pol)
        p2['coverage_gap_acceptances'][0].update(mut)
        w2 = ob(ev(pol=p2, signals={'wordpress': 'true'}, states=base), 'wordpress-components')
        check(w2['state'] == SO.COVERAGE_GAP, 'N3 an acceptance %s does not hold: COVERAGE_GAP' % label, w2['state'])
    pol = policy()
    ret = {'obligation': 'wordpress-components', 'decided_by': 'security-lead', 'risk_owner': 'risk-owner-1',
           'residual_risk_accepted_by': 'risk-owner-1', 'decided_on': '2026-11-20', 'reference': 'SEC-DEC-9'}
    pol['control_retirements'] = [ret]
    w = ob(ev(pol=pol, signals={'wordpress': 'true'}, states=base), 'wordpress-components')
    check(w['state'] == SO.CONTROL_RETIRED and not w['required'] and w['cause'] == SO.CAUSE_CONTROL_RETIRED,
          'S1 a control retirement whose residual risk the risk owner accepted: CONTROL_RETIRED', w)
    for label, mut in (('accepted by someone else', {'residual_risk_accepted_by': 'dev1'}),
                       ('with no risk owner', {'risk_owner': '', 'residual_risk_accepted_by': ''}),
                       ('with no deciding security approver', {'decided_by': ''})):
        p2 = copy.deepcopy(pol)
        p2['control_retirements'][0].update(mut)
        w2 = ob(ev(pol=p2, signals={'wordpress': 'true'}, states=base), 'wordpress-components')
        check(w2['state'] == SO.COVERAGE_GAP and w2['required'], 'N4 a control retirement %s does not retire it' % label)
    r = ev(signals={'deploy_targets': '[{"adapter":"containerapp"}]'}, states=base)
    check(ob(r, 'dast')['state'] == SO.EVALUATED_ELSEWHERE and 'dast' not in r['gate']['gaps'],
          'E1 a promotion-phase obligation (DAST) is evaluated at promotion, not at the pull-request gate')
    for o in ev(signals={'python': 'true', 'wordpress': 'true'}, states=base)['obligations']:
        if not ('outcome' in o and 'cause' in o and o['outcome'] in SO.OUTCOMES):
            check(False, 'E1 outcome and cause are separate fields (%s)' % o['obligation'], o)
            break
    else:
        check(True, 'E1 outcome and cause are separate fields on every obligation')


def tokens(fails):
    print('N1: token presence never decides an obligation')
    os.environ['SONAR_TOKEN'] = 'present-but-irrelevant'
    try:
        r = ev(signals={}, states={'gitleaks': st('gitleaks'), 'ext-sonar': st('ext-sonar')})
        check(not ob(r, 'source-sast')['required'], 'N1 a token (and even a run) with no discovery creates no obligation')
    finally:
        del os.environ['SONAR_TOKEN']
    r = ev(signals={'php': 'true'}, states={'gitleaks': st('gitleaks'), 'semgrep': st('semgrep')})
    s = ob(r, 'source-sast')
    check(s['required'] and s['state'] == SO.UNAVAILABLE,
          'N1 discovery with no token: the obligation stays required and the adopted provider is UNAVAILABLE', s)
    src = io.open(os.path.join(ROOT, 'scripts', 'scanner_obligations.py'), encoding='utf-8').read()
    check('os.environ' not in src.split('def self_test')[0] and 'getenv' not in src,
          'N1 the evaluator reads no environment variable at all (no token can reach the decision)')


def closure(fails):
    print('C: a retired tool\'s findings, and a replacement\'s clean result')
    pol = policy()
    pol['provider_lifecycle'].append({'provider': 'ext-sonar', 'state': 'RETIRED', 'on': '2026-11-20', 'by': 'owner',
                                      'replaced_by': 'semgrep'})
    finding = {'identity': 'fp-1', 'scanner': 'ext-sonar', 'issue_type': 'sast', 'rule': 'S2076', 'cwe': 'CWE-78',
               'path': 'app/run.py', 'line': 12, 'seen_at_commit': 'a' * 40}
    rescan = {'scanner': 'semgrep', 'established': True, 'scope': '.', 'commit': 'b' * 40,
              'path_inventory': ['app/run.py', 'app/__init__.py'], 'present_identities': [],
              'issue_types': ['sast'], 'cwes': ['CWE-78'], 'locations': [{'path': 'app/run.py'}]}
    d = SO.closure_decision(finding, rescan, pol)
    check(d['decision'] == SO.CLOSE_EQUIVALENT and d['identity'] == 'fp-1' and not d['missing'],
          'C1 equivalence shown (issue type, location, version, capability): the replacement closes it', d)
    for label, mut, want in (
            ('another issue type', {'issue_types': ['code-quality'], 'cwes': []}, 'issue_type'),
            ('the file not in the replacement\'s inventory', {'path_inventory': ['other.py']}, 'location'),
            ('the file outside the replacement\'s scope', {'scope': 'web/'}, 'location'),
            ('no scanned version recorded', {'commit': ''}, 'version'),
            ('the replacement did not complete', {'established': False}, 'version'),
            ('the replacement still reports it', {'present_identities': ['fp-1']}, 'absent')):
        r2 = dict(rescan, **mut)
        d2 = SO.closure_decision(finding, r2, pol)
        check(d2['decision'] == SO.PENDING_VERIFICATION and any(want in m for m in d2['missing']),
              'N5 %s: PENDING_VERIFICATION, %s named' % (label, want), d2)
    p2 = copy.deepcopy(pol)
    p2['obligations'][1]['providers'][0]['detects'] = ['secret']
    d3 = SO.closure_decision(finding, rescan, p2)
    check(d3['decision'] == SO.PENDING_VERIFICATION and any('capability' in m for m in d3['missing']),
          'N5 a replacement that cannot detect the issue type: PENDING_VERIFICATION, capability named', d3)
    d4 = SO.closure_decision(finding, dict(rescan, scanner='ext-sonar'), pol)
    check(d4['decision'] == SO.PENDING_VERIFICATION and any('retired' in m for m in d4['missing']),
          'N5 the retired tool\'s own absence never closes its finding', d4)
    check(d['pending_route'] == 'a verifier who is not the fixer, or an authorised disposition' or
          SO.closure_decision(finding, dict(rescan, commit=''), pol)['pending_route'],
          'N5 a pending closure names who may close it')


def ticket_path(fails):
    """T1: the ticket reconciler's rescan qualification (scripts/ticket_completion.py) uses the same rule."""
    print('T: the ticket path (ticket_completion.qualify_rescan)')
    import ticket_completion as tc
    pol = policy()
    pol['provider_lifecycle'].append({'provider': 'ext-sonar', 'state': 'RETIRED', 'on': '2026-11-20', 'by': 'owner'})
    entry = {'member_identities': ['fp-1'],
             'members': {'fp-1': [{'scanner': 'ext-sonar', 'path': 'app/run.py', 'scan_scope': '.',
                                   'issue_type': 'sast', 'cwe': 'CWE-78'}]}}
    inv = {'state': tc.PATH_INVENTORY_ESTABLISHED, 'paths': ['app/run.py']}
    semgrep = {'scanner': 'semgrep', 'established': True, 'gate': 'PASS', 'execution': 'COMPLETE', 'scope': '.',
               'issue_types': ['sast'], 'cwes': ['CWE-78']}
    cov = {'rows': [semgrep], 'path_inventory': inv}
    v = tc.qualify_rescan(entry, [], cov, run='r1', commit='b' * 40, obligations=pol)
    check(v['verdict'] == tc.RESCAN_QUALIFYING and any('closed through semgrep under shown equivalence' in x
                                                       for x in v['limits']),
          'T1 a retired tool\'s finding closes through the replacement only with equivalence shown', v)
    v = tc.qualify_rescan(entry, [], {'rows': [dict(semgrep, issue_types=['code-quality'], cwes=[])],
                                      'path_inventory': inv}, run='r1', commit='b' * 40, obligations=pol)
    check(v['verdict'] == tc.RESCAN_NOT_VERIFIED and
          [r['reason'] for r in v['reasons']] == [tc.RESCAN_PROVIDER_RETIRED_NO_EQUIVALENCE],
          'T1 without equivalence: RESCAN_PROVIDER_RETIRED_NO_EQUIVALENCE, pending a non-fixer verifier', v)
    v = tc.qualify_rescan(entry, [], {'rows': [], 'path_inventory': inv}, obligations=pol)
    check(v['verdict'] == tc.RESCAN_NOT_VERIFIED and
          v['reasons'][0]['reason'] == tc.RESCAN_PROVIDER_RETIRED_NO_EQUIVALENCE,
          'T1 the retired tool\'s absence alone never qualifies a rescan', v)
    import reconcile_tickets as rt
    check(tc.RESCAN_PROVIDER_RETIRED_NO_EQUIVALENCE in rt.CLEARANCE_BLOCKING_RESCAN,
          'T1 the reconciler\'s own clearance closes nothing on it')
    pol2 = policy()
    v = tc.qualify_rescan(entry, [], {'rows': [semgrep], 'path_inventory': inv}, commit='b' * 40, obligations=pol2)
    check(v['reasons'] and v['reasons'][0]['reason'] == tc.RESCAN_SCANNER_NOT_RUN,
          'T1 a provider that is NOT retired keeps the ordinary rule (its own row is required)', v)


def policy_file(fails):
    print('K: the shipped policy and its wiring')
    pol, probs = SO.load_policy(POLICY_PATH)
    check(pol is not None and not probs, 'K1 scanner-obligations.json validates', probs)
    floor = json.load(io.open(FLOOR_PATH, encoding='utf-8'))
    ids = set(i for c in floor['floor'] for i in c['identities'])
    core = set(i for o in (pol or {}).get('obligations', []) for p in o['providers'] if p['kind'] == 'core'
               for i in p.get('identities') or [p['provider']])
    check(core and core <= ids, 'K2 every core provider identity is a capability-floor identity', sorted(core - ids))
    bad = copy.deepcopy(pol)
    bad['obligations'][0]['providers'][0]['coverage'] = ['not-an-aspect-of-it']
    check(SO.validate(bad), 'N6 a provider claiming coverage its obligation does not define is refused')
    bad = copy.deepcopy(pol)
    bad['provider_lifecycle'] = [{'provider': 'gitleaks', 'state': 'RETIRED', 'on': '2026-11-20'}]
    check(any('by' in p for p in SO.validate(bad)), 'N6 a retirement record without "by" (who) is refused')
    tmp = tempfile.mkdtemp()
    bp = os.path.join(tmp, 'p.json')
    io.open(bp, 'w').write('{not json')
    p = subprocess.run([sys.executable, os.path.join(ROOT, 'scripts', 'scanner_obligations.py'), 'evaluate',
                        '--policy', bp, '--discovery', '{}', '--states', tmp, '--today', TODAY],
                       capture_output=True, text=True)
    check(p.returncode == 3, 'N6 an unreadable policy exits 3 (refused), never an empty obligation list', p.returncode)
    comp = io.open(COMPOSITE, encoding='utf-8').read() if os.path.exists(COMPOSITE) else ''
    check('GITHUB_ACTION_PATH' in comp and 'scanner-obligations.json' in comp and 'scripts/scanner_obligations.py' in comp,
          'K3 the composite runs the kit\'s evaluator over the kit\'s policy (through the action path, not the checkout)')
    wf = io.open(os.path.join(ROOT, '.github', 'workflows', 'reusable-security.yml'), encoding='utf-8').read()
    check('uses: $/.github/actions/scanner-obligations' in wf and 'G_OBL_STATE' in wf,
          'K3 the security gate runs the composite and reads its state')
    # End to end through the CLI: the GitHub outputs the gate reads.
    states = os.path.join(tmp, 'states')
    os.makedirs(states)
    for ident, a, e in (('gitleaks', 'APPLICABLE', 'COMPLETE'), ('semgrep', 'APPLICABLE', 'COMPLETE'),
                        ('ext-sonar', 'NOT_CONFIGURED', 'NOT_RUN')):
        json.dump(st(ident, a, e), io.open(os.path.join(states, 'state-%s.json' % ident), 'w'))
    pp = os.path.join(tmp, 'pol.json')
    json.dump(policy(), io.open(pp, 'w'))
    go = os.path.join(tmp, 'gh_out')
    p = subprocess.run([sys.executable, os.path.join(ROOT, 'scripts', 'scanner_obligations.py'), 'evaluate',
                        '--policy', pp, '--discovery', json.dumps({'python': 'true'}), '--states', states,
                        '--today', TODAY, '--github-output', go, '--json-out', os.path.join(tmp, 'o.json')],
                       capture_output=True, text=True)
    out = io.open(go).read() if os.path.exists(go) else ''
    check(p.returncode == 0 and 'obligation_state=UNAVAILABLE' in out and 'obligation_unavailable=ext-sonar(UNAVAILABLE)' in out,
          'G1 the CLI hands the gate obligation_state and the unavailable provider', (p.returncode, out, p.stderr[-300:]))


def gate(fails):
    """G2: the SHIPPED gate step, run by the KDEC-067 harness, reads the composite's outputs."""
    print('G2: the security gate reads the obligations (shipped step, crawl / walk / run)')
    try:
        import yaml
    except ImportError:
        check(False, 'G2 PyYAML is needed to read the shipped gate step')
        return
    import prove_bootstrap_failure as pbf
    import prove_gate_policy_enforcement as gp
    bash, why = pbf.usable_bash()
    if not bash:
        print('  UNKNOWN  G2 no usable bash here (%s); the gate cases run in the hosted self-test' % why)
        GATE_UNKNOWN.append(why)
        return
    doc = yaml.safe_load(io.open(pbf.WF, encoding='utf-8'))
    steps = doc['jobs']['security-gate'].get('steps') or []
    work = tempfile.mkdtemp()
    crawl = gp.policy_outputs(work, None, environment='dev')
    walk = gp.policy_outputs(work, gp.central([{'id': 'w', 'scope': {'org': 'acme'}, 'rung': 'walk'}]))
    run = gp.policy_outputs(work, gp.central([{'id': 'r', 'scope': {'org': 'acme'}, 'rung': 'run'}]))

    def seeded(state='SATISFIED', unavailable='', gaps='', accepted='', not_required=''):
        d = gp.scanners()
        d['steps.obligations.outputs.obligation_state'] = state
        d['steps.obligations.outputs.obligation_unavailable'] = unavailable
        d['steps.obligations.outputs.obligation_gaps'] = gaps
        d['steps.obligations.outputs.obligation_accepted'] = accepted
        d['steps.rows.outputs.external_not_required'] = not_required
        return d
    sonar, gap = 'ext-sonar(UNAVAILABLE)', 'wordpress-components(COVERAGE_GAP:wordpress-core)'
    acc = 'wordpress-components(GAP_ACCEPTED:wordpress-core:until-2027-01-31)'
    cases = [
        # name, policy, state, unavailable, gaps, accepted, not_required, route, verdict 0?, cause, assurance
        ('crawl_satisfied', crawl, 'SATISFIED', '', '', '', '', 'PROCEED', True, None, 'PASS'),
        ('crawl_token_removed', crawl, 'UNAVAILABLE', sonar, '', '', 'ext-sonar(NOT_CONFIGURED)',
         'PROCEED_WITH_ADVISORY', True, 'SCANNER_DID_NOT_RUN', 'PARTIAL'),
        ('walk_token_removed', walk, 'UNAVAILABLE', sonar, '', '', 'ext-sonar(NOT_CONFIGURED)',
         'EVIDENCE_UNTRUSTED', False, None, 'PARTIAL'),
        ('run_token_removed', run, 'UNAVAILABLE', sonar, '', '', 'ext-sonar(NOT_CONFIGURED)',
         'EVIDENCE_UNTRUSTED', False, None, 'PARTIAL'),
        ('crawl_coverage_gap', crawl, 'COVERAGE_GAP', '', gap, '', '', 'PROCEED_WITH_ADVISORY', True,
         'SCANNER_DID_NOT_RUN', 'PARTIAL'),
        ('walk_coverage_gap', walk, 'COVERAGE_GAP', '', gap, '', '', 'EVIDENCE_UNTRUSTED', False, None, 'PARTIAL'),
        ('run_gap_accepted', run, 'GAP_ACCEPTED', '', '', acc, '', 'PROCEED_WITH_ADVISORY', True, 'COVERAGE_PARTIAL',
         'PARTIAL'),
        ('run_not_evaluated', run, '', '', '', '', '', 'EVIDENCE_UNTRUSTED', False, None, None),
        ('crawl_not_evaluated', crawl, '', '', '', '', '', 'EVIDENCE_UNTRUSTED', False, None, None),
    ]
    for name, pol, state, una, gaps, accd, notreq, want_route, want_ok, want_cause, want_as in cases:
        r = gp.run_job(bash, steps, pol, seeded(state, una, gaps, accd, notreq))
        causes = set(c for c in (r['causes'] or '').split(',') if c)
        assurance = r['gate'].get('assurance_state')
        good = ((r['verdict_rc'] == 0) == want_ok and r['route'] == want_route and
                (want_cause is None or want_cause in causes) and (want_as is None or assurance == want_as))
        if una and '"ext-sonar":"UNAVAILABLE"' not in r['gate'].get('scanner_states', ''):
            good = False
        if una and '"ext-sonar":"NOT_CONFIGURED"' in r['gate'].get('scanner_states', ''):
            good = False
        check(good, 'G2 %-22s route=%s assurance=%s verdict=%s' % (name, r['route'], assurance, r['verdict_rc']),
              'wanted %s %s %s; scanner_states %s\n%s' % (want_route, want_as, want_ok,
                                                           r['gate'].get('scanner_states'), r['log'][-600:]))


GATE_UNKNOWN = []


def mutants(fails):
    print('M: mutants (each must be caught)')
    caught = 0
    cases = [
        ('token decides', 'provider_ran', lambda orig: (lambda s, ids: SO.RAN)),
        ('repo removal honoured', 'governed_exception', lambda orig: (lambda *a, **k: {'exception_ref': 'x'})),
        ('expired acceptance honoured', 'acceptance_valid', lambda orig: (lambda *a, **k: (True, ''))),
        ('partial counted as full', 'covered_aspects', lambda orig: (lambda o, ps: list(o['coverage']))),
        ('closure without location', 'location_matches', lambda orig: (lambda f, r: True)),
    ]
    for label, name, make in cases:
        orig = getattr(SO, name)
        setattr(SO, name, make(orig))
        before = len(FAILS)
        silent = io.StringIO()
        real = sys.stdout
        sys.stdout = silent
        try:
            for fn in (obligations, providers, satisfaction, tokens, closure):
                try:
                    fn([])
                except Exception:  # noqa: BLE001 -- a crash also kills the mutant
                    FAILS.append('crash')
        finally:
            sys.stdout = real
            setattr(SO, name, orig)
        killed = len(FAILS) > before
        del FAILS[before:]
        caught += killed
        print('  %s  mutant "%s" %s' % ('PASS' if killed else 'FAIL', label, 'caught' if killed else 'SURVIVED'))
        if not killed:
            FAILS.append('mutant %s survived' % label)
    return caught


def main():
    print('Scanner obligations (KDEC-069): discovery decides; a token says only whether a provider can run')
    for fn in (obligations, providers, satisfaction, tokens, closure, ticket_path, policy_file, gate):
        fn(FAILS)
    if FAILS:
        print('FAIL: %d claim(s)' % len(FAILS))
        return 1
    mutants(FAILS)
    if FAILS:
        print('FAIL: %d claim(s)' % len(FAILS))
        return 1
    if GATE_UNKNOWN:
        print('UNKNOWN: every other claim held; the shipped gate cases need a usable bash (never PASS).')
        return 2
    print('PASS: obligation from discovery and policy, providers with coverage, lifecycle records, visible gaps, '
          'equivalence-only closure; five mutants caught.')
    return 0


if __name__ == '__main__':
    sys.exit(main())

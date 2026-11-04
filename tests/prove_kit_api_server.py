#!/usr/bin/env python3
"""The kit's API, run side: intake refusals, tickets through the reconciler, findings, the result (KDEC-035).

WHY THIS EXISTS

    The run that answers a call holds the tracker credential and reads the security evidence, so
    every way it can be wrong is consequential:

      * an API-created ticket and a pipeline-created ticket for ONE finding must be ONE ticket --
        the API writes through the kit's reconciler, with its stamp and its lookup-before-create,
        never beside it;
      * a write of a SUBSET of findings must never close the others (the reconciler closes a
        ticket whose finding is absent from "this run's" findings; a subset is not a run);
      * the API tickets only what the kit's own scan established on the default branch -- an
        inline finding, a disposition or a branch run is refused by name;
      * a deploy requested through the API still meets every gate (approval bound to the digest,
        readiness, release block), and at least one human approver: the API never approves;
      * "the job succeeded" is not "it deployed": without the deploy's evidence the call FAILED;
      * every refusal is named, and the same refusal reaches the caller through the check run.

HOW

    The GitHub API of a SIMULATED GHE.com tenant is tests/_github_api_stub.py, in-process (the
    server and the client run unmodified; kit_api._transport is the one door). Jira and Azure
    DevOps are the stateful, documented-shape stand-ins of tests/prove_ticket_backends.py
    (urllib.request.urlopen replaced): no request can leave the machine. The pipeline's own
    reconciliation is run beside the API's -- scripts/reconcile_tickets.py main(), as the
    reusable workflow runs it -- so the dedupe is proven across the two writers, both orders.

CASES
    S1  intake refuses by name, before anything is read or written: every intake refusal in
        api/v1/refusals.json is produced, and each reaches the caller as a readable result
    S2  tickets.write on Jira: one ticket; a repeat creates nothing; the pipeline then creates
        nothing for that finding; the other order too; dry run writes nothing; a subset closes
        nothing; a finding the run did not establish and an unusable source run are refused
    S3  the same dedupe on Azure DevOps
    S4  tickets.get, tickets.search (fingerprint, finding id, cluster key, severity, status, cve,
        kev, text, repo) and tickets.comment (stamped only, prefixed, never a state change)
    S5  findings.search / findings.get: filters, KEV true/false and UNAVAILABLE (never false),
        "latest", ticket binding from the ledger, no code content in the answer
    S6  finish: a scan's verdict is reported as the kit's word (BLOCKED is a completed scan);
        no verdict, or a skipped scan, FAILED; a deploy that reported no outcome FAILED, never
        "deployed"
    S7  a release requested through the API meets the gates: the deploy's own decisions refuse
        it without approval, with the API caller approving, at an unready zone, under a block
    S8  the round trip on the simulated ghe.com host: submit -> run -> check run -> status, every
        request to api.example.ghe.com, the token nowhere else

EXIT  0 every case held  1 a case failed  2 could not be checked
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

import _github_api_stub as gs  # noqa: E402

FAILS = []
PRODUCED = set()       # refusal codes this proof saw the run produce


def check(cond, msg):
    if not cond:
        FAILS.append(msg)
    return cond


def imports():
    try:
        import kit_api
        import kit_api_server
        import reconcile_tickets
        import prove_ticket_backends as tb
        import finding_correlation as fc
        return kit_api, kit_api_server, reconcile_tickets, tb, fc
    except ImportError as exc:
        print('FAIL: cannot import the API server (%s): scripts/kit_api_server.py does not exist' % exc)
        return None


# ── the evidence of one security run ─────────────────────────────────────────────────

def observations(fc):
    recs = [
        {'scanner': 'trivy', 'tool': 'trivy', 'scanner_version': '0.71.2', 'rule_id': 'CVE-2021-44228',
         'severity': 'critical', 'line': 12, 'canonical_path': 'pom.xml',
         'finding_subject': 'SOURCE_DEPENDENCY', 'state': 'FINGERPRINTED', 'identity': 'a1' * 16,
         'what': 'cve-2021-44228', 'where': 'pom.xml', 'content': 'log4j-core 2.14.1',
         'identity_scope': '', 'what_aliases': ['cve-2021-44228', 'ghsa-jfh8-c2jp-5v3q'],
         'cwe': 'CWE-502', 'reason': '', 'detail': '', 'fp': 'f1' * 8, 'job': 'deps-scan',
         'row_established': True},
        {'scanner': 'semgrep', 'tool': 'semgrep', 'scanner_version': '1.178.0',
         'rule_id': 'python.lang.security.audit.eval-detected', 'severity': 'high', 'line': 40,
         'canonical_path': 'app/views.py', 'finding_subject': 'SOURCE', 'state': 'FINGERPRINTED',
         'identity': 'b2' * 16, 'what': 'cwe-95', 'where': 'app/views.py:render',
         'content': 'eval(<str>)', 'identity_scope': '', 'what_aliases': ['cwe-95'],
         'cwe': 'CWE-95', 'reason': '', 'detail': '', 'fp': 'f2' * 8, 'job': 'sast-semgrep',
         'row_established': True},
        {'scanner': 'gitleaks', 'tool': 'gitleaks', 'scanner_version': '8.21.2',
         'rule_id': 'generic-api-key', 'severity': 'high', 'line': 3, 'canonical_path': 'config.py',
         'finding_subject': 'SOURCE', 'state': 'UNFINGERPRINTABLE', 'identity': None,
         'what': '', 'where': '', 'content': '', 'identity_scope': '', 'what_aliases': [],
         'cwe': '', 'reason': 'SECRET_SUBJECT_NOT_BASELINEABLE', 'detail': '', 'fp': 'f3' * 8,
         'job': 'secret-scan', 'row_established': True},
    ]
    corr = fc.correlate(recs)
    for cl in corr['clusters']:
        for i in cl['members']:
            recs[i]['correlation_tier'] = cl['tier']
            recs[i]['cluster_key'] = cl['cluster_key']
    return recs


COVERAGE = {'schema': 'findings-coverage/1', 'rows': [
    {'scanner': 'trivy', 'job': 'deps-scan', 'established': True, 'gate': 'FINDINGS', 'scope': '.'},
    {'scanner': 'semgrep', 'job': 'sast-semgrep', 'established': True, 'gate': 'FINDINGS', 'scope': '.'}]}
KEV_FEED = {'catalogVersion': '2026.11.01', 'dateReleased': '2026-11-01T00:00:00Z',
            'vulnerabilities': [{'cveID': 'CVE-2021-44228'}]}


class World(object):
    """One repository: the GitHub stub, a security run with evidence, a ledger, a tracker env."""

    def __init__(self, ka, tracker_env, tmp, findings=None):
        self.ka = ka
        self.stub = gs.StubGitHub(repo='octo-org/app')
        ka._transport = self.stub.transport
        self.tmp = tmp
        self.findings = findings
        self.sec_run = self.stub.add_run(workflow='build-deploy.yml', head_sha='c' * 40)
        self.stub.add_artifact(self.sec_run, 'security-report-1', {
            'findings.json': json.dumps(findings), 'findings-coverage.json': json.dumps(COVERAGE)})
        self.ledger = os.path.join(tmp, 'ticket-ledger.json')
        self.kev = os.path.join(tmp, 'kev.json')
        io.open(self.kev, 'w', encoding='utf-8').write(json.dumps(KEV_FEED))
        self.env = dict(tracker_env)
        self.env.update({
            'GITHUB_API_URL': gs.API_URL, 'GITHUB_TOKEN': gs.TOKEN, 'GITHUB_REPOSITORY': self.stub.repo,
            'GITHUB_SERVER_URL': 'https://example.ghe.com', 'GITHUB_SHA': self.stub.head_sha,
            'GITHUB_ACTOR': 'tines-kit-app[bot]', 'GITHUB_TRIGGERING_ACTOR': 'tines-kit-app[bot]',
            'KIT_API_DEFAULT_BRANCH': 'main', 'KIT_API_LEDGER': self.ledger,
            'KIT_API_SECURITY_WORKFLOW': 'build-deploy.yml', 'KIT_API_KEV_FEED_FILE': self.kev,
            'KIT_API_TODAY': '2026-11-03', 'RUNNER_TEMP': tmp,
            'KIT_API_OPERATIONS': 'tickets.write,tickets.comment,tickets.get,tickets.search,'
                                  'findings.get,findings.search,scan.request,deploy.request',
            'KIT_API_DEPLOY_ENVIRONMENTS': 'dev,test,uat,prod',
            'KIT_API_BUILD_DEPLOY_ENVIRONMENTS': 'dev,test'})

    def client(self):
        cl, ref = self.ka.client_from_env({'GITHUB_API_URL': gs.API_URL, 'GH_TOKEN': gs.TOKEN})
        assert cl is not None, ref
        return cl

    def call(self, ks, operation, params, key=None, ref='main', event='workflow_dispatch',
             request_override=None, cid_override=None, key_input_override=None, extra_env=None,
             outcome_env=None, dry_run=False):
        """The whole call as the workflow runs it: intake, then the operation's job, then the
        result -- every phase through the server's own entry points, against the stub."""
        env_req = self.ka.build_request(operation, params, idempotency_key=key, dry_run=dry_run,
                                        on_behalf_of='analyst@example.invalid')
        cid = env_req['correlation_id']
        rid = self.stub.add_run(workflow='kit-api.yml', branch=ref, status='in_progress',
                                title=self.ka.run_title(cid), event=event)
        env = dict(self.env)
        env.update({'KIT_API_REQUEST': request_override if request_override is not None
                    else json.dumps(env_req),
                    'KIT_API_CORRELATION_ID': cid_override or cid,
                    'KIT_API_IDEMPOTENCY_KEY': key if key_input_override is None else key_input_override,
                    'GITHUB_EVENT_NAME': event, 'GITHUB_REF': 'refs/heads/%s' % ref,
                    'GITHUB_RUN_ID': str(rid), 'GITHUB_RUN_ATTEMPT': '1'})
        env['KIT_API_IDEMPOTENCY_KEY'] = env['KIT_API_IDEMPOTENCY_KEY'] or ''
        env.update(extra_env or {})
        out = tempfile.mkdtemp(dir=self.tmp)
        cl = self.client()
        intake = ks.intake(env, cl, out)
        if intake.get('accepted') and intake.get('idem_hash') and intake.get('write'):
            # The workflow's upload-artifact step: the marker a later duplicate finds.
            self.stub.add_artifact(rid, 'kit-api-idem-%s' % intake['idem_hash'],
                                   {'marker.json': json.dumps({'correlation_id': cid})})
        op_result = None
        if intake.get('accepted'):
            job = self.ka.OPERATIONS[intake['operation']]['job']
            if job == 'tickets':
                op_result = ks.tickets(intake, env, cl, out)
            elif job == 'findings':
                op_result = ks.findings(intake, env, cl, out)
            else:
                env.update(outcome_env or {})
        result = ks.finish(intake, env, cl, out, op_result=op_result)
        self.stub.runs[rid].update(status='completed', conclusion='success')
        if intake.get('refusal'):
            PRODUCED.add(intake['refusal']['code'])
        if result.get('refusal'):
            PRODUCED.add(result['refusal']['code'])
        # What the CALLER sees, through the check run alone.
        seen = self.ka.status(cl, self.stub.repo, cid)
        return result, seen, intake


def write_ledger(path, doc):
    io.open(path, 'w', encoding='utf-8').write(json.dumps({'schema': 1, 'clusters': doc}))


def read_ledger(path):
    if not os.path.exists(path):
        return {}
    return json.load(io.open(path, encoding='utf-8')).get('clusters') or {}


# ── S1 ────────────────────────────────────────────────────────────────────────────────

def s1_intake(ka, ks, rt, tb, fc, tmp):
    r = tb.install(tb.Replay())
    tb.JiraTracker(r)
    w = World(ka, tb.JIRA_ENV, tmp, observations(fc))
    sel = {'source': {'run_id': w.sec_run}, 'select': {'identities': ['a1' * 16]}}
    cases = [
        ('unparseable', dict(operation='findings.search', params={'run_id': 'latest'},
                             request_override='{not json'), 'API_REQUEST_UNPARSEABLE'),
        ('version', dict(operation='findings.search', params={'run_id': 'latest'},
                         request_override=None), None),
        ('unknown op', dict(operation='findings.search', params={'run_id': 'latest'}), None),
        ('schema', dict(operation='findings.search', params={'run_id': 'newest'}), 'API_SCHEMA_VIOLATION'),
        ('correlation', dict(operation='findings.search', params={'run_id': 'latest'},
                             cid_override='kapi-20261103T000000Z-000000000000'), 'API_CORRELATION_MISMATCH'),
        ('no key', dict(operation='tickets.write', params=sel), 'API_IDEMPOTENCY_KEY_REQUIRED'),
        ('key mismatch', dict(operation='tickets.write', params=sel, key='key-one-1234',
                              key_input_override='key-two-1234'), 'API_IDEMPOTENCY_KEY_REQUIRED'),
        ('branch', dict(operation='tickets.search', params={}, ref='feature/x'), 'API_REF_NOT_DEFAULT_BRANCH'),
        ('transport', dict(operation='deploy.request', key='rel-0001-abcd',
                           params={'mode': 'promote', 'environment': 'prod', 'promote_from_run_id': 7,
                                   'promote_from_environment': 'test'},
                           event='repository_dispatch'), 'API_TRANSPORT_NOT_PERMITTED'),
        ('disposition', dict(operation='tickets.write', key='disp-0001-abcd',
                             params=dict(sel, requested_disposition='risk_acceptance')),
         'API_DISPOSITION_NOT_VIA_API'),
        ('filter', dict(operation='tickets.search', params={'filters': {'cve': 'CVE-2021-44228'}}),
         'API_FILTER_NEEDS_FINDINGS_RUN'),
        ('break-glass', dict(operation='deploy.request', key='rel-0002-abcd',
                             params={'mode': 'promote', 'environment': 'prod', 'promote_from_run_id': 7,
                                     'promote_from_environment': 'test', 'release_path': 'break-glass'}),
         'API_RELEASE_PATH_NOT_PERMITTED'),
        ('env not listed', dict(operation='deploy.request', key='rel-0003-abcd',
                                params={'mode': 'promote', 'environment': 'staging',
                                        'promote_from_run_id': 7, 'promote_from_environment': 'test'}),
         'API_ENVIRONMENT_NOT_PERMITTED'),
        ('build prod', dict(operation='deploy.request', key='rel-0004-abcd',
                            params={'mode': 'build-deploy', 'environment': 'prod'}),
         'API_ENVIRONMENT_NOT_PERMITTED'),
        ('no source', dict(operation='deploy.request', key='rel-0005-abcd',
                           params={'mode': 'promote', 'environment': 'prod'}), 'API_PROMOTION_SOURCE_REQUIRED'),
        ('unreviewed', dict(operation='deploy.request', key='rel-0006-abcd',
                            params={'mode': 'promote', 'environment': 'uat', 'promote_from_run_id': 7,
                                    'promote_from_environment': 'test'}), 'API_DEPLOY_NEEDS_HUMAN_APPROVAL'),
    ]
    for label, kw, want in cases:
        if label == 'version':
            req = ka.build_request('findings.search', {'run_id': 'latest'})
            req['api_version'] = 'v2'
            kw = dict(kw, request_override=json.dumps(req), cid_override=req['correlation_id'])
            want = 'API_VERSION_UNSUPPORTED'
        if label == 'unknown op':
            req = ka.build_request('findings.search', {'run_id': 'latest'})
            req['operation'] = 'tickets.delete'
            kw = dict(kw, request_override=json.dumps(req), cid_override=req['correlation_id'])
            want = 'API_OPERATION_UNKNOWN'
        result, seen, intake = w.call(ks, **kw)
        got = (intake.get('refusal') or {}).get('code')
        check(got == want, 'S1 %s: intake answered %r, expected %s' % (label, got, want))
        check(result.get('api_state') == 'API_REFUSED' and (result.get('refusal') or {}).get('code') == want,
              'S1 %s: the result did not carry the refusal: %r' % (label, result.get('refusal')))
        if label not in ('unparseable', 'correlation', 'version', 'unknown op'):
            check(seen.get('api_state') == 'API_REFUSED' and (seen.get('refusal') or {}).get('code') == want,
                  'S1 %s: the caller read %r through the check run, not the refusal'
                  % (label, (seen.get('api_state'), seen.get('refusal'))))
    # Not enabled: the repository's list without writes.
    enabled = w.env['KIT_API_OPERATIONS']
    w.env['KIT_API_OPERATIONS'] = ''
    result, _seen, intake = w.call(ks, 'tickets.write', sel, key='write-0001-abcd')
    check((intake.get('refusal') or {}).get('code') == 'API_OPERATION_NOT_ENABLED',
          'S1: a write the repository never enabled was %r' % intake.get('refusal'))
    w.env['KIT_API_OPERATIONS'] = enabled
    # A reviewed environment is accepted, and the deploy inputs come from the validated request.
    w.stub.protect('prod', reviewers=1, prevent_self_review=True)
    result, seen, intake = w.call(ks, 'deploy.request',
                                  {'mode': 'promote', 'environment': 'prod', 'promote_from_run_id': 7,
                                   'promote_from_environment': 'test'}, key='rel-0007-abcd')
    check(intake.get('accepted') is True and (intake.get('deploy') or {}).get('environment') == 'prod'
          and (intake.get('deploy') or {}).get('promote_from_run_id') == '7',
          'S1: a reviewed prod promotion was not accepted with its inputs: %r' % intake)
    # Self-review allowed is not a human approval the API can rely on.
    w.stub.protect('test', reviewers=1, prevent_self_review=False)
    _r, _s, intake = w.call(ks, 'deploy.request', {'mode': 'build-deploy', 'environment': 'test'},
                            key='rel-0008-abcd')
    check((intake.get('refusal') or {}).get('code') == 'API_DEPLOY_NEEDS_HUMAN_APPROVAL',
          'S1: an environment that lets the requester approve themselves was %r' % intake.get('refusal'))
    # The same key twice: the second names the first and does nothing.
    w.stub.protect('test', reviewers=1, prevent_self_review=True)
    r1, _s, i1 = w.call(ks, 'deploy.request', {'mode': 'build-deploy', 'environment': 'test'},
                        key='rel-0009-abcd')
    r2, s2, i2 = w.call(ks, 'deploy.request', {'mode': 'build-deploy', 'environment': 'test'},
                        key='rel-0009-abcd')
    check(i1.get('accepted') and (i2.get('refusal') or {}).get('code') == 'API_DUPLICATE_REQUEST'
          and i1['correlation_id'] in (i2['refusal'].get('detail') or ''),
          'S1: a repeated key was not refused naming the first call: %r' % i2.get('refusal'))
    # A key whose history cannot be read is not risked.
    w.stub.fail[('GET', r'/actions/artifacts$')] = 500
    _r, _s, i3 = w.call(ks, 'deploy.request', {'mode': 'build-deploy', 'environment': 'test'},
                        key='rel-0010-abcd')
    w.stub.fail.clear()
    check((i3.get('refusal') or {}).get('code') == 'API_IDEMPOTENCY_UNVERIFIED',
          'S1: an unreadable idempotency history was %r' % i3.get('refusal'))
    # Nothing a refused intake guards was touched: no tracker call at all in this case.
    jira_calls = [q for q in r.requests]
    check(not jira_calls, 'S1: intake reached the tracker: %d request(s)' % len(jira_calls))


# ── S2 / S3 ───────────────────────────────────────────────────────────────────────────

def _pipeline(rt, env, findings_path, ledger, cov_path):
    """The pipeline's own reconciliation, as reusable-ticket-reconcile.yml runs it."""
    old = dict(os.environ)
    out = sys.stdout
    try:
        os.environ.update(env)
        sys.stdout = io.StringIO()
        return rt.main(['reconcile_tickets.py', '--findings', findings_path, '--ledger', ledger,
                        '--apply', '--today', '2026-11-03', '--coverage', cov_path])
    finally:
        sys.stdout = out
        os.environ.clear()
        os.environ.update(old)


def _dedupe(ka, ks, rt, tb, fc, tmp, kind):
    obs = observations(fc)
    fpath = os.path.join(tmp, 'findings-%s.json' % kind)
    cpath = os.path.join(tmp, 'findings-coverage.json')
    io.open(fpath, 'w', encoding='utf-8').write(json.dumps(obs))
    io.open(cpath, 'w', encoding='utf-8').write(json.dumps(COVERAGE))

    def tracker():
        r = tb.install(tb.Replay())
        if kind == 'jira':
            t = tb.JiraTracker(r)
            return t, (lambda: len(t.issues)), tb.JIRA_ENV
        t = tb.AzdoTracker(r)
        return t, (lambda: len([i for i in t.items if i >= 500])), tb.AZDO_ENV
    tb._sleeps(rt)
    sel_a = {'source': {'run_id': None}, 'select': {'identities': ['a1' * 16]}}

    # API first, then the API again, then the pipeline.
    t, count, tenv = tracker()
    d = tempfile.mkdtemp(dir=tmp)
    w = World(ka, tenv, d, obs)
    sel_a['source']['run_id'] = w.sec_run
    res, seen, _i = w.call(ks, 'tickets.write', sel_a, key='%s-write-0001' % kind)
    check(res.get('api_state') == 'API_COMPLETED' and count() == 1,
          'S2 %s: the API write made %d ticket(s), state %r: %r' % (kind, count(), res.get('api_state'),
                                                                  res.get('notes')))
    check(seen.get('api_state') == 'API_COMPLETED' and seen.get('data', {}).get('created'),
          'S2 %s: the caller did not read the created ticket back: %r' % (kind, seen.get('api_state')))
    created = (res.get('data') or {}).get('created') or []
    stamp = created[0]['cluster_key'] if created else None
    res2, _s, _i = w.call(ks, 'tickets.write', sel_a, key='%s-write-0002' % kind)
    check(count() == 1 and not (res2.get('data') or {}).get('created'),
          'S2 %s: a second API write created another ticket (%d)' % (kind, count()))
    rc = _pipeline(rt, tenv, fpath, w.ledger, cpath)
    check(rc in (0, 1) and count() == 2,
          'S2 %s: after the API ticketed A, the pipeline ended with %d ticket(s) (rc %s); expected 2 '
          '(B new, A found by its stamp)' % (kind, count(), rc))
    if kind == 'jira':
        stamps = sorted(i['fields']['customfield_10001'] for i in t.issues.values())
    else:
        stamps = sorted(it['fields'].get('Custom.KitClusterKey') for i, it in t.items.items() if i >= 500)
    check(stamp in stamps and len(set(stamps)) == len(stamps),
          'S2 %s: the stamps %r are not one per finding (API stamp %r)' % (kind, stamps, stamp))

    # Pipeline first, then the API: the API creates nothing.
    t, count, tenv = tracker()
    d = tempfile.mkdtemp(dir=tmp)
    w = World(ka, tenv, d, obs)
    sel_a['source']['run_id'] = w.sec_run
    rc = _pipeline(rt, tenv, fpath, w.ledger, cpath)
    before = count()
    res, _s, _i = w.call(ks, 'tickets.write', sel_a, key='%s-write-0003' % kind)
    check(before == 2 and count() == 2 and res.get('api_state') == 'API_COMPLETED',
          'S2 %s: after the pipeline, the API write moved the count %d -> %d (%r)'
          % (kind, before, count(), res.get('api_state')))
    outcomes = (res.get('data') or {}).get('outcomes') or {}
    check(outcomes.get('LEDGER_BOUND') or outcomes.get('BACKEND_BOUND'),
          'S2 %s: the API write did not bind the pipeline\'s ticket: %r' % (kind, outcomes))
    if kind == 'jira':
        # A subset never closes the rest: B's ticket is open and nothing was transitioned.
        check(not t.transitions_posted, 'S2 jira: the API write transitioned tickets %r'
              % t.transitions_posted)
        # Dry run: plans, writes nothing.
        t2, count2, tenv2 = tracker()
        d2 = tempfile.mkdtemp(dir=tmp)
        w2 = World(ka, tenv2, d2, obs)
        res_d, _s, _i = w2.call(ks, 'tickets.write', {'source': {'run_id': w2.sec_run},
                                                      'select': {'identities': ['a1' * 16]}},
                                key='jira-dry-0001', dry_run=True)
        check(count2() == 0 and res_d.get('api_state') == 'API_COMPLETED' and
              ((res_d.get('data') or {}).get('created') or [{}])[0].get('planned'),
              'S2: a dry run wrote %d ticket(s) or planned nothing: %r' % (count2(), res_d.get('data')))
        # Only what the kit established, from a usable run.
        res_x, _s, _i = w2.call(ks, 'tickets.write', {'source': {'run_id': w2.sec_run},
                                                      'select': {'identities': ['cd' * 16]}},
                                key='jira-unk-00001')
        check((res_x.get('refusal') or {}).get('code') == 'API_FINDING_NOT_KIT_ESTABLISHED' and count2() == 0,
              'S2: a finding the run never established was %r' % res_x.get('refusal'))
        PRODUCED.add((res_x.get('refusal') or {}).get('code'))
        branch_run = w2.stub.add_run(branch='feature/x')
        w2.stub.add_artifact(branch_run, 'security-report-1', {'findings.json': json.dumps(obs)})
        expired = w2.stub.add_run()
        w2.stub.add_artifact(expired, 'security-report-1', {'findings.json': '[]'}, expired=True)
        for label, rid in (('a branch run', branch_run), ('an expired artifact', expired),
                           ('a run that does not exist', 123)):
            res_e, _s, _i = w2.call(ks, 'tickets.write', {'source': {'run_id': rid},
                                                          'select': {'identities': ['a1' * 16]}},
                                    key='jira-src-%05d' % rid)
            check((res_e.get('refusal') or {}).get('code') == 'API_EVIDENCE_UNAVAILABLE',
                  'S2: %s as the source was %r' % (label, res_e.get('refusal')))
        check(count2() == 0, 'S2: an unusable source still produced a ticket')


def s2_jira(ka, ks, rt, tb, fc, tmp):
    _dedupe(ka, ks, rt, tb, fc, tmp, 'jira')


def s3_azdo(ka, ks, rt, tb, fc, tmp):
    _dedupe(ka, ks, rt, tb, fc, tmp, 'azdo')


# ── S4 ────────────────────────────────────────────────────────────────────────────────

def s4_ticket_reads(ka, ks, rt, tb, fc, tmp):
    obs = observations(fc)
    r = tb.install(tb.Replay())
    t = tb.JiraTracker(r)
    tb._sleeps(rt)
    w = World(ka, tb.JIRA_ENV, tmp, obs)
    fpath = os.path.join(tmp, 'f.json')
    cpath = os.path.join(tmp, 'findings-coverage.json')
    io.open(fpath, 'w', encoding='utf-8').write(json.dumps(obs))
    io.open(cpath, 'w', encoding='utf-8').write(json.dumps(COVERAGE))
    _pipeline(rt, tb.JIRA_ENV, fpath, w.ledger, cpath)
    led = read_ledger(w.ledger)
    check(len(led) == 2, 'S4: the pipeline left %d ledger entries' % len(led))
    key_a = [k for k, v in led.items() if 'a1' * 16 in (v.get('member_identities') or [])]
    ref_a = led[key_a[0]]['ref'] if key_a else None
    res, seen, _i = w.call(ks, 'tickets.get', {'ref': ref_a})
    tk = (res.get('data') or {}).get('ticket') or {}
    check(res.get('api_state') == 'API_COMPLETED' and tk.get('cluster_key') == (key_a or [''])[0]
          and tk.get('block', {}).get('severity') == 'critical',
          'S4: tickets.get by ref answered %r' % ((res.get('api_state'), tk),))
    res, _s, _i = w.call(ks, 'tickets.get', {'cluster_key': key_a[0]})
    check(((res.get('data') or {}).get('ticket') or {}).get('ref') == ref_a,
          'S4: tickets.get by cluster key answered %r' % res.get('data'))

    def search(filters, **more):
        params = dict({'filters': filters}, **more)
        res, _s, _i = w.call(ks, 'tickets.search', params)
        return res, sorted(x.get('cluster_key') for x in (res.get('data') or {}).get('tickets') or [])
    _r, all_ = search({})
    check(len(all_) == 2, 'S4: search with no filter found %r' % all_)
    for label, filters, more, want in (
            ('status open', {'status': 'open'}, {}, 2),
            ('status closed', {'status': 'closed'}, {}, 0),
            ('severity critical', {'severity': ['critical']}, {}, 1),
            ('cluster key', {'cluster_key': key_a[0]}, {}, 1),
            ('finding id', {'finding_id': 'b2' * 16}, {}, 1),
            ('fingerprint', {'fingerprint': 'f1' * 8}, {}, 1),
            ('cve', {'cve': 'CVE-2021-44228'}, {'findings_run_id': w.sec_run}, 1),
            ('kev', {'kev': True}, {'findings_run_id': 'latest'}, 1),
            ('text', {'text': 'views.py'}, {'findings_run_id': w.sec_run}, 1),
            ('repo', {'repo': 'octo-org/app'}, {}, 2)):
        res, keys = search(filters, **more)
        check(res.get('api_state') == 'API_COMPLETED' and len(keys) == want,
              'S4 search %s: %d result(s) (%r), expected %d' % (label, len(keys), res.get('api_state'), want))
    res, _k = search({'repo': 'octo-org/other'})
    check((res.get('refusal') or {}).get('code') == 'API_REPOSITORY_NOT_SERVED',
          'S4: another repository\'s filter was %r' % res.get('refusal'))
    PRODUCED.add((res.get('refusal') or {}).get('code'))
    # KEV unreadable: never "not exploited".
    w.env['KIT_API_KEV_FEED_FILE'] = os.path.join(tmp, 'no-such-feed.json')
    res, keys = search({'kev': True}, findings_run_id=w.sec_run)
    data = res.get('data') or {}
    check(data.get('kev_state') == 'UNAVAILABLE' and not keys and data.get('not_judged'),
          'S4: an unreadable KEV catalog answered %r' % ({k: data.get(k) for k in ('kev_state', 'not_judged')},))
    w.env['KIT_API_KEV_FEED_FILE'] = w.kev
    # Comment: a stamped ticket takes it, prefixed; nothing else changes.
    before = len(t.comments)
    res, _s, _i = w.call(ks, 'tickets.comment', {'ref': ref_a, 'text': 'triaged in the vuln UI'},
                         key='comment-0001-abcd')
    check(res.get('api_state') == 'API_COMPLETED' and len(t.comments) == before + 1,
          'S4: the comment was not written: %r' % res.get('notes'))
    if len(t.comments) > before:
        text = t.comments[-1][1]
        check('triaged in the vuln UI' in text and res['correlation_id'] in text and
              'tines-kit-app[bot]' in text and 'declared' in text,
              'S4: the comment does not say who asked and through what: %r' % text[:200])
    check(not t.transitions_posted, 'S4: a comment moved a ticket')
    res, _s, _i = w.call(ks, 'tickets.comment', {'ref': '999999', 'text': 'x'}, key='comment-0002-abcd')
    check((res.get('refusal') or {}).get('code') == 'API_TICKET_NOT_KIT_STAMPED',
          'S4: a comment on a ticket the kit does not own was %r' % res.get('refusal'))
    PRODUCED.add((res.get('refusal') or {}).get('code'))


# ── S5 ────────────────────────────────────────────────────────────────────────────────

def s5_findings(ka, ks, rt, tb, fc, tmp):
    obs = observations(fc)
    w = World(ka, {}, tmp, obs)
    key_a = [o['cluster_key'] for o in obs if o['identity'] == 'a1' * 16][0]
    write_ledger(w.ledger, {key_a: {'ref': '30001', 'key': 'KIT-30001', 'member_identities': ['a1' * 16]}})
    res, seen, _i = w.call(ks, 'findings.search', {'run_id': 'latest'})
    data = res.get('data') or {}
    check(res.get('api_state') == 'API_COMPLETED' and data.get('total') == 3,
          'S5: findings.search answered %r with %r' % (res.get('api_state'), data.get('total')))
    blob = json.dumps(data)
    check('log4j-core 2.14.1' not in blob and 'eval(<str>)' not in blob,
          'S5: code content left the run in the answer')
    by = dict((f.get('fingerprint'), f) for f in data.get('findings') or [])
    a = by.get('f1' * 8) or {}
    check(a.get('kev') is True and a.get('cves') == ['CVE-2021-44228'] and
          (a.get('ticket') or {}).get('key') == 'KIT-30001',
          'S5: the KEV flag or the ticket binding is wrong: %r' % a)
    b = by.get('f2' * 8) or {}
    check(b.get('kev') is None and b.get('cves') == [], 'S5: a finding with no CVE got kev %r' % b.get('kev'))
    for label, filters, want in (('severity', {'severity': ['critical']}, 1),
                                 ('scanner', {'scanner': 'semgrep'}, 1),
                                 ('job', {'job': 'secret-scan'}, 1),
                                 ('path', {'path': 'app/'}, 1),
                                 ('cve', {'cve': 'CVE-2021-44228'}, 1),
                                 ('kev', {'kev': True}, 1),
                                 ('kev false', {'kev': False}, 0),
                                 ('text', {'text': 'eval'}, 1),
                                 ('rule', {'rule': 'generic-api-key'}, 1),
                                 ('established', {'established_only': True}, 3)):
        res, _s, _i = w.call(ks, 'findings.search', {'run_id': w.sec_run, 'filters': filters})
        check((res.get('data') or {}).get('total') == want,
              'S5 %s: %r, expected %d' % (label, (res.get('data') or {}).get('total'), want))
    res, _s, _i = w.call(ks, 'findings.search', {'run_id': w.sec_run, 'limit': 1, 'offset': 1})
    data = res.get('data') or {}
    check(len(data.get('findings') or []) == 1 and data.get('total') == 3 and res.get('next_offset') == 2,
          'S5: paging answered %r' % ((len(data.get('findings') or []), data.get('total'),
                                       res.get('next_offset')),))
    res, _s, _i = w.call(ks, 'findings.get', {'run_id': w.sec_run, 'finding_id': 'b2' * 16})
    check(((res.get('data') or {}).get('finding') or {}).get('fingerprint') == 'f2' * 8,
          'S5: findings.get answered %r' % res.get('data'))
    w.env['KIT_API_KEV_FEED_FILE'] = os.path.join(tmp, 'absent.json')
    res, _s, _i = w.call(ks, 'findings.search', {'run_id': w.sec_run, 'filters': {'cve': 'CVE-2021-44228'}})
    f = ((res.get('data') or {}).get('findings') or [{}])[0]
    check(f.get('kev') == 'UNAVAILABLE' and (res.get('data') or {}).get('kev_state') == 'UNAVAILABLE',
          'S5: an unreadable KEV catalog gave kev %r -- never false' % f.get('kev'))
    res, _s, _i = w.call(ks, 'findings.search', {'run_id': w.sec_run, 'filters': {'kev': False}})
    check((res.get('data') or {}).get('total') == 0 and (res.get('data') or {}).get('not_judged'),
          'S5: kev:false with no catalog answered %r' % res.get('data'))


# ── S6 ────────────────────────────────────────────────────────────────────────────────

def s6_finish(ka, ks, rt, tb, fc, tmp):
    w = World(ka, {}, tmp, observations(fc))
    for label, outcome, want, word in (
            ('a blocked scan', {'KIT_API_JOB_RESULT': 'failure', 'KIT_API_ROUTING_RESULT': 'BLOCKED',
                                'KIT_API_ASSURANCE_STATE': 'FINDINGS',
                                'KIT_API_EVIDENCE_ARTIFACT': 'security-report-1'}, 'API_COMPLETED', 'BLOCKED'),
            ('a clean scan', {'KIT_API_JOB_RESULT': 'success', 'KIT_API_ROUTING_RESULT': 'PROCEED',
                              'KIT_API_ASSURANCE_STATE': 'PASS'}, 'API_COMPLETED', 'PROCEED'),
            ('no verdict', {'KIT_API_JOB_RESULT': 'failure', 'KIT_API_ROUTING_RESULT': ''}, 'API_FAILED', ''),
            ('a skipped scan', {'KIT_API_JOB_RESULT': 'skipped', 'KIT_API_ROUTING_RESULT': ''}, 'API_FAILED', ''),
            ('an unregistered verdict', {'KIT_API_JOB_RESULT': 'success', 'KIT_API_ROUTING_RESULT': 'OK'},
             'API_FAILED', '')):
        res, seen, _i = w.call(ks, 'scan.request', {'ref': 'main'}, outcome_env=outcome)
        check(res.get('api_state') == want and (res.get('routing_result') or '') == word,
              'S6 %s: %r / %r' % (label, res.get('api_state'), res.get('routing_result')))
        check(seen.get('api_state') == want, 'S6 %s: the caller read %r' % (label, seen.get('api_state')))
    w.stub.protect('test', reviewers=1, prevent_self_review=True)
    res, _s, intake = w.call(ks, 'deploy.request', {'mode': 'build-deploy', 'environment': 'test'},
                             key='rel-fin-0001', outcome_env={'KIT_API_JOB_RESULT': 'success'})
    check(res.get('api_state') == 'API_FAILED' and
          (res.get('data') or {}).get('deployment_outcome') == 'NOT_REPORTED',
          'S6: a deploy job that reported no outcome read as %r / %r -- never "deployed"'
          % (res.get('api_state'), (res.get('data') or {}).get('deployment_outcome')))
    # With the deploy's own evidence in the run, the outcome is reported in the deploy's words.
    rid = [r for r in w.stub.runs.values() if r['workflow'] == 'kit-api.yml'][-1]['id']
    env = dict(w.env, GITHUB_RUN_ID=str(rid), GITHUB_RUN_ATTEMPT='1', KIT_API_JOB_RESULT='success')
    w.stub.add_artifact(rid, 'deploy-evidence-%d-1' % rid, {'outcome.json': json.dumps(
        {'deployment_outcome': 'DEPLOY_HEALTHY', 'now_serving': 'sha256:' + 'e' * 64,
         'routing_result': 'PROCEED'})})
    res2 = ks.finish(intake, env, w.client(), tempfile.mkdtemp(dir=tmp))
    check(res2.get('api_state') == 'API_COMPLETED' and
          (res2.get('data') or {}).get('deployment_outcome') == 'DEPLOY_HEALTHY',
          'S6: a reported healthy deploy read as %r / %r' % (res2.get('api_state'), res2.get('data')))
    env['KIT_API_JOB_RESULT'] = 'failure'
    res3 = ks.finish(intake, env, w.client(), tempfile.mkdtemp(dir=tmp))
    check(res3.get('api_state') == 'API_FAILED', 'S6: a failed deploy job read as %r' % res3.get('api_state'))


# ── S7 ────────────────────────────────────────────────────────────────────────────────

def s7_gates(ka, ks, rt, tb, fc, tmp):
    """The release the API requests is the pipeline's: these are the deploy's own decisions, with
    the API caller as the requester (the deploy is a workflow_call of the API run, so GitHub's
    actor IS the caller -- tests/prove_kit_api_workflow.py W3/W4 hold that wiring)."""
    import release_gates as rg
    caller = 'tines-kit-app[bot]'
    digest = 'e' * 64
    out = rg.decide_approval('prod', 'prod', digest, [], [caller, caller], {'dev-author'}, 'required')
    check(out[0] == 'RELEASE_APPROVAL_ABSENT', 'S7: no approval at prod was %r' % (out[:2],))
    by_caller = [{'state': 'approved', 'user': {'login': caller}, 'comment': 'ok %s' % digest[:12],
                  'environments': [{'name': 'prod'}]}]
    out = rg.decide_approval('prod', 'prod', digest, by_caller, [caller, caller], {'dev-author'}, 'required')
    check(out[0] == 'SELF_DEPLOYMENT_APPROVAL', 'S7: the API caller approving its own request was %r' % (out[:2],))
    human = [{'state': 'approved', 'user': {'login': 'platform-lead'}, 'comment': 'checked %s' % digest[:12],
              'environments': [{'name': 'prod'}]}]
    out = rg.decide_approval('prod', 'prod', digest, human, [caller, caller], {'dev-author'}, 'required')
    check(out[0] == 'RELEASE_APPROVAL_VERIFIED', 'S7: a human, digest-quoting approval was %r' % (out[:2],))
    check(rg.decide_zone('prod', '')[1] == 'RELEASE_REFUSED_ZONE_NOT_READY', 'S7: an unvended readiness at prod passed')
    check(rg.decide_block('platform_halted')[0] == 'RELEASE_BLOCKED_BY_PLATFORM', 'S7: a platform block passed')


# ── S8 ────────────────────────────────────────────────────────────────────────────────

def s8_round_trip(ka, ks, rt, tb, fc, tmp):
    obs = observations(fc)
    w = World(ka, {}, tmp, obs)
    cl = w.client()
    sub = ka.submit(cl, w.stub.repo, 'findings.search', {'run_id': 'latest', 'filters': {'kev': True}})
    check(sub['api_state'] == 'API_ACCEPTED', 'S8: submit answered %r' % sub['api_state'])
    d = w.stub.dispatches[-1]
    run = [r for r in w.stub.runs.values() if r.get('inputs') is d['inputs']][0]
    run['status'] = 'in_progress'
    env = dict(w.env, KIT_API_REQUEST=d['inputs']['request'],
               KIT_API_CORRELATION_ID=d['inputs']['correlation_id'],
               KIT_API_IDEMPOTENCY_KEY=d['inputs']['idempotency_key'], GITHUB_EVENT_NAME='workflow_dispatch',
               GITHUB_REF='refs/heads/%s' % d['ref'], GITHUB_RUN_ID=str(run['id']), GITHUB_RUN_ATTEMPT='1')
    out = tempfile.mkdtemp(dir=tmp)
    intake = ks.intake(env, cl, out)
    mid = ka.status(cl, w.stub.repo, sub['correlation_id'])
    check(mid['api_state'] == 'API_IN_PROGRESS', 'S8: mid-run the caller read %r' % mid['api_state'])
    op = ks.findings(intake, env, cl, out)
    ks.finish(intake, env, cl, out, op_result=op)
    run.update(status='completed', conclusion='success')
    fin = ka.status(cl, w.stub.repo, sub['correlation_id'])
    check(fin['api_state'] == 'API_COMPLETED' and (fin.get('data') or {}).get('total') == 1,
          'S8: the caller read %r / %r at the end' % (fin['api_state'], (fin.get('data') or {}).get('total')))
    check((fin.get('actor') or {}).get('on_behalf_of_verified') is False,
          'S8: on_behalf_of was not marked unverified')
    hosts = sorted(set(q['host'] for q in w.stub.requests))
    check(set(hosts) <= {gs.API_HOST, gs.BLOB_HOST}, 'S8: requests went to %r' % hosts)
    leaked = [q for q in w.stub.requests if q['host'] != gs.API_HOST and q['authorization']]
    check(not leaked, 'S8: the token went to %r' % sorted(set(q['host'] for q in leaked)))
    check(os.path.isfile(os.path.join(out, 'result.json')), 'S8: no result.json for the artifact step')


def coverage_of_refusals(ka):
    doc = json.load(io.open(os.path.join(ROOT, 'api', 'v1', 'refusals.json'), encoding='utf-8'))
    run_side = sorted(k for k, v in doc['refusals'].items() if v['where'] != 'client')
    # KDEC-037's template refusals are produced, each by name, by tests/prove_ticket_templates.py (its T10
    # fails if any is never produced there); they are not re-run here.
    kdec037 = ('API_TEMPLATE_INVALID', 'API_REVIEW_NOT_FINALIZED', 'API_TEMPLATE_RULE_REFUSED',
               'API_TRACKER_QUERY_REFUSED')
    missing = [k for k in run_side if k not in PRODUCED and k != 'API_REQUEST_TOO_LARGE' and k not in kdec037]
    check(not missing, 'every run-side refusal must be produced by a case here; never produced: %r' % missing)


def main():
    mods = imports()
    if mods is None:
        return 1
    ka, ks, rt, tb, fc = mods
    tmp = tempfile.mkdtemp(prefix='kitapi-server-')
    real_urlopen = __import__('urllib.request').request.urlopen
    try:
        for case in (s1_intake, s2_jira, s3_azdo, s4_ticket_reads, s5_findings, s6_finish, s7_gates,
                     s8_round_trip):
            d = tempfile.mkdtemp(dir=tmp)
            try:
                case(ka, ks, rt, tb, fc, d)
            except Exception as exc:  # noqa: BLE001 -- a crash is a failed case, named
                import traceback
                FAILS.append('%s crashed: %s: %s\n%s' % (case.__name__, type(exc).__name__, exc,
                                                         traceback.format_exc()[-2500:]))
        coverage_of_refusals(ka)
    finally:
        __import__('urllib.request').request.urlopen = real_urlopen
        shutil.rmtree(tmp, ignore_errors=True)
    for f in FAILS:
        print('FAIL: %s' % f)
    if FAILS:
        print('\n%d failure(s)' % len(FAILS))
        return 1
    print('prove_kit_api_server: S1..S8 hold -- every run-side refusal named and readable by the caller; '
          'one ticket per finding across the API and the pipeline (Jira and Azure DevOps, both orders); '
          'a subset closes nothing; findings with KEV never false; a release meets every gate')
    return 0


if __name__ == '__main__':
    sys.exit(main())

#!/usr/bin/env python3
"""The kit's API, client side: the contract, the host rule, the dispatch, the status words (KDEC-035).

WHY THIS EXISTS

    An external program (Tines 3B first) is to call the kit through a versioned, schema-defined
    contract on GitHub's own API: a dispatch carries the request, a run answers it, and the answer
    comes back by correlation id. Each piece of that has a way to be wrong that reads as working:

      * a client that falls back to github.com sends a GHE.com tenant's token to a host that did
        not issue it (KDEC-027) -- and "no host named" must refuse, never default;
      * a client that follows GitHub's artifact redirect with its Authorization header hands the
        token to blob storage;
      * a request the schema refuses must refuse BEFORE anything is dispatched, by name;
      * "the run finished" is not "the call succeeded": a completed run whose result cannot be read
        is API_RESULT_UNREADABLE, a dispatch reply is API_ACCEPTED (received, never done), and a
        bounded wait that runs out returns the last word it saw, never a success.

HOW

    tests/_github_api_stub.py stands in for the GitHub API of a SIMULATED GHE.com tenant
    (api.example.ghe.com) in-process: kit_api._transport is replaced, every request is recorded
    with its host and Authorization header, and nothing can leave the machine. K9 runs the REAL
    stdlib opener against a loopback server that answers 302, to prove the shipped opener does not
    forward the header (the in-process stub cannot prove that half).

CASES
    K1  the schemas: every v1 operation has a params schema; every example request validates; a
        mutated one fails naming the field; the result schema holds every state word
    K2  the refusal registry (api/v1/refusals.json) equals assurance-taxonomy.yaml kit_api_refusal,
        and the state words equal kit_api_state
    K3  the host: nothing named -> API_HOST_NOT_NAMED (never github.com); GH_HOST=<t>.ghe.com ->
        https://api.<t>.ghe.com; http to a non-loopback host -> API_HOST_INSECURE
    K4  credentials: none -> API_CREDENTIAL_ABSENT; KIT_API_AUTH=proxy sends NO Authorization
    K5  submit: the workflow_dispatch payload (ref = default branch, inputs correlation_id,
        idempotency_key, request) and API_ACCEPTED with the correlation id; repository_dispatch
        shape; scan dispatched AT its ref
    K6  local refusals send nothing: schema violation, write without a key, unknown operation,
        a request over the size limit
    K7  status words: not found, queued, in progress, awaiting approval (pending deployments),
        completed -> the check run's result, completed without a readable result ->
        API_RESULT_UNREADABLE, cancelled
    K8  the bounded wait: never longer than asked, returns the last non-terminal word, exit 3
    K9  the token stays on its host: the artifact redirect is followed WITHOUT Authorization (in
        the stub) and the shipped opener does not auto-follow a 302 (real stdlib, loopback)

EXIT  0 every case held  1 a case failed  2 could not be checked
"""
import http.server
import io
import json
import os
import sys
import threading
import urllib.request

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, os.path.join(ROOT, 'scripts'))
sys.path.insert(0, HERE)

import _github_api_stub as gs  # noqa: E402

FAILS = []


def check(cond, msg):
    if not cond:
        FAILS.append(msg)
    return cond


def load_kit_api():
    try:
        import kit_api  # noqa: F401
        return kit_api
    except ImportError as exc:
        print('FAIL: scripts/kit_api.py cannot be imported (%s): the client does not exist' % exc)
        return None


def env_for(stub_url=gs.API_URL, **extra):
    e = {'GITHUB_API_URL': stub_url, 'GH_TOKEN': gs.TOKEN}
    e.update(extra)
    return e


def client_for(ka, stub, env=None):
    stub_env = env or env_for()
    url, ref = ka.resolve_api_url(stub_env)
    assert url, ref
    cl, ref2 = ka.client_from_env(stub_env)
    assert cl is not None, ref2
    ka._transport = stub.transport
    return cl


def k1_schemas(ka):
    schemas = ka.load_schemas()
    for op in ka.OPERATIONS:
        check(op in schemas['params'], 'K1: operation %s has no params schema' % op)
    ex_dir = os.path.join(ROOT, 'api', 'v1', 'examples')
    names = sorted(f for f in os.listdir(ex_dir) if f.endswith('.request.json'))
    check(len(names) >= len(ka.OPERATIONS), 'K1: %d example request(s) for %d operations'
          % (len(names), len(ka.OPERATIONS)))
    for n in names:
        doc = json.load(io.open(os.path.join(ex_dir, n), encoding='utf-8'))
        ref = ka.check_request(doc, schemas)
        check(ref is None, 'K1: example %s is refused: %r' % (n, ref))
        bad = json.loads(json.dumps(doc))
        bad['params']['__not_a_field__'] = 1
        ref = ka.check_request(bad, schemas)
        check(ref and ref['code'] == 'API_SCHEMA_VIOLATION' and '__not_a_field__' in ref.get('field', ''),
              'K1: example %s with an unknown params field was not refused naming it: %r' % (n, ref))
    for n in sorted(f for f in os.listdir(ex_dir) if f.endswith('.result.json')):
        doc = json.load(io.open(os.path.join(ex_dir, n), encoding='utf-8'))
        errs = ka.validate(doc, schemas['result'])
        check(not errs, 'K1: example result %s breaks the result schema: %r' % (n, errs[:3]))
    states = schemas['result']['properties']['api_state']['enum']
    check(sorted(states) == sorted(ka.API_STATES), 'K1: the result schema states %r != the client '
          'states %r' % (states, ka.API_STATES))
    # The validator is not vacuous: a wrong type, a pattern miss and a missing required field fail.
    env = {'api_version': 'v1', 'operation': 'findings.search',
           'correlation_id': 'kapi-20261103T101500Z-0123456789ab', 'params': {'run_id': 'latest'}}
    check(ka.check_request(env, schemas) is None, 'K1: a minimal valid request was refused')
    for mutate, want in ((lambda d: d.update(api_version=1), 'api_version'),
                         (lambda d: d.update(correlation_id='kapi-x'), 'correlation_id'),
                         (lambda d: d.pop('params'), 'params'),
                         (lambda d: d['params'].update(run_id='newest'), 'run_id'),
                         (lambda d: d['params'].update(limit=500), 'limit')):
        d = json.loads(json.dumps(env))
        mutate(d)
        ref = ka.check_request(d, schemas)
        check(ref and ref['code'] == 'API_SCHEMA_VIOLATION' and want in ref.get('field', ''),
              'K1: a request with a bad %s was not refused naming it: %r' % (want, ref))


def k2_vocabulary(ka):
    import yaml
    tax = yaml.safe_load(io.open(os.path.join(ROOT, 'assurance-taxonomy.yaml'), encoding='utf-8'))
    ns = tax.get('namespaces') or {}
    reg = sorted((ns.get('kit_api_refusal') or {}).get('values') or {})
    doc = json.load(io.open(os.path.join(ROOT, 'api', 'v1', 'refusals.json'), encoding='utf-8'))
    have = sorted(doc['refusals'])
    check(reg and reg == have, 'K2: api/v1/refusals.json %r and taxonomy kit_api_refusal %r differ'
          % (sorted(set(have) ^ set(reg)), ''))
    st = sorted((ns.get('kit_api_state') or {}).get('values') or {})
    check(st == sorted(ka.API_STATES), 'K2: taxonomy kit_api_state %r != client %r'
          % (st, sorted(ka.API_STATES)))
    check(sorted(ka.REFUSALS) == have, 'K2: the client\'s refusal constants differ from the registry: %r'
          % sorted(set(ka.REFUSALS) ^ set(have)))


def k3_host(ka):
    url, ref = ka.resolve_api_url({})
    check(url is None and ref and ref['code'] == 'API_HOST_NOT_NAMED',
          'K3: with nothing named the client chose %r (%r); it must refuse, never github.com' % (url, ref))
    url, ref = ka.resolve_api_url({'GH_HOST': 'example.ghe.com'})
    check(url == 'https://api.example.ghe.com', 'K3: GH_HOST=example.ghe.com gave %r' % url)
    url, ref = ka.resolve_api_url({'GITHUB_API_URL': 'https://api.example.ghe.com/'})
    check(url == 'https://api.example.ghe.com', 'K3: GITHUB_API_URL gave %r' % url)
    url, ref = ka.resolve_api_url({'KIT_API_URL': 'https://api.other.ghe.com',
                                   'GITHUB_API_URL': 'https://api.example.ghe.com'})
    check(url == 'https://api.other.ghe.com', 'K3: KIT_API_URL did not win: %r' % url)
    url, ref = ka.resolve_api_url({'GITHUB_API_URL': 'http://api.example.ghe.com'})
    check(url is None and ref and ref['code'] == 'API_HOST_INSECURE',
          'K3: plain http to a remote host was accepted: %r %r' % (url, ref))
    url, ref = ka.resolve_api_url({'GITHUB_API_URL': 'http://127.0.0.1:8080'})
    check(url == 'http://127.0.0.1:8080', 'K3: loopback http was refused: %r %r' % (url, ref))
    url, ref = ka.resolve_api_url({'GH_HOST': 'github.com'})
    check(url == 'https://api.github.com', 'K3: GH_HOST=github.com, NAMED, gave %r' % url)


def k4_credentials(ka):
    cl, ref = ka.client_from_env({'GITHUB_API_URL': gs.API_URL})
    check(cl is None and ref and ref['code'] == 'API_CREDENTIAL_ABSENT',
          'K4: no token and no proxy mode was accepted: %r' % (ref,))
    stub = gs.StubGitHub(require_token=False)
    cl, ref = ka.client_from_env({'GITHUB_API_URL': gs.API_URL, 'KIT_API_AUTH': 'proxy'})
    check(cl is not None, 'K4: proxy mode was refused: %r' % (ref,))
    if cl is None:
        return
    ka._transport = stub.transport
    res = ka.submit(cl, stub.repo, 'findings.search', {'run_id': 'latest'})
    check(res['api_state'] == 'API_ACCEPTED', 'K4: proxy-mode submit gave %r' % res.get('api_state'))
    check(stub.requests and all(not r['authorization'] for r in stub.requests),
          'K4: proxy mode sent an Authorization header itself: %r'
          % [r['authorization'][:12] for r in stub.requests])


def k5_submit(ka):
    stub = gs.StubGitHub()
    cl = client_for(ka, stub)
    res = ka.submit(cl, stub.repo, 'tickets.write',
                    {'source': {'run_id': 42}, 'select': {'identities': ['ab' * 16]}},
                    idempotency_key='tines-flow-7:run-311', on_behalf_of='analyst@example.invalid')
    check(res['api_state'] == 'API_ACCEPTED' and ka.CORRELATION_RE.match(res['correlation_id'] or ''),
          'K5: submit did not answer API_ACCEPTED with a correlation id: %r' % res)
    check(len(stub.dispatches) == 1, 'K5: %d dispatch(es), expected 1' % len(stub.dispatches))
    if stub.dispatches:
        d = stub.dispatches[0]
        check(d['workflow'] == 'kit-api.yml' and d['ref'] == 'main',
              'K5: dispatched %r at %r; expected kit-api.yml at the default branch' % (d['workflow'], d['ref']))
        inp = d['inputs']
        check(sorted(inp) == ['correlation_id', 'idempotency_key', 'request'],
              'K5: dispatch inputs %r' % sorted(inp))
        req = json.loads(inp.get('request') or '{}')
        check(req.get('correlation_id') == inp.get('correlation_id') == res['correlation_id'],
              'K5: the request, the input and the answer carry different correlation ids')
        check(req.get('idempotency_key') == inp.get('idempotency_key') == 'tines-flow-7:run-311',
              'K5: the idempotency key did not travel in both places')
        check(req.get('on_behalf_of') == 'analyst@example.invalid' and req.get('api_version') == 'v1',
              'K5: the envelope lost on_behalf_of or api_version: %r' % req)
    check(all(r['host'] == gs.API_HOST for r in stub.requests),
          'K5: a request left the issuing host: %r' % sorted(set(r['host'] for r in stub.requests)))
    # repository_dispatch: one event type, the same three members.
    stub2 = gs.StubGitHub()
    cl2 = client_for(ka, stub2)
    res2 = ka.submit(cl2, stub2.repo, 'findings.search', {'run_id': 'latest'},
                     transport='repository_dispatch')
    check(res2['api_state'] == 'API_ACCEPTED' and stub2.dispatches and
          stub2.dispatches[0].get('event_type') == 'kit-api' and
          sorted(stub2.dispatches[0]['client_payload']) == ['correlation_id', 'idempotency_key', 'request'],
          'K5: repository_dispatch shape %r' % (stub2.dispatches,))
    # A scan is dispatched AT the ref it scans.
    stub3 = gs.StubGitHub()
    cl3 = client_for(ka, stub3)
    ka.submit(cl3, stub3.repo, 'scan.request', {'ref': 'feature/x'})
    check(stub3.dispatches and stub3.dispatches[0]['ref'] == 'feature/x',
          'K5: scan.request was dispatched at %r, not at the ref it scans'
          % (stub3.dispatches[0]['ref'] if stub3.dispatches else None))


def k6_local_refusals(ka):
    for label, op, params, kw, want in (
            ('schema', 'findings.search', {'run_id': 'newest'}, {}, 'API_SCHEMA_VIOLATION'),
            ('no key', 'tickets.comment', {'ref': 'KIT-1', 'text': 'x'}, {}, 'API_IDEMPOTENCY_KEY_REQUIRED'),
            ('unknown', 'tickets.delete', {}, {}, 'API_OPERATION_UNKNOWN'),
            # Size is checked BEFORE the schema: an oversized request is refused as oversized, so the
            # limit (a dispatch input holds 65535 characters) is named rather than hidden in a
            # schema error about whatever field made it large.
            ('too large', 'findings.search', {'run_id': 'latest', 'filters': {'text': 'y' * 70000}},
             {}, 'API_REQUEST_TOO_LARGE')):
        stub = gs.StubGitHub()
        cl = client_for(ka, stub)
        res = ka.submit(cl, stub.repo, op, params, **kw)
        check(res['api_state'] == 'API_REFUSED' and (res.get('refusal') or {}).get('code') == want,
              'K6 %s: expected %s, got %r' % (label, want, res.get('refusal') or res.get('api_state')))
        check(not stub.dispatches, 'K6 %s: a refused request was still dispatched' % label)


def _completed_with_result(ka, stub, cid, result):
    rid = [r for r in stub.runs.values() if cid in r['display_title']][0]['id']
    stub.runs[rid].update(status='completed', conclusion='success')
    stub.check_runs[1] = {'id': 1, 'name': ka.check_run_name(cid), 'head_sha': stub.head_sha,
                          'status': 'completed', 'conclusion': 'success',
                          'output': {'title': 'x', 'summary': 'x', 'text': json.dumps(result)}}
    return rid


def k7_status(ka):
    stub = gs.StubGitHub()
    cl = client_for(ka, stub)
    st = ka.status(cl, stub.repo, 'kapi-20261103T101500Z-0123456789ab')
    check(st['api_state'] == 'API_NOT_FOUND', 'K7: no run read as %r' % st['api_state'])
    res = ka.submit(cl, stub.repo, 'findings.search', {'run_id': 'latest'})
    cid = res['correlation_id']
    st = ka.status(cl, stub.repo, cid)
    check(st['api_state'] == 'API_QUEUED', 'K7: a queued run read as %r' % st['api_state'])
    rid = [r for r in stub.runs.values() if cid in r['display_title']][0]['id']
    stub.runs[rid]['status'] = 'in_progress'
    check(ka.status(cl, stub.repo, cid)['api_state'] == 'API_IN_PROGRESS', 'K7: in_progress')
    stub.pending[rid] = [{'environment': {'name': 'prod'}, 'wait_timer': 0}]
    st = ka.status(cl, stub.repo, cid)
    check(st['api_state'] == 'API_AWAITING_APPROVAL' and 'prod' in json.dumps(st.get('data')),
          'K7: a run waiting on an environment read as %r' % st['api_state'])
    stub.pending[rid] = []
    stub.runs[rid].update(status='completed', conclusion='success')
    st = ka.status(cl, stub.repo, cid)
    check(st['api_state'] == 'API_RESULT_UNREADABLE',
          'K7: a completed run with NO result read as %r -- a finished run is not a finished call'
          % st['api_state'])
    result = {'api_version': 'v1', 'correlation_id': cid, 'operation': 'findings.search',
              'api_state': 'API_COMPLETED', 'notes': [], 'data': {'findings': [], 'total': 0}}
    _completed_with_result(ka, stub, cid, result)
    st = ka.status(cl, stub.repo, cid)
    check(st['api_state'] == 'API_COMPLETED' and st.get('data', {}).get('total') == 0,
          'K7: the check run\'s result was not returned: %r' % st)
    # A result that is not the schema's is unreadable, never trusted.
    stub.check_runs[1]['output']['text'] = json.dumps({'api_state': 'API_COMPLETED'})
    st = ka.status(cl, stub.repo, cid)
    check(st['api_state'] == 'API_RESULT_UNREADABLE', 'K7: a malformed result read as %r' % st['api_state'])
    stub.check_runs[1]['output']['text'] = json.dumps(dict(result, correlation_id='kapi-20261103T101500Z-ffffffffffff'))
    st = ka.status(cl, stub.repo, cid)
    check(st['api_state'] == 'API_RESULT_UNREADABLE', 'K7: another call\'s result was accepted: %r' % st['api_state'])
    # A finished run whose check run still says "in progress" (the answering job never ran) is not
    # in progress: it is unreadable.
    stub.check_runs[1]['output']['text'] = json.dumps(dict(result, api_state='API_IN_PROGRESS'))
    st = ka.status(cl, stub.repo, cid)
    check(st['api_state'] == 'API_RESULT_UNREADABLE',
          'K7: a finished run whose answer says in progress read as %r' % st['api_state'])
    res2 = ka.submit(cl, stub.repo, 'findings.search', {'run_id': 'latest'})
    rid2 = [r for r in stub.runs.values() if res2['correlation_id'] in r['display_title']][0]['id']
    stub.runs[rid2].update(status='completed', conclusion='cancelled')
    check(ka.status(cl, stub.repo, res2['correlation_id'])['api_state'] == 'API_CANCELLED', 'K7: cancelled')


def k8_bounded_wait(ka):
    stub = gs.StubGitHub()
    cl = client_for(ka, stub)
    clock = {'t': 0.0}
    sleeps = []

    def sleep(s):
        sleeps.append(s)
        clock['t'] += s
    res = ka.call(cl, stub.repo, 'findings.search', {'run_id': 'latest'}, wait_seconds=30,
                  poll_seconds=10, sleep=sleep, clock=lambda: clock['t'])
    check(res['api_state'] in ('API_QUEUED', 'API_NOT_FOUND', 'API_IN_PROGRESS'),
          'K8: a wait that ran out returned %r' % res['api_state'])
    check(sum(sleeps) <= 30, 'K8: waited %ss for a 30 s bound' % sum(sleeps))
    check(ka.exit_code(res) == 3, 'K8: a call that did not finish exits %d, not 3' % ka.exit_code(res))
    check(ka.exit_code({'api_state': 'API_COMPLETED'}) == 0 and
          ka.exit_code({'api_state': 'API_REFUSED'}) == 1 and
          ka.exit_code({'api_state': 'API_RESULT_UNREADABLE'}) == 3, 'K8: the exit-code table')
    # And it does finish when the run does.
    stub2 = gs.StubGitHub()
    cl2 = client_for(ka, stub2)
    state = {'n': 0}

    def sleep2(s):
        state['n'] += 1
        if state['n'] == 2:
            run = [r for r in stub2.runs.values() if r['event'] == 'workflow_dispatch'][0]
            cid = run['inputs']['correlation_id']
            _completed_with_result(ka, stub2, cid, {'api_version': 'v1', 'correlation_id': cid,
                                                    'operation': 'findings.search',
                                                    'api_state': 'API_COMPLETED', 'notes': [],
                                                    'data': {}})
    res2 = ka.call(cl2, stub2.repo, 'findings.search', {'run_id': 'latest'}, wait_seconds=300,
                   poll_seconds=5, sleep=sleep2, clock=lambda: state['n'] * 5.0)
    check(res2['api_state'] == 'API_COMPLETED', 'K8: the wait did not return the finished result: %r'
          % res2['api_state'])


def k9_token_stays_home(ka):
    stub = gs.StubGitHub()
    cl = client_for(ka, stub)
    rid = stub.add_run()
    aid = stub.add_artifact(rid, 'security-report-1', {'findings.json': '[]'})
    data = cl.download('/repos/%s/actions/artifacts/%d/zip' % (stub.repo, aid))
    check(data and data[:2] == b'PK', 'K9: the artifact was not downloaded through the redirect')
    blob = [r for r in stub.requests if r['host'] == gs.BLOB_HOST]
    check(blob and all(not r['authorization'] for r in blob),
          'K9: the blob host received an Authorization header: %r' % [r['authorization'][:10] for r in blob])
    api = [r for r in stub.requests if r['host'] == gs.API_HOST]
    check(api and all(r['authorization'] == 'Bearer %s' % gs.TOKEN for r in api),
          'K9: the issuing host did not receive the token')
    # The SHIPPED opener, against a real loopback server: a 302 is not followed by urllib itself.
    seen = []

    class H(http.server.BaseHTTPRequestHandler):
        def do_GET(self):
            seen.append((self.path, self.headers.get('Authorization')))
            if self.path.startswith('/start'):
                self.send_response(302)
                self.send_header('Location', 'http://127.0.0.1:%d/landed' % self.server.server_address[1])
                self.send_header('Content-Length', '0')
                self.end_headers()
            else:
                self.send_response(200)
                self.send_header('Content-Length', '2')
                self.end_headers()
                self.wfile.write(b'ok')

        def log_message(self, *a):
            return
    srv = http.server.HTTPServer(('127.0.0.1', 0), H)
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    try:
        import importlib
        fresh = importlib.reload(ka)       # the shipped _transport, not a stub
        req = urllib.request.Request('http://127.0.0.1:%d/start' % srv.server_address[1])
        req.add_header('Authorization', 'Bearer should-not-travel')
        try:
            fresh._transport(req, 5)
            followed = True
        except urllib.error.HTTPError as exc:
            followed = False
            check(exc.code == 302, 'K9: the opener raised %s, not the 302' % exc.code)
        check(not followed, 'K9: the shipped opener FOLLOWED the redirect itself, carrying the header')
        check(not any(p.startswith('/landed') for p, _a in seen),
              'K9: the redirect target was reached by the opener, with %r' % seen)
    finally:
        srv.shutdown()
        srv.server_close()


def main():
    ka = load_kit_api()
    if ka is None:
        return 1
    try:
        import yaml  # noqa: F401
    except ImportError:
        print('UNKNOWN: PyYAML is required')
        return 2
    for case in (k1_schemas, k2_vocabulary, k3_host, k4_credentials, k5_submit, k6_local_refusals,
                 k7_status, k8_bounded_wait, k9_token_stays_home):
        try:
            case(ka)
        except Exception as exc:  # noqa: BLE001 -- a crash is a failed case, named
            import traceback
            FAILS.append('%s crashed: %s: %s\n%s' % (case.__name__, type(exc).__name__, exc,
                                                     traceback.format_exc()[-1500:]))
    for f in FAILS:
        print('FAIL: %s' % f)
    if FAILS:
        print('\n%d failure(s)' % len(FAILS))
        return 1
    print('prove_kit_api_client: K1..K9 hold -- the contract validates and refuses by name, the host '
          'is never assumed, the token stays on its host, and only a readable result is a result')
    return 0


if __name__ == '__main__':
    sys.exit(main())

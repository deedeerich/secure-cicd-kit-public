#!/usr/bin/env python3
"""The kit's API, wired: the template, the reusable workflow, the composite, the release path (KDEC-035).

WHY THIS EXISTS

    tests/prove_kit_api_server.py proves what the server does when it is called. This proves it IS
    called that way, and that the wiring cannot open a door the kit keeps shut:

      * the release an API call asks for must be the repository's OWN build-deploy.yml, CALLED (not
        re-dispatched with the run's token -- that would make the requester github-actions[bot],
        and the API caller could then approve its own request), with intake's validated values
        and never the raw request; and that workflow's deploys still reach the kit's release
        gates (block, readiness, approval) before they log in to anything;
      * the API itself holds no deploy identity and dispatches nothing;
      * a ticket write runs in the ticketing environment and in the SAME concurrency group as the
        pipeline's reconciliation, so the two writers never interleave a lookup and a create;
      * intake holds no tracker credential;
      * every value the server reads is set by the step that runs it, and nothing set is unread;
      * the shipped composite step, run under bash as the runner runs it, answers.

CASES
    W1  templates/kit-api.yml: the dispatch inputs, repository_dispatch kit-api, the run-name that
        carries the correlation id for both, one concurrency group per idempotency key, never
        cancelled in progress
    W2  its jobs: api -> reusable-kit-api.yml; scan -> reusable-security.yml; deploy ->
        ./.github/workflows/build-deploy.yml with intake's VALIDATED outputs; finish always(), on
        the api's acceptance, for scan and deploy only
    W3  build-deploy.yml's workflow_call inputs are its dispatch inputs, name for name, type for
        type, default for default; its deploy and promote jobs call the kit's deploy reusables,
        whose release gates (block, readiness, approval) run before Azure login
    W4  the API deploys and dispatches nothing: no azure/login, no id-token, no /dispatches call
    W5  tickets: the ticketing environment; for a write, reusable-ticket-reconcile.yml's group
        (both its writing jobs carry it); intake in no environment and with no secret
    W6  no `${{ }}` in a run: block of the reusable workflow or the composite
    W7  the env contract: every KIT_API_* the server reads is set where it is read (or set by the
        composite, or a stated optional), and every KIT_API_* a step sets is read
    W8  the composite's phase step, run under bash against a loopback stub: an accepted call opens
        its check run; a refused call says so in its outputs

EXIT  0 every case held  1 a case failed  2 could not be checked
"""
import io
import json
import os
import re
import shutil
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, os.path.join(ROOT, 'scripts'))
sys.path.insert(0, HERE)

FAILS = []
TPL = os.path.join(ROOT, 'templates', 'kit-api.yml')
BD = os.path.join(ROOT, 'templates', 'build-deploy.yml')
RW = os.path.join(ROOT, '.github', 'workflows', 'reusable-kit-api.yml')
CA = os.path.join(ROOT, '.github', 'actions', 'kit-api', 'action.yml')
TR = os.path.join(ROOT, '.github', 'workflows', 'reusable-ticket-reconcile.yml')
SERVER = os.path.join(ROOT, 'scripts', 'kit_api_server.py')


def check(cond, msg):
    if not cond:
        FAILS.append(msg)
    return cond


def load(p):
    import yaml
    return yaml.safe_load(io.open(p, encoding='utf-8'))


def on_of(doc):
    return doc.get('on', doc.get(True)) or {}


def w1(t):
    on = on_of(t)
    wd = (on.get('workflow_dispatch') or {}).get('inputs') or {}
    check(sorted(wd) == ['correlation_id', 'idempotency_key', 'request'],
          'W1: the dispatch inputs are %r' % sorted(wd))
    check((on.get('repository_dispatch') or {}).get('types') == ['kit-api'],
          'W1: repository_dispatch types %r' % (on.get('repository_dispatch'),))
    rn = str(t.get('run-name') or '')
    check(rn.startswith('kit-api ') and 'inputs.correlation_id' in rn and
          'github.event.client_payload.correlation_id' in rn,
          'W1: the run-name %r does not carry the correlation id for both transports' % rn)
    import kit_api as ka
    check(ka.run_title('X') == 'kit-api X', 'W1: the client looks for %r' % ka.run_title('X'))
    c = t.get('concurrency') or {}
    check('idempotency_key' in str(c.get('group')) and c.get('cancel-in-progress') is False,
          'W1: concurrency %r' % c)
    check(t.get('permissions') == {'contents': 'read'}, 'W1: top-level permissions %r' % t.get('permissions'))


def w2(t):
    jobs = t.get('jobs') or {}
    api = jobs.get('api') or {}
    check(str(api.get('uses', '')).split('@')[0].endswith('/.github/workflows/reusable-kit-api.yml'),
          'W2: api uses %r' % api.get('uses'))
    scan = jobs.get('scan') or {}
    check(str(scan.get('uses', '')).split('@')[0].endswith('/.github/workflows/reusable-security.yml')
          and "needs.api.outputs.accepted == 'true'" in str(scan.get('if'))
          and 'scan.request' in str(scan.get('if')), 'W2: scan %r' % ({k: scan.get(k) for k in ('uses', 'if')},))
    dep = jobs.get('deploy') or {}
    check(dep.get('uses') == './.github/workflows/build-deploy.yml',
          'W2: the release is %r, not the repository\'s own build-deploy.yml, called' % dep.get('uses'))
    check("needs.api.outputs.accepted == 'true'" in str(dep.get('if')) and 'deploy.request' in str(dep.get('if')),
          'W2: deploy runs without intake\'s acceptance: %r' % dep.get('if'))
    w = dep.get('with') or {}
    for k, v in w.items():
        check('needs.api.outputs.' in str(v) and 'request' not in str(v).replace('deploy.request', ''),
              'W2: deploy input %s = %r is not an intake-validated value' % (k, v))
    check(sorted(w) == ['deploy', 'environment', 'promote_from_environment', 'promote_from_run_id',
                        'release_path'], 'W2: deploy passes %r -- never an exception record' % sorted(w))
    fin = jobs.get('finish') or {}
    check(str(fin.get('if', '')).startswith('always()') and "accepted == 'true'" in str(fin.get('if'))
          and (fin.get('with') or {}).get('phase') == 'finish',
          'W2: finish %r' % ({k: fin.get(k) for k in ('if',)},))
    check(sorted(fin.get('needs') or []) == ['api', 'deploy', 'scan'], 'W2: finish needs %r' % fin.get('needs'))


def w3():
    bd = load(BD)
    on = on_of(bd)
    wd = (on.get('workflow_dispatch') or {}).get('inputs') or {}
    wc = (on.get('workflow_call') or {}).get('inputs') or {}
    check(wc and wd and sorted(wc) == sorted(wd),
          'W3: build-deploy\'s workflow_call inputs %r differ from its dispatch inputs %r' % (sorted(wc), sorted(wd)))
    for k in wd:
        a, b = wd[k] or {}, wc.get(k) or {}
        check((a.get('type'), a.get('default')) == (b.get('type'), b.get('default')),
              'W3: input %s: dispatch %r, call %r' % (k, (a.get('type'), a.get('default')),
                                                     (b.get('type'), b.get('default'))))
    jobs = bd.get('jobs') or {}
    for jn in ('deploy', 'promote'):
        uses = str((jobs.get(jn) or {}).get('uses') or '')
        check(re.search(r'/\.github/workflows/reusable-deploy-(appservice|containerapp|staticwebapp)\.yml@', uses),
              'W3: build-deploy job %s calls %r, not a kit deploy reusable' % (jn, uses))
        callee = os.path.join(ROOT, '.github', 'workflows', os.path.basename(uses.split('@')[0]))
        if not os.path.isfile(callee):
            continue
        dj = (load(callee).get('jobs') or {})
        for name, job in dj.items():
            steps = job.get('steps') or []
            login = [i for i, s in enumerate(steps) if str(s.get('uses') or '').startswith('azure/login')]
            if not login:
                continue
            gates = {}
            for i, s in enumerate(steps):
                body = str(s.get('run') or '')
                for g in ('zone', 'approval'):
                    # The INVOCATION, at the start of a line -- not the inlined script's own text,
                    # which the materialise step carries for every gate whether or not one runs.
                    if re.search(r'^\s*python3 "\$RUNNER_TEMP/kit-deploy/release_gates\.py" %s(?:[ ]|$)' % g,
                                 body, re.M):
                        gates.setdefault(g, i)
            for g in ('zone', 'approval'):
                check(g in gates and gates[g] < login[0],
                      'W3: %s job %s: the release %s gate does not run before Azure login (gate at %r, '
                      'login at %d)' % (os.path.basename(callee), name, g, gates.get(g), login[0]))


def w4():
    rw = io.open(RW, encoding='utf-8').read()
    check('azure/login' not in rw and 'id-token' not in rw,
          'W4: reusable-kit-api.yml holds a deploy identity or logs in to Azure')
    srv = io.open(SERVER, encoding='utf-8').read()
    check('/dispatches' not in srv, 'W4: the API server dispatches a workflow (its token would become '
          'the requester)')
    check(not re.search(r"['\"]az ", srv), 'W4: the API server calls the Azure CLI')
    t = load(TPL)
    perms = [((j or {}).get('permissions') or {}) for n, j in (t.get('jobs') or {}).items() if n != 'deploy']
    check(not any(p.get('id-token') for p in perms), 'W4: a non-release job of the template holds id-token')


def w5(rw):
    jobs = rw.get('jobs') or {}
    tk = jobs.get('tickets') or {}
    check(tk.get('environment') == '${{ inputs.ticketing_environment }}', 'W5: tickets environment %r'
          % tk.get('environment'))
    grp = str((tk.get('concurrency') or {}).get('group') or '')
    check("operation == 'tickets.write'" in grp and "format('kit-ticket-writes-{0}', github.repository)" in grp
          and (tk.get('concurrency') or {}).get('cancel-in-progress') is False,
          'W5: the ticket write group is %r' % grp)
    tr = load(TR)
    for jn in ('reconcile', 'resurface'):
        c = ((tr.get('jobs') or {}).get(jn) or {}).get('concurrency') or {}
        check(c.get('group') == 'kit-ticket-writes-${{ github.repository }}' and c.get('cancel-in-progress') is False,
              'W5: reusable-ticket-reconcile.yml %s is not in the shared ticket-writer group: %r' % (jn, c))
    it = jobs.get('intake') or {}
    check('environment' not in it, 'W5: intake runs in an environment')
    check('secrets.' not in json.dumps(it), 'W5: intake reads a secret')
    check('findings' not in jobs, 'W5: a findings read takes a second billed job; it is answered in intake')
    for jn in ('finish',):
        check('secrets.' not in json.dumps(jobs.get(jn) or {}), 'W5: %s reads a secret' % jn)
    steps = [s.get('id') for s in it.get('steps') or []]
    check('findings' in steps and 'findings_answer' in steps and 'refused' in steps,
          'W5: intake does not answer a findings read and a refusal itself: %r' % steps)


def w6():
    for p in (RW, CA):
        doc = load(p)
        steps = []
        if p == CA:
            steps = (doc.get('runs') or {}).get('steps') or []
        else:
            for j in (doc.get('jobs') or {}).values():
                steps += j.get('steps') or []
        for s in steps:
            check('${{' not in str(s.get('run') or ''),
                  'W6: %s step %r has an expression in its script' % (os.path.basename(p), s.get('name')))


OPTIONAL = {
    # The composite sets these itself (the kit's own register, the KEV source from the mirror step).
    'KIT_API_CENTRAL_REGISTRATION': 'set by the composite from the kit delivered by $/',
    'KIT_API_KEV_FEED_FILE': 'set by the composite when the organisation mirror is current',
    'KIT_API_KEV_SHA256': 'set by the composite with the mirror file',
    'KIT_API_KEV_UNAVAILABLE': 'set by the composite when a configured mirror was refused',
    # Settings with a stated default in the server.
    'KIT_API_KEV_URL': 'optional override of the CISA feed URL; unset reads CISA\'s own feed',
    'KIT_API_TODAY': 'a proof\'s clock; unset is the runner\'s date',
    # Read only by the CLI's finish when the operation job left an answer file.
    'KIT_API_CHECK_RUN_ID': 'optional: intake\'s record carries the check run id',
    'KIT_API_OP_RESULT': 'set by the op jobs\' finish step; absent in the refused and finish paths',
}


def w7(rw):
    srv = io.open(SERVER, encoding='utf-8').read()
    read = set(re.findall(r"""(?:_e\(env, |env\.get\()'(KIT_API_[A-Z0-9_]+)'""", srv))
    composite = set(re.findall(r'export (KIT_API_[A-Z0-9_]+)=', io.open(CA, encoding='utf-8').read()))
    set_by = {}
    for jn, job in (rw.get('jobs') or {}).items():
        for s in job.get('steps') or []:
            if str(s.get('uses') or '').startswith('$/.github/actions/kit-api'):
                phase = (s.get('with') or {}).get('phase')
                for k in (s.get('env') or {}):
                    if str(k).startswith('KIT_API_'):
                        set_by.setdefault(k, set()).add(phase)
    for k in sorted(read):
        check(k in set_by or k in composite or k in OPTIONAL,
              'W7: the server reads %s and no step sets it, the composite does not, and it is no stated optional' % k)
    for k in sorted(set_by):
        check(k in read, 'W7: a step sets %s and the server never reads it' % k)
    import kit_api_server as ks
    for phase, names in ks.ENV_BY_PHASE.items():
        for k in names:
            if k.startswith('KIT_API_'):
                check(k in read, 'W7: ENV_BY_PHASE[%s] names %s, which the server never reads' % (phase, k))


def w8():
    import _step_harness as sh
    import _github_api_stub as gs
    import kit_api as ka
    bash, why = sh.usable_bash()
    if not bash:
        FAILS.append('W8: no usable bash to run the composite step (%s); UNKNOWN is not a pass' % why)
        return
    s = sh.step('.github/actions/kit-api/action.yml', None, 'p')
    if not check(s is not None, 'W8: the composite has no step `p`'):
        return
    stub = gs.StubGitHub(repo='octo-org/app')
    base, stop = stub.serve()
    tmp = tempfile.mkdtemp(prefix='kitapi-wf-')
    try:
        for label, req, want_acc, want_ref in (
                ('accepted', ka.build_request('findings.search', {'run_id': 'latest'}), 'true', ''),
                ('refused', dict(ka.build_request('findings.search', {'run_id': 'latest'}),
                                 params={'run_id': 'newest'}), 'false', 'API_SCHEMA_VIOLATION')):
            ws = tempfile.mkdtemp(dir=tmp)
            out = os.path.join(ws, 'kit-api')
            ctx = {'inputs.phase': 'intake', 'inputs.out-dir': out, 'inputs.kev-mirror-url': ''}
            env = {'GITHUB_ACTION_PATH': os.path.join(ROOT, '.github', 'actions', 'kit-api'),
                   'KIT_API_REQUEST': json.dumps(req), 'KIT_API_CORRELATION_ID': req['correlation_id'],
                   'KIT_API_IDEMPOTENCY_KEY': '', 'KIT_API_DEFAULT_BRANCH': 'main', 'KIT_API_OPERATIONS': '',
                   'GITHUB_API_URL': base, 'GITHUB_TOKEN': gs.TOKEN, 'GITHUB_REPOSITORY': stub.repo,
                   'GITHUB_EVENT_NAME': 'workflow_dispatch', 'GITHUB_REF': 'refs/heads/main',
                   'GITHUB_SHA': stub.head_sha, 'GITHUB_RUN_ID': '77', 'GITHUB_ACTOR': 'caller-bot'}
            r = sh.run(bash, s, ctx, ws, extra_env=env, composite=True)
            o = r['outputs']
            check(r['rc'] == 0 and o.get('accepted') == want_acc and o.get('refusal', '') == want_ref,
                  'W8 %s: rc %s, outputs accepted=%r refusal=%r\n%s' % (label, r['rc'], o.get('accepted'),
                                                                       o.get('refusal'), r['log'][-1500:]))
            check(os.path.isfile(os.path.join(out, 'intake.json')), 'W8 %s: no intake.json' % label)
            try:
                json.loads(o.get('intake') or '')
            except ValueError:
                FAILS.append('W8 %s: the intake output is not one-line JSON' % label)
        cr = stub.check_run_named(ka.check_run_name(json.loads(json.dumps(req))['correlation_id']))
        made = [c for c in stub.check_runs.values() if c.get('status') == 'in_progress']
        check(made, 'W8: the accepted call opened no check run on the stub')
    finally:
        stop()
        shutil.rmtree(tmp, ignore_errors=True)


def main():
    try:
        import yaml  # noqa: F401
    except ImportError:
        print('UNKNOWN: PyYAML is required')
        return 2
    for p in (TPL, RW, CA, SERVER):
        if not os.path.isfile(p):
            print('FAIL: %s does not exist' % os.path.relpath(p, ROOT))
            return 1
    t, rw = load(TPL), load(RW)
    for case, args in ((w1, (t,)), (w2, (t,)), (w3, ()), (w4, ()), (w5, (rw,)), (w6, ()), (w7, (rw,)), (w8, ())):
        try:
            case(*args)
        except Exception as exc:  # noqa: BLE001
            import traceback
            FAILS.append('%s crashed: %s: %s\n%s' % (case.__name__, type(exc).__name__, exc,
                                                     traceback.format_exc()[-1500:]))
    for f in FAILS:
        print('FAIL: %s' % f)
    if FAILS:
        print('\n%d failure(s)' % len(FAILS))
        return 1
    print('prove_kit_api_workflow: W1..W8 hold -- the release is the repository\'s own pipeline, called; '
          'the API holds no deploy identity and dispatches nothing; one ticket writer at a time; '
          'every value read is set; the shipped step answers')
    return 0


if __name__ == '__main__':
    sys.exit(main())

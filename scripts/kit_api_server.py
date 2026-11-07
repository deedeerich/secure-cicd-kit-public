#!/usr/bin/env python3
"""The kit's API, run side: what the run that answers a call does (KDEC-035).

WHAT THIS IS

    The `kit-api.yml` run (templates/kit-api.yml calling .github/workflows/reusable-kit-api.yml)
    answers one call in phases, each a job or a step that runs this file:

        intake     validate the request against the v1 contract, refuse by name, check the
                   idempotency key, open the call's check run. Holds no tracker credential.
        tickets    the ticket operations, THROUGH scripts/reconcile_tickets.py: the same backends,
                   stamp, lookup-before-create, routing and ledger as the pipeline's ticket
                   reconciliation, in the same protected environment. Never beside it.
        findings   read and search the findings a security run established (its findings.json).
        finish     write the result: result.json (the artifact), the run summary, and the check
                   run `kit-api/<correlation id>` -- the copy a caller reads through the API host.

    scan.request and deploy.request are carried out by the caller workflow's own jobs (the kit's
    security workflow; the repository's build-deploy.yml, called as a reusable workflow so that the
    API caller IS the release's requester), and `finish` reports what they established.

WHAT IT NEVER DOES

    It deploys nothing, dispatches nothing and approves nothing. It never writes a disposition, an
    exception, a register or the ledger (a ticket write leaves a ledger PROPOSAL as an artifact;
    the pipeline's own reconciliation binds the ticket by its stamp). It tickets only what the
    kit's scan established on the protected default branch. It never closes a ticket: closure is
    the reconciler's, on verified clearance, in a full run (KDEC-024) -- a subset is not a run.

USAGE (inputs arrive through env:, as data; templates and the reusable workflow set them)
    kit_api_server.py intake   --out-dir D
    kit_api_server.py tickets  --out-dir D      (KIT_API_INTAKE: the intake JSON)
    kit_api_server.py findings --out-dir D      (KIT_API_INTAKE)
    kit_api_server.py finish   --out-dir D      (KIT_API_INTAKE; KIT_API_OP_RESULT, a file)

EXIT  0 the phase ran (a refusal is a result, written)   2 usage
"""
import argparse
import datetime
import io
import json
import os
import re
import sys
import zipfile

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

import kit_api as ka  # noqa: E402 - after the path insert

# KDEC-037: the owner's template numbers (scripts/ticket_templates.py SETTING_DEFAULTS), read by the
# intake (validation) and tickets (the rules) phases; unset is the stated default.
TEMPLATE_SETTING_ENV = ('KIT_API_EXTENSION_DEFAULT_DAYS', 'KIT_API_EXTENSION_MAX', 'KIT_API_EXTENSION_CEILING_DAYS',
                        'KIT_API_VENDOR_ADVISORY_EXTENSIONS', 'KIT_API_VENDOR_ADVISORY_DAYS',
                        'KIT_API_NOFIX_EXEMPTION_DAYS', 'KIT_API_NOFIX_EXEMPTION_CEILING_DAYS',
                        'KIT_API_NOFIX_RECHECK_DAYS', 'KIT_API_NOFIX_REVIEW_DAYS', 'KIT_API_EXCEPTION_MAX_DAYS',
                        'KIT_API_REVIEW_MAX_AGE_DAYS', 'KIT_API_VERIFICATION_REMINDER_DAYS',
                        'KIT_API_FUZZY_TITLE_PERCENT')
# The environment each phase reads, for tests/prove_kit_api_workflow.py W7: the workflow must set
# every one of them (or leave it unset on purpose, where a default is stated here).
COMMON_ENV = ('GITHUB_API_URL', 'GITHUB_TOKEN', 'GITHUB_REPOSITORY', 'GITHUB_RUN_ID',
              'GITHUB_RUN_ATTEMPT', 'GITHUB_SERVER_URL', 'GITHUB_SHA', 'GITHUB_ACTOR',
              'GITHUB_TRIGGERING_ACTOR', 'GITHUB_EVENT_NAME', 'GITHUB_REF')
ENV_BY_PHASE = {
    'intake': ('KIT_API_REQUEST', 'KIT_API_CORRELATION_ID', 'KIT_API_IDEMPOTENCY_KEY',
               'KIT_API_OPERATIONS', 'KIT_API_DEFAULT_BRANCH', 'KIT_API_DEPLOY_ENVIRONMENTS',
               'KIT_API_BUILD_DEPLOY_ENVIRONMENTS') + TEMPLATE_SETTING_ENV,
    'tickets': ('KIT_API_INTAKE', 'KIT_API_LEDGER', 'KIT_API_SECURITY_WORKFLOW',
                'KIT_API_DEFAULT_BRANCH', 'KIT_API_REGISTRATION', 'KIT_API_CENTRAL_REGISTRATION',
                'KIT_API_GH_TICKET_TOKEN', 'TICKET_BACKEND', 'KIT_API_REVIEWS_DIR',
                'KIT_API_REVIEW_APPROVER_LIST', 'KIT_API_REVIEW_APPROVER_SOURCE', 'KIT_API_TEAM_READ_TOKEN',
                'KIT_API_BRANCH_ENVIRONMENTS', 'KIT_API_APPROVED_TOOLS',
                'KIT_API_EVIDENCE_STORES', 'KIT_INTEGRATION_IDENTITIES') + TEMPLATE_SETTING_ENV,
    'findings': ('KIT_API_INTAKE', 'KIT_API_LEDGER', 'KIT_API_SECURITY_WORKFLOW',
                 'KIT_API_DEFAULT_BRANCH', 'KIT_API_KEV_FEED_FILE', 'KIT_API_KEV_SHA256',
                 'KIT_API_KEV_UNAVAILABLE', 'KIT_API_KEV_URL'),
    'finish': ('KIT_API_INTAKE', 'KIT_API_OP_RESULT', 'KIT_API_JOB_RESULT',
               'KIT_API_ROUTING_RESULT', 'KIT_API_ASSURANCE_STATE', 'KIT_API_ADVISORY_CAUSES',
               'KIT_API_EVIDENCE_ARTIFACT', 'KIT_API_CHECK_RUN_ID'),
}
ROUTING_WORDS = ('PROCEED', 'PROCEED_WITH_ADVISORY', 'DECISION_REQUIRED', 'EVIDENCE_UNTRUSTED',
                 'BLOCKED')
EVIDENCE_PREFIX = 'security-report-'
IDEM_PREFIX = 'kit-api-idem-'
NOT_REPORTED = 'NOT_REPORTED'
KEV_UNAVAILABLE = 'UNAVAILABLE'
# A ticket write never selects more than this many findings (the params schema's own ceiling).
SELECT_MAX = 100


def _e(env, name, default=''):
    return str(env.get(name) or default).strip()


def _today(env):
    t = _e(env, 'KIT_API_TODAY')
    return t if re.match(r'^\d{4}-\d{2}-\d{2}$', t) else datetime.date.today().isoformat()


def _repo(env):
    return _e(env, 'GITHUB_REPOSITORY')


def _run_url(env, run_id=None):
    server = _e(env, 'GITHUB_SERVER_URL').rstrip('/')
    rid = run_id or _e(env, 'GITHUB_RUN_ID')
    return '%s/%s/actions/runs/%s' % (server, _repo(env), rid) if server and rid else ''


def _csv(text):
    return [x.strip() for x in str(text or '').split(',') if x.strip()]


def _single_line(value):
    s = str('' if value is None else value)
    return ' '.join(s.split()) if '\n' in s or '\r' in s else s


def emit(env, **values):
    """One line per value to $GITHUB_OUTPUT. A value never carries a newline (KDEC-027 item 5:
    a newline in an output value is output injection)."""
    path = _e(env, 'GITHUB_OUTPUT')
    lines = ['%s=%s' % (k, _single_line(v)) for k, v in values.items()]
    if path:
        with io.open(path, 'a', encoding='utf-8') as fh:
            fh.write('\n'.join(lines) + '\n')


def summary(env, text):
    path = _e(env, 'GITHUB_STEP_SUMMARY')
    if path:
        with io.open(path, 'a', encoding='utf-8') as fh:
            fh.write(text + '\n')


# ═════════════════════════════════════════════════════════════════════════════════════
# INTAKE
# ═════════════════════════════════════════════════════════════════════════════════════

def _deny(doc, code, detail, field='', data=None):
    doc['accepted'] = False
    doc['refusal'] = ka.refusal(code, detail, field)
    if data:
        doc['refused_data'] = data
    return doc


def _environment_needs_human(client, repo, environment):
    """-> '' when GitHub says the environment demands a human approver with self-review prevented,
    else why not. Read back with environment_protection's own evaluation, the deploys' rule; an
    environment that cannot be read is not protected for this purpose."""
    import environment_protection as ep
    status, doc, _h, err = client.get('/repos/%s/environments/%s' % (repo, environment))
    if err or not isinstance(doc, dict):
        return ('the environment %s could not be read (%s), so a human approval on it cannot be shown'
                % (environment, err or status))
    demand = {'approver_groups': [], 'approvers_required': 1, 'self_review_prevented': 'required'}
    outcome, why = ep.evaluate(doc, demand)[:2]
    if outcome != ep.VERIFIED:
        return '%s: %s' % (outcome, why)
    return ''


def _idempotency(client, repo, key_hash):
    """-> ('new'|'seen'|'unverified', first correlation id or '', why)."""
    name = IDEM_PREFIX + key_hash
    status, doc, _h, err = client.get('/repos/%s/actions/artifacts?name=%s&per_page=10' % (repo, name))
    if err or not isinstance(doc, dict):
        return 'unverified', '', 'the key\'s history could not be read (%s)' % (err or status)
    hits = [a for a in doc.get('artifacts') or [] if a.get('name') == name and not a.get('expired')]
    if not hits:
        return 'new', '', ''
    rid = (hits[-1].get('workflow_run') or {}).get('id')
    first = ''
    if rid:
        _s, run, _h2, err2 = client.get('/repos/%s/actions/runs/%s' % (repo, rid))
        title = (run or {}).get('display_title') or '' if isinstance(run, dict) else ''
        m = re.search(r'kapi-[0-9]{8}T[0-9]{6}Z-[0-9a-f]{12}', title)
        first = m.group(0) if m else ''
    return 'seen', first, ''


def intake(env, client, out_dir, schemas=None):
    """-> the intake record. Refuses by name before anything a call guards is read or written."""
    schemas = schemas or ka.load_schemas()
    cid_in = _e(env, 'KIT_API_CORRELATION_ID')
    raw = env.get('KIT_API_REQUEST') or ''
    repo = _repo(env)
    doc = {'accepted': False, 'refusal': None, 'operation': '', 'write': False, 'idem_hash': '',
           'correlation_id': cid_in if ka.CORRELATION_RE.match(cid_in) else '',
           'request': {}, 'deploy': {}, 'check_run_id': '', 'repository': repo,
           'transport': {'repository_dispatch': 'repository_dispatch'}.get(
               _e(env, 'GITHUB_EVENT_NAME'), 'workflow_dispatch'),
           'actor': {'actor': _e(env, 'GITHUB_ACTOR')[:100],
                     'triggering_actor': _e(env, 'GITHUB_TRIGGERING_ACTOR')[:100],
                     'on_behalf_of': '', 'on_behalf_of_verified': False},
           'request_sha256': ka.sha256(raw) if raw else '', 'idempotency_key_sha256': '',
           'received_at': ka.iso(), 'notes': []}
    try:
        _intake(doc, env, client, raw, cid_in, repo, schemas)
    finally:
        _save(out_dir, 'intake.json', doc)
        emit(env, accepted='true' if doc['accepted'] else 'false', operation=doc['operation'],
             refusal=(doc['refusal'] or {}).get('code', ''), write='true' if doc['write'] else 'false',
             idem_hash=doc['idem_hash'], check_run_id=doc['check_run_id'],
             correlation_id=doc['correlation_id'],
             deploy_mode=doc['deploy'].get('mode', ''),
             deploy_environment=doc['deploy'].get('environment', ''),
             promote_from_run_id=doc['deploy'].get('promote_from_run_id', ''),
             promote_from_environment=doc['deploy'].get('promote_from_environment', ''),
             release_path=doc['deploy'].get('release_path', ''),
             intake=json.dumps(doc, sort_keys=True, separators=(',', ':')))
    return doc


def _intake(doc, env, client, raw, cid_in, repo, schemas):
    if len(raw) > ka.REQUEST_MAX:
        return _deny(doc, ka.API_REQUEST_TOO_LARGE, 'the request is %d characters; the limit is %d'
                     % (len(raw), ka.REQUEST_MAX))
    try:
        req = json.loads(raw)
    except ValueError as exc:
        return _deny(doc, ka.API_REQUEST_UNPARSEABLE, 'the request is not JSON: %s' % str(exc)[:200])
    if isinstance(req, dict) and isinstance(req.get('operation'), str) and len(req['operation']) <= 40:
        doc['operation'] = req['operation']
    if isinstance(req, dict) and isinstance(req.get('on_behalf_of'), str):
        doc['actor']['on_behalf_of'] = req['on_behalf_of'][:200]
    r = ka.check_request(req, schemas)
    if r:
        return _deny(doc, r['code'], r['detail'], r.get('field', ''))
    doc['request'] = req
    op = req['operation']
    if not ka.CORRELATION_RE.match(cid_in) or req['correlation_id'] != cid_in:
        return _deny(doc, ka.API_CORRELATION_MISMATCH, 'the run was dispatched for correlation id %r '
                     'and the request names %r; the run answers only the call it was named for'
                     % (cid_in[:40], req['correlation_id']), 'correlation_id')
    doc['correlation_id'] = cid_in
    enabled = _csv(env.get('KIT_API_OPERATIONS')) or list(ka.DEFAULT_ENABLED)
    if op not in enabled:
        return _deny(doc, ka.API_OPERATION_NOT_ENABLED, '%s is not enabled in %s (enabled: %s); %s'
                     % (op, repo, ', '.join(enabled), 'writes are off until the repository turns them on'
                        if op in ka.WRITE_OPERATIONS else 'the repository narrowed its list'), 'operation')
    key = req.get('idempotency_key') or ''
    key_in = _e(env, 'KIT_API_IDEMPOTENCY_KEY')
    doc['write'] = op in ka.WRITE_OPERATIONS
    if key:
        doc['idem_hash'] = ka.sha256(key)[:32]
        doc['idempotency_key_sha256'] = ka.sha256(key)
    if (doc['write'] or key_in) and key != key_in:
        return _deny(doc, ka.API_IDEMPOTENCY_KEY_REQUIRED, 'the dispatch\'s idempotency_key input and '
                     'the request\'s key differ: one call, one key, the same in both places',
                     'idempotency_key')
    job = ka.OPERATIONS[op]['job']
    default = _e(env, 'KIT_API_DEFAULT_BRANCH')
    ref = _e(env, 'GITHUB_REF')
    if job in ('tickets', 'deploy') and (not default or ref != 'refs/heads/%s' % default):
        return _deny(doc, ka.API_REF_NOT_DEFAULT_BRANCH, '%s runs only on the protected default branch '
                     '(%s); this run is on %s' % (op, default or 'not named', ref or 'no ref'))
    p = req['params']
    if op == 'tickets.write':
        if 'requested_disposition' in p:
            return _deny(doc, ka.API_DISPOSITION_NOT_VIA_API, 'a disposition (%s) is a judgement merged '
                         'to the protected default branch under CODEOWNERS; the API never makes or '
                         'requests one' % str(p['requested_disposition'])[:40], 'params.requested_disposition')
        sel = p.get('select') or {}
        n = sum(len(sel.get(k) or []) for k in ('identities', 'cluster_keys', 'fingerprints'))
        if not n or n > SELECT_MAX:
            return _deny(doc, ka.API_SCHEMA_VIOLATION, 'select names %d finding(s); between 1 and %d'
                         % (n, SELECT_MAX), 'params.select')
    if op == 'tickets.submit':
        import ticket_templates as tt
        settings, sprob = tt.settings_from(template_settings(env))
        if settings is None:
            return _deny(doc, ka.API_TEMPLATE_INVALID, 'configuration: %s' % sprob)
        r = tt.validate_submit(p, settings, _today(env))
        if r:
            return _deny(doc, ka.API_TEMPLATE_INVALID, '%s: %s' % (r['code'], r['detail']), 'params.items',
                         data={'template_refusal': r})
    if op == 'tickets.search' and 'tracker_query' in p:
        import ticket_templates as tt
        errs = ka.validate(p['tracker_query'], tt.load_template('intake'), '$.params.tracker_query')
        if errs:
            return _deny(doc, ka.API_SCHEMA_VIOLATION, '%s %s' % errs[0], errs[0][0])
        jql = p['tracker_query'].get('jql') or ''
        if re.search(r'(?i)\border\s+by\b', jql) or any(c in jql for c in ';\n\r'):
            return _deny(doc, ka.API_TRACKER_QUERY_REFUSED, 'the JQL carries ORDER BY or a statement break; it is a '
                         'filter, wrapped as project in (...) AND (<jql>)', 'params.tracker_query.jql')
    if op == 'tickets.get' and bool(p.get('ref')) == bool(p.get('cluster_key')):
        return _deny(doc, ka.API_SCHEMA_VIOLATION, 'tickets.get takes exactly one of ref and cluster_key',
                     'params')
    if op == 'evidence.export':
        import evidence_export as ee
        bad = ee.params_problem(p, repo)
        if bad:
            return _deny(doc, bad['code'], bad['detail'], bad.get('field') or 'params')
    if op == 'findings.get' and bool(p.get('finding_id')) == bool(p.get('fingerprint')):
        return _deny(doc, ka.API_SCHEMA_VIOLATION, 'findings.get takes exactly one of finding_id and '
                     'fingerprint', 'params')
    if op == 'tickets.search':
        f = p.get('filters') or {}
        if f.get('repo') and f['repo'].lower() != repo.lower():
            return _deny(doc, ka.API_REPOSITORY_NOT_SERVED, 'this API serves %s, not %s; call that '
                         'repository\'s kit-api' % (repo, f['repo']), 'params.filters.repo')
        if any(k in f for k in ('cve', 'kev', 'text')) and not p.get('findings_run_id'):
            return _deny(doc, ka.API_FILTER_NEEDS_FINDINGS_RUN, 'a cve, kev or text filter reads the '
                         'findings of a security run: name findings_run_id (or "latest")',
                         'params.findings_run_id')
    if op == 'scan.request':
        want = p['ref']
        if ref not in ('refs/heads/%s' % want, 'refs/tags/%s' % want):
            return _deny(doc, ka.API_SCHEMA_VIOLATION, 'the scan asks for %s and this run was dispatched '
                         'at %s; a scan reads the ref it was dispatched at' % (want, ref or 'no ref'),
                         'params.ref')
    if op == 'deploy.request':
        r2 = _deploy_intake(doc, env, client, repo, p)
        if r2:
            return r2
    if key:
        state, first, why = _idempotency(client, repo, doc['idem_hash'])
        if state == 'unverified':
            return _deny(doc, ka.API_IDEMPOTENCY_UNVERIFIED, '%s; a write is never risked twice' % why)
        if state == 'seen':
            return _deny(doc, ka.API_DUPLICATE_REQUEST, 'this idempotency key was used by %s; nothing was '
                         'done again -- read that call with status.get' % (first or 'an earlier call '
                                                                            '(its run could not be read)'))
    doc['accepted'] = True
    doc['check_run_id'] = _check_run(client, env, doc, 'in_progress', None)
    return doc


def _deploy_intake(doc, env, client, repo, p):
    if doc['transport'] == 'repository_dispatch':
        return _deny(doc, ka.API_TRANSPORT_NOT_PERMITTED, 'a release is requested by workflow_dispatch '
                     'only: its token needs Actions write, never the contents write a repository_dispatch '
                     'token holds, and the caller of the run is the release\'s requester')
    path = p.get('release_path') or 'normal'
    if path not in ('normal', 'hotfix'):
        return _deny(doc, ka.API_RELEASE_PATH_NOT_PERMITTED, 'release_path %s needs an attributed '
                     'exception record a person makes; a person dispatches it, not the API' % path,
                     'params.release_path')
    environment = p['environment']
    allowed = _csv(env.get('KIT_API_DEPLOY_ENVIRONMENTS'))
    if environment not in allowed:
        return _deny(doc, ka.API_ENVIRONMENT_NOT_PERMITTED, 'environment %s is not in this repository\'s '
                     'API deploy list (%s)' % (environment, ', '.join(allowed) or 'empty: none'),
                     'params.environment')
    if p['mode'] == 'build-deploy':
        builds = _csv(env.get('KIT_API_BUILD_DEPLOY_ENVIRONMENTS')) or ['dev', 'test']
        if environment not in builds:
            return _deny(doc, ka.API_ENVIRONMENT_NOT_PERMITTED, 'build-deploy is for %s; %s is reached '
                         'by promoting a verified digest (KDEC-029)' % (', '.join(builds), environment),
                         'params.mode')
    else:
        if not p.get('promote_from_run_id') or not p.get('promote_from_environment'):
            return _deny(doc, ka.API_PROMOTION_SOURCE_REQUIRED, 'a promotion names the predecessor run '
                         'and environment whose verified record it promotes', 'params.promote_from_run_id')
    why = _environment_needs_human(client, repo, environment)
    if why:
        return _deny(doc, ka.API_DEPLOY_NEEDS_HUMAN_APPROVAL, 'a release requested through the API needs '
                     'a human approver who is not the requester: %s' % why, 'params.environment')
    doc['deploy'] = {'mode': p['mode'], 'environment': environment, 'release_path': path,
                     'promote_from_run_id': str(p.get('promote_from_run_id') or ''),
                     'promote_from_environment': p.get('promote_from_environment') or ''}
    return None


def _save(out_dir, name, doc):
    if out_dir:
        os.makedirs(out_dir, exist_ok=True)
        with io.open(os.path.join(out_dir, name), 'w', encoding='utf-8') as fh:
            json.dump(doc, fh, indent=2, sort_keys=True, default=str)
            fh.write('\n')


# ═════════════════════════════════════════════════════════════════════════════════════
# EVIDENCE: the findings a security run established
# ═════════════════════════════════════════════════════════════════════════════════════

def _members(blob):
    out = {}
    try:
        z = zipfile.ZipFile(io.BytesIO(blob))
    except zipfile.BadZipFile:
        return None
    for name in z.namelist():
        base = name.rsplit('/', 1)[-1]
        if base in ('findings.json', 'findings-coverage.json'):
            if base not in out or len(name) < len(out[base][0]):
                out[base] = (name, z.read(name))
    return dict((k, v[1]) for k, v in out.items())


def _run_evidence(client, repo, run):
    """-> (findings list, coverage or None, why)."""
    _s, doc, _h, err = client.get('/repos/%s/actions/runs/%s/artifacts?per_page=100' % (repo, run['id']))
    if err or not isinstance(doc, dict):
        return None, None, 'the artifacts of run %s could not be read (%s)' % (run['id'], err or _s)
    arts = [a for a in doc.get('artifacts') or [] if str(a.get('name') or '').startswith(EVIDENCE_PREFIX)]
    live = [a for a in arts if not a.get('expired')]
    if not live:
        return None, None, ('run %s kept no %s* artifact%s' % (run['id'], EVIDENCE_PREFIX,
                                                             ' (expired)' if arts else ''))

    def attempt(a):
        tail = str(a['name'])[len(EVIDENCE_PREFIX):]
        return int(tail) if tail.isdigit() else 0
    art = sorted(live, key=attempt)[-1]
    blob = client.download('/repos/%s/actions/artifacts/%s/zip' % (repo, art['id']))
    if not blob:
        return None, None, 'the evidence artifact %s could not be downloaded' % art['name']
    files = _members(blob)
    if files is None or 'findings.json' not in files:
        return None, None, 'the evidence artifact %s holds no findings.json' % art['name']
    try:
        findings = json.loads(files['findings.json'].decode('utf-8'))
    except ValueError:
        return None, None, 'findings.json in %s is not JSON' % art['name']
    if not isinstance(findings, list):
        return None, None, 'findings.json in %s is not a list' % art['name']
    cov = None
    if 'findings-coverage.json' in files:
        try:
            cov = json.loads(files['findings-coverage.json'].decode('utf-8'))
        except ValueError:
            cov = None
    return findings, cov, ''


def evidence(client, env, run_id, any_branch=False):
    """-> (run, findings, coverage, refusal). A completed run of the default branch that kept its
    evidence -- the kit's own scan, under the gate's rules -- or a refusal naming why not."""
    repo = _repo(env)
    default = _e(env, 'KIT_API_DEFAULT_BRANCH')
    wf = _e(env, 'KIT_API_SECURITY_WORKFLOW', 'build-deploy.yml')
    if run_id == 'latest':
        _s, doc, _h, err = client.get('/repos/%s/actions/workflows/%s/runs?branch=%s&status=completed'
                                      '&per_page=20' % (repo, wf, default))
        if err or not isinstance(doc, dict):
            return None, None, None, ka.refusal(ka.API_EVIDENCE_UNAVAILABLE, 'the runs of %s could not be '
                                                'read (%s)' % (wf, err or _s))
        whys = []
        for run in doc.get('workflow_runs') or []:
            if run.get('head_branch') != default or run.get('status') != 'completed':
                continue
            f, c, why = _run_evidence(client, repo, run)
            if f is not None:
                return run, f, c, None
            whys.append(why)
        return None, None, None, ka.refusal(ka.API_EVIDENCE_UNAVAILABLE, 'no completed %s run of %s kept '
                                            'its evidence%s' % (wf, default, ('; ' + '; '.join(whys[:3]))
                                                                if whys else ''))
    _s, run, _h, err = client.get('/repos/%s/actions/runs/%s' % (repo, run_id))
    if err or not isinstance(run, dict):
        return None, None, None, ka.refusal(ka.API_EVIDENCE_UNAVAILABLE, 'run %s could not be read (%s)'
                                            % (run_id, err or _s), 'run_id')
    if (run.get('head_branch') != default and not any_branch) or run.get('status') != 'completed':
        return None, None, None, ka.refusal(ka.API_EVIDENCE_UNAVAILABLE, 'run %s is %s on %s; the API reads '
                                            'only a COMPLETED run of the default branch %s'
                                            % (run_id, run.get('status'), run.get('head_branch'), default),
                                            'run_id')
    f, c, why = _run_evidence(client, repo, run)
    if f is None:
        return None, None, None, ka.refusal(ka.API_EVIDENCE_UNAVAILABLE, why, 'run_id')
    return run, f, c, None


CVE_RE = re.compile(r'CVE-\d{4}-\d{4,}', re.I)


def cves_of(f):
    out = []
    for t in [f.get('rule_id') or ''] + list(f.get('what_aliases') or []):
        for c in CVE_RE.findall(str(t)):
            c = c.upper()
            if c not in out:
                out.append(c)
    return out


def kev_catalog(env):
    import known_exploited as ke
    reason = _e(env, 'KIT_API_KEV_UNAVAILABLE')
    feed = _e(env, 'KIT_API_KEV_FEED_FILE')
    cache = os.path.join(_e(env, 'RUNNER_TEMP') or '.', 'kit-api-kev-cache') if _e(env, 'RUNNER_TEMP') else ''
    return ke.load_catalog(_e(env, 'KIT_API_KEV_URL') or ke.KEV_URL, cache, _today(env), feed_file=feed,
                           expect_sha256=_e(env, 'KIT_API_KEV_SHA256'), unavailable_reason=reason)


def kev_of(f, catalog):
    """True / False / UNAVAILABLE for a finding with a CVE; None for one with none. An unreadable
    catalog is never False: nobody showed the CVE is not exploited."""
    cs = cves_of(f)
    if not cs:
        return None
    if catalog is None or catalog.get('state') != 'AVAILABLE':
        return KEV_UNAVAILABLE
    return any(c in catalog['cves'] for c in cs)


# ═════════════════════════════════════════════════════════════════════════════════════
# FINDINGS
# ═════════════════════════════════════════════════════════════════════════════════════

FINDING_FIELDS = ('identity', 'fp', 'cluster_key', 'scanner', 'tool', 'scanner_version', 'job',
                  'rule_id', 'severity', 'canonical_path', 'line', 'finding_subject', 'cwe', 'state',
                  'reason', 'row_established', 'baseline_state', 'first_seen', 'correlation_tier')


def _ledger(env):
    import reconcile_tickets as rt
    led, note = rt.load_ledger(_e(env, 'KIT_API_LEDGER'))
    return led, note


def _ticket_index(ledger):
    """cluster key -> {ref, key}; and identity -> cluster key, from the ledger."""
    by_key, by_ident = {}, {}
    for k, e in (ledger or {}).items():
        if not isinstance(e, dict) or str(k).startswith('test:'):
            continue
        live = e.get('merged_into') or k
        if e.get('ref'):
            by_key[k] = {'ref': str(e.get('ref')), 'key': e.get('key') or '', 'cluster_key': live}
        for i in e.get('member_identities') or []:
            by_ident.setdefault(i, live)
    return by_key, by_ident


def shape_finding(f, catalog, tickets_by_key, key_by_ident):
    out = {'fingerprint' if k == 'fp' else ('path' if k == 'canonical_path' else
           ('subject' if k == 'finding_subject' else ('identity_state' if k == 'state' else k))): f.get(k)
           for k in FINDING_FIELDS}
    out['cves'] = cves_of(f)
    out['kev'] = kev_of(f, catalog)
    ck = f.get('cluster_key') or key_by_ident.get(f.get('identity') or '')
    t = tickets_by_key.get(ck or '') or (tickets_by_key.get(key_by_ident.get(f.get('identity') or '', ''))
                                         if f.get('identity') else None)
    out['ticket'] = t
    return out


def _match_finding(f, flt, catalog):
    """-> True / False / None (None: a filter that could not be judged, e.g. kev with no catalog)."""
    if flt.get('fingerprint') and f.get('fp') != flt['fingerprint']:
        return False
    if flt.get('finding_id') and f.get('identity') != flt['finding_id']:
        return False
    if flt.get('cluster_key') and f.get('cluster_key') != flt['cluster_key']:
        return False
    if flt.get('severity') and str(f.get('severity') or '').lower() not in flt['severity']:
        return False
    for k in ('scanner', 'job'):
        if flt.get(k) and f.get(k) != flt[k]:
            return False
    if flt.get('rule') and flt['rule'].lower() not in str(f.get('rule_id') or '').lower():
        return False
    if flt.get('path') and not str(f.get('canonical_path') or '').startswith(flt['path']):
        return False
    if flt.get('cve') and flt['cve'].upper() not in cves_of(f):
        return False
    if flt.get('established_only') and not f.get('row_established'):
        return False
    if flt.get('text'):
        hay = ' '.join(str(f.get(k) or '') for k in ('rule_id', 'canonical_path', 'scanner', 'tool', 'cwe',
                                                      'what', 'job')).lower()
        if flt['text'].lower() not in hay:
            return False
    if 'kev' in flt:
        k = kev_of(f, catalog)
        if k == KEV_UNAVAILABLE:
            return None
        if k is None or k != flt['kev']:
            return False
    return True


def _page(items, p):
    limit = int(p.get('limit') or 50)
    offset = int(p.get('offset') or 0)
    page = items[offset:offset + limit]
    nxt = offset + limit if offset + limit < len(items) else None
    return page, nxt


def answer(api_state, data=None, notes=None, routing_result='', refusal=None, next_offset=None):
    return {'api_state': api_state, 'data': data or {}, 'notes': list(notes or []),
            'routing_result': routing_result, 'refusal': refusal, 'next_offset': next_offset}


def findings(intake_doc, env, client, out_dir):
    req = intake_doc['request']
    if req.get('operation') == 'evidence.export':
        # KDEC-039: read-only, this repository only, every section or NOT ESTABLISHED by name.
        import evidence_export as ee
        return ee.serve(intake_doc, env, client, out_dir)
    p = req['params']
    run, recs, _cov, ref = evidence(client, env, p['run_id'])
    if ref:
        return answer(ka.API_REFUSED, refusal=ref)
    flt = dict(p.get('filters') or {})
    if req['operation'] == 'findings.get':
        flt = {'finding_id': p['finding_id']} if p.get('finding_id') else {'fingerprint': p['fingerprint']}
    needs_kev = 'kev' in flt or any(cves_of(f) for f in recs)
    catalog = kev_catalog(env) if needs_kev else None
    ledger, lnote = _ledger(env)
    by_key, by_ident = _ticket_index(ledger or {})
    matched, not_judged = [], 0
    for f in recs:
        m = _match_finding(f, flt, catalog)
        if m is None:
            not_judged += 1
        elif m:
            matched.append(f)
    shaped = [shape_finding(f, catalog, by_key, by_ident) for f in matched]
    data = {'run': {'id': run.get('id'), 'commit': run.get('head_sha'), 'url': run.get('html_url') or ''},
            'kev_state': (catalog or {}).get('state') if catalog else 'NOT_NEEDED',
            'kev_catalog': {k: (catalog or {}).get(k) for k in ('catalog_version', 'date_released', 'sha256')}
            if catalog else None,
            'not_judged': not_judged, 'ledger': lnote if ledger is not None else 'unreadable: %s' % lnote}
    notes = []
    if catalog and catalog.get('state') != 'AVAILABLE':
        notes.append('the KEV catalog could not be read (%s): no CVE here is shown not to be exploited, and '
                     'kev is UNAVAILABLE, never false' % catalog.get('why'))
    if req['operation'] == 'findings.get':
        data['found'] = bool(shaped)
        data['finding'] = shaped[0] if shaped else None
        if not shaped:
            notes.append('run %s established no such finding' % run.get('id'))
        return answer(ka.API_COMPLETED, data, notes)
    page, nxt = _page(shaped, p)
    data['total'] = len(shaped)
    data['findings'] = page
    return answer(ka.API_COMPLETED, data, notes, next_offset=nxt)


# ═════════════════════════════════════════════════════════════════════════════════════
# TICKETS -- through the kit's reconciler, never beside it
# ═════════════════════════════════════════════════════════════════════════════════════

BACKEND_VARS = {
    'jira': ('JIRA_',),
    'azdo': ('AZDO_',),
    'github': ('TICKET_REPO', 'TICKET_CALIBRATION_REF', 'GH_TOKEN'),
    'freshservice': ('FRESHSERVICE_',),
}


def tracker_env(env):
    """The tracker's settings exactly as reusable-ticket-reconcile.yml hands them over: only the
    selected backend's credentials survive (C-2 refuses two at once), and the run's GITHUB_TOKEN is
    never offered to the reconciler as a tracker credential."""
    out = dict((k, v) for k, v in env.items() if k not in ('GITHUB_TOKEN', 'GH_TOKEN'))
    want = _e(env, 'TICKET_BACKEND').lower()
    if want == 'github' and _e(env, 'KIT_API_GH_TICKET_TOKEN'):
        out['GH_TOKEN'] = _e(env, 'KIT_API_GH_TICKET_TOKEN')
    for other, prefixes in BACKEND_VARS.items():
        if other == want:
            continue
        for k in list(out):
            if any(k == p or (p.endswith('_') and k.startswith(p)) for p in prefixes):
                if want == 'github' and k == 'GH_TOKEN':
                    continue
                out.pop(k, None)
    out['TICKETING_MODE'] = 'real'
    return out


def _registers(env):
    reg = _e(env, 'KIT_API_REGISTRATION')
    central = _e(env, 'KIT_API_CENTRAL_REGISTRATION')
    return (central if central and os.path.isfile(central) else ''), (reg if reg and os.path.isfile(reg) else '')


def _sweep(backend, ledger, routing, repo):
    if hasattr(backend, 'set_routing'):
        backend.set_routing(routing, repo, sorted(set(str(e.get('project')) for e in (ledger or {}).values()
                                                      if isinstance(e, dict) and e.get('project'))))
    known = sorted(set(str(e.get('ref')) for e in (ledger or {}).values() if isinstance(e, dict) and e.get('ref')))
    return backend.sweep(known_refs=known)


def _find_ref(sweep_map, ref):
    for stamp, hits in (sweep_map or {}).items():
        for h in hits:
            if str(h.get('ref')) == str(ref) or (h.get('key') and str(h.get('key')) == str(ref)):
                return stamp, h
    return None, None


def _ledger_view(entry):
    e = entry if isinstance(entry, dict) else {}
    return {k: e.get(k) for k in ('severity', 'sla', 'raised_as', 'first_seen', 'last_seen', 'raised_run',
                                  'ticket_class', 'confidence', 'member_identities', 'fps', 'project')}


def _ticket_shape(stamp, hit, entry):
    return {'cluster_key': stamp, 'ref': str(hit.get('ref') or ''), 'key': hit.get('key') or
            (entry or {}).get('key') or '', 'url': hit.get('url') or '', 'state': hit.get('state') or '',
            'status_name': hit.get('status_name') or '', 'labels': list(hit.get('labels') or []),
            'ledger': _ledger_view(entry)}


def tickets(intake_doc, env, client, out_dir):
    import reconcile_tickets as rt
    req = intake_doc['request']
    op = req['operation']
    p = req['params']
    tenv = tracker_env(env)
    backend, note = rt.choose_backend(tenv)
    if backend is None:
        return answer(ka.API_FAILED, {'ticketing_state': rt.TICKETING_NOT_CONFIGURED},
                         ['no ticket backend: %s' % note], 'EVIDENCE_UNTRUSTED')
    ledger, lnote = _ledger(env)
    if ledger is None:
        return answer(ka.API_FAILED, {'ticketing_state': rt.TICKETING_UNAVAILABLE},
                         ['%s -- an unreadable ledger is not an empty one' % lnote], 'EVIDENCE_UNTRUSTED')
    central, repo_reg = _registers(env)
    repo = _repo(env)
    routing, r_note = rt.routing_from_registrations(central, repo_reg, repo)
    if op == 'tickets.write':
        return _tickets_write(rt, backend, ledger, routing, central, repo_reg, req, p, env, client, out_dir,
                              [note, lnote, 'routing: %s' % r_note])
    if op == 'tickets.submit':
        return _tickets_submit(rt, backend, ledger, routing, central, repo_reg, req, p, env, client, out_dir,
                               [note, lnote, 'routing: %s' % r_note], intake_doc)
    if op == 'tickets.search' and p.get('tracker_query') is not None:
        return _tickets_intake(rt, backend, ledger, routing, p, env, client, [note, lnote])
    sweep_map, complete, detail = _sweep(backend, ledger, routing, repo)
    base = {'backend': backend.name, 'sweep_complete': bool(complete), 'sweep': detail,
            'calls': getattr(backend, 'calls', None)}
    route = 'PROCEED' if complete else 'EVIDENCE_UNTRUSTED'
    notes = [] if complete else ['the tracker sweep was PARTIAL (%s): every count is a floor, and an absence '
                                 'is not established' % detail]
    if op == 'tickets.get':
        if p.get('cluster_key'):
            hits = sweep_map.get(p['cluster_key']) or []
            stamp, hit = (p['cluster_key'], hits[0]) if hits else (None, None)
            if len(hits) > 1:
                notes.append('%d tickets carry this stamp: BINDING_AMBIGUOUS, a person declares which is '
                             'canonical; the first is shown' % len(hits))
        else:
            stamp, hit = _find_ref(sweep_map, p['ref'])
        if hit is None:
            if not complete:
                return answer(ka.API_FAILED, base, notes, route)
            return answer(ka.API_REFUSED, base, notes, refusal=ka.refusal(
                ka.API_TICKET_NOT_KIT_STAMPED, '%s carries no kit cluster stamp in this tracker'
                % (p.get('ref') or p.get('cluster_key'))))
        desc, ok, d_read = backend.read_description(hit['ref'])
        tk = _ticket_shape(stamp, hit, ledger.get(stamp))
        tk['block'] = rt.block_facts(backend.description_text(desc)) if ok else None
        if not ok:
            notes.append('the ticket\'s description could not be read (%s): its block is not shown' % d_read)
        return answer(ka.API_COMPLETED, dict(base, ticket=tk), notes, route)
    if op == 'tickets.comment':
        stamp, hit = _find_ref(sweep_map, p['ref'])
        if hit is None:
            if not complete:
                return answer(ka.API_FAILED, base, notes, route)
            return answer(ka.API_REFUSED, base, notes, refusal=ka.refusal(
                ka.API_TICKET_NOT_KIT_STAMPED, '%s carries no kit cluster stamp in this tracker; comment on it '
                'in the tracker directly' % p['ref']))
        actor = intake_doc.get('actor') or {}
        text = ('Comment through the secure-cicd-kit API (correlation %s; requested by %s%s). It changes '
                'no state and decides nothing.\n\n%s' % (
                    intake_doc['correlation_id'], actor.get('actor') or 'unknown',
                    ('; on behalf of %s, as declared by the caller -- not verified' % actor['on_behalf_of'])
                    if actor.get('on_behalf_of') else '', p['text']))
        if req.get('dry_run'):
            return answer(ka.API_COMPLETED, dict(base, ref=hit['ref'], commented=False, planned=True),
                             notes + ['dry run: nothing was written'], route)
        ok_c, d_c = backend.comment(hit['ref'], text)
        if not ok_c:
            return answer(ka.API_FAILED, dict(base, ref=hit['ref'], commented=False),
                             notes + ['the comment was not written: %s' % d_c], 'EVIDENCE_UNTRUSTED')
        return answer(ka.API_COMPLETED, dict(base, ref=hit['ref'], key=hit.get('key') or '', cluster_key=stamp,
                                                commented=True), notes, route)
    return _tickets_search(rt, sweep_map, complete, base, ledger, p, env, client, notes, route)


def _tickets_search(rt, sweep_map, complete, base, ledger, p, env, client, notes, route):
    flt = p.get('filters') or {}
    joined, catalog = {}, None
    if p.get('findings_run_id'):
        run, recs, _c, ref = evidence(client, env, p['findings_run_id'])
        if ref:
            return answer(ka.API_REFUSED, base, notes, refusal=ref)
        _bk, by_ident = _ticket_index(ledger)
        for f in recs:
            ck = by_ident.get(f.get('identity') or '') or f.get('cluster_key')
            if ck:
                joined.setdefault(ck, []).append(f)
        base['findings_run'] = {'id': run.get('id'), 'commit': run.get('head_sha')}
        if 'kev' in flt:
            catalog = kev_catalog(env)
            base['kev_state'] = catalog.get('state')
    out, not_judged = [], 0
    for stamp in sorted(sweep_map or {}):
        entry = ledger.get(stamp) if isinstance(ledger.get(stamp), dict) else {}
        for hit in sweep_map[stamp]:
            verdict = _match_ticket(stamp, hit, entry, flt, joined.get(stamp) or [], catalog, rt)
            if verdict is None:
                not_judged += 1
            elif verdict:
                out.append(_ticket_shape(stamp, hit, entry))
    out.sort(key=lambda t: (0, int(t['ref'])) if t['ref'].isdigit() else (1, t['ref']))
    page, nxt = _page(out, p)
    data = dict(base, total=len(out), tickets=page, not_judged=not_judged)
    if catalog is not None and catalog.get('state') != 'AVAILABLE':
        notes.append('the KEV catalog could not be read (%s): %d ticket(s) not judged -- never "not '
                     'exploited"' % (catalog.get('why'), not_judged))
    return answer(ka.API_COMPLETED, data, notes, route, next_offset=nxt)


def _match_ticket(stamp, hit, entry, flt, joined, catalog, rt):
    if flt.get('cluster_key') and stamp != flt['cluster_key']:
        return False
    if flt.get('status') and hit.get('state') != flt['status']:
        return False
    idents = set(entry.get('member_identities') or []) | rt.identities_from_body(hit.get('body') or '')
    if flt.get('finding_id') and flt['finding_id'] not in idents:
        return False
    if flt.get('fingerprint') and flt['fingerprint'] not in set(entry.get('fps') or []):
        return False
    if flt.get('severity') and str(entry.get('severity') or '').lower() not in flt['severity']:
        return False
    if flt.get('cve') and not any(flt['cve'].upper() in cves_of(f) for f in joined):
        return False
    if flt.get('text'):
        needle = flt['text'].lower()
        hay = ' '.join([str(hit.get('key') or ''), str(hit.get('ref') or '')] +
                       [' '.join(str(f.get(k) or '') for k in ('rule_id', 'canonical_path', 'scanner', 'cwe'))
                        for f in joined]).lower()
        if needle not in hay:
            return False
    if 'kev' in flt:
        ks = [kev_of(f, catalog) for f in joined if cves_of(f)]
        if not ks:
            return False if flt['kev'] else True
        if KEV_UNAVAILABLE in ks:
            return None
        return any(ks) == flt['kev']
    return True


def _tickets_write(rt, backend, ledger, routing, central, repo_reg, req, p, env, client, out_dir, notes):
    run, recs, _cov, ref = evidence(client, env, p['source']['run_id'])
    if ref:
        return answer(ka.API_REFUSED, refusal=ref)
    sel = p.get('select') or {}
    want_i, want_k, want_f = (set(sel.get('identities') or []), set(sel.get('cluster_keys') or []),
                              set(sel.get('fingerprints') or []))
    chosen = [f for f in recs if f.get('identity') in want_i or f.get('cluster_key') in want_k
              or f.get('fp') in want_f]
    missing = sorted((want_i - set(f.get('identity') for f in recs)) |
                     (want_k - set(f.get('cluster_key') for f in recs)) |
                     (want_f - set(f.get('fp') for f in recs)))
    if missing:
        return answer(ka.API_REFUSED, refusal=ka.refusal(
            ka.API_FINDING_NOT_KIT_ESTABLISHED, 'run %s established no finding named %s; the API tickets only '
            'what the kit\'s own scan found' % (run.get('id'), ', '.join(m[:16] for m in missing[:5])),
            'params.select'))
    repo = _repo(env)
    numbers, n_note = rt.numbers_from_registrations(central, repo_reg)
    clusters, withheld = rt.build_clusters(chosen)
    dry = bool(req.get('dry_run'))
    # NO COVERAGE: a write of SOME findings is not a run of ALL of them, so nothing may be read as
    # cleared from what was not selected -- with coverage None the reconciler closes nothing.
    context = {'coverage': None, 'numbers': numbers, 'run_url': run.get('html_url') or _run_url(env, run.get('id')),
               'commit': run.get('head_sha') or '', 'routing': routing, 'repository': repo,
               'exceptions': rt.exceptions_from_registrations(central, repo_reg)}
    result = rt.reconcile(clusters, withheld, backend, ledger, not dry, approval=None, today=_today(env),
                          context=context)
    if not dry:
        _save(out_dir, 'ticket-ledger-proposal.json', {'schema': 1, 'clusters': ledger})
    keys = dict((k, (e or {}).get('key')) for k, e in ledger.items() if isinstance(e, dict))
    created = [{'cluster_key': c['cluster_key'], 'ref': c.get('ref'), 'key': keys.get(c['cluster_key']) or '',
                'title': c.get('title') or '', 'trigger': c.get('trigger') or '', 'planned': bool(c.get('planned'))}
               for c in result.get('created') or []]
    claim = (result.get('ticketing_claim') or {}).get('routing_result') or ''
    data = {'backend': backend.name, 'dry_run': dry, 'ticketing_state': result.get('ticketing_state'),
            'source_run': {'id': run.get('id'), 'commit': run.get('head_sha'), 'url': run.get('html_url') or ''},
            'selected': len(chosen), 'outcomes': result.get('outcomes') or {}, 'created': created,
            'updated': result.get('updated') or [], 'reopened': result.get('reopened') or [],
            'successors': result.get('successors') or [], 'merged': result.get('merged') or [],
            'escalations': result.get('escalations') or [], 'needs_decision': result.get('needs_decision') or [],
            'withheld_no_identity': result.get('withheld_no_identity') or [],
            'obligations': result.get('obligations') or [],
            'closed': [c for c in result.get('cleared') or [] if c.get('closed')],
            'calls': result.get('calls')}
    notes = notes + ['SLA: %s' % n_note,
                     'one ticket per finding: the pipeline\'s reconciliation finds these by their stamp',
                     'nothing was closed: closure is the reconciler\'s, on verified clearance, in a full run']
    state = ka.API_FAILED if claim == 'EVIDENCE_UNTRUSTED' else ka.API_COMPLETED
    if state == ka.API_FAILED:
        notes += list((result.get('ticketing_claim') or {}).get('causes') or [])[:5]
    return answer(state, data, notes, claim)


# ═════════════════════════════════════════════════════════════════════════════════════
# TICKETS FROM A FINALIZED REVIEW, THROUGH TEMPLATES (KDEC-037)
# ═════════════════════════════════════════════════════════════════════════════════════
#
# tickets.submit is carried out by scripts/ticket_submit.py: the review gate and separation of duties,
# dedupe against every ticket (manual ones included), the writes, the outbox. This builds its context
# from the environment the workflow hands over -- data, never code -- and drains an earlier outbox first.

def template_settings(env):
    """The owner's numbers (KDEC-037, answered 2026-11-04), as the workflow hands them over; '' is the default."""
    return {'extension_default_days': _e(env, 'KIT_API_EXTENSION_DEFAULT_DAYS'),
            'extension_max': _e(env, 'KIT_API_EXTENSION_MAX'),
            'extension_ceiling_days': _e(env, 'KIT_API_EXTENSION_CEILING_DAYS'),
            'vendor_advisory_extensions': _e(env, 'KIT_API_VENDOR_ADVISORY_EXTENSIONS'),
            'vendor_advisory_days': _e(env, 'KIT_API_VENDOR_ADVISORY_DAYS'),
            'nofix_exemption_days': _e(env, 'KIT_API_NOFIX_EXEMPTION_DAYS'),
            'nofix_exemption_ceiling_days': _e(env, 'KIT_API_NOFIX_EXEMPTION_CEILING_DAYS'),
            'nofix_recheck_days': _e(env, 'KIT_API_NOFIX_RECHECK_DAYS'),
            'nofix_review_days': _e(env, 'KIT_API_NOFIX_REVIEW_DAYS'),
            'exception_max_days': _e(env, 'KIT_API_EXCEPTION_MAX_DAYS'),
            'review_max_age_days': _e(env, 'KIT_API_REVIEW_MAX_AGE_DAYS'),
            'verification_reminder_days': _e(env, 'KIT_API_VERIFICATION_REMINDER_DAYS'),
            'fuzzy_title_percent': _e(env, 'KIT_API_FUZZY_TITLE_PERCENT')}


def _tickets_submit(rt, backend, ledger, routing, central, repo_reg, req, p, env, client, out_dir, notes, intake_doc):
    import ticket_submit as tsub
    import ticket_templates as tt
    settings, sprob = tt.settings_from(template_settings(env))
    if settings is None:
        return answer(ka.API_FAILED, {'ticketing_state': rt.TICKETING_NOT_CONFIGURED}, notes + [sprob])
    team_client = client
    team_token = _e(env, 'KIT_API_TEAM_READ_TOKEN')
    if team_token and client is not None:
        # A token that can read the organisation's members, sent only to the same API host (KDEC-027).
        team_client = ka.Client(client.api_url, token=team_token)
    numbers, _n = rt.numbers_from_registrations(central, repo_reg)
    ctx = {'rt': rt, 'backend': backend, 'ledger': ledger, 'routing': routing, 'central': central,
           'repo_reg': repo_reg, 'client': client, 'team_client': team_client, 'repo': _repo(env),
           'default_branch': _e(env, 'KIT_API_DEFAULT_BRANCH'), 'actor': intake_doc.get('actor') or {},
           'correlation_id': intake_doc.get('correlation_id') or '', 'out_dir': out_dir, 'today': _today(env),
           'now': ka.iso(), 'run_url': _run_url(env), 'commit': _e(env, 'GITHUB_SHA'), 'settings': settings,
           'numbers': numbers, 'reviews_dir': _e(env, 'KIT_API_REVIEWS_DIR'),
           'approver_source': _e(env, 'KIT_API_REVIEW_APPROVER_SOURCE') or (
               ('list:%s' % _e(env, 'KIT_API_REVIEW_APPROVER_LIST')) if _e(env, 'KIT_API_REVIEW_APPROVER_LIST')
               else tt.DEFAULT_APPROVER_SOURCE),
           'branch_map': _e(env, 'KIT_API_BRANCH_ENVIRONMENTS'),
           'approved_tools': _csv(_e(env, 'KIT_API_APPROVED_TOOLS')),
           'evidence_stores': _csv(_e(env, 'KIT_API_EVIDENCE_STORES')),
           # KDEC-043 rule 2: which identity each `via` integration name is registered as (name=identity,...).
           'integrations': __import__('ticket_governance').integrations_from(_e(env, 'KIT_INTEGRATION_IDENTITIES')),
           'evidence': lambda run_id, any_branch=False: evidence(client, env, run_id, any_branch)}
    dry = bool(req.get('dry_run'))
    drained = []
    if not dry and backend is not None:
        # AN EARLIER RUN'S OUTBOX IS RETRIED FIRST: nothing it held is lost while the tracker was away.
        inner = dict(ctx, out_dir='', correlation_id=ctx['correlation_id'] + '-drain')
        drained = tsub.drain_outbox(ctx, client, ctx['repo'],
                                    lambda params: tsub.submit(inner, params, False))
    state, data, extra, claim, ref = tsub.submit(ctx, p, dry)
    if drained:
        data['outbox_drained'] = drained
    for a in data.get('alerts') or []:
        print('::error title=kit-api tickets::%s' % a)
    return answer(state, data, notes + extra, claim if claim in ROUTING_WORDS else '', refusal=ref)


def _tickets_intake(rt, backend, ledger, routing, p, env, client, notes):
    """tickets.search with tracker_query: one page of EVERY ticket in this repository's projects."""
    import ticket_intake as ti
    q = p['tracker_query']
    repo = _repo(env)
    if hasattr(backend, 'set_routing'):
        backend.set_routing(routing, repo, sorted(set(str(e.get('project')) for e in (ledger or {}).values()
                                                      if isinstance(e, dict) and e.get('project'))))
    adapter = ti.adapter_for(backend, q.get('adapter') or '')
    page = adapter.search(projects=q.get('projects'), labels=q.get('labels'), jql=q.get('jql'),
                          page_token=q.get('page_token'), max_results=q.get('max_results') or 50)
    data = {'backend': backend.name, 'adapter': adapter.name, 'intake_state': page['state'],
            'projects': list(getattr(adapter, 'allowed_projects', []) or [])}
    if page['state'] == ti.TRACKER_QUERY_REFUSED:
        return answer(ka.API_REFUSED, data, notes, refusal=ka.refusal(ka.API_TRACKER_QUERY_REFUSED, page['detail'],
                                                                      'params.tracker_query'))
    if page['state'] != ti.TRACKER_INTAKE_COMPLETE:
        return answer(ka.API_FAILED, data, notes + [page['detail'] + ' -- not read is never "no tickets"'])
    keys = None
    if p.get('findings_run_id'):
        run, recs, _c, ref = evidence(client, env, p['findings_run_id'])
        if ref:
            return answer(ka.API_REFUSED, data, notes, refusal=ref)
        keys = set(f.get('cluster_key') for f in recs if f.get('cluster_key'))
        data['findings_run'] = {'id': run.get('id'), 'commit': run.get('head_sha')}
    import ticket_governance as tg
    prefix = '%s-ck-' % (getattr(backend, 'stamp_label', '') or rt.DEFAULT_STAMP_LABEL)
    out = []
    for t in page['tickets']:
        # KDEC-043: a LINKED key is a full key in a governed place (the stamp field, a stamp or link line in the
        # body). A label is a search aid: shown as a hint, never as a link -- on GitHub it may be a short form.
        cks = tg.ticket_keys(t)
        hints = set(x[len(prefix):] for x in t.get('labels') or [] if str(x).startswith(prefix)) - cks
        shaped = ti.public(t)
        shaped['linked_cluster_keys'] = sorted(cks & keys if keys is not None else cks)
        shaped['label_key_hints'] = sorted(hints)
        shaped['manual'] = not t.get('stamp')
        out.append(shaped)
    data.update(tickets=out, count=len(out), next_page_token=page['next_page_token'])
    return answer(ka.API_COMPLETED, data, notes + [page['detail']], 'PROCEED')


# ═════════════════════════════════════════════════════════════════════════════════════
# FINISH: the result, three ways
# ═════════════════════════════════════════════════════════════════════════════════════

def _scan_outcome(env):
    job = _e(env, 'KIT_API_JOB_RESULT')
    route = _e(env, 'KIT_API_ROUTING_RESULT')
    data = {'job_result': job, 'routing_result': route, 'assurance_state': _e(env, 'KIT_API_ASSURANCE_STATE'),
            'advisory_causes': _csv(env.get('KIT_API_ADVISORY_CAUSES')),
            'evidence_artifact': _e(env, 'KIT_API_EVIDENCE_ARTIFACT'), 'run_id': _e(env, 'GITHUB_RUN_ID')}
    if route in ROUTING_WORDS:
        return answer(ka.API_COMPLETED, data, ['the scan\'s verdict is the kit\'s own: read routing_result; '
                                                  'findings.search with run_id %s reads what it found'
                                                  % data['run_id']], route)
    why = ('the scan did not run (%s)' % (job or 'no job result') if job in ('skipped', 'cancelled', '')
           else 'the scan reported no registered verdict (%r)' % route[:40])
    return answer(ka.API_FAILED, data, [why + '; nothing here is a clean result'])


def _deploy_outcome(env, client, intake_doc):
    job = _e(env, 'KIT_API_JOB_RESULT')
    data = {'job_result': job, 'environment': (intake_doc.get('deploy') or {}).get('environment', ''),
            'mode': (intake_doc.get('deploy') or {}).get('mode', ''), 'deployment_outcome': NOT_REPORTED}
    repo, rid = _repo(env), _e(env, 'GITHUB_RUN_ID')
    notes = []
    _s, doc, _h, err = client.get('/repos/%s/actions/runs/%s/artifacts?per_page=100' % (repo, rid))
    arts = [a for a in (doc or {}).get('artifacts') or []] if isinstance(doc, dict) else []
    ev = [a for a in arts if str(a.get('name') or '').startswith('deploy-evidence-') and not a.get('expired')]
    if ev:
        blob = client.download('/repos/%s/actions/artifacts/%s/zip' % (repo, ev[-1]['id']))
        try:
            z = zipfile.ZipFile(io.BytesIO(blob or b''))
            name = [n for n in z.namelist() if n.rsplit('/', 1)[-1] == 'outcome.json']
            out = json.loads(z.read(name[0]).decode('utf-8')) if name else {}
        except (zipfile.BadZipFile, ValueError, KeyError, IndexError):
            out = {}
        if isinstance(out, dict) and out.get('deployment_outcome'):
            data['deployment_outcome'] = str(out['deployment_outcome'])[:60]
            data['now_serving'] = out.get('now_serving')
            data['gate'] = out.get('gate') if isinstance(out.get('gate'), dict) else None
    rec = [a for a in arts if str(a.get('name') or '').startswith('kit-promotion-record-')]
    if rec:
        data['promotion_record'] = rec[-1]['name']
    if job == 'success' and data['deployment_outcome'] != NOT_REPORTED:
        return answer(ka.API_COMPLETED, data, ['the release ran through the repository\'s own pipeline and '
                                                  'its gates; deployment_outcome is the deploy\'s own word'])
    if job == 'success':
        notes.append('the release job succeeded and reported NO outcome (no deploy-evidence outcome.json in '
                     'this run): nothing here says a release was deployed')
    else:
        notes.append('the release job ended %s: read the run for the gate that refused it (approval, '
                     'readiness, release block, promotion)' % (job or 'without a result'))
    return answer(ka.API_FAILED, data, notes)


_CONCLUSION = {ka.API_COMPLETED: 'success'}


def _check_run(client, env, intake_doc, status, result):
    """Create or update the call's check run. -> its id ('' when GitHub refused: the artifact and the
    summary still carry the result, and the run says so)."""
    repo = _repo(env)
    cid = intake_doc.get('correlation_id') or ''
    if not cid or client is None:
        return ''
    body = {'name': ka.check_run_name(cid), 'head_sha': _e(env, 'GITHUB_SHA'), 'status': status,
            'external_id': cid}
    if result is None:
        body['output'] = {'title': '%s: accepted' % (intake_doc.get('operation') or 'call'),
                          'summary': 'Accepted; running. Read the result when this check completes.',
                          'text': json.dumps(ka.result_doc(cid, intake_doc.get('operation'), ka.API_IN_PROGRESS,
                                                           transport=intake_doc.get('transport', ''),
                                                           repository=repo), sort_keys=True)}
    else:
        body['conclusion'] = _CONCLUSION.get(result['api_state'], 'neutral')
        body['output'] = {'title': '%s: %s' % (result.get('operation') or 'call', result['api_state']),
                          'summary': _summary_md(result)[:60000],
                          'text': json.dumps(result, sort_keys=True)}
    cr_id = str(intake_doc.get('check_run_id') or _e(env, 'KIT_API_CHECK_RUN_ID') or '')
    if cr_id and result is not None:
        _s, doc, _h, err = client.request('PATCH', '/repos/%s/check-runs/%s' % (repo, cr_id),
                                          dict((k, v) for k, v in body.items() if k != 'head_sha'))
        if err is None:
            return cr_id
    _s, doc, _h, err = client.request('POST', '/repos/%s/check-runs' % repo, body)
    if err or not isinstance(doc, dict):
        return ''
    return str(doc.get('id') or '')


def _summary_md(result):
    L = ['## Kit API: `%s` -- %s' % (result.get('operation') or '?', result['api_state']), '',
         '| field | value |', '|---|---|',
         '| correlation id | `%s` |' % result.get('correlation_id'),
         '| refusal | %s |' % ((result.get('refusal') or {}).get('code') or 'none'),
         '| routing_result | %s |' % (result.get('routing_result') or '--'),
         '| requested by | %s |' % ((result.get('actor') or {}).get('actor') or '--'),
         '| on behalf of (declared, not verified) | %s |' % ((result.get('actor') or {}).get('on_behalf_of') or '--')]
    if result.get('refusal'):
        L += ['', '> %s' % result['refusal'].get('detail', '')]
    for n in result.get('notes') or []:
        L += ['', '> %s' % n]
    return '\n'.join(L)


def _fit(result):
    """Keep the JSON under the check run's limit: trim the longest list in data, say so."""
    text = json.dumps(result, sort_keys=True)
    if len(text) <= ka.RESULT_TEXT_MAX:
        return result
    data = result.get('data') or {}
    for key in ('findings', 'tickets', 'created', 'updated', 'obligations', 'withheld_no_identity'):
        lst = data.get(key)
        while isinstance(lst, list) and lst and len(json.dumps(result, sort_keys=True)) > ka.RESULT_TEXT_MAX:
            lst.pop()
            result['truncated'] = True
    if result.get('truncated'):
        result['notes'] = list(result.get('notes') or []) + [
            'the answer was cut to fit the check run (%d characters); the artifact kit-api-result-%s holds the '
            'whole of it, and a search pages with offset' % (ka.RESULT_TEXT_MAX, result.get('correlation_id'))]
    return result


def finish(intake_doc, env, client, out_dir, op_result=None, schemas=None):
    """-> the result, written as result.json (the artifact step uploads it), the run summary and the
    call's check run."""
    schemas = schemas or ka.load_schemas()
    op = intake_doc.get('operation') or ''
    if not intake_doc.get('accepted'):
        res = answer(ka.API_REFUSED, intake_doc.get('refused_data'), refusal=intake_doc.get('refusal') or ka.refusal(
            ka.API_REQUEST_UNPARSEABLE, 'intake did not record its answer'))
    elif op_result is not None:
        res = op_result
    elif op == 'scan.request':
        res = _scan_outcome(env)
    elif op == 'deploy.request':
        res = _deploy_outcome(env, client, intake_doc)
    else:
        res = answer(ka.API_FAILED, notes=['the %s job left no answer' % (op or 'operation')])
    rid = _e(env, 'GITHUB_RUN_ID')
    result = ka.result_doc(intake_doc.get('correlation_id') or '', op, res['api_state'], res.get('refusal'),
                           res.get('data'), list(intake_doc.get('notes') or []) + list(res.get('notes') or []),
                           routing_result=res.get('routing_result') or '',
                           repository=_repo(env), transport=intake_doc.get('transport') or '',
                           run={'id': int(rid) if rid.isdigit() else rid,
                                'attempt': int(_e(env, 'GITHUB_RUN_ATTEMPT', '1') or 1),
                                'url': _run_url(env)},
                           actor=dict(intake_doc.get('actor') or {}, on_behalf_of_verified=False),
                           idempotency_key_sha256=intake_doc.get('idempotency_key_sha256') or '',
                           request_sha256=intake_doc.get('request_sha256') or '',
                           received_at=intake_doc.get('received_at') or '', finished_at=ka.iso(),
                           truncated=False, next_offset=res.get('next_offset'))
    if result['routing_result'] not in ('',) + ROUTING_WORDS:
        result['routing_result'] = ''
    result = _fit(result)
    errs = ka.validate(result, schemas['result'])
    if errs:
        # A result the contract would not accept is not sent as one: the run says what broke.
        result = ka.result_doc(intake_doc.get('correlation_id') or '', op[:40], ka.API_FAILED, None, {},
                               ['the run could not shape a valid result: %s %s' % errs[0]],
                               repository=_repo(env), transport=intake_doc.get('transport') or '')
    _save(out_dir, 'result.json', result)
    summary(env, _summary_md(result))
    cr = _check_run(client, env, intake_doc, 'completed', result)
    if not cr:
        summary(env, '\n> The check run could not be written; the result is in the artifact '
                     'kit-api-result-%s and this summary.' % result['correlation_id'])
    emit(env, api_state=result['api_state'], refusal=(result.get('refusal') or {}).get('code', ''))
    return result


# ═════════════════════════════════════════════════════════════════════════════════════

def main(argv=None):
    ap = argparse.ArgumentParser(description='The run side of the kit\'s API (KDEC-035).')
    ap.add_argument('phase', choices=('intake', 'tickets', 'findings', 'finish'))
    ap.add_argument('--out-dir', required=True)
    a = ap.parse_args(argv)
    env = os.environ
    client, ref = ka.client_from_env({'GITHUB_API_URL': env.get('GITHUB_API_URL', ''),
                                      'GITHUB_TOKEN': env.get('GITHUB_TOKEN', '')})
    if a.phase == 'intake':
        doc = intake(env, client, a.out_dir) if client is not None else _deny(
            {'accepted': False, 'operation': '', 'correlation_id': _e(env, 'KIT_API_CORRELATION_ID'),
             'deploy': {}, 'write': False, 'idem_hash': '', 'check_run_id': '', 'notes': []},
            ref['code'], ref['detail'])
        if client is None:
            _save(a.out_dir, 'intake.json', doc)
            emit(env, accepted='false', refusal=ref['code'], intake=json.dumps(doc, sort_keys=True,
                                                                                separators=(',', ':')))
        return 0
    try:
        intake_doc = json.loads(env.get('KIT_API_INTAKE') or '{}')
    except ValueError:
        intake_doc = {}
    if a.phase in ('tickets', 'findings'):
        if not intake_doc.get('accepted'):
            print('the intake did not accept this call; nothing to do', file=sys.stderr)
            return 0
        fn = tickets if a.phase == 'tickets' else findings
        try:
            res = fn(intake_doc, env, client, a.out_dir)
        except Exception as exc:  # noqa: BLE001 -- reported as the call's failure, never swallowed
            res = answer(ka.API_FAILED, notes=['the %s phase failed: %s: %s' % (a.phase, type(exc).__name__,
                                                                                  str(exc)[:300])])
        _save(a.out_dir, 'op-result.json', res)
        return 0
    res = None
    path = _e(env, 'KIT_API_OP_RESULT')
    if path and os.path.isfile(path):
        try:
            res = json.load(io.open(path, encoding='utf-8'))
        except ValueError:
            res = answer(ka.API_FAILED, notes=['the operation\'s answer could not be read'])
    elif ka.OPERATIONS.get(intake_doc.get('operation') or '', {}).get('job') in ('tickets', 'findings') \
            and intake_doc.get('accepted'):
        res = answer(ka.API_FAILED, notes=['the operation job left no answer (it did not run, or it '
                                              'failed before writing one)'])
    finish(intake_doc, env, client, a.out_dir, res)
    return 0


if __name__ == '__main__':
    sys.exit(main())

"""Run a deploy job's steps in order, locally, against stubbed Azure. Not a test; imported by them.

WHY A RUNNER AND NOT ONE STEP AT A TIME

    Most of the deploy contract is about ORDER and CONDITIONS: capture before mutate, provenance
    after health, a report that runs on every path, a reversal that fires only when it is owed.
    Running one extracted step proves what that step does; it cannot prove that the step runs at
    all on the path that needs it -- and "a conditional step whose condition excludes the case it
    exists to handle" is DCR gap 1's whole defect class. So this executes the job as shipped:
    every step in file order, each `if:` evaluated, `continue-on-error` honoured, `uses:` steps
    treated as succeeding no-ops (azure/login, upload-artifact), and `run:` bodies executed by
    the proven Git Bash probe with the step's resolved `env:`.

WHAT IT DOES NOT MODEL
    The Actions expression language beyond what the deploy workflows use. Anything outside the
    supported grammar raises, so an unmodelled condition is UNKNOWN rather than silently true.
    Cancellation is modelled only as "the run was cancelled after step N": later steps run only
    when their condition admits cancellation (always(), cancelled()).
"""
import io
import os
import re
import shutil
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import _deploy_steps as D  # noqa: E402

TOKEN = re.compile(r"\s*(?:(\|\||&&|==|!=|!|\(|\))|('(?:[^']|'')*')|([A-Za-z_][A-Za-z0-9_.\-]*\(\))"
                   r"|([A-Za-z_][A-Za-z0-9_.\-]*))")


class Unmodelled(Exception):
    pass


def evaluate(expr, ctx):
    """Evaluate the subset of the GitHub expression language the deploy workflows use."""
    expr = expr.strip()
    if expr.startswith('${{') and expr.endswith('}}'):
        expr = expr[3:-2].strip()
    toks, pos = [], 0
    while pos < len(expr):
        m = TOKEN.match(expr, pos)
        if not m or m.end() == pos:
            raise Unmodelled('cannot tokenise %r at %d' % (expr, pos))
        pos = m.end()
        op, lit, fn, ident = m.groups()
        toks.append(('op', op) if op else ('lit', lit[1:-1].replace("''", "'")) if lit
                    else ('fn', fn) if fn else ('id', ident))
    out = []
    for kind, val in toks:
        if kind == 'op':
            out.append({'||': ' or ', '&&': ' and ', '==': ' == ', '!=': ' != ',
                        '!': ' not ', '(': '(', ')': ')'}[val])
        elif kind == 'lit':
            out.append(repr(val))
        elif kind == 'fn':
            if val not in ('always()', 'success()', 'failure()', 'cancelled()'):
                raise Unmodelled('function %s' % val)
            out.append(repr(ctx['fn'][val]))
        else:
            if val in ('true', 'false'):
                out.append(repr(val == 'true'))
            else:
                out.append(repr(lookup(val, ctx)))
    src = ''.join(out)
    # Equality in Actions is case-insensitive for strings and coerces booleans; model the two
    # coercions the deploy files rely on: 'true'/'false' strings compare with booleans.
    return truthy(eval(src, {'__builtins__': {}}, {}))  # noqa: S307 (built from our own tokens)


def lookup(path, ctx):
    parts = path.split('.')
    if parts[0] == 'inputs':
        v = ctx['inputs'].get(parts[1], '')
    elif parts[0] == 'steps' and len(parts) >= 3:
        st = ctx['steps'].get(parts[1])
        if st is None:
            v = ''
        elif parts[2] == 'outputs':
            v = st['outputs'].get(parts[3], '') if len(parts) > 3 else ''
        else:
            v = st.get(parts[2], '')
    elif parts[0] == 'env' and len(parts) == 2:
        # The env context a step's `if:` sees: the job's env (resolved) with the harness's
        # extra_env over it. KDEC-030's opt-in lease steps read env.KIT_TARGET_LEASE_ACCOUNT.
        v = ctx.get('env', {}).get(parts[1], '')
    elif parts == ['job', 'status']:
        # job.status as GitHub reports it to a step: cancelled > failure > success.
        v = ctx.get('job_status', 'success')
    else:
        raise Unmodelled('context %s' % path)
    return v


def truthy(v):
    if isinstance(v, str):
        return v not in ('', 'false', '0')
    return bool(v)


def stringify(v):
    if isinstance(v, bool):
        return 'true' if v else 'false'
    return '' if v is None else str(v)


def run_job(path, inputs, path_prepend=None, extra_env=None, cancel_after=None, workdir=None,
            uses_outputs=None):
    """-> dict(steps={id_or_name: {...}}, order=[...], log=str, summary=str, rc=job result).
    `uses_outputs`: {step id: {output: value}} answered by a `uses:` step (a composite this harness
    does not run, e.g. the known-exploited check): recorded stand-ins; absent, a `uses:` step has
    no outputs, which every consumer reads as not established."""
    doc = D.load(path)
    bash, why = D.bash()
    if not bash:
        raise RuntimeError('no usable bash: %s' % why)
    runner_temp = workdir or tempfile.mkdtemp(prefix='runner-temp-')
    summary_path = os.path.join(runner_temp, 'job_summary.md')
    io.open(summary_path, 'w').close()
    ctx = {'inputs': {k: stringify(v) for k, v in inputs.items()}, 'steps': {}, 'fn': {}}
    values = {'inputs.%s' % k: stringify(v) for k, v in inputs.items()}
    job_failed, cancelled, logs, order = False, False, [], []
    if 'GITHUB_API_URL' not in (extra_env or {}):
        # A job always runs with a repository and an API. A harness that names none gets a recorded
        # one with no artifacts -- no rollback marker for the target (KDEC-023) -- rather than an
        # unreadable answer the deploy's rollback check would (rightly) refuse on.
        api_root = os.path.join(runner_temp, '_github_api')
        write_default_api(api_root)
        extra_env = dict({'GITHUB_REPOSITORY': 'o/r',
                          'GITHUB_API_URL': 'file:///' + api_root.replace('\\', '/').lstrip('/')},
                         **(extra_env or {}))
    try:
        for i, step in enumerate(D.steps(doc)):
            name = step.get('name') or step.get('uses') or '#%d' % i
            sid = step.get('id') or name
            ctx['fn'] = {'always()': True, 'success()': not job_failed and not cancelled,
                         'failure()': job_failed, 'cancelled()': cancelled}
            ctx['job_status'] = 'cancelled' if cancelled else ('failure' if job_failed else 'success')
            cond = step.get('if')
            if cond is not None and 'env.' in str(cond):
                for sname, st in ctx['steps'].items():
                    for k, v in st['outputs'].items():
                        values['steps.%s.outputs.%s' % (sname, k)] = v
                    values['steps.%s.outcome' % sname] = st['outcome']
                job_env = {k: expr_value(v, ctx, values) for k, v in (D.job(doc).get('env') or {}).items()}
                job_env.update(extra_env or {})
                ctx['env'] = job_env
            if cond is None:
                run_it = not job_failed and not cancelled
            else:
                run_it = evaluate(str(cond), ctx)
                if cancelled and 'always()' not in str(cond) and 'cancelled()' not in str(cond):
                    run_it = False
            if not run_it:
                ctx['steps'][sid] = {'outcome': 'skipped', 'conclusion': 'skipped', 'outputs': {}}
                order.append((name, 'skipped'))
                continue
            if 'run' not in step:
                ctx['steps'][sid] = {'outcome': 'success', 'conclusion': 'success',
                                     'outputs': dict((uses_outputs or {}).get(sid) or {})}
                order.append((name, 'success'))
                continue
            for sname, st in ctx['steps'].items():
                for k, v in st['outputs'].items():
                    values['steps.%s.outputs.%s' % (sname, k)] = v
                values['steps.%s.outcome' % sname] = st['outcome']
            env = {}
            for k, v in (D.job(doc).get('env') or {}).items():
                env[k] = expr_value(v, ctx, values)
            for k, v in (step.get('env') or {}).items():
                env[k] = expr_value(v, ctx, values)
            env['RUNNER_TEMP'] = runner_temp
            env.update(extra_env or {})
            rc, outputs, log, summ = D.run_script(bash, step['run'], env, cwd=runner_temp,
                                                  path_prepend=path_prepend)
            io.open(summary_path, 'a', encoding='utf-8').write(summ)
            logs.append('--- %s (exit %d)\n%s' % (name, rc, log))
            outcome = 'success' if rc == 0 else 'failure'
            conclusion = 'success' if (rc == 0 or step.get('continue-on-error') is True) else 'failure'
            ctx['steps'][sid] = {'outcome': outcome, 'conclusion': conclusion, 'outputs': outputs}
            order.append((name, outcome))
            if conclusion == 'failure':
                job_failed = True
            if cancel_after and name == cancel_after:
                cancelled = True
        return {'steps': ctx['steps'], 'order': order, 'log': '\n'.join(logs),
                'summary': io.open(summary_path, encoding='utf-8', errors='replace').read(),
                'failed': job_failed, 'runner_temp': runner_temp}
    finally:
        if not workdir:
            shutil.rmtree(runner_temp, ignore_errors=True)


def expr_value(v, ctx, values):
    """An env value: a whole-expression is evaluated (booleans included); else substituted."""
    if isinstance(v, str):
        m = re.fullmatch(r'\s*\$\{\{\s*(.*?)\s*\}\}\s*', v)
        if m and re.search(r'&&|\|\||==|!=|\(\)', m.group(1)):
            return stringify(evaluate(m.group(1), ctx))
    return D.resolve(v, values)


def stub_bin(fake_state_path, log_path):
    """Create a directory holding `az` and `curl` stand-ins for the fake cloud. -> its path.

    Both a bash form and a .cmd form are written. The .cmd form matters on Windows: Python's
    subprocess resolves `az` through PATHEXT and would otherwise find the REAL Azure CLI's
    az.cmd further down PATH. The harness refuses to run unless the stand-in is what resolves.
    """
    d = tempfile.mkdtemp(prefix='fake-cloud-bin-')
    py = sys.executable
    fake = os.path.join(HERE, '_fake_az.py')
    for tool in ('az', 'curl'):
        io.open(os.path.join(d, tool), 'w', encoding='utf-8', newline='\n').write(
            '#!/bin/bash\nexec "%s" "%s" %s "$@"\n' % (py.replace('\\', '/'),
                                                       fake.replace('\\', '/'), tool))
        os.chmod(os.path.join(d, tool), 0o755)
        io.open(os.path.join(d, tool + '.cmd'), 'w', encoding='utf-8', newline='\r\n').write(
            '@echo off\r\n"%s" "%s" %s %%*\r\n' % (py, fake, tool))
    # python3 resolves to THIS interpreter, so the steps run what the harness runs.
    io.open(os.path.join(d, 'python3'), 'w', encoding='utf-8', newline='\n').write(
        '#!/bin/bash\nexec "%s" "$@"\n' % py.replace('\\', '/'))
    os.chmod(os.path.join(d, 'python3'), 0o755)
    resolved = shutil.which('az', path=d + os.pathsep + os.environ.get('PATH', ''))
    if not resolved or os.path.dirname(os.path.abspath(resolved)) != os.path.abspath(d):
        shutil.rmtree(d, ignore_errors=True)
        raise RuntimeError('the az stand-in does not resolve first (%r); refusing to run '
                           'anything that could reach a real cloud' % resolved)
    return d


def break_glass(inputs):
    """KDEC-029 (owner, 2026-10-26): uat and prod are PROMOTED from a predecessor's verified record;
    a deploy there that names none is refused PROMOTION_REFUSED_NO_PREDECESSOR before login, unless
    it is break-glass under an attributed, time-limited exception. Proofs written before KDEC-029
    that exercise a production-tier deploy's OTHER controls take this path, so they keep proving
    those controls; tests/prove_promotion.py proves the promotion path itself."""
    import datetime
    exp = (datetime.date.today() + datetime.timedelta(days=3)).isoformat()
    out = dict(inputs)
    out['release_path'] = 'break-glass'
    out.setdefault('weakening_reason', 'proof of a production-tier control (KDEC-029 break-glass)')
    out.setdefault('weakening_authority', 'release-approvers')
    out.setdefault('weakening_exception_ref', 'EXC-PROOF-1')
    out.setdefault('weakening_expires', exp)
    return out


PROMOTION_SIGNER = 'o/secure-cicd-kit/.github/workflows/reusable-build-docker.yml'
_GH_VERIFIED = r'''
import json, sys
ref = [x for x in sys.argv[1:] if x.startswith('oci://')]
d = ref[0].rsplit('@sha256:', 1)[1] if ref else ''
print(json.dumps([{'verificationResult': {'statement': {'subject': [{'name': 'x', 'digest': {'sha256': d}}]}}}]))
'''
_TRIVY_CLEAN = r'''
import json, sys
a = sys.argv[1:]
if '--version' in a:
    print('Version: 0.71.2'); sys.exit(0)
out = a[a.index('--output') + 1]
doc = {'Results': []} if a[0] == 'sbom' else {'version': '2.1.0', 'runs': [{'tool': {'driver': {'name': 'Trivy'}}, 'results': []}]}
json.dump(doc, open(out, 'w'))
'''


def promoted(inputs, source_environment='test', source_run='90'):
    """KDEC-029: a uat/prod deploy is a PROMOTION of a record its predecessor verified. Proofs written
    before KDEC-029 that exercise a production-tier deploy's OTHER controls (the version-gap ruling)
    deploy as a clean promotion of the same digest: a verified test record, the build's SBOM, a
    verifying V1, a clean re-scan and KEV. -> (inputs, run_world keyword arguments).
    tests/prove_promotion.py proves the promotion gate itself."""
    import datetime
    import hashlib
    import json
    import zipfile
    digest = inputs.get('image_digest') or NEW
    sbom = b'{"spdxVersion": "SPDX-2.3", "packages": []}'
    at = (datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(hours=1)).strftime('%Y-%m-%dT%H:%M:%SZ')
    rec = {'schema': 'kit-promotion-record/1', 'record_id': '%s-1-%s' % (source_run, source_environment),
           'state': 'verified-for-promotion',
           'artifact': {'digest': digest, 'sbom_sha256': hashlib.sha256(sbom).hexdigest(),
                        'artifact_identity': 'REGISTRY_IDENTITY_PROVEN'},
           'environment': {'name': source_environment, 'tier': 'test'},
           'provenance': {'source_ref': 'refs/heads/main', 'build_workflow': PROMOTION_SIGNER,
                          'build_run_id': source_run},
           'conditions': {'established': [], 'missing': []}, 'validity': {'verified_at': at},
           'run': {'id': source_run}, 'approval': {'approvers': []}}

    def zipped(name, body):
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, 'w') as zf:
            zf.writestr(name, body)
        return buf.getvalue()
    arts = [{'id': 1, 'name': 'kit-promotion-record-%s' % source_environment, 'expired': False,
             'created_at': at, 'archive_download_url': '@API_ROOT@/zips/rec.zip',
             'workflow_run': {'id': int(source_run), 'head_branch': 'main'}},
            {'id': 2, 'name': 'sbom-' + digest.split(':', 1)[1], 'expired': False, 'created_at': at,
             'archive_download_url': '@API_ROOT@/zips/sbom.zip',
             'workflow_run': {'id': int(source_run), 'head_branch': 'main'}}]
    out = dict(inputs, promote_from_run_id=source_run, promote_from_environment=source_environment,
               promotion_predecessor=source_environment, attestation_signer_workflow=PROMOTION_SIGNER,
               attestations_available=True, artifact_identity='REGISTRY_IDENTITY_PROVEN')
    kw = {'api_files': {'repos/o/r/actions/artifacts': json.dumps({'total_count': 2, 'artifacts': arts})},
          'api_binary': {'zips/rec.zip': zipped('promotion-record.json', json.dumps(rec)),
                         'zips/sbom.zip': zipped('sbom.spdx.json', sbom)},
          'tools': {'gh': _GH_VERIFIED, 'trivy': _TRIVY_CLEAN},
          'uses_outputs': {'promotion_kev': {'kev_state': 'AVAILABLE', 'kev_verdict': 'CLEAR', 'kev_blocking': ''}},
          'env_extra': {'GITHUB_REF': 'refs/heads/main'}}
    return out, kw


GOOD = 'sha256:' + 'a' * 64
NEW = 'sha256:' + 'b' * 64
REG, REPO = 'registry.example', 'shop/web'


def ref(digest):
    return '%s/%s@%s' % (REG, REPO, digest)


def containerapp_state(mode='Multiple', empty=False, **faults):
    revs = {} if empty else {'web--r1': {'active': True, 'image': ref(GOOD), 'env': {},
                                         'createdTime': '2026-10-14T00:00:01Z',
                                         'fqdn': 'web--r1.revision.example'}}
    s = {'containerapp': {'name': 'web', 'id': '/subs/x/rg/rg-a/containerApps/web',
                          'revisionMode': mode, 'fqdn': 'web.app.example', 'tags': {},
                          'counter': 1, 'latestRevisionName': '' if empty else 'web--r1',
                          'traffic': [] if empty else [{'revisionName': 'web--r1', 'weight': 100}],
                          'revisions': revs}}
    s.update(faults)
    return s


def appservice_state(prior=GOOD, **faults):
    fx = ('DOCKER|' + ref(prior)) if prior else ''
    s = {'webapp': {'name': 'web', 'slots': {
        'production': {'id': '/subs/x/rg/rg-a/sites/web', 'host': 'web.site.example',
                       'linuxFxVersion': fx, 'tags': {}, 'appsettings': {}},
        'staging': {'id': '/subs/x/rg/rg-a/sites/web/slots/staging',
                    'host': 'web-staging.site.example', 'linuxFxVersion': fx, 'tags': {},
                    'appsettings': {}}}}}
    s.update(faults)
    return s


# What the fake GitHub API answers for the deploy's environment: required reviewers, self-review
# prevented -- a protected environment, so the deploy's protection step (owner, 2026-10-22) passes
# and each proof exercises what it is about. tests/prove_deploy_environment_protection.py proves the
# refusals; a caller here may pass its own answer, or None for an environment that cannot be read.
PROTECTED_ENVIRONMENT = {'protection_rules': [
    {'type': 'required_reviewers', 'prevent_self_review': True,
     'reviewers': [{'type': 'Team', 'reviewer': {'slug': 'release-approvers', 'name': 'Release approvers'}}]}]}


def add_tools(bin_dir, tools):
    """More stand-ins beside az and curl: {name: python source}. Each is reachable from bash (an
    extensionless wrapper) and from Python's subprocess on Windows (a .cmd wrapper), like az."""
    py = sys.executable
    for name, src in tools.items():
        script = os.path.join(bin_dir, '_tool_%s.py' % name)
        io.open(script, 'w', encoding='utf-8').write(src)
        io.open(os.path.join(bin_dir, name), 'w', encoding='utf-8', newline='\n').write(
            '#!/bin/bash\nexec "%s" "%s" "$@"\n' % (py.replace('\\', '/'), script.replace('\\', '/')))
        os.chmod(os.path.join(bin_dir, name), 0o755)
        io.open(os.path.join(bin_dir, name + '.cmd'), 'w', encoding='utf-8', newline='\r\n').write(
            '@echo off\r\n"%s" "%s" %%*\r\n' % (py, script))


def write_default_api(api_root):
    """The answers every deploy job reads from the GitHub API besides its environment: no artifact
    (so no rollback marker for the target, KDEC-023) and the commit it was built from."""
    import json
    repo = os.path.join(api_root, 'repos', 'o', 'r')
    os.makedirs(os.path.join(repo, 'actions'), exist_ok=True)
    listing = os.path.join(repo, 'actions', 'artifacts')
    if not os.path.exists(listing):
        io.open(listing, 'w', encoding='utf-8').write(json.dumps({'total_count': 0, 'artifacts': []}))


def run_world(path, inputs, state, cancel_after=None, environment_answer=PROTECTED_ENVIRONMENT,
              api_files=None, env_extra=None, tools=None, uses_outputs=None, api_binary=None):
    """Run the job against a fresh fake cloud. -> (result, final_state, az_calls). `api_files`:
    {path under the API root: body} answered by the recorded GitHub API (KDEC-023's rollback
    marker, commits, comparisons); `env_extra`: more job environment (the commit and the run id)."""
    import json
    work = tempfile.mkdtemp(prefix='fake-world-')
    try:
        api = os.path.join(work, 'api', 'repos', 'o', 'r', 'environments')
        os.makedirs(api)
        if environment_answer is not None and inputs.get('github_environment'):
            io.open(os.path.join(api, str(inputs['github_environment'])), 'w', encoding='utf-8').write(
                json.dumps(environment_answer))
        for rel, body in (api_files or {}).items():
            p = os.path.join(work, 'api', *rel.split('/'))
            if not os.path.isdir(os.path.dirname(p)):
                os.makedirs(os.path.dirname(p))
            # '@API_ROOT@' in a recorded answer is the file:// URL of this API (an artifact's
            # archive_download_url points into it).
            root_url = 'file:///' + os.path.join(work, 'api').replace('\\', '/').lstrip('/')
            io.open(p, 'w', encoding='utf-8').write(body.replace('@API_ROOT@', root_url))
        write_default_api(os.path.join(work, 'api'))
        state_path = os.path.join(work, 'state.json')
        log_path = os.path.join(work, 'calls.jsonl')
        io.open(state_path, 'w', encoding='utf-8').write(json.dumps(state))
        io.open(log_path, 'w').close()
        for rel, data in (api_binary or {}).items():
            p = os.path.join(work, 'api', *rel.split('/'))
            if not os.path.isdir(os.path.dirname(p)):
                os.makedirs(os.path.dirname(p))
            io.open(p, 'wb').write(data)
        bin_dir = stub_bin(state_path, log_path)
        add_tools(bin_dir, tools or {})
        try:
            # Git Bash rewrites environment values that look like POSIX paths ("/health") into
            # Windows paths when it starts a native program -- a harness artefact no Linux
            # runner has. Excluding every variable from that conversion keeps values byte-exact.
            env = {'MSYS2_ENV_CONV_EXCL': '*', 'MSYS_NO_PATHCONV': '1',
                   'fake_az_state': state_path, 'fake_az_log': log_path,
                   'AZURE_CONFIG_DIR': os.path.join(work, 'no-azure-config'),
                   'GITHUB_REPOSITORY': 'o/r',
                   'GITHUB_API_URL': 'file:///' + os.path.join(work, 'api').replace('\\', '/').lstrip('/')}
            env.update(env_extra or {})
            rt = os.path.join(work, 'runner-temp')
            os.makedirs(rt)
            env['FAKE_API_ROOT'] = os.path.join(work, 'api')
            res = run_job(path, inputs, path_prepend=bin_dir, extra_env=env, uses_outputs=uses_outputs,
                          cancel_after=cancel_after, workdir=rt)
            final = json.load(io.open(state_path, encoding='utf-8'))
            calls = [json.loads(l) for l in io.open(log_path, encoding='utf-8') if l.strip()]
            ev = os.path.join(rt, 'deploy-evidence')
            res['evidence'] = {}
            if os.path.isdir(ev):
                for f in os.listdir(ev):
                    try:
                        res['evidence'][f] = json.load(io.open(os.path.join(ev, f), encoding='utf-8'))
                    except ValueError:
                        res['evidence'][f] = io.open(os.path.join(ev, f), encoding='utf-8').read()
            return res, final, calls
        finally:
            shutil.rmtree(bin_dir, ignore_errors=True)
    finally:
        shutil.rmtree(work, ignore_errors=True)

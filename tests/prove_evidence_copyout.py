#!/usr/bin/env python3
"""Proof (KDEC-068): the kit's evidence copy-out sends only evidence, only where the contract allows, only
from a trusted run, and never with more than a read-only App token and the kit's own writer.

Offline: no GitHub, no store. The store contract is the landing-zone Terraform's real output
(tests/fixtures/evidence-store/store_contract.terraform.raw.json, byte-exact; derivation in the
evidence-store-client's tests/fixtures/DERIVATION.txt).

C1  each evidence artifact family routes to its container and layer; cross-run state, caches, script
    bundles and fixtures are SKIPPED by name
C2  every routing target is allowed by the contract for tool `kit`; a wrong layer is refused
C3  unsafe path segments are refused
C4  an artifact zip with '..', an absolute name or a symbolic link is refused; a normal one extracts
C5  the gate refuses pull_request and push events, another ref, an absent App, bad or mixed-owner lists
C6  the vendored client is at its pin; a changed copy is CLIENT_CHANGED
C7  push: 0 and 3 pass, 4 fails the job; a target outside the contract refuses before any upload
C8  collect stages under <container>/<layer>/<owner>/<repo>/runs/<run>-<attempt>/<artifact>/, skips
    the rest and expired artifacts
W1  the workflow: id-token write + contents read only; schedule and dispatch, no push or pull_request;
    the App token asks exactly contents/actions/metadata read; azure/login is OIDC from vars; the only
    secret is the App key; every action pinned; environment and timeout; the gate before the mint
C9  transport (owner decisions 2026-11-24): with the kit's API URL and audience the client is handed
    them and writes through the kit API app; without a URL the direct library write runs only when
    EVIDENCE_DIRECT_WRITE is true, otherwise NO_API refuses before any upload (exit 5)
C10 the publication gate (evidence-store-client PROTOCOL.md 4.2): a staged cicd-kit-gates file that is
    not a schema-valid, scanned object refuses the whole push before any upload (exit 5); raw
    cicd-kit-scans files are not gated
W2  the push step wires vars.EVIDENCE_KIT_API_URL, vars.EVIDENCE_KIT_API_AUDIENCE and
    vars.EVIDENCE_DIRECT_WRITE (the integration templates' pattern); retention is not touched here
M1-M5 mutants of the script must each fail a check above
"""
import importlib.util
import io
import json
import os
import shutil
import stat
import subprocess
import sys
import tempfile
import zipfile

import yaml

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SCRIPT = os.path.join(ROOT, 'scripts', 'evidence_copyout.py')
WORKFLOW = os.path.join(ROOT, '.github', 'workflows', 'evidence-copyout.yml')
CONTRACT = os.path.join(ROOT, 'tests', 'fixtures', 'evidence-store', 'store_contract.terraform.raw.json')
FAILS = []

ROUTES = {
    'sarif-semgrep-2': ('cicd-kit-scans', 'reported'), 'sarif-codeql-python-1': ('cicd-kit-scans', 'reported'),
    'sbom': ('cicd-kit-scans', 'reported'), 'sbom-0123abcd': ('cicd-kit-scans', 'reported'),
    'security-report-1': ('cicd-kit-scans', 'reported'), 'deployed-findings-9-1': ('cicd-kit-scans', 'reported'),
    'external-findings-sonar': ('cicd-kit-scans', 'reported'),
    'ai-artifact-inventory-1': ('cicd-kit-scans', 'reported'),
    'kit-security-record-1': ('cicd-kit-gates', 'evaluated'), 'deploy-evidence-9-1': ('cicd-kit-gates', 'evaluated'),
    'rollback-sequence-9-1': ('cicd-kit-gates', 'evaluated'), 'build-evidence-9-1': ('cicd-kit-gates', 'evaluated'),
    'kit-evidence-export-9': ('cicd-kit-gates', 'evaluated'),
    'kit-promotion-record-prod': ('cicd-kit-gates', 'approved'),
    'kit-promotion-record-uat--0123456789ab': ('cicd-kit-gates', 'approved'),
    # never evidence for the store: cross-run state, caches, bundles, fixtures
    'kit-deploy-state-web': None, 'kit-rollback-marker-web': None, 'kit-api-idem-0f0f': None,
    'kit-ticket-outbox-1': None, 'kit-scripts-1': None, 'test-only-seeds-1': None, 'fixture': None,
    'dependabot-yml-proposed': None, '../sarif-x': None,
}


def check(cond, what):
    print(('ok   ' if cond else 'FAIL ') + what)
    if not cond:
        FAILS.append(what)


def load(src=None):
    spec = importlib.util.spec_from_file_location('evidence_copyout_under_test', SCRIPT)
    m = importlib.util.module_from_spec(spec)
    if src is None:
        spec.loader.exec_module(m)
    else:
        m.__file__ = SCRIPT
        exec(compile(src, SCRIPT, 'exec'), m.__dict__)
    return m


def zip_bytes(entries):
    b = io.BytesIO()
    with zipfile.ZipFile(b, 'w') as z:
        for name, data, link in entries:
            info = zipfile.ZipInfo(name)
            if link:
                info.external_attr = (stat.S_IFLNK | 0o777) << 16
            z.writestr(info, data)
    return b.getvalue()


class FakeGH(object):
    def __init__(self, z, by_id=None):
        self.z = z
        self.by_id = by_id or {}
        self.calls = []

    def get(self, path, **q):
        self.calls.append(path)
        if path.endswith('/actions/runs'):
            return {'workflow_runs': [{'id': 77, 'run_attempt': 2}]}
        return {'artifacts': [{'id': 1, 'name': 'sarif-semgrep-2', 'expired': False},
                              {'id': 2, 'name': 'kit-promotion-record-prod', 'expired': False},
                              {'id': 3, 'name': 'kit-deploy-state-web', 'expired': False},
                              {'id': 4, 'name': 'security-report-2', 'expired': True}]}

    def download(self, path):
        self.calls.append(path)
        for aid, z in self.by_id.items():
            if path.endswith('/artifacts/%d/zip' % aid):
                return z
        return self.z


API_ENV = {'EVIDENCE_API_URL': 'https://func-x-evapi-kit-sbx.azurewebsites.net',
           'EVIDENCE_API_AUDIENCE': 'api://func-x-evapi-kit-sbx', 'EVIDENCE_DIRECT_WRITE': ''}
GOOD_ENV = {'EVENT': 'schedule', 'REF': 'refs/heads/main', 'DEFAULT_BRANCH': 'main', 'HAS_APP_KEY': 'true',
            'APP_CLIENT_ID': 'Iv1.placeholder', 'COPYOUT_REPOSITORIES': 'example-org/app-one, example-org/app-two'}


def checks(m, quiet_prefix=''):
    """Every C check over module m; -> number of failures (prints only when quiet_prefix is empty)."""
    fails = []

    def c(cond, what):
        if not quiet_prefix:
            check(cond, what)
        elif not cond:
            fails.append(what)
    c(all(m.classify(n) == w for n, w in ROUTES.items()),
      'C1 every artifact family routes as designed; state, caches, bundles and fixtures SKIPPED')
    sys.path.insert(0, os.path.join(ROOT, 'tools', 'evidence-store-client'))
    from evidence_store import load_contract
    from evidence_store.contract import check_write
    from evidence_store.errors import RefusedError
    k = load_contract(CONTRACT)
    ok = True
    for _rx, container, layer in m.RULES:
        try:
            check_write(k, 'kit', container, m.blob_prefix(layer, 'example-org/app-one', 77, 2, 'a') + '/x.json')
        except RefusedError:
            ok = False
    try:
        check_write(k, 'kit', 'cicd-kit-gates', 'reported/example-org/app-one/runs/77-2/a/x.json')
        ok = False
    except RefusedError:
        pass
    c(ok, 'C2 every target allowed by the Terraform contract; a wrong layer refused')
    bad = 0
    for seg in ('..', 'a/b', '', 'x y'):
        try:
            m.blob_prefix('reported', 'example-org/app-one', 77, 2, seg)
        except ValueError:
            bad += 1
    c(bad == 4, 'C3 unsafe path segments refused')
    d = tempfile.mkdtemp(prefix='copyout_proof_')
    try:
        refused = 0
        for e in ([('../evil.txt', b'x', False)], [('/abs.txt', b'x', False)], [('lnk', b'/etc', True)],
                  [('C:/x.txt', b'x', False)]):
            try:
                m.safe_extract(zip_bytes(e), os.path.join(d, 'z%d' % refused))
            except ValueError:
                refused += 1
        n = m.safe_extract(zip_bytes([('a/report.sarif', b'{}', False)]), os.path.join(d, 'ok'))
        c(refused == 4 and n == 1 and not os.path.exists(os.path.join(d, 'evil.txt')),
          'C4 traversal, absolute, drive and link names refused; a normal zip extracts')
        gate = []
        for k2, v in (('EVENT', 'pull_request'), ('EVENT', 'push'), ('EVENT', 'pull_request_target'),
                      ('REF', 'refs/heads/feature'), ('HAS_APP_KEY', 'false'), ('APP_CLIENT_ID', ''),
                      ('COPYOUT_REPOSITORIES', ''), ('COPYOUT_REPOSITORIES', 'not a repo'),
                      ('COPYOUT_REPOSITORIES', 'org-a/x,org-b/y')):
            gate.append(m.plan(dict(GOOD_ENV, **{k2: v}))[0])
        okp = m.plan(dict(GOOD_ENV))
        c(not any(gate) and okp[0] and okp[2] == ['example-org/app-one', 'example-org/app-two'],
          'C5 the gate refuses untrusted events, refs, absent App and bad lists; allows schedule on main')
        c(m.client_state()[0] == 'OK', 'C6 the vendored client is at its pinned tree hash')
        cc = os.path.join(d, 'client')
        shutil.copytree(os.path.join(ROOT, 'tools', 'evidence-store-client'), cc)
        with io.open(os.path.join(cc, 'evidence_store', 'core.py'), 'a', encoding='utf-8') as fh:
            fh.write('# edited\n')
        c(m.client_state(cc)[0] == 'CHANGED', 'C6 a changed copy is CLIENT_CHANGED')
        # C8 collect
        gh = FakeGH(zip_bytes([('report.sarif', b'{}', False)]),
                    by_id={2: zip_bytes([('outcome.json', b'{"deployment_outcome": "deployed"}', False)])})
        out = os.path.join(d, 'stage')
        rep = m.collect(gh, ['example-org/app-one'], out, '2031-01-01T00:00:00Z')
        got = m.staged(out)
        c([(x[0], x[1]) for x in got] == [
            ('cicd-kit-gates', 'approved/example-org/app-one/runs/77-2/kit-promotion-record-prod'),
            ('cicd-kit-scans', 'reported/example-org/app-one/runs/77-2/sarif-semgrep-2')] and
          len(rep['skipped']) == 1 and len(rep['expired']) == 1,
          'C8 collect stages evidence by container and layer; skips state and expired artifacts')
        # C7 push
        calls = []

        def runner(rc):
            def r(argv, **kw):
                calls.append(argv)
                return subprocess.CompletedProcess(argv, rc, stdout=json.dumps({'status': 'X'}), stderr='')
            return r
        res = [m.push_all(out, CONTRACT, run=runner(rc), env=API_ENV)[0] for rc in (0, 3, 4)]
        c(res == [0, 3, 4], 'C7 push: 0 passes, all-3 is 3, a CONFLICT (4) fails (%r)' % res)
        # C9 transport
        envs = []

        def seen(argv, **kw):
            envs.append(kw.get('env') or {})
            return subprocess.CompletedProcess(argv, 0, stdout=json.dumps({'status': 'OK', 'transport': 'api'}),
                                               stderr='')
        code, rows = m.push_all(out, CONTRACT, run=seen, env=API_ENV)
        c(code == 0 and len(envs) == 2 and all(e.get('EVIDENCE_API_URL') == API_ENV['EVIDENCE_API_URL'] and
                                              e.get('EVIDENCE_API_AUDIENCE') == API_ENV['EVIDENCE_API_AUDIENCE']
                                              for e in envs) and all(r.get('transport') == 'api' for r in rows),
          'C9 with the kit API URL and audience every push is handed them and records its transport')
        calls[:] = []
        code, rows = m.push_all(out, CONTRACT, run=runner(0), env={'EVIDENCE_API_URL': '', 'EVIDENCE_DIRECT_WRITE': ''})
        c(code == 5 and calls == [] and 'NO_API' in rows[0]['message'],
          'C9 no API URL and no direct-write flag: NO_API, refused before any upload')
        envs[:] = []
        code, _r = m.push_all(out, CONTRACT, run=seen, env={'EVIDENCE_API_URL': '', 'EVIDENCE_DIRECT_WRITE': 'true'})
        c(code == 0 and len(envs) == 2 and all(not e.get('EVIDENCE_API_URL') for e in envs),
          'C9 the direct library write runs only with EVIDENCE_DIRECT_WRITE = true (the fallback)')
        code, _r = m.push_all(out, CONTRACT, run=seen, env={'EVIDENCE_API_URL': API_ENV['EVIDENCE_API_URL'],
                                                             'EVIDENCE_API_AUDIENCE': ''})
        c(code == 5, 'C9 an API URL without its audience refuses before any upload')
        # C10 the publication gate, before any upload
        bad = os.path.join(out, 'cicd-kit-gates', 'evaluated', 'example-org', 'app-one', 'runs', '77-2',
                           'deploy-evidence-77-2')
        os.makedirs(bad)
        with open(os.path.join(bad, 'notes.json'), 'wb') as fh:
            fh.write(b'{"free": "text"}')
        calls[:] = []
        code, rows = m.push_all(out, CONTRACT, run=runner(0), env=API_ENV)
        c(code == 5 and calls == [] and 'PUB_NO_SCHEMA' in rows[0]['message'],
          'C10 a schema-less cicd-kit-gates file refuses the whole push before any upload')
        os.remove(os.path.join(bad, 'notes.json'))
        with open(os.path.join(bad, 'snapshot.json'), 'wb') as fh:
            fh.write(b'{"adapter": "appservice", "note": "AccountKey=' + b'A' * 40 + b'"}')
        code, rows = m.push_all(out, CONTRACT, run=runner(0), env=API_ENV)
        c(code == 5 and calls == [] and 'PUB_SECRET' in rows[0]['message'] and 'AAAA' not in rows[0]['message'],
          'C10 a secret shape in a gate record refuses before any upload, without echoing it')
        shutil.rmtree(bad)
        sc = os.path.join(out, 'cicd-kit-scans', 'reported', 'example-org', 'app-one', 'runs', '77-2', 'sarif-x')
        os.makedirs(sc)
        with open(os.path.join(sc, 'raw.sarif'), 'wb') as fh:
            fh.write(b'\x00 not json, raw container')
        code, _r = m.push_all(out, CONTRACT, run=runner(0), env=API_ENV)
        c(code == 0, 'C10 raw cicd-kit-scans files are not gated')
        shutil.rmtree(sc)
        os.makedirs(os.path.join(out, 'cicd-kit-scans', 'evaluated', 'example-org', 'app-one', 'runs', '1-1', 'x'))
        calls[:] = []
        code, _r = m.push_all(out, CONTRACT, run=runner(0), env=API_ENV)
        c(code == 5 and calls == [], 'C7 a staged target outside the contract refuses before any upload')
    finally:
        shutil.rmtree(d, ignore_errors=True)
    return len(fails)


def workflow():
    with io.open(WORKFLOW, encoding='utf-8') as fh:
        text = fh.read()
    w = yaml.safe_load(text)
    on = w.get(True) or w.get('on')
    job = w['jobs']['copyout']
    steps = job['steps']
    uses = [s['uses'] for s in steps if 'uses' in s]
    tok = [s for s in steps if s.get('uses', '').startswith('actions/create-github-app-token@')]
    login = [s for s in steps if s.get('uses', '').startswith('azure/login@')]
    import re
    secrets = set(re.findall(r'secrets\.([A-Z0-9_]+)', text))
    names = [s.get('id') for s in steps]
    check(w['permissions'] == {'id-token': 'write', 'contents': 'read'} and 'permissions' not in job,
          'W1 permissions exactly id-token write + contents read')
    check(set(on) == {'schedule', 'workflow_dispatch'}, 'W1 schedule and dispatch only (no push, no pull_request)')
    check(len(tok) == 1 and {k: v for k, v in tok[0]['with'].items() if k.startswith('permission-')} ==
          {'permission-contents': 'read', 'permission-actions': 'read', 'permission-metadata': 'read'},
          'W1 the App token asks exactly contents, actions and metadata read')
    check(len(login) == 1 and login[0]['with'].get('client-id') == '${{ vars.KIT_EVIDENCE_WRITER_CLIENT_ID }}'
          and set(login[0]['with']) == {'client-id', 'tenant-id', 'allow-no-subscriptions'},
          'W1 azure/login is OIDC with the kit writer from vars')
    check(secrets == {'KIT_COPYOUT_APP_PRIVATE_KEY'}, 'W1 the only secret is the App key (%s)' % sorted(secrets))
    check(all(re.match(r'^[^@]+@[0-9a-f]{40}$', u) for u in uses), 'W1 every action pinned to a full SHA')
    check(job.get('environment') and job.get('timeout-minutes'), 'W1 environment and timeout')
    check(names.index('plan') < names.index('token') and tok[0].get('if') == "steps.plan.outputs.run == 'true'",
          'W1 the gate decides before the token is minted')
    push = [s for s in steps if 'evidence_copyout.py push' in (s.get('run') or '')]
    penv = (push[0].get('env') or {}) if push else {}
    check(len(push) == 1 and penv.get('EVIDENCE_API_URL') == '${{ vars.EVIDENCE_KIT_API_URL }}'
          and penv.get('EVIDENCE_API_AUDIENCE') == '${{ vars.EVIDENCE_KIT_API_AUDIENCE }}'
          and penv.get('EVIDENCE_DIRECT_WRITE') == '${{ vars.EVIDENCE_DIRECT_WRITE }}',
          'W2 the push step is wired to the kit API app (URL + audience vars) with the direct-write flag')
    check(login and steps.index(login[0]) < steps.index(push[0]) if push else False,
          'W2 the push runs after the OIDC sign-in (its token is the API token source)')


def main():
    m = load()
    checks(m)
    workflow()
    src = io.open(SCRIPT, encoding='utf-8').read()
    mutants = {
        'M1 promotion records routed to evaluated': (
            "(r'^kit-promotion-record-[A-Za-z0-9._-]+$', GATES, 'approved')",
            "(r'^kit-promotion-record-[A-Za-z0-9._-]+$', GATES, 'evaluated')"),
        'M2 the gate trusts pull_request': (
            "TRUSTED_EVENTS = ('schedule', 'workflow_dispatch')",
            "TRUSTED_EVENTS = ('schedule', 'workflow_dispatch', 'pull_request')"),
        'M3 the zip check forgets .. and containment': [("p in ('.', '..') or ", ''),
                                                        ("if os.path.commonpath([root, full]) != root:", "if False:")],
        'M4 a CONFLICT counts as a pass': ("if p.returncode not in (0, 3):", "if p.returncode not in (0, 3, 4):"),
        'M5 the transport guard is dropped': ("if not api_url and not direct:", "if False:"),
    }
    for name, edits in mutants.items():
        edits = edits if isinstance(edits, list) else [edits]
        mut = src
        if any(src.count(a) != 1 for a, _b in edits):
            check(False, '%s: anchor not found' % name)
            continue
        for a, b in edits:
            mut = mut.replace(a, b)
        caught = checks(load(mut), quiet_prefix=name) > 0
        check(caught, '%s caught' % name)
    print('EVIDENCE COPY-OUT: %d check(s) failed' % len(FAILS) if FAILS else
          'EVIDENCE COPY-OUT OK: evidence only, contract-checked, trusted runs only, read-only App, OIDC writer')
    return 1 if FAILS else 0


if __name__ == '__main__':
    sys.exit(main())

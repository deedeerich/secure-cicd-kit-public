#!/usr/bin/env python3
"""The kit's scheduled evidence copy-out (KDEC-068): completed runs' evidence artifacts -> the store.

One scheduled job owned by the kit (.github/workflows/evidence-copyout.yml). Application
repositories hold no storage identity: this job reads their completed runs' artifacts with a
READ-ONLY GitHub App installation token (Contents, Actions, Metadata: read) and pushes them, put-once,
as tool `kit` with the kit's evidence writer (OIDC, no secret):

    SARIF, SBOMs, findings, the security report      -> cicd-kit-scans  reported/<owner>/<repo>/runs/<run>-<attempt>/<artifact>/
    the gate's security record, deploy / rollback     -> cicd-kit-gates  evaluated/<owner>/<repo>/runs/<run>-<attempt>/<artifact>/
    records, the evidence export, the build evidence
    the promotion record (it carries the approval)    -> cicd-kit-gates  approved/<owner>/<repo>/runs/<run>-<attempt>/<artifact>/

Any other artifact (caches, script bundles, cross-run state, test fixtures) is listed as SKIPPED with
its name, never pushed. Every target is checked against the store contract (terraform output -raw
store_contract) and every cicd-kit-gates file against the client's publication gate (a schema-valid,
scanned object: Tines reads that container) before any upload; one refusal refuses the batch. Exit
codes follow the client: 0 and 3 (ALREADY_PRESENT) pass, anything else fails.

Transport (owner decisions 2026-11-24, the client's integration-template pattern): the push goes
through the kit's own evidence API app when EVIDENCE_API_URL and EVIDENCE_API_AUDIENCE are set
(vars.EVIDENCE_KIT_API_URL / _AUDIENCE; the client takes the API token from the azure/login session).
The direct library write is the fallback, only with EVIDENCE_DIRECT_WRITE = true while the API is off;
neither -> NO_API, refused before any upload. Objects over 32 MiB go direct automatically (the client).

    python3 scripts/evidence_copyout.py plan                 the gate (event, ref, credential, repos, client pin)
    python3 scripts/evidence_copyout.py collect --out DIR    list runs and artifacts, download, extract safely
    python3 scripts/evidence_copyout.py push --staged DIR    push every staged artifact through the client
    python3 scripts/evidence_copyout.py classify NAME...     print where each artifact name goes

Host-agnostic (KDEC-027): the API base is GITHUB_API_URL, never a fixed host. The token is read from
COPYOUT_GH_TOKEN and never printed or written.
"""
import argparse
import hashlib
import io
import json
import os
import re
import subprocess
import sys
import urllib.error
import urllib.parse
import urllib.request
import zipfile

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
CLIENT_DIR = os.path.join(ROOT, 'tools', 'evidence-store-client')
# Re-vendored 2026-11-25 from evidence-store-client e7aa774 (integrate/evidence-api-2026-11-24).
CLIENT_TREE_SHA256 = '43852cb4c3678488a12144fcd223a86a0b337bed79e3317e3893b7f888859c4c'
TOOL = 'kit'
SCANS, GATES = 'cicd-kit-scans', 'cicd-kit-gates'

# (regex over the artifact name, container, layer). First match wins; no match = SKIPPED.
RULES = (
    (r'^sarif-[A-Za-z0-9._-]+$', SCANS, 'reported'),
    (r'^sbom(-[A-Za-z0-9._-]+)?$', SCANS, 'reported'),
    (r'^security-report-[0-9]+$', SCANS, 'reported'),
    (r'^deployed-findings-[0-9]+-[0-9]+$', SCANS, 'reported'),
    (r'^external-findings-[A-Za-z0-9._-]+$', SCANS, 'reported'),
    (r'^ai-artifact-inventory-[0-9]+$', SCANS, 'reported'),
    (r'^kit-security-record-[0-9]+$', GATES, 'evaluated'),
    (r'^deploy-evidence-[0-9]+-[0-9]+$', GATES, 'evaluated'),
    (r'^rollback-sequence-[0-9]+-[0-9]+$', GATES, 'evaluated'),
    (r'^build-evidence-[0-9]+-[0-9]+$', GATES, 'evaluated'),
    (r'^kit-evidence-export-[A-Za-z0-9._-]+$', GATES, 'evaluated'),
    (r'^kit-promotion-record-[A-Za-z0-9._-]+$', GATES, 'approved'),
)
SAFE_SEG = re.compile(r'^[A-Za-z0-9][A-Za-z0-9._-]{0,99}$')
REPO = re.compile(r'^[A-Za-z0-9][A-Za-z0-9-]{0,38}/[A-Za-z0-9._-]{1,100}$')
MAX_PAGES = 10
MAX_ARTIFACT_BYTES = 512 * 1024 * 1024
TRUSTED_EVENTS = ('schedule', 'workflow_dispatch')


def classify(name):
    """-> (container, layer) or None (SKIPPED)."""
    for rx, container, layer in RULES:
        if re.match(rx, name or ''):
            return container, layer
    return None


def blob_prefix(layer, repo, run_id, attempt, artifact):
    owner, name = repo.split('/', 1)
    for seg in (owner, name, str(run_id), str(attempt), artifact):
        if not SAFE_SEG.match(seg):
            raise ValueError('unsafe path segment %r' % seg)
    return '%s/%s/%s/runs/%s-%s/%s' % (layer, owner, name, run_id, attempt, artifact)


def client_state(client_dir=CLIENT_DIR):
    lines = []
    for d, dirs, files in os.walk(os.path.join(client_dir, 'evidence_store')):
        dirs[:] = sorted(x for x in dirs if x != '__pycache__')
        for f in sorted(files):
            if f.endswith('.pyc') or f == 'VENDORED.json':
                continue
            p = os.path.join(d, f)
            with open(p, 'rb') as fh:
                lines.append((os.path.relpath(p, client_dir).replace(os.sep, '/'), hashlib.sha256(fh.read()).hexdigest()))
    got = hashlib.sha256(''.join('%s %s\n' % (h, r) for r, h in sorted(lines)).encode()).hexdigest()
    return 'OK' if lines and got == CLIENT_TREE_SHA256 else 'CHANGED', got


def _output(**pairs):
    """Each keyword is one step output, written to GITHUB_OUTPUT (and printed)."""
    path = os.environ.get('GITHUB_OUTPUT')
    for k, v in pairs.items():
        v = re.sub(r'[\r\n]', ' ', str(v))            # one line per output, never a second key
        print('%s=%s' % (k, v))
        if path:
            with io.open(path, 'a', encoding='utf-8') as fh:
                fh.write('%s=%s\n' % (k, v))


def plan(env=None):
    """The gate. -> (run, reason, repos)."""
    env = os.environ if env is None else env
    event, ref = env.get('EVENT', ''), env.get('REF', '')
    default = env.get('DEFAULT_BRANCH', '')
    repos = [r.strip() for r in re.split(r'[,\s]+', env.get('COPYOUT_REPOSITORIES', '')) if r.strip()]
    if event not in TRUSTED_EVENTS:
        return False, 'EVENT_REFUSED: copy-out runs only on schedule or workflow_dispatch, not %r' % event, []
    if not default or ref != 'refs/heads/%s' % default:
        return False, 'REF_REFUSED: copy-out runs only on the default branch, not %r' % ref, []
    if env.get('HAS_APP_KEY') != 'true' or not env.get('APP_CLIENT_ID'):
        return False, 'COPYOUT_NOT_RUN: the read-only GitHub App is not configured (no client id or key)', []
    if not repos or [r for r in repos if not REPO.match(r)]:
        return False, 'COPYOUT_NOT_RUN: KIT_COPYOUT_REPOSITORIES must list owner/repo names', []
    if len({r.split('/')[0] for r in repos}) != 1:
        return False, 'REPOS_REFUSED: one App installation per owner; list one owner per run', []
    state, got = client_state()
    if state != 'OK':
        return False, 'CLIENT_CHANGED: the vendored client hashes to %s, not the pinned %s' % (got, CLIENT_TREE_SHA256), []
    return True, 'COPYOUT_RUN', repos


# ------------------------------------------------------------------------------------------------
class GitHub(object):
    def __init__(self, api, token, timeout=60):
        if not api.startswith('https://'):
            raise ValueError('GITHUB_API_URL must be https')
        self.api, self.token, self.timeout = api.rstrip('/'), token, timeout

    def _req(self, url):
        return urllib.request.Request(url, headers={'Authorization': 'Bearer ' + self.token,
                                                    'Accept': 'application/vnd.github+json',
                                                    'X-GitHub-Api-Version': '2022-11-28'})

    def get(self, path, **q):
        url = self.api + path + ('?' + urllib.parse.urlencode(q) if q else '')
        with urllib.request.urlopen(self._req(url), timeout=self.timeout) as r:
            return json.loads(r.read().decode('utf-8'))

    def download(self, path):
        with urllib.request.urlopen(self._req(self.api + path), timeout=self.timeout) as r:
            data = r.read(MAX_ARTIFACT_BYTES + 1)
        if len(data) > MAX_ARTIFACT_BYTES:
            raise ValueError('artifact larger than %d bytes' % MAX_ARTIFACT_BYTES)
        return data


def safe_extract(data, dest):
    """Extract a zip under dest; refuse absolute names, '..', drive letters and links."""
    os.makedirs(dest, exist_ok=True)
    root = os.path.realpath(dest)
    n = 0
    with zipfile.ZipFile(io.BytesIO(data)) as z:
        for info in z.infolist():
            name = info.filename.replace('\\', '/')
            parts = [p for p in name.split('/') if p]
            if name.startswith('/') or any(p in ('.', '..') or ':' in p for p in parts):
                raise ValueError('unsafe name in artifact zip: %r' % info.filename)
            if (info.external_attr >> 16) & 0o170000 == 0o120000:
                raise ValueError('symbolic link in artifact zip: %r' % info.filename)
            if info.is_dir() or not parts:
                continue
            full = os.path.realpath(os.path.join(root, *parts))
            if os.path.commonpath([root, full]) != root:
                raise ValueError('name escapes the target: %r' % info.filename)
            os.makedirs(os.path.dirname(full), exist_ok=True)
            with z.open(info) as src, open(full, 'xb') as dst:
                dst.write(src.read())
            n += 1
    return n


def collect(gh, repos, out, since):
    """-> report dict. Stages each artifact under out/<container>/<blob prefix>/."""
    rep = dict(staged=[], skipped=[], expired=[])
    for repo in repos:
        for page in range(1, MAX_PAGES + 1):
            runs = gh.get('/repos/%s/actions/runs' % repo, status='completed', created='>=' + since,
                          per_page=100, page=page).get('workflow_runs', [])
            for run in runs:
                arts = gh.get('/repos/%s/actions/runs/%d/artifacts' % (repo, run['id']), per_page=100)
                for a in arts.get('artifacts', []):
                    where = classify(a['name'])
                    if where is None:
                        rep['skipped'].append('%s#%s %s' % (repo, run['id'], a['name']))
                        continue
                    if a.get('expired'):
                        rep['expired'].append('%s#%s %s' % (repo, run['id'], a['name']))
                        continue
                    container, layer = where
                    prefix = blob_prefix(layer, repo, run['id'], run.get('run_attempt', 1), a['name'])
                    dest = os.path.join(out, container, *prefix.split('/'))
                    if os.path.exists(dest):
                        continue
                    safe_extract(gh.download('/repos/%s/actions/artifacts/%d/zip' % (repo, a['id'])), dest)
                    rep['staged'].append(dict(container=container, prefix=prefix, artifact_id=a['id']))
            if len(runs) < 100:
                break
    return rep


def staged(out):
    """-> [(container, prefix, dir)] for every staged artifact directory."""
    res = []
    for container in (SCANS, GATES):
        top = os.path.join(out, container)
        if not os.path.isdir(top):
            continue
        for base, dirs, _files in os.walk(top):
            rel = os.path.relpath(base, top).replace(os.sep, '/').split('/')
            if len(rel) == 6 and rel[3] == 'runs':          # layer/owner/repo/runs/<run>-<att>/<artifact>
                res.append((container, '/'.join(rel), base))
                dirs[:] = []
    return sorted(res)


def transport(env):
    """-> (api_url, audience, direct) from the environment, or raise ValueError (NO_API)."""
    api_url = (env.get('EVIDENCE_API_URL') or '').strip()
    audience = (env.get('EVIDENCE_API_AUDIENCE') or '').strip()
    direct = (env.get('EVIDENCE_DIRECT_WRITE') or '').strip().lower() == 'true'
    if not api_url and not direct:
        raise ValueError('NO_API: no evidence API URL for the kit (vars.EVIDENCE_KIT_API_URL); set '
                         'vars.EVIDENCE_DIRECT_WRITE = true only while the API is off')
    if api_url and not audience:
        raise ValueError('NO_API: vars.EVIDENCE_KIT_API_URL is set without vars.EVIDENCE_KIT_API_AUDIENCE')
    return api_url, audience, direct


def _gate(container, prefix, d):
    """The client's publication gate over every staged file of one artifact (raw containers pass)."""
    from evidence_store import core
    for base, _dirs, files in os.walk(d):
        for f in sorted(files):
            p = os.path.join(base, f)
            rel = os.path.relpath(p, d).replace(os.sep, '/')
            core._publication_check(container, prefix + '/' + rel, p, core._content_type(p),
                                    {'run_id': prefix.split('/')[4]}, {'source_system': 'github'})


def push_all(out, contract, run=subprocess.run, extra=(), env=None):
    """Check the transport, every target against the contract and every result-container file against
    the publication gate first, then push each artifact through the client CLI.
    -> (exit code, [result dict])."""
    env = dict(os.environ if env is None else env)
    try:
        api_url, audience, _direct = transport(env)
    except ValueError as e:
        return 5, [dict(status='REFUSED', message='%s; nothing sent' % e)]
    sys.path.insert(0, CLIENT_DIR)
    from evidence_store import load_contract
    from evidence_store.contract import check_write
    from evidence_store.errors import EvidenceStoreError
    c = load_contract(contract)
    todo = staged(out)
    try:
        for container, prefix, _d in todo:
            check_write(c, TOOL, container, prefix + '/probe.json')
    except EvidenceStoreError as e:
        return 5, [dict(status='REFUSED', message='outside the store contract, nothing sent: %s' % e)]
    try:
        for container, prefix, d in todo:
            _gate(container, prefix, d)
    except EvidenceStoreError as e:
        return 5, [dict(status='REFUSED', message='publication gate, nothing sent: %s' % e)]
    results, worst = [], 0
    env.update(PYTHONPATH=CLIENT_DIR, EVIDENCE_STORE_CONTRACT=contract)
    if not api_url:
        env.pop('EVIDENCE_API_URL', None)       # the fallback: the client writes directly
        env.pop('EVIDENCE_API_AUDIENCE', None)
    for container, prefix, d in todo:
        runid = prefix.split('/')[4]
        p = run([sys.executable, '-m', 'evidence_store', 'push', d, '--container', container, '--tool', TOOL,
                 '--prefix', prefix, '--run-id', runid, '--meta', 'source_system=github'] + list(extra),
                capture_output=True, text=True, timeout=900, env=env)
        try:
            doc = json.loads(p.stdout)
        except ValueError:
            doc = dict(status='ERROR', message='no JSON result')
        results.append(dict(container=container, prefix=prefix, exit=p.returncode, status=doc.get('status'),
                            transport=doc.get('transport', 'api' if api_url else 'direct'),
                            counts=doc.get('counts'), message=doc.get('message', '')))
        if p.returncode not in (0, 3):
            worst = worst or p.returncode
    if not todo:
        return 0, [dict(status='OK', message='nothing staged: no new evidence artifacts')]
    if worst:
        return worst, results
    return (3 if all(r['exit'] == 3 for r in results) else 0), results


def main(argv):
    ap = argparse.ArgumentParser(description='the kit evidence copy-out')
    sub = ap.add_subparsers(dest='cmd', required=True)
    sub.add_parser('plan')
    c = sub.add_parser('collect')
    c.add_argument('--out', required=True)
    c.add_argument('--since-hours', type=int, default=36)
    p = sub.add_parser('push')
    p.add_argument('--staged', required=True)
    p.add_argument('--contract', default=os.environ.get('EVIDENCE_STORE_CONTRACT', ''))
    k = sub.add_parser('classify')
    k.add_argument('names', nargs='+')
    a = ap.parse_args(argv)
    if a.cmd == 'classify':
        for n in a.names:
            w = classify(n)
            print('%s -> %s' % (n, 'SKIPPED' if w is None else '%s %s/' % w))
        return 0
    if a.cmd == 'plan':
        ok, why, repos = plan()
        run = 'true' if ok else 'false'
        owner = repos[0].split('/')[0] if repos else ''
        names = ','.join(r.split('/')[1] for r in repos)
        _output(run=run, owner=owner, repos=names, reason=why)
        print(why)
        return 0
    if a.cmd == 'collect':
        ok, why, repos = plan()
        if not ok:
            print(why)
            return 1
        import datetime
        since = (datetime.datetime.now(datetime.timezone.utc) -
                 datetime.timedelta(hours=a.since_hours)).strftime('%Y-%m-%dT%H:%M:%SZ')
        gh = GitHub(os.environ.get('GITHUB_API_URL', ''), os.environ.get('COPYOUT_GH_TOKEN', ''))
        rep = collect(gh, repos, a.out, since)
        print(json.dumps(dict(staged=len(rep['staged']), skipped=len(rep['skipped']),
                              expired=rep['expired']), indent=2))
        return 0
    code, results = push_all(a.staged, a.contract)
    print(json.dumps(results, indent=2))
    return code


if __name__ == '__main__':
    sys.exit(main(sys.argv[1:]))

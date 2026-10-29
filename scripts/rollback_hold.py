#!/usr/bin/env python3
"""After a rollback: the target's rollback MARKER, and the DEPENDENCY CHECK every incoming deploy of
that target runs before it logs in. (KDEC-023 item 4, owner 2026-10-23, lane L-RB3.)

WHY THIS EXISTS

    Owner, 2026-10-23, on a deploy that arrives while a rollback runs: "That's a conflict where the
    rollback must finish and then the other one can deploy...problem is if someone is trying to
    deploy they are probably trying to use the infrastructure and code from the one we just rolled
    back". Her decision, the same day: "We need to do a dependency check on the incoming deployment
    to ensure that it isn't reliant on things that were just rolled back and if they are you give a
    report to the deploying team or pipeline or whatever and let them know there is an error because
    of a rollback and what dependencies no longer are the same or no longer exist...and then they
    correct. If there are no dependencies on rolled back items then deploy it."

    The shared per-target concurrency group (KDEC-021) already makes the deploy WAIT for the
    rollback. Waiting is not enough: when the rollback finishes, the queued deploy -- built before
    it -- would put straight back what was just taken out, or stand on something that is gone.

THE MARKER (`marker`, run by reusable-rollback-sequence.yml when the sequence reversed anything)

    Uploaded as the artifact `kit-rollback-marker-<target key>` (the deploy evidence channel: the
    deploys already publish `deploy-evidence-*` artifacts; the marker is read the same way). It names
    the target, the rollback run, when it completed, the releases it rolled back (run, commit,
    images), and every node it changed with the state it left: gone (`absent`) or `restored`, with
    each field old -> new.

THE CHECK (`check`, run by both deploy reusables before login)

    No marker for the target                    ROLLBACK_CHECK_NOT_REQUIRED
    The deploy's base commit is newer than the  ROLLBACK_CHECK_NOT_REQUIRED (it was built after the
      rollback completed                          rollback, knowing it)
    Otherwise the deploy is checked for a DEPENDENCY on what was rolled back:
      release lineage    its commit contains a rolled-back release's commit (compare API)
      image              it deploys an image a rolled-back release deployed
      declared           each entry of `declared_dependencies` (resource ids, entry paths, host
                         names: app settings, connection strings, Key Vault references, NSG / Front
                         Door entries, schema or migration markers recorded as nodes) that names a
                         node the rollback removed or changed
    Any dependency                              DEPLOY_REFUSED_ROLLBACK_DEPENDENCY -- refused, with a
                                                report: which rollback, and each dependency, old ->
                                                new or "no longer exists". The deploying team
                                                corrects the deploy and deploys again. THERE IS NO
                                                OVERRIDE INPUT (owner): the fix is the correction.
    None                                        DEPLOY_NO_ROLLBACK_DEPENDENCY -- the deploy proceeds,
                                                with the note that the check ran and found none
    The state cannot be read (the artifact list, ROLLBACK_DEPENDENCY_CHECK_INCOMPLETE -- refused
      the marker, the commit, the comparison)     with the reason; never blind

    The report is the run summary, an annotation and `rollback-check.json` in the deploy evidence.

USAGE
    rollback_hold.py marker --record F --evidence-root D --environment E --resource-group G --name N
                            --run-id I --run-attempt A [--completed-at T] --out F [--github-output F]
    rollback_hold.py check  --environment E --resource-group G --name N --commit SHA --run-id I
                            [--declared-dependencies JSON] [--image REF] --out F [--summary F]
                            [--github-output F]
    rollback_hold.py --self-test
    GitHub API: $GITHUB_API_URL, $GITHUB_REPOSITORY, $GH_TOKEN. A file:// API is the local stand-in
    (tests): one recorded answer per path, with the `name` filter applied here as the server applies it.

EXIT  check: 0 not required / no dependency   1 refused (a dependency, or the check incomplete)
      marker: 0 written or nothing to mark   2 usage
"""
import argparse
import hashlib
import io
import json
import os
import re
import sys
import time
import urllib.parse
import urllib.request
import zipfile

# rollback_dependency_check (assurance-taxonomy.yaml)
NOT_REQUIRED = 'ROLLBACK_CHECK_NOT_REQUIRED'
NO_DEPENDENCY = 'DEPLOY_NO_ROLLBACK_DEPENDENCY'
REFUSED = 'DEPLOY_REFUSED_ROLLBACK_DEPENDENCY'
INCOMPLETE = 'ROLLBACK_DEPENDENCY_CHECK_INCOMPLETE'
HOST = re.compile(r'https?://([A-Za-z0-9.-]+)', re.I)
PROVIDER_KEYS = ('vaultUri', 'defaultHostName', 'fullyQualifiedDomainName', 'hostName', 'loginServer', 'fqdn')


class Unreadable(Exception):
    pass


def now():
    return time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime())


def target_key(environment, resource_group, name):
    slug = re.sub(r'[^A-Za-z0-9._-]', '-', name or 'target')[:40]
    h = hashlib.sha256(('%s\n%s\n%s' % (environment, resource_group, name)).encode('utf-8')).hexdigest()
    return '%s-%s' % (slug, h[:12])


def marker_name(environment, resource_group, name):
    return 'kit-rollback-marker-' + target_key(environment, resource_group, name)


# ----------------------------------------------------------------------------- GitHub API
def _env(name, default=''):
    return os.environ.get(name.upper(), default)


def _open(url):
    req = urllib.request.Request(url, headers={'Accept': 'application/vnd.github+json',
                                               'X-GitHub-Api-Version': '2022-11-28'})
    token = _env('gh_token')
    if token and url.startswith('https://'):
        # Unredirected: an artifact download redirects to storage, which must not get the token.
        req.add_unredirected_header('Authorization', 'Bearer %s' % token)
    with urllib.request.urlopen(req, timeout=60) as resp:
        return resp.read()


def api(path, params=None):
    """GET /repos/<repository>/<path>. Any failure is Unreadable -- never an empty answer."""
    base = _env('GITHUB_API_URL', 'https://api.github.com').rstrip('/')  # unset means github.com
    repo = _env('github_repository')
    if not repo:
        raise Unreadable('no repository is named ($GITHUB_REPOSITORY)')
    url = '%s/repos/%s/%s' % (base, repo, path)
    try:
        if url.startswith('file:'):
            doc = json.loads(_open(url).decode('utf-8'))
            if params and params.get('name') and isinstance(doc, dict) and 'artifacts' in doc:
                doc = dict(doc, artifacts=[a for a in doc['artifacts'] if a.get('name') == params['name']])
            return doc
        if params:
            url += '?' + urllib.parse.urlencode(params)
        return json.loads(_open(url).decode('utf-8'))
    except Exception as exc:  # noqa: BLE001 -- any failure is "could not read", never a pass
        raise Unreadable('GET %s failed: %s' % (url.split('?')[0], type(exc).__name__))


def download_json(url, member_suffix='.json'):
    try:
        data = _open(url)
        with zipfile.ZipFile(io.BytesIO(data)) as zf:
            names = [n for n in zf.namelist() if n.endswith(member_suffix)]
            return json.loads(zf.read(names[0]).decode('utf-8'))
    except Exception as exc:  # noqa: BLE001
        raise Unreadable('the marker artifact could not be downloaded or read: %s' % type(exc).__name__)


# ----------------------------------------------------------------------------- marker
def _image(v):
    v = v if isinstance(v, str) else ''
    v = v.split('|', 1)[-1]
    return v if '@sha256:' in v else ''


def _canon(x):
    return json.dumps(x, sort_keys=True, separators=(',', ':'))


def _diff(a, b, where=''):
    if isinstance(a, dict) and isinstance(b, dict):
        out = []
        for k in sorted(set(a) | set(b)):
            out += _diff(a.get(k), b.get(k), '%s.%s' % (where, k) if where else k)
        return out
    return [[where or '(body)', a, b]] if a != b else []


def _hosts(body):
    out = set()
    props = (body or {}).get('properties') or {} if isinstance(body, dict) else {}
    for k in PROVIDER_KEYS:
        v = props.get(k)
        if isinstance(v, str):
            m = HOST.match(v)
            out.add((m.group(1) if m else v).lower().rstrip('/'))
    return sorted(out)


def build_marker(record, evidence_root, environment, resource_group, name, run_id, run_attempt, completed):
    rolled, changed, notes = [], [], []
    for s in record.get('steps') or []:
        if ((s.get('rollback') or {}).get('result') or 'not-run') == 'not-run':
            continue
        rid, att = str(s.get('run_id') or ''), str(s.get('run_attempt') or '1')
        d = os.path.join(evidence_root, 'deploy-evidence-%s-%s' % (rid, att))
        commit = None
        try:
            commit = (api('actions/runs/%s' % rid) or {}).get('head_sha') or None
        except Unreadable as exc:
            notes.append('the commit of run %s could not be read (%s): a deploy is then checked as if '
                         'it were built on it' % (rid, exc))
        images = set()
        man = _read(os.path.join(d, 'manifest.json')) or {}
        for e in man.get('entries') or []:
            for v in (e.get('post'), ):
                if _image(v):
                    images.add(_image(v))
        res = _read(os.path.join(d, 'resources.json')) or {}
        by_id = dict((n.get('id', '').lower(), n) for n in res.get('nodes') or [])
        rolled.append({'release': 'run-%s-%s' % (rid, att), 'run_id': rid, 'run_attempt': att,
                       'commit': commit, 'images': sorted(images), 'step_result': s.get('step_result')})
        rv = s.get('dependency_review') or {}
        for r in rv.get('reversed') or []:
            if not (r.get('applied') and r.get('verified')):
                continue
            n = by_id.get((r.get('id') or '').lower()) or {}
            gone = str(r.get('op', '')).startswith('delete')
            changed.append({'id': r['id'], 'release': 'run-%s-%s' % (rid, att),
                            'after': 'absent' if gone else 'restored',
                            'hosts': _hosts(n.get('post')),
                            'changes': [] if gone else _diff(n.get('post') or {}, n.get('prior') or {})[:20]})
        for x in s.get('restored') or []:
            if s.get('adapter') in ('appservice', 'containerapp') and x.get('held'):
                changed.append({'id': '%s %s' % (s.get('target') or name, x.get('slot')),
                                'release': 'run-%s-%s' % (rid, att), 'after': 'restored', 'hosts': [],
                                'changes': [['image', ', '.join(sorted(images)) or 'the release\'s image',
                                             x.get('want')]]})
    if not rolled:
        return None
    return {'schema_version': 1, 'kind': 'kit-rollback-marker',
            'target': {'environment': environment, 'resource_group': resource_group, 'name': name},
            'rollback_run_id': str(run_id), 'rollback_run_attempt': str(run_attempt),
            'completed_at': completed or now(), 'sequence_result': record.get('result'),
            'rollback_state': record.get('rollback_state'), 'rolled_back': rolled, 'changed': changed,
            'notes': notes}


def _read(path):
    try:
        return json.load(io.open(path, encoding='utf-8'))
    except (OSError, ValueError):
        return None


def cmd_marker(a):
    record = _read(a.record)
    if record is None:
        print('no readable rollback record at %s: nothing to mark' % a.record)
        _out(a.github_output, marker_written='false')
        return 0
    mk = build_marker(record, a.evidence_root, a.environment, a.resource_group, a.name, a.run_id,
                      a.run_attempt, a.completed_at)
    if mk is None:
        print('the sequence reversed nothing (%s): no marker, deploys of the target are not checked '
              'against it' % record.get('result'))
        _out(a.github_output, marker_written='false')
        return 0
    os.makedirs(os.path.dirname(os.path.abspath(a.out)), exist_ok=True)
    io.open(a.out, 'w', encoding='utf-8').write(json.dumps(mk, indent=1, sort_keys=True))
    name = marker_name(a.environment, a.resource_group, a.name)
    print('rollback marker %s: %d release(s) rolled back, %d node(s) changed' % (
        name, len(mk['rolled_back']), len(mk['changed'])))
    _out(a.github_output, marker_written='true', marker_name=name)
    return 0


def _out(path, **kv):
    if path:
        with io.open(path, 'a', encoding='utf-8') as fh:
            for k, v in kv.items():
                fh.write('%s=%s\n' % (k, str(v).replace('\n', ' ')))


# ----------------------------------------------------------------------------- check
def _short(v):
    s = v if isinstance(v, str) else json.dumps(v, sort_keys=True)
    return s if len(s) <= 70 else s[:67] + '...'


def _matches(ref, node):
    r = ref.strip().lower().rstrip('/')
    nid = (node.get('id') or '').lower().rstrip('/')
    if not r:
        return False
    if r == nid or nid.endswith('/' + r.lstrip('/')) or r.startswith(nid + '/') or (nid and nid in r):
        return True
    return any(h and h in r for h in node.get('hosts') or [])


def check(a):
    deps, notes = [], []
    doc = {'rollback_check': None, 'why': '', 'target': {'environment': a.environment,
           'resource_group': a.resource_group, 'name': a.name}, 'commit': a.commit or None,
           'base_date': None, 'rollback': None, 'dependencies': deps, 'notes': notes}
    try:
        declared = json.loads(a.declared_dependencies) if (a.declared_dependencies or '').strip() else []
        if not isinstance(declared, list) or not all(isinstance(x, str) for x in declared):
            raise ValueError('not a JSON array of strings')
    except ValueError as exc:
        return finish(a, doc, INCOMPLETE, 'declared_dependencies could not be read (%s); the check '
                      'cannot judge what this deploy depends on' % exc)
    name = marker_name(a.environment, a.resource_group, a.name)
    try:
        listing = api('actions/artifacts', {'name': name, 'per_page': 100})
        found = [x for x in (listing or {}).get('artifacts') or [] if not x.get('expired')]
        if not found:
            return finish(a, doc, NOT_REQUIRED, 'no rollback of this target is on record (%s)' % name)
        newest = sorted(found, key=lambda x: x.get('created_at') or '')[-1]
        mk = download_json(newest.get('archive_download_url') or '')
        doc['rollback'] = {'run_id': mk.get('rollback_run_id'), 'completed_at': mk.get('completed_at'),
                           'releases': [r.get('release') for r in mk.get('rolled_back') or []],
                           'sequence_result': mk.get('sequence_result')}
        if not a.commit:
            raise Unreadable('the deploy names no commit ($GITHUB_SHA)')
        c = api('commits/%s' % a.commit)
        base = (((c or {}).get('commit') or {}).get('committer') or {}).get('date')
        if not base:
            raise Unreadable('the commit %s carries no committer date' % a.commit[:12])
        doc['base_date'] = base
        if base > (mk.get('completed_at') or ''):
            return finish(a, doc, NOT_REQUIRED, 'this deploy\'s base (commit %s, %s) is newer than the '
                          'rollback of the target by run %s (completed %s): it was built after it'
                          % (a.commit[:12], base, mk.get('rollback_run_id'), mk.get('completed_at')))
        for r in mk.get('rolled_back') or []:
            if not r.get('commit'):
                raise Unreadable('the commit of rolled-back release %s is not on record' % r.get('release'))
            cmp_ = api('compare/%s...%s' % (r['commit'], a.commit))
            status = (cmp_ or {}).get('status')
            if status not in ('ahead', 'identical', 'behind', 'diverged'):
                raise Unreadable('the comparison with %s answered %r' % (r['commit'][:12], status))
            if status in ('ahead', 'identical'):
                deps.append({'kind': 'release lineage', 'ref': a.commit,
                             'what': 'this deploy\'s commit %s is built on commit %s of %s, which was '
                                     'rolled back' % (a.commit[:12], r['commit'][:12], r.get('release')),
                             'state': 'rolled back', 'changes': []})
            if a.image and a.image in (r.get('images') or []):
                deps.append({'kind': 'image', 'ref': a.image,
                             'what': 'this deploy ships %s, the image %s deployed and the rollback '
                                     'removed' % (a.image, r.get('release')),
                             'state': 'rolled back', 'changes': []})
    except Unreadable as exc:
        return finish(a, doc, INCOMPLETE, str(exc))
    for ref in declared:
        for node in mk.get('changed') or []:
            if _matches(ref, node):
                gone = node.get('after') == 'absent'
                deps.append({'kind': 'declared dependency', 'ref': ref, 'id': node.get('id'),
                             'what': '%s %s' % (node.get('id'), 'no longer exists' if gone else
                                                'is no longer the same'),
                             'state': 'no longer exists' if gone else 'changed',
                             'changes': node.get('changes') or []})
    notes.append('checked: release lineage against %d rolled-back release(s), the image, and %d '
                 'declared dependenc(ies) against %d node(s) the rollback changed'
                 % (len(mk.get('rolled_back') or []), len(declared), len(mk.get('changed') or [])))
    if deps:
        return finish(a, doc, REFUSED, 'this deploy depends on what the rollback of the target by run %s '
                      '(completed %s) took out: %d dependenc(ies). Correct the deploy and deploy again'
                      % (mk.get('rollback_run_id'), mk.get('completed_at'), len(deps)))
    return finish(a, doc, NO_DEPENDENCY, 'the check ran against the rollback by run %s and found no '
                  'dependency on what was rolled back' % mk.get('rollback_run_id'))


def report(doc):
    rb = doc.get('rollback') or {}
    out = ['### Rollback dependency check: `%s`' % doc['rollback_check'], '', doc['why'], '']
    if rb:
        out.append('Rollback of `%s/%s` (environment `%s`) by run **%s**, completed %s; rolled back: %s.'
                   % (doc['target']['resource_group'], doc['target']['name'], doc['target']['environment'],
                      rb.get('run_id'), rb.get('completed_at'), ', '.join(rb.get('releases') or []) or 'none'))
        out.append('This deploy: commit `%s` (base %s).' % ((doc.get('commit') or 'none')[:12],
                                                          doc.get('base_date') or 'not read'))
        out.append('')
    if doc['dependencies']:
        out += ['What this deploy would bring back, or stands on, that the rollback changed:', '',
                '| kind | dependency | state | old -> new |', '|---|---|---|---|']
        for d in doc['dependencies']:
            ch = '; '.join('%s %s -> %s' % (p, _short(o), _short(n)) for p, o, n in d['changes'][:4])
            out.append('| %s | %s | %s | %s |' % (d['kind'], d['what'].replace('|', '/'), d['state'],
                                                   (ch or '-').replace('|', '/')))
        out += ['', '**Correct the deploy and deploy again**: rebuild it without the rolled-back '
                'release\'s changes, or restore what it depends on through its own reviewed change. '
                'There is no override (KDEC-023).']
    for n in doc.get('notes') or []:
        out.append('_%s_' % n)
    return '\n'.join(out) + '\n'


def finish(a, doc, outcome, why):
    doc['rollback_check'], doc['why'] = outcome, why
    if outcome == NO_DEPENDENCY:
        doc['why'] = why + ' (no dependency)'
    text = report(doc)
    os.makedirs(os.path.dirname(os.path.abspath(a.out)), exist_ok=True)
    io.open(a.out, 'w', encoding='utf-8').write(json.dumps(doc, indent=1, sort_keys=True))
    if a.summary:
        io.open(a.summary, 'a', encoding='utf-8').write(text)
    print(text)
    one = doc['why'].replace('\n', ' ').replace('::', ': :')
    if outcome in (REFUSED, INCOMPLETE):
        print('::error title=Deploy refused (%s)::%s' % (outcome, one))
    else:
        print('::notice title=Rollback dependency check (%s)::%s' % (outcome, one))
    _out(a.github_output, rollback_check=outcome)
    return 1 if outcome in (REFUSED, INCOMPLETE) else 0


# ----------------------------------------------------------------------------- self-test
def self_test():
    fails = []
    k1, k2 = marker_name('prod', 'rg', 'app'), marker_name('dev', 'rg', 'app')
    if k1 == k2 or not k1.startswith('kit-rollback-marker-app-'):
        fails.append('the marker name does not separate targets: %s %s' % (k1, k2))
    node = {'id': '/subscriptions/0/resourceGroups/g/providers/Microsoft.Network/networkSecurityGroups/n/securityRules/r',
            'hosts': ['kv.vault.example']}
    for ref, want in (('networkSecurityGroups/n/securityRules/r', True), (node['id'].upper(), True),
                      ('@Microsoft.KeyVault(SecretUri=https://kv.vault.example/secrets/x)', True),
                      ('networkSecurityGroups/n/securityRules/other', False)):
        if _matches(ref, node) != want:
            fails.append('%r matched %s' % (ref, not want))
    for f in fails:
        print('SELF-TEST FAILED: ' + f)
    if fails:
        return 2
    print('rollback_hold self-test ok: marker names separate targets; declared dependencies match a '
          'changed node by id, path suffix or host. The full proof is tests/prove_rollback_dependencies.py.')
    return 0


def main(argv):
    if argv[:1] == ['--self-test']:
        return self_test()
    ap = argparse.ArgumentParser(description=__doc__.split('\n')[0])
    sub = ap.add_subparsers(dest='cmd', required=True)
    for name in ('marker', 'check'):
        p = sub.add_parser(name)
        p.add_argument('--environment', default='')
        p.add_argument('--resource-group', default='')
        p.add_argument('--name', default='')
        p.add_argument('--run-id', default='')
        p.add_argument('--out', required=True)
        p.add_argument('--github-output', default='')
        if name == 'marker':
            p.add_argument('--record', required=True)
            p.add_argument('--evidence-root', default='')
            p.add_argument('--run-attempt', default='1')
            p.add_argument('--completed-at', default='')
        else:
            p.add_argument('--commit', default='')
            p.add_argument('--declared-dependencies', default='')
            p.add_argument('--image', default='')
            p.add_argument('--summary', default='')
    a = ap.parse_args(argv)
    return cmd_marker(a) if a.cmd == 'marker' else check(a)


if __name__ == '__main__':
    sys.exit(main(sys.argv[1:]))

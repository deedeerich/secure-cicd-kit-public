"""A stand-in for the slice of Azure the deploy reusables touch. Not a test; the harness's cloud.

    _fake_az.py az   <az arguments...>
    _fake_az.py curl <curl arguments...>

State lives in the JSON file named by fake_az_state and is MUTATED by mutating commands, so a
run's later reads see its earlier writes -- which is what lets a reversal be verified against
"live" state rather than against its own exit code. Every call is appended to fake_az_log.

Fault injection, all in the state file:
    fail                 [prefix...]  matching commands exit 1 before doing anything
    fail_after_mutation  [prefix...]  matching commands fail only once something has been mutated
    apply_then_fail      [prefix...]  matching commands APPLY their change, then exit 1
    unhealthy_images     [image ref]  any endpoint serving one of these answers 503
    second_actor         {after: <prefix>, do: <action>}  another actor changes state once, right
                                      after the first call matching `after` -- the case section
                                      8 of the reconciliation document exists for
                                      (modify_slot_image also takes `image`, and `restart` to
                                      record the platform starting that image)

Only the commands and flags the deploy workflows use are modelled. Anything else exits 2 with
"unmodelled", so a workflow change that reaches for a new command fails the harness loudly
instead of reading an empty answer as a real one.
"""
import io
import json
import os
import sys
import time


def load():
    return json.load(io.open(os.environ['fake_az_state'], encoding='utf-8'))


def save(s):
    io.open(os.environ['fake_az_state'], 'w', encoding='utf-8').write(json.dumps(s, indent=1))


def log(tool, args):
    p = os.environ.get('fake_az_log')
    if p:
        io.open(p, 'a', encoding='utf-8').write(json.dumps([tool] + args) + '\n')


def opt(args, *names, default=None):
    for i, a in enumerate(args):
        if a in names and i + 1 < len(args):
            return args[i + 1]
    return default


def multi(args, name):
    """Values following a flag up to the next flag (az's nargs='+')."""
    out, on = [], False
    for a in args:
        if a == name:
            on = True
            continue
        if on:
            if a.startswith('--') or (a.startswith('-') and len(a) == 2):
                break
            out.append(a)
    return out


QUERY = {}


def emit(obj):
    """JSON by default. A simple dotted --query with -o tsv is honoured; nothing richer is."""
    q = QUERY.get('query')
    # The two JMESPath queries the PRE-CONTRACT Container Apps workflow used, modelled exactly so
    # its defects can be reproduced (red receipts) rather than failing for an unrelated reason.
    legacy = {
        "[?properties.active].{n:name,t:properties.createdTime} | sort_by(@,&t) | [-1].n":
            lambda o: ([r['name'] for r in sorted((r for r in o if r['properties']['active']),
                                                   key=lambda r: r['properties']['createdTime'])]
                       or [None])[-1],
        "sort_by([], &properties.createdTime) | [-1].name":
            lambda o: ([r['name'] for r in sorted(o, key=lambda r: r['properties']['createdTime'])]
                       or [None])[-1],
    }
    if q in legacy:
        v = legacy[q](obj)
        sys.stdout.write(('' if v is None else str(v)) + '\n')
        return
    if q:
        if not all(p.replace('_', '').isalnum() for p in q.split('.')):
            fail('unmodelled --query %r' % q, 2)
        for part in q.split('.'):
            obj = obj.get(part) if isinstance(obj, dict) else None
        if QUERY.get('output') == 'tsv':
            sys.stdout.write(('' if obj is None else str(obj)) + '\n')
            return
    sys.stdout.write(json.dumps(obj) + '\n')


def fail(msg, code=1):
    sys.stderr.write('ERROR: %s\n' % msg)
    sys.exit(code)


def matches(cmd, prefixes):
    return any(cmd.startswith(p) for p in prefixes or [])


# --------------------------------------------------------------------------- container apps
def ca_view(s):
    a = s['containerapp']
    return {'name': a['name'], 'id': a['id'], 'tags': a.get('tags', {}),
            'properties': {'latestRevisionName': a['latestRevisionName'],
                           'configuration': {'activeRevisionsMode': a['revisionMode'],
                                             'ingress': {'fqdn': a['fqdn'],
                                                         'traffic': a['traffic']}},
                           'template': {'containers': [{'image': a['revisions'][a['latestRevisionName']]['image'],
                                                        'env': [{'name': k, 'value': v} for k, v in
                                                                a['revisions'][a['latestRevisionName']]['env'].items()]}]}
                           if a['latestRevisionName'] else {}}}


def rev_view(name, r):
    return {'name': name, 'properties': {
        'active': r['active'], 'createdTime': r['createdTime'], 'fqdn': r['fqdn'],
        'trafficWeight': 0,
        'template': {'containers': [{'image': r['image'],
                                     'env': [{'name': k, 'value': v} for k, v in r['env'].items()]}]}}}


def ca_new_revision(s, image=None, env_set=None):
    a = s['containerapp']
    a['counter'] += 1
    name = '%s--r%d' % (a['name'], a['counter'])
    base = a['revisions'].get(a['latestRevisionName']) or {'image': '', 'env': {}}
    env = dict(base['env'])
    env.update(env_set or {})
    a['revisions'][name] = {'active': True, 'image': image or base['image'], 'env': env,
                            'createdTime': '2026-10-14T00:00:%02dZ' % a['counter'],
                            'fqdn': '%s.revision.example' % name}
    a['latestRevisionName'] = name
    if a['revisionMode'] == 'Single':
        for n, r in a['revisions'].items():
            r['active'] = n == name
        a['traffic'] = [{'latestRevision': True, 'weight': 100}]
    return name


def ca(s, args):
    sub = args[1] if len(args) > 1 else ''
    a = s['containerapp']
    if sub == 'show':
        return emit(ca_view(s))
    if sub == 'update':
        image = opt(args, '--image')
        env_set = dict(x.split('=', 1) for x in multi(args, '--set-env-vars'))
        tags = multi(args, '--tags')
        if tags and not image and not env_set:
            a.setdefault('tags', {}).update(dict(x.split('=', 1) for x in tags))
            return emit(ca_view(s))
        if a['revisionMode'] == 'Multiple' and any(t.get('latestRevision') and t.get('weight', 0) > 0
                                                   for t in a['traffic']):
            # The platform routes the new revision AT ONCE when traffic follows the latest one
            # (observed live 2026-10-15 on a sandbox Container App).
            s['exposed_on_update'] = True
        ca_new_revision(s, image, env_set)
        s['mutated'] = True
        return emit(ca_view(s))
    if sub == 'revision':
        op = args[2]
        if op == 'list':
            # Like the real CLI (observed live 2026-10-15): without --all, an INACTIVE revision
            # is not listed at all -- so a revision this run deactivated vanishes from the read
            # that a later reversal entry takes its ownership stamp from.
            show_all = '--all' in args
            return emit([rev_view(n, r) for n, r in sorted(a['revisions'].items(),
                                                            key=lambda kv: kv[1]['createdTime'])
                         if show_all or r['active']])
        name = opt(args, '--revision')
        if name not in a['revisions']:
            fail('revision %s not found' % name)
        if op == 'show':
            return emit(rev_view(name, a['revisions'][name]))
        if op in ('activate', 'deactivate'):
            a['revisions'][name]['active'] = op == 'activate'
            s['mutated'] = True
            return emit({})
    if sub == 'ingress' and args[2] == 'traffic':
        if args[3] == 'show':
            return emit(a['traffic'])
        if args[3] == 'set':
            if a['revisionMode'] == 'Single':
                fail('Traffic splitting is not supported in single revision mode')
            weights = multi(args, '--revision-weight')
            new = []
            for w in weights:
                n, v = w.rsplit('=', 1)
                if n == 'latest':
                    new.append({'latestRevision': True, 'weight': int(v)})
                else:
                    if n not in a['revisions']:
                        fail('revision %s not found' % n)
                    new.append({'revisionName': n, 'weight': int(v)})
            a['traffic'] = new
            s['mutated'] = True
            return emit(a['traffic'])
    fail('unmodelled containerapp command: %s' % ' '.join(args), 2)


# --------------------------------------------------------------------------- app service
def slot_of(args):
    return opt(args, '--slot', '-s', default='production') or 'production'


def wa(s, args):
    w = s['webapp']
    sub = args[1] if len(args) > 1 else ''
    slot = slot_of(args)
    if slot not in w['slots']:
        fail('slot %s not found' % slot)
    sl = w['slots'][slot]
    if sub == 'show':
        return emit({'name': w['name'], 'id': sl['id'], 'defaultHostName': sl['host'],
                     'tags': sl.get('tags', {}), 'state': 'Running'})
    if sub == 'restart':
        # The platform's container log (what Kudu serves at /api/logs/docker): a restart creates a
        # container from the configured image and, unless injected otherwise, the site starts.
        # Until it starts, the PREVIOUS container keeps answering -- observed live 2026-10-15.
        now = time.strftime('%Y-%m-%dT%H:%M:%S', time.gmtime())
        fx = sl['linuxFxVersion']
        img = fx.split('|', 1)[1] if '|' in fx else ''
        lines = sl.setdefault('docker_log', [])
        if s.get('start_on_request'):
            # An idle site on a plan that unloads it (observed live on F1, run 38867771912): the
            # restart starts NOTHING until a request arrives for the site.
            sl['pending_start'] = img
            return emit({})
        lines.append('%s.1000000Z Creating container with image: %s from registry: x' % (now, img))
        if not s.get('container_never_starts'):
            lines.append('%s.2000000Z Site started.' % now)
        return emit({})
    if sub == 'config':
        if args[2] == 'show':
            return emit({'linuxFxVersion': sl['linuxFxVersion']})
        if args[2] == 'set':
            sl['linuxFxVersion'] = opt(args, '--linux-fx-version', default='')
            s['mutated'] = True
            return emit({'linuxFxVersion': sl['linuxFxVersion']})
        if args[2] == 'container' and args[3] == 'set':
            sl['linuxFxVersion'] = 'DOCKER|' + opt(args, '--container-image-name', '-i')
            s['mutated'] = True
            return emit([])
        if args[2] == 'appsettings' and args[3] == 'set':
            for kv in multi(args, '--settings'):
                k, v = kv.split('=', 1)
                sl.setdefault('appsettings', {})[k] = v
            s['mutated'] = True
            return emit([])
    if sub == 'deployment' and args[2] == 'slot' and args[3] == 'swap':
        src, dst = slot, opt(args, '--target-slot', default='production')
        a, b = w['slots'][src], w['slots'][dst]
        a['linuxFxVersion'], b['linuxFxVersion'] = b['linuxFxVersion'], a['linuxFxVersion']
        a['appsettings'], b['appsettings'] = b.get('appsettings', {}), a.get('appsettings', {})
        a['docker_log'], b['docker_log'] = b.get('docker_log', []), a.get('docker_log', [])
        s['mutated'] = True
        return emit({})
    fail('unmodelled webapp command: %s' % ' '.join(args), 2)


ARM_HOST = 'https://management.azure.com'


def _arm_key(store, path):
    low = path.lower()
    for k in store:
        if k.lower() == low:
            return k
    return None


def arm(s, args):
    """ARM through `az rest` (KDEC-023): GET / PUT / DELETE of a resource id, over state['arm'] =
    {resource id: body}. A GET of a path that is not a resource but whose parent is (a child
    collection: `.../securityRules`) lists the direct children as {"value": [...]}, as ARM does. A
    missing resource answers the way `az rest` does: exit 1, "(ResourceNotFound) ... Not Found"."""
    method = (opt(args, '--method', '-m') or 'get').lower()
    url = opt(args, '--url', '--uri', '-u') or ''
    path = url.split('?', 1)[0]
    if path.startswith(ARM_HOST):
        path = path[len(ARM_HOST):]
    path = path.rstrip('/')
    store = s.setdefault('arm', {})
    k = _arm_key(store, path)
    if method == 'get':
        if k is not None:
            return emit(store[k])
        low = path.lower() + '/'
        kids = [v for kk, v in store.items()
                if kk.lower().startswith(low) and '/' not in kk[len(low):]]
        if kids or _arm_key(store, path.rsplit('/', 1)[0]) is not None:
            return emit({'value': sorted(kids, key=lambda v: str(v.get('id', '')).lower())})
        fail('(ResourceNotFound) The Resource \'%s\' was not found. Not Found' % path)
    if method == 'put':
        body = opt(args, '--body', '-b') or '{}'
        if body.startswith('@'):
            body = io.open(body[1:], encoding='utf-8').read()
        doc = json.loads(body)
        store[k if k is not None else path] = doc
        s['mutated'] = True
        return emit(doc)
    if method == 'delete':
        if k is None:
            fail('(ResourceNotFound) The Resource \'%s\' was not found. Not Found' % path)
        low = k.lower() + '/'
        for kk in [kk for kk in store if kk == k or kk.lower().startswith(low)]:
            del store[kk]
        s['mutated'] = True
        return emit({})
    fail('unmodelled rest method %s' % method, 2)


def rest(s, args):
    """`az rest --method get --url https://<scm host>/api/logs/docker` (a JSON listing) and the log
    file it names (raw text) -- the App Service container log, read with an Entra token."""
    url = opt(args, '--url', '-u') or ''
    if url.startswith('/subscriptions/') or url.startswith(ARM_HOST):
        return arm(s, args)
    host = url.split('://', 1)[-1].split('/', 1)[0]
    for sl in (s.get('webapp') or {}).get('slots', {}).values():
        h = sl['host']
        if host == h.split('.', 1)[0] + '.scm.' + h.split('.', 1)[1]:
            if url.endswith('/api/logs/docker'):
                stamp = time.strftime('%Y-%m-%dT%H:%M:%S.0000000Z', time.gmtime())
                return emit([{'href': 'https://%s/api/vfs/LogFiles/fake_docker.log' % host,
                              'lastUpdated': stamp}])
            if url.endswith('_docker.log'):
                sys.stdout.write('\n'.join(sl.get('docker_log') or []) + '\n')
                return
    fail('unmodelled rest url %s' % url, 2)


def tag(s, args):
    if args[1] != 'update':
        fail('unmodelled tag command', 2)
    rid = opt(args, '--resource-id')
    tags = dict(x.split('=', 1) for x in multi(args, '--tags'))
    target = find_by_id(s, rid)
    if target is None:
        fail('resource %s not found' % rid)
    target.setdefault('tags', {}).update(tags)
    s['mutated'] = True
    return emit({'properties': {'tags': target['tags']}})


def resource(s, args):
    """`az resource list --resource-group RG [--tag k=v]` and `az resource delete --ids ID`,
    over state['resources'] = [{id, resource_group, tags}] -- the test harness's scope."""
    res = s.setdefault('resources', [])
    if args[1] == 'list':
        rg = opt(args, '--resource-group', '-g')
        tag = opt(args, '--tag')
        out = [r for r in res if r['resource_group'] == rg]
        if tag:
            k, v = tag.split('=', 1)
            out = [r for r in out if (r.get('tags') or {}).get(k) == v]
        return emit(out)
    if args[1] == 'delete':
        ids = multi(args, '--ids')
        if matches('resource delete', s.get('delete_fails')):
            fail('injected: delete refused')
        s['resources'] = [r for r in res if r['id'] not in ids]
        s['mutated'] = True
        return emit({})
    fail('unmodelled resource command', 2)


def find_by_id(s, rid):
    if 'containerapp' in s and s['containerapp']['id'] == rid:
        return s['containerapp']
    for sl in (s.get('webapp') or {}).get('slots', {}).values():
        if sl['id'] == rid:
            return sl
    return None


# --------------------------------------------------------------------------- endpoints
def serving_image(s, host):
    if 'containerapp' in s:
        a = s['containerapp']
        if host == a['fqdn']:
            imgs = []
            for t in a['traffic']:
                if t.get('weight', 0) <= 0:
                    continue
                n = a['latestRevisionName'] if t.get('latestRevision') else t.get('revisionName')
                r = a['revisions'].get(n)
                if not r or not r['active']:
                    return None
                imgs.append(r['image'])
            return imgs
        for n, r in a['revisions'].items():
            if host == r['fqdn']:
                return [r['image']] if r['active'] else None
    for sl in (s.get('webapp') or {}).get('slots', {}).values():
        if host == sl['host']:
            fx = sl['linuxFxVersion']
            return [fx.split('|', 1)[1]] if '|' in fx else None
    return None


def curl(s, args):
    url = [a for a in args if a.startswith('http')]
    host = url[0].split('://', 1)[1].split('/', 1)[0] if url else ''
    for sl in (s.get('webapp') or {}).get('slots', {}).values():
        if host == sl['host'] and sl.get('pending_start') is not None:
            now = time.strftime('%Y-%m-%dT%H:%M:%S', time.gmtime())
            sl.setdefault('docker_log', []).append(
                '%s.1000000Z Creating container with image: %s from registry: x'
                % (now, sl.pop('pending_start')))
            sl['docker_log'].append('%s.2000000Z Site started.' % now)
    if host in (s.get('healthy_hosts') or []):
        # A host the scenario declares answering (an ARM-modelled app with no image model).
        sys.stdout.write('200')
        return
    imgs = serving_image(s, host)
    if host in (s.get('unhealthy_hosts') or []):
        # The consumer-facing name fails while the revision's own name answers: serving fails
        # AFTER health and the traffic move.
        sys.stdout.write('503')
        return
    if imgs is None or not imgs:
        code = '503' if imgs == [] or imgs is None else '200'
    else:
        code = '503' if any(i in (s.get('unhealthy_images') or []) for i in imgs) else '200'
    sys.stdout.write(code)


def second_actor(s, cmd):
    sa = s.get('second_actor')
    if not sa or sa.get('done') or not cmd.startswith(sa['after']):
        return
    sa['done'] = True
    do = sa['do']
    a = s.get('containerapp')
    if do == 'modify_new_revision_traffic':
        # Another actor sends a share of traffic to the newest revision -- it now DEPENDS on it.
        a['traffic'].append({'revisionName': a['latestRevisionName'], 'weight': 0, 'label': 'canary'})
    elif do == 'new_revision_by_other':
        ca_new_revision(s, 'registry.example/other@sha256:' + 'e' * 64,
                        {'release_ownership_stamp': 'release_id=someone-else'})
    elif do == 'modify_slot_image':
        w = s['webapp']
        sl = w['slots'][sa.get('slot', 'production')]
        img = sa.get('image') or 'registry.example/other@sha256:' + 'f' * 64
        sl['linuxFxVersion'] = 'DOCKER|' + img
        if sa.get('restart'):
            # A container change the platform applies by restarting the site: its container log
            # then records a container created from the other actor's image, and started.
            now = time.strftime('%Y-%m-%dT%H:%M:%S', time.gmtime())
            sl.setdefault('docker_log', []).append(
                '%s.3000000Z Creating container with image: %s from registry: x' % (now, img))
            sl['docker_log'].append('%s.4000000Z Site started.' % now)
    elif do == 'retag_new_revision':
        r = a['revisions'][a['latestRevisionName']]
        r['env']['release_ownership_stamp'] = 'release_id=someone-else'


def main():
    tool, args = sys.argv[1], sys.argv[2:]
    log(tool, args)
    s = load()
    if tool == 'curl':
        curl(s, args)
        cmd = 'curl'
        second_actor(s, cmd)
        save(s)
        return
    QUERY['query'] = opt(args, '--query')
    QUERY['output'] = opt(args, '-o', '--output')
    cmd = ' '.join(a for a in args[:4] if not a.startswith('-'))
    if matches(cmd, s.get('fail')):
        fail('injected failure for "%s" (throttled / permission denied)' % cmd)
    if s.get('mutated') and matches(cmd, s.get('fail_after_mutation')):
        fail('injected post-mutation failure for "%s"' % cmd)
    try:
        if args[0] == 'containerapp':
            ca(s, args)
        elif args[0] == 'webapp':
            wa(s, args)
        elif args[0] == 'tag':
            tag(s, args)
        elif args[0] == 'rest':
            rest(s, args)
        elif args[0] == 'resource':
            resource(s, args)
        else:
            fail('unmodelled az command: %s' % ' '.join(args), 2)
    except SystemExit:
        save(s) if s.get('mutated') else None
        raise
    second_actor(s, cmd)
    save(s)
    if matches(cmd, s.get('apply_then_fail')):
        fail('injected failure AFTER applying "%s" (the change took; the caller cannot tell)' % cmd)


if __name__ == '__main__':
    main()
    time.sleep(0)

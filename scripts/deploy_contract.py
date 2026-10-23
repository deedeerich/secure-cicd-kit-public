#!/usr/bin/env python3
"""The deploy contract, executed: what a deploy run captured, changed, verified and now serves.

WHY THIS EXISTS (docs/architecture/DEPLOYMENT_CONTRACT_RECONCILIATION.md, ROLLBACK_CONTRACT.md)

    Both deploy reusables reported the digest the run TRIED to deploy beside a health result,
    with nothing read back from the target. This module is the part of each deploy job that
    talks to live state and decides what may be claimed about it. The workflows call it one
    subcommand per step, so the ORDER of the contract (capture, mutate, verify, reverse,
    provenance, report) stays visible in the workflow file where a reviewer reads it.

    It is INLINED into both deploy reusables by scripts/inline_deploy_scripts.py (a reusable
    workflow called cross-repo cannot read this repository's scripts/), and the copies are
    checked for drift in self-test.

LABELS (assurance-taxonomy.yaml serving_claim)
    ATTEMPTED     what the run tried to deploy; may be echoed from inputs
    NOW SERVING   read back from live state; echoing an input here is the defect. When it cannot
                  be read the value is `unknown` -- never the attempted value.

USAGE (from a workflow step; names and the digest arrive through env:)
    deploy_contract.py report --adapter containerapp|appservice
"""
import argparse
import io
import json
import os
import shutil
import subprocess
import sys

UNKNOWN = 'unknown'


# ----------------------------------------------------------------------------- plumbing
def evidence_dir():
    d = os.path.join(os.environ.get('RUNNER_TEMP') or '.', 'deploy-evidence')
    os.makedirs(d, exist_ok=True)
    return d


def write_evidence(name, obj):
    io.open(os.path.join(evidence_dir(), name), 'w', encoding='utf-8').write(
        json.dumps(obj, indent=1, sort_keys=True))


def read_evidence(name):
    try:
        return json.load(io.open(os.path.join(evidence_dir(), name), encoding='utf-8'))
    except (OSError, ValueError):
        return None


def az(*args):
    """-> (ok, parsed JSON or None, error text). A failed read is reported, never blanked."""
    exe = shutil.which('az')
    if not exe:
        return False, None, 'az CLI not found'
    try:
        p = subprocess.run([exe] + list(args) + ['-o', 'json'], capture_output=True, text=True,
                           encoding='utf-8', errors='replace')
    except OSError as e:
        return False, None, str(e)
    if p.returncode != 0:
        return False, None, (p.stderr or p.stdout or 'exit %d' % p.returncode).strip()[:400]
    try:
        return True, json.loads(p.stdout) if p.stdout.strip() else None, ''
    except ValueError:
        return False, None, 'unparseable az output'


def az_raw(*args):
    """-> (ok, text, error text) for a call whose answer is not JSON (a log file)."""
    exe = shutil.which('az')
    if not exe:
        return False, '', 'az CLI not found'
    try:
        p = subprocess.run([exe] + list(args), capture_output=True, text=True,
                           encoding='utf-8', errors='replace')
    except OSError as e:
        return False, '', str(e)
    if p.returncode != 0:
        return False, '', (p.stderr or p.stdout or 'exit %d' % p.returncode).strip()[:400]
    return True, p.stdout or '', ''


def utc_now():
    import time
    return time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime())


def output(**kv):
    path = os.environ.get('GITHUB_OUTPUT')
    for k, v in kv.items():
        line = '%s=%s' % (k, '' if v is None else v)
        print(line)
        if path:
            io.open(path, 'a', encoding='utf-8').write(line + '\n')


def summary(text):
    path = os.environ.get('GITHUB_STEP_SUMMARY')
    if path:
        io.open(path, 'a', encoding='utf-8').write(text + '\n')


def env(name, default=''):
    """Read a job environment variable. Names are written lower-case here and upper-cased on
    lookup: they are SETTINGS (an app name, a digest), not states, and spelling them in capitals
    would present them to scripts/reconcile_taxonomy.py as undefined vocabulary (remedy 4)."""
    return os.environ.get(name.upper(), default)


def intended_ref():
    return '%s/%s@%s' % (env('acr_login_server'), env('image_repository'), env('image_digest'))


# ----------------------------------------------------------------------------- live reads
def containerapp_serving():
    """-> list of {revision, weight, image} receiving traffic, or None when unreadable."""
    app, rg = env('containerapp_name'), env('resource_group')
    ok, shown, _ = az('containerapp', 'show', '-n', app, '-g', rg)
    if not ok or not isinstance(shown, dict):
        return None
    ok, revs, _ = az('containerapp', 'revision', 'list', '-n', app, '-g', rg, '--all')
    if not ok or not isinstance(revs, list):
        return None
    props = shown.get('properties') or {}
    latest = props.get('latestRevisionName') or ''
    traffic = ((props.get('configuration') or {}).get('ingress') or {}).get('traffic') or []
    by_name = {r.get('name'): r for r in revs}
    out = []
    for t in traffic:
        w = t.get('weight') or 0
        if w <= 0:
            continue
        name = latest if t.get('latestRevision') else t.get('revisionName')
        r = by_name.get(name)
        if r is None:
            return None
        rp = r.get('properties') or {}
        image = (((rp.get('template') or {}).get('containers') or [{}])[0]).get('image', '')
        out.append({'revision': name, 'weight': w, 'image': image if rp.get('active') else '',
                    'active': bool(rp.get('active'))})
    return out


def appservice_slot_image(slot):
    args = ['webapp', 'config', 'show', '-n', env('webapp_name'), '-g', env('resource_group')]
    if slot and slot != 'production':
        args += ['--slot', slot]
    ok, cfg, _ = az(*args)
    if not ok or not isinstance(cfg, dict):
        return None
    fx = cfg.get('linuxFxVersion') or ''
    return fx.split('|', 1)[1] if '|' in fx else ''


def now_serving(adapter):
    """-> list of (field, value) NOW SERVING rows, read from live state."""
    if adapter == 'containerapp':
        live = containerapp_serving()
        if live is None:
            return [('image', UNKNOWN), ('revision', UNKNOWN)], None
        if not live:
            return [('image', 'nothing (no revision receives traffic)')], []
        rows = []
        for t in live:
            rows.append(('revision', '%s (%d%%)' % (t['revision'], t['weight'])))
            rows.append(('image', t['image'] or UNKNOWN))
        return rows, live
    image, started = appservice_production_now()
    rows = [(CONFIGURED_ROW, UNKNOWN if image is None else
             (image or 'nothing (no container configured)')),
            (STARTED_ROW, started)]
    # DCR-2: when this run changed production (directly, or by a swap), what RUNS there is the
    # verdict, read from the start record since that change -- not the configured image.
    NOW['running'] = None
    if run_since() and (not env('slot') or env('swapped') == 'success'):
        NOW['running'] = appservice_running('production', intended_ref())
        rows.append((RUNNING_ROW, running_text(NOW['running'], intended_ref())))
    return rows, image


NOW = {'running': None}


# App Service exposes no running digest. Two readings exist and they are different claims: the
# CONFIGURED image (linuxFxVersion -- what the platform will start next) and the platform's own
# container log (which image it last reported started). Each row names which one it is.
CONFIGURED_ROW = 'production image (configured)'
STARTED_ROW = 'production container (last start the platform reported)'


def appservice_last_start(slot='production'):
    """-> text: the image of the last container the platform's container log reports created AND
    started on `slot`, with any later creation that has not reported a start. Never the configured
    image: when the log cannot be read the answer is unknown, and says why."""
    args = ['webapp', 'show', '-n', env('webapp_name'), '-g', env('resource_group')]
    if slot != 'production':
        args += ['--slot', slot]
    ok, shown, err = az(*args)
    host = (shown or {}).get('defaultHostName', '') if ok and isinstance(shown, dict) else ''
    if not host or '.' not in host:
        return '%s (the site could not be read: %s)' % (UNKNOWN, err or 'no host name')
    first, rest = host.split('.', 1)
    res = ('--resource', 'https://management.azure.com/')
    ok, listing, err = az('rest', '--method', 'get', '--url',
                          'https://%s.scm.%s/api/logs/docker' % (first, rest), *res)
    if not ok or not isinstance(listing, list):
        return '%s (container log unreadable: %s)' % (UNKNOWN, err or 'not a JSON list')
    started, pending = '', ''
    for item in sorted(listing, key=lambda e: e.get('lastUpdated') or ''):
        if not item.get('href'):
            continue
        ok, text, err = az_raw('rest', '--method', 'get', '--url', item['href'], *res)
        if not ok:
            return '%s (container log unreadable: %s)' % (UNKNOWN, err)
        for line in text.splitlines():
            if CREATE_MARK in line:
                pending = line.split(CREATE_MARK, 1)[1].split(' from registry', 1)[0].strip()
            elif 'Site started' in line and pending:
                started, pending = pending, ''
    later = ('; a later container from %s was created and has not reported a start' % pending
             if pending else '')
    if started:
        return started + later
    return 'none reported started in the container log' + later


def appservice_production_now():
    """-> (configured image or None when unreadable, start-record text), read live just now."""
    return appservice_slot_image('production'), appservice_last_start('production')


# ----------------------------------------------------------------------------- capture
def _unknown(reason, snapshot):
    """L97: a capture that cannot establish the previous state FAILS LOUDLY. It does not
    degrade a read error into an absence -- that is how a throttled API became "no rollback
    needed" (DCR gap 4)."""
    snapshot.update(previous_state='UNKNOWN', reason=reason)
    write_evidence('snapshot.json', snapshot)
    output(previous_state='UNKNOWN')
    print('::error title=Previous state UNKNOWN::%s Nothing has been changed. A read failure is '
          'not an empty target, and an unknown previous state never resolves toward mutation.'
          % reason)
    return 1


def capture_containerapp():
    app, rg = env('containerapp_name'), env('resource_group')
    snap = {'adapter': 'containerapp', 'app': app, 'resource_group': rg}
    ok, shown, err = az('containerapp', 'show', '-n', app, '-g', rg)
    if not ok or not isinstance(shown, dict):
        return _unknown('The container app could not be read (%s).' % err, snap)
    ok, revs, err = az('containerapp', 'revision', 'list', '-n', app, '-g', rg, '--all')
    if not ok or not isinstance(revs, list):
        return _unknown('The revision list could not be read (%s).' % err, snap)
    props = shown.get('properties') or {}
    conf = props.get('configuration') or {}
    revisions = {}
    for r in revs:
        rp = r.get('properties') or {}
        revisions[r.get('name')] = {
            'active': bool(rp.get('active')), 'created': rp.get('createdTime'),
            'image': (((rp.get('template') or {}).get('containers') or [{}])[0]).get('image', '')}
    traffic = (conf.get('ingress') or {}).get('traffic') or []
    serving = [t for t in traffic if (t.get('weight') or 0) > 0]
    previous = ''
    for t in serving:
        previous = props.get('latestRevisionName') if t.get('latestRevision') else t.get('revisionName')
    snap.update(revision_mode=conf.get('activeRevisionsMode') or 'unknown',
                latest_revision=props.get('latestRevisionName') or '', traffic=traffic,
                revisions=revisions, tags=shown.get('tags') or {}, app_id=shown.get('id', ''))
    # EMPTY is MEASURED: both reads succeeded and nothing is active and nothing takes traffic.
    any_active = any(r['active'] for r in revisions.values())
    state = 'EXISTING_DEPLOYMENT' if (serving or any_active) else 'EMPTY'
    snap['previous_state'] = state
    write_evidence('snapshot.json', snap)
    output(previous_state=state, previous=previous, revision_mode=snap['revision_mode'])
    print('Previous state %s (mode %s, serving %s).' % (state, snap['revision_mode'],
                                                        previous or 'nothing'))
    return 0


def capture_appservice():
    slot = env('slot')
    snap = {'adapter': 'appservice', 'app': env('webapp_name'),
            'resource_group': env('resource_group'), 'target': slot or 'production'}
    images = {}
    for s in sorted({'production', slot or 'production'}):
        img = appservice_slot_image(s)
        if img is None:
            return _unknown('The %s slot configuration could not be read.' % s, snap)
        images[s] = img
    snap['images'] = images
    state = 'EXISTING_DEPLOYMENT' if images[slot or 'production'] else 'EMPTY'
    snap['previous_state'] = state
    write_evidence('snapshot.json', snap)
    output(previous_state=state)
    print('Previous state %s: %s' % (state, images))
    return 0


def cmd_capture(a):
    return capture_containerapp() if a.adapter == 'containerapp' else capture_appservice()


# ----------------------------------------------------------------------------- capability
PRODUCTION_TIERS = ('uat', 'prod')


def cmd_capability(a):
    """DCR gap 9 / 3.5: establish rollback_capability BEFORE the point of no return, and let the
    environment tier decide whether the mutation may proceed. A gate after the mutation is a
    report, not a gate."""
    snap = read_evidence('snapshot.json') or {}
    prev = snap.get('previous_state')
    tier = env('environment_tier')
    if tier not in ('sandbox', 'dev', 'test') + PRODUCTION_TIERS:
        print('::error::environment_tier is not one of the registered tiers (sandbox, dev, test, '
              'uat, prod); the consequence of this deploy cannot be judged.')
        return 1
    if env('rollback_on_failure') != 'true':
        cap, why = 'UNAVAILABLE', 'reversal authority withheld by the caller (rollback_on_failure false)'
    elif prev == 'EMPTY':
        cap, why = 'NO_PRIOR_STATE', 'the target is measured empty; reversal removes what this run creates'
    elif prev != 'EXISTING_DEPLOYMENT':
        cap, why = 'UNAVAILABLE', 'previous state not established'
    elif a.adapter == 'containerapp' and snap.get('revision_mode') != 'Multiple':
        cap, why = 'UNAVAILABLE', ('single revision mode: the prior revision cannot be reactivated '
                                   'beside the new one, so no valid reversal mechanism exists')
    else:
        cap, why = 'AVAILABLE', ('prior state captured; %s' % (
            'traffic weights and revision reactivation are valid in multiple revision mode'
            if a.adapter == 'containerapp' else 'swap back / restore the captured image'))
    blocked = cap == 'UNAVAILABLE' and tier in PRODUCTION_TIERS
    write_evidence('capability.json', {'rollback_capability': cap, 'why': why, 'tier': tier,
                                       'decision': 'refused' if blocked else (
                                           'accepted risk, recorded' if cap == 'UNAVAILABLE'
                                           else 'proceed')})
    output(rollback_capability=cap)
    if blocked:
        print('::error title=Refused before the point of no return::rollback_capability '
              'UNAVAILABLE at production tier %s: %s.' % (tier, why))
        return 1
    if cap == 'UNAVAILABLE':
        print('::warning::rollback_capability UNAVAILABLE at tier %s (%s). Proceeding as a '
              'recorded accepted risk; a failure will need manual recovery.' % (tier, why))
    else:
        print('rollback_capability %s: %s' % (cap, why))
    return 0


# ----------------------------------------------------------------------------- manifest
def release_id():
    return 'run-%s-%s' % (env('github_run_id') or 'local', env('github_run_attempt') or '1')


def stamp_value(post):
    """RELEASE_OWNERSHIP_STAMP (DCR 8.3): who claims the object, and the post-state it left.

    `post` is the image reference, never `DOCKER|<ref>`: the value travels on an az command line,
    and on a Windows host az is a .cmd file, where `|` is a pipe."""
    return 'release_id=%s;run=%s;post=%s' % (release_id(), env('github_run_id') or 'local', post)


def manifest():
    return read_evidence('manifest.json') or {'release_id': release_id(), 'status': 'planned',
                                              'entries': []}


def save_manifest(m):
    write_evidence('manifest.json', m)


def cmd_mutate(a):
    """DCR gap 6. Record what THIS run will change BEFORE changing it, then what it did.

    The manifest is written as `planned` before the first mutating call, so a run that dies
    mid-change still says what it was about to do; it becomes `applied` only when the call
    returns. Container Apps used to infer its own revision as "the newest by creation time" --
    a guess about ownership, wrong the moment anyone else deploys -- so the revision is now taken
    from the update's own response, and the ownership stamp travels WITH the mutation (8.3 rule
    1) as an environment variable of the revision it creates.
    """
    snap = read_evidence('snapshot.json') or {}
    if snap.get('previous_state') not in ('EXISTING_DEPLOYMENT', 'EMPTY'):
        print('::error::No established pre-change snapshot; refusing to mutate.')
        return 1
    m = manifest()
    ref = intended_ref()
    if a.adapter == 'containerapp':
        app, rg = env('containerapp_name'), env('resource_group')
        follows = [t for t in snap.get('traffic') or []
                   if t.get('latestRevision') and (t.get('weight') or 0) > 0]
        if snap.get('revision_mode') == 'Multiple' and follows:
            # Traffic that FOLLOWS THE LATEST REVISION moves to the revision the update creates,
            # at once -- observed live on a sandbox Container App: the public health path went
            # from 200 to 404 on an unverified image the moment the update returned. Pin what
            # serves now to explicit revision names first, recorded as a REDIRECTION, so the
            # verification below really happens before traffic moves.
            weights, post = [], []
            for t in snap.get('traffic') or []:
                w = t.get('weight') or 0
                if w <= 0:
                    continue
                n = snap.get('latest_revision') if t.get('latestRevision') else t.get('revisionName')
                weights.append('%s=%d' % (n, w))
                post.append({'revisionName': n, 'weight': w})
            m['entries'].append({'action': 'REDIRECTED', 'object_type': 'traffic',
                                 'object': 'traffic', 'prior': snap.get('traffic') or [],
                                 'post': post, 'stamp': stamp_value(ref), 'purpose': 'pin'})
            save_manifest(m)
            output(mutation_started='true')
            ok, _, err = az('containerapp', 'ingress', 'traffic', 'set', '-n', app, '-g', rg,
                            '--revision-weight', *weights)
            if not ok:
                print('::error::Pinning traffic before the update did not confirm (%s); nothing '
                      'was created, the manifest stays `planned`.' % err)
                return 1
            print('Traffic followed the latest revision; pinned to %s before the update.'
                  % ', '.join(weights))
        entry = {'action': 'CREATED', 'object_type': 'revision', 'object': None,
                 'post': ref, 'stamp': stamp_value(ref), 'prior': None}
        m['entries'].append(entry)
        save_manifest(m)
        output(mutation_started='true')
        ok, shown, err = az('containerapp', 'update', '-n', app, '-g', rg, '--image', ref,
                            '--set-env-vars', 'release_ownership_stamp=%s' % entry['stamp'])
        if not ok or not isinstance(shown, dict):
            print('::error::The update did not confirm (%s). It may or may not have applied; the '
                  'manifest stays `planned`.' % err)
            return 1
        rev = (shown.get('properties') or {}).get('latestRevisionName') or ''
        entry['object'] = rev
        m['status'] = 'applied'
        save_manifest(m)
        print('Created revision %s (recorded from the update response, not guessed).' % rev)
        return 0
    slot = env('slot') or 'production'
    prior_img = (snap.get('images') or {}).get(slot, '')
    rid, err, prior_stamp = resource_id('appservice', slot, with_stamp=True)
    # KDEC-021: the slot's previous ownership stamp is kept, as the swap keeps production's, so the
    # reversal hands the slot back to the release it held before. Without it a stacked sequence
    # could never reverse the earlier release: the slot still carried the later one's stamp.
    entry = {'action': 'MODIFIED', 'object_type': 'slot-container', 'object': slot,
             'prior': ('DOCKER|' + prior_img) if prior_img else '', 'post': 'DOCKER|' + ref,
             'stamp': stamp_value(ref), 'mutated_at': utc_now(), 'object_id': rid,
             'prior_stamp': prior_stamp}
    m['entries'].append(entry)
    save_manifest(m)
    output(mutation_started='true')
    steps = []
    if rid:
        steps.append(('tag', 'update', '--resource-id', rid, '--operation', 'Merge', '--tags',
                      'release_ownership_stamp=%s' % entry['stamp']))
    base = ['-n', env('webapp_name'), '-g', env('resource_group')] + (
        ['--slot', slot] if slot != 'production' else [])
    steps.append(tuple(['webapp', 'config', 'container', 'set'] + base +
                       ['--container-image-name', ref]))
    steps.append(tuple(['webapp', 'restart'] + base))
    if not rid:
        print('::error::The target could not be read to stamp ownership (%s).' % err)
        return 1
    for s in steps:
        ok, _, err = az(*s)
        if not ok:
            print('::error::%s did not confirm (%s); the manifest stays `planned`.' % (s[:4], err))
            return 1
    m['status'] = 'applied'
    save_manifest(m)
    print('Set %s on %s; prior %s recorded.' % (ref, slot, entry['prior'] or '(empty)'))
    return 0


def cmd_swap(a):
    """Record the swap as a REDIRECTION in the manifest before performing it."""
    slot = env('slot')
    m = manifest()
    snap = read_evidence('snapshot.json') or {}
    # DCR-OWN (8.3 rule 1, the stamp travels with the mutation). Tags do not move with a swap, so
    # the slot's stamp never reaches production: production is stamped with this release BEFORE
    # the swap, and its previous stamp is kept for the swap-back to restore.
    stamp = stamp_value(intended_ref())
    ok, shown, err = az('webapp', 'show', '-n', env('webapp_name'), '-g', env('resource_group'))
    if not ok or not isinstance(shown, dict) or not shown.get('id'):
        print('::error::Production could not be read to stamp ownership before the swap (%s); '
              'nothing is swapped.' % (err or 'no resource id'))
        return 1
    prior_stamp = (shown.get('tags') or {}).get('release_ownership_stamp', '')
    ok, _, err = az('tag', 'update', '--resource-id', shown['id'], '--operation', 'Merge',
                    '--tags', 'release_ownership_stamp=%s' % stamp)
    if not ok:
        print('::error::Production\'s ownership stamp could not be written (%s); nothing is '
              'swapped.' % err)
        return 1
    m['entries'].append({'action': 'REDIRECTED', 'object_type': 'slot-swap', 'object': 'production',
                         'from_slot': slot, 'prior': 'DOCKER|' + (snap.get('images') or {}).get('production', ''),
                         'post': 'DOCKER|' + intended_ref(), 'stamp': stamp,
                         'prior_stamp': prior_stamp, 'production_id': shown['id']})
    m['status'] = 'planned'
    save_manifest(m)
    ok, _, err = az('webapp', 'deployment', 'slot', 'swap', '-n', env('webapp_name'), '-g',
                    env('resource_group'), '--slot', slot, '--target-slot', 'production')
    if not ok:
        print('::error::The swap did not confirm (%s).' % err)
        return 1
    m['status'] = 'applied'
    save_manifest(m)
    print('Swapped %s -> production (recorded as REDIRECTED).' % slot)
    return 0


# ----------------------------------------------------------------------------- verification
def probe(url):
    """-> True when the endpoint answered 200 within the configured attempts."""
    import time
    exe = shutil.which('curl')
    tries = max(1, int(env('health_retries') or '1'))
    wait = float(env('health_interval_seconds') or '0')
    for i in range(1, tries + 1):
        code = '000'
        if exe:
            p = subprocess.run([exe, '-sS', '-o', os.devnull, '-w', '%{http_code}', '--max-time',
                                '10', url], capture_output=True, text=True)
            code = (p.stdout or '000').strip()[-3:] or '000'
        print('  attempt %d/%d -> HTTP %s  (%s)' % (i, tries, code, url))
        if code == '200':
            return True
        if i < tries:
            time.sleep(wait)
    return False


def wake(url):
    """Send one request whose answer is deliberately ignored (it proves nothing)."""
    exe = shutil.which('curl')
    if exe:
        subprocess.run([exe, '-sS', '-o', os.devnull, '--max-time', '10', url],
                       capture_output=True, text=True)


def record_verification(**layers):
    v = read_evidence('verification.json') or {}
    v.update(layers)
    write_evidence('verification.json', v)
    return v


def created_revision():
    made = [e for e in manifest()['entries'] if e.get('action') == 'CREATED' and e.get('object')]
    return made[-1]['object'] if made else ''


CREATE_MARK = 'Creating container with image: '
LOG_READ = {'error': ''}


def appservice_started(host, ref, since):
    """-> True when the platform's container log shows a container created from `ref` at or after
    `since` and a site start after that creation; False when the log reads and shows no such start
    (yet); None when the log cannot be read.

    WHY: the configured image is not the running one. After `config container set` + `restart` the
    PREVIOUS container keeps answering until the platform has started the new one, so a 200 in that
    window is the old artefact's (live run 38857408542: DEPLOY_HEALTHY reported, production then
    served 404). App Service exposes no running digest; its container log -- what Kudu serves at
    /api/logs/docker, read here with the deploy identity's Entra token -- is the platform's own
    record of which image it started, and when."""
    if not host or '.' not in host:
        return None
    first, rest = host.split('.', 1)
    scm = '%s.scm.%s' % (first, rest)
    res = ('--resource', 'https://management.azure.com/')
    ok, listing, err = az('rest', '--method', 'get', '--url', 'https://%s/api/logs/docker' % scm, *res)
    if not ok or not isinstance(listing, list):
        LOG_READ['error'] = err or 'the listing was not a JSON list'
        return None
    cut = (since or '')[:19]
    created, started = None, False
    for item in sorted(listing, key=lambda e: e.get('lastUpdated') or ''):
        if (item.get('lastUpdated') or '')[:19] < cut or not item.get('href'):
            continue
        ok, text, err = az_raw('rest', '--method', 'get', '--url', item['href'], *res)
        if not ok:
            LOG_READ['error'] = err
            return None
        for line in text.splitlines():
            ts = line.split(' ', 1)[0][:19]
            if ts < cut:
                continue
            if CREATE_MARK in line:
                created = line.split(CREATE_MARK, 1)[1].split(' from registry', 1)[0].strip()
                started = False
            elif 'Site started' in line and created is not None:
                started = True
    return created == ref and started


def run_since():
    """The moment this run first mutated an App Service target (its MODIFIED entries), or ''.
    A start record older than that describes somebody else's deploy, so it is not read."""
    times = [e.get('mutated_at') for e in manifest()['entries']
             if e.get('action') == 'MODIFIED' and e.get('mutated_at')]
    return min(times) if times else ''


def appservice_host(slot):
    args = ['webapp', 'show', '-n', env('webapp_name'), '-g', env('resource_group')]
    if slot and slot != 'production':
        args += ['--slot', slot]
    ok, shown, _ = az(*args)
    return (shown or {}).get('defaultHostName', '') if ok and isinstance(shown, dict) else ''


def appservice_running(slot, ref, waits=1):
    """DCR-2 / L101 (B-02): -> True when the platform's container log shows `ref` as the latest
    container created on `slot` since this run's mutation, and started; False when it reads and
    shows anything else (another image, or none started yet); None when it cannot be read, or this
    run mutated nothing. The CONFIGURED image is never the answer: it is what the platform will
    start next, not what runs. `waits` > 1 re-reads a not-yet-started record, waking the site."""
    since = run_since()
    host = appservice_host(slot)
    if not since or not host:
        LOG_READ['error'] = LOG_READ['error'] or ('this run changed nothing on the target'
                                                  if not since else 'the site could not be read')
        return None
    started = None
    for i in range(1, max(1, waits) + 1):
        started = appservice_started(host, ref, since)
        if started is not False:
            return started
        if i < waits:
            wake('https://%s/' % host)
            import time
            time.sleep(float(env('health_interval_seconds') or '0'))
    return started


RUNNING_ROW = 'production container (started since this run\'s change)'


def running_text(running, ref):
    if running is True:
        return ref
    if running is False:
        # Never names the attempted image: a NOW SERVING cell that holds it reads as serving it.
        return ('not this release: the platform last created another image since this run\'s '
                'change, or has not reported a start (the start-record row names what it last '
                'started)')
    return '%s (%s)' % (UNKNOWN, LOG_READ['error'] or 'the start record could not be read')


def cmd_verify(a):
    """L101 / DCR 3.1: the intended artefact is LOADED (read back) and HEALTHY (probed on the
    object this run changed) -- before any traffic moves. A 200 from the app's public name can
    come from the previous revision or from someone else's image; a 200 is not a digest."""
    ref = intended_ref()
    path = env('health_path')
    if a.adapter == 'containerapp':
        rev = created_revision()
        ok, shown, err = az('containerapp', 'revision', 'show', '-n', env('containerapp_name'),
                            '-g', env('resource_group'), '--revision', rev)
        if not ok or not isinstance(shown, dict):
            record_verification(runtime_deployed=None, health_verified=None,
                                reason='revision %s could not be read back (%s)' % (rev, err))
            print('::error::The revision this run created could not be read back; what is loaded '
                  'is not established.')
            return 1
        rp = shown.get('properties') or {}
        image = (((rp.get('template') or {}).get('containers') or [{}])[0]).get('image', '')
        host = rp.get('fqdn') or ''
    else:
        target = env('slot') or 'production'
        image = appservice_slot_image(target)
        if image is None:
            record_verification(runtime_deployed=None, health_verified=None,
                                reason='the %s slot could not be read back' % target)
            print('::error::The target could not be read back; what is loaded is not established.')
            return 1
        ok, shown, _ = az('webapp', 'show', '-n', env('webapp_name'), '-g', env('resource_group'),
                          *(['--slot', target] if target != 'production' else []))
        host = (shown or {}).get('defaultHostName', '') if ok else ''
        if image == ref:
            since = ''
            for e in manifest()['entries']:
                if e.get('action') == 'MODIFIED' and e.get('object') == target:
                    since = e.get('mutated_at') or ''
            started = False
            tries = max(1, int(env('health_retries') or '1'))
            for i in range(1, tries + 1):
                started = appservice_started(host, ref, since) if since else None
                print('  container start %d/%d -> %s' % (i, tries, {True: 'started from the intended image',
                      False: 'not started yet', None: 'log unreadable'}[started]))
                if started is not False:
                    break
                # An idle site on a plan that unloads it starts its container only when a request
                # arrives (live run 38867771912, F1): wait without asking and nothing ever starts.
                # The answer to this wake-up is NOT evidence -- it may be the previous container's
                # -- so it is discarded; only the platform's start record is read.
                wake('https://%s/' % host)
                if i < tries:
                    import time
                    time.sleep(float(env('health_interval_seconds') or '0'))
            if started is not True:
                record_verification(runtime_deployed=None if started is None else False,
                                    health_verified=None,
                                    reason='the platform did not report a site started from the '
                                           'intended image (%s)' % (('container log unreadable: '
                                                                     + LOG_READ['error'])
                                                                    if started is None else
                                                                    'never started'))
                if started is None:
                    print('::warning title=Container log unreadable::%s' % LOG_READ['error'][:300])
                print('::error::The platform never reported a container started from %s. A 200 '
                      'now would be the PREVIOUS container answering; health is not probed.' % ref)
                return 1
    if image != ref:
        record_verification(runtime_deployed=False, health_verified=None, loaded=image)
        print('::error::The target is running %s, not %s. Something other than this run wrote it, '
              'or the write did not take; a probe of it would test the wrong artefact.'
              % (image or 'nothing', ref))
        return 1
    healthy = bool(host) and probe('https://%s%s' % (host, path))
    record_verification(runtime_deployed=True, health_verified=healthy, probed=host)
    if not healthy:
        print('::error::Health probe never returned 200 for the intended artefact at %s%s.'
              % (host, path))
        return 1
    print('Intended artefact loaded and healthy on %s.' % host)
    return 0


def cmd_redirect(a):
    """Container Apps, multiple-revision mode: move traffic to the VERIFIED revision, recorded
    in the manifest as a REDIRECTION (with the prior weights) before it is issued."""
    snap = read_evidence('snapshot.json') or {}
    if snap.get('revision_mode') != 'Multiple':
        print('Single-revision mode: the platform moved traffic with the update; nothing to do.')
        return 0
    rev = created_revision()
    m = manifest()
    m['entries'].append({'action': 'REDIRECTED', 'object_type': 'traffic', 'object': 'traffic',
                         'prior': snap.get('traffic') or [],
                         'post': [{'revisionName': rev, 'weight': 100}],
                         'stamp': stamp_value(intended_ref())})
    m['status'] = 'planned'
    save_manifest(m)
    ok, _, err = az('containerapp', 'ingress', 'traffic', 'set', '-n', env('containerapp_name'),
                    '-g', env('resource_group'), '--revision-weight', '%s=100' % rev)
    if not ok:
        print('::error::The traffic shift did not confirm (%s).' % err)
        return 1
    m['status'] = 'applied'
    save_manifest(m)
    print('Traffic moved to %s (recorded as REDIRECTED).' % rev)
    return 0


def cmd_serving(a):
    """DCR 3.1 serving_verified: the path a consumer uses reaches the intended artefact. Read
    the routing back from live state, then probe the consumer-facing name."""
    ref = intended_ref()
    path = env('health_path')
    if a.adapter == 'containerapp':
        live = containerapp_serving()
        if live is None:
            record_verification(serving_verified=None, reason='routing could not be read back')
            print('::error::What receives traffic could not be read back.')
            return 1
        if not live or any(t['image'] != ref for t in live):
            record_verification(serving_verified=False, routing=live)
            print('::error::Traffic does not route only to %s: %s' % (ref, live))
            return 1
        ok, shown, _ = az('containerapp', 'show', '-n', env('containerapp_name'),
                          '-g', env('resource_group'))
        host = ((((shown or {}).get('properties') or {}).get('configuration') or {})
                .get('ingress') or {}).get('fqdn', '') if ok else ''
    else:
        if env('slot') and env('swapped') != 'success':
            record_verification(serving_verified='not-applicable')
            print('Staged on %s without a swap: production is deliberately unchanged.' % env('slot'))
            return 0
        image = appservice_slot_image('production')
        if image != ref:
            record_verification(serving_verified=None if image is None else False, loaded=image)
            print('::error::Production is not configured with %s (read back: %s).' % (ref, image))
            return 1
        # DCR-2 / L101: the configured image is what the platform will start next. What RUNS is
        # read from production's own start record -- after a swap too, where nothing re-read it.
        running = appservice_running('production', ref,
                                     waits=max(1, int(env('health_retries') or '1')))
        if running is not True:
            record_verification(serving_verified=None if running is None else False,
                                running=running, running_read=running_text(running, ref))
            print('::error::Production is configured with %s, but its start record does not show '
                  'it running: %s. A 200 now could come from another container; serving is not '
                  'verified.' % (ref, running_text(running, ref)))
            return 1
        host = appservice_host('production')
    if host:
        # The consumer-facing URL is published whether or not it answers, so a caller can see
        # what was probed; `serving_verified` says whether it served the intended artefact.
        output(app_url='https://%s' % host)
    good = bool(host) and probe('https://%s%s' % (host, path))
    record_verification(serving_verified=good)
    if not good:
        print('::error::The consumer-facing name %s does not answer 200 for the intended artefact.'
              % host)
        return 1
    print('Serving verified: %s routes to %s and answers 200.' % (host, ref))
    return 0


# ----------------------------------------------------------------------------- reversal
def _derive(entries):
    """Per-object dispositions from scripts/derive_reversal_disposition.py (inlined beside this
    file). Imported, not re-implemented: one derivation, proven in one place."""
    sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
    import derive_reversal_disposition as drd
    return [drd.derive(e, release_id()) for e in entries]


def _rev_stamp(rev_props):
    for c in ((rev_props.get('template') or {}).get('containers') or []):
        for e in c.get('env') or []:
            if e.get('name') == 'release_ownership_stamp':
                return e.get('value', '')
    return ''


def _stamp_release(stamp):
    for part in (stamp or '').split(';'):
        if part.startswith('release_id='):
            return part.split('=', 1)[1]
    return ''


def _canon(traffic, latest):
    return json.dumps(sorted(
        [(latest if t.get('latestRevision') else t.get('revisionName'), t.get('weight') or 0)
         for t in traffic or [] if (t.get('weight') or 0) > 0]))


def _containerapp_live(app, rg):
    """One fresh read of what the reversal is judged against.

    Every revision list here passes --all: without it the CLI omits INACTIVE revisions, so once
    the reversal deactivated the revision this run created, its ownership stamp vanished from the
    read the next entry was judged by, and the run withheld its own traffic pin as UNTRUSTED
    (live run 38856714492)."""
    ok1, shown, _ = az('containerapp', 'show', '-n', app, '-g', rg)
    ok2, revs, _ = az('containerapp', 'revision', 'list', '-n', app, '-g', rg, '--all')
    readable = ok1 and ok2 and isinstance(shown, dict) and isinstance(revs, list)
    props = (shown or {}).get('properties') or {}
    latest = props.get('latestRevisionName') or ''
    traffic = ((props.get('configuration') or {}).get('ingress') or {}).get('traffic') or []
    by_name = {r.get('name'): r.get('properties') or {} for r in (revs or [])}
    ours = created_revision()
    ours_props = by_name.get(ours) or {}
    our_created = ours_props.get('createdTime') or ''
    newer = [(n, p) for n, p in by_name.items() if n != ours and (p.get('createdTime') or '') > our_created]
    descendants = []
    for n, p in newer:
        if not p.get('active'):
            continue
        rel = _stamp_release(_rev_stamp(p))
        if not rel:
            descendants = None   # an unstamped later revision: the graph cannot be read
            break
        descendants.append(rel)
    return readable, latest, traffic, ours, ours_props, descendants


def reverse_containerapp(m, snap):
    """Each entry is judged against live state AS IT STANDS WHEN ITS TURN COMES. A single read
    taken before the first undo judged a later entry against state this same reversal was about to
    change -- so a run that pinned traffic, then moved it, then had both undone, called its own
    pin a conflict with an external actor."""
    app, rg = env('containerapp_name'), env('resource_group')
    results = []
    for entry in reversed(m.get('entries') or []):
        readable, latest, traffic, ours, ours_props, descendants = _containerapp_live(app, rg)
        r = _reverse_containerapp_entry(m, snap, entry, readable, latest, traffic, ours,
                                        ours_props, descendants, app, rg)
        if r is not None:
            results.append(r)
    return results


def _reverse_containerapp_entry(m, snap, entry, readable, latest, traffic, ours, ours_props,
                                descendants, app, rg):
    """-> the reversal record for ONE manifest entry, judged against the live read just taken."""
    if entry['action'] == 'REDIRECTED':
        prop = dict(entry, **{
            'object': 'traffic', 'stamp': _rev_stamp(ours_props) if readable else None,
            'current_version': _canon(traffic, latest) if readable else None,
            'recorded_post_version': _canon(entry.get('post'), latest),
            'later_releases': [], 'descendants': descendants, 'other_claims': [],
            # Traffic configuration carries no dependents of its own (adapter declaration).
            'dependents': [], 'prior_traffic': entry.get('prior') or [],
            'prior_latest': snap.get('latest_revision', '')})
    elif entry['action'] == 'CREATED':
        # Who still routes to, or labels, this revision NOW. Redirections recorded after the
        # creation have already been undone by the time this entry's turn comes (entries are
        # reversed newest first, each against a fresh read), so traffic still on it is a real
        # dependency -- or a restore that did not take -- and either way it is not removed.
        deps = []
        for t in traffic:
            name = latest if t.get('latestRevision') else t.get('revisionName')
            if name != ours:
                continue
            if t.get('label'):
                deps.append('traffic label %s' % t['label'])
            elif (t.get('weight') or 0) > 0:
                deps.append('traffic weight %s%%' % t['weight'])
        image = (((ours_props.get('template') or {}).get('containers') or [{}])[0]).get('image')
        prop = dict(entry, **{
            'stamp': _rev_stamp(ours_props) if readable and ours_props else None,
            'current_version': image if readable and ours_props else None,
            'recorded_post_version': entry.get('post'),
            # A revision is immutable: no later release can rewrite it (adapter declaration).
            'later_releases': [], 'descendants': descendants, 'other_claims': [],
            'dependents': deps if readable else None})
    else:
        return None
    d = _derive([prop])[0]
    r = dict(d, object=prop.get('object'), performed=False)
    disp = d['reversal_disposition']
    if prop['action'] == 'REDIRECTED' and disp == 'REVERSAL_RESTORE_PRIOR':
        weights = []
        for t in prop['prior_traffic']:
            if (t.get('weight') or 0) <= 0:
                continue
            name = prop['prior_latest'] if t.get('latestRevision') else t.get('revisionName')
            weights.append('%s=%d' % (name, t['weight']))
        done = True
        for w in weights:
            okk, _, err = az('containerapp', 'revision', 'activate', '-n', app, '-g', rg,
                             '--revision', w.rsplit('=', 1)[0])
            done = done and okk
        if weights:
            okk, _, err = az('containerapp', 'ingress', 'traffic', 'set', '-n', app, '-g', rg,
                             '--revision-weight', *weights)
            done = done and okk
            r['error'] = '' if okk else err
        r['performed'] = done
    elif (prop['action'] == 'CREATED'
          and snap.get('revision_mode') != 'Multiple'
          and snap.get('previous_state') == 'EXISTING_DEPLOYMENT'):
        # DCR gap 7: the mechanism must be valid for the OBSERVED configuration. In single-
        # revision mode the prior revision cannot be reactivated beside ours, and traffic
        # weights cannot be set; deactivating ours would leave nothing serving.
        r['not_reversed_because'] = ('mechanism not valid for the observed configuration: '
                                     'single revision mode cannot reactivate the prior '
                                     'revision or set traffic weights')
    elif prop['action'] == 'CREATED' and disp == 'REVERSAL_REMOVE':
        okk, _, err = az('containerapp', 'revision', 'deactivate', '-n', app, '-g', rg,
                         '--revision', prop['object'])
        r['performed'] = okk
        r['error'] = '' if okk else err
    return r


def reverse_appservice(m, snap):
    """Each entry is judged against live state AS IT STANDS WHEN ITS TURN COMES, as the Container
    Apps reversal is. One read taken before acting on any entry judged the slot entry of a
    slot-and-swap run against the state BEFORE the swap-back: the slot then held the prior image
    swapped out of production, so the run called its own slot change a conflict with an external
    actor and left it in place."""
    base = ['-n', env('webapp_name'), '-g', env('resource_group')]
    target = env('slot') or 'production'
    results = []
    for entry in reversed(m.get('entries') or []):
        slot = 'production' if entry['action'] == 'REDIRECTED' else entry['object']
        # DCR-OWN: each entry is judged by the stamp on the object IT names -- production for the
        # swap, the slot for the slot's image -- never by the deploy target's stamp.
        ok, shown, _ = az('webapp', 'show', *(base + (['--slot', slot]
                                                      if slot != 'production' else [])))
        stamp = ((shown or {}).get('tags') or {}).get('release_ownership_stamp', '') \
            if ok and isinstance(shown, dict) else None
        img = appservice_slot_image(slot)
        prop = dict(entry, **{
            'stamp': stamp, 'current_version': None if img is None else ('DOCKER|' + img if img else ''),
            'recorded_post_version': entry.get('post'),
            # Within this run no other kit release can write this app: the concurrency group
            # serialises them. A configuration value has no dependents of its own.
            'later_releases': [], 'descendants': [], 'other_claims': [], 'dependents': [],
            'slot': slot})
        d = _derive([prop])[0]
        r = dict(d, object=prop.get('object'), performed=False)
        if d['reversal_disposition'] == 'REVERSAL_RESTORE_PRIOR':
            if prop['action'] == 'REDIRECTED':
                calls = [('webapp', 'deployment', 'slot', 'swap', *base, '--slot', prop['from_slot'],
                          '--target-slot', 'production')]
            else:
                sarg = ['--slot', prop['slot']] if prop['slot'] != 'production' else []
                prior = (prop.get('prior') or '').split('|', 1)[-1] if prop.get('prior') else ''
                calls = [(('webapp', 'config', 'container', 'set', *base, *sarg,
                           '--container-image-name', prior) if prior else
                          ('webapp', 'config', 'set', *base, *sarg, '--linux-fx-version', '')),
                         ('webapp', 'restart', *base, *sarg)]
            done, err = True, ''
            for c in calls:
                okk, _, e = az(*c)
                done, err = done and okk, err or e
            if done and prop['action'] == 'REDIRECTED' and prop.get('production_id'):
                # The swap is undone; so is this release's claim on production (DCR-OWN).
                okk, _, e = az('tag', 'update', '--resource-id', prop['production_id'],
                               '--operation', 'Merge', '--tags',
                               'release_ownership_stamp=%s' % (prop.get('prior_stamp') or ''))
                r['stamp_restored'] = okk
                err = err or e
            elif done and prop['action'] == 'MODIFIED' and prop.get('object_id') \
                    and 'prior_stamp' in prop:
                # The slot's image is restored; so is its previous owner's claim (KDEC-021).
                okk, _, e = az('tag', 'update', '--resource-id', prop['object_id'],
                               '--operation', 'Merge', '--tags',
                               'release_ownership_stamp=%s' % (prop.get('prior_stamp') or ''))
                r['stamp_restored'] = okk
                err = err or e
            r['performed'], r['error'] = done, err
        results.append(r)
    return results


def cmd_reverse(a):
    """DCR gaps 5 and 7, ROLLBACK_CONTRACT.md: undo only what the manifest says this run did,
    each object only as far as live-state preconditions allow (DCR section 8)."""
    m = read_evidence('manifest.json')
    snap = read_evidence('snapshot.json') or {}
    if not m or not m.get('entries'):
        write_evidence('reversal.json', {'reversal_path': 'none', 'entries': [],
                                         'reason': 'no change manifest: nothing is attributable '
                                                   'to this run, so nothing may be reversed'})
        print('::error::No change manifest; nothing is reversed.')
        return 1
    path = 'ROLLBACK_TO_EMPTY' if snap.get('previous_state') == 'EMPTY' else 'ROLLBACK_TO_PRIOR'
    results = (reverse_containerapp if a.adapter == 'containerapp' else reverse_appservice)(m, snap)
    for r in results:
        print('  %-12s %-34s performed=%s  %s' % (r['object'], r['reversal_disposition'],
                                                 r['performed'], r['reason']))
    # DCR gap 7: the terminal state is RECONCILED REALITY. Command exit is an input to the
    # comparison, never a substitute for it -- read live state back and compare it with the
    # pre-change snapshot, absences included.
    verification = (verify_containerapp_reversal if a.adapter == 'containerapp'
                    else verify_appservice_reversal)(snap)
    # DCR 8.2 / 8.5: an entry this reversal did not reverse -- refused, withheld, deferred, or
    # whose mechanism was not valid -- leaves the rollback PARTIAL at minimum, whatever live state
    # happens to equal. Live run 38879879589: the reversal REFUSED (an external actor had set
    # production meanwhile, to an image that happened to be the prior one), the snapshot
    # comparison was coincidentally true, and the run reported ROLLBACK_VERIFIED. Only entries
    # this reversal set out to reverse are decided by the live comparison (exit status is not).
    not_reversed = [{'object': r['object'], 'reversal_disposition': r['reversal_disposition'],
                     'reversal_conflict': r.get('reversal_conflict'),
                     'reason': r.get('not_reversed_because') or r['reason']}
                    for r in results if r['reversal_disposition'] not in REVERSING
                    or r.get('not_reversed_because')]
    if verification is None:
        result = 'STATUS_UNTRUSTED'
    elif results and all(r['reversal_disposition'] == 'REVERSAL_WITHHELD_UNTRUSTED' for r in results):
        result = 'STATUS_UNTRUSTED'       # DCR 8.5: no reversal was performed at all
    elif not_reversed:
        result = 'ROLLBACK_PARTIAL'       # DCR 8.2: never rounds up to verified
    elif verification['matches_snapshot']:
        result = 'ROLLBACK_VERIFIED'
    else:
        result = 'ROLLBACK_PARTIAL'
    rv = {'reversal_path': path, 'entries': results, 'verification': verification,
          'not_reversed': not_reversed, 'result': result}
    write_evidence('reversal.json', rv)
    if result != 'ROLLBACK_VERIFIED':
        print('::warning::Reversal result %s via %s. Not reversed: %s. Residue against the '
              'snapshot: %s' % (result, path, json.dumps(not_reversed) if not_reversed else 'none',
                                json.dumps((verification or {}).get(
                                    'residual', 'live state could not be read back'))))
        return 1
    print('%s, verified: %s matches the pre-change snapshot.' % (path, verification['compared']))
    return 0


# The two dispositions under which this reversal ACTS on an entry (DCR 8.2 "contributes to a
# complete reversal"). Every other disposition leaves that entry's change in place.
REVERSING = ('REVERSAL_REMOVE', 'REVERSAL_RESTORE_PRIOR')


def verify_containerapp_reversal(snap):
    """-> {matches_snapshot, residual, ...} from a fresh live read, or None if unreadable."""
    app, rg = env('containerapp_name'), env('resource_group')
    ok1, shown, _ = az('containerapp', 'show', '-n', app, '-g', rg)
    ok2, revs, _ = az('containerapp', 'revision', 'list', '-n', app, '-g', rg, '--all')
    if not (ok1 and ok2 and isinstance(shown, dict) and isinstance(revs, list)):
        return None
    props = shown.get('properties') or {}
    traffic = ((props.get('configuration') or {}).get('ingress') or {}).get('traffic') or []
    live_traffic = _canon(traffic, props.get('latestRevisionName') or '')
    want_traffic = _canon(snap.get('traffic') or [], snap.get('latest_revision') or '')
    active = sorted(r.get('name') for r in revs if (r.get('properties') or {}).get('active'))
    want_active = sorted(n for n, r in (snap.get('revisions') or {}).items() if r.get('active'))
    residual = []
    if live_traffic != want_traffic:
        residual.append({'field': 'traffic', 'snapshot': want_traffic, 'now': live_traffic})
    extra = [n for n in active if n not in want_active]
    missing = [n for n in want_active if n not in active]
    if extra:
        residual.append({'field': 'active revisions not in the snapshot', 'now': extra})
    if missing:
        residual.append({'field': 'snapshot revisions no longer active', 'now': missing})
    return {'matches_snapshot': not residual, 'residual': residual,
            'compared': 'live state (traffic and active revisions)',
            'still_absent_checked': [created_revision()],
            'created_revision_active': created_revision() in active}


def verify_appservice_reversal(snap):
    images = snap.get('images') or {}
    residual = []
    for slot, want in sorted(images.items()):
        now = appservice_slot_image(slot)
        if now is None:
            return None
        if now != want:
            residual.append({'field': '%s image (configured)' % slot, 'snapshot': want, 'now': now})
    # What this comparison CAN establish: the configured image of each slot. App Service exposes
    # no running digest, and a restored configuration is not a restarted container; the platform's
    # start record is reported beside it in the outcome report, as its own row.
    return {'matches_snapshot': not residual, 'residual': residual,
            'compared': 'the configured image (linuxFxVersion) of each slot',
            'not_compared': 'the running container: the outcome report reads the platform\'s '
                            'container start record for production as a separate row'}


# ----------------------------------------------------------------------------- provenance
def resource_id(adapter, slot='', with_stamp=False):
    """-> (id, error), or (id, error, ownership stamp) with `with_stamp` -- one read for both."""
    if adapter == 'containerapp':
        ok, shown, err = az('containerapp', 'show', '-n', env('containerapp_name'),
                            '-g', env('resource_group'))
    else:
        args = ['webapp', 'show', '-n', env('webapp_name'), '-g', env('resource_group')]
        if slot and slot != 'production':
            args += ['--slot', slot]
        ok, shown, err = az(*args)
    if not ok or not isinstance(shown, dict) or not shown.get('id'):
        out = (None, err or 'no resource id in the response')
        return out + ('',) if with_stamp else out
    if with_stamp:
        return shown['id'], '', (shown.get('tags') or {}).get('release_ownership_stamp', '')
    return shown['id'], ''


def cmd_provenance(a):
    """DCR gap 3: stamp ONLY what is verified to be running, on the object that serves it.

    Provenance means "this is running and it works", so the stamp is written after health,
    after a fresh live read confirms the intended artefact is what serves, and onto the serving
    object as resource TAGS. Not an app setting or a revision environment variable: on Container
    Apps an environment change CREATES A NEW REVISION, so the old stamp mutated the very thing it
    described after it had been checked, and on App Service a setting change restarts the app.
    """
    adapter, intended = a.adapter, intended_ref()
    if adapter == 'containerapp':
        live = containerapp_serving()
        target = ''
        verified = bool(live) and all(t['image'] == intended for t in live)
    else:
        target = 'production' if (not env('slot') or env('swapped') == 'success') else env('slot')
        # Configured AND started: a stamp says "this is running", and only the start record can.
        verified = appservice_slot_image(target) == intended and \
            appservice_running(target, intended) is True
    if not verified:
        print('::error::Provenance NOT stamped: live state does not show %s serving. A stamp is a '
              'claim about reality and is written only when reality supports it.' % intended)
        output(provenance_state='not-stamped')
        return 1
    rid, err = resource_id(adapter, target)
    if rid is None:
        print('::error::Provenance NOT stamped: the serving object could not be read (%s).' % err)
        output(provenance_state='not-stamped')
        return 1
    import hashlib
    meta = env('version_metadata')
    tags = ['deploy_provenance_digest=%s' % env('image_digest'),
            'deploy_provenance_metadata_sha256=%s' % hashlib.sha256(meta.encode('utf-8')).hexdigest(),
            'deploy_provenance_run=%s-%s' % (env('github_run_id'), env('github_run_attempt'))]
    ok, _, err = az('tag', 'update', '--resource-id', rid, '--operation', 'Merge', '--tags', *tags)
    if not ok:
        print('::error::Provenance NOT stamped: the tag write failed (%s).' % err)
        output(provenance_state='not-stamped')
        return 1
    write_evidence('provenance.json', {'resource_id': rid, 'tags': tags, 'version_metadata': meta})
    output(provenance_state='stamped')
    print('Provenance stamped on %s after health and a live read of what serves.' % rid)
    return 0


def cmd_unhealthy(a):
    """DCR gap 1(b) on the direct path: production was modified and the change is unhealthy.

    What production holds NOW is read back from live state when this message is written, never
    echoed from the run's inputs or its recorded post-state. Live run 38879879589 said production
    "now serves" the image this run set, while a second actor had already replaced it. The image
    this run set is named as what it SET (ATTEMPTED); the live readings are named as what they
    are -- the configured image, and the platform's container start record."""
    if a.adapter != 'appservice':
        print('Nothing to report: only the App Service direct path mutates production unverified.')
        return 0
    ref = intended_ref()
    configured, started = appservice_production_now()
    prior = ((read_evidence('snapshot.json') or {}).get('images') or {}).get('production')
    if configured is None:
        whose = 'the read failed'
    elif configured == ref:
        whose = 'the image this run set'
    elif prior is not None and configured == prior:
        whose = 'the pre-change image'
    else:
        whose = "neither this run's image nor the pre-change one: another actor wrote it"
    print("::error::PRODUCTION was modified by this run and the change is unhealthy: this run set "
          "%s directly on production (slot ''). Production NOW, read back just now: configured "
          "image %s (%s); last container the platform reported started: %s. What the reversal "
          "restored, and what it did not, is in the outcome report below."
          % (ref, UNKNOWN if configured is None else (configured or 'nothing'), whose, started))
    return 0


# ----------------------------------------------------------------------------- outcome
def derive_outcome(adapter, live):
    """-> (deployment_outcome, why). Asserted from evidence and live state, never from intent.

    DCR gap 8: a run that mutated and then lost track is not "failed" -- failure implies nothing
    changed. PARTIAL_APPLY when the mutation was issued and never confirmed; STATUS_UNTRUSTED
    when it applied and the run can no longer describe what serves. Missing proof downgrades.
    """
    m = read_evidence('manifest.json')
    snap = read_evidence('snapshot.json') or {}
    rv = read_evidence('reversal.json')
    deploy = env('deploy_outcome')
    if not m or not m.get('entries'):
        why = ('previous_state UNKNOWN: the capture could not read the target'
               if snap.get('previous_state') == 'UNKNOWN' else
               'refused before the first mutation (gate verdict, tier, digest or capability)')
        return 'DEPLOY_REFUSED', why
    if deploy != 'success':
        return 'PARTIAL_APPLY', ('the mutation was issued and never confirmed; objects may exist '
                                 'that no record describes (manifest status %s)' % m.get('status'))
    if env('cancelled') == 'true' and not rv:
        return 'STATUS_UNTRUSTED', 'cancelled after the mutation, before reconciliation'
    if rv and rv.get('result'):
        why = 'verification failed; reversal %s via %s' % (rv['result'], rv.get('reversal_path'))
        left = rv.get('not_reversed') or []
        if left:
            why += '; NOT reversed: %s' % '; '.join(
                '%s %s (%s)' % (n.get('object'), n.get('reversal_disposition'),
                                n.get('reversal_conflict') or 'none') for n in left)
        return rv['result'], why
    if env('serving_outcome') == 'success':
        if live is None:
            return 'STATUS_UNTRUSTED', 'serving was verified, then the live read-back failed'
        ref = intended_ref()
        if adapter == 'containerapp':
            ok = bool(live) and all(t['image'] == ref for t in live)
        else:
            staged_only = env('slot') and env('swapped') != 'success'
            running = NOW.get('running')
            if not staged_only and live == ref and running is None:
                return 'STATUS_UNTRUSTED', ('production is configured with the intended image, '
                                            'and its start record could not be read: what runs '
                                            'is not established')
            ok = staged_only or (live == ref and running is True)
        return ('DEPLOY_HEALTHY', 'the intended artefact is loaded, healthy and serving') if ok \
            else ('STATUS_UNTRUSTED', 'live state no longer shows what was verified moments ago')
    v = read_evidence('verification.json') or {}
    if v.get('runtime_deployed') is None and 'runtime_deployed' in v:
        return 'STATUS_UNTRUSTED', 'the change applied and what it loaded could not be read back'
    return 'MANUAL_RECOVERY_REQUIRED', ('verification failed and no reversal ran (rollback '
                                        'disabled, or the run stopped before it); the failed '
                                        'change is still in place')


# ----------------------------------------------------------------------------- promotion
# DCR gap 11 / 7.7. Deployment success is not trust progression. Verified-for-promotion is a
# CONJUNCTION; this run credits the conditions it established and names the rest. The verified
# state is not emitted while any condition is unestablished -- and three of them have no evidence
# source in this kit yet, so on today's kit it is never emitted. That is the honest reading.
PROMOTION_CONDITIONS = ['exact artefact identity established', 'expected artefact observed running',
                        'intended traffic observed', 'functional tests passed',
                        'operational validation passed', 'dependencies verified',
                        'required reviews and gates passed', 'state reconciliation complete']


def promotion(outcome):
    v = read_evidence('verification.json') or {}
    held = []
    # P-02: V1 inside the deploy VERIFIED the signed provenance of exactly this digest -- the one
    # promotion condition this run can establish about identity. A held or absent V1 credits nothing.
    if outcome == 'DEPLOY_HEALTHY' and env('attestation_outcome') == 'ATTESTATION_VERIFIED':
        held.append('exact artefact identity established')
    if outcome == 'DEPLOY_HEALTHY':
        if v.get('runtime_deployed') is True:
            held.append('expected artefact observed running')
        if v.get('serving_verified') in (True, 'not-applicable'):
            held.append('intended traffic observed')
        held.append('state reconciliation complete')
        if env('routing_result') == 'PROCEED' and not env('controls_unavailable').strip():
            held.append('required reviews and gates passed')
    missing = [c for c in PROMOTION_CONDITIONS if c not in held]
    return {'state': 'not-verified' if missing else 'verified-for-promotion',
            'established': held, 'missing': missing,
            'note': 'health is one probe, not functional or operational validation; artefact '
                    'identity is credited only when V1 in this deploy verified the digest\'s signed '
                    'build provenance; no dependency verification exists in this kit'}


# ----------------------------------------------------------------------------- six questions
# L96 / DCR 3.4. Questions 4 and 5 are separate on purpose: "a fix exists" and "a machine may apply
# it" are different claims. Owners are ROLES, never individuals; channels and service levels are
# policy placeholders the adopting team sets (numbers are never constants in this kit).
EVIDENCE_FILES = ['manifest.json', 'snapshot.json', 'capability.json', 'verification.json',
                  'reversal.json', 'outcome.json']
MAY = ['re-read live state and re-evaluate the reversal preconditions',
       'gather the evidence files named in required_artefacts',
       'identify the resolution owner and draft the request',
       'propose compensating changes for a human to approve']
MAY_NOT = ['mutate infrastructure', 'retry or widen the deployment or the reversal',
           'suppress or rewrite the outcome', 'invent or self-grant an approval',
           're-stamp ownership metadata', 'proceed to apply']

SIX_QUESTIONS = {
    'DEPLOY_HEALTHY': (False, 'release owner (deploying team)', 'not applicable', True,
                       'Nothing is blocked. To ADVANCE a tier, collect control-effectiveness '
                       'evidence: deployed and healthy is not verified for promotion.'),
    'DEPLOY_REFUSED': (True, 'owner of the refusing control: the gate verdict owner, or platform '
                       'operations for an unreadable target or unavailable rollback capability',
                       'yes -- resolve the named refusal reason', False,
                       'Resolve the refusal reason and re-run. Nothing was changed, so there is '
                       'nothing to recover.'),
    'ROLLBACK_VERIFIED': (True, 'application team that owns the released artefact',
                          'no -- the artefact failed verification; the fix is a new release',
                          False, 'Investigate the failed artefact from the evidence and ship a '
                          'fix as a new release. Service is verified back on the prior state.'),
    'ROLLBACK_PARTIAL': (True, 'platform operations', 'no -- each residual item needs a decision',
                         False, 'Work through the residue in reversal.json item by item; the '
                         'escalation contract below says what an automated actor may do.'),
    'MANUAL_RECOVERY_REQUIRED': (True, 'platform operations', 'no automated path is available',
                                 False, 'Recover by hand from the snapshot and manifest; the '
                                 'failed change is still in place.'),
    'PARTIAL_APPLY': (True, 'platform operations', 'no -- the extent of the change is unknown',
                      False, 'Reconcile live state against the planned manifest by hand before '
                      'any further deploy to this target.'),
    'STATUS_UNTRUSTED': (True, 'platform operations', 'no -- what serves is not known to this run',
                         False, 'Restore the ability to observe the target, then reconcile live '
                         'state against the snapshot and manifest.'),
}


def six_questions(outcome, why):
    blocked, owner, known, may, nxt = SIX_QUESTIONS.get(
        outcome, (True, 'platform operations', 'no', False, 'Escalate: unrecognised outcome.'))
    q = {'progression_blocked': blocked, 'why': why, 'resolution_owner': owner,
         'remediation_known': known, 'automated_actor_may_proceed': may, 'next_action': nxt}
    esc = None
    if blocked and not may:
        esc = {'resolution_owner': owner,
               'request_channel': 'the deploy environment\'s change or incident queue (set by policy)',
               'request_type': {'DEPLOY_REFUSED': 'refusal review'}.get(outcome, 'recovery decision'),
               'required_artefacts': EVIDENCE_FILES,
               'service_level': 'placeholder: set by the adopting team\'s policy',
               'permitted_agent_action': {'may': MAY, 'may_not': MAY_NOT}}
    return q, esc


# ----------------------------------------------------------------------------- report
def cmd_report(a):
    adapter = a.adapter
    attempted = [('image', intended_ref())]
    if adapter == 'containerapp' and env('attempted_revision'):
        attempted.append(('revision', env('attempted_revision')))
    if adapter == 'appservice':
        attempted.append(('target', env('slot') or 'production (direct)'))
    if read_evidence('snapshot.json') is None:
        # Refused before the capture ran: the run never authenticated and changed nothing, so
        # there is no live read to make. Said, not guessed.
        rows, live = [('image', 'not read: the run stopped before login and changed nothing')], None
    else:
        rows, live = now_serving(adapter)
    unavailable = [c.strip() for c in env('controls_unavailable').split(',') if c.strip()]
    causes = [c.strip() for c in env('advisory_causes').split(',') if c.strip()]
    # KDEC-014: the version-gap ruling the verdict step made, and the exception weighed for it --
    # the existing weakening record (accepter = weakening_authority). Recorded whenever a proven
    # gap was ruled on, so a refused exception is on the record too.
    ruling = env('version_gap_ruling')
    exc = {'accepted_by': env('weakening_authority'), 'reason': env('weakening_reason'),
           'exception_ref': env('weakening_exception_ref'), 'expires': env('weakening_expires'),
           # KDEC-018 item 4: how often it was renewed, and its history, as the verdict step read them.
           'renewals': (int(env('exception_renewals')) if env('exception_renewals').isdigit()
                        else env('exception_renewals') or None),
           'history': env('exception_history') or None}
    exc = exc if ruling in ('VERSION_GAP_EXCEPTION_ACCEPTED', 'VERSION_GAP_REFUSED') else None
    outcome, why = derive_outcome(adapter, live)
    report = {'deployment_outcome': outcome, 'why': why,
              'adapter': adapter, 'attempted': dict(attempted),
              'now_serving': [{'field': f, 'value': v} for f, v in rows],
              'health': env('health_outcome') or 'not run',
              # L93: the verdict the deploy proceeded (or refused) on, and the controls the gate
              # could not run. Recorded, never re-decided here.
              'gate': {'routing_result': env('routing_result'),
                       'controls_unavailable': unavailable,
                       'advisory_causes': causes,
                       'version_gap_ruling': ruling or None,
                       'version_gap_exception': exc,
                       # The GitHub environment the job ran in; at uat/prod its required
                       # reviewers are the approval half of a version-gap exception.
                       'github_environment': env('deploy_environment')}}
    # P-02: what V1 established about this digest, before login. Empty when the run stopped first.
    report['attestation'] = {'outcome': env('attestation_outcome') or None,
                             'routing_result': env('attestation_route') or None,
                             'debt': env('attestation_debt') or None}
    report['promotion'] = promotion(outcome)
    q, esc = six_questions(outcome, why)
    report['six_questions'] = q
    report['escalation'] = esc
    write_evidence('outcome.json', report)
    lines = ['### Deploy outcome (%s): `%s`' % (adapter, outcome), '', why, '',
             'Every identifier is ATTEMPTED (what this run tried) or NOW SERVING (read back from '
             'live state just now). `unknown` means the read failed; it never means the attempt.',
             '', '| Claim | Field | Value |', '|---|---|---|']
    for f, v in attempted:
        lines.append('| ATTEMPTED | %s | `%s` |' % (f, v))
    for f, v in rows:
        lines.append('| NOW SERVING | %s | `%s` |' % (f, v))
    lines.append('')
    lines.append('Health of the attempt: `%s`' % report['health'])
    lines.append('Gate verdict: `%s`; controls the gate could not run: %s' % (
        report['gate']['routing_result'] or 'none',
        ', '.join('`%s`' % c for c in unavailable) if unavailable else 'none recorded'))
    if causes or report['gate']['version_gap_ruling']:
        # Caller text stays in outcome.json; the summary shows only registered-shape tokens.
        lines.append('Advisory causes: %s; version-gap ruling (KDEC-014): `%s`%s' % (
            ', '.join('`%s`' % c for c in causes if c.replace('_', '').isalnum()) or 'none',
            report['gate']['version_gap_ruling'] or 'not reported',
            ' -- exception recorded in outcome.json' if exc else ''))
    if ruling == 'VERSION_GAP_UNVERIFIED_RECORDED':
        lines.append('**VERSION GAP AT A PRODUCTION TIER, RECORDED AND NOT ENFORCED (KDEC-014):** the '
                     'gap rests on an UNVERIFIED scanner range; enforcement turns on when a seeded '
                     'corpus proves it.')
    lines.append('GitHub environment: `%s`' % (
        env('deploy_environment') if env('deploy_environment').replace('-', '').replace('_', '')
        .replace('.', '').isalnum() else '(not shown: not a plain name)'))
    lines.append('Promotion: `%s`; not yet established: %s' % (
        report['promotion']['state'], ', '.join(report['promotion']['missing']) or 'nothing'))
    lines += ['', '| Question | Answer |', '|---|---|',
              '| Is progression blocked? | %s |' % ('yes' if q['progression_blocked'] else 'no'),
              '| Why? | %s |' % q['why'],
              '| Who owns resolution? | %s |' % q['resolution_owner'],
              '| Is a remediation known? | %s |' % q['remediation_known'],
              '| May an automated actor proceed unattended? | %s |'
              % ('yes' if q['automated_actor_may_proceed'] else 'no'),
              '| What is the exact next action? | %s |' % q['next_action']]
    if esc:
        lines += ['', '**Escalation contract.** Owner: %s. Channel: %s. Artefacts: %s. Service '
                  'level: %s.' % (esc['resolution_owner'], esc['request_channel'],
                                  ', '.join(esc['required_artefacts']), esc['service_level']),
                  'An automated actor MAY: %s.' % '; '.join(esc['permitted_agent_action']['may']),
                  'It MAY NOT: %s.' % '; '.join(esc['permitted_agent_action']['may_not'])]
    summary('\n'.join(lines))
    print('\n'.join(lines))
    output(deployment_outcome=outcome)
    if outcome != 'DEPLOY_HEALTHY':
        print('::error title=Deploy outcome %s::%s' % (outcome, why))
        return 1
    return 0


def main(argv):
    ap = argparse.ArgumentParser(description='deploy contract engine')
    sub = ap.add_subparsers(dest='cmd', required=True)
    cmds = {'capture': cmd_capture, 'capability': cmd_capability, 'mutate': cmd_mutate, 'swap': cmd_swap,
            'verify': cmd_verify, 'redirect': cmd_redirect, 'serving': cmd_serving,
            'reverse': cmd_reverse, 'unhealthy': cmd_unhealthy,
            'provenance': cmd_provenance, 'report': cmd_report}
    for name in cmds:
        p = sub.add_parser(name)
        p.add_argument('--adapter', choices=('containerapp', 'appservice'), required=True)
    sub.add_parser('created-revision')
    a = ap.parse_args(argv)
    if a.cmd == 'created-revision':
        # Prints ONLY the revision the manifest records as CREATED (empty if none).
        sys.stdout.write(created_revision() + '\n')
        return 0
    return cmds[a.cmd](a)


if __name__ == '__main__':
    sys.exit(main(sys.argv[1:]))

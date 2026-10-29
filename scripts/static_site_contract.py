#!/usr/bin/env python3
"""The deploy contract for Azure Static Web Apps: package by content digest, stage in a preview
environment, release to production, read back what serves, reverse to the prior artefact.
(OF-5 K-8, the LZ-vs-kit deployment review; KDEC-034 PROPOSED)

WHY THIS EXISTS

    The owner approved Static Web Apps for Phase 1 (landing zone G13). The kit released only containers
    (App Service, Container Apps), so a static site was deployed around it -- GitHub's own SWA workflow,
    a deployment token in a repository secret, no verdict, no digest, no read-back, no way back -- and
    the landing zone could only report "target vended, release pending" (its no-kit-adapter report).
    This module is the SWA half of reusable-deploy-staticwebapp.yml; everything that is not
    SWA-specific (the verdict, the bind, the zone and approval gates, promotion, the lease, the posture
    record, the six questions) is the other adapters' own code, shared.

THE ARTEFACT AND ITS DIGEST

    A static site has no registry digest, so its identity is its CONTENT: the TREE digest is
    sha256 over the lines "<posix relative path>\\0<sha256 hex of the file>\\n", sorted by path, for every
    file of the site except the root's kit-release.json. `package` writes that marker (the digest and
    the build's provenance) into the built site; the site is uploaded as the artifact
    `kit-static-site-<hex>` (and its SBOM as `sbom-<hex>`, so the promotion re-scan works unchanged).
    The marker is SERVED with the site, so what serves can be read back -- NOW SERVING is the live
    marker's digest, never the input echoed. The build's attestation signs the marker file, which binds
    the tree digest it holds (V1 here verifies that file, `attestation`).

THE STEPS (one subcommand per workflow step; names and the digest arrive through env:, as data)

    package          --dir D   write the marker, print site_digest, artifact_name, marker_sha256
    fetch            fetch the artifact by name from the run (GitHub API) into $RUNNER_TEMP/static-site
    verify-artifact  recompute the tree digest: it must equal site_digest and the marker's, else
                     SITE_DIGEST_MISMATCH -- refused before login (artifact_identity
                     CONTENT_DIGEST_PROVEN when they agree)
    attestation      V1 on the marker file: the five outcomes, routed by rung, refused before login
    capture          previous_state: EXISTING_DEPLOYMENT (a readable kit marker in production), EMPTY
                     (measured: no production build), UNKNOWN (content without a readable marker, or a
                     failed read) -- UNKNOWN fails before any mutation
    capability       AVAILABLE only when the prior digest's artefact is still retrievable; EMPTY ->
                     NO_PRIOR_STATE; UNAVAILABLE refuses at uat and prod
    deploy --env E   the deployment token read with the deploy identity, masked at once, handed to the
                     pinned SWA CLI through its environment (never a command-line argument); the
                     change manifest written `planned` first; production stamped with the release's
                     ownership stamp before it changes; the lease fenced before the CLI call
    verify --env E   the live marker of E must name site_digest, and E's health path answer 200
    reverse          a preview this run deployed is removed; a production this run changed gets the
                     prior artefact back (re-verified by digest, then on the live marker) -- unless
                     another actor changed production since (refused, reported)
    seam             KDEC-030 R3 / OF-5 K-6, opt-in with the lease (KIT_TARGET_LEASE_ACCOUNT): the
                     production app settings read before the first mutation; KIT_SETTING_KEYS naming a
                     key the landing zone backs with a Key Vault reference (secret-backed: the landing
                     zone's) -> SEAM_SETTING_OWNERSHIP_CONFLICT; unreadable -> SEAM_OWNERSHIP_NOT_
                     ESTABLISHED; both refuse. This adapter writes no app setting (its stamp is a tag)
                     and has no swap, so the deploy contract's decide_seam runs with nothing planned
    provenance       the kit's provenance tags on the static site, only after a live read
    (purge)          KDEC-030 D-4 / OF-5 K-7: the step runs the deploy contract's own purge,
                     `deploy_contract.py purge --adapter staticwebapp` -- ONLY the endpoint the landing
                     zone vends in KIT_EDGE_ENDPOINT, after a verified release and its stamp
    report           outcome.json in the deploy contract's vocabulary, with the six questions

    Vocabulary: assurance-taxonomy.yaml (deployment_outcome, previous_state, rollback_capability,
    artifact_identity CONTENT_DIGEST_PROVEN, static_site_artifact SITE_DIGEST_MISMATCH). Proven by
    tests/prove_deploy_staticwebapp.py against a stub cloud; not run against Azure.

EXIT 0 done / permitted   1 refused or failed (by name)   2 usage
"""
import argparse
import hashlib
import io
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import zipfile

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import deploy_contract as dc  # noqa: E402  (materialised beside this file)

MARKER = 'kit-release.json'
MARKER_SCHEMA = 'kit-static-site/1'
ARTIFACT_PREFIX = 'kit-static-site-'
DIGEST_RE = re.compile(r'^sha256:[0-9a-f]{64}$')
MISMATCH = 'SITE_DIGEST_MISMATCH'
CONTENT_PROVEN = 'CONTENT_DIGEST_PROVEN'
PRODUCTION = 'production'
PRODUCTION_BUILD = 'default'
PRODUCTION_TIERS = ('uat', 'prod')
UNKNOWN = dc.UNKNOWN
env = dc.env
summary = dc.summary


def output(**kv):
    """One line per value, appended to $GITHUB_OUTPUT (the deploy contract's own writer)."""
    dc.output(**kv)


# ----------------------------------------------------------------------------- the digest
def tree_digest(root):
    """-> 'sha256:<hex>' of every file under root except the root marker. A symlink is refused:
    what it points at is not part of the artefact a digest can name."""
    lines = []
    for dp, dns, fns in os.walk(root):
        dns.sort()
        for fn in fns:
            full = os.path.join(dp, fn)
            rel = os.path.relpath(full, root).replace(os.sep, '/')
            if rel == MARKER:
                continue
            if os.path.islink(full):
                raise ValueError('%s is a symbolic link' % rel)
            with io.open(full, 'rb') as fh:
                lines.append((rel, hashlib.sha256(fh.read()).hexdigest()))
    text = ''.join('%s\0%s\n' % (p, h) for p, h in sorted(lines))
    return 'sha256:' + hashlib.sha256(text.encode('utf-8')).hexdigest()


def artifact_name(digest):
    return ARTIFACT_PREFIX + digest.split(':', 1)[1]


def site_digest():
    return env('site_digest') or env('image_digest')


def site_dir():
    return os.path.join(os.environ.get('RUNNER_TEMP') or '.', 'static-site', 'site')


def cmd_package(a):
    root = a.dir
    if not os.path.isdir(root):
        print('::error title=No site to package::%s is not a directory.' % root)
        return 1
    try:
        d = tree_digest(root)
    except ValueError as e:
        print('::error title=Site not packaged::%s' % e)
        return 1
    marker = {'schema': MARKER_SCHEMA, 'tree_digest': d, 'repository': env('github_repository'),
              'run_id': env('github_run_id'), 'run_attempt': env('github_run_attempt') or '1',
              'sha': env('github_sha'), 'ref': env('github_ref'), 'built_at': dc.utc_now()}
    data = json.dumps(marker, indent=1, sort_keys=True).encode('utf-8')
    io.open(os.path.join(root, MARKER), 'wb').write(data)
    output(site_digest=d, artifact_name=artifact_name(d), digest_hex=d.split(':', 1)[1], marker_sha256=hashlib.sha256(data).hexdigest(),
           marker_path=os.path.join(root, MARKER))
    print('Packaged %s as %s.' % (root, d))
    return 0


# ----------------------------------------------------------------------------- the artefact
def _api():
    import rollback_hold as rh
    return rh


def find_artifact(digest, run_id=''):
    """-> the newest unexpired `kit-static-site-<hex>` artifact (of `run_id` when given), or None."""
    rh = _api()
    listing = rh.api('actions/artifacts', {'name': artifact_name(digest), 'per_page': 100})
    found = [x for x in (listing or {}).get('artifacts') or []
             if isinstance(x, dict) and x.get('name') == artifact_name(digest) and not x.get('expired')]
    if run_id:
        found = [x for x in found if str((x.get('workflow_run') or {}).get('id') or '') == str(run_id)]
    found.sort(key=lambda x: x.get('created_at') or '', reverse=True)
    return found[0] if found else None


def download_to(art, dest):
    rh = _api()
    data = rh._open(art['archive_download_url'])
    if os.path.isdir(dest):
        shutil.rmtree(dest)
    os.makedirs(dest)
    with zipfile.ZipFile(io.BytesIO(data)) as zf:
        for n in zf.namelist():
            target = os.path.normpath(os.path.join(dest, n))
            if not target.startswith(os.path.normpath(dest) + os.sep):
                raise ValueError('the artifact holds a path outside itself: %s' % n)
        zf.extractall(dest)


def cmd_fetch(a):
    d = site_digest()
    if not DIGEST_RE.match(d or ''):
        print('::error title=Deploy refused before login::site_digest is not sha256:<64 hex>.')
        return 1
    run_id = env('artifact_run_id') or env('github_run_id')
    try:
        art = find_artifact(d, run_id)
        if art is None:
            raise ValueError('run %s published no unexpired artifact %s' % (run_id, artifact_name(d)))
        download_to(art, site_dir())
    except Exception as e:  # noqa: BLE001 -- not fetched is not verified
        print('::error title=Deploy refused before login::the site artefact could not be fetched: %s' % e)
        output(artifact_fetch='failed')
        return 1
    output(artifact_fetch='fetched', site_dir=site_dir())
    print('Fetched %s from run %s.' % (artifact_name(d), run_id))
    return 0


def verify_dir(root, want):
    """-> (ok, why): the files hash to `want`, and the marker says so too."""
    try:
        got = tree_digest(root)
        marker = json.load(io.open(os.path.join(root, MARKER), encoding='utf-8'))
    except (OSError, ValueError) as e:
        return False, 'the artefact could not be read (%s)' % e
    if got != want:
        return False, 'its files hash to %s, not %s' % (got, want)
    if marker.get('tree_digest') != want:
        return False, 'its marker names %s, not %s' % (marker.get('tree_digest'), want)
    return True, ''


def cmd_verify_artifact(a):
    want = site_digest()
    ok, why = verify_dir(a.dir or site_dir(), want) if DIGEST_RE.match(want or '') else \
        (False, 'site_digest is not sha256:<64 hex>')
    dc.write_evidence('artifact.json', {'site_digest': want, 'identity': CONTENT_PROVEN if ok else MISMATCH,
                                        'why': why})
    if not ok:
        output(artifact_identity=MISMATCH)
        print('::error title=Deploy refused before login (%s)::%s. The artefact about to be released is not '
              'the one the digest names; nothing was deployed.' % (MISMATCH, why))
        summary('### Deploy refused before login\n\n`%s`: %s.' % (MISMATCH, why))
        return 1
    output(artifact_identity=CONTENT_PROVEN)
    print('The artefact hashes to %s: %s.' % (want, CONTENT_PROVEN))
    return 0


# ----------------------------------------------------------------------------- V1
def cmd_attestation(a):
    """V1 for a static site: the build's attestation of the marker file, verified before login. The
    same five outcomes and rung routing as the image V1 (PROVENANCE_AND_ATTESTATION.md 6.3)."""
    marker = os.path.join(a.dir or site_dir(), MARKER)
    rung = env('attestation_rung') or 'run'
    if rung not in ('crawl', 'walk', 'run'):
        print('::error title=Unknown rung::%r is not crawl, walk or run.' % rung)
        return 1
    debt = ''
    if env('visibility') != 'public' and env('attestations_available') != 'true':
        outcome, debt = 'ATTESTATION_HELD_BY_PLAN', 'IMPLEMENTATION_HELD'
    elif not env('signer_workflow') or not shutil.which('gh') or not os.path.exists(marker):
        outcome = 'ATTESTATION_NOT_ESTABLISHABLE'
    else:
        want = hashlib.sha256(io.open(marker, 'rb').read()).hexdigest()
        p = subprocess.run([shutil.which('gh'), 'attestation', 'verify', marker, '--repo', env('github_repository'),
                            '--signer-workflow', env('signer_workflow'), '--deny-self-hosted-runners',
                            '--format', 'json'], capture_output=True, text=True, encoding='utf-8', errors='replace')
        err = p.stderr or ''
        if p.returncode == 0:
            try:
                doc = json.loads(p.stdout)
                good = isinstance(doc, list) and doc and all(
                    want in [((s.get('digest') or {}).get('sha256')) for s in
                             ((x.get('verificationResult') or {}).get('statement') or {}).get('subject') or []]
                    for x in doc)
            except ValueError:
                good = False
            outcome = 'ATTESTATION_VERIFIED' if good else 'ATTESTATION_CONTRADICTED'
        elif re.search(r'no attestations found|HTTP 404', err, re.I):
            outcome = 'ATTESTATION_ABSENT'
        elif re.search(r'failed to verify|does not match|signature|certificate|mismatch|expected', err, re.I):
            outcome = 'ATTESTATION_CONTRADICTED'
        else:
            outcome = 'ATTESTATION_NOT_ESTABLISHABLE'
    route = {'ATTESTATION_VERIFIED': 'PROCEED', 'ATTESTATION_CONTRADICTED': 'BLOCKED',
             'ATTESTATION_HELD_BY_PLAN': 'PROCEED_WITH_ADVISORY'}.get(outcome)
    if outcome == 'ATTESTATION_ABSENT':
        route = 'PROCEED_WITH_ADVISORY' if rung == 'crawl' else 'DECISION_REQUIRED'
    route = route or 'EVIDENCE_UNTRUSTED'
    output(outcome=outcome, routing_result=route, debt=debt)
    summary('### Attestation verification (V1, static site marker)\n\n`%s` at rung %s routes `%s`%s.' % (
        outcome, rung, route, ' -- held: %s, trigger: the plan' % debt if debt else ''))
    if route not in ('PROCEED', 'PROCEED_WITH_ADVISORY'):
        print('::error title=Deploy refused before login (V1)::attestation %s at rung %s routes %s. The site '
              'about to be released is not shown to be the one the build signed. Nothing was deployed.'
              % (outcome, rung, route))
        return 1
    print('Attestation V1 %s: the deploy may proceed (%s).' % (outcome, route))
    return 0


# ----------------------------------------------------------------------------- live reads
def g(d, k):
    """az flattens a static site's properties; read either shape."""
    if not isinstance(d, dict):
        return None
    return d.get(k) if d.get(k) is not None else (d.get('properties') or {}).get(k)


def site():
    return dc.az('staticwebapp', 'show', '-n', env('site_name'), '-g', env('resource_group'))


def environments():
    """-> {buildId: {hostname, status}} or None when unreadable."""
    ok, envs, _ = dc.az('staticwebapp', 'environment', 'list', '-n', env('site_name'), '-g', env('resource_group'))
    if not ok or not isinstance(envs, list):
        return None
    return dict((str(g(e, 'buildId') or ''), {'hostname': g(e, 'hostname'), 'status': g(e, 'status')})
                for e in envs if isinstance(e, dict))


def build_id(name):
    return PRODUCTION_BUILD if name == PRODUCTION else name


def host_of(name, envs=None):
    if name == PRODUCTION:
        ok, shown, _ = site()
        if ok and g(shown, 'defaultHostname'):
            return g(shown, 'defaultHostname')
    envs = envs if envs is not None else environments()
    return ((envs or {}).get(build_id(name)) or {}).get('hostname')


def read_marker(host):
    """-> (digest or None, why). The marker the site SERVES, read now."""
    exe = shutil.which('curl')
    if not exe or not host:
        return None, 'no curl or no host'
    # The status after a separator no JSON body ends with (a newline would not survive a .cmd shim).
    p = subprocess.run([exe, '-sS', '--max-time', '10', '-w', '@@%{http_code}', 'https://%s/%s' % (host, MARKER)],
                       capture_output=True, text=True, encoding='utf-8', errors='replace')
    body, _, code = (p.stdout or '').rpartition('@@')
    if code.strip() != '200':
        return None, 'the marker answered HTTP %s' % (code.strip() or '000')
    try:
        d = json.loads(body).get('tree_digest')
    except (ValueError, AttributeError):
        return None, 'the marker is not readable JSON'
    return (d, '') if DIGEST_RE.match(d or '') else (None, 'the marker names no digest')


# ----------------------------------------------------------------------------- capture, capability
def _unknown(reason, snap):
    snap.update(previous_state='UNKNOWN', reason=reason)
    dc.write_evidence('snapshot.json', snap)
    output(previous_state='UNKNOWN')
    print('::error title=Previous state UNKNOWN::%s Nothing has been changed. A read failure, or content the '
          'kit cannot identify, is not an empty site, and an unknown previous state never resolves toward '
          'mutation.' % reason)
    return 1


def cmd_capture(a):
    snap = {'adapter': 'staticwebapp', 'app': env('site_name'), 'resource_group': env('resource_group'),
            'target': env('preview_environment') or 'production (direct)'}
    ok, shown, err = site()
    if not ok or not isinstance(shown, dict) or not g(shown, 'id'):
        return _unknown('The static site could not be read (%s).' % err, snap)
    envs = environments()
    if envs is None:
        return _unknown('The static site\'s environments could not be read.', snap)
    snap.update(resource_id=g(shown, 'id'), host=g(shown, 'defaultHostname'), tags=g(shown, 'tags') or {},
                environments=sorted(envs))
    prod = envs.get(PRODUCTION_BUILD)
    if not prod or str(prod.get('status') or '').lower() not in ('ready',):
        # MEASURED: both reads succeeded and production holds no build.
        snap.update(previous_state='EMPTY', prior_digest=None)
        dc.write_evidence('snapshot.json', snap)
        output(previous_state='EMPTY', previous='')
        print('Previous state EMPTY: the site has no production build.')
        return 0
    prior, why = read_marker(g(shown, 'defaultHostname'))
    if prior is None:
        return _unknown('Production serves a build, and its kit marker could not be read (%s): what serves is '
                        'not a release the kit can identify.' % why, snap)
    snap.update(previous_state='EXISTING_DEPLOYMENT', prior_digest=prior, prior_artifact=artifact_name(prior))
    dc.write_evidence('snapshot.json', snap)
    output(previous_state='EXISTING_DEPLOYMENT', previous=prior)
    print('Previous state EXISTING_DEPLOYMENT: production serves %s.' % prior)
    return 0


def cmd_capability(a):
    snap = dc.read_evidence('snapshot.json') or {}
    prev, tier = snap.get('previous_state'), env('environment_tier')
    if tier not in ('sandbox', 'dev', 'test') + PRODUCTION_TIERS:
        print('::error::environment_tier is not one of the registered tiers; the consequence of this deploy '
              'cannot be judged.')
        return 1
    art = None
    if env('rollback_on_failure') != 'true':
        cap, why = 'UNAVAILABLE', 'reversal authority withheld by the caller (rollback_on_failure false)'
    elif prev == 'EMPTY':
        cap, why = 'NO_PRIOR_STATE', ('production is measured empty; a static site cannot be emptied again, so a '
                                      'failed first release is reported for a human (the preview stage is the '
                                      'pre-traffic check)')
    elif prev != 'EXISTING_DEPLOYMENT':
        cap, why = 'UNAVAILABLE', 'previous state not established'
    else:
        try:
            art = find_artifact(snap['prior_digest'])
        except Exception as e:  # noqa: BLE001
            art, err = None, str(e)[:200]
        else:
            err = ''
        if art:
            cap, why = 'AVAILABLE', 'the prior release\'s artefact %s is retrievable' % artifact_name(snap['prior_digest'])
        else:
            cap, why = 'UNAVAILABLE', ('the prior release\'s artefact %s is %s: there is nothing to put back'
                                       % (artifact_name(snap['prior_digest']),
                                          'unreadable (%s)' % err if err else 'expired or never kept'))
    blocked = cap == 'UNAVAILABLE' and tier in PRODUCTION_TIERS
    dc.write_evidence('capability.json', {'rollback_capability': cap, 'why': why, 'tier': tier,
                                          'prior_artifact_id': (art or {}).get('id'),
                                          'decision': 'refused' if blocked else (
                                              'accepted risk, recorded' if cap == 'UNAVAILABLE' else 'proceed')})
    output(rollback_capability=cap)
    if blocked:
        print('::error title=Refused before the point of no return::rollback_capability UNAVAILABLE at production '
              'tier %s: %s.' % (tier, why))
        return 1
    if cap == 'UNAVAILABLE':
        print('::warning::rollback_capability UNAVAILABLE at tier %s (%s). Proceeding as a recorded accepted risk; '
              'a failure will need manual recovery.' % (tier, why))
    else:
        print('rollback_capability %s: %s' % (cap, why))
    return 0


# ----------------------------------------------------------------------------- the seam (K-6)
KV_REFERENCE = '@microsoft.keyvault('


def seam_entries(settings):
    """az's {name: value} map -> the deploy contract's entries. A Key Vault reference is secret-backed (the
    landing zone's, as a secretRef is on Container Apps); the value itself is only ever compared by digest."""
    return [dict({'name': k, 'value': v}, **({'secretRef': True} if str(v or '').strip().lower().startswith(KV_REFERENCE)
                                            else {}))
            for k, v in sorted((settings or {}).items())]


def cmd_seam(a):
    """The `seam` step: one owner per setting (KDEC-030 R3), decided before the first mutation."""
    if not os.environ.get('KIT_TARGET_LEASE_ACCOUNT'):
        output(seam_ownership='SEAM_OWNERSHIP_NOT_IN_FORCE')
        print('The seam is not in force for this environment (no KIT_TARGET_LEASE_ACCOUNT): nothing decided.')
        return 0
    ok, got, _err = dc.az('staticwebapp', 'appsettings', 'list', '-n', env('site_name'), '-g', env('resource_group'))
    props = g(got, 'properties') if ok and isinstance(got, dict) else None
    if ok and isinstance(got, dict) and props is None:
        props = {}   # a site with no settings: az shows no properties map
    prod = seam_entries(props) if isinstance(props, dict) else None
    # Nothing planned: the stamp and provenance are tags on the site, never app settings.
    outcome, why = dc.decide_seam('staticwebapp', env('kit_setting_keys'), prod, None, None, False, planned=[])
    dc.write_evidence('seam.json', {'seam_ownership': outcome, 'why': why, 'swap_checked': False,
                                    'kit_setting_keys': [k for k in (env('kit_setting_keys') or '').replace(',', ' ').split()
                                                         if k]})
    output(seam_ownership=outcome)
    summary('### Field ownership at the seam (KDEC-030 R3, before the first mutation)\n\n`%s`: %s' % (outcome, why))
    if outcome != 'SEAM_OWNERSHIP_HELD':
        print('::error title=Deploy refused before the first mutation (%s)::%s. Nothing was changed.' % (outcome, why))
        return 1
    print('seam ownership %s: %s' % (outcome, why))
    return 0


# ----------------------------------------------------------------------------- mutation
def fence(what):
    """KDEC-030: the SWA CLI is not an az call, so its fence is taken here. '' when it may proceed."""
    if not os.environ.get('KIT_TARGET_LEASE_ACCOUNT'):
        return ''
    try:
        import target_lease
        target_lease.fence_token_file()
    except Exception as e:  # noqa: BLE001 -- a fence that cannot run refuses
        code = getattr(e, 'code', 'LEASE_STORE_UNREACHABLE')
        print('::error title=target lease %s::%s was NOT sent: %s' % (code, what, ' '.join(str(e).split())))
        return '%s: %s' % (code, e)
    return ''


def token():
    ok, sec, err = dc.az('staticwebapp', 'secrets', 'list', '-n', env('site_name'), '-g', env('resource_group'))
    t = g(sec, 'apiKey') if ok else None
    if t:
        # Masked before anything else can print it; it is never written to an output or evidence file.
        print('::add-mask::%s' % t)
    return t, err


def swa(src, envname, tok):
    """-> (ok, text): the pinned SWA CLI, the token through its environment, never its arguments."""
    exe = shutil.which('swa')
    if not exe:
        return False, 'the SWA CLI is not installed'
    e = dict(os.environ, SWA_CLI_DEPLOYMENT_TOKEN=tok)
    p = subprocess.run([exe, 'deploy', src, '--env', envname, '--no-use-keychain'], env=e, capture_output=True,
                       text=True, encoding='utf-8', errors='replace')
    text = ((p.stdout or '') + (p.stderr or '')).replace(tok, '***')
    return p.returncode == 0, text.strip()[-400:]


def stamp_value():
    return 'release_id=%s;run=%s;post=static-site@%s' % (dc.release_id(), env('github_run_id') or 'local',
                                                        site_digest())


def deploy(envname, src, digest, m, entry_extra):
    """One release of `src` to environment `envname`, recorded before and after. -> True on success."""
    snap = dc.read_evidence('snapshot.json') or {}
    tok, err = token()
    if not tok:
        print('::error::The deployment token could not be read (%s); nothing was deployed to %s.' % (err, envname))
        return False
    entry = dict({'action': 'MODIFIED', 'object_type': 'static-site-environment', 'object': envname,
                  'post': digest, 'status': 'planned'}, **entry_extra)
    if envname == PRODUCTION:
        # The stamp travels with the mutation (DCR-OWN): production is claimed before it changes.
        stamp = stamp_value()
        prior_stamp = (snap.get('tags') or {}).get('release_ownership_stamp', '')
        ok, _, terr = dc.az('tag', 'update', '--resource-id', snap.get('resource_id', ''), '--operation', 'Merge',
                            '--tags', 'release_ownership_stamp=%s' % stamp)
        if not ok:
            print('::error::Production\'s ownership stamp could not be written (%s); nothing is deployed.' % terr)
            return False
        entry.update(stamp=stamp, prior_stamp=prior_stamp, resource_id=snap.get('resource_id'))
    m['entries'].append(entry)
    m['status'] = 'planned'
    dc.save_manifest(m)
    refused = fence('swa deploy --env %s' % envname)
    if refused:
        return False
    ok, text = swa(src, envname, tok)
    print(text)
    if not ok:
        print('::error::The SWA CLI did not confirm the deploy to %s.' % envname)
        return False
    entry['status'] = 'applied'
    m['status'] = 'applied'
    dc.save_manifest(m)
    return True


def cmd_deploy(a):
    envname = a.env
    snap = dc.read_evidence('snapshot.json') or {}
    m = dc.manifest()
    prior = snap.get('prior_digest') if envname == PRODUCTION else None
    ok = deploy(envname, site_dir(), site_digest(), m, {'prior': prior})
    output(deployed=envname if ok else '')
    return 0 if ok else 1


def cmd_verify(a):
    envname = a.env
    host = host_of(envname)
    live, why = read_marker(host)
    healthy = bool(host) and dc.probe('https://%s%s' % (host, env('health_path') or '/health'))
    held = live == site_digest() and healthy
    layer = {'host': host, 'marker': live, 'marker_why': why or None, 'health': 'passed' if healthy else 'failed'}
    if envname == PRODUCTION:
        dc.record_verification(production=layer, runtime_deployed=(live == site_digest()) if live else None,
                               serving_verified=held)
    else:
        dc.record_verification(**{'preview_' + re.sub(r'\W', '_', envname): layer})
    output(app_url='https://%s' % host if host else '', serving_digest=live or UNKNOWN)
    if not held:
        print('::error::%s does not serve %s healthily: marker %s (%s), health %s.' % (
            envname, site_digest(), live or UNKNOWN, why or 'read', layer['health']))
        return 1
    print('%s serves %s and answers health: verified on the live marker.' % (envname, site_digest()))
    return 0


def cmd_reverse(a):
    """Reverse what THIS run changed, newest first, each from live state."""
    m = dc.read_evidence('manifest.json') or {'entries': []}
    snap = dc.read_evidence('snapshot.json') or {}
    cap = dc.read_evidence('capability.json') or {}
    reversed_, left = [], []
    for e in reversed(m.get('entries') or []):
        envname = e.get('object')
        if envname != PRODUCTION:
            refused = fence('delete preview environment %s' % envname)
            ok = False
            if not refused:
                ok, _, err = dc.az('staticwebapp', 'environment', 'delete', '-n', env('site_name'), '-g',
                                   env('resource_group'), '--environment-name', envname, '--yes')
            envs = environments()
            gone = envs is not None and build_id(envname) not in envs
            (reversed_ if ok and gone else left).append(
                {'object': envname, 'reversal_disposition': 'REVERSAL_REMOVE',
                 'verified': gone, 'reversal_conflict': None if ok else (refused or 'the delete failed')})
            continue
        live, _ = read_marker(host_of(PRODUCTION))
        prior = e.get('prior')
        if live not in (site_digest(), prior):
            left.append({'object': envname, 'reversal_disposition': 'REVERSAL_REFUSED_CONFLICT',
                         'reversal_conflict': 'MODIFIED_BY_EXTERNAL_ACTOR: production serves %s, neither this '
                                              'release nor the one before it' % (live or UNKNOWN)})
            continue
        if not prior or cap.get('rollback_capability') != 'AVAILABLE':
            left.append({'object': envname, 'reversal_disposition': 'REVERSAL_WITHHELD_UNTRUSTED',
                         'reversal_conflict': 'PRECONDITION_UNESTABLISHED: %s' % (
                             cap.get('why') or 'no prior release to restore')})
            continue
        work = tempfile.mkdtemp(prefix='static-site-prior-')
        try:
            art = find_artifact(prior)
            if art is None:
                raise ValueError('the prior artefact is no longer retrievable')
            download_to(art, os.path.join(work, 'site'))
            ok, why = verify_dir(os.path.join(work, 'site'), prior)
            if not ok:
                raise ValueError('the prior artefact does not hash to %s: %s' % (prior, why))
            done = deploy(PRODUCTION, os.path.join(work, 'site'), prior, m,
                          {'prior': site_digest(), 'reversal_of': dc.release_id()})
            now, _ = read_marker(host_of(PRODUCTION))
            healthy = done and now == prior and dc.probe('https://%s%s' % (host_of(PRODUCTION), env('health_path') or '/health'))
            (reversed_ if healthy else left).append(
                {'object': envname, 'reversal_disposition': 'REVERSAL_RESTORE_PRIOR', 'restored': prior,
                 'verified': bool(healthy), 'now_serving': now or UNKNOWN,
                 'reversal_conflict': None if healthy else 'the restore did not verify on the live marker'})
        except Exception as ex:  # noqa: BLE001
            left.append({'object': envname, 'reversal_disposition': 'REVERSAL_RESTORE_PRIOR',
                         'reversal_conflict': 'not restored: %s' % ex})
        finally:
            shutil.rmtree(work, ignore_errors=True)
    result = 'ROLLBACK_VERIFIED' if reversed_ and not left else ('ROLLBACK_PARTIAL' if reversed_ or left else
                                                                 'STATUS_UNTRUSTED')
    dc.write_evidence('reversal.json', {'result': result, 'reversal_path': 'static site (static_site_contract.py)',
                                        'reversed': reversed_, 'not_reversed': left})
    output(reversal_result=result)
    print('Reversal %s: reversed %s; not reversed %s.' % (
        result, ', '.join(x['object'] for x in reversed_) or 'nothing',
        '; '.join('%s (%s)' % (x['object'], x.get('reversal_conflict')) for x in left) or 'nothing'))
    return 0 if result == 'ROLLBACK_VERIFIED' else 1


def cmd_provenance(a):
    live, why = read_marker(host_of(PRODUCTION))
    snap = dc.read_evidence('snapshot.json') or {}
    if live != site_digest():
        print('::error::Provenance NOT stamped: production serves %s (%s), not %s.' % (live or UNKNOWN, why,
                                                                                         site_digest()))
        output(provenance_state='not-stamped')
        return 1
    meta = env('version_metadata')
    tags = ['deploy_provenance_digest=%s' % site_digest(),
            'deploy_provenance_metadata_sha256=%s' % hashlib.sha256(meta.encode('utf-8')).hexdigest(),
            'deploy_provenance_run=%s-%s' % (env('github_run_id'), env('github_run_attempt'))]
    ok, _, err = dc.az('tag', 'update', '--resource-id', snap.get('resource_id', ''), '--operation', 'Merge',
                       '--tags', *tags)
    if not ok:
        print('::error::Provenance NOT stamped: the tag write failed (%s).' % err)
        output(provenance_state='not-stamped')
        return 1
    dc.write_evidence('provenance.json', {'resource_id': snap.get('resource_id'), 'tags': tags,
                                          'version_metadata': meta})
    output(provenance_state='stamped')
    print('Provenance stamped on the static site after a live read of what serves.')
    return 0


# ----------------------------------------------------------------------------- report
def derive_outcome(live):
    m = dc.read_evidence('manifest.json')
    snap = dc.read_evidence('snapshot.json') or {}
    rv = dc.read_evidence('reversal.json')
    if not m or not m.get('entries'):
        return 'DEPLOY_REFUSED', ('previous_state UNKNOWN: the capture could not identify what serves'
                                  if snap.get('previous_state') == 'UNKNOWN' else
                                  'refused before the first mutation (gate verdict, tier, digest, artefact or '
                                  'capability)')
    if any(e.get('status') != 'applied' for e in m['entries'] if not e.get('reversal_of')) and not rv:
        return 'PARTIAL_APPLY', 'a deploy was issued and never confirmed (manifest status %s)' % m.get('status')
    if env('cancelled') == 'true' and not rv:
        return 'STATUS_UNTRUSTED', 'cancelled after the mutation, before reconciliation'
    if rv and rv.get('result'):
        why = 'verification failed; reversal %s via %s' % (rv['result'], rv.get('reversal_path'))
        if rv.get('not_reversed'):
            why += '; NOT reversed: %s' % '; '.join('%s %s (%s)' % (n.get('object'), n.get('reversal_disposition'),
                                                                     n.get('reversal_conflict') or 'none')
                                                    for n in rv['not_reversed'])
        return rv['result'], why
    if env('serving_outcome') == 'success':
        if live is None:
            return 'STATUS_UNTRUSTED', 'serving was verified, then the live read-back failed'
        return ('DEPLOY_HEALTHY', 'the intended site is served and healthy, read on the live marker') \
            if live == site_digest() else ('STATUS_UNTRUSTED', 'production no longer serves what was verified')
    return 'MANUAL_RECOVERY_REQUIRED', ('verification failed and no reversal ran (rollback disabled, or the run '
                                        'stopped before it); the failed change is still in place')


def promotion(outcome):
    """The deploy contract's conjunction; identity here is the content digest proven before login plus V1."""
    proven = (dc.read_evidence('artifact.json') or {}).get('identity') == CONTENT_PROVEN
    # For a static site the registry proof's equivalent is the content digest recomputed from the very
    # files released; the deploy contract credits it only when this adapter says so.
    p = dc.promotion(outcome, content_proven=proven)
    p['identity_basis'] = CONTENT_PROVEN if proven else 'not established'
    return p


def cmd_report(a):
    snap = dc.read_evidence('snapshot.json')
    if snap is None:
        rows, live = [('site', 'not read: the run stopped before login and changed nothing')], None
    else:
        live, why = read_marker(host_of(PRODUCTION))
        rows = [('production site (live marker)', live or (UNKNOWN if snap.get('previous_state') != 'EMPTY' or
                                                           (dc.read_evidence('manifest.json') or {}).get('entries')
                                                           else 'nothing (no production build)'))]
    outcome, why = derive_outcome(live)
    unavailable = [c.strip() for c in env('controls_unavailable').split(',') if c.strip()]
    causes = [c.strip() for c in env('advisory_causes').split(',') if c.strip()]
    report = {'deployment_outcome': outcome, 'why': why, 'adapter': 'staticwebapp',
              'attempted': {'site': 'static-site@%s' % site_digest(),
                            'target': (env('preview_environment') + ' then production') if env('preview_environment')
                            else 'production (direct)'},
              'now_serving': [{'field': f, 'value': v} for f, v in rows],
              'health': env('health_outcome') or 'not run',
              'gate': {'routing_result': env('routing_result'), 'controls_unavailable': unavailable,
                       'advisory_causes': causes, 'version_gap_ruling': env('version_gap_ruling') or None,
                       'github_environment': env('deploy_environment')},
              'attestation': {'outcome': env('attestation_outcome') or None,
                              'routing_result': env('attestation_route') or None,
                              'debt': env('attestation_debt') or None}}
    report['promotion'] = promotion(outcome)
    q, esc = dc.six_questions(outcome, why)
    report['six_questions'], report['escalation'] = q, esc
    dc.write_evidence('outcome.json', report)
    lines = ['### Deploy outcome (staticwebapp): `%s`' % outcome, '', why, '',
             '| Claim | Field | Value |', '|---|---|---|']
    for f, v in report['attempted'].items():
        lines.append('| ATTEMPTED | %s | `%s` |' % (f, v))
    for f, v in rows:
        lines.append('| NOW SERVING | %s | `%s` |' % (f, v))
    lines += ['', 'Promotion: `%s`; not yet established: %s' % (
        report['promotion']['state'], ', '.join(report['promotion']['missing']) or 'nothing'),
        '', '| Question | Answer |', '|---|---|',
        '| Is progression blocked? | %s |' % ('yes' if q['progression_blocked'] else 'no'),
        '| Why? | %s |' % q['why'], '| Who owns resolution? | %s |' % q['resolution_owner'],
        '| What is the exact next action? | %s |' % q['next_action']]
    summary('\n'.join(lines))
    print('\n'.join(lines))
    output(deployment_outcome=outcome)
    if outcome != 'DEPLOY_HEALTHY':
        print('::error title=Deploy outcome %s::%s' % (outcome, why))
        return 1
    return 0


# ----------------------------------------------------------------------------- self-test
def self_test():
    d = tempfile.mkdtemp(prefix='static-site-selftest-')
    fails = []
    try:
        io.open(os.path.join(d, 'index.html'), 'w').write('a')
        os.makedirs(os.path.join(d, 'x'))
        io.open(os.path.join(d, 'x', 'b.js'), 'w').write('b')
        one = tree_digest(d)
        io.open(os.path.join(d, MARKER), 'w').write('{"tree_digest": "%s"}' % one)
        if tree_digest(d) != one:
            fails.append('the marker changed the digest it carries')
        if verify_dir(d, one) != (True, ''):
            fails.append('a site did not verify against its own digest')
        io.open(os.path.join(d, 'index.html'), 'a').write('!')
        if verify_dir(d, one)[0]:
            fails.append('a changed file still verified')
    finally:
        shutil.rmtree(d, ignore_errors=True)
    if fails:
        print('static_site_contract self-test FAILED: ' + '; '.join(fails))
        return 2
    print('static_site_contract self-test ok. The full proof is tests/prove_deploy_staticwebapp.py.')
    return 0


def main(argv=None):
    argv = list(sys.argv[1:] if argv is None else argv)
    if argv[:1] == ['--self-test']:
        return self_test()
    ap = argparse.ArgumentParser(description='Static Web Apps deploy contract (OF-5 K-8)')
    sub = ap.add_subparsers(dest='cmd', required=True)
    cmds = {'package': cmd_package, 'fetch': cmd_fetch, 'verify-artifact': cmd_verify_artifact,
            'attestation': cmd_attestation, 'capture': cmd_capture, 'capability': cmd_capability,
            'deploy': cmd_deploy, 'verify': cmd_verify, 'reverse': cmd_reverse, 'provenance': cmd_provenance,
            'report': cmd_report, 'seam': cmd_seam}
    for n in cmds:
        p = sub.add_parser(n)
        p.add_argument('--dir', default='')
        p.add_argument('--env', default=PRODUCTION)
    a = ap.parse_args(argv)
    return cmds[a.cmd](a)


if __name__ == '__main__':
    sys.exit(main())

#!/usr/bin/env python3
"""An organisation-hosted feed mirror is used only when it is CURRENT and INTACT; a stale, unreachable
or tampered mirror is a named refusal, never a silent fall back to "clean". (Release 4, owner
2026-10-27: "release 4 could have the mirrors yes? I could have it in the security platform azure
subscription"; KDEC-032 PROPOSED; docs/adoption/FEED_MIRRORS.md.)

WHY THIS EXISTS

    Every scan pulls three public feeds on its own: the Dependency-Check NVD datafeed, the CISA Known
    Exploited Vulnerabilities catalog (KEV) and the Trivy vulnerability database. At 500 repositories
    that is 500 cold pulls from third-party hosts (the cost redesign proposal, 0.4). The answer is one scheduled
    refresh into a private storage account the scans read. A mirror adds a new way to be wrong: it
    can stop refreshing, and a scan against a week-old database that reports nothing reads exactly
    like a clean one. So the consumer reads a MANIFEST the refresh wrote (source, upstream timestamp,
    sha256 per file, refreshed_at), and refuses -- by name -- whatever it cannot vouch for. Falling
    back to the public upstream happens only when the caller configured it, and is recorded.

WHAT IT PROVES (scripts/feed_mirror.py, .github/actions/feed-mirror, .github/actions/known-exploited,
scripts/known_exploited.py, reusable-feed-mirror-refresh.yml, the template, the consumer wiring and the
Terraform) -- file:// fixtures, no network, no Azure

    M1  the manifest lists every file with its sha256 and size, the feed, the generation's path, the
        upstream version and timestamp and refreshed_at; a tampered or missing file is named
    M2  a CURRENT mirror is used: the KEV file is fetched from the generation the manifest names and
        its sha256 checked (mirror_state MIRROR_CURRENT)
    M3  STALENESS REFUSES: refreshed_at older than the policy (48 h) is MIRROR_STALE, not usable; a
        caller may only TIGHTEN the policy -- a larger max age is clamped to the ceiling and said so
    M4  UNREACHABLE REFUSES: no manifest is MIRROR_UNREACHABLE, not usable
    M5  INTEGRITY REFUSES: a file whose bytes do not match the manifest, a manifest for another feed,
        an unreadable manifest, or a refreshed_at in the future is MIRROR_INTEGRITY_FAILED
    M6  EXPLICIT FALLBACK ONLY, AND RECORDED: with fallback `upstream` a refused mirror is
        MIRROR_FALLBACK_UPSTREAM with its cause, in the outputs, the summary and the evidence; with
        no fallback (or an unknown value) it refuses
    M7  TRIVY FAILS CLOSED: a current mirror is unpacked into the Trivy cache with the update switched
        off; a refused one WIPES any database already in the cache (a restored public copy) and still
        switches the update off, so every Trivy call in the job refuses instead of scanning stale data
        or silently reaching upstream
    M8  THE KEV COMPOSITE, as shipped (its run steps executed): a current mirror is read from the file
        (kev_source mirror, sha256 matched); a stale one is kev_state UNAVAILABLE naming MIRROR_STALE
        -- never CLEAR; not configured, the CISA feed as before
    M9  THE REFRESH SIDE: the NVD datafeed is copied from the upstream with each year's .meta sha256
        checked against the uncompressed bytes; a tampered year is refused
        (MIRROR_UPSTREAM_INTEGRITY_FAILED) and a stale upstream is refused (MIRROR_UPSTREAM_STALE);
        the KEV catalog must parse; a Trivy cache is packed with its metadata's UpdatedAt
    M10 pruning keeps the newest generations and never the one the manifest names
    M11 THE NVD PATH, as shipped: a refused NVD mirror marks the database update failed and the
        Dependency-Check run is not made (its report would read clean on a stale database)
    M12 WIRING: the refresh reusable (OIDC only, no key, no SAS, manifest uploaded LAST and read back
        through the consumer path), the daily + dispatch template, every Trivy and KEV consumer passes
        the mirror variables, and every mirror-consuming job can run on the private runner
    M13 THE AZURE SIDE (Terraform): public network access off, shared key off, private endpoints for
        `web` and `blob` with their private DNS zones, Storage Blob Data Contributor on the $web
        container only, AcrPush on the mirror registry only (anonymous pull, Premium, public off), no
        Owner/Contributor grant
    M14 the taxonomy registers every term

EXIT  0 proven   1 a rule failed (named)   2 could not be checked (UNKNOWN, never PASS)
"""
import datetime
import gzip
import hashlib
import io
import json
import os
import re
import shutil
import subprocess
import sys
import tarfile
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, HERE)
sys.path.insert(0, os.path.join(ROOT, 'scripts'))

FM = os.path.join(ROOT, 'scripts', 'feed_mirror.py')
KEV_SCRIPT = os.path.join(ROOT, 'scripts', 'known_exploited.py')
NOW = '2026-10-27T06:00:00Z'
KEV_CVE = 'CVE-2021-44228'
GEN = '20261027T050000Z-1'
WF = os.path.join(ROOT, '.github', 'workflows')
ACT = os.path.join(ROOT, '.github', 'actions')


def file_url(p):
    p = os.path.abspath(p).replace('\\', '/')
    return 'file:///' + p.lstrip('/')


def sha(b):
    return hashlib.sha256(b).hexdigest()


def write(p, data):
    os.makedirs(os.path.dirname(p), exist_ok=True)
    with io.open(p, 'wb') as fh:
        fh.write(data if isinstance(data, bytes) else data.encode('utf-8'))


def kev_bytes():
    return json.dumps({'title': 'CISA Catalog of Known Exploited Vulnerabilities', 'catalogVersion': '2026.10.26',
                       'dateReleased': '2026-10-26T17:00:00.0000Z', 'count': 1,
                       'vulnerabilities': [{'cveID': KEV_CVE, 'vendorProject': 'Apache', 'product': 'Log4j'}]},
                      indent=1).encode('utf-8')


def iso(dt):
    return dt.strftime('%Y-%m-%dT%H:%M:%SZ')


def ago(hours):
    return iso(datetime.datetime(2026, 10, 27, 6, 0, 0) - datetime.timedelta(hours=hours))


def publish(root, feed, files, refreshed_at, generation=GEN, upstream_version='v', upstream_ts='2026-10-26T00:00:00Z',
            tamper=None, feed_in_manifest=None):
    """A mirror laid out as the refresh writes it: <feed>/g/<gen>/<files> and <feed>/manifest.json."""
    path = '%s/g/%s/' % (feed, generation)
    entries = []
    for name, data in sorted(files.items()):
        write(os.path.join(root, *(path + name).split('/')), data)
        entries.append({'name': name, 'sha256': sha(data), 'size': len(data)})
    if tamper:
        write(os.path.join(root, *(path + tamper).split('/')), b'tampered bytes')
    man = {'schema': 'kit-feed-mirror-manifest/1', 'feed': feed_in_manifest or feed, 'generation': generation,
           'path': path, 'source_url': 'https://upstream.example/%s' % feed, 'upstream_version': upstream_version,
           'upstream_timestamp': upstream_ts, 'refreshed_at': refreshed_at, 'refreshed_by': 'run 1',
           'files': entries}
    write(os.path.join(root, feed, 'manifest.json'), json.dumps(man, indent=1))
    return man


def read_kv(path):
    out = {}
    if os.path.isfile(path):
        for line in io.open(path, encoding='utf-8'):
            if '=' in line:
                k, v = line.rstrip('\n').split('=', 1)
                out[k] = v
    return out


def consume(work, feed, mirror_url, *extra, tag='c'):
    d = os.path.join(work, tag)
    os.makedirs(d, exist_ok=True)
    go, ge, sm, ev = (os.path.join(d, n) for n in ('out', 'env', 'summary', 'evidence.json'))
    cmd = [sys.executable, FM, 'consume', '--feed', feed, '--mirror-url', mirror_url, '--now', NOW,
           '--out-dir', os.path.join(d, 'dl'), '--github-output', go, '--github-env', ge, '--summary', sm,
           '--evidence', ev] + list(extra)
    p = subprocess.run(cmd, capture_output=True, text=True)
    evid = {}
    if os.path.isfile(ev):
        try:
            evid = json.load(io.open(ev, encoding='utf-8'))
        except ValueError:
            pass
    summ = io.open(sm, encoding='utf-8').read() if os.path.isfile(sm) else ''
    return p.returncode, read_kv(go), read_kv(ge), summ, evid, p.stdout + p.stderr


def trivy_tar(inner_name, payload, updated_at):
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode='w:gz') as tf:
        for name, data in ((inner_name, payload),
                           ('metadata.json', json.dumps({'Version': 2, 'UpdatedAt': updated_at,
                                                         'NextUpdate': updated_at}).encode('utf-8'))):
            ti = tarfile.TarInfo(name)
            ti.size = len(data)
            tf.addfile(ti, io.BytesIO(data))
    return buf.getvalue()


def composite_steps(name):
    import yaml
    doc = yaml.safe_load(io.open(os.path.join(ACT, name, 'action.yml'), encoding='utf-8'))
    return doc, (doc.get('runs') or {}).get('steps') or []


def run_step(bash, step, env, cwd):
    """Run one composite `run:` step as shipped, with ${{ inputs.* }} already resolved in env."""
    script = step['run']
    script = re.sub(r'\$\{\{\s*[^}]*\}\}', '', script)  # every expression in these steps sits in env:
    f = os.path.join(cwd, 'step.sh')
    with io.open(f, 'w', encoding='utf-8', newline='\n') as fh:
        fh.write(script)
    e = dict(os.environ)
    e.update(env)
    p = subprocess.run([bash, f], capture_output=True, text=True, cwd=cwd, env=e)
    return p.returncode, p.stdout + p.stderr


def main():
    try:
        import yaml
        import prove_bootstrap_failure as pbf
    except ImportError as exc:
        print('UNKNOWN: %s' % exc)
        return 2
    if not os.path.isfile(FM):
        print('FAIL: scripts/feed_mirror.py does not exist: nothing reads a mirror manifest, so a stale or '
              'tampered organisation mirror would be scanned against as though it were current')
        return 1
    bash, why = pbf.usable_bash()
    if not bash:
        print('UNKNOWN: no usable bash (%s)' % why)
        return 2
    fails = []

    def check(cond, msg):
        if not cond:
            fails.append(msg)
        return cond

    work = tempfile.mkdtemp(prefix='feed-mirror-')
    try:
        sys.path.insert(0, os.path.join(ROOT, 'scripts'))
        import feed_mirror as fm

        # ---- M1 manifest build and local verification ---------------------------------------------
        d1 = os.path.join(work, 'm1')
        write(os.path.join(d1, 'a.json'), b'alpha')
        write(os.path.join(d1, 'sub', 'b.gz'), b'beta')
        man = fm.build_manifest('kev', d1, source_url='https://up/kev', upstream_version='2026.10.26',
                                upstream_timestamp='2026-10-26T17:00:00Z', generation=GEN, refreshed_at=NOW,
                                refreshed_by='run 1')
        names = sorted(f['name'] for f in man.get('files', []))
        check(names == ['a.json', 'sub/b.gz'], 'M1: manifest files are %r, not every file under the directory' % names)
        check(all(f.get('sha256') == sha(b'alpha' if f['name'] == 'a.json' else b'beta') and f.get('size') in (4, 5)
                  for f in man.get('files', [])), 'M1: manifest sha256/size do not match the bytes')
        for k in ('schema', 'feed', 'generation', 'path', 'source_url', 'upstream_version', 'upstream_timestamp',
                  'refreshed_at', 'refreshed_by'):
            check(k in man, 'M1: the manifest has no %s' % k)
        check(man.get('path') == 'kev/g/%s/' % GEN, 'M1: the manifest path is %r' % man.get('path'))
        check(fm.verify_dir(man, d1) == [], 'M1: an intact directory did not verify')
        write(os.path.join(d1, 'a.json'), b'ALPHA')
        os.remove(os.path.join(d1, 'sub', 'b.gz'))
        probs = fm.verify_dir(man, d1)
        check(any('a.json' in p for p in probs) and any('sub/b.gz' in p for p in probs),
              'M1: a tampered and a missing file were not both named: %r' % probs)
        print('  M1 manifest: %d files, verify names tampered+missing: %r' % (len(names), probs))

        # ---- M2 current KEV mirror ------------------------------------------------------------------
        mroot = os.path.join(work, 'mirror')
        kb = kev_bytes()
        publish(mroot, 'kev', {'known_exploited_vulnerabilities.json': kb}, ago(2), upstream_version='2026.10.26')
        rc, o, env, summ, ev, log = consume(work, 'kev', file_url(mroot), tag='m2')
        print('  M2 current: rc=%d state=%s file=%s' % (rc, o.get('mirror_state'), o.get('mirror_file')))
        check(rc == 0 and o.get('mirror_state') == 'MIRROR_CURRENT' and o.get('mirror_usable') == 'true',
              'M2: a current mirror was not MIRROR_CURRENT: %r\n%s' % (o, log[-600:]))
        f = o.get('mirror_file', '')
        check(f and os.path.isfile(f) and sha(io.open(f, 'rb').read()) == sha(kb) and o.get('mirror_sha256') == sha(kb),
              'M2: the KEV file was not fetched and sha-checked: %r' % o)
        check(o.get('mirror_url', '').endswith('/kev/g/%s/' % GEN), 'M2: mirror_url is not the generation: %r'
              % o.get('mirror_url'))
        check(o.get('mirror_upstream_version') == '2026.10.26' and o.get('mirror_refreshed_at') == ago(2),
              'M2: the upstream version and refreshed_at are not reported: %r' % o)

        # ---- M3 staleness ------------------------------------------------------------------------
        stale = os.path.join(work, 'stale')
        publish(stale, 'kev', {'known_exploited_vulnerabilities.json': kb}, ago(49))
        rc, o, _, summ, ev, log = consume(work, 'kev', file_url(stale), tag='m3a')
        print('  M3 49h old: state=%s usable=%s' % (o.get('mirror_state'), o.get('mirror_usable')))
        check(o.get('mirror_state') == 'MIRROR_STALE' and o.get('mirror_usable') == 'false' and not o.get('mirror_file'),
              'M3: a 49-hour-old mirror was not refused MIRROR_STALE: %r\n%s' % (o, log[-400:]))
        check('MIRROR_STALE' in summ, 'M3: the summary does not name MIRROR_STALE')
        fresh = os.path.join(work, 'fresh47')
        publish(fresh, 'kev', {'known_exploited_vulnerabilities.json': kb}, ago(47))
        _, o, _, _, _, _ = consume(work, 'kev', file_url(fresh), tag='m3b')
        check(o.get('mirror_state') == 'MIRROR_CURRENT', 'M3: a 47-hour-old mirror was refused: %r' % o)
        _, o, _, summ, _, _ = consume(work, 'kev', file_url(stale), '--max-age-hours', '1000', tag='m3c')
        check(o.get('mirror_state') == 'MIRROR_STALE' and o.get('mirror_max_age_hours') == '48',
              'M3: max-age 1000 widened the policy instead of being clamped to 48: %r' % o)
        check('ceiling' in summ.lower(), 'M3: the clamp is not said in the summary')
        _, o, _, _, _, _ = consume(work, 'kev', file_url(fresh), '--max-age-hours', '24', tag='m3d')
        check(o.get('mirror_state') == 'MIRROR_STALE' and o.get('mirror_max_age_hours') == '24',
              'M3: a tighter max age (24 h) was not honoured: %r' % o)

        # ---- M4 unreachable -------------------------------------------------------------------------
        _, o, _, summ, ev, _ = consume(work, 'kev', file_url(os.path.join(work, 'no-such-mirror')), tag='m4')
        print('  M4 unreachable: state=%s' % o.get('mirror_state'))
        check(o.get('mirror_state') == 'MIRROR_UNREACHABLE' and o.get('mirror_usable') == 'false',
              'M4: an unreachable mirror was not refused MIRROR_UNREACHABLE: %r' % o)
        _, o, _, _, _, _ = consume(work, 'kev', 'http://127.0.0.1:9/', '--timeout', '3', tag='m4b')
        check(o.get('mirror_state') == 'MIRROR_UNREACHABLE', 'M4: a closed port was not MIRROR_UNREACHABLE: %r' % o)

        # ---- M5 integrity ---------------------------------------------------------------------------
        cases = []
        t1 = os.path.join(work, 'tamper')
        publish(t1, 'kev', {'known_exploited_vulnerabilities.json': kb}, ago(1),
                tamper='known_exploited_vulnerabilities.json')
        cases.append(('bytes differ from the manifest', t1))
        t2 = os.path.join(work, 'wrongfeed')
        publish(t2, 'kev', {'known_exploited_vulnerabilities.json': kb}, ago(1), feed_in_manifest='nvd')
        cases.append(('a manifest for another feed', t2))
        t3 = os.path.join(work, 'garbage')
        write(os.path.join(t3, 'kev', 'manifest.json'), b'{not json')
        cases.append(('an unreadable manifest', t3))
        t4 = os.path.join(work, 'future')
        publish(t4, 'kev', {'known_exploited_vulnerabilities.json': kb}, ago(-3))
        cases.append(('refreshed_at in the future', t4))
        t5 = os.path.join(work, 'traversal')
        man5 = publish(t5, 'kev', {'known_exploited_vulnerabilities.json': kb}, ago(1))
        man5['files'][0]['name'] = '../../escape.json'
        write(os.path.join(t5, 'kev', 'manifest.json'), json.dumps(man5))
        cases.append(('a file name that escapes the generation', t5))
        for i, (what, root) in enumerate(cases):
            _, o, _, _, _, _ = consume(work, 'kev', file_url(root), tag='m5_%d' % i)
            check(o.get('mirror_state') == 'MIRROR_INTEGRITY_FAILED' and o.get('mirror_usable') == 'false',
                  'M5: %s was not MIRROR_INTEGRITY_FAILED: %r' % (what, o))
        print('  M5 integrity: %d refusal cases' % len(cases))

        # ---- M6 explicit fallback, recorded ---------------------------------------------------------
        _, o, _, summ, ev, _ = consume(work, 'kev', file_url(stale), '--fallback', 'upstream', tag='m6a')
        print('  M6 fallback: state=%s cause=%s' % (o.get('mirror_state'), o.get('mirror_cause')))
        check(o.get('mirror_state') == 'MIRROR_FALLBACK_UPSTREAM' and o.get('mirror_cause') == 'MIRROR_STALE'
              and o.get('mirror_usable') == 'true' and o.get('mirror_url') == '',
              'M6: an explicit upstream fallback was not MIRROR_FALLBACK_UPSTREAM with its cause: %r' % o)
        check('MIRROR_FALLBACK_UPSTREAM' in summ and 'MIRROR_STALE' in summ,
              'M6: the summary does not record the fallback and its cause')
        check(ev.get('mirror_state') == 'MIRROR_FALLBACK_UPSTREAM' and ev.get('mirror_cause') == 'MIRROR_STALE'
              and ev.get('fallback') == 'upstream', 'M6: the evidence does not record the fallback: %r' % ev)
        _, o, _, _, _, _ = consume(work, 'kev', file_url(stale), '--fallback', 'none', tag='m6b')
        check(o.get('mirror_state') == 'MIRROR_STALE', 'M6: fallback none did not refuse: %r' % o)
        _, o, _, _, _, _ = consume(work, 'kev', file_url(stale), '--fallback', 'Upstream-ish', tag='m6c')
        check(o.get('mirror_state') == 'MIRROR_STALE', 'M6: an unknown fallback value fell back: %r' % o)
        _, o, _, _, _, _ = consume(work, 'kev', file_url(mroot), '--fallback', 'upstream', tag='m6d')
        check(o.get('mirror_state') == 'MIRROR_CURRENT', 'M6: fallback was taken on a CURRENT mirror: %r' % o)
        _, o, _, _, ev, _ = consume(work, 'kev', '', tag='m6e')
        check(o.get('mirror_state') == 'NOT_CONFIGURED' and o.get('mirror_usable') == 'true' and o.get('mirror_url') == '',
              'M6: an unconfigured mirror is not NOT_CONFIGURED: %r' % o)

        # ---- M7 Trivy -------------------------------------------------------------------------------
        troot = os.path.join(work, 'tmirror')
        db = trivy_tar('trivy.db', b'MIRROR-DB', '2026-10-27T00:00:00Z')
        jdb = trivy_tar('trivy-java.db', b'MIRROR-JAVA-DB', '2026-10-26T00:00:00Z')
        publish(troot, 'trivy', {'db.tar.gz': db, 'java-db.tar.gz': jdb}, ago(3))
        cache = os.path.join(work, 'trivy-cache')
        write(os.path.join(cache, 'db', 'trivy.db'), b'RESTORED-PUBLIC-DB')
        _, o, env, _, _, log = consume(work, 'trivy', file_url(troot), '--trivy-cache-dir', cache, tag='m7a')
        got = io.open(os.path.join(cache, 'db', 'trivy.db'), 'rb').read() if os.path.isfile(
            os.path.join(cache, 'db', 'trivy.db')) else b''
        print('  M7 trivy current: state=%s db=%r env=%r' % (o.get('mirror_state'), got, sorted(env)))
        check(o.get('mirror_state') == 'MIRROR_CURRENT' and got == b'MIRROR-DB'
              and os.path.isfile(os.path.join(cache, 'java-db', 'trivy-java.db')),
              'M7: the current Trivy mirror was not unpacked into the cache: %r\n%s' % (o, log[-500:]))
        check(env.get('TRIVY_SKIP_DB_UPDATE') == 'true' and env.get('TRIVY_SKIP_JAVA_DB_UPDATE') == 'true'
              and env.get('TRIVY_CACHE_DIR') == cache,
              'M7: a current mirror did not switch the Trivy update off and pin the cache: %r' % env)
        tstale = os.path.join(work, 'tstale')
        publish(tstale, 'trivy', {'db.tar.gz': db, 'java-db.tar.gz': jdb}, ago(72))
        write(os.path.join(cache, 'db', 'trivy.db'), b'RESTORED-PUBLIC-DB')
        _, o, env, summ, _, _ = consume(work, 'trivy', file_url(tstale), '--trivy-cache-dir', cache, tag='m7b')
        print('  M7 trivy stale: state=%s db present=%s' % (o.get('mirror_state'),
                                                           os.path.exists(os.path.join(cache, 'db', 'trivy.db'))))
        check(o.get('mirror_state') == 'MIRROR_STALE' and not os.path.exists(os.path.join(cache, 'db', 'trivy.db'))
              and env.get('TRIVY_SKIP_DB_UPDATE') == 'true',
              'M7: a refused Trivy mirror left a database in the cache or let Trivy update from upstream: %r %r'
              % (o, env))
        evil = os.path.join(work, 'tevil')
        buf = io.BytesIO()
        with tarfile.open(fileobj=buf, mode='w:gz') as tf:
            ti = tarfile.TarInfo('../escaped.db')
            ti.size = 1
            tf.addfile(ti, io.BytesIO(b'x'))
        publish(evil, 'trivy', {'db.tar.gz': buf.getvalue(), 'java-db.tar.gz': jdb}, ago(1))
        _, o, _, _, _, _ = consume(work, 'trivy', file_url(evil), '--trivy-cache-dir', os.path.join(work, 'c2', 'tc'),
                                   tag='m7c')
        check(o.get('mirror_state') == 'MIRROR_INTEGRITY_FAILED' and not os.path.exists(os.path.join(work, 'c2', 'escaped.db')),
              'M7: an archive member escaping the cache was not refused: %r' % o)
        _, o, env, _, _, _ = consume(work, 'trivy', file_url(tstale), '--trivy-cache-dir', cache, '--fallback',
                                     'upstream', tag='m7d')
        check(o.get('mirror_state') == 'MIRROR_FALLBACK_UPSTREAM' and 'TRIVY_SKIP_DB_UPDATE' not in env,
              'M7: an explicit fallback did not let Trivy update from its upstream: %r %r' % (o, env))

        # ---- M8 the KEV composite as shipped ---------------------------------------------------------
        kdoc, ksteps = composite_steps('known-exploited')
        ins = kdoc.get('inputs') or {}
        check(all(k in ins for k in ('mirror-url', 'mirror-max-age-hours', 'mirror-fallback')),
              'M8: the known-exploited composite has no mirror-url / mirror-max-age-hours / mirror-fallback inputs')
        mstep = next((s for s in ksteps if s.get('id') == 'mirror'), None)
        kstep = next((s for s in ksteps if s.get('id') == 'k'), None)
        if check(mstep is not None and kstep is not None, 'M8: the composite has no `mirror` step before `k`'):
            check(ksteps.index(mstep) < ksteps.index(kstep), 'M8: the mirror step runs after the check')
            # The kit as a runner receives it: the composite's directory three levels under the root,
            # the scripts with LF endings (a Windows checkout's CRLF would stop bash, not the step).
            kit = os.path.join(work, 'kit')
            action_path = os.path.join(kit, '.github', 'actions', 'known-exploited')
            os.makedirs(action_path, exist_ok=True)
            for fn in ('feed_mirror.py', 'feed_mirror_step.sh', 'known_exploited.py'):
                data = io.open(os.path.join(ROOT, 'scripts', fn), 'rb').read().replace(b'\r\n', b'\n')
                write(os.path.join(kit, 'scripts', fn), data)

            def run_kev(tag, mirror_url, fallback='none', drop_mirror_outputs=False):
                d = os.path.join(work, tag)
                os.makedirs(d, exist_ok=True)
                go, sm = os.path.join(d, 'out'), os.path.join(d, 'sum')
                base = {'GITHUB_ACTION_PATH': action_path, 'RUNNER_TEMP': d, 'GITHUB_OUTPUT': go,
                        'GITHUB_STEP_SUMMARY': sm, 'GITHUB_ENV': os.path.join(d, 'env')}
                menv = dict(base, M_FEED='kev', M_URL=mirror_url, M_MAX_AGE='48', M_FALLBACK=fallback, M_NOW=NOW)
                rc1, l1 = run_step(bash, mstep, menv, d)
                mo = {} if drop_mirror_outputs else read_kv(go)
                os.remove(go) if os.path.exists(go) else None
                kenv = dict(base, K_CVE_FINDINGS='deps-scan:abcdefabcdef:%s' % KEV_CVE, K_SARIF='', K_SARIF_JOB='nvd',
                            K_EXCEPTIONS='[]', K_POLICY_STATE='POLICY_RESOLVED',
                            K_FEED_URL=file_url(os.path.join(work, 'no-public-feed.json')), K_DAY='2026-10-27',
                            K_MIRROR_STATE=mo.get('mirror_state', ''), K_MIRROR_USABLE=mo.get('mirror_usable', ''),
                            K_MIRROR_FILE=mo.get('mirror_file', ''), K_MIRROR_SHA256=mo.get('mirror_sha256', ''),
                            K_MIRROR_WHY=mo.get('mirror_why', ''), K_MIRROR_URL=mirror_url)
                rc2, l2 = run_step(bash, kstep, kenv, d)
                return mo, read_kv(go), l1 + l2

            mo, ko, log = run_kev('m8a', file_url(mroot))
            print('  M8 composite current: mirror=%s kev_state=%s source=%s verdict=%s'
                  % (mo.get('mirror_state'), ko.get('kev_state'), ko.get('kev_source'), ko.get('kev_verdict')))
            check(ko.get('kev_state') == 'AVAILABLE' and ko.get('kev_source') == 'mirror'
                  and ko.get('kev_sha256') == sha(kb) and ko.get('kev_verdict') == 'BLOCKED',
                  'M8: the composite did not read the current mirror (and block the catalogued CVE): %r %r\n%s'
                  % (mo, ko, log[-800:]))
            mo, ko, log = run_kev('m8b', file_url(stale))
            print('  M8 composite stale: kev_state=%s why=%s' % (ko.get('kev_state'), ko.get('kev_why', '')[:60]))
            check(ko.get('kev_state') == 'UNAVAILABLE' and ko.get('kev_verdict') == 'UNAVAILABLE'
                  and 'MIRROR_STALE' in ko.get('kev_why', ''),
                  'M8: a stale mirror was not kev_state UNAVAILABLE naming MIRROR_STALE: %r\n%s' % (ko, log[-800:]))
            mo, ko, log = run_kev('m8c', '')
            check(mo.get('mirror_state') == 'NOT_CONFIGURED' and ko.get('kev_state') == 'UNAVAILABLE'
                  and 'no-public-feed' in ko.get('kev_why', ''),
                  'M8: with no mirror the composite did not read the configured public feed: %r %r' % (mo, ko))
            # A mirror step that reported NOTHING, with a mirror named, is refused -- never read as
            # "not configured", which would quietly fall back to the public feed.
            mo, ko, log = run_kev('m8d', file_url(mroot), drop_mirror_outputs=True)
            check(ko.get('kev_state') == 'UNAVAILABLE' and 'MIRROR_UNREACHABLE' in ko.get('kev_why', ''),
                  'M8: an absent mirror state with a mirror named was not refused: %r %s' % (ko, log[-500:]))
            # A configured, readable mirror must never be bypassed for a cached public copy.
            texts = json.dumps(ksteps)
            check("steps.mirror.outputs.mirror_state != 'MIRROR_CURRENT'" in texts,
                  'M8: the date-keyed public cache is not skipped when the mirror is current')
            check(kdoc.get('outputs', {}).get('kev_mirror_state') is not None,
                  'M8: the composite does not output kev_mirror_state')

        # ---- M9 the refresh side --------------------------------------------------------------------
        up = os.path.join(work, 'upstream-nvd')
        years = {'2002': b'{"cves":[2002]}', '2026': b'{"cves":[2026]}', 'modified': b'{"cves":["mod"]}'}
        props = ['#generated', 'prefix=nvdcve-', 'lastModifiedDate=2026-10-27T05\\:00\\:00Z']
        for y, raw in years.items():
            gz = gzip.compress(raw)
            write(os.path.join(up, 'nvdcve-%s.json.gz' % y), gz)
            write(os.path.join(up, 'nvdcve-%s.meta' % y),
                  'lastModifiedDate:2026-10-27T05:00:00.000Z\r\nsize:%d\r\ngzSize:%d\r\nsha256:%s\r\n'
                  % (len(raw), len(gz), sha(raw)))
            props.append('lastModifiedDate.%s=2026-10-27T05\\:00\\:00Z' % y)
        write(os.path.join(up, 'cache.properties'), '\n'.join(props) + '\n')
        out = os.path.join(work, 'nvd-out')
        p = subprocess.run([sys.executable, FM, 'fetch-nvd', '--upstream', file_url(up) + '/', '--out', out,
                            '--now', NOW], capture_output=True, text=True)
        info = {}
        try:
            info = json.loads(p.stdout.strip().splitlines()[-1]) if p.stdout.strip() else {}
        except ValueError:
            pass
        got = sorted(os.listdir(out)) if os.path.isdir(out) else []
        print('  M9 nvd fetch: rc=%d files=%d ts=%s' % (p.returncode, len(got), info.get('upstream_timestamp')))
        check(p.returncode == 0 and 'cache.properties' in got and 'nvdcve-2026.json.gz' in got
              and 'nvdcve-modified.meta' in got and info.get('upstream_timestamp') == '2026-10-27T05:00:00Z',
              'M9: the NVD datafeed was not copied whole: rc=%d %r %r\n%s' % (p.returncode, got, info, p.stderr[-500:]))
        write(os.path.join(up, 'nvdcve-2026.json.gz'), gzip.compress(b'{"cves":["TAMPERED"]}'))
        p = subprocess.run([sys.executable, FM, 'fetch-nvd', '--upstream', file_url(up) + '/', '--out',
                            os.path.join(work, 'nvd-out2'), '--now', NOW], capture_output=True, text=True)
        check(p.returncode != 0 and 'MIRROR_UPSTREAM_INTEGRITY_FAILED' in p.stdout + p.stderr,
              'M9: a year whose bytes do not match its .meta sha256 was not refused: rc=%d %s'
              % (p.returncode, (p.stdout + p.stderr)[-300:]))
        write(os.path.join(up, 'nvdcve-2026.json.gz'), gzip.compress(years['2026']))
        p = subprocess.run([sys.executable, FM, 'fetch-nvd', '--upstream', file_url(up) + '/', '--out',
                            os.path.join(work, 'nvd-out3'), '--now', '2026-11-05T00:00:00Z'],
                           capture_output=True, text=True)
        check(p.returncode != 0 and 'MIRROR_UPSTREAM_STALE' in p.stdout + p.stderr,
              'M9: an upstream datafeed 9 days old was not refused MIRROR_UPSTREAM_STALE: rc=%d' % p.returncode)
        kup = os.path.join(work, 'kev-up.json')
        write(kup, kb)
        p = subprocess.run([sys.executable, FM, 'fetch-kev', '--upstream', file_url(kup), '--out',
                            os.path.join(work, 'kev-out')], capture_output=True, text=True)
        try:
            kinfo = json.loads(p.stdout.strip().splitlines()[-1])
        except (ValueError, IndexError):
            kinfo = {}
        check(p.returncode == 0 and kinfo.get('upstream_version') == '2026.10.26',
              'M9: the KEV catalog was not fetched with its catalogVersion: %r %s' % (kinfo, p.stderr[-300:]))
        write(kup, b'{"vulnerabilities": []}')
        p = subprocess.run([sys.executable, FM, 'fetch-kev', '--upstream', file_url(kup), '--out',
                            os.path.join(work, 'kev-out2')], capture_output=True, text=True)
        check(p.returncode != 0 and 'MIRROR_UPSTREAM_INTEGRITY_FAILED' in p.stdout + p.stderr,
              'M9: an empty KEV catalog was published: rc=%d' % p.returncode)
        tc = os.path.join(work, 'trivy-src')
        write(os.path.join(tc, 'db', 'trivy.db'), b'DB')
        write(os.path.join(tc, 'db', 'metadata.json'), json.dumps({'Version': 2, 'UpdatedAt': '2026-10-27T00:10:00Z'}))
        write(os.path.join(tc, 'java-db', 'trivy-java.db'), b'JDB')
        write(os.path.join(tc, 'java-db', 'metadata.json'), json.dumps({'Version': 1, 'UpdatedAt': '2026-10-26T01:00:00Z'}))
        p = subprocess.run([sys.executable, FM, 'pack-trivy', '--cache-dir', tc, '--out', os.path.join(work, 'tpack'),
                            '--now', NOW], capture_output=True, text=True)
        try:
            tinfo = json.loads(p.stdout.strip().splitlines()[-1])
        except (ValueError, IndexError):
            tinfo = {}
        check(p.returncode == 0 and tinfo.get('upstream_timestamp') == '2026-10-27T00:10:00Z'
              and sorted(os.listdir(os.path.join(work, 'tpack'))) == ['db.tar.gz', 'java-db.tar.gz'],
              'M9: the Trivy cache was not packed with its UpdatedAt: %r %s' % (tinfo, p.stderr[-300:]))

        # ---- M10 prune plan -------------------------------------------------------------------------
        gens = ['20261020T050000Z-1', '20261027T050000Z-9', '20261025T050000Z-5', '20261026T050000Z-7',
                '20261021T050000Z-2']
        drop = fm.prune_plan(gens, keep=3, current='20261021T050000Z-2')
        check(sorted(drop) == ['20261020T050000Z-1'],
              'M10: prune keeps the newest 3 plus the current generation; it would delete %r' % drop)
        check('20261027T050000Z-9' not in fm.prune_plan(gens, keep=0, current='20261027T050000Z-9'),
              'M10: prune would delete the generation the manifest names')

        # ---- M11 the NVD path as shipped -----------------------------------------------------------
        nvd = yaml.safe_load(io.open(os.path.join(WF, 'reusable-nvd-cve.yml'), encoding='utf-8'))
        nsteps = (nvd['jobs']['nvd-cve-scan'].get('steps') or [])
        ids = [s.get('id') for s in nsteps]
        mirror_steps = [s for s in nsteps if str(s.get('uses', '')).endswith('.github/actions/feed-mirror')]
        feeds = sorted(str((s.get('with') or {}).get('feed')) for s in mirror_steps)
        check(feeds == ['nvd', 'trivy', 'trivy-checks'], 'M11: reusable-nvd-cve.yml does not run the feed-mirror composite for nvd, trivy '
                                         'and trivy-checks (found %r)' % feeds)
        upd = next((s for s in nsteps if s.get('id') == 'nvd_update'), None)
        dcr = next((s for s in nsteps if s.get('id') == 'dc_run'), None)
        nm = next((s for s in mirror_steps if (s.get('with') or {}).get('feed') == 'nvd'), None)
        tm = next((s for s in mirror_steps if (s.get('with') or {}).get('feed') == 'trivy'), None)
        if check(upd is not None and dcr is not None and nm is not None and tm is not None,
                 'M11: the NVD path is missing nvd_update, dc_run or a mirror step'):
            check(ids.index(nm.get('id')) < ids.index('nvd_update'), 'M11: the NVD mirror is read after the update')
            check(ids.index(tm.get('id')) < ids.index('trivy_fs'), 'M11: the Trivy mirror is read after the scan')
            check('NVD_MIRROR_REFUSED' in str(dcr.get('if', '')), 'M11: dc_run is not skipped on a refused mirror')
            d = os.path.join(work, 'm11')
            os.makedirs(d, exist_ok=True)
            stub = os.path.join(d, 'dc.sh')
            with io.open(stub, 'w', encoding='utf-8', newline='\n') as fh:
                fh.write('#!/bin/sh\necho "$@" > "%s/dc-args"\nexit 0\n' % d.replace('\\', '/'))
            script = upd['run'].replace('/opt/dependency-check/bin/dependency-check.sh', 'sh ' + stub.replace('\\', '/'))
            script = script.replace('/tmp/nvd-data', d.replace('\\', '/') + '/nvd-data')
            step = {'run': script}
            for state, usable, url in (('MIRROR_STALE', 'false', ''),
                                       ('MIRROR_CURRENT', 'true', 'https://mirror.example/nvd/g/%s/' % GEN)):
                for f_ in ('env', 'out', 'dc-args'):
                    if os.path.exists(os.path.join(d, f_)):
                        os.remove(os.path.join(d, f_))
                env = {'GITHUB_ENV': os.path.join(d, 'env'), 'GITHUB_OUTPUT': os.path.join(d, 'out'),
                       'NVD_API_KEY': '', 'W_NVD_DATAFEED': 'https://dependency-check.github.io/x/',
                       'M_STATE': state, 'M_USABLE': usable, 'M_URL': url, 'M_WHY': 'refreshed 72 h ago'}
                rc, log = run_step(bash, step, env, d)
                genv, gout = read_kv(os.path.join(d, 'env')), read_kv(os.path.join(d, 'out'))
                args = io.open(os.path.join(d, 'dc-args'), encoding='utf-8').read() if os.path.isfile(
                    os.path.join(d, 'dc-args')) else ''
                if usable == 'false':
                    print('  M11 refused NVD mirror: rc=%d env=%r dc-ran=%s' % (rc, genv, bool(args)))
                    check(genv.get('NVD_UPDATE_FAILED') == 'true' and genv.get('NVD_MIRROR_REFUSED') == 'true'
                          and not args and gout.get('complete') != 'true',
                          'M11: a refused NVD mirror did not mark the update failed without running '
                          'Dependency-Check: rc=%d %r %r\n%s' % (rc, genv, args, log[-500:]))
                else:
                    check(('--nvdDatafeed ' + url) in args and 'dependency-check.github.io' not in args,
                          'M11: a current NVD mirror was not the datafeed the update read: %r\n%s' % (args, log[-500:]))

        # ---- M12 wiring -----------------------------------------------------------------------------
        ref_path = os.path.join(WF, 'reusable-feed-mirror-refresh.yml')
        if check(os.path.isfile(ref_path), 'M12: .github/workflows/reusable-feed-mirror-refresh.yml does not exist'):
            wtext = io.open(ref_path, encoding='utf-8').read()
            rdoc = yaml.safe_load(wtext)
            cpath = os.path.join(ACT, 'feed-mirror-refresh', 'action.yml')
            check(os.path.isfile(cpath) and '$/.github/actions/feed-mirror-refresh' in wtext,
                  'M12: the refresh workflow does not run the feed-mirror-refresh composite through $/')
            rtext = wtext + chr(10) + (io.open(cpath, encoding='utf-8').read() if os.path.isfile(cpath) else '')
            on = rdoc.get(True) or rdoc.get('on') or {}
            check('workflow_call' in on, 'M12: the refresh workflow is not reusable (workflow_call)')
            perms = rdoc.get('permissions') or {}
            check(perms == {'contents': 'read', 'id-token': 'write'},
                  'M12: the refresh workflow permissions are %r, not exactly contents read + id-token write' % perms)
            low = rtext.lower()
            for bad in ('--account-key', 'connection-string', '--sas-token', 'generate-sas', 'creds:', 'admin-enabled'):
                check(bad not in low, 'M12: the refresh workflow uses a key-shaped credential (%s)' % bad)
            check('--auth-mode login' in rtext, 'M12: blob writes are not Entra (--auth-mode login)')
            check('azure/login@' in rtext and re.search(r'azure/login@[0-9a-f]{40}', rtext),
                  'M12: azure/login is not pinned by SHA')
            for k in ('fetch-nvd', 'fetch-kev', 'pack-trivy', 'manifest', 'prune-plan', 'consume'):
                check(('"$fm" %s' % k) in rtext or ('feed_mirror.py %s' % k) in rtext,
                      'M12: the refresh workflow never runs feed_mirror.py %s' % k)
            i_files = rtext.find('upload-batch')
            i_man = rtext.find('manifest.json', i_files if i_files >= 0 else 0)
            i_ver = rtext.find('--verify-all')
            check(0 <= i_files < i_man < i_ver, 'M12: the manifest is not uploaded after the files and verified '
                                                'through the consumer path (--verify-all) after that')
            jobs = rdoc.get('jobs') or {}
            check(jobs and all('inputs.runner' in str(j.get('runs-on', '')) for j in jobs.values())
                  and all(j.get('environment') for j in jobs.values()),
                  'M12: a refresh job does not run on the caller-named (private) runner')
            check('docker buildx imagetools create' in rtext and 'oauth2/exchange' in rtext,
                  'M12: the image mirror does not copy by digest with a data-plane ACR token')
        tpath = os.path.join(ROOT, 'templates', 'feed-mirror-refresh.yml')
        if check(os.path.isfile(tpath), 'M12: templates/feed-mirror-refresh.yml does not exist'):
            tdoc = yaml.safe_load(io.open(tpath, encoding='utf-8'))
            ton = tdoc.get(True) or tdoc.get('on') or {}
            check('schedule' in ton and 'workflow_dispatch' in ton, 'M12: the template is not scheduled + dispatch')
            ttext = io.open(tpath, encoding='utf-8').read()
            check('reusable-feed-mirror-refresh.yml@' in ttext and 'id-token: write' in ttext,
                  'M12: the template does not call the reusable with id-token write')
        trivy_sites = {
            os.path.join(ACT, 'deps-scan', 'action.yml'): 'composite',
            os.path.join(ACT, 'docker-build-push', 'action.yml'): 'composite',
            os.path.join(WF, 'reusable-security.yml'): 'image-scan',
            os.path.join(WF, 'reusable-build-docker.yml'): 'workflow',
            os.path.join(WF, 'reusable-deploy-appservice.yml'): 'workflow',
            os.path.join(WF, 'reusable-deploy-containerapp.yml'): 'workflow',
            os.path.join(WF, 'reusable-deployed-scan.yml'): 'workflow',
            os.path.join(WF, 'reusable-nvd-cve.yml'): 'workflow',
        }
        for path in trivy_sites:
            t = io.open(path, encoding='utf-8').read()
            n_inst = len(re.findall(r'trivy_\$\{v\}_Linux-64bit|t=trivy_0\.71\.2_Linux-64bit', t))
            n_mirror = len(re.findall(r'\.github/actions/feed-mirror|scripts/feed_mirror_step\.sh', t))
            if path.endswith('reusable-nvd-cve.yml'):
                n_inst -= 1  # the Dockerfile config scan reads no vulnerability database
            check(n_mirror >= max(1, n_inst),
                  'M12: %s installs Trivy %d time(s) but reads the Trivy mirror %d time(s)'
                  % (os.path.relpath(path, ROOT), n_inst, n_mirror))
        kev_sites = ['reusable-security.yml', 'reusable-nvd-cve.yml', 'reusable-deployed-scan.yml',
                     'reusable-deploy-appservice.yml', 'reusable-deploy-containerapp.yml']
        for wf in kev_sites:
            doc = yaml.safe_load(io.open(os.path.join(WF, wf), encoding='utf-8'))
            for jn, job in (doc.get('jobs') or {}).items():
                uses = [s for s in job.get('steps') or [] if
                        str(s.get('uses', '')).endswith(('.github/actions/known-exploited', '.github/actions/feed-mirror',
                                                         '.github/actions/deps-scan', '.github/actions/docker-build-push'))]
                for s in uses:
                    w = s.get('with') or {}
                    key = 'mirror-url' if 'known-exploited' in s['uses'] or 'feed-mirror' in s['uses'] else 'feed-mirror-url'
                    check('vars.KIT_FEED_MIRROR_URL' in str(w.get(key, '')),
                          'M12: %s job %s step %r does not pass vars.KIT_FEED_MIRROR_URL as %s'
                          % (wf, jn, s.get('name'), key))
                if uses:
                    # The deploys' job has ONE caller-owned runner input (KDEC-030's runner_label): the lease
                    # store and the mirrors are both private, so the same private runner serves both.
                    ro = str(job.get('runs-on', ''))
                    check('vars.KIT_FEED_MIRROR_RUNNER' in ro or (wf.startswith('reusable-deploy-')
                                                                   and 'inputs.runner_label' in ro),
                          'M12: %s job %s reads the mirror but cannot run on the private runner '
                          '(runs-on %r)' % (wf, jn, job.get('runs-on')))
        sec = yaml.safe_load(io.open(os.path.join(WF, 'reusable-security.yml'), encoding='utf-8'))
        sg = sec['jobs'].get('sast-semgrep') or {}
        img = str((sg.get('container') or {}).get('image', ''))
        check('vars.KIT_SCANNER_IMAGE_REGISTRY' in img and '@sha256:32e459968daabe7ab86968184a29109b9564aa00392401156f9788452b42786b' in img,
              'M12: the semgrep image is not redirectable to the mirror registry by the SAME digest: %r' % img)
        check('vars.KIT_FEED_MIRROR_RUNNER' in str(sg.get('runs-on', '')),
              'M12: sast-semgrep cannot run on the private runner that reaches the mirror registry')
        fdoc, fsteps = composite_steps('feed-mirror')
        ftext = json.dumps(fsteps)
        check('scripts/feed_mirror_step.sh' in ftext and all(k in (fdoc.get('inputs') or {}) for k in
                                                         ('feed', 'mirror-url', 'max-age-hours', 'fallback')),
              'M12: the feed-mirror composite does not run scripts/feed_mirror.py with feed/mirror-url/max-age-hours/'
              'fallback inputs')

        # ---- M13 Terraform --------------------------------------------------------------------------
        tf_dir = os.path.join(ROOT, 'infra', 'feed-mirrors')
        tf = ''
        if check(os.path.isdir(tf_dir), 'M13: infra/feed-mirrors does not exist'):
            for fn in sorted(os.listdir(tf_dir)):
                if fn.endswith('.tf'):
                    tf += io.open(os.path.join(tf_dir, fn), encoding='utf-8').read() + '\n'
        norm = re.sub(r'\s+', ' ', tf)
        for rule, pat in (
                ('public network access off on the storage account', r'public_network_access_enabled = false'),
                ('shared key access off', r'shared_access_key_enabled = false'),
                ('anonymous blob access off (the static website is network-gated)',
                 r'allow_nested_items_to_be_public = false'),
                ('TLS 1.2', r'min_tls_version = "TLS1_2"'),
                ('Entra by default', r'default_to_oauth_authentication = true'),
                ('a private endpoint for the web sub-resource', r'subresource_names = \["web"\]'),
                ('a private endpoint for the blob sub-resource', r'subresource_names = \["blob"\]'),
                ('the web private DNS zone', r'privatelink\.web\.core\.windows\.net'),
                ('the blob private DNS zone', r'privatelink\.blob\.core\.windows\.net'),
                ('the static website', r'azurerm_storage_account_static_website'),
                ('Storage Blob Data Contributor', r'Storage Blob Data Contributor'),
                ('the grant scoped to the $web container', r'/blobServices/default/containers/\$\$?web'),
                ('the registry: Premium', r'sku = "Premium"'),
                ('the registry: anonymous pull', r'anonymous_pull_enabled = true'),
                ('the registry: no admin user', r'admin_enabled = false'),
                ('the registry: a private endpoint', r'subresource_names = \["registry"\]'),
                ('the registry private DNS zone', r'privatelink\.azurecr\.io'),
                ('AcrPush', r'"AcrPush"'),
                ('the federated credential is environment-scoped', r'environment:')):
            check(re.search(pat, norm), 'M13: the Terraform does not set %s' % rule)
        check(norm.count('public_network_access_enabled = false') >= 2,
              'M13: public network access is not off on both the storage account and the registry')
        for bad in ('"Owner"', '"Contributor"', 'Storage Blob Data Owner', 'Storage Account Contributor',
                    'Storage Blob Data Contributor" scope = azurerm_storage_account'):
            check(bad not in norm.replace('role_definition_name = ', ''),
                  'M13: the Terraform grants %s' % bad)

        # ---- M14 taxonomy ---------------------------------------------------------------------------
        tax = json.dumps(yaml.safe_load(io.open(os.path.join(ROOT, 'assurance-taxonomy.yaml'), encoding='utf-8')),
                         default=str)
        for term in ('NOT_CONFIGURED', 'MIRROR_CURRENT', 'MIRROR_STALE', 'MIRROR_UNREACHABLE', 'MIRROR_INTEGRITY_FAILED',
                     'MIRROR_FALLBACK_UPSTREAM', 'MIRROR_PUBLISHED', 'MIRROR_UPSTREAM_STALE',
                     'MIRROR_UPSTREAM_UNREACHABLE', 'MIRROR_UPSTREAM_INTEGRITY_FAILED', 'MIRROR_PUBLISH_UNVERIFIED'):
            check('"%s"' % term in tax, 'M14: %s is not a registered taxonomy term' % term)
    finally:
        shutil.rmtree(work, ignore_errors=True)

    if fails:
        for f in fails:
            print('FAIL: ' + f)
        return 1
    print('PASS: a feed mirror is used only when current and intact (manifest sha256 per file, refreshed_at within '
          'the 48 h policy, which a caller may only tighten); stale, unreachable and tampered mirrors are refused by '
          'name (MIRROR_STALE, MIRROR_UNREACHABLE, MIRROR_INTEGRITY_FAILED) and surface as KEV UNAVAILABLE, a failed '
          'NVD update and a Trivy that refuses -- never clean; the public upstream is used only on an explicit '
          'fallback, recorded (MIRROR_FALLBACK_UPSTREAM); the refresh verifies upstream and its own upload; the '
          'Azure side is private-only with container- and registry-scoped grants.')
    return 0


if __name__ == '__main__':
    sys.exit(main())

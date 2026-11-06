#!/usr/bin/env python3
"""Organisation-hosted mirrors of the kit's external data feeds (Release 4, KDEC-032 PROPOSED).

WHY THIS EXISTS

    Every scan pulls three public feeds itself: the Dependency-Check NVD datafeed, the CISA Known
    Exploited Vulnerabilities catalog (KEV) and the Trivy vulnerability database (with its Java
    index). Across hundreds of repositories that is hundreds of cold pulls from third-party hosts a
    day, and actions/cache cannot be shared between repositories (the cost redesign proposal, 0.4). The owner,
    2026-10-27: "release 4 could have the mirrors yes? I could have it in the security platform azure
    subscription". One scheduled refresh writes each feed into a private storage account (a static
    website reached through a private endpoint); the scans read it from there.

    A mirror adds a way to be wrong that the public feed did not have: it can stop refreshing. A scan
    against a database that stopped updating a week ago reports nothing, and nothing reads exactly
    like clean. So the refresh writes a MANIFEST per feed -- source, upstream version and timestamp,
    sha256 and size of every file, refreshed_at -- and the consumer refuses, BY NAME, whatever it
    cannot vouch for:

        MIRROR_CURRENT            the manifest is readable, for this feed, refreshed within the policy,
                                  and every file the consumer reads matches its sha256
        MIRROR_STALE              refreshed_at is older than the policy (48 h; a caller may only tighten)
        MIRROR_UNREACHABLE        the manifest or a file could not be fetched
        MIRROR_INTEGRITY_FAILED   unreadable manifest, another feed's manifest, a refreshed_at in the
                                  future, bytes that do not match, an archive member escaping its directory
        MIRROR_FALLBACK_UPSTREAM  refused, and the caller EXPLICITLY configured fallback `upstream`:
                                  the public feed is used and the cause is recorded
        NOT_CONFIGURED            no mirror named: the public feed, exactly as before Release 4

    A refusal is never "clean". Each consumer turns it into the state it already has for an
    unreadable feed: KEV -> kev_state UNAVAILABLE (KEV_UNAVAILABLE); NVD -> the database update failed
    (nvd-dependency-check unavailable, EVIDENCE_UNTRUSTED); Trivy -> the cache is emptied and the
    update switched off, so every Trivy call in the job refuses rather than scanning stale data or
    reaching the public registry the caller chose not to use.

THE LAYOUT (one static website, the `$web` container)
    <feed>/manifest.json                 the current generation; written LAST, read FIRST
    <feed>/g/<generation>/<files>        immutable per refresh; the manifest switch is atomic
    feeds: nvd (cache.properties, nvdcve-<year|modified>.meta/.json.gz -- Dependency-Check's datafeed
    format), kev (known_exploited_vulnerabilities.json), trivy (db.tar.gz, java-db.tar.gz).

USAGE
    consume     --feed F --mirror-url URL [--max-age-hours N] [--fallback none|upstream] [--now ISO]
                [--out-dir D] [--trivy-cache-dir D] [--verify-all] [--timeout S]
                [--github-output F] [--github-env F] [--summary F] [--evidence F]
    fetch-nvd   --upstream URL --out D [--now ISO] [--max-upstream-age-hours N]
    fetch-kev   --upstream URL --out D
    pack-trivy  --cache-dir D --out D [--now ISO] [--max-upstream-age-hours N]
    manifest    --feed F --dir D --source-url U --upstream-version V --upstream-timestamp T
                --generation G [--now ISO] [--refreshed-by R] --out FILE
    prune-plan  --keep N --current G   (generation names on stdin; the ones to delete on stdout)
    --self-test

EXIT  consume: 0 evaluated (the state is in the outputs)   fetch-*/pack-trivy: 0 ok, 1 refused (named)
      2 usage, or self-test failed
"""
import argparse
import datetime
import gzip
import hashlib
import io
import json
import os
import posixpath
import re
import shutil
import sys
import tarfile
import urllib.request

SCHEMA = 'kit-feed-mirror-manifest/1'
FEEDS = ('nvd', 'kev', 'trivy', 'trivy-checks', 'osv')
# THE POLICY NUMBER (owner-level, KDEC-032): a mirror older than this is refused. It is a CEILING: a
# caller may tighten it, never widen it -- a larger value is clamped and said so, so no repository
# variable can turn a stale mirror back into a current one.
MAX_AGE_HOURS_CEILING = 48
# The refresh refuses to publish an upstream older than this (the upstream itself stopped).
UPSTREAM_MAX_AGE_HOURS = 48
FUTURE_SKEW_SECONDS = 300
FETCH_TIMEOUT = 60

NOT_CONFIGURED = 'NOT_CONFIGURED'
MIRROR_CURRENT = 'MIRROR_CURRENT'
MIRROR_STALE = 'MIRROR_STALE'
MIRROR_UNREACHABLE = 'MIRROR_UNREACHABLE'
MIRROR_INTEGRITY_FAILED = 'MIRROR_INTEGRITY_FAILED'
MIRROR_FALLBACK_UPSTREAM = 'MIRROR_FALLBACK_UPSTREAM'
# Refresh-side outcomes (feed_mirror_refresh in assurance-taxonomy.yaml).
MIRROR_PUBLISHED = 'MIRROR_PUBLISHED'
MIRROR_UPSTREAM_STALE = 'MIRROR_UPSTREAM_STALE'
MIRROR_UPSTREAM_UNREACHABLE = 'MIRROR_UPSTREAM_UNREACHABLE'
MIRROR_UPSTREAM_INTEGRITY_FAILED = 'MIRROR_UPSTREAM_INTEGRITY_FAILED'
MIRROR_PUBLISH_UNVERIFIED = 'MIRROR_PUBLISH_UNVERIFIED'

KEV_FILE = 'known_exploited_vulnerabilities.json'
TRIVY_FILES = (('db.tar.gz', 'db'), ('java-db.tar.gz', 'java-db'))
# Trivy's misconfiguration checks bundle: <cache>/policy/{content/, metadata.json} (measured, Trivy 0.71.2).
CHECKS_FILE, CHECKS_SUB = 'checks.tar.gz', 'policy'
# osv-scanner 2.6 reads <OSV_SCANNER_LOCAL_DB_CACHE_DIRECTORY>/osv-scalibr/<Ecosystem>/all.zip (measured: the
# offline-mode page says `osv-scanner/`, which 2.6 does not read). One all.zip per OSV ecosystem.
OSV_SUB = 'osv-scalibr'
# The ecosystems the kit's languages resolve to (discover: python node go dotnet java/kotlin php swift) plus the
# small ones a repository commonly carries a lockfile for. npm is the large one (~220 MB, the MAL- entries).
OSV_ECOSYSTEMS = ('PyPI', 'npm', 'Go', 'NuGet', 'Maven', 'Packagist', 'SwiftURL', 'crates.io', 'RubyGems', 'Pub', 'Hex')
OSV_UPSTREAM = 'https://osv-vulnerabilities.storage.googleapis.com/'
DIGEST_RE = re.compile(r'^sha256:[0-9a-f]{64}$')
GEN_RE = re.compile(r'^\d{8}T\d{6}Z-[0-9A-Za-z._-]+$')


class Refused(Exception):
    def __init__(self, state, why):
        Exception.__init__(self, '%s: %s' % (state, why))
        self.state, self.why = state, why


# ----------------------------------------------------------------------------------------- helpers
def _now(text):
    if text:
        return parse_ts(text)
    return datetime.datetime.now(datetime.timezone.utc).replace(microsecond=0)


def parse_ts(text):
    """ISO-8601 (Z, offset, fractional seconds, Java-properties escaped colons) -> aware datetime."""
    t = str(text or '').strip().replace('\\:', ':')
    if not t:
        raise ValueError('empty timestamp')
    t = t.replace('Z', '+00:00').replace('z', '+00:00')
    m = re.match(r'^(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})(\.\d+)?([+-]\d{2}:\d{2})?$', t)
    if not m:
        raise ValueError('not an ISO timestamp: %r' % text)
    dt = datetime.datetime.strptime(m.group(1), '%Y-%m-%dT%H:%M:%S')
    off = m.group(3) or '+00:00'
    sign = 1 if off[0] == '+' else -1
    delta = datetime.timedelta(hours=int(off[1:3]), minutes=int(off[4:6])) * sign
    return (dt - delta).replace(tzinfo=datetime.timezone.utc)


def iso(dt):
    return dt.astimezone(datetime.timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')


def sha256_bytes(b):
    return hashlib.sha256(b).hexdigest()


def sha256_file(path):
    h = hashlib.sha256()
    with io.open(path, 'rb') as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b''):
            h.update(chunk)
    return h.hexdigest()


def fetch(url, timeout=FETCH_TIMEOUT):
    req = urllib.request.Request(url, headers={'User-Agent': 'secure-cicd-kit feed_mirror.py'})
    with urllib.request.urlopen(req, timeout=timeout) as resp:  # noqa: S310 -- the URL is the feed
        return resp.read()


def join_url(base, rel):
    return base.rstrip('/') + '/' + rel.lstrip('/')


def safe_name(name):
    """A manifest file name must stay inside its generation: relative, no `..`, no backslash."""
    n = str(name or '')
    if not n or n.startswith('/') or '\\' in n or ':' in n:
        return False
    return '..' not in posixpath.normpath(n).split('/') and not posixpath.normpath(n).startswith('..')


# ---------------------------------------------------------------------------------------- manifest
def build_manifest(feed, directory, source_url, upstream_version, upstream_timestamp, generation,
                   refreshed_at, refreshed_by=''):
    files = []
    for dp, _, fns in os.walk(directory):
        for fn in fns:
            full = os.path.join(dp, fn)
            rel = os.path.relpath(full, directory).replace('\\', '/')
            files.append({'name': rel, 'sha256': sha256_file(full), 'size': os.path.getsize(full)})
    files.sort(key=lambda f: f['name'])
    return {'schema': SCHEMA, 'feed': feed, 'generation': generation, 'path': '%s/g/%s/' % (feed, generation),
            'source_url': source_url, 'upstream_version': upstream_version or '',
            'upstream_timestamp': upstream_timestamp or '', 'refreshed_at': refreshed_at,
            'refreshed_by': refreshed_by or '', 'files': files}


def verify_dir(manifest, directory):
    """-> [problem], empty when every manifest file is present with its sha256 and size."""
    probs = []
    for f in manifest.get('files') or []:
        p = os.path.join(directory, *str(f.get('name')).split('/'))
        if not os.path.isfile(p):
            probs.append('%s: missing' % f.get('name'))
        elif sha256_file(p) != f.get('sha256'):
            probs.append('%s: sha256 %s, the manifest says %s' % (f.get('name'), sha256_file(p)[:16],
                                                                   str(f.get('sha256'))[:16]))
        elif os.path.getsize(p) != f.get('size'):
            probs.append('%s: size %d, the manifest says %s' % (f.get('name'), os.path.getsize(p), f.get('size')))
    return probs


def check_manifest(doc, feed, now, max_age_hours):
    """-> manifest, or raise Refused. Integrity before freshness: a forged manifest is not 'stale'."""
    if not isinstance(doc, dict) or doc.get('schema') != SCHEMA:
        raise Refused(MIRROR_INTEGRITY_FAILED, 'the manifest is not %s' % SCHEMA)
    if doc.get('feed') != feed:
        raise Refused(MIRROR_INTEGRITY_FAILED, 'the manifest is for feed %r, not %r' % (doc.get('feed'), feed))
    gen = str(doc.get('generation') or '')
    if not GEN_RE.match(gen) or doc.get('path') != '%s/g/%s/' % (feed, gen):
        raise Refused(MIRROR_INTEGRITY_FAILED, 'the manifest generation/path is malformed: %r %r'
                      % (gen, doc.get('path')))
    files = doc.get('files')
    if not isinstance(files, list) or not files:
        raise Refused(MIRROR_INTEGRITY_FAILED, 'the manifest lists no files')
    for f in files:
        if not isinstance(f, dict) or not safe_name(f.get('name')) or not re.match(
                r'^[0-9a-f]{64}$', str(f.get('sha256') or '')) or not isinstance(f.get('size'), int):
            raise Refused(MIRROR_INTEGRITY_FAILED, 'the manifest has a malformed file entry: %r' % (f,))
    try:
        refreshed = parse_ts(doc.get('refreshed_at'))
    except ValueError as exc:
        raise Refused(MIRROR_INTEGRITY_FAILED, 'refreshed_at is unreadable: %s' % exc)
    if (refreshed - now).total_seconds() > FUTURE_SKEW_SECONDS:
        raise Refused(MIRROR_INTEGRITY_FAILED, 'refreshed_at %s is in the future (now %s)' % (iso(refreshed), iso(now)))
    age_h = (now - refreshed).total_seconds() / 3600.0
    if age_h > max_age_hours:
        raise Refused(MIRROR_STALE, 'refreshed %s, %.1f h ago; the policy is %d h' % (iso(refreshed), age_h,
                                                                                      max_age_hours))
    return doc


def effective_max_age(raw):
    """-> (hours, note). The policy is a ceiling: absent, unreadable or larger values use it."""
    try:
        v = int(float(str(raw).strip())) if str(raw or '').strip() else MAX_AGE_HOURS_CEILING
    except ValueError:
        return MAX_AGE_HOURS_CEILING, 'max age %r is not a number; the policy ceiling (%d h) applies' % (
            raw, MAX_AGE_HOURS_CEILING)
    if v <= 0:
        return MAX_AGE_HOURS_CEILING, 'max age %r is not positive; the policy ceiling (%d h) applies' % (
            raw, MAX_AGE_HOURS_CEILING)
    if v > MAX_AGE_HOURS_CEILING:
        return MAX_AGE_HOURS_CEILING, ('max age %d h is above the policy ceiling (%d h): a caller may only '
                                       'tighten it, so the ceiling applies' % (v, MAX_AGE_HOURS_CEILING))
    return v, ''


# ----------------------------------------------------------------------------------------- consume
def _download(base, man, name, dest, timeout):
    data = fetch(join_url(base, man['path'] + name), timeout)
    entry = next(f for f in man['files'] if f['name'] == name)
    if sha256_bytes(data) != entry['sha256'] or len(data) != entry['size']:
        raise Refused(MIRROR_INTEGRITY_FAILED, '%s%s: sha256 %s, the manifest says %s'
                      % (man['path'], name, sha256_bytes(data)[:16], entry['sha256'][:16]))
    os.makedirs(os.path.dirname(dest), exist_ok=True)
    with io.open(dest, 'wb') as fh:
        fh.write(data)
    return data


def _safe_extract(archive, target):
    """Extract a .tar.gz into target, refusing any member that is not a plain file or directory inside it."""
    real = os.path.realpath(target)
    with tarfile.open(archive, mode='r:gz') as tf:
        members = tf.getmembers()
        for m in members:
            dest = os.path.realpath(os.path.join(target, m.name))
            if not (m.isfile() or m.isdir()) or not (dest == real or dest.startswith(real + os.sep)):
                raise Refused(MIRROR_INTEGRITY_FAILED, 'archive member %r escapes %s or is not a plain file'
                              % (m.name, os.path.basename(archive)))
        os.makedirs(target, exist_ok=True)
        for m in members:
            if m.isdir():
                os.makedirs(os.path.join(target, m.name), exist_ok=True)
                continue
            src = tf.extractfile(m)
            dest = os.path.join(target, m.name)
            os.makedirs(os.path.dirname(dest), exist_ok=True)
            with io.open(dest, 'wb') as fh:
                shutil.copyfileobj(src, fh)


def _wipe_trivy(cache):
    for _, sub in TRIVY_FILES:
        shutil.rmtree(os.path.join(cache, sub), ignore_errors=True)


def _cache(trivy_cache):
    return trivy_cache or os.path.join(os.environ.get('RUNNER_TEMP') or '.', 'trivy-cache')


def _osv_dir(osv_dir):
    return osv_dir or os.path.join(os.environ.get('RUNNER_TEMP') or '.', 'osv-db')


def consume(feed, mirror_url, max_age_raw='', fallback='none', now=None, out_dir='', trivy_cache='',
            verify_all=False, timeout=FETCH_TIMEOUT, osv_dir='', osv_ecosystems=''):
    """-> result dict (mirror_* keys, env, notes). Never raises for a mirror problem: it is the state."""
    now = now or _now('')
    max_age, note = effective_max_age(max_age_raw)
    fb = 'upstream' if str(fallback or '').strip() == 'upstream' else 'none'
    res = {'feed': feed, 'mirror_state': NOT_CONFIGURED, 'mirror_cause': '', 'mirror_usable': 'true',
           'mirror_url': '', 'mirror_file': '', 'mirror_sha256': '', 'mirror_generation': '',
           'mirror_refreshed_at': '', 'mirror_upstream_version': '', 'mirror_upstream_timestamp': '',
           'mirror_max_age_hours': str(max_age), 'mirror_why': '', 'fallback': fb, 'mirror_base': mirror_url or '',
           'checked_at': iso(now), 'notes': [note] if note else [], 'env': {}}
    if str(fallback or '').strip() not in ('', 'none', 'upstream'):
        res['notes'].append('fallback %r is not `none` or `upstream`; no fallback is taken' % fallback)
    if not mirror_url:
        res['mirror_why'] = 'no mirror is configured; the public upstream is read as before Release 4'
        return res
    base = mirror_url.rstrip('/') + '/'
    out_dir = out_dir or os.path.join(os.environ.get('RUNNER_TEMP') or '.', 'feed-mirror-%s' % feed)
    try:
        try:
            raw = fetch(join_url(base, '%s/manifest.json' % feed), timeout)
        except Exception as exc:  # noqa: BLE001 -- any failure to read the manifest is UNREACHABLE
            raise Refused(MIRROR_UNREACHABLE, 'the manifest %s%s/manifest.json could not be fetched: %s: %s'
                          % (base, feed, type(exc).__name__, str(exc)[:200]))
        try:
            doc = json.loads(raw.decode('utf-8-sig'))
        except (ValueError, UnicodeDecodeError) as exc:
            raise Refused(MIRROR_INTEGRITY_FAILED, 'the manifest is not JSON: %s' % exc)
        man = check_manifest(doc, feed, now, max_age)
        res.update(mirror_generation=man['generation'], mirror_refreshed_at=man.get('refreshed_at', ''),
                   mirror_upstream_version=str(man.get('upstream_version') or ''),
                   mirror_upstream_timestamp=str(man.get('upstream_timestamp') or ''),
                   mirror_url=join_url(base, man['path']))
        names = [f['name'] for f in man['files']]
        try:
            if feed == 'kev':
                if KEV_FILE not in names:
                    raise Refused(MIRROR_INTEGRITY_FAILED, 'the KEV manifest has no %s' % KEV_FILE)
                dest = os.path.join(out_dir, KEV_FILE)
                data = _download(base, man, KEV_FILE, dest, timeout)
                res.update(mirror_file=dest, mirror_sha256=sha256_bytes(data))
            elif feed == 'trivy-checks':
                if CHECKS_FILE not in names:
                    raise Refused(MIRROR_INTEGRITY_FAILED, 'the checks manifest has no %s' % CHECKS_FILE)
                _download(base, man, CHECKS_FILE, os.path.join(out_dir, CHECKS_FILE), timeout)
            elif feed == 'osv':
                have = sorted(n.split('/')[0] for n in names if n.endswith('/all.zip'))
                want = [e for e in (osv_ecosystems or '').split() if e] or have
                lack = [e for e in want if e not in have]
                if lack:
                    raise Refused(MIRROR_INTEGRITY_FAILED, 'the OSV manifest has no database for %s (it has %s); a '
                                  'scan of that ecosystem offline would fail, so the mirror is refused here, by name'
                                  % (', '.join(lack), ', '.join(have) or 'none'))
                for e in (have if verify_all else want):
                    _download(base, man, e + '/all.zip', os.path.join(out_dir, e, 'all.zip'), timeout)
                res['osv_ecosystems'] = want
            elif feed == 'trivy':
                missing = [n for n, _ in TRIVY_FILES if n not in names]
                if missing:
                    raise Refused(MIRROR_INTEGRITY_FAILED, 'the Trivy manifest has no %s' % ', '.join(missing))
                for name, _ in TRIVY_FILES:
                    _download(base, man, name, os.path.join(out_dir, name), timeout)
            else:  # nvd: Dependency-Check reads the datafeed itself; the index and every .meta are checked
                if 'cache.properties' not in names:
                    raise Refused(MIRROR_INTEGRITY_FAILED, 'the NVD manifest has no cache.properties')
                pick = names if verify_all else [n for n in names if n == 'cache.properties' or n.endswith('.meta')]
                for name in pick:
                    _download(base, man, name, os.path.join(out_dir, *name.split('/')), timeout)
        except Refused:
            raise
        except Exception as exc:  # noqa: BLE001
            raise Refused(MIRROR_UNREACHABLE, 'a mirror file could not be fetched: %s: %s'
                          % (type(exc).__name__, str(exc)[:200]))
        if feed == 'trivy':
            cache = _cache(trivy_cache)
            _wipe_trivy(cache)
            for name, sub in TRIVY_FILES:
                _safe_extract(os.path.join(out_dir, name), os.path.join(cache, sub))
            res['env'] = {'TRIVY_CACHE_DIR': cache, 'TRIVY_SKIP_DB_UPDATE': 'true', 'TRIVY_SKIP_JAVA_DB_UPDATE': 'true'}
        elif feed == 'trivy-checks':
            cache = _cache(trivy_cache)
            shutil.rmtree(os.path.join(cache, CHECKS_SUB), ignore_errors=True)
            _safe_extract(os.path.join(out_dir, CHECKS_FILE), os.path.join(cache, CHECKS_SUB))
            res['env'] = {'TRIVY_CACHE_DIR': cache, 'TRIVY_SKIP_CHECK_UPDATE': 'true'}
        elif feed == 'osv':
            od = _osv_dir(osv_dir)
            shutil.rmtree(os.path.join(od, OSV_SUB), ignore_errors=True)
            for e in res.get('osv_ecosystems') or []:
                dest = os.path.join(od, OSV_SUB, e)
                os.makedirs(dest, exist_ok=True)
                shutil.copyfile(os.path.join(out_dir, e, 'all.zip'), os.path.join(dest, 'all.zip'))
            res['env'] = {'OSV_SCANNER_LOCAL_DB_CACHE_DIRECTORY': od, 'KIT_OSV_OFFLINE': 'true'}
        res.update(mirror_state=MIRROR_CURRENT,
                   mirror_why='generation %s refreshed %s (upstream %s %s), every file read matched its sha256'
                   % (man['generation'], man.get('refreshed_at'), man.get('upstream_version') or '-',
                      man.get('upstream_timestamp') or '-'))
        return res
    except Refused as r:
        cache = _cache(trivy_cache)
        if feed == 'trivy':
            _wipe_trivy(cache)
        elif feed == 'trivy-checks':
            shutil.rmtree(os.path.join(cache, CHECKS_SUB), ignore_errors=True)
        elif feed == 'osv':
            shutil.rmtree(os.path.join(_osv_dir(osv_dir), OSV_SUB), ignore_errors=True)
        if fb == 'upstream':
            res.update(mirror_state=MIRROR_FALLBACK_UPSTREAM, mirror_cause=r.state, mirror_usable='true',
                       mirror_url='', mirror_file='', mirror_sha256='',
                       mirror_why='%s (%s); the caller configured fallback `upstream`, so the public feed is read '
                       'and this is recorded' % (r.state, r.why))
            return res
        res.update(mirror_state=r.state, mirror_usable='false', mirror_url='', mirror_file='', mirror_sha256='',
                   mirror_why=r.why)
        if feed == 'trivy':
            # FAIL CLOSED: an empty cache with the update off makes every Trivy call refuse ("--skip-db-update
            # cannot be specified on the first run"). Never a scan against a restored copy, never upstream.
            res['env'] = {'TRIVY_CACHE_DIR': cache, 'TRIVY_SKIP_DB_UPDATE': 'true', 'TRIVY_SKIP_JAVA_DB_UPDATE': 'true'}
        elif feed == 'trivy-checks':
            # FAIL CLOSED. With the update off and no cached bundle Trivy does NOT refuse: it "Falls back to
            # embedded checks" (measured, 0.71.2) -- an older rule set reading as a current scan. A custom-check
            # path that does not exist makes every `trivy config` fatal ("cache does not exist") instead.
            res['env'] = {'TRIVY_CACHE_DIR': cache, 'TRIVY_SKIP_CHECK_UPDATE': 'true',
                          'TRIVY_CONFIG_CHECK': os.path.join(cache, 'policy-refused-%s' % r.state)}
        elif feed == 'osv':
            # FAIL CLOSED: offline against an EMPTY database, osv-scanner exits non-zero ("no offline version of
            # the OSV database is available", measured 2.6.0) and the job's count step says COLLECTION_FAILED.
            res['env'] = {'OSV_SCANNER_LOCAL_DB_CACHE_DIRECTORY': _osv_dir(osv_dir), 'KIT_OSV_OFFLINE': 'true'}
        return res


def summary_lines(res):
    st = res['mirror_state']
    L = ['', '### Feed mirror: %s' % res['feed'], '', '| | |', '|---|---|',
         '| mirror_state | **%s**%s |' % (st, ' (cause %s)' % res['mirror_cause'] if res['mirror_cause'] else ''),
         '| mirror | %s |' % (res['mirror_base'] or '_(not configured)_'),
         '| generation | %s |' % (res['mirror_generation'] or '-'),
         '| refreshed_at | %s (policy %s h) |' % (res['mirror_refreshed_at'] or '-', res['mirror_max_age_hours']),
         '| upstream | %s %s |' % (res['mirror_upstream_version'] or '-', res['mirror_upstream_timestamp'] or ''),
         '| fallback configured | %s |' % res['fallback'], '', res['mirror_why']]
    for n in res['notes']:
        L.append('')
        L.append('Note: %s' % n)
    if st in (MIRROR_STALE, MIRROR_UNREACHABLE, MIRROR_INTEGRITY_FAILED):
        L += ['', '**%s: the mirror is refused.** This feed is NOT read from the public upstream either (no fallback '
                  'was configured). Whatever depends on it reports itself unavailable -- this is not a clean result.' % st]
    if st == MIRROR_FALLBACK_UPSTREAM:
        L += ['', '**MIRROR_FALLBACK_UPSTREAM:** the mirror was refused (%s) and the public upstream was read '
                  'because the caller configured it. Recorded here and in the evidence.' % res['mirror_cause']]
    return L


def write_outputs(res, github_output='', github_env='', summary='', evidence=''):
    keys = ('mirror_state', 'mirror_cause', 'mirror_usable', 'mirror_url', 'mirror_file', 'mirror_sha256',
            'mirror_generation', 'mirror_refreshed_at', 'mirror_upstream_version', 'mirror_upstream_timestamp',
            'mirror_max_age_hours', 'mirror_why')
    if github_output:
        with io.open(github_output, 'a', encoding='utf-8') as fh:
            for k in keys:
                fh.write('%s=%s\n' % (k, str(res.get(k, '')).replace('\n', ' ').replace('\r', ' ')))
    if github_env and res.get('env'):
        with io.open(github_env, 'a', encoding='utf-8') as fh:
            for k, v in sorted(res['env'].items()):
                fh.write('%s=%s\n' % (k, v))
    if summary:
        with io.open(summary, 'a', encoding='utf-8') as fh:
            fh.write('\n'.join(summary_lines(res)) + '\n')
    if evidence:
        d = os.path.dirname(evidence)
        if d:
            os.makedirs(d, exist_ok=True)
        with io.open(evidence, 'w', encoding='utf-8', newline='\n') as fh:
            fh.write(json.dumps(dict((k, v) for k, v in res.items() if k != 'env'), indent=2, sort_keys=True) + '\n')


# ------------------------------------------------------------------------------------ refresh side
def _props(text):
    out = {}
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith('#') or '=' not in line:
            continue
        k, v = line.split('=', 1)
        out[k.strip()] = v.strip().replace('\\:', ':')
    return out


def _meta(text):
    out = {}
    for line in text.splitlines():
        if ':' in line:
            k, v = line.split(':', 1)
            out[k.strip()] = v.strip()
    return out


def _stale_check(ts, now, max_h, what):
    try:
        t = parse_ts(ts)
    except ValueError as exc:
        raise Refused(MIRROR_UPSTREAM_INTEGRITY_FAILED, '%s timestamp unreadable: %s' % (what, exc))
    age = (now - t).total_seconds() / 3600.0
    if age > max_h:
        raise Refused(MIRROR_UPSTREAM_STALE, '%s last modified %s, %.1f h ago (limit %d h): the upstream itself '
                      'stopped; publishing it would reset refreshed_at over old data' % (what, iso(t), age, max_h))
    return iso(t)


def fetch_nvd(upstream, out, now, max_h=UPSTREAM_MAX_AGE_HOURS, timeout=FETCH_TIMEOUT):
    """Copy a Dependency-Check datafeed (the project's own mirror) and verify every year against its .meta."""
    base = upstream.rstrip('/') + '/'
    try:
        props_raw = fetch(base + 'cache.properties', timeout)
    except Exception as exc:  # noqa: BLE001
        raise Refused(MIRROR_UPSTREAM_UNREACHABLE, 'cache.properties: %s: %s' % (type(exc).__name__, str(exc)[:200]))
    props = _props(props_raw.decode('utf-8', 'replace'))
    prefix = props.get('prefix') or 'nvdcve-'
    if not re.match(r'^[A-Za-z0-9_-]+$', prefix):
        raise Refused(MIRROR_UPSTREAM_INTEGRITY_FAILED, 'cache.properties prefix %r is not a plain name' % prefix)
    keys = sorted(k.split('.', 1)[1] for k in props if k.startswith('lastModifiedDate.'))
    if not keys or not all(re.match(r'^(\d{4}|modified)$', k) for k in keys):
        raise Refused(MIRROR_UPSTREAM_INTEGRITY_FAILED, 'cache.properties names no years, or a malformed one: %r' % keys)
    ts = _stale_check(props.get('lastModifiedDate', ''), now, max_h, 'the NVD datafeed')
    os.makedirs(out, exist_ok=True)
    with io.open(os.path.join(out, 'cache.properties'), 'wb') as fh:
        fh.write(props_raw)
    for k in keys:
        name = '%s%s' % (prefix, k)
        try:
            meta_raw = fetch(base + name + '.meta', timeout)
            gz = fetch(base + name + '.json.gz', timeout)
        except Exception as exc:  # noqa: BLE001
            raise Refused(MIRROR_UPSTREAM_UNREACHABLE, '%s: %s: %s' % (name, type(exc).__name__, str(exc)[:200]))
        meta = _meta(meta_raw.decode('utf-8', 'replace'))
        try:
            raw = gzip.decompress(gz)
        except (OSError, EOFError) as exc:
            raise Refused(MIRROR_UPSTREAM_INTEGRITY_FAILED, '%s.json.gz is not gzip: %s' % (name, exc))
        if meta.get('sha256', '').lower() != sha256_bytes(raw) or str(len(gz)) != meta.get('gzSize', str(len(gz))) \
                or str(len(raw)) != meta.get('size', str(len(raw))):
            raise Refused(MIRROR_UPSTREAM_INTEGRITY_FAILED, '%s.json.gz does not match %s.meta (sha256 %s, meta %s)'
                          % (name, name, sha256_bytes(raw)[:16], meta.get('sha256', '')[:16]))
        for suffix, data in (('.meta', meta_raw), ('.json.gz', gz)):
            with io.open(os.path.join(out, name + suffix), 'wb') as fh:
                fh.write(data)
    return {'upstream_version': 'datafeed (%d files)' % len(keys), 'upstream_timestamp': ts, 'source_url': base}


def fetch_kev(upstream, out, timeout=FETCH_TIMEOUT):
    sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
    import known_exploited as ke  # the same parser the check uses: a catalog it would refuse is never published
    try:
        raw = fetch(upstream, timeout)
    except Exception as exc:  # noqa: BLE001
        raise Refused(MIRROR_UPSTREAM_UNREACHABLE, 'the KEV catalog: %s: %s' % (type(exc).__name__, str(exc)[:200]))
    doc, problem = ke._parse_feed(raw)  # noqa: SLF001
    if doc is None:
        raise Refused(MIRROR_UPSTREAM_INTEGRITY_FAILED, 'the KEV catalog is unusable: %s' % problem)
    os.makedirs(out, exist_ok=True)
    with io.open(os.path.join(out, KEV_FILE), 'wb') as fh:
        fh.write(raw)
    return {'upstream_version': str(doc.get('catalogVersion') or ''), 'upstream_timestamp': str(doc.get('dateReleased') or ''),
            'source_url': upstream}


def pack_trivy(cache_dir, out, now, max_h=UPSTREAM_MAX_AGE_HOURS):
    """Pack Trivy's own downloaded databases (db/, java-db/) as the archives a consumer unpacks."""
    os.makedirs(out, exist_ok=True)
    stamps = {}
    for name, sub in TRIVY_FILES:
        d = os.path.join(cache_dir, sub)
        md = os.path.join(d, 'metadata.json')
        if not os.path.isfile(md):
            raise Refused(MIRROR_UPSTREAM_UNREACHABLE, '%s has no metadata.json: the download did not complete' % d)
        try:
            meta = json.load(io.open(md, encoding='utf-8'))
        except ValueError as exc:
            raise Refused(MIRROR_UPSTREAM_INTEGRITY_FAILED, '%s is not JSON: %s' % (md, exc))
        stamps[sub] = _stale_check(meta.get('UpdatedAt', ''), now, max_h if sub == 'db' else max_h * 7,
                                   'the Trivy %s' % sub)
        with tarfile.open(os.path.join(out, name), mode='w:gz') as tf:
            for fn in sorted(os.listdir(d)):
                tf.add(os.path.join(d, fn), arcname=fn)
    return {'upstream_version': 'db %s, java-db %s' % (stamps['db'], stamps['java-db']),
            'upstream_timestamp': stamps['db'], 'source_url': 'trivy --download-db-only / --download-java-db-only'}


def pack_trivy_checks(cache_dir, out):
    """Pack Trivy's own checks-bundle download (<cache>/policy) as the archive a consumer unpacks."""
    d = os.path.join(cache_dir, CHECKS_SUB)
    md = os.path.join(d, 'metadata.json')
    if not os.path.isfile(md) or not os.path.isdir(os.path.join(d, 'content')):
        raise Refused(MIRROR_UPSTREAM_UNREACHABLE, '%s has no checks bundle: the download did not complete' % d)
    try:
        meta = json.load(io.open(md, encoding='utf-8'))
    except ValueError as exc:
        raise Refused(MIRROR_UPSTREAM_INTEGRITY_FAILED, '%s is not JSON: %s' % (md, exc))
    digest = str(meta.get('Digest') or '')
    if not DIGEST_RE.match(digest):
        raise Refused(MIRROR_UPSTREAM_INTEGRITY_FAILED, 'the checks bundle metadata has no digest: %r' % digest)
    os.makedirs(out, exist_ok=True)
    with tarfile.open(os.path.join(out, CHECKS_FILE), mode='w:gz') as tf:
        for fn in sorted(os.listdir(d)):
            tf.add(os.path.join(d, fn), arcname=fn)
    try:
        ts = iso(parse_ts(meta.get('DownloadedAt', '')))
    except ValueError:
        ts = ''
    return {'upstream_version': digest, 'upstream_timestamp': ts,
            'source_url': 'trivy config (its own checks-bundle download)'}


def fetch_osv(upstream, ecosystems, out, timeout=FETCH_TIMEOUT):
    """Copy each ecosystem's all.zip from the OSV bucket; each must be a readable zip of OSV records. No age
    limit: an ecosystem with no new advisories is not regenerated (Pub's all.zip was 12 days old on 2026-10-27)."""
    import zipfile
    base = upstream.rstrip('/') + '/'
    stamps = []
    for e in ecosystems:
        if not re.match(r'^[A-Za-z0-9.]+$', e):
            raise Refused(MIRROR_UPSTREAM_INTEGRITY_FAILED, 'ecosystem %r is not a plain OSV ecosystem name' % e)
        try:
            req = urllib.request.Request(base + e + '/all.zip', headers={'User-Agent': 'secure-cicd-kit feed_mirror.py'})
            with urllib.request.urlopen(req, timeout=timeout) as resp:  # noqa: S310 -- the URL is the feed
                data = resp.read()
                lm = (getattr(resp, 'headers', None) or {}).get('Last-Modified', '') or ''
        except Exception as exc:  # noqa: BLE001
            raise Refused(MIRROR_UPSTREAM_UNREACHABLE, '%s/all.zip: %s: %s' % (e, type(exc).__name__, str(exc)[:200]))
        try:
            with zipfile.ZipFile(io.BytesIO(data)) as zf:
                if zf.testzip() is not None or not any(n.endswith('.json') for n in zf.namelist()):
                    raise zipfile.BadZipFile('no readable OSV records')
        except zipfile.BadZipFile as exc:
            raise Refused(MIRROR_UPSTREAM_INTEGRITY_FAILED, '%s/all.zip is not a zip of OSV records: %s' % (e, exc))
        dest = os.path.join(out, e)
        os.makedirs(dest, exist_ok=True)
        with io.open(os.path.join(dest, 'all.zip'), 'wb') as fh:
            fh.write(data)
        stamps.append('%s %s' % (e, lm or '-'))
    return {'upstream_version': '%d ecosystems' % len(ecosystems), 'upstream_timestamp': '',
            'source_url': base, 'last_modified': stamps}


def image_target(registry, source):
    """-> (mirror repository, digest) for a source pinned BY DIGEST; a tag (or tag-only) source is refused."""
    src = str(source or '').strip()
    if '@' not in src or not DIGEST_RE.match(src.rsplit('@', 1)[1]):
        raise Refused(MIRROR_UPSTREAM_INTEGRITY_FAILED, '%s is not pinned by digest; a mirror of a moving tag is '
                      'refused' % src)
    name, digest = src.rsplit('@', 1)
    if name.startswith('docker.io/'):
        name = name[len('docker.io/'):]
    last = name.rsplit('/', 1)[-1]
    if ':' in last:
        name = name[:len(name) - len(last)] + last.split(':', 1)[0]
    if not re.match(r'^[a-z0-9][a-z0-9._/-]*$', name) or not re.match(r'^[A-Za-z0-9.-]+(:[0-9]+)?$', registry or ''):
        raise Refused(MIRROR_UPSTREAM_INTEGRITY_FAILED, 'cannot map %s into registry %r' % (src, registry))
    return '%s/%s' % (registry, name), digest


def prune_plan(generations, keep, current):
    """-> sorted generations to delete: all but the newest `keep`, never `current`."""
    gens = sorted(set(g for g in generations if GEN_RE.match(g)), reverse=True)
    survivors = set(gens[:max(int(keep), 0)]) | {current}
    return sorted(g for g in gens if g not in survivors)


# ------------------------------------------------------------------------------------------- main
def _selftest():
    fails = []
    now = parse_ts('2026-10-27T06:00:00Z')
    if effective_max_age('1000')[0] != 48 or effective_max_age('12')[0] != 12 or effective_max_age('x')[0] != 48:
        fails.append('the max-age ceiling is not enforced')
    man = {'schema': SCHEMA, 'feed': 'kev', 'generation': '20261027T050000Z-1', 'path': 'kev/g/20261027T050000Z-1/',
           'refreshed_at': '2026-10-24T00:00:00Z', 'files': [{'name': 'a', 'sha256': '0' * 64, 'size': 1}]}
    try:
        check_manifest(man, 'kev', now, 48)
        fails.append('a 78-hour-old manifest was accepted')
    except Refused as r:
        if r.state != MIRROR_STALE:
            fails.append('a stale manifest was %s' % r.state)
    if safe_name('../x') or not safe_name('nvdcve-2002.meta'):
        fails.append('safe_name is wrong')
    if prune_plan(['20261020T000000Z-1', '20261021T000000Z-2'], 0, '20261021T000000Z-2') != ['20261020T000000Z-1']:
        fails.append('prune would delete the current generation')
    if fails:
        for m in fails:
            sys.stderr.write('FAIL: %s\n' % m)
        return 2
    print('feed_mirror selftest ok: the age ceiling holds, a stale manifest is refused, names stay inside their '
          'generation, prune keeps the current generation. The full proof is tests/prove_feed_mirror.py.')
    return 0


def main(argv=None):
    ap = argparse.ArgumentParser(description='Organisation-hosted feed mirrors: consume, refresh, manifest.')
    ap.add_argument('--self-test', action='store_true')
    sub = ap.add_subparsers(dest='cmd')
    c = sub.add_parser('consume')
    c.add_argument('--feed', choices=FEEDS, required=True)
    c.add_argument('--mirror-url', default='')
    c.add_argument('--max-age-hours', default='')
    c.add_argument('--fallback', default='none')
    c.add_argument('--now', default='')
    c.add_argument('--out-dir', default='')
    c.add_argument('--trivy-cache-dir', default='')
    c.add_argument('--verify-all', action='store_true')
    c.add_argument('--timeout', type=int, default=FETCH_TIMEOUT)
    c.add_argument('--osv-dir', default='')
    c.add_argument('--osv-ecosystems', default='')
    for k in ('--github-output', '--github-env', '--summary', '--evidence'):
        c.add_argument(k, default='')
    n = sub.add_parser('fetch-nvd')
    n.add_argument('--upstream', required=True)
    n.add_argument('--out', required=True)
    n.add_argument('--now', default='')
    n.add_argument('--max-upstream-age-hours', type=int, default=UPSTREAM_MAX_AGE_HOURS)
    k_ = sub.add_parser('fetch-kev')
    k_.add_argument('--upstream', required=True)
    k_.add_argument('--out', required=True)
    t = sub.add_parser('pack-trivy')
    t.add_argument('--cache-dir', required=True)
    t.add_argument('--out', required=True)
    t.add_argument('--now', default='')
    t.add_argument('--max-upstream-age-hours', type=int, default=UPSTREAM_MAX_AGE_HOURS)
    tc = sub.add_parser('pack-trivy-checks')
    tc.add_argument('--cache-dir', required=True)
    tc.add_argument('--out', required=True)
    o = sub.add_parser('fetch-osv')
    o.add_argument('--upstream', default=OSV_UPSTREAM)
    o.add_argument('--ecosystems', default=' '.join(OSV_ECOSYSTEMS))
    o.add_argument('--out', required=True)
    it = sub.add_parser('image-target')
    it.add_argument('--registry', required=True)
    it.add_argument('--source', required=True)
    m = sub.add_parser('manifest')
    for k in ('--feed', '--dir', '--source-url', '--generation', '--out'):
        m.add_argument(k, required=True)
    for k in ('--upstream-version', '--upstream-timestamp', '--now', '--refreshed-by'):
        m.add_argument(k, default='')
    p = sub.add_parser('prune-plan')
    p.add_argument('--keep', type=int, default=3)
    p.add_argument('--current', required=True)
    a = ap.parse_args(argv)
    if a.self_test:
        return _selftest()
    if a.cmd == 'consume':
        res = consume(a.feed, a.mirror_url.strip(), a.max_age_hours, a.fallback, _now(a.now), a.out_dir,
                      a.trivy_cache_dir, a.verify_all, a.timeout, a.osv_dir, a.osv_ecosystems)
        write_outputs(res, a.github_output, a.github_env, a.summary, a.evidence)
        print('feed %s: %s%s -- %s' % (a.feed, res['mirror_state'],
                                        ' (cause %s)' % res['mirror_cause'] if res['mirror_cause'] else '',
                                        res['mirror_why']))
        return 0
    if a.cmd == 'image-target':
        try:
            repo, digest = image_target(a.registry, a.source)
        except Refused as r:
            print('::error title=%s::%s' % (r.state, r.why))
            return 1
        print('%s %s' % (repo, digest))
        return 0
    if a.cmd in ('fetch-nvd', 'fetch-kev', 'pack-trivy', 'pack-trivy-checks', 'fetch-osv'):
        try:
            if a.cmd == 'fetch-nvd':
                info = fetch_nvd(a.upstream, a.out, _now(a.now), a.max_upstream_age_hours)
            elif a.cmd == 'fetch-kev':
                info = fetch_kev(a.upstream, a.out)
            elif a.cmd == 'pack-trivy-checks':
                info = pack_trivy_checks(a.cache_dir, a.out)
            elif a.cmd == 'fetch-osv':
                info = fetch_osv(a.upstream, [e for e in a.ecosystems.split() if e], a.out)
            else:
                info = pack_trivy(a.cache_dir, a.out, _now(a.now), a.max_upstream_age_hours)
        except Refused as r:
            print('::error title=%s::%s' % (r.state, r.why))
            print(json.dumps({'state': r.state, 'why': r.why}))
            return 1
        print(json.dumps(info, sort_keys=True))
        return 0
    if a.cmd == 'manifest':
        if a.feed not in FEEDS or not GEN_RE.match(a.generation):
            print('usage: --feed must be one of %s and --generation like 20261027T050000Z-<run>' % (FEEDS,))
            return 2
        man = build_manifest(a.feed, a.dir, a.source_url, a.upstream_version, a.upstream_timestamp, a.generation,
                             iso(_now(a.now)), a.refreshed_by)
        with io.open(a.out, 'w', encoding='utf-8', newline='\n') as fh:
            fh.write(json.dumps(man, indent=2, sort_keys=True) + '\n')
        print('manifest %s: %d files, generation %s' % (a.feed, len(man['files']), a.generation))
        return 0
    if a.cmd == 'prune-plan':
        for g in prune_plan([line.strip().strip('/') for line in sys.stdin if line.strip()], a.keep, a.current):
            print(g)
        return 0
    ap.print_help()
    return 2


if __name__ == '__main__':
    sys.exit(main())

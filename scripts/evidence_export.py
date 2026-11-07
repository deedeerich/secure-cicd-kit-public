#!/usr/bin/env python3
"""evidence.export: the kit's half of the per-app evidence bundle -- read-only, one repository. (KDEC-039)

WHY THIS EXISTS

    The evidence harness builds one folder per app for a CAB change or an adoption review
    (src/app_evidence_bundle.py, docs/APP_EVIDENCE_BUNDLE.md, HDEC-009). It read the kit's half as a
    pile of downloaded artifacts -- kit-security-record-<attempt>, security-report-<attempt>,
    deploy-evidence-<run>-<attempt>, kit-promotion-record-<env>, kit-ticket-outbox-<id>, the durable
    kit-release-record deployment -- that a person had to find, download and keep before they expired,
    and it found three facts no kit record carried: whether any finding is on CISA KEV, the SBOM's
    digest, and who authored the commit (its prefill printed "KEV verdict NOT ESTABLISHED in the
    record", "SBOM NOT ESTABLISHED", "author NOT ESTABLISHED").

    The owner, 2026-11-06: the kit produces "the back half of the bundle".

WHAT IT RETURNS (api/v1/evidence-export.schema.json, schema kit-evidence-export/1)

    For ONE repository at ONE commit (or one release: a kit-release-record deployment, read for its
    commit), ten sections, each ESTABLISHED with its records and their sources (artifact name, run id
    and sha256, or deployment id), or NOT ESTABLISHED with the reason -- never an empty list standing
    in for a record nobody could read:

        security_record     the newest kit-security-record of a run on that commit
        review_signals      verdict_provenance, weakening_check, readiness_source, tier_reality and the
                            kit watermark, per release, and the security run's own
        promotion_records   the kit-promotion-record artifacts still live, and the summary each release
                            record now carries durably
        release_records     the DURABLE GitHub deployment records (task kit-release-record) for that
                            commit, with their latest status -- these survive artifact expiry
        findings            the security report's findings.json: identities, keys, rule, path, line,
                            severity -- never a message, a snippet or a detail
        ticket_outbox       the repository's ticket outbox: pending and drained
        ticket_links        each finding's ticket, from the ticket ledger on the default branch
        kev                 the gate's KEV verdict, and whether any finding is on CISA KEV
        sbom                the SBOM's sha256
        author              the commit author as a pseudonym (person:<10 hex>, the harness's own
                            scheme) and the committer verification state. NEVER an email.

    `unpack` writes the same records as the files the harness reads today (pass the folder as
    --kit-evidence); the API run uploads that folder as kit-evidence-export-<correlation id>.

THE RULES (KDEC-035's, unchanged)

    * READ-ONLY. Nothing is written but the answer and its artifact.
    * ONE REPOSITORY. A record naming another repository is never copied; it is counted
      (excluded_other_repository) so its absence is visible.
    * IDEMPOTENT. No clock is read; every list is sorted on stable keys: the same reads give the
      same bytes.
    * NO SECRETS, NO FREE TEXT. Every record is copied through an ALLOWLIST of its schema's fields,
      and any value that looks like a credential is withheld by name. A weakening's free-text reasons,
      a finding's message and an outbox's submitted params are never copied.
    * REFUSALS NAMED: exactly one of commit and release (API_SCHEMA_VIOLATION); another repository
      (API_REPOSITORY_NOT_SERVED); a release that is not a kit release record (API_EVIDENCE_UNAVAILABLE).

USAGE
    from evidence_export import export, unpack
    python3 evidence_export.py --self-test
"""
import hashlib
import io
import json
import os
import re
import sys
import zipfile

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

SCHEMA = 'kit-evidence-export/1'
ESTABLISHED = 'ESTABLISHED'
NOT_ESTABLISHED = 'NOT ESTABLISHED'
SECTIONS = ('security_record', 'review_signals', 'promotion_records', 'release_records', 'findings',
            'ticket_outbox', 'ticket_links', 'kev', 'sbom', 'author')
WITHHELD = '(withheld: secret-shaped value)'
ARTIFACT_PREFIX = 'kit-evidence-export-'
INLINE_MAX = 50000

# Mutation switches for tests/prove_evidence_export.py (M1-M4). The shipped values are the only correct ones.
repository_filter = True
missing_as_empty = False
copy_whole_records = False
author_by_email = False

COMMIT_RE = re.compile(r'^[0-9a-f]{40}$')
REPO_RE = re.compile(r'^[A-Za-z0-9_.-]{1,100}/[A-Za-z0-9_.-]{1,100}$')

# The harness's own secret test (src/app_evidence_bundle.py looks_secret), so both sides withhold alike.
SECRET_RX = re.compile(
    r'(gh[pousr]_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,}|AKIA[0-9A-Z]{16}|ASIA[0-9A-Z]{16}|xox[abpors]-[A-Za-z0-9-]{10,}'
    r'|-----BEGIN [A-Z ]*PRIVATE KEY|eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}|(?i:password|passwd|secret|token|apikey'
    r'|api_key|sig)=\S+|AccountKey=|SharedAccessSignature|sk-[A-Za-z0-9]{20,})')
SAFE_LONG = re.compile(r'^(?:[0-9a-f]{32,64}|sha256:[0-9a-f]{64}|/subscriptions/\S+|arn:aws[a-z-]*:\S+|'
                       r'[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12})$')


def looks_secret(v):
    s = str(v or '')
    if SECRET_RX.search(s):
        return True
    for t in re.split(r'[\s,;|]+', s):
        if len(t) >= 32 and not SAFE_LONG.match(t) and re.search(r'[A-Z]', t) and re.search(r'[a-z]', t) \
                and re.search(r'\d', t) and '/' not in t and ':' not in t:
            return True
    return False


def person(login):
    """The harness's pseudonym: the same login is always the same pseudonym; the login is never written."""
    n = str(login or '').strip().lstrip('@').lower()
    return ('person:' + hashlib.sha256(n.encode('utf-8')).hexdigest()[:10]) if n else ''


def _s(v):
    return v.strip() if isinstance(v, str) else ''


def _int(v, d=0):
    try:
        return int(str(v).strip())
    except (TypeError, ValueError):
        return d


def _clean(v):
    if isinstance(v, str):
        return WITHHELD if looks_secret(v) else v
    if isinstance(v, (bool, int, float)) or v is None:
        return v
    if isinstance(v, list):
        return [_clean(x) for x in v]
    if isinstance(v, dict):
        return dict((str(k), _clean(x)) for k, x in v.items())
    return None


def _pick(obj, spec):
    """Copy `obj` through `spec`: None = the value (scalars and lists of scalars only); a tuple = those keys;
    a dict = nested specs; ('list', sub) = each item through sub. Anything else is dropped."""
    if copy_whole_records:      # mutant M3 only
        return obj
    if spec is None:
        if isinstance(obj, (str, bool, int, float)) or obj is None:
            return _clean(obj)
        if isinstance(obj, list) and all(isinstance(x, (str, bool, int, float)) or x is None for x in obj):
            return _clean(obj)
        return None
    if isinstance(spec, tuple) and spec and spec[0] == 'list':
        return [_pick(x, spec[1]) for x in obj] if isinstance(obj, list) else None
    if not isinstance(obj, dict):
        return None
    out = {}
    keys = spec.items() if isinstance(spec, dict) else ((k, None) for k in spec)
    for k, sub in keys:
        if k in obj:
            val = _pick(obj[k], sub)
            if val is not None:
                out[k] = val
    return out


# ── the allowlists: each record's schema fields, never its free text ─────────────────────────────
SECURITY_RECORD = {
    'schema': None,
    'run': ('repository', 'run_id', 'run_attempt', 'commit', 'ref', 'actor', 'triggering_actor'),
    'verdict': ('routing_result', 'advisory_causes'),
    'weakening': {'attribution': None, 'check': ('state', 'missing', 'self_named', 'approver_list', 'ceiling_days',
                                                 'expires')},
    'capability_floor': ('state', 'missing'), 'token_preflight': None, 'leak_gates': None, 'leak_gate_alarm': None,
    'policy': {'source': None, 'resolution': None, 'rung_effective': None, 'environment_tier': None,
               'notices': ('list', ('code',))},
    'deploy_coverage': {'no_kit_adapter': None},
    'kit': ('state', 'source_commit', 'kit_ref', 'kit_repository'),
    'evidence': ('artifact', 'record_artifact', 'retention_days', 'retention'),
    'run_record': {'assurance_state': None, 'enforcement_state': None, 'secret_gate': None,
                   'secret_exceptions': ('list', ('finding', 'ticket', 'approver', 'expires'))},
    'kev': ('state', 'verdict', 'kev_state', 'on_kev', 'why'),
    'sbom': ('state', 'digest', 'artifact', 'why'),
    'author': {'state': None, 'id': None, 'committer_id': None, 'why': None, 'basis': None,
               'verification': ('verified', 'reason')},
}
RELEASE_RECORD = {k: None for k in (
    'schema', 'repository', 'run_id', 'run_attempt', 'commit', 'environment', 'tier', 'adapter', 'digest',
    'routing_result', 'deployment_outcome', 'release_approval', 'release_approval_by', 'zone_readiness',
    'release_block', 'verdict_provenance', 'weakening_check', 'tier_source', 'tier_reality', 'tier_reality_signals',
    'readiness_source', 'hosting_kind', 'lease', 'seam', 'kit_source_commit', 'kit_watermark',
    'promotion_record_sha256', 'evidence_artifact', 'retention_days', 'release_record', 'release_record_ref')}
RELEASE_RECORD['promotion'] = ('record_id', 'state', 'release_path', 'expires_at', 'target_resource_id', 'digest')
PROMOTION_RECORD = {'schema': None, 'record_id': None, 'state': None, 'release_path': None,
                    'artifact': ('digest',), 'environment': ('name', 'tier', 'adapter', 'target_resource_id'),
                    'validity': ('expires_at',), 'run': ('id', 'attempt', 'url')}
FINDING = ('identity', 'fp', 'scanner', 'tool', 'scanner_version', 'job', 'rule_id', 'severity', 'canonical_path',
           'line', 'finding_subject', 'cwe', 'state', 'reason', 'row_established', 'rule_family', 'symbol_path',
           'ticket_anchor', 'ticket_key_state', 'secret_family', 'secret_key', 'is_secret_finding', 'what_aliases')
SIGNALS = ('environment', 'run_id', 'run_attempt', 'verdict_provenance', 'weakening_check', 'readiness_source',
           'tier_reality', 'kit_watermark', 'release_approval', 'routing_result')
CVE_RE = re.compile(r'CVE-\d{4}-\d{4,}', re.I)


def refusal(code, detail, field=''):
    import kit_api as ka
    return ka.refusal(code, detail, field)


def params_problem(p, repository):
    """-> the refusal for these params, or None. Exactly one of commit and release; this repository only."""
    import kit_api as ka
    p = p if isinstance(p, dict) else {}
    if bool(p.get('commit')) == bool(p.get('release')):
        return refusal(ka.API_SCHEMA_VIOLATION, 'evidence.export takes exactly one of commit and release', 'params')
    want = _s(p.get('repository'))
    if want and want.lower() != _s(repository).lower():
        return refusal(ka.API_REPOSITORY_NOT_SERVED, 'this API serves %s, not %s; call that repository\'s kit-api '
                                                     '(an export is one repository, never two)' % (repository, want),
                       'params.repository')
    return None


# ── reading GitHub ─────────────────────────────────────────────────────────────────────────────
def _members(blob):
    out = {}
    if not blob:
        return None
    try:
        z = zipfile.ZipFile(io.BytesIO(blob))
    except zipfile.BadZipFile:
        return None
    for name in sorted(z.namelist()):
        base = name.rsplit('/', 1)[-1]
        if base not in out:
            out[base] = z.read(name)
    return out


def _json(raw):
    try:
        return json.loads(raw.decode('utf-8'))
    except (ValueError, AttributeError, UnicodeDecodeError):
        return None


ARTIFACT_KINDS = (('kit-security-record-', 'kit-security-record.json', 'security_records'),
                  ('security-report-', 'findings.json', 'findings'),
                  ('deploy-evidence-', 'review-signals.json', 'review_signals'),
                  ('kit-promotion-record-', 'promotion-record.json', 'promotions'))


def collect(client, repo, commit):
    """-> the raw reads for one commit. Every read that failed is named in raw['reads'] (section -> why)."""
    raw = {'security_records': [], 'findings': [], 'review_signals': [], 'promotions': [], 'deployments': [],
           'outboxes': [], 'drained': [], 'sbom_digest': None, 'commit': None, 'reads': {}, 'expired': []}
    st, doc, _h, err = client.get('/repos/%s/actions/runs?head_sha=%s&per_page=100' % (repo, commit))
    runs = []
    if err or not isinstance(doc, dict):
        raw['reads']['runs'] = 'the runs of %s could not be read (%s)' % (commit[:12], err or st)
    else:
        runs = sorted([r for r in doc.get('workflow_runs') or [] if r.get('head_sha') == commit],
                      key=lambda r: _int(r.get('id')))
    for run in runs:
        st, adoc, _h, err = client.get('/repos/%s/actions/runs/%s/artifacts?per_page=100' % (repo, run['id']))
        if err or not isinstance(adoc, dict):
            raw['reads']['artifacts'] = 'the artifacts of run %s could not be read (%s)' % (run['id'], err or st)
            continue
        for a in sorted(adoc.get('artifacts') or [], key=lambda x: (str(x.get('name')), _int(x.get('id')))):
            name = str(a.get('name') or '')
            kind = [k for k in ARTIFACT_KINDS if name.startswith(k[0])]
            if not kind and name != 'sbom':
                continue
            if a.get('expired'):
                raw['expired'].append(name)
                continue
            files = _members(client.download('/repos/%s/actions/artifacts/%s/zip' % (repo, a['id'])))
            if files is None:
                raw['reads'][name] = 'the artifact %s could not be downloaded' % name
                continue
            if name == 'sbom':
                body = files.get('sbom.cyclonedx.json')
                if body:
                    raw['sbom_digest'] = ('sha256:' + hashlib.sha256(body).hexdigest(),
                                          {'kind': 'artifact', 'name': name, 'run_id': _int(run['id'])})
                continue
            prefix, member, key = kind[0]
            body = files.get(member)
            if body is None:
                raw['reads'][name] = 'the artifact %s holds no %s' % (name, member)
                continue
            parsed = _json(body)
            src = {'kind': 'artifact', 'name': name, 'run_id': _int(run['id']),
                   'sha256': hashlib.sha256(body).hexdigest()}
            raw[key].append((src, parsed))
    st, deps, _h, err = client.get('/repos/%s/deployments?sha=%s&task=kit-release-record&per_page=100' % (repo, commit))
    if err or not isinstance(deps, list):
        raw['reads']['deployments'] = ('the deployments of %s could not be read (%s): the api job needs '
                                       'deployments: read (templates/kit-api.yml)' % (commit[:12], err or st))
    else:
        for d in sorted(deps, key=lambda x: _int(x.get('id'))):
            if d.get('task') != 'kit-release-record' or d.get('sha') != commit:
                continue
            st, sts, _h, err = client.get('/repos/%s/deployments/%s/statuses?per_page=1' % (repo, d['id']))
            state = (sts[0].get('state') if isinstance(sts, list) and sts else '') or 'not read'
            raw['deployments'].append(({'kind': 'deployment', 'id': _int(d['id'])}, d, state))
    st, adoc, _h, err = client.get('/repos/%s/actions/artifacts?per_page=100' % repo)
    if err or not isinstance(adoc, dict):
        raw['reads']['outbox'] = 'the repository\'s artifacts could not be read (%s)' % (err or st)
    else:
        arts = [a for a in adoc.get('artifacts') or [] if not a.get('expired')]
        for a in sorted(arts, key=lambda x: str(x.get('name'))):
            name = str(a.get('name') or '')
            if name.startswith('kit-ticket-outbox-done-'):
                files = _members(client.download('/repos/%s/actions/artifacts/%s/zip' % (repo, a['id']))) or {}
                done = _json(files.get('outbox-done.json') or b'') or {}
                raw['drained'] += [str(x) for x in done.get('drained') or []]
            elif name.startswith('kit-ticket-outbox-'):
                files = _members(client.download('/repos/%s/actions/artifacts/%s/zip' % (repo, a['id']))) or {}
                body = files.get('outbox.json')
                if body is not None:
                    raw['outboxes'].append(({'kind': 'artifact', 'name': name, 'run_id': _int((a.get('workflow_run') or {})
                                                                                              .get('id')),
                                             'sha256': hashlib.sha256(body).hexdigest()}, _json(body)))
    st, cdoc, _h, err = client.get('/repos/%s/commits/%s' % (repo, commit))
    raw['commit'] = cdoc if (not err and isinstance(cdoc, dict)) else None
    return raw


# ── assembling ─────────────────────────────────────────────────────────────────────────────────
def _ne(why, **extra):
    out = {'state': NOT_ESTABLISHED, 'why': why}
    if missing_as_empty:        # mutant M2 only
        return dict(extra, state=ESTABLISHED, why='', records=[], findings=[], links=[], pending=[], drained=[])
    out.update(extra)
    return out


def _repo_of_url(url):
    m = re.match(r'^https?://[^/]+/([A-Za-z0-9_.-]+)/([A-Za-z0-9_.-]+)/', str(url or ''))
    return ('%s/%s' % (m.group(1), m.group(2))).lower() if m else ''


def _theirs(record_repo, repo):
    return repository_filter and bool(_s(record_repo)) and _s(record_repo).lower() != _s(repo).lower()


def assemble(repo, commit, subject, raw, ledger=None, ledger_note=''):
    """Pure. -> the export document."""
    excluded = []
    secs = {}
    why_missing = lambda what, keys: '; '.join(  # noqa: E731
        [raw['reads'][k] for k in keys if k in raw['reads']] +
        (['expired: %s' % ', '.join(sorted(x for x in raw['expired'] if x.startswith(what)))]
         if any(x.startswith(what) for x in raw['expired']) else []))

    # security record
    recs = []
    for src, doc in raw['security_records']:
        if not isinstance(doc, dict) or doc.get('schema') != 'kit-security-record/1':
            continue
        if _theirs((doc.get('run') or {}).get('repository'), repo):
            excluded.append('security record')
            continue
        if _s((doc.get('run') or {}).get('commit')) not in ('', commit):
            continue
        recs.append((src, doc))
    recs.sort(key=lambda x: (_int((x[1].get('run') or {}).get('run_id')), _int((x[1].get('run') or {}).get('run_attempt'))))
    sec_doc = recs[-1][1] if recs else None
    if recs:
        secs['security_record'] = {'state': ESTABLISHED, 'source': recs[-1][0], 'record': _pick(sec_doc, SECURITY_RECORD),
                                   'runs': [_int((d.get('run') or {}).get('run_id')) for _s2, d in recs]}
    else:
        secs['security_record'] = _ne('no kit-security-record of a run on %s: %s' % (
            commit[:12], why_missing('kit-security-record-', ('runs', 'artifacts')) or 'none was kept for this commit'))

    # release records: durable first, then any deploy evidence artifact still live
    releases, seen = [], set()
    for src, d, status in raw['deployments']:
        payload = d.get('payload') if isinstance(d.get('payload'), dict) else {}
        if payload.get('schema') != 'kit-release-record/1':
            continue
        if _theirs(payload.get('repository'), repo):
            excluded.append('release record')
            continue
        key = (_int(payload.get('run_id')), _int(payload.get('run_attempt')), _s(payload.get('environment')))
        seen.add(key)
        releases.append({'source': src, 'deployment_id': _int(d.get('id')), 'environment': _s(d.get('environment')),
                         'created_at': _s(d.get('created_at')), 'status': status,
                         'payload': _pick(payload, RELEASE_RECORD)})
    for src, doc in raw['review_signals']:
        if not isinstance(doc, dict) or doc.get('schema') != 'kit-release-record/1':
            continue
        if _theirs(doc.get('repository'), repo):
            excluded.append('release record')
            continue
        key = (_int(doc.get('run_id')), _int(doc.get('run_attempt')), _s(doc.get('environment')))
        if key in seen:
            continue
        seen.add(key)
        releases.append({'source': src, 'deployment_id': None, 'environment': _s(doc.get('environment')),
                         'created_at': '', 'status': 'not a deployment record', 'payload': _pick(doc, RELEASE_RECORD)})
    releases.sort(key=lambda r: (_int(r['payload'].get('run_id')), _int(r['payload'].get('run_attempt')),
                                 r['environment']))
    if releases:
        secs['release_records'] = {'state': ESTABLISHED, 'records': releases}
    else:
        secs['release_records'] = _ne('no kit release record for %s: %s' % (commit[:12], why_missing(
            'deploy-evidence-', ('deployments',)) or 'no deployment with task kit-release-record names this commit'))

    # review signals
    sig = {}
    if sec_doc:
        sig['security'] = {'routing_result': _clean((sec_doc.get('verdict') or {}).get('routing_result')),
                           'weakening_check': _clean(((sec_doc.get('weakening') or {}).get('check') or {}).get('state')),
                           'kit_watermark': _clean((sec_doc.get('kit') or {}).get('state'))}
    if releases:
        sig['releases'] = [dict((k, r['payload'].get(k)) for k in SIGNALS if k in r['payload']) for r in releases]
    secs['review_signals'] = dict(state=ESTABLISHED, **sig) if sig else _ne(
        'no security record and no release record carry the review signals for %s' % commit[:12])

    # promotion records
    promos = []
    for src, doc in raw['promotions']:
        if not isinstance(doc, dict) or doc.get('schema') != 'kit-promotion-record/1':
            continue
        if _theirs(_repo_of_url((doc.get('run') or {}).get('url')), repo):
            excluded.append('promotion record')
            continue
        promos.append({'source': src, 'record': _pick(doc, PROMOTION_RECORD)})
    for r in releases:
        if isinstance(r['payload'].get('promotion'), dict):
            promos.append({'source': r['source'], 'durable': True, 'environment': r['environment'],
                           'summary': r['payload']['promotion']})
    promos.sort(key=lambda p: (json.dumps(p['source'], sort_keys=True), p.get('environment') or ''))
    secs['promotion_records'] = {'state': ESTABLISHED, 'records': promos} if promos else _ne(
        'no kit-promotion-record artifact is live and no release record carries a promotion summary for %s%s'
        % (commit[:12], ('; ' + why_missing('kit-promotion-record-', ())) if why_missing('kit-promotion-record-', ()) else ''))

    # findings
    reports = [(src, doc) for src, doc in raw['findings'] if isinstance(doc, list)]
    reports.sort(key=lambda x: (x[0].get('run_id') or 0, x[0].get('name') or ''))
    links_by_ident = {}
    if isinstance(ledger, dict):
        for ck, e in sorted(ledger.items()):
            if not isinstance(e, dict) or str(ck).startswith('test:') or not e.get('ref'):
                continue
            for ident in e.get('member_identities') or []:
                links_by_ident.setdefault(str(ident), (str(e.get('merged_into') or ck), str(e.get('ref')),
                                                        str(e.get('key') or '')))
    if reports:
        src, flist = reports[-1]
        shaped = []
        for f in flist:
            if not isinstance(f, dict):
                continue
            g = _pick(f, FINDING)
            g['cves'] = sorted(set(c.upper() for t in [f.get('rule_id') or ''] + list(f.get('what_aliases') or [])
                                   for c in CVE_RE.findall(str(t))))
            idents = [x for x in (f.get('identity'), ('secret:' + f['secret_key']) if f.get('secret_key') else None) if x]
            hit = [links_by_ident[i] for i in idents if i in links_by_ident]
            if hit:
                g['ticket'] = {'cluster_key': hit[0][0], 'ref': hit[0][1], 'key': hit[0][2]}
            shaped.append(g)
        shaped.sort(key=lambda g: (str(g.get('job')), str(g.get('scanner')), str(g.get('canonical_path')),
                                   _int(g.get('line')), str(g.get('identity') or g.get('fp'))))
        sev = {}
        for g in shaped:
            sev[str(g.get('severity') or 'unknown').lower()] = sev.get(str(g.get('severity') or 'unknown').lower(), 0) + 1
        secs['findings'] = {'state': ESTABLISHED, 'source': src, 'count': len(shaped), 'by_severity': sev,
                            'findings': shaped}
    else:
        secs['findings'] = _ne('no security report (findings.json) of a run on %s: %s' % (
            commit[:12], why_missing('security-report-', ('runs', 'artifacts')) or 'none was kept for this commit'))

    # ticket links
    if not isinstance(ledger, dict):
        secs['ticket_links'] = _ne('the ticket ledger could not be read (%s)' % (ledger_note or 'no ledger'))
    elif secs['findings']['state'] != ESTABLISHED:
        secs['ticket_links'] = _ne('no findings were read for this commit, so none can be linked')
    else:
        links = {}
        for g in secs['findings']['findings']:
            t = g.get('ticket')
            if t:
                ent = links.setdefault(t['cluster_key'], {'cluster_key': t['cluster_key'], 'ref': t['ref'],
                                                          'key': t['key'], 'member_identities': []})
                for i in (g.get('identity'), ('secret:' + g['secret_key']) if g.get('secret_key') else None):
                    if i and i in links_by_ident and i not in ent['member_identities']:
                        ent['member_identities'].append(i)
        secs['ticket_links'] = {'state': ESTABLISHED, 'ledger': _clean(ledger_note or ''),
                                'links': sorted(links.values(), key=lambda x: x['cluster_key'])}

    # ticket outbox
    if 'outbox' in raw['reads']:
        secs['ticket_outbox'] = _ne(raw['reads']['outbox'])
    else:
        drained = sorted(set(raw['drained']))
        pending = []
        for src, doc in raw['outboxes']:
            if not isinstance(doc, dict) or doc.get('schema') != 'kit-ticket-outbox/1':
                continue
            if _theirs(doc.get('repository'), repo):
                excluded.append('ticket outbox')
                continue
            cid = _s(doc.get('correlation_id'))
            if cid in drained:
                continue
            pending.append({'source': src, 'correlation_id': cid, 'created_at': _clean(_s(doc.get('created_at'))),
                            'items_held': len(doc.get('items') or []), 'reason': _clean(_s(doc.get('reason'))[:200])})
        pending.sort(key=lambda x: x['correlation_id'])
        secs['ticket_outbox'] = {'state': ESTABLISHED, 'pending': pending, 'drained': drained}

    # KEV, SBOM, author: the security record first, then what the export can read itself
    k = (sec_doc or {}).get('kev')
    secs['kev'] = dict(_pick(k, SECURITY_RECORD['kev']), source=recs[-1][0]) if isinstance(k, dict) and \
        k.get('state') == ESTABLISHED else _ne((k or {}).get('why') if isinstance(k, dict) and k.get('why') else (
            'the security record predates KDEC-039 and carries no KEV verdict' if sec_doc else 'no security record'))
    b = (sec_doc or {}).get('sbom')
    if isinstance(b, dict) and b.get('state') == ESTABLISHED:
        secs['sbom'] = dict(_pick(b, SECURITY_RECORD['sbom']), source=recs[-1][0])
    elif raw.get('sbom_digest'):
        secs['sbom'] = {'state': ESTABLISHED, 'digest': raw['sbom_digest'][0], 'source': raw['sbom_digest'][1],
                        'basis': 'computed from the live sbom artifact (sbom.cyclonedx.json)'}
    else:
        secs['sbom'] = _ne('no SBOM digest in the security record and no live sbom artifact for %s%s' % (
            commit[:12], '; expired: sbom' if 'sbom' in raw['expired'] else ''))
    a = (sec_doc or {}).get('author')
    if isinstance(a, dict) and a.get('state') == ESTABLISHED:
        secs['author'] = dict(_pick(a, SECURITY_RECORD['author']), source=recs[-1][0])
    else:
        secs['author'] = author_of(raw.get('commit'))

    for name in SECTIONS:
        secs.setdefault(name, _ne('not read'))
    doc = {'schema': SCHEMA, 'repository': repo, 'commit': commit, 'subject': subject, 'sections': secs,
           'not_established': [n for n in SECTIONS if secs[n]['state'] == NOT_ESTABLISHED],
           'excluded_other_repository': {'count': len(excluded), 'kinds': sorted(set(excluded))}}
    return doc


def author_of(cdoc):
    """The commit author from GET /repos/{repo}/commits/{sha}: a pseudonym of the GitHub login and the committer
    verification state. The commit's email is never read."""
    if not isinstance(cdoc, dict):
        return _ne('the commit could not be read')
    login = _s((cdoc.get('author') or {}).get('login'))
    ver = ((cdoc.get('commit') or {}).get('verification') or {})
    if author_by_email:      # mutant M4 only
        return {'state': ESTABLISHED, 'id': ((cdoc.get('commit') or {}).get('author') or {}).get('email')}
    if not login:
        return _ne('the commit author has no GitHub account linked; the commit email is never recorded')
    return {'state': ESTABLISHED, 'id': person(login),
            'committer_id': person((cdoc.get('committer') or {}).get('login')) or None,
            'verification': {'verified': bool(ver.get('verified')), 'reason': _clean(_s(ver.get('reason')) or 'unknown')},
            'basis': 'the GitHub login of the commit author, pseudonymised (sha256, 10 hex); read from the commit',
            'source': {'kind': 'commit', 'sha': _s(cdoc.get('sha'))}}


def export(client, repo, params, ledger=None, ledger_note=''):
    """-> (doc, None) or (None, refusal)."""
    import kit_api as ka
    bad = params_problem(params, repo)
    if bad:
        return None, bad
    if params.get('release'):
        did = _int(params['release'])
        st, d, _h, err = client.get('/repos/%s/deployments/%s' % (repo, did))
        if err or not isinstance(d, dict):
            return None, refusal(ka.API_EVIDENCE_UNAVAILABLE, 'deployment %s could not be read (%s)' % (did, err or st),
                                 'params.release')
        if d.get('task') != 'kit-release-record' or not COMMIT_RE.match(_s(d.get('sha'))):
            return None, refusal(ka.API_EVIDENCE_UNAVAILABLE, 'deployment %s is not a kit release record (task %r)'
                                 % (did, d.get('task')), 'params.release')
        commit, subject = d['sha'], {'kind': 'release', 'ref': str(did)}
    else:
        commit, subject = _s(params['commit']), {'kind': 'commit', 'ref': _s(params['commit'])}
    raw = collect(client, repo, commit)
    return assemble(repo, commit, subject, raw, ledger, ledger_note), None


# ── the harness's files ────────────────────────────────────────────────────────────────────────
def _put(path, doc):
    d = os.path.dirname(path)
    if d and not os.path.isdir(d):
        os.makedirs(d)
    with io.open(path, 'w', encoding='utf-8', newline='\n') as fh:
        fh.write(json.dumps(doc, indent=1, sort_keys=True) + '\n')
    return path


def _slug(v):
    return re.sub(r'[^A-Za-z0-9._-]+', '-', str(v or ''))[:80] or 'x'


def unpack(doc, out_dir):
    """Write the export as the record files the harness reads (pass `out_dir` as --kit-evidence). -> paths."""
    secs = doc.get('sections') or {}
    written = [_put(os.path.join(out_dir, 'evidence-export.json'), doc)]
    s = secs.get('security_record') or {}
    if s.get('state') == ESTABLISHED:
        rec = s['record']
        written.append(_put(os.path.join(out_dir, 'kit-security-record-%s' % _slug((rec.get('run') or {}).get('run_attempt')
                                                                                    or '1'), 'kit-security-record.json'), rec))
    f = secs.get('findings') or {}
    if f.get('state') == ESTABLISHED:
        rows = []
        for g in f['findings']:
            row = dict(g)
            if g.get('ticket'):
                row['ticket'] = {'ref': g['ticket'].get('key') or g['ticket'].get('ref'), 'id': g['ticket'].get('ref')}
            rows.append(row)
        written.append(_put(os.path.join(out_dir, 'security-report-%s' % _slug((f.get('source') or {}).get('run_id')),
                                         'findings.json'), rows))
    for r in (secs.get('release_records') or {}).get('records') or []:
        if r.get('deployment_id'):
            written.append(_put(os.path.join(out_dir, 'release-record-%s.json' % r['deployment_id']),
                                {'id': r['deployment_id'], 'task': 'kit-release-record', 'payload': r['payload']}))
        else:
            p = r['payload']
            written.append(_put(os.path.join(out_dir, 'deploy-evidence-%s-%s' % (_slug(p.get('run_id')),
                                                                                 _slug(p.get('run_attempt'))),
                                             'review-signals.json'), p))
    for pr in (secs.get('promotion_records') or {}).get('records') or []:
        if pr.get('record'):
            env = ((pr['record'].get('environment') or {}).get('name')) or 'unknown'
            written.append(_put(os.path.join(out_dir, 'kit-promotion-record-%s' % _slug(env), 'promotion-record.json'),
                                pr['record']))
    for e in (secs.get('ticket_outbox') or {}).get('pending') or []:
        written.append(_put(os.path.join(out_dir, 'kit-ticket-outbox-%s' % _slug(e['correlation_id']), 'outbox.json'),
                            {'schema': 'kit-ticket-outbox/1', 'correlation_id': e['correlation_id'],
                             'created_at': e.get('created_at') or '', 'items': list(range(int(e.get('items_held') or 0))),
                             'reason': e.get('reason') or '', 'repository': doc.get('repository')}))
    return written


def summary_of(doc):
    """An abridged export for a check run that cannot hold the whole: every section's state, reason and count."""
    secs = {}
    for name, s in (doc.get('sections') or {}).items():
        n = {'state': s.get('state')}
        if s.get('why'):
            n['why'] = s['why']
        for k in ('records', 'findings', 'links', 'pending'):
            if isinstance(s.get(k), list):
                n['count'] = len(s[k])
        secs[name] = n
    return dict(schema=doc['schema'], repository=doc['repository'], commit=doc['commit'], subject=doc['subject'],
                not_established=doc['not_established'], excluded_other_repository=doc['excluded_other_repository'],
                sections=secs, abridged=True)


def serve(intake_doc, env, client, out_dir):
    """The API run's answer to evidence.export (scripts/kit_api_server.py findings phase)."""
    import kit_api as ka
    import kit_api_server as ks
    import reconcile_tickets as rt
    req = intake_doc['request']
    repo = _s(env.get('GITHUB_REPOSITORY'))
    ledger, lnote = rt.load_ledger(_s(env.get('KIT_API_LEDGER')))
    doc, ref = export(client, repo, req.get('params') or {}, ledger if isinstance(ledger, dict) else None,
                      lnote if isinstance(ledger, dict) else 'unreadable: %s' % lnote)
    if ref:
        return ks.answer(ka.API_REFUSED, refusal=ref)
    cid = _s(intake_doc.get('correlation_id'))
    full = json.dumps(doc, sort_keys=True)
    if out_dir:
        unpack(doc, os.path.join(out_dir, 'evidence-export'))
    data = {'export_sha256': hashlib.sha256(full.encode('utf-8')).hexdigest(),
            'artifact': ARTIFACT_PREFIX + (cid or 'unnamed')}
    notes = []
    if len(full) <= INLINE_MAX:
        data['export'] = doc
    else:
        data['export'] = summary_of(doc)
        notes.append('the export is %d characters; the answer carries every section\'s state and count, and the '
                     'artifact %s holds the whole export and its unpacked records' % (len(full), data['artifact']))
    if doc['not_established']:
        notes.append('NOT ESTABLISHED: %s -- each section says why; absence is not a negative'
                     % ', '.join(doc['not_established']))
    return ks.answer(ka.API_COMPLETED, data, notes)


def _selftest():
    fails = []
    if not looks_secret('ghp_' + 'A1' * 18) or looks_secret('a' * 40) or looks_secret('sha256:' + 'b' * 64):
        fails.append('the secret test is wrong')
    if person('Dev-One') != person('dev-one') or not person('x').startswith('person:'):
        fails.append('the pseudonym is not the harness\'s')
    d = assemble('o/r', 'c' * 40, {'kind': 'commit', 'ref': 'c' * 40},
                 {'security_records': [], 'findings': [], 'review_signals': [], 'promotions': [], 'deployments': [],
                  'outboxes': [], 'drained': [], 'sbom_digest': None, 'commit': None, 'reads': {}, 'expired': []})
    if sorted(d['not_established']) != sorted(n for n in SECTIONS if n != 'ticket_outbox'):
        fails.append('an empty read did not make every record section NOT ESTABLISHED: %r' % d['not_established'])
    if fails:
        for f in fails:
            sys.stderr.write('FAIL: %s\n' % f)
        return 2
    print('evidence_export selftest ok: secret-shaped values withheld, the harness\'s pseudonym, and an empty read is '
          'NOT ESTABLISHED in every record section. The cases run in tests/prove_evidence_export.py.')
    return 0


if __name__ == '__main__':
    if len(sys.argv) == 2 and sys.argv[1] in ('--self-test', '--selftest'):
        sys.exit(_selftest())
    print('usage: evidence_export.py --self-test   (library; the API serves evidence.export)', file=sys.stderr)
    sys.exit(2)

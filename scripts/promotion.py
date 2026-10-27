#!/usr/bin/env python3
"""Build once, promote the same digest: the promotion record, the promotion gate, the checks that
make a deploy "tested", and the daily scan of what is actually serving. (KDEC-029, owner 2026-10-26.)

WHY THIS EXISTS

    The deploy contract computed `promotion` and could never read "verified" (COMPLETION_LEDGER
    DCR-11, open decision O-11): three of its conditions had no evidence source, and nothing
    consumed the answer. The owner closed O-11 on 2026-10-26:

      1  A merge to main builds ONCE; that exact digest moves through the environments.
      2  dev and test deploy in parallel from the same build; uat and prod are PROMOTED from the
         prior environment (prod's predecessor is test or uat, per product; default test).
      3  "Tested" = health, the end-to-end test period (KDEC-021), DAST (where configured) with
         no new blocking finding, and the security-settings posture check.
         Only then does the record read `verified-for-promotion`.
      4  14 days is a MAXIMUM: a newer verified build in the same predecessor supersedes an older
         one; and eligibility is revocable at once (a new critical or known-exploited finding, a
         revoked signing identity, a revoked approval, invalidated test evidence).
      5  The promotion gate refuses, naming its reason, before the deploy identity is used.
      6  Hotfix = the same path compressed; break-glass = an approved, time-limited exception,
         recorded BREAK_GLASS, with the testing owed afterwards and flagged until done.
      7  Prod gets passive checks only (health, posture); active DAST against prod is refused.
      8  A daily scan reconciles what is serving, rescans that digest (never a rebuild), and
         reports artifact drift and security drift separately; it never rolls anything back.

WHERE IT RUNS

    Inlined into both deploy reusables beside deploy_contract.py (scripts/inline_deploy_scripts.py),
    one subcommand per step, and run from the kit checkout by the deployed-scan composite:

      preflight     every deploy, before login: release path, DAST vs prod, uat/prod need a
                    predecessor, the break-glass exception, the test-period bounds
      gate-collect  promotion only, before login: the source record (exactly run Y, environment
                    Y, digest X), the predecessor's history, the revocation register, the build's
                    SBOM (sha256 checked) re-scanned by the pinned Trivy
      gate-decide   promotion only, before login: the verdict, with the KEV re-check and V1
      test-period   after serving: health + the caller's e2e command at start/intervals/end
      dast          after serving: the caller's DAST command (its report as SARIF); never at prod

    DAST IS A NEUTRAL HOOK. The owner's decision names ZAP baseline; ZAP is recorded as overlay
    custody (the overlay's CAPABILITY_CUSTODY.csv, tests/check_custody.py), so the core runs the
    caller's `dast_command` against PROMOTION_APP_URL and reads the SARIF it writes to
    PROMOTION_DAST_SARIF; an overlay supplies ZAP baseline through it (docs/adoption/USAGE.md).
      posture       after serving: the target's security settings, read live
      record        always: the promotion record (schemas/promotion-record.schema.json)
      deployed-scan the daily scan (reconcile, artifact drift, security drift, break-glass owed)

    GitHub API: $GITHUB_API_URL, $GITHUB_REPOSITORY, $GH_TOKEN (rollback_hold's client). A file://
    API is the local stand-in (tests).
"""
import argparse
import base64
import datetime
import hashlib
import io
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import time
import zipfile

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import deploy_contract as dc  # noqa: E402  (materialised beside this file)
import rollback_hold as rh  # noqa: E402

SCHEMA = 'kit-promotion-record/1'
VERIFIED = 'verified-for-promotion'
NOT_VERIFIED = 'not-verified'
BREAK_GLASS = 'BREAK_GLASS'
MAX_AGE_DAYS = 14            # the owner's number: a maximum, never a guarantee
BREAK_GLASS_MAX_DAYS = 7     # lane default: a break-glass exception lives a week at most
DEFAULT_PERIOD_MINUTES = 15  # KDEC-021
MAX_PERIOD_MINUTES = 240
PREDECESSOR_TIERS = ('test', 'uat')   # a dev or sandbox success never satisfies a predecessor
RELEASE_PATHS = ('normal', 'hotfix', 'rollback', 'break-glass')
DAST_TIMEOUT_SECONDS = 1800   # bound on the caller's DAST command
TRIVY_VERSION = '0.71.2'
REVOCATIONS_PATH = '.security/promotion-revocations.json'
REVOCATION_KINDS = ('digest', 'signer', 'approval', 'test-evidence')

# Every refusal the gate and the preflight can give. The code is the reason's name; the text says
# what to do about it.
REFUSALS = {
    'PROMOTION_REFUSED_SOURCE_UNREADABLE': 'the source record (run, environment) could not be read',
    'PROMOTION_REFUSED_DIGEST_MISMATCH': 'the digest to deploy is not the digest the source record '
                                         'verified: a substituted artefact',
    'PROMOTION_REFUSED_WRONG_PREDECESSOR': 'the source is not the required predecessor environment '
                                           '(a dev success never satisfies a test or uat predecessor)',
    'PROMOTION_REFUSED_NOT_VERIFIED': 'the digest was not verified-for-promotion in the predecessor',
    'PROMOTION_REFUSED_NOT_FROM_MAIN': 'the digest was not built from the default branch',
    'PROMOTION_REFUSED_SIGNATURE': 'the digest\'s signed build provenance did not verify (V1)',
    'PROMOTION_REFUSED_REVOKED': 'eligibility was revoked',
    'PROMOTION_REFUSED_NEW_FINDING': 'a new blocking finding exists against the digest since it was built',
    'PROMOTION_REFUSED_RECHECK_INCOMPLETE': 'the promotion-time re-check (SBOM re-scan, KEV) could '
                                            'not be completed; never a pass',
    'PROMOTION_REFUSED_STALE': 'verified more than %d days ago' % MAX_AGE_DAYS,
    'PROMOTION_REFUSED_SUPERSEDED': 'a newer build has since been verified in the same predecessor',
    'PROMOTION_REFUSED_NO_PREDECESSOR': 'uat and prod are promoted from the prior environment, '
                                        'never deployed from a build',
    'PROMOTION_REFUSED_PATH_UNKNOWN': 'release_path is not normal, hotfix, rollback or break-glass',
    'DAST_REFUSED_PRODUCTION_TARGET': 'active DAST against prod is refused: it runs against the '
                                      'predecessor (test or uat)',
    'TEST_PERIOD_REFUSED_OUT_OF_BOUNDS': 'e2e_test_period_minutes must be > 0 and <= %d'
                                         % MAX_PERIOD_MINUTES,
    'BREAK_GLASS_REFUSED_NO_EXCEPTION': 'break-glass needs an attributed exception: weakening_reason, '
                                        'weakening_authority, weakening_exception_ref, weakening_expires',
    'BREAK_GLASS_REFUSED_EXPIRED': 'the break-glass exception has expired',
    'BREAK_GLASS_REFUSED_TOO_LONG': 'a break-glass exception lives at most %d days'
                                    % BREAK_GLASS_MAX_DAYS,
}
# What break-glass may override at the gate, and what nothing overrides. A revoked signer, a
# substituted digest or a build from another branch is not an emergency the exception covers.
BREAK_GLASS_OVERRIDES = ('PROMOTION_REFUSED_NOT_VERIFIED', 'PROMOTION_REFUSED_WRONG_PREDECESSOR',
                         'PROMOTION_REFUSED_STALE', 'PROMOTION_REFUSED_SUPERSEDED',
                         'PROMOTION_REFUSED_NEW_FINDING', 'PROMOTION_REFUSED_RECHECK_INCOMPLETE')

env = dc.env
output = dc.output
summary = dc.summary


# ----------------------------------------------------------------------------- small helpers
def now_dt():
    """The clock, overridable for tests (KIT_PROMOTION_NOW, ISO-8601 Z)."""
    fixed = env('kit_promotion_now')
    if fixed:
        return parse_ts(fixed)
    return datetime.datetime.now(datetime.timezone.utc).replace(microsecond=0)


def iso(dt):
    return dt.strftime('%Y-%m-%dT%H:%M:%SZ') if dt else None


def parse_ts(text):
    try:
        t = str(text or '').strip().replace('Z', '+00:00')
        d = datetime.datetime.fromisoformat(t)
        return d if d.tzinfo else d.replace(tzinfo=datetime.timezone.utc)
    except ValueError:
        return None


def parse_day(text):
    try:
        return datetime.date.fromisoformat(str(text or '').strip())
    except ValueError:
        return None


def record_key(environment):
    """The artifact name a record is published under: one per environment, every run."""
    slug = re.sub(r'[^A-Za-z0-9._-]', '-', environment or 'env')[:40]
    return 'kit-promotion-record-%s' % slug


def default_branch():
    return env('default_branch') or 'main'


def is_default_ref(ref):
    return ref in ('refs/heads/%s' % default_branch(), default_branch())


def wdir(*parts):
    d = os.path.join(os.environ.get('RUNNER_TEMP') or '.', 'promotion', *parts)
    os.makedirs(d, exist_ok=True)
    return d


def jload(path):
    try:
        return json.load(io.open(path, encoding='utf-8'))
    except (OSError, ValueError):
        return None


def jsave(path, obj):
    io.open(path, 'w', encoding='utf-8').write(json.dumps(obj, indent=1, sort_keys=True))


def metadata():
    try:
        m = json.loads(env('version_metadata') or '{}')
        return m if isinstance(m, dict) else {}
    except ValueError:
        return {}


def exception_record():
    return {'reason': env('weakening_reason'), 'authority': env('weakening_authority'),
            'exception_ref': env('weakening_exception_ref'), 'expires': env('weakening_expires')}


def exception_state(exc, today, max_days=None):
    """-> None when the attributed exception is valid, else the BREAK_GLASS_REFUSED_* code."""
    if not all((exc.get(k) or '').strip() for k in ('reason', 'authority', 'exception_ref', 'expires')):
        return 'BREAK_GLASS_REFUSED_NO_EXCEPTION'
    exp = parse_day(exc['expires'])
    if exp is None:
        return 'BREAK_GLASS_REFUSED_NO_EXCEPTION'
    if exp < today:
        return 'BREAK_GLASS_REFUSED_EXPIRED'
    if max_days is not None and (exp - today).days > max_days:
        return 'BREAK_GLASS_REFUSED_TOO_LONG'
    return None


# ----------------------------------------------------------------------------- GitHub reads
class Missing(Exception):
    """The API answered that the thing does not exist (HTTP 404, or no recorded file)."""


def api_optional(path, params=None):
    """-> the JSON answer, raising Missing on a 404 and rh.Unreadable on any other failure."""
    base = env('GITHUB_API_URL', 'https://api.github.com').rstrip('/')  # unset means github.com
    if base.startswith('file:'):
        local = rh.urllib.request.url2pathname(rh.urllib.parse.urlparse(
            '%s/repos/%s/%s' % (base, env('github_repository'), path)).path)
        if not os.path.exists(local):
            raise Missing(path)
    try:
        return rh.api(path, params)
    except rh.Unreadable as exc:
        if 'HTTPError' in str(exc) and _status(path, params) == 404:
            raise Missing(path)
        raise


def _status(path, params):
    import urllib.error
    import urllib.parse
    base = env('GITHUB_API_URL', 'https://api.github.com').rstrip('/')  # unset means github.com
    url = '%s/repos/%s/%s' % (base, env('github_repository'), path)
    if params:
        url += '?' + urllib.parse.urlencode(params)
    try:
        rh._open(url)
        return 200
    except urllib.error.HTTPError as exc:
        return exc.code
    except Exception:  # noqa: BLE001
        return 0


def artifacts(name):
    """Every unexpired artifact of this name in the repository, newest first."""
    listing = rh.api('actions/artifacts', {'name': name, 'per_page': 100})
    found = [a for a in (listing or {}).get('artifacts') or []
             if isinstance(a, dict) and a.get('name') == name and not a.get('expired')]
    return sorted(found, key=lambda a: a.get('created_at') or '', reverse=True)


def download(artifact, suffix):
    """-> bytes of the first member ending `suffix` in the artifact's zip."""
    data = rh._open(artifact['archive_download_url'])
    with zipfile.ZipFile(io.BytesIO(data)) as zf:
        names = [n for n in zf.namelist() if n.endswith(suffix)]
        if not names:
            raise rh.Unreadable('%s holds no %s' % (artifact.get('name'), suffix))
        return zf.read(names[0])


def read_record(artifact):
    rec = json.loads(download(artifact, 'promotion-record.json').decode('utf-8'))
    if not isinstance(rec, dict) or rec.get('schema') != SCHEMA:
        raise rh.Unreadable('%s is not a %s record' % (artifact.get('name'), SCHEMA))
    rec['_artifact'] = {'id': artifact.get('id'), 'created_at': artifact.get('created_at'),
                        'run_id': str((artifact.get('workflow_run') or {}).get('id') or ''),
                        'head_branch': (artifact.get('workflow_run') or {}).get('head_branch')}
    return rec


def revocations():
    """-> the revocation register's entries ([] when the file does not exist on the default
    branch). Unreadable raises: a register nobody could read is not an empty one."""
    try:
        doc = api_optional('contents/' + REVOCATIONS_PATH, {'ref': default_branch()})
    except Missing:
        return []
    if isinstance(doc, dict) and 'content' in doc:
        doc = json.loads(base64.b64decode(doc['content']).decode('utf-8'))
    entries = doc.get('revocations') if isinstance(doc, dict) else doc
    if not isinstance(entries, list):
        raise rh.Unreadable('%s is not a list of revocations' % REVOCATIONS_PATH)
    return [e for e in entries if isinstance(e, dict)]


def approvals(run_id):
    """-> the environment approvals of a run, as the API reports them."""
    try:
        doc = rh.api('actions/runs/%s/approvals' % run_id)
    except rh.Unreadable as exc:
        return {'state': 'UNREADABLE', 'why': str(exc), 'approvers': []}
    out = []
    for a in doc if isinstance(doc, list) else []:
        out.append({'login': ((a.get('user') or {}).get('login') or ''), 'state': a.get('state'),
                    'environments': [e.get('name') for e in a.get('environments') or []],
                    'comment': (a.get('comment') or '')[:200]})
    state = 'APPROVED' if any(a['state'] == 'approved' for a in out) else (
        'REJECTED' if any(a['state'] == 'rejected' for a in out) else 'NONE_REQUIRED_OR_RECORDED')
    return {'state': state, 'approvers': out, 'recorded_at': iso(now_dt())}


# ----------------------------------------------------------------------------- the judgement
def revoked_reasons(rec, entries, rescan, kev):
    """-> [reason] that revoke this record's eligibility now."""
    out = []
    digest = (rec.get('artifact') or {}).get('digest')
    signer = (rec.get('provenance') or {}).get('build_workflow') or ''
    logins = set(a.get('login') for a in ((rec.get('approval') or {}).get('approvers') or []))
    run = str((rec.get('run') or {}).get('id') or '')
    envname = (rec.get('environment') or {}).get('name') or ''
    for e in entries:
        kind, match = e.get('kind'), str(e.get('match') or '')
        why = '%s (%s, %s)' % (e.get('reason') or 'no reason given', e.get('revoked_by') or '?',
                               e.get('revoked_at') or '?')
        if kind == 'digest' and match == digest:
            out.append('DIGEST_REVOKED: ' + why)
        elif kind == 'signer' and match and signer and (match == signer or signer.startswith(match + '@')):
            out.append('SIGNING_IDENTITY_REVOKED: ' + why)
        elif kind == 'approval' and match in logins:
            out.append('APPROVAL_REVOKED: %s: %s' % (match, why))
        elif kind == 'test-evidence' and match in (run, '%s/%s' % (run, envname)):
            out.append('TEST_EVIDENCE_INVALIDATED: ' + why)
    for f in (kev or {}).get('blocking') or []:
        out.append('NEW_KNOWN_EXPLOITED: %s' % f)
    for f in (rescan or {}).get('critical') or []:
        out.append('NEW_CRITICAL_FINDING: %s' % f)
    return out


def judge(ctx):
    """The promotion gate, as a pure function. ctx keys:
         digest, required_predecessor, source_environment, source (record or None), source_error,
         history ([records in the predecessor]), revocations, rescan {state, critical, high},
         kev {state, blocking}, attestation, release_path, exception, now
       -> {verdict: PROMOTION_ALLOWED | <code>, refusals: [{code, why}], overridden: [...]}"""
    refusals = []

    def refuse(code, why):
        refusals.append({'code': code, 'why': why})

    rec = ctx.get('source')
    if rec is None:
        refuse('PROMOTION_REFUSED_SOURCE_UNREADABLE', ctx.get('source_error') or 'no record')
        return finish_judgement(refusals, ctx)
    art, envd = rec.get('artifact') or {}, rec.get('environment') or {}
    if art.get('digest') != ctx['digest']:
        refuse('PROMOTION_REFUSED_DIGEST_MISMATCH', 'deploying %s; the record verified %s'
               % (ctx['digest'], art.get('digest')))
    if (ctx['source_environment'] != ctx['required_predecessor'] or
            envd.get('name') != ctx['required_predecessor'] or envd.get('tier') not in PREDECESSOR_TIERS):
        refuse('PROMOTION_REFUSED_WRONG_PREDECESSOR', 'required %s (a %s tier); the source is %s '
               '(record environment %s, tier %s)' % (
                   ctx['required_predecessor'], ' or '.join(PREDECESSOR_TIERS),
                   ctx['source_environment'], envd.get('name'), envd.get('tier')))
    if rec.get('state') != VERIFIED:
        refuse('PROMOTION_REFUSED_NOT_VERIFIED', 'the record reads %s; missing: %s' % (
            rec.get('state'), ', '.join((rec.get('conditions') or {}).get('missing') or []) or '?'))
    prov = rec.get('provenance') or {}
    branch = (rec.get('_artifact') or {}).get('head_branch')
    if not is_default_ref(prov.get('source_ref') or '') or (branch and branch != default_branch()):
        refuse('PROMOTION_REFUSED_NOT_FROM_MAIN', 'built from %s (run on %s); the default branch is %s'
               % (prov.get('source_ref') or 'unknown', branch or 'unknown', default_branch()))
    if ctx.get('attestation') != 'ATTESTATION_VERIFIED':
        refuse('PROMOTION_REFUSED_SIGNATURE', 'V1 in this deploy read %s'
               % (ctx.get('attestation') or 'nothing'))
    rescan, kev = ctx.get('rescan') or {}, ctx.get('kev') or {}
    revoked = revoked_reasons(rec, ctx.get('revocations') or [], rescan, kev)
    if revoked:
        refuse('PROMOTION_REFUSED_REVOKED', '; '.join(revoked))
    if rescan.get('high'):
        refuse('PROMOTION_REFUSED_NEW_FINDING', 'found now, absent at build (the build gate passed '
               'HIGH,CRITICAL clean): %s' % ', '.join(rescan['high'][:10]))
    if rescan.get('state') != 'COMPLETE' or kev.get('state') != 'AVAILABLE':
        refuse('PROMOTION_REFUSED_RECHECK_INCOMPLETE', 'SBOM re-scan %s (%s); KEV %s' % (
            rescan.get('state') or 'not run', rescan.get('why') or '', kev.get('state') or 'not run'))
    verified_at = parse_ts((rec.get('validity') or {}).get('verified_at'))
    age = (ctx['now'] - verified_at) if verified_at else None
    if age is None or age > datetime.timedelta(days=MAX_AGE_DAYS):
        why = ('verified %s (%s days ago); the maximum is %d' % (
            iso(verified_at), age.days, MAX_AGE_DAYS)) if age else 'no verification time recorded'
        if (verified_at and ctx.get('release_path') in ('hotfix', 'rollback') and
                exception_state(ctx.get('exception') or {}, ctx['now'].date()) is None):
            ctx.setdefault('overridden', []).append({
                'code': 'PROMOTION_REFUSED_STALE', 'why': why,
                'by': 'a named %s decision (attributed exception %s)' % (
                    ctx['release_path'], (ctx.get('exception') or {}).get('exception_ref'))})
        else:
            refuse('PROMOTION_REFUSED_STALE', why)
    newer = [h for h in ctx.get('history') or []
             if h.get('state') == VERIFIED and (h.get('artifact') or {}).get('digest') != art.get('digest')
             and verified_at and (parse_ts((h.get('validity') or {}).get('verified_at')) or verified_at) > verified_at]
    if newer:
        n = sorted(newer, key=lambda h: (h.get('validity') or {}).get('verified_at') or '')[-1]
        ctx['superseded_by'] = {'digest': (n.get('artifact') or {}).get('digest'),
                                'run_id': (n.get('run') or {}).get('id'),
                                'verified_at': (n.get('validity') or {}).get('verified_at')}
        refuse('PROMOTION_REFUSED_SUPERSEDED', '%s was verified in %s at %s, after this one' % (
            ctx['superseded_by']['digest'], ctx['required_predecessor'],
            ctx['superseded_by']['verified_at']))
    return finish_judgement(refusals, ctx)


def finish_judgement(refusals, ctx):
    overridden = list(ctx.get('overridden') or [])
    if ctx.get('release_path') == 'break-glass':
        kept = []
        for r in refusals:
            if r['code'] in BREAK_GLASS_OVERRIDES:
                overridden.append(dict(r, by='break-glass exception %s'
                                       % (ctx.get('exception') or {}).get('exception_ref')))
            else:
                kept.append(r)
        refusals = kept
    return {'verdict': refusals[0]['code'] if refusals else 'PROMOTION_ALLOWED',
            'refusals': refusals, 'overridden': overridden,
            'superseded_by': ctx.get('superseded_by')}


def preflight_codes(tier, promoting, path, has_dast, period, has_e2e, exc, today):
    """-> [(code, why)] refusals before login, for every deploy."""
    out = []
    if path not in RELEASE_PATHS:
        out.append(('PROMOTION_REFUSED_PATH_UNKNOWN', 'release_path %r' % path))
    if has_dast and tier == 'prod':
        out.append(('DAST_REFUSED_PRODUCTION_TARGET', 'a dast_command is configured at tier prod'))
    if tier in ('uat', 'prod') and not promoting and path != 'break-glass':
        out.append(('PROMOTION_REFUSED_NO_PREDECESSOR', 'a %s deploy names no promote_from_run_id'
                    % tier))
    if path == 'break-glass':
        code = exception_state(exc, today, BREAK_GLASS_MAX_DAYS)
        if code:
            out.append((code, 'expires %r' % exc.get('expires')))
    if has_e2e:
        try:
            p = float(period)
        except (TypeError, ValueError):
            p = -1
        if not 0 < p <= MAX_PERIOD_MINUTES:
            out.append(('TEST_PERIOD_REFUSED_OUT_OF_BOUNDS', 'e2e_test_period_minutes %r' % period))
    return out


# ----------------------------------------------------------------------------- preflight
def cmd_preflight(a):
    tier = env('environment_tier')
    codes = preflight_codes(tier, bool(env('promote_from_run_id')), env('release_path') or 'normal',
                            bool(env('dast_command').strip()), env('e2e_test_period_minutes') or DEFAULT_PERIOD_MINUTES,
                            bool(env('e2e_test_command').strip()), exception_record(), now_dt().date())
    if env('promote_from_run_id') and env('promotion_predecessor') == env('deploy_environment'):
        codes.append(('PROMOTION_REFUSED_WRONG_PREDECESSOR', 'an environment cannot be its own predecessor'))
    doc = {'preflight': codes[0][0] if codes else 'PREFLIGHT_PASSED',
           'refusals': [{'code': c, 'why': w} for c, w in codes],
           'release_path': env('release_path') or 'normal', 'tier': tier}
    dc.write_evidence('promotion-preflight.json', doc)
    output(promotion_preflight=doc['preflight'])
    if codes:
        for c, w in codes:
            print('::error title=%s::%s -- %s. Nothing was deployed.' % (c, REFUSALS.get(c, c), w))
        summary('### Deploy refused before login (KDEC-029)\n\n' + '\n'.join(
            '- `%s`: %s (%s)' % (c, REFUSALS.get(c, c), w) for c, w in codes))
        return 1
    print('Promotion preflight passed: release path %s, tier %s.' % (doc['release_path'], tier))
    return 0


# ----------------------------------------------------------------------------- gate
def sbom_rescan(sbom_path, out_dir):
    """-> {state, critical, high, sarif, why}. The pinned Trivy re-scans the build's SBOM at the
    build gate's thresholds (HIGH,CRITICAL, unfixed ignored): the build passed clean, so anything
    found now is new since the build. Never a rebuild, never a registry pull."""
    exe = shutil.which('trivy')
    if not exe:
        return {'state': 'NOT_ESTABLISHED', 'why': 'trivy is not installed', 'critical': [], 'high': []}
    rj, rs = os.path.join(out_dir, 'rescan.json'), os.path.join(out_dir, 'rescan.sarif')
    p = subprocess.run([exe, 'sbom', '--quiet', '--scanners', 'vuln', '--severity', 'HIGH,CRITICAL',
                        '--ignore-unfixed', '--format', 'json', '--output', rj, sbom_path],
                       capture_output=True, text=True, encoding='utf-8', errors='replace')
    doc = jload(rj)
    if p.returncode != 0 or not isinstance(doc, dict):
        return {'state': 'NOT_ESTABLISHED', 'why': 'trivy sbom exit %d' % p.returncode,
                'critical': [], 'high': []}
    subprocess.run([exe, 'convert', '--format', 'sarif', '--output', rs, rj],
                   capture_output=True, text=True, encoding='utf-8', errors='replace')
    crit, high = [], []
    for res in doc.get('Results') or []:
        for v in res.get('Vulnerabilities') or []:
            tok = '%s@%s:%s' % (v.get('VulnerabilityID'), v.get('PkgName'), v.get('InstalledVersion'))
            (crit if v.get('Severity') == 'CRITICAL' else high).append(tok)
    return {'state': 'COMPLETE', 'why': '', 'critical': sorted(set(crit)), 'high': sorted(set(high)),
            'sarif': rs if os.path.exists(rs) else ''}


def fetch_sbom(digest, want_sha, out_dir):
    """-> (path, why). The build's SBOM artifact `sbom-<hex>`, its sha256 checked against the
    record (the identity chain: the SBOM is the one the build hashed)."""
    hexd = (digest or '').split(':', 1)[-1]
    try:
        found = artifacts('sbom-%s' % hexd)
    except rh.Unreadable as exc:
        return None, 'the SBOM listing could not be read: %s' % exc
    if not found:
        return None, 'no SBOM artifact sbom-%s (expired, or never uploaded)' % hexd[:12]
    try:
        data = download(found[0], '.json')
    except Exception as exc:  # noqa: BLE001
        return None, 'the SBOM could not be downloaded: %s' % type(exc).__name__
    got = hashlib.sha256(data).hexdigest()
    if want_sha and got != want_sha:
        return None, 'the SBOM sha256 %s is not the recorded %s' % (got[:12], want_sha[:12])
    path = os.path.join(out_dir, 'sbom.spdx.json')
    io.open(path, 'wb').write(data)
    return path, ''


def cmd_gate_collect(a):
    """Before login: the source record, the predecessor's history, the revocations, and the
    re-scan of the build's SBOM. Writes promotion/collected.json; the decision is gate-decide."""
    out = wdir()
    run_id, src_env = env('promote_from_run_id'), env('promote_from_environment')
    col = {'run_id': run_id, 'source_environment': src_env,
           'required_predecessor': env('promotion_predecessor') or 'test',
           'source': None, 'source_error': '', 'history': [], 'revocations': [],
           'rescan': {'state': 'NOT_ESTABLISHED', 'why': 'not reached', 'critical': [], 'high': []}}
    try:
        mine = [x for x in artifacts(record_key(src_env))
                if str((x.get('workflow_run') or {}).get('id') or '') == run_id]
        if not mine:
            raise rh.Unreadable('run %s published no %s' % (run_id, record_key(src_env)))
        col['source'] = read_record(mine[0])
    except Exception as exc:  # noqa: BLE001 -- any failure is "could not read", never a pass
        col['source_error'] = str(exc)[:300]
    try:
        hist = artifacts(record_key(col['required_predecessor']))[:30]
        col['history'] = [read_record(x) for x in hist]
    except Exception as exc:  # noqa: BLE001
        col['history_error'] = str(exc)[:300]
        col['rescan']['why'] = 'the predecessor history could not be read'
    try:
        col['revocations'] = revocations()
    except Exception as exc:  # noqa: BLE001
        col['revocations_error'] = str(exc)[:300]
    if col['source']:
        sbom, why = fetch_sbom(env('image_digest'),
                               (col['source'].get('artifact') or {}).get('sbom_sha256'), out)
        col['rescan'] = sbom_rescan(sbom, out) if sbom else {
            'state': 'NOT_ESTABLISHED', 'why': why, 'critical': [], 'high': []}
        if col.get('history_error') or col.get('revocations_error'):
            col['rescan']['state'] = 'NOT_ESTABLISHED'
            col['rescan']['why'] = (col.get('history_error') or col.get('revocations_error'))
    jsave(os.path.join(out, 'collected.json'), col)
    output(rescan_sarif=col['rescan'].get('sarif') or '', rescan_state=col['rescan']['state'])
    print('Promotion source: %s; rescan %s.' % (
        'read' if col['source'] else 'UNREADABLE (%s)' % col['source_error'], col['rescan']['state']))
    return 0


def cmd_gate_decide(a):
    col = jload(os.path.join(wdir(), 'collected.json')) or {}
    kev = {'state': env('kev_state') or 'UNAVAILABLE',
           'blocking': [t for t in (env('kev_blocking') or '').split() if t]}
    ctx = {'digest': env('image_digest'), 'required_predecessor': col.get('required_predecessor') or
           env('promotion_predecessor') or 'test',
           'source_environment': col.get('source_environment') or env('promote_from_environment'),
           'source': col.get('source'), 'source_error': col.get('source_error') or 'not collected',
           'history': col.get('history') or [], 'revocations': col.get('revocations') or [],
           'rescan': col.get('rescan') or {}, 'kev': kev, 'attestation': env('attestation_outcome'),
           'release_path': env('release_path') or 'normal', 'exception': exception_record(),
           'now': now_dt()}
    if col.get('revocations_error'):
        ctx['rescan'] = dict(ctx['rescan'], state='NOT_ESTABLISHED',
                             why='the revocation register could not be read')
    res = judge(ctx)
    src = col.get('source') or {}
    gate = {'promotion_gate': res['verdict'], 'refusals': res['refusals'],
            'overridden': res['overridden'], 'superseded_by': res['superseded_by'],
            'source': {'run_id': col.get('run_id'), 'environment': col.get('source_environment'),
                       'record_id': src.get('record_id'),
                       'verified_at': (src.get('validity') or {}).get('verified_at')},
            'required_predecessor': ctx['required_predecessor'],
            'carried': {k: src.get(k) for k in ('artifact', 'provenance')},
            'rescan': {k: v for k, v in (col.get('rescan') or {}).items() if k != 'sarif'},
            'kev': kev, 'attestation': ctx['attestation'], 'decided_at': iso(ctx['now'])}
    dc.write_evidence('promotion-gate.json', gate)
    output(promotion_gate=res['verdict'])
    lines = ['### Promotion gate (KDEC-029): `%s`' % res['verdict'], '',
             'Promote `%s` from run `%s` in `%s`; required predecessor `%s`.' % (
                 ctx['digest'], col.get('run_id'), ctx['source_environment'], ctx['required_predecessor'])]
    for r in res['refusals']:
        lines.append('- REFUSED `%s`: %s -- %s' % (r['code'], REFUSALS.get(r['code'], ''), r['why']))
    for r in res['overridden']:
        lines.append('- OVERRIDDEN `%s` by %s: %s' % (r['code'], r['by'], r['why']))
    summary('\n'.join(lines))
    print('\n'.join(lines))
    if res['refusals']:
        for r in res['refusals']:
            print('::error title=%s::%s -- %s. Nothing was deployed.' % (
                r['code'], REFUSALS.get(r['code'], r['code']), r['why'][:400]))
        return 1
    return 0


# ----------------------------------------------------------------------------- tested
def end_to_end(cmd, timeout, extra):
    """-> ('passed'|'failed'|'timed-out', exit code). Without the deploy identity's Azure session."""
    cfg = tempfile.mkdtemp(prefix='e2e-azure-config-')
    e = dict(os.environ)
    for k in ('GITHUB_OUTPUT', 'GITHUB_STEP_SUMMARY'):
        e.pop(k, None)
    e.update(extra)
    e['AZURE_CONFIG_DIR'] = cfg
    try:
        p = subprocess.run(cmd, shell=True, env=e, timeout=timeout)  # noqa: S602 (the caller's own tests)
        return ('passed' if p.returncode == 0 else 'failed'), p.returncode
    except subprocess.TimeoutExpired:
        return 'timed-out', None
    finally:
        shutil.rmtree(cfg, ignore_errors=True)


def period_plan(period, interval):
    plan = [('start', 0.0)]
    if interval and interval > 0:
        k = 1
        while interval * k < period - 1e-9:
            plan.append(('interval', interval * k))
            k += 1
    plan.append(('end', float(period)))
    return plan


def cmd_test_period(a):
    tier, cmd = env('environment_tier'), env('e2e_test_command').strip()
    rec = {'result': None, 'checks': [], 'period_minutes': None, 'release_path': env('release_path') or 'normal'}
    if tier == 'prod':
        rec['result'] = 'NOT_APPLICABLE_PASSIVE'
        rec['why'] = 'prod gets passive checks only (health, posture); the e2e period ran in the predecessor'
    elif not cmd:
        rec['result'] = 'NOT_CONFIGURED'
        rec['why'] = 'no e2e_test_command: the end-to-end test period cannot pass, so this deploy cannot be verified for promotion'
    else:
        period = float(env('e2e_test_period_minutes') or DEFAULT_PERIOD_MINUTES) * 60
        interval = float(env('e2e_check_interval_minutes') or 0) * 60
        timeout = max(1, int(float(env('e2e_timeout_minutes') or 10) * 60))
        url = env('app_url').rstrip('/')
        rec.update(period_minutes=period / 60, interval_minutes=interval / 60, url=url or None,
                   command_sha256=hashlib.sha256(cmd.encode('utf-8')).hexdigest(),
                   started_at=iso(now_dt()))
        t0 = time.time()
        result = 'PASSED'
        for phase, offset in period_plan(period, interval):
            wait = t0 + offset - time.time()
            if wait > 0:
                time.sleep(wait)
            c = {'phase': phase, 'offset_seconds': round(time.time() - t0, 3)}
            good = bool(url) and dc.probe(url + (env('health_path') or '/health'))
            c['health'] = 'passed' if good else 'failed'
            if good:
                c['e2e'], c['exit_code'] = end_to_end(cmd, timeout, {
                    'PROMOTION_APP_URL': url, 'PROMOTION_CHECK_PHASE': phase,
                    'PROMOTION_ENVIRONMENT': env('deploy_environment')})
            rec['checks'].append(c)
            if not good or c.get('e2e') != 'passed':
                result = 'FAILED'
                break
        rec['result'] = result
        rec['ended_at'] = iso(now_dt())
        if rec['period_minutes'] < DEFAULT_PERIOD_MINUTES:
            rec['compressed'] = ('hotfix: a compressed period, recorded' if rec['release_path'] == 'hotfix'
                                 else 'under the %d-minute default: a recorded weakening' % DEFAULT_PERIOD_MINUTES)
    dc.write_evidence('test-period.json', rec)
    output(test_period=rec['result'])
    summary('End-to-end test period (KDEC-021/029): `%s`%s' % (
        rec['result'], ' -- ' + rec['why'] if rec.get('why') else ''))
    print('test period: %s' % rec['result'])
    return 1 if rec['result'] == 'FAILED' else 0


def sarif_blocking(path):
    """-> list of blocking results, or None when the report cannot be read. Blocking = level
    `error` and not suppressed (an accepted suppression is the DAST tool's own baseline: what is
    accepted is not new)."""
    doc = jload(path)
    if not isinstance(doc, dict) or not isinstance(doc.get('runs'), list):
        return None
    out = []
    for run in doc['runs']:
        if not isinstance(run.get('results'), list):
            return None
        for r in run['results']:
            sup = [x for x in r.get('suppressions') or [] if x.get('status', 'accepted') == 'accepted']
            if r.get('level', 'warning') == 'error' and not sup:
                out.append('%s %s' % (r.get('ruleId') or '?', ((r.get('message') or {}).get('text') or '')[:80]))
    return out


def cmd_dast(a):
    tier, cmd = env('environment_tier'), env('dast_command').strip()
    rec = {'configured': bool(cmd), 'result': None, 'blocking': []}
    if tier == 'prod':
        rec['result'] = 'NOT_APPLICABLE_PASSIVE'
        rec['why'] = 'never active DAST against prod; it runs against the predecessor'
    elif not cmd:
        rec['result'] = 'NOT_CONFIGURED'
    else:
        url = env('app_url').rstrip('/')
        report = os.path.join(wdir('dast'), 'dast.sarif')
        if os.path.exists(report):
            os.remove(report)
        res, code = end_to_end(cmd, DAST_TIMEOUT_SECONDS, {
            'PROMOTION_APP_URL': url, 'PROMOTION_DAST_SARIF': report,
            'PROMOTION_ENVIRONMENT': env('deploy_environment')})
        rec.update(exit_code=code, url=url or None,
                   command_sha256=hashlib.sha256(cmd.encode('utf-8')).hexdigest())
        blocking = sarif_blocking(report)
        if blocking is None:
            rec['result'] = 'DAST_INCOMPLETE'
            rec['why'] = 'the command %s and left no readable SARIF at PROMOTION_DAST_SARIF' % res
        else:
            rec['blocking'] = blocking
            rec['result'] = 'DAST_BLOCKING_FINDINGS' if blocking else 'DAST_PASSED'
    dc.write_evidence('dast.json', rec)
    output(dast=rec['result'])
    summary('DAST (KDEC-029): `%s`%s' % (rec['result'], (
        ' -- ' + ', '.join(rec['blocking'][:10])) if rec['blocking'] else ''))
    print('dast: %s' % rec['result'])
    return 1 if rec['result'] in ('DAST_BLOCKING_FINDINGS', 'DAST_INCOMPLETE') else 0


def security_settings(adapter):
    """-> (result, [failed checks], [checks read]). Passive: reads only."""
    failed, read = [], []
    if adapter == 'containerapp':
        ok, shown, err = dc.az('containerapp', 'show', '-n', env('containerapp_name'),
                               '-g', env('resource_group'))
        if not ok or not isinstance(shown, dict):
            return 'POSTURE_UNREADABLE', [err or 'no answer'], read
        ing = ((shown.get('properties') or {}).get('configuration') or {}).get('ingress') or {}
        read.append('ingress.allowInsecure=%s' % ing.get('allowInsecure', False))
        if ing.get('allowInsecure') is True:
            failed.append('ingress allows plain HTTP (allowInsecure true)')
        return ('POSTURE_FAILED' if failed else 'POSTURE_PASSED'), failed, read
    ok, site, err = dc.az('webapp', 'show', '-n', env('webapp_name'), '-g', env('resource_group'))
    ok2, cfg, err2 = dc.az('webapp', 'config', 'show', '-n', env('webapp_name'), '-g', env('resource_group'))
    if not ok or not ok2 or not isinstance(site, dict) or not isinstance(cfg, dict):
        return 'POSTURE_UNREADABLE', [err or err2 or 'no answer'], read
    checks = [('httpsOnly', site.get('httpsOnly'), lambda v: v is True, 'HTTPS is not enforced'),
              ('minTlsVersion', cfg.get('minTlsVersion'),
               lambda v: str(v or '') in ('1.2', '1.3'), 'minimum TLS below 1.2'),
              ('ftpsState', cfg.get('ftpsState'), lambda v: v in ('Disabled', 'FtpsOnly'),
               'plain FTP is allowed'),
              ('remoteDebuggingEnabled', cfg.get('remoteDebuggingEnabled'), lambda v: v is not True,
               'remote debugging is on')]
    for name, val, good, why in checks:
        read.append('%s=%s' % (name, val))
        if not good(val):
            failed.append(why)
    return ('POSTURE_FAILED' if failed else 'POSTURE_PASSED'), failed, read


def cmd_posture(a):
    result, failed, read = security_settings(a.adapter)
    rec = {'result': result, 'failed': failed, 'read': read, 'at': iso(now_dt())}
    dc.write_evidence('security-settings.json', rec)
    output(security_settings=result)
    summary('Security-settings posture (live, passive): `%s`%s' % (
        result, ' -- ' + '; '.join(failed) if failed else ''))
    print('security settings: %s %s' % (result, '; '.join(failed)))
    return 0 if result == 'POSTURE_PASSED' else 1


# ----------------------------------------------------------------------------- the record
def cmd_record(a):
    """Always: what this deploy establishes about this digest in this environment."""
    outcome = dc.read_evidence('outcome.json') or {}
    prom = outcome.get('promotion') or {}
    gate = dc.read_evidence('promotion-gate.json') or {}
    pre = dc.read_evidence('promotion-preflight.json') or {}
    prov_ev = dc.read_evidence('provenance.json') or {}
    snap = dc.read_evidence('snapshot.json') or {}
    meta = metadata()
    carried = gate.get('carried') or {}
    path = env('release_path') or 'normal'
    tier = env('environment_tier')
    now = now_dt()
    promoted = bool(env('promote_from_run_id'))
    state = prom.get('state') or NOT_VERIFIED
    if path == 'break-glass' and outcome.get('deployment_outcome') == 'DEPLOY_HEALTHY':
        state = BREAK_GLASS
    if outcome.get('deployment_outcome') != 'DEPLOY_HEALTHY':
        state = NOT_VERIFIED
    rid = prov_ev.get('resource_id') or snap.get('resource_id') or None
    if rid is None and snap:
        rid, _ = dc.resource_id(a.adapter)
    artifact = dict(carried.get('artifact') or {}) if promoted else {}
    artifact.update({'digest': env('image_digest'),
                     'image': dc.intended_ref(),
                     'sbom_sha256': artifact.get('sbom_sha256') or meta.get('sbom_sha256') or None,
                     'artifact_identity': artifact.get('artifact_identity') or
                     env('artifact_identity') or meta.get('artifact_identity') or None,
                     # The build's stamp, carried so a promotion stamps the same provenance.
                     'version_metadata': artifact.get('version_metadata') or env('version_metadata') or None})
    if promoted and carried.get('provenance'):
        provenance = dict(carried['provenance'])
    else:
        provenance = {'source_sha': meta.get('git_sha') or env('github_sha') or None,
                      'source_ref': meta.get('git_ref') or env('github_ref') or None,
                      'build_run_id': meta.get('run_id') or env('github_run_id') or None,
                      'build_workflow': env('attestation_signer_workflow') or None,
                      'scanner_evidence': [x for x in (
                          'sbom-%s' % env('image_digest').split(':', 1)[-1] if env('image_digest') else '',
                          'build-evidence-%s' % (meta.get('run_id') or env('github_run_id'))) if x],
                      'gate_routing_result': env('routing_result') or None,
                      'controls_unavailable': [c for c in env('controls_unavailable').split(',') if c.strip()],
                      'advisory_causes': [c for c in env('advisory_causes').split(',') if c.strip()]}
    provenance['attestation_outcome'] = env('attestation_outcome') or None
    run = {'id': env('github_run_id') or None, 'attempt': env('github_run_attempt') or None,
           'url': '%s/%s/actions/runs/%s' % (env('github_server_url', 'https://github.com'),
                                              env('github_repository'), env('github_run_id'))}
    tests = {'health': outcome.get('health'),
             'e2e_test_period': dc.read_evidence('test-period.json'),
             'dast': dc.read_evidence('dast.json'),
             'security_settings': dc.read_evidence('security-settings.json')}
    rec = {
        'schema': SCHEMA,
        'record_id': '%s-%s-%s' % (run['id'], run['attempt'], env('deploy_environment')),
        'state': state,
        'release_path': path,
        'artifact': artifact,
        'provenance': provenance,
        'environment': {'name': env('deploy_environment'), 'tier': tier, 'adapter': a.adapter,
                        'target_resource_id': rid,
                        'oidc_subject': 'repo:%s:environment:%s' % (env('github_repository'),
                                                                    env('deploy_environment'))},
        'predecessor': {'required': (env('promotion_predecessor') or 'test') if tier in ('uat', 'prod') else None,
                        'promoted_from': gate.get('source') if promoted else None,
                        'gate': gate.get('promotion_gate') if promoted else None,
                        'overridden': gate.get('overridden') or []},
        'tests': tests,
        'conditions': {'established': prom.get('established') or [],
                       'missing': prom.get('missing') or []},
        'approval': approvals(env('github_run_id')) if env('github_run_id') else
        {'state': 'UNREADABLE', 'why': 'no run id', 'approvers': []},
        'validity': {'verified_at': iso(now) if state == VERIFIED else None,
                     'expires_at': iso(now + datetime.timedelta(days=MAX_AGE_DAYS)) if state == VERIFIED else None,
                     'superseded_by': None, 'revoked': None,
                     'note': 'eligibility is re-judged at every promotion: superseded, revoked and '
                             'stale are computed then, never trusted from this file'},
        'live_state': {'deployment_outcome': outcome.get('deployment_outcome'),
                       'now_serving': outcome.get('now_serving') or [],
                       'verified_serving': 'expected artefact observed running' in (prom.get('established') or [])},
        'run': run,
        'preflight': pre.get('preflight'),
        'break_glass': None,
    }
    if path == 'break-glass':
        rec['break_glass'] = {'exception': exception_record(),
                              'testing_owed': sorted(set((prom.get('missing') or []) +
                                                         ['verified-for-promotion in %s' % (
                                                             env('promotion_predecessor') or 'test')])),
                              'flagged_until': 'a verified-for-promotion record for this digest in the '
                                               'predecessor; the daily deployed scan raises a ticket until then'}
    out = wdir('record')
    jsave(os.path.join(out, 'promotion-record.json'), rec)
    dc.write_evidence('promotion-record.json', rec)
    output(promotion_state=state, promotion_record_name=record_key(env('deploy_environment')))
    summary('Promotion record (`%s`): **`%s`**%s' % (
        record_key(env('deploy_environment')), state,
        '; not yet established: ' + ', '.join(rec['conditions']['missing']) if rec['conditions']['missing'] else ''))
    print('promotion record: %s' % state)
    return 0


# ----------------------------------------------------------------------------- daily scan
def serving_now(adapter):
    """-> list of {where, weight, image, digest} actually serving, or None when unreadable.
    Container Apps: every revision receiving traffic, with its weight. App Service: the production
    slot's configured image and every named slot's."""
    if adapter == 'containerapp':
        live = dc.containerapp_serving()
        if live is None:
            return None
        return [{'where': 'revision %s' % t['revision'], 'weight': t['weight'], 'image': t['image'],
                 'digest': t['image'].split('@', 1)[1] if '@' in t['image'] else None} for t in live]
    out = []
    for slot in ['production'] + [s for s in (env('slots') or '').split(',') if s.strip()]:
        img = dc.appservice_slot_image(slot.strip())
        if img is None:
            return None
        out.append({'where': 'slot %s' % slot.strip(), 'weight': 100 if slot == 'production' else 0,
                    'image': img, 'digest': img.split('@', 1)[1] if '@' in img else None})
    return out


def finding(rule, text, where, level='error', props=None):
    return {'ruleId': rule, 'level': level, 'message': {'text': text},
            'locations': [{'physicalLocation': {'artifactLocation': {'uri': where},
                                                'region': {'startLine': 1}}}],
            'properties': dict(props or {})}


def sarif(results, tool, rules):
    return {'version': '2.1.0', '$schema': 'https://json.schemastore.org/sarif-2.1.0.json',
            'runs': [{'tool': {'driver': {'name': tool, 'version': '1',
                                          'rules': [{'id': r, 'shortDescription': {'text': d}}
                                                    for r, d in rules.items()]}},
                      'invocations': [{'executionSuccessful': True}], 'results': results}]}


DRIFT_RULES = {'KIT-ARTIFACT-DRIFT': 'the serving digest is not the last promoted digest',
               'KIT-SERVING-UNREADABLE': 'what is serving could not be read',
               'KIT-SECURITY-SETTINGS': 'the security-settings posture check failed',
               'KIT-BREAK-GLASS-TESTING-OWED': 'a break-glass deploy is still owed its testing',
               'KIT-RESCAN-NOT-ESTABLISHED': 'the serving digest could not be re-scanned'}


def cmd_deployed_scan(a):
    """Phase 1 of the daily scan for ONE environment (the job's own): reconcile, then the two
    drifts. Writes promotion/deployed/: deployed-state.json, state SARIFs, and the re-scan SARIF the
    KEV composite reads. Never mutates, never rolls back, never rebuilds."""
    out = wdir('deployed')
    envname, adapter = env('deploy_environment'), a.adapter
    doc = {'environment': envname, 'adapter': adapter, 'at': iso(now_dt()), 'serving': None,
           'promoted': None, 'artifact_drift': None, 'security_drift': None, 'rescans': [],
           'posture': None, 'break_glass_owed': None}
    results = []
    where = 'deployed/%s/%s' % (envname, env('containerapp_name') or env('webapp_name'))
    serving = serving_now(adapter)
    doc['serving'] = serving
    try:
        recs = [read_record(x) for x in artifacts(record_key(envname))[:30]]
    except Exception as exc:  # noqa: BLE001
        recs, doc['records_error'] = [], str(exc)[:300]
    healthy = [r for r in recs if (r.get('live_state') or {}).get('deployment_outcome') == 'DEPLOY_HEALTHY']
    last = healthy[0] if healthy else None
    doc['promoted'] = {'digest': (last.get('artifact') or {}).get('digest'), 'run_id': (last.get('run') or {}).get('id'),
                       'state': last.get('state')} if last else None
    if serving is None:
        results.append(finding('KIT-SERVING-UNREADABLE', 'What %s serves could not be read; nothing '
                               'about it is established.' % envname, where))
    else:
        want = (doc['promoted'] or {}).get('digest')
        drift = [s for s in serving if s['weight'] > 0 and s['digest'] != want]
        doc['artifact_drift'] = bool(drift) if want else None
        for s in drift:
            results.append(finding('KIT-ARTIFACT-DRIFT', '%s serves %s at %d%%; the last promoted '
                                   'digest is %s.' % (s['where'], s['digest'] or s['image'], s['weight'],
                                                      want or 'none on record'),
                                   '%s/%s' % (where, s['where'].replace(' ', '-'))))
    # Security drift: re-scan EVERY digest truly serving -- never a nominal tag -- from its build SBOM.
    vuln_results = []
    for s in [x for x in (serving or []) if x['digest']]:
        rec = next((r for r in recs if (r.get('artifact') or {}).get('digest') == s['digest']), None)
        sbom, why = fetch_sbom(s['digest'], ((rec or {}).get('artifact') or {}).get('sbom_sha256'),
                               wdir('deployed', s['digest'].split(':', 1)[-1][:16]))
        r = sbom_rescan(sbom, os.path.dirname(sbom)) if sbom else {'state': 'NOT_ESTABLISHED', 'why': why,
                                                                   'critical': [], 'high': []}
        r['digest'] = s['digest']
        doc['rescans'].append({k: v for k, v in r.items()})
        if r['state'] != 'COMPLETE':
            results.append(finding('KIT-RESCAN-NOT-ESTABLISHED', 'The serving digest %s could not be '
                                   're-scanned: %s.' % (s['digest'], r.get('why')),
                                   '%s/%s' % (where, s['digest'].split(':', 1)[-1][:16])))
        elif r.get('sarif'):
            vuln_results.append(r['sarif'])
    doc['security_drift'] = any(r.get('critical') or r.get('high') for r in doc['rescans']) if doc['rescans'] else None
    result, failed, read = security_settings(adapter)
    doc['posture'] = {'result': result, 'failed': failed, 'read': read}
    if result != 'POSTURE_PASSED':
        results.append(finding('KIT-SECURITY-SETTINGS', 'Security settings of %s: %s (%s).' % (
            envname, result, '; '.join(failed)), where))
    if last and last.get('state') == BREAK_GLASS:
        dig = (last.get('artifact') or {}).get('digest')
        pred = (last.get('predecessor') or {}).get('required') or 'test'
        try:
            done = any(r.get('state') == VERIFIED and (r.get('artifact') or {}).get('digest') == dig
                       for r in [read_record(x) for x in artifacts(record_key(pred))[:30]])
        except Exception:  # noqa: BLE001
            done = False
        doc['break_glass_owed'] = not done
        if not done:
            results.append(finding('KIT-BREAK-GLASS-TESTING-OWED', 'Break-glass deploy of %s (exception '
                                   '%s) is still owed: %s.' % (dig, ((last.get('break_glass') or {}).get('exception') or {}).get('exception_ref'),
                                                               ', '.join((last.get('break_glass') or {}).get('testing_owed') or [])),
                                   '%s/break-glass' % where))
    # The state rows the core report reads (scripts/scan_report.py --batch): one for the state
    # findings, one per re-scan SARIF, named by environment so every environment's rows can be
    # merged into one report. Coverage rows are what let a ticket close on clearance.
    slug = record_key(envname)[len('kit-promotion-record-'):]
    jsave(os.path.join(out, 'deployed-state-%s.sarif' % slug), sarif(results, 'kit-deployed-state', DRIFT_RULES))
    rows = [{'scanner': 'deployed-state-%s' % slug, 'applicability': 'APPLICABLE', 'execution': 'COMPLETE',
             'scope': where, 'artifact': 'UPLOADED', 'upload': 'NOT_APPLICABLE', 'gate': 'REPORTED',
             'sarif': 'deployed-state-%s.sarif' % slug}]
    for i, p in enumerate(vuln_results):
        name = 'deployed-rescan-%s-%d.sarif' % (slug, i)
        shutil.copy(p, os.path.join(out, name))
        rows.append({'scanner': 'deployed-image-rescan-%s' % slug, 'applicability': 'APPLICABLE',
                     'execution': 'COMPLETE', 'scope': where, 'artifact': 'UPLOADED',
                     'upload': 'NOT_APPLICABLE', 'gate': 'REPORTED', 'sarif': name})
    jsave(os.path.join(out, 'state-deployed-%s.json' % slug), rows)
    jsave(os.path.join(out, 'deployed-scan-%s.json' % slug), doc)
    output(artifact_drift=str(doc['artifact_drift']).lower(), security_drift=str(doc['security_drift']).lower(),
           rescan_sarifs=' '.join(os.path.join(out, r['sarif']) for r in rows[1:]),
           findings=str(len(results)))
    lines = ['### Deployed scan: `%s` (%s)' % (envname, adapter), '',
             '| serving | weight | digest |', '|---|---|---|']
    for s in serving or []:
        lines.append('| %s | %s | `%s` |' % (s['where'], s['weight'], s['digest'] or s['image']))
    lines += ['', 'Last promoted: `%s`' % ((doc['promoted'] or {}).get('digest') or 'none on record'),
              'Artifact drift: **%s**; security drift: **%s**; posture: `%s`; break-glass owed: %s' % (
                  doc['artifact_drift'], doc['security_drift'], result, doc['break_glass_owed']),
              'Nothing is rolled back by this scan: findings change promotion eligibility and tickets.']
    summary('\n'.join(lines))
    print('\n'.join(lines))
    return 0


def cmd_deployed_finish(a):
    """Phase 2: the KEV composite's verdict on the serving digests' re-scan joins the state
    findings. A known-exploited CVE on what serves is security drift, at every tier."""
    envname = env('deploy_environment')
    slug = record_key(envname)[len('kit-promotion-record-'):]
    out = wdir('deployed')
    sp = os.path.join(out, 'deployed-state-%s.sarif' % slug)
    doc = jload(sp)
    scan = jload(os.path.join(out, 'deployed-scan-%s.json' % slug)) or {}
    if not doc:
        print('::error::the deployed scan wrote no state; nothing to finish')
        return 1
    res = doc['runs'][0]['results']
    state = env('kev_state') or 'UNAVAILABLE'
    where = 'deployed/%s/%s' % (envname, env('containerapp_name') or env('webapp_name'))
    if state != 'AVAILABLE' and scan.get('rescans'):
        res.append(finding('KIT-RESCAN-NOT-ESTABLISHED', 'The KEV re-check of what %s serves could not '
                           'be completed (kev_state %s).' % (envname, state), where + '/kev'))
    for tok in [t for t in (env('kev_blocking') or '').split() if t]:
        res.append(finding('KIT-KNOWN-EXPLOITED-SERVING', 'A known-exploited CVE is in what %s serves: %s.'
                           % (envname, tok), '%s/%s' % (where, tok.split('@', 1)[0])))
        scan['security_drift'] = True
    rules = doc['runs'][0]['tool']['driver']['rules']
    if not any(r['id'] == 'KIT-KNOWN-EXPLOITED-SERVING' for r in rules):
        rules.append({'id': 'KIT-KNOWN-EXPLOITED-SERVING',
                      'shortDescription': {'text': 'a known-exploited CVE is in what is serving'}})
    jsave(sp, doc)
    jsave(os.path.join(out, 'deployed-scan-%s.json' % slug), scan)
    output(security_drift=str(scan.get('security_drift')).lower(), kev_state=state)
    print('deployed scan finished: kev %s, security drift %s' % (state, scan.get('security_drift')))
    return 0


def cmd_deployed_report(a):
    """Phase 3, one job for every environment: the core report over the merged state rows, so the
    reconcile path tickets what the scans found (findings.json beside findings-coverage.json)."""
    d = a.state_dir
    here = os.path.dirname(os.path.abspath(__file__))
    p = subprocess.run([sys.executable, os.path.join(here, 'scan_report.py'), '--batch', d,
                        '--findings-out', os.path.join(d, 'findings.json'), '--out',
                        os.environ.get('GITHUB_STEP_SUMMARY', '')],
                       capture_output=True, text=True, encoding='utf-8', errors='replace')
    sys.stdout.write(p.stdout[-4000:])
    ok = os.path.exists(os.path.join(d, 'findings.json'))
    output(findings_written=str(ok).lower())
    if not ok:
        print('::error::the report wrote no findings.json (exit %d): %s' % (p.returncode, p.stderr[-400:]))
        return 1
    return 0


# ----------------------------------------------------------------------------- self-test
def self_test():
    fails = []
    now = parse_ts('2026-10-26T12:00:00Z')
    d1, d2 = 'sha256:' + '1' * 64, 'sha256:' + '2' * 64

    def rec(digest=d1, envname='test', tier='test', state=VERIFIED, at='2026-10-25T12:00:00Z'):
        return {'schema': SCHEMA, 'state': state, 'artifact': {'digest': digest},
                'environment': {'name': envname, 'tier': tier},
                'provenance': {'source_ref': 'refs/heads/main', 'build_workflow': 'o/k/.github/workflows/b.yml'},
                'validity': {'verified_at': at}, 'run': {'id': '7'}, 'approval': {'approvers': []},
                '_artifact': {'head_branch': 'main'}}

    def ctx(**o):
        c = {'digest': d1, 'required_predecessor': 'test', 'source_environment': 'test', 'source': rec(),
             'history': [], 'revocations': [], 'rescan': {'state': 'COMPLETE', 'critical': [], 'high': []},
             'kev': {'state': 'AVAILABLE', 'blocking': []}, 'attestation': 'ATTESTATION_VERIFIED',
             'release_path': 'normal', 'exception': {}, 'now': now}
        c.update(o)
        return c
    cases = [('allowed', ctx(), 'PROMOTION_ALLOWED'),
             ('dev', ctx(source=rec(envname='dev', tier='dev'), source_environment='dev'),
              'PROMOTION_REFUSED_WRONG_PREDECESSOR'),
             ('swap', ctx(digest=d2), 'PROMOTION_REFUSED_DIGEST_MISMATCH'),
             ('stale', ctx(source=rec(at='2026-10-01T00:00:00Z')), 'PROMOTION_REFUSED_STALE'),
             ('super', ctx(history=[rec(digest=d2, at='2026-10-26T00:00:00Z')]), 'PROMOTION_REFUSED_SUPERSEDED'),
             ('kev', ctx(kev={'state': 'AVAILABLE', 'blocking': ['CVE-1@x']}), 'PROMOTION_REFUSED_REVOKED')]
    for label, c, want in cases:
        got = judge(c)['verdict']
        if got != want:
            fails.append('%s: %s, wanted %s' % (label, got, want))
    if fails:
        print('promotion self-test FAILED: ' + '; '.join(fails))
        return 1
    print('promotion self-test ok')
    return 0


def main(argv):
    ap = argparse.ArgumentParser(description='KDEC-029 promotion')
    sub = ap.add_subparsers(dest='cmd', required=True)
    cmds = {'preflight': cmd_preflight, 'gate-collect': cmd_gate_collect, 'gate-decide': cmd_gate_decide,
            'test-period': cmd_test_period, 'dast': cmd_dast, 'posture': cmd_posture,
            'record': cmd_record, 'deployed-scan': cmd_deployed_scan,
            'deployed-finish': cmd_deployed_finish, 'deployed-report': cmd_deployed_report}
    for name in cmds:
        p = sub.add_parser(name)
        p.add_argument('--adapter', choices=('containerapp', 'appservice'), default='containerapp')
        p.add_argument('--state-dir', default='')
    sub.add_parser('self-test')
    a = ap.parse_args(argv)
    if a.cmd == 'self-test':
        return self_test()
    return cmds[a.cmd](a)


if __name__ == '__main__':
    sys.exit(main(sys.argv[1:]))

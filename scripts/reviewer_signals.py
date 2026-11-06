#!/usr/bin/env python3
"""What a security reviewer could not see from the kit, recorded on every run (KDEC-036 PROPOSED).

WHY THIS EXISTS

    The security-review lane (docs/security-review/, 2026-11-03) walked one application review through
    the kit's own outputs and found signals a reviewer needs and the kit either did not compute or put
    only in a job summary, which expires with the logs and no program can read:

      G2  `weakening_authority` was free text. It could name the requester, or the team itself, and the
      G3  run still read WEAKENING_ATTRIBUTED, with or without an expiry. Owner rulings 2026-11-03: an
          exception is APPROVED (WEAKENING_ATTRIBUTED) only with an evidence reference, a reason, a named
          owner (weakening_authority), an expiry within the ceiling (central numbers.
          weakening_expiry_ceiling_days, default 90) and an approver (weakening_approver) on a K-9
          approver list who is not the requester. Missing any is WEAKENING_NOT_APPROVED, naming the field:
          the run proceeds at crawl with the control still counted weakened, uat/prod refuses. The
          requester, the actor or the released commit's author as owner or approver is
          WEAKENING_SELF_APPROVED: never approved, BLOCKED by the gate and refused by every deploy.
      G5  the capability floor, the job-token preflight, the leak-gate alarm, the policy notices, the
          release approver and the lease/seam state were summary text. They are workflow outputs and
          fields of a machine-readable record: kit-security-record.json (the artifact
          kit-security-record-<attempt>) and the deploy evidence's review-signals.json.
      G6  every record expired with its artifact. With the lease off, each release now writes a
          durable record to the GitHub Deployments API (a deployment with task kit-release-record,
          its payload the record, and a status): the cheapest durable store a private repository
          without GitHub Advanced Security on GHE.com has (deployments: write, no plan, no licence).
          Artifact retention is KIT_EVIDENCE_RETENTION_DAYS, never below the audit floor (90).
      G8  a deploy could not tell its gate's verdict from a typed one. It now reads the security record
          of the run the verdict came from (this run, the promotion source, or security_run_id) and
          compares: VERDICT_FROM_GATE; MANUAL_REVIEW_VERDICT (typed, with an AppSec reviewer on the AppSec
          list who is neither requester nor author, a reference and a date: owner ruling 2026-11-03);
          TYPED_VERDICT (any other typed verdict: refused at uat/prod, warned below),
          VERDICT_CONTRADICTED (more permissive than the gate, a dropped cause, another commit:
          refused at every tier), VERDICT_RECORD_UNREADABLE (refused at uat/prod).
      G9  the kit host copy's watermark was a file nobody read at run time. The record carries the
          called kit ref and the watermark's source_commit, read from the kit the reusable runs from.
      G4  the tier's source (TIER_VENDED: the landing zone's hand-off; TIER_SELF_DECLARED otherwise) and
          a reality signal from the target the deploy already reads: a custom domain, or public
          ingress at production-like scale, under a dev/test tier is TIER_MISMATCH_SUSPECTED (warn).
      G1  readiness_source (owner ruling 2026-11-03): READINESS_SOURCE_LZ_HANDOFF (the landing zone's
          hand-off marker); READINESS_SOURCE_APPSEC_ATTESTATION (.kit/zone-readiness.json, merged through
          a pull request an AppSec approver who is not its author approved, for this environment,
          unexpired); READINESS_ATTESTATION_REFUSED; READINESS_SOURCE_SELF_SET_REFUSED (set by the
          repository: refused at uat/prod); READINESS_SOURCE_TEST_FIXTURE (labelled); READINESS_NOT_SET.
      G10 a repository holding Kubernetes manifests, VM infrastructure or code-packaged Functions has no
          kit deploy adapter for them: NO_KIT_ADAPTER:<kind>, from discovery, in the record and the
          summary; a deploy whose environment vends a KIT_HOSTING_KIND this adapter does not serve is
          refused NO_KIT_ADAPTER:<kind>.

    Every value is the kit's own word (assurance-taxonomy.yaml: weakening_authority_check,
    verdict_provenance, tier_source, tier_reality, readiness_source, kit_watermark, evidence_retention,
    release_record, deploy_coverage). The kit cannot see who wrote a GitHub variable, team membership,
    or admin-only settings: those stay the reviewer's to obtain (docs/security-review/).

USAGE (inputs arrive through the environment, as data; names below are the variables)
    reviewer_signals.py discover --root DIR          KIT_EVIDENCE_RETENTION_DAYS
    reviewer_signals.py weakening --central FILE     w_reason w_authority w_expires, or w_supplied (+ actors)
    reviewer_signals.py security --kit-root DIR --out FILE      s_* (the gate's outputs)
    reviewer_signals.py deploy-pre --kit-root DIR --adapter A   the deploy job's environment
    reviewer_signals.py deploy-post --adapter A                 the deploy job's environment, d_*
    reviewer_signals.py --self-test

EXIT 0 recorded (warnings included)   1 refused by name   2 usage
"""
import argparse
import datetime
import hashlib
import io
import json
import os
import re
import sys
import urllib.request
import zipfile

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

PRODUCTION_TIERS = ('uat', 'prod')
LOWER_TIERS = ('sandbox', 'dev', 'test')

# the weakening record's approval (G2, G3; owner rulings 2026-11-03)
ATTRIBUTED = 'WEAKENING_ATTRIBUTED'          # approved: all five fields, approver listed, nobody self-named
NOT_APPROVED = 'WEAKENING_NOT_APPROVED'      # a field missing, named; proceeds at crawl, refused at uat/prod
SELF_APPROVED = 'WEAKENING_SELF_APPROVED'    # owner or approver is the requester/actor/author: never approved
EXPIRED = 'WEAKENING_EXCEPTION_EXPIRED'
UNATTRIBUTED = 'WEAKENING_UNATTRIBUTED'
REVIEW_CAUSES = (NOT_APPROVED,)              # the gate's cause a uat/prod deploy refuses
DEFAULT_CEILING_DAYS = 90       # owner decision O-36b; the central register may set 1..365
CEILING_KEY = 'weakening_expiry_ceiling_days'
APPSEC_LIST_KEY = 'appsec_approver_list'
DEFAULT_APPSEC_LIST = 'appsec'  # owner decision O-36j: the K-9 list naming AppSec reviewers (GitHub logins)

# verdict_provenance (G8)
FROM_GATE = 'VERDICT_FROM_GATE'
TYPED = 'TYPED_VERDICT'
CONTRADICTED = 'VERDICT_CONTRADICTED'
RECORD_UNREADABLE = 'VERDICT_RECORD_UNREADABLE'
MANUAL = 'MANUAL_REVIEW_VERDICT'
MANUAL_REVIEW_MAX_AGE_DAYS = 30  # owner decision O-36k
ROUTES = ('PROCEED', 'PROCEED_WITH_ADVISORY', 'DECISION_REQUIRED', 'EVIDENCE_UNTRUSTED', 'BLOCKED')
RECORD_PREFIX = 'kit-security-record-'
RECORD_FILE = 'kit-security-record.json'
RECORD_SCHEMA = 'kit-security-record/1'

# tier_source, tier_reality, readiness_source (G4, G1)
TIER_VENDED = 'TIER_VENDED'
TIER_SELF = 'TIER_SELF_DECLARED'
MISMATCH = 'TIER_MISMATCH_SUSPECTED'
CONSISTENT = 'TIER_CONSISTENT'
REALITY_UNREAD = 'TIER_REALITY_UNREAD'
READINESS_LZ = 'READINESS_SOURCE_LZ_HANDOFF'
READINESS_APPSEC = 'READINESS_SOURCE_APPSEC_ATTESTATION'
READINESS_SELF = 'READINESS_SOURCE_SELF_SET_REFUSED'
READINESS_FIXTURE = 'READINESS_SOURCE_TEST_FIXTURE'
READINESS_ATT_REFUSED = 'READINESS_ATTESTATION_REFUSED'
READINESS_UNSET = 'READINESS_NOT_SET'
ATTESTATION_PATH = '.kit/zone-readiness.json'
ATTESTABLE = ('READY', 'READY_WITH_EXCEPTIONS', 'NOT_READY')
LZ_ISSUER = 'landing-zone'

# kit_watermark (G9)
WM_BOUND = 'WATERMARK_BOUND'
WM_DIRTY = 'WATERMARK_DIRTY'
WM_ABSENT = 'WATERMARK_ABSENT'
WM_UNREADABLE = 'WATERMARK_UNREADABLE'
WATERMARK = '.neutral-export-watermark.json'

# evidence_retention, release_record (G6)
AUDIT_FLOOR_DAYS = 90           # owner decision O-36c (default)
MAX_RETENTION_DAYS = 400        # GitHub's ceiling for a private repository's artifacts
RET_DEFAULT = 'EVIDENCE_RETENTION_DEFAULT'
RET_SET = 'EVIDENCE_RETENTION_SET'
RET_FLOOR = 'EVIDENCE_RETENTION_RAISED_TO_FLOOR'
RET_CAPPED = 'EVIDENCE_RETENTION_CAPPED'
KEPT_DEPLOYMENT = 'RELEASE_RECORD_KEPT_DEPLOYMENT'
KEPT_LEASE = 'RELEASE_RECORD_KEPT'          # the lease store's own word (K-4)
NOT_KEPT = 'RELEASE_RECORD_NOT_KEPT'
RELEASE_SCHEMA = 'kit-release-record/1'

# deploy_coverage (G10)
NO_ADAPTER = 'NO_KIT_ADAPTER'
ADAPTER_KINDS = {'containerapp': ('container_app',), 'appservice': ('app_service',),
                 'functionapp': ('function_app',), 'staticwebapp': ('static_web_app',)}


def env(name, default=''):
    """Job environment names are written lower-case here and upper-cased on lookup: they are settings,
    not vocabulary (the deploy contract's rule; scripts/reconcile_taxonomy.py remedy 4)."""
    return os.environ.get(name.upper(), default)


def output(**kv):
    lines = ['%s=%s' % (k, ' '.join(str('' if v is None else v).split())) for k, v in kv.items()]
    path = env('github_output')
    if path:
        with io.open(path, 'a', encoding='utf-8') as fh:
            fh.write('\n'.join(lines) + '\n')
    print('\n'.join(lines))


def summary(text):
    path = env('github_step_summary')
    if path:
        with io.open(path, 'a', encoding='utf-8') as fh:
            fh.write(text + '\n')


def plain(v):
    return bool(re.match(r'^[A-Za-z0-9@][A-Za-z0-9._/@:+-]{0,119}$', v or ''))


def shown(v):
    return '(none)' if not v else ("'%s'" % v if plain(v) else '(a value that is not a plain token, not shown)')


def jload(text, default):
    try:
        v = json.loads(text) if (text or '').strip() else default
    except ValueError:
        return default
    return v if isinstance(v, type(default)) else default


def csv(text):
    return [x for x in re.split(r'[,\s]+', text or '') if x]


def today():
    t = env('kit_today')          # tests only; a run reads the clock
    return datetime.date.fromisoformat(t) if t else datetime.datetime.now(datetime.timezone.utc).date()


def evidence_dir():
    d = os.path.join(env('runner_temp') or '.', 'deploy-evidence')
    os.makedirs(d, exist_ok=True)
    return d


# ----------------------------------------------------------------------------- G2, G3 (owner rulings 2026-11-03)
def norm(name):
    return (name or '').strip().lstrip('@').lower()


def load_central(path):
    """-> (central register dict, approver lists {name: [group]}, problem). Absent is {} (no lists)."""
    if not path or not os.path.exists(path):
        return {}, {}, ''
    try:
        doc = json.loads(io.open(path, encoding='utf-8').read())
    except (OSError, ValueError) as exc:
        return {}, {}, 'the central register could not be read (%s)' % type(exc).__name__
    if not isinstance(doc, dict):
        return {}, {}, 'the central register is not an object'
    lists = doc.get('approver_lists')
    src = doc.get('approver_lists_source')
    if lists is None and isinstance(src, str) and src and not os.path.isabs(src) and '..' not in src:
        try:
            got = json.loads(io.open(os.path.join(os.path.dirname(path), src), encoding='utf-8').read())
            lists = got.get('approver_lists') if isinstance(got, dict) else None
        except (OSError, ValueError) as exc:
            return doc, {}, 'the approver list source could not be read (%s)' % type(exc).__name__
    if not isinstance(lists, dict):
        return doc, {}, ''
    return doc, {str(k): [str(g) for g in v] for k, v in lists.items() if isinstance(v, list)}, ''


def ceiling_days(central):
    v = ((central or {}).get('numbers') or {}).get(CEILING_KEY)
    if isinstance(v, bool) or not isinstance(v, int) or not 1 <= v <= 365:
        return DEFAULT_CEILING_DAYS
    return v


def appsec_list(central):
    """The AppSec approver list's name: numbers.appsec_approver_list, default 'appsec' (owner decision)."""
    v = ((central or {}).get('numbers') or {}).get(APPSEC_LIST_KEY)
    return v if isinstance(v, str) and re.match(r'^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$', v) else DEFAULT_APPSEC_LIST


def on_list(who, lists, only=None):
    """-> the list name `who` is on (a list's name, a group, or a group's last segment), '' when none."""
    a = norm(who)
    for name, groups in sorted(lists.items()):
        if only and name != only:
            continue
        if not only and a == norm(name):
            return name
        for g in groups:
            if a in (norm(g), norm(g).rsplit('/', 1)[-1]):
                return name
    return ''


def commit_authors(shas):
    """-> the GitHub logins that authored these commits (a merge's second parent too), or None when any
    cannot be read: the approver can then not be shown not to be the author."""
    import rollback_hold as rh
    out = set()
    try:
        for sha in [s for s in shas if s]:
            doc = rh.api('commits/%s' % sha)
            login = (((doc or {}).get('author') or {}).get('login') or '').strip()
            if not login:
                return None
            out.add(login.lower())
            parents = (doc or {}).get('parents') or []
            if len(parents) > 1 and isinstance(parents[1], dict) and parents[1].get('sha'):
                p = rh.api('commits/%s' % parents[1]['sha'])
                pl = (((p or {}).get('author') or {}).get('login') or '').strip()
                if not pl:
                    return None
                out.add(pl.lower())
    except Exception:  # noqa: BLE001 -- unreadable is never "nobody"
        return None
    return out


def weakening_check(rec, requesters, authors, lists, day, ceiling):
    """Pure. `rec` {reason, authority, approver, exception_ref, expires}; `authors` None = unreadable.
    -> {state, missing, self_named, approver_list, why, ceiling_days}; state '' when nothing is declared.

    Owner rulings 2026-11-03: an exception is APPROVED (WEAKENING_ATTRIBUTED) only with an evidence
    reference, a reason, a named owner (weakening_authority, never the requester), an expiry within the
    ceiling, and an approver (weakening_approver) on a registered approver list who is not the requester.
    Naming the requester, the actor or the released commit's author as owner or approver is
    WEAKENING_SELF_APPROVED: never approved, in any mode. An exception with no expiry is never approved."""
    r = dict((k, (str((rec or {}).get(k) or '')).strip()) for k in ('reason', 'authority', 'approver',
                                                                     'exception_ref', 'expires'))
    out = {'state': '', 'missing': [], 'self_named': [], 'approver_list': '', 'why': [], 'ceiling_days': ceiling}
    if not any(r.values()):
        return out
    miss, why = out['missing'], out['why']
    people = set(norm(x) for x in requesters if x) | set(authors or ())
    for field in ('authority', 'approver'):
        if r[field] and norm(r[field]) in people:
            out['self_named'].append(field)
            why.append('the %s (weakening_%s) names the requester, the actor or the release\'s author' % (
                'owner' if field == 'authority' else 'approver', field))
    if not r['reason']:
        miss.append('reason')
    if not r['authority']:
        miss.append('owner')
    if not r['exception_ref']:
        miss.append('evidence reference')
    expired = False
    if not r['expires']:
        miss.append('expiry')
        why.append('no expiry (weakening_expires): an exception without an end is never approved')
    else:
        exp = None
        if re.match(r'^\d{4}-\d{2}-\d{2}$', r['expires']):
            try:
                exp = datetime.date.fromisoformat(r['expires'])
            except ValueError:
                exp = None
        if exp is None:
            expired = True
            why.append('an expiry that is not a YYYY-MM-DD date')
        elif exp < day:
            expired = True
            why.append('expired on %s' % r['expires'])
        elif (exp - day).days > ceiling:
            miss.append('expiry within the ceiling')
            why.append('an expiry %d days out, past the %d-day ceiling' % ((exp - day).days, ceiling))
    if not r['approver']:
        miss.append('approver')
    elif not lists:
        miss.append('approver on a registered approver list')
        why.append('no approver list is registered (approver_lists), so no approver can be shown to be one')
    else:
        out['approver_list'] = on_list(r['approver'], lists)
        if not out['approver_list']:
            miss.append('approver on a registered approver list')
    if authors is None:
        miss.append('independence from the release author')
        why.append('the released commit\'s author could not be read')
    if out['self_named']:
        out['state'] = SELF_APPROVED
    elif not r['reason'] or not r['authority']:
        out['state'] = UNATTRIBUTED
    elif expired:
        out['state'] = EXPIRED
    elif miss:
        out['state'] = NOT_APPROVED
    else:
        out['state'] = ATTRIBUTED
    if miss:
        why.insert(0, 'not approved: missing %s' % ', '.join(miss))
    return out


def review_causes(check):
    return [c for c in REVIEW_CAUSES if (check or {}).get('state') == c]


def record_from_env(prefix=''):
    return dict((k, env(prefix + 'weakening_' + k)) for k in ('reason', 'authority', 'approver', 'exception_ref',
                                                             'expires'))


def cmd_weakening(a):
    """The security gate's check (resolve-policy runs it): outputs the check as JSON, never fails."""
    central, lists, problem = load_central(a.central)
    sup = jload(env('w_supplied'), {})       # resolve-policy passes toJSON(inputs) of the caller
    rec = dict((k, str(sup.get('weakening_' + k) or '')) for k in ('reason', 'authority', 'approver',
                                                                  'exception_ref', 'expires'))
    authors = commit_authors([env('github_sha')]) if any(rec.values()) else set()
    check = weakening_check(rec, [env('github_actor'), env('github_triggering_actor')], authors, lists, today(),
                            ceiling_days(central))
    if problem:
        check['why'].append(problem)
    output(weakening_check=json.dumps(check, sort_keys=True, separators=(',', ':')))
    return 0


# ----------------------------------------------------------------------------- G9, G6 retention
def watermark(kit_root):
    rec = {'state': WM_ABSENT, 'kit_repository': env('github_action_repository'),
           'kit_ref': env('github_action_ref'), 'source_commit': ''}
    path = os.path.join(kit_root or '.', WATERMARK)
    if not kit_root or not os.path.exists(path):
        return rec
    try:
        wm = json.loads(io.open(path, encoding='utf-8').read())
        if not isinstance(wm, dict):
            raise ValueError('not an object')
    except (OSError, ValueError):
        rec['state'] = WM_UNREADABLE
        return rec
    conflicts = wm.get('unresolved_conflicts') or {}
    rec.update(source_commit=str(wm.get('source_commit') or ''), profile=str(wm.get('profile') or ''),
               exported_at_utc=str(wm.get('exported_at_utc') or ''), source_dirty=bool(wm.get('source_dirty')),
               unresolved_conflicts=len(conflicts) if isinstance(conflicts, (dict, list)) else 1)
    rec['state'] = WM_DIRTY if (rec['source_dirty'] or rec['unresolved_conflicts']) else (
        WM_BOUND if re.match(r'^[0-9a-f]{40}$', rec['source_commit']) else WM_UNREADABLE)
    return rec


def watermark_row(wm):
    where = '%s@%s' % (wm.get('kit_repository') or '(kit)', (wm.get('kit_ref') or '(ref unknown)')[:40])
    if wm['state'] == WM_ABSENT:
        return '| kit host copy (G9) | `%s` | %s carries no %s: the run cannot be tied to a kit source commit |' % (
            WM_ABSENT, where, WATERMARK)
    return '| kit host copy (G9) | `%s` | %s received kit source `%s` (profile %s, exported %s, dirty %s, conflicts %s) |' % (
        wm['state'], where, wm.get('source_commit') or '?', wm.get('profile') or '?',
        wm.get('exported_at_utc') or '?', str(wm.get('source_dirty')).lower(), wm.get('unresolved_conflicts', '?'))


def retention(value):
    """-> (days, state). The floor is the audit minimum; GitHub caps a private repository at 400."""
    v = (value or '').strip()
    if not v:
        return AUDIT_FLOOR_DAYS, RET_DEFAULT
    if not re.match(r'^\d{1,4}$', v) or int(v) < AUDIT_FLOOR_DAYS:
        return AUDIT_FLOOR_DAYS, RET_FLOOR
    if int(v) > MAX_RETENTION_DAYS:
        return MAX_RETENTION_DAYS, RET_CAPPED
    return int(v), RET_SET


# ----------------------------------------------------------------------------- G10 discovery
SKIP_DIRS = {'.git', 'node_modules', 'vendor', '.venv', 'venv', '__pycache__', 'dist', 'build', 'target'}
K8S_KIND = re.compile(r'^kind:\s*(Deployment|StatefulSet|DaemonSet|CronJob|Ingress)\s*$', re.M)
K8S_WF = re.compile(r'azure/k8s-deploy|azure/aks-set-context|\bkubectl\s+(apply|set\s+image|rollout)|\bhelm\s+(upgrade|install)', re.I)
VM_IAC = re.compile(r'azurerm_(linux_|windows_)?virtual_machine(_scale_set)?\b|Microsoft\.Compute/virtualMachines', re.I)
VM_WF = re.compile(r'\baz\s+vmss?\s|azure/arm-deploy.*virtualMachines', re.I)
FUNC_WF = re.compile(r'azure/functions-action', re.I)


def deploy_targets(root, max_depth=8):
    """-> {kind: [evidence path, ...]} for hosting kinds the kit has no deploy adapter for."""
    found = {}

    def add(kind, rel):
        found.setdefault(kind, [])
        if len(found[kind]) < 5:
            found[kind].append(rel.replace('\\', '/'))
    for d, dirs, files in os.walk(root):
        rel_d = os.path.relpath(d, root)
        depth = 0 if rel_d == '.' else rel_d.count(os.sep) + 1
        dirs[:] = [x for x in dirs if x not in SKIP_DIRS and depth < max_depth]
        in_wf = rel_d.replace('\\', '/').startswith('.github/workflows')
        docker = any(f.startswith('Dockerfile') or f == 'Containerfile' for f in files)
        for f in files:
            p = os.path.join(d, f)
            rel = os.path.relpath(p, root)
            if f in ('Chart.yaml', 'kustomization.yaml'):
                add('aks', rel)
                continue
            if f == 'host.json' and not docker:
                add('function_app_code', rel)
                continue
            if not f.endswith(('.yml', '.yaml', '.tf', '.bicep', '.json')):
                continue
            try:
                if os.path.getsize(p) > 512 * 1024:
                    continue
                text = io.open(p, encoding='utf-8', errors='replace').read()
            except OSError:
                continue
            if in_wf:
                for kind, rx in (('aks', K8S_WF), ('vm', VM_WF), ('function_app_code', FUNC_WF)):
                    if rx.search(text):
                        add(kind, rel)
            elif f.endswith(('.yml', '.yaml')) and K8S_KIND.search(text) and 'apiVersion:' in text:
                add('aks', rel)
            elif f.endswith(('.tf', '.bicep', '.json')) and VM_IAC.search(text):
                add('vm', rel)
    return found


def cmd_discover(a):
    days, state = retention(env('kit_evidence_retention_days'))
    try:
        targets = deploy_targets(a.root)
        gaps = ','.join('%s:%s' % (NO_ADAPTER, k) for k in sorted(targets))
        detail = json.dumps(targets, sort_keys=True, separators=(',', ':'))
    except Exception as exc:  # noqa: BLE001 -- a failed survey is said, never read as "none"
        gaps, detail = '%s:UNDETERMINED' % NO_ADAPTER, json.dumps({'error': type(exc).__name__})
    output(no_kit_adapter=gaps, deploy_targets=detail, evidence_retention_days=days, evidence_retention=state)
    rows = ['| deploy coverage (G10) | `%s` | %s |' % (
        gaps or 'none found', 'the kit scans this code but has no deploy adapter for it: deployment governance '
        'is not established by the kit (MOD-OUTSIDE-KIT)' if gaps else 'no AKS, VM or code-packaged Functions '
        'deployment found within 8 levels'),
        '| evidence retention (G6) | `%s` | %d days (floor %d; KIT_EVIDENCE_RETENTION_DAYS) |' % (state, days, AUDIT_FLOOR_DAYS)]
    summary('\n### Reviewer signals (discovery)\n\n| signal | value | meaning |\n|---|---|---|\n' + '\n'.join(rows))
    if gaps:
        print('::warning title=%s::%s. The kit scans this code; its deploy is outside the kit (docs/security-review/modules/MOD-OUTSIDE-KIT.md).' % (gaps, detail[:300]))
    return 0


# ----------------------------------------------------------------------------- the security record
def cmd_security(a):
    """G5, G9: the gate's signals as one machine-readable record, outputs and a summary table."""
    wm = watermark(a.kit_root)
    days, ret_state = retention(env('s_retention_days'))
    check = jload(env('s_weakening_check'), {})
    rec = {
        'schema': RECORD_SCHEMA,
        'run': {'repository': env('github_repository'), 'run_id': env('github_run_id'),
                'run_attempt': env('github_run_attempt'), 'commit': env('github_sha'), 'ref': env('github_ref'),
                'actor': env('github_actor'), 'triggering_actor': env('github_triggering_actor')},
        'verdict': {'routing_result': env('s_routing_result'), 'advisory_causes': csv(env('s_advisory_causes'))},
        'weakening': {'attribution': env('s_weakening_attribution'), 'check': check},
        'capability_floor': {'state': env('s_floor_state') or 'BREACHED', 'missing': csv(env('s_floor_missing'))},
        'token_preflight': env('s_token_preflight'),
        'leak_gates': jload(env('s_leak_gates'), {}), 'leak_gate_alarm': env('s_leak_gate_alarm'),
        'policy': {'source': env('s_policy_source'), 'resolution': env('s_policy_resolution'),
                   'rung_effective': env('s_rung_effective'), 'environment_tier': env('s_environment_tier'),
                   'notices': jload(env('s_policy_notices'), [])},
        'deploy_coverage': {'no_kit_adapter': csv(env('s_no_kit_adapter')),
                            'deploy_targets': jload(env('s_deploy_targets'), {})},
        'kit': wm,
        'evidence': {'artifact': env('s_evidence_artifact'), 'record_artifact': RECORD_PREFIX + env('github_run_attempt', '1'),
                     'retention_days': days, 'retention': ret_state},
        'run_record': jload(env('s_assurance_result'), {}),
    }
    os.makedirs(os.path.dirname(os.path.abspath(a.out)), exist_ok=True)
    with io.open(a.out, 'w', encoding='utf-8') as fh:
        json.dump(rec, fh, indent=1, sort_keys=True)
    compact = json.dumps(rec, sort_keys=True, separators=(',', ':'))
    output(security_record=compact, kit_watermark=json.dumps(wm, sort_keys=True, separators=(',', ':')),
           kit_source_commit=wm.get('source_commit', ''), record_artifact=rec['evidence']['record_artifact'],
           retention_days=days)
    rows = [watermark_row(wm),
            '| weakening approval (G2, G3) | `%s` | %s |' % (check.get('state') or 'none declared',
                                                        '; '.join(check.get('why') or []) or 'no weakening record'),
            '| capability floor | `%s` | %s |' % (rec['capability_floor']['state'], ' '.join(rec['capability_floor']['missing']) or '-'),
            '| job token preflight | `%s` | the clean answer is TOKEN_ACCEPTED |' % (rec['token_preflight'] or 'not reported'),
            '| leak-gate alarm | `%s` | %s |' % (rec['leak_gate_alarm'] or 'none', 'only the CI scan stands before the default branch' if rec['leak_gate_alarm'] else 'a pre-CI layer is ON'),
            '| policy notices | `%d` | %s |' % (len(rec['policy']['notices']), ', '.join(sorted(set(str(n.get('code')) for n in rec['policy']['notices'] if isinstance(n, dict)))) or '-'),
            '| deploy coverage (G10) | `%s` | %s |' % (','.join(rec['deploy_coverage']['no_kit_adapter']) or 'no gap found', 'deploys outside the kit' if rec['deploy_coverage']['no_kit_adapter'] else '-'),
            '| record | `%s` | machine-readable; kept %d days (`%s`) |' % (RECORD_FILE, days, ret_state)]
    summary('\n### Reviewer signals (KDEC-036)\n\n| signal | value | detail |\n|---|---|---|\n' + '\n'.join(rows))
    if wm['state'] != WM_BOUND:
        print('::notice title=Kit copy %s::%s' % (wm['state'], watermark_row(wm)))
    for c in review_causes(check):
        print('::warning title=%s (KDEC-036)::%s. Recorded here, the control still counted weakened; a uat or '
              'prod deploy refuses it.' % (c, '; '.join(check.get('why') or [])))
    if check.get('state') == SELF_APPROVED:
        print('::error title=%s (KDEC-036)::%s. A requester never approves their own exception: the gate '
              'routes BLOCKED in every mode.' % (SELF_APPROVED, '; '.join(check.get('why') or [])))
    return 0


# ----------------------------------------------------------------------------- G8
def rank(route):
    return ROUTES.index(route) if route in ROUTES else len(ROUTES)


def judge_verdict(routing, causes, record, expected_commits):
    """Pure. -> (verdict_provenance, why). `record` None = no record found; 'unreadable' = could not read."""
    if record == 'unreadable':
        return RECORD_UNREADABLE, 'the security record of the run the verdict came from could not be read'
    if record is None:
        return TYPED, ('no kit security record exists for the run this verdict names: the value was typed or '
                       'carried from somewhere the kit cannot trace')
    gate = (record.get('verdict') or {})
    g_route, g_causes = gate.get('routing_result') or '', set(gate.get('advisory_causes') or [])
    commit = ((record.get('run') or {}).get('commit') or '').lower()
    if expected_commits and commit not in set(c.lower() for c in expected_commits if c):
        return CONTRADICTED, 'the security record is for commit %s, not the commit released' % shown(commit[:12])
    if rank(routing) < rank(g_route):
        return CONTRADICTED, ('routing_result %s is more permissive than the gate\'s own %s'
                              % (shown(routing), shown(g_route)))
    missing = sorted(g_causes - set(causes))
    if missing and rank(routing) <= rank('PROCEED_WITH_ADVISORY'):
        return CONTRADICTED, 'advisory_causes drops the gate\'s %s' % ', '.join(missing)
    return FROM_GATE, 'routing_result %s matches (or is stricter than) the gate\'s own %s, run %s' % (
        shown(routing), shown(g_route), shown(str((record.get('run') or {}).get('run_id') or '')))


def read_security_record(run_id):
    """-> the record dict, None (none exists), or 'unreadable'."""
    import rollback_hold as rh
    try:
        listing = rh.api('actions/runs/%s/artifacts' % run_id, {'per_page': 100})
        arts = [x for x in (listing or {}).get('artifacts') or []
                if isinstance(x, dict) and str(x.get('name') or '').startswith(RECORD_PREFIX) and not x.get('expired')]
        if not arts:
            return None
        art = sorted(arts, key=lambda x: int((x['name'][len(RECORD_PREFIX):] or '0')
                                             if x['name'][len(RECORD_PREFIX):].isdigit() else 0))[-1]
        data = rh._open(art['archive_download_url'])
        with zipfile.ZipFile(io.BytesIO(data)) as zf:
            names = [n for n in zf.namelist() if n.endswith(RECORD_FILE)]
            rec = json.loads(zf.read(names[0]).decode('utf-8')) if names else None
        if not isinstance(rec, dict) or rec.get('schema') != RECORD_SCHEMA:
            return 'unreadable'
        return rec
    except Exception:  # noqa: BLE001 -- unreadable is never "no record"
        return 'unreadable'


# ----------------------------------------------------------------------------- G4, G1
def tier_source(bound_tier, issuer):
    if bound_tier and (issuer or '').strip().lower().split(':', 1)[0] == LZ_ISSUER:
        return TIER_VENDED
    return TIER_SELF


def tier_reality(tier, reality):
    """-> (tier_reality, signals). Warn only (owner may tighten)."""
    if not isinstance(reality, dict) or not reality:
        return REALITY_UNREAD, []
    signals = []
    if reality.get('custom_domains'):
        signals.append('custom domain %s' % ', '.join(str(d) for d in reality['custom_domains'][:3]))
    scale = reality.get('min_replicas') if isinstance(reality.get('min_replicas'), int) else 0
    if reality.get('public_ingress') and scale >= 2:
        signals.append('public ingress at production-like scale (min replicas %d)' % scale)
    if tier in LOWER_TIERS and signals:
        return MISMATCH, signals
    return CONSISTENT, signals


# ----------------------------------------------------------------------------- G1 (owner ruling 2026-11-03)
def attestation_ok(att, environment, day):
    """Pure. -> (state or None, problems). The readiness attestation's own fields."""
    probs = []
    if not isinstance(att, dict):
        return None, ['the attestation is not a JSON object']
    envs = att.get('environment')
    envs = envs if isinstance(envs, list) else [envs]
    if not environment or environment not in [str(e) for e in envs if e]:
        probs.append('it does not name this environment (%s)' % shown(environment))
    state = str(att.get('state') or '')
    if state not in ATTESTABLE:
        probs.append('its state %s is not READY, READY_WITH_EXCEPTIONS or NOT_READY' % shown(state))
    if str(att.get('issuer_role') or '').lower() != 'appsec':
        probs.append('its issuer_role is not appsec')
    for k in ('issued_by', 'evidence_ref'):
        if not str(att.get(k) or '').strip():
            probs.append('no %s' % k)
    if not isinstance(att.get('exceptions', []), list):
        probs.append('exceptions is not a list')
    elif state == 'READY_WITH_EXCEPTIONS' and not att.get('exceptions'):
        probs.append('READY_WITH_EXCEPTIONS lists no exception')
    for k, past in (('issued_on', True), ('expires_on', False)):
        v = str(att.get(k) or '')
        try:
            d = datetime.date.fromisoformat(v) if re.match(r'^\d{4}-\d{2}-\d{2}$', v) else None
        except ValueError:
            d = None
        if d is None:
            probs.append('%s is not a YYYY-MM-DD date' % k)
        elif past and d > day:
            probs.append('issued_on lies in the future')
        elif not past and d < day:
            probs.append('it expired on %s' % v)
    return (state if not probs else None), probs


def attestation_approval(appsec, lists):
    """-> (approver login or '', problems): the attestation's latest change on the default branch arrived
    through a merged pull request approved by a member of the AppSec approver list who is not its author."""
    import rollback_hold as rh
    branch = env('default_branch').strip()
    if not branch:
        return '', ['the default branch is not named']
    try:
        commits = rh.api('commits', {'path': ATTESTATION_PATH, 'sha': branch, 'per_page': 1})
        if not isinstance(commits, list) or not commits:
            return '', ['no commit on %s touches %s' % (shown(branch), ATTESTATION_PATH)]
        sha = commits[0].get('sha') or ''
        pulls = rh.api('commits/%s/pulls' % sha)
        merged = [p for p in pulls or [] if isinstance(p, dict) and p.get('merged_at')]
        if not merged:
            return '', ['its latest change (%s) did not arrive through a merged pull request' % sha[:12]]
        pr = merged[0]
        author = norm((pr.get('user') or {}).get('login'))
        reviews = rh.api('pulls/%s/reviews' % pr.get('number'))
    except Exception as exc:  # noqa: BLE001 -- unreadable is never approved
        return '', ['its change history could not be read (%s)' % type(exc).__name__]
    if not lists.get(appsec):
        return '', ['no AppSec approver list %s is registered' % shown(appsec)]
    approvers = [norm((r.get('user') or {}).get('login')) for r in reviews or []
                 if isinstance(r, dict) and r.get('state') == 'APPROVED']
    good = [w for w in approvers if w and w != author and on_list(w, lists, only=appsec)]
    if not good:
        return '', ['pull request #%s was not approved by a member of the AppSec list %s other than its author'
                    % (pr.get('number'), shown(appsec))]
    return good[0], []


def cmd_readiness(a):
    """Before the zone step: where KIT_ZONE_READINESS comes from. Never refuses; the zone step decides."""
    tier = env('environment_tier').strip()
    value, issuer = env('kit_zone_readiness').strip(), env('kit_handoff_issuer')
    rec = {'tier': tier}
    if issuer.strip().lower().split(':', 1)[0] == LZ_ISSUER:
        src, attested, why = READINESS_LZ, '', 'the landing zone\'s hand-off'
    elif tier not in PRODUCTION_TIERS:
        src, attested, why = (READINESS_SELF if value else READINESS_UNSET), '', 'below uat: recorded, not read further'
    else:
        import rollback_hold as rh
        central, lists, _p = load_central(os.path.join(a.kit_root or '.', 'policy', 'policy-registration.json'))
        appsec = appsec_list(central)
        att = None
        try:
            doc = rh.api('contents/%s' % ATTESTATION_PATH, {'ref': env('default_branch')})
            import base64
            att = json.loads(base64.b64decode((doc or {}).get('content') or '').decode('utf-8'))
            found = True
        except Exception:  # noqa: BLE001 -- absent or unreadable: no attestation
            found = False
        if not found:
            if value and env('kit_zone_readiness_test_fixture').strip().lower() == 'true':
                src, attested, why = READINESS_FIXTURE, '', 'KIT_ZONE_READINESS_TEST_FIXTURE is true: a TEST FIXTURE'
            elif value:
                src, attested, why = READINESS_SELF, '', ('KIT_ZONE_READINESS is set with no landing-zone hand-off '
                                                          'and no AppSec attestation (%s)' % ATTESTATION_PATH)
            else:
                src, attested, why = READINESS_UNSET, '', 'not set, and no attestation'
        else:
            state, probs = attestation_ok(att, env('deploy_environment').strip(), today())
            approver, more = attestation_approval(appsec, lists) if state else ('', [])
            probs += more
            if probs:
                src, attested, why = READINESS_ATT_REFUSED, '', 'the attestation: ' + '; '.join(probs)
            else:
                src, attested = READINESS_APPSEC, state
                why = 'AppSec attestation %s, issued by %s, approved by %s, expires %s' % (
                    shown(str(att.get('evidence_ref'))), shown(str(att.get('issued_by'))), shown(approver),
                    shown(str(att.get('expires_on'))))
                rec['attestation'] = dict(att, approved_by=approver)
    rec.update(readiness_source=src, attested_readiness=attested, why=why)
    with io.open(os.path.join(evidence_dir(), 'readiness.json'), 'w', encoding='utf-8') as fh:
        json.dump(rec, fh, indent=1, sort_keys=True)
    output(readiness_source=src, attested_readiness=attested)
    summary('### Zone readiness source (KDEC-036 G1)\n\n`%s`: %s' % (src, why))
    return 0


# ----------------------------------------------------------------------------- G8 manual review (owner ruling)
def judge_manual(by, ref, date, lists, appsec, people, day):
    """-> (accepted, why). A typed verdict is a MANUAL_REVIEW_VERDICT only with the reviewer on the AppSec
    approver list (not the requester or author), a review reference and a date (not in the future, at most
    MANUAL_REVIEW_MAX_AGE_DAYS old)."""
    probs = []
    if not by.strip():
        probs.append('no reviewer (manual_review_by)')
    elif not lists.get(appsec) or not on_list(by, lists, only=appsec):
        probs.append('the reviewer %s is not on the AppSec approver list %s' % (shown(by), shown(appsec)))
    elif norm(by) in people:
        probs.append('the reviewer is the requester or the release\'s author')
    if not ref.strip():
        probs.append('no review reference (manual_review_ref)')
    d = None
    if re.match(r'^\d{4}-\d{2}-\d{2}$', date or ''):
        try:
            d = datetime.date.fromisoformat(date)
        except ValueError:
            d = None
    if d is None:
        probs.append('no review date (manual_review_date, YYYY-MM-DD)')
    elif d > day or (day - d).days > MANUAL_REVIEW_MAX_AGE_DAYS:
        probs.append('the review date is in the future or more than %d days old' % MANUAL_REVIEW_MAX_AGE_DAYS)
    if probs:
        return False, 'a typed verdict with a manual review that does not hold: ' + '; '.join(probs)
    return True, 'a manual review by %s (AppSec), reference %s, dated %s' % (shown(by), shown(ref), date)


# ----------------------------------------------------------------------------- deploy, before login
def cmd_deploy_pre(a):
    tier = env('environment_tier').strip()
    production = tier in PRODUCTION_TIERS
    refusals, warnings, rows = [], [], []
    rec = {'adapter': a.adapter, 'tier': tier}
    central, lists, problem = load_central(os.path.join(a.kit_root or '.', 'policy', 'policy-registration.json'))
    appsec = appsec_list(central)

    # G10: a vended hosting kind this adapter does not serve.
    kind = env('kit_hosting_kind').strip().lower()
    served = ADAPTER_KINDS.get(a.adapter, ())
    if kind and kind not in served:
        rec['hosting_kind'] = '%s:%s' % (NO_ADAPTER, kind if plain(kind) else 'unshown')
        refusals.append('%s: this environment vends KIT_HOSTING_KIND %s, which the %s adapter does not release '
                        '(it serves %s). The kit has no deploy adapter for it.' % (rec['hosting_kind'], shown(kind),
                                                                                    a.adapter, ', '.join(served)))
    else:
        rec['hosting_kind'] = kind or served[0]

    # Who may not approve: the requester, the actor, the released commit's author.
    expected = [] if env('promote_from_run_id').strip() else [env('github_sha')]
    gate_file = os.path.join(evidence_dir(), 'promotion-gate.json')
    if os.path.exists(gate_file):
        src = ((jload(io.open(gate_file, encoding='utf-8').read(), {}).get('carried') or {}).get('provenance') or {})
        if src.get('source_sha'):
            expected = [src['source_sha']]
    requesters = [env('github_actor'), env('github_triggering_actor')]
    authors = commit_authors(expected or [env('github_sha')])
    people = set(norm(x) for x in requesters if x) | set(authors or ())

    # G8: the verdict's provenance; a manual review when the verdict was typed.
    run_id = env('security_run_id').strip() or env('promote_from_run_id').strip() or env('github_run_id').strip()
    record = read_security_record(run_id) if re.match(r'^\d{1,20}$', run_id) else None
    prov, why = judge_verdict(env('routing_result').strip(), csv(env('advisory_causes')), record, expected)
    manual = [env('manual_review_by'), env('manual_review_ref'), env('manual_review_date')]
    if prov == TYPED and any(x.strip() for x in manual):
        ok, mwhy = judge_manual(manual[0], manual[1], manual[2].strip(), lists, appsec, people, today())
        prov, why = (MANUAL, mwhy) if ok else (TYPED, mwhy)
        rec['manual_review'] = {'by': manual[0], 'ref': manual[1], 'date': manual[2], 'accepted': ok}
    rec['verdict_provenance'] = {'state': prov, 'why': why, 'run_id': run_id}
    rows.append('| verdict provenance (G8) | `%s` | %s |' % (prov, why))
    if prov == CONTRADICTED:
        refusals.append('%s: %s. The deploy reads its gate\'s own record; a verdict that disagrees with it is '
                        'refused at every tier.' % (prov, why))
    elif prov in (TYPED, RECORD_UNREADABLE):
        (refusals if production else warnings).append(
            '%s: %s. %s' % (prov, why, 'Refused at %s: pass needs.security.outputs.routing_result from the run '
                            'that scanned this commit (or security_run_id), or an AppSec manual review '
                            '(manual_review_by, manual_review_ref, manual_review_date).' % tier if production
                            else 'Recorded and warned below uat.'))

    # G2, G3: the gate's cause and this deploy's own weakening record (owner rulings 2026-11-03).
    wrec = record_from_env()
    check = weakening_check(wrec, requesters, authors, lists, today(), ceiling_days(central))
    if problem:
        check['why'].append(problem)
    rec['weakening_check'] = check
    gate_causes = [c for c in csv(env('advisory_causes')) if c in REVIEW_CAUSES]
    rows.append('| weakening approval (G2, G3) | `%s` | gate causes: %s; this deploy\'s record: %s |' % (
        check['state'] or 'none declared', ', '.join(gate_causes) or 'none', '; '.join(check['why']) or 'none'))
    if check['state'] == SELF_APPROVED:
        refusals.append('%s: %s. A requester never approves their own exception, at any tier.' % (
            SELF_APPROVED, '; '.join(check['why'])))
    elif check['state'] and check['state'] != ATTRIBUTED:
        (refusals if production else warnings).append(
            '%s: this deploy\'s weakening record is not approved: %s. %s' % (
                check['state'], '; '.join(check['why']),
                'Refused at %s: an evidence reference, a reason, a named owner, an expiry within %d days and '
                'an approver on a registered list who is not the requester.' % (tier, check['ceiling_days'])
                if production else 'Recorded below uat; the control stays counted as weakened.'))
    for c in gate_causes:
        (refusals if production else warnings).append(
            '%s: the security gate recorded a weakening that is not approved. %s' % (
                c, 'Refused at %s.' % tier if production else 'Recorded below uat.'))

    # G4: where the tier came from.
    issuer = env('kit_handoff_issuer')
    rec['tier_source'] = tier_source(env('kit_bound_environment_tier').strip(), issuer)
    rec['handoff_issuer'] = issuer if plain(issuer) else ('(not shown)' if issuer else '')
    rows.append('| tier source (G4) | `%s` | tier `%s`; %s |' % (rec['tier_source'], tier or 'none', 'bound to the value the landing zone vended' if rec['tier_source'] == TIER_VENDED else 'set by the caller or the repository, not by a landing-zone hand-off'))

    # G6, G9
    rec['retention_days'], rec['retention'] = retention(env('kit_evidence_retention_days'))
    rec['kit'] = watermark(a.kit_root)
    rows.append(watermark_row(rec['kit']))
    rows.append('| hosting kind (G10) | `%s` | adapter %s |' % (rec['hosting_kind'], a.adapter))

    with io.open(os.path.join(evidence_dir(), 'review-pre.json'), 'w', encoding='utf-8') as fh:
        json.dump(rec, fh, indent=1, sort_keys=True)
    output(verdict_provenance=prov, weakening_check=check['state'], tier_source=rec['tier_source'],
           hosting_kind=rec['hosting_kind'], retention_days=rec['retention_days'],
           kit_source_commit=rec['kit'].get('source_commit', ''), kit_watermark=rec['kit']['state'])
    summary('### Reviewer signals before login (KDEC-036)\n\n| signal | value | detail |\n|---|---|---|\n' + '\n'.join(rows))
    for w in warnings:
        print('::warning title=Reviewer signal (KDEC-036)::%s' % w)
    if refusals:
        for r in refusals:
            print('::error title=Deploy refused before login (KDEC-036)::%s Nothing was deployed.' % r)
        summary('\n'.join('> **Refused:** %s' % r for r in refusals))
        return 1
    return 0


# ----------------------------------------------------------------------------- deploy, after
def api_post(path, body):
    """POST /repos/<repository>/<path> -> the JSON answer. Any failure raises."""
    base = os.environ.get('GITHUB_API_URL', 'https://api.github.com').rstrip('/')  # unset means github.com
    url = '%s/repos/%s/%s' % (base, env('github_repository'), path)
    req = urllib.request.Request(url, data=json.dumps(body).encode('utf-8'), method='POST',
                                 headers={'Accept': 'application/vnd.github+json', 'Content-Type': 'application/json',
                                          'X-GitHub-Api-Version': '2022-11-28'})
    token = env('gh_token')
    if token and url.startswith(('https://', 'http://127.0.0.1')):
        req.add_unredirected_header('Authorization', 'Bearer %s' % token)
    with urllib.request.urlopen(req, timeout=30) as resp:
        return json.loads(resp.read().decode('utf-8') or '{}')


def sha256_of(path):
    try:
        return hashlib.sha256(io.open(path, 'rb').read()).hexdigest()
    except OSError:
        return ''


def keep_deployment_record(payload, healthy, tier, app_url):
    """G6: a durable record in the GitHub Deployments API. -> (state, ref, why)."""
    desc = ('kit %s %s %s' % (payload.get('routing_result') or '-', payload.get('deployment_outcome') or '-',
                              (payload.get('digest') or '')[:19]))[:140]
    try:
        dep = api_post('deployments', {
            'ref': env('github_sha'), 'task': 'kit-release-record', 'environment': env('deploy_environment'),
            'auto_merge': False, 'required_contexts': [], 'payload': payload, 'description': desc,
            'transient_environment': False, 'production_environment': tier in PRODUCTION_TIERS})
        dep_id = dep.get('id')
        if not dep_id:
            raise ValueError('the deployment answer carries no id')
        run_url = '%s/%s/actions/runs/%s' % (env('github_server_url', 'https://github.com'),
                                             env('github_repository'), env('github_run_id'))
        status = {'state': 'success' if healthy else 'failure', 'description': desc, 'log_url': run_url,
                  'auto_inactive': False}
        if app_url.startswith('https://'):
            status['environment_url'] = app_url
        api_post('deployments/%s/statuses' % dep_id, status)
        return KEPT_DEPLOYMENT, str(dep_id), 'deployment %s with task kit-release-record' % dep_id
    except Exception as exc:  # noqa: BLE001 -- a record not kept is said, by name
        return NOT_KEPT, '', 'the Deployments API refused or could not be reached (%s)' % type(exc).__name__


def cmd_deploy_post(a):
    ev = evidence_dir()
    pre = jload(io.open(os.path.join(ev, 'review-pre.json'), encoding='utf-8').read(), {}) \
        if os.path.exists(os.path.join(ev, 'review-pre.json')) else {}
    tier = env('environment_tier').strip()
    snap = jload(io.open(os.path.join(ev, 'snapshot.json'), encoding='utf-8').read(), {}) \
        if os.path.exists(os.path.join(ev, 'snapshot.json')) else {}
    reality, signals = tier_reality(tier, snap.get('reality'))
    lease_on = bool(env('kit_target_lease_account').strip())
    lease_state = env('d_lease_state') or ('LEASE_NOT_IN_FORCE' if not lease_on else 'not reported')
    seam_state = env('d_seam_ownership') or ('SEAM_OWNERSHIP_NOT_IN_FORCE' if not lease_on else 'not reported')
    promo = os.path.join(env('runner_temp') or '.', 'promotion', 'record', 'promotion-record.json')
    outcome = env('d_deployment_outcome')
    payload = {
        'schema': RELEASE_SCHEMA, 'repository': env('github_repository'), 'run_id': env('github_run_id'),
        'run_attempt': env('github_run_attempt'), 'commit': env('github_sha'), 'environment': env('deploy_environment'),
        'tier': tier, 'adapter': a.adapter, 'digest': env('image_digest'), 'routing_result': env('d_routing_result'),
        'deployment_outcome': outcome, 'release_approval': env('d_release_approval'),
        'release_approval_by': csv(env('d_release_approval_by')), 'zone_readiness': env('d_zone_readiness'),
        'release_block': env('d_release_block'),
        'verdict_provenance': (pre.get('verdict_provenance') or {}).get('state', 'not reported'),
        'weakening_check': (pre.get('weakening_check') or {}).get('state', ''),
        'tier_source': pre.get('tier_source', 'not reported'), 'tier_reality': reality, 'tier_reality_signals': signals,
        'readiness_source': env('d_readiness_source') or 'not reported', 'hosting_kind': pre.get('hosting_kind', ''),
        'lease': lease_state, 'seam': seam_state,
        'kit_source_commit': (pre.get('kit') or {}).get('source_commit', ''),
        'kit_watermark': (pre.get('kit') or {}).get('state', ''),
        'promotion_record_sha256': sha256_of(promo),
        'evidence_artifact': 'deploy-evidence-%s-%s' % (env('github_run_id'), env('github_run_attempt')),
        'retention_days': pre.get('retention_days', AUDIT_FLOOR_DAYS),
    }
    if lease_on:
        rr, rr_ref, rr_why = KEPT_LEASE, '', 'the lease is on: the record is kept create-only in the lease store (K-4)'
    else:
        rr, rr_ref, rr_why = keep_deployment_record(payload, outcome == 'DEPLOY_HEALTHY', tier, env('d_app_url'))
    payload.update(release_record=rr, release_record_ref=rr_ref)
    with io.open(os.path.join(ev, 'review-signals.json'), 'w', encoding='utf-8') as fh:
        json.dump(payload, fh, indent=1, sort_keys=True)
    output(tier_reality=reality, release_record=rr, release_record_ref=rr_ref, lease_state=lease_state,
           seam_state=seam_state, review_signals=json.dumps(payload, sort_keys=True, separators=(',', ':')))
    rows = ['| tier reality (G4) | `%s` | %s |' % (reality, '; '.join(signals) or 'no custom domain or production-like scale read'),
            '| release record (G6) | `%s` | %s |' % (rr, rr_why),
            '| release approval by | `%s` | the approvers read before login |' % (env('d_release_approval_by') or 'none'),
            '| lease / seam | `%s` / `%s` | |' % (lease_state, seam_state)]
    summary('### Reviewer signals after the release (KDEC-036)\n\n| signal | value | detail |\n|---|---|---|\n' + '\n'.join(rows))
    if reality == MISMATCH:
        print('::warning title=%s (KDEC-036)::tier %s, but the target shows %s. Warn only.' % (MISMATCH, tier, '; '.join(signals)))
    if rr == NOT_KEPT:
        print('::error title=%s::%s. Grant the deploy job deployments: write.' % (NOT_KEPT, rr_why))
        return 1
    return 0


# ----------------------------------------------------------------------------- self-test
def self_test():
    fails = []
    d = datetime.date(2026, 11, 3)
    lists = {'deployment-approvers': ['org/security', 'architects'], 'appsec': ['appsec-reviewer']}
    ok = dict(reason='r', authority='release-owner', approver='security', exception_ref='EXC-1', expires='2026-12-01')
    W = weakening_check
    cases = [
        (W(ok, ['dev1'], set(), lists, d, 90)['state'], ATTRIBUTED),
        (W(dict(ok, approver='dev1'), ['dev1'], set(), lists, d, 90)['state'], SELF_APPROVED),
        (W(dict(ok, authority='author1'), ['dev1'], {'author1'}, lists, d, 90)['state'], SELF_APPROVED),
        (W(dict(ok, approver='the team'), ['dev1'], set(), lists, d, 90)['state'], NOT_APPROVED),
        (W(dict(ok, expires=''), ['dev1'], set(), lists, d, 90)['state'], NOT_APPROVED),
        (W(dict(ok, expires='2027-12-01'), ['dev1'], set(), lists, d, 90)['state'], NOT_APPROVED),
        (W(dict(ok, exception_ref=''), ['dev1'], set(), lists, d, 90)['state'], NOT_APPROVED),
        (W(ok, ['dev1'], None, lists, d, 90)['state'], NOT_APPROVED),
        (W(dict(ok, expires='2026-01-01'), ['dev1'], set(), lists, d, 90)['state'], EXPIRED),
        (W(dict(ok, reason=''), ['dev1'], set(), lists, d, 90)['state'], UNATTRIBUTED),
        (W({}, ['dev1'], set(), lists, d, 90)['state'], ''),
        (judge_manual('appsec-reviewer', 'REV-1', '2026-11-01', lists, 'appsec', {'dev1'}, d)[0], True),
        (judge_manual('dev1', 'REV-1', '2026-11-01', lists, 'appsec', {'dev1'}, d)[0], False),
        (judge_verdict('PROCEED', [], None, [])[0], TYPED),
        (judge_verdict('PROCEED', [], {'verdict': {'routing_result': 'BLOCKED'}}, [])[0], CONTRADICTED),
        (judge_verdict('BLOCKED', [], {'verdict': {'routing_result': 'PROCEED'}}, [])[0], FROM_GATE),
        (retention('7'), (AUDIT_FLOOR_DAYS, RET_FLOOR)), (retention(''), (AUDIT_FLOOR_DAYS, RET_DEFAULT)),
        (tier_source('prod', 'landing-zone:lz-1'), TIER_VENDED), (tier_source('prod', ''), TIER_SELF),
        (attestation_ok({'environment': 'prod', 'state': 'READY', 'issuer_role': 'appsec', 'issued_by': 'a',
                         'evidence_ref': 'E-1', 'issued_on': '2026-11-01', 'expires_on': '2026-12-01',
                         'exceptions': []}, 'prod', d)[0], 'READY'),
        (tier_reality('dev', {'custom_domains': ['shop.example']})[0], MISMATCH),
    ]
    for i, (got, want) in enumerate(cases):
        if got != want:
            fails.append('case %d: %r, wanted %r' % (i, got, want))
    if fails:
        print('reviewer_signals self-test FAILED: ' + '; '.join(fails))
        return 2
    print('reviewer_signals self-test ok. The full proof is tests/prove_reviewer_signals.py.')
    return 0


def main(argv=None):
    argv = list(sys.argv[1:] if argv is None else argv)
    if argv[:1] == ['--self-test']:
        return self_test()
    ap = argparse.ArgumentParser(description=__doc__.split('\n')[0])
    sub = ap.add_subparsers(dest='cmd', required=True)
    p = sub.add_parser('discover')
    p.add_argument('--root', default='.')
    p = sub.add_parser('weakening')
    p.add_argument('--central', default='')
    p = sub.add_parser('security')
    p.add_argument('--kit-root', default='')
    p.add_argument('--out', required=True)
    for name in ('deploy-pre', 'deploy-post', 'readiness'):
        p = sub.add_parser(name)
        p.add_argument('--kit-root', default='')
        p.add_argument('--adapter', required=True, choices=sorted(ADAPTER_KINDS))
    a = ap.parse_args(argv)
    return {'discover': cmd_discover, 'weakening': cmd_weakening, 'security': cmd_security,
            'deploy-pre': cmd_deploy_pre, 'deploy-post': cmd_deploy_post, 'readiness': cmd_readiness}[a.cmd](a)


if __name__ == '__main__':
    sys.exit(main())

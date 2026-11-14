#!/usr/bin/env python3
"""THE BASELINE an external finding is matched against, and THE IDENTITY MODEL of that match (KDEC-049).

    Owner ruling 2026-11-11: "It should never drop the vuln it should enhance the existing ticket with
    additional evidence." Reviewer requirements, adopted by the coordinator (KDEC-049 R1-R5): the match is
    made against a SELECTED baseline, never "the latest green run", and against the DURABLE REGISTER, so a
    finding still open but absent from the latest scan still matches; a CVE alone is not the same
    vulnerability; a match that cannot be established is never assumed to be "no match".

WHAT IS MATCHED AGAINST (both, always)

    (a) THE BASELINE RUN: the latest run of the security suite on the repository's default branch that is
        successful, of THIS repository (not a fork), on a commit that is an ancestor of or equal to the
        default-branch head, whose security-report-<attempt> artifact holds findings.json AND
        findings-coverage.json, and whose coverage rows for the finding's capability are all ESTABLISHED
        (the scanner population COMPLETE). Selected by `select()`; its receipt (repository, run id, commit
        SHA, timestamp, artifact digest, completeness) goes into the pull output as `baseline`.
    (b) THE REGISTER: the kit's ticket ledger (.security/ticket-ledger.json, the reconciler's binding store:
        cluster key -> ticket ref/key, members, dispositions, clearance) read from the default branch.
        Every bound cluster is a kit observation here, whether or not the latest scan still reports it.

BASELINE STATES (assurance-taxonomy.yaml :: external_findings_baseline)

    BASELINE_SELECTED      a qualifying run was found; its receipt is recorded
    BASELINE_UNAVAILABLE   no qualifying run (or the runs could not be read)
    BASELINE_PARTIAL       the newest candidate's scanner population for the capability is not COMPLETE
    BASELINE_STALE         the selected run is older than max_age_days (PROPOSED default 7)
    BASELINE_INCOMPATIBLE  the artifact is not the findings/coverage shape this reader knows

    Anything but SELECTED: every item carries `baseline.state`, is routed to triage, its evidence kept.
    The register match (b) still runs: an unavailable baseline is never read as "no match".

MATCH STATES (the identity model; `classify()`)

    MATCHED                       same vulnerability identity AND same affected asset (repository + path;
                                  component too when both sides name one), exactly one kit cluster
    MATCH_SEPARATE_INSTANCE       same identity, a different component or path: a separate affected
                                  instance, linked as related, never merged
    MATCH_AMBIGUOUS               more than one kit cluster qualifies: both kept, flagged, never merged
    MATCH_SCOPE_MISMATCH          same identity and path in a different repository: never merged
    NO_MATCH                      nothing qualifies
"""
import datetime
import hashlib
import io
import json
import os
import re
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

SELECTED = 'BASELINE_SELECTED'
UNAVAILABLE = 'BASELINE_UNAVAILABLE'
PARTIAL = 'BASELINE_PARTIAL'
STALE = 'BASELINE_STALE'
INCOMPATIBLE = 'BASELINE_INCOMPATIBLE'
STATES = (SELECTED, UNAVAILABLE, PARTIAL, STALE, INCOMPATIBLE)

MATCHED = 'MATCHED'
SEPARATE = 'MATCH_SEPARATE_INSTANCE'
AMBIGUOUS = 'MATCH_AMBIGUOUS'
MATCH_SCOPE_MISMATCH = 'MATCH_SCOPE_MISMATCH'
NO_MATCH = 'NO_MATCH'

# PROPOSED defaults (KDEC-049): the scanners whose coverage rows make a capability COMPLETE, the age past
# which a baseline is STALE, and how many runs are examined.
CAPABILITY_SCANNERS = {'SOURCE': ('semgrep', 'codeql', 'bandit', 'gosec', 'gitleaks'),
                       'SOURCE_DEPENDENCY': ('osv-scanner', 'trivy'),
                       'IAC_PLAN': ('checkov',), 'IMAGE': ('trivy-image',)}
MAX_AGE_DAYS = 7
MAX_CANDIDATES = 10
REPORT_PREFIX = 'security-report-'
COVERAGE_SCHEMA = 'findings-coverage/1'


def _now():
    return datetime.datetime.utcnow().replace(microsecond=0)


def _parse_ts(v):
    try:
        return datetime.datetime.strptime(str(v)[:19], '%Y-%m-%dT%H:%M:%S')
    except ValueError:
        return None


def capability_complete(cov, capability):
    """-> (COMPLETE | PARTIAL | INCOMPATIBLE, why). Every APPLICABLE row of the capability's scanners is
    ESTABLISHED, and there is at least one."""
    if not isinstance(cov, dict) or cov.get('schema') != COVERAGE_SCHEMA or not isinstance(cov.get('rows'), list):
        return INCOMPATIBLE, 'findings-coverage.json is not %s' % COVERAGE_SCHEMA
    want = CAPABILITY_SCANNERS.get(capability) or ()
    rows = [r for r in cov['rows'] if isinstance(r, dict) and r.get('scanner') in want
            and str(r.get('applicability') or '').upper() == 'APPLICABLE']
    if not rows:
        return PARTIAL, 'no APPLICABLE coverage row for capability %s (%s)' % (capability, ', '.join(want))
    short = [r['scanner'] for r in rows if not r.get('established')]
    if short:
        return PARTIAL, 'not ESTABLISHED for %s: %s' % (capability, ', '.join(sorted(short)))
    return 'COMPLETE', '%d row(s) ESTABLISHED: %s' % (len(rows), ', '.join(sorted(r['scanner'] for r in rows)))


def select(client, repo, default_branch, capability, now=None, max_age_days=MAX_AGE_DAYS):
    """-> (receipt, observations). Never raises on a read failure: the receipt names it."""
    import evidence_export as ee
    now = now or _now()
    receipt = {'state': UNAVAILABLE, 'repository': repo, 'default_branch': default_branch,
               'capability': capability, 'selected_at': now.strftime('%Y-%m-%dT%H:%M:%SZ'), 'examined': []}
    if client is None:
        receipt['detail'] = 'no API client (the pull job needs actions: read and a token)'
        return receipt, []
    st, br, _h, err = client.get('/repos/%s/branches/%s' % (repo, default_branch))
    head = ((br or {}).get('commit') or {}).get('sha') if isinstance(br, dict) else None
    if err or not head:
        receipt['detail'] = 'the default-branch head could not be read (%s)' % (err or st)
        return receipt, []
    receipt['default_branch_head'] = head
    runs, err, short = ee._get_all(client, '/repos/%s/actions/runs?branch=%s&status=success&per_page=100'
                                   % (repo, default_branch), 'workflow_runs')
    if runs is None:
        receipt['detail'] = 'the runs could not be read (%s)' % err
        return receipt, []
    runs = [r for r in runs if isinstance(r, dict)]
    runs.sort(key=lambda r: (str(r.get('created_at') or ''), ee._int(r.get('id'))), reverse=True)
    partial_seen = None
    for run in runs[:MAX_CANDIDATES * 5]:
        why = []
        if run.get('conclusion') != 'success':
            why.append('conclusion %s' % run.get('conclusion'))
        if run.get('head_branch') != default_branch:
            why.append('branch %s' % run.get('head_branch'))
        if ((run.get('head_repository') or {}).get('full_name') or repo) != repo:
            why.append('a run of another repository')
        if why:
            continue
        if len(receipt['examined']) >= MAX_CANDIDATES:
            break
        row = {'run_id': ee._int(run.get('id')), 'commit_sha': run.get('head_sha'), 'created_at': run.get('created_at')}
        receipt['examined'].append(row)
        sha = str(run.get('head_sha') or '')
        if sha != head:
            _s, cmp_, _h2, cerr = client.get('/repos/%s/compare/%s...%s' % (repo, sha, head))
            if cerr or not isinstance(cmp_, dict) or cmp_.get('status') not in ('ahead', 'identical'):
                row['rejected'] = 'commit is not an ancestor of the default-branch head (%s)' % (
                    cerr or (cmp_ or {}).get('status'))
                continue
        arts, aerr, _sh = ee._get_all(client, '/repos/%s/actions/runs/%s/artifacts?per_page=100' % (repo, row['run_id']),
                                      'artifacts')
        rep = sorted([a for a in arts or [] if str(a.get('name') or '').startswith(REPORT_PREFIX) and not a.get('expired')],
                     key=lambda a: str(a.get('name')), reverse=True)
        if not rep:
            row['rejected'] = 'no unexpired %s<attempt> artifact (%s)' % (REPORT_PREFIX, aerr or 'none listed')
            continue
        files = ee._members(client.download('/repos/%s/actions/artifacts/%s/zip' % (repo, rep[0]['id']))) or {}
        fbody, cbody = files.get('findings.json'), files.get('findings-coverage.json')
        obs, cov = ee._json(fbody or b''), ee._json(cbody or b'')
        if fbody is None or cbody is None or not isinstance(obs, list):
            row['rejected'] = 'the artifact does not hold findings.json and findings-coverage.json'
            receipt.update(state=INCOMPATIBLE, detail=row['rejected'])
            continue
        comp, cwhy = capability_complete(cov, capability)
        if comp != 'COMPLETE':
            row['rejected'] = cwhy
            partial_seen = partial_seen or (comp, cwhy, row)
            continue
        receipt.update(state=SELECTED, run_id=row['run_id'], commit_sha=sha, created_at=run.get('created_at'),
                       artifact=rep[0].get('name'), artifact_digest='sha256:' + hashlib.sha256(fbody).hexdigest(),
                       coverage_digest='sha256:' + hashlib.sha256(cbody).hexdigest(), completeness=cwhy,
                       detail='the latest qualifying run')
        ts = _parse_ts(run.get('created_at'))
        if ts is None or (now - ts).days > max_age_days:
            receipt.update(state=STALE, detail='the latest qualifying run is older than %d day(s)' % max_age_days)
        return receipt, with_cluster_keys([o for o in obs if isinstance(o, dict)], repo)
    if partial_seen and receipt['state'] != INCOMPATIBLE:
        receipt.update(state=PARTIAL if partial_seen[0] == PARTIAL else INCOMPATIBLE, detail=partial_seen[1])
    elif receipt['state'] == UNAVAILABLE:
        receipt['detail'] = 'no successful default-branch run of this repository qualified'
    return receipt, []


def with_cluster_keys(observations, repo):
    """The kit's own cluster key for each observation, computed as the reconciler computes its stamp."""
    import finding_correlation as fc
    views = [dict(o, where=o.get('where') or o.get('canonical_path') or '', finding_subject=o.get('finding_subject') or '')
             for o in observations if o.get('identity')]
    out = []
    for cl in fc.correlate(views)['clusters']:
        members = [views[i] for i in cl['members']]
        ck = cl.get('cluster_key') or fc.cluster_key(members[0]['finding_subject'], members[0]['where'],
                                                     str(members[0]['identity']).lower())
        for m in members:
            out.append(dict(m, cluster_key=ck, repository=repo, register='baseline-run'))
    return out


def register_observations(ledger, repo):
    """The ticket ledger's bound clusters as kit observations (open, closed, dispositioned): a finding still
    bound but absent from the latest scan still matches."""
    out = []
    for ck, e in sorted((ledger or {}).items()):
        if not isinstance(e, dict) or str(ck).startswith('test:') or not re.match(r'^[0-9a-f]{32}$', str(ck)):
            continue
        disp = [m.get('disposition') for m in e.get('members') or [] if isinstance(m, dict) and
                isinstance(m.get('disposition'), dict)]
        for m in e.get('members') or []:
            if not isinstance(m, dict):
                continue
            out.append({'cluster_key': str(e.get('merged_into') or ck), 'repository': repo, 'register': 'ticket-ledger',
                        'identity': m.get('identity'), 'scanner': m.get('scanner'),
                        'rule_id': m.get('rule_id') or m.get('rule'), 'severity': m.get('severity'),
                        'line': m.get('line'), 'cwe': m.get('cwe'),
                        'canonical_path': m.get('canonical_path') or m.get('uri') or m.get('where'),
                        'what_aliases': list(m.get('what_aliases') or m.get('aliases') or []),
                        'component': m.get('component'), 'ref': e.get('ref'), 'key': e.get('key'),
                        'ticket_state': 'closed' if (e.get('clearance') or e.get('closed')) else 'open',
                        'dispositions': disp})
    return out


def _path_eq(a, b):
    a, b = str(a or '').lower().lstrip('/'), str(b or '').lower().lstrip('/')
    return bool(a) and bool(b) and (a == b or a.endswith('/' + b) or b.endswith('/' + a))


def _identity_basis(item, o):
    cves = {a.upper() for a in item.get('aliases', []) if str(a).upper().startswith('CVE-')}
    if cves and cves & {str(a).upper() for a in o.get('what_aliases') or []}:
        return 'kit-finding-cve-path'
    if (item.get('cwe') and str(o.get('cwe') or '').upper() == item['cwe'].upper() and
            item['asset'].get('line') and o.get('line') == item['asset'].get('line')):
        return 'kit-finding-path-line-cwe'
    return ''


def classify(item, kit, repo=None):
    """-> (state, the matching observation or None, basis, related [cluster keys]). See MATCH STATES."""
    path, comp = item['asset']['path'], str(item.get('component') or '').lower()
    irepo = str(item['asset'].get('repository') or '').lower()
    hits, related, scope = {}, set(), set()
    for o in kit:
        basis = _identity_basis(item, o)
        if not basis:
            continue
        orepo = str(o.get('repository') or repo or '').lower()
        ocomp = str(o.get('component') or '').lower()
        same_path = _path_eq(o.get('canonical_path'), path)
        if same_path and orepo and irepo and orepo != irepo:
            scope.add(o.get('cluster_key'))
            continue
        if not same_path or (comp and ocomp and comp != ocomp):
            related.add(o.get('cluster_key'))
            continue
        ck = o.get('cluster_key')
        if ck not in hits or o.get('register') == 'ticket-ledger':
            hits[ck] = (o, basis)
    if len(hits) == 1:
        (o, basis), = hits.values()
        return MATCHED, o, basis, sorted(x for x in related if x)
    if len(hits) > 1:
        return AMBIGUOUS, None, '', sorted(x for x in hits if x)
    if scope:
        return MATCH_SCOPE_MISMATCH, None, '', sorted(x for x in scope if x)
    if related:
        return SEPARATE, None, '', sorted(x for x in related if x)
    return NO_MATCH, None, '', []


REGISTER_READ = 'REGISTER_READ'
REGISTER_NOT_ESTABLISHED = 'REGISTER_NOT_ESTABLISHED'
REGISTER_UNREADABLE = 'REGISTER_UNREADABLE'
register_states = (REGISTER_READ, REGISTER_NOT_ESTABLISHED, REGISTER_UNREADABLE)


def load_register(path):
    """The ticket ledger from a checkout of the default branch -> (ledger dict or None, note)."""
    import reconcile_tickets as rt
    return rt.load_ledger(path)


def read_register(path):
    """-> (ledger dict or None, REGISTER_* state, note). Unlike the reconciler's first-run reading, a MISSING
    register is never an empty one here: matching against nothing would classify every unmatched item as new.
    No path named, or no file at it: REGISTER_NOT_ESTABLISHED (ledger None). Present but unreadable:
    REGISTER_UNREADABLE (ledger None). Read: REGISTER_READ."""
    if not path:
        return None, REGISTER_NOT_ESTABLISHED, ('no register was named (ledger_path empty); no item can be '
                                                'classified as new without it')
    if not os.path.exists(path):
        return None, REGISTER_NOT_ESTABLISHED, ('no register at %s; a missing register is not an empty one, '
                                                'so no item is classified as new' % path)
    led, note = load_register(path)
    if led is None:
        return None, REGISTER_UNREADABLE, note
    return led, REGISTER_READ, note


def main(argv=None):
    import argparse
    import kit_api as ka
    ap = argparse.ArgumentParser(description='Select the baseline run an external pull is matched against.')
    ap.add_argument('--repository', required=True, help='owner/name; the API host comes from GITHUB_API_URL (KDEC-027), never this value')
    ap.add_argument('--default-branch', required=True)
    ap.add_argument('--capability', required=True, choices=sorted(CAPABILITY_SCANNERS))
    ap.add_argument('--max-age-days', type=int, default=MAX_AGE_DAYS)
    ap.add_argument('--out', required=True)
    a = ap.parse_args(argv)
    client, ref = ka.client_from_env()
    receipt, obs = select(client, a.repository, a.default_branch, a.capability, max_age_days=a.max_age_days)
    if client is None:
        receipt['detail'] = 'no API client: %s' % (ref or {}).get('detail')
    io.open(a.out, 'w', encoding='utf-8').write(json.dumps({'receipt': receipt, 'observations': obs}, indent=1,
                                                           sort_keys=True))
    print('%s %s run %s commit %s: %s' % (receipt['state'], a.repository, receipt.get('run_id'), receipt.get('commit_sha'),
                                          receipt.get('detail')))
    return 0


if __name__ == '__main__':
    sys.exit(main())

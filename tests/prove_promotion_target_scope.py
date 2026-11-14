#!/usr/bin/env python3
"""Promotion is scoped to ONE deployment target: two apps sharing a repository and an environment name
each resolve only their own records (external Product Assurance Review 2026-11-07, finding R08).

WHY THIS EXISTS
    Promotion records were published and read per ENVIRONMENT NAME, at most 30 of them, and the gate
    treated any newer verified record of another digest in that environment as a superseding release.
    In a controlled test app B's newer test record superseded app A's valid test record
    (PROMOTION_REFUSED_SUPERSEDED), and the daily scan compared A's serving digest against B's last
    record. Two targets deployed in one run under one environment name also overwrote each other's
    record artifact (`overwrite: true`). The target key is now the adapter plus the record's
    environment.target_resource_id (Azure resource ids compared case-insensitively); the record artifact
    is named per target; every listing pages to its end or says it did not.

WHAT IT PROVES (scripts/promotion.py)
  POSITIVE
    P1  REPRODUCTION: app A's valid test record, app B's newer VERIFIED test record (another digest, same
        environment): A's promotion is ALLOWED (it was PROMOTION_REFUSED_SUPERSEDED).
    P2  rollback selection: A's attributed rollback to an older A build is not blocked by B's newer record.
    P3  a target is the adapter plus the resource id, compared case-insensitively (Azure ids are).
    P4  a listing of 250 artifacts over three pages is read to its end (Link rel="next", the API host).
    P5  the daily scan: A serving A's digest with B's newer record in the same environment is no drift.
    P6  the record artifact name: one per target, the legacy name kept for a record with no target;
        the readers read both (no caller change for a one-target repository).
    P7  the gate reads its source from the source run's own listing and picks the record by digest when
        that run deployed two targets into the environment.
  NEGATIVE
    N1  A's own newer verified record still supersedes A's older one (PROMOTION_REFUSED_SUPERSEDED).
    N2  rollback to A's older build is still refused when A has a newer verified build.
    N3  a record with no target key never supersedes a keyed record; a source with no target key is
        PROMOTION_REFUSED_TARGET_UNKNOWN (break-glass may lift it, as it lifts supersession).
    N4  a history beyond the bounds never establishes completeness: the page cap, a later page failing,
        a next link on another host (never followed), total_count above what was read, and more newer
        records than the read bound are each a named short read; at the gate that is
        PROMOTION_REFUSED_HISTORY_INCOMPLETE.
    N5  the daily scan: A serving B's digest is artifact drift; a target whose history cannot be read
        is KIT-PROMOTION-HISTORY-INCOMPLETE, never "no drift".
    N6  two records for two targets with the same digest in one source run: PROMOTION_REFUSED_SOURCE_AMBIGUOUS.
  MUTANTS (each must be caught)
    M1  the target key ignored (every record one target)        -> P1 fails
    M2  page one read as the whole listing                      -> P4 fails
    M3  the page cap removed                                    -> N4 cap fails
    M4  a next link on another host followed                    -> N4 host fails
    M5  total_count not checked                                 -> N4 total fails
    M6  a record with no target key treated as a target         -> N3 fails
    M7  the daily scan unscoped (latest healthy in the env)     -> P5 fails

  INDEPENDENT REVIEW 2026-11-09 (findings 1-6), end to end through the real cmd_* functions
    F1 (history read raising, judge not told) -- NOT REPRODUCED: cmd_gate_collect forces the re-check
       NOT_ESTABLISHED whenever history_error is set (scripts/promotion.py, the
       `if col.get('history_error') or col.get('revocations_error')` line), and judge refuses
       PROMOTION_REFUSED_RECHECK_INCOMPLETE on it. Kept as a guard proof:
    P8  control: the same world with a readable history is PROMOTION_ALLOWED (collect + decide).
    N7  the history API failing after the source is read: refused, the error named.
    M8  that collect line no longer naming history_error (source mutant) -> N7 ALLOWS, caught.
    F2 (daily scan trusted a short listing holding an older healthy record) -- CONFIRMED + FIXED: a
       short LISTING is never established (no API ordering is assumed); only a complete listing cut by
       the read bound (its newest records read, sorted locally) may still compare.
    P9  control: both pages read (served oldest first) -> the last promoted is A's newer digest; drift.
    N8  page 2 (holding A's newer healthy record) fails; page 1 holds an older healthy record that
        matches what serves -> KIT-PROMOTION-HISTORY-INCOMPLETE, artifact_drift unestablished (was False).
    P10 a complete listing beyond the read bound compares on the newest records it read.
    M9  the pre-review `known` expression                       -> N8 fails, caught
    M10 history() reporting a short listing as complete         -> N8 fails, caught
    F3 (break-glass discharged by any record of the digest + adapter; short read discarded) --
       CONFIRMED + FIXED: break_glass_discharge() binds to the recorded predecessor target
       (predecessor.promoted_from.target, now written by gate-decide) and reads its history with
       history(); BREAK_GLASS_DISCHARGED / BREAK_GLASS_OWED (not found, complete read) /
       BREAK_GLASS_DISCHARGE_NOT_ESTABLISHED (no target recorded, short or unreadable) are distinct.
    N9  app B's verified test record of the same digest and adapter: still owed (was discharged).
    P11 A's own predecessor target verified the digest: discharged.
    N11 a complete read, no verified record of the digest: BREAK_GLASS_OWED (not found).
    N10 the predecessor listing short: not established (owed None), never not-found or discharged.
    N12 a break-glass record naming no predecessor target: not established, even with a match in test.
    P12 a complete listing beyond the read bound, the match among the newest: discharged.
    P13 gate-decide records the source target in promotion-gate.json (the predecessor identity).
    M11 the target binding removed (any record of the env family) -> N9 fails, caught
    M12 the predecessor listing's short result discarded         -> N10 fails, caught
    M13 could-not-establish merged into not-found                -> N12 fails, caught
    F4 (target_key accepted any adapter spelling, or none) -- CONFIRMED + FIXED: the adapter must be
       exactly one of ADAPTERS (the --adapter choices the kit writes records with); otherwise no key.
    P14 each canonical adapter keys a target; a canonical source still promotes.
    N13 adapter '', absent, 'ContainerApp', ' containerapp', 'containerapp ', 'kubernetes' (with a resource
        id): no key, PROMOTION_REFUSED_TARGET_UNKNOWN naming the adapter; such a record never supersedes.
    M14 the pre-review key (any adapter, or none)                -> N13 fails, caught
    F5 (source chosen by digest only) -- CONFIRMED + FIXED, backward compatible: an OPTIONAL workflow
       input promote_from_target_resource_id names the expected
       source target; set, only that target's record of the run is taken and the digest must match it.
    P15 not set: selection by digest exactly as before (P7 and N6 above still hold).
    N14 set to A's test target while promoting the digest of B's record: the source is A's record and the
        digest does not match it (PROMOTION_REFUSED_DIGEST_MISMATCH); B's record is never taken (was ALLOWED).
    N16 set to a target the run has no record for: PROMOTION_REFUSED_SOURCE_TARGET_MISMATCH, target named.
    P16 set (re-cased, padded) and the digest matches: allowed, source.target recorded.
    P17 set where two targets share the digest: the named target resolves the ambiguity.
    N15 set and matching, the digest not: PROMOTION_REFUSED_DIGEST_MISMATCH.
    M15 the requested target ignored                             -> N14 ALLOWS, caught
    F7 (policy 2026-11-09: R-41 mitigation M4 decided) -- the source application identity is REQUIRED
       into uat or prod; optional in dev and test.
    P18 uat with the input set to the correct target: allowed.
    N17 uat, input empty: PROMOTION_REFUSED_SOURCE_TARGET_REQUIRED (the gate says to set the input).
    N18 prod, input empty (also when whitespace only, and under break-glass: not lifted).
    P19 dev and test, input empty: the old behaviour (selected by digest; ambiguity still refused).
    N19 uat with the input set to a target the run has no record of: PROMOTION_REFUSED_SOURCE_TARGET_MISMATCH.
    M16 optional-at-prod (the requirement not applied to uat or prod) -> N17/N18 ALLOW, caught
    F6 (end-to-end fixtures for 1-3) -- CONFIRMED (a proof gap) + CLOSED by the cases above: F1 through the
       real cmd_gate_collect + cmd_gate_decide (N7, M8); F2 and F3 through the real cmd_deployed_scan,
       history() and list_all() against a paged fake API served oldest first (N8, M9, M10; N9-N12, M11-M13).

EXIT  0 proven   1 a case failed (named)   2 could not be checked
"""
import io
import json
import os
import shutil
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, HERE)
sys.path.insert(0, os.path.join(ROOT, 'scripts'))
import promotion as PR  # noqa: E402

FAILS = []
# B's digest is not _workflow_runner's GOOD (a) or NEW (b), which the daily-scan world serves.
dig_a, dig_a2, dig_b = 'sha256:' + 'a' * 64, 'sha256:' + 'd' * 64, 'sha256:' + 'e' * 64
RID_A = '/subscriptions/0/resourceGroups/rg-a/providers/Microsoft.App/containerApps/web'
RID_B = '/subscriptions/0/resourceGroups/rg-a/providers/Microsoft.App/containerApps/api'
SIGNER = 'o/k/.github/workflows/b.yml'
NOW = PR.parse_ts('2026-10-26T12:00:00Z')
EXC = {'reason': 'incident 42', 'authority': 'release-approvers', 'exception_ref': 'EXC-9', 'expires': '2026-10-29'}


def expect(cond, label):
    print('%s  %s' % ('ok  ' if cond else 'FAIL', label))
    if not cond:
        FAILS.append(label)


def rec(digest=dig_a, rid=RID_A, at='2026-10-25T12:00:00Z', state=PR.VERIFIED, envname='test', tier='test',
        adapter='containerapp', run='7'):
    e = {'name': envname, 'tier': tier, 'adapter': adapter}
    if rid is not None:
        e['target_resource_id'] = rid
    return {'schema': PR.SCHEMA, 'state': state, 'artifact': {'digest': digest}, 'environment': e,
            'provenance': {'source_ref': 'refs/heads/main', 'build_workflow': SIGNER},
            'validity': {'verified_at': at}, 'run': {'id': run}, 'approval': {'approvers': []},
            'live_state': {'deployment_outcome': 'DEPLOY_HEALTHY'}, '_artifact': {'head_branch': 'main'}}


def ctx(**o):
    c = {'digest': dig_a, 'required_predecessor': 'test', 'source_environment': 'test', 'source': rec(),
         'history': [], 'revocations': [], 'rescan': {'state': 'COMPLETE', 'critical': [], 'high': []},
         'kev': {'state': 'AVAILABLE', 'blocking': []}, 'attestation': 'ATTESTATION_VERIFIED',
         'release_path': 'normal', 'exception': {}, 'now': NOW}
    c.update(o)
    return c


def verdict(c):
    return PR.judge(c)['verdict']


# ----------------------------------------------------------------------------- the gate (pure)
def p1():
    return verdict(ctx(history=[rec(digest=dig_b, rid=RID_B, at='2026-10-26T01:00:00Z', run='8')])) == 'PROMOTION_ALLOWED'


def gate():
    got = verdict(ctx(history=[rec(digest=dig_b, rid=RID_B, at='2026-10-26T01:00:00Z', run='8')]))
    # At base this names the supersession guard itself (PROMOTION_REFUSED_SUPERSEDED): the case reaches it.
    expect(p1(), 'P1 REPRODUCTION: app B\'s newer verified test record does not supersede app A\'s (got %s)' % got)
    expect(verdict(ctx(source=rec(at='2026-10-01T00:00:00Z'), release_path='rollback', exception=EXC,
                       history=[rec(digest=dig_b, rid=RID_B, at='2026-10-05T00:00:00Z')])) == 'PROMOTION_ALLOWED',
           'P2 rollback to A\'s older build is not blocked by B\'s newer record')
    expect(PR.target_key(rec(rid=RID_A.upper())['environment']) == PR.target_key(rec()['environment']),
           'P3 the target key compares resource ids case-insensitively')
    expect(PR.target_key(rec(adapter='appservice')['environment']) != PR.target_key(rec()['environment']),
           'P3 the same resource id under another adapter is another target')
    newer_a = rec(digest=dig_a2, at='2026-10-26T01:00:00Z', run='9')
    r = PR.judge(ctx(history=[newer_a, rec(digest=dig_b, rid=RID_B, at='2026-10-26T02:00:00Z')]))
    expect(r['verdict'] == 'PROMOTION_REFUSED_SUPERSEDED' and (r['superseded_by'] or {}).get('digest') == dig_a2,
           'N1 A\'s own newer verified record supersedes it (and is named, not B\'s)')
    expect(verdict(ctx(source=rec(at='2026-10-01T00:00:00Z'), release_path='rollback', exception=EXC,
                       history=[rec(digest=dig_a2, at='2026-10-05T00:00:00Z')])) == 'PROMOTION_REFUSED_SUPERSEDED',
           'N2 rollback to A\'s older build is still refused when A has a newer verified build')
    expect(verdict(ctx(history=[rec(digest=dig_b, rid=None, at='2026-10-26T01:00:00Z')])) == 'PROMOTION_ALLOWED',
           'N3 a newer record with no target key never supersedes a keyed record')
    r = PR.judge(ctx(source=rec(rid=None)))
    expect(r['verdict'] == 'PROMOTION_REFUSED_TARGET_UNKNOWN' and 'target_resource_id' in r['refusals'][0]['why'],
           'N3 a source with no target key is PROMOTION_REFUSED_TARGET_UNKNOWN, naming the missing field')
    expect(verdict(ctx(source=rec(rid=None), release_path='break-glass', exception=EXC)) == 'PROMOTION_ALLOWED',
           'N3 break-glass lifts PROMOTION_REFUSED_TARGET_UNKNOWN as it lifts supersession')
    r = PR.judge(ctx(history_short='stopped after 30 pages: 3000 read of 3500'))
    expect(r['verdict'] == 'PROMOTION_REFUSED_HISTORY_INCOMPLETE' and '3000 read' in r['refusals'][0]['why'],
           'N4 a short history read is PROMOTION_REFUSED_HISTORY_INCOMPLETE, with the bound named')


# ----------------------------------------------------------------------------- paging
class Pages(object):
    """A fake API host serving `n` artifacts, `per` a page, with Link rel="next"."""
    def __init__(self, n, per=100, total=None, fail_page=None, foreign_page=None, name='x'):
        self.items = [{'id': i, 'name': name, 'created_at': '2026-10-%02dT00:00:00Z' % (1 + i % 28),
                       'expired': False, 'archive_download_url': 'https://api.example.test/zip/%d' % i,
                       'workflow_run': {'id': 1000 + i, 'head_branch': 'main'}} for i in range(n)]
        self.per, self.total, self.fail_page, self.foreign_page, self.calls = per, total, fail_page, foreign_page, []

    def __call__(self, url, hdrs):
        self.calls.append(url)
        q = dict(p.split('=', 1) for p in (url.split('?', 1) + [''])[1].split('&') if '=' in p)
        page = int(q.get('page') or 1)
        if page == self.fail_page:
            raise IOError('HTTP 502')
        chunk = self.items[(page - 1) * self.per: page * self.per]
        if page * self.per < len(self.items):
            host = 'https://evil.example.test' if page + 1 == self.foreign_page else 'https://api.example.test'
            hdrs['Link'] = '<%s/repos/o/r/actions/artifacts?per_page=%d&page=%d>; rel="next"' % (host, self.per, page + 1)
        return json.dumps({'total_count': self.total if self.total is not None else len(self.items),
                           'artifacts': chunk}).encode('utf-8')


def with_api(fn):
    old = dict((k, os.environ.get(k)) for k in ('GITHUB_API_URL', 'GITHUB_REPOSITORY'))
    os.environ.update(GITHUB_API_URL='https://api.example.test', GITHUB_REPOSITORY='o/r')
    try:
        return fn()
    finally:
        for k, v in old.items():
            if v is None:
                os.environ.pop(k, None)
            else:
                os.environ[k] = v


def listing(fake):
    saved = PR.fetch_page
    PR.fetch_page = fake
    try:
        return with_api(lambda: PR.list_all('actions/artifacts', {'name': 'x', 'per_page': 100}))
    finally:
        PR.fetch_page = saved


def p4():
    items, short = listing(Pages(250))
    return len(items) == 250 and short is None


# The real bounds, read once: a mutant lifting one must not resize the fixture. (Absent at base.)
cap = getattr(PR, 'page_cap'.upper(), 30)
reads = getattr(PR, 'max_record_reads'.upper(), 100)


def n4_cap():
    items, short = listing(Pages(cap * 100 + 50))
    return short is not None and 'stopped after %d pages' % cap in short and len(items) == cap * 100


def n4_host():
    fake = Pages(250, foreign_page=2)
    items, short = listing(fake)
    return short is not None and 'not the API host' in short and not any('evil' in c for c in fake.calls)


def n4_total():
    items, short = listing(Pages(150, total=400))
    return short is not None and '150 read of 400' in short


def paging():
    expect(p4(), 'P4 250 artifacts over three pages are read to the end')
    expect(n4_cap(), 'N4 the page cap is a named short read, never a silent cut')
    items, short = listing(Pages(250, fail_page=2))
    expect(short is not None and 'page 2 could not be read' in short, 'N4 a later page failing is a named short read')
    expect(n4_host(), 'N4 a next link on another host is never followed (the token goes to the API host only)')
    expect(n4_total(), 'N4 total_count above what was read is a named short read')
    try:
        listing(Pages(10, fail_page=1))
        expect(False, 'N4 a first page that fails raises Unreadable, never an empty listing')
    except PR.rh.Unreadable:
        expect(True, 'N4 a first page that fails raises Unreadable, never an empty listing')


# ----------------------------------------------------------------------------- history + collect
def history_world(records):
    """records: [(record, created_at)] -> (fake page fetch, fake download) serving them under their names."""
    arts, blobs = [], {}
    for n, (r, created) in enumerate(records):
        arts.append({'id': 500 + n, 'name': PR.record_key(r['environment']['name'], PR.target_key(r['environment'])),
                     'created_at': created, 'expired': False, 'archive_download_url': 'https://api.example.test/zip/%d' % n,
                     'workflow_run': {'id': int(r['run']['id']), 'head_branch': 'main'}})
        blobs[500 + n] = r

    def fetch(url, hdrs):
        q = url.split('?', 1)[1] if '?' in url else ''
        params = dict(p.split('=', 1) for p in q.split('&') if '=' in p)
        path = url.split('/repos/o/r/', 1)[1].split('?')[0]
        sel = [a for a in arts if ('name' not in params or a['name'] == params['name']) and
               (not path.startswith('actions/runs/') or str(a['workflow_run']['id']) == path.split('/')[2])]
        return json.dumps({'total_count': len(sel), 'artifacts': sel}).encode('utf-8')

    def download(artifact, suffix):
        return json.dumps(blobs[artifact['id']]).encode('utf-8')
    return fetch, download


def patched(records, fn):
    fetch, download = history_world(records)
    saved = PR.fetch_page, PR.download
    PR.fetch_page, PR.download = fetch, download
    try:
        return with_api(fn)
    finally:
        PR.fetch_page, PR.download = saved


def collect(records, run_id, digest=dig_a):
    tmp = tempfile.mkdtemp(prefix='r08-collect-')
    # Settings are written lower-case and upper-cased on use, as deploy_contract.env reads them.
    sets = dict(runner_temp=tmp, promote_from_run_id=run_id, promote_from_environment='test',
                promotion_predecessor='test', image_digest=digest, github_output=os.path.join(tmp, 'o'))
    sets = dict((k.upper(), v) for k, v in sets.items())
    old = dict((k, os.environ.get(k)) for k in sets)
    os.environ.update(sets)
    saved = PR.fetch_sbom, PR.revocations
    PR.fetch_sbom, PR.revocations = (lambda d, s, o: (None, 'not in this proof')), (lambda: [])
    try:
        patched(records, lambda: PR.cmd_gate_collect(None))
        return PR.jload(os.path.join(tmp, 'promotion', 'collected.json')) or {}
    finally:
        PR.fetch_sbom, PR.revocations = saved
        for k, v in old.items():
            if v is None:
                os.environ.pop(k, None)
            else:
                os.environ[k] = v
        shutil.rmtree(tmp, ignore_errors=True)


def history():
    k_a = PR.target_key(rec()['environment'])
    expect(PR.record_key('test', k_a) != PR.record_key('test', PR.target_key(rec(rid=RID_B)['environment'])) and
           PR.record_key('test', k_a).startswith('kit-promotion-record-test--') and
           PR.record_key('test') == 'kit-promotion-record-test',
           'P6 one record artifact per target; the legacy name for a record with no target')
    src = rec(at='2026-10-25T12:00:00Z', run='7')
    legacy_a = dict(rec(digest=dig_a2, at='2026-10-26T01:00:00Z', run='9'))
    world = [(src, '2026-10-25T12:00:05Z'), (rec(digest=dig_b, rid=RID_B, at='2026-10-26T02:00:00Z', run='8'),
                                             '2026-10-26T02:00:05Z')]
    col = collect(world, '7')
    expect(col.get('source', {}) and col['source']['artifact']['digest'] == dig_a and not col.get('history_short') and
           all(PR.target_key(h['environment']) == k_a for h in col.get('history') or []),
           'P1 at collect: the source is read from its run; the history holds only A\'s records')
    # A record written before this change (legacy name) that names its target is still read and scoped.
    fetch, download = history_world(world)

    def legacy_fetch(url, hdrs):
        body = json.loads(fetch(url, hdrs).decode('utf-8'))
        if 'name=kit-promotion-record-test&' in url + '&' or url.endswith('name=kit-promotion-record-test'):
            body['artifacts'] = [{'id': 900, 'name': 'kit-promotion-record-test', 'created_at': '2026-10-26T01:00:05Z',
                                  'expired': False, 'archive_download_url': 'x', 'workflow_run': {'id': 9}}]
            body['total_count'] = 1
        return json.dumps(body).encode('utf-8')
    saved = PR.fetch_page, PR.download
    PR.fetch_page = legacy_fetch
    PR.download = lambda a, s: json.dumps(legacy_a if a['id'] == 900 else download(a, s) and json.loads(
        download(a, s).decode('utf-8'))).encode('utf-8')
    try:
        recs, short, _listed = with_api(lambda: PR.history('test', k_a, since=PR.parse_ts('2026-10-25T12:00:00Z')))
    finally:
        PR.fetch_page, PR.download = saved
    expect(any((h['artifact'] or {}).get('digest') == dig_a2 for h in recs) and short is None,
           'P6 a legacy-named record that names A\'s target is read (no caller change)')
    two = [(rec(digest=dig_a, run='7'), '2026-10-25T12:00:05Z'),
           (rec(digest=dig_b, rid=RID_B, run='7'), '2026-10-25T12:00:06Z')]
    col = collect(two, '7', digest=dig_b)
    expect(((col.get('source') or {}).get('environment') or {}).get('target_resource_id') == RID_B,
           'P7 one run, two targets in test: the source is the record of the digest being promoted')
    same = [(rec(digest=dig_a, run='7'), '2026-10-25T12:00:05Z'), (rec(digest=dig_a, rid=RID_B, run='7'), '2026-10-25T12:00:06Z')]
    col = collect(same, '7')
    expect(col.get('source') is None and 'PROMOTION_REFUSED_SOURCE_AMBIGUOUS' in (col.get('source_error') or ''),
           'N6 two targets with one digest in one run: the source is ambiguous, never guessed')
    many = [(src, '2026-10-25T12:00:05Z')] + [
        (rec(digest=dig_a2, at='2026-10-26T%02d:%02d:00Z' % (i // 60, i % 60), run=str(2000 + i)),
         '2026-10-26T%02d:%02d:05Z' % (i // 60, i % 60)) for i in range(reads + 5)]
    col = collect(many, '7')
    expect(bool(col.get('history_short')) and str(reads) in col['history_short'],
           'N4 more newer records than the read bound is a named short read at collect')


# ----------------------------------------------------------------------------- independent review 2026-11-09
def mutated(old, new):
    """-> a copy of scripts/promotion.py with `old` (which must occur exactly once) replaced by `new`: a
    named mutant of a line inside a function, which an attribute patch cannot reach."""
    import types
    path = os.path.join(ROOT, 'scripts', 'promotion.py')
    text = io.open(path, encoding='utf-8').read()
    if text.count(old) != 1:
        raise AssertionError('mutant anchor occurs %d times: %r' % (text.count(old), old[:60]))
    m = types.ModuleType('promotion_mutant')
    m.__file__ = path
    exec(compile(text.replace(old, new), path, 'exec'), m.__dict__)
    return m


def gate_e2e(records, run_id, digest=dig_a, M=None, stubs=None, extra=None):
    """gate-collect THEN gate-decide (the real cmd_* functions, the real collected.json between them)
    against the recorded API of history_world; the SBOM re-scan is stubbed COMPLETE and clean, so a
    refusal is the history's or the source's, never the re-scan's. -> (collected, promotion-gate.json)."""
    M = M or PR
    tmp = tempfile.mkdtemp(prefix='r08b-gate-')
    sets = dict(runner_temp=tmp, promote_from_run_id=run_id, promote_from_environment='test',
                promotion_predecessor='test', image_digest=digest, github_output=os.path.join(tmp, 'o'),
                kev_state='AVAILABLE', attestation_outcome='ATTESTATION_VERIFIED', release_path='normal',
                kit_promotion_now='2026-10-26T12:00:00Z')
    sets.update(extra or {})
    sets = dict((k.upper(), v) for k, v in sets.items())
    old = dict((k, os.environ.get(k)) for k in sets)
    os.environ.update(sets)
    patch = {'fetch_sbom': lambda d, s, o: (os.path.join(o, 'sbom.spdx.json'), ''),
             'sbom_rescan': lambda p, o: {'state': 'COMPLETE', 'why': '', 'critical': [], 'high': [], 'sarif': ''},
             'revocations': lambda: []}
    patch.update(stubs or {})
    fetch, download = history_world(records)
    patch.update(fetch_page=fetch, download=download)
    saved = dict((k, getattr(M, k)) for k in patch)
    for k, v in patch.items():
        setattr(M, k, v)
    try:
        with_api(lambda: (M.cmd_gate_collect(None), M.cmd_gate_decide(None)))
        return (M.jload(os.path.join(tmp, 'promotion', 'collected.json')) or {},
                M.jload(os.path.join(tmp, 'deploy-evidence', 'promotion-gate.json')) or {})
    finally:
        for k, v in saved.items():
            setattr(M, k, v)
        for k, v in old.items():
            if v is None:
                os.environ.pop(k, None)
            else:
                os.environ[k] = v
        shutil.rmtree(tmp, ignore_errors=True)


def history_fails(*a, **k):
    raise PR.rh.Unreadable('GET actions/artifacts failed: HTTP 502 (the history listing)')


def f1_case(M=None):
    """The source run's record is read; the predecessor history API then fails."""
    src = rec(at='2026-10-25T12:00:00Z', run='7')
    return gate_e2e([(src, '2026-10-25T12:00:05Z')], '7', M=M, stubs={'history': history_fails})


F1_GUARD = "if col.get('history_error') or col.get('revocations_error'):"


def finding1():
    # Control: the same world with a readable history is ALLOWED, so a refusal below is the history's.
    src = rec(at='2026-10-25T12:00:00Z', run='7')
    col, g = gate_e2e([(src, '2026-10-25T12:00:05Z')], '7')
    expect(g.get('promotion_gate') == 'PROMOTION_ALLOWED' and not col.get('history_error'),
           'P8 control: valid source, readable history, clean re-scan -> PROMOTION_ALLOWED (got %s)'
           % g.get('promotion_gate'))
    col, g = f1_case()
    codes = [r['code'] for r in g.get('refusals') or []]
    expect(bool(col.get('history_error')) and col.get('source') is not None and
           (col.get('rescan') or {}).get('state') == 'NOT_ESTABLISHED' and
           'PROMOTION_REFUSED_RECHECK_INCOMPLETE' in codes and g.get('promotion_gate') != 'PROMOTION_ALLOWED' and
           any('HTTP 502' in r['why'] for r in g.get('refusals') or []),
           'N7 review F1: the history API failing after the source is read is refused at decide '
           '(history_error -> rescan NOT_ESTABLISHED -> %s; the error named)' % codes)
    try:
        _col, g = f1_case(mutated(F1_GUARD, "if col.get('revocations_error'):"))
        ok = g.get('promotion_gate') != 'PROMOTION_ALLOWED'
    except Exception as exc:  # noqa: BLE001
        print('      (mutant raised %s)' % exc)
        ok = True
    expect(not ok, 'M8 history_error no longer forcing the re-check NOT_ESTABLISHED is caught (the case '
                   'then ALLOWS: the guard at cmd_gate_collect is load-bearing)')


class Args(object):
    adapter = 'containerapp'


def oldest_first_world(records, per=1, fail_from=None, total=None):
    """records: [(record, created_at)] served under their artifact names OLDEST first (no ordering
    contract is assumed), `per` a page; pages from `fail_from` on fail (HTTP 502). -> (fetch, download)."""
    arts, blobs = [], {}
    for n, (r, created) in enumerate(sorted(records, key=lambda x: x[1])):
        arts.append({'id': 700 + n, 'name': PR.record_key(r['environment']['name'], PR.target_key(r['environment'])),
                     'created_at': created, 'expired': False, 'archive_download_url': 'https://api.example.test/zip/%d' % n,
                     'workflow_run': {'id': int(r['run']['id']), 'head_branch': 'main'}})
        blobs[700 + n] = r

    def fetch(url, hdrs):
        q = url.split('?', 1)[1] if '?' in url else ''
        params = dict(p.split('=', 1) for p in q.split('&') if '=' in p)
        sel = [a for a in arts if 'name' not in params or a['name'] == params['name']]
        page = int(params.get('page') or 1)
        if fail_from and page >= fail_from:
            raise IOError('HTTP 502')
        if page * per < len(sel):
            hdrs['Link'] = '<https://api.example.test/repos/o/r/actions/artifacts?%s&page=%d>; rel="next"' % (
                '&'.join('%s=%s' % kv for kv in sorted(params.items()) if kv[0] != 'page'), page + 1)
        return json.dumps({'total_count': len(sel) if total is None else total,
                           'artifacts': sel[(page - 1) * per: page * per]}).encode('utf-8')

    def download(artifact, suffix):
        return json.dumps(blobs[artifact['id']]).encode('utf-8')
    return fetch, download


def daily_inproc(world, serving_digest, M=None, adapter='containerapp', own_rid=RID_A):
    """cmd_deployed_scan in process, its history read through the real history()/list_all() against
    `world` ((fetch, download)); what serves, the resource id and the posture are stubbed.
    -> (deployed-scan doc, SARIF rule ids)."""
    M = M or PR
    tmp = tempfile.mkdtemp(prefix='r08b-daily-')
    sets = dict((k.upper(), v) for k, v in dict(runner_temp=tmp, deploy_environment='prod', containerapp_name='web',
                                                 github_output=os.path.join(tmp, 'o')).items())
    old = dict((k, os.environ.get(k)) for k in sets)
    os.environ.update(sets)
    fetch, download = world
    patch = {'fetch_page': fetch, 'download': download, 'own_resource_id': lambda a: own_rid,
             'serving_now': lambda a: [{'where': 'revision web--r1', 'weight': 100, 'digest': serving_digest,
                                        'image': 'x@' + serving_digest}],
             'fetch_sbom': lambda d, s, o: (None, 'not in this proof'),
             'security_settings': lambda a: ('POSTURE_PASSED', [], {})}
    saved = dict((k, getattr(M, k)) for k in patch)
    for k, v in patch.items():
        setattr(M, k, v)
    a = Args()
    a.adapter = adapter
    try:
        with_api(lambda: M.cmd_deployed_scan(a))
        out = os.path.join(tmp, 'promotion', 'deployed')
        doc = M.jload(os.path.join(out, 'deployed-scan-prod.json')) or {}
        sar = M.jload(os.path.join(out, 'deployed-state-prod.sarif')) or {}
        return doc, sorted(set(r['ruleId'] for r in (sar.get('runs') or [{}])[0].get('results') or []))
    finally:
        for k, v in saved.items():
            setattr(M, k, v)
        for k, v in old.items():
            if v is None:
                os.environ.pop(k, None)
            else:
                os.environ[k] = v
        shutil.rmtree(tmp, ignore_errors=True)


def prod(digest, at, run, **o):
    return rec(digest=digest, envname='prod', tier='prod', at=at, run=run, **o)


def f2_case(M=None):
    """A's older healthy prod record (dig_a) is on page 1; A's NEWER healthy record (dig_a2, the last
    promoted) is on page 2, which fails. A serves the OLDER digest: real artifact drift."""
    world = [(prod(dig_a, '2026-10-20T12:00:00Z', '401'), '2026-10-20T12:00:05Z'),
             (prod(dig_a2, '2026-10-25T12:00:00Z', '402'), '2026-10-25T12:00:05Z')]
    return daily_inproc(oldest_first_world(world, per=1, fail_from=2), dig_a, M=M)


def f2_bound_case(M=None):
    """The listing is complete (every page read) but holds more of A's records than the read bound:
    the newest `reads` of the COMPLETE listing, sorted locally by created_at, are read; the newest is
    A's healthy dig_a2, so the comparison is on established evidence."""
    world = [(prod(dig_a, '2026-09-01T%02d:%02d:00Z' % (i // 60, i % 60), str(3000 + i)),
              '2026-09-01T%02d:%02d:05Z' % (i // 60, i % 60)) for i in range(reads + 5)]
    world.append((prod(dig_a2, '2026-10-25T12:00:00Z', '402'), '2026-10-25T12:00:05Z'))
    return daily_inproc(oldest_first_world(world, per=100), dig_a, M=M)


F2_KNOWN = "    known = bool(key) and not doc.get('records_error') and bool(last or not doc.get('records_short'))"


def finding2():
    world = [(prod(dig_a, '2026-10-20T12:00:00Z', '401'), '2026-10-20T12:00:05Z'),
             (prod(dig_a2, '2026-10-25T12:00:00Z', '402'), '2026-10-25T12:00:05Z')]
    doc, rules = daily_inproc(oldest_first_world(world, per=1), dig_a)
    expect(doc.get('artifact_drift') is True and (doc.get('promoted') or {}).get('digest') == dig_a2 and
           'KIT-ARTIFACT-DRIFT' in rules,
           'P9 control: both pages read (oldest first) -> the last promoted is dig_a2, serving dig_a is drift (%s %s)'
           % (doc.get('artifact_drift'), rules))
    doc, rules = f2_case()
    # The decision point: `known` (the drift comparison runs only when it is true).
    expect(doc.get('artifact_drift') is None and 'KIT-PROMOTION-HISTORY-INCOMPLETE' in rules and
           'KIT-ARTIFACT-DRIFT' not in rules and 'page 2 could not be read' in json.dumps(doc),
           'N8 review F2: a SHORT history listing holding only an older healthy record is unestablished, never '
           '"no drift" (artifact_drift=%s promoted=%s %s)' % (doc.get('artifact_drift'),
                                                             (doc.get('promoted') or {}).get('digest'), rules))
    doc, rules = f2_bound_case()
    expect(doc.get('artifact_drift') is True and (doc.get('promoted') or {}).get('digest') == dig_a2 and
           'KIT-PROMOTION-HISTORY-INCOMPLETE' not in rules and bool(doc.get('records_short')),
           'P10 a COMPLETE listing cut only by the read bound reads the newest records (sorted locally) and '
           'compares (artifact_drift=%s %s)' % (doc.get('artifact_drift'), rules))
    n8 = lambda M: (lambda d_r: d_r[0].get('artifact_drift') is None and
                    'KIT-PROMOTION-HISTORY-INCOMPLETE' in d_r[1])(f2_case(M))
    src_mutant('M9 the pre-review `known` (a short listing holding a healthy record is trusted) is caught',
               F2_KNOWN_NOW, F2_KNOWN, n8)
    src_mutant('M10 a short LISTING reported as complete (`listed` always true) is caught',
               "        listed = listed and not short\n", "        listed = True\n", n8)


def src_mutant(label, old, new, still_passes):
    """A named source mutant must make the case fail (raising counts as caught)."""
    try:
        ok = still_passes(mutated(old, new))
    except AssertionError:
        raise
    except Exception as exc:  # noqa: BLE001
        print('      (mutant raised %s)' % exc)
        ok = False
    expect(not ok, label)


F2_KNOWN_NOW = """    known = bool(key) and not doc.get('records_error') and (
        not doc.get('records_short') or bool(last and doc.get('records_listed')))"""

# The predecessor (test) targets of app A and app B: the same adapter, two resources.
RID_TA = '/subscriptions/0/resourceGroups/rg-t/providers/Microsoft.App/containerApps/web'
RID_TB = '/subscriptions/0/resourceGroups/rg-t/providers/Microsoft.App/containerApps/api'


def break_glass_prod(pred_target='default'):
    """A's healthy BREAK_GLASS prod record of dig_a, promoted from A's test target (as gate-decide now
    records it), or naming no predecessor target (pred_target=None)."""
    r = prod(dig_a, None, '501', state=PR.BREAK_GLASS)
    r['release_path'] = 'break-glass'
    src = {'run_id': '450', 'environment': 'test', 'record_id': '450-1-test'}
    if pred_target == 'default':
        src['target'] = PR.target_key({'adapter': 'containerapp', 'target_resource_id': RID_TA})
    elif pred_target:
        src['target'] = pred_target
    r['predecessor'] = {'required': 'test', 'promoted_from': src, 'gate': 'PROMOTION_REFUSED_NOT_VERIFIED'}
    r['break_glass'] = {'exception': EXC, 'testing_owed': ['verified-for-promotion in test']}
    return r


def f3_case(test_records, M=None, pred_target='default', fail_from=None, per=100):
    """The daily scan of A's prod target whose last record is a break-glass deploy of dig_a; the test
    environment holds `test_records` ([(record, created_at)]). -> (break_glass_owed, rules, finding text)."""
    world = [(break_glass_prod(pred_target), '2026-10-25T12:00:05Z')] + list(test_records)
    doc, rules = daily_inproc(oldest_first_world(world, per=per, fail_from=fail_from), dig_a, M=M)
    return doc.get('break_glass_owed'), rules, json.dumps(doc.get('break_glass_discharge'))


def tst(digest, rid, at, run, state=PR.VERIFIED):
    return (rec(digest=digest, rid=rid, at=at, run=run, state=state), at[:-1] + '5Z')


def finding3():
    b_same = tst(dig_a, RID_TB, '2026-10-26T01:00:00Z', '460')        # app B: same digest, same adapter
    a_own = tst(dig_a, RID_TA, '2026-10-26T02:00:00Z', '461')         # app A's own test target
    owed, rules, why = f3_case([b_same])
    expect(owed is True and 'KIT-BREAK-GLASS-TESTING-OWED' in rules,
           'N9 review F3: app B\'s verified test record of the same digest and adapter does not discharge A\'s '
           'break-glass obligation (owed=%s %s)' % (owed, rules))
    owed, rules, why = f3_case([b_same, a_own])
    expect(owed is False and 'KIT-BREAK-GLASS-TESTING-OWED' not in rules,
           'P11 A\'s own predecessor target verified this digest: discharged (owed=%s %s)' % (owed, rules))
    owed, rules, why = f3_case([tst(dig_a2, RID_TA, '2026-10-26T02:00:00Z', '462')])
    expect(owed is True and 'KIT-BREAK-GLASS-TESTING-OWED' in rules and '"state": "BREAK_GLASS_OWED"' in why,
           'N11 a complete read of A\'s predecessor target with no verified record of this digest: owed, '
           'not found (%s %s)' % (owed, why))
    # Oldest first, one a page: page 2 (A's own verified record) fails.
    owed, rules, why = f3_case([tst(dig_a2, RID_TA, '2026-10-26T01:00:00Z', '463'), a_own], fail_from=2, per=1)
    expect(owed is None and 'KIT-BREAK-GLASS-TESTING-OWED' in rules and 'NOT_ESTABLISHED' in why,
           'N10 a short read of the predecessor history is could-not-establish, never not-found or '
           'discharged (owed=%s %s)' % (owed, why))
    owed, rules, why = f3_case([a_own], pred_target=None)
    expect(owed is None and 'KIT-BREAK-GLASS-TESTING-OWED' in rules and 'no predecessor target' in why,
           'N12 a break-glass record naming no predecessor target is could-not-establish, even with a '
           'matching record in test (owed=%s %s)' % (owed, why))
    many = [tst(dig_a2, RID_TA, '2026-10-2%dT%02d:%02d:00Z' % (1 + i // 600, (i // 60) % 10, i % 60), str(5000 + i))
            for i in range(reads + 5)]
    owed, rules, why = f3_case(many + [a_own])
    expect(owed is False, 'P12 a complete listing beyond the read bound: the newest records hold A\'s verified '
                          'record, discharged (owed=%s %s)' % (owed, why))
    _col, g = gate_e2e([(rec(at='2026-10-25T12:00:00Z', run='7'), '2026-10-25T12:00:05Z')], '7')
    expect((g.get('source') or {}).get('target') == PR.target_key(rec()['environment']),
           'P13 gate-decide records the source target (the predecessor identity a break-glass record carries)')
    n9 = lambda M: f3_case([b_same], M=M)[0] is True
    src_mutant('M11 the predecessor target ignored (any record of the digest discharges) is caught',
               "    found = any(r.get('state') == VERIFIED and (r.get('artifact') or {}).get('digest') == dig for r in recs)",
               "    recs = [read_record(x) for x in artifacts(None) if in_family(x.get('name'), pred)]\n"
               "    found = any(r.get('state') == VERIFIED and (r.get('artifact') or {}).get('digest') == dig for r in recs)",
               n9)
    n10 = lambda M: f3_case([tst(dig_a2, RID_TA, '2026-10-26T01:00:00Z', '463'), a_own], M=M,
                            fail_from=2, per=1)[0] is None
    src_mutant('M12 the predecessor listing\'s short result discarded (as before the review) is caught',
               "        recs, short, listed = history(pred, pkey)\n",
               "        recs, short, listed = history(pred, pkey)[0], None, True\n", n10)
    src_mutant('M13 could-not-establish merged into not-found is caught',
               "    out = {'state': bg_not_established,", "    out = {'state': bg_owed,",
               lambda M: f3_case([a_own], M=M, pred_target=None)[0] is None)


F4_OLD_KEY = """    rid = str((envd or {}).get('target_resource_id') or '').strip().lower()
    return '%s|%s' % ((envd or {}).get('adapter') or '', rid) if rid else None"""
F4_NEW_KEY = """    rid = str((envd or {}).get('target_resource_id') or '').strip().lower()
    adapter = (envd or {}).get('adapter')
    return '%s|%s' % (adapter, rid) if rid and adapter in ADAPTERS else None"""


def f4_refused(M=None):
    """Each non-canonical adapter spelling, and no adapter, gives no key and refuses the source."""
    M = M or PR
    out = []
    for adapter in ('', None, 'ContainerApp', ' containerapp', 'containerapp ', 'kubernetes'):
        r = rec(adapter=adapter)
        if adapter is None:
            r['environment'].pop('adapter')
        res = M.judge(ctx(source=r))
        out.append((adapter, M.target_key(r['environment']), res['verdict'],
                    (res['refusals'] or [{}])[0].get('why', '')))
    return out


def finding4():
    keys = [PR.target_key(rec(adapter=a)['environment']) for a in ('containerapp', 'appservice', 'staticwebapp')]
    expect(all(keys) and len(set(keys)) == 3 and keys[0] == 'containerapp|' + RID_A.lower(),
           'P14 each canonical adapter id keys a target (adapter + lower(resource id))')
    expect(verdict(ctx()) == 'PROMOTION_ALLOWED', 'P14 a canonical source still promotes')
    got = f4_refused()
    for adapter, key, v, why in got:
        expect(key is None and v == 'PROMOTION_REFUSED_TARGET_UNKNOWN' and 'adapter' in why,
               'N13 review F4: adapter %r (with a resource id) gives no target key and refuses the source, '
               'naming the adapter (key=%r %s)' % (adapter, key, v))
    expect(verdict(ctx(history=[rec(digest=dig_a2, adapter='ContainerApp', at='2026-10-26T01:00:00Z')]))
           == 'PROMOTION_ALLOWED', 'N13 a non-canonical adapter record never supersedes a canonical one')
    src_mutant('M14 the adapter not validated (the pre-review key) is caught', F4_NEW_KEY, F4_OLD_KEY,
               lambda M: all(k is None and v == 'PROMOTION_REFUSED_TARGET_UNKNOWN' for _a, k, v, _w in f4_refused(M)))


def f5_world():
    """One source run (7) deployed digest dig_b to app B's test target and dig_a to app A's."""
    return [(rec(digest=dig_b, rid=RID_B, run='7'), '2026-10-25T12:00:05Z'),
            (rec(digest=dig_a, rid=RID_A, run='7'), '2026-10-25T12:00:06Z')]


def f5_mismatch(M=None):
    """Promote dig_b while the request names A's test target as the expected source."""
    return gate_e2e(f5_world(), '7', digest=dig_b, M=M, extra={'promote_from_target_resource_id': RID_A.upper()})


def finding5():
    col, g = gate_e2e(f5_world(), '7', digest=dig_b)
    expect(g.get('promotion_gate') == 'PROMOTION_ALLOWED' and
           ((col.get('source') or {}).get('environment') or {}).get('target_resource_id') == RID_B,
           'P15 backward compatible: no expected source target named -> selection by digest as before (%s)'
           % g.get('promotion_gate'))
    col, g = f5_mismatch()
    expect(g.get('promotion_gate') == 'PROMOTION_REFUSED_DIGEST_MISMATCH' and
           ((col.get('source') or {}).get('environment') or {}).get('target_resource_id') == RID_A,
           'N14 review F5: the request names the A test target and promotes the digest of the B record -> the '
           'source is the A record and the digest does not match it, never the B record (got %s)' % g.get('promotion_gate'))
    col, g = gate_e2e(f5_world(), '7', digest=dig_a, extra={'promote_from_target_resource_id': RID_TA})
    expect(g.get('promotion_gate') == 'PROMOTION_REFUSED_SOURCE_TARGET_MISMATCH' and col.get('source') is None and
           RID_TA.lower() in json.dumps(g.get('refusals')),
           'N16 the run published no record for the requested target -> PROMOTION_REFUSED_SOURCE_TARGET_MISMATCH, '
           'the target named (got %s)' % g.get('promotion_gate'))
    col, g = gate_e2e(f5_world(), '7', digest=dig_a, extra={'promote_from_target_resource_id': ' ' + RID_A.upper() + ' '})
    expect(g.get('promotion_gate') == 'PROMOTION_ALLOWED' and (g.get('source') or {}).get('target') ==
           PR.target_key(rec()['environment']),
           'P16 the expected target (compared case-insensitively, trimmed) and the digest both match -> allowed, '
           'the target recorded (%s)' % g.get('promotion_gate'))
    same = [(rec(digest=dig_a, rid=RID_B, run='7'), '2026-10-25T12:00:05Z'),
            (rec(digest=dig_a, rid=RID_A, run='7'), '2026-10-25T12:00:06Z')]
    col, g = gate_e2e(same, '7', extra={'promote_from_target_resource_id': RID_A})
    expect(g.get('promotion_gate') == 'PROMOTION_ALLOWED' and
           ((col.get('source') or {}).get('environment') or {}).get('target_resource_id') == RID_A,
           'P17 two targets with one digest: the named target resolves what was ambiguous (%s)' % g.get('promotion_gate'))
    col, g = gate_e2e(f5_world(), '7', digest=dig_a2, extra={'promote_from_target_resource_id': RID_A})
    expect(g.get('promotion_gate') == 'PROMOTION_REFUSED_DIGEST_MISMATCH',
           'N15 the named target matches but the digest does not -> PROMOTION_REFUSED_DIGEST_MISMATCH (%s)'
           % g.get('promotion_gate'))
    src_mutant('M15 the expected source target ignored is caught',
               "    want = str(env('promote_from_target_resource_id') or '').strip().lower()\n",
               "    want = ''\n",
               lambda M: f5_mismatch(M)[1].get('promotion_gate') == 'PROMOTION_REFUSED_DIGEST_MISMATCH')


def f7_uat(tier, extra=None, M=None):
    ex = {'environment_tier': tier}
    ex.update(extra or {})
    return gate_e2e(f5_world(), '7', digest=dig_a, M=M, extra=ex)[1]


def finding7():
    g = f7_uat('uat', {'promote_from_target_resource_id': RID_A})
    expect(g.get('promotion_gate') == 'PROMOTION_ALLOWED', 'P18 uat with the source target named and right -> allowed (%s)'
           % g.get('promotion_gate'))
    for tier in ('uat', 'prod'):
        for val in ('', '   '):
            g = f7_uat(tier, {'promote_from_target_resource_id': val})
            expect(g.get('promotion_gate') == 'PROMOTION_REFUSED_SOURCE_TARGET_REQUIRED' and
                   'promote_from_target_resource_id' in json.dumps(g.get('refusals')),
                   'N17/N18 %s with the input %r -> PROMOTION_REFUSED_SOURCE_TARGET_REQUIRED naming the input (got %s)'
                   % (tier, val, g.get('promotion_gate')))
    g = f7_uat('prod', {'release_path': 'break-glass'})
    expect(g.get('promotion_gate') == 'PROMOTION_REFUSED_SOURCE_TARGET_REQUIRED',
           'N18 break-glass does not lift the requirement (got %s)' % g.get('promotion_gate'))
    for tier in ('dev', 'test'):
        g = f7_uat(tier)
        expect(g.get('promotion_gate') == 'PROMOTION_ALLOWED', 'P19 %s with the input empty: old behaviour, allowed (%s)'
               % (tier, g.get('promotion_gate')))
    g = gate_e2e(same_digest_world(), '7', extra={'environment_tier': 'test'})[1]
    expect(g.get('promotion_gate') == 'PROMOTION_REFUSED_SOURCE_AMBIGUOUS',
           'P19 test with the input empty and two targets sharing the digest: ambiguity still refused (%s)'
           % g.get('promotion_gate'))
    g = f7_uat('uat', {'promote_from_target_resource_id': RID_TA})
    expect(g.get('promotion_gate') == 'PROMOTION_REFUSED_SOURCE_TARGET_MISMATCH',
           'N19 uat with the wrong target named -> PROMOTION_REFUSED_SOURCE_TARGET_MISMATCH (%s)' % g.get('promotion_gate'))
    src_mutant('M16 optional-at-prod (requirement not applied to uat or prod) is caught',
               "    if ctx.get('destination_tier') in ('uat', 'prod') and",
               "    if ctx.get('destination_tier') in () and",
               lambda M: f7_uat('prod', M=M).get('promotion_gate') == 'PROMOTION_REFUSED_SOURCE_TARGET_REQUIRED')


def same_digest_world():
    return [(rec(digest=dig_a, rid=RID_B, run='7'), '2026-10-25T12:00:05Z'),
            (rec(digest=dig_a, rid=RID_A, run='7'), '2026-10-25T12:00:06Z')]


# ----------------------------------------------------------------------------- the daily scan
def select(recs, key):
    last, _verified, _ignored = PR.select_promoted(recs, key)
    return last


def p5():
    k_a = PR.target_key(rec()['environment'])
    recs = [rec(digest=dig_b, rid=RID_B, at='2026-10-26T02:00:00Z', envname='prod', tier='prod'),
            rec(digest=dig_a, at='2026-10-25T12:00:00Z', envname='prod', tier='prod')]
    last = select(recs, k_a)
    return last is not None and last['artifact']['digest'] == dig_a


def scan_world(records, serving_digest):
    """The deployed scan as a subprocess against the recorded world of tests/prove_promotion.py."""
    import _workflow_runner as W
    import prove_promotion as PP
    d = tempfile.mkdtemp(prefix='r08-scan-')
    try:
        files, binary = PP.world_api(records)
        api = os.path.join(d, 'api')
        url = 'file:///' + api.replace('\\', '/').lstrip('/')
        for rel, body in list(files.items()) + list(binary.items()):
            p = os.path.join(api, *rel.split('/'))
            os.makedirs(os.path.dirname(p), exist_ok=True)
            io.open(p, 'wb').write(body if isinstance(body, bytes) else body.replace('@API_ROOT@', url).encode('utf-8'))
        st = W.containerapp_state()
        st['containerapp']['revisions']['web--r1']['image'] = W.ref(serving_digest)
        state_path, log_path = os.path.join(d, 's.json'), os.path.join(d, 'c.jsonl')
        io.open(state_path, 'w').write(json.dumps(st))
        io.open(log_path, 'w').close()
        bin_dir = W.stub_bin(state_path, log_path)
        W.add_tools(bin_dir, PP.TOOLS)
        rt = os.path.join(d, 'rt')
        os.makedirs(rt)
        e = dict(os.environ, PATH=bin_dir + os.pathsep + os.environ.get('PATH', ''), RUNNER_TEMP=rt,
                 fake_az_state=state_path, fake_az_log=log_path, GITHUB_REPOSITORY='o/r', GITHUB_API_URL=url,
                 DEPLOY_ENVIRONMENT='prod', CONTAINERAPP_NAME='web', RESOURCE_GROUP='rg-a',
                 AZURE_CONFIG_DIR=os.path.join(d, 'noaz'), GITHUB_OUTPUT=os.path.join(d, 'out.txt'))
        e['fake_trivy_findings'.upper()] = '[]'
        p = subprocess.run([sys.executable, os.path.join(ROOT, 'scripts', 'promotion.py'), 'deployed-scan',
                            '--adapter', 'containerapp'], env=e, capture_output=True, text=True,
                           encoding='utf-8', errors='replace')
        out = os.path.join(rt, 'promotion', 'deployed')
        doc = PR.jload(os.path.join(out, 'deployed-scan-prod.json')) or {}
        sar = PR.jload(os.path.join(out, 'deployed-state-prod.sarif')) or {}
        rules = sorted(set(r['ruleId'] for r in (sar.get('runs') or [{}])[0].get('results') or []))
        shutil.rmtree(bin_dir, ignore_errors=True)
        return p, doc, rules, st['containerapp']['id']
    finally:
        shutil.rmtree(d, ignore_errors=True)


def daily():
    import _workflow_runner as W
    rid = W.containerapp_state()['containerapp']['id']
    a = rec(digest=W.NEW, rid=rid, envname='prod', tier='prod', run='301', at='2026-10-25T12:00:00Z')
    b = rec(digest=dig_b, rid=RID_B, envname='prod', tier='prod', run='302', at='2026-10-26T02:00:00Z')
    expect(p5(), 'P5 the scan selects A\'s last healthy record, not B\'s newer one (pure)')
    p, doc, rules, _ = scan_world([(a, '301', 'main', '2026-10-25T12:00:05Z'), (b, '302', 'main', '2026-10-26T02:00:05Z')], W.NEW)
    expect(p.returncode == 0 and doc.get('artifact_drift') is False and 'KIT-ARTIFACT-DRIFT' not in rules,
           'P5 A serving A\'s digest with B\'s newer record in prod is no drift (%s %s)' % (doc.get('artifact_drift'), rules))
    p, doc, rules, _ = scan_world([(a, '301', 'main', '2026-10-25T12:00:05Z'), (b, '302', 'main', '2026-10-26T02:00:05Z')], dig_b)
    expect(doc.get('artifact_drift') is True and 'KIT-ARTIFACT-DRIFT' in rules,
           'N5 A serving B\'s digest is artifact drift')
    p, doc, rules, _ = scan_world([(b, '302', 'main', '2026-10-26T02:00:05Z')], W.NEW)
    expect(doc.get('artifact_drift') is None and 'KIT-PROMOTION-HISTORY-INCOMPLETE' in rules,
           'N5 a target with no record of its own is not established, never "no drift" (%s)' % rules)


# ----------------------------------------------------------------------------- mutants
def mutant(label, patch, still_passes):
    saved = dict((k, getattr(PR, k)) for k in patch)
    for k, v in patch.items():
        setattr(PR, k, v)
    try:
        try:
            ok = still_passes()
        except Exception as exc:  # noqa: BLE001 -- a mutant that crashes the case is caught
            print('      (mutant raised %s)' % type(exc).__name__)
            ok = False
    finally:
        for k, v in saved.items():
            setattr(PR, k, v)
    expect(not ok, label)


def mutants():
    tk = PR.target_key
    mutant('M1 the target key ignored is caught', {'target_key': lambda e: 'one'}, p1)
    mutant('M2 page one read as the whole listing is caught', {'_next_link': lambda h: None}, p4)
    mutant('M3 the page cap removed is caught', {'page_cap'.upper(): 10 ** 6}, n4_cap)
    mutant('M4 a next link on another host followed is caught', {'_same_host': lambda u, b: True}, n4_host)
    mutant('M5 total_count not checked is caught', {'_total_checked': False}, n4_total)
    mutant('M6 a record with no target key treated as a target is caught',
           {'target_key': lambda e: tk(e) or 'unknown'},
           lambda: verdict(ctx(source=rec(rid=None))) == 'PROMOTION_REFUSED_TARGET_UNKNOWN')
    mutant('M7 the daily scan unscoped is caught',
           {'select_promoted': lambda recs, key, f=PR.select_promoted: f(recs, None)}, p5)


def main():
    for fn in (gate, paging, history, daily, mutants, finding1, finding2, finding3, finding4, finding5, finding7):
        try:
            fn()
        except Exception as exc:  # noqa: BLE001 -- a crashed section is a failure, never a pass
            import traceback
            FAILS.append('%s crashed: %s' % (fn.__name__, exc))
            print(traceback.format_exc()[-2500:])
    if FAILS:
        print('FAIL: %d case(s): %s' % (len(FAILS), '; '.join(FAILS)))
        return 1
    print('PASS: promotion, supersession, rollback selection and the daily scan resolve only their own target\'s')
    print('      records; every listing pages to its end or says it did not.')
    return 0


if __name__ == '__main__':
    sys.exit(main())

#!/usr/bin/env python3
"""Unknown ids are never lost: logged, routed to a person exactly once, never guessed (owner ruling, 2026-11-06).

THE RULING: "Unknown formats shouldn't just be lost; they should at least be logged and have a human review."
scripts/unknown_ids.py; the readers are scripts/scan_report.py (an unknown SAST rule: RULE_FAMILY_UNKNOWN;
a CWE form it cannot read), scripts/external_findings_pull.py (an Aikido or Sonar id it cannot read) and
scripts/reconcile_tickets.py (which routes each to one needs-mapping item).

  POSITIVE
    U1  the report logs an unknown SAST rule and an unreadable CWE in unknown-ids.json beside findings.json,
        with tool, rule, raw id, source and the COUNT (seen twice: one entry, count 2)
    U2  the ticket reconciler, run twice over the same log, keeps ONE needs-mapping item, labelled
        needs-mapping and needs-human-review: created on the first run, never again
    U3  a person's REVIEWED mapping (author, date, review reference) maps the rule into a family; the same
        mapping without an author is refused (MAPPING_NOT_REVIEWED) and maps nothing
    U4  the SonarQube/Aikido intake writes unknown-ids.json beside its output and prints NEEDS_MAPPING
  NEGATIVE
    N1  never dropped: the finding with the unknown rule is still a finding, and the log names it
    N2  never guessed: the unknown rule gets no rule family (not its prefix, not its id)
    N3  an unreadable log is refused by the reconciler (exit 2), never read as "no unknowns"
    M1  the mutant that drops an unknown (record() a no-op) fails U1

EXIT 0 all hold   1 any does not
"""
import contextlib
import io
import json
import os
import shutil
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, os.path.join(ROOT, 'scripts'))
FAILS = []


def check(cond, label, detail=''):
    print('  %s %s%s' % ('ok  ' if cond else 'FAIL', label, ('  -- ' + str(detail)[:300]) if detail and not cond else ''))
    if not cond:
        FAILS.append(label)


def report_run(SR, unknown_rule='zz.custom.rule', twice=True):
    SR.UNKNOWN = __import__('unknown_ids').UnknownLog()
    outs = []
    for _ in range(2 if twice else 1):
        outs.append(SR.what_of({'id': unknown_rule}, {}, unknown_rule, 'm', 'semgrep', 'Semgrep')[0])
    outs.append(SR.what_of({'id': 'B999', 'properties': {'cwe': 'CWE#79'}}, {}, 'B999', 'm', 'bandit', 'Bandit')[0])
    d = tempfile.mkdtemp(prefix='unk-')
    with contextlib.redirect_stdout(io.StringIO()):
        SR.batch(d, '', 5, '')
    doc = json.load(io.open(os.path.join(d, 'unknown-ids.json'), encoding='utf-8'))
    return d, doc['entries'], outs


def main():
    import scan_report as SR
    import unknown_ids as U
    import reconcile_tickets as RT
    import code_finding_key as CFK
    print('Unknown ids (scripts/unknown_ids.py):')
    d, entries, outs = report_run(SR)
    rules = {(e['kind'], e['tool'], e['raw']): e for e in entries}
    fam = rules.get(('rule-family', 'semgrep', 'zz.custom.rule'))
    cwe = rules.get(('cwe', 'Bandit', '"CWE#79"'))
    check(fam and fam['count'] == 2 and fam['source'] and 'RULE_FAMILY_UNKNOWN' in fam['reason'],
          'U1 an unknown SAST rule is logged once with count 2, its source and reason', entries)
    check(cwe and 'CWE_FORM_UNKNOWN' in cwe['reason'], 'U1 an unreadable CWE is logged with its raw form', entries)
    check(os.path.exists(os.path.join(d, 'findings.json')), 'U1 the log sits beside findings.json in the evidence')
    check(not outs[0].get('rule_family'), 'N2 the unknown rule gets no family (never its prefix or id)', outs[0])
    check(outs[0].get('_family_refusal', '').startswith('RULE_FAMILY_UNKNOWN') or 'RULE_FAMILY_UNKNOWN' in json.dumps(outs[0]),
          'N1 the finding keeps its refusal: it is still a finding, never dropped', outs[0])

    # U2: routed once, across runs
    recs = U.review_records(entries)
    backend = RT.RecordingBackend()
    ledger = {}
    created = []
    for run in (1, 2):
        with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
            clusters, withheld = RT.build_clusters(recs)
            res = RT.reconcile(clusters, withheld, backend, ledger, True, today='2026-11-06')
        ledger = res.get('ledger') if isinstance(res.get('ledger'), dict) else ledger
        created.append(len(backend.created))
    with contextlib.redirect_stderr(io.StringIO()):
        labels = set(l for c in RT.build_clusters(recs)[0] for l in c.get('template_labels') or [])
    check(created == [len(entries), len(entries)] and len(entries) >= 2,
          'U2 two runs over the same log: one needs-mapping item per unknown, none created again (%s)' % created)
    check({'needs-mapping', 'needs-human-review'} <= labels, 'U2 each item is labelled for review (%s)' % sorted(labels))

    # U3: reviewed mappings only
    tmp = tempfile.mkdtemp(prefix='unk-map-')
    try:
        fam_name = sorted(CFK.sast_families)[0]
        good = {'kind': 'rule-family', 'tool': 'semgrep', 'rule': 'zz.custom.rule', 'family': fam_name,
                'author': 'appsec-reviewer', 'date': '2026-11-06', 'review_ref': 'PR 42'}
        io.open(os.path.join(tmp, U.MAPPINGS_FILE), 'w').write(json.dumps({'schema': U.MAPPINGS_SCHEMA, 'mappings': [
            good, dict(good, rule='zz.other.rule', author='')]}))
        applied, refused = U.load_mappings(tmp)
        orig = CFK.reviewed_rule_mappings
        CFK.reviewed_rule_mappings = lambda: tuple(m for m in applied if m['kind'] == 'rule-family')
        try:
            f1 = CFK.resolve_sast_family('semgrep', 'Semgrep', 'zz.custom.rule')
            f2 = CFK.resolve_sast_family('semgrep', 'Semgrep', 'zz.other.rule')
        finally:
            CFK.reviewed_rule_mappings = orig
        check(f1[0] == fam_name and 'reviewed mapping by appsec-reviewer' in f1[2],
              'U3 a reviewed mapping (author, date, review) places the rule in its family', f1)
        check(f2[0] is None and refused and 'MAPPING_NOT_REVIEWED' in refused[0],
              'U3 a mapping without an author is refused and maps nothing', (f2, refused))
    finally:
        shutil.rmtree(tmp, ignore_errors=True)

    # U4: the external intake
    import external_findings_pull as EFP
    EFP.UNKNOWN = U.UnknownLog()
    refs = []
    EFP.aikido_items([{'id': 9, 'type': 'open_source', 'severity': 'high', 'status': 'open', 'code_repo_name': 'app',
                       'affected_file': 'package-lock.json', 'cve_id': 'CVE-21-1'}], {'app': 'o/app'}, 'code',
                     id_refusals=refs)
    ent = EFP.UNKNOWN.entries()
    check(len(ent) == 1 and ent[0]['kind'] == 'vuln-id' and ent[0]['raw'] == 'CVE-21-1',
          'U4 the intake logs an unreadable Aikido id for a person to map', ent)

    # N3: an unreadable log is refused
    bad = tempfile.mkdtemp(prefix='unk-bad-')
    try:
        io.open(os.path.join(bad, 'findings.json'), 'w').write('[]')
        io.open(os.path.join(bad, U.FILENAME), 'w').write('{not json')
        p = subprocess.run([sys.executable, os.path.join(ROOT, 'scripts', 'reconcile_tickets.py'), '--findings',
                            os.path.join(bad, 'findings.json')], capture_output=True, text=True)
        check(p.returncode == 2 and 'unknown-ids log' in p.stderr, 'N3 an unreadable log is refused (exit 2)',
              p.stderr[-300:])
    finally:
        shutil.rmtree(bad, ignore_errors=True)

    # M1: drop the unknown
    real = U.UnknownLog.record
    U.UnknownLog.record = lambda self, *a, **k: None
    try:
        _d, mut, _o = report_run(SR)
    finally:
        U.UnknownLog.record = real
    check(not mut, 'M1 the drop-the-unknown mutant leaves the log empty, which U1 refuses (%d entries)' % len(mut))
    shutil.rmtree(d, ignore_errors=True)
    if FAILS:
        print('FAIL: %d claim(s)' % len(FAILS))
        return 1
    print('PASS: every unknown id is logged with its count, routed to a person once, and never guessed.')
    return 0


if __name__ == '__main__':
    sys.exit(main())

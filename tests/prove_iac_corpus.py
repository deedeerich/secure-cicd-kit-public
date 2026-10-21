#!/usr/bin/env python3
"""The IaC ranges KDEC-014 enforces on are MEASURED, by a probe that can tell "could not read".

WHY THIS EXISTS (D-VF-4, ledger V-02)

    KDEC-014 refuses a version gap at uat/prod only where READ ranges establish it, and the
    checkov and trivy-config rows were UNVERIFIED, so no IaC gap was ever enforced. They are READ
    now because tests/corpora/probe_iac_corpus.py ran the pinned scanners over the seeded corpus in
    tests/corpora/terraform_corpus.py. A READ row is a claim the enforcement acts on, so the thing
    that produced it is held here, without the real scanners (a stub stands in for them), and the
    real measurement is re-run weekly by .github/workflows/probe-scanner-corpora.yml.

WHAT IS PROVED
    C1  the corpus: every family is a distinct, ascending Terraform release, its file holds its
        construct AND the seed, with the seed after the construct; the control is unparseable
    C2  the seeds are never committed as IaC: nothing under tests/corpora is a file an IaC scanner
        reads (KDEC-011's rule: test-only input is generated, never shipped as a finding)
    C3  the probe tells READ / MISSED / COLLECTION_FAILED apart and the range is contiguous from the
        oldest family: a silent drop at 1.8 -> 0.12..1.7; a crash at 1.10 -> ..1.9; a family read
        ABOVE the first miss does not raise the ceiling
    C4  the probe REFUSES (no range) when it cannot measure: a scanner that reports the seed from
        the unparseable control; a scanner that cannot read the oldest family
    C5  --check: a registry claiming more than was measured, or READ against a refusal, fails
    C6  the shipped rows: both READ, naming this corpus, min = the oldest family, max a family
    C7  --write edits only the one entry, keeps every other byte, and the composite copy stays
        equal to the registry (the equality tests/test_resolve.py holds)
    C8  the probe workflow: read-only, scheduled and dispatchable (push only path-filtered to the
        registry, the corpus and the probe), every scanner pinned by digest,
        both tools compared with --check

EXIT 0 all hold; 1 one does not; 2 could not be checked.
"""
import io
import json
import os
import re
import shutil
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
CORPORA = os.path.join(HERE, 'corpora')
sys.path.insert(0, CORPORA)
WORKFLOW = os.path.join(ROOT, '.github', 'workflows', 'probe-scanner-corpora.yml')
STUB = os.path.join(CORPORA, 'stub_iac_scanner.py')
IAC_EXT = ('.tf', '.tfvars', '.hcl', '.tf.json', '.bicep', '.yaml', '.yml', '.json')


def stub_cmd():
    # Forward slashes: the probe splits --cmd POSIX-style, which would eat a Windows backslash.
    return '"%s" -I "%s"' % (sys.executable.replace('\\', '/'), STUB.replace('\\', '/'))


def run_measure(P, tool, **env):
    keys = ('stub_unreadable', 'stub_crash', 'stub_lenient')
    saved = {k: os.environ.get(k) for k in keys}
    try:
        for k in keys:
            os.environ.pop(k, None)
        os.environ.update(env)
        return P.measure(tool, stub_cmd())
    finally:
        for k, v in saved.items():
            if v is None:
                os.environ.pop(k, None)
            else:
                os.environ[k] = v


def main():
    try:
        import yaml
        import terraform_corpus as C
        import probe_iac_corpus as P
    except ImportError as e:
        print('UNKNOWN: %s' % e)
        return 2
    bad = []

    # C1 the corpus
    names = C.family_names()
    vt = [tuple(int(x) for x in f.split('.')) for f in names]
    if vt != sorted(vt) or len(set(vt)) != len(vt):
        bad.append('C1 families are not distinct and ascending: %s' % names)
    for fam, construct, body in C.FAMILIES:
        src = C.source(fam)
        if not construct or body.strip() == '' or C.SEED not in src or src.index(body) > src.index(C.SEED):
            bad.append('C1 family %s does not hold its construct before the seed' % fam)
    if C.SEED not in C.source(C.CONTROL) or C.control_body not in C.source(C.CONTROL):
        bad.append('C1 the control is not the unparseable body plus the seed')
    print('  C1 corpus: %d families %s..%s, one control' % (len(names), names[0], names[-1]))

    # C2 never committed as IaC
    committed = []
    for d, _dirs, files in os.walk(CORPORA):
        for f in files:
            if f.lower().endswith(IAC_EXT) or f in ('Dockerfile', 'Chart.yaml'):
                committed.append(os.path.relpath(os.path.join(d, f), ROOT))
    if committed:
        bad.append('C2 IaC files are committed under tests/corpora (a consumer scan would read the '
                   'seeds): %s' % committed)
    print('  C2 nothing under tests/corpora is an IaC file: %s' % ('held' if not committed else committed))

    # C3 the three outcomes and the contiguous range
    cases = [
        ('silent drop at 1.8', 'checkov', {'stub_unreadable': 'provider::'}, '1.7', '1.8', ['1.9', '1.10', '1.11', '1.14']),
        ('crash at 1.10', 'trivy-config', {'stub_crash': 'ephemeral "random_password"'}, '1.9', '1.10', ['1.11', '1.14']),
        ('reads every family', 'trivy-config', {}, names[-1], None, []),
    ]
    for label, tool, env, want_max, want_first, want_above in cases:
        r = run_measure(P, tool, **env)
        got = (r.get('min'), r.get('max'), r.get('first_unread'), r.get('read_above_ceiling'))
        if 'refused' in r or got != (names[0], want_max, want_first, want_above):
            bad.append('C3 %s: got %r (refused=%r), want min %s max %s first_unread %s above %s'
                       % (label, got, r.get('refused'), names[0], want_max, want_first, want_above))
        states = {p['family']: p['state'] for p in r['families']}
        if label == 'silent drop at 1.8' and states.get('1.8') != 'MISSED':
            bad.append('C3 a silent drop is not MISSED: %s' % states.get('1.8'))
        if label == 'crash at 1.10' and states.get('1.10') != 'COLLECTION_FAILED':
            bad.append('C3 a crash is not COLLECTION_FAILED: %s' % states.get('1.10'))
        print('  C3 %-20s -> %s..%s first unread %s' % (label, r.get('min'), r.get('max'), r.get('first_unread')))

    # C4 refusals
    r = run_measure(P, 'checkov', stub_lenient='1')
    if 'refused' not in r or 'control' not in r['refused']:
        bad.append('C4 a scanner that reads the unparseable control was given a range: %r' % r)
    r = run_measure(P, 'checkov', stub_unreadable='dynamic "egress"')
    if 'refused' not in r or 'oldest family' not in r['refused']:
        bad.append('C4 a scanner that cannot read the oldest family was given a range: %r' % r)
    print('  C4 refusals: lenient control and unreadable oldest family both refused')

    # C5 --check compares
    measured = {'tool': 'checkov', 'min': '0.12', 'max': '1.7', 'families': []}
    row = {'tool': 'checkov', 'min': '0.12', 'max': '1.14', 'verified': 'READ', 'corpus': P.corpus_id}
    if not P.compare(measured, row):
        bad.append('C5 a registry claiming 1.14 against a measured 1.7 passed --check')
    if P.compare(dict(measured, max='1.14'), row):
        bad.append('C5 an exact match failed --check: %s' % P.compare(dict(measured, max='1.14'), row))
    if not P.compare({'tool': 'checkov', 'refused': 'x', 'families': []}, row):
        bad.append('C5 a READ row against a refused measurement passed --check')
    if not P.compare(dict(measured, max='1.14'), dict(row, corpus=None)):
        bad.append('C5 a row that does not name its corpus passed --check')

    # C6 the shipped rows
    reg = yaml.safe_load(io.open(os.path.join(ROOT, 'scanner-registry.yaml'), encoding='utf-8'))
    rows = {e['tool']: e for e in reg['version_support']['iac-scan']['iac']}
    for tool in P.TOOLS:
        e = rows.get(tool) or {}
        if not (e.get('verified') == 'READ' and e.get('corpus') == P.corpus_id
                and e.get('min') == names[0] and e.get('max') in names
                and 'MEASURED' in (e.get('basis') or '')):
            bad.append('C6 the shipped %s row is not a corpus measurement: %r' % (tool, e))
    print('  C6 shipped: %s' % ', '.join('%s %s..%s %s' % (t, rows[t].get('min'), rows[t].get('max'),
                                                         rows[t].get('verified')) for t in P.TOOLS))

    # C7 --write is surgical, and the composite copy stays equal
    work = tempfile.mkdtemp(prefix='corpus-write-')
    try:
        reg_text = io.open(os.path.join(ROOT, 'scanner-registry.yaml'), encoding='utf-8').read()
        new = P.write_registry(reg_text, 'trivy-config',
                               {'min': '"0.12"', 'max': '"1.7"', 'verified': 'READ',
                                'basis': '"x"', 'corpus': P.corpus_id})
        before, after = reg_text.split('\n'), new.split('\n')
        changed = [i for i, (a, b) in enumerate(zip(before, after)) if a != b]
        doc = yaml.safe_load(new)
        e = {x['tool']: x for x in doc['version_support']['iac-scan']['iac']}
        if len(before) != len(after) or len(changed) > 4 or e['trivy-config']['max'] != '1.7' \
                or e['checkov'] != rows['checkov']:
            bad.append('C7 --write changed more than the one entry (lines %s)' % changed)
        act = io.open(os.path.join(ROOT, '.github', 'actions', 'resolve', 'action.yml'),
                      encoding='utf-8').read()
        act2 = P.write_action_copy(act, doc['version_support'])
        m = re.search(r"<<'JSON'\n(.*?)\n        JSON\n", act2, re.S)
        if not m or json.loads(m.group(1)) != doc['version_support']:
            bad.append('C7 the composite copy written by --write is not equal to the registry')
        if P.write_action_copy(act, reg['version_support']) != act:
            bad.append('C7 the shipped composite copy is not what --write produces from the registry')
    finally:
        shutil.rmtree(work, ignore_errors=True)
    print('  C7 --write: one entry, and the composite copy equals the registry')

    # C8 the workflow
    wf = yaml.safe_load(io.open(WORKFLOW, encoding='utf-8'))
    on = wf.get('on', wf.get(True)) or {}
    text = io.open(WORKFLOW, encoding='utf-8').read()
    jobs = wf.get('jobs') or {}
    # push is allowed only when filtered to what a range rests on: the registry, the corpus and
    # the probe. GitHub dispatches and schedules a workflow only from the default branch, so this
    # is how a change to a range is re-measured before it reaches main; an unfiltered push would
    # re-run the probe on every commit for nothing.
    want_paths = {'scanner-registry.yaml', 'tests/corpora/**',
                  '.github/workflows/probe-scanner-corpora.yml'}
    push = on.get('push') if isinstance(on, dict) else None
    if set(on) - {'push'} != {'schedule', 'workflow_dispatch'}:
        bad.append('C8 triggers are %s, want schedule and workflow_dispatch (and a path-filtered '
                   'push)' % sorted(on))
    if 'push' in on and (not isinstance(push, dict) or set(push) != {'paths'}
                         or set(push.get('paths') or []) != want_paths):
        bad.append('C8 push is not filtered to exactly %s' % sorted(want_paths))
    if wf.get('permissions') != {'contents': 'read'} or any(j.get('permissions') for j in jobs.values()):
        bad.append('C8 permissions are not contents: read only')
    if not re.search(r'ghcr\.io/bridgecrewio/checkov@sha256:[0-9a-f]{64}', text):
        bad.append('C8 checkov is not pulled by digest')
    shas = [i.get('sha256') for i in jobs.get('trivy', {}).get('strategy', {}).get('matrix', {}).get('include', [])]
    if not shas or not all(re.fullmatch(r'[0-9a-f]{64}', s or '') for s in shas) or 'sha256sum -c' not in text:
        bad.append('C8 trivy is not digest-verified for every version')
    if text.count('--check') < 2 or '--write' in text.replace('--write is', ''):
        bad.append('C8 the workflow does not --check both tools, or it writes')
    if not all(j.get('timeout-minutes') for j in jobs.values()):
        bad.append('C8 a job has no timeout')
    print('  C8 workflow: read-only, scheduled + dispatch, digests pinned, --check both')

    print()
    if bad:
        for b in bad:
            print('FAIL: %s' % b)
        return 1
    print('PASS: the IaC ranges are corpus measurements, the probe tells a silent drop from a read '
          'and refuses what it cannot measure, and the registry it writes is the one resolve reads.')
    return 0


if __name__ == '__main__':
    sys.exit(main())

#!/usr/bin/env python3
"""The BASELINE LEDGER: its format, and the only sanctioned way to read it (ETFB section 5.4, L45).

WHAT THE LEDGER IS

    The record of which findings existed before the baseline for each (repository, environment)
    cell, and since when. A GOVERNANCE ARTIFACT, not a scanner output: the scanner's observation set
    is evidence; the ledger is the record of decisions about that evidence, and the two must not
    share a write path. One JSON document on the protected default branch, under CODEOWNERS:

        .security/finding-baseline.json
        {
          "schema_version": 1,
          "header":  {established_on, established_commit, approver_role,
                      [scanner_generations, severity_formula_version, cohort_decision_ref]},
          "entries": [ one per (identity, environment), sorted, see the entry allowlist below ]
        }

    Pretty-printed with sorted keys and sorted entries, so a ledger change is a reviewable diff --
    ETFB section 13 names "a ledger nobody can review" as an open question, and an unstable
    serialisation would answer it badly by default.

WHO MAY WRITE IT

    Nobody, from here. `scripts/propose_ledger.py` is the only write authority, and it does not
    write either: it produces the payload of a pull request that branch protection and CODEOWNERS
    then review. A PR run may only read (SINGLE_PIPELINE_TARGET.md section 6.1, section 9.3).

HOW IT IS READ, AND WHY THERE IS NO "READ THIS FILE" FUNCTION

    From a GIT REF, never from a working tree. ETFB section 5.4: "Read from the protected default
    branch, never from the PR under evaluation" -- otherwise a PR adds its own finding to the
    baseline and grandfathers it, which is a self-signed certificate. `read_for_evaluation`
    implements the two-commit rule:

        grandfathering  from the MERGE BASE of the PR and the default branch: nothing can be added
                        underneath a PR while it is open.
        removals        from the default branch TIP: a remediation merged by someone else
                        strengthens the gate at once.

        effective = entries at the merge base whose (identity, environment) is still at the tip.

    That is the floor rule applied to time: strengthening takes effect at once; weakening requires
    review. Its cost -- an author blocked by a removal somebody else merged -- is ETFB section 13's
    merge-base race, and is accepted here as the design accepts it.

REFUSE, NEVER DEGRADE

    Every entry is checked against an ALLOWLIST of fields. Matched material -- a snippet, a
    construct, a message, a scanner's partialFingerprints -- is not merely unused, it is refused:
    for a secret scanner those can be the secret itself, and a ledger on a readable branch holding
    one is an offline-crackable oracle (ETFB section 5.2, section 5.7). An entry whose identity does
    not re-derive from its three components, whose age flag is not a boolean, whose age claims to
    be established from a non-claimable time source, whose subject is not durable, or whose key is
    duplicated makes the whole ledger LEDGER_LINE_UNPARSEABLE -- the cascade then answers
    BASELINE_UNAVAILABLE, never a guess from the entries that did parse.

    States reuse lineage_ledger_integrity: LEDGER_ABSENT (no ledger at the ref), LEDGER_EMPTY (an
    established ledger with no entries -- every finding NEW, correctly), LEDGER_INTACT,
    LEDGER_LINE_UNPARSEABLE (unreadable, malformed, or the ref itself unreadable). There is no hash
    chain, so never LEDGER_TAMPERED: integrity here is the protected branch's review.

USAGE
    python3 baseline_ledger.py --self-test
    python3 baseline_ledger.py --repo . --default-ref origin/main --head-ref HEAD [--out f.json]
    from baseline_ledger import read_for_evaluation, parse_ledger, entry_from_identity

EXIT  0 the ledger is usable   1 it is not (state printed)   2 usage, or self-test failed
"""
import argparse
import io
import json
import os
import subprocess
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from finding_identity import SPEC, SUBJECTS, DURABLE, _h  # noqa: E402

SCHEMA_VERSION = 1
default_ledger_path = '.security/finding-baseline.json'

LEDGER_ABSENT = 'LEDGER_ABSENT'
LEDGER_EMPTY = 'LEDGER_EMPTY'
LEDGER_INTACT = 'LEDGER_INTACT'
LEDGER_LINE_UNPARSEABLE = 'LEDGER_LINE_UNPARSEABLE'
USABLE = (LEDGER_INTACT, LEDGER_EMPTY)

HEADER_REQUIRED = ('established_on', 'established_commit', 'approver_role')
HEADER_OPTIONAL = ('scanner_generations', 'severity_formula_version', 'cohort_decision_ref',
                   'environment_presence')

# ETFB section 8.8 rule 4: "A finding cannot be grandfathered into an environment it was never present
# in ... The evidence for presence in an environment is a scan of the DEPLOYED ARTEFACT [scan_depth
# `revalidate`] ... Where an estate has no such scan, the honest fallback is a DECLARED, DATED
# ASSUMPTION OF INHERITANCE, recorded as an assumption, and never a silent inheritance."
#
#   environment_presence: {<environment>: {evidence: <scan_depth>, assumption: bool,
#                                          declared_on: YYYY-MM-DD, run_id: <run>}}
#
# `evidence` reuses the registered scan_depth values. Only `revalidate` evidences presence; any other
# depth (a source scan of the default branch) is an assumption, and `assumption: false` with it is
# refused -- the silent inheritance the rule forbids, spelled as a claim.
PRESENCE_EVIDENCE = ('pr', 'merge', 'nightly', 'release', 'revalidate')
PRESENCE_REQUIRED = ('evidence', 'assumption', 'declared_on', 'run_id')


def presence_faults(presence):
    """-> list of problems with a header's environment_presence block (ETFB section 8.8 rule 4)."""
    if not isinstance(presence, dict):
        return ['environment_presence is not an object']
    out = []
    for env, p in presence.items():
        if not isinstance(p, dict):
            out.append('environment_presence[%r] is not an object' % env)
            continue
        unknown = [k for k in p if k not in PRESENCE_REQUIRED]
        missing = [k for k in PRESENCE_REQUIRED if k != 'assumption' and not _s(p.get(k))]
        if unknown or missing or not isinstance(p.get('assumption'), bool):
            out.append('environment_presence[%r] must carry exactly %s (assumption a boolean); '
                       'missing %s, unknown %s' % (env, ', '.join(PRESENCE_REQUIRED), missing, unknown))
            continue
        if p['evidence'] not in PRESENCE_EVIDENCE:
            out.append('environment_presence[%r]: evidence %r is not a registered scan_depth'
                       % (env, p['evidence']))
        elif p['evidence'] != 'revalidate' and p['assumption'] is not True:
            out.append('environment_presence[%r]: a %s scan does not observe the deployed artefact, so '
                       'presence in %s is an ASSUMPTION; recording it as anything else is the silent '
                       'inheritance ETFB section 8.8 rule 4 forbids' % (env, p['evidence'], env))
    return out

# ETFB section 5.4's field list. REQUIRED is what the cascade and the SLA clock cannot do without;
# OPTIONAL is carried when present and is mostly owed by L47 (severity, fix availability, SLA),
# which is not built -- so absent, never defaulted.
ENTRY_REQUIRED = ('identity', 'what', 'where', 'content', 'finding_subject', 'environment',
                  'first_seen', 'first_seen_provenance', 'age_established')
ENTRY_OPTIONAL = ('what_aliases', 'severity_by_scanner', 'effective_severity',
                  'effective_severity_formula_version', 'fix_availability',
                  'fix_availability_established_on', 'classification', 'owner', 'disposition_ref',
                  'remediation_track_ref', 'sla_deadline', 'detection_change',
                  'admitted_by')
# ONE MOVE RECORD (L51 / B-08). ETFB section 5.4 lists "move history" among an entry's fields; it is
# kept ONCE, in the lineage ledger (.security/finding-lineage.jsonl, scripts/finding_lineage.py), which
# is hash-chained and head-anchored. A second copy inside the entry is refused by name, because two
# records of one move can disagree and nothing would say which is right.
MOVE_RECORD_ELSEWHERE = ('move_history',)
PROVENANCE_REQUIRED = ('run_id', 'observed_at', 'observed_at_source')
# provenance_identity.observation_time.sources, and which of them may establish an age.
observation_time_sources = ('DECLARED_IN_CONTENT', 'SIDECAR', 'FILENAME', 'FILE_MTIME', 'UNKNOWN')
CLAIMABLE = ('DECLARED_IN_CONTENT', 'SIDECAR')
# Named so the refusal can say WHY, not merely "unknown field". Any other unknown key is refused too.
MATCHED_MATERIAL = ('snippet', 'construct', 'message', 'partial_fingerprints',
                    'partialFingerprints', 'secret', 'match', 'matched_text', 'is_secret_finding')


def _s(v):
    return v.strip() if isinstance(v, str) else ''


def composite_identity(subject, what, where, content):
    """The identity finding_identity.identify() would compute from these three components."""
    return _h('IDENTITY/' + subject, [what, where, content])


def entry_from_identity(ident, environment, first_seen, first_seen_provenance, age_established,
                        **optional):
    """Build a ledger entry from an identify() result. Never copies anything but the components."""
    entry = {
        'identity': ident['identity'], 'what': ident['what'], 'where': ident['where'],
        'content': ident['content'], 'finding_subject': ident['finding_subject'],
        'environment': environment, 'first_seen': first_seen,
        'first_seen_provenance': dict(first_seen_provenance),
        'age_established': bool(age_established),
    }
    if ident.get('what_aliases'):
        entry['what_aliases'] = sorted(ident['what_aliases'])
    for key, value in optional.items():
        if key not in ENTRY_OPTIONAL:
            raise ValueError('%r is not a ledger field' % key)
        entry[key] = value
    return entry


def new_ledger(header, entries):
    return {'schema_version': SCHEMA_VERSION, 'header': dict(header), 'entries': list(entries)}


def serialise(doc):
    doc = dict(doc)
    doc['entries'] = sorted(doc.get('entries') or [],
                            key=lambda e: (_s(e.get('environment')), _s(e.get('identity'))))
    return json.dumps(doc, indent=2, sort_keys=True, ensure_ascii=True) + '\n'


def _entry_faults(i, e):
    out = []
    if not isinstance(e, dict):
        return ['entry %d is not an object' % i]
    for key in e:
        if key in MATCHED_MATERIAL:
            out.append('entry %d carries %r. Matched material never enters the ledger: for a secret '
                       'scanner it can be the secret itself, and this file is readable by everyone '
                       'with read access (ETFB section 5.2, section 5.7)' % (i, key))
        elif key in MOVE_RECORD_ELSEWHERE:
            out.append('entry %d carries %r. A move is recorded once, as an event in the lineage '
                       'ledger (.security/finding-lineage.jsonl); a second copy here could disagree '
                       'with it (L51)' % (i, key))
        elif key not in ENTRY_REQUIRED and key not in ENTRY_OPTIONAL:
            out.append('entry %d carries unknown field %r. The ledger reads through an allowlist, so '
                       'nothing can arrive under a name nobody reviewed' % (i, key))
    for key in ENTRY_REQUIRED:
        if key in ('age_established', 'first_seen_provenance'):
            continue
        if not _s(e.get(key)):
            out.append('entry %d lacks %s' % (i, key))
    if out:
        return out
    subject = _s(e['finding_subject'])
    if subject not in SUBJECTS:
        out.append('entry %d has unregistered subject %r' % (i, subject))
    elif SPEC[subject]['scope'] != DURABLE:
        out.append('entry %d is %s-scoped, which is valid within one release only and is never a '
                   'ledger key' % (i, subject))
    elif composite_identity(subject, e['what'], e['where'], e['content']) != _s(e['identity']):
        out.append('entry %d: its identity does not derive from its WHAT, WHERE and CONTENT, so '
                   'either was edited by hand' % i)
    if not isinstance(e.get('age_established'), bool):
        out.append('entry %d: age_established is %r, not a boolean. An age is established or it is '
                   'not; anything else would be read as one or the other by somebody' % (i, e.get('age_established')))
    prov = e.get('first_seen_provenance')
    if not isinstance(prov, dict):
        out.append('entry %d: first_seen_provenance is missing' % i)
    else:
        missing = [k for k in PROVENANCE_REQUIRED if not _s(prov.get(k))]
        if missing:
            out.append('entry %d: first_seen_provenance lacks %s' % (i, ', '.join(missing)))
        src = _s(prov.get('observed_at_source'))
        if src and src not in observation_time_sources:
            out.append('entry %d: observed_at_source %r is not a registered observation-time source'
                       % (i, src))
        if e.get('age_established') is True and src not in CLAIMABLE:
            out.append('entry %d claims an established age from %r, which is not a claimable time '
                       'source -- the FILE_MTIME error, at ledger scale' % (i, src or None))
    if 'detection_change' in e and not isinstance(e['detection_change'], bool):
        out.append('entry %d: detection_change is not a boolean' % i)
    return out


def parse_ledger(text):
    """-> (entries, state, notes, header). Refuses the WHOLE ledger on any malformed entry."""
    if not _s(text):
        return ([], LEDGER_LINE_UNPARSEABLE, ['the ledger file is empty. An established ledger with '
                                              'no entries is a JSON document saying so; an empty '
                                              'file is a broken write'], {})
    try:
        doc = json.loads(text)
    except ValueError as exc:
        return ([], LEDGER_LINE_UNPARSEABLE, ['not valid JSON: %s' % exc], {})
    if not isinstance(doc, dict):
        return ([], LEDGER_LINE_UNPARSEABLE, ['the ledger is not a JSON object'], {})
    notes = []
    if doc.get('schema_version') != SCHEMA_VERSION:
        notes.append('schema_version is %r, this reader understands %d'
                     % (doc.get('schema_version'), SCHEMA_VERSION))
    header = doc.get('header')
    if not isinstance(header, dict):
        notes.append('no header: the baseline establishment record (ETFB section 10) is missing')
        header = {}
    else:
        missing = [k for k in HEADER_REQUIRED if not _s(header.get(k))]
        if missing:
            notes.append('header lacks %s. A baseline nobody approved is not a baseline'
                         % ', '.join(missing))
        unknown = [k for k in header if k not in HEADER_REQUIRED + HEADER_OPTIONAL]
        if unknown:
            notes.append('header carries unknown field(s) %s' % ', '.join(sorted(unknown)))
        if 'environment_presence' in header:
            notes.extend(presence_faults(header['environment_presence']))
    entries = doc.get('entries')
    if not isinstance(entries, list):
        notes.append('entries is not a list')
        entries = []
    seen = set()
    for i, e in enumerate(entries):
        notes.extend(_entry_faults(i, e))
        if isinstance(e, dict):
            key = (_s(e.get('identity')), _s(e.get('environment')))
            if key in seen:
                notes.append('entry %d duplicates the key (identity, environment) %r' % (i, key))
            seen.add(key)
    unknown = [k for k in doc if k not in ('schema_version', 'header', 'entries')]
    if unknown:
        notes.append('top-level unknown field(s) %s' % ', '.join(sorted(unknown)))
    if notes:
        return ([], LEDGER_LINE_UNPARSEABLE, notes, header)
    if not entries:
        return ([], LEDGER_EMPTY, ['an established ledger with no entries'], header)
    declared = (header or {}).get('environment_presence') or {}
    silent = sorted(set(_s(e.get('environment')) for e in entries) - set(declared))
    info = ['%d entr(y/ies)' % len(entries)]
    if silent:
        # Usable (ledgers written before rule 4 was built carry none), and SAID: the next proposal
        # for that environment declares it (ETFB section 8.8 rule 4).
        info.append('presence in %s is not declared in the header: an inheritance nobody declared'
                    % ', '.join(silent))
    return (entries, LEDGER_INTACT, info, header)


def _git(repo, *args):
    p = subprocess.run(['git', '-C', repo] + list(args), capture_output=True)
    return p.returncode, p.stdout, p.stderr.decode('utf-8', 'replace').strip()


def read_at_ref(repo, ref, path=default_ledger_path):
    """-> (entries, state, notes, header, sha). Reads the BLOB at the ref, never a working tree."""
    rc, out, err = _git(repo, 'rev-parse', '--verify', '--quiet', '%s^{commit}' % ref)
    if rc != 0:
        return ([], LEDGER_LINE_UNPARSEABLE, ['ref %r cannot be resolved (%s). Cannot read is not '
                                              'empty' % (ref, err or 'no such ref')], {}, '')
    sha = out.decode().strip()
    rc, out, err = _git(repo, 'cat-file', '-e', '%s:%s' % (sha, path))
    if rc != 0:
        return ([], LEDGER_ABSENT, ['no ledger at %s:%s. Nobody has established a baseline for '
                                    'this repository at that commit' % (ref, path)], {}, sha)
    rc, out, err = _git(repo, 'show', '%s:%s' % (sha, path))
    if rc != 0:
        return ([], LEDGER_LINE_UNPARSEABLE, ['cannot read %s:%s: %s' % (ref, path, err)], {}, sha)
    entries, state, notes, header = parse_ledger(out.decode('utf-8', 'replace'))
    return (entries, state, notes, header, sha)


def read_for_evaluation(repo, default_ref, head_ref, path=default_ledger_path):
    """The PR-safe read. -> {entries, state, notes, merge_base, tip}.

    Grandfathering from merge-base(default_ref, head_ref); removals from default_ref's tip.
    `head_ref` is used ONLY to find the merge base. Nothing is ever read from it.
    """
    result = {'entries': [], 'state': LEDGER_LINE_UNPARSEABLE, 'notes': [], 'merge_base': '',
              'tip': '', 'header': {}}
    tip_entries, tip_state, tip_notes, _hdr, tip_sha = read_at_ref(repo, default_ref, path)
    result['tip'] = tip_sha
    if not tip_sha:
        result['notes'] = ['default branch: ' + n for n in tip_notes]
        return result
    rc, out, err = _git(repo, 'merge-base', tip_sha, head_ref)
    if rc != 0 or not out.strip():
        result['notes'] = ['no merge base between %s and %s (%s). A shallow clone looks exactly '
                           'like this -- fetch the default branch with history. Without a merge '
                           'base there is no defensible grandfathering point'
                           % (default_ref, head_ref, err or 'none found')]
        return result
    mb = out.decode().strip()
    result['merge_base'] = mb
    mb_entries, mb_state, mb_notes, mb_header, _sha = read_at_ref(repo, mb, path)
    result['header'] = mb_header
    notes = ['merge base %s: %s' % (mb[:12], '; '.join(mb_notes)),
             'default tip %s: %s' % (tip_sha[:12], '; '.join(tip_notes))]
    for state in (mb_state, tip_state):
        if state not in USABLE:
            result['state'] = state
            result['notes'] = notes + (['the ledger did not exist when this branch left the default '
                                        'branch; rebase onto it'] if mb_state == LEDGER_ABSENT else [])
            return result
    still = set((_s(e['identity']), _s(e['environment'])) for e in tip_entries)
    effective = [e for e in mb_entries if (_s(e['identity']), _s(e['environment'])) in still]
    dropped = len(mb_entries) - len(effective)
    if dropped:
        notes.append('%d entr(y/ies) removed on the default branch since the merge base: no longer '
                     'grandfathered (strengthening takes effect at once)' % dropped)
    added = len(still - set((_s(e['identity']), _s(e['environment'])) for e in mb_entries))
    if added:
        notes.append('%d entr(y/ies) added on the default branch since the merge base: NOT '
                     'grandfathered for this evaluation (nothing is added underneath an open PR)'
                     % added)
    result['entries'] = effective
    result['state'] = LEDGER_INTACT if effective else LEDGER_EMPTY
    result['notes'] = notes
    return result


def _selftest():
    fails = []
    sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
    from finding_identity import identify
    ident = identify({'finding_subject': 'SOURCE_DEPENDENCY', 'cve': 'CVE-2018-18074',
                      'purl': 'pkg:pypi/requests@2.19.1'})
    prov = {'run_id': '7', 'observed_at': '2026-02-01T00:00:00Z', 'observed_at_source': 'SIDECAR'}
    e = entry_from_identity(ident, 'prod', '2026-02-01', prov, True)
    hdr = {'established_on': '2026-02-01', 'established_commit': 'c' * 40, 'approver_role': 'sec'}
    text = serialise(new_ledger(hdr, [e]))
    entries, state, notes, _h2 = parse_ledger(text)
    if state != LEDGER_INTACT or len(entries) != 1:
        fails.append('a well-formed ledger did not round-trip: %s %r' % (state, notes))
    if serialise(json.loads(text)) != text:
        fails.append('serialisation is not stable, so every write would be a noisy diff')
    for mut, label in ((lambda d: d['entries'][0].update(age_established=True,
                                                        first_seen_provenance=dict(prov, observed_at_source='FILE_MTIME')),
                        'an established age from FILE_MTIME'),
                       (lambda d: d['entries'][0].update(colour='red'), 'an unknown field'),
                       (lambda d: d['entries'][0].update(message='x'), 'a scanner message'),
                       (lambda d: d.update(extra=1), 'an unknown top-level field')):
        d = json.loads(text)
        mut(d)
        _e, st, nt, _hh = parse_ledger(json.dumps(d))
        if st != LEDGER_LINE_UNPARSEABLE or not nt:
            fails.append('%s was accepted (%s)' % (label, st))
    try:
        entry_from_identity(ident, 'prod', '2026-02-01', prov, True, snippet='x')
        fails.append('entry_from_identity accepted a snippet')
    except ValueError:
        pass
    if fails:
        for f in fails:
            sys.stderr.write('FAIL: %s\n' % f)
        return 2
    print('baseline_ledger selftest ok: a ledger round-trips and serialises stably; an established '
          'age from a non-claimable source, an unknown field, matched material and an unknown '
          'top-level field each make the whole ledger unusable. The git-ref read rules are '
          'proven by tests/prove_ledger_read_authority.py.')
    return 0


def main(argv=None):
    ap = argparse.ArgumentParser(description='Read the baseline ledger the PR-safe way.')
    ap.add_argument('--self-test', action='store_true')
    ap.add_argument('--repo', default='.')
    ap.add_argument('--default-ref', default='')
    ap.add_argument('--head-ref', default='HEAD')
    ap.add_argument('--path', default=default_ledger_path)
    ap.add_argument('--out', default='')
    a = ap.parse_args(argv)
    if a.self_test:
        return _selftest()
    if not a.default_ref:
        print('--default-ref is required: the ledger is read from the protected default branch, '
              'and there is no default for which branch that is', file=sys.stderr)
        return 2
    r = read_for_evaluation(a.repo, a.default_ref, a.head_ref, a.path)
    print('%s  (%d effective entr(y/ies))' % (r['state'], len(r['entries'])))
    for n in r['notes']:
        print('  ' + n)
    if a.out:
        with io.open(a.out, 'w', encoding='utf-8') as fh:
            json.dump(r, fh, indent=2, sort_keys=True)
    return 0 if r['state'] in USABLE else 1


if __name__ == '__main__':
    sys.exit(main())

#!/usr/bin/env python3
"""Build and VALIDATE the run record (schemas/assurance-result.schema.json) from what the security
gate established. (ledger L36)

    The schema is the machine contract for a security run; until now nothing emitted it. This
    builds it from the gate's own outputs only -- nothing re-derived, nothing invented -- and
    validates it against the schema before anything is emitted. A record that does not validate is
    NOT emitted: an invalid contract handed to a consumer is worse than an absent one, which a
    consumer can at least see is absent.

    Inputs arrive through the environment (the gate step's outputs, as data):
      ASSURANCE, ENFORCEMENT, SECRET_GATE, DISCOVERY, SCANNER_STATES (JSON object id -> state),
      REPORT_RESULT, BLOCKING_FINDINGS, EVIDENCE_ARTIFACT, REPOSITORY, REPOSITORY_ID, COMMIT_SHA,
      REF, RUN_ID.

    evidence_state: CANONICAL only when the report job succeeded AND published a findings count;
    PARTIAL when it succeeded without one; UNAVAILABLE otherwise. publication_state is
    NOT_ATTEMPTED: the gate publishes nothing itself. An UNAVAILABLE scanner carries reason
    INFRASTRUCTURE_UNKNOWN -- the gate cannot tell billing from timeout, and the schema requires a
    reason rather than silence. capture_state is BOUND only when repository, commit and run id are all
    present; a record with no commit or run id is refused (the schema requires both).

USAGE  python3 run_record.py [--schema PATH] [--out FILE] [--github-output FILE]
EXIT   0 valid and emitted   1 invalid, not emitted (reasons printed)
"""
import argparse
import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
DEFAULT_SCHEMA = os.path.join(os.path.dirname(HERE), 'schemas', 'assurance-result.schema.json')


# The environment-variable NAMES the composite sets (names of data, never states).
SCANNER_STATES = 'SCANNER_STATES'
REPORT_RESULT = 'REPORT_RESULT'
BLOCKING_FINDINGS = 'BLOCKING_FINDINGS'
SECRET_GATE = 'SECRET_GATE'
EVIDENCE_ARTIFACT = 'EVIDENCE_ARTIFACT'
SECRET_EXCEPTIONS = 'SECRET_EXCEPTIONS'
POLICY_EXCEPTIONS = 'POLICY_EXCEPTIONS'


def _renewals(v):
    """A renewal count as the integer it is; anything unreadable is None (never 0)."""
    try:
        n = int(str(v).strip())
    except (TypeError, ValueError):
        return None
    return n if n >= 0 else None


def _e(name):
    return (os.environ.get(name) or '').strip()


def build():
    problems = []
    try:
        states = json.loads(_e('SCANNER_STATES') or '{}')
    except ValueError:
        states, problems = None, ['SCANNER_STATES is not JSON']
    if states is not None and not isinstance(states, dict):
        states, problems = None, ['SCANNER_STATES is not a JSON object']
    scanners = []
    for sid, st in sorted((states or {}).items()):
        entry = {'id': str(sid), 'state': st}
        if st == 'UNAVAILABLE':
            entry['reason'] = 'INFRASTRUCTURE_UNKNOWN'
        scanners.append(entry)
    report, count = _e('REPORT_RESULT'), _e('BLOCKING_FINDINGS')
    evidence = 'CANONICAL' if report == 'success' and count else ('PARTIAL' if report == 'success' else 'UNAVAILABLE')
    repo, sha, run_id = _e('REPOSITORY'), _e('COMMIT_SHA'), _e('RUN_ID')
    prov = {'repository': repo, 'commit_sha': sha, 'run_id': run_id,
            'capture_state': 'BOUND' if (repo and sha and run_id) else ('PARTIAL' if (repo or sha or run_id) else 'UNBOUND')}
    if repo and '/' in repo:
        prov['organization'] = repo.split('/', 1)[0]
    for k, v in (('repository_id', _e('REPOSITORY_ID')), ('ref', _e('REF'))):
        if v:
            prov[k] = v
    rec = {'schema_version': 1, 'assurance_state': _e('ASSURANCE'), 'enforcement_state': _e('ENFORCEMENT'),
           'secret_gate': _e('SECRET_GATE') or 'NOT_APPLICABLE', 'discovery_state': _e('DISCOVERY'),
           'evidence_state': evidence, 'publication_state': 'NOT_ATTEMPTED',
           'evidence_artifact_name': _e('EVIDENCE_ARTIFACT'), 'scanners': scanners, 'provenance': prov}
    # EVERY APPLIED SECRET EXCEPTION, BY FINDING (owner ruling 2026-10-22, lane L-S): the ticket,
    # the approver and the expiry are the log the owner asked for. Unreadable is a problem, never [].
    sx_text = _e('SECRET_EXCEPTIONS') or '[]'
    try:
        sx = json.loads(sx_text)
    except ValueError:
        sx, problems = [], problems + ['SECRET_EXCEPTIONS is not JSON']
    if not isinstance(sx, list):
        sx, problems = [], problems + ['SECRET_EXCEPTIONS is not a JSON list']
    if sx:
        rec['secret_exceptions'] = []
        for x in sx:
            row = dict((k, str((x or {}).get(k, ''))) for k in ('finding', 'ticket', 'approver', 'expires', 'entry'))
            # KDEC-018 item 4: whether it was excepted before, how often, since when, on which tickets.
            n = _renewals((x or {}).get('renewals', 0))
            if n is None:
                problems.append('a secret exception\'s renewal count is unreadable')
                n = 0
            row['renewals'] = n
            row['history'] = str((x or {}).get('history') or 'first exception')
            rec['secret_exceptions'].append(row)
    # EVERY REGISTER SOFTENING IN FORCE, with its history (KDEC-018 item 4): the policy step's
    # weakening rows that came from a register entry ("policy entry <id>").
    pe_text = _e('POLICY_EXCEPTIONS') or '[]'
    try:
        pe = json.loads(pe_text)
    except ValueError:
        pe, problems = [], problems + ['POLICY_EXCEPTIONS is not JSON']
    if not isinstance(pe, list):
        pe, problems = [], problems + ['POLICY_EXCEPTIONS is not a JSON list']
    rows = []
    for x in pe:
        inp = str((x or {}).get('input') or '') if isinstance(x, dict) else ''
        if not inp.startswith('policy entry '):
            continue
        n = _renewals(x.get('renewals', 0))
        if n is None:
            problems.append('a policy exception\'s renewal count is unreadable')
            n = 0
        rows.append({'entry': inp[len('policy entry '):], 'control': str(x.get('control') or ''),
                     'authority': str(x.get('authority') or ''), 'expires': str(x.get('expires') or ''),
                     'exception_ref': str(x.get('exception_ref') or ''), 'renewals': n,
                     'history': str(x.get('history') or 'first exception')})
    if rows:
        rec['policy_exceptions'] = rows
    if count.isdigit():
        # The gate knows the blocking count, not its split by severity: it is recorded as the
        # count it is (high = blocking-severity), never spread across levels it did not measure.
        rec['findings'] = {'high': int(count)}
    if not sha:
        problems.append('no commit_sha: the record would not say which code it is about')
    if not run_id:
        problems.append('no run_id: the record would not say which run produced it')
    return rec, problems


def validate(rec, schema_path):
    """-> list of problems. jsonschema when present; otherwise the schema's own required / enum /
    additionalProperties rules, applied recursively (the subset this schema uses)."""
    schema = json.load(open(schema_path, encoding='utf-8'))
    try:
        import jsonschema
        v = jsonschema.Draft202012Validator(schema) if hasattr(jsonschema, 'Draft202012Validator') else None
        if v is not None:
            return ['%s: %s' % ('/'.join(str(x) for x in e.path) or '(root)', e.message) for e in v.iter_errors(rec)]
    except ImportError:
        pass
    out = []

    def walk(node, sch, where):
        if 'const' in sch and node != sch['const']:
            out.append('%s: %r is not %r' % (where, node, sch['const']))
        if 'enum' in sch and node not in sch['enum']:
            out.append('%s: %r is not one of %s' % (where, node, sch['enum']))
        if sch.get('type') == 'object' or 'properties' in sch:
            if not isinstance(node, dict):
                out.append('%s: not an object' % where)
                return
            for r in sch.get('required', []):
                if r not in node:
                    out.append('%s: %s is required' % (where, r))
            props = sch.get('properties', {})
            for k, val in node.items():
                if k in props:
                    walk(val, props[k], '%s/%s' % (where, k))
                elif sch.get('additionalProperties') is False:
                    out.append('%s: %s is not allowed' % (where, k))
        if sch.get('type') == 'array':
            if not isinstance(node, list):
                out.append('%s: not an array' % where)
                return
            for i, item in enumerate(node):
                walk(item, sch.get('items', {}), '%s/%d' % (where, i))
        if sch.get('type') == 'integer' and (not isinstance(node, int) or node < sch.get('minimum', node)):
            out.append('%s: not a valid integer' % where)
        if sch.get('type') == 'string' and not isinstance(node, str):
            out.append('%s: not a string' % where)
    walk(rec, schema, '(root)')
    return out


def main(argv=None):
    ap = argparse.ArgumentParser(description='Build and validate the run record.')
    ap.add_argument('--schema', default=DEFAULT_SCHEMA)
    ap.add_argument('--out', default='')
    ap.add_argument('--github-output', default='')
    a = ap.parse_args(argv)
    rec, problems = build()
    problems += validate(rec, a.schema)
    valid = not problems
    for pr in problems:
        print('run record refused: %s' % pr)
    compact = json.dumps(rec, sort_keys=True, separators=(',', ':'))
    if valid and a.out:
        with open(a.out, 'w', encoding='utf-8') as fh:
            json.dump(rec, fh, indent=2, sort_keys=True)
    if a.github_output:
        with open(a.github_output, 'a', encoding='utf-8') as fh:
            fh.write('run_record=%s\n' % ('valid' if valid else 'invalid'))
            fh.write('assurance_result=%s\n' % (compact if valid else ''))
    print('run record %s (%d scanner(s), evidence %s, identity %s)'
          % ('valid' if valid else 'INVALID, not emitted', len(rec['scanners']), rec['evidence_state'],
             rec['provenance']['capture_state']))
    return 0 if valid else 1


if __name__ == '__main__':
    sys.exit(main())

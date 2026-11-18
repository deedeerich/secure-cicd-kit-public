#!/usr/bin/env python3
"""KE-07 (KDEC-051): an exported approval carries its own dates, checked and never changed. NO NETWORK.

WHY
    scripts/evidence_export.decision_of checked the decision object's keys, schema, vocabulary and basis, but not
    its dates or its separation-of-duties value: APPROVED_EFFECTIVE was exported unchanged with an expiry before
    its own evaluation date, with expires "never", with expires null, and with separation_of_duties "ESTABLISHED"
    (which the evaluator can never write). Probe recon5/kit-enf p2_adversarial C2 to C5.

THE CONTRACT (reviewer requirement adopted by the coordinator, 2026-11-11; every default PROPOSED)
    The exported object is the ORIGINAL record, evaluated on its evaluated_on: never re-dated, never re-decided.
    Whether it still holds at a later review is a SEPARATE, separately dated evaluation described by
    api/v1/disposition-review.contract.json (kit-disposition-review/1), which the evidence harness vendors with
    the export schema. tests/fixtures/approval_review/cases.json is the ONE fixture both legs read
    (tests/prove_kit_harness_pair.py runs both and fails when either leg did not run).

WHAT IT PROVES
  POSITIVE
    A1  an approved, in-date object (expires on or after evaluated_on, separation_of_duties NOT_ESTABLISHED) is
        exported APPROVED_EFFECTIVE verbatim, its dates unchanged, and validates against the export schema
    A2  the contract names the decision object's eleven fields, the decision schema, every check with a pass,
        fail and not-established state, and the staleness policy as a PROPOSED default (never an expiry)
    A3  the legacy-key window's closing date lives in ONE constant (scripts/scan_report.py
        legacy_key_window_days; closes derived): no script restates the date, and changing that one line moves
        the window (a copy of scan_report with 37 days honours a legacy key on 2026-11-20; 30 days does not)
  NEGATIVE (the shared fixture's kit expectations; each reason names the guard)
    AN1 expires before evaluated_on (C2)    -> DECISION_NOT_ESTABLISHED "before its own evaluation"
    AN2 expires "never" (C3)                -> DECISION_NOT_ESTABLISHED "is not a date"
    AN3 expires null (C4)                   -> DECISION_NOT_ESTABLISHED "no expiry date"
    AN4 separation_of_duties ESTABLISHED (C5) -> DECISION_NOT_ESTABLISHED "the kit cannot establish it"
    AN5 the schema refuses an object with expires "never" and with separation_of_duties ESTABLISHED
  MUTANTS (a modified copy of the source; the original is untouched)
    expiry_cross_check_removed -> AN1   non_date_expiry_passed -> AN2   missing_expiry_read_as_unexpired -> AN3
    sod_copied_unchecked -> AN4         schema_sod_enum_dropped / schema_expires_pattern_dropped -> AN5
    legacy_window_restated (a second constant) -> A3

    --emit-leg PATH writes the kit leg's results for the pair test (tests/prove_kit_harness_pair.py).

EXIT  0 proven   1 a case failed (named)   2 could not be checked
"""
import copy
import datetime
import hashlib
import io
import json
import os
import re
import sys
import types

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
SCRIPTS = os.path.join(ROOT, 'scripts')
sys.path.insert(0, SCRIPTS)
CASES = os.path.join(HERE, 'fixtures', 'approval_review', 'cases.json')
CONTRACT = os.path.join(ROOT, 'api', 'v1', 'disposition-review.contract.json')
SCHEMA = os.path.join(ROOT, 'api', 'v1', 'evidence-export.schema.json')
FAILS = []


def check(cond, msg):
    print('  %s %s' % ('ok  ' if cond else 'FAIL', msg))
    if not cond:
        FAILS.append(msg)
    return bool(cond)


def lf_sha(path):
    return hashlib.sha256(io.open(path, 'rb').read().replace(b'\r\n', b'\n')).hexdigest()


def load(path):
    return json.load(io.open(path, encoding='utf-8'))


def case_inputs(fx, case):
    """-> (decision, basis, finding, facts, review_on) for one case of the shared fixture."""
    dec = copy.deepcopy(fx['base_decision'])
    dec.update(copy.deepcopy(case.get('decision') or {}))
    fnd = dict(fx['base_finding'], **(case.get('finding') or {}))
    facts = case.get('facts')
    if facts == 'full':
        facts = dict(fx['full_facts'])
    elif isinstance(facts, dict):
        facts = dict(fx['full_facts'], **facts)
    return dec, case.get('basis', 'durable'), fnd, facts, case['review_on']


def module_from(path, old=None, new=None, name='mutant'):
    text = io.open(path, encoding='utf-8').read()
    if old is not None:
        if text.count(old) != 1:
            raise ValueError('mutant anchor found %d time(s) in %s' % (text.count(old), os.path.basename(path)))
        text = text.replace(old, new)
    m = types.ModuleType(name)
    m.__file__ = path
    exec(compile(text, path, 'exec'), m.__dict__)
    return m


LEGACY_CONTEXT = re.compile(r'legacy|window|migration|OD-6', re.I)


def restatements(texts, closes):
    """-> the scripts that spell the legacy window's closing date (A3: it must live in one derived constant).

    A line counts when it holds the date AND speaks of the legacy window (legacy, window, migration, OD-6). A
    fixture's coincidental expiry on the same day (a self-test's '2026-12-31' exception) is not a restatement;
    a second constant or a message that spells the close is (mutant legacy_window_restated)."""
    return [n for n, t in sorted(texts.items())
            if any(closes in ln and LEGACY_CONTEXT.search(ln) for ln in t.split('\n'))]


def decision_schema(schema):
    return (schema['properties']['sections']['properties']['findings']['properties']['findings']['items']
            ['properties']['disposition_decision'])


WANT_REASON = {'N2_expired_before_evaluation_KE-07_C2': 'before its own evaluation',
               'N3_expires_never_KE-07_C3': 'is not a date',
               'N4_expires_null_KE-07_C4': 'no expiry date',
               'N5_sod_claimed_KE-07_C5': 'the kit cannot establish it'}


def kit_leg(ee, fx):
    """-> {case id: exported object} through decision_of (the kit leg of the pair)."""
    out = {}
    for case in fx['cases']:
        dec, basis, _f, _facts, _r = case_inputs(fx, case)
        out[case['id']] = ee.decision_of(dec, basis)
    return out


def kit_cases_hold(ee, fx, schema, quiet=False):
    """-> [failing case ids] for the kit expectations of the shared fixture (effective decision, guard reason)."""
    import kit_api as ka
    bad = []
    for cid, out in sorted(kit_leg(ee, fx).items()):
        case = [c for c in fx['cases'] if c['id'] == cid][0]
        want = case['expect']['kit_effective']
        ok = out is not None and out.get('effective_decision') == want
        if ok and cid in WANT_REASON:
            ok = WANT_REASON[cid] in out.get('reason', '')
        if ok:
            ok = not ka.validate(out, decision_schema(schema))
        if ok and want == 'APPROVED_EFFECTIVE':
            dec, _b, _f, _x, _r = case_inputs(fx, case)
            ok = out['evaluated_on'] == dec['evaluated_on'] and out['expires'] == dec['expires']
        if not ok:
            bad.append(cid)
    return bad


def main(argv):
    import evidence_export as ee
    import kit_api as ka
    import scan_report as sr
    fx, contract, schema = load(CASES), load(CONTRACT), load(SCHEMA)
    if '--emit-leg' in argv:
        path = argv[argv.index('--emit-leg') + 1]
        res = kit_leg(ee, fx)
        bad = kit_cases_hold(ee, fx, schema)
        leg = {'leg': 'kit', 'ran': len(res), 'failed': bad, 'fixture_sha256': lf_sha(CASES),
               'contract_sha256': lf_sha(CONTRACT), 'export_schema_sha256': lf_sha(SCHEMA),
               'results': [{'id': k, 'basis': case_inputs(fx, c)[1], 'exported': res[k]}
                           for c in fx['cases'] for k in [c['id']]]}
        with io.open(path, 'w', encoding='utf-8', newline='\n') as fh:
            json.dump(leg, fh, indent=1, sort_keys=True)
        print('kit leg: %d case(s), %d failed -> %s' % (len(res), len(bad), path))
        return 0 if res and not bad else 1

    print('KE-07 positive')
    bad = kit_cases_hold(ee, fx, schema)
    pos = [c['id'] for c in fx['cases'] if c['expect']['kit_effective'] == 'APPROVED_EFFECTIVE']
    check(pos and not [x for x in pos if x in bad],
          'A1 approved, in-date objects are exported APPROVED_EFFECTIVE, dates unchanged, schema-valid (%d)' % len(pos))
    rv = contract['review_evaluation']
    check(contract['applies_to'] == sr.DECISION_SCHEMA and contract['original_record']['fields'] == list(ee.DECISION_KEYS)
          and all(set(v) >= {'pass', 'fail', 'not_established'} for v in rv['checks'].values())
          and rv['check_order'] == ['expiry', 'revocation', 'scope', 'approver_authority', 'separation_of_duties']
          and rv['staleness']['policy_default_status'] == 'PROPOSED' and 'never an expiry' in rv['staleness']['rule'],
          'A2 the contract names the original fields, every check with three states, staleness a PROPOSED policy')
    # A3: ONE constant for the legacy window
    closes = sr.legacy_key_window_closes
    texts = dict((n, io.open(os.path.join(SCRIPTS, n), encoding='utf-8').read())
                 for n in sorted(os.listdir(SCRIPTS)) if n.endswith('.py'))
    restated = restatements(texts, closes)
    path = os.path.join(SCRIPTS, 'scan_report.py')
    longer = module_from(path, 'legacy_key_window_days = 78\n', 'legacy_key_window_days = 85\n', 'sr85')
    f = {'identity': 'i' * 32, 'fp': 'f' * 32}
    day = datetime.date(2027, 1, 5)
    check(closes == '2026-12-31' and not restated and longer.legacy_key_window_closes == '2027-01-07'
          and longer.disposition_for(f, {'f' * 32: {}}, day)[1] == 'legacy'
          and sr.disposition_for(f, {'f' * 32: {}}, day)[1] != 'legacy'
          and closes not in json.dumps(contract),
          'A3 the legacy window closes %s from ONE constant (scan_report.legacy_key_window_days); no script or the '
          'contract restates it; a one-line change moves it (restated in: %s)' % (closes, ', '.join(restated) or 'none'))

    print('KE-07 negative')
    for cid in sorted(WANT_REASON):
        check(cid not in bad, 'AN %s -> DECISION_NOT_ESTABLISHED, the reason naming "%s"' % (cid, WANT_REASON[cid]))
    ds = decision_schema(schema)
    base = fx['base_decision']
    check(ka.validate(dict(base, expires='never'), ds) and ka.validate(dict(base, separation_of_duties='ESTABLISHED'), ds)
          and not ka.validate(base, ds),
          'AN5 the schema refuses expires "never" and separation_of_duties ESTABLISHED; the base object validates')

    print('KE-07 mutants (each must be caught)')
    ee_path = os.path.join(SCRIPTS, 'evidence_export.py')
    for name, old, new, target in (
            ('expiry_cross_check_removed',
             '        elif expires is not None and evaluated is not None and expires < evaluated:\n',
             '        elif False:\n', 'N2_expired_before_evaluation_KE-07_C2'),
            ('non_date_expiry_passed', '    if exp_text is not None and expires is None:\n', '    if False:\n',
             'N3_expires_never_KE-07_C3'),
            ('missing_expiry_read_as_unexpired', '        if exp_text is None:\n', '        if False:\n',
             'N4_expires_null_KE-07_C4'),
            ('sod_copied_unchecked',
             "    if obj.get('separation_of_duties') != sr.DECISION_SOD_NOT_ESTABLISHED:\n", '    if False:\n',
             'N5_sod_claimed_KE-07_C5')):
        m = module_from(ee_path, old, new, 'ee_' + name)
        check(target in kit_cases_hold(m, fx, schema), 'mutant %s caught by %s' % (name, target))
    for name, key, field in (('schema_sod_enum_dropped', 'enum', 'separation_of_duties'),
                             ('schema_expires_pattern_dropped', 'pattern', 'expires')):
        s2 = copy.deepcopy(schema)
        del decision_schema(s2)['properties'][field][key]
        if key == 'enum':
            decision_schema(s2)['properties'][field]['type'] = ['string', 'null']
        caught = not (ka.validate(dict(base, expires='never'), decision_schema(s2)) and
                      ka.validate(dict(base, separation_of_duties='ESTABLISHED'), decision_schema(s2)))
        check(caught, 'mutant %s caught by AN5' % name)
    twin = dict(texts)
    twin['scan_report.py'] = twin['scan_report.py'].replace(
        'legacy_key_window_days = 78\n', "legacy_key_window_days = 78\nlegacy_close_text = '%s'\n" % closes, 1)
    check(restatements(twin, closes) == ['scan_report.py'] and not restated,
          'mutant legacy_window_restated (a second constant holding the date) caught by A3')

    print('%s: %d check(s) failed' % ('FAIL' if FAILS else 'PASS', len(FAILS)) if FAILS else 'PASS')
    return 1 if FAILS else 0


if __name__ == '__main__':
    try:
        sys.exit(main(sys.argv[1:]))
    except (OSError, ValueError, KeyError) as e:
        print('could not be checked: %s' % e)
        sys.exit(2)

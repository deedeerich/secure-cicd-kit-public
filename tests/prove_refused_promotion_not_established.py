#!/usr/bin/env python3
"""KREQ-322 (review round 2 F13, P1): a refused promotion record never reads as an established promotion. NO NETWORK.

WHY
    A promotion record is written for every deploy, including one whose promotion gate refused (a break-glass
    that overrode PROMOTION_REFUSED_HISTORY_INCOMPLETE, or a uat promotion the gate refused). The export's
    `promotion_records` section reads ESTABLISHED when such records were COLLECTED: that word is about the
    collection, never about the promotion decision. The decision travels as the gate's own code, verbatim. If
    the code were dropped anywhere on the way out (the record filter, the durable summary, or the release
    record's filter), a reader would see only a collected record and could take a refused promotion for an
    established one. The rows review (2026-11-11) found the guard built but un-named and without a mutant;
    the owner accepted that direction on 2026-11-13 (KDEC-052 item 3).

THE GUARDS (named; each carries a "KREQ-322 guard" comment in the source)
    G1  scripts/evidence_export.py  PROMOTION_RECORD['predecessor'] keeps `gate` and `overridden[].code`
    G2  scripts/reviewer_signals.py promotion_summary() keeps `state`, `gate` and the overridden codes
    G3  scripts/evidence_export.py  RELEASE_RECORD['promotion'] keeps `gate` and `overridden`
    The record's own `state` is written by scripts/promotion.py (break-glass reads BREAK_GLASS, an unhealthy
    deploy reads not-verified); this proof reads it from the record and checks it is carried verbatim.

WHAT IT PROVES (through the production path: evidence_export.assemble, reviewer_signals.promotion_summary)
  POSITIVE
    P1  an allowed promotion (gate PROMOTION_ALLOWED, state verified-for-promotion) is exported with that
        state and gate verbatim, in the record and in the durable summary
    P2  a deploy that was not a promotion (gate None) has an empty gate in its summary, never a refusal
  NEGATIVE
    N1  a refused uat promotion (gate PROMOTION_REFUSED_HISTORY_INCOMPLETE, state not-verified): the record
        and the durable summary carry the refusal code verbatim; no value inside either reads ESTABLISHED or
        verified-for-promotion
    N2  a break-glass prod deploy that overrode HISTORY_INCOMPLETE and TARGET_UNKNOWN: state BREAK_GLASS and
        both overridden codes, in the record and in the durable summary; never ESTABLISHED
  MUTANTS (a modified copy of the source; the original is untouched)
    summary_gate_dropped -> N1          summary_overridden_dropped -> N2
    summary_state_read_established -> N1, N2
    record_gate_dropped -> N1           release_summary_codes_dropped -> N1, N2

EXIT  0 proven   1 a case failed (named)   2 could not be checked
"""
import io
import os
import sys
import types

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
SCRIPTS = os.path.join(ROOT, 'scripts')
sys.path.insert(0, SCRIPTS)

REPO = 'o/r'
COMMIT = 'c' * 40
HIST = 'PROMOTION_REFUSED_HISTORY_INCOMPLETE'
TGT = 'PROMOTION_REFUSED_TARGET_UNKNOWN'
VERIFIED = 'verified-for-promotion'


def load(name, replace=None):
    """The module from its source, optionally with one anchored replacement (a named mutant)."""
    path = os.path.join(SCRIPTS, name + '.py')
    text = io.open(path, encoding='utf-8').read()
    if replace:
        old, new = replace
        if text.count(old) != 1:
            raise AssertionError('mutant anchor occurs %d times in %s: %r' % (text.count(old), name, old[:70]))
        text = text.replace(old, new)
    mod = types.ModuleType(name + '_under_test')
    mod.__file__ = path
    exec(compile(text, path, 'exec'), mod.__dict__)  # noqa: S102 -- the kit's own source
    return mod


def record(env, tier, state, gate, overridden=(), path='normal'):
    return {'schema': 'kit-promotion-record/1', 'record_id': '7-1-%s' % env, 'state': state, 'release_path': path,
            'artifact': {'digest': 'sha256:' + 'a' * 64},
            'environment': {'name': env, 'tier': tier, 'adapter': 'containerapp', 'target_resource_id': '/s/app'},
            'validity': {'expires_at': None}, 'run': {'id': '7', 'attempt': '1',
                                                    'url': 'https://github.com/o/r/actions/runs/7'},
            'predecessor': {'required': 'test', 'gate': gate,
                            'promoted_from': {'run_id': '6', 'environment': 'test', 'record_id': '6-1-test'},
                            'overridden': [{'code': c, 'why': 'free text never exported', 'by': 'x'}
                                           for c in overridden]}}


def export(ee, rs, rec):
    """One record through the real export: the live record AND the durable release record's summary."""
    summary = rs.promotion_summary(rec)
    payload = {'schema': 'kit-release-record/1', 'repository': REPO, 'run_id': '7', 'run_attempt': '1',
               'commit': COMMIT, 'environment': rec['environment']['name'], 'promotion': summary}
    raw = {'security_records': [], 'findings': [], 'review_signals': [], 'deployments': [
        ('deployment 9', {'id': 9, 'environment': rec['environment']['name'], 'payload': payload}, 'success')],
        'promotions': [('kit-promotion-record-x', rec)], 'outboxes': [], 'drained': [], 'sbom_digest': None,
        'commit': None, 'reads': {}, 'expired': []}
    doc = ee.assemble(REPO, COMMIT, {'kind': 'commit', 'ref': COMMIT}, raw)
    entries = doc['sections']['promotion_records']['records']
    live = [e['record'] for e in entries if 'record' in e]
    durable = [e['summary'] for e in entries if e.get('durable')]
    released = [r['payload'].get('promotion') for r in doc['sections']['release_records']['records']]
    return live, durable, released


def values(obj):
    if isinstance(obj, dict):
        for v in obj.values():
            for x in values(v):
                yield x
    elif isinstance(obj, list):
        for v in obj:
            for x in values(v):
                yield x
    else:
        yield obj


def g(obj, *keys):
    """A missing key reads None, so a dropped field fails the case's assertion, never a crash."""
    for k in keys:
        obj = obj.get(k) if isinstance(obj, dict) else None
    return obj


def codes(lst):
    return sorted(o.get('code') if isinstance(o, dict) else o for o in (lst or []))


def cases(ee, rs):
    """-> {case: (ok, detail)}"""
    out = {}
    live, durable, rel = export(ee, rs, record('uat', 'uat', VERIFIED, 'PROMOTION_ALLOWED'))
    ok = (len(live) == 1 and g(live[0], 'state') == VERIFIED and g(live[0], 'predecessor', 'gate') == 'PROMOTION_ALLOWED'
          and len(durable) == 1 and g(durable[0], 'state') == VERIFIED and g(durable[0], 'gate') == 'PROMOTION_ALLOWED'
          and rel and rel[0] and rel[0].get('gate') == 'PROMOTION_ALLOWED')
    out['P1'] = (ok, 'allowed promotion: live %r durable %r' % (live, durable))
    live, durable, rel = export(ee, rs, record('dev', 'dev', VERIFIED, None))
    ok = len(durable) == 1 and g(durable[0], 'gate') == '' and g(durable[0], 'overridden') == []
    out['P2'] = (ok, 'not a promotion: durable %r' % durable)

    live, durable, rel = export(ee, rs, record('uat', 'uat', 'not-verified', HIST))
    bad = set(values(live)) | set(values(durable)) | set(values(rel))
    ok = (len(live) == 1 and g(live[0], 'predecessor', 'gate') == HIST and g(live[0], 'state') == 'not-verified'
          and len(durable) == 1 and g(durable[0], 'gate') == HIST and g(durable[0], 'state') == 'not-verified'
          and rel and rel[0] and rel[0].get('gate') == HIST
          and 'ESTABLISHED' not in bad and VERIFIED not in bad)
    out['N1'] = (ok, 'refused promotion: live %r durable %r released %r' % (live, durable, rel))

    live, durable, rel = export(ee, rs, record('prod', 'prod', 'BREAK_GLASS', 'PROMOTION_ALLOWED', (HIST, TGT),
                                               path='break-glass'))
    bad = set(values(live)) | set(values(durable)) | set(values(rel))
    ok = (len(live) == 1 and g(live[0], 'state') == 'BREAK_GLASS' and codes(g(live[0], 'predecessor', 'overridden')) ==
          [HIST, TGT] and len(durable) == 1 and g(durable[0], 'state') == 'BREAK_GLASS'
          and codes(g(durable[0], 'overridden')) == [HIST, TGT] and rel and rel[0]
          and codes(rel[0].get('overridden')) == [HIST, TGT]
          and 'ESTABLISHED' not in bad and VERIFIED not in bad)
    out['N2'] = (ok, 'break-glass override: live %r durable %r released %r' % (live, durable, rel))
    return out


MUTANTS = (
    ('summary_gate_dropped', 'reviewer_signals', "'gate': pred.get('gate') or '',", "'gate': '',", ('N1',)),
    ('summary_overridden_dropped', 'reviewer_signals',
     "'overridden': [str(o.get('code')) for o in (pred.get('overridden') or [])",
     "'overridden': [str(o.get('code')) for o in []", ('N2',)),
    ('summary_state_read_established', 'reviewer_signals', "'state': pdoc.get('state', ''),",
     "'state': 'ESTABLISHED',", ('N1', 'N2')),
    ('record_gate_dropped', 'evidence_export', "'predecessor': {'required': None, 'gate': None,",
     "'predecessor': {'required': None,", ('N1',)),
    ('release_summary_codes_dropped', 'evidence_export',
     "'digest',\n                               'gate', 'overridden')", "'digest')", ('N1', 'N2')),
)


def main():
    try:
        ee, rs = load('evidence_export'), load('reviewer_signals')
        base = cases(ee, rs)
    except Exception as exc:  # noqa: BLE001
        print('NOT CHECKED: the production modules could not be loaded or run (%s: %s)' % (type(exc).__name__, exc))
        return 2
    fails = 0
    for name in ('P1', 'P2', 'N1', 'N2'):
        ok, detail = base[name]
        print('  %s %s' % ('PASS' if ok else 'FAIL', name))
        if not ok:
            print('      ' + detail[:600])
            fails += 1
    for label, mod, old, new, must_fail in MUTANTS:
        try:
            m = load(mod, (old, new))
            got = cases(m, rs) if mod == 'evidence_export' else cases(ee, m)
            caught = [c for c in must_fail if not got[c][0]]
            ok = caught == list(must_fail)
            why = 'caught by %s' % ', '.join(caught) if ok else 'NOT caught by %s' % ', '.join(
                c for c in must_fail if c not in caught)
        except AssertionError as exc:
            ok, why = False, 'anchor problem: %s' % exc
        except Exception as exc:  # noqa: BLE001 -- a crash is not a guard's refusal: it does not count
            ok, why = False, 'crashed before reaching the guard (%s: %s)' % (type(exc).__name__, exc)
        print('  %s mutant %s: %s' % ('PASS' if ok else 'FAIL', label, why))
        fails += 0 if ok else 1
    if fails:
        print('FAIL: %d case(s) of KREQ-322 failed: a refused promotion could read as established' % fails)
        return 1
    print('PASS: KREQ-322 a refused or overridden promotion carries its gate code verbatim in the record, the durable '
          'summary and the release record, and never reads ESTABLISHED (4 cases, %d named mutants caught)'
          % len(MUTANTS))
    return 0


if __name__ == '__main__':
    sys.exit(main())

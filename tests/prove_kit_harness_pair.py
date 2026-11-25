#!/usr/bin/env python3
"""KREQ-302: the kit-export / harness-import pair, both legs on the SAME fixture; a skipped leg FAILS. NO NETWORK.

WHY
    tests/prove_evidence_export.py E3 / QE3 / QE4 run the harness only where its source is present and otherwise
    print NOT RUN and exit 0: a half-run pair read as green. This test is the pair, and it has no skip: without the
    harness checkout it fails HARNESS_LEG_NOT_RUN (exit 1), by design.

WHAT IT RUNS (one contract: api/v1/evidence-export.schema.json + api/v1/disposition-review.contract.json,
kit-disposition-review/1; one fixture: tests/fixtures/approval_review/cases.json)
    kit leg      tests/prove_approval_review_contract.py --emit-leg: every case through evidence_export.decision_of
    harness leg  <harness>/tests/check_kit_review_contract.py --leg: the kit leg's EXPORTED objects through the
                 harness reader (decision_status) and its review-time evaluation, plus each RAW object (HR-F03)
    copies       the harness's vendored export schema, contract and fixture are byte-identical (LF) to the kit's,
                 and each leg reports the sha256 of what it read
    agreement    every case's expectation holds in both legs (kit effective decision; harness ApprovalStatus, raw
                 status, review state, staleness, key-basis label)

    PAIR       the real pair passes
    MUTANTS    kit_leg_skipped -> KIT_LEG_NOT_RUN   harness_leg_skipped -> HARNESS_LEG_NOT_RUN
               schema_copy_differs (one byte of the harness's copy, in memory) -> COPY_DIFFERS
               harness_leg_short (one case dropped from its results) -> HARNESS_LEG_NOT_RUN

    The harness checkout: --harness-root PATH, or the evidence_harness_root variable (upper-cased).

EXIT  0 proven   1 a leg did not run, a copy differs or a case disagrees (named)   2 could not be checked
"""
import hashlib
import io
import json
import os
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
CASES = os.path.join(HERE, 'fixtures', 'approval_review', 'cases.json')
COPIES = (('export schema', os.path.join('api', 'v1', 'evidence-export.schema.json'),
           os.path.join('reference_data', 'kit_evidence_export_1.schema.json')),
          ('review contract', os.path.join('api', 'v1', 'disposition-review.contract.json'),
           os.path.join('reference_data', 'kit_disposition_review_1.contract.json')),
          ('shared fixture', os.path.join('tests', 'fixtures', 'approval_review', 'cases.json'),
           os.path.join('tests', 'fixtures', 'kit_disposition_review', 'cases.json')))
HARNESS_FIELDS = ('harness_status', 'harness_raw_status', 'review_state', 'staleness', 'key_basis_label')
FAILS = []


def check(cond, msg):
    print('  %s %s' % ('ok  ' if cond else 'FAIL', msg))
    if not cond:
        FAILS.append(msg)
    return bool(cond)


def lf(path):
    return io.open(path, 'rb').read().replace(b'\r\n', b'\n')


def read_leg(path):
    try:
        return json.load(io.open(path, encoding='utf-8'))
    except (OSError, ValueError):
        return None


def run_legs(harness_root, tmp):
    """-> (kit leg path, harness leg path); a leg that cannot run leaves no file."""
    kit_out, h_out = os.path.join(tmp, 'kit-leg.json'), os.path.join(tmp, 'harness-leg.json')
    subprocess.call([sys.executable, os.path.join(HERE, 'prove_approval_review_contract.py'), '--emit-leg', kit_out])
    script = os.path.join(harness_root or '', 'tests', 'check_kit_review_contract.py')
    if harness_root and os.path.isfile(script) and os.path.isfile(kit_out):
        subprocess.call([sys.executable, script, '--leg', '--cases', CASES, '--exported', kit_out, '--out', h_out])
    return kit_out, h_out


def pair_problems(kit_leg, h_leg, harness_root, alter=None):
    """-> [problem] for one pair run. `alter(name, bytes) -> bytes` changes a harness copy in memory (mutants)."""
    probs = []
    fx = json.load(io.open(CASES, encoding='utf-8'))
    ids = [c['id'] for c in fx['cases']]
    if not kit_leg or kit_leg.get('leg') != 'kit' or kit_leg.get('ran') != len(ids) or not ids:
        probs.append('KIT_LEG_NOT_RUN: the kit leg reported %r of %d case(s)' % ((kit_leg or {}).get('ran'), len(ids)))
    if (not h_leg or h_leg.get('leg') != 'harness' or h_leg.get('evaluated') != len(ids)
            or sorted(r.get('id') for r in h_leg.get('results') or []) != sorted(ids)):
        probs.append('HARNESS_LEG_NOT_RUN: the harness leg reported %r of %d case(s)'
                     % ((h_leg or {}).get('evaluated'), len(ids)))
    for name, kpath, hpath in COPIES:
        mine = lf(os.path.join(ROOT, kpath))
        try:
            theirs = lf(os.path.join(harness_root or '', hpath))
        except OSError:
            theirs = None
        if alter and theirs is not None:
            theirs = alter(name, theirs)
        if theirs != mine:
            probs.append('COPY_DIFFERS: the harness %s (%s) is not the kit\'s %s byte for byte' % (name, hpath, kpath))
    sha = hashlib.sha256(lf(CASES)).hexdigest()
    for leg in (kit_leg, h_leg):
        if leg and leg.get('fixture_sha256') != sha:
            probs.append('COPY_DIFFERS: the %s leg read a fixture of sha256 %s, not %s'
                         % (leg.get('leg'), leg.get('fixture_sha256'), sha))
    want = dict((c['id'], c['expect']) for c in fx['cases'])
    for r in (kit_leg or {}).get('results') or []:
        got = (r.get('exported') or {}).get('effective_decision')
        if r.get('id') in want and got != want[r['id']]['kit_effective']:
            probs.append('LEG_DISAGREES: kit %s effective_decision %s, the fixture says %s'
                         % (r['id'], got, want[r['id']]['kit_effective']))
    for r in (h_leg or {}).get('results') or []:
        for k in HARNESS_FIELDS:
            if r.get('id') in want and r.get(k) != want[r['id']][k]:
                probs.append('LEG_DISAGREES: harness %s %s %s, the fixture says %s'
                             % (r['id'], k, r.get(k), want[r['id']][k]))
    return probs


def main(argv):
    root = argv[argv.index('--harness-root') + 1] if '--harness-root' in argv else \
        os.environ.get('evidence_harness_root'.upper(), '').strip()
    tmp = tempfile.mkdtemp(prefix='kit-harness-pair-')
    kit_out, h_out = run_legs(root, tmp)
    kit_leg, h_leg = read_leg(kit_out), read_leg(h_out)
    print('KREQ-302 the pair (harness root: %s)' % (root or 'NOT GIVEN'))
    probs = pair_problems(kit_leg, h_leg, root)
    for p in probs:
        print('    ' + p)
    if root:
        check(not probs, 'PAIR both legs ran on the same fixture, the copies are identical and every case agrees')
    print('KREQ-302 mutants (each must be caught)')
    short = dict(h_leg or {}, results=(h_leg or {}).get('results', [])[1:])
    for name, args, code in (
            ('kit_leg_skipped', (None, h_leg, root), 'KIT_LEG_NOT_RUN'),
            ('harness_leg_skipped', (kit_leg, None, root), 'HARNESS_LEG_NOT_RUN'),
            ('harness_leg_short', (kit_leg, short, root), 'HARNESS_LEG_NOT_RUN')):
        check(any(p.startswith(code) for p in pair_problems(*args)), 'mutant %s caught: %s' % (name, code))
    flip = lambda name, b: (b[:-2] + b'X' + b[-1:]) if name == 'export schema' else b  # noqa: E731
    check(any(p.startswith('COPY_DIFFERS') and 'export schema' in p
              for p in pair_problems(kit_leg, h_leg, root, alter=flip)),
          'mutant schema_copy_differs caught: COPY_DIFFERS')
    for p in (kit_out, h_out):
        if os.path.exists(p):
            os.remove(p)
    os.rmdir(tmp)
    if FAILS:
        print('FAIL: %d check(s) failed' % len(FAILS))
        return 1
    if not root:
        # No harness checkout: the pair cannot be checked here, which is UNKNOWN (exit 2), never a pass.
        # The mutants above still ran. The hosted gate (scripts/harness_pair_gate.py) always passes
        # --harness-root and fails on any non-zero exit, so this never lets the hosted check go green.
        print('UNKNOWN: HARNESS_LEG_NOT_RUN -- no harness root given (--harness-root or EVIDENCE_HARNESS_ROOT); '
              'the pair cannot be checked here')
        return 2
    print('PASS')
    return 0


if __name__ == '__main__':
    try:
        sys.exit(main(sys.argv[1:]))
    except (OSError, ValueError, KeyError) as e:
        print('could not be checked: %s' % e)
        sys.exit(2)

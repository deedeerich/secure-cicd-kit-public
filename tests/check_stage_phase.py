#!/usr/bin/env python3
"""No stage may claim a maturity its evidence does not carry.

WHY THIS EXISTS

    The kit has a rung ladder for how hard a control BITES -- advisory through blocking -- and it is
    well developed. It has nothing for how far a stage has actually GOT.

    So every stage of the pipeline is discussed in the same voice whether it is running in
    production, written down as a proposal, or absent entirely. `SINGLE_PIPELINE_TARGET.md` is
    careful about this in prose, and prose is not a gate: a document saying "stage 13 is absent"
    sits in the same repository as a document describing what stage 13 will do, and six weeks later
    somebody cites the second one.

    That already happened once in a smaller way. `CAPABILITY_MATRIX.md` recorded 19/19 under a
    contract too weak to notice two dead scanners, and the matrix did not lie -- it reported
    evidence faithfully against a contract that could not detect the failure. The fix was a stronger
    contract, not a more careful reader.

    This is that, one level up. The phase of every stage is declared HERE, in code, with the
    evidence each claim requires, and the build fails when a claim outruns its evidence.

THE PHASE LADDER

    Each rung needs its own evidence. Nothing is inherited from the rung below, and nothing is
    inferred from the presence of a file.

        ABSENT      nothing exists
        DESIGNED    a document specifies it. Proves intent, nothing more.
        BUILT       code exists on a path something actually runs. Not a prototype, not a probe.
        EXERCISED   it has run. A run ID, against a named commit.
        PROVEN      it produced the RIGHT answer on seeded input, attributed to itself.
        ENFORCED    it refused a real prohibited operation, and the refusal was recorded.

    The two that get skipped are the two that matter. BUILT to PROVEN is where a dead scanner hides,
    because running and working are different. PROVEN to ENFORCED is where most controls in this
    programme stop. The first to cross it was deployment (stage 15): a deploy on a BLOCKED verdict,
    an irreversible production deploy and an overwrite of a second actor's change were each
    attempted live and refused, and the register cites those runs.

    CHECKED, NOT HOPED (G-07): a run claim must cite a run id; ENFORCED must cite its refusal run;
    BUILT code must be reached by something that runs; a stage the validation registry has observed
    at workflow level may not sit below EXERCISED; and every guardrail names the test a workflow
    runs to prove it, or says UNTESTED and why.

THE GUARDRAIL

    A stage may not emit a verdict stronger than its weakest input allows.

    Gating that reports PASS while evidence validity is PARTIAL is asserting a posture over
    reports that may have come from tools that read nothing. Correlation that clusters on an
    identity which resets every upgrade is grouping yesterday's findings. These are not style
    points: each one converts an unknown into a claim at a stage boundary, and the boundary is
    exactly where nobody is looking.

USAGE
    python tests/check_stage_phase.py
    python tests/check_stage_phase.py --self-test

EXIT
    0  every claim is supported and every guardrail is declared
    1  a claim outruns its evidence, or a stage is unregistered
    2  self-test failed
"""
import argparse
import glob
import io
import os
import re
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)

PHASES = ('ABSENT', 'DESIGNED', 'BUILT', 'EXERCISED', 'PROVEN', 'ENFORCED')
RANK = {p: i for i, p in enumerate(PHASES)}

# What each rung costs to claim. A claim at rung N must satisfy this and every rung below it.
EVIDENCE_REQUIRED = {
    'ABSENT':    'nothing',
    'DESIGNED':  'a document path that exists',
    'BUILT':     'a code path that exists AND is reachable from something that runs',
    'EXERCISED': 'a run id',
    'PROVEN':    'a run id AND a named seeded signal attributed to this stage',
    'ENFORCED':  'a recorded refusal of a real prohibited operation',
}

# ── the register ────────────────────────────────────────────────────────────────────
#
# Fifteen stages. `phase` is the CLAIM; everything else is what has to be true for it.
#
# `design` and `code` are repo-relative paths, checked for existence. `run` and `proof` are free
# text and are NOT checked -- a run id cannot be verified from inside the repository, so they are
# recorded for a human and the absence of one is what this file enforces.
#
# A stage whose phase outruns its evidence fails the build. A stage missing from here fails too:
# an unregistered stage is drift, and drift is how a fifteen-stage pipeline becomes a shrug.
#
# G-07 (completion ledger, lane L-E, 2026-10-21): this register was stale BOTH WAYS and nothing ran
# it. Stage 15 said DESIGNED while the registry cited live deploys and live refusals; stage 13 said
# no workflow calls its script while reusable-ticket-reconcile.yml does; stages 2 and 6 carried no
# run id (stage 6 cited "validate-scanners on main", which is not one). So three things are now
# CHECKED, not hoped:
#   - a claim of EXERCISED or above must cite a numeric run id (`run`), and ENFORCED a recorded
#     refusal with a run id (`refusal`);
#   - a stage BELOW EXERCISED whose registry capability (`capabilities`) is observed at WORKFLOW
#     level is understated -- the registry has a run the register is not citing;
#   - BUILT means reachable: the code path must be a workflow, or be named by a workflow or
#     composite that runs.
# Run ids are cited from tests/reconcile_validation.py and docs/assurance/RELEASE_1_EVIDENCE_MANIFEST.md.
STAGES = {
    # DESIGNED, not ABSENT: the rung, registration and axes libraries exist and are proven as
    # libraries (prove_rung_ladder, prove_policy_registration, prove_enforcement_axes), but nothing
    # that runs calls them -- the gate has no rung input and resolve-policy does not exist (ledger
    # S-01). Code that nothing runs earns no BUILT.
    1:  dict(name='policy resolution', phase='DESIGNED',
             design='docs/architecture/RUNG_DERIVATION_TABLE.md', code=None, run=None, proof=None,
             refuses='a run whose policy_mode was supplied rather than computed'),
    # The `discover` job's step bodies run from .github/actions/discover since 2026-10-15
    # (inline, they held the flagship over the 475 KB fail line); the job still lives in
    # reusable-security.yml and keeps its outputs. Proven locally by tests/test_discovery.py,
    # from the composite. EXERCISED on every consumer-path run: the seeded languages were
    # discovered and their scanners started (38934329462 on main ef4b15d; 38811950471 on the trunk).
    # Not PROVEN: no seeded signal is attributed to discovery itself on a runner.
    2:  dict(name='discovery', phase='EXERCISED',
             design=None, code='.github/actions/discover/action.yml',
             run='consumer-path 38934329462 (main ef4b15d); 38811950471 (trunk 13f1518)', proof=None,
             refuses='turning "not discovered" into "not applicable"'),
    # BUILT on 2026-10-14 (lane/version-fitness): the `resolve` job in reusable-security.yml
    # probes a target version per class and root with its evidence strength, and matches each
    # scanner's DECLARED range (scanner-registry.yaml version_support) against it. Its step
    # bodies run from .github/actions/resolve since 2026-10-15 (inline, they took the flagship
    # over the 500 KB ceiling). On a path that runs: every run of the reusable workflow. Proven
    # locally by tests/test_resolve.py against fixture trees, from the composite -- which is not
    # EXERCISED (no run id) and is deliberately not claimed.
    # CONSUMED since 2026-10-15 (KDEC-010, lane/capability-selection): the resolver selects,
    # per (capability, root), the first carried scanner that can read the target
    # (scanner-registry.yaml capability_selection); the gate caps a job pointed at a
    # VERSION_GAP at PARTIAL (never PASS, never a block) and names a substitution as one; the
    # report renders the same per row. Proven locally by tests/test_resolve.py,
    # tests/prove_bootstrap_failure.py, tests/prove_gate_routing.py and
    # tests/prove_capability_selection.py. WHAT IS NOT CLAIMED: a run id -- stage 4 stays BUILT
    # until a hosted run shows a capped row and a labelled substitution on a real repository.
    # The scanner jobs themselves still start on discover's outputs alone, by design: every
    # scanner runs; the selection decides what its silence may mean.
    3:  dict(name='version discovery', phase='BUILT',
             design='docs/architecture/PIPELINE_ORDERING_AND_SCAN_VALIDITY.md',
             code='.github/actions/resolve/action.yml', run=None, proof=None,
             refuses='treating an unreadable version as a supported one'),
    4:  dict(name='capability selection', phase='BUILT',
             design='docs/architecture/PIPELINE_ORDERING_AND_SCAN_VALIDITY.md',
             code='.github/actions/resolve/action.yml', run=None, proof=None,
             refuses='counting a VERSION_UNSUPPORTED scanner\'s silence as coverage'),
    # DESIGNED, and only that. The design is a proposal marked for owner review; the advisory
    # plan object `resolve` emits is a prototype of the data shape that nothing enforces, so it
    # earns no rung by itself. "Emitting a plan is not executing one."
    5:  dict(name='execution planning', phase='DESIGNED',
             design='docs/architecture/EXECUTION_PLANNING.md', code=None, run=None, proof=None,
             refuses='a job set nobody can read before it runs'),
    6:  dict(name='scanning', phase='PROVEN',
             design=None, code='.github/workflows/reusable-security.yml',
             run='consumer-path 38934329462 (main ef4b15d), negative 38934348351; 38811950471 (trunk)',
             proof='tool-pinned seeded signals, 20/20 attribution; negative control clean',
             capabilities=('codeql',),
             refuses='one scanner satisfying another scanner\'s assertion'),
    7:  dict(name='evidence validity', phase='BUILT',
             design='docs/architecture/PIPELINE_ORDERING_AND_SCAN_VALIDITY.md',
             code='.github/workflows/reusable-security.yml', run=None, proof=None,
             refuses='a zero-finding zero-artifact report reading as clean'),
    8:  dict(name='normalization', phase='BUILT',
             design=None, code='scripts/normalize_sarif.py', run=None, proof=None,
             refuses='publication before redaction'),
    9:  dict(name='baseline and classification', phase='BUILT',
             design=None, code='scripts/finding_identity.py', run=None, proof=None,
             refuses='an identity that resets when a scanner is upgraded'),
    10: dict(name='severity and disposition', phase='BUILT',
             design=None, code='scripts/scan_report.py', run=None, proof=None,
             refuses='a disposition read from anywhere but the protected branch'),
    11: dict(name='correlation', phase='BUILT',
             design='docs/architecture/PRIOR_CORRELATION_WORK.md',
             code='scripts/scan_report.py', run=None, proof=None,
             refuses='a cluster acting on anything but an anchored match'),
    # PROVEN, not ENFORCED: the consumer-path run's seeded findings blocked the caller and its
    # negative twin failed as designed -- the right answer on seeded input, attributed to the gate.
    # A seeded test is not a real prohibited operation, so ENFORCED is not claimed here (stage 15
    # holds the live refusals). The rung half of the design (S-01) is not built.
    12: dict(name='gating', phase='PROVEN',
             design='docs/architecture/ENFORCEMENT_TIERS_AND_FINDING_BASELINE.md',
             code='.github/workflows/reusable-security.yml',
             run='consumer-path 38934329462 (main ef4b15d); 38811950471 (trunk 13f1518)',
             proof='seeded findings blocked the caller; negative run 38934348351 failed as designed',
             capabilities=('security-gate',),
             refuses='a verdict emitted as a job result rather than an output'),
    # BUILT, and the word is doing exactly as much work as the ladder says and no more.
    #
    # WHAT EARNS IT: `scripts/reconcile_tickets.py` carries the Section 3 lookup cascade and is
    # called by `reusable-ticket-reconcile.yml` (W-1), which self-test calls on pull requests as a
    # negative control (the guard must refuse). The reconciler has run LIVE on the owner's personal
    # Jira (R-1, R-2, T-6..T-8, tests/live_ticketing_run.py; the registry records it at TOOL level).
    #
    # WHY NOT EXERCISED: the ladder's EXERCISED needs a run id against a named commit, and the live
    # Jira runs were a local script with transcripts kept outside this repository -- no GitHub run
    # id exists for any ticketing run, and the armed workflow has never run (ledger T-19, O-18).
    # No consumer template calls the workflow yet (L-W). Was (before 2026-10-21): "no workflow
    # calls this script", which stopped being true when W-1 landed.
    13: dict(name='ticket reconciliation', phase='BUILT',
             design='docs/architecture/TICKETING_CONTRACT.md',
             code='scripts/reconcile_tickets.py', run=None, proof=None,
             capabilities=('ticket-reconciliation',),
             refuses='creating a ticket before a lookup has established nothing is already there'),
    14: dict(name='reporting', phase='BUILT',
             design=None, code='.github/workflows/reusable-security.yml', run=None, proof=None,
             refuses='a verdict printed without the context label that bounds it'),
    # ENFORCED (was DESIGNED until 2026-10-21, which understated what the registry had cited for
    # five days). Both adapters ran live on the owner's test subscription through
    # live-deploy-acceptance.yml, and REAL prohibited operations were attempted and refused:
    # a deploy on a BLOCKED verdict refused before Azure login (38853176286, DEPLOY_REFUSED); an
    # irreversible deploy at prod refused before login (38853184615); a reversal that met a second
    # actor's change refused to overwrite it (38886279650, REVERSAL_REFUSED_CONFLICT). PROVEN on
    # seeded unhealthy digests: rollback verified against a fresh live read (38878189985,
    # 38855747496). Not claimed: a gate verdict flowing into deploy in ONE run (every live deploy
    # was given a typed verdict; ledger S-15).
    15: dict(name='deployment and verification', phase='ENFORCED',
             design='docs/architecture/ROLLBACK_CONTRACT.md',
             code='.github/workflows/reusable-deploy-appservice.yml',
             run='live-deploy-acceptance 38857271571, 38857259257 (healthy deploys)',
             proof='seeded unhealthy digests reversed and verified live: 38878189985, 38855747496',
             refusal='38853176286 deploy on a BLOCKED verdict refused before login; 38853184615 '
                     'irreversible prod deploy refused; 38886279650 second actor\'s change not '
                     'overwritten',
             capabilities=('deploy-appservice', 'deploy-containerapp'),
             refuses='reversing a change whose ownership or dependents are unestablished'),
}

# ── the inter-stage guardrails ──────────────────────────────────────────────────────
#
# (downstream, upstream, what the boundary must refuse). A guardrail is not a nice-to-have: each
# one names a place where an unknown becomes a claim because two stages met and neither owned the
# join. (Three fields, because tests/build_pipeline_overlays.py renders them; the test is below.)
GUARDRAILS = [
    (12, 7,  'gating must not emit PASS while evidence validity is PARTIAL -- a posture asserted '
             'over reports that may have come from tools that read nothing'),
    (12, 2,  'gating must not emit PASS when discovery failed -- skipped scanners project to '
             'NOT_APPLICABLE, and NOT_APPLICABLE over unscanned code is the collapse this kit exists '
             'to refuse'),
    (11, 9,  'correlation must not cluster on an identity that resets on upgrade, or it groups '
             'yesterday\'s findings under today\'s key'),
    (13, 11, 'no ticket may be created from an unanchored cluster -- one cluster is one obligation '
             'is at most one ticket'),
    (10, 9,  'a disposition may not be inherited by a finding whose identity was not matched, '
             'because the approval was given for something else'),
    (15, 12, 'deployment must not proceed on a gate verdict that was never emitted as an output'),
    (6,  4,  'a scanner must not run as coverage for a version its capability table does not claim'),
    (4,  3,  'capability selection must not answer SCANNER_SUPPORTS for a target that was not '
             'discovered, or for a constraint that merely overlaps the declared range -- undetermined '
             'is a gap, and assume-supported is the one forbidden answer'),
    (3,  2,  'version discovery must not report a version for a class discovery did not establish '
             'as present, and must not read a manifest it could not parse as a manifest that was '
             'absent -- unreadable is its own sentinel'),
    (7,  6,  'evidence validity must not read a scanner that failed to acquire as a scanner that '
             'found nothing'),
    (2,  1,  'discovery must not accept a narrowed scope from a policy nobody registered -- stage 1 '
             'is not on a running path, so every scope today is the default one, and a future policy '
             'that quietly excludes a root would be indistinguishable from a root that is not there'),
    (9,  8,  'classification must not assign identity across inconsistently rooted paths. One '
             'scanner reports scope-relative URIs where two others report repo-relative, so the '
             'same file arrives under two identities and one finding becomes two -- a live defect, '
             'open in FUTURE_WORK, and exactly the join this boundary owns'),
]

# TIED TO TESTS (G-07). A guardrail was a string, so a boundary nobody had ever tested read exactly
# like one a proof refused on every push. Each (downstream, upstream) now names either a test under
# tests/ that a workflow RUNS (checked: the file exists and a workflow invokes it), or the word
# UNTESTED followed by why -- an untested boundary is allowed, an unmarked one is not.
GUARDRAIL_TESTS = {
    (12, 7): 'tests/prove_capability_selection.py',
    (12, 2): 'tests/prove_bootstrap_failure.py',
    (11, 9): 'tests/prove_identity_durability.py',
    (13, 11): 'tests/prove_ticket_idempotency.py',
    (10, 9): 'tests/prove_baseline_cascade.py',
    (15, 12): 'tests/prove_deploy_gate.py',
    (6, 4): 'tests/prove_capability_selection.py',
    (4, 3): 'tests/test_resolve.py',
    (3, 2): 'tests/test_resolve.py',
    (7, 6): 'UNTESTED: acquisition failure is typed for gosec and cppcheck but no forced-failure '
            'proof exists for the flagship (ledger L09); prove_nvd_workflow_honest covers the NVD '
            'path only',
    (2, 1): 'UNTESTED: there is no policy resolution on a running path to narrow anything yet (S-01)',
    (9, 8): 'UNTESTED: the Trivy scope-relative URI defect is not re-traced and has no collision '
            'fixture (ledger FW-section-1)',
}

RUN_ID = re.compile(r'\b\d{8,}\b')


def invoked_by_a_workflow(root, rel):
    """True when a workflow or composite under .github/ runs `rel` (a `python... rel` line that is
    not a comment)."""
    pat = re.compile(r'^(?![ \t]*#)[^\n]*\bpython3?\b[^\n]*%s' % re.escape(rel), re.M)
    for p in (glob.glob(os.path.join(root, '.github', 'workflows', '*.yml'))
              + glob.glob(os.path.join(root, '.github', 'actions', '*', 'action.yml'))):
        if pat.search(io.open(p, encoding='utf-8', errors='replace').read()):
            return True
    return False


def _without_comments(text):
    """The text with comment lines and trailing ` # ...` comments removed. A comment that NAMES a
    file does not run it: lane L-A's gate cites wiring/gate-rung.patch.md in three comments of
    reusable-security.yml, and with comments counted that design note became "reached" -- the
    self-test's own unreached fixture -- so the BUILT-needs-reach control passed when it had to
    fail (Release 3 candidate, public job 119903702614)."""
    out = []
    for ln in text.splitlines():
        if ln.lstrip().startswith('#'):
            continue
        out.append(re.sub(r'\s#\s.*$', '', ln))
    return '\n'.join(out)


def reachable(root, rel):
    """BUILT means reachable from something that runs: the code path IS a workflow or composite, or
    a workflow or composite names it on a line that is not a comment."""
    if rel.startswith('.github/'):
        return True
    base = os.path.basename(rel)
    for p in (glob.glob(os.path.join(root, '.github', 'workflows', '*.yml'))
              + glob.glob(os.path.join(root, '.github', 'actions', '*', 'action.yml'))):
        if base in _without_comments(io.open(p, encoding='utf-8', errors='replace').read()):
            return True
    return False


def observed_at_workflow(caps):
    """-> the capabilities in `caps` the validation registry records observed at workflow level."""
    try:
        sys.path.insert(0, HERE)
        import reconcile_validation as R
    except Exception:  # noqa: BLE001 -- reported by the caller as a failure, never a pass
        return None
    return [c for c in caps if R.VALIDATION_REGISTRY.get(c, {}).get('state') == 'observed'
            and R.VALIDATION_REGISTRY.get(c, {}).get('level') == 'workflow']


def check(root=ROOT):
    """-> (failures, rows). A failure is a claim outrunning its evidence."""
    fails, rows = [], []

    for n in sorted(STAGES):
        s = STAGES[n]
        phase = s['phase']
        if phase not in RANK:
            fails.append('stage %d: unknown phase %r' % (n, phase))
            continue
        r = RANK[phase]

        missing = []
        if r >= RANK['DESIGNED'] and not s.get('design') and not s.get('code'):
            missing.append('claims %s with neither a design nor a code path' % phase)
        for key, label in (('design', 'design'), ('code', 'code')):
            p = s.get(key)
            if p and not os.path.exists(os.path.join(root, p)):
                missing.append('%s path does not exist: %s' % (label, p))
        if r >= RANK['BUILT'] and not s.get('code'):
            missing.append('claims %s with no code path' % phase)
        elif (r >= RANK['BUILT'] and os.path.exists(os.path.join(root, s['code']))
              and not reachable(root, s['code'])):
            missing.append('claims %s but %s is reached by no workflow or composite -- code '
                           'nothing runs is not BUILT' % (phase, s['code']))
        if r >= RANK['EXERCISED'] and not s.get('run'):
            missing.append('claims %s with no run id' % phase)
        elif r >= RANK['EXERCISED'] and not RUN_ID.search(str(s.get('run'))):
            missing.append('claims %s and its `run` (%r) cites no run id -- a description of '
                           'where a run might be is not a run' % (phase, s.get('run')))
        if r >= RANK['PROVEN'] and not s.get('proof'):
            missing.append('claims %s with no attributed seeded signal' % phase)
        if r >= RANK['ENFORCED'] and not RUN_ID.search(str(s.get('refusal') or '')):
            missing.append('claims ENFORCED with no recorded refusal -- cite the run in which a real '
                           'prohibited operation was attempted and refused (`refusal`)')
        if not s.get('refuses'):
            missing.append('declares no guardrail -- every stage must state what it refuses')
        # UNDERSTATED: the registry cites a workflow-level observation the register does not.
        caps = s.get('capabilities') or ()
        if caps and r < RANK['EXERCISED']:
            seen = observed_at_workflow(caps)
            if seen is None:
                missing.append('could not read the validation registry to compare capabilities')
            elif seen:
                missing.append('claims %s while tests/reconcile_validation.py records %s observed '
                               'at WORKFLOW level -- the register understates a run it does not '
                               'cite' % (phase, ', '.join(seen)))

        for m in missing:
            fails.append('stage %d (%s): %s' % (n, s['name'], m))
        rows.append((n, s['name'], phase, 'ok' if not missing else 'BLOCKING'))

    declared = set(g[0] for g in GUARDRAILS)
    for n in sorted(STAGES):
        if RANK[STAGES[n]['phase']] >= RANK['BUILT'] and n not in declared and n not in (8, 14):
            fails.append('stage %d (%s) is BUILT or beyond and no guardrail names it as a '
                         'downstream consumer' % (n, STAGES[n]['name']))
    for d, u, _w in GUARDRAILS:
        if d not in STAGES or u not in STAGES:
            fails.append('guardrail references an unregistered stage: %s -> %s' % (d, u))
        test = GUARDRAIL_TESTS.get((d, u))
        if test is None:
            fails.append('guardrail (%d, %d) has no test field -- name the test that proves it, or '
                         'mark it UNTESTED with a reason' % (d, u))
            continue
        if str(test).startswith('UNTESTED:') and len(test.strip()) > len('UNTESTED:') + 10:
            continue
        if not str(test).startswith('tests/'):
            fails.append('guardrail %s -> %s: test %r is neither a tests/ path nor UNTESTED with a '
                         'reason' % (d, u, test))
        elif not os.path.exists(os.path.join(root, test)):
            fails.append('guardrail %s -> %s: test %s does not exist' % (d, u, test))
        elif not invoked_by_a_workflow(root, test):
            fails.append('guardrail %s -> %s: test %s exists but no workflow runs it -- a proof '
                         'nothing runs is a string' % (d, u, test))

    return fails, rows


def self_test():
    fails = []

    # A phase above its evidence must fail, and the message must say which rung.
    saved = STAGES[2].copy()
    STAGES[2].update(phase='PROVEN', run=None)
    f, _ = check()
    if not any('stage 2' in x and 'no run id' in x for x in f):
        fails.append('a PROVEN claim with no run id was not refused')
    STAGES[2].update(saved)

    # A nonexistent path must fail rather than be assumed present.
    saved = STAGES[6].copy()
    STAGES[6]['code'] = 'does/not/exist.yml'
    f, _ = check()
    if not any('does not exist' in x for x in f):
        fails.append('a missing code path was not refused')
    STAGES[6].update(saved)

    # ENFORCED can never be claimed silently.
    saved = STAGES[6].copy()
    STAGES[6]['phase'] = 'ENFORCED'
    f, _ = check()
    if not any('stage 6' in x and 'no recorded refusal' in x for x in f):
        fails.append('an ENFORCED claim was accepted without a recorded refusal')
    STAGES[6].update(saved)

    # Every stage must declare what it refuses.
    saved = STAGES[2].copy()
    STAGES[2]['refuses'] = ''
    f, _ = check()
    if not any('declares no guardrail' in x for x in f):
        fails.append('a stage with no declared guardrail was accepted')
    STAGES[2].update(saved)

    # G-07: a `run` that names no run id does not support EXERCISED or above.
    saved = STAGES[6].copy()
    STAGES[6]['run'] = 'validate-scanners on main'
    f, _ = check()
    if not any('stage 6' in x and 'cites no run id' in x for x in f):
        fails.append('a PROVEN claim citing "validate-scanners on main" (no run id) was accepted')
    STAGES[6].update(saved)

    # G-07: a stage below EXERCISED whose capability is observed at workflow level is understated.
    saved = STAGES[15].copy()
    STAGES[15].update(phase='DESIGNED')
    f, _ = check()
    if not any('stage 15' in x and 'understates' in x for x in f):
        fails.append('stage 15 at DESIGNED with deploy-appservice observed at workflow level was '
                     'accepted')
    STAGES[15].clear()
    STAGES[15].update(saved)

    # G-07: BUILT code nothing runs is refused.
    saved = STAGES[9].copy()
    STAGES[9]['code'] = 'wiring/gate-rung.patch.md'   # exists; nothing that runs names it
    f, _ = check()
    if not any('stage 9' in x and 'reached by no workflow' in x for x in f):
        fails.append('a BUILT claim on code no workflow reaches was accepted')
    STAGES[9].update(saved)
    # ...and a comment naming the file is not reach (how the control above went green-when-red).
    if 'gate-rung' in _without_comments('  # wiring/gate-rung.patch.md\n  run: x  # gate-rung.md'):
        fails.append('a comment naming a file was counted as reaching it')

    # G-07: a guardrail's test must exist and be run by a workflow; UNTESTED needs a reason.
    saved_g = dict(GUARDRAIL_TESTS)
    k0, k1, k2 = [g[:2] for g in GUARDRAILS[:3]]
    GUARDRAIL_TESTS[k0] = 'tests/does_not_exist.py'
    GUARDRAIL_TESTS[k1] = 'UNTESTED:'
    del GUARDRAIL_TESTS[k2]
    f, _ = check()
    GUARDRAIL_TESTS.clear()
    GUARDRAIL_TESTS.update(saved_g)
    for want, why in (('does not exist', 'a guardrail naming a missing test was accepted'),
                      ('neither a tests/ path nor UNTESTED with a reason',
                       'a bare UNTESTED with no reason was accepted'),
                      ('has no test field', 'a guardrail with no test field was accepted')):
        if not any(want in x for x in f):
            fails.append(why)

    if len(STAGES) != 15:
        fails.append('expected 15 stages, found %d' % len(STAGES))

    if fails:
        for x in fails:
            sys.stderr.write('FAIL: %s\n' % x)
        return 2
    print('self-test ok: a phase above its evidence is refused and the message names the missing '
          'rung; a code path that does not exist is refused rather than assumed; ENFORCED cannot be '
          'claimed without a recorded refusal run; a stage declaring no guardrail is refused; a run '
          'field with no run id, an understated stage the registry has observed at workflow level, '
          'BUILT code nothing runs, and a guardrail whose test is missing, unmarked or reasonless '
          'are each refused')
    return 0


def main():
    ap = argparse.ArgumentParser(description='No stage may claim a maturity its evidence lacks.')
    ap.add_argument('--self-test', action='store_true')
    a = ap.parse_args()
    if a.self_test:
        return self_test()
    # The negative controls run on EVERY invocation, not only under --self-test: the local sweep
    # (tests/prove_tests_leave_tree_clean.py) runs this file with no arguments, and on the Release 3
    # candidate it reported exit=0 while the hosted --self-test failed. A checker whose controls
    # no longer fail cannot pass anything.
    if self_test() != 0:
        sys.stderr.write('FAIL: the stage-phase checker\'s own negative controls did not hold (above); '
                         'its verdict on the register cannot be trusted.\n')
        return 1

    fails, rows = check()

    print('')
    print('STAGE PHASE  -- what each stage has actually reached')
    print('=' * 78)
    for n, name, phase, state in rows:
        mark = ' ' if state == 'ok' else '!'
        print('%s %2d  %-30s %-10s' % (mark, n, name[:30], phase))
    print('')
    counts = {}
    for n in STAGES:
        counts[STAGES[n]['phase']] = counts.get(STAGES[n]['phase'], 0) + 1
    print('  ' + '   '.join('%s %d' % (p, counts.get(p, 0)) for p in PHASES))
    print('')
    tested = sum(1 for g in GUARDRAILS
                 if str(GUARDRAIL_TESTS.get(g[:2], '')).startswith('tests/'))
    print('  %d guardrails declared across stage boundaries; %d tied to a test a workflow runs, '
          '%d marked UNTESTED with a reason.' % (len(GUARDRAILS), tested, len(GUARDRAILS) - tested))
    enforced = [n for n in STAGES if STAGES[n]['phase'] == 'ENFORCED']
    if enforced:
        print('  ENFORCED: %s -- each cites the run in which a real prohibited operation was '
              'refused.' % ', '.join('stage %d' % n for n in enforced))
    print('  Configured is not enforced until something prohibited has been attempted and refused.')
    print('')

    if fails:
        for f in fails:
            sys.stderr.write('::error::%s\n' % f)
        sys.stderr.write('\nSTAGE_PHASE_GAP -- %d claim(s) outrun their evidence.\n' % len(fails))
        return 1
    print('  Every claim is supported by the evidence it names.')
    return 0


if __name__ == '__main__':
    sys.exit(main())

#!/usr/bin/env python3
"""A reconciler that creates without looking up produces every ticket again on every run.

WHY THIS EXISTS, AND WHY IT IS NOT A WRAPPER

    `scripts/reconcile_tickets.py --self-test` asserts the cascade's behaviour from inside the
    module. That is necessary and it is not sufficient, for the reason this repository has already
    paid for once: a self-test can be green because its own fixtures stopped being able to fail.
    `CAPABILITY_MATRIX.md` recorded 19/19 under a contract too weak to notice two dead scanners,
    and the matrix did not lie -- it reported evidence faithfully against a contract that could not
    detect the failure.

    So this file does three things the module's own self-test cannot do for itself:

    1. RUNS IT FROM A CLEAN PROCESS, with the environment scrubbed of every tracker credential, so
       a pass cannot depend on in-process state and cannot reach a network.

    2. MUTATES THE GUARDS AND REQUIRES THE SELF-TEST TO GO RED. A single substring change to the
       passing implementation, one at a time. If the self-test still passes with a guard broken,
       that assertion was decorative and the green meant nothing. This is the control that makes
       the other file's green worth reading.

    3. PROVES THE ANTI-VACUITY GUARD FIRES. Most of the reconciler's assertions have the form "X
       creates nothing", and all of them pass trivially against a program that creates nothing at
       all. The self-test asserts the positive case first and aborts if it fails; this proves that
       abort actually happens rather than being a comment.

    4. RUNS THE FOUR CASES THROUGH THE REAL COMMAND LINE. `docs/PROOF_RULE.md` states the rule:
       allowed, attack, missing-evidence, recovery -- and both receipts kept. The deferral
       resolution path is driven end to end here, with the environment scrubbed, because it is
       the one disposition whose gate can be exercised through the actual CLI without a tracker.

A NOTE ON WHAT CHANGED HERE, AND WHY IT MATTERS

    This suite used to carry ONE mutant for the approval gate -- "the human-in-loop gate is
    bypassed" -- and it was proving half a control. A reconciler that refused EVERY creation
    would have passed it, and that reconciler is exactly what the blanket "every mutation needs a
    human" invariant produced. The over-broad direction is now mutated too:
    `routine creation is gated on a human approval` and `routine mutations are gated anyway` both
    have to die, and so does `a disposition runs unattended`. A gate has two failure modes and a
    suite that only tests one of them is a suite that cannot tell a control from a brick.

NO NETWORK. Nothing here contacts a tracker. The backend used throughout is the in-memory
recording backend, the subprocess runs with every credential variable removed, and a mutant that
tried to reach out would fail on the scrubbed environment rather than on a timeout.

USAGE
    python3 tests/prove_ticket_idempotency.py

EXIT
    0  lookup-before-create holds, the guards are live, and the anti-vacuity abort fires
    1  a guard is decorative, or the reconciler duplicates
    2  could not be checked -- reported as UNKNOWN, never as PASS
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
TARGET = os.path.join(ROOT, 'scripts', 'reconcile_tickets.py')
# The parent/child model, the deferral discipline, the compliance pairing and the confidence
# derivation live here. Mutated separately, against its own self-test, because a guard in one file
# proven by the other file's test would be proven by coincidence.
MODEL = os.path.join(ROOT, 'scripts', 'ticket_model.py')

# Every variable that could point a mutant at a real tracker. Removed from the child environment,
# so "no network" is a property of the harness rather than a hope about the code.
CREDENTIAL_KEYS = ('GH_TOKEN', 'GITHUB_TOKEN', 'TICKET_BACKEND', 'TICKET_REPO',
                   'TICKET_STAMP_LABEL', 'JIRA_HOST', 'JIRA_EMAIL', 'JIRA_TOKEN',
                   'JIRA_PROJECT', 'JIRA_STAMP_FIELD', 'GITHUB_STEP_SUMMARY')


def scrubbed_env():
    env = dict(os.environ)
    for k in CREDENTIAL_KEYS:
        env.pop(k, None)
    return env


def run(args, cwd=None, env=None):
    """-> (rc, stdout, stderr). No shell, no inherited credentials."""
    p = subprocess.run([sys.executable] + args, cwd=cwd or ROOT,
                       env=env if env is not None else scrubbed_env(),
                       capture_output=True, text=True, timeout=300)
    return p.returncode, p.stdout, p.stderr


# ── THE MUTANTS ──────────────────────────────────────────────────────────────────────
#
# Each is a single substring replacement against the PASSING source. A mutant must not be able to
# fail for an unrelated reason, which is why none of them changes more than one expression -- this
# repository has already shipped a fixture that "proved" a guard whose regex was dead.
#
# (label, find, replace, what the mutation removes)
MUTANTS = [
    ('creation ignores a partial sweep',
     "    if not sweep_complete:\n        return (UNCLASSIFIED_DEFAULT, hits,\n"
     "                'the sweep was incomplete, so nothing may be concluded from a miss in it')",
     "    if False:\n        return (UNCLASSIFIED_DEFAULT, hits,\n"
     "                'the sweep was incomplete, so nothing may be concluded from a miss in it')",
     'a PARTIAL sweep would license a creation, so an outage would duplicate the estate'),

    ('creation ignores the calibration probe',
     '    if not observable:',
     '    if False and not observable:',
     'a channel never shown able to see foreign tickets would license a creation'),

    ('the unclassified case defaults to absent',
     'UNCLASSIFIED_DEFAULT = BINDING_UNESTABLISHED',
     'UNCLASSIFIED_DEFAULT = BINDING_ABSENT',
     'every lookup that established nothing would read as nothing-found'),

    ('an empty identity is ticketed anyway',
     "        if not ident or state != 'FINGERPRINTED':",
     "        if False:",
     'a finding with no durable identity would get a ticket nothing can ever find again'),

    ('the state label is trusted over the value',
     "        if not ident or state != 'FINGERPRINTED':",
     "        if state != 'FINGERPRINTED':",
     'a record claiming FINGERPRINTED with an empty identity would be ticketed'),

    ('ambiguity picks the first candidate',
     '    if len(hits) > 1:',
     '    if False and len(hits) > 1:',
     'two tickets for one cluster would be resolved by pagination order'),

    ('the cluster key is a hash of its members',
     "        anchor = str(cl.get('anchor') or rec0['identity']).lower()",
     "        anchor = '+'.join(sorted(m['identity'] for m in members))",
     'adding a member would mint a new key and duplicate an already-ticketed obligation'),

    # L55. A run that could not establish the ticketing claim says so.
    ('the control being off reads as a trusted claim',
     "    if result['backend'] is None:\n        causes.append(",
     "    if False:\n        causes.append(",
     'a run with no tracker configured would report a clean ticketing claim and exit 0'),

    ('an unfinished lookup reads as a trusted claim',
     "    if result['outcomes'].get(BINDING_UNESTABLISHED):",
     '    if False:',
     'a rate-limited or partial sweep would leave obligations untracked under a clean claim'),

    ('every finding withheld reads as a trusted claim',
     "    if result['clusters'] == 0 and result['outcomes'].get(IDENTITY_NOT_ESTABLISHED):",
     '    if False:',
     'a run that could key nothing, and so tracked nothing, would read as fine'),

    # TC 6.5. The creation ceiling holds, and the order is by consequence.
    ('the creation ceiling is ignored',
     '            if apply_changes and ceiling is not None and \\',
     '            if False and \\',
     'a day-one cohort would open every ticket in one run, past the declared ceiling and the '
     'binding content-generating limit'),

    ('creation follows discovery order',
     '    clusters = sorted(clusters, key=lambda c: _SEV_ORDER.index(c[\'severity\'])',
     '    clusters = sorted(clusters, key=lambda c: 0 and _SEV_ORDER.index(c[\'severity\'])',
     'a ceiling would delay the most urgent work and spend the budget on the cheapest'),

    # ETFB 9.4. The ticketing path consumes the anchored tier; it does not rebuild a transitive one.
    ('the ticketing clusterer ignores correlation and merges everything at a locus',
     "        members = [fingerprinted[i] for i in cl['members']]",
     "        members = list(fingerprinted)",
     'every fingerprinted finding in a run would share one ticket, chains included'),

    # J-6 / T-7 / T-8. Reopen when unbacked; never when backed; successor when refused.
    ('a backed closure is reopened anyway',
     "                if backing == 'backed':",
     '                if False:',
     'a ticket closed behind an unexpired approved disposition would be reopened every run, '
     'which teaches the team the bridge is broken'),

    ('a refused reopen leaves the obligation with no surface',
     "                    elif not tm.authorise('ticket.successor', approval):",
     '                    elif False:',
     'a tracker that refuses the reopen would leave a reproducing finding with only a closed '
     'ticket, and nothing records why'),

    ('a predecessor reads as a second candidate',
     "    hits = [h for h in (sweep_map.get(key) or []) if str(h.get('ref')) not in preds]",
     '    hits = list(sweep_map.get(key) or [])',
     'the run after a successor would read predecessor + successor as an ambiguity and stop '
     'tracking the obligation'),

    # T2. The stamp, once set, does not move with membership.
    ('the stamp moves with membership',
     '    rebind(clusters, identity_bindings(ledger, sweep_map))',
     '    pass',
     'a scanner joining or leaving would mint a new key, find nothing under it, and open a '
     'second ticket for an obligation that already had one'),

    ('a merge or split is resolved by picking',
     "    if cluster.get('binding_conflict'):",
     '    if False:',
     'two clusters inheriting one stamp would both write to it, a decision made by iteration '
     'order'),

    # The members-added trigger AND the members the rewrite renders: since T-13 a scanner change
    # also triggers a rewrite, so the trigger alone is no longer the only path to the write.
    ('membership added is never written to the ticket',
     "                    shown = dict(cluster, member_identities=sorted(known | current),",
     "                    shown = dict(cluster, member_identities=sorted(known),",
     'a member that joined would be unknown to the ticket, so when the original member leaves '
     'and the ledger proposal is not yet merged, the next run duplicates'),

    ('a member joining is not a delta',
     '            if not current <= known and hit.get(\'ref\'):',
     '            if False:',
     'a member that joined would be unknown to the ticket, so when the original member leaves '
     'and the ledger proposal is not yet merged, the next run duplicates'),

    # T-13. Act on deltas: an unchanged run is free, and a stopped scanner is named, not omitted.
    ('an unchanged run reads every ticket anyway',
     '            if rendered is None:',
     '            if True:',
     'every bound ticket would be read on every run although the ledger already says nothing '
     'changed -- the call budget grows with the backlog (TC 6.1)'),

    ('a stopped scanner is omitted from the block',
     "                                 scanners_stopped=want['stopped'], "
     "members_absent=want['absent'],",
     "                                 scanners_stopped=[], members_absent=want['absent'],",
     'a dead detector would vanish from the ticket and hide behind a live one (TC 5.1)'),

    # T-06. A carried obligation counts its consecutive degraded runs, and a bound lookup ends it.
    ('the degraded streak is not counted',
     "            'attempts': int(prev.get('attempts') or (1 if prev else 0)) + 1,",
     "            'attempts': 1,",
     'a tracker degraded for weeks would read as degraded once, and the escalation to a person '
     'at the promotion review (TC 4.1) would never fire'),

    ('a bound lookup does not end the degraded streak',
     "                    entry.pop('owed')",
     '                    pass',
     'a streak would survive the run that established the binding, so "consecutive" would count '
     'every degraded run ever and escalate a healthy cell'),

    # T-08. A reopen says why: the registered lapse, a falsified REMEDIATED, or an unbacked close.
    # KDEC-024 moved the call onto two lines (RECURRED has its own comment); the mutant follows it,
    # keeping the rest of the statement as an inert tuple so only the comment is removed.
    ('a reopen does not say why on the ticket',
     "                        ok_c, d_c = backend.comment(\n                            hit['ref'], "
     "recurred_comment(",
     "                        ok_c, d_c = True, 'not written'; _unwritten = (\n"
     "                            hit['ref'], recurred_comment(",
     'a reopened ticket would carry no reason, so a lapse reads as the bridge flapping'),

    ('an expired disposition reads as an unbacked closure',
     '            return REOPENED_BY_LAPSE',
     "            return 'unbacked'",
     'a lapsed acceptance would be reopened without the registered REOPENED_BY_LAPSE, so nobody '
     'is told to re-decide with a named approver and a new expiry'),

    # T-02. The members-added update replaces the block and nothing else, and never writes blind.
    ('the update trusts the sweep\'s copy of the body',
     "                desc, read_ok, d_read = backend.read_description(hit['ref'])",
     "                desc, read_ok, d_read = hit.get('body') or '', True, 'sweep copy'",
     'THE T-02 DEFECT RETURNS: Jira and Azure DevOps sweeps carry no body, so the block is '
     'rendered against nothing and the write erases every sentence a person wrote'),

    ('an unreadable description is written anyway',
     '                if read_ok and (not current <= known or changed):',
     '                if (not current <= known or changed):',
     'a description the run could not read would be overwritten blind with the block alone'),

    ('the splice replaces the whole body',
     '        return existing[:i] + block + existing[tail_start:], True',
     '        return block, True',
     'a block rewrite would discard the human text before and after the delimiters'),

    # T1. Two loci, two clusters, one stamp: one ticket for two obligations.
    # L48 (KDEC-024): the hash now lives in finding_correlation.cluster_key, the kit's one key
    # function; the orchestrator's delegate is where the locus can still be dropped.
    ('the cluster key omits the locus',
     "    return fc.cluster_key(subject, locus, anchor)",
     "    return fc.cluster_key(subject, '', anchor)",
     'one advisory in two manifests would share one stamp, so one ticket stands for two '
     'obligations and the second reads as a dangling reference'),

    ('clustering collapses across subject classes',
     "                          finding_subject=rec.get('finding_subject') or ''))",
     "                          finding_subject=''))",
     'two obligations with two owners would merge into one ticket'),

    ('a dry run writes',
     '            if apply_changes:\n                ref, detail2 = backend.create(',
     '            if True:\n                ref, detail2 = backend.create(',
     'the default mode would write to an issue tracker'),

    ('a dangling reference is an absence',
     '        return (BINDING_DANGLING, hits,',
     '        return (BINDING_ABSENT, hits,',
     'an unresolved reference would license a second ticket'),

    # ── THE CORRECTED GATE. Both directions, because a gate has two failure modes. ──
    #
    # The previous version of this suite had ONE mutant here -- "the human-in-loop gate is
    # bypassed" -- and it was proving half a control. It would have passed against a reconciler
    # that refused every creation, and that reconciler is exactly what the blanket approval
    # invariant produced. So the over-broad direction is now mutated too.
    ('routine creation is gated on a human approval',
     "            gate = tm.authorise('ticket.create', approval)",
     "            gate = tm.require_approval('ticket.create', approval)",
     'THE CORRECTED DEFECT RETURNS: a policy-authorised reconciler could not open a work item '
     'for a fingerprinted, anchored, evidence-backed finding without somebody signing for it -- '
     'so it gets switched off and nothing is reconciled at all'),

    ('the disposition gate is bypassed',
     '            if gate:\n                blocked_by_disposition = True',
     '            if False:\n                blocked_by_disposition = True',
     'an exception, exclusion, false-positive call or risk acceptance would reach the tracker '
     'with nobody having approved the judgement'),

    ('a refused disposition still writes the routine half',
     '        if blocked_by_disposition:',
     '        if False and blocked_by_disposition:',
     'a REMEDIATION_WORK_ITEM would be raised for a finding somebody asked to have excepted, so '
     'the asking disappears and the request is answered with "please fix it"'),

    ('the past-due deferral sweep does not run',
     "    result['past_due'] = sweep_past_due(ledger, today)",
     "    result['past_due'] = []",
     'an acceptance whose end date has passed would be invisible in every run -- a suppression '
     'that outlived its own expiry, which is the hole the deferral discipline exists to close'),
]

# Mutants against the MODEL. Same discipline, different file and different self-test.
MODEL_MUTANTS = [
    ('a deferral needs no reason',
     "        if not (deferred_reason or '').strip():",
     '        if False:',
     'a finding could be deferred with no justification, which is indistinguishable from '
     'quietly dropping it'),

    ('a deferral needs no end date',
     "        if not (deferred_until or '').strip():",
     '        if False:',
     'a deferral with no end date never expires and nobody is asked to renew it -- silence '
     'made permanent'),

    ('reopening needs no trigger',
     "    if not (trigger or '').strip():",
     '    if False:',
     'the end date passing would perform the reopen by itself, which is an obligation changing '
     'state with nobody having decided anything'),

    ('reopening needs no approval',
     "    err = authorise('task.deferral.reopen', approval)",
     "    err = ''",
     'a deferred obligation would reopen with no human in the loop'),

    # ── THE MUTATION CLASSIFIER. Both bad defaults, and both gate directions. ──────
    ('an unclassified mutation defaults to routine',
     '        return MUTATION_CLASS_NOT_STATED, (',
     '        return ROUTINE_RECONCILIATION, (',
     'a mutation nobody classified would run UNATTENDED -- so a disposition added later and not '
     'added to the table reaches the tracker through the automatic door'),

    ('an unclassified mutation defaults to approval',
     '        return MUTATION_CLASS_NOT_STATED, (',
     '        return GOVERNANCE_DISPOSITION, (',
     'a mutation nobody classified would become performable by anyone holding any approval, '
     'which is the blanket gate returning by the back door and calling itself a control'),

    ('routine mutations are gated anyway',
     "        # UNATTENDED, DELIBERATELY. No approval is consulted and none is required.\n"
     "        return ''",
     '        # UNATTENDED, DELIBERATELY. No approval is consulted and none is required.\n'
     '        return require_approval(mutation, approval)',
     'THE CORRECTED DEFECT RETURNS, one layer lower: every transition, every validation and '
     'every link would need a person, and "everything is refused" is a broken pipeline rather '
     'than a control'),

    ('a disposition runs unattended',
     "        return require_approval('%s is a %s (%s), and it' % (mutation, "
     'GOVERNANCE_DISPOSITION,\n                                                             '
     'why), approval)',
     "        return ''",
     'an exception, a risk acceptance, a mitigation accepted instead of a fix, a budget '
     'commitment or a posture change would be performed by an automated run'),

    ('the evidenced closure needs no children',
     '        if tasks is None:',
     '        if False:',
     'a parent would close unattended with no children to read -- closure on an absence, and '
     'the unattended path is unattended BECAUSE it is evidenced'),

    ('the evidenced closure ignores the children',
     '        if not satisfied:',
     '        if False:',
     'a parent would close unattended over children that are still open, disputed or deferred'),

    # ── THE PAST-DUE REVIEW OBLIGATION. ───────────────────────────────────────────
    ('an elapsed deferral reads as in term',
     '    if iso_date(until) < iso_date(now):',
     '    if False:',
     'an acceptance that ended last March would report as still in force and go on suppressing '
     'the finding, with nobody ever asked to renew it'),

    # G2-6. The shape check alone let TBD0-00-00 through and the lexical compare read it as in
    # term for ever. Mutated to return the string, which is exactly the pre-fix behaviour.
    ('a date-shaped placeholder is parsed hopefully',
     '        return datetime.date.fromisoformat(s)',
     '        return s',
     'TBD0-00-00 or 2026-13-45 would be string-compared against today, letters sort after '
     'digits, and the acceptance would read as in term for ever'),

    # G2-6. VALIDATED is somebody else establishing the fix, on evidence.
    ('VALIDATED needs no evidence',
     '        bad = check_validation_evidence(task, evidence)',
     "        bad = ''",
     'the reconciler that recorded FIXED would establish its own claim with nothing in hand, and '
     'ALL_CHILDREN_RESOLVED would then close a parent over children nobody evidenced'),

    ('the party that claimed FIXED may validate it',
     '    if source in self_parties:',
     '    if False:',
     'self-validation: the claim and its establishment would come from the same party'),

    ('a reproducing finding can be validated',
     "    if evidence.get('reproduced') is not False:",
     '    if False:',
     'a finding the scanner still reports would be recorded as fixed'),

    ('absence over an uncovered scope validates',
     "    if evidence.get('scope_covered') is not True:",
     '    if False:',
     'a finding that merely stopped appearing -- POTENTIALLY_ABSENT -- would be recorded as fixed'),

    ('a deferral end date is not validated at entry',
     '        if iso_date(deferred_until) is None:',
     '        if False:',
     'a deferral could be recorded with an end date no run can compare, which is the undated '
     'deferral wearing a date\'s clothes'),

    ('the past-due sweep drops the undated case',
     '        if state == DEFERRAL_WITHIN_TERM:',
     '        if state != DEFERRAL_PAST_DUE:',
     'a deferral with NO end date would be the one case that stays quiet -- and that is the '
     'original defect, not an edge of it'),

    ('the ordinary transition path can reopen a deferral',
     '    if task.state == DEFERRED and new_state == OPEN:',
     '    if False:',
     'the reopen discipline could be bypassed entirely by a caller who knew the edge existed'),

    ('a parent closes over open children',
     '        elif t.state not in TERMINAL_TASK_STATES:',
     '        elif False:',
     'a cluster would close while its findings were still open'),

    # DELIBERATELY NOT A MUTANT: "DISPUTED counts as resolved".
    #
    # It was one, and it SURVIVED -- correctly. DISPUTED is refused by two independent checks in
    # `evaluate_closure`: its own explicit branch, and the TERMINAL_TASK_STATES membership test
    # beneath it. Adding DISPUTED to that tuple is an EQUIVALENT MUTANT -- it changes no reachable
    # behaviour, because the explicit branch catches DISPUTED before the membership test is
    # consulted. No single-substring mutation can defeat a property guarded twice.
    #
    # The honest response is to retire the mutant rather than contrive one that appears to kill,
    # and to say where the property IS proven: the model's own self-test drives one child to
    # DISPUTED, every other child to terminal, and requires closure to be refused AND the
    # disputed child to be named as the blocker. A mutant that cannot fail is not evidence, and
    # leaving it in the list to be counted would be the decoration this suite exists to detect.
    ('a deferred child does not block closure',
     '        if t.state == DEFERRED:',
     '        if False:',
     'a deferred finding would be closed away rather than held open'),

    ('a childless parent can close',
     "        return False, ['no child tasks: a parent with no children has established nothing']",
     "        return True, []",
     'an obligation whose work was never represented would close cleanly'),

    ('an unknown closure rule passes',
     '    if ticket.closure_rule != ALL_CHILDREN_RESOLVED:',
     '    if False:',
     'a closure rule added later and not handled would fall through to permitted'),

    ('an authority override needs no rationale',
     "        if not (ticket.authority_override_rationale or '').strip():",
     '        if False:',
     'an obligation could be overridden closed with no stated reason'),

    ('the compliance pairing defaults instead of refusing',
     '    if subject not in COMPLIANCE_PAIRING:',
     '    if False:',
     'an unrecognised subject would inherit a neighbouring subject\'s governance consequence'),

    ('confidence claims corroboration on a degraded channel',
     '    if channel_degraded:',
     '    if False:',
     'a partial contributor set would be reported as corroboration, when scanners that would '
     'have agreed may simply not have been read'),

    ('an unestablished identity still gets a confidence label',
     '    if not identity_established:',
     '    if False:',
     'a finding with no durable identity would carry a confidence claim about nothing'),

    ('an approval needs no actor',
     '    if not approval.actor:',
     '    if False:',
     'an unattributed approval would permit a mutation -- a decision nobody has made'),

    ('an approval needs no reason',
     '    if len(approval.reason) < MIN_APPROVAL_REASON:',
     '    if False:',
     'an approval nobody can review later would permit a mutation'),
]


def main():
    fails, notes = [], []

    if not os.path.exists(TARGET):
        print('UNKNOWN: %s does not exist, so nothing was checked.' % TARGET)
        return 2
    try:
        source = io.open(TARGET, encoding='utf-8').read()
    except OSError as exc:
        print('UNKNOWN: could not read %s: %s' % (TARGET, exc))
        return 2

    print('PROVING LOOKUP-BEFORE-CREATE')
    print('=' * 92)

    # ── 1. THE POSITIVE CONTROL. The real thing passes, from a clean process. ────────
    rc, out, err = run([TARGET, '--self-test'])
    if rc != 0:
        fails.append('the unmutated self-test does not pass (exit %d). Every mutant below would '
                     'then "fail" for a reason that has nothing to do with the mutation.' % rc)
        print('  self-test on the real source        exit %d  FAIL' % rc)
        print((out + err)[-2000:])
    else:
        print('  self-test on the real source        exit 0   pass')
    if 'NOT vacuously' not in out:
        fails.append('the self-test does not claim to have asserted the positive case first')

    # ── 2. THE ANTI-VACUITY ABORT FIRES. ───────────────────────────────────────────
    #
    # Cripple creation only. Every "X creates nothing" assertion then holds trivially, so a
    # self-test without the abort would report success against a program that can create nothing.
    crippled = source.replace(
        "    def create(self, cluster, body, title):\n        ref = str(self.next_ref)",
        "    def create(self, cluster, body, title):\n        return None, 'crippled'\n"
        "        ref = str(self.next_ref)")
    if crippled == source:
        fails.append('could not cripple RecordingBackend.create -- the anti-vacuity check below '
                     'did not run, so it is unproven')
    else:
        rc_v, out_v, err_v = run_mutant(crippled)
        if rc_v == 0:
            fails.append('WITH CREATION CRIPPLED THE SELF-TEST STILL PASSED. Its assertions are '
                         'vacuous: they all hold against a program that creates nothing.')
            print('  anti-vacuity abort                  exit 0   FAIL (should have aborted)')
        elif 'VACUOUS' not in (out_v + err_v):
            fails.append('creation crippled: the self-test failed (exit %d) but never named the '
                         'vacuity -- a reader would hunt the wrong defect' % rc_v)
            print('  anti-vacuity abort                  exit %d   partial' % rc_v)
        else:
            print('  anti-vacuity abort                  exit %d   fires, and says VACUOUS' % rc_v)

    # ── 3. THE MUTANTS. Each guard must be load-bearing. ───────────────────────────
    print('')
    print('MUTATION: the cascade. Each guard is broken one at a time; the self-test must go red')
    print('-' * 92)
    for i, (label, find, repl, consequence) in enumerate(MUTANTS, 1):
        mutate(label, find, repl, consequence, source, run_mutant, fails, i)
        # Heartbeat, per iteration.
        sys.stdout.flush()

    # ── 3b. THE MODEL'S GUARDS, against the model's own self-test. ─────────────────
    print('')
    print('MUTATION: the work-item model -- parent/child, deferral, pairing, confidence')
    print('-' * 92)
    if not os.path.exists(MODEL):
        fails.append('UNKNOWN: %s does not exist, so none of the model guards were checked'
                     % MODEL)
    else:
        model_source = io.open(MODEL, encoding='utf-8').read()
        # The positive control for this half: the unmutated model must pass, or every mutant
        # below "dies" for a reason unrelated to the mutation.
        rc_mm, out_mm, _e = run([MODEL, '--self-test'])
        if rc_mm != 0:
            fails.append('the unmutated model self-test does not pass (exit %d); the model '
                         'mutants below prove nothing' % rc_mm)
            print('  model self-test on the real source             exit %d  FAIL' % rc_mm)
        else:
            print('  model self-test on the real source             exit 0   pass')
        for i, (label, find, repl, consequence) in enumerate(MODEL_MUTANTS, 1):
            mutate(label, find, repl, consequence, model_source, run_model_mutant, fails, i)
            sys.stdout.flush()
        # The model file must be byte-identical to what it was before this ran. A mutation suite
        # that leaves a mutant behind has edited the thing it was measuring.
        if io.open(MODEL, encoding='utf-8').read() != model_source:
            fails.append('the model file was not restored after mutation -- the suite has left a '
                         'mutant in the tree')
        else:
            print('  model restored byte-identical after mutation')

    # ── 4. THE CLI, END TO END, WITH NO BACKEND AND NO NETWORK. ───────────────────
    print('')
    print('THE COMMAND LINE, against a real findings file and a scrubbed environment')
    print('-' * 92)
    tmp = tempfile.mkdtemp(prefix='prove_ticket_idempotency_')
    try:
        findings = os.path.join(tmp, 'findings.json')
        io.open(findings, 'w', encoding='utf-8').write(json.dumps([
            {'scanner': 'trivy', 'rule': 'CVE-2024-0001', 'uri': 'go.mod', 'line': 3,
             'severity': 'high', 'identity': 'a' * 40, 'identity_state': 'FINGERPRINTED',
             'finding_subject': 'DEPENDENCY', 'what_aliases': ['cve-2024-0001']},
            {'scanner': 'semgrep', 'rule': 'rule-x', 'uri': 'app.py', 'line': 9,
             'severity': 'high', 'identity': '', 'identity_state': 'UNFINGERPRINTABLE',
             'identity_reason': 'no symbol path', 'finding_subject': 'SOURCE'},
        ]))

        # No backend configured. The control is off, and that must not read as a clean run.
        rc_c, out_c, _e = run([TARGET, '--findings', findings])
        # L55 / T-11: the control being off is NEVER exit 0. It used to be (and was only a note
        # here), so a scheduled run with no tracker configured read as a run with nothing to do.
        if rc_c != 3:
            fails.append('the CLI with no backend exited %d; the ticketing claim is '
                         'EVIDENCE_UNTRUSTED and the exit must be 3 (L55)' % rc_c)
        if 'control is off' not in out_c.lower():
            fails.append('the CLI with no backend did not report that the control is off')
        if 'IDENTITY_NOT_ESTABLISHED' not in out_c:
            fails.append('the CLI did not report the withheld finding as '
                         'IDENTITY_NOT_ESTABLISHED')
        if 'not a clean result' not in out_c:
            fails.append('the CLI let a withheld finding read as a clean result')
        print('  no backend configured               exit %d   reports the control is off' % rc_c)

        # L55 / T-11, the other ways in: both backends, a named value missing, every finding
        # withheld. Each refused BY NAME, exit 3, never 0. The env carries placeholders only and
        # every one of these refuses before any request could be made.
        withheld_only = os.path.join(tmp, 'withheld.json')
        io.open(withheld_only, 'w', encoding='utf-8').write(json.dumps([
            {'scanner': 'semgrep', 'rule': 'rule-x', 'uri': 'app.py', 'identity': '',
             'identity_state': 'UNFINGERPRINTABLE', 'finding_subject': 'SOURCE'}]))
        both = dict(scrubbed_env(), GH_TOKEN='placeholder', TICKET_REPO='o/r',
                    TICKET_STAMP_LABEL='kit', JIRA_HOST='https://example.invalid',
                    JIRA_EMAIL='e', JIRA_TOKEN='placeholder', JIRA_PROJECT='P')
        nolabel = dict(scrubbed_env(), TICKET_BACKEND='github', GH_TOKEN='placeholder',
                       TICKET_REPO='o/r')
        for label, args, env, needle in (
                ('both backends configured', [TARGET, '--findings', findings], both,
                 'CONFIGURATION DEFECT'),
                ('a required value missing', [TARGET, '--findings', findings], nolabel,
                 'TICKET_STAMP_LABEL'),
                ('every finding withheld', [TARGET, '--findings', withheld_only], None,
                 'IDENTITY_NOT_ESTABLISHED')):
            rc_x, out_x, err_x = run(args, env=env)
            if rc_x != 3:
                fails.append('%s exited %d; expected 3, EVIDENCE_UNTRUSTED (L55)' % (label, rc_x))
            if needle not in out_x + err_x or 'EVIDENCE_UNTRUSTED' not in out_x:
                fails.append('%s was not refused by name (%s) with the claim stated' % (label,
                                                                                       needle))
            print('  %-34s exit %d' % (label, rc_x))

        # --apply with no backend must still write nothing and must not crash.
        ledger = os.path.join(tmp, 'ledger.json')
        rc_a, out_a, _e2 = run([TARGET, '--findings', findings, '--ledger', ledger, '--apply'])
        if os.path.exists(ledger):
            fails.append('--apply with no backend configured wrote a ledger')
        print('  --apply with no backend             exit %d   wrote nothing' % rc_a)

        # An unreadable ledger must refuse rather than being treated as empty.
        bad = os.path.join(tmp, 'bad.json')
        io.open(bad, 'w', encoding='utf-8').write('{not json')
        rc_b, out_b, err_b = run([TARGET, '--findings', findings, '--ledger', bad])
        if rc_b != 2 or 'REFUSING' not in (out_b + err_b):
            fails.append('an unreadable ledger did not refuse (exit %d). Treating it as empty '
                         'would duplicate every already-ticketed obligation.' % rc_b)
        print('  unreadable ledger                   exit %d   refuses' % rc_b)

        # Unparseable findings are a collection failure, not zero findings.
        io.open(os.path.join(tmp, 'broken.json'), 'w', encoding='utf-8').write('{[')
        rc_p, _o, _e3 = run([TARGET, '--findings', os.path.join(tmp, 'broken.json')])
        if rc_p != 2:
            fails.append('unparseable findings exited %d; a broken handoff must not read as '
                         '"no findings to ticket"' % rc_p)
        print('  unparseable findings                exit %d   refuses' % rc_p)

        # ── 5. THE FOUR CASES, AT THE REAL ENFORCEMENT POINT. ─────────────────────
        #
        # `docs/PROOF_RULE.md` states the rule this section applies: state the claim, construct
        # a counterexample, run it through the REAL path, show the refusal, run the valid
        # counterpart, keep both receipts.
        #
        # THE REAL PATH, AND WHY IT IS THIS ONE. The deferral-resolution CLI needs no tracker
        # and no network, so it can be driven end to end from here with the environment scrubbed
        # -- which makes it the one disposition whose gate can be exercised through the actual
        # command line rather than through the module. It is not a helper: `--resolve-deferral`
        # is the operator-facing entry point, and `ticket_model.authorise` is the enforcement
        # point it reaches.
        print('')
        print('THE FOUR CASES: allowed, attack, missing evidence, recovery')
        print('-' * 92)

        def fresh_ledger(name, **deferral):
            """A ledger holding exactly one deferral. -> its path."""
            p = os.path.join(tmp, name)
            io.open(p, 'w', encoding='utf-8').write(json.dumps({
                'schema': 1,
                'clusters': {'c' * 32: {'ref': '101', 'backend': 'github',
                                        'deferrals': {'t/1': deferral}}}}, indent=2))
            return p

        def ledger_deferrals(path):
            return json.load(io.open(path, encoding='utf-8'))['clusters']['c' * 32]['deferrals']

        ELAPSED = {'reason': 'upstream has no patch', 'until': '2026-06-30'}
        TODAY = '2026-10-08'

        # 5a. ATTACK -- the prohibited action, through the real path. An elapsed acceptance
        #     renewed with NOBODY approving it.
        lp = fresh_ledger('attack.json', **ELAPSED)
        before = json.dumps(ledger_deferrals(lp), sort_keys=True)
        rc, out, err = run([TARGET, '--ledger', lp, '--today', TODAY,
                            '--resolve-deferral', 't/1', '--resolution', 'extend',
                            '--until', '2027-06-30',
                            '--deferral-reason', 'upstream still has no patch'])
        blob = out + err
        if rc == 0:
            fails.append('ATTACK SUCCEEDED: a past-due acceptance was renewed with no approver, '
                         'through the real command line. The disposition gate is disproven.')
        if 'REFUSED' not in blob or 'GOVERNANCE_DISPOSITION' not in blob:
            fails.append('the refusal did not name itself a disposition refusal (%r), so an '
                         'operator cannot tell it from a usage error' % blob[-400:])
        if json.dumps(ledger_deferrals(lp), sort_keys=True) != before:
            fails.append('a REFUSED renewal still wrote to the ledger')
        print('  attack:  unapproved renewal        exit %d   refused, ledger untouched' % rc)

        # 5a-ii. The other door, same attack. Ending an acceptance is a judgement too.
        lp2 = fresh_ledger('attack2.json', **ELAPSED)
        rc2, out2, err2 = run([TARGET, '--ledger', lp2, '--today', TODAY,
                               '--resolve-deferral', 't/1', '--resolution', 'reopen',
                               '--trigger', 'the date passed'])
        if rc2 == 0:
            fails.append('ATTACK SUCCEEDED: a deferral was reopened with no approver')
        if 't/1' not in ledger_deferrals(lp2):
            fails.append('a refused reopen still removed the deferral from the ledger')
        print('  attack:  unapproved reopen         exit %d   refused, deferral intact' % rc2)

        # 5a-iii. And the subtler attack: renewing to a date ALREADY PAST, with a valid
        #         approval. That would clear the review obligation without the review.
        lp3 = fresh_ledger('attack3.json', **ELAPSED)
        rc3, out3, err3 = run([TARGET, '--ledger', lp3, '--today', TODAY,
                               '--resolve-deferral', 't/1', '--resolution', 'extend',
                               '--until', '2026-01-01', '--deferral-reason', 'still waiting',
                               '--approved-by', 'platform-security',
                               '--approval-reason', 'carrying this for another quarter'])
        if rc3 == 0:
            fails.append('ATTACK SUCCEEDED: an approved renewal to a date ALREADY PAST was '
                         'accepted. The past-due state would read as resolved with no review.')
        print('  attack:  renewal into the past     exit %d   refused' % rc3)

        # 5b. MISSING EVIDENCE -- absent, partial or unreadable evidence must refuse a clean
        #     verdict rather than produce one.
        lp4 = fresh_ledger('missing.json', reason='waiting on upstream')   # no `until` at all
        rc4, out4, err4 = run([TARGET, '--ledger', lp4, '--today', TODAY,
                               '--resolve-deferral', 't/1', '--resolution', 'extend',
                               '--until', '2027-06-30', '--deferral-reason', 'still waiting',
                               '--approved-by', 'platform-security',
                               '--approval-reason', 'carrying this for another quarter'])
        if 'DEFERRAL_TERM_UNKNOWN' not in (out4 + err4):
            fails.append('a deferral with NO end date did not report %s; an absent expiry read '
                         'as an established term' % 'DEFERRAL_TERM_UNKNOWN')
        print('  missing: deferral with no end date exit %d   reports term unknown' % rc4)

        # No --until on an extend: the resolution has no evidence of a future term.
        lp5 = fresh_ledger('missing2.json', **ELAPSED)
        rc5, out5, err5 = run([TARGET, '--ledger', lp5, '--today', TODAY,
                               '--resolve-deferral', 't/1', '--resolution', 'extend',
                               '--deferral-reason', 'still waiting',
                               '--approved-by', 'platform-security',
                               '--approval-reason', 'carrying this for another quarter'])
        if rc5 == 0:
            fails.append('an extension with NO new end date was accepted, which is a deferral '
                         'with no expiry -- the exact hole the discipline exists to close')
        print('  missing: extend with no new date   exit %d   refused' % rc5)

        # A dangling task id is not a resolved obligation.
        lp6 = fresh_ledger('missing3.json', **ELAPSED)
        rc6, out6, err6 = run([TARGET, '--ledger', lp6, '--today', TODAY,
                               '--resolve-deferral', 't/does-not-exist',
                               '--resolution', 'reopen', '--trigger', 'upstream released',
                               '--approved-by', 'platform-security',
                               '--approval-reason', 'the upstream fix has landed'])
        if rc6 != 2:
            fails.append('a dangling task id exited %d; a typo must not read as a resolved '
                         'obligation' % rc6)
        print('  missing: dangling task id          exit %d   refuses' % rc6)

        # And the sweep itself: no --today is not "nothing has elapsed".
        rc7, out7, err7 = run([TARGET, '--findings', findings, '--ledger',
                               fresh_ledger('sweep.json', **ELAPSED)])
        if 'DEFERRAL_TERM_UNKNOWN' not in (out7 + err7):
            fails.append('a run with no reference date did not report %s for a deferral it '
                         'could not evaluate' % 'DEFERRAL_TERM_UNKNOWN')
        print('  missing: no reference date         exit %d   reports term unknown' % rc7)

        # 5c. ALLOWED -- the valid counterpart of 5a, through the same real path. Without this
        #     the three refusals above hold against a program that refuses everything, and
        #     "everything is refused" is not security.
        lp8 = fresh_ledger('allowed.json', **ELAPSED)
        rc8, out8, err8 = run([TARGET, '--ledger', lp8, '--today', TODAY,
                               '--resolve-deferral', 't/1', '--resolution', 'extend',
                               '--until', '2027-06-30',
                               '--deferral-reason', 'upstream still has no patch; tracked',
                               '--approved-by', 'platform-security',
                               '--approval-reason', 'carrying this for another quarter'])
        if rc8 != 0:
            fails.append('ALLOWED CASE FAILED: a properly approved renewal to a future date was '
                         'refused (exit %d). Both cases failing means the control is unusable -- '
                         'a past-due obligation nobody can renew is one nobody can carry '
                         'honestly. %s' % (rc8, (out8 + err8)[-400:]))
        after = ledger_deferrals(lp8).get('t/1') or {}
        if after.get('until') != '2027-06-30':
            fails.append('an approved renewal did not update the ledger: %r' % after)
        if after.get('reason') == ELAPSED['reason']:
            fails.append('an approved renewal carried the ORIGINAL reason forward. "Still '
                         'waiting" inherited for three quarters is renewal through silence')
        print('  allowed: approved renewal          exit %d   ledger updated to 2027-06-30' % rc8)

        # The other door, allowed: ending the acceptance with a role and a named trigger.
        lp9 = fresh_ledger('allowed2.json', **ELAPSED)
        rc9, out9, err9 = run([TARGET, '--ledger', lp9, '--today', TODAY,
                               '--resolve-deferral', 't/1', '--resolution', 'reopen',
                               '--trigger', 'upstream released 2.1',
                               '--approved-by', 'platform-security',
                               '--approval-reason', 'the upstream fix has landed'])
        if rc9 != 0:
            fails.append('ALLOWED CASE FAILED: an approved reopen with a named trigger was '
                         'refused (exit %d): %s' % (rc9, (out9 + err9)[-400:]))
        if 't/1' in ledger_deferrals(lp9):
            fails.append('an approved reopen left the deferral in the ledger, so the finding '
                         'would still report past due after being resolved')
        print('  allowed: approved reopen           exit %d   deferral cleared' % rc9)

        # 5d. RECOVERY -- after a refusal, is the state accurate and can work resume?
        lpA = fresh_ledger('recovery.json', **ELAPSED)
        rcA, outA, errA = run([TARGET, '--ledger', lpA, '--today', TODAY,
                               '--resolve-deferral', 't/1', '--resolution', 'extend',
                               '--until', '2027-06-30', '--deferral-reason', 'still waiting'])
        if rcA == 0:
            fails.append('the recovery scenario did not start from a refusal')
        # (i) the state is accurate: the deferral is untouched and still reports past due in an
        #     ORDINARY run, with no flag asking for it.
        rcB, outB, errB = run([TARGET, '--findings', findings, '--ledger', lpA,
                               '--today', TODAY])
        if 'PAST DUE' not in (outB + errB):
            fails.append('after a refused resolution the ordinary run did not report the '
                         'deferral as past due -- the refusal lost the obligation')
        # 1 for the past-due decision, or 3 because this run also has no backend configured and
        # EVIDENCE_UNTRUSTED outranks DECISION_REQUIRED (L55). Never 0.
        if rcB not in (1, 3):
            fails.append('a run carrying a past-due deferral exited %d. An elapsed acceptance '
                         'that exits 0 is one nobody will chase.' % rcB)
        # (ii) work resumes safely: the same resolution succeeds once it carries an approver,
        #      and nothing from the refused attempt is left behind.
        rcC, outC, errC = run([TARGET, '--ledger', lpA, '--today', TODAY,
                               '--resolve-deferral', 't/1', '--resolution', 'extend',
                               '--until', '2027-06-30',
                               '--deferral-reason', 'upstream still has no patch; tracked',
                               '--approved-by', 'platform-security',
                               '--approval-reason', 'carrying this for another quarter'])
        if rcC != 0:
            fails.append('RECOVERY FAILED: after a refusal the approved resolution did not '
                         'succeed (exit %d): %s' % (rcC, (outC + errC)[-400:]))
        if (ledger_deferrals(lpA).get('t/1') or {}).get('until') != '2027-06-30':
            fails.append('recovery left the ledger in a state that does not match what the run '
                         'reported')
        # (iii) and the obligation is then GONE from the ordinary run -- a review obligation that
        #       never clears becomes noise, and noise gets ignored.
        rcD, outD, errD = run([TARGET, '--findings', findings, '--ledger', lpA,
                               '--today', TODAY])
        if 'PAST DUE' in (outD + errD):
            fails.append('a RENEWED deferral still reported past due. A signal that never '
                         'clears is one a reader learns to ignore.')
        print('  recovery: refuse -> still past due, exit 1 -> approved -> clears')

        # ── 6. L59 / FW D5: THE CLOCK, ON A SCHEDULE, WITH NO SCAN. ──────────────────
        #
        # REOPENED_BY_LAPSE comes from the calendar, not a diff: on the day an acceptance
        # expires the scan is byte-identical to yesterday's. So the sweep must run with NO
        # findings at all, from the ledger and a date, and say what elapsed.
        print('')
        print('L59: the past-due sweep alone, as a schedule runs it')
        print('-' * 92)
        lpS = fresh_ledger('sched.json', **ELAPSED)
        before_s = io.open(lpS, encoding='utf-8').read()
        rcS, outS, errS = run([TARGET, '--sweep-deferrals', '--ledger', lpS, '--today', TODAY])
        if rcS != 1 or 'PAST DUE' not in outS + errS:
            fails.append('the scheduled sweep over an elapsed deferral exited %d without '
                         'reporting it PAST DUE (L59): %s' % (rcS, (outS + errS)[-300:]))
        if io.open(lpS, encoding='utf-8').read() != before_s:
            fails.append('the scheduled sweep MUTATED the ledger; observing must not resolve')
        print('  elapsed deferral                   exit %d' % rcS)
        lpT = fresh_ledger('sched-ok.json', reason='upstream has no patch', until='2027-06-30')
        rcT, outT, errT = run([TARGET, '--sweep-deferrals', '--ledger', lpT, '--today', TODAY])
        if rcT != 0:
            fails.append('the scheduled sweep over an in-term deferral exited %d; a signal that '
                         'fires on deferrals in good standing is noise (L59)' % rcT)
        print('  in-term deferral                   exit %d' % rcT)
        rcU, outU, errU = run([TARGET, '--sweep-deferrals',
                               '--ledger', os.path.join(tmp, 'no-such-ledger.json'),
                               '--today', TODAY])
        if rcU != 3:
            fails.append('a scheduled sweep with NO ledger exited %d; nothing was swept, which '
                         'is not "nothing elapsed" (expected 3) (L59)' % rcU)
        print('  no ledger                          exit %d' % rcU)
        rcV, outV, errV = run([TARGET, '--sweep-deferrals', '--ledger', lpS])
        if rcV != 1 or 'DEFERRAL_TERM_UNKNOWN' not in outV + errV:
            fails.append('a scheduled sweep with no --today exited %d without reporting '
                         'DEFERRAL_TERM_UNKNOWN (L59)' % rcV)
        print('  no reference date                  exit %d' % rcV)
    finally:
        # Removed by the exact path mkdtemp returned, and nothing derived from it.
        shutil.rmtree(tmp, ignore_errors=True)

    print('')
    print('=' * 92)
    for n in notes:
        print('  note: %s' % n)
    if fails:
        print('')
        for i, f in enumerate(fails, 1):
            print('  %d. %s' % (i, f))
        print('')
        print('::error title=Ticket reconciliation unproven::%d failure(s). A reconciler whose '
              'lookup guards are decorative creates every ticket again on every run.' % len(fails))
        return 1
    print('  lookup-before-create holds; %d guard(s) are load-bearing (%d in the cascade, %d in'
          % (len(MUTANTS) + len(MODEL_MUTANTS), len(MUTANTS), len(MODEL_MUTANTS)))
    print('  the work-item model); the anti-vacuity abort fires; and the command line refuses an')
    print('  unreadable ledger, unparseable findings, and reports an unconfigured backend as the')
    print('  control being off.')
    print('')
    print('  BOTH DIRECTIONS OF THE GATE ARE PROVEN, not one. Routine reconciliation runs')
    print('  UNATTENDED -- the mutants that gate it refuse to survive -- and an unapproved')
    print('  disposition is refused, at the real command line, with the ledger untouched. The')
    print('  four cases ran: allowed, attack, missing evidence, recovery.')
    print('')
    print('  WHAT THIS DOES NOT PROVE: that either real backend works. GitHub Issues and Jira')
    print('  are exercised by nothing here -- no network call is made, by design. Their request')
    print('  shapes are UNVERIFIED against a live tracker.')
    print('')
    print('  Nor does it prove the COMPLIANCE PAIRING TABLE is right. That a lookup is')
    print('  deterministic and refuses to default is proven; which subject warrants which review')
    print('  is a governance judgement awaiting an owner, and no test can establish it.')
    return 0


def _scripts_copy():
    """A throwaway copy of scripts/*.py. Mutants are written HERE and never into the repository.

    Both runners used to write into scripts/ itself: the orchestrator mutant as a new file beside
    the original, and the MODEL mutant OVER the tracked ticket_model.py, restored in a `finally`. A
    killed or concurrent run therefore left a mutant in the tree -- a broken guard one `git commit
    -a` from shipping (N51). The scripts import their siblings from their own directory
    (`sys.path.insert(0, HERE)`), so a copied set resolves exactly as the real one does.
    """
    tmp = tempfile.mkdtemp(prefix='ticket-mutant-')
    src = os.path.join(ROOT, 'scripts')
    for f in os.listdir(src):
        if f.endswith('.py'):
            shutil.copyfile(os.path.join(src, f), os.path.join(tmp, f))
    return tmp


def run_mutant(text):
    """Write a mutated copy of the orchestrator into a scripts copy and run its self-test."""
    tmp = _scripts_copy()
    try:
        path = os.path.join(tmp, '_mutant.py')
        io.open(path, 'w', encoding='utf-8', newline='').write(text)
        return run([path, '--self-test'])
    finally:
        # Removed by the exact path mkdtemp returned, and nothing derived from it.
        shutil.rmtree(tmp, ignore_errors=True)


def run_model_mutant(text):
    """Mutate the MODEL in a scripts copy and run the model's own self-test there.

    The mutant takes the name the orchestrator imports (ticket_model.py), but in the copy -- the
    tracked file is never opened for writing, so no interruption can leave it mutated.
    """
    tmp = _scripts_copy()
    try:
        path = os.path.join(tmp, 'ticket_model.py')
        io.open(path, 'w', encoding='utf-8', newline='').write(text)
        return run([path, '--self-test'])
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


def mutate(label, find, repl, consequence, source, runner, fails, index):
    """Apply one mutant and require the relevant self-test to go red. -> True when killed."""
    if find not in source:
        # A mutant that cannot be applied proves nothing, and silently skipping it is how a
        # mutation suite rots into decoration after a refactor renames a line.
        fails.append('mutant %r could not be applied: its target text is not in the source. The '
                     'guard may have been renamed, and this mutant is now proving nothing.'
                     % label)
        print('  %2d. %-46s NOT APPLICABLE -- target text absent' % (index, label))
        return False
    mutated = source.replace(find, repl, 1)
    if mutated == source:
        fails.append('mutant %r changed nothing' % label)
        return False
    rc_m, out_m, err_m = runner(mutated)
    if rc_m == 0:
        fails.append('MUTANT SURVIVED: %s. Nothing in the self-test noticed, so that guard is '
                     'decorative. Consequence: %s' % (label, consequence))
        print('  %2d. %-46s SURVIVED  <-- guard is decorative' % (index, label))
        return False
    print('  %2d. %-46s killed (exit %d)' % (index, label, rc_m))
    return True


if __name__ == '__main__':
    sys.exit(main())

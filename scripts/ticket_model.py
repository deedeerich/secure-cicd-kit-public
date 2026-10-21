#!/usr/bin/env python3
"""Parent ticket, child tasks, deferral discipline, and the compliance pairing.

PROVENANCE

    The shape here is carried from a PRIOR ENGAGEMENT'S TICKET ENGINE -- a reference estate that
    had solved several things this kit had not. It is re-expressed rather than copied, and only
    the mechanism travels: every engineering fact survives, the identity does not. That is the
    same rule `tests/check_export_safety.py` applies to this repository about itself.

    Its ticket creation was DETERMINISTIC. A vulnerability class mapped to a ticket and to the
    corresponding compliance request through a table, with no model and no agent anywhere in the
    path, and it assigned confidence without one either. That property is the reason to carry it:
    a reconciler whose output depends on a model cannot be reasoned about by the person who has to
    defend it to an auditor.

WHAT THIS ADDS TO WHAT WAS HERE

    The kit's reconciler produced ONE ticket per cluster and no child objects, so a cluster's
    individual findings had nowhere to carry their own state. A cluster of six findings was six
    obligations wearing one status. This gives each finding a child task with its own lifecycle,
    and gives the parent a closure rule it cannot satisfy on its own.

THE FOUR DISCIPLINES

    1. PARENT CANNOT CLOSE OVER OPEN CHILDREN. `evaluate_closure` returns blocking reasons rather
       than a boolean, so a caller cannot accidentally read "not closable" as "closable".

    2. A DEFERRAL WITHOUT A REASON IS REFUSED. This is the hole the kit already had, found in the
       exceptions path: an exception with no end date suppresses forever because nothing ever goes
       red to prompt a review. The reference estate had solved it properly and the solution is
       carried unchanged in substance -- `deferred_reason` is required, not recommended.

    3. REOPENING IS EXPLICIT, NEVER SILENT -- AND AN ELAPSED DEFERRAL IS NOT NOTHING. This is
       where this file DEPARTS from its source. The reference engine stated the rule correctly --
       "silent/automatic reopening is forbidden" -- and then its split path reopened past-due
       tasks itself, with the actor recorded as the system.

       The date passing is a PRECONDITION that makes reopening available. It is not a trigger
       that performs it. But the first draft of this file stopped there, and that was a second
       defect wearing the first one's clothes: a deferral whose date had passed either went on
       suppressing the finding for ever, or waited for a trigger nobody fires. Both of those are
       silence, and silence is what the rule exists to forbid.

       So an elapsed deferral now creates a REVIEW OBLIGATION. `deferral_state` returns
       DEFERRAL_PAST_DUE, the task STAYS DEFERRED -- no silent reopen -- and every ordinary run
       reports it, unasked, until an authorised person resolves it. Visible, not reopened, and
       not silently still suppressing.

    4. A MUTATION IS CLASSIFIED BEFORE IT IS GATED, AND MOST MUTATIONS NEED NO APPROVAL. The
       reference estate carried a blanket invariant -- every creation, closure, transition,
       split, reopen, suppression and validation required an explicit human approval -- and the
       first draft of this file imported it whole. That was wrong, and it was wrong in the
       expensive direction: a reconciler that needs a person for every create is a reconciler
       nobody runs, and determinism is worth nothing if a human sits in front of it.

       Approval is required for DISPOSITIONS -- judgements that change what the organisation
       accepts. It is NOT required for routine, deterministic, evidence-backed reconciliation.
       `MUTATION_CLASS` below states which is which for every mutation this model performs, and
       an unlisted mutation REFUSES rather than defaulting either way.

CONFIDENCE IS A LABEL WITH ITS DERIVATION ATTACHED, NEVER A NUMBER

    The reference estate carried `confidence: float = 0.5`. That default is not carried, and the
    registry already says why -- `epistemic_property.CONFIDENCE` requires a confidence figure to
    be answerable: "confidence in WHAT claim, based on WHICH evidence, diminished by WHICH missing
    observations, computed under WHICH model, at WHAT time", and calls one without provenance
    "numerology with an API". A float defaulting to 0.5 answers none of those and is
    indistinguishable, downstream, from a measured 0.5.

    So `derive_confidence` returns a LABEL and the DERIVATION that produced it, computed from
    three things that are actually observable: how many scanners anchored on the cluster, whether
    identity was established, and whether the evidence channel was degraded.

USAGE
    python3 scripts/ticket_model.py --self-test
    python3 scripts/ticket_model.py --explain-pairing
"""
import datetime
import sys

# ── TICKET LIFECYCLE (assurance-taxonomy.yaml : ticket_state) ────────────────────────
DRAFT = 'DRAFT'
OPEN = 'OPEN'
IN_PROGRESS = 'IN_PROGRESS'
BLOCKED = 'BLOCKED'
RESOLVED = 'RESOLVED'
CLOSED = 'CLOSED'

# RESOLVED AND CLOSED ARE NOT THE SAME CLAIM, and collapsing them is the reason the distinction is
# here. RESOLVED is the execution path saying the work is done. CLOSED is somebody having
# established that it is. A team must be able to represent "we finished" without that assertion
# also deciding that the obligation is discharged -- otherwise the only way to record completed
# work is to close the obligation, and the two facts become one field.
TICKET_TRANSITIONS = {
    DRAFT: (OPEN,),
    OPEN: (IN_PROGRESS, BLOCKED),
    IN_PROGRESS: (BLOCKED, RESOLVED, CLOSED),
    BLOCKED: (IN_PROGRESS,),
    RESOLVED: (CLOSED,),
    CLOSED: (),
}

# ── TASK LIFECYCLE (assurance-taxonomy.yaml : task_state) ───────────────────────────
FIXED = 'FIXED'
VALIDATED = 'VALIDATED'
DISPUTED = 'DISPUTED'
DEFERRED = 'DEFERRED'

TASK_TRANSITIONS = {
    OPEN: (IN_PROGRESS, DEFERRED),
    IN_PROGRESS: (FIXED, DISPUTED, DEFERRED),
    # FIXED is a claim by whoever did the work. VALIDATED is somebody else establishing it. The
    # edge from FIXED to DISPUTED is what makes the first one falsifiable.
    FIXED: (VALIDATED, DISPUTED),
    VALIDATED: (CLOSED,),
    DISPUTED: (IN_PROGRESS,),
    # The ONLY edge out of DEFERRED, and it is reachable only through `reopen_deferred`.
    DEFERRED: (OPEN,),
    CLOSED: (),
}

# A task in one of these has reached a terminal state honestly. DISPUTED is deliberately absent:
# conflicting evidence is not a resolution, and counting it as one would let a cluster close over
# the findings its own scanners disagreed about.
TERMINAL_TASK_STATES = (VALIDATED, CLOSED)

# ── CLOSURE RULES (assurance-taxonomy.yaml : ticket_closure_rule) ───────────────────
ALL_CHILDREN_RESOLVED = 'ALL_CHILDREN_RESOLVED'
AUTHORITY_OVERRIDE = 'AUTHORITY_OVERRIDE'

# THE REFERENCE ESTATE'S THIRD RULE IS NOT CARRIED. It had a `quorum` rule closing a parent when
# a configurable fraction of children were resolved, defaulting to 0.8. A threshold nobody
# derived, applied to obligations of unequal severity, closes a parent over the 20% that might be
# the only ones that mattered. If a consumer wants it, it is a governance decision with a named
# authority and a defended number -- not a default.
CLOSURE_RULES = (ALL_CHILDREN_RESOLVED, AUTHORITY_OVERRIDE)

# ── HUMAN APPROVAL (assurance-taxonomy.yaml : human_approval) ───────────────────────
APPROVAL_GRANTED = 'APPROVAL_GRANTED'
APPROVAL_NOT_GRANTED = 'APPROVAL_NOT_GRANTED'


class Approval(object):
    """An explicit human approval for ONE mutation.

    Required by every mutating function here. It carries an actor and a reason because an approval
    with neither is a rubber stamp with extra steps -- the phrase the disposition-request schema
    already uses for the same shape.

    `actor` is a ROLE, never a person's name. The schema gives the reason: "a pipeline routed to an
    individual becomes an undocumented API, and needs reconstructive surgery when they leave."
    """

    def __init__(self, actor, reason, granted=True):
        self.actor = (actor or '').strip()
        self.reason = (reason or '').strip()
        self.granted = bool(granted)

    def state(self):
        return APPROVAL_GRANTED if self.granted else APPROVAL_NOT_GRANTED

    def __repr__(self):
        return 'Approval(actor=%r, granted=%r)' % (self.actor, self.granted)


# Not an approval. Used where a caller is reading rather than mutating, so that the absence of an
# approval is never represented by `None` -- `None` reads as "not supplied yet" at one call site
# and as "not needed" at another, and the two must not share a spelling.
NO_APPROVAL = Approval(actor='', reason='', granted=False)

MIN_APPROVAL_REASON = 10


def require_approval(action, approval):
    """-> '' when the mutation may proceed, else why it may not.

    Returns a REASON rather than raising or returning False. A caller that gets a string can print
    it; a caller that gets False has to guess, and guessing produces "approval failed" in a log
    with nothing a reader can act on.
    """
    if approval is None:
        # THE WORDING MATTERS. An earlier version of this message said "every creation,
        # transition, closure, split, reopen and suppression is gated", which was the blanket
        # invariant this model was corrected to drop -- and a refusal that restates a rule the
        # code no longer holds teaches the next reader the wrong contract.
        return ('%s requires an explicit human approval and none was supplied. ROUTINE '
                'RECONCILIATION IS NOT GATED -- creation, update, linking, re-sync and the '
                'ordinary transitions run unattended. What needs a person is a judgement about '
                'what the organisation accepts, and this is one of those. Supply a ROLE and a '
                'reason: --approved-by <role> --approval-reason <why>.' % action)
    if not approval.granted:
        return '%s was not approved (%s)' % (action, APPROVAL_NOT_GRANTED)
    if not approval.actor:
        return ('%s carries an approval with no actor. An unattributed approval is a decision '
                'nobody has made -- the registry spells that %s one namespace over.'
                % (action, 'control_weakening.WEAKENING_UNATTRIBUTED'))
    if len(approval.reason) < MIN_APPROVAL_REASON:
        return ('%s carries an approval with a %d-character reason. An approval whose rationale '
                'cannot be read later is unreviewable, which is the same defect as an exception '
                'with no justification.' % (action, len(approval.reason)))
    return ''


# ── WHICH MUTATIONS NEED A PERSON (assurance-taxonomy.yaml : mutation_class) ─────────
#
# THE DEFECT THIS CORRECTS, NAMED.
#
#     The first draft of this model imported a blanket invariant from the reference estate:
#     "every creation, closure, transition, split, reopen, suppression and validation requires
#     explicit human approval". Applied to a reconciler, that is not a control -- it is an
#     off switch. A policy-authorised reconciler that cannot open a ticket for a corroborated,
#     fingerprinted, evidence-backed finding without someone signing for it will be run once,
#     in a demo, and then disabled. And the whole reason this model is deterministic -- a table
#     lookup, no model, no agent, no float -- is so that it CAN run unattended and be defended
#     afterwards from its own record.
#
#     The operator's correction, in their words: a human is consulted "for something like an
#     exception, exclusion, risk acceptance, mitigation, false positive, something that requires
#     budget judgement or would impact the security and governance of the environment and
#     system."
#
# SO THERE ARE TWO CLASSES AND THEY ARE NOT THE SAME FACT.
#
#     ROUTINE_RECONCILIATION  Deterministic, evidence-backed bookkeeping. It carries identity,
#                             evidence, audit history and idempotency, and it changes nothing
#                             about what the organisation accepts. It runs UNATTENDED.
#     GOVERNANCE_DISPOSITION  A judgement that changes what the organisation accepts: an
#                             exception, an exclusion, a false-positive call, a risk acceptance,
#                             accepting a compensating control instead of a fix, a closure
#                             reached by decision rather than by evidence, anything committing
#                             budget, anything moving the security or governance posture. A
#                             PERSON approves it, by role, with a readable reason.
#
# AND A THIRD THAT IS NOT A CLASS BUT A REFUSAL.
#
#     MUTATION_CLASS_NOT_STATED  The mutation is not in the table. It is refused. Defaulting to
#                             automatic would let a disposition through the unattended door;
#                             defaulting to approval reproduces the blanket gate this section
#                             exists to remove. Neither default is safe, so there is none.
ROUTINE_RECONCILIATION = 'ROUTINE_RECONCILIATION'
GOVERNANCE_DISPOSITION = 'GOVERNANCE_DISPOSITION'
MUTATION_CLASS_NOT_STATED = 'MUTATION_CLASS_NOT_STATED'

# What the audit history records as the actor of an unattended mutation. Deliberately lower-case
# prose and deliberately NOT a person, a role, or the word "system": the reference engine wrote
# the system into the actor field of an automatic reopen, and that is how an unapproved mutation
# comes to look approved six months later. A reader of this history must be able to see at a
# glance that nobody signed for it, because nobody had to.
ROUTINE_ACTOR = 'reconciler (policy-authorised, unattended)'

# THE TABLE. Every mutation this model or its orchestrator performs, mapped EXPLICITLY. Nothing
# here is inferred from a name, a prefix or a state's position in a tuple -- `classify_mutation`
# is a dict lookup and nothing else, because a classifier with a rule in it is a classifier that
# can be argued with.
#
# The KEYS are deliberately lower-case dotted names rather than new upper-case state words. They
# identify an operation, not a state, and nothing projects a verdict from one; minting a dozen
# upper-case words for call sites would be the vocabulary inflation `scripts/reconcile_taxonomy.py`
# exists to catch. The same reasoning the clustering tiers are spelled `anchored`/`proposed` under.
#
# Each row carries WHY it is on the side it is on. A table whose rows cannot be argued with
# individually is a policy nobody reviewed.
MUTATION_CLASS = {
    # ── ROUTINE. Runs unattended. ────────────────────────────────────────────────────
    'ticket.create': (
        ROUTINE_RECONCILIATION,
        'a fingerprinted, anchored cluster observed by a scanner is WORK. Opening a work item '
        'for it asserts nothing about what is accepted, and is reversible by closing it'),
    'ticket.body_resync': (
        ROUTINE_RECONCILIATION,
        'rewriting the machine-owned block to match current evidence. A human\'s notes live '
        'outside the delimiters and are never touched'),
    'ticket.child_link': (
        ROUTINE_RECONCILIATION,
        'attaching a child task to its parent. Structure, not judgement'),
    'ledger.bind': (
        ROUTINE_RECONCILIATION,
        'recording the cluster -> ticket binding so the next run finds it instead of creating a '
        'duplicate. This is the idempotency itself'),
    'ticket.advance.' + OPEN: (
        ROUTINE_RECONCILIATION,
        'a DRAFT proposal becoming an open obligation. It makes the estate MORE visible, never '
        'less'),
    'ticket.advance.' + IN_PROGRESS: (
        ROUTINE_RECONCILIATION,
        'somebody started work. Observable from the tracker, and it accepts nothing'),
    'ticket.advance.' + BLOCKED: (
        ROUTINE_RECONCILIATION,
        'work is stalled. BLOCKED does not satisfy closure and does not suppress anything -- it '
        'is strictly more visible than IN_PROGRESS'),
    'ticket.advance.' + RESOLVED: (
        ROUTINE_RECONCILIATION,
        'the execution path saying the work is done. It is NOT closure: RESOLVED still owes '
        'somebody establishing it'),
    'ticket.close.' + ALL_CHILDREN_RESOLVED: (
        ROUTINE_RECONCILIATION,
        'closure because EVERY child is evidenced complete. Deterministic: `evaluate_closure` '
        'reads the children and the children carry their own evidence. No judgement is exercised, '
        'so no judgement is approved -- and this mutation REFUSES without the children to read'),
    'task.advance.' + IN_PROGRESS: (
        ROUTINE_RECONCILIATION,
        'a child finding picked up. Bookkeeping'),
    'task.advance.' + FIXED: (
        ROUTINE_RECONCILIATION,
        'a claim by whoever did the work, and a falsifiable one -- FIXED can still go DISPUTED. '
        'It is not terminal and it discharges nothing'),
    'task.advance.' + VALIDATED: (
        ROUTINE_RECONCILIATION,
        'evidence establishing the fix: the finding is no longer reported by the scanner that '
        'reported it. Evidence-backed and deterministic -- and this mutation REFUSES without the '
        'evidence, or when the evidence comes from the party that recorded FIXED'),
    'task.advance.' + DISPUTED: (
        ROUTINE_RECONCILIATION,
        'recording that the evidence conflicts. It makes closure HARDER, never easier -- '
        'DISPUTED is deliberately not a terminal state'),
    'task.advance.' + CLOSED: (
        ROUTINE_RECONCILIATION,
        'discharging a child that is already VALIDATED. The only edge into it, and the judgement '
        'was already made and evidenced at VALIDATED'),
    'ticket.reopen': (
        ROUTINE_RECONCILIATION,
        'reopening a closed ticket beside a finding the scanner still reproduces, when nothing '
        'unexpired and approved backs the closure (TICKETING_CONTRACT.md 4.2 makes this the '
        'required behaviour). It accepts nothing and makes the estate MORE visible; a closure '
        'that IS backed is never reopened'),
    'ticket.successor': (
        ROUTINE_RECONCILIATION,
        'opening a successor when the tracker refuses the reopen, with the predecessor kept in '
        'the ledger and referenced from the successor (TC 4.2). The obligation already existed; '
        'this only gives it a tracking surface the tracker will accept'),
    'deferral.past_due_flag': (
        ROUTINE_RECONCILIATION,
        'marking an elapsed deferral as past due in the run\'s report. It changes no state and '
        'grants nothing; it makes an obligation VISIBLE, which is the opposite of a disposition'),

    # ── DISPOSITION. A person approves it, by role, with a reason. ──────────────────
    'ticket.close.' + AUTHORITY_OVERRIDE: (
        GOVERNANCE_DISPOSITION,
        'closure by DECISION rather than by evidence. This is the judgement half of closure and '
        'it is exactly what the operator named: an obligation discharged because somebody with '
        'authority accepted it unremediated'),
    'task.advance.' + DEFERRED: (
        GOVERNANCE_DISPOSITION,
        'deciding the organisation will carry this risk until a date. A deferral is a '
        'time-boxed risk acceptance wearing a work-item\'s clothes'),
    'task.deferral.reopen': (
        GOVERNANCE_DISPOSITION,
        'ending a deferral. Whether the date has passed or not, somebody is deciding the '
        'acceptance is over -- and the record must say who and on what trigger'),
    'task.deferral.extend': (
        GOVERNANCE_DISPOSITION,
        'renewing an acceptance that has run out. Renewal through silence is the defect the '
        'whole deferral discipline exists to prevent, so renewal is a fresh decision'),
    'disposition.exception': (
        GOVERNANCE_DISPOSITION,
        'an exception. Named by the operator'),
    'disposition.exclusion': (
        GOVERNANCE_DISPOSITION,
        'an exclusion -- removing something from scope. Named by the operator'),
    'disposition.false_positive': (
        GOVERNANCE_DISPOSITION,
        'declaring a finding untrue. Named by the operator, and the one disposition that makes a '
        'finding disappear rather than be carried'),
    'disposition.risk_acceptance': (
        GOVERNANCE_DISPOSITION,
        'accepting the risk unremediated. Named by the operator'),
    'disposition.mitigation_accepted': (
        GOVERNANCE_DISPOSITION,
        'accepting a compensating control INSTEAD of a fix. Named by the operator, and the '
        'judgement is that the control is sufficient -- which no table can establish'),
    'disposition.budget_commitment': (
        GOVERNANCE_DISPOSITION,
        'committing money. Named by the operator'),
    'disposition.posture_change': (
        GOVERNANCE_DISPOSITION,
        'changing the security or governance posture of the environment or system. Named by the '
        'operator, and the catch-all for anything that moves what the estate enforces'),
}


def classify_mutation(mutation):
    """-> (class, why). A DICT LOOKUP. No prefix rule, no inference, no default.

    An unlisted mutation is MUTATION_CLASS_NOT_STATED, and `authorise` refuses it. That is the
    whole point: a mutation added to this model and not added to the table stops working rather
    than quietly picking a side. Defaulting to routine would hand a disposition the unattended
    path; defaulting to approval would rebuild the blanket gate.
    """
    row = MUTATION_CLASS.get(mutation)
    if row is None:
        return MUTATION_CLASS_NOT_STATED, (
            'mutation %r is not in MUTATION_CLASS, so whether it is routine reconciliation or a '
            'governance disposition has not been stated. It is refused rather than defaulted: '
            'defaulting to automatic would let a disposition run unattended, and defaulting to '
            'approval would reproduce the blanket gate that made the reconciler unrunnable.'
            % mutation)
    return row[0], row[1]


def authorise(mutation, approval):
    """THE ENFORCEMENT POINT. -> '' when the mutation may proceed, else why it may not.

    Every mutating function in this file routes through here, and so does the orchestrator's
    creation path. There is no second door: `require_approval` is now only reachable THROUGH
    this function, because a caller who could reach it directly could also decide for itself
    that its mutation was routine.

    ROUTINE mutations return '' with no approval supplied, by design. That is not a hole; it is
    the correction. A reconciler that refuses everything is not secure, it is broken.
    """
    cls, why = classify_mutation(mutation)
    if cls == MUTATION_CLASS_NOT_STATED:
        return 'REFUSED (%s): %s' % (MUTATION_CLASS_NOT_STATED, why)
    if cls == ROUTINE_RECONCILIATION:
        # UNATTENDED, DELIBERATELY. No approval is consulted and none is required.
        return ''
    if cls == GOVERNANCE_DISPOSITION:
        return require_approval('%s is a %s (%s), and it' % (mutation, GOVERNANCE_DISPOSITION,
                                                             why), approval)
    # Unreachable while the two classes are the only two. Fails closed rather than falling
    # through to permitted, for the same reason `evaluate_closure` does.
    return ('REFUSED: mutation class %r is not one of %s or %s, so nothing can be concluded '
            'about whether it needs a person' % (cls, ROUTINE_RECONCILIATION,
                                                 GOVERNANCE_DISPOSITION))


def mutation_class_table():
    """-> [(mutation, class, why)], sorted by class then name. For the report and the docs."""
    order = {ROUTINE_RECONCILIATION: 0, GOVERNANCE_DISPOSITION: 1}
    rows = [(m, c, w) for m, (c, w) in MUTATION_CLASS.items()]
    rows.sort(key=lambda r: (order.get(r[1], 9), r[0]))
    return rows


# ── THE COMPLIANCE PAIRING (assurance-taxonomy.yaml : compliance_review_type) ───────
COMPLIANCE_VALIDATION = 'COMPLIANCE_VALIDATION'
FRAMEWORK_GAP_REVIEW = 'FRAMEWORK_GAP_REVIEW'
REGULATORY_OVERLAY_REVIEW = 'REGULATORY_OVERLAY_REVIEW'

# When a subject class implies no compliance review. RETURNED, never defaulted to.
PAIRING_NOT_ESTABLISHED = 'PAIRING_NOT_ESTABLISHED'

# A finding class implies a remediation obligation AND, where the class warrants it, a compliance
# review of a named type. Keyed on `finding_subject`, which is a registered nine-value namespace
# and is derived from the SARIF rather than declared by a job -- so the pairing is deterministic
# from something already established upstream.
#
# THE TABLE'S CONTENT IS A GOVERNANCE PROPOSAL, NOT AN ESTABLISHED DECISION. The MECHANISM --
# a table, looked up, with an explicit not-established outcome -- is what was carried. Which
# subject warrants which review is a judgement an owner has to make, and it is recorded here as
# the kit's default so that a consumer can see it and override it, rather than discovering it by
# watching tickets appear. Every row carries why it is the way it is.
COMPLIANCE_PAIRING = {
    'IAC_PLAN': (FRAMEWORK_GAP_REVIEW,
                 'a misconfiguration in infrastructure code is a control the framework requires '
                 'and the declared estate does not implement, visible BEFORE deployment -- which '
                 'is a gap in the framework mapping, not only a defect to fix'),
    'RESOURCE': (COMPLIANCE_VALIDATION,
                 'a deployed resource contradicting a control is the assurance question: the '
                 'control was declared, and this is evidence about whether it is in force'),
    'IDENTITY_ASSIGNMENT': (REGULATORY_OVERLAY_REVIEW,
                            'access and entitlement are where a regulatory overlay bites hardest, '
                            'and an over-broad assignment is reportable under several overlays '
                            'independently of whether it is exploited'),
    'POLICY': (FRAMEWORK_GAP_REVIEW,
               'a finding about a policy object is a finding about the control itself rather than '
               'about something the control governs'),
    'RUNTIME_OBSERVATION': (COMPLIANCE_VALIDATION,
                            'a control observed failing at runtime is the strongest evidence '
                            'available about whether it is effective, which is exactly what a '
                            'validation review exists to establish'),
    # DELIBERATELY UNMAPPED, and the absence is the decision rather than an omission.
    'SOURCE': (PAIRING_NOT_ESTABLISHED,
               'a weakness in code is a remediation obligation. Whether a given class of code '
               'weakness also implies a compliance review depends on the framework the consumer '
               'is held to, and this kit does not know it. Defaulting one in would manufacture '
               'compliance work nobody asked for and teach readers to ignore the queue'),
    'SOURCE_DEPENDENCY': (PAIRING_NOT_ESTABLISHED,
                          'a vulnerable dependency is a remediation obligation with an SLA. It '
                          'becomes a compliance matter through the SLA being breached, which is a '
                          'different trigger and is not established at creation time'),
    'IMAGE': (PAIRING_NOT_ESTABLISHED,
              'the same reasoning as a dependency: the image is a delivery vehicle, and the '
              'obligation belongs to what is in it'),
    'RELEASE': (PAIRING_NOT_ESTABLISHED,
                'a release-scoped finding is about the act of shipping. Which review that owes '
                'depends on the consumer\'s change-management regime, which is not readable here'),
}


def pair_compliance(finding_subject, is_secret=False):
    """-> (review_type_or_PAIRING_NOT_ESTABLISHED, why). Deterministic. No inference.

    A SECRET IS A SPECIAL CASE AND IT IS NOT A COMPLIANCE REQUEST. The remedy for an exposed
    credential is rotation, and "it was already in production" is the reason to rotate rather than
    a reason to schedule a review. Pairing a compliance review to it would put a governance
    conversation in front of an action that should already have happened.
    """
    if is_secret:
        return (PAIRING_NOT_ESTABLISHED,
                'a secret finding routes to rotation, not to a review. It is never grandfathered '
                'and it carries no compliance pairing -- a review in front of a rotation is delay '
                'wearing governance clothing')
    subject = (finding_subject or '').strip()
    if not subject:
        return (PAIRING_NOT_ESTABLISHED,
                'no finding_subject was established, so there is no key to look up. This is not '
                '"no review required" -- it is a lookup that could not be performed')
    if subject not in COMPLIANCE_PAIRING:
        return (PAIRING_NOT_ESTABLISHED,
                'subject %r is not in the pairing table. An unrecognised subject gets NO pairing '
                'rather than a default one: a near-miss spelling must not silently inherit '
                'another subject\'s governance consequence' % subject)
    return COMPLIANCE_PAIRING[subject]


# ── CONFIDENCE (assurance-taxonomy.yaml : finding_confidence) ───────────────────────
CORROBORATED_ANCHORED = 'CORROBORATED_ANCHORED'
SINGLE_SOURCE_ANCHORED = 'SINGLE_SOURCE_ANCHORED'
CONFIDENCE_NOT_ESTABLISHED = 'CONFIDENCE_NOT_ESTABLISHED'


def derive_confidence(scanners, identity_established, channel_degraded=False):
    """-> (label, derivation). Deterministic, from three observable things.

    NO MODEL, NO AGENT, NO NUMBER. The derivation string is not decoration: the registry requires
    a confidence claim to say what evidence it rests on, and a label whose basis is not carried
    alongside it becomes a number with extra steps the moment somebody puts it in a table.

    Note what this is confidence IN. It is confidence that this cluster is ONE REAL OBLIGATION --
    that the finding exists and that the members belong together. It is NOT confidence that the
    finding is exploitable, severe, or worth fixing first; those are different claims with
    different evidence, and a single label covering all of them would be the composite verdict
    this repository's governing rule forbids.
    """
    names = sorted(set(s for s in (scanners or []) if s))

    if not identity_established:
        return (CONFIDENCE_NOT_ESTABLISHED,
                'identity was not established, so there is no durable thing to be confident '
                'about. Not low confidence -- NO confidence, which is a different state')
    if channel_degraded:
        return (CONFIDENCE_NOT_ESTABLISHED,
                'the evidence channel was degraded (%s), so the contributor set is a FLOOR rather '
                'than a count: scanners that would have corroborated may simply not have been '
                'read' % 'routing_result.EVIDENCE_UNTRUSTED')
    if len(names) >= 2:
        return (CORROBORATED_ANCHORED,
                '%d scanners (%s) anchored on the same durable identity. Corroboration across '
                'independent detectors, not one tool agreeing with itself'
                % (len(names), ', '.join(names)))
    return (SINGLE_SOURCE_ANCHORED,
            'one scanner (%s) with an established durable identity. The finding is anchored and '
            'uncorroborated -- which is NOT doubt about it, only the absence of a second '
            'observation' % (names[0] if names else 'unnamed'))


# ── THE OBJECTS ─────────────────────────────────────────────────────────────────────


class Task(object):
    """A child work item: ONE finding, with its own state.

    This is what the kit was missing. A cluster of six findings was six obligations sharing one
    status, so "partially fixed" was not representable and the only honest rendering of a cluster
    where five were done was the same as one where none were.
    """

    def __init__(self, task_id, parent_ticket_id, cluster_key, identity,
                 scanner, rule, uri, line=None, severity=''):
        self.task_id = task_id
        self.parent_ticket_id = parent_ticket_id
        self.cluster_key = cluster_key
        self.identity = identity
        self.scanner = scanner
        self.rule = rule
        self.uri = uri
        self.line = line
        self.severity = severity
        self.state = OPEN
        self.deferred_reason = None
        self.deferred_until = None
        self.history = []

    def record(self, frm, to, actor, reason):
        self.history.append({'from': frm, 'to': to, 'actor': actor, 'reason': reason})

    def as_dict(self):
        return {'task_id': self.task_id, 'parent_ticket_id': self.parent_ticket_id,
                'cluster_key': self.cluster_key, 'identity': self.identity,
                'scanner': self.scanner, 'rule': self.rule, 'uri': self.uri,
                'line': self.line, 'severity': self.severity, 'state': self.state,
                'deferred_reason': self.deferred_reason, 'deferred_until': self.deferred_until,
                'history': list(self.history)}


class Ticket(object):
    """A parent work item: ONE cluster, coordinating its children.

    It cannot certify its own closure. `evaluate_closure` is what decides, and it reads the
    children rather than the parent's own opinion of them.
    """

    def __init__(self, ticket_id, cluster_key, title, severity,
                 closure_rule=ALL_CHILDREN_RESOLVED, subject='',
                 compliance_review=PAIRING_NOT_ESTABLISHED, compliance_why='',
                 confidence=CONFIDENCE_NOT_ESTABLISHED, confidence_basis=''):
        self.ticket_id = ticket_id
        self.cluster_key = cluster_key
        self.title = title
        self.severity = severity
        self.subject = subject
        self.closure_rule = closure_rule
        self.authority_override_rationale = None
        self.child_task_ids = []
        self.compliance_review = compliance_review
        self.compliance_why = compliance_why
        self.confidence = confidence
        self.confidence_basis = confidence_basis
        # DRAFT, not OPEN. A ticket this program creates is a PROPOSAL until a person advances it,
        # which is the human-in-loop rule expressed as the initial state rather than as a comment.
        self.state = DRAFT
        self.history = []

    def record(self, frm, to, actor, reason):
        self.history.append({'from': frm, 'to': to, 'actor': actor, 'reason': reason})

    def as_dict(self):
        return {'ticket_id': self.ticket_id, 'cluster_key': self.cluster_key,
                'title': self.title, 'severity': self.severity, 'subject': self.subject,
                'closure_rule': self.closure_rule, 'state': self.state,
                'child_task_ids': list(self.child_task_ids),
                'authority_override_rationale': self.authority_override_rationale,
                'compliance_review': self.compliance_review,
                'compliance_why': self.compliance_why,
                'confidence': self.confidence, 'confidence_basis': self.confidence_basis,
                'history': list(self.history)}


def build_ticket(cluster, ticket_id, channel_degraded=False):
    """-> (Ticket, [Task]). A parent and one child per member. Creates nothing outward-facing.

    The cluster key is NOT recomputed here. It comes from `reconcile_tickets.build_clusters`,
    which anchors it on a durable identity -- the reference estate's engine clustered on a
    root-cause key with a confidence float and no identity anchoring, so that part of this kit
    stays as it is and only the parent/child shape is carried in.
    """
    subject = cluster.get('subject') or ''
    members = cluster.get('members') or []
    is_secret = any(str(m.get('is_secret_finding', '')).strip().lower() in ('1', 'true', 'yes')
                    for m in members)

    review, why = pair_compliance(subject, is_secret=is_secret)
    label, basis = derive_confidence(cluster.get('scanners') or [],
                                     identity_established=bool(cluster.get('cluster_key')),
                                     channel_degraded=channel_degraded)

    ticket = Ticket(ticket_id=ticket_id, cluster_key=cluster['cluster_key'],
                    title=cluster.get('title') or 'remediation', severity=cluster.get('severity', ''),
                    subject=subject, compliance_review=review, compliance_why=why,
                    confidence=label, confidence_basis=basis)

    tasks = []
    for n, m in enumerate(members):
        tid = '%s/task-%d' % (ticket_id, n + 1)
        tasks.append(Task(task_id=tid, parent_ticket_id=ticket_id,
                          cluster_key=cluster['cluster_key'], identity=m.get('identity') or '',
                          scanner=m.get('scanner') or '', rule=m.get('rule') or '',
                          uri=m.get('uri') or '', line=m.get('line'),
                          severity=m.get('severity') or ''))
    ticket.child_task_ids = [t.task_id for t in tasks]
    return ticket, tasks


# ── AN ELAPSED DEFERRAL (assurance-taxonomy.yaml : deferral_obligation) ─────────────
#
# THE DEFECT THIS CORRECTS, NAMED.
#
#     Discipline 3 got half the problem right and shipped the other half. It forbade silent
#     reopening -- correctly -- and then left a past-due deferral with nowhere to go. In
#     practice that meant one of two things, and both are the failure the discipline exists to
#     prevent:
#
#         the deferral goes on suppressing       nobody is asked to renew it, and an acceptance
#                                                that outlived its own end date is an exception
#                                                with no expiry
#         it waits for a trigger nobody fires    `reopen_deferred` needs a named trigger, and
#                                                nothing in the kit generates one on a date
#
#     So the date passing now produces a STATE, reported in every ordinary run, and that state
#     is an obligation on a person rather than an action by the machine.
#
# THREE VALUES AND NEVER A BOOLEAN. "This deferral is fine" and "this deferral has no date to
# check" are different facts, and a caller that cannot tell them apart will render the second as
# the first -- which is how the undated suppression got into this kit the first time.
DEFERRAL_WITHIN_TERM = 'DEFERRAL_WITHIN_TERM'
DEFERRAL_PAST_DUE = 'DEFERRAL_PAST_DUE'
DEFERRAL_TERM_UNKNOWN = 'DEFERRAL_TERM_UNKNOWN'


def iso_date(value):
    """-> datetime.date for a real `YYYY-MM-DD` calendar date, else None. Never a guess.

    THE SHAPE IS NOT THE DATE. This model used to accept anything ten characters long with dashes
    at positions 4 and 7, then compare lexically -- so `TBD0-00-00` sorted after every real date
    and read as in term for ever, and `2026-02-30` was compared as though February had thirty days
    (G2-6). The shape is checked first because `fromisoformat` alone also accepts forms this model
    does not (`20260630`), and then the calendar decides.
    """
    s = str(value or '')[:10]
    if len(s) != 10 or s[4] != '-' or s[7] != '-':
        return None
    try:
        return datetime.date.fromisoformat(s)
    except ValueError:
        return None


def deferral_state(deferred_until, today):
    """-> (state, detail). Pure: reads two dates and decides nothing else.

    It does NOT mutate, reopen, extend or suppress. Computing the state is deliberately separate
    from acting on it, because the whole correction is that the machine observes and a person
    acts.

    DATES ARE REAL CALENDAR DATES, in `YYYY-MM-DD` form, on the first ten characters, compared as
    dates (`iso_date`). Anything else -- including something merely SHAPED like a date, such as
    `TBD0-00-00` or `2026-02-30` -- is DEFERRAL_TERM_UNKNOWN rather than parsed hopefully. A date
    this function guessed at would decide whether an acceptance is still in force.
    """
    until = str(deferred_until or '')[:10]
    now = str(today or '')[:10]
    if not until:
        return DEFERRAL_TERM_UNKNOWN, (
            'no end date is recorded, so whether the deferral has elapsed cannot be established. '
            'An absent expiry is NOT an open-ended one -- it is unspecified, and it is the '
            'defect this kit shipped once in its suppression path')
    if not now:
        return DEFERRAL_TERM_UNKNOWN, (
            'no reference date was supplied, so %r could not be compared to anything. The run '
            'did not establish that this deferral is still in force' % until)
    if iso_date(until) is None:
        return DEFERRAL_TERM_UNKNOWN, (
            'end date %r is not a real ISO YYYY-MM-DD calendar date. It is not parsed hopefully: '
            'a date this model guessed at would decide whether an acceptance is still in force'
            % until)
    if iso_date(now) is None:
        return DEFERRAL_TERM_UNKNOWN, (
            'reference date %r is not a real ISO YYYY-MM-DD calendar date, so %r could not be '
            'compared to anything' % (now, until))
    if iso_date(until) < iso_date(now):
        return DEFERRAL_PAST_DUE, (
            'the deferral ended %s and today is %s. It is PAST DUE: the task stays %s -- nothing '
            'reopens by itself -- and it is reported in every run until an authorised person '
            'ends it, renews it with a fresh date and reason, or records an acceptance. Until '
            'then the acceptance has lapsed and the suppression is no longer authorised'
            % (until, now, DEFERRED))
    return DEFERRAL_WITHIN_TERM, 'deferred until %s; today is %s' % (until, now)


def past_due_deferrals(tasks, today):
    """-> [{task_id, until, reason, state, detail}] for every child that owes a review.

    DEFERRAL_TERM_UNKNOWN IS INCLUDED, not filtered out. A deferral whose term cannot be
    established is not a deferral in good standing; reporting only the provably-elapsed ones
    would let the undated case -- the original defect -- be the one thing that stays quiet.
    """
    out = []
    for t in tasks:
        if t.state != DEFERRED:
            continue
        state, detail = deferral_state(t.deferred_until, today)
        if state == DEFERRAL_WITHIN_TERM:
            continue
        out.append({'task_id': t.task_id, 'identity': getattr(t, 'identity', ''),
                    'until': t.deferred_until, 'reason': t.deferred_reason,
                    'state': state, 'detail': detail})
    return out


# ── TRANSITIONS ─────────────────────────────────────────────────────────────────────


def advance_ticket(ticket, new_state, approval=None, tasks=None, today=None):
    """-> '' on success (ticket mutated), else why it was refused.

    CLOSURE IS THE ONE TRANSITION THAT IS BOTH CLASSES, depending on HOW it was reached, and
    that distinction is the operator's: "closure where judgement is involved, as distinct from
    closure because every child task is evidenced complete, which is deterministic."

        ALL_CHILDREN_RESOLVED  deterministic. `evaluate_closure` reads the children, and the
                               children carry their own evidence. Runs unattended -- AND REFUSES
                               WITHOUT THE CHILDREN TO READ, because closing on the strength of
                               a `tasks` argument nobody passed would be closing on an absence.
        AUTHORITY_OVERRIDE     a judgement. Approved by a role, with a rationale, like any other
                               disposition.
    """
    mutation = ('ticket.close.%s' % ticket.closure_rule) if new_state == CLOSED \
        else ('ticket.advance.%s' % new_state)
    err = authorise(mutation, approval)
    if err:
        return err
    allowed = TICKET_TRANSITIONS.get(ticket.state, ())
    if new_state not in allowed:
        return ('refused transition %s -> %s. Allowed from %s: %s'
                % (ticket.state, new_state, ticket.state,
                   ', '.join(allowed) if allowed else 'nothing, it is terminal'))
    if new_state == CLOSED and ticket.closure_rule == ALL_CHILDREN_RESOLVED:
        # THE EVIDENCE PRECONDITION FOR THE UNATTENDED PATH. This closure needs no approval
        # BECAUSE it is evidenced; so the evidence is required, and absent evidence refuses
        # rather than being read as satisfied.
        if tasks is None:
            return ('refused: %s closure is unattended because it is DETERMINISTIC from the '
                    'children, so the children are required. None were supplied, and closing '
                    'without reading them would be closing on an absence'
                    % ALL_CHILDREN_RESOLVED)
        satisfied, blockers = evaluate_closure(ticket, tasks, today=today)
        if not satisfied:
            return ('refused: %s closure is not satisfied. %s'
                    % (ALL_CHILDREN_RESOLVED, '; '.join(blockers)))
    if ticket.state == IN_PROGRESS and new_state == CLOSED:
        # Skipping RESOLVED means closing an obligation nobody said was finished. It is available,
        # because sometimes an obligation is discharged by a decision rather than by work -- but
        # only under a named override with a rationale, never as an ordinary edge.
        if ticket.closure_rule != AUTHORITY_OVERRIDE:
            return ('refused: closing directly from %s skips %s, so it requires the %s closure '
                    'rule. Current rule is %s' % (IN_PROGRESS, RESOLVED, AUTHORITY_OVERRIDE,
                                                  ticket.closure_rule))
        if not (ticket.authority_override_rationale or '').strip():
            return ('refused: %s closure requires a rationale. An override with no stated reason '
                    'is indistinguishable from a mistake six months later' % AUTHORITY_OVERRIDE)
    # A ROUTINE MUTATION HAS NO APPROVER, AND THE HISTORY SAYS SO RATHER THAN INVENTING ONE.
    # Recording the system as the actor is how the reference engine's split path laundered an
    # automatic reopen into something that looked approved.
    actor = approval.actor if approval is not None and approval.granted else ROUTINE_ACTOR
    reason = approval.reason if approval is not None and approval.granted \
        else '%s: %s' % (ROUTINE_RECONCILIATION, mutation)
    ticket.record(ticket.state, new_state, actor, reason)
    ticket.state = new_state
    return ''


VALIDATION_EVIDENCE_FIELDS = ('scanner', 'run', 'reproduced', 'scope_covered')


def check_validation_evidence(task, evidence):
    """-> '' when `evidence` establishes the fix, else why it does not. Pure; mutates nothing.

    VALIDATED IS SOMEBODY ELSE ESTABLISHING THE FIX (task_state). The transition is routine and
    unattended BECAUSE it is evidenced -- the same bargain as the ALL_CHILDREN_RESOLVED closure --
    so the evidence is required, and it has to be evidence of the right thing:

        scanner        who re-observed. Never the reconciler, and never the party that recorded
                       FIXED: a claim cannot be established by the party that made it (G2-6).
        run            which run re-observed, so the establishment can be checked later.
        reproduced     must be False: the scanner looked and did not find it.
        scope_covered  must be True: absence over a scope that did not cover the locus is
                       POTENTIALLY_ABSENT, never a fix (TICKETING_CONTRACT.md section 4.3).
    """
    if not isinstance(evidence, dict):
        return ('refused: VALIDATED requires validation evidence -- a scanner, a run, the finding '
                'not reproduced, over a scope shown to cover where it lived. None was supplied, '
                'and validating on nothing is the party that claimed FIXED establishing its own '
                'claim')
    missing = [k for k in VALIDATION_EVIDENCE_FIELDS if k not in evidence]
    if missing or not str(evidence.get('scanner') or '').strip() \
            or not str(evidence.get('run') or '').strip():
        return ('refused: the validation evidence is incomplete (missing or empty: %s)'
                % ', '.join(missing or ['scanner or run']))
    if evidence.get('reproduced') is not False:
        return ('refused: the validation evidence does not say the finding stopped reproducing '
                '(reproduced=%r). A reproducing finding is not fixed' % evidence.get('reproduced'))
    if evidence.get('scope_covered') is not True:
        return ('refused: the scan did not cover the scope the finding lived in, so its absence is '
                'POTENTIALLY_ABSENT -- "establish coverage before calling it fixed"')
    source = str(evidence['scanner']).strip()
    fixed_by = [h['actor'] for h in task.history if h.get('to') == FIXED]
    self_parties = [ROUTINE_ACTOR] + fixed_by[-1:]
    if source in self_parties:
        return ('refused: self-validation. The evidence names %r, which is the party that recorded '
                'FIXED (or the reconciler itself). VALIDATED is somebody else establishing the '
                'fix' % source)
    return ''


def advance_task(task, new_state, approval=None, deferred_reason=None, deferred_until=None,
                 evidence=None):
    """-> '' on success (task mutated), else why it was refused.

    VALIDATED takes `evidence` (see `check_validation_evidence`) and refuses without it.

    DEFERRAL DISCIPLINE. Moving to DEFERRED requires a reason. This is carried from the reference
    estate essentially unchanged, because it is the properly-solved version of the hole this kit
    already had: a suppression with no end date and nobody's name on it, which nothing ever
    revisits because nothing ever goes red.

    DEFERRED IS THE ONLY DISPOSITION IN THIS STATE MACHINE. Every other task transition is
    routine bookkeeping over evidence -- picked up, claimed fixed, validated, disputed,
    discharged -- and runs unattended. Deferring is a time-boxed decision to carry a risk, so it
    is approved like any other acceptance. `MUTATION_CLASS` states all of this row by row.
    """
    # THE DOOR CHECK COMES FIRST, BEFORE THE CLASS GATE. Deliberately: `task.advance.OPEN` is
    # absent from MUTATION_CLASS -- the only route into OPEN from DEFERRED is `reopen_deferred`
    # -- so the table would refuse this call too, and a refusal from the table would make the
    # branch below dead code that still LOOKS load-bearing. Answering on the most specific
    # ground keeps the guard that owns this edge the thing that enforces it.
    if task.state == DEFERRED and new_state == OPEN:
        # Not reachable here. `reopen_deferred` owns it, so that a reopen cannot be performed by a
        # caller who merely knew the edge existed.
        return ('refused: reopening a deferred task goes through reopen_deferred(), which '
                'requires the end date to have passed AND an explicit trigger. The edge exists; '
                'this is not the door to it')

    err = authorise('task.advance.%s' % new_state, approval)
    if err:
        return err
    allowed = TASK_TRANSITIONS.get(task.state, ())
    if new_state not in allowed:
        return ('refused transition %s -> %s. Allowed from %s: %s'
                % (task.state, new_state, task.state,
                   ', '.join(allowed) if allowed else 'nothing, it is terminal'))

    if new_state == DEFERRED:
        if not (deferred_reason or '').strip():
            return ('refused: deferring requires a reason. A deferral with none does not expire '
                    'and nobody is asked to renew it -- the finding simply stops appearing, which '
                    'is how a deferral becomes a permanent silent exception')
        if not (deferred_until or '').strip():
            # The reference estate had this field OPTIONAL ("recommended"). It is required here,
            # for the reason the registry gives three separate times: silence never renews. A
            # deferral with no end date is silence made permanent, and `expires` being absent is
            # exactly the hole already found in this kit's own suppression path.
            return ('refused: deferring requires an end date. The reference pattern treated this '
                    'as optional; it is required here because a deferral with no date is the '
                    'defect this kit already shipped once in its disposition path -- an absent '
                    'expiry reads as open-ended rather than as unspecified')
        if iso_date(deferred_until) is None:
            # A date no run can compare is the undated deferral in a date's clothes: every
            # past-due sweep would report it DEFERRAL_TERM_UNKNOWN for ever, or -- before G2-6 -- read it
            # as in term for ever.
            # Worded so it cannot answer for the missing-date guard above: the self-test asserts
            # each refusal names its own reason.
            return ('refused: the deferral end date %r is not a real calendar date in '
                    'YYYY-MM-DD form' % deferred_until)
        task.record(task.state, new_state, approval.actor, approval.reason)
        task.state = new_state
        task.deferred_reason = deferred_reason.strip()
        task.deferred_until = deferred_until.strip()
        return ''

    if new_state == VALIDATED:
        bad = check_validation_evidence(task, evidence)
        if bad:
            return bad

    actor = approval.actor if approval is not None and approval.granted else ROUTINE_ACTOR
    reason = approval.reason if approval is not None and approval.granted \
        else '%s: task.advance.%s' % (ROUTINE_RECONCILIATION, new_state)
    if new_state == VALIDATED:
        ev = evidence if isinstance(evidence, dict) else {}
        reason = '%s (established by %s in %s: not reproduced over a covering scope)' % (
            reason, ev.get('scanner'), ev.get('run'))
    task.record(task.state, new_state, actor, reason)
    task.state = new_state
    return ''


def reopen_deferred(task, approval, trigger='', today=None):
    """The ONLY reopen path. -> '' on success (task mutated), else why it was refused.

    WHERE THIS DEPARTS FROM ITS SOURCE. The reference engine declared that silent or automatic
    reopening was forbidden, and then reopened past-due tasks inside its split routine with the
    actor recorded as the system. Both of its own rules -- the deferral discipline and the
    human-in-loop invariant -- were bypassed by that path.

    The date passing is a PRECONDITION. It makes reopening AVAILABLE. It does not perform it, and
    nothing in this file reopens a task as a side effect of doing something else. A deferral that
    nobody re-examined must not become an open obligation with no one having decided anything --
    that is a disposition renewing itself through silence, arriving through the work-item door.

    AND THE DATE PASSING IS NOT NOTHING EITHER. `deferral_state` turns it into DEFERRAL_PAST_DUE
    and `past_due_deferrals` puts it in every ordinary run's output, so the obligation is visible
    without anyone asking for it. This function is one of the two authorised ways to discharge
    that obligation; `extend_deferral` is the other.
    """
    err = authorise('task.deferral.reopen', approval)
    if err:
        return err
    if task.state != DEFERRED:
        return 'refused: task is %s, not %s' % (task.state, DEFERRED)
    if not (trigger or '').strip():
        return ('refused: reopening requires a named trigger. "The date passed" is a '
                'precondition, not a trigger -- something or someone has to act, and the record '
                'has to say which')
    # T4 (N40). The date passing is the PRECONDITION, so it must be ESTABLISHED: no reference date,
    # or one that is not a real date, refuses -- the check used to be skipped when `today` was None.
    if task.deferred_until:
        if iso_date(today) is None:
            return ('refused: no usable reference date (%r), so whether the deferral until %s has '
                    'passed is not established. Supply --today' % (today, task.deferred_until))
        until = iso_date(task.deferred_until)
        if until is not None and until > iso_date(today):
            return ('refused: deferred until %s, which has not passed. Reopening early is a '
                    'decision to overrule the deferral, and it needs its own record rather than '
                    'arriving as a reopen' % task.deferred_until)
    task.record(DEFERRED, OPEN, approval.actor,
                '%s (trigger: %s)' % (approval.reason, trigger.strip()))
    task.state = OPEN
    task.deferred_reason = None
    task.deferred_until = None
    return ''


def extend_deferral(task, approval, deferred_reason='', deferred_until='', today=None):
    """The OTHER authorised way out of a past-due deferral. -> '' on success, else the refusal.

    RENEWAL IS A FRESH DECISION, NEVER A ROLLOVER. The task stays DEFERRED, but the reason and
    the date are replaced by new ones somebody approved -- so an acceptance carried for another
    quarter is a thing a named role did on a stated date, not an old record that nobody got round
    to clearing.

    THE NEW DATE MUST BE IN THE FUTURE. An extension to a date already past is not an extension;
    it is the past-due state rewritten to look resolved, which would make the review obligation
    disappear without the review happening.
    """
    err = authorise('task.deferral.extend', approval)
    if err:
        return err
    if task.state != DEFERRED:
        return 'refused: task is %s, not %s -- there is no deferral to extend' % (task.state,
                                                                                  DEFERRED)
    if not (deferred_reason or '').strip():
        return ('refused: extending a deferral requires a reason, and the ORIGINAL reason is not '
                'carried forward. "Still waiting" written once and inherited for three quarters '
                'is renewal through silence')
    state, detail = deferral_state(deferred_until, today)
    if state != DEFERRAL_WITHIN_TERM:
        return ('refused: the new end date does not establish a future term (%s). %s'
                % (state, detail))
    task.record(DEFERRED, DEFERRED, approval.actor,
                '%s (deferral extended to %s: %s)' % (approval.reason, str(deferred_until)[:10],
                                                      deferred_reason.strip()))
    task.deferred_reason = deferred_reason.strip()
    task.deferred_until = str(deferred_until)[:10]
    return ''


# ── CLOSURE AND PROGRESS ────────────────────────────────────────────────────────────


def compute_progress(tasks):
    """-> dict of state -> count, plus the total. Recomputed, never accumulated.

    A counter incremented on each transition drifts from the thing it counts the first time a
    transition is refused halfway through. Recomputing from the children is the only version that
    cannot disagree with them.
    """
    counts = {'total': len(tasks)}
    for state in (OPEN, IN_PROGRESS, FIXED, VALIDATED, DISPUTED, DEFERRED, CLOSED):
        counts[state] = sum(1 for t in tasks if t.state == state)
    return counts


def evaluate_closure(ticket, tasks, today=None):
    """-> (satisfied, blocking_reasons). Never a bare boolean.

    Returning reasons rather than False is what stops a caller reading "not closable" as
    "closable" -- and it is what lets the summary say WHICH children are holding a parent open,
    which is the only form of that message anybody can act on.

    EVALUATION ONLY. A satisfied closure rule means a person MAY close the ticket. It does not
    close it: `advance_ticket` does, and it demands an approval.
    """
    reasons = []

    if ticket.closure_rule == AUTHORITY_OVERRIDE:
        if not (ticket.authority_override_rationale or '').strip():
            reasons.append('%s closure requires a rationale and none is recorded'
                           % AUTHORITY_OVERRIDE)
        return (not reasons), reasons

    if ticket.closure_rule != ALL_CHILDREN_RESOLVED:
        # An unrecognised closure rule FAILS CLOSED. Membership of the allowed set, never
        # inequality with one bad value -- so a rule added later and not handled here refuses
        # instead of falling through to permitted.
        return False, ['closure rule %r is not one of %s, so closure is not established'
                       % (ticket.closure_rule, ', '.join(CLOSURE_RULES))]

    if not tasks:
        # A parent with no children has nothing to have finished. Closing it would be closing an
        # obligation whose work was never represented.
        return False, ['no child tasks: a parent with no children has established nothing']

    for t in tasks:
        if t.state == DEFERRED:
            # PAST DUE IS NAMED SEPARATELY. Both block closure, but "deferred until next March"
            # and "deferred until last March" are different facts about the estate, and a reader
            # who cannot tell them apart will treat the second as the first and wait.
            dstate, _d = deferral_state(t.deferred_until, today)
            if dstate == DEFERRAL_WITHIN_TERM:
                reasons.append('%s is %s until %s (%s)'
                               % (t.task_id, DEFERRED, t.deferred_until,
                                  t.deferred_reason or 'no reason recorded'))
            else:
                reasons.append('%s is %s and %s -- end date %s (%s). The acceptance has lapsed '
                               'and an authorised person owes a review'
                               % (t.task_id, DEFERRED, dstate,
                                  t.deferred_until or 'none recorded',
                                  t.deferred_reason or 'no reason recorded'))
        elif t.state == DISPUTED:
            # Conflicting evidence is NOT a resolution. A cluster closing over its own scanners'
            # disagreement is the merged-away finding that leaves no trace.
            reasons.append('%s is %s -- conflicting evidence is not a resolution' % (t.task_id,
                                                                                     DISPUTED))
        elif t.state not in TERMINAL_TASK_STATES:
            reasons.append('%s is %s' % (t.task_id, t.state))

    return (not reasons), reasons


# ── EXPLAIN ─────────────────────────────────────────────────────────────────────────


def _explain_pairing():
    print('THE COMPLIANCE PAIRING TABLE')
    print('=' * 92)
    print('')
    print('A finding class implies a remediation obligation AND, where the class warrants it, a')
    print('compliance review of a named type. Looked up, never inferred. Where no mapping exists')
    print('the answer is %s -- which is a state, not a silent "none required".'
          % PAIRING_NOT_ESTABLISHED)
    print('')
    print('THE TABLE\'S CONTENT IS A PROPOSAL AWAITING AN OWNER. The mechanism is settled; which')
    print('subject warrants which review is a governance judgement this kit cannot make for a')
    print('consumer. Override it rather than inheriting it by accident.')
    print('')
    for subject in sorted(COMPLIANCE_PAIRING):
        review, why = COMPLIANCE_PAIRING[subject]
        print('  %-22s -> %s' % (subject, review))
        words, line = why.split(), '       '
        for w in words:
            if len(line) + len(w) > 90:
                print(line)
                line = '       '
            line += w + ' '
        print(line)
        print('')
    return 0


def _wrap(text, indent):
    """Print `text` wrapped at 92 columns under a fixed indent."""
    line = indent
    for w in text.split():
        if len(line) + len(w) > 90:
            print(line)
            line = indent
        line += w + ' '
    print(line.rstrip())


def explain_mutations():
    print('WHICH MUTATIONS NEED A PERSON, AND WHICH DO NOT')
    print('=' * 92)
    print('')
    _wrap('Approval is required for DISPOSITIONS -- exception, exclusion, false-positive call, '
          'risk acceptance, accepting a compensating control instead of a fix, closure reached '
          'by judgement, anything committing budget, anything moving the security or governance '
          'posture of the environment. It is NOT required for routine, deterministic, '
          'evidence-backed reconciliation, which runs unattended.', '  ')
    print('')
    _wrap('A mutation that is not in this table is refused. Defaulting to automatic would let a '
          'disposition run unattended; defaulting to approval would reproduce the blanket gate '
          'that made the reconciler unrunnable. Neither default is safe, so there is none.', '  ')
    print('')
    current = None
    for mutation, cls, why in mutation_class_table():
        if cls != current:
            current = cls
            print('')
            print('-- %s %s' % (cls, '-' * (88 - len(cls))))
            if cls == ROUTINE_RECONCILIATION:
                print('   no approval is consulted, and none is required')
            else:
                print('   a ROLE approves it, with a reason at least %d characters long'
                      % MIN_APPROVAL_REASON)
            print('')
        print('  %-38s' % mutation)
        _wrap(why, '       ')
        print('')
    print('=' * 92)
    print('%d mutation(s) classified: %d %s, %d %s'
          % (len(MUTATION_CLASS),
             sum(1 for r in mutation_class_table() if r[1] == ROUTINE_RECONCILIATION),
             ROUTINE_RECONCILIATION,
             sum(1 for r in mutation_class_table() if r[1] == GOVERNANCE_DISPOSITION),
             GOVERNANCE_DISPOSITION))
    return 0


def _selftest():
    """Each assertion is a way a work-item model lets an obligation disappear."""
    fails = []

    def appr(reason='a stated reason for the record'):
        return Approval(actor='platform-security', reason=reason)

    # What a scanner re-run establishes when a fix holds: the finding is not reproduced, over a
    # scope shown to cover where it lived, by a named scanner in a named run.
    EV = {'scanner': 'trivy', 'run': 'run-4242', 'reproduced': False, 'scope_covered': True}

    cluster = {
        'cluster_key': 'abc123', 'subject': 'SOURCE_DEPENDENCY', 'severity': 'high',
        'title': 'CVE-2024-0001 in go.mod',
        'scanners': ['trivy', 'grype'],
        'members': [
            {'identity': 'id-a', 'scanner': 'trivy', 'rule': 'CVE-2024-0001', 'uri': 'go.mod',
             'severity': 'high'},
            {'identity': 'id-b', 'scanner': 'grype', 'rule': 'GHSA-xxxx', 'uri': 'go.mod',
             'severity': 'high'},
        ],
    }

    # ── 1. THE POSITIVE CASE FIRST. A parent and one child per member. ──────────────
    ticket, tasks = build_ticket(cluster, 'ticket-1')
    if len(tasks) != 2:
        fails.append('two members produced %d child task(s)' % len(tasks))
    if ticket.state != DRAFT:
        fails.append('a created ticket is %s, not %s -- it must be a proposal until a person '
                     'advances it' % (ticket.state, DRAFT))
    if ticket.child_task_ids != [t.task_id for t in tasks]:
        fails.append('the parent does not name its children')
    if any(t.parent_ticket_id != 'ticket-1' for t in tasks):
        fails.append('a child does not name its parent')
    # Each child carries its OWN state, which is the whole point of the shape.
    if len(set(t.task_id for t in tasks)) != 2:
        fails.append('two children share one id, so they cannot carry separate state')

    # ── 2. THE TWO CLASSES, AND BOTH SIDES OF EACH. ──────────────────────────────
    #
    # THIS SECTION PROVES A CONTROL, WHICH MEANS IT HAS TO PROVE THE ALLOWED CASE TOO. A suite
    # that only showed the refusals would pass against a model that refuses everything, and
    # "everything is refused" is not security -- it is the blanket gate this model was corrected
    # to remove. So each class is asserted in both directions.

    # 2a. EVERY MUTATION IS CLASSIFIED, EXPLICITLY. An unlisted one refuses.
    for mutation in ('ticket.create', 'ticket.advance.' + OPEN,
                     'ticket.close.' + ALL_CHILDREN_RESOLVED,
                     'task.advance.' + DEFERRED, 'task.deferral.reopen',
                     'disposition.risk_acceptance'):
        cls, why = classify_mutation(mutation)
        if cls == MUTATION_CLASS_NOT_STATED:
            fails.append('mutation %r has no stated class, so it cannot be performed at all'
                         % mutation)
        if not why:
            fails.append('mutation %r is classified with no reason, so the row cannot be '
                         'reviewed' % mutation)
    cls, why = classify_mutation('ticket.invent_something')
    if cls != MUTATION_CLASS_NOT_STATED:
        fails.append('an unlisted mutation was classified as %s rather than %s -- a mutation '
                     'nobody classified must refuse, not pick a side' % (cls,
                                                                         MUTATION_CLASS_NOT_STATED))
    if not authorise('ticket.invent_something', appr()):
        fails.append('an unlisted mutation was AUTHORISED, and with a valid approval -- so an '
                     'unclassified mutation can be performed by supplying any approval at all')
    # The table must actually distinguish. One whose every row says the same thing is a default
    # wearing a table's clothes, which is the defect this whole section corrects.
    classes = set(c for _m, (c, _w) in MUTATION_CLASS.items())
    if classes != set([ROUTINE_RECONCILIATION, GOVERNANCE_DISPOSITION]):
        fails.append('the mutation table yields classes %r; it must distinguish exactly %s from '
                     '%s' % (sorted(classes), ROUTINE_RECONCILIATION, GOVERNANCE_DISPOSITION))

    # 2b. ROUTINE RUNS UNATTENDED. No approval supplied, and it proceeds.
    err = advance_ticket(ticket, OPEN, None)
    if err:
        fails.append('A ROUTINE TRANSITION WAS REFUSED WITH NO APPROVER. This is the corrected '
                     'defect: a reconciler that needs a person to move a DRAFT to OPEN is a '
                     'reconciler nobody will run. Refusal: %s' % err)
    if ticket.state != OPEN:
        fails.append('an unattended routine transition did not take effect')
    if not ticket.history or ticket.history[-1]['actor'] != ROUTINE_ACTOR:
        fails.append('an unattended transition did not record itself as unattended -- a history '
                     'that names a person or "the system" for a mutation nobody approved is how '
                     'an automatic change comes to look signed-for')
    t_un, tk_un = build_ticket(cluster, 'ticket-unattended')
    for state in (IN_PROGRESS, FIXED, VALIDATED, CLOSED):
        err = advance_task(tk_un[0], state, None, evidence=EV)
        if err:
            fails.append('a routine task transition to %s was refused with no approver: %s'
                         % (state, err))
    if tk_un[0].state != CLOSED:
        fails.append('a child finding could not be walked from %s to %s unattended, so no '
                     'evidence-backed progress can be recorded without a person' % (OPEN, CLOSED))

    # 2c. A ROUTINE MUTATION ALSO ACCEPTS AN APPROVAL WITHOUT BREAKING. An operator-driven run
    #     supplies one for the whole run; a routine mutation must not refuse it as surplus.
    t_appr, tk_appr = build_ticket(cluster, 'ticket-appr')
    if advance_ticket(t_appr, OPEN, appr()):
        fails.append('a routine transition refused a supplied approval as surplus')
    if t_appr.history[-1]['actor'] != 'platform-security':
        fails.append('a routine transition with an approval did not credit the approver')

    # 2d. A DISPOSITION IS REFUSED WITHOUT A PERSON -- and for the RIGHT reason.
    t_def, tk_def = build_ticket(cluster, 'ticket-disp')
    advance_task(tk_def[0], IN_PROGRESS, None)
    for label, bad in (('none', None),
                       ('not granted', Approval('platform-security', 'because', granted=False)),
                       ('no actor', Approval('', 'a stated reason for the record')),
                       ('reason too thin', Approval('platform-security', 'ok'))):
        err = advance_task(tk_def[0], DEFERRED, bad,
                           deferred_reason='waiting on an upstream fix',
                           deferred_until='2099-01-01')
        if not err:
            fails.append('a %s DISPOSITION proceeded with an approval that was %s'
                         % (DEFERRED, label))
        elif GOVERNANCE_DISPOSITION not in err:
            fails.append('deferring was refused without naming itself a %s (%r), so a reader '
                          'cannot tell a disposition refusal from a state-machine refusal'
                         % (GOVERNANCE_DISPOSITION, err))
    if tk_def[0].state == DEFERRED:
        fails.append('a refused disposition still mutated the task')

    # 2e. AND WITH A PERSON IT PROCEEDS. Without this, 2d holds against a model that refuses
    #     every disposition, which is the same half-a-control in the other direction.
    if advance_task(tk_def[0], DEFERRED, appr(), deferred_reason='waiting on an upstream fix',
                    deferred_until='2099-01-01'):
        fails.append('a properly approved disposition was refused')
    if tk_def[0].state != DEFERRED:
        fails.append('an approved disposition did not take effect')

    # 2f. VALIDATED IS SOMEBODY ELSE ESTABLISHING THE FIX (G2-6). It is routine BECAUSE it is
    #     evidenced, so the evidence is required -- the same rule as the evidenced closure. Before
    #     this, any caller moved FIXED -> VALIDATED -> CLOSED with nothing in hand, and the
    #     reconciler that recorded FIXED "established" its own claim.
    def _at_fixed(name, approval=None):
        _t, _tk = build_ticket(cluster, name)
        advance_task(_tk[0], IN_PROGRESS, None)
        advance_task(_tk[0], FIXED, approval)
        return _tk[0]

    t_v = _at_fixed('ticket-val-none')
    err = advance_task(t_v, VALIDATED, None)
    if not err:
        fails.append('A TASK WAS VALIDATED WITH NO EVIDENCE. The party that recorded FIXED '
                     'established its own claim -- self-validation, which task_state forbids')
    elif 'validation evidence' not in err:
        fails.append('validating with no evidence was refused for the wrong reason: %r' % err)
    if t_v.state != FIXED:
        fails.append('a refused validation still moved the task to %s' % t_v.state)
    for label, ev in (('names the reconciler as its source', dict(EV, scanner=ROUTINE_ACTOR)),
                      ('says the finding still reproduces', dict(EV, reproduced=True)),
                      ('did not cover the scope', dict(EV, scope_covered=False)),
                      ('names no run', dict(EV, run=''))):
        t_v = _at_fixed('ticket-val-bad')
        try:
            err = advance_task(t_v, VALIDATED, None, evidence=ev)
        except TypeError:
            err = ''
            fails.append('advance_task takes no validation evidence at all, so VALIDATED cannot '
                         'be tied to anything')
            break
        if not err or t_v.state != FIXED:
            fails.append('validation evidence that %s was accepted' % label)
    # The party that claimed FIXED cannot be the source of the evidence that validates it.
    t_v = _at_fixed('ticket-val-same', approval=appr())
    try:
        err = advance_task(t_v, VALIDATED, None, evidence=dict(EV, scanner='platform-security'))
    except TypeError:
        err = ''
    if not err:
        fails.append('the party that recorded FIXED supplied the evidence that VALIDATED it')
    # AND WITH REAL EVIDENCE IT PROCEEDS, unattended. Without this, the refusals above hold
    # against a model that can never validate anything.
    t_v = _at_fixed('ticket-val-ok')
    try:
        err = advance_task(t_v, VALIDATED, None, evidence=EV)
    except TypeError:
        err = 'advance_task takes no validation evidence'
    if err or t_v.state != VALIDATED:
        fails.append('a task with scanner evidence of non-reproduction over a covering scope was '
                     'not validated: %r' % err)
    elif not any(EV['run'] in h.get('reason', '') for h in t_v.history):
        fails.append('the validation did not record the run that established it')

    # ── 3. THE STATE MACHINE REFUSES AN ILLEGAL EDGE. ────────────────────────────
    #
    # With no approval at all, deliberately: an illegal edge must be refused by the state machine
    # rather than by the gate, and supplying an approval here would leave both explanations open.
    if not advance_ticket(ticket, CLOSED, None, tasks=tasks):
        fails.append('a ticket jumped from %s straight to %s' % (OPEN, CLOSED))
    if not advance_task(tasks[0], VALIDATED, None):
        fails.append('a task jumped from %s to %s without being fixed' % (IN_PROGRESS, VALIDATED))

    # ── 4. A PARENT CANNOT CLOSE OVER OPEN CHILDREN. ────────────────────────────
    ok, reasons = evaluate_closure(ticket, tasks)
    if ok:
        fails.append('closure was satisfied with both children %s' % OPEN)
    if len(reasons) != 2:
        fails.append('closure gave %d blocking reason(s) for 2 open children; it must say WHICH '
                     'children hold the parent open' % len(reasons))

    # Walk one child all the way to terminal; the parent still cannot close.
    for state in (IN_PROGRESS, FIXED, VALIDATED, CLOSED):
        err = advance_task(tasks[0], state, appr(), evidence=EV)
        if err:
            fails.append('walking a task to %s was refused: %s' % (state, err))
    ok, reasons = evaluate_closure(ticket, tasks)
    if ok:
        fails.append('a parent closed with one child still open')

    # Now both terminal -> closure is satisfied. The positive control for section 4.
    for state in (IN_PROGRESS, FIXED, VALIDATED, CLOSED):
        advance_task(tasks[1], state, appr(), evidence=EV)
    ok, reasons = evaluate_closure(ticket, tasks)
    if not ok:
        fails.append('closure was NOT satisfied with every child terminal: %r' % reasons)

    # ── 5. A PARENT WITH NO CHILDREN HAS ESTABLISHED NOTHING. ──────────────────
    empty, _ = build_ticket({'cluster_key': 'k', 'subject': 'SOURCE', 'members': [],
                             'scanners': []}, 'ticket-empty')
    ok, reasons = evaluate_closure(empty, [])
    if ok:
        fails.append('a childless parent satisfied its closure rule')

    # ── 6. DISPUTED NEVER COUNTS AS RESOLVED. ─────────────────────────────────
    t2, tk2 = build_ticket(cluster, 'ticket-2')
    advance_task(tk2[0], IN_PROGRESS, appr())
    advance_task(tk2[0], DISPUTED, appr())
    for state in (IN_PROGRESS, FIXED, VALIDATED, CLOSED):
        advance_task(tk2[1], state, appr(), evidence=EV)
    ok, reasons = evaluate_closure(t2, tk2)
    if ok:
        fails.append('a cluster closed over a %s child -- conflicting evidence counted as a '
                     'resolution' % DISPUTED)
    if not any(DISPUTED in r for r in reasons):
        fails.append('the %s child was not named as the blocker' % DISPUTED)

    # ── 7. DEFERRAL DISCIPLINE. ───────────────────────────────────────────────
    t3, tk3 = build_ticket(cluster, 'ticket-3')
    advance_task(tk3[0], IN_PROGRESS, appr())
    # THE REFUSAL MUST BE FOR THE RIGHT REASON. Asserting only "it was refused" is too weak: with
    # both halves missing, removing the reason check still leaves the date check to refuse, so the
    # test passed while the guard it named was gone. A mutation run caught exactly that.
    err = advance_task(tk3[0], DEFERRED, appr())
    if not err:
        fails.append('a task deferred with NO REASON -- that is a permanent silent exception')
    elif 'requires a reason' not in err:
        fails.append('deferring with no reason was refused, but not for the missing reason (%r). '
                     'The reason guard is not what refused it.' % err)
    err = advance_task(tk3[0], DEFERRED, appr(), deferred_reason='waiting on an upstream fix')
    if not err:
        fails.append('a task deferred with a reason but NO END DATE. An absent expiry reads as '
                     'open-ended, which is the hole this kit already shipped once')
    elif 'requires an end date' not in err:
        fails.append('deferring with no end date was refused for the wrong reason: %r' % err)
    err = advance_task(tk3[0], DEFERRED, appr(), deferred_reason='waiting on an upstream fix',
                       deferred_until='2099-01-01')
    if err:
        fails.append('a properly disciplined deferral was refused: %s' % err)
    if tk3[0].state != DEFERRED or not tk3[0].deferred_reason:
        fails.append('the deferral did not record its reason')

    # A deferred child blocks closure, and says until when and why.
    for state in (IN_PROGRESS, FIXED, VALIDATED, CLOSED):
        advance_task(tk3[1], state, appr(), evidence=EV)
    ok, reasons = evaluate_closure(t3, tk3)
    if ok:
        fails.append('a cluster closed over a %s child' % DEFERRED)
    if not any('2099-01-01' in r and 'upstream' in r for r in reasons):
        fails.append('the deferral blocker did not carry its date and reason: %r' % reasons)

    # ── 8. REOPENING IS EXPLICIT, AND THE DATE IS A PRECONDITION NOT A TRIGGER. ──
    #
    # This is the departure from the reference pattern, so it is asserted hardest.
    # THE REFUSAL MUST BE FOR THE RIGHT REASON, and here that is load-bearing in a new way.
    # `task.advance.OPEN` is deliberately absent from MUTATION_CLASS -- the only route into OPEN
    # from DEFERRED is `reopen_deferred` -- so the mutation table ALSO refuses this call. Two
    # independent guards over one property is good engineering and terrible testing: asserting
    # only "it was refused" would pass with the reopen-discipline branch deleted, because the
    # table would refuse in its place. So the branch has to be the thing that answers.
    err = advance_task(tk3[0], OPEN, appr())
    if not err:
        fails.append('a deferred task was reopened through the ordinary transition path, '
                     'bypassing the reopen discipline entirely')
    elif 'reopen_deferred' not in err:
        fails.append('the ordinary path refused a reopen, but NOT with the reopen discipline '
                     '(%r). Something else answered -- so the branch that owns this edge could '
                     'be deleted and this assertion would still pass.' % err)
    # The date HAS passed here, so the trigger guard is the only thing that can refuse -- and the
    # refusal must say so (T4 added a date guard that would otherwise answer in its place).
    err = reopen_deferred(tk3[0], appr(), trigger='', today='2099-06-01')
    if not err:
        fails.append('a deferred task reopened with NO TRIGGER -- the date passing performed the '
                     'reopen by itself, which is silence renewing an obligation')
    elif 'named trigger' not in err:
        fails.append('a reopen with no trigger was refused for the wrong reason: %r' % err)
    if not reopen_deferred(tk3[0], appr(), trigger='upstream released 2.1',
                           today='2026-10-08'):
        fails.append('a task deferred until 2099 was reopened in 2026 without that being its own '
                     'decision')
    # T4 (N40): WITH NO REFERENCE DATE, "the date has passed" is not established, so the reopen
    # refuses -- it used to skip the check and end a 2099 deferral in 2026.
    err = reopen_deferred(tk3[0], appr(), trigger='upstream released 2.1', today=None)
    if not err:
        fails.append('a deferral until 2099 was reopened with NO reference date, so whether it had '
                     'elapsed was never checked (T4)')
    elif 'reference date' not in err:
        fails.append('a reopen with no reference date was refused for the wrong reason: %r' % err)
    if not reopen_deferred(tk3[0], None, trigger='upstream released 2.1', today='2099-06-01'):
        fails.append('a reopen proceeded with no human approval')
    # The positive case: date passed AND a named trigger AND an approval.
    err = reopen_deferred(tk3[0], appr(), trigger='upstream released 2.1', today='2099-06-01')
    if err:
        fails.append('a fully qualified reopen was refused: %s' % err)
    if tk3[0].state != OPEN:
        fails.append('an approved reopen did not take effect')
    if tk3[0].deferred_reason is not None or tk3[0].deferred_until is not None:
        fails.append('a reopened task kept its deferral fields, so it reads as both open and '
                     'deferred')
    if not any('upstream released 2.1' in h.get('reason', '') for h in tk3[0].history):
        fails.append('the reopen did not record its trigger')

    # ── 9. THE TWO CLOSURES ARE TWO DIFFERENT MUTATIONS. ─────────────────────
    #
    # Closure reached BECAUSE every child is evidenced complete is deterministic and unattended.
    # Closure reached by JUDGEMENT is a disposition. Same destination state, different class,
    # and the operator named the distinction explicitly.

    # 9a. THE EVIDENCED CLOSURE RUNS UNATTENDED -- and refuses without the evidence.
    t4, tk4 = build_ticket(cluster, 'ticket-4')
    advance_ticket(t4, OPEN, None)
    advance_ticket(t4, IN_PROGRESS, None)
    for t in tk4:
        for state in (IN_PROGRESS, FIXED, VALIDATED):
            advance_task(t, state, None, evidence=EV)
    # Children terminal, but closing from IN_PROGRESS still skips RESOLVED. The skip guard is
    # the ONLY thing that can refuse here, which is what makes this an assertion about it.
    err = advance_ticket(t4, CLOSED, None, tasks=tk4)
    if not err:
        fails.append('a ticket closed straight from %s, skipping %s, under the ordinary closure '
                     'rule' % (IN_PROGRESS, RESOLVED))
    elif ('skips %s' % RESOLVED) not in err:
        # NOT a substring search for RESOLVED alone: `ALL_CHILDREN_RESOLVED` contains it, so that
        # assertion would be satisfied by the closure-rule refusal and would be testing nothing.
        fails.append('closing from %s was refused for the wrong reason (%r)' % (IN_PROGRESS, err))
    # Through RESOLVED, unattended, then closed -- unattended, because the children carry the
    # evidence. This is the positive control for the evidenced closure.
    if advance_ticket(t4, RESOLVED, None):
        fails.append('a routine advance to %s was refused with no approver' % RESOLVED)
    err = advance_ticket(t4, CLOSED, None, tasks=tk4)
    if err:
        fails.append('AN EVIDENCED CLOSURE WAS REFUSED WITH NO APPROVER. Closure because every '
                     'child is evidenced complete is deterministic, and gating it is the blanket '
                     'gate returning through the closure door. Refusal: %s' % err)
    if t4.state != CLOSED:
        fails.append('an evidenced closure did not take effect')
    # 9b. AND IT REFUSES WITHOUT THE CHILDREN TO READ. Absent evidence must not read as
    #     satisfied -- it is unattended BECAUSE it is evidenced.
    t4b, tk4b = build_ticket(cluster, 'ticket-4b')
    for st in (OPEN, IN_PROGRESS, RESOLVED):
        advance_ticket(t4b, st, None)
    for t in tk4b:
        for state in (IN_PROGRESS, FIXED, VALIDATED):
            advance_task(t, state, None, evidence=EV)
    err = advance_ticket(t4b, CLOSED, None)
    if not err:
        fails.append('an evidenced closure proceeded with NO CHILDREN SUPPLIED. It is unattended '
                     'because it is deterministic from the children; with none to read it is '
                     'closing on an absence')
    elif 'children are required' not in err:
        fails.append('closure with no children was refused for the wrong reason: %r' % err)
    if t4b.state == CLOSED:
        fails.append('a refused closure still closed the ticket')
    # And with one child NOT terminal it refuses too, naming the child.
    t4c, tk4c = build_ticket(cluster, 'ticket-4c')
    for st in (OPEN, IN_PROGRESS, RESOLVED):
        advance_ticket(t4c, st, None)
    for state in (IN_PROGRESS, FIXED, VALIDATED):
        advance_task(tk4c[0], state, None, evidence=EV)
    err = advance_ticket(t4c, CLOSED, None, tasks=tk4c)
    if not err or tk4c[1].task_id not in err:
        fails.append('an unattended closure over an unevidenced child was permitted, or did not '
                     'name the child holding it open: %r' % err)

    # 9c. THE JUDGEMENT CLOSURE IS A DISPOSITION, and needs a rationale as well as a person.
    t5a, tk5a = build_ticket(cluster, 'ticket-5a')
    advance_ticket(t5a, OPEN, None)
    advance_ticket(t5a, IN_PROGRESS, None)
    t5a.closure_rule = AUTHORITY_OVERRIDE
    err = advance_ticket(t5a, CLOSED, None)
    if not err:
        fails.append('AN %s CLOSURE RAN UNATTENDED. Discharging an obligation by decision rather '
                     'than by evidence is exactly the judgement the operator reserved for a '
                     'person' % AUTHORITY_OVERRIDE)
    elif GOVERNANCE_DISPOSITION not in err:
        fails.append('an %s closure was refused without naming itself a %s: %r'
                     % (AUTHORITY_OVERRIDE, GOVERNANCE_DISPOSITION, err))
    if not advance_ticket(t5a, CLOSED, appr()):
        fails.append('an override closure proceeded with no rationale')
    t5a.authority_override_rationale = 'accepted at the architecture board, minuted'
    if advance_ticket(t5a, CLOSED, appr()):
        fails.append('a rationalised, approved override closure was refused')
    if t5a.state != CLOSED:
        fails.append('an approved override closure did not take effect')

    # 9b. An unrecognised closure rule FAILS CLOSED.
    #
    # EVERY CHILD IS DRIVEN TERMINAL FIRST, deliberately. With open children the per-child loop
    # would refuse closure on its own, so the assertion would hold with the closure-rule check
    # removed entirely -- it would be testing the children, not the rule. A mutation run caught
    # that: the rule guard was deleted and this assertion still passed. Terminal children leave
    # the unrecognised rule as the ONLY thing that can refuse.
    t5, tk5 = build_ticket(cluster, 'ticket-5')
    for t in tk5:
        for state in (IN_PROGRESS, FIXED, VALIDATED, CLOSED):
            advance_task(t, state, appr(), evidence=EV)
    t5.closure_rule = 'SOME_FUTURE_RULE'
    ok, reasons = evaluate_closure(t5, tk5)
    if ok:
        fails.append('an unrecognised closure rule was treated as satisfied -- the check must be '
                     'membership of the allowed set, never inequality with one bad value')
    if not any('SOME_FUTURE_RULE' in r for r in reasons):
        fails.append('an unrecognised closure rule was refused without naming itself: %r'
                     % reasons)

    # ── 10. THE COMPLIANCE PAIRING IS A TABLE, AND ITS GAPS ARE A STATE. ────
    mapped = pair_compliance('IAC_PLAN')
    if mapped[0] != FRAMEWORK_GAP_REVIEW:
        fails.append('a mapped subject did not pair: %r' % (mapped,))
    if not mapped[1]:
        fails.append('a pairing carried no reason, so nobody can tell why the review was raised')
    for subject, label in (('SOURCE', 'a deliberately unmapped subject'),
                           ('', 'an unestablished subject'),
                           ('NOT_A_SUBJECT', 'an unrecognised subject')):
        got, why = pair_compliance(subject)
        if got != PAIRING_NOT_ESTABLISHED:
            fails.append('%s returned %r instead of %s' % (label, got, PAIRING_NOT_ESTABLISHED))
        if not why:
            fails.append('%s gave no reason' % label)
    # A secret pairs to nothing, and the reason says rotation.
    got, why = pair_compliance('SOURCE', is_secret=True)
    if got != PAIRING_NOT_ESTABLISHED or 'rotation' not in why:
        fails.append('a secret finding was paired to a compliance review instead of rotation')
    # The table must actually distinguish -- three different review types, not one word applied
    # everywhere. A table whose every row says the same thing is a default in disguise.
    reviews = set(v[0] for v in COMPLIANCE_PAIRING.values()) - {PAIRING_NOT_ESTABLISHED}
    if len(reviews) != 3:
        fails.append('the pairing table yields %d distinct review types; the compliance family '
                     'has three and collapsing them loses the distinction' % len(reviews))
    # Every subject in the identity module's namespace must have a row. A missing row and a
    # deliberate non-pairing look identical from the outside, so the table is required to be
    # exhaustive and to say which it means.
    for subject in ('IMAGE', 'SOURCE', 'SOURCE_DEPENDENCY', 'IAC_PLAN', 'RESOURCE',
                    'IDENTITY_ASSIGNMENT', 'RUNTIME_OBSERVATION', 'POLICY', 'RELEASE'):
        if subject not in COMPLIANCE_PAIRING:
            fails.append('subject %s has no row in the pairing table, so a deliberate '
                         'non-pairing is indistinguishable from an oversight' % subject)

    # ── 11. CONFIDENCE IS A LABEL WITH A DERIVATION, AND NEVER A NUMBER. ───
    lbl, basis = derive_confidence(['trivy', 'grype'], identity_established=True)
    if lbl != CORROBORATED_ANCHORED:
        fails.append('two scanners did not yield %s' % CORROBORATED_ANCHORED)
    if 'trivy' not in basis or 'grype' not in basis:
        fails.append('the derivation does not name the evidence it rests on')
    lbl, _b = derive_confidence(['trivy'], identity_established=True)
    if lbl != SINGLE_SOURCE_ANCHORED:
        fails.append('one scanner did not yield %s' % SINGLE_SOURCE_ANCHORED)
    # Identity not established is NO confidence, not low confidence.
    lbl, basis = derive_confidence(['trivy', 'grype'], identity_established=False)
    if lbl != CONFIDENCE_NOT_ESTABLISHED:
        fails.append('an unestablished identity still produced a confidence label')
    if 'NO confidence' not in basis:
        fails.append('an unestablished identity read as low confidence rather than none')
    # A degraded channel makes the contributor set a FLOOR, so corroboration is not claimable.
    lbl, basis = derive_confidence(['trivy', 'grype'], identity_established=True,
                                   channel_degraded=True)
    if lbl != CONFIDENCE_NOT_ESTABLISHED:
        fails.append('a degraded channel still claimed corroboration from a partial contributor '
                     'set')
    if 'FLOOR' not in basis:
        fails.append('a degraded channel did not say its count was a floor')
    # Every label carries a non-empty derivation. The registry requires it.
    for args in (([], False), (['a'], True), (['a', 'b'], True)):
        _l, b = derive_confidence(args[0], identity_established=args[1])
        if not b or len(b) < 20:
            fails.append('a confidence label carried no usable derivation: %r' % b)
    # And there is no number anywhere in the model's output.
    d = ticket.as_dict()
    if isinstance(d.get('confidence'), (int, float)):
        fails.append('confidence is a number. The registry calls a figure without provenance '
                     '"numerology with an API", and a default one is worse than a label')

    # ── 12. PROGRESS IS RECOMPUTED FROM THE CHILDREN. ─────────────────────
    p = compute_progress(tk3)
    if p['total'] != 2 or p[OPEN] != 1 or p[CLOSED] != 1:
        fails.append('progress disagreed with the children it counted: %r' % p)
    if sum(p[s] for s in (OPEN, IN_PROGRESS, FIXED, VALIDATED, DISPUTED, DEFERRED, CLOSED)) \
            != p['total']:
        fails.append('the per-state counts do not sum to the total, so one state is unaccounted')

    # ── 13. AN ELAPSED DEFERRAL CREATES A REVIEW OBLIGATION. ─────────────────
    #
    # Three facts, and they are separate: the deferral is in term, the deferral has elapsed, or
    # the term cannot be established at all. A caller that cannot tell the third from the first
    # renders an undated suppression as one in good standing, which is the defect this kit
    # already shipped once in its disposition path.
    t6, tk6 = build_ticket(cluster, 'ticket-6')
    advance_task(tk6[0], IN_PROGRESS, None)
    if advance_task(tk6[0], DEFERRED, appr(), deferred_reason='upstream has no patch',
                    deferred_until='2026-06-30'):
        fails.append('a disciplined deferral was refused')
    for state in (FIXED, VALIDATED, CLOSED):
        advance_task(tk6[1], state, None, evidence=EV)

    st, detail = deferral_state('2026-06-30', '2026-06-01')
    if st != DEFERRAL_WITHIN_TERM:
        fails.append('a deferral ending next month read as %s' % st)
    st, detail = deferral_state('2026-06-30', '2026-10-08')
    if st != DEFERRAL_PAST_DUE:
        fails.append('a deferral that ended four months ago read as %s rather than %s'
                     % (st, DEFERRAL_PAST_DUE))
    if 'no longer authorised' not in detail:
        fails.append('a past-due deferral did not say the suppression is no longer authorised, '
                     'so it reads as still in force: %r' % detail)
    # An absent or unparseable term is its OWN state and is never read as in-term.
    for bad_until, label in ((None, 'no end date'), ('', 'an empty end date'),
                             ('soon', 'a non-ISO end date'), ('2026/06/30', 'a slashed date'),
                             # SHAPED LIKE A DATE AND NOT ONE. A shape check passed all three, and
                             # the lexical comparison then sorted letters after digits: TBD0-00-00
                             # read as in term for ever, a permanent silent suppression (G2-6).
                             ('TBD0-00-00', 'a placeholder in date shape'),
                             ('2026-13-45', 'a thirteenth month'),
                             ('2026-02-30', 'the thirtieth of February')):
        st, _d = deferral_state(bad_until, '2026-10-08')
        if st != DEFERRAL_TERM_UNKNOWN:
            fails.append('%s yielded %s rather than %s' % (label, st, DEFERRAL_TERM_UNKNOWN))
    # A garbage REFERENCE date is unknown too: it is the other side of the same comparison.
    st, _d = deferral_state('2026-06-30', 'TBD0-00-00')
    if st != DEFERRAL_TERM_UNKNOWN:
        fails.append('a placeholder reference date yielded %s rather than %s'
                     % (st, DEFERRAL_TERM_UNKNOWN))
    # AND IT IS REFUSED AT ENTRY, for the right reason. A deferral recorded with a date nobody can
    # compare is the undated deferral wearing a date's clothes.
    t_bad, tk_bad = build_ticket(cluster, 'ticket-bad-date')
    advance_task(tk_bad[0], IN_PROGRESS, None)
    err = advance_task(tk_bad[0], DEFERRED, appr(), deferred_reason='waiting on upstream',
                       deferred_until='TBD0-00-00')
    if not err:
        fails.append('a deferral was recorded with end date TBD0-00-00, which no run can compare '
                     'against today')
    elif 'not a real calendar date' not in err:
        fails.append('a placeholder end date was refused for the wrong reason: %r' % err)
    if tk_bad[0].state == DEFERRED:
        fails.append('a refused deferral still mutated the task')
    # No reference date is also unknown -- a run that did not establish today established nothing
    # about whether an acceptance is still in force.
    st, _d = deferral_state('2026-06-30', None)
    if st != DEFERRAL_TERM_UNKNOWN:
        fails.append('a deferral compared against no reference date yielded %s' % st)

    # 13a. IT IS VISIBLE WITHOUT ANYONE ASKING. The sweep over the children reports it, and the
    #      undated case is reported too rather than being the one thing that stays quiet.
    pd = past_due_deferrals(tk6, '2026-10-08')
    if len(pd) != 1 or pd[0]['state'] != DEFERRAL_PAST_DUE:
        fails.append('the past-due sweep did not surface the elapsed deferral: %r' % pd)
    if past_due_deferrals(tk6, '2026-06-01'):
        fails.append('the past-due sweep reported a deferral that is still in term, so the '
                     'signal would be noise and a reader would learn to ignore it')
    tk6[0].deferred_until = None
    if len(past_due_deferrals(tk6, '2026-10-08')) != 1:
        fails.append('a deferral with NO end date was not surfaced as owing a review -- the '
                     'undated case is the original defect and must not be the quiet one')
    tk6[0].deferred_until = '2026-06-30'

    # 13b. IT DOES NOT SILENTLY REOPEN. The task is still DEFERRED after every observation.
    if tk6[0].state != DEFERRED:
        fails.append('observing a past-due deferral changed the task state. Nothing here reopens '
                     'a task as a side effect of looking at it -- that is the reference engine\'s '
                     'defect, where the date passing performed the reopen')

    # 13c. IT DOES NOT SILENTLY KEEP SUPPRESSING EITHER. Closure still refuses, and the blocker
    #      names the past-due state rather than reading like an ordinary deferral.
    ok, reasons = evaluate_closure(t6, tk6, today='2026-10-08')
    if ok:
        fails.append('a cluster closed over a PAST-DUE deferred child')
    if not any(DEFERRAL_PAST_DUE in r for r in reasons):
        fails.append('a past-due deferral was reported as an ordinary deferral in the closure '
                     'blockers, so "deferred until next March" and "deferred until last March" '
                     'read identically: %r' % reasons)
    if not any('a review' in r for r in reasons):
        fails.append('the past-due blocker did not say a person owes a review')

    # 13d. RESOLVING IT TAKES AN AUTHORISED PERSON, and there are exactly two doors.
    if not reopen_deferred(tk6[0], None, trigger='past due', today='2026-10-08'):
        fails.append('a past-due deferral was reopened with NO APPROVER. Past due makes the '
                     'reopen AVAILABLE; it does not perform it')
    if not extend_deferral(tk6[0], None, deferred_reason='upstream still has no patch',
                           deferred_until='2027-06-30', today='2026-10-08'):
        fails.append('a deferral was extended with no approver -- renewal is a fresh decision')
    if not extend_deferral(tk6[0], appr(), deferred_reason='',
                           deferred_until='2027-06-30', today='2026-10-08'):
        fails.append('a deferral was extended with no reason, so the original reason would be '
                     'inherited for another term')
    err = extend_deferral(tk6[0], appr(), deferred_reason='upstream still has no patch',
                          deferred_until='2026-01-01', today='2026-10-08')
    if not err:
        fails.append('a deferral was extended to a date ALREADY PAST, which rewrites the '
                     'past-due state to look resolved without the review happening')
    # The positive control for 13d: an approved extension with a future date proceeds, and the
    # task leaves the past-due set.
    if extend_deferral(tk6[0], appr(), deferred_reason='upstream still has no patch',
                       deferred_until='2027-06-30', today='2026-10-08'):
        fails.append('a properly approved extension was refused, so the only way out of past due '
                     'would be reopening -- and an obligation nobody can renew is one nobody can '
                     'carry honestly')
    if tk6[0].deferred_until != '2027-06-30' or tk6[0].state != DEFERRED:
        fails.append('an approved extension did not take effect')
    if past_due_deferrals(tk6, '2026-10-08'):
        fails.append('a renewed deferral still reported as past due, so the review obligation '
                     'never clears and the signal becomes noise')
    if not any('extended to 2027-06-30' in h.get('reason', '') for h in tk6[0].history):
        fails.append('the extension recorded no history, so a renewal would be invisible')
    # And the reopen door works too, with a person and a trigger.
    if reopen_deferred(tk6[0], appr(), trigger='upstream released 3.0', today='2027-07-01'):
        fails.append('a fully qualified reopen of a past-due deferral was refused')

    for i, f in enumerate(fails, 1):
        print('  %d. %s' % (i, f))
    if fails:
        print('')
        print('SELF-TEST FAILED: %d assertion(s)' % len(fails))
        return 2
    print('self-test ok:')
    print('   1  a cluster yields one parent and one child per member, each with its own state,')
    print('      and the parent is a DRAFT proposal rather than an open obligation')
    print('   2  every mutation is CLASSIFIED explicitly and an unlisted one refuses; routine')
    print('      reconciliation runs UNATTENDED and records itself as unattended; a %s'
          % GOVERNANCE_DISPOSITION)
    print('      is refused without a role and a readable reason, AND proceeds with one -- both')
    print('      sides of both classes, because half a control passes against a model that')
    print('      refuses everything')
    print('   3  an illegal edge is refused in both state machines, with no approval in play')
    print('   4  a parent cannot close over an open child, and names WHICH child holds it open')
    print('   5  a parent with no children has established nothing')
    print('   6  DISPUTED never counts as resolved')
    print('   7  a deferral with no reason, or no end date, is refused')
    print('   8  reopening needs the date passed AND a named trigger AND an approval; the')
    print('      ordinary transition path cannot reach it')
    print('   9  the evidenced closure runs unattended and REFUSES without the children to read;')
    print('      the judgement closure is a disposition needing a role and a rationale; an')
    print('      unknown closure rule fails closed')
    print('  10  compliance pairing is an exhaustive table, distinguishes three review types,')
    print('      returns %s for its gaps, and routes a secret to rotation' % PAIRING_NOT_ESTABLISHED)
    print('  11  confidence is a label carrying its derivation, never a number, and an')
    print('      unestablished identity yields NO confidence rather than low confidence')
    print('  12  progress is recomputed from the children and sums to their total')
    print('  13  an elapsed deferral becomes %s, stays %s, blocks closure by name,'
          % (DEFERRAL_PAST_DUE, DEFERRED))
    print('      appears in the ordinary past-due sweep unasked -- the UNDATED case included --')
    print('      and clears only through an approved reopen or an approved renewal to a FUTURE')
    print('      date; a renewal to a date already past is refused')
    return 0


def main(argv):
    if len(argv) == 2 and argv[1] in ('--self-test', '--selftest'):
        return _selftest()
    if len(argv) == 2 and argv[1] == '--explain-pairing':
        return _explain_pairing()
    if len(argv) == 2 and argv[1] == '--explain-mutations':
        return explain_mutations()
    print('usage: ticket_model.py --self-test | --explain-pairing | --explain-mutations',
          file=sys.stderr)
    print('', file=sys.stderr)
    print('A library. scripts/reconcile_tickets.py drives it; nothing here contacts a tracker.',
          file=sys.stderr)
    return 2


if __name__ == '__main__':
    sys.exit(main(sys.argv))

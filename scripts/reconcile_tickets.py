#!/usr/bin/env python3
"""Reconcile findings to tickets. A LOOKUP ALWAYS PRECEDES A CREATION.

WHY THIS EXISTS

    `docs/architecture/TICKETING_CONTRACT.md` specified this and said, in its own words, that
    nothing in it was built: "Not the ticket classes, not the stamp, not the lookup cascade, not
    the update path, not the budget." A grep of the repository for any ticket-system call -- a REST
    path, JQL, `gh issue create`, a curl to an issue API -- returned nothing. The kit was being
    delivered on the promise that a team could respond to tickets and request exceptions, and
    neither path existed.

    This is the lookup cascade and the creation path. The exceptions path is in
    `scripts/lint_suppressions.py --exceptions`, which already owned "a suppression must say why it
    is safe" and now also owns "an exception must say who owns it and when it expires".

THE DEFECT THIS PREVENTS, NAMED

    Duplicate tickets on every run. A reconciler that creates without looking up produces a fresh
    set of tickets every time the pipeline runs, and the team learns within a fortnight that the
    pipeline is noise. `ENFORCEMENT_TIERS_AND_FINDING_BASELINE.md` section 9.5 states the rule:
    "The ticket carries the cluster key, and the pipeline looks up by cluster key before creating
    anything."

    LOOKUP IS BY DURABLE IDENTITY, NEVER BY MESSAGE TEXT. A scanner's message changes when the
    scanner is upgraded, when a version number in it moves, and when a path is re-rooted. Matching
    on it would make every upgrade look like a new finding -- which is the same defect in a
    different costume.

THE FOUR STATES, WHICH NEVER COLLAPSE

    This file is written against them, because the permissive collapse here is expensive:

        nothing found          the sweep ran, saw the project, and no ticket matched this cluster
                               -> BINDING_ABSENT, and it is THE ONLY state creation may follow
        nothing exists         not representable from a lookup, and deliberately so. A sweep
                               establishes what the channel could see, never what is out there
        nothing was looked at  the lookup did not complete -- rate limit, outage, dead credential
                               -> BINDING_UNESTABLISHED. THE UNCLASSIFIED CASE DEFAULTS HERE
        the control is off     no backend configured -> the run says so and withholds, and this is
                               never rendered as "no tickets were needed"

    And one more that the contract did not anticipate, because it assumed identity worked:

        IDENTITY_NOT_ESTABLISHED   the finding has no durable identity, so there is nothing to look
                               up and nothing may be created. Covered below.

WHY AN EMPTY IDENTITY IS REFUSED RATHER THAN WORKED AROUND

    `scripts/finding_identity.py` is the identity authority and it refuses to fabricate: a record
    it cannot fingerprint comes back UNFINGERPRINTABLE with `identity: None` and a reason, and the
    module's own comment says why -- "No hash. Not a truncated one, not a partial one, not a hash
    of the fields that WERE present. The absence is the signal."

    Identity extraction is currently returning UNFINGERPRINTABLE for findings that should
    fingerprint; another worker owns that defect. A reconciler that ticketed anyway would key those
    tickets on nothing, find nothing on the next run, and create the entire set again -- every run,
    forever. So a finding with no durable identity gets NO TICKET, and the withholding is
    REPORTED as its own state rather than counted as a success or hidden in a zero.

    This is not a workaround for the current defect. It is the correct behaviour permanently: a
    ticket keyed on nothing cannot be found again, so creating one is strictly worse than not.

DRY-RUN IS THE DEFAULT

    Writing to an issue tracker is outward-facing and not undoable -- GitHub has no delete endpoint
    and issue numbers are not reused. So the default prints the plan and touches nothing; `--apply`
    performs it. The contract does not specify a mode split (it has no dry-run design at all), so
    this is an addition and is recorded as one.

WHAT A TICKET IS NOT

    Not a disposition. Not an authorization. Having a ticket does not soften a gate, and closing a
    ticket does not clear a finding. A disposition lives on the protected default branch under
    CODEOWNERS and is the only thing that changes enforcement. This program never writes one.

ROUTINE RECONCILIATION RUNS UNATTENDED. APPROVAL IS FOR DISPOSITIONS.

    The first draft of this file demanded a human approval before it would create ANY ticket. It
    had imported a blanket invariant from the engine the work-item model came from -- "every
    creation, closure, transition, split, reopen, suppression and validation requires explicit
    human approval" -- and that was a real defect, in the expensive direction. A reconciler that
    needs somebody to sign for every create will be run once and then switched off, and the
    entire reason this path is deterministic is so that it can run unattended and be defended
    afterwards from its own record.

    So creating, updating, linking and re-syncing tickets happen with `--apply` and NO approver.
    `--apply` is still a gate: it is the operator or the policy that scheduled the run intending
    writes rather than a plan.

    What needs a person is a DISPOSITION -- an exception, an exclusion, a false-positive call, a
    risk acceptance, a compensating control accepted instead of a fix, a closure reached by
    judgement rather than by evidence, anything committing budget, anything moving the security
    or governance posture of the environment. A finding carrying `requested_disposition` is
    refused without a role and a reason, and the refusal is reported as its OWN outcome.

    `ticket_model.classify_mutation` states the class of every mutation, row by row, with
    reasoning for each. `ticket_model.authorise` is the single enforcement point. A mutation that
    is not in the table REFUSES rather than defaulting either way.
        python3 scripts/reconcile_tickets.py --explain-mutations

AN ELAPSED DEFERRAL IS A REVIEW OBLIGATION, REPORTED UNASKED

    A deferral recorded in the ledger whose end date has passed becomes DEFERRAL_PAST_DUE. It
    appears in every ordinary run's summary with no flag enabling it, it makes the run exit 1, and
    it clears only through `--resolve-deferral` -- which ends the acceptance or renews it to a
    future date, and is a disposition either way. Nothing reopens by itself, and nothing goes on
    quietly suppressing.

USAGE
    python3 scripts/reconcile_tickets.py --findings <records.json>              plan only
    python3 scripts/reconcile_tickets.py --findings <records.json> --apply      perform it
    python3 scripts/reconcile_tickets.py --explain-mutations                    the class table
    python3 scripts/reconcile_tickets.py --ledger <l.json> --today 2026-10-08 \
        --resolve-deferral <task-id> --resolution extend --until 2027-01-31 \
        --deferral-reason '<why>' --approved-by <role> --approval-reason '<why>'
    python3 scripts/reconcile_tickets.py --self-test

ENVIRONMENT (read, never written, never logged)
    TICKET_BACKEND      `github` or `jira`. Absent means the control is off.
    TICKET_STAMP_LABEL  the umbrella stamp. Provisioned once by a human.
    GH_TOKEN            GitHub: credential. Also accepted as GITHUB_TOKEN.
    TICKET_REPO         GitHub: `owner/repo`, one repository, not an organisation.
    JIRA_HOST           Jira: `https://<site>.atlassian.net`
    JIRA_EMAIL          Jira: basic auth is email:token; the token alone is a 401.
    JIRA_TOKEN          Jira: credential.
    JIRA_PROJECT        Jira: project key.
    JIRA_STAMP_FIELD    Jira: `customfield_<id>` holding the cluster stamp. Per-site.

EXIT
    0  the run completed and reported what it did
    1  a decision is owed to a person: an ambiguity, a dangling reference, a disposition nobody
       approved, or a deferral whose term has run out
    2  self-test failed, or the invocation was misuse
    3  the ticketing claim is EVIDENCE_UNTRUSTED: the control is off or misconfigured, two
       backends are configured, a lookup did not complete, or every finding was withheld. The
       obligations are carried with their cause. Outranks 1.
"""
import argparse
import base64
import datetime
import email.utils
import hashlib
import io
import json
import os
import random
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, HERE)

# The parent/child work-item model, the deferral discipline, the compliance pairing table and the
# deterministic confidence labels. Carried from a prior engagement's ticket engine and re-expressed
# there; this file is the orchestrator and that one is the model.
import ticket_model as tm  # noqa: E402 - after the sys.path insert that makes it importable

# ── THE LOOKUP OUTCOMES (assurance-taxonomy.yaml : ticket_lookup_outcome) ─────────────
#
# Six outcomes and never a boolean. "A ticket was not found" is three different facts -- the sweep
# saw the project and nothing matched, the sweep never ran, or a reference existed and did not
# resolve -- and only the first of them may be followed by a creation.
LEDGER_BOUND = 'LEDGER_BOUND'
BACKEND_BOUND = 'BACKEND_BOUND'
BINDING_ABSENT = 'BINDING_ABSENT'
BINDING_AMBIGUOUS = 'BINDING_AMBIGUOUS'
BINDING_DANGLING = 'BINDING_DANGLING'
BINDING_UNESTABLISHED = 'BINDING_UNESTABLISHED'
# The finding never reached a lookup, because it has no durable identity to look up.
IDENTITY_NOT_ESTABLISHED = 'IDENTITY_NOT_ESTABLISHED'

# THE UNCLASSIFIED CASE DEFAULTS HERE. Named as a constant rather than written inline at each
# fallback, so that a future branch which forgets to classify its outcome still cannot land on the
# permissive one. `BINDING_ABSENT` is reachable from exactly one place in this file.
UNCLASSIFIED_DEFAULT = BINDING_UNESTABLISHED

# ── WHAT A TICKET IS FOR (assurance-taxonomy.yaml : ticket_class) ────────────────────
#
# A CLASS NEVER SUPPRESSES ANYTHING. The class says what is being asked for; the disposition says
# what was granted; and they are different objects in different places.
REMEDIATION_WORK_ITEM = 'REMEDIATION_WORK_ITEM'
FALSE_POSITIVE_REQUEST = 'FALSE_POSITIVE_REQUEST'
ACCEPTED_RISK_REQUEST = 'ACCEPTED_RISK_REQUEST'
MITIGATED_REQUEST = 'MITIGATED_REQUEST'
GRANDFATHER_TRACK_ITEM = 'GRANDFATHER_TRACK_ITEM'

# A finding observed by a scanner, with nobody asking for anything, is work. It is the only class
# this program opens UNATTENDED: the other four are REQUESTS, and a request is a disposition
# judgement -- so opening one is gated on a person, by the mutation-class table in
# `ticket_model`.
DEFAULT_CLASS = REMEDIATION_WORK_ITEM

# ── WHAT A FINDING MAY ASK FOR, AND WHICH MUTATION THAT IS ───────────────────────────
#
# A normalised finding record may carry `requested_disposition`. That field is written by a person
# filing a request -- it is never derived from a scanner -- and it moves this cluster out of
# REMEDIATION_WORK_ITEM and into one of the four request classes.
#
# OPENING A REQUEST-CLASS TICKET IS A DISPOSITION ACT, not bookkeeping. The class is what the
# governance stream reads: an ACCEPTED_RISK_REQUEST appearing in the tracker asserts that the
# organisation is being asked to carry something unremediated, and an automated run that could
# raise one would be manufacturing requests nobody made. So each maps to a mutation name in
# the mutation-class table in `ticket_model`, every one of them a GOVERNANCE_DISPOSITION, and an unapproved
# one is REFUSED and reported as its own outcome.
#
# Keys are the lower-case words a request carries. An UNRECOGNISED word maps to nothing, so
# `ticket_model.classify_mutation` returns MUTATION_CLASS_NOT_STATED and the mutation refuses --
# which is the behaviour wanted. A request this program did not understand must not be silently
# downgraded to ordinary remediation work: that would turn "we are asking you to accept this
# risk" into "somebody please fix this", and the asking would disappear.
DISPOSITION_REQUESTS = {
    'exception': ('disposition.exception', FALSE_POSITIVE_REQUEST),
    'exclusion': ('disposition.exclusion', GRANDFATHER_TRACK_ITEM),
    'false_positive': ('disposition.false_positive', FALSE_POSITIVE_REQUEST),
    'risk_acceptance': ('disposition.risk_acceptance', ACCEPTED_RISK_REQUEST),
    'mitigation': ('disposition.mitigation_accepted', MITIGATED_REQUEST),
    'budget': ('disposition.budget_commitment', REMEDIATION_WORK_ITEM),
    'posture': ('disposition.posture_change', REMEDIATION_WORK_ITEM),
}


def _requested(members):
    """-> sorted list of the disposition words the members carry. Verbatim, never normalised.

    Nothing here maps a near-miss onto a known word. `risk-accepted` is not `risk_acceptance`,
    and silently treating it as one would be the near-miss defect `reconcile_taxonomy.py` calls
    worse than a wild value: it would make an unrecognised request act like a recognised one.
    """
    out = set()
    for m in members:
        word = str(m.get('requested_disposition') or '').strip()
        if word:
            out.add(word)
    return sorted(out)

# ── OBSERVATION QUALITY, reused rather than respelled ─────────────────────────────────
VERIFIED_ABSENT = 'VERIFIED_ABSENT'
DISTINCTION_OBSERVABLE = 'DISTINCTION_OBSERVABLE'
DISTINCTION_NOT_OBSERVABLE = 'DISTINCTION_NOT_OBSERVABLE'
PUBLICATION_DEGRADED = 'PUBLICATION_DEGRADED'
EVIDENCE_UNTRUSTED = 'EVIDENCE_UNTRUSTED'
DECISION_REQUIRED = 'DECISION_REQUIRED'

# Correlation tiers. Deliberately lower-case: `ENFORCEMENT_TIERS_AND_FINDING_BASELINE.md` section
# 9.4 writes them this way, and minting three new upper-case state words for a distinction that
# document already names in prose would be the vocabulary inflation `reconcile_taxonomy.py` exists
# to catch. Only `anchored` acts.
TIER_ANCHORED = 'anchored'
TIER_PROPOSED = 'proposed'
TIER_SINGLETON = 'singleton'

# The delimiters of the machine-owned region of a ticket body. Automation writes BETWEEN these and
# nowhere else. A ticket whose delimiters are missing is reported and re-appended to, never
# rewritten from scratch -- somebody's triage notes are outside the block and are not ours.
BLOCK_OPEN = '<!-- secure-cicd-kit: machine-owned block. Edits inside are overwritten. -->'
BLOCK_CLOSE = '<!-- secure-cicd-kit: end machine-owned block. Write below this line. -->'


# ═════════════════════════════════════════════════════════════════════════════════════
# CLUSTERING
# ═════════════════════════════════════════════════════════════════════════════════════
#
# ONE CLUSTER IS ONE OBLIGATION IS AT MOST ONE TICKET. `tests/check_stage_phase.py` declares the
# boundary this owns: "no ticket may be created from an unanchored cluster".
#
# There was no machine-readable correlation artifact to consume. `scripts/scan_report.py` computes
# cross-scanner agreement as `seen[(uri, rule)]` and renders it as one sentence of Markdown into
# the step summary; it is never serialised, and `(uri, rule)` is a HEURISTIC rather than an anchor
# -- section 9.4 calls that tier `proposed` and says explicitly that it is "not applied to
# enforcement. A human confirms or splits."
#
# So this clusters on the identity module's output rather than re-deriving identity, and it
# clusters only on an ANCHORED match:
#
#   * identical durable identity -- the same finding seen twice. Anchored by construction.
#   * intersecting external-alias sets with the same subject and the same locus. Section 9.4's
#     "shared external identifier plus matching package coordinates", and `identify()` returns
#     `what_aliases` as a SET precisely because "matching on an alias set intersection is better
#     than matching on an id".
#
# It will NOT cluster on `(uri, rule)`, on message text, or on CWE agreement. Those are the
# `proposed` tier, and a proposed cluster gets no ticket here.


def _cluster_key(subject, locus, anchor):
    """The stamp. Derived from the cluster's SUBJECT, LOCUS and ANCHOR, never from its membership.

    This matters more than it looks. If the key were a hash of the member set, adding a member
    would change the key, the next run would find nothing under the new key, and it would create a
    second ticket for an obligation that already had one -- the duplicate defect arriving through
    the back door. Members added is an UPDATE to an existing ticket (contract section 5.1), so the
    key has to be stable across membership change.

    THE LOCUS IS IN THE KEY (T1). Clustering already buckets by (subject, locus) -- "the locus is
    part of the anchor" -- and the key did not carry it. One advisory in two manifests made two
    clusters under ONE stamp: the first got the ticket, the second read as a dangling reference
    to it, and one ticket stood for two obligations with two fixes.
    """
    h = hashlib.sha256()
    h.update(('CLUSTER/%s/%s/%s' % (subject or '', locus or '', anchor or '')).encode('utf-8'))
    return h.hexdigest()[:32]


def _aliases(rec):
    vals = rec.get('what_aliases') or []
    if isinstance(vals, str):
        vals = [vals]
    return frozenset(str(v).strip().lower() for v in vals if str(v).strip())


class ClusterList(list):
    """The acting clusters, carrying the PROPOSALS correlation recorded beside them (a chain, or
    CWE-plus-path agreement). Proposals change no count and get no ticket; they are reported."""
    proposals = ()


def build_clusters(records):
    """-> (clusters, withheld).

    `clusters` is a list of dicts: cluster_key, subject, anchor, tier, members, scanners.
    `withheld` is a list of (record, outcome, reason) -- findings that get no ticket and WHY.

    A withheld finding is never silently dropped. It is returned, counted separately, and printed.
    """
    withheld, fingerprinted = [], []

    for i, rec in enumerate(records, 1):
        state = (rec.get('identity_state') or '').strip()
        ident = (rec.get('identity') or '').strip()
        # AN EMPTY IDENTITY IS THE REFUSAL, WHATEVER THE STATE FIELD SAYS. Checking both is
        # deliberate: a record could carry state FINGERPRINTED and an empty identity if an upstream
        # stage dropped the field, and trusting the label over the value is how an inference
        # overwrites an observation.
        if not ident or state != 'FINGERPRINTED':
            withheld.append((rec, IDENTITY_NOT_ESTABLISHED,
                             rec.get('identity_reason') or state or 'no identity on the record'))
        else:
            fingerprinted.append(rec)
        # Heartbeat, per iteration. A long record set that dies halfway must not look like a short
        # one that completed.
        if i % 200 == 0 or i == len(records):
            print('  ... examined %d/%d record(s)' % (i, len(records)), file=sys.stderr)

    # ONE ANCHORING RULE FOR THE KIT: scripts/finding_correlation.py (ETFB 9.1-9.4, L48). It clusters
    # identical identities, and alias sets only where an identifier is COMMON TO EVERY MEMBER within
    # one subject and one locus. An alias CHAIN -- A{x,y}, B{y,z}, C{z} -- is a PROPOSAL: each member
    # acts on its own and a human confirms or splits. This file used to union alias intersections
    # transitively, so a chain became one cluster and one ticket carried findings that share no
    # identifier (found and run-confirmed by the identity lane).
    import finding_correlation as fc
    views = []
    for rec in fingerprinted:
        # The locus is WHERE, falling back to the uri, so a record without `where` still buckets.
        views.append(dict(rec, where=rec.get('where') or rec.get('uri') or '',
                          finding_subject=rec.get('finding_subject') or ''))
    corr = fc.correlate(views)
    print('  ... correlated %d record(s): %d acting cluster(s), %d proposal(s)'
          % (len(views), corr['summary']['acting_clusters'], corr['summary']['proposals']),
          file=sys.stderr)

    clusters = ClusterList()
    clusters.proposals = [dict(p, member_identities=p.get('member_identities') or sorted(set(
        views[i]['identity'] for i in p.get('members') or []))) for p in corr['proposals']]
    acting = corr['clusters']
    for n, cl in enumerate(acting, 1):
        members = [fingerprinted[i] for i in cl['members']]
        rec0 = members[0]
        subject = rec0.get('finding_subject') or ''
        # The anchor: the identifier common to every member, else the identity itself. Both are
        # anchored; neither is a heuristic.
        anchor = str(cl.get('anchor') or rec0['identity']).lower()
        scanners = sorted(set(str(m.get('scanner') or '') for m in members))
        clusters.append({
            # Every member shares this locus: correlation buckets by (subject, locus).
            'cluster_key': _cluster_key(subject, rec0.get('where') or rec0.get('uri') or '',
                                        anchor),
            'subject': subject,
            'anchor': anchor,
            'tier': TIER_ANCHORED if cl['tier'] == fc.ANCHORED else TIER_SINGLETON,
            'members': members,
            'member_identities': sorted(set(m['identity'] for m in members)),
            'scanners': scanners,
            'severity': _worst(members),
            # What a PERSON has asked for on these findings, if anything. Carried through to
            # `reconcile`, which gates it as a disposition.
            'requested_dispositions': _requested(members),
        })
        print('  ... built cluster %d/%d (%d member(s), %d scanner(s))'
              % (n, len(acting), len(members), len(scanners)), file=sys.stderr)

    return clusters, withheld


_SEV_ORDER = ('critical', 'high', 'medium', 'moderate', 'low', 'info', 'note', 'none', '')


def _worst(members):
    """The cluster's effective severity. Scanner disagreement is NOT averaged -- the contract's
    section 5.1 forbids it -- so this takes the worst and the caller keeps the per-scanner values."""
    best = len(_SEV_ORDER) - 1
    for m in members:
        s = str(m.get('severity') or '').strip().lower()
        if s in _SEV_ORDER:
            best = min(best, _SEV_ORDER.index(s))
    return _SEV_ORDER[best] or 'none'


# ═════════════════════════════════════════════════════════════════════════════════════
# BACKENDS
# ═════════════════════════════════════════════════════════════════════════════════════
#
# One interface, three implementations. The cascade below is written against the interface and has
# no backend-specific branch in it, which is what makes the fake backend in the self-test a real
# test of the cascade rather than a test of a mock.
#
# EXACTLY ONE BACKEND IS AUTHORITATIVE. Two configured at once is a configuration defect and is
# refused by name -- not "create in both", not "prefer whichever is listed first".


class TicketBackend(object):
    """The interface. Five operations, and `sweep` is the one the cascade depends on."""

    name = 'abstract'

    def probe(self):
        """-> (observable, detail). Can this credential see a ticket it did not create?

        THE CALIBRATION PROBE. Until this answers yes, a not-found response is ambiguous between
        "deleted" and "invisible to me", and the contract requires that no not-found may license a
        creation in a run where this failed. One call per run, at most.
        """
        raise NotImplementedError

    def sweep(self, known_refs=()):
        """-> (stamp -> [ref], complete, detail). One paginated read of everything carrying the
        umbrella stamp. `complete` False means the map is PARTIAL and every count off it is a
        FLOOR, never a total."""
        raise NotImplementedError

    def resolve(self, ref):
        """-> (record or None, resolved, detail). `resolved` False is an unresolved reference and
        is NOT an absence."""
        raise NotImplementedError

    def create(self, cluster, body, title):
        """-> (ref, detail). Called from exactly one place, behind --apply."""
        raise NotImplementedError

    def comment(self, ref, text):
        """-> (ok, detail). The update path. Never touches anything outside the block."""
        raise NotImplementedError

    # ── THE BLOCK UPDATE: READ IN FULL, REPLACE THE BLOCK, WRITE BACK EVERYTHING ELSE (T-02). ──
    #
    # A ticket's description belongs to people everywhere outside the delimiters (TC 5.4, 5.2).
    # The sweep is deliberately cheap and, on Jira and Azure DevOps, returns NO body -- and the
    # members-added update used to render the block against that empty body, so the write replaced
    # the whole description with the kit's block and erased every sentence a person had written
    # (completion ledger row T-02). So the update path is three steps and never one:
    #
    #   read_description   the CURRENT description, in full, in the backend's native form
    #                      (Jira: an ADF document; Azure DevOps: HTML; GitHub: Markdown text)
    #   splice_description replace the delimited block and NOTHING else; every other node or
    #                      byte is carried through exactly as read. Missing delimiters re-append
    #   write_description  write that back
    #
    # A description that could not be read is NOT written. Writing anyway is a blind overwrite of
    # whatever is there; the obligation is carried as BINDING_UNESTABLISHED instead (TC 4.1).

    def read_description(self, ref):
        """-> (description, ok, detail). `ok` False means NOTHING may be written to this ticket's
        description this run -- the read is the precondition of the write, never optional."""
        raise NotImplementedError

    def description_text(self, description):
        """The description as plain lines, for reading the block back (member identities)."""
        return str(description or '')

    def splice_description(self, description, block):
        """-> (new description, delimiters_found). Only the machine-owned block changes."""
        return splice_text(self.description_text(description), block)

    def write_description(self, ref, new_description, read):
        """-> (ok, detail). `read` is what read_description returned, for a backend that can make
        the write conditional on nothing having changed since (Azure DevOps `test /rev`)."""
        raise NotImplementedError

    def reopen(self, ref):
        """-> (ok, why_not). Reopen a closed ticket. A refusal is not "impossible": the caller
        takes the successor path and records `why_not` (TC 4.2)."""
        raise NotImplementedError

    # TC 6.5: the per-run creation ceiling, from TICKET_CREATE_CEILING. None = not configured
    # (only the in-memory and GitHub backends; Jira and Azure DevOps refuse to start without it).
    create_ceiling = None

    # Per-class ceiling on tier -1 instances (TICKETING_BACKENDS.md 2; J-8). Owner-set
    # (TICKET_INSTANCE_THRESHOLD); ZERO when unset, so no number is invented in code and the
    # class carries a count instead.
    instance_threshold = 0

    # Consecutive degraded runs after which a carried obligation is escalated to a person (TC 4.1;
    # T-06). Owner-set (TICKET_DEGRADED_RUN_THRESHOLD); ZERO when unset -- attempts are still
    # counted and recorded, and no number is invented in code.
    degraded_threshold = 0

    def create_instance(self, parent_ref, member, body, title):
        """-> (ref, detail). A tier -1 item under the tier-0 item. It carries NO stamp: instances
        are found through their parent, never by a sweep of their own."""
        return None, '%s does not itemise instances' % self.name


# Replaced by the proofs so a Retry-After of minutes is observed without being slept.
_sleep = time.sleep
THROTTLE_STATUSES = (429, 503)


def parse_retry_after(value, now=None):
    """-> seconds to wait, or None when absent or unreadable. Both documented forms: an integer
    number of seconds, or an HTTP-date (RFC 9110). A date in the past is a wait of 0."""
    v = str(value or '').strip()
    if not v:
        return None
    if v.isdigit():
        return int(v)
    try:
        when = email.utils.parsedate_to_datetime(v)
    except (TypeError, ValueError, IndexError):
        return None
    if when is None:
        return None
    if when.tzinfo is None:
        when = when.replace(tzinfo=datetime.timezone.utc)
    now = now or datetime.datetime.now(datetime.timezone.utc)
    return max(0, int((when - now).total_seconds()))


def first_read_refusal(status, host_var, cred_var, project_var, project):
    """The first read of a run says WHICH value is wrong, by name (TICKETING_BACKENDS.md R-1):
    no answer at all is the host, 401/403 the credential, 404 the project. Anything else is named
    as unestablished rather than guessed."""
    if status is None:
        return '%s could not be reached (no HTTP answer); nothing was established' % host_var
    if status in (401, 403):
        return '%s was refused (HTTP %s); the credential is wrong, expired or lacks access' % (
            cred_var, status)
    if status == 404:
        return '%s %s was not found (HTTP 404) by this credential' % (project_var, project)
    return '%s %s could not be read (HTTP %s)' % (project_var, project, status)


class HttpBackend(TicketBackend):
    """The request path every real backend shares: JSON in and out, the call count, and the
    THROTTLE RULE (TICKETING_BACKENDS.md 3.3, 4.2; J-4).

    On 429 or 503 it waits for `Retry-After` (seconds or HTTP-date); with no header, a bounded
    exponential backoff with jitter. At most `retry_ceiling` retries per request, configured by
    the owner (TICKET_RETRY_CEILING) and ZERO when unset -- the first throttle then ends the
    request, because a retry budget nobody chose is a number in code (TC 11.4). Exhausting it
    returns an error, which the callers read as BINDING_UNESTABLISHED: never a create. Every
    throttle seen is recorded for the run report, so the budget is a measurement.
    """

    retry_ceiling = 0

    def _init_http(self, retry_ceiling=0):
        self.calls = 0
        self.throttles = []
        self.retry_ceiling = int(retry_ceiling or 0)

    def _headers(self):
        raise NotImplementedError

    def _http(self, method, url, payload=None, content_type='application/json'):
        """-> (doc, status, err). `doc` is None for an empty body (204); `err` None on 2xx."""
        import urllib.error
        import urllib.request
        data = json.dumps(payload).encode('utf-8') if payload is not None else None
        attempt = 0
        while True:
            r = urllib.request.Request(url, data=data, method=method)
            for k, v in self._headers():
                r.add_header(k, v)
            r.add_header('User-Agent', 'secure-cicd-kit')
            if data is not None:
                r.add_header('Content-Type', content_type)
            self.calls += 1
            try:
                with urllib.request.urlopen(r, timeout=30) as resp:
                    raw = resp.read().decode('utf-8')
                    self._observe_rate(getattr(resp, 'headers', None))
                    return (json.loads(raw) if raw.strip() else None), resp.status, None
            except urllib.error.HTTPError as exc:
                hdrs = exc.headers or {}
                if exc.code in THROTTLE_STATUSES:
                    ra = parse_retry_after(hdrs.get('Retry-After'))
                    self.throttles.append({'status': exc.code, 'method': method,
                                           'retry_after': ra, 'attempt': attempt + 1})
                    if attempt < self.retry_ceiling:
                        _sleep(ra if ra is not None else (2 ** attempt) + random.uniform(0.1, 1))
                        attempt += 1
                        continue
                    return None, exc.code, _no_credential_in(
                        'HTTP %s; retry ceiling %d reached' % (exc.code, self.retry_ceiling))
                return None, exc.code, _no_credential_in('HTTP %s' % exc.code)
            except Exception as exc:                  # noqa: BLE001 - reported, never swallowed
                return None, None, _no_credential_in('%s: %s' % (type(exc).__name__, exc))

    def _observe_rate(self, headers):
        """Hook for a backend that slows down before it is delayed (Azure DevOps)."""
        return None


def _no_credential_in(detail):
    """Credentials never reach a log, an exception message or a summary. This is belt and braces
    over the rule that nothing reads a token into a message in the first place: a backend's own
    error strings can quote a request, and a request carries an Authorization header."""
    lowered = str(detail).lower()
    for marker in ('authorization', 'bearer ', 'basic ', 'token ', 'password'):
        if marker in lowered:
            return 'detail withheld: it contained something credential-shaped'
    return detail


class GitHubIssues(HttpBackend):
    """GitHub Issues.

    Exercisable against a PERSONAL account: a classic or fine-grained PAT with issues:write on one
    personal repository is enough, and `TICKET_REPO` names that repository. No organisation, no app
    identity, and the sweep filters on the umbrella label only -- `GET /search/issues` is not used,
    because a text index is not an identity lookup and its default behaviour changed under us once.
    """

    name = 'github'

    def __init__(self, repo, token, stamp_label, calibration='', retry_ceiling=0):
        self.repo = repo
        self._token = token            # read once, never printed, never written anywhere
        self.stamp_label = stamp_label
        # A known-present issue this credential did NOT create, provisioned once by a human.
        self.calibration = (calibration or '').strip()
        self._init_http(retry_ceiling)

    def _headers(self):
        return [('Accept', 'application/vnd.github+json'),
                ('X-GitHub-Api-Version', '2022-11-28'),
                ('Authorization', 'Bearer %s' % self._token)]

    def _req(self, method, path, payload=None):
        return self._http(method, 'https://api.github.com' + path, payload)

    def probe(self):
        # Reading the repository proves REACH, not visibility of tickets this credential did not
        # create (L54). The calibration probe (TC 4.5) resolves a KNOWN-PRESENT, FOREIGN issue:
        # it must resolve, and it must not carry the umbrella label -- a stamped issue may be one
        # this kit created, which proves nothing about foreign visibility.
        doc, status, err = self._req('GET', '/repos/%s' % self.repo)
        if err or not doc:
            return False, 'could not read %s (status %s)' % (self.repo, status)
        if not doc.get('has_issues', True):
            return False, 'issues are disabled on %s, so no ticket can exist here' % self.repo
        if not self.calibration:
            return False, ('no calibration issue configured (TICKET_CALIBRATION_REF), so a '
                           'not-found cannot be told from an issue this credential cannot see')
        cal, status, err = self._req('GET', '/repos/%s/issues/%s' % (self.repo, self.calibration))
        if err or not cal:
            return False, ('the calibration issue did not resolve (status %s): the channel is '
                           'not shown able to see a foreign ticket' % status)
        labels = [(lb.get('name') if isinstance(lb, dict) else lb) for lb in cal.get('labels') or []]
        if self.stamp_label in labels:
            return False, ('the calibration issue carries the umbrella label, so it may be one '
                           'this kit created; it cannot calibrate foreign visibility')
        return True, 'calibration probe resolved a known-present foreign issue'

    def sweep(self, known_refs=()):
        out, page, complete = {}, 1, True
        while True:
            doc, status, err = self._req(
                'GET', '/repos/%s/issues?labels=%s&state=all&per_page=100&page=%d'
                % (self.repo, self.stamp_label, page))
            if err or doc is None:
                # PARTIAL. The map so far is a FLOOR and the caller must not treat a miss in it as
                # an absence.
                return out, False, 'sweep stopped at page %d (status %s)' % (page, status)
            for issue in doc:
                stamp = stamp_from_body(issue.get('body') or '')
                if stamp:
                    out.setdefault(stamp, []).append({
                        'ref': str(issue.get('number')),
                        'url': issue.get('url') or '',
                        'node': issue.get('node_id') or '',
                        'state': issue.get('state') or '',
                        'body': issue.get('body') or '',
                    })
            print('  ... swept page %d (%d issue(s))' % (page, len(doc)), file=sys.stderr)
            if len(doc) < 100:
                break
            page += 1
            if page > 100:
                complete = False
                break
        return out, complete, 'swept %d page(s)' % page

    def resolve(self, ref):
        doc, status, err = self._req('GET', '/repos/%s/issues/%s' % (self.repo, ref))
        if doc:
            return doc, True, 'resolved'
        return None, False, 'did not resolve (status %s)' % status

    def create(self, cluster, body, title):
        # Labels go in the CREATE call, not a second request: it halves the cost against GitHub's
        # content-generating limit, which is the binding one (500/hour) rather than the 1,000/hour
        # primary limit everybody quotes.
        doc, status, err = self._req('POST', '/repos/%s/issues' % self.repo,
                                     {'title': title, 'body': body,
                                      'labels': [self.stamp_label]})
        if err or not doc:
            return None, 'create failed (status %s)' % status
        return str(doc.get('number')), 'created issue %s' % doc.get('number')

    def comment(self, ref, text):
        doc, status, err = self._req('POST', '/repos/%s/issues/%s/comments' % (self.repo, ref),
                                     {'body': text})
        return (doc is not None), 'comment status %s' % status

    def read_description(self, ref):
        doc, status, err = self._req('GET', '/repos/%s/issues/%s' % (self.repo, ref))
        if err or not isinstance(doc, dict):
            return None, False, 'the issue body could not be read (status %s)' % status
        return doc.get('body') or '', True, 'read'

    def write_description(self, ref, new_description, read):
        doc, status, err = self._req('PATCH', '/repos/%s/issues/%s' % (self.repo, ref),
                                     {'body': new_description})
        return (doc is not None), 'body update status %s' % status

    def reopen(self, ref):
        doc, status, err = self._req('PATCH', '/repos/%s/issues/%s' % (self.repo, ref),
                                     {'state': 'open', 'state_reason': 'reopened'})
        if err or doc is None:
            return False, 'reopen refused (status %s)' % status
        return True, 'reopened'


DEFAULT_STAMP_LABEL = 'secure-cicd-kit'


# The rollup family label (WORK_ITEM_HIERARCHY.md moved the rollup to a label), keyed on the
# registered finding_subject. A subject with no row gets NO family label rather than a guess.
FAMILY_BY_SUBJECT = {'SOURCE_DEPENDENCY': 'sca', 'DEPENDENCY': 'sca', 'SOURCE': 'sast',
                     'IAC_PLAN': 'iac', 'RESOURCE': 'iac', 'POLICY': 'iac', 'IMAGE': 'container'}


def family_of(cluster):
    """-> 'secrets' | 'sca' | 'sast' | 'iac' | 'container' | ''."""
    if any(str(m.get('is_secret_finding', '')).strip().lower() in ('1', 'true', 'yes')
           for m in cluster.get('members') or []):
        return 'secrets'
    return FAMILY_BY_SUBJECT.get(cluster.get('subject') or '', '')


def adf_from_text(text):
    """Plain text as an Atlassian Document Format document: one paragraph per line, each line a
    single TEXT node. Finding text therefore reaches Jira as data -- markup, backticks and `$(...)`
    stay characters (TC 7.4) -- and a blank line is an empty paragraph, because ADF refuses an
    empty text node."""
    content = []
    for line in str(text or '').split('\n'):
        line = line.rstrip('\r')
        content.append({'type': 'paragraph',
                        'content': [{'type': 'text', 'text': line}] if line else []})
    return {'type': 'doc', 'version': 1, 'content': content}


# ADF nodes that hold a line of inline content. Everything else is a container walked into.
_ADF_LINE_NODES = ('paragraph', 'heading', 'codeBlock')


def adf_node_lines(node, out=None):
    """-> the plain lines of one ADF node: one line per paragraph-like node, its text nodes joined.
    Containers (panels, lists, tables) are walked, so a block a person moved inside one is still
    READ -- it is only never spliced there (see adf_splice)."""
    out = [] if out is None else out
    if not isinstance(node, dict):
        return out
    kids = [k for k in node.get('content') or [] if isinstance(k, dict)]
    if node.get('type') in _ADF_LINE_NODES:
        out.append(''.join(str(k.get('text') or '') for k in kids if k.get('type') == 'text'))
    elif node.get('type') == 'text':
        out.append(str(node.get('text') or ''))
    else:
        for k in kids:
            adf_node_lines(k, out)
    return out


def adf_text_lines(doc):
    """An ADF document as plain text, one line per paragraph-like node."""
    return '\n'.join(adf_node_lines(doc) if isinstance(doc, dict) else [])


def adf_splice(doc, block):
    """-> (new ADF document, delimiters_found). REPLACE THE MACHINE-OWNED BLOCK AND NOTHING ELSE.

    The block is the run of TOP-LEVEL nodes from the one whose text is BLOCK_OPEN to the first one
    after it whose text is BLOCK_CLOSE. Every node before and after it -- a person's paragraphs,
    marks, mentions, lists, panels -- is carried through as the very object that was read. With
    no intact delimiters the block is RE-APPENDED and nothing is replaced (TC 5.4): a bridge that
    regenerates a body loses every human sentence in it on its first bad parse.
    """
    content = list(doc.get('content') or []) if isinstance(doc, dict) else []
    new_block = adf_from_text(block)['content']
    lines = ['\n'.join(adf_node_lines(n)) for n in content]
    found, spliced = False, None
    for i, text in enumerate(lines):
        if text.strip() != BLOCK_OPEN:
            continue
        for j in range(i + 1, len(lines)):
            if lines[j].strip() == BLOCK_CLOSE:
                spliced = content[:i] + new_block + content[j + 1:]
                found = True
                break
        break
    out = dict(doc) if isinstance(doc, dict) else {'type': 'doc', 'version': 1}
    out.setdefault('type', 'doc')
    out.setdefault('version', 1)
    out['content'] = spliced if found else content + new_block
    return out, found


def _jql_quote(value):
    """A configuration value inside a JQL string literal: backslash and double quote escaped, so
    a project key or label cannot close the literal and append a clause."""
    return str(value or '').replace('\\', '\\\\').replace('"', '\\"')


class Jira(HttpBackend):
    """Jira Cloud.

    Exercisable against a PERSONAL account: a free Atlassian Cloud site, an API token from
    id.atlassian.com, and one project. Basic auth is `email:token` -- the token alone is a 401,
    which `scripts/check_env.py` already records as a defect somebody hit.

    Two Jira facts change the design and are honoured here:
      * The issue KEY is not a stable identifier; the numeric id is. The ledger stores the id.
      * Enhanced search is eventually consistent, so this NEVER reads after a write.
    """

    name = 'jira'

    def __init__(self, host, email, token, project, stamp_field, calibration='',
                 retry_ceiling=0, **opts):
        self.host = (host or '').rstrip('/')
        self.project = project
        self.stamp_field = stamp_field
        # TICKETING_BACKENDS.md 3.1. Values with a documented default carry it here; values
        # without one are required by choose_backend and validated at run start.
        self.stamp_label = opts.get('stamp_label') or DEFAULT_STAMP_LABEL
        self.type_cluster = opts.get('type_cluster') or 'Story'
        self.type_instance = opts.get('type_instance') or 'Subtask'
        self.epic_id = str(opts.get('epic_id') or '').strip()
        self.transition_reopen = (opts.get('transition_reopen') or '').strip()
        # JIRA_CALIBRATION_ISSUE: the numeric id of a known-present ticket this credential did
        # NOT create, made once by a human (TICKETING_BACKENDS.md 3.4).
        self.calibration = (calibration or '').strip()
        self._auth = base64.b64encode(
            ('%s:%s' % (email or '', token or '')).encode('utf-8')).decode('ascii')
        self._init_http(retry_ceiling)

    def _headers(self):
        return [('Accept', 'application/json'), ('Authorization', 'Basic %s' % self._auth)]

    def _req(self, method, path, payload=None):
        return self._http(method, self.host + path, payload)

    def probe(self):
        if not self.stamp_field:
            # Field discovery is NOT exhaustive on Jira -- fields not on a used screen are not
            # returned -- so "the stamp field was not found" is a could-not-establish, not an
            # absence. Refusing here is the only answer that does not guess.
            return False, ('no stamp field configured, and Jira field discovery cannot establish '
                           'absence: a field missing from the response may simply be off-screen')
        doc, status, err = self._req('GET', '/rest/api/3/project/%s' % self.project)
        if err or not doc:
            return False, 'could not read project %s (status %s)' % (self.project, status)
        # The project being readable is REACH. Visibility of tickets this credential did not
        # create is what licenses reading a not-found as an absence (TC 4.5; L54, J-3).
        if not self.calibration:
            return False, ('no calibration ticket configured (JIRA_CALIBRATION_ISSUE), so no '
                           'not-found this run may license a creation')
        cal, status, err = self._req('GET', '/rest/api/3/issue/%s?fields=%s'
                                     % (self.calibration, self.stamp_field))
        if err or not cal:
            return False, ('the calibration ticket did not resolve (status %s): the channel is not '
                           'shown able to see a foreign ticket' % status)
        if ((cal.get('fields') or {}).get(self.stamp_field) or ''):
            return False, ('the calibration ticket carries a cluster stamp, so it may be one this '
                           'kit created; it cannot calibrate foreign visibility')
        return True, 'calibration probe resolved a known-present foreign ticket'

    def validate(self):
        """RUN START: establish the site's shape once, then act (TICKETING_BACKENDS.md 3.2; J-7).
        -> (ok, detail). Any failure means nothing is created or updated this run.

        "Field not found" is COULD-NOT-ESTABLISH, never absence: createmeta omits fields that are
        not on a screen (TC 3.2). Either way the answer is the same -- do not write -- and the
        detail names which value failed so the refusal is actionable.
        """
        # THE CREDENTIAL FIRST. Jira Cloud answers a bad token as an ANONYMOUS caller, so a
        # project read alone is a 404 and would name JIRA_PROJECT for a broken JIRA_TOKEN (found
        # by the live R-1 run, 2026-10-15). /myself answers 401 for exactly that case.
        me, status, err = self._req('GET', '/rest/api/3/myself')
        if err or not me:
            if status is None or status in (401, 403):
                return False, first_read_refusal(status, 'JIRA_HOST', 'JIRA_EMAIL/JIRA_TOKEN',
                                                 'JIRA_PROJECT', self.project)
            return False, ('JIRA_EMAIL/JIRA_TOKEN could not be established: /myself answered '
                           'HTTP %s' % status)
        doc, status, err = self._req('GET', '/rest/api/3/project/%s' % self.project)
        if err or not doc:
            return False, first_read_refusal(status, 'JIRA_HOST', 'JIRA_EMAIL/JIRA_TOKEN',
                                             'JIRA_PROJECT', self.project)
        types, status, err = self._req('GET', '/rest/api/3/issue/createmeta/%s/issuetypes'
                                       % self.project)
        if err or not types:
            return False, ('createmeta for %s could not be read (status %s), so whether the stamp '
                           'field can be set is not established' % (self.project, status))
        listed = types.get('issueTypes') or types.get('values') or []
        by_name = dict((t.get('name'), t) for t in listed if isinstance(t, dict))
        for var, name in (('JIRA_TYPE_CLUSTER', self.type_cluster),
                          ('JIRA_TYPE_INSTANCE', self.type_instance)):
            if name not in by_name:
                return False, ('%s %r is not an issue type in %s (have: %s)'
                               % (var, name, self.project, ', '.join(sorted(
                                   n for n in by_name if n)) or 'none'))
        self.type_ids = dict((n, str(t.get('id'))) for n, t in by_name.items())
        meta, status, err = self._req('GET', '/rest/api/3/issue/createmeta/%s/issuetypes/%s'
                                      % (self.project, self.type_ids[self.type_cluster]))
        if err or not meta:
            return False, 'createmeta for %s could not be read (status %s)' % (self.type_cluster,
                                                                              status)
        fields = meta.get('fields') or meta.get('values') or []
        stamp = [f for f in fields if isinstance(f, dict) and
                 (f.get('fieldId') or f.get('key')) == self.stamp_field]
        if not stamp:
            return False, ('JIRA_STAMP_FIELD %s is not settable on %s: not found by createmeta, '
                           'which is could-not-establish (a field off-screen is omitted), never '
                           'absence' % (self.stamp_field, self.type_cluster))
        if ((stamp[0].get('schema') or {}).get('type')) != 'string':
            return False, ('JIRA_STAMP_FIELD %s is not a single-line text field (schema %r)'
                           % (self.stamp_field, (stamp[0].get('schema') or {}).get('type')))
        epic, status, err = self._req('GET', '/rest/api/3/issue/%s?fields=project,issuetype'
                                      % self.epic_id)
        if err or not epic:
            return False, 'JIRA_EPIC_ID %s did not resolve (status %s)' % (self.epic_id, status)
        if ((epic.get('fields') or {}).get('project') or {}).get('key') != self.project:
            return False, 'JIRA_EPIC_ID %s is not in project %s' % (self.epic_id, self.project)
        return True, ('project, issue types (%s, %s), stamp field and epic established'
                      % (self.type_cluster, self.type_instance))

    def jql(self):
        """The bounded sweep query (TICKETING_BACKENDS.md 3.3; J-1): this project, the umbrella
        label, the tier-0 type. Instances are found through their parent, never swept."""
        return ('project = "%s" AND labels = "%s" AND issuetype = "%s" ORDER BY created DESC'
                % (_jql_quote(self.project), _jql_quote(self.stamp_label),
                   _jql_quote(self.type_cluster)))

    def sweep(self, known_refs=()):
        out, token, pages, complete = {}, None, 0, True
        while True:
            # maxResults: the enhanced search documents 5000 only for id/key-only requests; with
            # the three fields requested, the honoured maximum is UNVERIFIED, so 100.
            payload = {'jql': self.jql(), 'maxResults': 100,
                       'fields': [self.stamp_field, 'status', 'labels']}
            # reconcileIssues: numeric ids only; Atlassian documents a cap on how many may be
            # passed (50 is the figure in circulation, UNVERIFIED here), so at most 50.
            ids = [int(x) for x in known_refs if str(x).isdigit()][:50]
            if ids:
                payload['reconcileIssues'] = ids
            if token:
                payload['nextPageToken'] = token
            # The enhanced endpoint. The legacy /rest/api/3/search is being removed (CHANGE-2046),
            # so designing against it would be building on something with a published end date.
            doc, status, err = self._req('POST', '/rest/api/3/search/jql', payload)
            if err or doc is None:
                return out, False, 'sweep stopped after %d page(s) (status %s)' % (pages, status)
            for issue in (doc.get('issues') or []):
                fields = issue.get('fields') or {}
                stamp = (fields.get(self.stamp_field) or '')
                status = fields.get('status') or {}
                if isinstance(stamp, str) and stamp.strip():
                    out.setdefault(stamp.strip(), []).append({
                        # THE NUMERIC ID, not the key. The key is a human-facing label that moves.
                        'ref': str(issue.get('id')),
                        'key': issue.get('key') or '',
                        'url': '%s/rest/api/3/issue/%s' % (self.host, issue.get('id')),
                        # Projected only where a decision needs it (TC 9.2): the status
                        # CATEGORY is Jira's stable open/closed axis; the name is recorded
                        # verbatim beside it because workflows rename statuses.
                        'state': ('closed' if (status.get('statusCategory') or {}).get('key')
                                  == 'done' else 'open') if status else '',
                        'status_name': status.get('name') or '',
                        'body': '',
                    })
            pages += 1
            print('  ... swept page %d' % pages, file=sys.stderr)
            token = doc.get('nextPageToken')
            if not token:
                break
            if pages > 100:
                complete = False
                break
        return out, complete, 'swept %d page(s)' % pages

    def resolve(self, ref):
        doc, status, err = self._req('GET', '/rest/api/3/issue/%s' % ref)
        if doc:
            return doc, True, 'resolved'
        return None, False, 'did not resolve (status %s)' % status

    def create(self, cluster, body, title):
        # EVERYTHING IN ONE CALL (TICKETING_BACKENDS.md 3.3; J-2): the tier-0 type, the umbrella
        # and family labels, the product epic as parent, the stamp, and the machine-owned block
        # as the ADF description. A second call to finish a ticket is a second chance to leave
        # one half-made, and it doubles the cost against the binding limit.
        labels = [self.stamp_label] + ([family_of(cluster)] if family_of(cluster) else [])
        fields = {
            'project': {'key': self.project},
            'summary': title,
            'issuetype': {'name': self.type_cluster},
            'labels': labels,
            self.stamp_field: cluster['cluster_key'],
            'description': adf_from_text(body),
        }
        if self.epic_id:
            fields['parent'] = {'id': self.epic_id}
        doc, status, err = self._req('POST', '/rest/api/3/issue', {'fields': fields})
        if err or not doc:
            return None, 'create failed (status %s)' % status
        # THE NUMERIC ID is the reference; the key is a label that moves. Never read after write.
        return str(doc.get('id')), 'created %s' % doc.get('key')

    def create_instance(self, parent_ref, member, body, title):
        doc, status, err = self._req('POST', '/rest/api/3/issue', {'fields': {
            'project': {'key': self.project},
            'summary': title,
            'issuetype': {'name': self.type_instance},
            'parent': {'id': str(parent_ref)},
            'description': adf_from_text(body),
        }})
        if err or not doc:
            return None, 'instance create failed (status %s)' % status
        return str(doc.get('id')), 'created instance %s' % doc.get('key')

    def comment(self, ref, text):
        doc, status, err = self._req(
            'POST', '/rest/api/3/issue/%s/comment' % ref,
            {'body': {'type': 'doc', 'version': 1,
                      'content': [{'type': 'paragraph',
                                   'content': [{'type': 'text', 'text': text}]}]}})
        return (doc is not None), 'comment status %s' % status

    def reopen(self, ref):
        """TICKETING_BACKENDS.md 3.3: read the transitions offered for this issue and post the one
        whose NAME is JIRA_TRANSITION_REOPEN (ids are workflow-specific). An EMPTY list is
        ambiguous between not-permitted and not-applicable -- DISTINCTION_NOT_OBSERVABLE -- so it
        is a refusal with that reason, never "reopen is impossible here"."""
        if not self.transition_reopen:
            return False, ('JIRA_TRANSITION_REOPEN is not configured, so no transition can be '
                           'chosen without guessing; the successor path is the normal case')
        # Every refusal NAMES the setting (TICKETING_BACKENDS.md R-1; T-24), so a site whose
        # workflow has no transition of that name is told which value to correct.
        doc, status, err = self._req('GET', '/rest/api/3/issue/%s/transitions' % ref)
        if err or doc is None:
            return False, ('JIRA_TRANSITION_REOPEN %r could not be tried: the transitions could '
                           'not be read (status %s)' % (self.transition_reopen, status))
        offered = [t for t in (doc.get('transitions') or []) if isinstance(t, dict)]
        if not offered:
            return False, ('JIRA_TRANSITION_REOPEN %r: the transitions list is EMPTY: not '
                           'permitted and not applicable arrive identically (%s)'
                           % (self.transition_reopen, DISTINCTION_NOT_OBSERVABLE))
        match = [t for t in offered
                 if (t.get('name') or '').strip().lower() == self.transition_reopen.lower()]
        if not match:
            return False, ('JIRA_TRANSITION_REOPEN %r is not offered (offered: %s)'
                           % (self.transition_reopen,
                              ', '.join(t.get('name') or '?' for t in offered)))
        _d, status, err = self._req('POST', '/rest/api/3/issue/%s/transitions' % ref,
                                    {'transition': {'id': str(match[0].get('id'))}})
        if err:
            return False, 'the transition was refused (status %s)' % status
        return True, 'reopened by transition %r' % self.transition_reopen

    def read_description(self, ref):
        """The CURRENT description, as Jira holds it: an ADF document, or null when empty."""
        doc, status, err = self._req('GET', '/rest/api/3/issue/%s?fields=description' % ref)
        if err or not isinstance(doc, dict):
            return None, False, 'the description could not be read (status %s)' % status
        desc = (doc.get('fields') or {}).get('description')
        if desc is not None and not (isinstance(desc, dict) and desc.get('type') == 'doc'):
            # Not an ADF document (an API version or app rewrote it): nothing here can splice it
            # without guessing, so it is not written.
            return None, False, ('the description is not an ADF document (%s), so the block '
                                 'cannot be replaced without rewriting the rest'
                                 % type(desc).__name__)
        return desc, True, 'read'

    def description_text(self, description):
        return adf_text_lines(description)

    def splice_description(self, description, block):
        return adf_splice(description, block)

    def write_description(self, ref, new_description, read):
        doc, status, err = self._req(
            'PUT', '/rest/api/3/issue/%s' % ref, {'fields': {'description': new_description}})
        # PUT /issue returns 204 with no body: success is the status, not a document. RESIDUAL,
        # named: Jira's issue edit takes no precondition, so a person saving in the seconds between
        # this run's read and its write is not detected here (Azure DevOps' `test /rev` is).
        return (err is None and status in (200, 204)), 'description update status %s' % status


AZDO_API = '7.1'
# A single WIQL query returns at most 20,000 results. Documented in a Microsoft Q&A answer; the
# REST reference page is UNVERIFIED (TICKETING_BACKENDS.md 4.2). A PLATFORM limit, not a policy
# number: a result count at it is PARTIAL, never complete.
WIQL_CAP = 20000
# workitemsbatch accepts at most 200 ids per call (documented maximum, TICKETING_BACKENDS.md 4.2).
AZDO_BATCH_MAX = 200


def _wiql_quote(value):
    """A configuration value inside a WIQL string literal: single quotes doubled."""
    return str(value or '').replace("'", "''")


def html_text_lines(markup):
    """System.Description HTML as plain lines: line-ending tags become newlines, other tags go,
    entities are decoded. For READING the block back; nothing is ever written from this."""
    import html
    import re
    t = re.sub(r'(?i)<br\s*/?>', '\n', markup or '')
    t = re.sub(r'(?i)</(p|div|pre|li|h[1-6]|tr)\s*>', '\n', t)
    t = re.sub(r'<[^>]*>', '', t)
    return html.unescape(t)


def html_splice(markup, block):
    """-> (new HTML, delimiters_found). REPLACE THE MACHINE-OWNED BLOCK AND NOTHING ELSE.

    The block was written as escaped text, so its delimiters sit in the stored HTML as escaped
    text. Everything from the escaped BLOCK_OPEN to the first escaped BLOCK_CLOSE after it is
    replaced by the new block, escaped the same way; every byte before and after is the byte that
    was read. Without both delimiters the block is RE-APPENDED and nothing is replaced (TC 5.4).
    """
    import html
    markup = markup or ''
    e_open, e_close = html.escape(BLOCK_OPEN), html.escape(BLOCK_CLOSE)
    i = markup.find(e_open)
    j = markup.find(e_close, i + len(e_open)) if i >= 0 else -1
    if i >= 0 and j >= 0:
        return markup[:i] + html.escape(block) + markup[j + len(e_close):], True
    return markup + '<pre>%s</pre>' % html.escape(block), False


class AzureDevOps(HttpBackend):
    """Azure DevOps Boards, to the same contract as Jira (TICKETING_BACKENDS.md section 4; A-1).

    Tier 0 is `AZDO_TYPE_CLUSTER` (default `Issue`), tier -1 `AZDO_TYPE_INSTANCE` (default
    `Task`), both under the product epic. The stamp is a custom single-line text field added once
    by a human in an INHERITED process; the umbrella stamp is a TAG.

    Authentication is Basic with an EMPTY user name and the PAT as the password; the PAT never
    reaches a URL, a message or a record. Both organisation URL forms are accepted:
    `https://dev.azure.com/<org>` and the legacy `https://<org>.visualstudio.com`.
    """

    name = 'azdo'

    def __init__(self, org_url, project, pat, stamp_field, epic_id='', calibration='',
                 stamp_label='', type_cluster='', type_instance='', state_reopen='',
                 state_done='', retry_ceiling=0, create_ceiling=None):
        self.org_url = (org_url or '').rstrip('/')
        self.project = project or ''
        self.stamp_field = stamp_field or ''
        self.epic_id = str(epic_id or '').strip()
        self.calibration = str(calibration or '').strip()
        self.stamp_label = stamp_label or DEFAULT_STAMP_LABEL
        self.type_cluster = type_cluster or 'Issue'
        self.type_instance = type_instance or 'Task'
        self.state_reopen = state_reopen or 'To Do'
        self.state_done = state_done or 'Done'
        self.create_ceiling = create_ceiling
        self._auth = base64.b64encode((':%s' % (pat or '')).encode('utf-8')).decode('ascii')
        self._init_http(retry_ceiling)

    def _headers(self):
        return [('Accept', 'application/json'), ('Authorization', 'Basic %s' % self._auth)]

    def _url(self, path, project=True, api=AZDO_API):
        import urllib.parse
        base = self.org_url + ('/' + urllib.parse.quote(self.project) if project else '')
        return '%s%s%sapi-version=%s' % (base, path, '&' if '?' in path else '?', api)

    def _req(self, method, path, payload=None, project=True, patch=False, api=AZDO_API):
        return self._http(method, self._url(path, project, api), payload,
                          content_type='application/json-patch+json' if patch
                          else 'application/json')

    def _observe_rate(self, headers):
        """Azure DevOps sends Retry-After (and X-RateLimit-*) BEFORE it starts delaying. Honour
        it on a successful response too, so the run slows down instead of being delayed."""
        if not headers:
            return
        ra = parse_retry_after(headers.get('Retry-After'))
        if ra is not None:
            self.throttles.append({'status': 200, 'method': 'advisory', 'retry_after': ra,
                                   'remaining': headers.get('X-RateLimit-Remaining')})
            _sleep(ra)

    def _tags(self, item):
        return [t.strip() for t in str((item.get('fields') or {}).get('System.Tags') or '')
                .split(';') if t.strip()]

    def _item_url(self, wid):
        return '%s/_apis/wit/workItems/%s' % (self.org_url, wid)

    # ── run start ───────────────────────────────────────────────────────────────────────

    def validate(self):
        import urllib.parse
        doc, status, err = self._req('GET', '/_apis/projects/%s' % urllib.parse.quote(
            self.project), project=False)
        if err or not doc:
            return False, first_read_refusal(status, 'AZDO_ORG_URL', 'AZDO_PAT', 'AZDO_PROJECT',
                                             self.project)
        types, status, err = self._req('GET', '/_apis/wit/workitemtypes')
        if err or not types:
            return False, 'the work item types could not be read (status %s)' % status
        names = set(t.get('name') for t in types.get('value') or [] if isinstance(t, dict))
        for var, name in (('AZDO_TYPE_CLUSTER', self.type_cluster),
                          ('AZDO_TYPE_INSTANCE', self.type_instance)):
            if name not in names:
                return False, '%s %r is not a work item type in %s' % (var, name, self.project)
        q = urllib.parse.quote(self.type_cluster)
        fields, status, err = self._req('GET', '/_apis/wit/workitemtypes/%s/fields' % q)
        if err or not fields:
            return False, 'the fields of %s could not be read (status %s)' % (self.type_cluster,
                                                                              status)
        stamp = [f for f in fields.get('value') or [] if isinstance(f, dict)
                 and f.get('referenceName') == self.stamp_field]
        if not stamp:
            return False, ('AZDO_STAMP_FIELD %s is not a field of %s. Custom fields need an '
                           'inherited process; the system process cannot hold them'
                           % (self.stamp_field, self.type_cluster))
        if (stamp[0].get('type') or 'string') != 'string':
            return False, 'AZDO_STAMP_FIELD %s is not single-line text (%r)' % (
                self.stamp_field, stamp[0].get('type'))
        states, status, err = self._req('GET', '/_apis/wit/workitemtypes/%s/states' % q)
        have = set(s.get('name') for s in (states or {}).get('value') or [] if isinstance(s, dict))
        for var, name in (('AZDO_STATE_REOPEN', self.state_reopen),
                          ('AZDO_STATE_DONE', self.state_done)):
            if name not in have:
                return False, '%s %r is not a state of %s' % (var, name, self.type_cluster)
        epic, status, err = self._req('GET', '/_apis/wit/workitems/%s' % self.epic_id)
        if err or not epic:
            return False, 'AZDO_EPIC_ID %s did not resolve (status %s)' % (self.epic_id, status)
        if (epic.get('fields') or {}).get('System.TeamProject') not in (None, self.project):
            return False, 'AZDO_EPIC_ID %s is not in project %s' % (self.epic_id, self.project)
        return True, 'project, work item types, stamp field, states and epic established'

    def probe(self):
        if not self.calibration:
            return False, ('no calibration item configured (AZDO_CALIBRATION_ITEM), so no '
                           'not-found this run may license a creation')
        cal, status, err = self._req('GET', '/_apis/wit/workitems/%s' % self.calibration)
        if err or not cal:
            return False, ('the calibration work item did not resolve (status %s): the channel '
                           'is not shown able to see a foreign item' % status)
        if (cal.get('fields') or {}).get(self.stamp_field) or self.stamp_label in self._tags(cal):
            return False, ('the calibration item carries our stamp or umbrella tag, so it may be '
                           'one this kit created; it cannot calibrate foreign visibility')
        return True, 'calibration probe resolved a known-present foreign work item'

    # ── the sweep: WIQL for ids, then workitemsbatch for fields ─────────────────────────

    def wiql(self, after_id=0):
        return ("SELECT [System.Id] FROM WorkItems WHERE [System.TeamProject] = @project "
                "AND [System.WorkItemType] = '%s' AND [System.Tags] CONTAINS '%s' "
                "AND [System.Id] > %d ORDER BY [System.Id]"
                % (_wiql_quote(self.type_cluster), _wiql_quote(self.stamp_label), int(after_id)))

    def sweep(self, known_refs=()):
        out, complete, pages, last = {}, True, 0, 0
        ids = []
        while True:
            doc, status, err = self._req('POST', '/_apis/wit/wiql', {'query': self.wiql(last)})
            if err or doc is None:
                return out, False, 'WIQL stopped after %d page(s) (status %s)' % (pages, status)
            page = [int(w['id']) for w in doc.get('workItems') or [] if 'id' in w]
            pages += 1
            ids.extend(page)
            if len(page) >= WIQL_CAP:
                # AT THE CAP: the query may have been truncated. Page on by id so later items are
                # still seen, and the sweep is PARTIAL regardless -- never complete.
                complete = False
                last = max(page)
                if pages > 100:
                    break
                continue
            break
        for n in range(0, len(ids), AZDO_BATCH_MAX):
            chunk = ids[n:n + AZDO_BATCH_MAX]
            doc, status, err = self._req('POST', '/_apis/wit/workitemsbatch', {
                'ids': chunk,
                'fields': ['System.Id', 'System.State', 'System.Tags', self.stamp_field]})
            if err or doc is None:
                return out, False, 'batch read stopped at %d/%d (status %s)' % (n, len(ids),
                                                                                status)
            for item in doc.get('value') or []:
                fields = item.get('fields') or {}
                stamp = fields.get(self.stamp_field) or ''
                # WIQL CONTAINS is a substring match; the umbrella is matched as a whole TAG.
                if not stamp or self.stamp_label not in self._tags(item):
                    continue
                state = fields.get('System.State') or ''
                out.setdefault(str(stamp).strip(), []).append({
                    'ref': str(item.get('id')), 'url': self._item_url(item.get('id')),
                    'state': 'closed' if state == self.state_done else 'open',
                    'status_name': state, 'body': ''})
            print('  ... batch-read %d/%d work item(s)' % (min(n + AZDO_BATCH_MAX, len(ids)),
                                                           len(ids)), file=sys.stderr)
        return out, complete, 'WIQL %d page(s), %d id(s)%s' % (
            pages, len(ids), '' if complete else ' -- AT THE WIQL CAP, PARTIAL')

    def resolve(self, ref):
        doc, status, err = self._req('GET', '/_apis/wit/workitems/%s' % ref)
        if doc:
            return doc, True, 'resolved'
        return None, False, 'did not resolve (status %s)' % status

    # ── writes ──────────────────────────────────────────────────────────────────────────

    def _create(self, type_name, title, tags, body, parent_id, stamp=None):
        import html
        import urllib.parse
        ops = [{'op': 'add', 'path': '/fields/System.Title', 'value': title},
               # The block as TEXT inside HTML: escaped, so finding text stays data (TC 7.4).
               {'op': 'add', 'path': '/fields/System.Description',
                'value': '<pre>%s</pre>' % html.escape(body)}]
        if tags:
            ops.append({'op': 'add', 'path': '/fields/System.Tags', 'value': '; '.join(tags)})
        if stamp is not None:
            ops.append({'op': 'add', 'path': '/fields/%s' % self.stamp_field, 'value': stamp})
        if parent_id:
            ops.append({'op': 'add', 'path': '/relations/-', 'value': {
                'rel': 'System.LinkTypes.Hierarchy-Reverse', 'url': self._item_url(parent_id)}})
        doc, status, err = self._req('POST', '/_apis/wit/workitems/$%s'
                                     % urllib.parse.quote(type_name), ops, patch=True)
        if err or not doc:
            return None, 'create failed (status %s)' % status
        return str(doc.get('id')), 'created work item %s' % doc.get('id')

    def create(self, cluster, body, title):
        tags = [self.stamp_label] + ([family_of(cluster)] if family_of(cluster) else [])
        return self._create(self.type_cluster, title, tags, body, self.epic_id,
                            stamp=cluster['cluster_key'])

    def create_instance(self, parent_ref, member, body, title):
        return self._create(self.type_instance, title, [], body, parent_ref)

    def comment(self, ref, text):
        import html
        doc, status, err = self._req('POST', '/_apis/wit/workItems/%s/comments' % ref,
                                     {'text': '<pre>%s</pre>' % html.escape(text)},
                                     api='7.1-preview.4')
        return (doc is not None), 'comment status %s' % status

    def read_description(self, ref):
        """The CURRENT System.Description (HTML) and the work item's revision."""
        doc, status, err = self._req('GET', '/_apis/wit/workitems/%s?fields=System.Description'
                                     % ref)
        if err or not isinstance(doc, dict):
            return None, False, 'the description could not be read (status %s)' % status
        desc = (doc.get('fields') or {}).get('System.Description')
        if desc is not None and not isinstance(desc, str):
            return None, False, 'System.Description is not HTML text (%s)' % type(desc).__name__
        return {'html': desc or '', 'rev': doc.get('rev')}, True, 'read'

    def description_text(self, description):
        return html_text_lines((description or {}).get('html') or '')

    def splice_description(self, description, block):
        new_html, found = html_splice((description or {}).get('html') or '', block)
        return dict(description or {}, html=new_html), found

    def write_description(self, ref, new_description, read):
        # `test /rev` FIRST: the write applies only to the revision this run read. A person who
        # saved in between makes Azure DevOps refuse the whole patch, so their edit is never
        # overwritten; the refusal is reported and the update is owed to the next run.
        ops = []
        rev = (read or {}).get('rev')
        if rev is not None:
            ops.append({'op': 'test', 'path': '/rev', 'value': rev})
        ops.append({'op': 'add', 'path': '/fields/System.Description',
                    'value': (new_description or {}).get('html') or ''})
        doc, status, err = self._req('PATCH', '/_apis/wit/workitems/%s' % ref, ops, patch=True)
        return (doc is not None), 'description update status %s' % status

    def reopen(self, ref):
        """A state write to AZDO_STATE_REOPEN. A refusal by a process rule is the successor path,
        as in Jira, and its reason is recorded."""
        doc, status, err = self._req('PATCH', '/_apis/wit/workitems/%s' % ref, [
            {'op': 'add', 'path': '/fields/System.State', 'value': self.state_reopen}],
            patch=True)
        if err or doc is None:
            return False, 'the state write to %r was refused (status %s)' % (self.state_reopen,
                                                                            status)
        return True, 'reopened to %r' % self.state_reopen


class RecordingBackend(TicketBackend):
    """An in-memory backend that records what was asked of it. Used by the self-test.

    It is NOT a mock of the cascade: the cascade calls the same five methods it calls on the real
    backends, so the self-test exercises the real decision logic. What it fakes is the network.
    """

    name = 'recording'

    def __init__(self, observable=True, sweep_complete=True, sweep_returns_body=True):
        self.store = {}            # stamp -> [record]
        self.created = []
        self.comments = []
        self.block_updates = []
        self.reopened = []
        self.instances = []
        self.refuse_reopen = False
        self.sweeps = 0
        self._observable = observable
        self._sweep_complete = sweep_complete
        # Jira and Azure DevOps sweeps return NO body (T-02). False models them, so the update
        # path is proven to read the description itself rather than trust the sweep's copy.
        self._sweep_returns_body = sweep_returns_body
        # Refs whose description read fails: nothing may then be written to them.
        self.unreadable = set()
        self.description_reads = 0
        self.next_ref = 1

    def probe(self):
        return self._observable, ('calibration probe resolved a known-present ticket'
                                  if self._observable else 'probe could not see a foreign ticket')

    def sweep(self, known_refs=()):
        self.sweeps += 1
        if self._sweep_returns_body:
            out = dict((k, list(v)) for k, v in self.store.items())
        else:
            out = dict((k, [dict(r, body='') for r in v]) for k, v in self.store.items())
        return out, self._sweep_complete, 'in-memory sweep %d' % self.sweeps

    def resolve(self, ref):
        for recs in self.store.values():
            for r in recs:
                if r['ref'] == str(ref):
                    return r, True, 'resolved'
        return None, False, 'no such ticket'

    def create(self, cluster, body, title):
        ref = str(self.next_ref)
        self.next_ref += 1
        self.store.setdefault(cluster['cluster_key'], []).append(
            {'ref': ref, 'url': 'memory://%s' % ref, 'state': 'open', 'body': body})
        self.created.append({'ref': ref, 'cluster_key': cluster['cluster_key'], 'title': title})
        return ref, 'created %s' % ref

    def comment(self, ref, text):
        self.comments.append((str(ref), text))
        return True, 'commented'

    def create_instance(self, parent_ref, member, body, title):
        ref = str(self.next_ref)
        self.next_ref += 1
        self.instances.append({'ref': ref, 'parent': str(parent_ref), 'title': title})
        return ref, 'created instance %s' % ref

    def reopen(self, ref):
        if getattr(self, 'refuse_reopen', False):
            return False, 'the in-memory tracker was set to refuse reopening'
        for recs in self.store.values():
            for r in recs:
                if r['ref'] == str(ref):
                    r['state'] = 'open'
                    self.reopened.append(str(ref))
                    return True, 'reopened'
        return False, 'no such ticket'

    def read_description(self, ref):
        self.description_reads += 1
        if str(ref) in self.unreadable:
            return None, False, 'the in-memory tracker was set to refuse this read'
        for recs in self.store.values():
            for r in recs:
                if r['ref'] == str(ref):
                    return r.get('body') or '', True, 'read'
        return None, False, 'no such ticket'

    def write_description(self, ref, new_description, read):
        for recs in self.store.values():
            for r in recs:
                if r['ref'] == str(ref):
                    r['body'] = new_description
                    self.block_updates.append(str(ref))
                    return True, 'block rewritten'
        return False, 'no such ticket'


# ═════════════════════════════════════════════════════════════════════════════════════
# THE STAMP
# ═════════════════════════════════════════════════════════════════════════════════════

STAMP_PREFIX = 'secure-cicd-kit-cluster:'


def stamp_from_body(body):
    """Read the cluster stamp out of a ticket body. -> stamp or ''.

    The body copy is a REDUNDANT index, and it is read from records the sweep already returned --
    it is never asked of a text search. The authoritative stamp on GitHub is an issue field; this
    costs nothing because the list endpoint returns `body` anyway, and whether issue-field values
    are returned by or filterable on that endpoint is UNVERIFIED (contract section 11.3 calls it
    the single most valuable thing to establish by experiment).
    """
    for line in (body or '').split('\n'):
        line = line.strip()
        if line.startswith(STAMP_PREFIX):
            return line[len(STAMP_PREFIX):].strip()
    return ''


def render_body(cluster, existing='', ticket=None, tasks=None):
    """The machine-owned block. Everything outside it belongs to a person.

    A ticket whose delimiters are missing or damaged is NOT rewritten from scratch: the block is
    re-appended and the damage reported. Somebody's triage notes live outside the block, and
    replacing a body to repair an index would destroy them.

    `ticket` and `tasks` are optional so that the body still renders for a caller holding only a
    cluster. When they are supplied the block also carries the child task table, the compliance
    pairing and the confidence derivation.
    """
    lines = [
        BLOCK_OPEN,
        STAMP_PREFIX + ' ' + cluster['cluster_key'],
        '',
        '**This ticket is a request for work. It is not a disposition and it suppresses nothing.**',
        'A finding stops blocking only when an exact, unexpired, approved disposition is merged to',
        'the protected default branch. Closing this ticket does not clear the finding.',
        '',
        '| field | value |',
        '|---|---|',
        '| cluster key | `%s` |' % cluster['cluster_key'],
        '| ticket class | %s |' % cluster.get('ticket_class', DEFAULT_CLASS),
        '| correlation tier | %s |' % cluster['tier'],
        '| finding subject | %s |' % (cluster['subject'] or 'not declared'),
        '| effective severity | %s (worst of the contributors, never averaged) |'
        % cluster['severity'],
        '| contributing scanners | %s |' % ', '.join(cluster['scanners'] or ['none named']),
        '| members | %d |' % len(cluster['members']),
    ]
    if cluster.get('scanners_stopped'):
        # TC 5.1: "a detector that stopped contributing is named as stopped, not omitted" -- a
        # dead detector must not hide behind a live one on the ticket (T-13).
        lines.append('| scanners no longer contributing | %s (named as stopped, not omitted) |'
                     % ', '.join(cluster['scanners_stopped']))
    if cluster.get('last_seen'):
        lines.append('| last seen | %s |' % cluster['last_seen'])
    if cluster.get('predecessor'):
        # TC 4.2: the successor references the predecessor by stamp and reference, because the
        # overturn is only legible beside the argument it overturns.
        lines.append('| predecessor | %s (reopen refused: %s) |' % (
            cluster['predecessor'], cluster.get('reopen_refused') or 'no reason recorded'))
        if cluster.get('reopen_classification'):
            # T-08: why the predecessor needed reopening, in TC 4.2's words.
            lines.append('| why it was reopened | %s |' % cluster['reopen_classification'])
    lines += [
        '',
        'Member identities:',
    ]
    for ident in cluster['member_identities']:
        lines.append('- `%s`' % ident)
    if cluster.get('members_absent'):
        # TC 4.3 / 5.1: a member that stopped appearing is POTENTIALLY_ABSENT -- "establish
        # coverage before calling it fixed". Listed, never dropped (T-13).
        lines += ['', '%s -- members not observed this run; not fixed, coverage over where they '
                      'lived is not established:' % ABSENT_HEADER]
        for ident in cluster['members_absent']:
            lines.append('* `%s`' % ident)
    lines += [
        '',
        'Per-scanner view (disagreement is recorded, not reconciled):',
        '',
        '| scanner | rule | severity | location |',
        '|---|---|---|---|',
    ]
    for m in cluster['members']:
        lines.append('| %s | `%s` | %s | `%s:%s` |' % (
            m.get('scanner') or '?', m.get('rule') or '?', m.get('severity') or '?',
            m.get('uri') or '?', m.get('line') or '?'))

    if ticket is not None:
        # CONFIDENCE CARRIES ITS DERIVATION INTO THE TICKET. A label on its own becomes a number
        # with extra steps the moment somebody puts it in a dashboard column, and the registry
        # requires a confidence claim to say what evidence it rests on.
        lines += [
            '',
            '| assessment | value |',
            '|---|---|',
            '| confidence | **%s** |' % ticket.confidence,
            '| derived from | %s |' % ticket.confidence_basis,
            '| closure rule | %s |' % ticket.closure_rule,
            '',
            'Confidence here is confidence that this is ONE REAL OBLIGATION -- that the finding',
            'exists and that the members belong together. It is NOT a claim about exploitability,',
            'business risk or fix priority. No number is given because none is derivable: a',
            'figure without provenance is numerology, and a default one is worse than a label.',
        ]
        if ticket.compliance_review != tm.PAIRING_NOT_ESTABLISHED:
            lines += [
                '',
                '### A compliance review is owed alongside the fix: %s'
                % ticket.compliance_review,
                '',
                'Why this class pairs to that review: %s' % ticket.compliance_why,
                '',
                'This is a SECOND obligation, not a restatement of the first. Remediating the',
                'finding does not discharge it, and the review does not remediate the finding.',
            ]
        else:
            lines += [
                '',
                '### No compliance review is paired to this finding class',
                '',
                '%s -- %s' % (tm.PAIRING_NOT_ESTABLISHED, ticket.compliance_why),
                '',
                'That is the lookup\'s answer, not a default. It does not establish that no',
                'review is required; it establishes that this kit does not know of one.',
            ]

    if tasks:
        lines += [
            '',
            '### Child tasks -- %d, each with its own state' % len(tasks),
            '',
            'This parent cannot close while any child is open, deferred or disputed. A cluster',
            'is one obligation to COORDINATE and several to DISCHARGE, and collapsing those',
            'leaves a partially-fixed cluster indistinguishable from an untouched one.',
            '',
            '| task | state | scanner | rule | location |',
            '|---|---|---|---|---|',
        ]
        for t in tasks:
            lines.append('| `%s` | %s | %s | `%s` | `%s:%s` |' % (
                t.task_id, t.state, t.scanner or '?', t.rule or '?',
                t.uri or '?', t.line if t.line is not None else '?'))
        lines += [
            '',
            'A child may be deferred only with a reason AND an end date, and a deferred child',
            'reopens only by an explicit act with a named trigger. The end date passing makes a',
            'reopen AVAILABLE; it never performs one. Silence must never renew an obligation.',
        ]

    lines += ['', BLOCK_CLOSE]
    block = '\n'.join(lines)
    return splice_text(existing, block)[0] if existing else block


# The block's POTENTIALLY_ABSENT list opens with this (finding_classification.POTENTIALLY_ABSENT).
ABSENT_HEADER = 'POTENTIALLY_ABSENT'


def block_facts(text):
    """-> what a ticket's machine-owned block says about the TC 5.1 facts: effective severity,
    contributing scanners, scanners named as stopped, members listed POTENTIALLY_ABSENT. Read
    from text the run already holds; never asked of a text index (TC 3.3). Lists come back
    sorted; a fact the block does not state comes back empty, which reads as a change."""
    facts = {'severity': None, 'scanners': [], 'stopped': [], 'absent': []}
    in_absent = False

    def cell(line):
        parts = line.split('|')
        return parts[2].strip() if len(parts) > 3 else ''

    for line in (text or '').split('\n'):
        s = line.strip()
        if in_absent:
            if s.startswith('* `') and s.endswith('`') and len(s) > 4:
                facts['absent'].append(s[3:-1])
                continue
            in_absent = False
        if s.startswith('| effective severity |'):
            facts['severity'] = (cell(s).split() or [None])[0]
        elif s.startswith('| contributing scanners |'):
            v = cell(s)
            facts['scanners'] = [] if v == 'none named' else [
                x.strip() for x in v.split(',') if x.strip()]
        elif s.startswith('| scanners no longer contributing |'):
            facts['stopped'] = [x.strip() for x in cell(s).split('(')[0].split(',') if x.strip()]
        elif s.startswith(ABSENT_HEADER + ' -- members not observed'):
            in_absent = True
    return dict((k, sorted(v) if isinstance(v, list) else v) for k, v in facts.items())


def rendered_facts(cluster):
    """The TC 5.1 facts a freshly rendered block states, in block_facts' shape."""
    return {'severity': cluster.get('severity'), 'scanners': sorted(cluster.get('scanners') or []),
            'stopped': sorted(cluster.get('scanners_stopped') or []),
            'absent': sorted(cluster.get('members_absent') or [])}


def splice_text(existing, block):
    """-> (text, delimiters_found). A text body with ONLY its machine-owned block replaced.

    Everything before BLOCK_OPEN and after the first BLOCK_CLOSE following it is returned byte for
    byte. Without both delimiters, in that order, the block is RE-APPENDED and nothing is replaced
    -- and the caller reports it (TC 5.4)."""
    existing = existing or ''
    i = existing.find(BLOCK_OPEN)
    j = existing.find(BLOCK_CLOSE, i + len(BLOCK_OPEN)) if i >= 0 else -1
    tail_start = j + len(BLOCK_CLOSE)
    if i >= 0 and j >= 0:
        return existing[:i] + block + existing[tail_start:], True
    if existing:
        return existing + '\n\n' + block, False
    return block, False


# Jira's summary and Azure DevOps' System.Title both cap a title at 255 characters; a longer one
# makes the CREATE fail. The full rule and path are in the machine-owned block, verbatim.
TITLE_MAX = 255
TRUNCATION_MARK = ' ...[truncated; full text in the body]'


def bounded_title(text):
    """A title that fits every tracker, saying so when it was cut (T-9). Never silently cut."""
    t = ' '.join(str(text or '').split())
    if len(t) <= TITLE_MAX:
        return t
    return t[:TITLE_MAX - len(TRUNCATION_MARK)] + TRUNCATION_MARK


def instance_title(cluster, member):
    return bounded_title('[%s] %s at %s:%s' % (
        member.get('severity') or cluster.get('severity') or 'none',
        member.get('rule') or 'finding', member.get('uri') or '?',
        member.get('line') if member.get('line') is not None else '?'))


def instance_body(parent_ref, member):
    """A tier -1 item's text. The same discipline as the tier-0 block: rule, severity, file,
    line and identity -- no snippet, no context region, no scanner partial fingerprint (TC 7.4)."""
    return '\n'.join([
        BLOCK_OPEN,
        'Instance of %s. This item is one observation; it is not a disposition and closing it '
        'clears nothing.' % parent_ref,
        '',
        '| field | value |',
        '|---|---|',
        '| scanner | %s |' % (member.get('scanner') or '?'),
        '| rule | `%s` |' % (member.get('rule') or '?'),
        '| severity | %s |' % (member.get('severity') or '?'),
        '| location | `%s:%s` |' % (member.get('uri') or '?', member.get('line') or '?'),
        '| identity | `%s` |' % (member.get('identity') or '?'),
        '',
        BLOCK_CLOSE])


def render_title(cluster):
    """No finding message text in the title, and nothing the stamp is parsed out of.

    The title is for a human to recognise. It carries the rule id, the severity, the file and the
    line, which the contract's section 7.4 permits, and no snippet, no context region and no
    scanner-supplied partial fingerprint.
    """
    m = cluster['members'][0]
    return bounded_title('[%s] %s in %s' % (cluster['severity'],
                                            m.get('rule') or 'finding',
                                            m.get('uri') or cluster['subject']
                                            or 'unknown location'))


# ═════════════════════════════════════════════════════════════════════════════════════
# THE CASCADE
# ═════════════════════════════════════════════════════════════════════════════════════


# WHY A CLOSED TICKET IS REOPENED (TC 4.2's table; T-08). The lapse is the registered
# finding_classification value. The other two are lower-case on purpose, like the correlation
# tiers: they name a row of TC 4.2's table in its own words rather than minting new state words.
REOPENED_BY_LAPSE = 'REOPENED_BY_LAPSE'
REOPEN_FALSIFIED = 'falsified'      # an approved REMEDIATED the scanner still reproduces
REOPEN_UNBACKED = 'unbacked'        # closed with nothing approved behind it


def closure_backing(cluster, today):
    """-> 'backed' | 'unbacked' | 'unknown'. What backs a closed ticket beside a finding the scanner
    still reproduces (TICKETING_CONTRACT.md 4.2's table, read from the members' dispositions).

        backed    an approved disposition other than REMEDIATED that is unexpired today
        unbacked  nothing approved, only expired ones, or REMEDIATED -- which is self-invalidating:
                  a REMEDIATED finding that reproduces is a falsified disposition
        unknown   an approved disposition exists but its expiry cannot be compared to today
                  (no reference date, or not a real date). Nothing is done on an unknown.
    """
    seen_unknown = False
    for m in cluster.get('members') or []:
        d = m.get('disposition')
        if not isinstance(d, dict):
            continue
        if str(d.get('disposition_type') or '').upper() == 'REMEDIATED':
            continue
        if str(d.get('state') or '').lower() != 'approved':
            continue
        until, now = tm.iso_date(d.get('expires')), tm.iso_date(today)
        if until is None or now is None:
            seen_unknown = True
            continue
        if until >= now:
            return 'backed'
    return 'unknown' if seen_unknown else 'unbacked'


def reopen_classification(cluster, today):
    """-> REOPENED_BY_LAPSE | REOPEN_FALSIFIED | REOPEN_UNBACKED, for a closure `closure_backing`
    found NOT backed. TC 4.2's table, row by row:

        an approved disposition whose expiry has passed   REOPENED_BY_LAPSE: the finding never
                                                          changed, its disposition did
        an approved REMEDIATED, still reproduced          falsified: self-invalidating, so the
                                                          disposition is stale or wrong
        nothing approved                                  unbacked: somebody just closed it
    The lapse outranks the others: an overturned FALSE_POSITIVE is the case TC 4.2 singles out.
    """
    now = tm.iso_date(today)
    remediated = False
    for m in cluster.get('members') or []:
        d = m.get('disposition')
        if not isinstance(d, dict) or str(d.get('state') or '').lower() != 'approved':
            continue
        if str(d.get('disposition_type') or '').upper() == 'REMEDIATED':
            remediated = True
            continue
        until = tm.iso_date(d.get('expires'))
        if until is not None and now is not None and until < now:
            return REOPENED_BY_LAPSE
    return REOPEN_FALSIFIED if remediated else REOPEN_UNBACKED


def reopen_comment(classification, today):
    """The one comment a reopen writes: what kind of reopen it is, in TC 4.2's words. A bare
    reopen reads as the bridge flapping; this is the label the ticket carries for a reader."""
    lead = 'Reopened by secure-cicd-kit (run date %s): %s.' % (today or 'not supplied',
                                                              classification)
    why = {
        REOPENED_BY_LAPSE: 'The finding never changed; the disposition that backed this closure '
                           'expired. Re-decide with a named approver and a new expiry: silence '
                           'never renews a disposition.',
        REOPEN_FALSIFIED: 'This was closed as REMEDIATED and the scanner still reproduces the '
                          'finding, so that disposition is stale or wrong and must not suppress.',
        REOPEN_UNBACKED: 'This ticket was closed with no approved, unexpired disposition behind '
                         'it, and the scanner still reproduces the finding.',
    }.get(classification, '')
    return '%s %s Closing a ticket does not clear a finding; only the scanner no longer ' \
           'reproducing it does.' % (lead, why)


def identities_from_body(body):
    """-> set of member identities listed in a ticket's machine-owned block. Parsed from a record
    the sweep already returned; never asked of a text index (TICKETING_CONTRACT.md 3.3)."""
    out, inside = set(), False
    for line in (body or '').split('\n'):
        s = line.strip()
        if s.startswith('Member identities:'):
            inside = True
            continue
        if inside:
            if s.startswith('- `') and s.endswith('`') and len(s) > 4:
                out.add(s[3:-1])
                continue
            break
    return out


def identity_bindings(ledger, sweep_map):
    """-> {member identity: set(cluster keys)} from the ledger and from the swept ticket blocks."""
    b = {}
    for key, entry in (ledger or {}).items():
        if isinstance(entry, dict):
            for ident in entry.get('member_identities') or []:
                b.setdefault(ident, set()).add(key)
    for key, refs in (sweep_map or {}).items():
        for r in refs:
            for ident in identities_from_body(r.get('body') or ''):
                b.setdefault(ident, set()).add(key)
    return b


def rebind(clusters, bindings):
    """THE STAMP, ONCE SET, DOES NOT MOVE (TICKETING_CONTRACT.md 5.2; T2, L53).

    The computed key derives from the shared-alias anchor, and that anchor moves when a member
    joins or leaves: a second scanner joining a singleton narrows the shared aliases, and the
    original scanner leaving changes them again. Before this, every such run minted a new key,
    found nothing under it, and opened a second ticket for an obligation that already had one.

    So a cluster whose members are ALREADY bound -- in the ledger, or in a swept ticket's block --
    inherits that binding's key. Members bound to two different existing obligations is a merge,
    and two clusters inheriting one key is a split; both are events a human decides
    (section 4.3), so they are marked here and never resolved by picking.
    """
    for c in clusters:
        bound = set()
        for ident in c['member_identities']:
            bound |= bindings.get(ident, set())
        if len(bound) == 1:
            key = next(iter(bound))
            if key != c['cluster_key']:
                c['computed_key'] = c['cluster_key']
                c['cluster_key'] = key
        elif len(bound) > 1:
            c['binding_conflict'] = sorted(bound)
    counts = {}
    for c in clusters:
        counts[c['cluster_key']] = counts.get(c['cluster_key'], 0) + 1
    for c in clusters:
        if counts[c['cluster_key']] > 1 and 'binding_conflict' not in c:
            c['binding_conflict'] = [c['cluster_key']]
    return clusters


def classify(cluster, ledger, sweep_map, sweep_complete, observable):
    """-> (outcome, refs, detail). The ONLY function that may return BINDING_ABSENT.

    Order is the contract's section 3: the ledger first because it is free, then the backend sweep
    because the ledger is authoritative about INTENT rather than about reality, and creation only
    from the one outcome that establishes absence through a channel shown able to see what it is
    reporting absent.
    """
    key = cluster['cluster_key']
    # A PREDECESSOR IS NOT A CANDIDATE. When a reopen was refused, the successor carries the same
    # stamp and the ledger records the old ticket as its predecessor (TC 4.2), so the pair is
    # history, not an ambiguity.
    preds = set(str(p) for p in ((ledger.get(key) or {}).get('predecessors') or []))
    hits = [h for h in (sweep_map.get(key) or []) if str(h.get('ref')) not in preds]

    # A merge or a split (see `rebind`). Cardinality, never guessing: nothing is created or
    # updated, and every existing obligation involved is named.
    if cluster.get('binding_conflict'):
        cands = []
        for k in cluster['binding_conflict']:
            cands.extend(sweep_map.get(k) or [{'ref': (ledger.get(k) or {}).get('ref') or k}])
        return (BINDING_AMBIGUOUS, cands,
                'this cluster\'s members are bound to %d existing obligation(s) shared with '
                'another cluster or with each other -- a merge or a split, which a human decides'
                % len(cluster['binding_conflict']))

    # More than one stamped ticket for one cluster. Ambiguity is resolved by cardinality, never by
    # guessing which one is canonical -- so nothing is created AND nothing is updated. Picking the
    # first would be a decision made by pagination.
    if len(hits) > 1:
        return (BINDING_AMBIGUOUS, hits,
                '%d tickets carry this cluster stamp; a human must declare which is canonical'
                % len(hits))

    ledger_ref = (ledger.get(key) or {}).get('ref')

    if ledger_ref:
        for h in hits:
            if h['ref'] == str(ledger_ref):
                return LEDGER_BOUND, hits, 'ledger reference resolved in the sweep'
        if not sweep_complete:
            # The reference is missing from a PARTIAL map. That is not a dangling reference and it
            # is certainly not an absence -- the map is a floor.
            return (UNCLASSIFIED_DEFAULT, hits,
                    'the ledger names %s and the sweep was incomplete, so its absence from the '
                    'map establishes nothing' % ledger_ref)
        return (BINDING_DANGLING, hits,
                'the ledger names %s and the completed sweep did not return it. A reference that '
                'did not resolve is an unresolved reference, not an absence' % ledger_ref)

    if len(hits) == 1:
        # No ledger entry, one stamped ticket. Somebody created it by hand with the stamp applied,
        # or a previous run's ledger write was lost. Creates nothing, and owes a ledger repair.
        return BACKEND_BOUND, hits, 'one stamped ticket found with no ledger entry; ledger owes a repair'

    if not sweep_complete:
        return (UNCLASSIFIED_DEFAULT, hits,
                'the sweep was incomplete, so nothing may be concluded from a miss in it')

    if not observable:
        # The sweep completed and saw nothing. Without a probe establishing that this channel can
        # see a ticket it did not create, "saw nothing" and "cannot see" are the same response.
        return (UNCLASSIFIED_DEFAULT, hits,
                'the sweep found nothing, and the calibration probe did not establish that this '
                'channel can see tickets it did not create (%s)' % DISTINCTION_NOT_OBSERVABLE)

    # Ledger miss, completed sweep, nothing stamped, and a channel shown able to see foreign
    # tickets. This is the one outcome creation may follow.
    return (BINDING_ABSENT, [], 'established absent (%s / %s)'
            % (VERIFIED_ABSENT, DISTINCTION_OBSERVABLE))


def sweep_past_due(ledger, today):
    """-> [{cluster_key, ref, task_id, until, reason, state, detail}] for every elapsed deferral.

    THE LEDGER IS WHERE A DEFERRAL PERSISTS. A run builds its parent and children fresh from the
    findings every time, so every child is OPEN in memory; the deferral that somebody approved
    last quarter lives in the ledger entry, under `deferrals`, keyed by task id. Reading it here
    is what makes a past-due acceptance visible in an ORDINARY run with nobody asking for it.

    IT REPORTS. It does not reopen, extend, clear or suppress -- `--resolve-deferral` does that,
    and it is a disposition. The reference engine's defect was performing the reopen inside a
    routine sweep with the actor recorded as the system; this function cannot, because it holds
    no approval and mutates nothing.
    """
    out = []
    for cluster_key in sorted(ledger or {}):
        entry = ledger[cluster_key] or {}
        if not isinstance(entry, dict):
            continue
        deferrals = entry.get('deferrals') or {}
        if not isinstance(deferrals, dict):
            continue
        for task_id in sorted(deferrals):
            rec = deferrals[task_id] or {}
            if not isinstance(rec, dict):
                # A malformed deferral record is REPORTED, never skipped. A deferral this program
                # could not read is a suppression nobody can account for, which is strictly worse
                # than one that elapsed.
                out.append({'cluster_key': cluster_key, 'ref': entry.get('ref'),
                            'task_id': task_id, 'until': None, 'reason': None,
                            'state': tm.DEFERRAL_TERM_UNKNOWN,
                            'detail': 'the deferral record is %s, not an object, so neither its '
                                      'end date nor its reason could be read'
                                      % type(rec).__name__})
                continue
            state, detail = tm.deferral_state(rec.get('until'), today)
            if state == tm.DEFERRAL_WITHIN_TERM:
                continue
            out.append({'cluster_key': cluster_key, 'ref': entry.get('ref'),
                        'task_id': task_id, 'until': rec.get('until'),
                        'reason': rec.get('reason'), 'state': state, 'detail': detail})
    return out


PROCEED = 'PROCEED'


def carry_owed(ledger, key, outcome, cause, today, **extra):
    """Record in the ledger that this obligation is OWED, with its streak (TC 4.1 step 3, TC 8:
    "outcome, cause, attempts, first-degraded-at"; T-06). -> the owed record.

    `attempts` counts CONSECUTIVE runs that carried it: a run that establishes the binding clears
    the record (see the bound path), so the next degraded run starts again at 1. An older record
    with no counter counts as one earlier attempt whose start is unestablished, never as zero.
    Members a previous run could not write (`update_owed`) survive into the new record.
    """
    entry = dict(ledger.get(key) or {})
    prev = entry.get('owed') if isinstance(entry.get('owed'), dict) else {}
    owed = {'outcome': outcome, 'cause': cause,
            'attempts': int(prev.get('attempts') or (1 if prev else 0)) + 1,
            'first_degraded_at': prev.get('first_degraded_at') or (
                'unestablished' if prev else (today or 'unestablished'))}
    if prev.get('update_owed') is not None and 'update_owed' not in extra:
        owed['update_owed'] = prev['update_owed']
    owed.update(extra)
    entry['owed'] = owed
    ledger[key] = entry
    return owed


def note_degraded(result, backend, key, owed):
    """Past the owner's threshold of consecutive degraded runs, the obligation is escalated as
    owed to a person (TC 4.1: DECISION_REQUIRED at the cell's next promotion review). The
    threshold is TICKET_DEGRADED_RUN_THRESHOLD, owner-set; unset (0) counts but never escalates."""
    threshold = int(getattr(backend, 'degraded_threshold', 0) or 0)
    if threshold and int(owed.get('attempts') or 0) >= threshold:
        result.setdefault('degraded_escalations', []).append({
            'cluster_key': key, 'attempts': owed['attempts'], 'threshold': threshold,
            'first_degraded_at': owed.get('first_degraded_at'), 'cause': owed.get('cause')})


def finish_claim(result, backend_note='', backend=None):
    """THE RUN'S TICKETING CLAIM (TICKETING_CONTRACT.md 4.1; L55). Computed last, from what the run
    actually established, and stated in the summary and the exit code.

    EVIDENCE_UNTRUSTED -- "a result that cannot be relied on, never DECISION_REQUIRED and never
    clean" -- when the control is off or misconfigured, when any lookup did not complete, or when
    every finding was withheld for want of an identity. The publication channel is then
    PUBLICATION_DEGRADED. The findings' own routing is untouched: a ticketing failure never
    softens a finding, and it never hardens one either.
    """
    causes = []
    # The budget is a measurement (TC 6.4): calls spent and every throttle seen, per run.
    result['calls'] = getattr(backend, 'calls', None) if backend is not None else 0
    result['throttles'] = list(getattr(backend, 'throttles', None) or [])
    if result['backend'] is None:
        causes.append(backend_note or 'no ticket backend is configured')
    if result['outcomes'].get(BINDING_UNESTABLISHED):
        causes.append('%d lookup(s) did not complete (%s)'
                      % (result['outcomes'][BINDING_UNESTABLISHED], BINDING_UNESTABLISHED))
    if (result.get('shape') or {}).get('established') is False:
        causes.append('run-start validation failed: %s' % result['shape']['detail'])
    if result.get('create_failed'):
        causes.append('%d creation(s) failed, so their obligations are carried untracked'
                      % result['create_failed'])
    if result.get('update_unestablished'):
        causes.append('%d ticket description(s) could not be read, so their update was withheld '
                      'rather than written blind (%s)' % (result['update_unestablished'],
                                                         BINDING_UNESTABLISHED))
    if result.get('update_failed'):
        causes.append('%d ticket update(s) failed, so those tickets do not show what changed'
                      % result['update_failed'])
    if result['clusters'] == 0 and result['outcomes'].get(IDENTITY_NOT_ESTABLISHED):
        causes.append('every finding was withheld (%s): nothing could be keyed, so nothing could '
                      'be tracked' % IDENTITY_NOT_ESTABLISHED)
    if causes:
        claim = {'routing_result': EVIDENCE_UNTRUSTED, 'publication_state': PUBLICATION_DEGRADED,
                 'causes': causes}
    elif result['needs_decision'] or result['refused_disposition'] or result['past_due']:
        claim = {'routing_result': DECISION_REQUIRED, 'causes': ['a decision is owed to a person']}
    else:
        claim = {'routing_result': PROCEED, 'causes': []}
    result['ticketing_claim'] = claim
    return result


def reconcile(clusters, withheld, backend, ledger, apply_changes, approval=None, today=None,
              backend_note=''):
    """-> result dict. Routine reconciliation runs UNATTENDED under `apply_changes` alone.

    THE CORRECTION THIS FUNCTION CARRIES, NAMED.

        Its first draft demanded an approval before it would create ANY ticket, because the
        engine the work-item model came from held "every mutation requires explicit human
        approval" as a numbered invariant. Applied to a reconciler that is the whole point --
        deterministic, idempotent, evidence-backed, auditable -- a blanket gate is not a control.
        It is an off switch, and a reconciler nobody runs reconciles nothing.

        So creation, update, linking and re-sync are ROUTINE_RECONCILIATION and they run with
        `--apply` and NO approver. `--apply` remains a real gate: it is the operator (or the
        policy that scheduled the run) intending writes this run rather than a plan.

        APPROVAL IS FOR DISPOSITIONS. A finding carrying `requested_disposition` -- an exception,
        an exclusion, a false-positive call, a risk acceptance, a compensating control accepted
        instead of a fix, a budget commitment, a posture change -- is a judgement about what the
        organisation accepts, and it is refused without a role and a readable reason. The refusal
        is REPORTED AS ITS OWN OUTCOME, never folded into the dry-run path.

        Which mutation is which is not decided here. `ticket_model.classify_mutation` states it row
        by row, and `ticket_model.authorise` is the single enforcement point; a mutation absent
        from that table refuses rather than defaulting either way.

    `today` is the reference date for the past-due deferral sweep. Absent, the sweep reports
    DEFERRAL_TERM_UNKNOWN rather than silence -- a run that did not establish today established
    nothing about whether an acceptance is still in force.
    """
    result = {
        'backend': backend.name if backend else None,
        'apply': bool(apply_changes),
        'approval': approval.state() if approval is not None else 'NOT SUPPLIED',
        'outcomes': {},
        'created': [],
        'updated': [],
        'withheld_no_identity': [],
        'needs_decision': [],
        # Dispositions this run was asked for and REFUSED for want of an approver. Its own key,
        # because "nobody approved this judgement" is not "the operator asked for a plan" and is
        # not "this cluster is ambiguous".
        'refused_disposition': [],
        'applied_disposition': [],
        # Deferrals whose term has elapsed or cannot be established. Reported unasked.
        'past_due': [],
        # Clusters that owe a ticket this run could not establish: carried, with the cause, so
        # the next run acts on them without re-deriving anything (TC 4.1 step 3).
        'obligations': [],
        'reopened': [],
        'successors': [],
        # Clusters owing a ticket past the per-run creation ceiling, in queue order (TC 6.5).
        'carried': [],
        # Correlation proposals (an alias chain, CWE-plus-path): recorded for a human, never
        # applied -- each member acts on its own (ETFB 9.4).
        'proposals': list(getattr(clusters, 'proposals', None) or []),
        'ticketing_claim': None,
        'tickets': [],
        'compliance': {},
        'confidence': {},
        'sweep_complete': None,
        'probe': None,
        'clusters': len(clusters),
        'today': today,
        'notes': [],
    }

    # ── THE PAST-DUE DEFERRAL SWEEP, BEFORE ANYTHING ELSE AND WITHOUT BEING ASKED. ──
    #
    # It runs over the WHOLE LEDGER rather than only this run's clusters, deliberately. A finding
    # that stopped being reported -- fixed, or no longer scanned -- still has a deferral record,
    # and a past-due acceptance must not become invisible because the scanner went quiet. It also
    # runs before the backend check, so an unconfigured tracker does not take the review
    # obligation down with it.
    result['past_due'] = sweep_past_due(ledger, today)
    if result['past_due']:
        result['outcomes'][tm.DEFERRAL_PAST_DUE] = sum(
            1 for p in result['past_due'] if p['state'] == tm.DEFERRAL_PAST_DUE)
        unknown = sum(1 for p in result['past_due'] if p['state'] == tm.DEFERRAL_TERM_UNKNOWN)
        if unknown:
            result['outcomes'][tm.DEFERRAL_TERM_UNKNOWN] = unknown

    # THE WITHHELD FINDINGS, FIRST AND VISIBLY. They are reported before anything else happens, so
    # that a run which withholds everything cannot read as a run with nothing to do.
    for rec, outcome, reason in withheld:
        result['withheld_no_identity'].append({
            'scanner': rec.get('scanner'), 'rule': rec.get('rule'),
            'uri': rec.get('uri'), 'outcome': outcome, 'reason': reason,
        })
    result['outcomes'][IDENTITY_NOT_ESTABLISHED] = len(withheld)

    if backend is None:
        result['notes'].append(
            'THE CONTROL IS OFF: no backend configured. No lookup was attempted and no ticket was '
            'created. This is not "no tickets were needed" -- nothing was checked.')
        for c in clusters:
            result['obligations'].append({'cluster_key': c['cluster_key'],
                                          'outcome': BINDING_UNESTABLISHED,
                                          'cause': backend_note or 'no backend configured'})
        return finish_claim(result, backend_note, backend)

    # RUN START: the site's shape, before any read that could lead to a write (J-7).
    if hasattr(backend, 'validate'):
        shape_ok, shape_detail = backend.validate()
        result['shape'] = {'established': bool(shape_ok), 'detail': shape_detail}
        if not shape_ok:
            result['notes'].append('RUN-START VALIDATION FAILED: %s. Nothing was created or '
                                   'updated; every obligation is carried.' % shape_detail)
            for c in clusters:
                result['obligations'].append({'cluster_key': c['cluster_key'],
                                              'outcome': BINDING_UNESTABLISHED,
                                              'cause': 'run-start validation: %s' % shape_detail})
            return finish_claim(result, backend_note, backend)

    observable, probe_detail = backend.probe()
    result['probe'] = {'observable': bool(observable), 'detail': probe_detail,
                       'state': DISTINCTION_OBSERVABLE if observable
                       else DISTINCTION_NOT_OBSERVABLE}

    # The ledger's references go with the sweep: on Jira they buy read-after-write consistency
    # for exactly the set where a false absence costs most (J-5). Other backends ignore them.
    known_refs = sorted(set(str(e.get('ref')) for e in (ledger or {}).values()
                            if isinstance(e, dict) and e.get('ref')))
    sweep_map, sweep_complete, sweep_detail = backend.sweep(known_refs=known_refs)
    result['sweep_complete'] = bool(sweep_complete)
    result['notes'].append('sweep: %s' % sweep_detail)
    if not sweep_complete:
        result['notes'].append(
            'THE SWEEP IS PARTIAL. Every count taken from it is a FLOOR and never a total, and no '
            'creation may follow a miss in it. The ticketing claim for this run is %s and routes '
            '%s; the findings route exactly as their rung says -- a ticketing failure does not '
            'soften a finding.' % (PUBLICATION_DEGRADED, EVIDENCE_UNTRUSTED))

    # The stamp, once set, does not move when membership does (T2). Before classification.
    rebind(clusters, identity_bindings(ledger, sweep_map))

    # CONSEQUENCE ORDER (TC 6.5): the most severe first, so a creation ceiling delays the cheapest
    # work rather than the most urgent. Stable, so equal severities keep discovery order.
    clusters = sorted(clusters, key=lambda c: _SEV_ORDER.index(c['severity'])
                      if c.get('severity') in _SEV_ORDER else len(_SEV_ORDER))
    ceiling = getattr(backend, 'create_ceiling', None)

    for n, cluster in enumerate(clusters, 1):
        outcome, refs, detail = classify(cluster, ledger, sweep_map, sweep_complete, observable)
        result['outcomes'][outcome] = result['outcomes'].get(outcome, 0) + 1

        if outcome == BINDING_UNESTABLISHED:
            # CREATE NOTHING, CLEAR NOTHING, RECORD THE OBLIGATION WITH ITS CAUSE (TC 4.1). The
            # existing mapping is untouched; the debt is added beside it.
            result['obligations'].append({'cluster_key': cluster['cluster_key'],
                                          'outcome': outcome, 'cause': detail})
            if apply_changes:
                note_degraded(result, backend, cluster['cluster_key'], carry_owed(
                    ledger, cluster['cluster_key'], outcome, detail, today))

        # ── THE DISPOSITION GATE. Checked per cluster, before anything is written. ──
        #
        # A cluster carrying a requested disposition is a JUDGEMENT this run is being asked to
        # act on, and it is the one thing here that needs a person. The gate is
        # `ticket_model.authorise` -- the same single enforcement point the model's own
        # transitions use -- so a disposition cannot reach the tracker through this file by a
        # route the model has not classified.
        ticket_class = DEFAULT_CLASS
        blocked_by_disposition = False
        for word in cluster.get('requested_dispositions') or []:
            mutation, requested_class = DISPOSITION_REQUESTS.get(
                word, ('disposition.%s' % word, DEFAULT_CLASS))
            gate = tm.authorise(mutation, approval)
            if gate:
                blocked_by_disposition = True
                result['refused_disposition'].append({
                    'cluster_key': cluster['cluster_key'], 'requested': word,
                    'mutation': mutation, 'reason': gate})
                print('  [%d/%d] %-24s %s (REFUSED: %s needs an approver)'
                      % (n, len(clusters), outcome, cluster['cluster_key'][:12], word),
                      file=sys.stderr)
            else:
                ticket_class = requested_class
                result['applied_disposition'].append({
                    'cluster_key': cluster['cluster_key'], 'requested': word,
                    'mutation': mutation, 'ticket_class': requested_class,
                    'approved_by': approval.actor if approval is not None else '',
                    'approval_reason': approval.reason if approval is not None else ''})
        if blocked_by_disposition:
            # NOTHING IS WRITTEN FOR THIS CLUSTER. Not the routine half either: creating the
            # ticket as ordinary remediation work while the request half was refused would put a
            # REMEDIATION_WORK_ITEM in the tracker for a finding somebody asked to have excepted,
            # and the asking would vanish. The whole cluster waits for the approver.
            continue
        cluster['ticket_class'] = ticket_class

        # A PROPOSED CLUSTER NEVER GETS A TICKET. `tests/check_stage_phase.py` declares the
        # boundary: "no ticket may be created from an unanchored cluster". Nothing in this file
        # produces a proposed cluster today -- clustering is anchored-only -- and the branch exists
        # so that a future heuristic tier cannot reach creation by being added upstream.
        if cluster['tier'] == TIER_PROPOSED:
            result['needs_decision'].append({
                'cluster_key': cluster['cluster_key'], 'outcome': outcome,
                'detail': 'cluster tier is %s; a human confirms or splits before it is ticketed'
                          % TIER_PROPOSED})
            print('  [%d/%d] %-24s %s (proposed tier -- not ticketed)'
                  % (n, len(clusters), outcome, cluster['cluster_key'][:12]), file=sys.stderr)
            continue

        if outcome == BINDING_ABSENT:
            # THE PARENT AND ITS CHILDREN ARE BUILT WHETHER OR NOT ANYTHING IS WRITTEN. Building
            # is not mutating: the plan is what a reviewer reads before approving, and a dry run
            # that could not show the child tasks would be asking for approval of something
            # nobody can see.
            cluster['title'] = render_title(cluster)
            ticket, tasks = tm.build_ticket(
                cluster, 'ticket-%s' % cluster['cluster_key'][:12],
                channel_degraded=not sweep_complete)
            result['tickets'].append({'ticket': ticket.as_dict(),
                                      'tasks': [t.as_dict() for t in tasks],
                                      'progress': tm.compute_progress(tasks)})
            result['compliance'][ticket.compliance_review] = \
                result['compliance'].get(ticket.compliance_review, 0) + 1
            result['confidence'][ticket.confidence] = \
                result['confidence'].get(ticket.confidence, 0) + 1

            title, body = ticket.title, render_body(cluster, ticket=ticket, tasks=tasks)

            # THE CREATION GATE, AND IT IS THE CLASSIFIER RATHER THAN A PERSON. `ticket.create`
            # is ROUTINE_RECONCILIATION in the mutation-class table: a fingerprinted,
            # anchored cluster that a scanner observed is WORK, opening a work item for it
            # asserts nothing about what the organisation accepts, and it is reversible. So this
            # returns '' with no approver and the creation proceeds unattended.
            #
            # IT IS STILL A GATE. A mutation name absent from the table refuses here, which is
            # what stops a future author reaching the tracker by inventing a call site.
            gate = tm.authorise('ticket.create', approval)
            if apply_changes and gate:
                result['needs_decision'].append({
                    'cluster_key': cluster['cluster_key'], 'outcome': outcome, 'detail': gate,
                    'candidates': []})
                print('  [%d/%d] %-24s %s (REFUSED: %s)'
                      % (n, len(clusters), outcome, cluster['cluster_key'][:12], gate[:40]),
                      file=sys.stderr)
                continue

            if apply_changes and ceiling is not None and \
                    sum(1 for c in result['created'] if c.get('ref')) >= int(ceiling):
                # THE PER-RUN CREATION CEILING (TC 6.5). Carried, not dropped, with its position
                # in the queue: a truncated batch reported as a completed one is the same lie as
                # a truncated scan reported as clean. It never softens the finding's routing.
                pos = len(result['carried']) + 1
                result['carried'].append({'cluster_key': cluster['cluster_key'],
                                          'severity': cluster['severity'], 'position': pos})
                result['obligations'].append({
                    'cluster_key': cluster['cluster_key'], 'outcome': outcome,
                    'cause': 'creation ceiling %s reached; carried at position %d'
                             % (ceiling, pos)})
                continue

            if apply_changes:
                ref, detail2 = backend.create(cluster, body, title)
                if ref:
                    result['created'].append({'cluster_key': cluster['cluster_key'], 'ref': ref,
                                              'title': title,
                                              'children': len(tasks),
                                              'ticket_class': ticket_class,
                                              'compliance_review': ticket.compliance_review,
                                              'confidence': ticket.confidence})
                    ledger[cluster['cluster_key']] = {
                        'ref': ref, 'backend': backend.name,
                        'member_identities': cluster['member_identities'],
                        'child_task_ids': ticket.child_task_ids,
                        'ticket_class': ticket_class,
                        'compliance_review': ticket.compliance_review,
                        'confidence': ticket.confidence,
                        # Deferrals already recorded for this cluster survive a re-bind. Dropping
                        # them would clear a past-due review obligation by rewriting the ledger,
                        # which is the silent-suppression defect arriving through bookkeeping.
                        'deferrals': (ledger.get(cluster['cluster_key']) or {}).get(
                            'deferrals') or {},
                        # What the block says, so the next run's delta costs nothing (T-13).
                        'rendered': rendered_facts(cluster),
                        'last_seen': today}
                    # TIER -1: one instance per observation, under the tier-0 item, up to the
                    # owner's per-class threshold; above it the class carries a COUNT, recorded
                    # rather than dropped (TICKETING_BACKENDS.md 2; J-8). `ticket.child_link`.
                    if not tm.authorise('ticket.child_link', approval):
                        inst = {}
                        limit = max(0, int(getattr(backend, 'instance_threshold', 0) or 0))
                        for m in cluster['members'][:limit]:
                            i_ref, i_d = backend.create_instance(
                                ref, m, instance_body(ref, m), instance_title(cluster, m))
                            if i_ref:
                                inst[m['identity']] = i_ref
                            else:
                                result['notes'].append('instance not itemised under %s: %s'
                                                       % (ref, i_d))
                        entry_i = ledger[cluster['cluster_key']]
                        entry_i['instances'] = inst
                        entry_i['instances_not_itemised'] = len(cluster['members']) - len(inst)
                else:
                    # NOT A NOTE: an obligation that owes a ticket the run could not write. It is
                    # carried with its cause and it makes the claim untrusted (TC 4.1).
                    result['notes'].append('create failed for %s: %s'
                                           % (cluster['cluster_key'][:12], detail2))
                    result['create_failed'] = result.get('create_failed', 0) + 1
                    result['obligations'].append({'cluster_key': cluster['cluster_key'],
                                                  'outcome': outcome,
                                                  'cause': 'create failed: %s' % detail2})
                    # Carried in the ledger too, with its streak (TC 4.1 step 3; T-06).
                    note_degraded(result, backend, cluster['cluster_key'], carry_owed(
                        ledger, cluster['cluster_key'], outcome,
                        'create failed: %s' % detail2, today))
            else:
                result['created'].append({'cluster_key': cluster['cluster_key'], 'ref': None,
                                          'title': title, 'planned': True,
                                          'children': len(tasks),
                                          'ticket_class': ticket_class,
                                          'compliance_review': ticket.compliance_review,
                                          'confidence': ticket.confidence})

        elif outcome in (LEDGER_BOUND, BACKEND_BOUND):
            # The steady state. Nothing is read or written unless something in the updatable set
            # changed (TC 6.1; T-13, below). Commenting on every ticket every run is the noise
            # this whole file exists to avoid.
            hit = refs[0] if refs else {}
            entry = ledger.get(cluster['cluster_key']) if isinstance(
                ledger.get(cluster['cluster_key']), dict) else {}
            known = set(entry.get('member_identities') or []) | identities_from_body(
                hit.get('body') or '')
            # Members a previous run could NOT write to the ticket are not known to it yet.
            known -= set((entry.get('owed') or {}).get('update_owed') or [])
            current = set(cluster['member_identities'])
            if outcome == BACKEND_BOUND:
                result['updated'].append({'cluster_key': cluster['cluster_key'],
                                          'ref': hit.get('ref'),
                                          'repair': 'ledger owes an entry for this ticket'})
            if apply_changes and not tm.authorise('ledger.bind', approval):
                # The binding is the idempotency itself (`ledger.bind`, routine). Membership is
                # APPEND-ONLY here: a member that left is POTENTIALLY_ABSENT, not forgotten, so a
                # later run that sees it again still finds this obligation.
                entry = dict(entry)
                entry.setdefault('ref', hit.get('ref'))
                entry.setdefault('backend', backend.name)
                entry['member_identities'] = sorted(known | current)
                # THE LOOKUP ESTABLISHED THE BINDING, so a lookup this entry was owed is
                # discharged and the degraded streak ends (T-06). An owed UPDATE is not: it
                # clears only when that update is written.
                if isinstance(entry.get('owed'), dict) and \
                        entry['owed'].get('update_owed') is None:
                    entry.pop('owed')
                ledger[cluster['cluster_key']] = entry
            # THE DELTA (TC 5.1, 6.1; T-13). What the block last said, from the ledger for free:
            # effective severity, the contributing scanners, those that STOPPED (named, never
            # omitted) and members not observed this run (POTENTIALLY_ABSENT, never "fixed").
            # Membership is append-only, so a member that left is still listed.
            cur_scanners = set(cluster['scanners'])
            rendered = entry.get('rendered') if isinstance(entry.get('rendered'), dict) else None

            def facts_wanted(prev_scanners, known_ids):
                return {'severity': cluster['severity'], 'scanners': sorted(cur_scanners),
                        'stopped': sorted(set(prev_scanners) - cur_scanners),
                        'absent': sorted(set(known_ids) - current)}
            if rendered is None:
                # NOT RECORDED is not UNCHANGED: the ledger never saw this ticket's block (a
                # ledger that is not persisted, T-20, or a ticket an older run wrote). Read it.
                facts_changed = True
            else:
                facts_changed = facts_wanted(
                    set(rendered.get('scanners') or []) | set(rendered.get('stopped') or []),
                    known) != dict((k, rendered.get(k)) for k in (
                        'severity', 'scanners', 'stopped', 'absent'))
            members_added = False
            if not current <= known and hit.get('ref'):
                # MEMBERS ADDED: an allowed update (TICKETING_CONTRACT.md 5.1).
                members_added = True
            desc, read_ok, d_read, intact, changed = None, False, '', True, []
            if (members_added or facts_changed) and hit.get('ref'):
                # One block rewrite when something in the 5.1 set changed, never a comment per
                # run -- and NOTHING when nothing did (TC 6.1: no read, no write).
                #
                # READ THE DESCRIPTION FIRST, IN FULL (T-02). The sweep's copy of the body is empty
                # on Jira and Azure DevOps by design, and rendering the block against it replaced
                # the whole description -- every sentence a person wrote outside the delimiters.
                # Only the block is replaced; a description that cannot be read is not written.
                desc, read_ok, d_read = backend.read_description(hit['ref'])
                if not read_ok:
                    cause = ('the description of ticket %s could not be read (%s), so its '
                             'block update was NOT written: writing blind would replace '
                             'whatever a person wrote outside the block (TC 5.4)'
                             % (hit['ref'], d_read))
                    result['obligations'].append({'cluster_key': cluster['cluster_key'],
                                                  'outcome': BINDING_UNESTABLISHED,
                                                  'cause': cause})
                    result['update_unestablished'] = result.get('update_unestablished', 0) + 1
                    result['notes'].append(cause)
                    if apply_changes:
                        # Owed to the next run: these members are NOT on the ticket yet, so they
                        # must not read as known when the next run compares (TC 4.1 step 3).
                        note_degraded(result, backend, cluster['cluster_key'], carry_owed(
                            ledger, cluster['cluster_key'], BINDING_UNESTABLISHED, cause, today,
                            update_owed=sorted(current - known)))
                else:
                    # What the ticket itself already says counts: a block that already names
                    # every member and states every current fact owes no write.
                    text = backend.description_text(desc)
                    known |= identities_from_body(text)
                    on_ticket = block_facts(text)
                    want = facts_wanted(
                        set(on_ticket['scanners']) | set(on_ticket['stopped'])
                        | set((rendered or {}).get('scanners') or [])
                        | set((rendered or {}).get('stopped') or []), known)
                    changed = [k for k in ('severity', 'scanners', 'stopped', 'absent')
                               if on_ticket[k] != want[k]]
                    if current <= known and not changed and apply_changes:
                        # The ticket is already right. Record that, so the next run is free.
                        entry_r = dict(ledger.get(cluster['cluster_key']) or {})
                        entry_r['rendered'] = want
                        ledger[cluster['cluster_key']] = entry_r
                if read_ok and (not current <= known or changed):
                    shown = dict(cluster, member_identities=sorted(known | current),
                                 scanners_stopped=want['stopped'], members_absent=want['absent'],
                                 last_seen=today)
                    new_desc, intact = backend.splice_description(desc, render_body(shown))
                    if not intact:
                        result['notes'].append(
                            'ticket %s: the machine-owned block\'s delimiters are missing or '
                            'damaged, so the block was RE-APPENDED and nothing outside it was '
                            'replaced (TC 5.4)' % hit['ref'])
                    if apply_changes and not tm.authorise('ticket.body_resync', approval):
                        ok, d_up = backend.write_description(hit['ref'], new_desc, desc)
                        if not ok:
                            result['notes'].append('membership update failed for %s: %s'
                                                   % (cluster['cluster_key'][:12], d_up))
                            result['update_failed'] = result.get('update_failed', 0) + 1
                            result['obligations'].append({
                                'cluster_key': cluster['cluster_key'], 'outcome': outcome,
                                'cause': 'members-added update of ticket %s failed: %s'
                                         % (hit['ref'], d_up)})
                            note_degraded(result, backend, cluster['cluster_key'], carry_owed(
                                ledger, cluster['cluster_key'], outcome,
                                'members-added update failed: %s' % d_up, today,
                                update_owed=sorted(current - known)))
                        else:
                            entry_w = dict(ledger.get(cluster['cluster_key']) or {})
                            # What the block now says: the next run's delta source (TC 6.1).
                            entry_w['rendered'] = want
                            if (entry_w.get('owed') or {}).get('update_owed') is not None:
                                # The update this entry owed has now been written.
                                entry_w.pop('owed', None)
                            ledger[cluster['cluster_key']] = entry_w
                    result['updated'].append({'cluster_key': cluster['cluster_key'],
                                              'ref': hit['ref'], 'planned': not apply_changes,
                                              'membership_added': sorted(current - known),
                                              'changed': changed + (
                                                  ['members'] if not current <= known else []),
                                              'block_intact': intact})
            if apply_changes and isinstance(ledger.get(cluster['cluster_key']), dict):
                # LAST-SEEN goes to the LEDGER every run, which costs nothing; to the ticket only
                # when something else is being written (TC 6.1).
                ledger[cluster['cluster_key']]['last_seen'] = today

            # A CLOSED TICKET BESIDE A FINDING THE SCANNER STILL REPRODUCES (TC 4.2; J-6, T-7).
            if hit.get('state') == 'closed' and hit.get('ref'):
                backing = closure_backing(cluster, today)
                if backing == 'backed':
                    # An unexpired approved disposition stands: the ticket STAYS closed. Reopening
                    # it every run teaches the team the bridge is broken (TC 5.2).
                    pass
                elif backing == 'unknown':
                    result['notes'].append(
                        'ticket %s is closed and an approved disposition exists whose expiry '
                        'could not be compared to the reference date; it was neither reopened '
                        'nor left as authorised -- supply --today' % hit['ref'])
                elif not apply_changes:
                    result['reopened'].append({
                        'cluster_key': cluster['cluster_key'], 'ref': hit['ref'], 'planned': True,
                        'classification': reopen_classification(cluster, today)})
                elif not tm.authorise('ticket.reopen', approval):
                    # T-08: WHY it is reopened travels with the reopen -- in the run record, the
                    # ledger's append-only history, and one comment on the ticket (TC 4.2, 5.1).
                    cls_r = reopen_classification(cluster, today)
                    ok_r, why = backend.reopen(hit['ref'])
                    if ok_r:
                        result['reopened'].append({'cluster_key': cluster['cluster_key'],
                                                   'ref': hit['ref'], 'detail': why,
                                                   'classification': cls_r})
                        ok_c, d_c = backend.comment(hit['ref'], reopen_comment(cls_r, today))
                        if not ok_c:
                            result['notes'].append('ticket %s was reopened (%s) but the comment '
                                                   'saying why failed: %s' % (hit['ref'], cls_r,
                                                                              d_c))
                        entry = dict(ledger.get(cluster['cluster_key']) or {})
                        entry['reopens'] = list(entry.get('reopens') or []) + [{
                            'ref': str(hit['ref']), 'classification': cls_r, 'on': today,
                            'commented': bool(ok_c)}]
                        ledger[cluster['cluster_key']] = entry
                    elif not tm.authorise('ticket.successor', approval):
                        # REOPEN REFUSED: a SUCCESSOR that references the predecessor; the
                        # predecessor is kept in the ledger history with the reason (TC 4.2).
                        succ = dict(cluster, predecessor=hit['ref'], reopen_refused=why,
                                    reopen_classification=cls_r)
                        succ['title'] = render_title(cluster)
                        ref_s, d_s = backend.create(succ, render_body(succ), succ['title'])
                        if ref_s:
                            entry = dict(ledger.get(cluster['cluster_key']) or {})
                            entry['predecessors'] = sorted(set(
                                [str(p) for p in entry.get('predecessors') or []]
                                + [str(hit['ref'])]))
                            entry['ref'] = ref_s
                            entry['reopen_refused'] = why
                            entry['member_identities'] = sorted(known | current)
                            entry['rendered'] = rendered_facts(succ)
                            entry.setdefault('backend', backend.name)
                            entry['reopens'] = list(entry.get('reopens') or []) + [{
                                'ref': str(hit['ref']), 'classification': cls_r, 'on': today,
                                'successor': ref_s}]
                            ledger[cluster['cluster_key']] = entry
                            result['successors'].append({
                                'cluster_key': cluster['cluster_key'], 'ref': ref_s,
                                'predecessor': hit['ref'], 'reason': why,
                                'classification': cls_r})
                        else:
                            result['create_failed'] = result.get('create_failed', 0) + 1
                            result['obligations'].append({
                                'cluster_key': cluster['cluster_key'], 'outcome': outcome,
                                'cause': 'reopen refused (%s) and successor create failed: %s'
                                         % (why, d_s)})

        elif outcome in (BINDING_AMBIGUOUS, BINDING_DANGLING):
            result['needs_decision'].append({
                'cluster_key': cluster['cluster_key'], 'outcome': outcome, 'detail': detail,
                'candidates': [r.get('ref') for r in refs]})

        # Heartbeat, per iteration.
        print('  [%d/%d] %-24s %s' % (n, len(clusters), outcome, cluster['cluster_key'][:12]),
              file=sys.stderr)

    return finish_claim(result, backend_note, backend)


# ═════════════════════════════════════════════════════════════════════════════════════
# CONFIGURATION
# ═════════════════════════════════════════════════════════════════════════════════════

ENV_BACKEND = 'TICKET_BACKEND'
ENV_STAMP_LABEL = 'TICKET_STAMP_LABEL'
ENV_REPO = 'TICKET_REPO'
ENV_JIRA_FIELD = 'JIRA_STAMP_FIELD'


def https_origin_problem(name, value):
    """-> '' when `value` is an https origin with no credentials, path, query or fragment, else
    why not, naming the variable (TICKETING_BACKENDS.md 3.1/4.1). A URL carrying a user and
    password would put a credential in every request line and every log of it."""
    import urllib.parse
    v = (value or '').strip()
    try:
        u = urllib.parse.urlsplit(v)
    except ValueError:
        return '%s is not a URL' % name
    if u.scheme != 'https':
        return '%s must be an https URL' % name
    if not u.hostname or '@' in u.netloc:
        return '%s must be a host with no credentials in it' % name
    if u.path not in ('', '/') or u.query or u.fragment:
        return '%s must have no path, query or fragment' % name
    return ''


def common_config_problem(env):
    """Values every tracker backend shares, refused by name (T-11)."""
    label = env.get(ENV_STAMP_LABEL) or ''
    if label and (label != label.strip() or any(ch.isspace() for ch in label)):
        # TC 11.2: Jira does not reliably refuse a label with a space; validate client-side.
        return '%s %r contains whitespace; the umbrella stamp must be one token' % (
            ENV_STAMP_LABEL, label)
    ceiling = (env.get('TICKET_CREATE_CEILING') or '').strip()
    if not ceiling.isdigit() or int(ceiling) < 1:
        return ('TICKET_CREATE_CEILING is %s; it must be a positive integer from the policy file. '
                'No default exists in code (TC 11.4)' % (repr(ceiling) if ceiling else 'unset'))
    return ''


def jira_config_problem(env):
    import re
    bad = https_origin_problem('JIRA_HOST', env.get('JIRA_HOST'))
    if bad:
        return bad
    if not re.match(r'^customfield_\d+$', (env.get(ENV_JIRA_FIELD) or '').strip()):
        return ('%s must be customfield_<numeric id> of a single-line text field provisioned '
                'once by a human' % ENV_JIRA_FIELD)
    if not (env.get('JIRA_EPIC_ID') or '').strip().isdigit():
        return 'JIRA_EPIC_ID must be the NUMERIC id of the product epic (the key moves)'
    cal = (env.get('JIRA_CALIBRATION_ISSUE') or '').strip()
    if cal and not cal.isdigit():
        return 'JIRA_CALIBRATION_ISSUE must be a NUMERIC issue id'
    return common_config_problem(env)


def azdo_config_problem(env, org_url):
    """TICKETING_BACKENDS.md 4.1, refused by name. Both organisation forms are accepted:
    `https://dev.azure.com/<org>` (exactly one path segment) and the legacy
    `https://<org>.visualstudio.com` (no path). Anything else is not an organisation URL."""
    import re
    import urllib.parse
    v = (org_url or '').strip().rstrip('/')
    u = urllib.parse.urlsplit(v) if v else None
    if not u or u.scheme != 'https' or '@' in u.netloc or u.query or u.fragment:
        return 'AZDO_ORG_URL must be an https organisation URL with no credentials in it'
    host = (u.hostname or '').lower()
    segs = [s for s in u.path.split('/') if s]
    if host == 'dev.azure.com':
        if len(segs) != 1:
            return ('AZDO_ORG_URL must be https://dev.azure.com/<org> -- exactly one path segment, '
                    'the organisation (got %d)' % len(segs))
    elif host.endswith('.visualstudio.com') and host.count('.') == 2:
        if segs:
            return 'AZDO_ORG_URL in the legacy form must be https://<org>.visualstudio.com, no path'
    else:
        return ('AZDO_ORG_URL must be https://dev.azure.com/<org> or the legacy '
                'https://<org>.visualstudio.com')
    if not re.match(r'^[A-Za-z][A-Za-z0-9_]*(\.[A-Za-z0-9_]+)+$',
                    (env.get('AZDO_STAMP_FIELD') or '').strip()):
        return ('AZDO_STAMP_FIELD must be a field REFERENCE name such as Custom.KitClusterKey, '
                'added once by a human in an inherited process')
    if not (env.get('AZDO_EPIC_ID') or '').strip().isdigit():
        return 'AZDO_EPIC_ID must be the numeric work item id of the product epic'
    cal = (env.get('AZDO_CALIBRATION_ITEM') or '').strip()
    if cal and not cal.isdigit():
        return 'AZDO_CALIBRATION_ITEM must be a numeric work item id'
    return common_config_problem(env)


def choose_backend(env=None):
    """-> (backend or None, note). Credentials are read from the environment and nowhere else.

    No token is ever written to a file, a summary, a ledger or a log. They are read here, held on
    the backend instance, and used only as a request header.
    """
    env = env if env is not None else os.environ
    want = (env.get(ENV_BACKEND) or '').strip().lower()

    gh_ready = bool(env.get('GH_TOKEN') or env.get('GITHUB_TOKEN')) and bool(env.get(ENV_REPO))
    jira_ready = all(bool(env.get(k)) for k in ('JIRA_HOST', 'JIRA_EMAIL', 'JIRA_TOKEN',
                                                'JIRA_PROJECT'))
    azdo_org = (env.get('AZDO_ORG_URL') or env.get('AZDO_ORG') or '').strip()
    azdo_ready = bool(azdo_org) and bool(env.get('AZDO_PAT')) and bool(env.get('AZDO_PROJECT'))
    ready = [n for n, r in (('github', gh_ready), ('jira', jira_ready), ('azdo', azdo_ready)) if r]

    # TWO BACKENDS CONFIGURED AT ONCE IS A CONFIGURATION DEFECT, refused by name (TC 4.6; C-2).
    # Not "create in both"; not "prefer whichever is listed first" -- and, since KDEC-004, not
    # "whichever TICKET_BACKEND names" either: a run that HOLDS a second tracker's credential is
    # one edit away from writing to it, and the contract makes one backend authoritative per
    # cell. The dated migration case (TC 4.6) is a policy-file event, not an ambient credential.
    if len(ready) > 1:
        return None, ('CONFIGURATION DEFECT: %s credentials are all configured in this run. '
                      'Exactly one backend is authoritative per repository and environment, so '
                      'the run must hold exactly one tracker credential (%s=%s).'
                      % (' and '.join(ready), ENV_BACKEND, want or 'unset'))

    if not want:
        if ready:
            want = ready[0]
        else:
            return None, ('no ticket backend configured: %s is unset and no complete credential '
                          'set is present' % ENV_BACKEND)

    raw_ceiling = (env.get('TICKET_RETRY_CEILING') or '').strip()
    if raw_ceiling and not raw_ceiling.isdigit():
        return None, ('TICKET_RETRY_CEILING is %r; it must be a non-negative integer (the owner '
                      'sets it in the policy file; unset means no retries)' % raw_ceiling)
    retry_ceiling = int(raw_ceiling or 0)
    raw_threshold = (env.get('TICKET_INSTANCE_THRESHOLD') or '').strip()
    if raw_threshold and not raw_threshold.isdigit():
        return None, ('TICKET_INSTANCE_THRESHOLD is %r; it must be a non-negative integer (unset '
                      'means no instances are itemised and the class carries a count)'
                      % raw_threshold)
    instance_threshold = int(raw_threshold or 0)
    raw_degraded = (env.get('TICKET_DEGRADED_RUN_THRESHOLD') or '').strip()
    if raw_degraded and not raw_degraded.isdigit():
        return None, ('TICKET_DEGRADED_RUN_THRESHOLD is %r; it must be a non-negative integer '
                      '(unset means degraded runs are counted and never escalated)'
                      % raw_degraded)
    degraded_threshold = int(raw_degraded or 0)
    built = _build_backend(want, env, gh_ready, jira_ready, azdo_ready, azdo_org, retry_ceiling,
                           instance_threshold)
    if built[0] is not None:
        built[0].degraded_threshold = degraded_threshold
    return built


def _build_backend(want, env, gh_ready, jira_ready, azdo_ready, azdo_org, retry_ceiling,
                   instance_threshold):
    """choose_backend's construction half: one backend, or (None, why)."""
    if want == 'github':
        if not gh_ready:
            return None, ('%s names github, and either the credential or %s is missing'
                          % (ENV_BACKEND, ENV_REPO))
        label = (env.get(ENV_STAMP_LABEL) or '').strip()
        if not label:
            # The umbrella stamp is provisioned once, by a human. Inventing one here would make the
            # sweep look at a label nothing carries and report every cluster as absent.
            return None, ('%s is unset. The umbrella stamp is provisioned once by a human; a label '
                          'this program invented would make every sweep find nothing and every '
                          'cluster look absent.' % ENV_STAMP_LABEL)
        return GitHubIssues(env.get(ENV_REPO), env.get('GH_TOKEN') or env.get('GITHUB_TOKEN'),
                            label, calibration=env.get('TICKET_CALIBRATION_REF') or '',
                            retry_ceiling=retry_ceiling), \
            'github backend configured'

    if want == 'jira':
        if not jira_ready:
            return None, '%s names jira, and the credential set is incomplete' % ENV_BACKEND
        bad = jira_config_problem(env)
        if bad:
            return None, 'CONFIGURATION REFUSED: %s' % bad
        jb = Jira(env.get('JIRA_HOST'), env.get('JIRA_EMAIL'), env.get('JIRA_TOKEN'),
                  env.get('JIRA_PROJECT'), (env.get(ENV_JIRA_FIELD) or '').strip(),
                  calibration=env.get('JIRA_CALIBRATION_ISSUE') or '',
                  retry_ceiling=retry_ceiling,
                  stamp_label=(env.get(ENV_STAMP_LABEL) or '').strip(),
                  type_cluster=(env.get('JIRA_TYPE_CLUSTER') or '').strip(),
                  type_instance=(env.get('JIRA_TYPE_INSTANCE') or '').strip(),
                  epic_id=(env.get('JIRA_EPIC_ID') or '').strip(),
                  transition_reopen=(env.get('JIRA_TRANSITION_REOPEN') or '').strip())
        jb.instance_threshold = instance_threshold
        jb.create_ceiling = int(env.get('TICKET_CREATE_CEILING'))
        return jb, 'jira backend configured'

    if want == 'azdo':
        if not azdo_ready:
            missing = [k for k, v in (('AZDO_ORG_URL', azdo_org), ('AZDO_PAT', env.get('AZDO_PAT')),
                                      ('AZDO_PROJECT', env.get('AZDO_PROJECT'))) if not v]
            return None, ('CONFIGURATION REFUSED: %s names azdo and %s is missing'
                          % (ENV_BACKEND, ', '.join(missing)))
        bad = azdo_config_problem(env, azdo_org)
        if bad:
            return None, 'CONFIGURATION REFUSED: %s' % bad
        ab = AzureDevOps(azdo_org, env.get('AZDO_PROJECT'), env.get('AZDO_PAT'),
                         (env.get('AZDO_STAMP_FIELD') or '').strip(),
                         epic_id=(env.get('AZDO_EPIC_ID') or '').strip(),
                         calibration=(env.get('AZDO_CALIBRATION_ITEM') or '').strip(),
                         stamp_label=(env.get(ENV_STAMP_LABEL) or '').strip(),
                         type_cluster=(env.get('AZDO_TYPE_CLUSTER') or '').strip(),
                         type_instance=(env.get('AZDO_TYPE_INSTANCE') or '').strip(),
                         state_reopen=(env.get('AZDO_STATE_REOPEN') or '').strip(),
                         state_done=(env.get('AZDO_STATE_DONE') or '').strip(),
                         retry_ceiling=retry_ceiling,
                         create_ceiling=int(env.get('TICKET_CREATE_CEILING')))
        ab.instance_threshold = instance_threshold
        return ab, 'azdo backend configured'

    return None, 'unrecognised %s value %r; expected jira, azdo or github' % (ENV_BACKEND, want)


def load_ledger(path):
    """The identity -> ticket map, read from the checkout. Zero API calls.

    A missing ledger is an EMPTY ledger and says so. It is not an error: the first run has no
    ledger. What it is not is evidence that no tickets exist -- which is why the backend sweep
    runs even on a ledger miss.
    """
    if not path or not os.path.exists(path):
        return {}, 'no ledger at %s; treating as empty, which establishes nothing about what exists' % (
            path or '<unset>')
    try:
        doc = json.load(io.open(path, encoding='utf-8'))
    except (IOError, ValueError) as exc:
        # An unreadable ledger is NOT an empty one. Continuing with {} would make every cluster
        # look unbound and create a duplicate for every obligation already ticketed.
        return None, 'ledger at %s could not be read: %s' % (path, exc)
    entries = doc.get('clusters') if isinstance(doc, dict) else doc
    return (entries or {}), 'ledger loaded with %d entry(ies)' % len(entries or {})


def save_ledger(path, ledger):
    io.open(path, 'w', encoding='utf-8').write(
        json.dumps({'schema': 1, 'clusters': ledger}, indent=2, sort_keys=True) + '\n')


# ═════════════════════════════════════════════════════════════════════════════════════
# REPORT
# ═════════════════════════════════════════════════════════════════════════════════════


def render_summary(result):
    L = ['## Ticket reconciliation', '']
    if not result['apply']:
        L.append('**DRY RUN.** Nothing was written. `--apply` performs it.')
        L.append('')
    L.append('| field | value |')
    L.append('|---|---|')
    L.append('| backend | %s |' % (result['backend'] or 'NONE -- the control is off'))
    claim = result.get('ticketing_claim') or {}
    L.append('| ticketing claim | **%s**%s |' % (
        claim.get('routing_result') or 'NOT COMPUTED',
        (' / %s -- %s' % (claim.get('publication_state'), '; '.join(claim.get('causes') or []))
         if claim.get('routing_result') == EVIDENCE_UNTRUSTED else '')))
    thr = result.get('throttles') or []
    L.append('| calls spent | %s; throttled %d time(s)%s |' % (
        result.get('calls') if result.get('calls') is not None else 'not counted (in-memory)',
        len(thr), (' -- ' + ', '.join('%s %s (Retry-After %s)' % (t['status'], t['method'],
                                                                t['retry_after'])
                                      for t in thr[:10])) if thr else ''))
    if result.get('carried'):
        L.append('| carried past the creation ceiling | %d obligation(s) owe a ticket and are '
                 'carried in consequence order to the next run; their findings route exactly as '
                 'the rung says |' % len(result['carried']))
    if result.get('proposals'):
        L.append('| correlation proposals | %d, recorded for a human to confirm or split; none '
                 'was applied, so each member is ticketed on its own (ETFB 9.4) |'
                 % len(result['proposals']))
    if result.get('reopened') or result.get('successors'):
        L.append('| closed tickets beside a reproducing finding | %d reopened%s; %d successor(s) '
                 'where the tracker refused the reopen%s |' % (
                     len(result.get('reopened') or []),
                     (' (planned)' if not result['apply'] else '') + ''.join(
                         ' -- %s %s' % (x['ref'], x.get('classification') or '')
                         for x in (result.get('reopened') or [])[:5]),
                     len(result.get('successors') or []),
                     ''.join(' -- %s replaces %s (%s)' % (s['ref'], s['predecessor'], s['reason'])
                             for s in (result.get('successors') or [])[:5])))
    if result.get('obligations'):
        L.append('| obligations carried | %d cluster(s) owe a ticket this run could not '
                 'establish; each is recorded with its cause |' % len(result['obligations']))
    if result.get('degraded_escalations'):
        esc = result['degraded_escalations']
        L.append('| degraded for consecutive runs | %d obligation(s) carried for at least %d '
                 'consecutive runs (since %s): %s at the cell\'s next promotion review -- a '
                 'person decides, the run does not (TC 4.1) |'
                 % (len(esc), esc[0]['threshold'],
                    ', '.join(sorted(set(str(e['first_degraded_at']) for e in esc))),
                    DECISION_REQUIRED))
    L.append('| clusters | %d |' % result['clusters'])
    # NAMED FOR WHAT IT GOVERNS, not for the whole run. The old row said "human approval" beside
    # a run that needed none, which taught a reader that an unapproved run was a withheld one.
    L.append('| disposition approval | %s |' % result['approval'])
    L.append('| routine reconciliation | %s |'
             % ('UNATTENDED -- no approver is required or consulted'
                if result['apply'] else 'planned only'))
    L.append('| reference date | %s |' % (result.get('today') or 'NOT SUPPLIED -- the past-due '
                                          'sweep cannot establish what has elapsed'))
    probe = result['probe']
    L.append('| calibration probe | %s |' % (probe['state'] if probe else 'not run'))
    sc = result['sweep_complete']
    L.append('| sweep | %s |' % ('complete' if sc else
                                 ('PARTIAL -- counts below are FLOORS' if sc is False
                                  else 'not run')))
    L.append('')
    L.append('| lookup outcome | clusters |')
    L.append('|---|---|')
    for k in sorted(result['outcomes']):
        L.append('| %s | %d |' % (k, result['outcomes'][k]))
    L.append('')

    n_withheld = len(result['withheld_no_identity'])
    if n_withheld:
        L.append('### %d finding(s) withheld: %s' % (n_withheld, IDENTITY_NOT_ESTABLISHED))
        L.append('')
        L.append('These findings have no durable identity, so there is nothing to look a ticket up')
        L.append('by. A ticket keyed on nothing could not be found on the next run, and the run')
        L.append('after that would create it again -- so no ticket was created.')
        L.append('')
        L.append('**This is not a clean result, and it is not a count of zero problems.** It is')
        L.append('work that cannot be tracked at all until identity is established upstream.')
        L.append('')
        L.append('| scanner | rule | location | reason |')
        L.append('|---|---|---|---|')
        for w in result['withheld_no_identity'][:25]:
            L.append('| %s | `%s` | `%s` | %s |' % (w['scanner'], w['rule'], w['uri'], w['reason']))
        if n_withheld > 25:
            L.append('')
            L.append('... and %d more.' % (n_withheld - 25))
        L.append('')

    if result['created']:
        verb = 'created' if result['apply'] else 'WOULD create'
        L.append('### %d parent ticket(s) %s' % (len(result['created']), verb))
        L.append('')
        L.append('| cluster | class | children | confidence | compliance review | title |')
        L.append('|---|---|---|---|---|---|')
        for c in result['created']:
            L.append('| `%s` | %s | %d | %s | %s | %s |' % (
                c['cluster_key'][:12], c.get('ticket_class', DEFAULT_CLASS),
                c.get('children', 0),
                c.get('confidence', '--'), c.get('compliance_review', '--'), c['title']))
        L.append('')
        if result['apply'] and not result['applied_disposition']:
            L.append('Created **unattended**: no approver was required or consulted. Each is a')
            L.append('deterministic, idempotent, evidence-backed work item keyed on a durable')
            L.append('identity -- it asserts nothing about what the organisation accepts.')
            L.append('')

    if result['compliance']:
        paired = sum(v for k, v in result['compliance'].items()
                     if k != tm.PAIRING_NOT_ESTABLISHED)
        L.append('### Compliance pairing')
        L.append('')
        L.append('| review type | clusters |')
        L.append('|---|---|')
        for k in sorted(result['compliance']):
            L.append('| %s | %d |' % (k, result['compliance'][k]))
        L.append('')
        if paired:
            L.append('**%d cluster(s) owe a compliance review as well as a fix.** That is a'
                     % paired)
            L.append('second obligation: remediating the finding does not discharge it.')
        L.append('')
        L.append('Pairing is a table lookup keyed on the finding subject -- deterministic, with no')
        L.append('model and no inference anywhere in it. `%s` is the lookup\'s'
                 % tm.PAIRING_NOT_ESTABLISHED)
        L.append('answer where this kit knows of no review, and it does NOT establish that none is')
        L.append('required. Run `scripts/ticket_model.py --explain-pairing` for the table.')
        L.append('')

    if result['confidence']:
        L.append('### Confidence')
        L.append('')
        L.append('| label | clusters |')
        L.append('|---|---|')
        for k in sorted(result['confidence']):
            L.append('| %s | %d |' % (k, result['confidence'][k]))
        L.append('')
        L.append('Derived, not scored. Each label is computed from how many scanners anchored on')
        L.append('the cluster, whether identity was established, and whether the evidence channel')
        L.append('was degraded -- and every ticket carries the derivation that produced its own.')
        L.append('**No percentage is given, because none is derivable from what was observed.**')
        L.append('')

    # ── PAST-DUE DEFERRALS, IN THE ORDINARY OUTPUT AND NEAR THE TOP. ──────────────
    #
    # Nobody has to ask for this section and no flag enables it. A past-due acceptance that only
    # appears under `--show-deferrals` is a past-due acceptance nobody sees.
    if result.get('past_due'):
        n_pd = len(result['past_due'])
        L.append('### %d deferral(s) PAST DUE -- a review is owed' % n_pd)
        L.append('')
        L.append('These findings were deferred by somebody, with a reason and an end date, and')
        L.append('**the end date has passed** (or could not be established at all). Two things')
        L.append('deliberately did NOT happen:')
        L.append('')
        L.append('- **Nothing reopened.** The tasks are still %s. A deferral that reopens because'
                 % tm.DEFERRED)
        L.append('  a date passed is an obligation changing state with nobody having decided')
        L.append('  anything -- the same failure as a disposition renewing itself through silence.')
        L.append('- **Nothing went on quietly suppressing.** The acceptance has LAPSED. It is')
        L.append('  reported here in every run until an authorised person ends it')
        L.append('  (`--resolve-deferral ... --resolution reopen`) or renews it to a future date')
        L.append('  with a fresh reason (`--resolution extend --until <date>`). Both are')
        L.append('  dispositions and both need an approver.')
        L.append('')
        L.append('| state | task | ended | reason | ticket |')
        L.append('|---|---|---|---|---|')
        for p in result['past_due'][:50]:
            L.append('| **%s** | `%s` | %s | %s | %s |' % (
                p['state'], p['task_id'], p['until'] or 'none recorded',
                p['reason'] or 'none recorded', p['ref'] or '--'))
        if n_pd > 50:
            L.append('')
            L.append('... and %d more.' % (n_pd - 50))
        L.append('')

    if result['refused_disposition']:
        L.append('### %d disposition(s) refused: no approver'
                 % len(result['refused_disposition']))
        L.append('')
        L.append('A finding asked for a DISPOSITION -- an exception, an exclusion, a')
        L.append('false-positive call, a risk acceptance, a compensating control accepted instead')
        L.append('of a fix, a budget commitment, or a change to the posture of the environment.')
        L.append('Those are judgements about what the organisation accepts, and an automated run')
        L.append('does not make them. **Routine reconciliation was unaffected and ran**')
        L.append('**unattended; only the judgement is waiting.** The whole cluster is held rather')
        L.append('than half-written: raising ordinary remediation work for a finding somebody')
        L.append('asked to have excepted would make the asking disappear.')
        L.append('')
        L.append('| cluster | requested | mutation | why it was refused |')
        L.append('|---|---|---|---|')
        for r in result['refused_disposition']:
            L.append('| `%s` | %s | `%s` | %s |' % (r['cluster_key'][:12], r['requested'],
                                                    r['mutation'], r['reason']))
        L.append('')

    if result['applied_disposition']:
        L.append('### %d disposition(s) approved' % len(result['applied_disposition']))
        L.append('')
        L.append('Each carries the ROLE that approved it and the reason, for the record. A')
        L.append('disposition request reaching a ticket is still not a disposition: a finding')
        L.append('stops blocking only when an exact, unexpired, approved disposition is merged to')
        L.append('the protected default branch. **This program never writes one.**')
        L.append('')
        L.append('| cluster | requested | ticket class | approved by | reason |')
        L.append('|---|---|---|---|---|')
        for r in result['applied_disposition']:
            L.append('| `%s` | %s | %s | %s | %s |' % (r['cluster_key'][:12], r['requested'],
                                                       r['ticket_class'], r['approved_by'],
                                                       r['approval_reason']))
        L.append('')

    if result['needs_decision']:
        L.append('### %d cluster(s) need a human decision' % len(result['needs_decision']))
        L.append('')
        L.append('Routing: %s. Nothing was created and nothing was updated for these -- an'
                 % DECISION_REQUIRED)
        L.append('ambiguity resolved by picking the first candidate is a decision made by')
        L.append('pagination. **The findings themselves route exactly as their rung says.**')
        L.append('')
        for d in result['needs_decision']:
            L.append('- `%s` %s -- %s' % (d['cluster_key'][:12], d['outcome'], d['detail']))
        L.append('')

    for note in result['notes']:
        L.append('> %s' % note)
        L.append('')
    return '\n'.join(L)


# ═════════════════════════════════════════════════════════════════════════════════════
# SELF-TEST
# ═════════════════════════════════════════════════════════════════════════════════════


def _rec(scanner, rule, uri, ident, state='FINGERPRINTED', aliases=None, subject='DEPENDENCY',
         severity='high', reason='', line=1):
    return {'scanner': scanner, 'rule': rule, 'uri': uri, 'line': line, 'severity': severity,
            'identity': ident, 'identity_state': state, 'identity_reason': reason,
            'finding_subject': subject, 'what_aliases': aliases or [], 'where': uri}


def _selftest():
    """Every assertion names a defect this would otherwise ship.

    THE ANTI-VACUITY RULE. "No duplicates were created" is trivially true when nothing was ever
    created, and "an empty identity created nothing" is trivially true in a program that creates
    nothing at all. So the POSITIVE case is asserted FIRST and the test aborts loudly if it did not
    hold -- every later assertion is then a statement about a program shown able to create.
    """
    fails = []

    # The approval every mutating call below carries. A ROLE and a reason, never a person.
    APPR = tm.Approval(actor='platform-security',
                       reason='self-test exercising the approved creation path')

    # ── 1. THE POSITIVE CASE, FIRST. A good finding gets a ticket. ────────────────────
    be = RecordingBackend()
    recs = [_rec('trivy', 'CVE-2024-0001', 'go.mod', 'id-aaa', aliases=['cve-2024-0001'])]
    clusters, withheld = build_clusters(recs)
    r1 = reconcile(clusters, withheld, be, {}, apply_changes=True, approval=APPR)

    if len(be.created) != 1:
        # Abort rather than continue. Every assertion below is about what a creating program
        # refuses to create; if nothing can be created, they all pass and prove nothing.
        print('')
        print('VACUOUS SELF-TEST ABORTED.')
        print('  The positive case did not hold: a fingerprinted finding against a healthy')
        print('  backend produced %d ticket(s), expected exactly 1.' % len(be.created))
        print('  Every remaining assertion in this file is of the form "X creates nothing", and')
        print('  all of them would pass trivially against a program that creates nothing at all.')
        print('  Refusing to report a pass. Outcomes seen: %r' % r1['outcomes'])
        return 2

    if r1['outcomes'].get(BINDING_ABSENT) != 1:
        fails.append('the creating run did not classify the cluster %s: %r'
                     % (BINDING_ABSENT, r1['outcomes']))

    # ── 2. LOOKUP BEFORE CREATE: a second run creates nothing new. ───────────────────
    #
    # This is the named defect: duplicate tickets on every run. The ledger is deliberately NOT
    # passed, so the only thing preventing the duplicate is the backend sweep finding the stamp.
    created_after_first = len(be.created)
    clusters2, withheld2 = build_clusters(recs)
    r2 = reconcile(clusters2, withheld2, be, {}, apply_changes=True, approval=APPR)
    if len(be.created) != created_after_first:
        fails.append('A SECOND RUN CREATED A DUPLICATE: %d tickets after one run, %d after two. '
                     'This is the defect the whole file exists to prevent.'
                     % (created_after_first, len(be.created)))
    if r2['outcomes'].get(BACKEND_BOUND) != 1:
        fails.append('the second run did not report %s, so the duplicate was prevented by '
                     'something other than the lookup: %r' % (BACKEND_BOUND, r2['outcomes']))

    # 2b. And with the ledger populated, the same run is LEDGER_BOUND -- the zero-cost steady
    #     state. Asserting both proves the two steps of the cascade work independently.
    ledger = {clusters[0]['cluster_key']: {'ref': be.created[0]['ref'], 'backend': be.name}}
    r2b = reconcile(build_clusters(recs)[0], [], be, ledger, apply_changes=True, approval=APPR)
    if r2b['outcomes'].get(LEDGER_BOUND) != 1:
        fails.append('a populated ledger did not produce %s: %r' % (LEDGER_BOUND, r2b['outcomes']))
    if len(be.created) != created_after_first:
        fails.append('the ledger-bound run created something')

    # ── 3. AN EMPTY IDENTITY CREATES NOTHING AT ALL. ─────────────────────────────────
    be3 = RecordingBackend()
    bad = [
        _rec('semgrep', 'rule-x', 'a.py', '', state='UNFINGERPRINTABLE',
             reason='SYMBOL_REQUIRED_FOR_COARSE_WHAT'),
        _rec('codeql', 'rule-y', 'b.py', None, state='UNFINGERPRINTABLE',
             reason='WHAT_UNDERIVABLE'),
        # The nastier shape: the state field CLAIMS success and the identity is empty anyway.
        _rec('trivy', 'rule-z', 'c.py', '', state='FINGERPRINTED'),
    ]
    c3, w3 = build_clusters(bad)
    r3 = reconcile(c3, w3, be3, {}, apply_changes=True, approval=APPR)
    if be3.created:
        fails.append('A FINDING WITH NO DURABLE IDENTITY GOT A TICKET (%d). Every run would create '
                     'a fresh set, forever.' % len(be3.created))
    if len(w3) != 3 or r3['outcomes'].get(IDENTITY_NOT_ESTABLISHED) != 3:
        fails.append('withholding was not reported as %s for all three records: %r'
                     % (IDENTITY_NOT_ESTABLISHED, r3['outcomes']))
    if c3:
        fails.append('an unfingerprintable record reached clustering: %d cluster(s)' % len(c3))
    # IT MUST BE VISIBLE, not silent. A withheld finding that nobody can see is the same as a
    # dropped one.
    summ = render_summary(r3)
    if IDENTITY_NOT_ESTABLISHED not in summ or 'withheld' not in summ.lower():
        fails.append('the withholding was silent -- it is not in the summary a human reads')
    if 'not a clean result' not in summ:
        fails.append('the summary let a withheld finding read as a clean result')

    # ── 4. A CORRELATED CLUSTER YIELDS ONE TICKET, NOT ONE PER SCANNER. ─────────────
    be4 = RecordingBackend()
    # Every member carries the SHARED identifier. (This fixture used to be trivy{cve,ghsa},
    # grype{ghsa}, osv{cve} -- an alias CHAIN in which grype and osv share nothing -- and the
    # assertion below demanded one cluster from it, which encoded the transitive-anchoring
    # defect as the expected behaviour. 4b-vi now proves a chain is a proposal.)
    cluster_recs = [
        _rec('trivy', 'CVE-2024-9999', 'go.mod', 'id-t', aliases=['cve-2024-9999', 'ghsa-xxxx']),
        _rec('grype', 'GHSA-xxxx', 'go.mod', 'id-g', aliases=['ghsa-xxxx', 'cve-2024-9999']),
        _rec('osv', 'CVE-2024-9999', 'go.mod', 'id-o', aliases=['cve-2024-9999']),
    ]
    c4, w4 = build_clusters(cluster_recs)
    if len(c4) != 1:
        fails.append('three scanners reporting one condition produced %d clusters, not 1' % len(c4))
    r4 = reconcile(c4, w4, be4, {}, apply_changes=True, approval=APPR)
    if len(be4.created) != 1:
        fails.append('A CORRELATED CLUSTER PRODUCED %d TICKETS. One cluster is one obligation is '
                     'at most one ticket.' % len(be4.created))
    if c4 and sorted(c4[0]['scanners']) != ['grype', 'osv', 'trivy']:
        fails.append('the cluster did not name every contributing scanner: %r'
                     % (c4[0]['scanners'] if c4 else None))

    # 4b. The cluster key is stable across a MEMBERSHIP change. If it were a hash of the member
    #     set, a fourth scanner joining would mint a new key and the next run would duplicate.
    if c4:
        key_before = c4[0]['cluster_key']
        c4b, _ = build_clusters(cluster_recs + [
            _rec('snyk', 'CVE-2024-9999', 'go.mod', 'id-s', aliases=['cve-2024-9999'])])
        if len(c4b) != 1 or c4b[0]['cluster_key'] != key_before:
            fails.append('the cluster key changed when a member was added, so the next run would '
                         'create a second ticket for the same obligation')
        # And the run after the membership change still creates nothing.
        r4b = reconcile(c4b, [], be4, {}, apply_changes=True, approval=APPR)
        if len(be4.created) != 1:
            fails.append('a membership change created a second ticket: %r' % r4b['outcomes'])

    # 4b-ii. T2 / TICKETING_BACKENDS.md test T-2. MEMBERSHIP JOINS AND THEN NARROWS. A scanner joins a
    #     singleton (the shared-alias anchor moves), then the original scanner drops out. One
    #     obligation throughout, so one ticket throughout -- with the ledger carried between runs
    #     (the production path) AND with no ledger at all, where only the sweep can bind.
    j_a = _rec('trivy', 'CVE-2024-8888', 'go.mod', 'id-ja', aliases=['cve-2024-8888', 'ghsa-88'])
    j_b = _rec('grype', 'GHSA-88', 'go.mod', 'id-jb', aliases=['ghsa-88'])
    for label, keep_ledger in (('with the ledger carried', True), ('with no ledger', False)):
        be_j, led_j = RecordingBackend(), {}
        keys = []
        for members in ([j_a], [j_a, j_b], [j_b]):
            cj = build_clusters(members)[0]
            reconcile(cj, [], be_j, led_j if keep_ledger else {}, apply_changes=True,
                      approval=APPR)
            keys.append(cj[0]['cluster_key'])
        if len(be_j.created) != 1:
            fails.append('a cluster that gained and then lost a member produced %d tickets %s; '
                         'one obligation is one ticket (T2)' % (len(be_j.created), label))
        if len(set(keys)) != 1:
            fails.append('the stamp a cluster was reconciled under moved as its membership '
                         'changed %s: %r (T2)' % (label, [k[:8] for k in keys]))

    # 4b-iii. A SPLIT IS AN EVENT A HUMAN DECIDES. Two members once bound to one obligation now
    #     arrive as two clusters (their shared alias is gone). Both inherit the same stamp; picking
    #     one to keep the ticket would be a decision made by iteration order.
    be_s = RecordingBackend()
    led_s = {'k' * 32: {'ref': '77', 'backend': 'recording',
                        'member_identities': ['id-s1', 'id-s2']}}
    be_s.store['k' * 32] = [{'ref': '77', 'url': 'memory://77', 'state': 'open', 'body': ''}]
    r_s = reconcile(build_clusters([
        _rec('trivy', 'CVE-S1', 'go.mod', 'id-s1', aliases=['cve-s1']),
        _rec('grype', 'GHSA-S2', 'go.mod', 'id-s2', aliases=['ghsa-s2'])])[0],
        [], be_s, led_s, apply_changes=True, approval=APPR)
    if be_s.created or be_s.block_updates or r_s['outcomes'].get(BINDING_AMBIGUOUS) != 2:
        fails.append('a split cluster was resolved without a human: %d created, %d updated, %r'
                     % (len(be_s.created), len(be_s.block_updates), r_s['outcomes']))

    # 4b-iv. TICKETING_BACKENDS.md T-7: A CLOSED TICKET BESIDE A REPRODUCING FINDING (TC 4.2).
    #     Reopen when the closure is unbacked, expired or a falsified REMEDIATED; leave it alone
    #     while an unexpired approved disposition stands.
    def _closed_run(disposition, today='2026-10-14', refuse=False):
        be_c = RecordingBackend()
        be_c.refuse_reopen = refuse
        rec_c = _rec('trivy', 'CVE-7', 'go.mod', 'id-c7', aliases=['cve-c7'])
        if disposition is not None:
            rec_c['disposition'] = disposition
        cc = build_clusters([rec_c])[0]
        key_c = cc[0]['cluster_key']
        be_c.store[key_c] = [{'ref': '70', 'url': 'memory://70', 'state': 'closed', 'body': ''}]
        led_c = {key_c: {'ref': '70', 'backend': 'recording', 'member_identities': ['id-c7']}}
        r_c = reconcile(cc, [], be_c, led_c, apply_changes=True, approval=APPR, today=today)
        return be_c, led_c, key_c, r_c, rec_c

    for label, disp, want_reopen in (
            ('closed with nothing backing it', None, True),
            ('closed behind an expired acceptance',
             {'disposition_type': 'ACCEPTED_RISK', 'state': 'approved', 'expires': '2026-01-01'},
             True),
            ('closed as REMEDIATED while the finding still reproduces',
             {'disposition_type': 'REMEDIATED', 'state': 'approved', 'expires': '2027-01-01'},
             True),
            ('closed behind an unexpired approved FALSE_POSITIVE',
             {'disposition_type': 'FALSE_POSITIVE', 'state': 'approved', 'expires': '2027-01-01'},
             False),
            ('closed behind an unexpired but UNAPPROVED acceptance',
             {'disposition_type': 'ACCEPTED_RISK', 'state': 'proposed', 'expires': '2027-01-01'},
             True)):
        be_c, _l, _k, r_c, _r = _closed_run(disp)
        got = getattr(be_c, 'reopened', None)
        if got is None:
            fails.append('the backend has no reopen path at all (J-6, T-7)')
            break
        if bool(got) != want_reopen:
            fails.append('%s: reopened=%r, expected %r (T-7)' % (label, got, want_reopen))
        if be_c.created:
            fails.append('%s: a closed ticket led to a NEW ticket rather than a reopen' % label)
        # T-08 (TC 4.2's table): A REOPEN SAYS WHY, in the run record, the ledger and on the
        # ticket. An expired acceptance is the registered REOPENED_BY_LAPSE ("re-decide with a
        # named approver and a new expiry"); a falsified REMEDIATED and a closure nothing backed
        # are named as what they are. A bare reopen reads as the bridge flapping.
        want_cls = {'closed behind an expired acceptance': REOPENED_BY_LAPSE,
                    'closed as REMEDIATED while the finding still reproduces': REOPEN_FALSIFIED,
                    'closed with nothing backing it': REOPEN_UNBACKED,
                    'closed behind an unexpired but UNAPPROVED acceptance': REOPEN_UNBACKED
                    }.get(label)
        if want_reopen and want_cls:
            rs = r_c.get('reopened') or [{}]
            if rs[0].get('classification') != want_cls:
                fails.append('%s: the reopen was recorded as %r, expected %r (T-08)'
                             % (label, rs[0].get('classification'), want_cls))
            if not any(want_cls in text for _ref, text in be_c.comments):
                fails.append('%s: the reopened ticket carries no comment naming %s, so a reader '
                             'cannot tell a lapse from the bridge flapping (T-08)'
                             % (label, want_cls))
            hist = (_l.get(_k) or {}).get('reopens') or []
            if not hist or hist[-1].get('classification') != want_cls:
                fails.append('%s: the ledger does not record the reopen and its classification: '
                             '%r (T-08)' % (label, hist))

    # 4b-v. T-8: REOPEN REFUSED -> A SUCCESSOR, the predecessor kept, the reason recorded; and
    #     the next run binds the successor without reading the pair as an ambiguity.
    be_c, led_c, key_c, r_c, rec_c = _closed_run(None, refuse=True)
    entry_c = led_c.get(key_c) or {}
    if len(be_c.created) != 1:
        fails.append('a refused reopen produced %d successor(s), expected 1 (T-8)'
                     % len(be_c.created))
    elif '70' not in (entry_c.get('predecessors') or []) or not entry_c.get('reopen_refused'):
        fails.append('the successor did not keep the predecessor and the refusal reason in the '
                     'ledger: %r (T-8)' % entry_c)
    elif '70' not in (be_c.store[key_c][-1].get('body') or ''):
        fails.append('the successor ticket does not reference its predecessor (T-8)')
    else:
        r_next = reconcile(build_clusters([rec_c])[0], [], be_c, led_c, apply_changes=True,
                           approval=APPR, today='2026-10-14')
        if r_next['outcomes'].get(BINDING_AMBIGUOUS) or len(be_c.created) != 1:
            fails.append('the run after a successor read predecessor + successor as an ambiguity '
                         'or created again: %r (T-8)' % r_next['outcomes'])

    # 4b-vi. AN ALIAS CHAIN IS A PROPOSAL, NEVER AN ANCHOR (ETFB 9.4; found by the identity lane).
    #     A{x,y}, B{y,z}, C{z}: A and C share no identifier, so one ticket must not carry both.
    #     Each acts on its own; the chain is recorded for a human to confirm or split.
    chain = [_rec('trivy', 'R-A', 'go.mod', 'id-ca', aliases=['x-1', 'y-1']),
             _rec('grype', 'R-B', 'go.mod', 'id-cb', aliases=['y-1', 'z-1']),
             _rec('osv', 'R-C', 'go.mod', 'id-cc', aliases=['z-1'])]
    c_ch, _w = build_clusters(chain)
    if any(len(c['members']) > 1 for c in c_ch):
        fails.append('an alias CHAIN was anchored into one cluster (%s): members that share no '
                     'identifier would share one ticket'
                     % [sorted(m['identity'] for m in c['members']) for c in c_ch])
    be_ch = RecordingBackend()
    r_ch = reconcile(c_ch, [], be_ch, {}, apply_changes=True, approval=APPR)
    if len(be_ch.created) != 3:
        fails.append('an alias chain produced %d ticket(s); each member acts on its own, so 3'
                     % len(be_ch.created))
    if not r_ch.get('proposals'):
        fails.append('the alias chain was not recorded as a proposal for a human')

    # 4b-vii. TC 6.5: THE PER-RUN CREATION CEILING. Creation stops at the declared number, the
    #     rest are CARRIED with their queue position, and the order is by consequence -- the
    #     most severe first -- not by discovery order.
    be_cap = RecordingBackend()
    be_cap.create_ceiling = 2
    cap_recs = [_rec('trivy', 'CVE-L', 'a/go.mod', 'id-l', aliases=['cve-l'], severity='low'),
                _rec('trivy', 'CVE-C', 'b/go.mod', 'id-c', aliases=['cve-c'], severity='critical'),
                _rec('trivy', 'CVE-M', 'c/go.mod', 'id-m', aliases=['cve-m'], severity='medium'),
                _rec('trivy', 'CVE-H', 'd/go.mod', 'id-h', aliases=['cve-h'], severity='high')]
    r_cap = reconcile(*build_clusters(cap_recs), backend=be_cap, ledger={}, apply_changes=True,
                      approval=APPR)
    made = sorted(c['title'].split(']')[0].strip('[') for c in be_cap.created)
    if made != ['critical', 'high']:
        fails.append('a creation ceiling of 2 created %r; expected the two most severe '
                     '(critical, high) (TC 6.5)' % made)
    carried = r_cap.get('carried') or []
    if len(carried) != 2 or [c.get('position') for c in carried] != [1, 2]:
        fails.append('the clusters past the ceiling were not carried with their queue position: '
                     '%r (TC 6.5)' % carried)
    if 'carried' not in render_summary(r_cap).lower():
        fails.append('the summary does not say how many obligations were carried')

    # 4c. NOTHING CORRELATES ACROSS SUBJECT CLASSES. Two records sharing an external identifier
    #     and a locus, with DIFFERENT subjects, are two obligations with two owners and two fixes
    #     -- section 9.3 says so outright. Merging them would hide one behind the other's ticket,
    #     and the merged-away finding leaves no trace.
    be4c = RecordingBackend()
    cross = [
        _rec('trivy', 'CVE-2024-5555', 'app/x', 'id-dep', aliases=['cve-2024-5555'],
             subject='DEPENDENCY'),
        _rec('checkov', 'CVE-2024-5555', 'app/x', 'id-res', aliases=['cve-2024-5555'],
             subject='RESOURCE'),
    ]
    c4c, _w = build_clusters(cross)
    if len(c4c) != 2:
        fails.append('a DEPENDENCY finding and a RESOURCE finding sharing an identifier merged '
                     'into %d cluster(s). Nothing correlates across subject classes: those are '
                     'two obligations with two owners.' % len(c4c))
    reconcile(c4c, [], be4c, {}, apply_changes=True, approval=APPR)
    if len(be4c.created) != 2:
        fails.append('two obligations in different subject classes produced %d ticket(s), so one '
                     'of them is hidden behind the other and leaves no trace'
                     % len(be4c.created))

    # 4d. And the locus still separates: the same subject and identifier in two different files is
    #     two obligations too. Asserting both directions is what proves the bucket key is doing
    #     work rather than one half of it happening to hold.
    c4d, _w2 = build_clusters([
        _rec('trivy', 'CVE-2024-6666', 'a/go.mod', 'id-a', aliases=['cve-2024-6666']),
        _rec('trivy', 'CVE-2024-6666', 'b/go.mod', 'id-b', aliases=['cve-2024-6666']),
    ])
    if len(c4d) != 2:
        fails.append('one advisory in two different files merged into %d cluster(s); the locus is '
                     'part of the anchor' % len(c4d))
    # T1. Two clusters are not enough: they must carry two KEYS. Two loci under one stamp is one
    #     ticket for two obligations, and the second locus reads as a dangling reference to the
    #     first one's ticket. A monorepo with one CVE in two manifests is the ordinary case.
    if len(set(c['cluster_key'] for c in c4d)) != 2:
        fails.append('one advisory in two files produced two clusters under ONE cluster key, so '
                     'both obligations share a single stamp and a single ticket (T1)')
    be4d = RecordingBackend()
    led4d = {}
    r4d = reconcile(c4d, [], be4d, led4d, apply_changes=True, approval=APPR)
    if len(be4d.created) != 2 or r4d['needs_decision']:
        fails.append('one advisory in two files produced %d ticket(s) and %d spurious decision(s); '
                     'expected 2 tickets and none (T1)'
                     % (len(be4d.created), len(r4d['needs_decision'])))
    r4d2 = reconcile(build_clusters([
        _rec('trivy', 'CVE-2024-6666', 'a/go.mod', 'id-a', aliases=['cve-2024-6666']),
        _rec('trivy', 'CVE-2024-6666', 'b/go.mod', 'id-b', aliases=['cve-2024-6666']),
    ])[0], [], be4d, led4d, apply_changes=True, approval=APPR)
    if len(be4d.created) != 2 or r4d2['outcomes'].get(LEDGER_BOUND) != 2:
        fails.append('the second monorepo run was not two LEDGER_BOUND with no new ticket: %r, '
                     '%d ticket(s)' % (r4d2['outcomes'], len(be4d.created)))

    # ── 5. DRY RUN IS THE DEFAULT AND WRITES NOTHING. ───────────────────────────────
    be5 = RecordingBackend()
    c5, w5 = build_clusters([_rec('trivy', 'CVE-1', 'x', 'id-dry', aliases=['cve-1'])])
    r5 = reconcile(c5, w5, be5, {}, apply_changes=False)
    if be5.created or be5.comments:
        fails.append('a dry run wrote to the backend')
    if not r5['created'] or not r5['created'][0].get('planned'):
        fails.append('a dry run did not report the ticket it WOULD create')
    if 'DRY RUN' not in render_summary(r5):
        fails.append('a dry run did not say so in its summary')

    # ── 6. NOTHING-WAS-LOOKED-AT NEVER BECOMES NOTHING-FOUND. ───────────────────────
    #
    # A partial sweep and an unobservable channel are the two ways the lookup fails to establish
    # anything, and neither may license a creation. This is the four-state collapse that matters
    # most here, because the collapse is in the permissive direction.
    for label, backend in (('partial sweep', RecordingBackend(sweep_complete=False)),
                           ('unobservable channel', RecordingBackend(observable=False))):
        c6, w6 = build_clusters([_rec('trivy', 'CVE-2', 'y', 'id-u', aliases=['cve-2'])])
        r6 = reconcile(c6, w6, backend, {}, apply_changes=True, approval=APPR)
        if backend.created:
            fails.append('a %s licensed a creation' % label)
        if r6['outcomes'].get(BINDING_UNESTABLISHED) != 1:
            fails.append('a %s did not report %s: %r'
                         % (label, BINDING_UNESTABLISHED, r6['outcomes']))
        if r6['outcomes'].get(BINDING_ABSENT):
            fails.append('a %s reported %s -- nothing-was-looked-at became nothing-found'
                         % (label, BINDING_ABSENT))

    # ── 7. AMBIGUITY CREATES NOTHING AND UPDATES NOTHING. ──────────────────────────
    be7 = RecordingBackend()
    c7, _ = build_clusters([_rec('trivy', 'CVE-3', 'z', 'id-amb', aliases=['cve-3'])])
    be7.store[c7[0]['cluster_key']] = [
        {'ref': '10', 'url': 'memory://10', 'state': 'open', 'body': ''},
        {'ref': '11', 'url': 'memory://11', 'state': 'open', 'body': ''}]
    r7 = reconcile(c7, [], be7, {}, apply_changes=True, approval=APPR)
    if be7.created or be7.comments:
        fails.append('an ambiguous binding was resolved by writing to one of the candidates')
    if r7['outcomes'].get(BINDING_AMBIGUOUS) != 1:
        fails.append('two stamped tickets did not report %s: %r'
                     % (BINDING_AMBIGUOUS, r7['outcomes']))

    # ── 8. A DANGLING REFERENCE IS NOT AN ABSENCE. ─────────────────────────────────
    be8 = RecordingBackend()
    c8, _ = build_clusters([_rec('trivy', 'CVE-4', 'w', 'id-dang', aliases=['cve-4'])])
    r8 = reconcile(c8, [], be8, {c8[0]['cluster_key']: {'ref': '999'}}, apply_changes=True, approval=APPR)
    if be8.created:
        fails.append('a dangling reference licensed a creation -- an unresolved reference was '
                     'treated as an absence')
    if r8['outcomes'].get(BINDING_DANGLING) != 1:
        fails.append('a ledger reference missing from a complete sweep did not report %s: %r'
                     % (BINDING_DANGLING, r8['outcomes']))

    # ── 9. THE CONTROL BEING OFF IS ITS OWN STATE. ─────────────────────────────────
    c9, w9 = build_clusters([_rec('trivy', 'CVE-5', 'v', 'id-off', aliases=['cve-5'])])
    r9 = reconcile(c9, w9, None, {}, apply_changes=True, approval=APPR)
    s9 = render_summary(r9)
    if 'control is off' not in s9.lower():
        fails.append('an unconfigured backend did not report that the control is off')
    if BINDING_ABSENT in r9['outcomes']:
        fails.append('an unconfigured backend produced a lookup outcome it never looked up')

    # 9b. Two backends configured at once is refused by name, not guessed.
    both = {'GH_TOKEN': 'x', ENV_REPO: 'o/r', ENV_STAMP_LABEL: 'l', 'JIRA_HOST': 'h',
            'JIRA_EMAIL': 'e', 'JIRA_TOKEN': 't', 'JIRA_PROJECT': 'P'}
    b, note = choose_backend(both)
    if b is not None or 'CONFIGURATION DEFECT' not in note:
        fails.append('two configured backends did not refuse by name: %r' % note)
    # AND A SELECTOR DOES NOT MAKE IT ACCEPTABLE (C-2, KDEC-004). This used to assert the
    # opposite; TC 4.6 makes one backend authoritative per cell, and a run holding a second
    # tracker's credential is one edit from writing to it.
    both2 = dict(both)
    both2[ENV_BACKEND] = 'github'
    b2, n2 = choose_backend(both2)
    if b2 is not None or 'CONFIGURATION DEFECT' not in n2:
        fails.append('two configured backends were accepted because a selector named one: %r'
                     % n2)
    # The valid counterpart: one backend's credentials alone resolve.
    b3, _n3 = choose_backend({'GH_TOKEN': 'x', ENV_REPO: 'o/r', ENV_STAMP_LABEL: 'l'})
    if b3 is None or b3.name != 'github':
        fails.append('a single complete credential set did not resolve its backend')

    # 9b-ii. L55 / TICKETING_BACKENDS.md T-11. A run that could not establish the ticketing claim
    #     says so in the claim itself: EVIDENCE_UNTRUSTED, the obligations carried by name. Four
    #     ways in -- the control off, the lookup unestablished, every finding withheld -- and
    #     the clean counterpart, which must NOT be untrusted.
    def _claim(r):
        return (r.get('ticketing_claim') or {}).get('routing_result')
    if _claim(r9) != EVIDENCE_UNTRUSTED:
        fails.append('the control being off produced ticketing claim %r, not %s (L55)'
                     % (_claim(r9), EVIDENCE_UNTRUSTED))
    if len(r9.get('obligations') or []) != 1:
        fails.append('the control being off carried %d obligation(s) for 1 cluster; the finding '
                     'lost its only tracking surface and nothing says so (L55)'
                     % len(r9.get('obligations') or []))
    r9u = reconcile(*build_clusters([_rec('trivy', 'CVE-9U', 'v', 'id-9u', aliases=['cve-9u'])]),
                    backend=RecordingBackend(sweep_complete=False), ledger={},
                    apply_changes=True, approval=APPR)
    if _claim(r9u) != EVIDENCE_UNTRUSTED or len(r9u.get('obligations') or []) != 1:
        fails.append('a partial sweep left the claim %r with %d obligation(s) (L55)'
                     % (_claim(r9u), len(r9u.get('obligations') or [])))
    r9w = reconcile(*build_clusters([_rec('semgrep', 'r', 'a.py', '', state='UNFINGERPRINTABLE')]),
                    backend=RecordingBackend(), ledger={}, apply_changes=True, approval=APPR)
    if _claim(r9w) != EVIDENCE_UNTRUSTED:
        fails.append('every finding withheld produced claim %r -- a run that ticketed nothing '
                     'because nothing could be keyed read as fine (L55)' % _claim(r9w))
    if _claim(r1) == EVIDENCE_UNTRUSTED or r1.get('obligations'):
        fails.append('a healthy creating run was itself reported untrusted, so the claim refuses '
                     'everything and means nothing')
    if 'EVIDENCE_UNTRUSTED' not in render_summary(r9):
        fails.append('the summary of a run with the control off does not state the claim')

    # 9c. An unreadable ledger is not an empty one.
    led, note = load_ledger(os.path.join(ROOT, 'does-not-exist-%s.json' % os.getpid()))
    if led != {}:
        fails.append('a missing ledger was not treated as empty')
    if 'establishes nothing' not in note:
        fails.append('a missing ledger was reported as evidence that no tickets exist')

    # ── 10. NO CREDENTIAL REACHES A MESSAGE. ───────────────────────────────────────
    for probe in ('Authorization: Bearer abc123', 'basic Zm9vOmJhcg==', 'token ghp_xyz'):
        if 'withheld' not in _no_credential_in(probe):
            fails.append('a credential-shaped detail was not withheld: %r' % probe)
    if 'withheld' in _no_credential_in('HTTP 404'):
        fails.append('an ordinary detail was withheld, so the guard is a blanket refusal rather '
                     'than a discriminating one')

    # ── 11. LOOKUP IS NOT BY MESSAGE TEXT. ─────────────────────────────────────────
    #
    # Same identity, same aliases, completely different message and rule spelling -- the shape of a
    # scanner upgrade. It must bind to the existing ticket, not create a second one.
    be11 = RecordingBackend()
    before = _rec('trivy', 'CVE-2024-7777', 'go.mod', 'id-up', aliases=['cve-2024-7777'])
    before['message'] = 'old wording from the previous scanner generation'
    c11, _ = build_clusters([before])
    reconcile(c11, [], be11, {}, apply_changes=True, approval=APPR)
    after = _rec('trivy', 'TRIVY-RENAMED-RULE', 'go.mod', 'id-up', aliases=['cve-2024-7777'])
    after['message'] = 'entirely new wording after the upgrade'
    c11b, _ = build_clusters([after])
    if c11b[0]['cluster_key'] != c11[0]['cluster_key']:
        fails.append('a rule rename changed the cluster key, so an upgrade would duplicate every '
                     'ticket in the estate')
    reconcile(c11b, [], be11, {}, apply_changes=True, approval=APPR)
    if len(be11.created) != 1:
        fails.append('a scanner upgrade created a duplicate: %d ticket(s)' % len(be11.created))

    # ── 12. A TICKET SAYS WHAT IT IS NOT. ─────────────────────────────────────────
    body = render_body(c4[0]) if c4 else ''
    for need in ('not a disposition', 'suppresses nothing', 'does not clear the finding'):
        if need not in body:
            fails.append('the ticket body does not say %r, so a reader may take it for an '
                         'authorization' % need)
    if STAMP_PREFIX not in body or c4[0]['cluster_key'] not in body:
        fails.append('the ticket body does not carry the cluster stamp, so no future run can '
                     'find it')
    # 12b. The block is re-appended, never used to replace a human's notes.
    human = 'Triage note from a person.\n\n' + body
    merged = render_body(c4[0], existing=human)
    if 'Triage note from a person.' not in merged:
        fails.append('re-rendering a body destroyed text outside the machine-owned block')
    damaged = 'Triage note only, delimiters gone.'
    repaired = render_body(c4[0], existing=damaged)
    if 'Triage note only' not in repaired or BLOCK_OPEN not in repaired:
        fails.append('a body with damaged delimiters was rewritten from scratch instead of being '
                     'appended to')

    # 12c. T-02: A MEMBERS-ADDED UPDATE ON A TRACKER WHOSE SWEEP RETURNS NO BODY (Jira, Azure
    #      DevOps) keeps every byte a person wrote outside the block. It used to render the block
    #      against the sweep's empty body and write that back -- the whole description replaced.
    t02a = _rec('trivy', 'CVE-T02', 'go.mod', 'id-t02a', aliases=['cve-t02', 'ghsa-t02'])
    t02b = _rec('grype', 'GHSA-T02', 'go.mod', 'id-t02b', aliases=['ghsa-t02', 'cve-t02'])
    before_h, after_h = 'Triage: owned by payments.\n\n', '\n\nWorkaround: pinned in prod.\n'
    for unreadable in (False, True):
        be12 = RecordingBackend(sweep_returns_body=False)
        led12 = {}
        reconcile(build_clusters([t02a])[0], [], be12, led12, apply_changes=True, approval=None)
        rec12 = [r for recs in be12.store.values() for r in recs]
        if len(rec12) != 1:
            fails.append('T-02: the first run made %d ticket(s), expected 1' % len(rec12))
            break
        rec12[0]['body'] = before_h + rec12[0]['body'] + after_h
        if unreadable:
            be12.unreadable.add(rec12[0]['ref'])
        r12 = reconcile(build_clusters([t02a, t02b])[0], [], be12, led12, apply_changes=True,
                        approval=None)
        body12 = rec12[0]['body']
        if not unreadable:
            if not be12.block_updates:
                fails.append('T-02: a member joined and the block was never rewritten, so '
                             'preservation was not tested')
            elif not (body12.startswith(before_h) and body12.endswith(after_h)):
                fails.append('T-02: A MEMBERS-ADDED UPDATE ERASED THE HUMAN TEXT outside the '
                             'machine-owned block: %r' % body12[:80])
            elif 'id-t02b' not in body12 or body12.count(BLOCK_OPEN) != 1:
                fails.append('T-02: the rewritten block lacks the joined member or is duplicated')
        else:
            if be12.block_updates:
                fails.append('T-02: AN UNREADABLE DESCRIPTION WAS WRITTEN ANYWAY -- a blind '
                             'overwrite of whatever a person wrote')
            if not any(o.get('outcome') == BINDING_UNESTABLISHED
                       for o in r12.get('obligations') or []) or \
                    (r12.get('ticketing_claim') or {}).get('routing_result') != EVIDENCE_UNTRUSTED:
                fails.append('T-02: an unreadable description was not carried as %s with an '
                             'untrusted claim: %r' % (BINDING_UNESTABLISHED, r12.get('obligations')))
            # And the members it could not write are OWED, so the next readable run writes them.
            be12.unreadable.clear()
            reconcile(build_clusters([t02a, t02b])[0], [], be12, led12, apply_changes=True,
                      approval=None)
            if 'id-t02b' not in rec12[0]['body'] or not rec12[0]['body'].startswith(before_h):
                fails.append('T-02: after an unreadable run, the next readable run did not write '
                             'the owed member while keeping the human text')

    # ── 13. THE GATE IS CLASSIFIED, NOT BLANKET. BOTH SIDES, OR IT PROVES NOTHING. ──
    #
    # 13a. ROUTINE RECONCILIATION RUNS UNATTENDED. `--apply`, no approver, and a ticket is
    #      created. This is the CORRECTED DEFECT and it is asserted as a positive: a suite that
    #      only proved the refusal would pass against a reconciler that refuses everything, and
    #      "everything is refused" is a broken pipeline rather than a control.
    be13 = RecordingBackend()
    c13, w13 = build_clusters([_rec('trivy', 'CVE-13', 'go.mod', 'id-13', aliases=['cve-13'])])
    r13 = reconcile(c13, w13, be13, {}, apply_changes=True, approval=None)
    if len(be13.created) != 1:
        fails.append('APPLY MODE WITH NO APPROVER CREATED %d TICKET(S), expected 1. Routine, '
                     'deterministic, evidence-backed reconciliation must run unattended -- a '
                     'reconciler that needs a person for every create is one nobody will run.'
                     % len(be13.created))
    if r13['refused_disposition']:
        fails.append('a routine creation was reported as a refused disposition: %r'
                     % r13['refused_disposition'])
    if r13['created'] and r13['created'][0].get('ticket_class') != REMEDIATION_WORK_ITEM:
        fails.append('an unattended creation opened something other than %s'
                     % REMEDIATION_WORK_ITEM)
    s13 = render_summary(r13)
    if 'UNATTENDED' not in s13:
        fails.append('the summary did not say the routine run was unattended, so a reader cannot '
                     'tell an unattended success from a withheld plan')

    # 13b. A DISPOSITION IS REFUSED WITHOUT AN APPROVER, and the refusal is its OWN outcome --
    #      not a dry run, not an ambiguity, not a silent skip.
    for word in sorted(DISPOSITION_REQUESTS):
        be_d = RecordingBackend()
        rec_d = _rec('trivy', 'CVE-D', 'go.mod', 'id-d-%s' % word, aliases=['cve-d-%s' % word])
        rec_d['requested_disposition'] = word
        cd, wd = build_clusters([rec_d])
        rd = reconcile(cd, wd, be_d, {}, apply_changes=True, approval=None)
        if be_d.created:
            fails.append('an unapproved %r DISPOSITION reached the tracker' % word)
        if not rd['refused_disposition']:
            fails.append('an unapproved %r disposition was not reported as refused -- it would '
                         'read as a clean run' % word)
        if rd['applied_disposition']:
            fails.append('an unapproved %r disposition was recorded as applied' % word)
    s13b = render_summary(rd)
    if 'disposition(s) refused' not in s13b:
        fails.append('the summary did not report the refused disposition as its own outcome')

    # 13c. A HOLLOW APPROVAL IS NOT AN APPROVAL, on the disposition path.
    for label, bad in (('not granted', tm.Approval('platform-security', 'a stated reason here',
                                                   granted=False)),
                       ('no actor', tm.Approval('', 'a stated reason here')),
                       ('thin reason', tm.Approval('platform-security', 'ok'))):
        be_x = RecordingBackend()
        rec_x = _rec('trivy', 'CVE-X', 'go.mod', 'id-x', aliases=['cve-x'])
        rec_x['requested_disposition'] = 'risk_acceptance'
        cx, wx = build_clusters([rec_x])
        rx = reconcile(cx, wx, be_x, {}, apply_changes=True, approval=bad)
        if be_x.created or rx['applied_disposition']:
            fails.append('a disposition proceeded with an approval that was %s' % label)

    # 13d. AND WITH A PROPER APPROVAL THE DISPOSITION PROCEEDS, in its request class. Without
    #      this, 13b and 13c hold against a reconciler that refuses every disposition for ever.
    be13d = RecordingBackend()
    rec13d = _rec('trivy', 'CVE-13D', 'go.mod', 'id-13d', aliases=['cve-13d'])
    rec13d['requested_disposition'] = 'risk_acceptance'
    c13d, w13d = build_clusters([rec13d])
    r13d = reconcile(c13d, w13d, be13d, {}, apply_changes=True, approval=APPR)
    if len(be13d.created) != 1:
        fails.append('an APPROVED disposition created %d ticket(s), expected 1. A disposition '
                     'nobody can ever approve is an obligation nobody can carry honestly.'
                     % len(be13d.created))
    if not r13d['applied_disposition']:
        fails.append('an approved disposition was not recorded as applied, so the approval left '
                     'no trace')
    elif r13d['applied_disposition'][0]['approved_by'] != 'platform-security':
        fails.append('an applied disposition did not record WHO approved it')
    if r13d['created'] and r13d['created'][0].get('ticket_class') != ACCEPTED_RISK_REQUEST:
        fails.append('an approved risk-acceptance request opened a %r rather than a %s, so the '
                     'governance stream cannot see what was asked for'
                     % (r13d['created'][0].get('ticket_class'), ACCEPTED_RISK_REQUEST))

    # 13e. AN UNRECOGNISED REQUEST WORD REFUSES. It is not downgraded to ordinary work: that
    #      would turn "we are asking you to accept this risk" into "please fix this", and the
    #      asking would disappear. Refused even WITH a valid approval, because the class of the
    #      mutation was never stated.
    be13e = RecordingBackend()
    rec13e = _rec('trivy', 'CVE-13E', 'go.mod', 'id-13e', aliases=['cve-13e'])
    rec13e['requested_disposition'] = 'risk-accepted'
    c13e, w13e = build_clusters([rec13e])
    r13e = reconcile(c13e, w13e, be13e, {}, apply_changes=True, approval=APPR)
    if be13e.created:
        fails.append('an UNRECOGNISED disposition request (%r, a near miss of risk_acceptance) '
                     'was acted on. A near-miss request treated as a known one is worse than a '
                     'wild one.' % 'risk-accepted')
    if not r13e['refused_disposition']:
        fails.append('an unrecognised disposition request was not reported as refused')
    elif tm.MUTATION_CLASS_NOT_STATED not in r13e['refused_disposition'][0]['reason']:
        fails.append('an unrecognised disposition request was refused without naming %s, so a '
                     'reader cannot tell it from a missing approval: %r'
                     % (tm.MUTATION_CLASS_NOT_STATED,
                        r13e['refused_disposition'][0]['reason']))

    # ── 14. PARENT AND CHILDREN, EACH CARRYING ITS OWN STATE. ────────────────────
    be14 = RecordingBackend()
    three = [
        _rec('trivy', 'CVE-14', 'go.mod', 'id-14a', aliases=['cve-14']),
        _rec('grype', 'GHSA-14', 'go.mod', 'id-14b', aliases=['cve-14']),
        _rec('osv', 'CVE-14', 'go.mod', 'id-14c', aliases=['cve-14']),
    ]
    c14, w14 = build_clusters(three)
    r14 = reconcile(c14, w14, be14, {}, apply_changes=True, approval=APPR)
    if len(be14.created) != 1:
        fails.append('a correlated cluster produced %d parent ticket(s)' % len(be14.created))
    if len(r14['tickets']) != 1:
        fails.append('the result carried %d ticket object(s)' % len(r14['tickets']))
    else:
        tk = r14['tickets'][0]
        if len(tk['tasks']) != 3:
            fails.append('three members produced %d child task(s) -- without children a '
                         'partially-fixed cluster is indistinguishable from an untouched one'
                         % len(tk['tasks']))
        if tk['progress']['total'] != 3 or tk['progress'][tm.OPEN] != 3:
            fails.append('child progress disagreed with the children: %r' % tk['progress'])
        if tk['ticket']['state'] != tm.DRAFT:
            fails.append('a created parent is %s rather than %s -- a ticket this program opens '
                         'is a proposal' % (tk['ticket']['state'], tm.DRAFT))
        if len(set(t['task_id'] for t in tk['tasks'])) != 3:
            fails.append('child tasks share ids, so they cannot carry separate state')
    # The children must be visible in the ticket body, or the parent/child shape exists only in
    # memory and a human reading the ticket still sees one undifferentiated obligation.
    body14 = render_body(c14[0], ticket=tm.build_ticket(c14[0], 'ticket-14')[0],
                         tasks=tm.build_ticket(c14[0], 'ticket-14')[1])
    if 'Child tasks' not in body14 or body14.count('task-') < 3:
        fails.append('the ticket body does not show the child tasks')
    if 'cannot close while any child is open' not in body14:
        fails.append('the body does not state that the parent cannot close over open children')

    # ── 15. THE COMPLIANCE PAIRING REACHES THE TICKET AND THE SUMMARY. ──────────
    be15 = RecordingBackend()
    # IAC_PLAN pairs to a framework gap review; SOURCE_DEPENDENCY deliberately pairs to nothing.
    c15, w15 = build_clusters([
        _rec('checkov', 'CKV-1', 'main.tf', 'id-iac', aliases=['cwe-16'], subject='IAC_PLAN'),
        _rec('trivy', 'CVE-15', 'go.mod', 'id-dep', aliases=['cve-15'],
             subject='SOURCE_DEPENDENCY'),
    ])
    r15 = reconcile(c15, w15, be15, {}, apply_changes=True, approval=APPR)
    if r15['compliance'].get(tm.FRAMEWORK_GAP_REVIEW) != 1:
        fails.append('an IAC_PLAN cluster did not pair to %s: %r'
                     % (tm.FRAMEWORK_GAP_REVIEW, r15['compliance']))
    if r15['compliance'].get(tm.PAIRING_NOT_ESTABLISHED) != 1:
        fails.append('a deliberately unpaired subject did not report %s: %r'
                     % (tm.PAIRING_NOT_ESTABLISHED, r15['compliance']))
    s15 = render_summary(r15)
    if 'Compliance pairing' not in s15 or tm.FRAMEWORK_GAP_REVIEW not in s15:
        fails.append('the compliance pairing is not in the summary a human reads')
    if 'second obligation' not in s15:
        fails.append('the summary does not say a compliance review is a SECOND obligation, so a '
                     'reader may take remediation as discharging it')
    if 'does NOT establish that none is' not in s15:
        fails.append('the summary let %s read as "no review required"'
                     % tm.PAIRING_NOT_ESTABLISHED)

    # ── 16. CONFIDENCE IS A DERIVED LABEL, AND NEVER A NUMBER. ─────────────────
    if r14['confidence'].get(tm.CORROBORATED_ANCHORED) != 1:
        fails.append('three scanners did not yield %s: %r'
                     % (tm.CORROBORATED_ANCHORED, r14['confidence']))
    tkt = r14['tickets'][0]['ticket']
    if isinstance(tkt.get('confidence'), (int, float)):
        fails.append('confidence reached the ticket as a NUMBER. A figure without provenance is '
                     'numerology, and a defaulted one is worse than a label')
    if not tkt.get('confidence_basis') or len(tkt['confidence_basis']) < 20:
        fails.append('a confidence label travelled without the derivation that produced it')
    for scanner in ('trivy', 'grype', 'osv'):
        if scanner not in tkt['confidence_basis']:
            fails.append('the derivation does not name %s, so it cannot be checked' % scanner)
    # A DEGRADED CHANNEL (T5, N41). This used to assert that a partial sweep claimed no
    # corroboration -- and it held vacuously: a partial sweep never reaches BINDING_ABSENT, so no
    # ticket is built and the confidence dict is always empty. With the degraded-channel guard
    # in derive_confidence removed, it still passed. docs/PROOF_RULE.md: a check that cannot fail is
    # retired, and where the property IS proven is named -- `ticket_model.py --self-test`
    # section 11 drives derive_confidence(channel_degraded=True) and requires
    # CONFIDENCE_NOT_ESTABLISHED and a FLOOR derivation; mutant "confidence claims corroboration
    # on a degraded channel" in tests/prove_ticket_idempotency.py kills against it.
    # What the RECONCILER owes on a partial sweep is asserted here instead, and it can fail:
    # nothing is built or created, and the outcome is unestablished.
    be16 = RecordingBackend(sweep_complete=False)
    c16, w16 = build_clusters(three)
    r16 = reconcile(c16, w16, be16, {}, apply_changes=True, approval=APPR)
    if r16['tickets'] or be16.created or r16['outcomes'].get(BINDING_UNESTABLISHED) != 1:
        fails.append('a partial sweep built %d ticket(s), created %d, outcomes %r; nothing may be '
                     'built from a floor' % (len(r16['tickets']), len(be16.created),
                                             r16['outcomes']))
    if 'No percentage is given' not in render_summary(r14):
        fails.append('the summary does not say that no percentage is derivable')

    # ── 17. AN ELAPSED DEFERRAL IS VISIBLE IN THE ORDINARY OUTPUT. ─────────────
    #
    # No flag enables this section and nobody has to ask for it. A past-due acceptance that only
    # appears under a switch is a past-due acceptance nobody sees.
    # THE DEFERRAL IS UNDER A DIFFERENT CLUSTER KEY THAN THE ONE BEING RECONCILED, deliberately.
    # The sweep must cover the WHOLE ledger: a finding that stopped being reported -- fixed, or
    # no longer scanned -- still has an acceptance recorded against it, and that acceptance must
    # not become invisible because the scanner went quiet.
    def _led17():
        return {'0' * 32: {'ref': '17', 'backend': 'recording',
                           'deferrals': {'ticket-17/task-1': {
                               'reason': 'upstream has no patch', 'until': '2026-06-30'}}}}

    be17 = RecordingBackend()
    c17, w17 = build_clusters([_rec('trivy', 'CVE-17', 'go.mod', 'id-17', aliases=['cve-17'])])
    led17 = _led17()
    r17 = reconcile(c17, w17, be17, led17, apply_changes=True, approval=None,
                    today='2026-10-08')
    if not r17['past_due']:
        fails.append('A PAST-DUE DEFERRAL WAS NOT REPORTED. It would go on suppressing silently, '
                     'which is the defect the deferral discipline exists to prevent')
    elif r17['past_due'][0]['state'] != tm.DEFERRAL_PAST_DUE:
        fails.append('an elapsed deferral was reported as %s' % r17['past_due'][0]['state'])
    s17 = render_summary(r17)
    if 'PAST DUE' not in s17:
        fails.append('the past-due deferral is not in the summary a person reads')
    for needle in ('Nothing reopened', 'quietly suppressing'):
        if needle not in s17:
            fails.append('the past-due section does not say %r, so a reader cannot tell what the '
                         'run did and did not do' % needle)
    # It is reported in a run that is otherwise entirely clean -- and the routine creation still
    # happened unattended beside it. The review obligation does not block reconciliation.
    if not r17['created']:
        fails.append('a past-due deferral elsewhere in the ledger stopped routine reconciliation')
    # A deferral still in term is NOT reported. Without this, the signal is noise and a reader
    # learns to ignore the section.
    r17b = reconcile(*build_clusters([_rec('trivy', 'CVE-17', 'go.mod', 'id-17',
                                           aliases=['cve-17'])]),
                     backend=RecordingBackend(), ledger=_led17(), apply_changes=True,
                     approval=None, today='2026-06-01')
    if r17b['past_due']:
        fails.append('a deferral still in term was reported as past due: %r' % r17b['past_due'])
    # NO REFERENCE DATE IS NOT "NOTHING ELAPSED". It is DEFERRAL_TERM_UNKNOWN, reported.
    r17c = reconcile(*build_clusters([_rec('trivy', 'CVE-17', 'go.mod', 'id-17',
                                           aliases=['cve-17'])]),
                     backend=RecordingBackend(), ledger=_led17(), apply_changes=True,
                     approval=None, today=None)
    if not r17c['past_due'] or r17c['past_due'][0]['state'] != tm.DEFERRAL_TERM_UNKNOWN:
        fails.append('a run with no reference date reported %r rather than %s -- "we did not '
                     'check" must not read as "nothing has elapsed"'
                     % (r17c['past_due'], tm.DEFERRAL_TERM_UNKNOWN))
    # A deferral with no end date at all is reported too. It is the original defect, and it must
    # not be the one case that stays quiet.
    led17d = {'0' * 32: {'ref': '17', 'deferrals': {'t/1': {'reason': 'waiting'}}}}
    r17d = reconcile(*build_clusters([_rec('trivy', 'CVE-17', 'go.mod', 'id-17',
                                           aliases=['cve-17'])]),
                     backend=RecordingBackend(), ledger=led17d, apply_changes=True,
                     approval=None, today='2026-10-08')
    if not r17d['past_due']:
        fails.append('an UNDATED deferral was not surfaced. An absent expiry is not an '
                     'open-ended one; it is the suppression hole this kit already shipped once')
    # A malformed deferral record is reported rather than skipped.
    led17e = {'0' * 32: {'ref': '17', 'deferrals': {'t/1': 'not an object'}}}
    r17e = reconcile(*build_clusters([_rec('trivy', 'CVE-17', 'go.mod', 'id-17',
                                           aliases=['cve-17'])]),
                     backend=RecordingBackend(), ledger=led17e, apply_changes=True,
                     approval=None, today='2026-10-08')
    if not r17e['past_due']:
        fails.append('a malformed deferral record was silently skipped -- a suppression nobody '
                     'can account for is worse than one that elapsed')
    # AND THE SWEEP MUTATES NOTHING. Nothing reopens, nothing is cleared, nothing is extended.
    # Compared on the DEFERRAL SUBTREE rather than the whole ledger, because the run legitimately
    # binds the new cluster into it -- that is the routine half working, not the sweep acting.
    led17f = _led17()
    before = json.dumps(led17f['0' * 32]['deferrals'], sort_keys=True)
    reconcile(*build_clusters([_rec('trivy', 'CVE-17', 'go.mod', 'id-17', aliases=['cve-17'])]),
              backend=RecordingBackend(), ledger=led17f, apply_changes=True, approval=None,
              today='2026-10-08')
    if json.dumps(led17f['0' * 32]['deferrals'], sort_keys=True) != before:
        fails.append('THE PAST-DUE SWEEP MUTATED THE LEDGER. Observing an elapsed deferral must '
                     'not resolve it: that is the reference engine\'s defect, where the date '
                     'passing performed the reopen with the system recorded as the actor')

    # ── 18. T-06: DEGRADED FOR MORE THAN ONE RUN IS A GOVERNANCE FACT (TC 4.1, TC 8). ──────
    #
    # An obligation carried because the lookup did not complete records HOW MANY consecutive runs
    # it has been carried and SINCE WHEN -- not only the last cause. Past the owner's threshold the
    # run escalates it as owed to a person (DECISION_REQUIRED at the cell's promotion review).
    # A run that establishes the binding ends the streak, so "consecutive" means consecutive.
    rec18 = _rec('trivy', 'CVE-18', 'go.mod', 'id-18', aliases=['cve-18'])
    key18 = build_clusters([rec18])[0][0]['cluster_key']
    led18 = {}
    runs18 = []
    for day in ('2026-10-01', '2026-10-02', '2026-10-03'):
        be18 = RecordingBackend(sweep_complete=False)
        be18.degraded_threshold = 3
        runs18.append(reconcile(build_clusters([rec18])[0], [], be18, led18, apply_changes=True,
                                approval=None, today=day))
    owed18 = (led18.get(key18) or {}).get('owed') or {}
    if owed18.get('attempts') != 3 or owed18.get('first_degraded_at') != '2026-10-01':
        fails.append('T-06: three consecutive degraded runs recorded %r; expected attempts 3 since '
                     '2026-10-01 (TC 8: outcome, cause, attempts, first-degraded-at)' % owed18)
    if runs18[1].get('degraded_escalations') or not runs18[2].get('degraded_escalations'):
        fails.append('T-06: the escalation fired at the wrong run: run 2 %r, run 3 %r (threshold '
                     '3)' % (runs18[1].get('degraded_escalations'),
                             runs18[2].get('degraded_escalations')))
    elif DECISION_REQUIRED not in render_summary(runs18[2]) or \
            'consecutive' not in render_summary(runs18[2]):
        fails.append('T-06: the summary does not report the escalation as owed to a person')
    # A healthy run ends the streak; the next degraded run counts from one again. The healthy run
    # BINDS an existing ticket (not a create, which rewrites the entry anyway), so the streak is
    # ended by the lookup establishing the binding.
    be18h = RecordingBackend()
    be18h.store[key18] = [{'ref': '18', 'url': 'memory://18', 'state': 'open',
                           'body': render_body(build_clusters([rec18])[0][0])}]
    reconcile(build_clusters([rec18])[0], [], be18h, led18, apply_changes=True, approval=None,
              today='2026-10-04')
    be18d = RecordingBackend(sweep_complete=False)
    be18d.degraded_threshold = 3
    reconcile(build_clusters([rec18])[0], [], be18d, led18, apply_changes=True, approval=None,
              today='2026-10-05')
    owed18b = (led18.get(key18) or {}).get('owed') or {}
    if owed18b.get('attempts') != 1 or owed18b.get('first_degraded_at') != '2026-10-05':
        fails.append('T-06: after a run that established the binding, the next degraded run '
                     'carried %r; the streak must restart at 1' % owed18b)

    # ── 19. T-13: ACT ON DELTAS (TC 5.1, 6.1). ───────────────────────────────────────────
    #
    # The ticket is rewritten when something in the 5.1 set CHANGED -- effective severity, the
    # contributing scanners (a scanner that stopped is NAMED as stopped, never omitted), members
    # that went unobserved (POTENTIALLY_ABSENT, never "fixed") -- and ONLY then. An unchanged run
    # with the ledger carried costs no read and no write; last-seen goes to the ledger every run.
    def _t13(ledger_carried):
        be = RecordingBackend(sweep_returns_body=False)
        led = {}
        a13 = _rec('trivy', 'CVE-T13', 'go.mod', 'id-t13a', aliases=['cve-t13'], severity='high')
        b13 = _rec('grype', 'GHSA-T13', 'go.mod', 'id-t13b', aliases=['cve-t13'],
                   severity='high')
        steps = []
        for day, members in (('2026-10-01', [a13, b13]),       # create
                             ('2026-10-02', [a13, b13]),       # unchanged
                             ('2026-10-03', [dict(a13, severity='critical'), b13]),  # severity
                             ('2026-10-04', [dict(a13, severity='critical'), b13]),  # unchanged
                             # trivy stops and a goes unobserved (b now critical too, so the
                             # severity is unchanged and only the membership facts move)
                             ('2026-10-05', [dict(b13, severity='critical')]),
                             ('2026-10-06', [dict(b13, severity='critical')])):  # unchanged
            writes0, reads0 = len(be.block_updates), be.description_reads
            reconcile(build_clusters(members)[0], [], be, led if ledger_carried else {},
                      apply_changes=True, approval=None, today=day)
            steps.append((day, len(be.block_updates) - writes0, be.description_reads - reads0))
        body = [r for recs in be.store.values() for r in recs][0]['body']
        return steps, body, led

    for carried in (True, False):
        steps, body, led = _t13(carried)
        label = 'ledger carried' if carried else 'no ledger (the hosted case, T-20)'
        writes = [w for _d, w, _r in steps]
        if writes != [0, 0, 1, 0, 1, 0]:
            fails.append('T-13 (%s): block writes per run %r, expected [0, 0, 1, 0, 1, 0] -- a '
                         'severity change and a scanner stopping are each ONE write, and an '
                         'unchanged run is none' % (label, writes))
        if carried and [r for _d, _w, r in steps][1] != 0:
            fails.append('T-13: an unchanged run with the ledger carried read the description %d '
                         'time(s); TC 6.1 says no read and no write' % steps[1][2])
        if '| effective severity | critical' not in body:
            fails.append('T-13 (%s): the block does not show the new effective severity' % label)
        if 'no longer contributing' not in body or 'trivy' not in body.split(
                'no longer contributing', 1)[-1].split('\n', 1)[0]:
            fails.append('T-13 (%s): a scanner that stopped contributing is not NAMED as stopped '
                         '(TC 5.1: "named as stopped, not omitted")' % label)
        if 'POTENTIALLY_ABSENT' not in body or 'id-t13a' not in body.split(
                'POTENTIALLY_ABSENT', 1)[-1]:
            fails.append('T-13 (%s): a member no longer observed is not marked POTENTIALLY_ABSENT '
                         'in the block' % label)
        if carried and (led.get(next(iter(led))) or {}).get('last_seen') != '2026-10-06':
            fails.append('T-13: last-seen was not recorded in the ledger on the last run: %r'
                         % (led.get(next(iter(led))) or {}).get('last_seen'))
    # A member joining with NOTHING else changed (same scanner, same severity) is a delta on its
    # own: one write, and the block names the new member.
    be19 = RecordingBackend(sweep_returns_body=False)
    led19 = {}
    m19 = [_rec('grype', 'GHSA-T19A', 'go.mod', 'id-t19a', aliases=['cve-t19']),
           _rec('grype', 'GHSA-T19B', 'go.mod', 'id-t19b', aliases=['cve-t19'])]
    reconcile(build_clusters(m19[:1])[0], [], be19, led19, apply_changes=True, approval=None,
              today='2026-10-01')
    reconcile(build_clusters(m19)[0], [], be19, led19, apply_changes=True, approval=None,
              today='2026-10-02')
    body19 = [r for recs in be19.store.values() for r in recs][0]['body']
    if len(be19.block_updates) != 1 or 'id-t19b' not in body19:
        fails.append('T-13: a member joining from the same scanner at the same severity made %d '
                     'write(s) and the block %s the new member; expected one write naming it'
                     % (len(be19.block_updates),
                        'names' if 'id-t19b' in body19 else 'does not name'))

    for i, f in enumerate(fails, 1):
        print('  %d. %s' % (i, f))
    if fails:
        print('')
        print('SELF-TEST FAILED: %d assertion(s)' % len(fails))
        return 2
    print('')
    print('self-test ok, and NOT vacuously -- the positive case is asserted first:')
    print('  1  a fingerprinted finding against a healthy backend DOES get a ticket')
    print('  2  a second run creates nothing new, by lookup; ledger-bound and backend-bound are')
    print('     both exercised, so each step of the cascade is shown to work on its own')
    print('  3  a finding with no durable identity gets NO ticket, and the withholding is')
    print('     reported as %s rather than counted as clean' % IDENTITY_NOT_ESTABLISHED)
    print('  4  three scanners reporting one condition yield ONE ticket, every contributor named,')
    print('     and the cluster key survives a membership change -- while two subject classes,')
    print('     or two loci, stay two obligations and get two tickets')
    print('  5  dry run is the default and writes nothing')
    print('  6  a partial sweep and an unobservable channel both refuse to license a creation')
    print('  7  ambiguity creates nothing AND updates nothing')
    print('  8  a dangling reference is not an absence')
    print('  9  the control being off is its own state; two backends at once is refused by name')
    print(' 10  no credential reaches a message, and the guard still passes ordinary detail')
    print(' 11  a rule rename does not duplicate: lookup is by identity, never by message text')
    print(' 12  the ticket says it is not a disposition, and a human\'s notes survive a re-render')
    print('     AND a members-added update on a body-less sweep (T-02): the description is read,')
    print('     only the block is replaced, and an unreadable one is never written, only owed')
    print(' 13  ROUTINE RECONCILIATION RUNS UNATTENDED: apply mode with NO approver creates the')
    print('     ticket, because a deterministic evidence-backed work item accepts nothing. A')
    print('     DISPOSITION is refused without a role and a readable reason, the refusal is its')
    print('     own reported outcome, a hollow approval is refused too, an unrecognised request')
    print('     word refuses as %s -- and an APPROVED disposition' % tm.MUTATION_CLASS_NOT_STATED)
    print('     proceeds in its request class, so neither half is a blanket')
    print(' 14  a cluster yields a parent and one child per finding, each with its own state,')
    print('     the parent opens as a DRAFT proposal, and the children are visible in the body')
    print(' 15  compliance pairing reaches the ticket and the summary, names itself a SECOND')
    print('     obligation, and never lets %s read as "none required"' % tm.PAIRING_NOT_ESTABLISHED)
    print(' 16  confidence travels as a label WITH its derivation, never as a number, and a')
    print('     degraded channel refuses to claim corroboration from a floor')
    print(' 17  an elapsed deferral is in the ORDINARY summary with no flag enabling it, across')
    print('     the whole ledger rather than only this run\'s clusters; the undated and malformed')
    print('     cases are reported too; an in-term deferral is NOT reported; no reference date')
    print('     reads as %s rather than as nothing elapsed; the sweep'
          % tm.DEFERRAL_TERM_UNKNOWN)
    print('     mutates nothing; and routine reconciliation runs beside it unaffected')
    return 0


# ═════════════════════════════════════════════════════════════════════════════════════
# RESOLVING A PAST-DUE DEFERRAL
# ═════════════════════════════════════════════════════════════════════════════════════


def sweep_deferrals_cli(args):
    """THE CLOCK (FUTURE_WORK.md D5; TC 5.6; L59). -> exit code. Runs with NO findings.

    REOPENED_BY_LAPSE comes from the calendar, not a diff: on the day an acceptance expires the
    scan is byte-identical to yesterday's, so a pipeline that reacts only to scanner output is
    structurally incapable of seeing it. This is what a schedule runs: the whole ledger, against a
    reference date, reported in the ordinary output. It contacts no tracker and mutates nothing.

    EXIT  0 nothing elapsed   1 past due, or a term that cannot be established
          2 misuse / unreadable ledger   3 no ledger at all: nothing was swept, which is not
            "nothing elapsed" (EVIDENCE_UNTRUSTED)
    """
    if not args.ledger or not os.path.exists(args.ledger):
        text = ('## Past-due deferral sweep\n\n**%s**: no ledger at %s, so NOTHING WAS SWEPT. '
                'This is not "no deferral has elapsed".\n' % (EVIDENCE_UNTRUSTED,
                                                            args.ledger or '<unset>'))
        print(text)
        if args.out:
            io.open(args.out, 'a', encoding='utf-8').write(text + '\n')
        return 3
    ledger, note = load_ledger(args.ledger)
    if ledger is None:
        print('REFUSING: %s' % note, file=sys.stderr)
        return 2
    result = {'apply': False, 'backend': None, 'clusters': 0, 'approval': 'NOT SUPPLIED',
              'outcomes': {}, 'created': [], 'updated': [], 'withheld_no_identity': [],
              'needs_decision': [], 'refused_disposition': [], 'applied_disposition': [],
              'past_due': sweep_past_due(ledger, args.today or None), 'tickets': [],
              'compliance': {}, 'confidence': {}, 'sweep_complete': None, 'probe': None,
              'today': args.today or None, 'notes': [note]}
    L = ['## Past-due deferral sweep (scheduled; no scan, no tracker)', '',
         '| field | value |', '|---|---|',
         '| ledger | %s |' % note,
         '| reference date | %s |' % (args.today or 'NOT SUPPLIED -- nothing can be established '
                                                   'as elapsed or in term'),
         '| deferrals owing a review | %d |' % len(result['past_due']), '']
    # The past-due section is the ordinary summary's own, so the wording cannot drift between the
    # scheduled sweep and an ordinary run.
    text = '\n'.join(L) + '\n' + (('### ' + render_summary(result).split('### ', 1)[-1])
                                  if result['past_due'] else 'No deferral has elapsed.\n')
    print(text)
    if args.out:
        io.open(args.out, 'a', encoding='utf-8').write(text + '\n')
    return 1 if result['past_due'] else 0


def resolve_deferral_cli(args):
    """The authorised way out of DEFERRAL_PAST_DUE. -> exit code.

    TWO DOORS AND NO THIRD. End the acceptance (`reopen`), or renew it to a future date with a
    fresh reason (`extend`). Both are GOVERNANCE_DISPOSITION in the mutation-class table, so
    both refuse without a role and a readable reason, and the refusal is printed rather than
    exited silently.

    THERE IS DELIBERATELY NO "CLEAR" OR "DISMISS". A past-due review obligation that could be
    marked handled without either ending or renewing the acceptance would be a suppression with a
    tidier name, and the tidiness is the danger.
    """
    if not args.ledger:
        print('--resolve-deferral requires --ledger: the deferral lives in it', file=sys.stderr)
        return 2
    if not args.resolution:
        print('--resolve-deferral requires --resolution reopen|extend. There is no third option: '
              'an obligation marked handled without the acceptance being ended or renewed is a '
              'suppression with a tidier name.', file=sys.stderr)
        return 2
    ledger, note = load_ledger(args.ledger)
    if ledger is None:
        print('REFUSING: %s' % note, file=sys.stderr)
        return 2

    found = None
    for cluster_key in sorted(ledger):
        entry = ledger[cluster_key] or {}
        if isinstance(entry, dict) and args.resolve_deferral in (entry.get('deferrals') or {}):
            found = (cluster_key, entry)
            break
    if found is None:
        # NOT "nothing to do". A task id that resolves to no deferral is a dangling reference,
        # and reporting it as a clean run would let a typo read as a resolved obligation.
        print('REFUSING: no deferral recorded for task %r in %s. A task id that resolves to '
              'nothing is a dangling reference, not a resolved obligation.'
              % (args.resolve_deferral, args.ledger), file=sys.stderr)
        return 2

    cluster_key, entry = found
    rec = entry['deferrals'][args.resolve_deferral]
    # A Task carrying exactly the deferral the ledger holds, so the model's own guards -- not a
    # reimplementation of them here -- decide whether this resolution is allowed.
    task = tm.Task(task_id=args.resolve_deferral, parent_ticket_id=entry.get('ref') or '',
                   cluster_key=cluster_key, identity=rec.get('identity') or '',
                   scanner=rec.get('scanner') or '', rule=rec.get('rule') or '',
                   uri=rec.get('uri') or '')
    task.state = tm.DEFERRED
    task.deferred_reason = rec.get('reason')
    task.deferred_until = rec.get('until')

    approval = None
    if args.approved_by or args.approval_reason:
        approval = tm.Approval(actor=args.approved_by, reason=args.approval_reason)

    state, detail = tm.deferral_state(task.deferred_until, args.today or None)
    print('task %s: %s' % (args.resolve_deferral, state))
    print('  %s' % detail)

    if args.resolution == 'reopen':
        err = tm.reopen_deferred(task, approval, trigger=args.trigger,
                                 today=args.today or None)
    else:
        err = tm.extend_deferral(task, approval, deferred_reason=args.deferral_reason,
                                 deferred_until=args.until, today=args.today or None)
    if err:
        print('')
        print('REFUSED: %s' % err)
        print('')
        print('The obligation is UNCHANGED and still %s. A refused resolution leaves the state '
              'exactly as it was' % state)
        print('and the finding still appears in the past-due section of every run -- which is the')
        print('recovery property: a refusal here loses nothing and work can resume safely.')
        return 1

    if args.resolution == 'reopen':
        del entry['deferrals'][args.resolve_deferral]
        print('')
        print('RESOLVED by reopening. The deferral is removed from the ledger and the child task')
        print('is %s again. Approved by %s.' % (tm.OPEN, approval.actor))
    else:
        rec['reason'] = task.deferred_reason
        rec['until'] = task.deferred_until
        print('')
        print('RESOLVED by renewal to %s with a fresh reason. Approved by %s.'
              % (task.deferred_until, approval.actor))
    for h in task.history:
        print('  history: %s -> %s by %s (%s)' % (h['from'], h['to'], h['actor'], h['reason']))
    save_ledger(args.ledger, ledger)
    return 0


# ═════════════════════════════════════════════════════════════════════════════════════


def main(argv):
    ap = argparse.ArgumentParser(
        description='Reconcile findings to tickets. A lookup always precedes a creation.')
    ap.add_argument('--findings', default='',
                    help='JSON array of normalised finding records carrying identity fields')
    ap.add_argument('--ledger', default='',
                    help='the cluster -> ticket map. Read from the checkout; zero API calls.')
    ap.add_argument('--apply', action='store_true',
                    help='PERFORM the plan. Without it nothing is written.')
    # THE APPROVAL IS SEPARATE FROM --apply ON PURPOSE. A schedule can set --apply; a schedule is
    # not a person approving a creation. Both are required before anything is written.
    ap.add_argument('--approved-by', default='',
                    help='the ROLE approving these mutations, never a person\'s name. Required '
                         'with --apply.')
    ap.add_argument('--approval-reason', default='',
                    help='why this DISPOSITION is approved, for the record. Required for a '
                         'disposition; routine reconciliation needs neither.')
    ap.add_argument('--today', default='',
                    help='reference date (YYYY-MM-DD) for the past-due deferral sweep. Absent, '
                         'the sweep reports %s rather than silence.' % tm.DEFERRAL_TERM_UNKNOWN)
    # RESOLVING A PAST-DUE DEFERRAL. Its own flags, because it is a different act from
    # reconciliation and must not be reachable as a side effect of one.
    ap.add_argument('--resolve-deferral', default='',
                    help='task id of a deferral to resolve. A DISPOSITION: needs --approved-by '
                         'and --approval-reason.')
    ap.add_argument('--sweep-deferrals', action='store_true',
                    help='the scheduled clock: sweep the ledger for elapsed deferrals with no '
                         'findings and no tracker (L59). Needs --ledger and --today.')
    ap.add_argument('--resolution', default='', choices=['', 'reopen', 'extend'],
                    help='reopen ends the acceptance; extend renews it to a FUTURE date.')
    ap.add_argument('--until', default='', help='new end date for --resolution extend.')
    ap.add_argument('--trigger', default='',
                    help='what acted, for --resolution reopen. "The date passed" is a '
                         'precondition, not a trigger.')
    ap.add_argument('--deferral-reason', default='',
                    help='fresh reason for --resolution extend. The original is NOT carried '
                         'forward: renewal is a new decision.')
    ap.add_argument('--out', default=os.environ.get('GITHUB_STEP_SUMMARY', ''))
    ap.add_argument('--record', default='',
                    help='write the machine-readable run record (JSON) here.')
    ap.add_argument('--self-test', '--selftest', dest='self_test', action='store_true')
    ap.add_argument('--explain-mutations', action='store_true',
                    help='print the mutation -> class table and exit.')
    args = ap.parse_args(argv[1:])

    if args.self_test:
        return _selftest()
    if args.explain_mutations:
        return tm.explain_mutations()

    if args.resolve_deferral:
        return resolve_deferral_cli(args)
    if args.sweep_deferrals:
        return sweep_deferrals_cli(args)

    if not args.findings:
        print('--findings is required (or --self-test)', file=sys.stderr)
        return 2
    try:
        doc = json.load(io.open(args.findings, encoding='utf-8'))
    except IOError as exc:
        print('cannot read %s: %s' % (args.findings, exc), file=sys.stderr)
        return 2
    except ValueError as exc:
        # Unparseable input is a collection failure wearing a report's clothes. Exiting 0 here
        # would let a broken handoff read as "no findings to ticket".
        print('%s is not valid JSON: %s' % (args.findings, exc), file=sys.stderr)
        return 2
    records = doc if isinstance(doc, list) else (doc.get('findings') or [doc])

    ledger, ledger_note = load_ledger(args.ledger)
    if ledger is None:
        print('REFUSING: %s' % ledger_note, file=sys.stderr)
        print('An unreadable ledger is not an empty one. Continuing would treat every already-'
              'ticketed obligation as unbound and duplicate all of them.', file=sys.stderr)
        return 2

    backend, note = choose_backend()
    print('%s' % note, file=sys.stderr)
    print('%s' % ledger_note, file=sys.stderr)

    clusters, withheld = build_clusters(records)
    approval = None
    if args.approved_by or args.approval_reason:
        approval = tm.Approval(actor=args.approved_by, reason=args.approval_reason)

    result = reconcile(clusters, withheld, backend, ledger, args.apply, approval=approval,
                       today=args.today or None, backend_note=note if backend is None else '')
    result['notes'].insert(0, note)
    result['notes'].insert(1, ledger_note)

    text = render_summary(result)
    print(text)
    if args.out:
        io.open(args.out, 'a', encoding='utf-8').write(text + '\n')
    if args.apply and args.ledger and backend is not None:
        save_ledger(args.ledger, ledger)
    if args.record:
        # The machine-readable run record (TC section 8): backend, outcome distribution, claim,
        # obligations. No credential is ever on the result, so none can reach this file.
        io.open(args.record, 'w', encoding='utf-8').write(
            json.dumps(result, indent=2, sort_keys=True, default=str) + '\n')

    # THE TICKETING CLAIM COULD NOT BE ESTABLISHED: EXIT 3 (L55). Off, misconfigured, two backends,
    # a lookup that did not complete, or every finding withheld. Never 0 -- a run that checked
    # nothing must not read as a run with nothing to do -- and distinct from 1, which is a
    # decision owed. It outranks 1 the way EVIDENCE_UNTRUSTED outranks DECISION_REQUIRED.
    if (result.get('ticketing_claim') or {}).get('routing_result') == EVIDENCE_UNTRUSTED:
        return 3

    # A DECISION OWED TO A PERSON IS EXIT 1. Not a crash and not a pass: the run did its work and
    # is waiting on a judgement. Three things land here and all three are judgements --
    # an ambiguity or a dangling reference, a disposition nobody approved, and a deferral whose
    # term has run out. A PAST-DUE DEFERRAL EXITS 1 EVEN WHEN EVERYTHING ELSE SUCCEEDED, because
    # an elapsed acceptance that exits 0 is an elapsed acceptance nobody will chase.
    return 1 if (result['needs_decision'] or result['refused_disposition']
                 or result['past_due']) else 0


if __name__ == '__main__':
    sys.exit(main(sys.argv))

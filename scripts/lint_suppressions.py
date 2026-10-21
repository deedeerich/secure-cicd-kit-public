#!/usr/bin/env python3
"""Every error suppression must state WHY it is safe.

WHY ANNOTATION RATHER THAN PROHIBITION

`|| true`, `2>/dev/null` and `continue-on-error` are not defects. Some are correct and necessary:
cleanup must run after failure, noisy stderr can be suppressed without losing exit status, a
nonzero exit sometimes genuinely means "nothing found".

Outlawing the syntax produces a lint everybody disables. Requiring a stated reason produces a
RECORD -- so that six months from now, somebody who sees `continue-on-error: true` and tidies it
away has to first read why it exists. That has already happened once here in reverse: a publication
failure killed an entire deep scan because nobody had recorded that publication and detection are
different concerns.

THE ADVERSARIAL QUESTION each annotation must survive:

    If this command fails in a way DIFFERENT from the failure the author expected, what happens?

`grep -c` is the worked example. The author meant "exit 1 = zero matches". `grep` also exits 2 when
it cannot read the file. `|| echo 0` collapsed both, so an unreadable file counted as zero hits --
a multi-state dependency projected into a boolean before its states were understood.

REASONS (see assurance-taxonomy.yaml : suppression_reason)

    PRESENTATION_ONLY                     noise suppressed; exit status and failure state survive
    EXPECTED_NEGATIVE_RESULT              nonzero means "nothing found", and the distinction from
                                          "something broke" is handled explicitly
    FAILURE_ISOLATION_WITH_STATE_CAPTURE  execution continues AND the error becomes propagated data
    CLEANUP_AFTER_FAILURE                 must run after failure; makes no new assurance claim
    UNSAFE                                the signal that determines truth is destroyed -- fix it

THE SECOND KIND OF SUPPRESSION

    The above is about suppressing an ERROR. A finding can be suppressed too, by a disposition --
    and the same question applies with more at stake, because the answer decides whether a real
    vulnerability stops blocking.

    `scripts/scan_report.py` enforces expiry when a disposition HAS one:
    `not_suppressed_because()` returns `EXPIRED <date>` for a lapsed acceptance, and its comment
    gives the reason -- "showing an expiry date while still honouring a lapsed acceptance is how a
    90-day risk acceptance becomes permanent". That is right, and it leaves one hole: when
    `expires` is ABSENT the function returns '' and the disposition suppresses, forever, silently.
    An exception with no end date and nobody's name on it is how a finding disappears permanently.

    So the exceptions check below is the same control as the one above, applied to the governance
    layer: an exception must state WHO owns it and WHEN it ends, and the gate fails when it does
    not. It reports, it does not rewrite -- the registry is the authority and a linter that
    repaired it would be minting approvals.

    WHAT AN EXCEPTION LICENSES, STATED PLAINLY

        It licenses:      a NAMED finding, identified by its DURABLE IDENTITY, not blocking a
                          build, within the scope the record names, until the date it names.
        It does NOT license:
                          * anything about any other finding, including the same weakness in
                            another file or the same file after it moves to a new identity
                          * the finding being absent, fixed, wrong, or safe. The observation is
                            preserved forever and the scanner keeps reporting it
                          * its own renewal. Silence NEVER renews an exception -- the three
                            namespaces that say so are `validation_debt_state.ACCEPTED_DEBT`,
                            `disposition_type` ("approved -> expired ... silence NEVER renews")
                            and `control_weakening.WEAKENING_EXCEPTION_EXPIRED`
                          * being created by whoever benefits from it. A request is not a
                            disposition, and only a merged approval on the protected default
                            branch changes enforcement
                          * being keyed on a message, a rule id or a path alone. Those move; the
                            approval would silently follow them to a different finding

USAGE
    # suppression: PRESENTATION_ONLY -- stderr is noisy; rc is checked on the next line
    some-command 2>/dev/null

    python3 scripts/lint_suppressions.py            report
    python3 scripts/lint_suppressions.py --check    fail on unannotated suppressions
    python3 scripts/lint_suppressions.py --exceptions <path>   lint a disposition registry
    python3 scripts/lint_suppressions.py --self-test
"""

import datetime
import io
import json
import os
import re
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SCAN = [".github/workflows", "scripts", "tests"]
EXT = (".yml", ".yaml", ".sh")

REASONS = {
    "PRESENTATION_ONLY",
    "EXPECTED_NEGATIVE_RESULT",
    "FAILURE_ISOLATION_WITH_STATE_CAPTURE",
    "CLEANUP_AFTER_FAILURE",
    "UNSAFE",
}

IDIOMS = [
    (re.compile(r"\|\|\s*true\b"), "|| true"),
    (re.compile(r"\|\|\s*echo\s+0\b"), "|| echo 0"),
    (re.compile(r"2>\s*/dev/null"), "2>/dev/null"),
    (re.compile(r"continue-on-error:\s*true"), "continue-on-error"),
    (re.compile(r"\bset\s+\+e\b"), "set +e"),
]

ANNOT = re.compile(r"#\s*suppression:\s*([A-Z_]+)")
# STATING A REASON IS NOT SUFFICIENT. Suppression is permissible only when the suppressed signal is
# non-semantic for every relevant consumer, or its meaning survives through another explicit
# channel. So the annotation must name WHAT IS DISCARDED and WHERE IT SURVIVES.
DISCARDS = re.compile(r"#\s*discards:\s*(\S.*)")
PRESERVED = re.compile(r"#\s*preserved[_-]by:\s*(\S.*)")
# How far above a suppression its annotation may sit. Widened from 6 after completing the
# annotations pushed the `suppression:` marker out of range -- the count then dropped and looked
# like a regression when nothing had changed but the lookback. A measuring instrument's own limits
# must not present as a property of the thing measured.
WINDOW = 16


def files():
    for d in SCAN:
        for dp, _, fns in os.walk(os.path.join(ROOT, d)):
            for f in fns:
                if f.endswith(EXT):
                    yield os.path.join(dp, f)


# ─────────────────────────────────────────────────────────────────────────────────────
# THE EXCEPTIONS REGISTRY
# ─────────────────────────────────────────────────────────────────────────────────────
#
# The registered `disposition_type` values, read from the one place that defines them rather than
# respelled here. Respelling is what produced the RISK_ACCEPTED / ACCEPTED_RISK split that made
# the reporter honour nothing written to the registered schema.
SUPPRESSING_STATES = ("FALSE_POSITIVE", "ACCEPTED_RISK", "MITIGATED", "REMEDIATED")

# An owner is a ROLE, never a person. `schemas/disposition-request.schema.json` says why: "A
# pipeline routed to an individual becomes an undocumented API, and needs reconstructive surgery
# when they leave." Any one of these fields satisfies it.
OWNER_FIELDS = ("owner_role", "approved_by", "approver_role", "owner")
EXPIRY_FIELDS = ("expires", "expires_at")

# The two registered `control_weakening` values this check reports. Reused rather than invented:
# an exception with nobody's name on it IS an unattributed weakening, and a lapsed one IS an
# expired exception. Minting a third spelling of either would be the drift the taxonomy gate exists
# to catch.
WEAKENING_UNATTRIBUTED = "WEAKENING_UNATTRIBUTED"
WEAKENING_EXCEPTION_EXPIRED = "WEAKENING_EXCEPTION_EXPIRED"

# A durable identity, as `scripts/finding_identity.py` produces it. The schema requires at least 8
# characters for a reason: a short key collides, and a collision in identity is a finding
# inheriting another finding's approval.
MIN_IDENTITY = 8


def state_is_deferral(rec):
    """-> True when the record's own state word says it is deferred.

    Kept as a named predicate rather than an inline comparison because the deferral checks below
    fire on three different signals, and a reader has to be able to see that the state word is one
    of them rather than inferring it from a long boolean.
    """
    for field in ("state", "disposition_type", "status"):
        if str(rec.get(field) or "").strip().upper() == "DEFERRED":
            return True
    return False


def _parse_date(raw):
    """-> (date, None) or (None, why). An unreadable expiry is NOT an open-ended one."""
    try:
        parts = [int(x) for x in str(raw)[:10].split("-")]
        return datetime.date(*parts), None
    except (ValueError, TypeError):
        return None, "unparseable"


def lint_exceptions(path, today=None):
    """-> (findings, state). Each finding is (key, severity, token, message).

    `state` distinguishes the four answers this kit refuses to collapse: NOT CONFIGURED (no
    registry -- the governance layer is not in place), PRESENT BUT UNREADABLE (a file exists and
    established nothing), EMPTY (a registry with no exceptions in it), and LOADED.

    NOT CONFIGURED IS NOT CLEAN. A missing registry means nothing was checked, and reporting it as
    "no bad exceptions found" is the collapse that lets an absent control read as a passing one.
    """
    today = today or datetime.date.today()
    if not path:
        return [], "NOT CONFIGURED"
    if not os.path.exists(path):
        return [], "NOT CONFIGURED"
    try:
        doc = json.load(io.open(path, encoding="utf-8", errors="replace"))
    except (ValueError, IOError):
        return [], "PRESENT BUT UNREADABLE"

    # Accept the shapes the kit already writes: a bare map, a {"dispositions": ...} wrapper, or a
    # list of records. Reading only one of them would make a valid registry look empty.
    if isinstance(doc, dict) and "dispositions" in doc:
        doc = doc["dispositions"]
    if isinstance(doc, list):
        doc = dict((x.get("fingerprint") or x.get("identity") or "", x)
                   for x in doc if isinstance(x, dict))
    if not isinstance(doc, dict):
        return [], "PRESENT BUT UNREADABLE"
    if not doc:
        return [], "EMPTY"

    out = []
    items = sorted(doc.items())
    for n, (key, rec) in enumerate(items, 1):
        if not isinstance(rec, dict):
            out.append((str(key), "ERROR", "", "not a record"))
            print("   ... linted %d/%d exception(s)" % (n, len(items)), file=sys.stderr)
            continue

        # `requested_disposition` IS DELIBERATELY NOT READ HERE.
        #
        # It is the CLAIM a requester makes, and the schema separates it from `request_state` as
        # "two lifecycles, deliberately not one enum" precisely so that nothing downstream reads a
        # claim as a grant. A pending request carrying `requested_disposition: ACCEPTED_RISK`
        # suppresses nothing -- `forbidden_transition` in the registry says it outright:
        # "proposed -> suppressing (a proposal never buys passage)".
        #
        # The first draft of this function did read it, and its own self-test caught the result: a
        # request that had been approved by nobody was linted as a live exception missing an
        # owner. That is the conflation arriving as a false positive instead of a false negative,
        # but it is the same conflation, and a checker that commits it teaches readers to ignore
        # its output.
        # THE CLAIM AND THE LIFECYCLE ARE TWO FIELDS (L49). schemas/disposition.schema.json puts
        # the claim in `disposition_type` and reserves `state` for the lifecycle, of which only
        # `approved` suppresses. This file read `state` as the claim -- so a record written to
        # the schema was skipped as "not an exception" while a record written the old way was
        # linted as live. The reporter now honours only the schema shape; a record carrying the
        # claim in `state` has silently stopped working, and THAT is a defect to report.
        claim = str(rec.get("disposition_type") or "").strip()
        lifecycle = str(rec.get("state") or "proposed").strip()      # the schema's default
        legacy_shape = (not claim) and lifecycle in SUPPRESSING_STATES
        live = claim in SUPPRESSING_STATES and lifecycle == "approved"

        # Only a live exception, a legacy-shaped one, or a deferral is this check's business. A
        # record in any other lifecycle state is a REQUEST, and a request buys no passage -- it
        # must not be reported as a defective exception.
        #
        # A DEFERRAL IS IN SCOPE EVEN THOUGH IT IS NOT A REGISTERED disposition_type. A deferred
        # finding is not blocking, which makes it a suppression however it is spelled, and the
        # first draft of this scope test let one through: the guard ran before the deferral checks
        # and DEFERRED is not in SUPPRESSING_STATES, so a record deferred by its own state word
        # was skipped entirely by the checks written to catch it.
        if not (live or legacy_shape or state_is_deferral(rec)):
            print("   ... linted %d/%d exception(s)" % (n, len(items)), file=sys.stderr)
            continue
        if legacy_shape:
            out.append((str(key), "ERROR", "",
                        "the claim %s is written in `state`. The schema puts the claim in "
                        "disposition_type and reserves state for the lifecycle (only `approved` "
                        "suppresses); scan_report.py honours nothing written this way, so this "
                        "exception has silently stopped suppressing. Re-write it to the schema"
                        % lifecycle))

        # 1. KEYED ON A DURABLE IDENTITY. A path, a rule id or a message moves; an approval that
        #    followed one of those would land on a different finding and suppress it.
        #
        #    LENGTH ALONE IS NOT ENOUGH, and the first draft of this check proved it: the schema's
        #    `minLength: 8` passed `app/legacy/handler.py` comfortably, so a registry keyed on
        #    file paths would have linted clean. The SHAPE is the test -- a durable identity out
        #    of finding_identity.py is a hex digest, and anything carrying a path separator or a
        #    source extension is a locus wearing an identity's job.
        kstr = str(key or "")
        if not kstr or len(kstr) < MIN_IDENTITY:
            out.append((kstr, "ERROR", "",
                        "key %r is not a durable identity (under %d characters). A short or "
                        "absent key collides, and a collision in identity is one finding "
                        "inheriting another finding's approval" % (key, MIN_IDENTITY)))
        elif not re.match(r"^[0-9a-fA-F]{8,}$", kstr):
            out.append((kstr, "ERROR", "",
                        "key %r is not a durable identity -- it is a %s. finding_identity.py "
                        "produces a hex digest, and a key like this one MOVES: the approval would "
                        "follow it to whatever finding arrives at that location next, and "
                        "suppress that one instead"
                        % (key, "path" if ("/" in kstr or "\\" in kstr) else
                           "rule id or free-text key")))

        # 2. AN OWNER. Not for blame -- for the review that has to happen when it expires.
        if not any(str(rec.get(f) or "").strip() for f in OWNER_FIELDS):
            out.append((str(key), "ERROR", WEAKENING_UNATTRIBUTED,
                        "no owner. An exception nobody owns is a decision nobody has made, and "
                        "there is no one to ask when it lapses. One of: %s"
                        % ", ".join(OWNER_FIELDS)))

        # 3. AN EXPIRY. This WAS the hole in the enforcement path: scan_report.py honoured a
        #    disposition with no `expires` forever, because the absent field read as open-ended.
        #    The schema requires one and the reporter now refuses a record without it (L49) --
        #    so the defect has moved, not gone: a record with no end date is one that silently
        #    suppresses nothing, and a registry full of those is a registry nobody notices has
        #    stopped working.
        raw = next((rec.get(f) for f in EXPIRY_FIELDS if rec.get(f)), None)
        if not raw:
            out.append((str(key), "ERROR", "",
                        "NO EXPIRY. The schema requires one, so scan_report.py refuses this "
                        "record and the finding blocks as though no exception existed. Silence "
                        "must never renew an exception, and an absent end date is silence made "
                        "permanent -- state when it ends"))
        else:
            when, why = _parse_date(raw)
            if when is None:
                out.append((str(key), "ERROR", "",
                            "expiry %r is %s -- an unreadable expiry is not an open-ended one"
                            % (raw, why)))
            elif when < today:
                # Reported as a WARNING rather than an error: the enforcement path already
                # refuses a lapsed disposition, so this is the registry carrying dead weight
                # rather than a live hole. Saying so is still worth it -- a registry full of
                # expired records is how the next reader concludes expiry is not enforced.
                out.append((str(key), "WARN", WEAKENING_EXCEPTION_EXPIRED,
                            "expired %s; scan_report.py already refuses it. Remove it or renew "
                            "it deliberately" % raw))

        # 4. A REASON. The schema requires 30 characters of justification; "please ignore the
        #    scanner" is not a justification.
        just = str(rec.get("rationale") or rec.get("justification") or rec.get("reason") or "")
        if len(just.strip()) < 30:
            out.append((str(key), "ERROR", "",
                        "justification is %d characters; the registered schema requires 30. A "
                        "reason nobody can evaluate cannot be reviewed when it expires"
                        % len(just.strip())))

        # 5b. DEFERRAL DISCIPLINE. A deferral is an exception with a date on it, and it fails the
        #     same way: a deferred finding that nobody re-examines is a permanent silent
        #     exception. Carried from a prior engagement's ticket engine, which required a reason
        #     when a work item became deferred and forbade silent reopening.
        #
        #     BOTH FIELDS OR NEITHER. A record carrying one half of a deferral is the shape that
        #     reads as deferred to one consumer and as active to another.
        d_until = str(rec.get("deferred_until") or "").strip()
        d_reason = str(rec.get("deferred_reason") or "").strip()
        if d_until or d_reason or state_is_deferral(rec):
            if not d_reason:
                out.append((kstr, "ERROR", "",
                            "deferred with no deferred_reason. A deferral nobody justified is "
                            "indistinguishable from a finding that was quietly dropped"))
            if not d_until:
                out.append((kstr, "ERROR", "",
                            "deferred with no deferred_until. The reference pattern treated the "
                            "end date as optional; an absent one is silence made permanent, and "
                            "silence must never renew a deferral"))
            else:
                when, why = _parse_date(d_until)
                if when is None:
                    out.append((kstr, "ERROR", "",
                                "deferred_until %r is %s -- an unreadable date is not an "
                                "open-ended one" % (d_until, why)))

        # 5c. REOPENING IS EXPLICIT, NEVER SILENT. A record that shows it was reopened must name
        #     what reopened it. The end date passing is a PRECONDITION that makes a reopen
        #     available; it is not a trigger that performs one. A reference engine stated this
        #     rule and then reopened past-due items itself, with the actor recorded as the
        #     system -- which bypasses both the rule and the approval it depends on.
        reopened = str(rec.get("reopened_at") or "").strip()
        trigger = str(rec.get("reopen_trigger") or "").strip()
        if reopened and not trigger:
            out.append((kstr, "ERROR", "",
                        "reopened at %s with no reopen_trigger. 'The date passed' is a "
                        "precondition, not a trigger -- something or someone acted, and the "
                        "record has to say which, or an obligation has changed state with "
                        "nobody having decided anything" % reopened))

        # 5. THE REQUESTER IS NOT THE REVIEWER. A PR cannot approve its own request; an exception
        #    whose author reviewed it is a self-signed decision.
        requester = str(rec.get("requester") or "").strip().lower()
        reviewer = str((rec.get("review") or {}).get("reviewer")
                       if isinstance(rec.get("review"), dict)
                       else rec.get("reviewer") or "").strip().lower()
        if requester and reviewer and requester == reviewer:
            out.append((str(key), "ERROR", "",
                        "the requester and the reviewer are the same (%r). Implementer is not "
                        "reviewer, and a self-approved exception delegates the gate's authority "
                        "to whoever benefits from it" % requester))

        print("   ... linted %d/%d exception(s)" % (n, len(items)), file=sys.stderr)

    return out, "LOADED"


def report_exceptions(path, today=None):
    """-> exit contribution (0 or 1). Prints the registry's state and every defect."""
    rows, state = lint_exceptions(path, today)

    print("")
    print("EXCEPTIONS REGISTRY -- does every exception name an owner and an end date?")
    print("-" * 92)
    print("  registry   %s" % (path or "<not supplied>"))
    print("  state      %s" % state)

    if state == "NOT CONFIGURED":
        print("")
        print("  NOTHING WAS CHECKED. There is no exceptions registry at that path, so this is")
        print("  not a clean result -- it is an unexamined one. The governance layer either is")
        print("  not in place yet or is somewhere else.")
        return 0
    if state == "PRESENT BUT UNREADABLE":
        print("")
        print("::error title=Exceptions registry unreadable::A file exists and established")
        print(" nothing. An unreadable registry is not an empty one: every exception in it is")
        print(" currently unaccounted for.")
        return 1
    if state == "EMPTY":
        print("")
        print("  The registry loaded and holds no exceptions. Nothing is being suppressed.")
        return 0

    errors = [r for r in rows if r[1] == "ERROR"]
    warns = [r for r in rows if r[1] == "WARN"]
    print("  defects    %d error(s), %d warning(s)" % (len(errors), len(warns)))

    if warns:
        print("")
        print("-- EXPIRED, AND ALREADY REFUSED BY THE ENFORCEMENT PATH --")
        for key, _sev, token, msg in warns:
            print("   %-20s %-30s %s" % (str(key)[:20], token, msg))

    if errors:
        print("")
        print("== EXCEPTIONS THAT CANNOT BE REVIEWED ==")
        for key, _sev, token, msg in errors:
            print("   %-20s %-30s %s" % (str(key)[:20], token, msg))
        print("")
        print("::error title=Unreviewable exception::%d defect(s). An exception with no owner or"
              " no end date does not expire and nobody is asked to renew it -- the finding simply"
              " stops appearing. State who owns it and when it ends." % len(errors))
        return 1

    print("")
    print("  every exception names an owner, an end date, and a reason long enough to review")
    return 0


def _selftest():
    """Each assertion is a way an exception becomes permanent."""
    import shutil
    import tempfile

    fails = []
    today = datetime.date(2026, 10, 8)
    # mkdtemp returns the ONLY path that is ever removed, captured here and used verbatim below.
    tmp = tempfile.mkdtemp(prefix="lint_exceptions_selftest_")
    try:
        def write(name, obj):
            p = os.path.join(tmp, name)
            io.open(p, "w", encoding="utf-8").write(json.dumps(obj))
            return p

        # Written TO THE SCHEMA (L49): the claim in disposition_type, the lifecycle in state.
        good = {
            "disposition_type": "ACCEPTED_RISK", "state": "approved",
            "owner_role": "platform-security", "evidence_ref": "change-record-17",
            "expires": "2099-01-01",
            "rationale": "Upstream has no patch; the service is not internet facing and the "
                         "compensating network rule is recorded in the change ticket.",
        }

        # 1. THE POSITIVE CASE FIRST. A complete exception passes. Without this, every assertion
        #    below would also hold for a checker that rejected everything.
        rows, state = lint_exceptions(write("ok.json", {"a" * 40: dict(good)}), today)
        if state != "LOADED":
            fails.append("a well-formed registry did not load: %s" % state)
        if [r for r in rows if r[1] == "ERROR"]:
            fails.append("a complete exception was reported as defective: %r" % rows)

        # 2. NO EXPIRY. The live hole: scan_report.py honours this forever.
        rec = dict(good)
        del rec["expires"]
        rows, _ = lint_exceptions(write("noexp.json", {"a" * 40: rec}), today)
        if not any("NO EXPIRY" in r[3] for r in rows):
            fails.append("an exception with no expiry was accepted -- it suppresses forever")

        # 3. NO OWNER.
        rec = dict(good)
        del rec["owner_role"]
        rows, _ = lint_exceptions(write("noown.json", {"a" * 40: rec}), today)
        if not any(r[2] == WEAKENING_UNATTRIBUTED for r in rows):
            fails.append("an ownerless exception was not reported as %s" % WEAKENING_UNATTRIBUTED)

        # 4. AN UNREADABLE EXPIRY IS NOT AN OPEN-ENDED ONE.
        rec = dict(good)
        rec["expires"] = "whenever"
        rows, _ = lint_exceptions(write("badexp.json", {"a" * 40: rec}), today)
        if not any("unparseable" in r[3] for r in rows):
            fails.append("an unparseable expiry was treated as a date")

        # 5. AN EXPIRED ONE IS NAMED, using the registered word.
        rec = dict(good)
        rec["expires"] = "2020-01-01"
        rows, _ = lint_exceptions(write("old.json", {"a" * 40: rec}), today)
        if not any(r[2] == WEAKENING_EXCEPTION_EXPIRED for r in rows):
            fails.append("a lapsed exception was not reported as %s"
                         % WEAKENING_EXCEPTION_EXPIRED)

        # 6. KEYED ON SOMETHING THAT MOVES. Both shapes: too short, and long enough to pass a
        #    length test while still being a path. The second is the one that got through the
        #    first draft -- `minLength: 8` from the schema accepted a 22-character file path.
        rows, _ = lint_exceptions(write("shortkey.json", {"app.py": dict(good)}), today)
        if not any("durable identity" in r[3] for r in rows):
            fails.append("an exception keyed on a short name was accepted")
        rows, _ = lint_exceptions(
            write("pathkey.json", {"app/legacy/handler.py": dict(good)}), today)
        if not any("durable identity" in r[3] for r in rows):
            fails.append("an exception keyed on a PATH long enough to pass the length test was "
                         "accepted; the approval would follow the path to whatever finding "
                         "arrives there next")
        # And a real hex digest is NOT flagged, or the check is a blanket refusal rather than a
        # discriminating one.
        rows, _ = lint_exceptions(write("hexkey.json", {"7f3a9c1e8b2d4f6a": dict(good)}), today)
        if any("durable identity" in r[3] for r in rows):
            fails.append("a genuine hex identity was rejected, so the key check refuses "
                         "everything rather than discriminating: %r" % rows)

        # 7. A JUSTIFICATION NOBODY CAN EVALUATE.
        rec = dict(good)
        rec["rationale"] = "false positive"
        rows, _ = lint_exceptions(write("thin.json", {"a" * 40: rec}), today)
        if not any("30" in r[3] for r in rows):
            fails.append("a one-phrase justification was accepted")

        # 8. SELF-APPROVAL.
        rec = dict(good)
        rec["requester"] = "team-a"
        rec["review"] = {"reviewer": "team-a"}
        rows, _ = lint_exceptions(write("self.json", {"a" * 40: rec}), today)
        if not any("requester and the reviewer" in r[3] for r in rows):
            fails.append("a self-approved exception was accepted")

        # 9. A REQUEST IS NOT AN EXCEPTION. A record in a non-suppressing state buys no passage
        #    and must not be reported as a defective exception -- that would teach a reader to
        #    ignore this check's output.
        rows, _ = lint_exceptions(write("req.json", {
            "a" * 40: {"requested_disposition": "ACCEPTED_RISK", "request_state": "REQUESTED"}}),
            today)
        if rows:
            fails.append("a pending request was linted as though it already suppressed: %r" % rows)
        # 9a. THE SCHEMA SHAPE (L49). A record proposed under the schema is a request; a record
        #     carrying the claim in `state` is the legacy shape, which the reporter no longer
        #     honours, and the defect must name the field to migrate to.
        rows, _ = lint_exceptions(write("proposed.json", {"a" * 40: dict(good, state="proposed")}),
                                  today)
        if rows:
            fails.append("a schema record in state proposed was linted as a live exception: %r" % rows)
        rows, _ = lint_exceptions(write("legacy.json", {
            "a" * 40: {"state": "ACCEPTED_RISK", "owner_role": "team-a", "expires": "2099-01-01",
                       "rationale": "Upstream has no patch; recorded in the change ticket."}}),
            today)
        if not any(r[1] == "ERROR" and "disposition_type" in r[3] for r in rows):
            fails.append("the legacy shape (claim in `state`) was not reported as a defect naming "
                         "disposition_type: %r" % rows)

        # 9b. DEFERRAL DISCIPLINE. A deferral is an exception with a date, and it fails the same
        #     way. Both halves or neither.
        rec = dict(good)
        rec["deferred_until"] = "2099-06-01"
        rows, _ = lint_exceptions(write("defnoreason.json", {"a" * 40: rec}), today)
        if not any("deferred_reason" in r[3] for r in rows):
            fails.append("a deferral with a date but no reason was accepted")
        rec = dict(good)
        rec["deferred_reason"] = "waiting on an upstream release"
        rows, _ = lint_exceptions(write("defnodate.json", {"a" * 40: rec}), today)
        if not any("deferred_until" in r[3] for r in rows):
            fails.append("a deferral with a reason but no end date was accepted -- that is "
                         "silence made permanent")
        rec = dict(good)
        rec["deferred_reason"] = "waiting on an upstream release"
        rec["deferred_until"] = "whenever"
        rows, _ = lint_exceptions(write("defbaddate.json", {"a" * 40: rec}), today)
        if not any("unreadable date" in r[3] for r in rows):
            fails.append("an unparseable deferred_until was treated as a date")
        # A COMPLETE deferral passes, or every assertion above holds against a checker that
        # refuses all deferrals.
        rec = dict(good)
        rec["deferred_reason"] = "waiting on an upstream release"
        rec["deferred_until"] = "2099-06-01"
        rows, _ = lint_exceptions(write("defok.json", {"a" * 40: rec}), today)
        if [r for r in rows if r[1] == "ERROR"]:
            fails.append("a complete deferral was reported as defective: %r" % rows)

        # 9c. A RECORD DEFERRED BY ITS OWN STATE WORD IS IN SCOPE. This is the hole the first
        #     draft had: DEFERRED is not a registered disposition_type, so the scope guard
        #     skipped it before the deferral checks could run.
        rows, _ = lint_exceptions(write("defstate.json", {
            "a" * 40: {"state": "DEFERRED", "owner_role": "team-a",
                       "rationale": "Deferred pending the vendor's patch, tracked in the "
                                    "quarterly review."}}), today)
        if not any("deferred_until" in r[3] for r in rows):
            fails.append("a record deferred by its STATE word escaped the deferral checks "
                         "entirely -- the scope guard ran first and skipped it")

        # 9d. REOPENING IS EXPLICIT. A reopened record must name what reopened it.
        rec = dict(good)
        rec["reopened_at"] = "2026-05-01"
        rows, _ = lint_exceptions(write("silentreopen.json", {"a" * 40: rec}), today)
        if not any("reopen_trigger" in r[3] for r in rows):
            fails.append("a record reopened with no trigger was accepted -- an obligation "
                         "changed state with nobody having decided anything")
        rec["reopen_trigger"] = "upstream published a fix"
        rows, _ = lint_exceptions(write("reopenok.json", {"a" * 40: rec}), today)
        if any("reopen_trigger" in r[3] for r in rows):
            fails.append("a properly attributed reopen was still flagged")

        # 10. THE FOUR STATES STAY APART.
        seen = {
            "missing": lint_exceptions(os.path.join(tmp, "nope.json"), today)[1],
            "empty": lint_exceptions(write("empty.json", {}), today)[1],
            "loaded": lint_exceptions(write("ok2.json", {"a" * 40: dict(good)}), today)[1],
        }
        bad = os.path.join(tmp, "bad.json")
        io.open(bad, "w", encoding="utf-8").write("{not json")
        seen["unreadable"] = lint_exceptions(bad, today)[1]
        if len(set(seen.values())) != 4:
            fails.append("four registry states collapsed into %d: %r"
                         % (len(set(seen.values())), seen))
        if seen["missing"] == seen["empty"]:
            fails.append("a missing registry and an empty one reported identically, so an absent "
                         "governance layer reads as a clean one")
    finally:
        # Removed by the exact path mkdtemp returned, and nothing derived from it.
        shutil.rmtree(tmp, ignore_errors=True)

    for i, f in enumerate(fails, 1):
        print("  %d. %s" % (i, f))
    if fails:
        print("SELF-TEST FAILED: %d" % len(fails))
        return 2
    print("self-test ok: a complete exception passes, and one with no expiry, no owner, an")
    print("              unreadable expiry, a non-durable key, a thin justification or a")
    print("              self-approval is refused; a lapsed one is named with the registered")
    print("              word; a pending request is not linted as a live exception; and")
    print("              missing, unreadable, empty and loaded stay four distinct states.")
    print("")
    print("              Deferral discipline: a deferral needs BOTH a reason and an end date,")
    print("              an unreadable date is not an open-ended one, a record deferred by its")
    print("              own state word is in scope, and a reopen must name its trigger --")
    print("              the date passing is a precondition, never a trigger.")
    return 0


def main(argv):
    if "--self-test" in argv or "--selftest" in argv:
        return _selftest()

    check = "--check" in argv
    exc_path = ""
    if "--exceptions" in argv:
        i = argv.index("--exceptions")
        exc_path = argv[i + 1] if i + 1 < len(argv) else ""
        return report_exceptions(exc_path)

    unannotated, annotated, unsafe, incomplete = [], [], [], []

    for p in files():
        if os.path.basename(p) == "lint_suppressions.py":
            continue
        try:
            lines = io.open(p, encoding="utf-8", errors="ignore").read().split("\n")
        except OSError:
            continue
        rel = os.path.relpath(p, ROOT).replace("\\", "/")

        for i, line in enumerate(lines):
            if line.lstrip().startswith("#"):
                continue                      # the doc-comment describing an idiom is not one
            for rx, label in IDIOMS:
                if not rx.search(line):
                    continue
                window = lines[max(0, i - WINDOW):i + 1]
                m = None
                for w in window:
                    m = ANNOT.search(w) or m
                if not m:
                    unannotated.append((rel, i + 1, label, line.strip()[:70]))
                elif m.group(1) not in REASONS:
                    unannotated.append((rel, i + 1, label,
                                        "unknown reason '%s'" % m.group(1)))
                elif m.group(1) == "UNSAFE":
                    unsafe.append((rel, i + 1, label))
                else:
                    blob = "\n".join(window)
                    if not (DISCARDS.search(blob) and PRESERVED.search(blob)):
                        incomplete.append((rel, i + 1, label, m.group(1)))
                    else:
                        annotated.append((rel, i + 1, label, m.group(1)))

    print("suppressions: %d complete, %d reason-only, %d unannotated, %d UNSAFE"
          % (len(annotated), len(incomplete), len(unannotated), len(unsafe)))

    if incomplete:
        print("\n-- REASON GIVEN, BUT NOT WHAT IS DISCARDED OR WHERE IT SURVIVES --")
        for rel, ln, label, reason in sorted(incomplete)[:12]:
            print("   %-34s:%-5d %-18s %s" % (rel, ln, label, reason))
        if len(incomplete) > 12:
            print("   ... and %d more" % (len(incomplete) - 12))
        print("   A reason explains the syntax. It does not establish that the discarded")
        print("   distinction is irrelevant to EVERY consumer, or preserved somewhere else.")

    if unsafe:
        print("\n-- MARKED UNSAFE (known defect, must be fixed) --")
        for rel, ln, label in unsafe:
            print("   %s:%d  %s" % (rel, ln, label))

    if unannotated:
        print("\n== UNANNOTATED SUPPRESSIONS ==")
        for rel, ln, label, src in sorted(unannotated):
            print("   %-34s:%-5d %-18s %s" % (rel, ln, label, src))
        print("\n::error title=Unannotated suppression::%d site(s) swallow an error without stating"
              " why that is safe. Add `# suppression: <REASON>` and answer: if this fails in a way"
              " DIFFERENT from the one you expected, what happens?" % len(unannotated))
        return 1 if check else 0

    print("\nevery suppression states why it is safe")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))

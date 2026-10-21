#!/usr/bin/env python3
"""Turn scanner output into a work surface. Five sections, two audiences, no fabricated zeros.

WHY THIS EXISTS
    Of sixteen scanner jobs in this kit, six wrote a step-summary block, nine emitted only a log
    annotation, one printed nothing, and THREE reported a findings count. A pipeline whose scanners
    say "completed" is a scoreboard. Security cannot tell whether collection can be trusted;
    engineering cannot tell what to fix without downloading five artifacts.

    Both audiences are served by one contract, because they need different halves of the same run:

      Security needs   what ran - whether collection is trustworthy - severity - gate result
                       - where the evidence went - disposition state
      Engineering needs the exact thing that failed - file, component, line - fix version
                       - recommended remediation - whether a ticket already exists
                       - fix it, or request an exception

THE SECTION THAT MATTERS MOST IS `ACTION REQUIRED`, AND IT IS SPLIT BY WHO CAN ACT
    A developer cannot enable GitHub Code Security. Telling them to "fix the pipeline" when the
    missing capability is an organisation-level licensing decision wastes their afternoon and
    teaches them the gate is noise. So developer action and platform action are separate fields and
    either may be NONE.

THE MOST DANGEROUS NUMBER IN THIS FILE IS ZERO
    `Findings: 0` and `Findings: NOT ESTABLISHED` render almost identically to a tired reader at
    5pm, and mean opposite things. Zero says the scanner looked and the scope is clean. NOT
    ESTABLISHED says nobody looked. A scanner that was unlicensed, skipped, crashed or produced no
    parseable output must NEVER report 0 -- that is the CodeQL failure with a number attached, and
    it is the one thing this file's self-test refuses to let pass.

    Likewise a scanner whose output cannot be parsed reports
        PRESENT -- count unavailable from current parser
    and never 0.

WHAT IT CANNOT ESTABLISH
    It reads reports. It proves what the report says, never what is true of the environment. A
    clean SARIF from a scanner pointed at an empty directory is a clean SARIF. Applicability and
    scope are inputs here precisely so that a reader can see the denominator rather than infer it.

USAGE
    python3 scan_report.py --scanner trivy --sarif trivy.sarif \\
        --applicability APPLICABLE --execution COMPLETE --scope "filesystem + IaC" \\
        [--dispositions .security/dispositions.json] [--gate FAIL] [--max-detail 20]

    python3 scan_report.py --self-test

EXIT
    0 always for the report itself -- reporting is not gating. The gate reads job results.
    2 self-test failed
"""
import argparse
import datetime
import hashlib
import io
import json
import os
import re
import sys

# Sibling modules. The identity half existed and was called by nothing; the subject
# half is what it needed and did not have.
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from finding_identity import identify      # noqa: E402
from finding_subject import subject_for    # noqa: E402
# The three libraries that were built, proven and called by nothing (L44, L46, L48). Each is a
# pure function over records; this file is where the records are, so this file calls them.
import finding_correlation                 # noqa: E402
import finding_match                       # noqa: E402
import rule_family                         # noqa: E402

SEV_ORDER = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFORMATIONAL']
BLOCKING = ('CRITICAL', 'HIGH')

# A scanner that did not produce a trustworthy result must not be able to report a count.
# These are the states where "0 findings" would be a lie, not a measurement.
#
# NOT_DECLARED JOINED THIS LIST BECAUSE IT IS THE DEFAULT, AND THE DEFAULT WAS COMPLETE.
#
# `--execution` defaulted to COMPLETE and `batch()` substituted COMPLETE for any state file that
# omitted the field. So an OMISSION produced the strongest claim in the namespace: a consumer
# wiring their own job and forgetting one argument got a clean verdict for free, and there was no
# statement they could have made that would have been stronger than saying nothing. Silence must
# degrade a verdict, never strengthen it.
NO_COUNT_STATES = ('NOT_RUN', 'FAILED', 'COLLECTION_FAILED', 'NOT_DECLARED')
# COVERAGE_GAP JOINED THIS LIST BECAUSE IT IS THE ONE THAT MOST LOOKS LIKE AN ANSWER.
#
# assurance-taxonomy.yaml :: discovery_state :: COVERAGE_GAP -- the artefact is here, a control
# is owed, and nothing looked. NOT_APPLICABLE means there is nothing to find; CLEAN means a
# scanner ran and found nothing. COVERAGE_GAP is absence of EVIDENCE, and a finding count
# rendered beside it would be a count of what nobody collected.
# UNKNOWN is here for the same reason, and it is the registered applicability default now. Its own
# taxonomy entry already says "Run anyway and say so; never report a clean result" -- it was the
# one value in the namespace carrying that instruction and the one value this list omitted.
NO_COUNT_APPLIC = ('UNAVAILABLE', 'NOT_CONFIGURED', 'NOT_APPLICABLE', 'COVERAGE_GAP', 'UNKNOWN')

# ─────────────────────────────────────────────────────────────────────────────────────
# `scan_examination` -- WHETHER THE SCAN READ ANYTHING, derived from the SARIF.
#
# WHY THIS IS A SEPARATE AXIS FROM `execution_state`
#
#     `execution_state` is DECLARED by the job that ran the scanner. This is DERIVED from the
#     scanner's own report, and it has to be, because the declaring job is the thing being
#     checked. A scanner that fails internally and exits 0 produces a job that TRUTHFULLY
#     declares COMPLETE over a run that read nothing. Asking that job again gets the same answer.
#
#     Until 2026-10-08 the reporter owned the vocabulary to refuse a hollow scan and consulted it
#     only on values the caller supplied. SARIF carried four witnesses the whole time and this
#     file read none of them. Five document shapes -- a declared-unsuccessful invocation, an
#     empty rule set, zero artifacts, no runs at all, and a state file declaring nothing --
#     every one rendered `Findings: **NONE** in the scanned scope.`
#     (The empty-rule-set shape was retired as a witness on 2026-10-16 per KDEC-008 OD-2: it is
#     exactly what a clean bandit run emits. See rules_witness.)
EXAMINED = 'EXAMINED'
EXAMINED_NOTHING = 'EXAMINED_NOTHING'
EXAMINATION_NOT_DECLARED = 'NOT_DECLARED'

# Only EXAMINED may carry a count. Listed rather than negated so adding a value cannot silently
# default to permissive -- an unrecognised examination state must fail closed, and a membership
# test does that while `!= EXAMINED_NOTHING` would not.
COUNTABLE_EXAMINATION = (EXAMINED,)


# â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
# REDACTION. Applied to every string this file prints, without exception.
# â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
#
# WHY THIS IS NOT ALREADY HANDLED UPSTREAM
#     The kit runs gitleaks with --redact and then strips `snippet` and `partialFingerprints`
#     from gitleaks.sarif. That is correct and it covers ONE scanner. This reporter prints
#     messages from all sixteen. Semgrep can put matched source in a message; Trivy's secret
#     mode, detect-secrets and anything a consumer adds have their own conventions. A reporter
#     that faithfully echoes whatever a scanner wrote will eventually echo a live credential
#     into a step summary and a run log -- both readable by anyone with repo read access, and
#     both retained.
#
# WHAT A READER STILL GETS, WHICH IS EVERYTHING THEY NEED TO ACT
#     the rule, the FILE, the LINE, the severity, the remediation, and a short prefix of the
#     value so they can tell WHICH credential it is. Never the whole value.
#
#         Issue: AWS key AKIA****************** [redacted: aws-access-key-id, 20 chars]
#
#     Four characters identifies a secret to the person who owns it and is useless to anyone
#     else. Length is kept because it distinguishes a token from a password.
#
# IT ERRS TOWARD OVER-REDACTING
#     A 40-character git SHA or a package checksum will be masked. That costs a little
#     readability. The opposite error publishes a credential. When the two are not symmetric,
#     the guard does not sit in the middle.
SECRET_PATTERNS = [
    (re.compile(r'-----BEGIN[A-Z ]*PRIVATE KEY-----'), 'private-key'),
    (re.compile(r'\bAKIA[0-9A-Z]{16}\b'), 'aws-access-key-id'),
    (re.compile(r'\bgh[pousr]_[A-Za-z0-9]{16,}'), 'github-token'),
    (re.compile(r'\bxox[baprs]-[A-Za-z0-9-]{10,}'), 'slack-token'),
    (re.compile(r'\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}'), 'jwt'),
    (re.compile(r'\b[A-Za-z0-9~._-]{3}8Q~[A-Za-z0-9~._-]{31,34}\b'), 'entra-client-secret'),
    (re.compile(r'(?i)\b(?:AccountKey|SharedAccessKey|password|pwd|secret|token|api[_-]?key)'
                r'\s*[:=]\s*["\']?([^\s;,"\'&]{8,})'), 'keyed-value'),
    (re.compile(r'\b[A-Za-z0-9+/]{32,}={0,2}(?![A-Za-z0-9+/=])'), 'high-entropy'),
    (re.compile(r'\b[0-9a-fA-F]{32,}\b'), 'hex-or-digest'),
]


def _mask(value, label):
    keep = value[:4]
    return '%s%s [redacted: %s, %d chars]' % (keep, '*' * min(len(value) - len(keep), 18),
                                              label, len(value))


REDACTED_MARK = '[redacted: '


def redact(text):
    """Mask anything that looks like credential material. Returns the safe string.

    IDEMPOTENT, which is not free. Masking `password: AKIAIOSFODNN7EXAMPLE` produces
    `password: AKIA**************** [redacted: ...]`, and that output STILL matches the
    keyed-value pattern -- so a second pass masked the mask, and a third masked that. It
    matters because a SARIF can legitimately be redacted twice: once in the scanner job before
    upload, once in the consolidated report after download. Non-idempotent redaction would
    corrupt the text on the second pass and make the finding unreadable.
    """
    if not text:
        return text
    out = text
    for pat, label in SECRET_PATTERNS:
        def _sub(m, _l=label):
            whole = m.group(0)
            v = m.group(1) if m.groups() and m.group(1) else whole
            if len(v) < 8 or REDACTED_MARK in whole or '****' in v:
                return whole
            return whole.replace(v, _mask(v, _l))
        out = pat.sub(_sub, out)
    return out


def severity_of(result, rules):
    """SARIF says almost nothing about severity directly. Derive it the way GitHub does.

    `properties.security-severity` is a CVSS-style number and is authoritative when present.
    Otherwise fall back to `level`, which only distinguishes error/warning/note. A scanner that
    supplies neither lands in INFORMATIONAL rather than being silently dropped -- an unclassified
    finding that disappears is worse than one filed too low.
    """
    props = (result.get('properties') or {})
    rid = result.get('ruleId') or ''
    rule = rules.get(rid) or {}
    ss = props.get('security-severity')
    if ss is None:
        ss = ((rule.get('properties') or {}).get('security-severity'))
    if ss is not None:
        try:
            v = float(ss)
            if v >= 9.0:
                return 'CRITICAL'
            if v >= 7.0:
                return 'HIGH'
            if v >= 4.0:
                return 'MEDIUM'
            if v > 0:
                return 'LOW'
            return 'INFORMATIONAL'
        except (TypeError, ValueError):
            pass
    lvl = (result.get('level') or (rule.get('defaultConfiguration') or {}).get('level') or '')
    return {'error': 'HIGH', 'warning': 'MEDIUM', 'note': 'LOW',
            'none': 'INFORMATIONAL'}.get(str(lvl).lower(), 'MEDIUM')


def location_of(result):
    locs = result.get('locations') or []
    if not locs:
        return ('', 0)
    pl = (locs[0].get('physicalLocation') or {})
    uri = ((pl.get('artifactLocation') or {}).get('uri') or '')
    line = ((pl.get('region') or {}).get('startLine') or 0)
    return (uri, line)


def fingerprint(scanner, rule_id, uri, message):
    """Stable identity for a finding across runs.

    Deliberately EXCLUDES the line number. Code moves; a finding that shifts down three lines
    because someone added an import is the same finding, and a fingerprint that changed would
    orphan its tracking item and its risk acceptance on every unrelated edit. That is how disposition
    systems quietly stop working: not by failing, but by losing track of what was already decided.
    """
    norm = re.sub(r'\d+', '#', (message or ''))[:200]
    raw = '|'.join([scanner, rule_id or '', uri or '', norm])
    return hashlib.sha256(raw.encode('utf-8', 'replace')).hexdigest()[:12]


def remediation_of(result, rules):
    """A recommended action, or an honest absence. Never invented."""
    props = (result.get('properties') or {})
    rid = result.get('ruleId') or ''
    rule = rules.get(rid) or {}
    fixed = props.get('fixed_version') or props.get('fixedVersion')
    pkg = props.get('package') or props.get('pkgName')
    if fixed and pkg:
        return 'Upgrade %s -> %s' % (pkg, fixed)
    if fixed:
        return 'Upgrade to %s' % fixed
    fixes = result.get('fixes') or []
    if fixes:
        d = ((fixes[0].get('description') or {}).get('text') or '').strip()
        if d:
            return d.split('\n')[0][:200]
    for src in (rule.get('help') or {}, rule.get('fullDescription') or {}):
        t = (src.get('text') or '').strip()
        if t:
            return t.split('\n')[0][:200]
    return ''


def rules_witness(scanner):
    """May an empty `rules[]` from this scanner be read as "examined nothing"? Per tool, from the
    same profile the runner-side validity check uses (KDEC-008 OD-2); False when unknown, which
    is OD-2's default ("not a universal empty-rules rule")."""
    try:
        from sarif_validity import PROFILES
    except ImportError:
        return False
    return bool((PROFILES.get(str(scanner or '').lower()) or {}).get('rules_witness'))


def examination_of(doc, scanner=None):
    """-> (scan_examination state, witnesses). Read from the SARIF, never from the caller.

    FOUR WITNESSES, AND EACH ONE IS SUFFICIENT ON ITS OWN. A scan is hollow if ANY of them says
    so, because they do not corroborate each other -- they describe different ways of reading
    nothing, and requiring agreement would mean a scanner has to fail in two ways before anyone
    is told.

        executionSuccessful: false      the tool's own verdict on its own run. A scanner that
                                        crashed and exited 0 says so HERE and nowhere else, which
                                        is why the shell that watches exit codes cannot see it.
        tool{Execution,Configuration}   an error- or fatal-level notification in EITHER array.
          Notifications                 The reason, in the tool's words, and present even where
                                        the flag above is not.
        tool.driver.rules: []           no rules loaded -- but ONLY for a tool whose profile
                                        says an empty rules array means that (rules_witness;
                                        none does, KDEC-008 OD-2: bandit lists only rules that
                                        fired, so a clean bandit run emits exactly this).
        artifacts: []                   nothing read. Indistinguishable from a clean repository
                                        without the denominator, which is LM-015.

    THE ASYMMETRY IS DELIBERATE, AND IT IS WHERE THE CARE IS. `rules` and `artifacts` are OPTIONAL
    in SARIF, so their ABSENCE proves nothing and must not be read as emptiness -- `artifacts` not
    present and `artifacts: []` are different facts, and a reporter that merged them would fail
    every conforming scanner that omits the array. Only an array that is PRESENT and EMPTY is a
    witness. Where no witness is present at all the answer is NOT_DECLARED, which carries no count
    either: absence of a witness is not a witness of presence.

    A run with findings is EXAMINED regardless, and that is not a shortcut. A result is itself
    proof that something was read, and it is stronger proof than any of the four witnesses -- so a
    scanner that reports findings while omitting its metadata is not punished for the omission.
    """
    witnesses = []
    runs = doc.get('runs') if isinstance(doc, dict) else None
    if not isinstance(runs, list) or not runs:
        return (EXAMINATION_NOT_DECLARED,
                ['the report carries no `runs`, so it records neither a tool, a rule set, nor '
                 'anything examined -- there is nothing here to be clean about'])

    declared_any = False
    for i, run in enumerate(runs):
        if not isinstance(run, dict):
            continue
        where = ('run %d' % i) if len(runs) > 1 else 'the run'

        for inv in (run.get('invocations') or []):
            if not isinstance(inv, dict):
                continue
            if inv.get('executionSuccessful') is False:
                declared_any = True
                witnesses.append('%s declares `executionSuccessful: false` -- the scanner\'s own '
                                 'verdict on its own run, whatever its exit code was' % where)
            elif inv.get('executionSuccessful') is True:
                # AN AFFIRMATIVE WITNESS, and it has to count as one.
                #
                # The first draft of this function did not count it, and the self-test caught the
                # consequence: `rules` and `artifacts` are OPTIONAL in SARIF, so a conforming
                # scanner that declares a successful invocation and omits both would have been
                # read as having examined nothing. That is the common shape for several real
                # tools, so NOT ESTABLISHED would have become the ordinary result of a healthy
                # scan -- a false-failure flood, which gets a gate muted and is no safer than a
                # false pass.
                #
                # RESIDUAL, STATED RATHER THAN HIDDEN: a scanner that declares success, omits
                # both optional arrays, and genuinely read nothing is EXAMINED here. This axis
                # cannot see that, and only the denominator could. It is the weakest row in this
                # function and the first to revisit against real scanner output.
                declared_any = True
            # BOTH notification arrays (SARIF 3.20.21 / 3.20.22). Bandit files the file it could
            # not parse under toolCONFIGURATIONNotifications, at error, with exit 0 and results []
            # (measured, PIPELINE_ORDERING 3.2) -- reading only the execution array missed it,
            # and the empty-rules witness below used to catch that run for the wrong reason.
            for key, kind in (('toolExecutionNotifications', 'execution'),
                              ('toolConfigurationNotifications', 'configuration')):
                for note in (inv.get(key) or []):
                    if not isinstance(note, dict):
                        continue
                    if str(note.get('level') or '').lower() in ('error', 'fatal'):
                        text = ((note.get('message') or {}).get('text') or '').strip()
                        declared_any = True
                        witnesses.append('%s reports a %s-level %s notification: %s'
                                         % (where, note.get('level'), kind,
                                            redact(text.split('\n')[0][:200]) or '(no text)'))

        driver = ((run.get('tool') or {}).get('driver') or {})
        rules = driver.get('rules')
        if isinstance(rules, list):
            declared_any = True
            # AN EMPTY RULES ARRAY IS A WITNESS ONLY FOR A TOOL WHOSE PROFILE SAYS SO, and none
            # does (KDEC-008 OD-2, sarif_validity.PROFILES rules_witness). Bandit lists only the
            # rules that FIRED, so a clean bandit run emits `rules: []` -- reading that as "loaded
            # no rules" rendered every clean bandit row as a pipeline defect, NOT ESTABLISHED,
            # while the runner-side check and the gate called the same run clean.
            if not rules and rules_witness(scanner):
                witnesses.append('%s loaded NO rules, so nothing could have been detected -- the '
                                 'zero describes the scanner\'s configuration, not the code' % where)

        artifacts = run.get('artifacts')
        if isinstance(artifacts, list):
            declared_any = True
            if not artifacts:
                witnesses.append('%s examined NO artifacts. Without the denominator this is '
                                 'indistinguishable from a clean repository' % where)

        if (run.get('results') or []):
            # A finding is proof of reading, and outranks every witness above.
            return (EXAMINED, [])

    if witnesses:
        return (EXAMINED_NOTHING, witnesses)
    if not declared_any:
        return (EXAMINATION_NOT_DECLARED,
                ['the report records no `invocations`, no rule set and no artifact list, so it '
                 'makes no statement about what it examined'])
    return (EXAMINED, [])


def parse_sarif(path, scanner, table=None):
    """-> (findings, parse_state, examination).

    parse_state is COMPLETE, ABSENT or UNPARSEABLE -- whether a machine-readable report arrived.
    examination is `(state, witnesses)` from `examination_of` -- whether it read anything. TWO
    AXES, because a perfectly well-formed report of a scan that read nothing is COMPLETE on the
    first and EXAMINED_NOTHING on the second, and collapsing them is how the second was missed.

    UNPARSEABLE is not zero findings. It is a collection failure wearing a report's clothes.

    `table` is the parsed rule-family alias table (rule_family.parse_table), or None when no
    usable table was read for this run. See `what_of` for what each case does to WHAT.
    """
    if not path or not os.path.exists(path) or os.path.getsize(path) == 0:
        return ([], 'ABSENT',
                (EXAMINATION_NOT_DECLARED, ['no report was produced, so nothing records what '
                                            'was examined']))
    try:
        doc = json.load(io.open(path, encoding='utf-8', errors='replace'))
    except (ValueError, IOError):
        return ([], 'UNPARSEABLE',
                (EXAMINATION_NOT_DECLARED, ['the report could not be parsed, so nothing in it '
                                            'can be read as a statement about what it examined']))
    # THE FOURTH STATE, DECLARED (L06). Valid JSON that is not SARIF-shaped used to RAISE out of
    # the walk below, and in batch mode the exception escaped batch(): no report, no counts, no
    # findings file, fifteen scanners' evidence gone because one wrote a broken file. It is
    # UNPARSEABLE -- a collection failure wearing a report's clothes -- with a witness that says
    # the document decoded and then could not be read, which is a different fact from "not JSON".
    if not isinstance(doc, dict):
        return ([], 'UNPARSEABLE',
                (EXAMINATION_NOT_DECLARED, ['the report is valid JSON but not SARIF-shaped: the '
                                            'top level is a %s, not an object, so nothing in it '
                                            'can be read as a statement about what it examined'
                                            % type(doc).__name__]))
    try:
        return _parse_runs(doc, scanner, table)
    except (AttributeError, TypeError, KeyError, ValueError, IndexError) as exc:
        return ([], 'UNPARSEABLE',
                (EXAMINATION_NOT_DECLARED, ['the report is valid JSON but not SARIF-shaped: '
                                            'reading it failed with %s: %s -- nothing in it can '
                                            'be read as a statement about what it examined'
                                            % (type(exc).__name__, str(exc)[:200])]))


def _parse_runs(doc, scanner, table):
    """The SARIF walk, separated so parse_sarif can declare its fourth state (L06)."""
    examination = examination_of(doc, scanner)
    out = []
    for run in (doc.get('runs') or []):
        driver = ((run.get('tool') or {}).get('driver') or {})
        rules = {}
        for r in (driver.get('rules') or []):
            if r.get('id'):
                rules[r['id']] = r
        for ext in (run.get('tool') or {}).get('extensions') or []:
            for r in (ext.get('rules') or []):
                if r.get('id'):
                    rules.setdefault(r['id'], r)
        tool = driver.get('name') or scanner
        # The running version, for the alias table (L46). `semanticVersion` is the SARIF field
        # for it; `version` is what several tools actually populate. Absent is absent -- an
        # alias cannot be applied to a version nobody stated, and rule_family.resolve says so.
        version = str(driver.get('semanticVersion') or driver.get('version') or '').strip()
        for res in (run.get('results') or []):
            rid = res.get('ruleId') or ''
            msg = ((res.get('message') or {}).get('text') or '').strip()
            uri, line = location_of(res)
            # REDACTED AT CONSTRUCTION, NOT AT PRINT TIME. There are four places a finding's
            # text reaches output; guarding each one is how one of them eventually gets missed.
            # The fingerprint is computed from the RAW message so identity survives redaction --
            # it is a hash, and it never reaches a reader.
            # â”€â”€ IDENTITY: the durable one, with the legacy hash kept as an alias â”€â”€â”€â”€â”€â”€â”€â”€â”€
            #
            # `fingerprint(scanner, rule_id, uri, message)` is built from four inputs that
            # `finding_identity.py` lists as FORBIDDEN, with the reason for each: a scanner
            # upgrade orphans every disposition approved against that scanner, a rule rename
            # does it at a minor version, and the message is the vendor's prose -- a reworded
            # sentence silently invalidates an approved exception.
            #
            # The correct implementation existed the whole time and nothing called it. It is
            # called now, through `finding_subject.subject_for`, which was the missing link:
            # identify() refuses to compute an identity without a declared subject, correctly,
            # because a default would apply one subject's locus rule to another subject's
            # finding.
            #
            # BOTH KEYS ARE CARRIED, and that is deliberate rather than tidy. Approvals already
            # granted are keyed to the legacy hash. Swapping the key in one step would orphan
            # every one of them at once -- findings already risk-accepted would reappear as new,
            # and a reviewer facing a wall of re-raised findings approves them in bulk or stops
            # reading. So `fp` stays the legacy hash until the ledger is migrated, `identity` is
            # the durable one, and `identity_state` says whether it could be computed at all.
            subj, subj_basis = subject_for(scanner=scanner, tool=tool, uri=uri)
            what, what_basis = what_of(rules.get(rid), res, rid, msg, scanner=scanner, tool=tool,
                                       version=version, table=table)
            rec = {
                'finding_subject': subj,
                'scanner': scanner, 'tool': tool, 'rule_id': rid,
                'uri': uri, 'message': msg, 'start_line': line,
                # WHERE, named as the identity model names it. `uri` is what SARIF calls it and
                # `canonical_path` is what the identity requires, and they are not automatically
                # the same thing: one scanner reports paths relative to the scope it was handed
                # while others report them relative to the repository root, so the same file can
                # arrive twice under two spellings. Normalisation upstream is what makes this
                # assignment honest -- without it this line would be quietly wrong for one
                # scanner and nobody would see it, which is the open path-rooting defect.
                'canonical_path': uri,
            }
            # SYMBOL, when the scanner emits one. A CWE-only WHAT is coarse -- two unrelated
            # findings in one file can share CWE-798 -- so the identity model requires a
            # symbol-level locus to separate them, and refuses rather than collapsing two findings
            # into one identity. Scanners that emit `logicalLocations` (CodeQL reliably, others
            # sometimes) get a durable source identity; the rest stay UNFINGERPRINTABLE and say so,
            # which is the correct outcome and is visible in `identity_state`.
            sym = ''
            for loc in (res.get('locations') or []):
                for ll in (loc.get('logicalLocations') or []):
                    sym = (ll.get('fullyQualifiedName') or ll.get('name') or '').strip()
                    if sym:
                        break
                if sym:
                    break
            if sym:
                rec['symbol_path'] = sym
            rec.update(what)

            # A SECRET FINDING HAS NO BASELINE IDENTITY, and declaring that is what makes the
            # construct extraction below safe to perform at all. Section 5.7: the baseline has no
            # authority over secrets -- they block at every rung and are never grandfathered --
            # so `identify()` refuses them by name rather than computing a key nothing may use.
            # Without this flag a secret scanner's SARIF read before redaction would hash the
            # matched credential into a durable key.
            if is_secret_scanner(scanner, tool, rid):
                rec['is_secret_finding'] = 'true'

            # THE REST OF THE RECORD. `what_of` answers WHAT; this answers WHERE and CONTENT,
            # dispatched on the established subject. Fields it cannot derive are left ABSENT so
            # `identify()` refuses and names them -- never filled with a plausible value.
            locus, locus_basis = locus_of(subj, rules.get(rid), res, rid, msg, uri, what)
            rec.update(locus)

            ident = identify(rec) if subj != 'UNKNOWN' else {
                'state': 'UNFINGERPRINTABLE', 'identity': '',
                'reason': 'SUBJECT_NOT_ESTABLISHED', 'detail': subj_basis,
            }
            out.append({
                'scanner': scanner, 'tool': tool, 'rule': redact(rid),
                'severity': severity_of(res, rules),
                'message': redact(msg), 'uri': uri, 'line': line,
                'remediation': redact(remediation_of(res, rules)),
                'fp': fingerprint(scanner, rid, uri, msg),
                'identity': ident.get('identity') or '',
                'identity_state': ident.get('state') or 'UNFINGERPRINTABLE',
                'identity_reason': ident.get('reason') or '',
                # The refusal's DETAIL, not only its class. `CONTENT_UNDERIVABLE` says which
                # component failed; this says which field, which is the difference between an
                # operator knowing there is a gap and an operator being able to close it.
                'identity_detail': ident.get('detail') or '',
                'finding_subject': subj,
                'finding_subject_basis': subj_basis,
                'what_basis': what_basis,
                'locus_basis': locus_basis,
                # THE THREE COMPONENTS, CARRIED SEPARATELY (L52). The cascade in
                # finding_match.py tells MOVED from NEW by comparing them apart, and a consumer
                # handed only the composite gets exact-match and nothing else. Empty when the
                # identity refused -- never a hash of what happened to be present.
                'what': ident.get('what') or '',
                'where': ident.get('where') or '',
                'content': ident.get('content') or '',
                'identity_scope': ident.get('identity_scope') or '',
                'what_aliases': list(ident.get('what_aliases') or []),
                'cwe': what.get('cwe') or '',
                'canonical_path': rec['canonical_path'],
                'scanner_version': version,
            })
    return (out, 'COMPLETE', examination)


# ── THE "WHAT", LIFTED OUT OF SARIF ──────────────────────────────────────────────────
#
# `identify()` refuses to build a durable identity from a bare rule_id, and it is right to: a rule
# rename is exactly the event the identity has to survive. It wants a CVE, GHSA or OSV id, a purl,
# a CWE, or a rule family -- something that still names the same weakness after the scanner ships
# a new taxonomy.
#
# SARIF carries all of those, scattered. CodeQL puts CWE in `rule.relationships` against a CWE
# taxonomy; Semgrep puts it in `rule.properties.tags` as `external/cwe/cwe-079`; Bandit uses
# `properties.cwe.id`; dependency scanners put the advisory id in the ruleId itself. Nobody agrees,
# so this reads all of them and reports which one answered.
#
# A finding with none of them stays UNFINGERPRINTABLE, which is the correct outcome and is visible
# in `identity_state` rather than silently defaulting to the rule_id the identity refuses.
_CVE = re.compile(r'\b(CVE-\d{4}-\d{4,})\b', re.I)
_GHSA = re.compile(r'\b(GHSA-[0-9a-z]{4}-[0-9a-z]{4}-[0-9a-z]{4})\b', re.I)
_OSV = re.compile(r'\b((?:OSV|PYSEC|GO|RUSTSEC|MAL)-\d{4}-\d+)\b', re.I)
_CWE = re.compile(r'\bcwe[-_/ ]?(\d{1,5})\b', re.I)
_PURL = re.compile(r'\b(pkg:[a-z0-9.+-]+/[^\s"\']+)', re.I)


def what_of(rule, res, rid, msg, scanner='', tool='', version='', table=None):
    """-> dict of identity-grade WHAT fields, plus the basis that found each.

    `scanner`, `tool`, `version` and `table` feed the rule-family alias table (L46); see the
    rule-family block at the end for the tiers and the one case that refuses.
    """
    out, basis = {}, []
    rule = rule or {}
    props = rule.get('properties') or {}
    hay = ' '.join(str(x) for x in (
        rid, msg, rule.get('id') or '', (rule.get('name') or ''),
        json.dumps(props, ensure_ascii=False) if props else '',
        json.dumps(res.get('properties') or {}, ensure_ascii=False),
    ))

    # EVERY ALIAS, NOT THE FIRST ONE FOUND.
    #
    # This loop used to `break` after the first hit. `finding_identity._derive_what` builds WHAT
    # from an alias SET and says why in its own comment -- "carried as a SET because advisories
    # re-alias; section 5.6 matches on INTERSECTION, which needs the members" -- and a set with
    # exactly one member by construction cannot intersect with anything usefully. A finding whose
    # SARIF carried both CVE-2018-18074 and GHSA-x84v-xcm2-53pg produced the single-element set
    # {CVE-2018-18074}, so the alias machinery existed and was fed one alias forever.
    #
    # THE CONSEQUENCE, STATED RATHER THAN HIDDEN: WHAT hashes the sorted set, so a feed adding an
    # alias to an existing advisory now MOVES the identity. That is a real event and it is not
    # introduced by this change -- it was always going to happen the first time two aliases
    # appeared in one document. It is exactly the case `scripts/finding_lineage.py` records under
    # ADVISORY_ALIAS_ADDED, and the honest answer to it is a lineage event, not a smaller set.
    for rx, key, label in ((_CVE, 'cve', 'CVE'), (_GHSA, 'ghsa', 'GHSA'), (_OSV, 'osv', 'OSV')):
        m = rx.search(hay)
        if m:
            out[key] = m.group(1).upper()
            basis.append('%s from %s' % (label, 'ruleId' if rx.search(rid or '') else 'rule metadata'))

    m = _PURL.search(hay)
    if m:
        out['purl'] = m.group(1)
        basis.append('purl from rule or result properties')

    # CWE: relationships first (the structured place), then tags, then anywhere.
    cwe = ''
    for rel in (rule.get('relationships') or []):
        tgt = rel.get('target') or {}
        comp = ((tgt.get('toolComponent') or {}).get('name') or '').upper()
        tid = str(tgt.get('id') or '')
        if 'CWE' in comp or tid.upper().startswith('CWE'):
            mm = _CWE.search(tid) or _CWE.search(comp + tid)
            if mm:
                cwe = mm.group(1)
                basis.append('CWE from rule.relationships taxonomy')
                break
    if not cwe:
        for t in (props.get('tags') or []):
            mm = _CWE.search(str(t))
            if mm:
                cwe = mm.group(1)
                basis.append('CWE from rule.properties.tags')
                break
    if not cwe and props.get('cwe'):
        mm = _CWE.search(json.dumps(props.get('cwe')))
        if mm:
            cwe = mm.group(1)
            basis.append('CWE from rule.properties.cwe')
    if cwe:
        out['cwe'] = 'CWE-%s' % cwe

    # Rule family, in two tiers, and the tier is recorded.
    #
    #   1  THE ALIAS TABLE (L46, scripts/rule_family.py). A reviewed table on the protected branch
    #      mapping (scanner, version range, rule id) onto a stable family key. Adding an alias is
    #      how an upgrade is absorbed. Tried under the roster name first and the SARIF driver name
    #      second, because the table is keyed on whichever its author wrote and both name one tool.
    #   2  THE NAMESPACED PREFIX of the rule id, the weakest acceptable WHAT. Derived WHENEVER the
    #      table did not answer -- `identify()` accepts an advisory id or a purl alone, but a CWE
    #      only in company with a family, because a CWE is a class of weakness and thousands of
    #      findings share one. A family survives a rename WITHIN it even though it would not
    #      survive a re-taxonomy.
    #
    # ONE CASE REFUSES INSTEAD OF FALLING THROUGH: a table whose aliases DISAGREE for this rule.
    # rule_family.resolve says "a table that answers two ways answers nothing", and reaching past
    # a table that was consulted and found self-contradictory for a string split would turn the
    # reviewed answer into decoration. No family, so identify() refuses WHAT_UNDERIVABLE.
    #
    # THE FALLBACK TIER IS A STANDING DECISION, STATED: L46's strict reading is that an unaliased
    # rule resolves to nothing. The prefix tier is the behaviour that shipped before the table
    # existed and is what tests/prove_identity_durability.py proves durable; removing it would
    # refuse every SAST finding in every repository until an alias table is authored. Which of
    # the two the kit should ship is recorded as an owner decision in this lane's report.
    disagreed = False
    if table:
        for name in [n for n in dict.fromkeys((scanner, tool)) if n]:
            fam, why = rule_family.resolve(table, name, version, rid)
            if fam:
                out['rule_family'] = fam
                basis.append('rule_family from the alias table (tier 1): %s' % why)
                break
            if 'disagree' in why:
                disagreed = True
                basis.append('rule_family REFUSED: %s' % why)
                break
            basis.append('alias table did not answer for %r: %s' % (name, why))
    else:
        basis.append('no usable rule-family alias table for this run')
    if not out.get('rule_family') and not disagreed and rid and ('.' in rid or '/' in rid):
        fam = re.split(r'[./]', rid)
        if len(fam) > 1:
            out['rule_family'] = '.'.join(fam[:-1])
            basis.append('rule_family from the namespaced rule id (tier 2, weakest acceptable WHAT)')

    return out, '; '.join(basis) or 'no advisory id, purl, CWE or rule family found in the SARIF'


# ── THE "WHERE" AND THE "CONTENT", LIFTED OUT OF SARIF, PER SUBJECT ──────────────────
#
# D-2 WAS NOT A NORMALISATION BUG. `identify()` survives a scanner swap, a version bump, a rule
# rename, a reworded message and a line move -- proven on a complete record by both
# `finding_identity.py --self-test` and the CONTROL in `tests/prove_identity_durability.py`. What
# it had never once received was a complete record. `parse_sarif` populated three identity fields
# (`purl`, `canonical_path`, `symbol_path`); the reachable subjects require seventeen between
# them, and the other fourteen names appeared NOWHERE in this file. So every finding from every
# scanner refused, every consumer fell back to the legacy `fp`, and the legacy `fp` is built from
# scanner + rule_id + uri + message -- the four fields a vendor change moves.
#
# THE RULE THIS SECTION KEEPS, WHICH IS THE WHOLE POINT
#
#   A field that is not in the SARIF is NOT SUPPLIED. It is left absent, `identify()` refuses,
#   and `identity_reason` names the field. Nothing here invents a plausible value to get a hash,
#   because a hash is opaque: a reader downstream cannot tell a derived identity from a guessed
#   one, and a guessed one is stable-looking and wrong -- which is strictly worse than no
#   identity at all. REFUSE, NEVER DEGRADE applies to extraction exactly as it applies to
#   normalisation.
#
# BASIS TIERS, STRONGEST FIRST, AND THE TIER IS RECORDED
#
#   Same discipline as provenance_identity.observation_time in assurance-taxonomy.yaml: weaker
#   sources are not forbidden, they are forbidden from being mistaken for strong ones. Every
#   extractor records which tier answered in `locus_basis`, so a reader can see that a package
#   name came out of a rendered message rather than out of a structured field.
#
#     1  a structured SARIF field the scanner chose for the purpose (`properties.purl`)
#     2  a structured field under one of the several names the scanners disagree about
#     3  a LABELLED value inside the rendered message ("Package: requests")
#
#   Tier 3 is the weakest and is deliberately last. Its failure mode is the safe one: a vendor
#   rewording the label makes the pattern MISS, which refuses, rather than capturing a different
#   value that would move the identity silently. The capture is additionally constrained to a
#   coordinate-shaped token so a reworded label cannot hand it a sentence.

# `pkg:type/namespace/name@version?qualifiers#subpath` -- RFC-shaped, parsed rather than split
# blindly, because the namespace is optional and the version is what an upgrade changes.
_PURL_PARTS = re.compile(r'^pkg:([a-z0-9.+-]+)/(.+?)@([^?#]+)', re.I)
# A coordinate-shaped token: no whitespace, no comma, no sentence. See the tier-3 note above.
_COORD = re.compile(r'^[A-Za-z0-9][A-Za-z0-9._:+~@/-]{0,200}$')
# A Terraform/Bicep style address, with an optional module prefix of any depth.
_IAC_ADDR = re.compile(r'^((?:module\.[A-Za-z0-9_-]+\.)*)([A-Za-z0-9_-]+)\.([A-Za-z0-9_\[\]."-]+)$')

# Comment syntax is DECLARED, never guessed -- `finding_identity._strip_line_comments` refuses to
# guess and records that it did not. This maps the extensions the kit's own scanners actually
# produce; an unknown extension yields no declaration, which is a weaker but honest normalisation
# and is recorded in the content hash rather than hidden.
_LANGUAGE_FAMILY = {
    'c_like': ('.c', '.h', '.cc', '.cpp', '.cxx', '.hpp', '.java', '.cs', '.go', '.js', '.jsx',
               '.ts', '.tsx', '.mjs', '.cjs', '.php', '.swift', '.kt', '.kts', '.scala', '.rs',
               '.m', '.mm', '.groovy', '.dart'),
    'hash': ('.py', '.sh', '.bash', '.zsh', '.rb', '.pl', '.yml', '.yaml', '.tf', '.tfvars',
             '.toml', '.cfg', '.conf', '.ini', '.dockerfile', '.ps1', '.r'),
    'sql': ('.sql', '.psql', '.pgsql'),
}


def language_family_of(uri):
    """-> the declared comment family for this path, or '' when nothing declares it."""
    low = (uri or '').lower()
    base = os.path.basename(low)
    if base in ('dockerfile', 'makefile') or base.startswith('dockerfile.'):
        return 'hash'
    ext = os.path.splitext(low)[1]
    for family, exts in _LANGUAGE_FAMILY.items():
        if ext in exts:
            return family
    return ''


def _props(res, rule):
    """Result properties first, then rule properties. A result-level value is about THIS finding;
    a rule-level value is about every finding the rule ever produced, so it never wins."""
    out = {}
    for src in ((rule or {}).get('properties') or {}, (res or {}).get('properties') or {}):
        if isinstance(src, dict):
            for k, v in src.items():
                if isinstance(v, (str, int, float)) and not isinstance(v, bool):
                    out[str(k)] = str(v)
    return out


def _first_prop(props, names):
    """-> (value, which_key) for the first populated key, searched case-insensitively.

    Scanners disagree about spelling -- `pkgName`, `PkgName`, `package_name`, `packageName` are
    four tools naming one thing. Matching case-insensitively on an explicit NAME LIST keeps that
    an enumerated disagreement rather than a heuristic that could absorb an unrelated field.
    """
    lowered = dict((k.lower(), (k, v)) for k, v in props.items())
    for n in names:
        hit = lowered.get(n.lower())
        if hit and str(hit[1]).strip():
            return (str(hit[1]).strip(), hit[0])
    return ('', '')


def _labelled(msg, label):
    """-> a coordinate-shaped value following `<label>:` in a rendered message, or ''.

    TIER 3. See the basis-tier note above: this misses rather than mis-captures.
    """
    m = re.search(r'(?im)^\s*%s\s*:\s*(\S+)\s*$' % re.escape(label), msg or '')
    if not m:
        m = re.search(r'(?i)\b%s\s*:\s*([^\s,;]+)' % re.escape(label), msg or '')
    if not m:
        return ''
    value = m.group(1).strip().strip('.,;')
    return value if _COORD.match(value) else ''


def purl_parts(purl):
    """-> (name, version) from a purl, or ('', ''). The namespace stays WITH the name: `@scope/pkg`
    and `pkg` are different packages, and dropping the namespace would merge them."""
    m = _PURL_PARTS.match((purl or '').strip())
    if not m:
        return ('', '')
    return (m.group(2).strip('/'), m.group(3).strip())


def construct_of(res):
    """-> (the matched construct, basis) or ('', why not).

    THE CONSTRUCT IS THE SNIPPET, AND NORMALISATION IS WHAT MAKES THAT SAFE.

    `finding_identity.EXCLUDED` lists `snippet` with "matched material -- the baseline never
    needs to hold one", and that is about the RAW snippet, which for a secret scanner is the
    secret. It is still the only thing in a SARIF document that carries the construct, so the
    reconciliation is twofold and neither half is optional:

      1  Secret findings never reach here with an identity at all. `parse_sarif` marks them
         `is_secret_finding`, and `identify()` refuses them outright under
         SECRET_SUBJECT_NOT_BASELINEABLE -- so no secret-derived material is ever hashed into
         anything, which is section 5.7's rule and not a convenience.
      2  CONTENT for SOURCE is LITERALS_PLACEHOLDERED. Every string and numeric literal is
         replaced before hashing, so `conn = connect("hunter2")` and `conn = connect("letmein")`
         normalise to one construct. The hash cannot be an offline oracle for a value that was
         destroyed before it was hashed.

    THE RESIDUAL, STATED: the kit's own pre-upload redactor strips `snippet` and
    `contextRegion.snippet` from every SARIF before it becomes an artifact, and the `report` job
    reads those artifacts. So on the real pipeline this returns '' for most SAST findings and
    the identity REFUSES with CONTENT_UNDERIVABLE -- which is the honest state and is visible in
    `identity_state`, but it is a conflict between two controls rather than a working path. See
    docs/KNOWN_DEFECTS.md.
    """
    for loc in (res.get('locations') or []):
        pl = loc.get('physicalLocation') or {}
        for region_key in ('region', 'contextRegion'):
            text = (((pl.get(region_key) or {}).get('snippet') or {}).get('text') or '')
            if text.strip():
                return (text, 'construct from physicalLocation.%s.snippet' % region_key)
    direct = ((res.get('properties') or {}).get('snippet') or '')
    if isinstance(direct, str) and direct.strip():
        return (direct, 'construct from result properties.snippet')
    return ('', 'no snippet in any region and none in result properties -- the matched construct '
                'is not in this document, so CONTENT cannot be derived from it')


def _iac_address(addr):
    """-> (module_path, resource_type, resource_name) or ('', '', '').

    `module.platform.azurerm_storage_account.artifacts` -> ('module.platform',
    'azurerm_storage_account', 'artifacts'). A ROOT-MODULE resource yields '' for the module
    path, which `identify()` treats as PRESENT AND EMPTY rather than missing -- the distinction
    its `=module_path` prefix exists for.
    """
    m = _IAC_ADDR.match((addr or '').strip())
    if not m:
        return ('', '', '')
    return (m.group(1).rstrip('.'), m.group(2), m.group(3))


def locus_of(subject, rule, res, rid, msg, uri, what):
    """-> (dict of identity-grade WHERE/CONTENT fields, basis prose).

    ONE FUNCTION, DISPATCHED ON THE DECLARED SUBJECT, because the locus is subject-scaled by
    design: an image finding's locus is a package coordinate and a source finding's is a symbol,
    and a single "generic" extractor would have to pick one and be wrong about the rest. The
    subject is already established by `finding_subject.subject_for`, so nothing here guesses it.

    Returns ONLY fields it could actually derive. An absent field is absent.
    """
    out, basis = {}, []
    props = _props(res, rule)

    if subject == 'SOURCE':
        # WHERE is `canonical_path` (+ `symbol_path`), both set by the caller from SARIF's own
        # location structures. What was missing was CONTENT.
        text, why = construct_of(res)
        if text:
            out['construct'] = text
            basis.append(why)
        else:
            basis.append(why)
        family = language_family_of(uri)
        if family:
            out['language_family'] = family
            basis.append('language_family %r declared from the path extension' % family)
        else:
            basis.append('no language family declared for %r, so comments stay in the construct '
                         'and the content hash records that' % (os.path.splitext(uri or '')[1]
                                                                or uri or ''))
        # `?dependency_scope` and `?manifest_role` are DELIBERATELY NOT POPULATED here. They are
        # optional locus fields, and an optional locus field that a scanner reports in one run
        # and omits in the next MOVES the identity between runs -- which is the defect this whole
        # module exists to prevent, arriving through the fix for it. Nothing the kit's scanners
        # emit states either one reliably, so neither is supplied and the locus is the same shape
        # on every run.

    elif subject == 'SOURCE_DEPENDENCY':
        # The locus is the purl and nothing else. `what_of` already lifts a purl where the SARIF
        # carries one; this adds the two weaker tiers and refuses rather than assembling a purl
        # out of parts, because a GUESSED ecosystem produces a plausible-looking coordinate for
        # the wrong registry -- `pkg:npm/requests` and `pkg:pypi/requests` are different packages.
        if what.get('purl'):
            basis.append('purl already lifted by what_of (tier 1)')
        else:
            value, key = _first_prop(props, ('purl', 'packageUrl', 'package_url', 'pkgIdentifier',
                                             'PkgIdentifier'))
            if value.lower().startswith('pkg:'):
                out['purl'] = value
                basis.append('purl from properties.%s (tier 2)' % key)
            else:
                basis.append('no purl in the SARIF. A dependency locus is the package '
                             'coordinate, and assembling one from a package name plus a guessed '
                             'ecosystem would name the wrong registry -- so this refuses and '
                             'says which field is missing')

    elif subject == 'IMAGE':
        name, version, how = '', '', ''
        if what.get('purl'):
            name, version = purl_parts(what['purl'])
            how = 'package coordinate from the purl (tier 1)'
        if not (name and version):
            pn, kn = _first_prop(props, ('pkgName', 'PkgName', 'package_name', 'packageName',
                                         'package'))
            pv, kv = _first_prop(props, ('installedVersion', 'InstalledVersion',
                                         'installed_version', 'packageVersion',
                                         'package_version', 'version'))
            if pn and pv:
                name, version, how = pn, pv, ('package coordinate from properties.%s/%s (tier 2)'
                                              % (kn, kv))
        if not (name and version):
            pn = _labelled(msg, 'Package')
            pv = _labelled(msg, 'Installed Version')
            if pn and pv:
                name, version, how = pn, pv, ('package coordinate from the labelled "Package" '
                                              'and "Installed Version" lines of the rendered '
                                              'message (tier 3, the weakest)')
        if name and version:
            out['package_name'] = name
            out['package_version'] = version
            basis.append(how)
        else:
            basis.append('no package name and version could be derived from a purl, from '
                         'structured properties, or from labelled lines in the message. The '
                         'installed package coordinate IS an image finding, so without it there '
                         'is no locus and the identity refuses -- deliberately NOT the image '
                         'digest, which changes on every rebuild')
        # `?package_source` separates two copies of one library at two paths inside one image.
        # Populated only from an explicit field: its presence is a property of the package KIND
        # (an OS package has no path, a bundled jar does), so it is stable per finding rather
        # than varying run to run.
        src, ks = _first_prop(props, ('pkgPath', 'PkgPath', 'package_path', 'packagePath'))
        if src:
            out['package_source'] = src
            basis.append('package_source from properties.%s' % ks)

    elif subject == 'IAC_PLAN':
        addr, ka = _first_prop(props, ('resource', 'resourceId', 'resource_id',
                                       'resourceAddress', 'resource_address'))
        how = 'resource address from properties.%s' % ka if addr else ''
        if not addr:
            addr = _labelled(msg, 'Resource')
            how = 'resource address from the labelled "Resource" line of the message (tier 3)'
        module_path, rtype, rname = _iac_address(addr)
        if rtype and rname:
            # Present and EMPTY for a root-module resource, which is a value and not a gap.
            out['module_path'] = module_path
            out['resource_type'] = rtype
            out['resource_name'] = rname
            basis.append('%s -> module_path=%r type=%r name=%r'
                         % (how, module_path, rtype, rname))
        else:
            basis.append('no parseable resource address (%r). The plan\'s resource ADDRESS is '
                         'the locus precisely because it survives the file being reformatted or '
                         'split, and the file offset does not -- so a finding without one '
                         'refuses rather than falling back to a line number' % addr)
        attr, kt = _first_prop(props, ('attribute', 'attributePath', 'attribute_path',
                                       'checkPath', 'check_path', 'evaluatedKeys'))
        if attr:
            out['attribute_path'] = attr
            basis.append('attribute_path from properties.%s' % kt)
        else:
            basis.append('no attribute path in the SARIF. For declarative state the VALUE is the '
                         'finding, so CONTENT is hashed verbatim and must be the attribute -- the '
                         'matched block as a whole would move the identity whenever an unrelated '
                         'attribute beside it changed')

    elif subject == 'RUNTIME_OBSERVATION':
        host, path, port = _url_locus(uri)
        if host:
            out['target_host'] = host
            out['target_path'] = path          # '=target_path': '' is the root, not a gap
            basis.append('target_host/%s from the probed URL (deliberately not the resolved IP, '
                         'which rotates behind a load balancer)'
                         % ('target_path=%r' % path))
            if port:
                out['observed_port'] = port
                basis.append('observed_port %s stated explicitly in the URL' % port)
        else:
            basis.append('locator %r is not a URL, so there is no host and path to anchor a '
                         'runtime observation to' % uri)
        cond, kc = _first_prop(props, ('evidence', 'observed', 'observedCondition',
                                       'observed_condition', 'attack', 'other'))
        if cond:
            out['observed_condition'] = cond
            basis.append('observed_condition from properties.%s' % kc)
        else:
            basis.append('no observed condition in the SARIF. The scanner\'s prose is excluded '
                         'from identity by construction, so there is nothing else to hash and '
                         'the identity refuses')

    else:
        # RESOURCE, IDENTITY_ASSIGNMENT, POLICY and RELEASE are registered subjects that NO
        # SCANNER IN THIS KIT PRODUCES -- `finding_subject.BY_SCANNER` maps nothing to them and
        # only an explicit `mode=` declaration can reach them. Saying so is the point: an empty
        # branch that silently returned nothing would be indistinguishable from an extractor that
        # ran and found nothing, which is the four-state collapse this kit refuses. They need a
        # cloud-posture or RBAC reader that does not exist yet, not a SARIF extractor.
        basis.append('subject %s has no SARIF extractor: no scanner in this kit emits it, so '
                     'nothing here can derive its locus and the identity refuses. This is NOT '
                     '"the fields were absent" -- it is "no extraction was attempted"' % subject)

    return out, '; '.join(basis)


def _url_locus(uri):
    """-> (host, path, port) from a probed URL, or ('', '', '').

    Hand-parsed rather than via urllib so this stays inlinable into the workflow with no import
    the bootstrap copy might not have, and so a non-URL locator returns a clean negative instead
    of a surprising parse of a filesystem path.
    """
    text = (uri or '').strip()
    m = re.match(r'(?i)^(https?)://([^/?#]+)([^?#]*)', text)
    if not m:
        return ('', '', '')
    authority = m.group(2)
    path = m.group(3) or '/'
    authority = authority.rsplit('@', 1)[-1]        # strip any userinfo
    port = ''
    if authority.startswith('['):                   # IPv6 literal
        host, _, rest = authority.partition(']')
        host = host.lstrip('[')
        if rest.startswith(':'):
            port = rest[1:]
    elif authority.count(':') == 1:
        host, _, port = authority.partition(':')
    else:
        host = authority
    if port and not port.isdigit():
        port = ''
    return (host.lower(), path, port)


# Scanners whose findings ARE credential material. A secret finding has no baseline identity by
# design -- section 5.7: the baseline has no authority over secrets, they block at every rung and
# are never grandfathered -- and `identify()` refuses them under SECRET_SUBJECT_NOT_BASELINEABLE.
#
# Declaring this is what makes the construct extraction above safe: without it a gitleaks SARIF
# read before redaction would hash the matched secret into a durable key and commit it to a
# readable branch, which is the offline-crackable oracle `finding_identity.EXCLUDED` warns about
# under `partial_fingerprints`. The refusal is also a BETTER state than the one these findings
# reported before: CONTENT_UNDERIVABLE said the record was incomplete; this says the baseline is
# not the right mechanism, which is a different and correct sentence.
SECRET_SCANNERS = ('gitleaks', 'detect-secrets', 'trufflehog')


def is_secret_scanner(scanner, tool, rid):
    name = (scanner or '').strip().lower()
    driver = (tool or '').strip().lower()
    if name in SECRET_SCANNERS or driver in SECRET_SCANNERS:
        return True
    # Trivy and Semgrep both have secret/credential rule namespaces, and a credential reported by
    # a general-purpose scanner is still a credential.
    return bool(re.search(r'(?i)(^|[._/-])(secret|credential)s?([._/-]|$)', rid or ''))


def load_dispositions(path):
    """Approved exceptions, keyed by fingerprint. Absent file is not an error -- it means the
    governance layer is not yet in place, which is a state to report, not to crash on."""
    if not path or not os.path.exists(path):
        return ({}, 'NOT CONFIGURED')
    try:
        d = json.load(io.open(path, encoding='utf-8', errors='replace'))
    except (ValueError, IOError):
        return ({}, 'PRESENT BUT UNREADABLE')
    if isinstance(d, dict) and 'dispositions' in d:
        d = d['dispositions']
    if isinstance(d, list):
        d = dict((x.get('fingerprint'), x) for x in d if isinstance(x, dict))
    if not isinstance(d, dict):
        return ({}, 'LOADED')
    # The key IS the fingerprint. A register keyed by it need not repeat it inside each record,
    # and the schema's required field is satisfied by the key rather than refused for its absence.
    out = {}
    for k, v in d.items():
        if isinstance(v, dict) and not str(v.get('fingerprint') or '').strip():
            v = dict(v, fingerprint=str(k))
        out[k] = v
    return (out, 'LOADED')


# ── DISPOSITIONS: TO THE SCHEMA (L49), ON THE DURABLE KEY (KDEC-008 OD-6) ──────────────
#
# THE REGISTERED disposition_type VOCABULARY, not a paraphrase of it.
#
# This said RISK_ACCEPTED. assurance-taxonomy.yaml says ACCEPTED_RISK. Same concept, reversed,
# and the reporter suppressed only on ITS spelling -- so a disposition written to the registered
# schema would have suppressed nothing and the gate would have blocked an approved exception
# forever, with no error anywhere. A third spelling (RISK_ACCEPTANCE) was in circulation in
# conversation. One truth, three names.
SUPPRESSING = ('FALSE_POSITIVE', 'ACCEPTED_RISK', 'MITIGATED', 'REMEDIATED')

# THE CLAIM AND THE LIFECYCLE ARE TWO FIELDS, and this file read one as the other (L49).
#
# schemas/disposition.schema.json: `disposition_type` is the CLAIM (one of SUPPRESSING) and
# `state` is the LIFECYCLE -- proposed, under_review, approved, rejected, needs_evidence,
# expired, invalidated -- of which ONLY `approved` suppresses: "a proposal never buys passage".
# This file matched `state` against the claim vocabulary, so a record written exactly to the
# schema suppressed nothing, a record written to neither suppressed, and a record with no
# `expires` -- which the schema REQUIRES -- suppressed forever. Now the schema is the contract:
# a record outside it suppresses nothing, and the reason says which field.
approved_state = 'approved'
schema_required = ('fingerprint', 'scanner', 'rule', 'scope_path', 'disposition_type',
                   'rationale', 'approver_role', 'created', 'expires')
rationale_min_length = 20

# THE KEY MIGRATION WINDOW (KDEC-008 OD-6, accepted 2026-10-14). Dispositions are honoured on
# the durable identity. For thirty days from the decision the legacy fingerprint -- scanner,
# rule id, path and message, the four fields a vendor change moves -- is ALSO honoured, so no
# approval already granted is orphaned overnight. After the window a legacy key stops
# suppressing and the run names it and the identity to re-key to. The anchor is the decision
# date rather than each record's own date because the window is one migration, not a per-record
# grace period: a record keyed last year and a record keyed yesterday both have until the same
# day. The owner may move either number by a new decision; nothing else here depends on them.
legacy_key_window_opened = '2026-10-14'
legacy_key_window_days = 30
legacy_key_window_closes = (datetime.date(*[int(x) for x in legacy_key_window_opened.split('-')])
                            + datetime.timedelta(days=legacy_key_window_days)).isoformat()


def _date(text):
    try:
        return datetime.date(*[int(x) for x in str(text)[:10].split('-')])
    except (ValueError, TypeError):
        return None


def not_suppressed_because(d, today=None):
    """-> the reason this disposition does NOT suppress, or '' when it DOES.

    Named for what it returns. `suppressed_by()` returning a reason it is NOT suppressed reads
    exactly backwards at the call site, which is how an inverted condition survives review.

    THE SCHEMA IS CHECKED HERE, NOT ONLY BY A VALIDATOR SOMEWHERE ELSE. A record that a validator
    would refuse and this function would honour is a record that suppresses without ever having
    been valid, and the two readers must not disagree about what buys passage.

    EXPIRY IS ENFORCED, NOT DISPLAYED. The registered model says
    `approved -> expired (automatic; silence NEVER renews)`. Showing an expiry date while still
    honouring a lapsed acceptance is how a 90-day risk acceptance becomes permanent: nobody
    revisits it, because nothing ever went red again. And an ABSENT expiry is not open-ended --
    the schema requires one, so a record without it is outside the schema and suppresses nothing.
    """
    if not isinstance(d, dict) or not d:
        return 'no disposition recorded'
    claim = str(d.get('disposition_type') or '').strip()
    if not claim:
        if d.get('state') in SUPPRESSING:
            return ('the claim %s is written in `state`. The schema puts the claim in '
                    '`disposition_type` and reserves `state` for the lifecycle, of which only '
                    '`approved` suppresses -- re-write the record to the schema' % d['state'])
        return 'no disposition_type -- a record outside the schema suppresses nothing'
    if claim not in SUPPRESSING:
        return 'disposition_type %s is not a registered claim' % claim
    state = str(d.get('state') or 'proposed').strip()      # the schema's default is proposed
    if state != approved_state:
        return 'state %s does not suppress -- only approved does; a proposal never buys passage' % state
    missing = [k for k in schema_required if not str(d.get(k) or '').strip()]
    if missing:
        return ('schema-invalid: lacks %s -- a record outside the schema suppresses nothing'
                % ', '.join(missing))
    if len(str(d['rationale']).strip()) < rationale_min_length:
        return ('rationale is %d characters; the schema requires %d, because a reason nobody can '
                'evaluate cannot be reviewed when it expires'
                % (len(str(d['rationale']).strip()), rationale_min_length))
    if claim == 'MITIGATED' and not str(d.get('compensating_control') or '').strip():
        return 'MITIGATED names no compensating_control, and naming it is what distinguishes mitigation from acceptance'
    if claim == 'ACCEPTED_RISK' and not str(d.get('evidence_ref') or '').strip():
        return 'ACCEPTED_RISK carries no evidence_ref: accepting a real risk requires a record of who accepted it and under what conditions'
    when = _date(d['expires'])
    if when is None:
        return 'expiry %r is unparseable -- an unreadable expiry is not an open-ended one' % d['expires']
    if when < (today or datetime.date.today()):
        return 'EXPIRED %s' % d['expires']
    return ''


def disposition_for(f, disp, today=None):
    """-> (record or None, key basis, note). Which register entry applies to this finding.

    THE DURABLE IDENTITY FIRST, THE LEGACY FINGERPRINT INSIDE THE WINDOW, NOTHING AFTER IT.
    The basis is returned so a reader can see WHICH key an approval rode in on, and the note is
    what the run says about a legacy key: until when it is honoured, or that it no longer is and
    what to re-key it to. A record found under the durable key wins whenever one exists, even a
    proposed one -- it is the record for this finding under the scheme the kit now keys on.
    """
    disp = disp or {}
    today = today or datetime.date.today()
    ident = str(f.get('identity') or '')
    if ident and ident in disp:
        return (disp[ident], 'durable', '')
    fp = str(f.get('fp') or '')
    if fp and fp in disp:
        if today.isoformat() <= legacy_key_window_closes:
            return (disp[fp], 'legacy',
                    'keyed on the legacy fingerprint, honoured until %s (KDEC-008 OD-6), after '
                    'which it stops suppressing; re-key it to the durable identity %s'
                    % (legacy_key_window_closes, ('`%s`' % ident) if ident else '(NOT COMPUTED for this finding)'))
        return (None, 'legacy-closed',
                'a disposition keyed on the legacy fingerprint `%s` exists and the %d-day window '
                'closed on %s, so it NO LONGER SUPPRESSES. Re-key it to the durable identity %s'
                % (fp, legacy_key_window_days, legacy_key_window_closes,
                   ('`%s`' % ident) if ident else '(NOT COMPUTED for this finding -- see identity_state)'))
    return (None, '', '')


def is_suppressed(f, disp, today=None):
    rec, _basis, _note = disposition_for(f, disp, today)
    return rec is not None and not not_suppressed_because(rec, today)


def blocking_of(findings, disp, today=None):
    """THE definition of a blocking finding. Called by both the summary table and the detail
    section, because computing it twice is how a report comes to disagree with itself -- the
    table saying 2 while the list beneath it shows 1, and a reader trusting whichever they read
    first. One truth, one function."""
    return [f for f in findings if f['severity'] in BLOCKING and not is_suppressed(f, disp, today)]


def counts_of(findings):
    c = dict((s, 0) for s in SEV_ORDER)
    for f in findings:
        c[f['severity']] = c.get(f['severity'], 0) + 1
    return c


def render(cfg, findings, parse_state, disp, disp_state, examination, today=None):
    """The five sections. Written once so sixteen scanners cannot invent sixteen dialects.

    `examination` is `(state, witnesses)` from `examination_of`, and it is REQUIRED rather than
    defaulted. A default here would be the defect this parameter exists to close, one layer up:
    every caller that forgot it would get the permissive answer, which is exactly how
    `--execution` came to default to COMPLETE. There is no safe default, so there is no default.
    """
    L = []
    add = L.append
    scanner = cfg['scanner']
    applic = cfg['applicability']
    execu = cfg['execution']
    exam_state, exam_witnesses = examination

    established = (parse_state == 'COMPLETE'
                   and execu not in NO_COUNT_STATES
                   and applic not in NO_COUNT_APPLIC
                   and exam_state in COUNTABLE_EXAMINATION)

    add('### %s' % scanner)
    add('')
    add('| | |')
    add('|---|---|')
    add('| Applicability | %s |' % applic)
    add('| Execution | %s |' % execu)
    add('| Scope | %s |' % (cfg['scope'] or 'NOT DECLARED'))
    add('')

    # ---- RESULT -------------------------------------------------------------
    add('**RESULT**')
    add('')
    if not established:
        why = {'UNAVAILABLE': 'the capability is not licensed or not available to this repository',
               'NOT_CONFIGURED': 'the capability is available but not enabled',
               'NOT_APPLICABLE': 'no files in scope for this scanner',
               'COVERAGE_GAP': 'the artefact is present, a control is owed, and nothing looked',
               'UNKNOWN': 'applicability could not be established -- the token could not see the '
                          'answer, and an unknown is not a negative',
               }.get(applic, '')
        if not why:
            why = {'COLLECTION_FAILED': 'the scanner ran and produced no usable report',
                   'FAILED': 'the scanner did not complete',
                   'NOT_RUN': 'the scanner did not run',
                   'NOT_DECLARED': 'the invoking job declared no execution state, and silence is '
                                   'not a result',
                   }.get(execu, '')
        # THE EXAMINATION AXIS IS CHECKED LAST AND ITS REASON WINS.
        #
        # Order matters and this is the useful order. Where the caller declared APPLICABLE and
        # COMPLETE -- which is what a crashed-but-exited-0 scanner produces -- the two lookups
        # above find nothing, and the old fallback string was "the report could not be parsed".
        # That would have been a FALSE explanation for a report that parsed perfectly well, which
        # is its own small lie and would send an engineer to the wrong place.
        if exam_state not in COUNTABLE_EXAMINATION:
            why = ('the scan examined nothing' if exam_state == EXAMINED_NOTHING
                   else 'the report does not record that anything was examined')
        # A REPORT THAT COULD NOT BE READ IS THE ROOT CAUSE, and it outranks the examination
        # axis: the examination of an unreadable document is undeclared BECAUSE it is unreadable,
        # and saying only the former sends an engineer after the wrong thing.
        if parse_state == 'UNPARSEABLE' or not why:
            why = 'the report could not be parsed'
        add('Findings: **NOT ESTABLISHED** -- %s.' % why)
        add('')
        add('This is not zero. Nothing looked at this scope, so no statement about it is')
        add('supported by this run.')
        if exam_state not in COUNTABLE_EXAMINATION and exam_witnesses:
            add('')
            add('What the report itself says about what it examined:')
            add('')
            for w in exam_witnesses[:6]:
                add('- %s' % w)
            if len(exam_witnesses) > 6:
                add('- _and %d further witness(es), all in the artifact._'
                    % (len(exam_witnesses) - 6))
    elif not findings:
        add('Findings: **NONE** in the scanned scope.')
    else:
        c = counts_of(findings)
        add('| Severity | Count |')
        add('|---|---|')
        for s in SEV_ORDER:
            if c.get(s):
                add('| %s | %d |' % (s.title(), c[s]))
        add('| **Total** | **%d** |' % len(findings))
    add('')

    # ---- ASSURANCE ----------------------------------------------------------
    add('**ASSURANCE**')
    add('')
    add('| | |')
    add('|---|---|')
    add('| Machine output | %s |' % {'COMPLETE': 'COMPLETE', 'ABSENT': 'ABSENT',
                                     'UNPARSEABLE': 'UNPARSEABLE'}[parse_state])
    add('| SARIF | %s |' % ('GENERATED' if parse_state == 'COMPLETE' else
                            'NOT GENERATED' if parse_state == 'ABSENT' else 'INVALID'))
    # Reported on EVERY row, green ones included. A caveat that appears only when it is bad
    # teaches a reader that its absence means nothing was checked.
    add('| Scan examination | %s |' % exam_state)
    add('| Artifact | %s |' % cfg['artifact'])
    add('| GitHub Security upload | %s |' % cfg['upload'])
    add('| Gate state | %s |' % cfg['gate'])
    # KDEC-010: a row the capability selection capped says WHY, on the row, in the resolver's
    # words -- the gap and the registry row that closes it, or the scanner that was selected
    # instead. Rendered only when set: an uncapped row has no fitness caveat to print.
    if cfg.get('fitness'):
        add('| Version fitness | %s -- %s |' % cfg['fitness'])
    add('| Disposition register | %s |' % disp_state)
    add('')
    if cfg.get('fitness'):
        add('Coverage claim: **PARTIAL** (%s). Findings above are findings; the absence of '
            'findings is not coverage for the target named, because this scanner cannot read it.'
            % cfg['fitness'][0])
        add('')

    # ---- ACTION REQUIRED ----------------------------------------------------
    blocking = blocking_of(findings, disp, today)
    add('**ACTION REQUIRED**')
    add('')
    if not established:
        # The distinction that stops a developer being sent after a licensing decision.
        add('Platform or security action required. Developer action: **NONE**.')
        add('')
        if applic == 'UNAVAILABLE':
            add('`%s` did not run because the capability is not available to this repository.' % scanner)
            add('')
            add('Platform action:')
            add('- Confirm licensing covers this repository')
            add('- Enable the capability if this repository is in scope')
            add('- Re-run validation')
        elif applic == 'NOT_CONFIGURED':
            add('`%s` is available but not enabled for this repository.' % scanner)
            add('')
            add('Platform action:')
            add('- Enable it in repository or organisation settings')
            add('- Re-run validation')
        elif applic == 'NOT_APPLICABLE':
            add('No files in scope for `%s`. Nothing to do.' % scanner)
            add('')
            add('Confirm the scope is what you expect -- a scanner reporting no applicable files')
            add('because it was pointed at the wrong path looks identical to one on a clean repo.')
        elif exam_state not in COUNTABLE_EXAMINATION:
            # BEFORE the generic branch, because the generic branch blames `execution` -- and in
            # the case that matters `execution` is COMPLETE and is not lying. "failed to produce a
            # usable result (COMPLETE)" is a sentence that sends an engineer looking for a
            # collection failure that did not happen.
            if exam_state == EXAMINED_NOTHING:
                add('`%s` ran and examined NOTHING. The report parsed; it establishes that the '
                    'scan read nothing.' % scanner)
            else:
                add('`%s` produced a report that does not record what it examined.' % scanner)
            add('')
            add('The declared execution state is `%s`, and that is not contradicted here -- the '
                'process may well have exited 0.' % execu)
            add('This axis is the scanner\'s own account of its run, and it disagrees.')
            add('')
            add('Platform action:')
            add('- Inspect the job log for a vulnerability-database or rule-pack failure')
            add('- Confirm the scanner was pointed at a path that exists and is non-empty')
            add('- This is a pipeline defect, not a code defect -- do not chase it as a finding')
            add('- Treat this scope as UNMEASURED until a run examines it')
        else:
            add('`%s` failed to produce a usable result (%s).' % (scanner, execu))
            add('')
            add('Platform action:')
            add('- Inspect the job log for the collection failure')
            add('- This is a pipeline defect, not a code defect -- do not chase it as a finding')
        add('')
        add('Finding state: **NOT ESTABLISHED**')
    elif not blocking:
        add('None.')
        add('')
        info = len(findings)
        if info:
            add('No blocking findings were identified in the scanned scope.')
            add('Informational and low findings: %d -- review recommended; no merge block.' % info)
        else:
            add('No findings were identified in the scanned scope.')
    else:
        add('Blocking findings: **%d**' % len(blocking))
        add('')
        for i, f in enumerate(blocking[:cfg['max_detail']], 1):
            rec, basis, note = disposition_for(f, disp, today)
            d = rec or {}
            add('%d. `%s`' % (i, f['rule'] or '(no rule id)'))
            add('   - Severity: %s' % f['severity'])
            if f['uri']:
                add('   - Location: `%s%s`' % (f['uri'], (':%d' % f['line']) if f['line'] else ''))
            if f['message']:
                add('   - Issue: %s' % f['message'].split('\n')[0][:300])
            if f['remediation']:
                add('   - Recommended action: %s' % f['remediation'])
            else:
                add('   - Recommended action: NOT SUPPLIED by the scanner -- needs triage')
            add('   - Tracking: %s' % (d.get('ticket') or d.get('evidence_ref') or 'NOT CREATED'))
            # A blocking finding with a record is a record that does NOT suppress, and the reason
            # is printed beside it: the lifecycle, the missing field, the lapsed date, or the
            # legacy key whose window closed.
            why = not_suppressed_because(d, today) if d else (note or 'no disposition recorded')
            add('   - Disposition: %s%s' % ((d.get('disposition_type') or d.get('state') or 'NONE'),
                                            '' if (not d and not note) else
                                            ('  (%s)' % why if why else '  -- honoured')))
            if d.get('expires'):
                add('   - Expires: %s%s' % (d['expires'],
                                            '  -- LAPSED, no longer suppressing'
                                            if why.startswith('EXPIRED') else
                                            '  -- revalidate before expiry'))
            add('   - Identity: `%s`' % (f.get('identity') or ('NOT COMPUTED (%s)' % (f.get('identity_reason') or 'no reason'))))
            add('   - Legacy fingerprint: `%s`' % f['fp'])
        if len(blocking) > cfg['max_detail']:
            add('')
            add('_%d further blocking findings not listed here; all %d are in the artifact._'
                % (len(blocking) - cfg['max_detail'], len(blocking)))
        add('')
        add('**NEXT STEP** -- resolve the %d blocking finding(s), or submit an approved disposition'
            % len(blocking))
        add('(false positive, mitigation, risk acceptance, deferral) keyed on the durable identity.')
    add('')

    # ---- TRACKING / DISPOSITION --------------------------------------------
    if established and findings:
        # Every finding a register entry applies to, under either key, suppressing or not --
        # including a legacy key whose window has closed, which is the one the run must name.
        held = [(f,) + disposition_for(f, disp, today) for f in findings]
        held = [h for h in held if h[1] is not None or h[2]]
        add('**TRACKING / DISPOSITION**')
        add('')
        if disp_state == 'NOT CONFIGURED':
            add('No disposition register configured. Every finding above is untriaged by')
            add('definition -- an accepted risk that is not recorded is indistinguishable from')
            add('one nobody noticed.')
        elif not held:
            add('%d finding(s), none carrying a recorded disposition.' % len(findings))
        else:
            add('| Identity | Disposition | Key | Approver role | Expires |')
            add('|---|---|---|---|---|')
            for f, d, basis, note in held[:cfg['max_detail']]:
                d = d or {}
                why = not_suppressed_because(d, today) if d else note
                add('| `%s` | %s%s | %s | %s | %s |'
                    % (f.get('identity') or ('legacy `%s`' % f['fp']),
                       d.get('disposition_type') or d.get('state') or 'NONE',
                       ('' if not why else ' (%s)' % why) if d else ' (%s)' % why,
                       basis, d.get('approver_role') or d.get('approved_by') or '--',
                       d.get('expires', '--')))
            closed = [note for _f, d, basis, note in held if basis == 'legacy-closed']
            if closed:
                add('')
                add('Legacy disposition keys no longer honoured -- the %d-day window closed on %s:'
                    % (legacy_key_window_days, legacy_key_window_closes))
                for n in closed[:cfg['max_detail']]:
                    add('- %s' % n)
        add('')

    # ---- DETAILS / EVIDENCE -------------------------------------------------
    add('**DETAILS / EVIDENCE**')
    add('')
    add('- Artifact: %s' % (cfg['sarif'] or 'none'))
    add('- GitHub Security: %s' % cfg['upload'])
    if cfg['run_url']:
        add('- Run: %s' % cfg['run_url'])
    return '\n'.join(L)


def roster_faults(states, expect):
    """EXACTLY ONE TYPED RESULT PER REGISTERED SCANNER. Returns a list of faults, by scanner ID.

    TWO FAILURES, AND BOTH ARE SILENT WITHOUT THIS.

      no result   a scanner on the roster dropped no state. It is rendered as NOT_RUN below, which
                 is honest -- but a roster entry nothing ever writes is a scanner that was
                 REGISTERED AND WIRED TO NOTHING, and it will render NOT_RUN forever while
                 reading as a scanner that merely did not apply today. This kit has shipped that
                 exact shape repeatedly: `maldeps*.sarif` never matched anything, `checkov*.sarif`
                 never matched anything, and both rows sat in the table looking answered.

      two results two states carrying the same scanner id. The later one wins the row and the
                 earlier one is erased -- including, if they disagree, an erased FINDINGS.

    Named by ID, not counted, because "1 scanner is missing" sends nobody anywhere.
    """
    faults = []
    seen = {}
    for st in states:
        name = st.get('scanner')
        if name:
            seen[name] = seen.get(name, 0) + 1
    for name, n in sorted(seen.items()):
        if n > 1:
            faults.append('two results for %r -- %d states carry this id; one row can only '
                          'show one of them, and the row that loses is erased, not merged'
                          % (name, n))
    for name in expect:
        if name and name not in seen:
            faults.append('no result for %r -- it is on the roster and no state was written '
                          'for it. An absent row reads as nothing to report.' % name)
    return faults


# THE MACHINE-READABLE HALF OF THE REPORT (L52). Written beside the state files so the evidence
# artifact carries it, and so the propose-ledger job and ticket reconciliation read identify()
# results rather than scraping a markdown table. The state loader skips this name: a findings
# file read back as a state file on the next call would be a list of records with `scanner`
# keys, and every one would become a phantom scanner row.
findings_filename = 'findings.json'

# What each observation record carries, and what it never does. Keyed by the names identify()
# uses, because finding_match, finding_correlation and propose_ledger read those names: `state`,
# `reason` and `detail` rather than the reporter's `identity_*` spellings. No `message`, no
# `construct`, no snippet: the file is an artifact anyone with read access can download, and the
# ledger reader's matched-material allowlist refuses every one of those on the way into the ledger.
observation_fields = ('scanner', 'tool', 'scanner_version', 'rule_id', 'severity', 'line',
                      'canonical_path', 'finding_subject', 'state', 'identity', 'what', 'where',
                      'content', 'identity_scope', 'what_aliases', 'cwe', 'reason', 'detail',
                      'fp', 'job', 'row_established')


def observation_of(f, job, established):
    """One finding -> the record the findings file carries. Nothing else is copied."""
    o = {
        'scanner': f['scanner'], 'tool': f['tool'], 'scanner_version': f.get('scanner_version', ''),
        'rule_id': f['rule'], 'severity': f['severity'], 'line': f['line'],
        'canonical_path': f.get('canonical_path', f['uri']),
        'finding_subject': f['finding_subject'],
        'state': f['identity_state'], 'identity': f['identity'] or None,
        'what': f.get('what', ''), 'where': f.get('where', ''), 'content': f.get('content', ''),
        'identity_scope': f.get('identity_scope', ''),
        'what_aliases': list(f.get('what_aliases') or []), 'cwe': f.get('cwe', ''),
        'reason': f['identity_reason'], 'detail': f['identity_detail'],
        'fp': f['fp'], 'job': job, 'row_established': bool(established),
    }
    assert tuple(o) == observation_fields
    return o


def load_ledger(path):
    """-> the dict baseline_ledger.py --out wrote, or None when no ledger was read for this run.

    NONE IS NOT EMPTY. A run that never read the ledger has no baseline, and finding_match answers
    BASELINE_UNAVAILABLE for a state it cannot use -- which is the honest answer, and is different
    from LEDGER_EMPTY (read, established, holds nothing: every finding NEW, correctly).
    """
    if not path:
        return None
    try:
        d = json.load(io.open(path, encoding='utf-8', errors='replace'))
    except (ValueError, IOError) as exc:
        return {'entries': [], 'state': finding_match.LEDGER_LINE_UNPARSEABLE,
                'notes': ['the ledger read result at %s could not be parsed: %s' % (path, exc)]}
    if not isinstance(d, dict):
        return {'entries': [], 'state': finding_match.LEDGER_LINE_UNPARSEABLE,
                'notes': ['the ledger read result is not an object']}
    return d


def load_rule_families(path):
    """-> (table or None, note). The alias table as rule_family.parse_table reads it."""
    if not path:
        return (None, 'no rule-family alias table supplied')
    try:
        text = io.open(path, encoding='utf-8', errors='replace').read()
    except IOError as exc:
        return (None, 'alias table unreadable: %s' % exc)
    table, state, notes = rule_family.parse_table(text)
    if state != rule_family.USABLE:
        return (None, 'alias table unusable: %s' % '; '.join(notes[:3]))
    return (table, 'alias table loaded: %s' % '; '.join(notes[:3]))


def fitness_note(notes, job):
    """The resolver's notes for one job, from its ' ; '-separated fitness_notes output."""
    mine = [n.strip() for n in (notes or '').split(' ; ') if n.strip().startswith(job + ':')]
    return '; '.join(n[len(job) + 1:].strip() for n in mine)


def batch(state_dir, disp_path, max_detail, run_url, expect=(), summary=None, findings_out='',
          ledger=None, environment='', rule_families='', today=None, capped_jobs=(),
          not_selected_jobs=(), fitness_notes=''):
    """Render every scanner from the state files they each dropped. One contract, N inputs.

    WHY BATCH RATHER THAN SIXTEEN PER-JOB REPORTERS
        Two reasons, and the second is the load-bearing one.

        (1) A contract implemented in sixteen places is a contract that drifts in sixteen places.
            This kit already lost fourteen Azure gitleaks rules and a flawfinder fix to exactly
            that, and its own LANDMINES register carries "one truth in three places" as a named
            hazard. Each job establishes only what it alone can know -- did the tool run, was the
            artifact kept, did the upload succeed -- and writes it down. Interpretation happens
            once, here.

        (2) DEDUPLICATION AND CORRELATION ARE ONLY POSSIBLE WHERE EVERY FINDING IS VISIBLE AT
            ONCE. Trivy, Checkov and CodeQL will each report the same exposed storage account.
            Sixteen reporters each holding one scanner's SARIF cannot tell that; they will file
            three tickets and three risk acceptances for one condition, and a later revalidation
            will settle one of them and leave two stale. Cross-scanner identity has to be
            established before anything is routed anywhere.

    A scanner that ran and dropped no state file is reported as MISSING, never omitted. An absent
    row in a report reads as "not applicable" to every human who has ever read one.

    `findings_out` is where the machine-readable findings file is written (L52); empty means
    `<state_dir>/findings.json`. It is written BEFORE this function returns a roster fault, for
    the reason the gate's counts are: a defect in the pipeline must not erase the evidence.

    `ledger` is the dict baseline_ledger.py --out wrote (entries, state, notes), or None when
    none was read; `environment` is the cell the ledger is keyed by; `rule_families` is the path
    of the alias table. THE BASELINE DECIDES NOTHING ABOUT BLOCKING. It says which findings are
    old, and when it cannot say, it says that -- `identity_routing` publishes EVIDENCE_UNTRUSTED
    for the identity claim while `blocking_findings` is computed exactly as before.

    `capped_jobs`, `not_selected_jobs` and `fitness_notes` are the capability selection (KDEC-010)
    as the resolve job publishes it. A row whose job is in either list, and whose gate state is
    PASS, renders PARTIAL -- never PASS -- with the resolver's note beside it: a VERSION_GAP no
    carried scanner can read, or a target another scanner was SELECTED for (a substitution, never
    equivalence). ONLY PASS IS CAPPED. Findings on a capped row are findings and are counted.
    """
    states = []
    findings_out = findings_out or os.path.join(state_dir, findings_filename)
    table, table_note = load_rule_families(rule_families)
    for fn in sorted(os.listdir(state_dir)) if os.path.isdir(state_dir) else []:
        if not fn.endswith('.json') or fn.startswith('.') or fn == findings_filename:
            continue
        try:
            d = json.load(io.open(os.path.join(state_dir, fn), encoding='utf-8',
                                  errors='replace'))
        except (ValueError, IOError):
            states.append({'scanner': fn[:-5], 'applicability': 'APPLICABLE',
                           'execution': 'COLLECTION_FAILED', 'scope': '',
                           'artifact': 'UNKNOWN', 'upload': 'UNKNOWN', 'gate': 'UNDETERMINED',
                           'sarif': '', '_bad_state': True})
            continue
        for item in (d if isinstance(d, list) else [d]):
            if isinstance(item, dict) and item.get('scanner'):
                states.append(item)

    # THE ROSTER IS CHECKED BEFORE THE BACKFILL BELOW FILLS ITS HOLES.
    #
    # Order matters: the backfill invents a NOT_RUN row for every expected scanner that wrote
    # nothing, which is the right thing to RENDER and would make a check run afterwards see a
    # complete roster every time. The faults are therefore collected here, while the difference
    # between "wrote a state" and "had one invented for it" still exists.
    faults = roster_faults(states, expect)

    # A SCANNER THAT WAS EXPECTED AND DROPPED NO STATE FILE MUST APPEAR AS A ROW.
    # An absent row reads as "not applicable" to every human who has ever read a report, so a
    # job that died before writing its state would silently shrink the denominator -- the same
    # defect as a coverage figure whose denominator quietly excludes a modality (LM-015).
    # THE MACHINE-READABLE HALF (C3). The gate decided assurance_state from job conclusions, and a
    # scanner job succeeds WITH findings whenever enforcement is softened -- so recorded findings
    # read as PASS. `summary`, when given, receives what the gate needs to read findings as
    # evidence: the blocking total over ESTABLISHED rows only, and which JOBS established any.
    # A row that established nothing contributes nothing -- it is not a zero.
    by_job = {}
    present = set(st.get('scanner') for st in states)
    for name in expect:
        if name and name not in present:
            states.append({'scanner': name, 'applicability': 'APPLICABLE',
                           'execution': 'NOT_RUN', 'scope': '', 'artifact': 'NONE',
                           'upload': 'NONE', 'gate': 'UNDETERMINED', 'sarif': '',
                           '_missing': True})

    disp, disp_state = load_dispositions(disp_path)
    blocks, index, observations, legacy_closed = [], [], [], 0
    for st in states:
        sarif = st.get('sarif') or ''
        if sarif and not os.path.isabs(sarif):
            cand = os.path.join(state_dir, sarif)
            sarif = cand if os.path.exists(cand) else sarif
        # ISOLATED PER SCANNER (L06). parse_sarif declares its own failures, and this is the
        # second wall: a parser failure that escapes anyway becomes THIS scanner's UNPARSEABLE
        # row with a witness, and the loop goes on. One scanner's broken file must never erase
        # fifteen others' evidence, and a row that could not be read never carries a count.
        try:
            findings, parse_state, examination = parse_sarif(sarif, st['scanner'], table)
        except Exception as exc:  # noqa: BLE001 -- the wall; the reason is kept, never swallowed
            findings, parse_state = [], 'UNPARSEABLE'
            examination = (EXAMINATION_NOT_DECLARED,
                           ['the parser failed on this report: %s: %s -- the row is isolated so '
                            'the other scanners still render' % (type(exc).__name__, str(exc)[:200])])
        if st.get('_bad_state'):
            parse_state = 'UNPARSEABLE'
        # THE WEAKEST VALUE IN EACH NAMESPACE, NOT THE STRONGEST.
        #
        # These two defaults used to be APPLICABLE and COMPLETE, so a state file that named a
        # scanner and a SARIF and nothing else got a clean verdict with 0 in the Blocking and
        # Total columns. There was no statement a job could have made that was stronger than
        # saying nothing, which inverts the whole point of a typed result. An omission must now
        # degrade the verdict, and the row says which field was never declared.
        cfg = dict(scanner=st['scanner'],
                   applicability=st.get('applicability') or 'UNKNOWN',
                   execution=st.get('execution') or 'NOT_DECLARED',
                   scope=st.get('scope', ''), artifact=st.get('artifact', 'UNKNOWN'),
                   upload=st.get('upload', 'UNKNOWN'), gate=st.get('gate', 'UNDETERMINED'),
                   sarif=sarif, run_url=run_url, max_detail=max_detail)
        # KDEC-010: THE CAPABILITY SELECTION CAPS PASS, AND ONLY PASS. The state builder marks a
        # row PASS when the job completed, was applicable and a report arrived; it cannot know
        # whether the scanner could READ the code at its version. resolve established that, and
        # a PASS over a target the scanner cannot read is scanner_state.PARTIAL -- which "MUST NOT
        # be projected, summarised or rounded into PASS". tests/prove_capability_selection.py.
        cap_job = st.get('job') or ''
        if cfg['gate'] == 'PASS' and cap_job:
            if cap_job in capped_jobs:
                cfg['gate'] = 'PARTIAL'
                cfg['fitness'] = ('VERSION_GAP', fitness_note(fitness_notes, cap_job) or
                                  'no carried scanner can read the target version at a root this '
                                  'job was pointed at -- PARTIAL, never PASS (see the resolve job)')
            elif cap_job in not_selected_jobs:
                cfg['gate'] = 'PARTIAL'
                cfg['fitness'] = ('NOT_SELECTED', fitness_note(fitness_notes, cap_job) or
                                  'another carried scanner was selected for a target this one '
                                  'cannot read; it carries the claim (SUBSTITUTION, not equivalence)')
        blocks.append(render(cfg, findings, parse_state, disp, disp_state, examination, today))

        # A STATE FILE THAT DECLARES NEITHER FIELD IS A ROSTER FAULT, not merely a weak row.
        # Degrading the verdict keeps the report honest; the fault is what stops the wiring defect
        # being permanently absorbed by an honest-looking NOT ESTABLISHED row.
        undeclared = [k for k in ('applicability', 'execution') if not st.get(k)]
        if undeclared and not st.get('_missing') and not st.get('_bad_state'):
            faults.append("%r wrote a state file declaring no %s -- a typed result is the one "
                          "thing a scanner job alone can establish, and this one established "
                          "none of it" % (st['scanner'], ' and no '.join(undeclared)))

        established = (parse_state == 'COMPLETE'
                       and cfg['execution'] not in NO_COUNT_STATES
                       and cfg['applicability'] not in NO_COUNT_APPLIC
                       and examination[0] in COUNTABLE_EXAMINATION)
        blk = blocking_of(findings, disp, today)
        job = st.get('job') or ''
        if established and job:
            by_job[job] = by_job.get(job, 0) + len(blk)
        held = len([f for f in findings if is_suppressed(f, disp, today)])
        legacy_closed += len([f for f in findings
                              if disposition_for(f, disp, today)[1] == 'legacy-closed'])
        index.append((cfg['scanner'], cfg['applicability'], cfg['execution'],
                      ('%d' % len(blk)) if established else 'NOT ESTABLISHED',
                      ('%d' % len(findings)) if established else '--',
                      ('%d' % held) if established else '--',
                      cfg['gate']))
        for f in findings:
            observations.append(observation_of(f, job, established))

    # ── THE BASELINE CASCADE (L44/L45), over the observations of this run ─────────────────
    #
    # SECRET FINDINGS ARE LEFT OUT, AND SAID SO. identify() refuses them under
    # SECRET_SUBJECT_NOT_BASELINEABLE because the baseline has no authority over secrets (section
    # 5.7): they block at every rung and are never grandfathered. Handing them to the cascade would
    # read a deliberate refusal as missing evidence and mark every run that found a credential
    # EVIDENCE_UNTRUSTED on the identity claim -- a design fact reported as a collection failure.
    # Every other refusal IS missing evidence, and routes exactly as finding_match says.
    secret_idx = set(i for i, o in enumerate(observations)
                     if o['reason'] == 'SECRET_SUBJECT_NOT_BASELINEABLE')
    cascade_in = [o for i, o in enumerate(observations) if i not in secret_idx]
    ledger_state = (ledger or {}).get('state') if ledger else None
    cascade = finding_match.match(cascade_in, (ledger or {}).get('entries') or [], ledger_state,
                                  environment)
    back = [i for i in range(len(observations)) if i not in secret_idx]
    for f in cascade['findings']:
        o = observations[back[f['index']]]
        o['identity_match'] = f['match']
        o['baseline_state'] = f['baseline_state']
        o['first_seen'] = f.get('first_seen')
        o['baseline_why'] = f['why']
    for i in secret_idx:
        observations[i]['identity_match'] = None
        observations[i]['baseline_state'] = None
        observations[i]['first_seen'] = None
        observations[i]['baseline_why'] = ('a secret finding is outside the baseline by design '
                                           '(section 5.7); it blocks at every rung')
    # THE IDENTITY CLAIM, AS A ROUTING RESULT. EVIDENCE_UNTRUSTED when the ledger could not be
    # used or any identity could not be computed; PROCEED otherwise. It is published beside
    # the blocking count and never folded into it.
    identity_routing = (finding_match.EVIDENCE_UNTRUSTED
                        if cascade['routes_to'] == finding_match.EVIDENCE_UNTRUSTED else 'PROCEED')
    baseline_state = cascade['baseline'] or ledger_state

    # ── CORRELATION (L48), above the observations, never replacing them ───────────────────
    # The old key was (uri, rule_id): the correlation key finding_identity names as valid for one
    # moment and fatal across runs, and it could neither see one advisory at one purl reported
    # under two manifest paths nor refuse two credential scanners agreeing on a line. Only the
    # anchored tier acts; proposals are recorded for a person.
    corr = finding_correlation.correlate(observations)
    for n, cl in enumerate(corr['clusters']):
        for i in cl['members']:
            observations[i]['correlation_tier'] = cl['tier']
            observations[i]['cluster_key'] = cl['cluster_key']
    multi = [cl for cl in corr['clusters']
             if cl['tier'] == finding_correlation.ANCHORED and len(set(cl['scanners'])) > 1]

    # WRITTEN BEFORE THE REPORT IS ASSEMBLED, so a fault below cannot stop it. An absent file
    # means the reporter never got this far, which a consumer must read as unknown, never as
    # "no findings" -- the same rule as the gate's absent count.
    with io.open(findings_out, 'w', encoding='utf-8') as fh:
        json.dump(observations, fh, indent=1, sort_keys=True)
        fh.write('\n')

    L = ['## Security scan report', '',
         '| Scanner | Applicability | Execution | Blocking | Total | Dispositioned | Gate |',
         '|---|---|---|---|---|---|---|']
    for row in index:
        L.append('| %s |' % ' | '.join(row))
    unest = [r[0] for r in index if r[3] == 'NOT ESTABLISHED']
    L.append('')
    if unest:
        L.append('**%d scanner(s) established nothing:** %s' % (len(unest), ', '.join(unest)))
        L.append('')
        L.append('Those rows are not zero. The scope they would have covered is unmeasured, and')
        L.append('the overall result below is only as strong as the scope that was actually read.')
        L.append('')
    # Cross-scanner correlation: one durable identity, or one shared advisory at one locus, seen
    # by more than one tool. Anchored clusters only -- a proposal is a question for a person.
    if multi:
        L.append('**Correlated across scanners:** %d finding(s) reported by more than one tool '
                 '(%s).' % (len(multi), '; '.join('%s: %s' % (cl['anchor'], ', '.join(cl['scanners']))
                                                 for cl in multi[:10])))
        L.append('One condition, several detectors -- triage once, not once per scanner. Every')
        L.append('observation is kept; corroboration is not duplication.')
        L.append('')
    if corr['proposals']:
        L.append('**Proposed correlations (not applied):** %d -- a heuristic agreement for a person '
                 'to confirm or split; each member acts on its own until then.' % len(corr['proposals']))
        L.append('')
    # THE KEY MIGRATION, STATED ON EVERY RUN THAT READS A REGISTER (KDEC-008 OD-6).
    if disp_state == 'LOADED':
        if (today or datetime.date.today()).isoformat() <= legacy_key_window_closes:
            L.append('**Dispositions** are honoured on the durable identity. Legacy-fingerprint keys '
                     'are also honoured until %s (KDEC-008 OD-6); after that they stop suppressing.'
                     % legacy_key_window_closes)
        else:
            L.append('**Dispositions** are honoured on the durable identity only. The legacy-fingerprint '
                     'window closed on %s (KDEC-008 OD-6)%s.'
                     % (legacy_key_window_closes,
                        ': %d finding(s) carry a legacy-keyed disposition that NO LONGER SUPPRESSES; '
                        'each is named in its scanner\'s TRACKING section' % legacy_closed
                        if legacy_closed else ''))
        L.append('')
    # ── BASELINE: the identity claim, separately from the block ───────────────────────────
    L.append('**BASELINE (identity claim)**')
    L.append('')
    L.append('| | |')
    L.append('|---|---|')
    L.append('| Environment | %s |' % (environment or 'NOT DECLARED'))
    L.append('| Ledger | %s |' % (baseline_state or 'NOT READ'))
    L.append('| Rule-family aliases | %s |' % table_note)
    L.append('| Identity routing | %s |' % identity_routing)
    s = cascade['summary']
    L.append('| New / continued / potentially absent / untrusted | %d / %d / %d / %d |'
             % (s['new'], s['continuations'], s['potentially_absent'], s['evidence_untrusted']))
    if secret_idx:
        L.append('| Secret findings | %d outside the baseline by design (section 5.7); never '
                 'grandfathered |' % len(secret_idx))
    L.append('')
    if identity_routing == finding_match.EVIDENCE_UNTRUSTED:
        L.append('The identity claim is **EVIDENCE_UNTRUSTED**: %s.' % cascade['why'])
        L.append('This does not change which findings block. The baseline says which findings are')
        L.append('old; when it cannot say, nothing is grandfathered and nothing is newly blocked.')
        L.append('')
    for n in ((ledger or {}).get('notes') or [])[:6]:
        L.append('- ledger: %s' % n)
    if (ledger or {}).get('notes'):
        L.append('')
    if faults:
        L.append('**SCANNER ROSTER FAULT -- %d.** Every registered scanner must emit exactly one'
                 % len(faults))
        L.append('typed result. These did not, and the table above is therefore reporting on a')
        L.append('denominator it cannot vouch for:')
        L.append('')
        for f in faults:
            L.append('- `%s`' % f)
        L.append('')
    L.append('')
    if summary is not None:
        summary['blocking_findings'] = sum(by_job.values())
        summary['jobs_with_findings'] = sorted(j for j, n in by_job.items() if n > 0)
        summary['findings'] = findings_out
        summary['identity_routing'] = identity_routing
        summary['baseline_state'] = baseline_state or ''
    return ('\n'.join(L) + '\n' + '\n\n'.join(blocks), faults)


def self_test():
    """Every assertion here is a defect this kit has actually shipped at least once."""
    fails = []

    # The examination axis, spelled out at every call site rather than defaulted. `render` has no
    # default for it deliberately -- see its docstring -- and writing it out here is what makes
    # each assertion say which axis it is testing.
    DID_EXAMINE = (EXAMINED, [])
    NOT_RECORDED = (EXAMINATION_NOT_DECLARED, ['no document'])

    # 1. A scanner that did not run must NEVER report 0 findings.
    for applic, execu in (('UNAVAILABLE', 'NOT_RUN'), ('NOT_CONFIGURED', 'NOT_RUN'),
                          ('APPLICABLE', 'COLLECTION_FAILED'), ('APPLICABLE', 'FAILED')):
        cfg = dict(scanner='codeql', applicability=applic, execution=execu, scope='x',
                   artifact='-', upload='-', gate='-', sarif='', run_url='', max_detail=5)
        txt = render(cfg, [], 'ABSENT', {}, 'NOT CONFIGURED', NOT_RECORDED)
        if 'NOT ESTABLISHED' not in txt:
            fails.append('%s/%s did not report NOT ESTABLISHED' % (applic, execu))
        if re.search(r'Findings:\s+\*\*0', txt) or '| Total | 0 |' in txt:
            fails.append('%s/%s reported a zero count' % (applic, execu))

    # 2. Unlicensed capability must not send a developer after it.
    cfg = dict(scanner='codeql', applicability='UNAVAILABLE', execution='NOT_RUN', scope='x',
               artifact='-', upload='-', gate='-', sarif='', run_url='', max_detail=5)
    txt = render(cfg, [], 'ABSENT', {}, 'NOT CONFIGURED', NOT_RECORDED)
    if 'Developer action: **NONE**' not in txt or 'Platform action' not in txt:
        fails.append('unlicensed capability did not separate platform from developer action')

    # 3. A genuinely clean run MAY say none.
    cfg = dict(scanner='trivy', applicability='APPLICABLE', execution='COMPLETE', scope='fs',
               artifact='RETAINED', upload='COMPLETE', gate='PASS', sarif='t.sarif',
               run_url='', max_detail=5)
    txt = render(cfg, [], 'COMPLETE', {}, 'LOADED', DID_EXAMINE)
    if '**NONE** in the scanned scope' not in txt:
        fails.append('clean run did not report NONE')
    if 'NOT ESTABLISHED' in txt:
        fails.append('clean run wrongly reported NOT ESTABLISHED')

    # 3b. A HOLLOW SCAN MUST NOT RENDER THE CLEAN SENTENCE, and the control above is what makes
    # this assertion mean something: a reporter that refused every verdict would satisfy 3b and
    # fail 3, so the pair together prove discrimination rather than blanket refusal.
    #
    # Note the caller's declaration in `cfg` here: APPLICABLE and COMPLETE, unchanged from the
    # clean case. That is exactly what a crashed-but-exited-0 scanner produces, and it is why
    # this axis cannot be sourced from the caller.
    for state, label in ((EXAMINED_NOTHING, 'a scan that examined nothing'),
                         (EXAMINATION_NOT_DECLARED, 'a report recording no examination')):
        hollow = render(cfg, [], 'COMPLETE', {}, 'LOADED', (state, ['the witness, verbatim']))
        if '**NONE** in the scanned scope' in hollow:
            fails.append('%s rendered the CLEAN verdict -- nothing was looked at, printed as '
                         'nothing found' % label)
        if 'NOT ESTABLISHED' not in hollow:
            fails.append('%s did not report NOT ESTABLISHED' % label)
        if re.search(r'\|\s+\*\*Total\*\*\s+\|\s+\*\*0', hollow):
            fails.append('%s rendered a zero total' % label)
        if 'the witness, verbatim' not in hollow:
            fails.append('%s did not print the witness, so a reader cannot tell WHY the scope '
                         'is unmeasured' % label)
    # The axis must be on every row, including the green one. A caveat that appears only when it
    # is bad teaches a reader that its absence means nothing was checked.
    if '| Scan examination | %s |' % EXAMINED not in txt:
        fails.append('a clean row did not state its examination state, so the field is only '
                     'visible when it is bad')
    # An UNRECOGNISED examination state must fail closed. This is the membership-test guarantee:
    # a future value added to the namespace and not to COUNTABLE_EXAMINATION must refuse, not pass.
    rogue = render(cfg, [], 'COMPLETE', {}, 'LOADED', ('SOME_FUTURE_VALUE', []))
    if '**NONE** in the scanned scope' in rogue or 'NOT ESTABLISHED' not in rogue:
        fails.append('an unrecognised examination state was treated as countable -- the check '
                     'must be membership of the allowed set, never inequality with one bad value')

    # 3c. THE FOUR WITNESSES, read from a document rather than handed in. Each is sufficient
    # alone: they describe different ways of reading nothing and do not corroborate each other.
    for doc, want, label in (
        ({'runs': [{'tool': {'driver': {'name': 'x', 'rules': [{'id': 'r'}]}},
                    'invocations': [{'executionSuccessful': False}],
                    'artifacts': [{'location': {'uri': 'a'}}], 'results': []}]},
         EXAMINED_NOTHING, 'executionSuccessful: false'),
        ({'runs': [{'tool': {'driver': {'name': 'x', 'rules': [{'id': 'r'}]}},
                    'invocations': [{'executionSuccessful': True,
                                     'toolExecutionNotifications': [
                                         {'level': 'error',
                                          'message': {'text': 'db download failed'}}]}],
                    'artifacts': [{'location': {'uri': 'a'}}], 'results': []}]},
         EXAMINED_NOTHING, 'an error-level execution notification'),
        # KDEC-008 OD-2: an empty rule set is NOT a witness -- bandit's clean run emits it.
        ({'runs': [{'tool': {'driver': {'name': 'Bandit', 'rules': []}},
                    'invocations': [{'executionSuccessful': True}], 'results': []}]},
         EXAMINED, 'a clean bandit run (an empty rule set)'),
        # ...and bandit's hollow run is caught by what it actually says, in the configuration
        # notification array.
        ({'runs': [{'tool': {'driver': {'name': 'Bandit', 'rules': []}},
                    'invocations': [{'executionSuccessful': True,
                                     'toolConfigurationNotifications': [
                                         {'level': 'error',
                                          'message': {'text': 'syntax error'}}]}],
                    'results': []}]},
         EXAMINED_NOTHING, 'an error-level configuration notification'),
        ({'runs': [{'tool': {'driver': {'name': 'x', 'rules': [{'id': 'r'}]}},
                    'invocations': [{'executionSuccessful': True}],
                    'artifacts': [], 'results': []}]},
         EXAMINED_NOTHING, 'an empty artifact list'),
        ({'runs': []}, EXAMINATION_NOT_DECLARED, 'no runs at all'),
        ({'runs': [{'tool': {'driver': {'name': 'x'}}, 'results': []}]},
         EXAMINATION_NOT_DECLARED, 'a report that records nothing about what it examined'),
        ({'runs': [{'tool': {'driver': {'name': 'x', 'rules': [{'id': 'r'}]}},
                    'invocations': [{'executionSuccessful': True}],
                    'artifacts': [{'location': {'uri': 'a'}}], 'results': []}]},
         EXAMINED, 'a real run that read a file and found nothing'),
        # A FINDING IS PROOF OF READING, and outranks a missing witness. A scanner that reports
        # results while omitting its metadata must not be punished for the omission.
        ({'runs': [{'tool': {'driver': {'name': 'x'}},
                    'results': [{'ruleId': 'r', 'message': {'text': 'm'}}]}]},
         EXAMINED, 'a finding present with no metadata'),
    ):
        got, witnesses = examination_of(doc)
        if got != want:
            fails.append('examination_of(%s) -> %s, expected %s' % (label, got, want))
        if got != EXAMINED and not witnesses:
            fails.append('examination_of(%s) refused with no witness, so the refusal is a shrug'
                         % label)
    # ABSENT IS NOT EMPTY. `rules` and `artifacts` are OPTIONAL in SARIF, so a conforming scanner
    # that omits them must not be read as having loaded none -- that would refuse every finding
    # from several real tools. Only an array PRESENT AND EMPTY is a witness.
    omitted = {'runs': [{'tool': {'driver': {'name': 'x'}},
                         'invocations': [{'executionSuccessful': True}], 'results': []}]}
    if examination_of(omitted)[0] != EXAMINED:
        fails.append('a successful run omitting the optional `rules` and `artifacts` arrays was '
                     'read as having examined nothing -- absent and empty are different facts')

    # 4. Severity derives from security-severity when present, level otherwise.
    rules = {'R1': {'properties': {'security-severity': '9.8'}}}
    if severity_of({'ruleId': 'R1'}, rules) != 'CRITICAL':
        fails.append('security-severity 9.8 not CRITICAL')
    if severity_of({'ruleId': 'R2', 'level': 'error'}, {}) != 'HIGH':
        fails.append('level=error not HIGH')
    if severity_of({'ruleId': 'R3'}, {}) != 'MEDIUM':
        fails.append('unclassified finding was dropped rather than defaulted')

    # 5. Fingerprint is stable across line movement and unstable across real change.
    a = fingerprint('trivy', 'CVE-1', 'a/b.py', 'thing at line 42')
    b = fingerprint('trivy', 'CVE-1', 'a/b.py', 'thing at line 87')
    c = fingerprint('trivy', 'CVE-2', 'a/b.py', 'thing at line 42')
    if a != b:
        fails.append('fingerprint changed when only a line number changed')
    if a == c:
        fails.append('fingerprint collided across different rules')

    # 6. An approved disposition suppresses the block; an expired-but-unrecorded one does not.
    #
    # Records are written TO THE SCHEMA (L49): the claim in disposition_type, the lifecycle in
    # state, every required field present. Keyed on the DURABLE IDENTITY (OD-6), so these
    # assertions do not depend on the legacy-key window still being open.
    def _disp(key, claim='ACCEPTED_RISK', **over):
        d = {'schema_version': 1, 'fingerprint': key, 'scanner': 't', 'rule': 'CVE-1',
             'scope_path': 'a.py', 'disposition_type': claim,
             'rationale': 'Upstream has no patch; the compensating network rule is recorded.',
             'evidence_ref': 'change-record-1', 'approver_role': 'security-lead',
             'created': '2026-01-01', 'expires': '2099-01-01', 'state': 'approved'}
        d.update(over)
        return dict((k, v) for k, v in d.items() if v is not None)

    fs = [{'scanner': 't', 'tool': 't', 'rule': 'CVE-1', 'severity': 'CRITICAL',
           'message': 'm', 'uri': 'a.py', 'line': 1, 'remediation': '', 'fp': 'ff00',
           'identity': 'id00', 'identity_state': 'FINGERPRINTED', 'identity_reason': ''}]
    txt = render(cfg, fs, 'COMPLETE', {'id00': _disp('id00')}, 'LOADED', DID_EXAMINE)
    if 'Blocking findings' in txt:
        fails.append('accepted risk still counted as blocking')
    if '| durable |' not in txt:
        fails.append('the tracking table does not say the approval rode in on the durable key')
    txt = render(cfg, fs, 'COMPLETE', {}, 'LOADED', DID_EXAMINE)
    if 'Blocking findings: **1**' not in txt:
        fails.append('undispositioned critical was not blocking')
    if 'Disposition: NONE' not in txt:
        fails.append('untriaged finding did not say so')

    # 6b. AN EXPIRED ACCEPTANCE MUST BLOCK AGAIN. Silence never renews.
    past = _disp('id00', expires='2020-01-01')
    if not not_suppressed_because(past):
        fails.append('an expired risk acceptance still suppressed')
    if 'EXPIRED' not in not_suppressed_because(past):
        fails.append('expiry was not the stated reason')
    if not_suppressed_because(_disp('id00')):
        fails.append('an unexpired acceptance failed to suppress: %s' % not_suppressed_because(_disp('id00')))
    if not not_suppressed_because(_disp('id00', expires='soon')):
        fails.append('an unparseable expiry was treated as open-ended')
    # 6c. AN UNREGISTERED SYNONYM MUST NOT SUPPRESS. The taxonomy says ACCEPTED_RISK; this file
    # once said RISK_ACCEPTED, and a third spelling (RISK_ACCEPTANCE) was in circulation.
    for synonym in ('RISK_ACCEPTED', 'RISK_ACCEPTANCE', 'accepted_risk'):
        if not not_suppressed_because(_disp('id00', claim=synonym)):
            fails.append('unregistered disposition spelling %s suppressed a finding' % synonym)
    # 6d. THE SCHEMA IS THE CONTRACT (L49). The claim lives in disposition_type; only state
    # `approved` suppresses; an absent expiry is invalid, not open-ended; the conditional
    # fields are required by claim.
    for label, rec in (('claim written in state (legacy shape)',
                        {'state': 'ACCEPTED_RISK', 'expires': '2099-01-01', 'approved_by': 'x'}),
                       ('state proposed', _disp('id00', state='proposed')),
                       ('state absent', _disp('id00', state=None)),
                       ('no expires', _disp('id00', expires=None)),
                       ('no approver_role', _disp('id00', approver_role=None)),
                       ('MITIGATED without a control', _disp('id00', claim='MITIGATED')),
                       ('ACCEPTED_RISK without evidence', _disp('id00', evidence_ref=None))):
        if not not_suppressed_because(rec):
            fails.append('%s suppressed a finding' % label)
    if 'disposition_type' not in not_suppressed_because({'state': 'ACCEPTED_RISK'}):
        fails.append('the legacy-shape refusal does not name the field to migrate to')
    # 6e. THE KEY MIGRATION (OD-6). Legacy inside the window suppresses; after it, it does not,
    # and the basis says which; the durable key wins whenever present.
    inside = datetime.date(*[int(x) for x in legacy_key_window_opened.split('-')])
    after = datetime.date(*[int(x) for x in legacy_key_window_closes.split('-')]) + datetime.timedelta(days=1)
    if not is_suppressed(fs[0], {'ff00': _disp('ff00')}, inside):
        fails.append('a legacy-keyed approval was refused inside the window')
    if disposition_for(fs[0], {'ff00': _disp('ff00')}, inside)[1] != 'legacy':
        fails.append('the legacy basis was not reported')
    if is_suppressed(fs[0], {'ff00': _disp('ff00')}, after):
        fails.append('a legacy-keyed approval still suppressed after the window closed')
    rec, basis, note = disposition_for(fs[0], {'ff00': _disp('ff00')}, after)
    if rec is not None or basis != 'legacy-closed' or 'ff00' not in note or 'id00' not in note:
        fails.append('after the window the run does not name the orphaned key and the identity to re-key to')
    if disposition_for(fs[0], {'ff00': _disp('ff00'), 'id00': _disp('id00')}, inside)[1] != 'durable':
        fails.append('with both keys present the durable one did not win')
    if not is_suppressed(fs[0], {'id00': _disp('id00')}, after):
        fails.append('the durable key stopped suppressing after the window')

    # 7. Unparseable output is not a clean result.
    txt = render(cfg, [], 'UNPARSEABLE', {}, 'LOADED', NOT_RECORDED)
    if 'NOT ESTABLISHED' not in txt or 'INVALID' not in txt:
        fails.append('unparseable SARIF read as a clean result')

    # 8. Batch: an expected scanner that dropped no state file must still appear, as NOT_RUN.
    import tempfile
    td = tempfile.mkdtemp()
    io.open(os.path.join(td, 'trivy.json'), 'w', encoding='utf-8').write(json.dumps(
        {'scanner': 'trivy', 'applicability': 'APPLICABLE', 'execution': 'COMPLETE',
         'sarif': '', 'gate': 'PASS'}))
    txt, faults = batch(td, '', 5, '', ['trivy', 'codeql'])
    if '| codeql |' not in txt:
        fails.append('an expected scanner that wrote no state file vanished from the report')
    if 'NOT_RUN' not in txt:
        fails.append('a missing scanner was not reported as NOT_RUN')

    # 8b. EXACTLY ONE TYPED RESULT PER REGISTERED SCANNER, and the check must name the scanner.
    # Rendering the missing row is not the same as reporting that the roster is broken: the row
    # says "this did not run today", the fault says "this is wired to nothing".
    if not any(f.startswith("no result for 'codeql'") for f in faults):
        fails.append('a roster entry that nothing writes was not reported as a fault')
    if any(f.startswith("no result for 'trivy'") for f in faults):
        fails.append('a scanner that DID write its state was reported missing')
    dup = tempfile.mkdtemp()
    io.open(os.path.join(dup, 'a.json'), 'w', encoding='utf-8').write(json.dumps(
        {'scanner': 'trivy', 'applicability': 'APPLICABLE', 'execution': 'COMPLETE',
         'sarif': '', 'gate': 'PASS'}))
    io.open(os.path.join(dup, 'b.json'), 'w', encoding='utf-8').write(json.dumps(
        {'scanner': 'trivy', 'applicability': 'APPLICABLE', 'execution': 'FAILED',
         'sarif': '', 'gate': 'UNDETERMINED'}))
    _t, dfaults = batch(dup, '', 5, '', ['trivy'])
    if not any(f.startswith("two results for 'trivy'") for f in dfaults):
        fails.append('two states sharing one scanner id passed silently -- one verdict erases '
                     'the other and the erased one may be the FINDINGS')
    # A clean roster must produce NO faults, or the check is unfalsifiable.
    _t, cfaults = batch(td, '', 5, '', ['trivy'])
    if cfaults:
        fails.append('a complete roster reported faults: %s' % cfaults)

    # 8d. A STATE FILE THAT DECLARES NOTHING MUST NOT RENDER A CLEAN ROW.
    #
    # This is the wiring half of the hollow-scan defect and it needs no scanner failure at all.
    # `batch()` substituted APPLICABLE and COMPLETE for any absent field, so a state file naming
    # only a scanner and a SARIF produced `| trivy | APPLICABLE | COMPLETE | 0 | 0 | 0 |` -- the
    # strongest row in the table, from a job that established nothing. It is also the shape a
    # consumer wiring their own job is most likely to produce.
    bare = tempfile.mkdtemp()
    io.open(os.path.join(bare, 'trivy.json'), 'w', encoding='utf-8').write(json.dumps(
        {'scanner': 'trivy', 'sarif': 'nothing.sarif'}))
    btxt, bfaults = batch(bare, '', 5, '', ['trivy'])
    if '| trivy | APPLICABLE | COMPLETE |' in btxt:
        fails.append('a state file declaring neither applicability nor execution was rendered as '
                     'APPLICABLE/COMPLETE -- an omission produced the strongest claim available')
    if ' | 0 | 0 | ' in btxt:
        fails.append('a state file declaring nothing rendered a zero count')
    if 'NOT ESTABLISHED' not in btxt:
        fails.append('a state file declaring nothing did not report NOT ESTABLISHED')
    if not any('declaring no applicability' in f for f in bfaults):
        fails.append('a state file declaring no typed result was not reported as a roster fault, '
                     'so the wiring defect would be absorbed by an honest-looking row')

    # 8c. COVERAGE_GAP MUST NOT RENDER A COUNT. The artefact is present and nothing looked; a
    # zero beside it would be a count of what nobody collected.
    gap = render(dict(scanner='trivy-image', applicability='COVERAGE_GAP', execution='COMPLETE',
                      scope='img', artifact='NONE', upload='NONE', gate='UNDETERMINED',
                      sarif='', run_url='', max_detail=5), [], 'ABSENT', {}, 'ABSENT',
                 NOT_RECORDED)
    if 'NOT ESTABLISHED' not in gap:
        fails.append('COVERAGE_GAP rendered as an established result')
    # and it must not be able to claim zero findings
    codeql_block = txt.split('### codeql')[-1] if '### codeql' in txt else ''
    if 'NOT ESTABLISHED' not in codeql_block:
        fails.append('a scanner that never ran did not report NOT ESTABLISHED in batch mode')

    # 8e. KDEC-010: A ROW THE CAPABILITY SELECTION CAPPED RENDERS PARTIAL, NEVER PASS. The state
    # builder marks a completed, applicable, reported row PASS; it cannot know the scanner could
    # not READ the code at its version. The resolver can, and its lists cap PASS -- only PASS.
    capd = tempfile.mkdtemp()
    io.open(os.path.join(capd, 'cv.sarif'), 'w', encoding='utf-8').write(json.dumps(
        {'version': '2.1.0', 'runs': [{'tool': {'driver': {'name': 'checkov', 'rules': [{'id': 'CKV'}]}},
                                       'invocations': [{'executionSuccessful': True}], 'results': []}]}))
    io.open(os.path.join(capd, 'cv.json'), 'w', encoding='utf-8').write(json.dumps(
        {'scanner': 'checkov', 'applicability': 'APPLICABLE', 'execution': 'COMPLETE',
         'sarif': 'cv.sarif', 'gate': 'PASS', 'job': 'iac-scan'}))
    ptxt, _ = batch(capd, '', 5, '', ['checkov'])
    if '| Gate state | PASS |' not in ptxt.split('### checkov')[-1]:
        fails.append('the control: an uncapped clean row did not render PASS, so the cap check '
                     'below proves nothing')
    ctxt, _ = batch(capd, '', 5, '', ['checkov'], capped_jobs=['iac-scan'],
                    fitness_notes='iac-scan: VERSION_GAP iac@infra -- PARTIAL, never PASS; closes: '
                                  'scanner-registry.yaml version_support iac-scan/checkov')
    cblock = ctxt.split('### checkov')[-1]
    if '| Gate state | PARTIAL |' not in cblock or 'PASS' in cblock.replace('never PASS', '') \
            or 'VERSION_GAP' not in cblock or 'scanner-registry.yaml' not in cblock:
        fails.append('a row the capability selection capped rendered PASS, or without the gap '
                     'and the row that closes it (KDEC-010)')

    # 8a. NO CREDENTIAL MAY REACH RENDERED OUTPUT. Fake values, real shapes.
    SECRETS = [
        ('AKIAIOSFODNN7EXAMPLE', 'aws-access-key-id'),
        ('ghp_16CharsAndMoreHere0123456789abcd', 'github-token'),
        ('eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dBjftJeZ4CVPmB92K27uhbUJU1p1r',
         'jwt'),
        ('abc8Q~xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx', 'entra-client-secret'),
        ('-----BEGIN RSA PRIVATE KEY-----', 'private-key'),
        ('AccountKey=aGVsbG93b3JsZGhlbGxvd29ybGRoZWxsb3dvcmxkaGVsbG93b3JsZA==',
         'keyed-value'),
        ('password=SuperSecret123!', 'keyed-value'),
    ]
    for raw, _label in SECRETS:
        r = redact(raw)
        if raw in r:
            fails.append('redact() left %s... intact' % raw[:8])
        if not raw.startswith('-----') and raw[:4] not in r:
            fails.append('redact() dropped the identifying prefix of %s...' % raw[:8])

    # and end to end, through a real SARIF into the rendered report
    io.open(os.path.join(td, 'sec.sarif'), 'w', encoding='utf-8').write(json.dumps(
        {'version': '2.1.0', 'runs': [{'tool': {'driver': {'name': 'secretscan'}}, 'results': [
            {'ruleId': 'leaked-key', 'level': 'error',
             'message': {'text': 'Found AWS key AKIAIOSFODNN7EXAMPLE in config'},
             'locations': [{'physicalLocation': {
                 'artifactLocation': {'uri': 'infra/main.tf'},
                 'region': {'startLine': 42,
                            'snippet': {'text': 'key = AKIAIOSFODNN7EXAMPLE'}}}}]}]}]}))
    io.open(os.path.join(td, 'sec.json'), 'w', encoding='utf-8').write(json.dumps(
        {'scanner': 'secretscan', 'applicability': 'APPLICABLE', 'execution': 'COMPLETE',
         'sarif': 'sec.sarif', 'gate': 'FAIL'}))
    rep, _f = batch(td, '', 5, '', [])
    if 'AKIAIOSFODNN7EXAMPLE' in rep:
        fails.append('a live-shaped credential reached the rendered report')
    if 'infra/main.tf' not in rep or '42' not in rep:
        fails.append('redaction destroyed the file/line a reader needs to act')
    if 'AKIA' not in rep:
        fails.append('redaction removed the prefix that identifies WHICH credential')

    # 8b. The summary table and the detail section must report the SAME blocking count.
    io.open(os.path.join(td, 'acc.sarif'), 'w', encoding='utf-8').write(json.dumps(
        {'version': '2.1.0', 'runs': [{'tool': {'driver': {'name': 'T'}}, 'results': [
            {'ruleId': 'X1', 'level': 'error', 'message': {'text': 'one'},
             'locations': [{'physicalLocation': {'artifactLocation': {'uri': 'a.py'}}}]},
            {'ruleId': 'X2', 'level': 'error', 'message': {'text': 'two'},
             'locations': [{'physicalLocation': {'artifactLocation': {'uri': 'b.py'}}}]}]}]}))
    io.open(os.path.join(td, 'acc.json'), 'w', encoding='utf-8').write(json.dumps(
        {'scanner': 'acc', 'applicability': 'APPLICABLE', 'execution': 'COMPLETE',
         'sarif': 'acc.sarif', 'gate': 'FAIL'}))
    # These findings carry no durable identity (a bare rule id, no CWE), so the only key a
    # disposition can use is the legacy fingerprint -- which is exactly the window case. Run
    # with a date INSIDE the window, and once more after it to see the approval lapse.
    fp1 = fingerprint('acc', 'X1', 'a.py', 'one')
    io.open(os.path.join(td, 'd.json'), 'w', encoding='utf-8').write(json.dumps(
        {'dispositions': {fp1: _disp(fp1)}}))
    txt, _f = batch(td, os.path.join(td, 'd.json'), 5, '', [], today=inside)
    row = [ln for ln in txt.splitlines() if ln.startswith('| acc |')]
    detail = txt.split('### acc')[-1]
    if not row:
        fails.append('batch summary lost a scanner row')
    elif '| 1 | 2 | 1 |' not in row[0]:
        fails.append('summary row did not report 1 blocking / 2 total / 1 dispositioned: %s'
                     % row[0])
    if 'Blocking findings: **1**' not in detail:
        fails.append('detail section disagreed with the summary table on blocking count')
    if legacy_key_window_closes not in txt:
        fails.append('a run inside the window does not say until when legacy keys are honoured')
    txt, _f = batch(td, os.path.join(td, 'd.json'), 5, '', [], today=after)
    row = [ln for ln in txt.splitlines() if ln.startswith('| acc |')]
    if not row or '| 2 | 2 | 0 |' not in row[0]:
        fails.append('after the window a legacy-keyed approval still counted as dispositioned: %s'
                     % (row and row[0]))
    if 'NO LONGER SUPPRESSES' not in txt or fp1 not in txt:
        fails.append('after the window the run does not name the legacy key that stopped suppressing')

    # 9. Batch: a corrupt state file is a collection failure, not an omission.
    io.open(os.path.join(td, 'semgrep.json'), 'w', encoding='utf-8').write('{ not json')
    txt, _f = batch(td, '', 5, '', [])
    if '### semgrep' not in txt or 'NOT ESTABLISHED' not in txt.split('### semgrep')[-1]:
        fails.append('a corrupt state file was dropped instead of reported')

    # 9b. A MALFORMED SARIF IS UNPARSEABLE, NEVER A TRACEBACK AND NEVER A FINDING (L06). Valid
    # JSON that is not SARIF-shaped is the fourth parse state, and it is declared.
    for label, doc in (('runs that are not objects', {'runs': ['a-string']}),
                       ('fields of the wrong type', {'runs': [{'tool': 'x', 'results': [
                           {'ruleId': 5, 'message': 'm', 'locations': 'nope'}]}]}),
                       ('a top-level list', [1, 2])):
        mp = os.path.join(td, 'malformed.sarif')
        io.open(mp, 'w', encoding='utf-8').write(json.dumps(doc))
        try:
            got, ps, (es, witnesses) = parse_sarif(mp, 'x')
        except Exception as exc:  # noqa: BLE001
            fails.append('%s RAISED %s out of parse_sarif' % (label, type(exc).__name__))
            continue
        if ps != 'UNPARSEABLE' or got or not witnesses:
            fails.append('%s was not UNPARSEABLE with a witness (%s, %d findings)' % (label, ps, len(got)))

    if fails:
        print('SELF-TEST FAILED:')
        for f in fails:
            print('  - %s' % f)
        return False
    print('self-test ok: a scanner that did not run reports NOT ESTABLISHED and can never report 0;')
    print('              platform action is separated from developer action;')
    print('              fingerprints survive line movement; unparseable output is not clean;')
    print('              a scan that examined nothing is NOT ESTABLISHED and prints its witness,')
    print('              a genuinely clean run can still say NONE, an unrecognised examination')
    print('              state fails closed, and a state file declaring nothing is a roster fault')
    return True


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--scanner')
    ap.add_argument('--sarif', default='')
    # THE WEAKEST VALUE IN EACH NAMESPACE IS THE DEFAULT. These were APPLICABLE and COMPLETE, so
    # omitting an argument produced a stronger claim than any argument could have supplied.
    # UNKNOWN's own taxonomy entry says "Run anyway and say so; never report a clean result";
    # NOT_DECLARED is registered for exactly this position.
    ap.add_argument('--applicability', default='UNKNOWN',
                    choices=['APPLICABLE', 'NOT_APPLICABLE', 'UNAVAILABLE', 'NOT_CONFIGURED'])
    ap.add_argument('--execution', default='NOT_DECLARED',
                    choices=['COMPLETE', 'FAILED', 'COLLECTION_FAILED', 'NOT_RUN'])
    ap.add_argument('--scope', default='')
    ap.add_argument('--artifact', default='UNKNOWN')
    ap.add_argument('--upload', default='UNKNOWN')
    ap.add_argument('--gate', default='UNDETERMINED')
    ap.add_argument('--dispositions', default='')
    ap.add_argument('--max-detail', type=int, default=20)
    ap.add_argument('--run-url', default=os.environ.get('RUN_URL', ''))
    ap.add_argument('--out', default=os.environ.get('GITHUB_STEP_SUMMARY', ''))
    ap.add_argument('--batch', default='',
                    help='directory of per-scanner state JSON files; render all of them')
    ap.add_argument('--expect', default='',
                    help='comma-separated scanners that MUST appear; any that dropped no state '
                         'file is rendered as NOT_RUN rather than silently omitted')
    ap.add_argument('--findings-out', default='',
                    help='where the machine-readable findings file goes (L52); default '
                         '<batch dir>/%s' % findings_filename)
    ap.add_argument('--ledger', default='',
                    help='the JSON baseline_ledger.py --out wrote for this run (L45). Absent '
                         'means no ledger was read: BASELINE_UNAVAILABLE, never empty')
    ap.add_argument('--environment', default='',
                    help='the (repository, environment) cell the ledger is keyed by. No default: '
                         'without it nothing can be grandfathered')
    ap.add_argument('--rule-families', default='',
                    help='the rule-family alias table read from the protected branch (L46)')
    # KDEC-010: the capability selection, as the resolve job publishes it.
    ap.add_argument('--capped-jobs', default='',
                    help='space-separated jobs pointed at a VERSION_GAP no carried scanner can '
                         'read; their PASS renders PARTIAL, never PASS')
    ap.add_argument('--not-selected-jobs', default='',
                    help='space-separated jobs not selected for a target another scanner serves; '
                         'their PASS renders PARTIAL, labelled as a substitution')
    ap.add_argument('--fitness-notes', default='',
                    help='the resolver\'s " ; "-separated notes, one per capped or not-selected job')
    ap.add_argument('--self-test', action='store_true')
    a = ap.parse_args()

    if a.self_test:
        return 0 if self_test() else 2
    if not self_test():
        print('ABORTING -- a reporter that can fabricate a zero is worse than no reporter.')
        return 2

    if a.batch:
        summary = {}
        text, faults = batch(a.batch, a.dispositions, a.max_detail, a.run_url,
                             [x.strip() for x in a.expect.split(',') if x.strip()], summary,
                             findings_out=a.findings_out, ledger=load_ledger(a.ledger),
                             environment=a.environment, rule_families=a.rule_families,
                             capped_jobs=a.capped_jobs.split(),
                             not_selected_jobs=a.not_selected_jobs.split(),
                             fitness_notes=a.fitness_notes)
        print(text)
        # PUBLISHED FOR THE GATE, BEFORE ANY FAULT EXIT. A roster fault fails this job below, and
        # the gate already reads that; the counts it can vouch for are still the evidence it has.
        gh_out = os.environ.get('GITHUB_OUTPUT', '')
        if gh_out:
            with io.open(gh_out, 'a', encoding='utf-8') as fh:
                fh.write('blocking_findings=%d\n' % summary.get('blocking_findings', 0))
                fh.write('jobs_with_findings=%s\n'
                         % ' '.join(summary.get('jobs_with_findings', [])))
                fh.write('findings=%s\n' % summary.get('findings', ''))
                # THE IDENTITY CLAIM, beside the block and never inside it (L44/L45).
                fh.write('identity_routing=%s\n' % summary.get('identity_routing', ''))
                fh.write('baseline_state=%s\n' % summary.get('baseline_state', ''))
        if a.out:
            with io.open(a.out, 'a', encoding='utf-8') as fh:
                fh.write(text + '\n\n')
        if faults:
            # THE REPORT IS STILL WRITTEN, AND THEN THIS FAILS.
            #
            # Rendering first is deliberate: a roster fault is a defect in the PIPELINE, and
            # suppressing the evidence because the evidence is incomplete is how a partial
            # result becomes no result. Failing afterwards is equally deliberate -- the gate
            # reads this job's conclusion, so a roster the reporter cannot vouch for surfaces
            # as UNDETERMINED rather than as a table somebody reads as complete.
            for f in faults:
                print('::error title=Scanner roster fault::%s' % f)
            print('EXACTLY ONE TYPED RESULT PER REGISTERED SCANNER. %d fault(s) above.'
                  % len(faults))
            return 3
        return 0

    if not a.scanner:
        print('--scanner or --batch is required')
        return 2

    findings, parse_state, examination = parse_sarif(a.sarif, a.scanner)
    disp, disp_state = load_dispositions(a.dispositions)
    cfg = dict(scanner=a.scanner, applicability=a.applicability, execution=a.execution,
               scope=a.scope, artifact=a.artifact, upload=a.upload, gate=a.gate,
               sarif=a.sarif, run_url=a.run_url, max_detail=a.max_detail)
    text = render(cfg, findings, parse_state, disp, disp_state, examination)

    # Both destinations, deliberately. The step summary is where a reviewer looks; the run log is
    # where an engineer already is when the job goes red.
    print(text)
    if a.out:
        with io.open(a.out, 'a', encoding='utf-8') as fh:
            fh.write(text + '\n\n')
    return 0


if __name__ == '__main__':
    sys.exit(main())

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

SEV_ORDER = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFORMATIONAL']
BLOCKING = ('CRITICAL', 'HIGH')

# A scanner that did not produce a trustworthy result must not be able to report a count.
# These are the states where "0 findings" would be a lie, not a measurement.
NO_COUNT_STATES = ('NOT_RUN', 'FAILED', 'COLLECTION_FAILED')
NO_COUNT_APPLIC = ('UNAVAILABLE', 'NOT_CONFIGURED', 'NOT_APPLICABLE')


# ─────────────────────────────────────────────────────────────────────────────
# REDACTION. Applied to every string this file prints, without exception.
# ─────────────────────────────────────────────────────────────────────────────
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


def parse_sarif(path, scanner):
    """-> (findings, parse_state). parse_state is COMPLETE, ABSENT or UNPARSEABLE.

    UNPARSEABLE is not zero findings. It is a collection failure wearing a report's clothes.
    """
    if not path or not os.path.exists(path) or os.path.getsize(path) == 0:
        return ([], 'ABSENT')
    try:
        doc = json.load(io.open(path, encoding='utf-8', errors='replace'))
    except (ValueError, IOError):
        return ([], 'UNPARSEABLE')
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
        for res in (run.get('results') or []):
            rid = res.get('ruleId') or ''
            msg = ((res.get('message') or {}).get('text') or '').strip()
            uri, line = location_of(res)
            # REDACTED AT CONSTRUCTION, NOT AT PRINT TIME. There are four places a finding's
            # text reaches output; guarding each one is how one of them eventually gets missed.
            # The fingerprint is computed from the RAW message so identity survives redaction --
            # it is a hash, and it never reaches a reader.
            out.append({
                'scanner': scanner, 'tool': tool, 'rule': redact(rid),
                'severity': severity_of(res, rules),
                'message': redact(msg), 'uri': uri, 'line': line,
                'remediation': redact(remediation_of(res, rules)),
                'fp': fingerprint(scanner, rid, uri, msg),
            })
    return (out, 'COMPLETE')


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
    return (d if isinstance(d, dict) else {}, 'LOADED')


# THE REGISTERED disposition_type VOCABULARY, not a paraphrase of it.
#
# This said RISK_ACCEPTED. assurance-taxonomy.yaml says ACCEPTED_RISK. Same concept, reversed,
# and the reporter suppressed only on ITS spelling -- so a disposition written to the registered
# schema would have suppressed nothing and the gate would have blocked an approved exception
# forever, with no error anywhere. A third spelling (RISK_ACCEPTANCE) was in circulation in
# conversation. One truth, three names.
SUPPRESSING = ('FALSE_POSITIVE', 'ACCEPTED_RISK', 'MITIGATED', 'REMEDIATED')


def not_suppressed_because(d, today=None):
    """-> the reason this disposition does NOT suppress, or '' when it DOES.

    Named for what it returns. `suppressed_by()` returning a reason it is NOT suppressed reads
    exactly backwards at the call site, which is how an inverted condition survives review.

    EXPIRY IS ENFORCED, NOT DISPLAYED. The registered model says
    `approved -> expired (automatic; silence NEVER renews)`. Showing an expiry date while still
    honouring a lapsed acceptance is how a 90-day risk acceptance becomes permanent: nobody
    revisits it, because nothing ever went red again.
    """
    state = (d or {}).get('state')
    if state not in SUPPRESSING:
        return 'state %s is not an approved disposition' % (state or 'NONE')
    exp = (d or {}).get('expires')
    if exp:
        try:
            when = datetime.date(*[int(x) for x in str(exp)[:10].split('-')])
        except (ValueError, TypeError):
            return 'expiry %r is unparseable -- an unreadable expiry is not an open-ended one' % exp
        if when < (today or datetime.date.today()):
            return 'EXPIRED %s' % exp
    return ''


def blocking_of(findings, disp):
    """THE definition of a blocking finding. Called by both the summary table and the detail
    section, because computing it twice is how a report comes to disagree with itself -- the
    table saying 2 while the list beneath it shows 1, and a reader trusting whichever they read
    first. One truth, one function."""
    return [f for f in findings
            if f['severity'] in BLOCKING and not_suppressed_because(disp.get(f['fp']))]


def counts_of(findings):
    c = dict((s, 0) for s in SEV_ORDER)
    for f in findings:
        c[f['severity']] = c.get(f['severity'], 0) + 1
    return c


def render(cfg, findings, parse_state, disp, disp_state):
    """The five sections. Written once so sixteen scanners cannot invent sixteen dialects."""
    L = []
    add = L.append
    scanner = cfg['scanner']
    applic = cfg['applicability']
    execu = cfg['execution']

    established = (parse_state == 'COMPLETE'
                   and execu not in NO_COUNT_STATES
                   and applic not in NO_COUNT_APPLIC)

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
               }.get(applic, '')
        if not why:
            why = {'COLLECTION_FAILED': 'the scanner ran and produced no usable report',
                   'FAILED': 'the scanner did not complete',
                   'NOT_RUN': 'the scanner did not run',
                   }.get(execu, 'the report could not be parsed')
        add('Findings: **NOT ESTABLISHED** -- %s.' % why)
        add('')
        add('This is not zero. Nothing looked at this scope, so no statement about it is')
        add('supported by this run.')
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
    add('| Artifact | %s |' % cfg['artifact'])
    add('| GitHub Security upload | %s |' % cfg['upload'])
    add('| Gate state | %s |' % cfg['gate'])
    add('| Disposition register | %s |' % disp_state)
    add('')

    # ---- ACTION REQUIRED ----------------------------------------------------
    blocking = blocking_of(findings, disp)
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
            d = disp.get(f['fp']) or {}
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
            add('   - Tracking: %s' % (d.get('ticket') or 'NOT CREATED'))
            why = not_suppressed_because(d) if d else 'no disposition recorded'
            add('   - Disposition: %s%s' % ((d.get('state') or 'NONE'),
                                            '' if not d else ('  (%s)' % why if why else
                                                              '  -- honoured')))
            if d.get('expires'):
                add('   - Expires: %s%s' % (d['expires'],
                                            '  -- LAPSED, no longer suppressing'
                                            if why.startswith('EXPIRED') else
                                            '  -- revalidate before expiry'))
            add('   - Fingerprint: `%s`' % f['fp'])
        if len(blocking) > cfg['max_detail']:
            add('')
            add('_%d further blocking findings not listed here; all %d are in the artifact._'
                % (len(blocking) - cfg['max_detail'], len(blocking)))
        add('')
        add('**NEXT STEP** -- resolve the %d blocking finding(s), or submit an approved disposition'
            % len(blocking))
        add('(false positive, mitigation, risk acceptance, deferral) referencing the fingerprint.')
    add('')

    # ---- TRACKING / DISPOSITION --------------------------------------------
    if established and findings:
        held = [f for f in findings if f['fp'] in disp]
        add('**TRACKING / DISPOSITION**')
        add('')
        if disp_state == 'NOT CONFIGURED':
            add('No disposition register configured. Every finding above is untriaged by')
            add('definition -- an accepted risk that is not recorded is indistinguishable from')
            add('one nobody noticed.')
        elif not held:
            add('%d finding(s), none carrying a recorded disposition.' % len(findings))
        else:
            add('| Fingerprint | Disposition | Approved by | Expires |')
            add('|---|---|---|---|')
            for f in held[:cfg['max_detail']]:
                d = disp[f['fp']]
                add('| `%s` | %s | %s | %s |'
                    % (f['fp'], d.get('state', '?'), d.get('approved_by', '--'),
                       d.get('expires', '--')))
        add('')

    # ---- DETAILS / EVIDENCE -------------------------------------------------
    add('**DETAILS / EVIDENCE**')
    add('')
    add('- Artifact: %s' % (cfg['sarif'] or 'none'))
    add('- GitHub Security: %s' % cfg['upload'])
    if cfg['run_url']:
        add('- Run: %s' % cfg['run_url'])
    return '\n'.join(L)


def batch(state_dir, disp_path, max_detail, run_url, expect=()):
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
    """
    states = []
    for fn in sorted(os.listdir(state_dir)) if os.path.isdir(state_dir) else []:
        if not fn.endswith('.json') or fn.startswith('.'):
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

    # A SCANNER THAT WAS EXPECTED AND DROPPED NO STATE FILE MUST APPEAR AS A ROW.
    # An absent row reads as "not applicable" to every human who has ever read a report, so a
    # job that died before writing its state would silently shrink the denominator -- the same
    # defect as a coverage figure whose denominator quietly excludes a modality (LM-015).
    present = set(st.get('scanner') for st in states)
    for name in expect:
        if name and name not in present:
            states.append({'scanner': name, 'applicability': 'APPLICABLE',
                           'execution': 'NOT_RUN', 'scope': '', 'artifact': 'NONE',
                           'upload': 'NONE', 'gate': 'UNDETERMINED', 'sarif': '',
                           '_missing': True})

    disp, disp_state = load_dispositions(disp_path)
    blocks, index, seen = [], [], {}
    for st in states:
        sarif = st.get('sarif') or ''
        if sarif and not os.path.isabs(sarif):
            cand = os.path.join(state_dir, sarif)
            sarif = cand if os.path.exists(cand) else sarif
        findings, parse_state = parse_sarif(sarif, st['scanner'])
        if st.get('_bad_state'):
            parse_state = 'UNPARSEABLE'
        cfg = dict(scanner=st['scanner'],
                   applicability=st.get('applicability', 'APPLICABLE'),
                   execution=st.get('execution', 'COMPLETE'),
                   scope=st.get('scope', ''), artifact=st.get('artifact', 'UNKNOWN'),
                   upload=st.get('upload', 'UNKNOWN'), gate=st.get('gate', 'UNDETERMINED'),
                   sarif=sarif, run_url=run_url, max_detail=max_detail)
        blocks.append(render(cfg, findings, parse_state, disp, disp_state))

        established = (parse_state == 'COMPLETE'
                       and cfg['execution'] not in NO_COUNT_STATES
                       and cfg['applicability'] not in NO_COUNT_APPLIC)
        blk = blocking_of(findings, disp)
        held = len([f for f in findings
                    if f['fp'] in disp and not not_suppressed_because(disp[f['fp']])])
        index.append((cfg['scanner'], cfg['applicability'], cfg['execution'],
                      ('%d' % len(blk)) if established else 'NOT ESTABLISHED',
                      ('%d' % len(findings)) if established else '--',
                      ('%d' % held) if established else '--',
                      cfg['gate']))
        for f in findings:
            key = (f['uri'], f['rule'])
            seen.setdefault(key, []).append(f['scanner'])

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
    # Cross-scanner correlation: the same location and rule seen by more than one tool.
    dupes = dict((k, v) for k, v in seen.items() if len(set(v)) > 1)
    if dupes:
        L.append('**Correlated across scanners:** %d finding(s) reported by more than one tool.'
                 % len(dupes))
        L.append('One condition, several detectors -- triage once, not once per scanner.')
        L.append('')
    L.append('')
    return '\n'.join(L) + '\n' + '\n\n'.join(blocks)


def self_test():
    """Every assertion here is a defect this kit has actually shipped at least once."""
    fails = []

    # 1. A scanner that did not run must NEVER report 0 findings.
    for applic, execu in (('UNAVAILABLE', 'NOT_RUN'), ('NOT_CONFIGURED', 'NOT_RUN'),
                          ('APPLICABLE', 'COLLECTION_FAILED'), ('APPLICABLE', 'FAILED')):
        cfg = dict(scanner='codeql', applicability=applic, execution=execu, scope='x',
                   artifact='-', upload='-', gate='-', sarif='', run_url='', max_detail=5)
        txt = render(cfg, [], 'ABSENT', {}, 'NOT CONFIGURED')
        if 'NOT ESTABLISHED' not in txt:
            fails.append('%s/%s did not report NOT ESTABLISHED' % (applic, execu))
        if re.search(r'Findings:\s+\*\*0', txt) or '| Total | 0 |' in txt:
            fails.append('%s/%s reported a zero count' % (applic, execu))

    # 2. Unlicensed capability must not send a developer after it.
    cfg = dict(scanner='codeql', applicability='UNAVAILABLE', execution='NOT_RUN', scope='x',
               artifact='-', upload='-', gate='-', sarif='', run_url='', max_detail=5)
    txt = render(cfg, [], 'ABSENT', {}, 'NOT CONFIGURED')
    if 'Developer action: **NONE**' not in txt or 'Platform action' not in txt:
        fails.append('unlicensed capability did not separate platform from developer action')

    # 3. A genuinely clean run MAY say none.
    cfg = dict(scanner='trivy', applicability='APPLICABLE', execution='COMPLETE', scope='fs',
               artifact='RETAINED', upload='COMPLETE', gate='PASS', sarif='t.sarif',
               run_url='', max_detail=5)
    txt = render(cfg, [], 'COMPLETE', {}, 'LOADED')
    if '**NONE** in the scanned scope' not in txt:
        fails.append('clean run did not report NONE')
    if 'NOT ESTABLISHED' in txt:
        fails.append('clean run wrongly reported NOT ESTABLISHED')

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
    fs = [{'scanner': 't', 'tool': 't', 'rule': 'CVE-1', 'severity': 'CRITICAL',
           'message': 'm', 'uri': 'a.py', 'line': 1, 'remediation': '', 'fp': 'ff00'}]
    txt = render(cfg, fs, 'COMPLETE', {'ff00': {'state': 'ACCEPTED_RISK'}}, 'LOADED')
    if 'Blocking findings' in txt:
        fails.append('accepted risk still counted as blocking')
    txt = render(cfg, fs, 'COMPLETE', {}, 'LOADED')
    if 'Blocking findings: **1**' not in txt:
        fails.append('undispositioned critical was not blocking')
    if 'Disposition: NONE' not in txt:
        fails.append('untriaged finding did not say so')

    # 6b. AN EXPIRED ACCEPTANCE MUST BLOCK AGAIN. Silence never renews.
    past = {'state': 'ACCEPTED_RISK', 'expires': '2020-01-01', 'approved_by': 'x'}
    if not not_suppressed_because(past):
        fails.append('an expired risk acceptance still suppressed')
    if 'EXPIRED' not in not_suppressed_because(past):
        fails.append('expiry was not the stated reason')
    future = {'state': 'ACCEPTED_RISK', 'expires': '2099-01-01'}
    if not_suppressed_because(future):
        fails.append('an unexpired acceptance failed to suppress')
    if not not_suppressed_because({'state': 'ACCEPTED_RISK', 'expires': 'soon'}):
        fails.append('an unparseable expiry was treated as open-ended')
    # 6c. AN UNREGISTERED SYNONYM MUST NOT SUPPRESS. The taxonomy says ACCEPTED_RISK; this file
    # once said RISK_ACCEPTED, and a third spelling (RISK_ACCEPTANCE) was in circulation.
    for synonym in ('RISK_ACCEPTED', 'RISK_ACCEPTANCE', 'accepted_risk'):
        if not not_suppressed_because({'state': synonym}):
            fails.append('unregistered disposition spelling %s suppressed a finding' % synonym)

    # 7. Unparseable output is not a clean result.
    txt = render(cfg, [], 'UNPARSEABLE', {}, 'LOADED')
    if 'NOT ESTABLISHED' not in txt or 'INVALID' not in txt:
        fails.append('unparseable SARIF read as a clean result')

    # 8. Batch: an expected scanner that dropped no state file must still appear, as NOT_RUN.
    import tempfile
    td = tempfile.mkdtemp()
    io.open(os.path.join(td, 'trivy.json'), 'w', encoding='utf-8').write(json.dumps(
        {'scanner': 'trivy', 'applicability': 'APPLICABLE', 'execution': 'COMPLETE',
         'sarif': '', 'gate': 'PASS'}))
    txt = batch(td, '', 5, '', ['trivy', 'codeql'])
    if '| codeql |' not in txt:
        fails.append('an expected scanner that wrote no state file vanished from the report')
    if 'NOT_RUN' not in txt:
        fails.append('a missing scanner was not reported as NOT_RUN')
    # and it must not be able to claim zero findings
    codeql_block = txt.split('### codeql')[-1] if '### codeql' in txt else ''
    if 'NOT ESTABLISHED' not in codeql_block:
        fails.append('a scanner that never ran did not report NOT ESTABLISHED in batch mode')

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
    rep = batch(td, '', 5, '', [])
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
    fp1 = fingerprint('acc', 'X1', 'a.py', 'one')
    io.open(os.path.join(td, 'd.json'), 'w', encoding='utf-8').write(json.dumps(
        {'dispositions': {fp1: {'state': 'ACCEPTED_RISK', 'approved_by': 'x'}}}))
    txt = batch(td, os.path.join(td, 'd.json'), 5, '', [])
    row = [ln for ln in txt.splitlines() if ln.startswith('| acc |')]
    detail = txt.split('### acc')[-1]
    if not row:
        fails.append('batch summary lost a scanner row')
    elif '| 1 | 2 | 1 |' not in row[0]:
        fails.append('summary row did not report 1 blocking / 2 total / 1 dispositioned: %s'
                     % row[0])
    if 'Blocking findings: **1**' not in detail:
        fails.append('detail section disagreed with the summary table on blocking count')

    # 9. Batch: a corrupt state file is a collection failure, not an omission.
    io.open(os.path.join(td, 'semgrep.json'), 'w', encoding='utf-8').write('{ not json')
    txt = batch(td, '', 5, '', [])
    if '### semgrep' not in txt or 'NOT ESTABLISHED' not in txt.split('### semgrep')[-1]:
        fails.append('a corrupt state file was dropped instead of reported')

    if fails:
        print('SELF-TEST FAILED:')
        for f in fails:
            print('  - %s' % f)
        return False
    print('self-test ok: a scanner that did not run reports NOT ESTABLISHED and can never report 0;')
    print('              platform action is separated from developer action;')
    print('              fingerprints survive line movement; unparseable output is not clean')
    return True


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--scanner')
    ap.add_argument('--sarif', default='')
    ap.add_argument('--applicability', default='APPLICABLE',
                    choices=['APPLICABLE', 'NOT_APPLICABLE', 'UNAVAILABLE', 'NOT_CONFIGURED'])
    ap.add_argument('--execution', default='COMPLETE',
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
    ap.add_argument('--self-test', action='store_true')
    a = ap.parse_args()

    if a.self_test:
        return 0 if self_test() else 2
    if not self_test():
        print('ABORTING -- a reporter that can fabricate a zero is worse than no reporter.')
        return 2

    if a.batch:
        text = batch(a.batch, a.dispositions, a.max_detail, a.run_url,
                     [x.strip() for x in a.expect.split(',') if x.strip()])
        print(text)
        if a.out:
            with io.open(a.out, 'a', encoding='utf-8') as fh:
                fh.write(text + '\n\n')
        return 0

    if not a.scanner:
        print('--scanner or --batch is required')
        return 2

    findings, parse_state = parse_sarif(a.sarif, a.scanner)
    disp, disp_state = load_dispositions(a.dispositions)
    cfg = dict(scanner=a.scanner, applicability=a.applicability, execution=a.execution,
               scope=a.scope, artifact=a.artifact, upload=a.upload, gate=a.gate,
               sarif=a.sarif, run_url=a.run_url, max_detail=a.max_detail)
    text = render(cfg, findings, parse_state, disp, disp_state)

    # Both destinations, deliberately. The step summary is where a reviewer looks; the run log is
    # where an engineer already is when the job goes red.
    print(text)
    if a.out:
        with io.open(a.out, 'a', encoding='utf-8') as fh:
            fh.write(text + '\n\n')
    return 0


if __name__ == '__main__':
    sys.exit(main())

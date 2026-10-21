#!/usr/bin/env python3
"""One finding, one identity, across a scanner wording and version change -- END TO END.

WHY THIS FILE EXISTS, AND WHY `finding_identity.py --self-test` DOES NOT COVER IT

    `finding_identity.py --self-test` is green and it is a good test. It mutates every excluded
    field on a HAND-BUILT record and proves the identity does not move. What it cannot establish
    is whether anything ever hands it such a record.

    That gap is the whole defect. `risks.md` R-10 records it in prose -- "the durable finding
    identity is wired and produces nothing" -- and prose is not a gate. A risk register entry
    does not fail a build, so the state it describes can persist indefinitely while the one
    self-test that touches identity stays green and reads as coverage.

    So this file does not test `identify()`. It tests the PATH: a real SARIF document, through
    `scan_report.parse_sarif`, which is the only code in this kit that turns scanner output into
    identity records. Then it changes what a vendor actually changes -- the message prose and the
    tool version, and separately the rule id -- and asks whether the identity held.

    The invariant chain this walks: `identify()` is INVOKED (commit 88c4a80 established that) but
    its output is not COMPLETED, because the record reaching it cannot satisfy any subject's
    specification. Invoked is not effective, and a green self-test one layer down cannot tell the
    difference.

THE TRAP THIS FILE IS BUILT TO AVOID

    The obvious test is `identity_before == identity_after`. That assertion PASSES TODAY, because
    both sides are the empty string. '' == '' is True, and a test written that way would report
    durable identity over a pipeline that computes none at all -- *nothing found* rendered as
    *nothing wrong*, inside the test suite that exists to refuse exactly that collapse.

    Therefore NON-EMPTINESS IS ASSERTED FIRST and separately, and the failure message for the
    empty case says something different from the failure message for the moved case. A reader of
    the output must be able to tell "the identity changed" from "there was never an identity".

THE CONTROL, WHICH IS NOT OPTIONAL

    Scenario C calls `identify()` directly with a COMPLETE record and proves the identity model
    itself is durable across a scanner swap, a version bump, a rule rename, a reworded message
    and line movement. Without it, a failure here is ambiguous between "the model is wrong" and
    "nothing feeds the model" -- and those two have opposite fixes. The control passing while the
    end-to-end path fails localises the defect to field extraction in `scan_report.parse_sarif`,
    which is where it is.

WHAT THIS FILE DOES NOT ESTABLISH

    That a real Semgrep 1.45 and a real Semgrep 1.92 emit the SARIF shapes used here. The
    documents are constructed, and they are constructed to be GENEROUS to the kit: CWE in the
    tags where Semgrep puts it, a `logicalLocations` symbol, a purl and a CVE on the dependency
    case. If the identity cannot be computed from these, it cannot be computed from a real one
    either -- but a real-SARIF corpus would still be stronger evidence, and this is not it.

ONE FIXTURE FIELD WAS ADDED WHEN D-2 WAS FIXED, AND IT IS DECLARED HERE RATHER THAN BURIED

    The SAST documents originally carried no `region.snippet`. They therefore could not satisfy
    SOURCE's CONTENT no matter how the extraction was written, so the file's own description of
    itself as GENEROUS was wrong in exactly the place that mattered: it withheld the one field
    the subject specification names, while the CWE and the symbol it supplied so carefully were
    never the blocker.

    Semgrep does emit `locations[].physicalLocation.region.snippet.text`. So the snippet is now
    in the fixture, at the key Semgrep uses, and `scenario_construct_required` below is the price
    of adding it: it feeds the SAME document with the snippet REMOVED and asserts the identity is
    refused with CONTENT_UNDERIVABLE and carries no hash. Without that scenario this change would
    be indistinguishable from making CONTENT optional to turn a red file green -- which is the
    permissive direction, and the one direction a security gate may not move in.

    The "after" document additionally REFORMATS the snippet -- same code, different whitespace --
    so the scenario now also proves what it only claimed before: that a formatter rollout does
    not manufacture new findings.

    WHAT THIS MEANS FOR THE REAL PIPELINE, STATED PLAINLY: `scripts/redact_sarif.py` strips
    `snippet` and `contextRegion.snippet` from every SARIF BEFORE it is uploaded, and the `report`
    job reads those uploaded artifacts. So on the real pipeline the construct is gone by the time
    the reporter sees it, and these SAST findings will refuse there even though they fingerprint
    here. That is a conflict between two controls, not a passing path, and this file is not
    evidence that it works end to end in CI. See docs/KNOWN_DEFECTS.md.

USAGE
    python tests/prove_identity_durability.py
    python tests/prove_identity_durability.py --self-test

EXIT
    0  one finding kept one non-empty durable identity across every vendor-side change
    1  the identity went empty, moved, or collided -- the message says which
    2  could not be checked -- reported as UNKNOWN, never as PASS
"""
import argparse
import io
import json
import os
import shutil
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, os.path.join(ROOT, 'scripts'))

# Two distinct failure vocabularies. They must never be reported under one word: an identity that
# MOVED is a normalisation bug, an identity that was NEVER COMPUTED is an extraction bug, and the
# remedies share nothing.
NEVER_COMPUTED = 'IDENTITY_NEVER_COMPUTED'
IDENTITY_MOVED = 'IDENTITY_MOVED'
IDENTITY_COLLIDED = 'IDENTITY_COLLIDED'


# ── the SARIF a SAST scanner actually emits, parameterised by what a vendor changes ──
SAST_CONSTRUCT = 'cursor.execute("SELECT * FROM users WHERE id = " + user_id)'
# THE SAME CODE, REFORMATTED. A formatter rollout is not a change to the program.
SAST_CONSTRUCT_REFORMATTED = ('cursor.execute(\n'
                              '    "SELECT * FROM users WHERE id = " + user_id )  # nosec?\n')


def sast_sarif(version, message, rule_id, symbol='app.db.queries.fetch_user',
               line=42, path='app/db/queries.py', snippet=SAST_CONSTRUCT):
    """A Semgrep-shaped SOURCE finding. CWE lives in `rule.properties.tags`, which is where
    Semgrep puts it, the symbol in `logicalLocations`, which is the strongest locus the identity
    model will accept for a CWE-only WHAT, and the matched line in `region.snippet.text`, which
    is where Semgrep puts the construct and which SOURCE's CONTENT names.

    `snippet=None` builds the SAME finding with the construct REMOVED -- the shape the kit's own
    pre-upload redactor produces. It must refuse, and `scenario_construct_required` asserts it
    does."""
    region = {'startLine': line, 'startColumn': 9}
    if snippet is not None:
        region['snippet'] = {'text': snippet}
    return {
        'version': '2.1.0',
        '$schema': 'https://json.schemastore.org/sarif-2.1.0.json',
        'runs': [{
            'tool': {'driver': {
                'name': 'Semgrep',
                'version': version,
                'semanticVersion': version,
                'rules': [{
                    'id': rule_id,
                    'name': rule_id,
                    'shortDescription': {'text': 'SQL injection'},
                    'properties': {
                        'tags': ['security', 'external/cwe/cwe-089', 'confidence:HIGH'],
                        'security-severity': '8.5',
                    },
                }],
            }},
            'invocations': [{'executionSuccessful': True}],
            'results': [{
                'ruleId': rule_id,
                'level': 'error',
                'message': {'text': message},
                'locations': [{
                    'physicalLocation': {
                        'artifactLocation': {'uri': path},
                        'region': region,
                    },
                    'logicalLocations': [{'fullyQualifiedName': symbol, 'kind': 'function'}],
                }],
            }],
        }],
    }


def dep_sarif(version, message, rule_id, purl='pkg:pypi/requests@2.19.1'):
    """A dependency finding, where the WHAT is an advisory id and the WHERE is a purl -- the
    strongest inputs the identity model accepts. If this one cannot be fingerprinted, no finding
    from any scanner can be."""
    return {
        'version': '2.1.0',
        'runs': [{
            'tool': {'driver': {'name': 'Trivy', 'version': version,
                                'rules': [{'id': rule_id,
                                           'properties': {'security-severity': '9.1'}}]}},
            'invocations': [{'executionSuccessful': True}],
            'results': [{
                'ruleId': rule_id,
                'level': 'error',
                'message': {'text': message},
                'properties': {'purl': purl, 'package': 'requests',
                               'fixed_version': '2.31.0'},
                'locations': [{'physicalLocation': {
                    'artifactLocation': {'uri': 'requirements.txt'},
                    'region': {'startLine': 7}}}],
            }],
        }],
    }


def through_the_pipeline(doc, scanner, workdir):
    """-> the single finding record `scan_report.parse_sarif` produces, or a reason it produced
    none. Deliberately the real entry point: the point of this file is the PATH."""
    import scan_report
    p = os.path.join(workdir, 'in.sarif')
    with io.open(p, 'w', encoding='utf-8') as fh:
        json.dump(doc, fh)
    try:
        findings, parse_state, _examination = scan_report.parse_sarif(p, scanner)
    except Exception as exc:                                  # noqa: BLE001
        # NOT swallowed -- reported under its own name. `parse_sarif` once had a fourth,
        # undeclared state: valid JSON whose SARIF structure is wrong RAISED out of the parser
        # instead of returning UNPARSEABLE. L06 closed it (tests/prove_malformed_sarif_isolated.py),
        # so a raise here is a regression and is still reported by name rather than inherited.
        return None, 'parse_sarif RAISED %s: %s' % (type(exc).__name__, exc)
    if parse_state != 'COMPLETE':
        return None, 'parse_state=%s' % parse_state
    if len(findings) != 1:
        return None, 'expected exactly 1 finding, got %d' % len(findings)
    return findings[0], ''


def end_to_end(name, scanner, before, after, workdir):
    """-> list of (code, message). Empty list means the identity held."""
    bad = []
    a, why_a = through_the_pipeline(before, scanner, workdir)
    b, why_b = through_the_pipeline(after, scanner, workdir)
    if a is None or b is None:
        return [('UNPARSED', '%s: the reporter produced no comparable finding (%s / %s)'
                 % (name, why_a, why_b))]

    print('  %-34s before: state=%-20s identity=%s' % (name, a['identity_state'],
                                                       a['identity'] or '(empty)'))
    print('  %-34s after : state=%-20s identity=%s' % ('', b['identity_state'],
                                                       b['identity'] or '(empty)'))
    if a['identity_reason'] or b['identity_reason']:
        print('  %-34s refusal reasons: %s / %s'
              % ('', a['identity_reason'] or '-', b['identity_reason'] or '-'))

    # (1) NON-EMPTINESS FIRST. This ordering is the point of the file -- see the docstring. An
    # equality assertion on two empty strings passes, and would report durability over a pipeline
    # that computes no identity at all.
    for label, rec in (('before', a), ('after', b)):
        if not rec['identity']:
            bad.append((NEVER_COMPUTED,
                        '%s (%s): identity is EMPTY. The reporter called identify() and it '
                        'refused with %s. This is not a durable identity that moved -- it is no '
                        'identity at all, so every downstream consumer falls back to the legacy '
                        '`fp`, which is built from scanner, rule_id, uri and message: the four '
                        'fields a vendor change moves.'
                        % (name, label, rec['identity_reason'] or 'no stated reason')))
        if rec['identity_state'] != 'FINGERPRINTED':
            bad.append((NEVER_COMPUTED,
                        '%s (%s): identity_state is %s, not FINGERPRINTED'
                        % (name, label, rec['identity_state'])))

    # (2) Only now is equality meaningful.
    if a['identity'] and b['identity'] and a['identity'] != b['identity']:
        bad.append((IDENTITY_MOVED,
                    '%s: the identity MOVED when the scanner reworded its message and bumped its '
                    'version. Every disposition approved against the old key is orphaned, and the '
                    'finding reappears as NEW at the next scan.' % name))

    # (3) The legacy key is reported either way. It is not asserted on -- carrying both keys is a
    # deliberate, documented migration state -- but a reader must see what the legacy key did,
    # because that is what dispositions are still keyed on today.
    print('  %-34s legacy fp: %s -> %s  (%s)'
          % ('', a['fp'], b['fp'],
             'HELD' if a['fp'] == b['fp'] else 'MOVED, so approvals keyed on it are orphaned'))
    return bad


def distinctness(workdir):
    """Two genuinely different findings in one file must not share one identity.

    This is the other half of R-10's "validation needed" line, and it is the half that is
    dangerous to get wrong in the permissive direction: a collision means the second finding
    silently inherits the first finding's risk acceptance.
    """
    bad = []
    one = sast_sarif('1.92.3', 'SQL built by concatenation',
                     'python.lang.security.audit.sqli.sql-injection',
                     symbol='app.db.queries.fetch_user')
    two = sast_sarif('1.92.3', 'SQL built by concatenation',
                     'python.lang.security.audit.sqli.sql-injection',
                     symbol='app.db.queries.delete_user', line=118)
    a, _ = through_the_pipeline(one, 'semgrep', workdir)
    b, _ = through_the_pipeline(two, 'semgrep', workdir)
    if a is None or b is None:
        return [('UNPARSED', 'distinctness: no comparable findings')]
    print('  %-34s symbol A=%s  symbol B=%s' % ('two findings, one file',
                                                a['identity'] or '(empty)',
                                                b['identity'] or '(empty)'))
    if not a['identity'] or not b['identity']:
        bad.append((NEVER_COMPUTED,
                    'distinctness is UNTESTABLE: neither finding has an identity, so the question '
                    '"do two different findings collide?" has no answer. An empty identity shared '
                    'by every finding in the estate is the worst possible collision, and it is '
                    'not visible as one because nothing compares empty strings.'))
    elif a['identity'] == b['identity']:
        bad.append((IDENTITY_COLLIDED,
                    'distinctness: two findings in different symbols produced ONE identity. The '
                    'second would inherit the first\'s approvals.'))
    return bad


def scenario_construct_required(workdir):
    """A SAST finding whose construct is ABSENT must REFUSE, and say which field is missing.

    THIS SCENARIO IS THE PRICE OF THE FIXTURE GAINING A SNIPPET. See the docstring at the top.

    Every other scenario here asserts that something was computed. This one asserts that
    something was NOT, and it is the only guard against the cheap way to make this file green:
    spell SOURCE's content `?construct` and a record that merely failed to carry its construct
    returns the declared not-applicable sentinel instead of refusing. Two different injections
    in one function would then share one identity, and the second would inherit the first's risk
    acceptance.

    The two states this keeps apart are the kit's founding distinction: "this subject has no
    matched construct" (true of a dependency finding, and the reason SOURCE_DEPENDENCY exists)
    is not "this finding has one and we could not read it".
    """
    bad = []
    doc = sast_sarif('1.92.3', 'SQL built by concatenation',
                     'python.lang.security.audit.sqli.sql-injection', snippet=None)
    rec, why = through_the_pipeline(doc, 'semgrep', workdir)
    if rec is None:
        return [('UNPARSED', 'construct-required: no comparable finding (%s)' % why)]
    print('  %-34s state=%-20s identity=%s' % ('construct absent (redactor shape)',
                                               rec['identity_state'],
                                               rec['identity'] or '(empty, as required)'))
    print('  %-34s refusal: %s' % ('', rec['identity_reason'] or '(none -- WRONG)'))
    if rec['identity']:
        bad.append((IDENTITY_COLLIDED,
                    'construct-required: a SAST finding with NO construct was FINGERPRINTED. '
                    'CONTENT has been made optional somewhere, so every SAST finding whose '
                    'construct is merely missing now hashes as though no construct existed -- '
                    'and two different findings at one locus share one identity, which means the '
                    'second silently inherits the first\'s approvals. This is the permissive '
                    'direction, and it is worse than the empty identity it replaced.'))
    if rec['identity_reason'] != 'CONTENT_UNDERIVABLE':
        bad.append((NEVER_COMPUTED,
                    'construct-required: the refusal reason is %r, expected CONTENT_UNDERIVABLE. '
                    '"could not be derived" and "not applicable to this subject" are different '
                    'answers and an operator must be able to tell which one they got.'
                    % (rec['identity_reason'] or 'none')))
    if 'construct' not in (rec.get('identity_detail') or ''):
        bad.append((NEVER_COMPUTED,
                    'construct-required: the refusal does not name the missing field (%r). A '
                    'refusal that does not say what is absent is a shrug, and nobody can close a '
                    'gap they cannot name.' % (rec.get('identity_detail') or '')))
    return bad


def control():
    """The identity MODEL, exercised directly on a complete record.

    Not a duplicate of `finding_identity.py --self-test`: this exists to localise a failure. If
    this passes and the end-to-end scenarios fail, the model is sound and the extraction is not,
    which is a different bug with a different owner.
    """
    from finding_identity import identify, FINGERPRINTED
    bad = []
    complete = {
        'finding_subject': 'SOURCE',
        'cwe': 'CWE-89',
        'rule_family': 'python.lang.security.audit.sqli',
        'canonical_path': 'app/db/queries.py',
        'symbol_path': 'app.db.queries.fetch_user',
        'construct': 'cursor.execute("SELECT * FROM u WHERE id=" + user_id)',
        'language_family': 'hash',
        # everything a vendor moves
        'scanner': 'semgrep', 'scanner_version': '1.45.0', 'tool': 'Semgrep',
        'rule_id': 'python.lang.security.audit.sqli.sql-injection',
        'message': 'Detected SQL string concatenation with a user-controlled value',
        'start_line': 42, 'severity': 'HIGH',
    }
    base = identify(complete)
    if base['state'] != FINGERPRINTED or not base.get('identity'):
        bad.append((NEVER_COMPUTED,
                    'CONTROL: a COMPLETE record was not fingerprinted (%s / %s). The identity '
                    'model itself is broken, which is a different and larger defect than the '
                    'extraction gap this file was written to find.'
                    % (base.get('reason'), base.get('detail'))))
        return bad, None

    vendor_change = dict(complete,
                         scanner_version='1.92.3',
                         rule_id='python.lang.security.audit.sqli.sql-injection-concat',
                         message='User input flows into an SQL query built by concatenation; '
                                 'use parameterised queries instead',
                         start_line=987)
    moved = identify(vendor_change)
    print('  %-34s identity %s' % ('CONTROL complete record', base['identity'][:16]))
    print('  %-34s identity %s  (%s)'
          % ('CONTROL after vendor change', (moved.get('identity') or '(empty)')[:16],
             'HELD' if moved.get('identity') == base['identity'] else 'MOVED'))
    if moved.get('identity') != base['identity']:
        bad.append((IDENTITY_MOVED,
                    'CONTROL: the identity model moved on a scanner version, rule rename, message '
                    'rewording and line move. Those are all on its own EXCLUDED list.'))
    return bad, base['identity']


def prove():
    """-> (failures, control_ok). A failure is (code, message)."""
    workdir = tempfile.mkdtemp(prefix='identity-')
    try:
        print('=== the identity MODEL, on a complete record (the control) ===')
        print('')
        ctl, ctl_identity = control()
        print('')
        print('=== the identity PATH, SARIF -> scan_report.parse_sarif -> identify() ===')
        print('')
        bad = list(ctl)

        bad += end_to_end(
            'SAST, message + version change', 'semgrep',
            sast_sarif('1.45.0',
                       'Detected SQL string concatenation with a user-controlled value',
                       'python.lang.security.audit.sqli.sql-injection'),
            # The snippet is REFORMATTED, not merely carried over: a formatter rollout must not
            # manufacture a new finding, and asserting that here costs nothing.
            sast_sarif('1.92.3',
                       'User input flows into an SQL query built by concatenation; use '
                       'parameterised queries instead',
                       'python.lang.security.audit.sqli.sql-injection',
                       snippet=SAST_CONSTRUCT_REFORMATTED),
            workdir)
        print('')
        bad += end_to_end(
            'SAST, + rule renamed', 'semgrep',
            sast_sarif('1.45.0',
                       'Detected SQL string concatenation with a user-controlled value',
                       'python.lang.security.audit.sqli.sql-injection'),
            sast_sarif('1.92.3',
                       'User input flows into an SQL query built by concatenation',
                       'python.lang.security.audit.sqli.sql-injection-concat'),
            workdir)
        print('')
        bad += scenario_construct_required(workdir)
        print('')
        bad += end_to_end(
            'dependency, CVE + purl present', 'trivy',
            dep_sarif('0.48.0', 'requests: CRLF injection via Location header',
                      'CVE-2018-18074'),
            dep_sarif('0.56.1', 'requests 2.19.1: Authorization header leak on redirect '
                                '(reworded advisory summary)', 'CVE-2018-18074'),
            workdir)
        print('')
        bad += distinctness(workdir)
        return bad, (not ctl)
    finally:
        shutil.rmtree(workdir, ignore_errors=True)


def self_test():
    """Prove this file can fail, and prove it refuses the vacuous pass.

    A proof that has never failed is decoration. More specifically: the exact mistake this file
    exists to avoid is an equality assertion that passes on two empty strings, so the self-test
    asserts that an empty identity is reported as NEVER_COMPUTED and not as a pass.
    """
    fails = []
    workdir = tempfile.mkdtemp(prefix='identity-st-')
    try:
        # 1. Two identical EMPTY identities must be refused, not accepted as "stable".
        #
        # The document is the SNIPPET-LESS one, deliberately. Since D-2 was fixed a complete
        # SAST document fingerprints, so it can no longer stand in for the empty case -- and a
        # self-test whose "empty" fixture quietly started producing a real identity would report
        # that this file still refuses the vacuous pass while testing nothing of the kind. The
        # redactor shape is a genuinely empty-identity document, and it is the one in production.
        same = sast_sarif('1.0.0', 'm', 'a.b.c', snippet=None)
        bad = end_to_end('selftest/vacuous', 'semgrep', same, dict(same), workdir)
        if not any(code == NEVER_COMPUTED for code, _ in bad):
            fails.append('two identical EMPTY identities were not reported as NEVER_COMPUTED. '
                         'This file would report durability over a pipeline computing none.')
        if any(code == IDENTITY_MOVED for code, _ in bad):
            fails.append('an empty identity was reported as MOVED -- the two failure vocabularies '
                         'have collapsed, and a reader cannot tell an extraction bug from a '
                         'normalisation bug')

        # 2. A document yielding no comparable finding must be UNPARSED, never a silent pass.
        bad = end_to_end('selftest/empty', 'semgrep', {'version': '2.1.0', 'runs': []},
                         {'version': '2.1.0', 'runs': []}, workdir)
        if not bad:
            fails.append('a document yielding no findings was accepted as a pass')

        # 3. A structurally malformed SARIF must be reported, not propagated as a traceback.
        #
        # Before L06 the parser RAISED on this document and this assertion required the exception
        # to be surfaced by name. The parser now declares the state -- UNPARSEABLE -- and that is
        # what must be reported: a reader can still tell a broken document from an empty one, and
        # a raise would now be a regression (reported as RAISED by through_the_pipeline).
        bad = end_to_end('selftest/malformed', 'semgrep', {'runs': ['a-string-not-an-object']},
                         {'runs': ['a-string-not-an-object']}, workdir)
        if not any(code == 'UNPARSED' for code, _ in bad):
            fails.append('a structurally malformed SARIF was not reported as UNPARSED')
        if not any('UNPARSEABLE' in m for _c, m in bad):
            fails.append('a malformed SARIF was not reported as parse_state=UNPARSEABLE (%r), so a '
                         'reader cannot tell a broken document from an empty report'
                         % [m for _c, m in bad])
        if any('RAISED' in m for _c, m in bad):
            fails.append('a malformed SARIF RAISED out of parse_sarif -- the fourth state L06 '
                         'closed is open again')

        # 3b. THE CONSTRUCT-REQUIRED SCENARIO MUST BE ABLE TO DISCRIMINATE.
        #
        # It asserts a refusal. A scenario that asserts a refusal passes trivially if nothing
        # ever fingerprints -- which was the state of this entire file before D-2 was fixed. So
        # prove the two cases actually differ: the same finding WITH its construct must produce
        # an identity, and WITHOUT it must produce none. If they agree, the scenario is
        # decoration and the fixture's snippet is an unguarded change.
        with_c, why_w = through_the_pipeline(sast_sarif('1.0.0', 'm', 'a.b.c'), 'semgrep', workdir)
        without_c, why_o = through_the_pipeline(sast_sarif('1.0.0', 'm', 'a.b.c', snippet=None),
                                                'semgrep', workdir)
        if with_c is None or without_c is None:
            fails.append('could not build the with/without-construct pair (%s / %s)'
                         % (why_w, why_o))
        else:
            if not with_c['identity']:
                fails.append('a SAST finding WITH its construct produced no identity (%s), so '
                             'the construct-required scenario cannot discriminate and would pass '
                             'over a pipeline that fingerprints nothing'
                             % (with_c['identity_reason'] or 'no stated reason'))
            if without_c['identity']:
                fails.append('a SAST finding WITHOUT its construct produced an identity, so '
                             'CONTENT is optional somewhere and two findings at one locus can '
                             'share one approval')
            if not any(code == NEVER_COMPUTED or code == IDENTITY_COLLIDED
                       for code, _ in scenario_construct_required(workdir)) \
                    and without_c['identity_reason'] != 'CONTENT_UNDERIVABLE':
                fails.append('the construct-required scenario reported nothing while the refusal '
                             'reason was %r' % without_c['identity_reason'])

        # 4. The control must be able to detect a model that moved. Force it by hand.
        from finding_identity import identify
        a = identify({'finding_subject': 'SOURCE', 'cve': 'CVE-2024-1',
                      'canonical_path': 'a.py', 'symbol_path': 's', 'construct': 'x',
                      'language_family': 'hash'})
        b = identify({'finding_subject': 'SOURCE', 'cve': 'CVE-2024-2',
                      'canonical_path': 'a.py', 'symbol_path': 's', 'construct': 'x',
                      'language_family': 'hash'})
        if not (a['identity'] and b['identity'] and a['identity'] != b['identity']):
            fails.append('identify() gave two different advisories the same identity, so the '
                         'control cannot distinguish anything')
    finally:
        shutil.rmtree(workdir, ignore_errors=True)

    if fails:
        for f in fails:
            sys.stderr.write('FAIL: %s\n' % f)
        return 2
    print('self-test ok: an EMPTY identity on both sides is reported as IDENTITY_NEVER_COMPUTED '
          'rather than as a stable one, which is the vacuous pass this file exists to refuse; the '
          'two failure vocabularies stay separate so an extraction bug cannot be read as a '
          'normalisation bug; a document that yields no comparable finding is UNPARSED rather '
          'than a pass; a structurally malformed SARIF is reported as UNPARSEABLE rather than '
          'propagating as a traceback that reads as this file crashing; '
          'identify() separates two different advisories, so the control is able to discriminate; '
          'and the construct-required scenario DISCRIMINATES -- the same SAST finding '
          'fingerprints with its construct and refuses without it -- so the refusal it asserts '
          'cannot be passing merely because nothing fingerprints at all.')
    return 0


def main():
    ap = argparse.ArgumentParser(
        description='One finding keeps one non-empty durable identity across a scanner '
                    'wording and version change -- proven end to end, not on a hand-built record.')
    ap.add_argument('--self-test', action='store_true',
                    help='prove this proof can fail, including on the vacuous empty==empty pass')
    a = ap.parse_args()
    if a.self_test:
        return self_test()

    try:
        import scan_report    # noqa: F401
        import finding_identity  # noqa: F401
    except ImportError as exc:
        print('UNKNOWN: cannot import the reporter or the identity module (%s). A check that '
              'could not execute is not a pass.' % exc)
        return 2

    bad, control_ok = prove()

    print('')
    print('=' * 74)
    if not bad:
        print('PASS: one finding keeps ONE NON-EMPTY identity across a message rewording, a')
        print('      version bump and a rule rename, and two different findings in one file do')
        print('      not collide.')
        print('')
        print('      THIS PROVES THE PATH ON CONSTRUCTED SARIF. It does not prove a real')
        print('      Semgrep or Trivy release emits these shapes; a real-output corpus would be')
        print('      stronger evidence and this is not one.')
        return 0

    never = [m for c, m in bad if c == NEVER_COMPUTED]
    movedm = [m for c, m in bad if c == IDENTITY_MOVED]
    collid = [m for c, m in bad if c == IDENTITY_COLLIDED]
    unpars = [m for c, m in bad if c == 'UNPARSED']

    for label, group in (('IDENTITY NEVER COMPUTED', never), ('IDENTITY MOVED', movedm),
                         ('IDENTITY COLLIDED', collid), ('NO COMPARABLE FINDING', unpars)):
        if not group:
            continue
        sys.stderr.write('\n-- %s --\n' % label)
        for m in group:
            sys.stderr.write('::error::%s\n' % m)

    sys.stderr.write('\n')
    if never and not movedm:
        sys.stderr.write(
            'THE DEFECT IS EXTRACTION, NOT NORMALISATION.\n'
            '%s\n'
            'Every end-to-end identity is EMPTY while the control on a complete record holds.\n'
            'So `identify()` is correct and `scan_report.parse_sarif` does not build a record it\n'
            'can accept. Invoked is not effective: the durable identity is called on every\n'
            'finding and returns none, and the legacy `fp` -- scanner, rule_id, uri, message --\n'
            'is what every disposition is still keyed on.\n'
            % ('CONTROL HELD.' if control_ok else 'THE CONTROL ALSO FAILED, so read that first.'))
    sys.stderr.write('IDENTITY_NOT_DURABLE -- %d failure(s).\n' % len(bad))
    return 1


if __name__ == '__main__':
    sys.exit(main())

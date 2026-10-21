#!/usr/bin/env python3
"""A scan that ran and examined NOTHING must not produce a clean verdict.

WHY THIS FILE EXISTS

    The kit's governing rule is that four states never collapse into each other:

        nothing found          a scanner looked at the scope and it is clean
        nothing exists         there was nothing in scope to find
        nothing was looked at  no evidence was collected
        the control is off     the capability is disabled or unlicensed

    `scan_report.py` has the vocabulary for all four. `NO_COUNT_STATES` and `NO_COUNT_APPLIC`
    exist precisely so a scanner that did not produce a trustworthy result cannot render a count,
    and the reason COVERAGE_GAP was added to that list is written out in the source.

    But both of those lists are consulted on values the CALLER SUPPLIES. `applicability` and
    `execution` arrive as command-line arguments, or as fields in a state file, and they default
    to the two strongest values in the vocabulary -- APPLICABLE and COMPLETE. Nothing in the
    reporter reads the SARIF's own account of whether the run succeeded.

    SARIF has that account. `runs[].invocations[].executionSuccessful` is the field a scanner
    sets to declare its own failure, and `toolExecutionNotifications` is where it writes the
    reason. `runs[].tool.driver.rules` says how many rules were loaded. `runs[].artifacts` says
    what was examined. The reporter reads none of them.

    So the collapse is reachable: a scanner that crashed, exited 0, and wrote a SARIF saying
    `executionSuccessful: false` renders as *Findings: NONE in the scanned scope* -- a clean
    verdict over a scope nothing read, produced from a report in which the scanner itself said
    it had failed. The tool told the truth and the reporter overrode it.

THE FOUR SHAPES A HOLLOW SCAN TAKES, AND WHY EACH IS DISTINCT

    declared_failure   the scanner says `executionSuccessful: false` and attaches a FATAL
                       notification. This is the crashed-scanner-that-exits-0 case: CI sees
                       exit 0, the shell that computes `execution` sees success, and the only
                       witness to the failure is the field nobody reads.

    bandit_unparsed    bandit skipped the file it could not parse and said so only in
                       `toolConfigurationNotifications`, at error. (This slot held `zero_rules`,
                       an empty rule set read as hollow, until KDEC-008 OD-2 ruled that a clean
                       bandit run -- which lists no rules -- is not hollow. That shape is now a
                       CONTROL that must read clean.)

    zero_artifacts     `artifacts: []` with the run reporting success -- the scanner was pointed
                       at a path containing nothing. Indistinguishable from a clean repository
                       unless the denominator is reported, which is LM-015.

    no_runs            a schema-valid SARIF with `runs: []`. No tool name, no rules, no results,
                       nothing. The weakest possible document, and the strongest-looking verdict.

    A fifth is not a SARIF shape but a wiring shape:

    permissive_default a state file that names a scanner and a SARIF and omits `applicability`
                       and `execution` entirely. The reporter fills in APPLICABLE and COMPLETE.
                       An omission therefore produces the strongest claim the vocabulary can
                       express, which is the opposite of fail-closed, and it is the shape a
                       consumer wiring their own job is most likely to produce.

WHAT A CORRECT RESULT LOOKS LIKE

    Any of: `NOT ESTABLISHED`, or a COVERAGE_GAP / COLLECTION_FAILED state, or anything that is
    not the clean sentence. What must never appear is the clean sentence itself, and what must
    never appear in the batch table is a `0` in the Blocking or Total column, because a zero
    beside an unread scope is a count of what nobody collected.

WHAT THIS FILE DOES NOT ESTABLISH

    That a real scanner emits these documents. It establishes what the reporter DECIDES when one
    does, which is the half that does not need a runner. It also does not test the workflow's own
    shell, which computes `execution` out of band and may catch the crashed-scanner case when the
    process exit code is non-zero -- the case proven here is the one where it is zero, which is
    the case that shell cannot see.

USAGE
    python tests/prove_hollow_scan.py
    python tests/prove_hollow_scan.py --self-test

EXIT
    0  no hollow scan produced a clean verdict
    1  at least one did -- the scenario and the exact sentence are printed
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

# The exact sentence that constitutes a clean verdict. Matched literally rather than by keyword:
# a keyword match on "NONE" would also hit "Developer action: **NONE**", which is a different and
# correct statement, and a test that conflated them would be unfalsifiable in one direction.
CLEAN_SENTENCE = 'Findings: **NONE** in the scanned scope.'
NOT_ESTABLISHED = 'Findings: **NOT ESTABLISHED**'

DRIVER = 'Trivy'


def _driver(rules=None):
    return {'name': DRIVER, 'version': '0.52.0',
            'rules': [{'id': 'AVD-AZU-0001'}] if rules is None else rules}


SCENARIOS = [
    ('declared_failure',
     'the scanner declared its own failure and still exited 0, so the shell that computes '
     '`execution` saw success. `executionSuccessful: false` is the only witness, and the '
     'reporter does not read it.',
     {'version': '2.1.0', 'runs': [{
         'tool': {'driver': _driver()},
         'invocations': [{
             'executionSuccessful': False,
             'exitCode': 0,
             'toolExecutionNotifications': [{
                 'level': 'error',
                 'message': {'text': 'FATAL: failed to download vulnerability DB: '
                                     'context deadline exceeded'}}]}],
         'results': []}]}),

    # REPLACED 2026-10-16 (KDEC-008 OD-2). This slot held `zero_rules` -- an empty rules[] with a
    # successful invocation, asserted hollow. That is byte for byte what a CLEAN bandit run emits
    # (bandit lists only rules that fired; measured, PIPELINE_ORDERING 3.2), and the owner ruled
    # "a clean bandit run is not hollow". The proof was defending the rule the decision retired,
    # which is why the reporter never moved. The clean bandit shape is now a CONTROL that must
    # read clean (check_declared_states_still_work); the hollow bandit shape is this one.
    ('bandit_unparsed',
     'bandit could not parse the file it was given (target language newer than its interpreter): '
     'exit 0, results [], rules [], executionSuccessful true, and the skip disclosed ONLY as an '
     'error-level notification in toolConfigurationNotifications -- the array a reader of '
     'toolExecutionNotifications alone never opens.',
     {'version': '2.1.0', 'runs': [{
         'tool': {'driver': {'name': 'Bandit', 'rules': []}},
         'invocations': [{
             'executionSuccessful': True,
             'toolConfigurationNotifications': [{
                 'level': 'error',
                 'message': {'text': 'syntax error while parsing AST from file'}}]}],
         'results': []}]}),

    ('zero_artifacts',
     'the run succeeded and examined no files. Without the denominator this is '
     'indistinguishable from a clean repository, which is the coverage-denominator defect '
     'recorded as LM-015.',
     {'version': '2.1.0', 'runs': [{
         'tool': {'driver': _driver()},
         'invocations': [{'executionSuccessful': True}],
         'artifacts': [],
         'properties': {'files_scanned': 0},
         'results': []}]}),

    ('no_runs',
     'a schema-valid SARIF carrying no runs at all: no tool name, no rules, no results. The '
     'weakest document that can be written, and it produces the strongest-looking verdict.',
     {'version': '2.1.0', 'runs': []}),
]


def verdict(doc, workdir, overrides=None, exam_override=None):
    """-> (rendered_markdown, parse_state). Renders through the real reporter.

    `exam_override` replaces the examination verdict the reporter derived. It is used ONLY by
    `--self-test`, to establish that the refusal this file observes is CAUSED BY the examination
    axis rather than by something incidental to these documents. A refusal with an unverified
    cause is a passing test that could pass for the wrong reason.
    """
    import scan_report
    p = os.path.join(workdir, 'hollow.sarif')
    with io.open(p, 'w', encoding='utf-8') as fh:
        json.dump(doc, fh)
    findings, parse_state, examination = scan_report.parse_sarif(p, 'trivy')
    if exam_override is not None:
        examination = exam_override
    # The caller still declares APPLICABLE and COMPLETE in every scenario, unchanged from before
    # the fix. That is the point: those are the values a crashed-but-exited-0 scanner's job
    # truthfully produces, so the refusal must come from the document and not from the caller.
    cfg = dict(scanner='trivy', applicability='APPLICABLE', execution='COMPLETE',
               scope='filesystem + IaC', artifact='RETAINED', upload='SUCCEEDED',
               gate='UNDETERMINED', sarif=p, run_url='', max_detail=20)
    cfg.update(overrides or {})
    return (scan_report.render(cfg, findings, parse_state, {}, 'NOT CONFIGURED', examination),
            parse_state)


def check_sarif_scenarios(workdir):
    """-> list of (scenario, message). Empty means no hollow scan read as clean."""
    bad = []
    for name, why, doc in SCENARIOS:
        text, parse_state = verdict(doc, workdir)
        clean = CLEAN_SENTENCE in text
        print('  %-18s parse_state=%-11s CLEAN=%-5s NOT_ESTABLISHED=%s'
              % (name, parse_state, clean, NOT_ESTABLISHED in text))
        sys.stdout.flush()
        if clean:
            bad.append((name,
                        '%s rendered the clean verdict %r. %s' % (name, CLEAN_SENTENCE, why)))
    return bad


def check_permissive_default(workdir):
    """A state file that omits applicability and execution must not default to the strongest
    pair in the vocabulary."""
    import scan_report
    bad = []
    sd = os.path.join(workdir, 'states')
    if os.path.isdir(sd):
        shutil.rmtree(sd)
    os.makedirs(sd)
    with io.open(os.path.join(sd, 'trivy.json'), 'w', encoding='utf-8') as fh:
        json.dump({'scanner': 'trivy', 'sarif': 'hollow.sarif'}, fh)
    with io.open(os.path.join(sd, 'hollow.sarif'), 'w', encoding='utf-8') as fh:
        json.dump(SCENARIOS[0][2], fh)

    text, faults = scan_report.batch(sd, '', 20, '')
    row = [ln for ln in text.split('\n') if ln.startswith('| trivy ')]
    clean = CLEAN_SENTENCE in text
    print('  %-18s row: %s' % ('permissive_default', row[0] if row else '(no row)'))
    print('  %-18s CLEAN=%-5s roster_faults=%d' % ('', clean, len(faults)))
    sys.stdout.flush()
    if clean:
        bad.append(('permissive_default',
                    'a state file naming only `scanner` and `sarif` rendered the clean verdict. '
                    'The reporter substituted applicability=APPLICABLE and execution=COMPLETE, '
                    'so an OMISSION produced the strongest claim the vocabulary can express.'))
    if row and ' | 0 | 0 | ' in row[0]:
        bad.append(('permissive_default',
                    'the batch table printed `0` in the Blocking and Total columns for a scanner '
                    'whose SARIF declared its own failure. A zero beside an unread scope is a '
                    'count of what nobody collected.'))
    return bad


def check_declared_states_still_work(workdir):
    """THE CONTROL, AND IT IS NOT OPTIONAL.

    Everything above asserts that a clean verdict is refused. A reporter that refused every
    verdict would satisfy all of it, so two things must be shown to still work: a genuinely
    clean run must be able to say NONE, and a declared collection failure must say NOT
    ESTABLISHED. Without these the file proves nothing about discrimination.
    """
    bad = []
    real = {'version': '2.1.0', 'runs': [{
        'tool': {'driver': _driver()},
        'invocations': [{'executionSuccessful': True}],
        'artifacts': [{'location': {'uri': 'infra/main.tf'}}],
        'properties': {'files_scanned': 128},
        'results': []}]}
    text, _ = verdict(real, workdir)
    print('  %-18s CLEAN=%-5s  (a real run that read 128 files and found nothing)'
          % ('CONTROL clean', CLEAN_SENTENCE in text))
    if CLEAN_SENTENCE not in text:
        bad.append(('CONTROL',
                    'a genuinely clean run -- execution successful, rules loaded, 128 artifacts '
                    'examined, no results -- could NOT say NONE. The reporter has stopped '
                    'discriminating, and every assertion above is satisfied by a reporter that '
                    'refuses everything.'))

    # KDEC-008 OD-2: "A clean bandit run is not hollow." Bandit's measured clean document lists
    # no rules (it lists only rules that fired) and no artifacts. It must be able to say NONE.
    bandit_clean = {'version': '2.1.0', 'runs': [{
        'tool': {'driver': {'name': 'Bandit', 'rules': []}},
        'invocations': [{'executionSuccessful': True}],
        'results': []}]}
    text_b, _ = verdict(bandit_clean, workdir)
    print('  %-18s CLEAN=%-5s  (a clean bandit run: results [], rules [], success)'
          % ('CONTROL bandit', CLEAN_SENTENCE in text_b))
    if CLEAN_SENTENCE not in text_b:
        bad.append(('CONTROL',
                    'a clean bandit run (results [], rules [], executionSuccessful true) could NOT '
                    'say NONE. KDEC-008 OD-2 rules it is not hollow; an empty rules[] is not a '
                    'witness for a tool that lists only the rules that fired.'))

    text, _ = verdict(real, workdir, overrides={'execution': 'COLLECTION_FAILED'})
    print('  %-18s NOT_ESTABLISHED=%-5s  (a declared collection failure)'
          % ('CONTROL failed', NOT_ESTABLISHED in text))
    if NOT_ESTABLISHED not in text:
        bad.append(('CONTROL',
                    'a declared COLLECTION_FAILED did not render NOT ESTABLISHED, so the '
                    'mechanism this file relies on is itself broken'))
    return bad


def prove():
    workdir = tempfile.mkdtemp(prefix='hollow-')
    try:
        print('=== the control: the reporter still discriminates ===')
        print('')
        bad = check_declared_states_still_work(workdir)
        print('')
        print('=== hollow SARIF shapes, rendered through scan_report.render ===')
        print('')
        bad += check_sarif_scenarios(workdir)
        print('')
        print('=== a state file that omits its own typed result ===')
        print('')
        bad += check_permissive_default(workdir)
        return bad
    finally:
        shutil.rmtree(workdir, ignore_errors=True)


def self_test():
    """Prove this file can fail and can pass, on the same mechanism."""
    fails = []
    workdir = tempfile.mkdtemp(prefix='hollow-st-')
    try:
        # 1. THE MATCHER MUST NOT BE VACUOUS. If `CLEAN_SENTENCE` no longer appears anywhere the
        #    reporter can produce it, every assertion in this file passes by matching nothing --
        #    which is the failure mode of a literal-string detector and the one that looks green.
        #    The control below produces it; this asserts the string is reachable at all.
        real = {'version': '2.1.0', 'runs': [{
            'tool': {'driver': _driver()},
            'invocations': [{'executionSuccessful': True}],
            'artifacts': [{'location': {'uri': 'infra/main.tf'}}],
            'results': []}]}
        text, _ = verdict(real, workdir)
        if CLEAN_SENTENCE not in text:
            fails.append('the clean sentence %r is not producible by the reporter at all, so '
                         'every assertion in this file now matches nothing and passes vacuously. '
                         'Either the sentence was reworded -- update CLEAN_SENTENCE -- or the '
                         'reporter can no longer report a clean scope, which is a defect of its '
                         'own.' % CLEAN_SENTENCE)

        # 1b. THE REFUSAL MUST BE CAUSED BY THE EXAMINATION AXIS, not by something incidental to
        #     these hand-built documents. Each hollow shape is re-rendered with the examination
        #     verdict FORCED to EXAMINED: it must then render clean. If it does not, the refusal
        #     the main run observes is coming from somewhere else and this file is measuring the
        #     wrong thing while reporting success.
        import scan_report
        for name, _why, doc in SCENARIOS:
            if name == 'no_runs':
                # A document with no runs has no findings and nothing to render a count from for
                # reasons that are not the examination axis, so forcing the axis cannot isolate
                # it. Excluded here and still asserted in the main run.
                continue
            forced, _ = verdict(doc, workdir, exam_override=(scan_report.EXAMINED, []))
            if CLEAN_SENTENCE not in forced:
                fails.append('%s was refused for a reason OTHER than the examination axis -- '
                             'forcing the axis to EXAMINED still did not produce a clean verdict, '
                             'so this file is not measuring what it claims' % name)

        # 2. The detector must NOT fire when the caller declares the failure properly.
        text, _ = verdict(SCENARIOS[0][2], workdir, overrides={'execution': 'COLLECTION_FAILED'})
        if CLEAN_SENTENCE in text:
            fails.append('a declared COLLECTION_FAILED still produced a clean verdict')
        if NOT_ESTABLISHED not in text:
            fails.append('a declared COLLECTION_FAILED did not say NOT ESTABLISHED')
        # 3. The sentence must not be matchable by accident. "Developer action: **NONE**" appears
        #    in the NOT ESTABLISHED branch and must not be mistaken for a clean verdict.
        if 'Developer action: **NONE**' not in text:
            fails.append('the NOT ESTABLISHED branch no longer contains the developer-action '
                         'sentence this file deliberately does NOT match on; the near-miss case '
                         'this guards against may have moved')
        # 4. The control must be able to go green.
        if check_declared_states_still_work(workdir):
            fails.append('the control could not go green, so a failing run proves nothing')
    finally:
        shutil.rmtree(workdir, ignore_errors=True)

    if fails:
        for f in fails:
            sys.stderr.write('FAIL: %s\n' % f)
        return 2
    print('')
    print('self-test ok: the clean sentence is PRODUCIBLE, so this file is not matching nothing '
          'and passing vacuously; every hollow shape renders clean again when the examination '
          'verdict is forced to EXAMINED, which establishes that the refusal is caused by that '
          'axis and not by something incidental to these documents; the sentence is matched '
          'literally and not by the word NONE, which also appears in the NOT ESTABLISHED branch '
          'as "Developer action: **NONE**"; a caller-declared COLLECTION_FAILED is refused a '
          'count; and the control -- a genuinely clean run saying NONE -- goes green, so this '
          'file reports discrimination rather than blanket refusal.')
    return 0


def main():
    ap = argparse.ArgumentParser(
        description='A scan that ran and examined nothing must not produce a clean verdict.')
    ap.add_argument('--self-test', action='store_true',
                    help='prove this proof can both fail and pass on the same mechanism')
    a = ap.parse_args()
    if a.self_test:
        return self_test()

    try:
        import scan_report   # noqa: F401
    except ImportError as exc:
        print('UNKNOWN: cannot import the reporter (%s). A check that could not execute is not '
              'a pass.' % exc)
        return 2

    bad = prove()

    print('')
    print('=' * 74)
    if not bad:
        print('PASS: no hollow scan produced a clean verdict, and a genuinely clean run still')
        print('      can. The four states are not collapsing.')
        print('')
        print('      THIS SETTLES WHAT THE REPORTER DECIDES, NOT WHAT A SCANNER EMITS. The')
        print('      documents are constructed; only a dispatch establishes that a real')
        print('      scanner produces them.')
        return 0

    for name, msg in bad:
        sys.stderr.write('::error::%s\n' % msg)
    sys.stderr.write(
        '\nHOLLOW_SCAN_READS_AS_CLEAN -- %d scenario(s).\n'
        '\n'
        'A HOLLOW SCAN IS NOT A CLEAN SCAN. Every scenario above ran, examined nothing, and\n'
        'was rendered as a scope with no findings in it. That is `nothing was looked at`\n'
        'printed as `nothing found`, which is the one collapse this kit exists to refuse, and\n'
        'the verdict it produces is the strongest-looking output the reporter can emit.\n'
        '\n'
        'THE MISSING READ: `runs[].invocations[].executionSuccessful`,\n'
        '`runs[].tool.driver.rules` and `runs[].artifacts` are in the SARIF and the reporter\n'
        'does not look at any of them. `applicability` and `execution` are supplied by the\n'
        'caller and default to APPLICABLE and COMPLETE, so the scanner\'s own account of its\n'
        'run is overridden by a default.\n'
        % len(bad))
    return 1


if __name__ == '__main__':
    sys.exit(main())

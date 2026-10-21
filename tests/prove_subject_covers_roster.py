#!/usr/bin/env python3
"""Every scanner on the report's roster must map to a finding subject (L42, G3-3).

WHY THIS EXISTS

    `scan_report.parse_sarif` calls `finding_subject.subject_for(scanner=<state-file name>, ...)`.
    The state-file name is the ROSTER name the report job writes -- `java-sast`, `trivy-iac`,
    `codeql-python` -- and the scanner wins over the SARIF driver name. The subject map was keyed on
    bare tool names only, so twelve of the twenty-four roster rows answered UNKNOWN, and every finding
    from those rows was UNFINGERPRINTABLE / SUBJECT_NOT_ESTABLISHED: no durable identity for Java, C#,
    C/C++, Trivy-IaC, OSV, the container image or any CodeQL language, however good the extraction
    layer underneath. The module's own self-test used bare tool names, so it could not see this.

    So this reads the roster FROM THE WORKFLOW, the way the report receives it, and asks the module
    the question the reporter asks.

WHAT IS ASSERTED

    1  the roster is read and is NOT EMPTY, from both places the workflow spells it (the `expect:`
       input of the report step and the `add "<name>"` state-file writers), and the two agree.
       An empty roster would make every assertion below vacuously true.
    2  every roster name is in the subject map. UNKNOWN for a roster name is the defect.
    3  a fixed mapping is a registered finding_subject; a multi-modal one resolves from a locator of
       the shape that job scans.
    4  the four roster rows whose subject is NOT the tool's usual one say so: trivy-image is IMAGE,
       trivy-iac is IAC_PLAN, malicious-deps is SOURCE_DEPENDENCY, codeql-* is SOURCE. Without these
       a map that sent everything to SOURCE would pass 2 and 3.
    5  the driver-name fallback: a job name nobody mapped, carrying a mapped SARIF driver, resolves
       from the driver and SAYS so in its basis; a job name AND a driver nobody mapped stay UNKNOWN.

EXIT  0 every roster name maps   1 one or more do not   2 could not be checked (UNKNOWN, never PASS)
"""
import io
import os
import re
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, os.path.join(ROOT, 'scripts'))
WF = os.path.join(ROOT, '.github', 'workflows', 'reusable-security.yml')

# A locator of the shape each multi-modal roster row actually scans, so the multi-modal path is
# exercised the way the reporter exercises it rather than with a convenient string.
LOCATOR_FOR_MULTIMODAL = {
    'trivy': 'requirements.txt',  # deps-scan: trivy fs over dependency manifests
}

# Judgement assertions: the rows whose subject differs from what the tool name suggests.
EXPECTED = {
    'trivy-image': 'IMAGE',
    'trivy-image-secret': 'IMAGE',
    'trivy-iac': 'IAC_PLAN',
    'malicious-deps': 'SOURCE_DEPENDENCY',
}


def read_roster(text):
    """-> (expect_names, writer_names). Both lists, in file order."""
    expect = []
    for m in re.finditer(r'^\s*expect:\s*([A-Za-z0-9_,.-]+)\s*$', text, re.M):
        expect.extend(n.strip() for n in m.group(1).split(',') if n.strip())
    writers = re.findall(r'^\s*add\s+"([A-Za-z0-9_.-]+)"', text, re.M)
    # cq_lang <language> writes `codeql-<language>` through one `add "codeql-$1"` line.
    for lang in re.findall(r'^\s*cq_lang\s+([A-Za-z0-9_.-]+)\s', text, re.M):
        writers.append('codeql-' + lang)
    writers = [w for w in writers if '$' not in w]
    return expect, writers


def main():
    try:
        import finding_subject as fs
        from finding_identity import SUBJECTS
    except ImportError as exc:
        print('UNKNOWN: could not import the subject map: %s' % exc)
        return 2
    try:
        text = io.open(WF, encoding='utf-8').read()
    except (IOError, OSError) as exc:
        print('UNKNOWN: cannot read %s: %s' % (WF, exc))
        return 2

    expect, writers = read_roster(text)
    fails = []
    # 1. NON-EMPTY FIRST, and separately. An empty roster makes every check below pass.
    if not expect or not writers:
        print('UNKNOWN: roster not found (expect=%d names, writers=%d). Nothing inspected is not '
              'nothing wrong.' % (len(expect), len(writers)))
        return 2
    if sorted(set(expect)) != sorted(set(writers)):
        fails.append('the two spellings of the roster disagree: only in expect: %s; only in writers: '
                     '%s' % (sorted(set(expect) - set(writers)), sorted(set(writers) - set(expect))))

    mapped = fs.mapped_names() if hasattr(fs, 'mapped_names') else None
    print('roster: %d name(s) from the report step, %d from the state-file writers'
          % (len(expect), len(writers)))
    for name in sorted(set(expect) | set(writers)):
        subj, basis = fs.subject_for(scanner=name, tool='', uri=LOCATOR_FOR_MULTIMODAL.get(name, ''))
        mark = 'ok ' if subj != fs.UNKNOWN else 'BAD'
        print('  %s %-30s -> %-18s %s' % (mark, name, subj, basis[:70]))
        # 2. every roster name is in the map
        if mapped is not None and name not in mapped:
            fails.append('%r is on the roster and not in the subject map' % name)
        if subj == fs.UNKNOWN:
            fails.append('%r -> UNKNOWN (%s). Every finding from that row is UNFINGERPRINTABLE.'
                         % (name, basis))
            continue
        # 3. a registered subject
        if subj not in SUBJECTS:
            fails.append('%r -> %r, which is not a registered finding_subject' % (name, subj))
        # 4. judgement rows
        want = EXPECTED.get(name) or ('SOURCE' if name.startswith('codeql-') else None)
        if want and subj != want:
            fails.append('%r -> %s, expected %s' % (name, subj, want))

    # 5. the driver-name fallback, both directions
    got, basis = fs.subject_for(scanner='a-job-nobody-mapped', tool='CodeQL', uri='src/app.py')
    if got != 'SOURCE' or 'driver' not in basis:
        fails.append('an unmapped job name with the mapped driver CodeQL gave %s (%s); expected SOURCE '
                     'from the driver, saying so' % (got, basis))
    got, basis = fs.subject_for(scanner='a-job-nobody-mapped', tool='a-driver-nobody-mapped',
                                uri='src/app.py')
    if got != fs.UNKNOWN:
        fails.append('an unmapped job name with an unmapped driver gave %s (%s); expected UNKNOWN, '
                     'never a guess' % (got, basis))

    print('')
    if fails:
        for f in fails:
            print('FAIL: ' + f)
        return 1
    print('PASS: all %d roster names map to a registered finding_subject; the multi-modal row '
          'resolves from the locator it scans; the driver fallback resolves a mapped driver and '
          'refuses an unmapped one.' % len(set(expect)))
    print('      THIS PROVES THE MAP, NOT THE SARIF. Whether each scanner\'s real output then yields '
          'a complete identity record is tests/prove_identity_durability.py\'s question.')
    return 0


if __name__ == '__main__':
    sys.exit(main())

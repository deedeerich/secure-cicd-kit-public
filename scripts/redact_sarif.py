#!/usr/bin/env python3
"""Strip credential material from a SARIF file IN PLACE, before it becomes an artifact.

WHY THIS EXISTS
    The kit redacted exactly one scanner. gitleaks ran with --redact and had `snippet` and
    `partialFingerprints` stripped before upload. Thirteen other jobs uploaded raw SARIF, and
    several of those scanners embed matched source by design:

        bandit    B105 hardcoded_password_string -- the snippet IS the password
        semgrep   snippet carries the matched source line
        trivy     secret mode reports the match
        checkov   includes the offending code block
        gosec     includes the offending line

    An artifact is downloadable by anyone with repository read access and is retained for
    weeks. Redacting the rendered summary while shipping the raw value in a downloadable file
    is theatre -- it moves the credential from a page someone reads to a file someone opens.

    The consolidated report job made it worse by copying every SARIF into one artifact.

WHAT SURVIVES, WHICH IS EVERYTHING NEEDED TO FIX THE FINDING
    rule id, severity, FILE, LINE, message with credential-shaped substrings masked to a short
    prefix. What is removed: `snippet`, `contextRegion.snippet`, and `partialFingerprints`
    (which for a secret scanner can be a hash of the secret itself).

IT IS NOT A SUBSTITUTE FOR --redact AT THE SCANNER
    Defence in depth. A scanner that can be told not to emit the value should be told. This
    catches the ones that cannot, and the ones a consumer adds later.

USAGE
    python3 redact_sarif.py <file.sarif> [more.sarif ...]
    python3 redact_sarif.py --self-test

EXIT
    0 rewritten (or nothing to do)      1 a file was unreadable      2 self-test failed
    3 a report could not be rewritten and was WITHHELD from upload instead
    4 a report could be neither redacted nor withheld -- credential material may be published

    Only 4 is worth failing a job over. 1, 2 and 3 mean the reports at risk are no longer on
    the upload path, so the scan's verdict stands and nothing leaks; failing there would be a
    housekeeping step deciding a security verdict, which is the defect this file keeps hitting.
"""
import io
import json
import os
import re
import sys
import tempfile

EXIT_OK = 0
EXIT_UNREADABLE = 1
EXIT_SELFTEST = 2
EXIT_WITHHELD = 3
EXIT_UNPROTECTED = 4

# BEGIN SECRET_PATTERNS -- must stay identical to scripts/scan_report.py.
# Two copies exist because each file is inlined into the workflow separately and neither can
# import the other at consumer runtime. tests/check_redaction_parity.py fails the build if they
# diverge, so the duplication is an enforced invariant rather than a hope -- the same treatment
# the SARIF normalizer gets for the same reason.
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
# END SECRET_PATTERNS


def scrub(doc):
    """-> (snippets_removed, messages_masked). Mutates doc."""
    snips = masked = 0
    for run in (doc.get('runs') or []):
        for res in (run.get('results') or []):
            msg = ((res.get('message') or {}).get('text'))
            if msg:
                r = redact(msg)
                if r != msg:
                    res['message']['text'] = r
                    masked += 1
            for loc in (res.get('locations') or []) + (res.get('relatedLocations') or []):
                pl = (loc.get('physicalLocation') or {})
                for key in ('region', 'contextRegion'):
                    reg = pl.get(key) or {}
                    if 'snippet' in reg:
                        reg.pop('snippet', None)
                        snips += 1
            # A partial fingerprint from a secret scanner can be a hash OF THE SECRET, which is
            # an offline-guessable artifact for anything low-entropy. It buys correlation that
            # this kit gets from file+rule instead.
            if res.pop('partialFingerprints', None) is not None:
                snips += 1
            for cf in (res.get('codeFlows') or []):
                for tf in (cf.get('threadFlows') or []):
                    for lo in (tf.get('locations') or []):
                        pl = ((lo.get('location') or {}).get('physicalLocation') or {})
                        for key in ('region', 'contextRegion'):
                            reg = pl.get(key) or {}
                            if 'snippet' in reg:
                                reg.pop('snippet', None)
                                snips += 1
    return (snips, masked)


def self_test():
    fails = []
    doc = {'version': '2.1.0', 'runs': [{'tool': {'driver': {'name': 'bandit'}}, 'results': [
        {'ruleId': 'B105', 'level': 'error',
         'message': {'text': 'Possible hardcoded password: AKIAIOSFODNN7EXAMPLE'},
         'partialFingerprints': {'x': 'deadbeef'},
         'locations': [{'physicalLocation': {
             'artifactLocation': {'uri': 'app/config.py'},
             'region': {'startLine': 12,
                        'snippet': {'text': 'PASSWORD = "AKIAIOSFODNN7EXAMPLE"'}},
             'contextRegion': {'snippet': {'text': 'ctx AKIAIOSFODNN7EXAMPLE'}}}}]}]}]}
    snips, masked = scrub(doc)
    blob = json.dumps(doc)
    if 'AKIAIOSFODNN7EXAMPLE' in blob:
        fails.append('a credential survived scrub()')
    if 'app/config.py' not in blob or '12' not in blob:
        fails.append('scrub() destroyed the file/line needed to fix it')
    if 'AKIA' not in blob:
        fails.append('scrub() removed the prefix identifying WHICH credential')
    if snips < 3:
        fails.append('snippet/contextRegion/partialFingerprints not all removed (%d)' % snips)
    if masked != 1:
        fails.append('message was not masked')
    # Idempotent: running twice must not double-mask or crash.
    s2, m2 = scrub(doc)
    if (s2, m2) != (0, 0):
        fails.append('scrub() is not idempotent (%d,%d on second pass)' % (s2, m2))
    # A clean report must come through untouched.
    clean = {'runs': [{'results': [{'ruleId': 'X', 'message': {'text': 'unused import os'},
                                    'locations': [{'physicalLocation': {
                                        'artifactLocation': {'uri': 'a.py'},
                                        'region': {'startLine': 1}}}]}]}]}
    before = json.dumps(clean)
    scrub(clean)
    if json.dumps(clean) != before:
        fails.append('a clean finding was altered')
    if fails:
        print('SELF-TEST FAILED:')
        for f in fails:
            print('  - %s' % f)
        return False
    print('self-test ok: credential masked, snippet/contextRegion/partialFingerprints removed, '
          'file and line preserved, idempotent, clean findings untouched')
    return True


def _write_back(p, payload):
    """Rewrite p in place with payload. -> None on success, else a short reason string.

    READABLE IS NOT WRITABLE, AND THIS USED TO BE FATAL TOO.

    checkov-action is a CONTAINER action: it runs as root and leaves
    checkov.sarif/results_sarif.sarif owned by root at mode 0644 inside a root-owned
    directory. The runner user could open it for reading -- so json.load() succeeded, scrub()
    succeeded, the self-test passed -- and then died on the write back with
    `PermissionError: [Errno 13] Permission denied`, unhandled, exit 1. Once again a job whose
    SCAN HAD SUCCEEDED went red in its housekeeping.

    Three ways in, cheapest first: the file may merely lack the write bit while still being
    ours (chmod); or it may not be ours while its DIRECTORY is, in which case replacing the
    inode works where writing through it does not.
    """
    try:
        io.open(p, 'w', encoding='utf-8').write(payload)
        return None
    except (OSError, IOError) as e:
        reason = '%s: %s' % (type(e).__name__, e)
    try:
        os.chmod(p, os.stat(p).st_mode | 0o200)
        io.open(p, 'w', encoding='utf-8').write(payload)
        return None
    except (OSError, IOError):
        pass
    tmp = None
    try:
        fd, tmp = tempfile.mkstemp(dir=os.path.dirname(os.path.abspath(p)), suffix='.redacted')
        with io.open(fd, 'w', encoding='utf-8') as fh:
            fh.write(payload)
        os.replace(tmp, p)
        return None
    except (OSError, IOError):
        if tmp and os.path.exists(tmp):
            try:
                os.unlink(tmp)
            except OSError:
                pass
    return reason


def withhold(p):
    """Move a report we could not redact off the upload path. -> the new name, or None.

    FAILING THE STEP DOES NOT STOP THE UPLOAD. Every upload step downstream carries
    `if: always()` -- deliberately, so one scanner's verdict cannot cancel another's
    collection -- which means a red redaction step publishes the unredacted file anyway.
    Exiting non-zero is a complaint, not a control. The only defence that actually works is
    to make the path stop existing.

    Renaming needs write permission on the CONTAINING directory, not on the file. When the
    report is root-owned inside a root-owned directory, the directory the runner CAN rename
    is the one above that, so walk up until a rename succeeds. Never touches the working
    directory itself.
    """
    target = os.path.abspath(p)
    stop = os.path.abspath(os.getcwd())
    while len(target) > len(stop):
        dest = target + '.UNREDACTED-WITHHELD'
        try:
            os.rename(target, dest)
            return dest
        except OSError:
            pass
        parent = os.path.dirname(target)
        if parent == target:
            break
        target = parent
    return None


def _save_or_withhold(p, payload, note):
    """Write payload over p, or take p off the upload path. -> exit-code contribution."""
    err = _write_back(p, payload)
    if not err:
        print('  %s: %s' % (os.path.basename(p), note))
        return EXIT_OK
    dest = withhold(p)
    if dest:
        print('::error title=SARIF withheld, not redacted::%s could not be rewritten in place '
              '(%s), so it was moved to %s and will NOT be uploaded. The scan itself succeeded '
              'and its findings already reached the gate; only the downloadable copy is gone.'
              % (p, err, os.path.basename(dest)))
        return EXIT_WITHHELD
    print('::error title=UNREDACTED SARIF MAY BE PUBLISHED::%s could be neither rewritten (%s) '
          'nor moved out of the upload path. It may still carry credential material.'
          % (p, err))
    return EXIT_UNPROTECTED


def _withhold_all(paths, why):
    """Last resort when nothing can be redacted at all. -> exit-code contribution."""
    rc = EXIT_OK
    for p in paths:
        if not os.path.isfile(p):
            continue
        dest = withhold(p)
        if dest:
            print('::error title=SARIF withheld, not redacted::%s was moved to %s and will NOT '
                  'be uploaded (%s).' % (p, os.path.basename(dest), why))
            rc = max(rc, EXIT_WITHHELD)
        else:
            print('::error title=UNREDACTED SARIF MAY BE PUBLISHED::%s could not be moved out '
                  'of the upload path (%s).' % (p, why))
            rc = max(rc, EXIT_UNPROTECTED)
    return rc


def main():
    argv = [a for a in sys.argv[1:] if not a.startswith('-')]
    if '--self-test' in sys.argv:
        return 0 if self_test() else 2
    if not self_test():
        print('ABORTING -- a redactor that cannot prove it redacts is worse than none.')
        # Aborting alone would still publish every report, because the upload steps run with
        # if: always(). Unproven redaction means the reports must not leave the runner.
        return max(EXIT_SELFTEST, _withhold_all(argv, 'the redactor failed its own self-test'))
    rc = 0
    for p in argv:
        # A DIRECTORY IS NOT A REPORT, AND THIS USED TO BE FATAL.
        #
        # checkov-action treats `output_file_path` as a DIRECTORY and writes the report inside it,
        # so a caller globbing *.sarif hands this function a directory. os.path.exists() said yes,
        # json.load() raised IsADirectoryError, the handler below tried to overwrite the
        # "unparseable report" with an empty one -- and raised IsADirectoryError AGAIN, this time
        # unhandled. A redaction step then failed a job whose SCAN HAD SUCCEEDED, and took the
        # scanner behind it with it. isfile(), not exists(): only a real file can be redacted, and
        # skipping a non-file loses nothing, because a directory never carried a credential.
        if not os.path.isfile(p) or os.path.getsize(p) == 0:
            print('  %s: not a readable SARIF file, nothing to redact' % p)
            continue
        try:
            doc = json.load(io.open(p, encoding='utf-8', errors='replace'))
        except (ValueError, IOError) as e:
            # A SARIF that cannot be parsed cannot be redacted, and must NOT be uploaded on the
            # assumption that it is probably fine. Emptying it loses nothing a reader could
            # have used -- an unparseable report establishes nothing either way -- and it
            # cannot leak what it was carrying.
            print('::warning title=Unredactable SARIF::%s could not be parsed (%s); it is '
                  'replaced with an empty report rather than uploaded unexamined.'
                  % (p, type(e).__name__))
            rc = max(rc, EXIT_UNREADABLE, _save_or_withhold(
                p, json.dumps({'version': '2.1.0', 'runs': [],
                               '_redaction': 'ORIGINAL UNPARSEABLE - WITHHELD'}),
                'unparseable, replaced with an empty report'))
            continue
        snips, masked = scrub(doc)
        rc = max(rc, _save_or_withhold(
            p, json.dumps(doc),
            '%d snippet/fingerprint field(s) removed, %d message(s) masked' % (snips, masked)))
    return rc


if __name__ == '__main__':
    sys.exit(main())

#!/usr/bin/env python3
"""sast-semgrep's PHP range is MEASURED on the Semgrep the job runs, by a probe that can tell
"could not read" (lane L-PHP; D-VF-4, ledger V-02).

WHY THIS EXISTS

    The version_support row sast-semgrep/php/semgrep decides whether a PHP target is SERVED or a
    VERSION_GAP (KDEC-010), and -- once READ -- whether a gap is enforced at uat/prod (KDEC-014). It
    is READ because tests/corpora/probe_php_corpus.py ran the job's own Semgrep image over the
    seeded corpus in tests/corpora/php_corpus.py. A READ row is a claim enforcement acts on, so what
    produced it is held here without the real Semgrep (a stub stands in for it), and the real
    measurement is re-run weekly by .github/workflows/probe-scanner-corpora.yml.

    MEASURED 2026-10-21, locally: the semgrep/semgrep 1.90.0 image the job ran until lane L-SG
    reads the corpus 5.6..7.2 and reports PartialParsing -- exit 3 under the job's --strict -- for
    7.3 (reference assignment in list()), 8.1 (promoted readonly properties), 8.2 (DNF types), 8.3
    (typed class constants) and 8.4 (asymmetric visibility); semgrep 1.178.0 (pip, and its own
    image) reads every family 5.6..8.4 with no error. Lane L-SG moved the job to the 1.178.0 image,
    pinned by digest, and re-measured the row on it (KDEC-016: PHP 8.x must work).

WHAT IS PROVED
    P1  the corpus: every family a distinct, ascending PHP release, its construct before the seed;
        the control is the unparseable body plus the seed
    P2  no .php file is committed under tests/corpora: the seeds are data, never a finding a
        consumer scan or an export of this kit could meet (KDEC-011)
    P3  the probe tells READ / PARSE_ERROR / MISSED / COLLECTION_FAILED apart, and the range is
        contiguous from the oldest family: a silent drop at 8.1 -> ..8.0; a partial parse at 7.3
        -> ..7.2 with the families read above it named, never counted
    P4  the probe REFUSES (no range) when it cannot measure: a control that draws no error, an
        oldest family that is not read, a Semgrep that wrote no report
    P5  --check: a registry claiming more than was measured, a READ row against a refusal, or a row
        that does not name its corpus, fails
    P6  the shipped row: READ, naming this corpus, min the oldest family, max a family, and its basis
        names the Semgrep version the sast-semgrep job's container runs -- so a container change
        without a re-measurement fails here
    P7  --write edits only that entry and keeps the composite copy equal to the registry
    P8  the probe workflow measures the job's own image -- the SAME digest the job pins, with the
        version that digest is -- compares with --check and never writes
    P9  KDEC-016, PHP 8.x is required: the job's image is pinned by digest, the shipped row reads
        at least through KDEC016_FLOOR (8.4), and a ceiling below the corpus's newest family is
        recorded in the basis as that family MEASURED unread. FAILS ON 7fe3d54: the job ran the
        semgrep/semgrep 1.90.0 tag and the row was READ only to 7.2.
    P10 the corpus reaches the newest PHP release line in production use (NEWEST_PHP, below), so a
        target on it is measured rather than a VERSION_GAP by omission. FAILS ON 5569274: PHP 8.5
        is in production use (php.net ChangeLog-8 lists 8.5.12 as a fixed release in the
        php2shell advisory) and the corpus stopped at 8.4.
    P11 KDEC-016 amended 2026-10-22 (owner: "scan what parses, flag the rest"): the probe measures
        a parse-evidence ceiling -- the newest family in the contiguous run of PARSE_ERROR families
        directly above the read ceiling (a file Semgrep NAMES as not fully parsed, which the job
        flags PARTIAL); a silent drop (MISSED) never extends it; --check compares it; the shipped
        row carries 8.5 and says so in its basis. FAILS ON 2cd078e: no parse_evidence_max, so PHP
        8.5 was a proven VERSION_GAP refused at uat/prod.

EXIT 0 all hold; 1 one does not; 2 could not be checked.
"""
import io
import json
import os
import re
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
CORPORA = os.path.join(HERE, 'corpora')
sys.path.insert(0, CORPORA)
WORKFLOW = os.path.join(ROOT, '.github', 'workflows', 'probe-scanner-corpora.yml')
FLAGSHIP = os.path.join(ROOT, '.github', 'workflows', 'reusable-security.yml')
STUB = os.path.join(CORPORA, 'stub_php_semgrep.py')
KEYS = ('stub_unreadable', 'stub_partial', 'stub_crash', 'stub_silent')
# The newest PHP release line in production use. Raise it, and add its family to
# tests/corpora/php_corpus.py, when php.net ships a new minor: until then a target on it is a
# VERSION_GAP only because nobody measured it. 8.5: php.net ChangeLog-8 lists 8.5.12 (2026-10-21).
NEWEST_PHP = '8.5'
# The newest family the job's Semgrep (1.178.0) was measured to read, locally in its image on
# 2026-10-21. A row below it is a regression. 8.5 was measured PARSE_ERROR on 1.178.0 (the (void)
# cast and final promoted properties draw PartialParsing; the pipe operator parses), and on 1.182.0.
KDEC016_FLOOR = '8.4'
# The newest family the job's Semgrep NAMES per file when it cannot fully parse it (PARSE_ERROR,
# never MISSED): PHP 8.5, measured 2026-10-21/22. Up to it the job's parse evidence decides coverage
# (owner, 2026-10-22: "scan what parses, flag the rest"; KDEC-016 amended).
PARSE_EVIDENCE_85 = '8.5'


def stub_cmd():
    # Forward slashes: the probe splits --cmd POSIX-style, which would eat a Windows backslash.
    return '"%s" -I "%s"' % (sys.executable.replace('\\', '/'), STUB.replace('\\', '/'))


def run_measure(P, **env):
    saved = {k: os.environ.get(k) for k in KEYS}
    try:
        for k in KEYS:
            os.environ.pop(k, None)
        os.environ.update(env)
        return P.measure(stub_cmd())
    finally:
        for k, v in saved.items():
            if v is None:
                os.environ.pop(k, None)
            else:
                os.environ[k] = v


def shipped_semgrep_version():
    """-> (image, version, problem): tests/_semgrep_pin.py reads the job's digest pin and the
    version its line names."""
    sys.path.insert(0, HERE)
    import _semgrep_pin
    return _semgrep_pin.flagship(FLAGSHIP)


def main():
    try:
        import yaml
        import php_corpus as C
        import probe_php_corpus as P
    except ImportError as e:
        print('UNKNOWN: %s' % e)
        return 2
    bad = []
    names = C.family_names()

    # P1 the corpus
    vt = [tuple(int(x) for x in f.split('.')) for f in names]
    if vt != sorted(vt) or len(set(vt)) != len(vt):
        bad.append('P1 families are not distinct and ascending: %s' % names)
    for fam, construct, body in C.FAMILIES:
        src = C.source(fam)
        if not construct or not body.strip() or C.SEED not in src or src.index(body) > src.index(C.SEED):
            bad.append('P1 family %s does not hold its construct before the seed' % fam)
    if C.SEED not in C.source(C.CONTROL) or C.control_body not in C.source(C.CONTROL):
        bad.append('P1 the control is not the unparseable body plus the seed')
    print('  P1 corpus: %d families %s..%s, one control' % (len(names), names[0], names[-1]))

    # P2 never committed as PHP
    committed = [os.path.relpath(os.path.join(d, f), ROOT) for d, _ds, fs in os.walk(CORPORA)
                 for f in fs if f.lower().endswith(('.php', '.phtml', '.inc'))]
    if committed:
        bad.append('P2 PHP files are committed under tests/corpora: %s' % committed)
    print('  P2 nothing under tests/corpora is a PHP file: %s' % ('held' if not committed else committed))

    # P3 the outcomes and the contiguous range
    # The last field: parse_evidence_max (P11) -- the newest family in the CONTIGUOUS run of
    # PARSE_ERROR families directly above the read ceiling. A silent drop (MISSED) never extends
    # it: only a file Semgrep NAMES as not fully parsed can be flagged by the job's parse evidence.
    cases = [
        ('silent drop at 8.1', {'stub_unreadable': 'enum Suit'}, '8.0', '8.1', 'MISSED',
         names[names.index('8.1') + 1:], None),
        ('partial parse at 7.3', {'stub_partial': '[$first, &$second]'}, '7.2', '7.3', 'PARSE_ERROR',
         names[names.index('7.3') + 1:], '7.3'),
        ('partial 8.1, drop 8.2', {'stub_partial': 'readonly', 'stub_unreadable': ')|null'},
         '8.0', '8.1', 'PARSE_ERROR', names[names.index('8.3'):], '8.1'),
        ('reads every family', {}, names[-1], None, None, [], None),
    ]
    for label, env, want_max, want_first, want_state, want_above, want_pe in cases:
        r = run_measure(P, **env)
        got = (r.get('min'), r.get('max'), r.get('first_unread'), r.get('read_above_ceiling'))
        if 'refused' in r or got != (names[0], want_max, want_first, want_above):
            bad.append('P3 %s: got %r (refused=%r), want min %s max %s first_unread %s above %s'
                       % (label, got, r.get('refused'), names[0], want_max, want_first, want_above))
        pe = P.parse_evidence_max(r) if hasattr(P, 'parse_evidence_max') else 'NO FUNCTION'
        if pe != want_pe:
            bad.append('P11 %s: parse_evidence_max %r, want %r' % (label, pe, want_pe))
        states = {p['family']: p['state'] for p in r['families']}
        if want_first and states.get(want_first) != want_state:
            bad.append('P3 %s: %s is %s, want %s' % (label, want_first, states.get(want_first), want_state))
        print('  P3 %-22s -> %s..%s first unread %s' % (label, r.get('min'), r.get('max'),
                                                         r.get('first_unread')))

    # P4 refusals
    r = run_measure(P, stub_silent='1')
    if 'refused' not in r or 'control' not in r['refused']:
        bad.append('P4 a Semgrep silent about the unparseable control was given a range: %r' % r)
    r = run_measure(P, stub_unreadable='...$numbers')
    if 'refused' not in r or 'oldest family' not in r['refused']:
        bad.append('P4 a Semgrep that cannot read the oldest family was given a range: %r' % r)
    r = run_measure(P, stub_crash='1')
    if 'refused' not in r or 'did not run' not in r['refused']:
        bad.append('P4 a Semgrep that wrote no report was given a range: %r' % r)
    print('  P4 refusals: silent control, unreadable oldest family, no report -- all refused')

    # P5 --check compares
    measured = {'tool': 'semgrep', 'min': '5.6', 'max': '7.2', 'families': []}
    row = {'tool': 'semgrep', 'min': '5.6', 'max': '8.4', 'verified': 'READ', 'corpus': P.corpus_id}
    if not P.compare(measured, row):
        bad.append('P5 a registry claiming 8.4 against a measured 7.2 passed --check')
    if P.compare(dict(measured, max='8.4'), row):
        bad.append('P5 an exact match failed --check')
    if not P.compare({'tool': 'semgrep', 'refused': 'x', 'families': []}, row):
        bad.append('P5 a READ row against a refused measurement passed --check')
    if not P.compare(dict(measured, max='8.4'), dict(row, corpus=None)):
        bad.append('P5 a row that does not name its corpus passed --check')
    # P11 the parse-evidence ceiling is a measurement too: a row claiming one nobody measured, or
    # omitting one that was, fails --check.
    fams = [{'family': f, 'state': 'READ'} for f in names[:names.index('8.4') + 1]] + \
        [{'family': '8.5', 'state': 'PARSE_ERROR'}]
    m85 = dict(measured, max='8.4', families=fams)
    if P.compare(m85, dict(row, parse_evidence_max='8.5')):
        bad.append('P11 a row whose parse_evidence_max equals the measured one failed --check')
    if not P.compare(m85, row):
        bad.append('P11 a row omitting the measured parse_evidence_max 8.5 passed --check')
    if not P.compare(dict(m85, families=fams[:-1] + [{'family': '8.5', 'state': 'MISSED'}]),
                     dict(row, parse_evidence_max='8.5')):
        bad.append('P11 a row claiming parse evidence over a SILENTLY dropped family passed --check')

    # P6 the shipped row, and the tool it was measured on
    reg = yaml.safe_load(io.open(os.path.join(ROOT, 'scanner-registry.yaml'), encoding='utf-8'))
    e = ((reg['version_support'].get('sast-semgrep') or {}).get('php') or [{}])[0]
    image, version, pin_problem = shipped_semgrep_version()
    if not (e.get('verified') == 'READ' and e.get('corpus') == P.corpus_id
            and e.get('min') == names[0] and e.get('max') in names
            and 'MEASURED' in (e.get('basis') or '')):
        bad.append('P6 the shipped sast-semgrep/php row is not a corpus measurement: %r' % e)
    if not version or ('semgrep %s ' % version) not in (e.get('basis') or ''):
        bad.append('P6 the row was not measured on the Semgrep the job runs (%s): basis %r'
                   % (image, (e.get('basis') or '')[:160]))
    print('  P6 shipped: semgrep php %s..%s %s, measured on %s (%s)'
          % (e.get('min'), e.get('max'), e.get('verified'), image, version))

    # P9 KDEC-016: PHP 8.x is required. The row may not fall below what the job's Semgrep was
    # measured to read (KDEC016_FLOOR), and a ceiling below the corpus's newest family must be a
    # MEASURED one: its basis names the next family as unread, never silence.
    if pin_problem:
        bad.append('P9 %s' % pin_problem)

    def vt(v):
        return tuple(int(x) for x in str(v).split('.')) if v and v in names else (0,)
    if vt(e.get('max')) < vt(KDEC016_FLOOR):
        bad.append('P9 KDEC-016 requires PHP 8.x: the shipped row reads PHP only to %s, below the %s '
                   'the job\'s Semgrep was measured to read' % (e.get('max'), KDEC016_FLOOR))
    if e.get('max') != names[-1]:
        nxt = names[names.index(e['max']) + 1] if e.get('max') in names[:-1] else None
        if not nxt or not re.search(r'%s was (PARSE_ERROR|MISSED)' % re.escape(nxt),
                                    e.get('basis') or ''):
            bad.append('P9 the row stops at %s below the corpus newest %s and its basis does not '
                       'record %s as measured unread' % (e.get('max'), names[-1], nxt))
    print('  P9 KDEC-016: image digest-pinned=%s, row max %s (floor %s), corpus newest %s'
          % (pin_problem is None, e.get('max'), KDEC016_FLOOR, names[-1]))

    # P11 KDEC-016 amended 2026-10-22 (owner): PHP 8.5 is "scan what parses, flag the rest". The
    # shipped row carries the MEASURED parse-evidence ceiling (8.5 was PARSE_ERROR on the job's
    # Semgrep -- named per file, never silent), and its basis says the job's parse evidence
    # handles it. FAILS ON 2cd078e: the row had no parse_evidence_max, so 8.5 was a proven gap.
    if str(e.get('parse_evidence_max')) != PARSE_EVIDENCE_85 \
            or 'parse evidence' not in (e.get('basis') or '') \
            or not re.search(r'%s was PARSE_ERROR' % re.escape(PARSE_EVIDENCE_85), e.get('basis') or ''):
        bad.append('P11 the shipped row does not carry the measured parse-evidence ceiling %s with a '
                   'basis saying the job\'s parse evidence handles it: parse_evidence_max=%r'
                   % (PARSE_EVIDENCE_85, e.get('parse_evidence_max')))
    print('  P11 parse evidence: row parse_evidence_max %s (8.5 measured PARSE_ERROR, named per file)'
          % e.get('parse_evidence_max'))

    # P10 the corpus reaches the newest PHP line in production use
    if names[-1] != NEWEST_PHP:
        bad.append('P10 the corpus stops at %s, but PHP %s is in production use: a %s target would '
                   'be a VERSION_GAP because it was never measured, not because Semgrep cannot '
                   'read it' % (names[-1], NEWEST_PHP, NEWEST_PHP))
    print('  P10 corpus newest %s, newest PHP in production use %s' % (names[-1], NEWEST_PHP))

    # P7 --write is surgical, and the composite copy stays equal
    reg_text = io.open(os.path.join(ROOT, 'scanner-registry.yaml'), encoding='utf-8').read()
    new = P.write_registry(reg_text, {'min': '"5.6"', 'max': '"7.0"', 'verified': 'READ',
                                      'basis': '"x"', 'corpus': P.corpus_id})
    import difflib
    before, after = reg_text.split('\n'), new.split('\n')
    # Every line removed or added must sit inside the one entry: at most its five scalar fields
    # rewritten and one (corpus) appended.
    delta = [ln for ln in difflib.unified_diff(before, after, lineterm='', n=0)
             if ln[:1] in '+-' and not ln.startswith(('+++', '---'))]
    doc = yaml.safe_load(new)
    e2 = doc['version_support']['sast-semgrep']['php'][0]
    want = dict(reg, version_support=dict(reg['version_support'], **{
        'sast-semgrep': dict(reg['version_support']['sast-semgrep'], php=[e2])}))
    if len(delta) > 11 or any(not ln[1:].startswith('        ') for ln in delta) \
            or e2['max'] != '7.0' or doc != want \
            or [ln for ln in before if ln.lstrip().startswith('#')] != \
               [ln for ln in after if ln.lstrip().startswith('#')]:
        bad.append('P7 --write changed more than the one entry: %s' % delta[:12])
    act = io.open(os.path.join(ROOT, '.github', 'actions', 'resolve', 'action.yml'), encoding='utf-8').read()
    act2 = P.write_action_copy(act, doc['version_support'])
    m = re.search(r"<<'JSON'\n(.*?)\n        JSON\n", act2, re.S)
    if not m or json.loads(m.group(1)) != doc['version_support']:
        bad.append('P7 the composite copy written by --write is not equal to the registry')
    if P.write_action_copy(act, reg['version_support']) != act:
        bad.append('P7 the shipped composite copy is not what --write produces from the registry')
    print('  P7 --write: one entry, and the composite copy equals the registry')

    # P8 the workflow
    wf = yaml.safe_load(io.open(WORKFLOW, encoding='utf-8'))
    jobs = wf.get('jobs') or {}
    job = jobs.get('semgrep-php') or {}
    text = '\n'.join(str(s.get('run', '')) + '\n' + str((s.get('env') or {})) for s in job.get('steps') or [])
    pin = re.search(r'semgrep/semgrep@sha256:[0-9a-f]{64}', text)
    if not job:
        bad.append('P8 probe-scanner-corpora.yml has no semgrep-php job')
    else:
        if not pin:
            bad.append('P8 the semgrep image is not pulled by digest')
        elif pin.group(0) != image:
            bad.append('P8 the probe measures %s, not the image the sast-semgrep job runs (%s)'
                       % (pin.group(0), image))
        if not version or ('--tool-version %s ' % version) not in text \
                or version not in str(job.get('name', '')):
            bad.append('P8 the job does not record the version the sast-semgrep job runs (%s) as '
                       '--tool-version and in its name' % version)
        if 'probe_php_corpus.py' not in text or '--check' not in text or '--write' in text:
            bad.append('P8 the job does not --check with probe_php_corpus.py, or it writes')
        if not job.get('timeout-minutes') or job.get('permissions'):
            bad.append('P8 the job has no timeout, or widens permissions')
    print('  P8 workflow: the job\'s image by digest, --check, never --write')

    print()
    if bad:
        for b in bad:
            print('FAIL: %s' % b)
        return 1
    print('PASS: the PHP range is a corpus measurement of the Semgrep the job runs; the probe tells a '
          'partial parse and a silent drop from a read, and refuses what it cannot measure.')
    return 0


if __name__ == '__main__':
    sys.exit(main())

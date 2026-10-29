#!/usr/bin/env python3
"""A stand-in Semgrep for tests/prove_php_corpus.py -- never a measurement.

Invoked exactly as tests/corpora/probe_php_corpus.py invokes Semgrep (`scan --config RULE ...
--json-output=FILE FILE...`), it writes a Semgrep-shaped JSON reporting the corpus seed for every
file it "can read". What it cannot read is set by the environment, so the proof can make the probe
meet every outcome it must tell apart:

    stub_unreadable   comma-separated substrings; a file containing one is DROPPED silently (no
                      result, no error) -- the failure the corpus exists to see
    stub_partial      comma-separated substrings; a file containing one draws a PartialParsing
                      error (and the seed is still reported, as Semgrep 1.90.0 did)
    stub_crash        "1": exit 2 and write no report
    stub_silent       "1": the unparseable control draws no error (the control must catch this)
"""
import json
import os
import sys

UNPARSEABLE = 'public function oops( {'


def main(argv):
    out = next(a.split('=', 1)[1] for a in argv if a.startswith('--json-output='))
    if os.environ.get('stub_crash') == '1':
        sys.stderr.write('stub: crashed\n')
        return 2
    files = [a for a in argv if a.endswith('.php')]
    results, errors = [], []
    drop = [x for x in os.environ.get('stub_unreadable', '').split(',') if x]
    part = [x for x in os.environ.get('stub_partial', '').split(',') if x]
    for f in files:
        text = open(f, encoding='utf-8').read()
        if any(s in text for s in drop):
            continue
        broken = UNPARSEABLE in text
        if broken and os.environ.get('stub_silent') == '1':
            continue
        if broken or any(s in text for s in part):
            errors.append({'code': 3, 'level': 'warn', 'type': ['PartialParsing', []], 'path': f,
                           'spans': [{'file': f, 'start': {'line': 1}}]})
            if broken:
                continue
        line = text.count('\n', 0, text.index('system(')) + 1
        results.append({'check_id': 'tmp.corpus-php-seed', 'path': f, 'start': {'line': line}})
    with open(out, 'w', encoding='utf-8') as fh:
        json.dump({'results': results, 'errors': errors, 'paths': {'scanned': files}}, fh)
    return 3 if errors and '--strict' in argv else 0


if __name__ == '__main__':
    sys.exit(main(sys.argv[1:]))

#!/usr/bin/env python3
"""A stand-in IaC scanner for tests/prove_iac_corpus.py -- never a measurement.

Invoked exactly as tests/corpora/probe_iac_corpus.py invokes checkov (`-d DIR ... -o json`, report
on stdout) or trivy (`config --format json --output FILE ... DIR`), it reports the seeded rule for a
main.tf it "can read". What it cannot read is set by the environment, so the proof can make the
probe meet every outcome it must tell apart:

    stub_unreadable   comma-separated substrings; a file containing one is DROPPED silently (exit 0,
                      an empty report) -- the failure the corpus exists to see
    stub_crash        a substring; a file containing it makes the stub exit 2 with no report
    stub_lenient      "1": an unparseable file is still reported (the control must catch this)
"""
import json
import os
import sys

UNPARSEABLE = '[1, 2\n'


def readable(text):
    for s in [x for x in os.environ.get('stub_unreadable', '').split(',') if x]:
        if s in text:
            return False
    if UNPARSEABLE in text and os.environ.get('stub_lenient') != '1':
        return False
    return True


def main(argv):
    trivy = bool(argv) and argv[0] == 'config'
    directory = argv[-1] if trivy else argv[argv.index('-d') + 1]
    path = os.path.join(directory, 'main.tf')
    text = open(path, encoding='utf-8').read()
    crash = os.environ.get('stub_crash')
    if crash and crash in text:
        sys.stderr.write('stub: crashed reading %s\n' % path)
        return 2
    hit = readable(text)
    if trivy:
        out = argv[argv.index('--output') + 1]
        mis = [{'ID': 'AWS-0107', 'AVDID': 'AVD-AWS-0107', 'Status': 'FAIL'}] if hit else []
        doc = {'SchemaVersion': 2, 'Results': [{'Target': 'main.tf', 'Misconfigurations': mis}]}
        with open(out, 'w', encoding='utf-8') as f:
            json.dump(doc, f)
        return 0
    failed = [{'check_id': 'ckv_aws_24'.upper(), 'file_path': '/main.tf'}] if hit else []
    print(json.dumps({'check_type': 'terraform', 'results': {'failed_checks': failed},
                      'summary': {'failed': len(failed)}}))
    return 0


if __name__ == '__main__':
    sys.exit(main(sys.argv[1:]))

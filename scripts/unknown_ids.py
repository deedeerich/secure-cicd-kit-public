#!/usr/bin/env python3
"""Unknown ids are never lost: logged durably, and routed to a person for mapping (owner ruling, 2026-11-06).

THE RULING
    "Unknown formats shouldn't just be lost; they should at least be logged and have a human review." So any
    CWE, vulnerability id, SAST rule or other id form the kit does not recognise (scripts/finding_ids.py
    CWE_FORM_UNKNOWN / VULN_ID_FORM_UNKNOWN; scripts/code_finding_key.py RULE_FAMILY_UNKNOWN):

      a  is RECORDED in a durable log: `unknown-ids.json` beside findings.json in the report's evidence
         artifact (and beside an external pull's output), one entry per (kind, tool, rule, raw id) with
         the source, the reason and the COUNT seen in the run;
      b  is ROUTED TO A PERSON: each entry becomes one review record the kit's own ticket reconciler reads
         beside findings.json -- a `triage` / needs-mapping item, labelled `needs-mapping` and
         `needs-human-review`, keyed by a review key over (kind, tool, rule, raw id). The reconciler looks up
         by that key before it creates, so repeated runs keep ONE item, never a new one per run;
      c  is never dropped and never guessed into a family: an unknown stays unknown until a person maps it.

    A PERSON MAPS IT in `id-mappings.json` at the repository root (protect it with CODEOWNERS): a reviewed
    change carrying the author, the date and the review reference. code_finding_key and finding_ids read
    only entries that carry all three; an entry missing one is refused by name and applies nothing.

USAGE   from unknown_ids import UnknownLog, review_records, load_mappings
        python3 scripts/unknown_ids.py --self-test
"""
import datetime
import hashlib
import io
import json
import os
import re
import sys

FILENAME = 'unknown-ids.json'
SCHEMA = 'kit-unknown-ids/1'
MAPPINGS_FILE = 'id-mappings.json'
MAPPINGS_SCHEMA = 'kit-id-mappings/1'
NEEDS_MAPPING = 'NEEDS_MAPPING'
MAPPING_NOT_REVIEWED = 'MAPPING_NOT_REVIEWED'
REVIEW_LABELS = ('needs-mapping', 'needs-human-review')
KINDS = ('cwe', 'vuln-id', 'rule-family')


def review_key(kind, tool, rule, raw):
    return hashlib.sha256(('kit-id-review/1|%s|%s|%s|%s' % (kind, str(tool or '').lower(), str(rule or ''),
                                                           str(raw or ''))).encode('utf-8')).hexdigest()[:32]


class UnknownLog(object):
    """Accumulates unknown ids for one run, counting repeats. Nothing recorded is ever removed."""

    def __init__(self):
        self._e = {}

    def record(self, kind, tool, rule, raw, source, reason):
        k = review_key(kind, tool, rule, raw)
        e = self._e.get(k)
        if e is None:
            e = self._e[k] = {'review_key': k, 'kind': kind, 'tool': str(tool or ''), 'rule': str(rule or ''),
                              'raw': str(raw if raw is not None else '')[:200], 'source': str(source or '')[:200],
                              'reason': str(reason or '')[:400], 'count': 0, 'state': NEEDS_MAPPING}
        e['count'] += 1
        return k

    def entries(self):
        return sorted(self._e.values(), key=lambda e: (e['kind'], e['tool'], e['rule'], e['raw']))

    def write(self, path):
        doc = {'schema': SCHEMA, 'written_at': datetime.datetime.utcnow().strftime('%Y-%m-%dT%H:%M:%SZ'),
               'entries': self.entries()}
        with io.open(path, 'w', encoding='utf-8', newline='\n') as fh:
            json.dump(doc, fh, indent=1, sort_keys=True)
        return len(doc['entries'])


def load(path):
    """-> entries, [] when the file is absent. A file that exists and does not parse RAISES: an unreadable
    log is not an empty one."""
    if not path or not os.path.exists(path):
        return []
    with io.open(path, encoding='utf-8') as fh:
        doc = json.load(fh)
    if not isinstance(doc, dict) or doc.get('schema') != SCHEMA or not isinstance(doc.get('entries'), list):
        raise ValueError('%s is not a %s document' % (path, SCHEMA))
    return doc['entries']


def review_records(entries):
    """-> the records the ticket reconciler reads (scripts/reconcile_tickets.py build_clusters): one per
    review key, FINGERPRINTED on that key, so the lookup-before-create holds one item per unknown."""
    out = []
    for e in entries or []:
        k = e.get('review_key') or review_key(e.get('kind'), e.get('tool'), e.get('rule'), e.get('raw'))
        title = 'Needs mapping: %s %r from %s %s' % (e.get('kind'), e.get('raw'), e.get('tool') or 'unknown tool',
                                                     e.get('rule') or '')
        out.append({
            'identity': k, 'state': 'FINGERPRINTED', 'identity_state': 'FINGERPRINTED',
            'finding_subject': 'POLICY', 'where': 'kit-id-review', 'uri': 'kit-id-review/%s' % (e.get('tool') or 'unknown'),
            'canonical_path': 'kit-id-review/%s' % (e.get('tool') or 'unknown'),
            'rule': 'needs-mapping', 'rule_id': 'needs-mapping', 'scanner': e.get('tool') or 'kit',
            'tool': e.get('tool') or 'kit', 'severity': 'info', 'job': 'id-review', 'fp': '',
            'what_aliases': [str(e.get('raw') or '').lower()], 'line': None,
            'template': 'triage', 'template_labels': list(REVIEW_LABELS), 'kit_class': 'needs-mapping',
            'title': title[:200], 'review': {'kind': e.get('kind'), 'tool': e.get('tool'), 'rule': e.get('rule'),
                                             'raw': e.get('raw'), 'source': e.get('source'),
                                             'reason': e.get('reason'), 'count': e.get('count', 1)},
        })
    return out


def load_mappings(root):
    """-> (applied, refused). Only REVIEWED entries apply: author, date (YYYY-MM-DD) and review_ref present.
    rule-family {tool, rule, family}; cwe-form {raw, canonical}; vuln-id-form {raw, canonical}."""
    p = os.path.join(root or '.', MAPPINGS_FILE)
    if not os.path.exists(p):
        return [], []
    try:
        doc = json.load(io.open(p, encoding='utf-8'))
    except ValueError as e:
        return [], ['%s: %s does not parse (%s); no mapping applied' % (MAPPING_NOT_REVIEWED, MAPPINGS_FILE, e)]
    applied, refused = [], []
    for i, m in enumerate((doc or {}).get('mappings') or []):
        miss = [k for k in ('author', 'date', 'review_ref') if not str((m or {}).get(k) or '').strip()]
        if not miss and not re.match(r'^\d{4}-\d{2}-\d{2}$', str(m.get('date'))):
            miss.append('date as YYYY-MM-DD')
        need = {'rule-family': ('tool', 'rule', 'family'), 'cwe-form': ('raw', 'canonical'),
                'vuln-id-form': ('raw', 'canonical')}.get((m or {}).get('kind'))
        if need is None:
            refused.append('%s: mapping %d has kind %r' % (MAPPING_NOT_REVIEWED, i, (m or {}).get('kind')))
            continue
        miss += [k for k in need if not str(m.get(k) or '').strip()]
        if miss:
            refused.append('%s: mapping %d (%s) lacks %s' % (MAPPING_NOT_REVIEWED, i, m.get('kind'), ', '.join(miss)))
            continue
        applied.append(m)
    return applied, refused


def self_test():
    log = UnknownLog()
    a = log.record('rule-family', 'semgrep', 'x.y.z', 'x.y.z', 'semgrep', 'RULE_FAMILY_UNKNOWN')
    b = log.record('rule-family', 'semgrep', 'x.y.z', 'x.y.z', 'semgrep', 'RULE_FAMILY_UNKNOWN')
    log.record('cwe', 'bandit', 'B999', 'CWE#79', 'bandit', 'CWE_FORM_UNKNOWN')
    bad = []
    if a != b or len(log.entries()) != 2 or log.entries()[1]['count'] != 2:
        bad.append('repeats must count on one entry: %r' % log.entries())
    recs = review_records(log.entries())
    if len({r['identity'] for r in recs}) != 2 or any('needs-mapping' not in r['template_labels'] for r in recs):
        bad.append('one review record per key, labelled: %r' % recs)
    for b_ in bad:
        print('SELF-TEST FAIL: %s' % b_)
    print('self-test %s' % ('FAILED' if bad else 'ok'))
    return 1 if bad else 0


if __name__ == '__main__':
    sys.exit(self_test() if '--self-test' in sys.argv else 0)

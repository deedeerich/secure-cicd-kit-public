#!/usr/bin/env python3
"""The plain-English error layer: every refusal the kit can show a developer, said in plain words first.

WHY THIS EXISTS (owner, 2026-11-06)
    Developers are new to this way of working. A run that ends `::error title=BLOCKED::a control refused
    this run (see the posture record)` is accurate and useless to someone who has never seen a posture
    record. docs/errors/errors.json gives every refusal or failure state the kit's taxonomy holds a plain
    sentence (what happened), why it matters, the exact fix, and a link; the state name follows in
    brackets so the precise word is never lost.

COMMANDS
    summary  --states "ns:STATE ns:A,B STATE" [--source gate]   (the workflows call this through
             .github/actions/plain-errors) For every state that is a failure: an annotation whose TITLE is
             the plain sentence (annotations sit at the top of the run page, above every log and job
             summary, so it is read first) and a "What happened, in plain words" section in the step summary.
             A state the catalogue has no entry for is still shown, by name, never dropped. Exit 0 always:
             explaining a failure must never become one.
    explain  STATE [...]           print the plain entry (ns.STATE or a bare STATE)
    render   [--write]             docs/errors/ERRORS.md from the JSON (print, or write)
    check                          the catalogue against assurance-taxonomy.yaml (below)
    --self-test                    the check refuses a missing entry and an unscoped namespace (mutants)

THE CHECK (exit 1 naming each problem)
    C1  every taxonomy namespace is scoped: `developer`, or `internal: <why, five words or more>`
    C2  every value of a developer namespace has an entry, or is listed in not_a_failure
    C3  every entry has what (one sentence, ending in a full stop), why, fix and a link to a file that
        exists; a same_as points at a full entry; an entry names a real value of its namespace
    C4  no value is both an entry and not_a_failure
    C5  docs/errors/ERRORS.md is exactly what `render` produces
EXIT  0 held   1 a rule refused   2 could not run (the JSON or, for check, PyYAML unavailable)
"""
import argparse
import io
import json
import os
import re
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
CATALOGUE = os.path.join(ROOT, 'docs', 'errors', 'errors.json')
ERRORS_MD = os.path.join(ROOT, 'docs', 'errors', 'ERRORS.md')
TAXONOMY = os.path.join(ROOT, 'assurance-taxonomy.yaml')
# Shown as a warning, not an error: the run continues and a person should still read it.
WARN_NAMESPACES = {'advisory_cause', 'policy_notice', 'control_weakening', 'leak_gate_state', 'feed_mirror',
                   'version_applicability', 'discovery_state', 'coverage_state', 'scan_partial_reason',
                   'tier_source', 'tier_reality', 'kit_watermark', 'evidence_retention', 'exception_resurfacing',
                   'edge_purge', 'api_boundary', 'publication_state', 'dependabot_triage_rule',
                   'human_control_availability', 'remediation_track_state', 'capability_floor_state'}
WARN_STATES = {'routing_result.PROCEED_WITH_ADVISORY', 'routing_result.DECISION_REQUIRED',
               'kit_init_state.KIT_INIT_HUMAN_EDIT_PRESERVED', 'known_exploited.UNAVAILABLE',
               'known_exploited.EXCEPTED'}
ERROR_STATES = {'capability_floor_state.BREACHED'}


def load(path=None):
    with io.open(path or CATALOGUE, encoding='utf-8') as fh:
        return json.load(fh)


def resolve(cat, key):
    """-> (key, entry) following same_as, or (key, None)."""
    seen = set()
    ent = cat['entries'].get(key)
    while ent and 'same_as' in ent and key not in seen:
        seen.add(key)
        key = ent['same_as']
        ent = cat['entries'].get(key)
    return key, ent


def lookup(cat, token):
    """`ns.STATE`, `ns:STATE` or a bare `STATE` -> [(full key, entry or None, is_ok)]."""
    token = token.strip()
    if not token:
        return []
    m = re.match(r'^([a-z_][a-z0-9_]*)[.:](.+)$', token)
    if m:
        ns, state = m.group(1), m.group(2)
        key = '%s.%s' % (ns, state)
        if state in cat['not_a_failure'].get(ns, []):
            return [(key, None, True)]
        k2, ent = resolve(cat, key)
        return [(key, ent, False)]
    hits = [k for k in cat['entries'] if k.split('.', 1)[1] == token]
    oks = [ns for ns, vals in cat['not_a_failure'].items() if token in vals]
    if not hits and oks:
        return [('%s.%s' % (oks[0], token), None, True)]
    if not hits:
        return [('?.%s' % token, None, False)]
    return [(k, resolve(cat, k)[1], False) for k in hits]


def parse_states(text):
    """'routing_result:BLOCKED advisory_cause:A,B STATE' -> ['routing_result.BLOCKED', 'advisory_cause.A', ...]."""
    out = []
    for tok in re.split(r'[\s;]+', text or ''):
        if not tok:
            continue
        m = re.match(r'^([a-z_][a-z0-9_]*):(.*)$', tok)
        if m:
            for v in m.group(2).split(','):
                v = v.strip()
                # a value may carry a detail after a colon (NO_KIT_ADAPTER:aks); the state is the head
                v = v.split(':', 1)[0]
                if v:
                    out.append('%s.%s' % (m.group(1), v))
        else:
            out.extend(v.strip() for v in tok.split(',') if v.strip())
    seen, uniq = set(), []
    for s in out:
        if s not in seen:
            seen.add(s)
            uniq.append(s)
    return uniq


def esc_data(s):
    return s.replace('%', '%25').replace('\r', '%0D').replace('\n', '%0A')


def esc_prop(s):
    return esc_data(s).replace(':', '%3A').replace(',', '%2C')


def link_url(link):
    base = os.environ.get('KIT_DOCS_BASE', '')
    return (base.rstrip('/') + '/' + link) if base else link


def level_of(key):
    ns = key.split('.', 1)[0]
    if key in ERROR_STATES:
        return 'error'
    if key in WARN_STATES or ns in WARN_NAMESPACES:
        return 'warning'
    return 'error'


def explain_lines(cat, tokens):
    """-> list of (level, key, state, entry-or-None) for every failure token (ok states skipped)."""
    out = []
    for tok in tokens:
        for key, ent, is_ok in lookup(cat, tok):
            if is_ok:
                continue
            out.append((level_of(key), key, key.split('.', 1)[1], ent))
    return out


def summary(cat, tokens, source, out=sys.stdout, summary_path=None):
    rows = explain_lines(cat, tokens)
    if not rows:
        return 0
    md = ['### What happened, in plain words%s' % (' (%s)' % source if source else ''), '']
    for level, key, state, ent in rows:
        if ent is None:
            title = 'The run ended in a state the plain-English catalogue does not describe yet.'
            out.write('::%s title=%s::%s [%s] See %s\n' % (level, esc_prop(title), esc_data(
                'Search docs/errors/ERRORS.md and the kit\'s taxonomy for it, and tell the platform team it needs an entry.'),
                state, esc_data(link_url('docs/errors/ERRORS.md'))))
            md += ['- **%s** [%s]' % (title, state), '']
            continue
        out.write('::%s title=%s::%s Fix: %s [%s] See %s\n' % (
            level, esc_prop(ent['what'][:240]), esc_data(ent['why']), esc_data(ent['fix']), state,
            esc_data(link_url(ent['link']))))
        md += ['- **%s** [%s]' % (ent['what'], state), '  - Why it matters: %s' % ent['why'],
               '  - Fix: %s' % ent['fix'], '  - More: %s' % link_url(ent['link']), '']
    path = summary_path if summary_path is not None else os.environ.get('GITHUB_STEP_SUMMARY')
    if path:
        with io.open(path, 'a', encoding='utf-8') as fh:
            fh.write('\n'.join(md) + '\n')
    else:
        out.write('\n'.join(md) + '\n')
    return 0


# ── the human catalogue ──────────────────────────────────────────────────────────────────────────
def render(cat):
    L = ['# What the kit\'s errors mean, in plain words', '',
         '<!-- GENERATED by `python3 scripts/plain_errors.py render --write` from docs/errors/errors.json. '
         'Edit the JSON, then regenerate; `scripts/plain_errors.py check` fails when this file drifts. -->', '',
         'Every refusal or failure the kit can show you, written for someone new to security tooling. Each entry '
         'says **what happened**, **why it matters**, **the exact fix**, and where to read more. The state\'s '
         'exact name is in brackets after the plain sentence: it is the word to search for in a log, and the '
         'word to quote when you ask for help.', '',
         'In a run, the same sentence is the title of the annotation at the top of the run page and the first '
         'line of "What happened, in plain words" in the job\'s summary. New to the kit? Start with '
         '[Getting started in 1 hour](../adoption/GETTING_STARTED_1_HOUR.md).', '']
    by_ns = {}
    for key in cat['entries']:
        ns = key.split('.', 1)[0]
        by_ns.setdefault(ns, []).append(key)
    L += ['## Contents', '']
    for ns in sorted(by_ns):
        L.append('- [%s](#%s) (%d)' % (ns, ns, len(by_ns[ns])))
    L.append('')
    for ns in sorted(by_ns):
        L += ['## %s' % ns, '']
        oks = cat['not_a_failure'].get(ns, [])
        if oks:
            L += ['Not failures (nothing to do): %s.' % ', '.join('`%s`' % o for o in oks), '']
        for key in sorted(by_ns[ns]):
            state = key.split('.', 1)[1]
            ent = cat['entries'][key]
            if 'same_as' in ent:
                L += ['### %s (%s)' % (state, ns), '', 'Same meaning and fix as [`%s`](#%s).' % (
                    ent['same_as'], anchor(ent['same_as'])), '']
                continue
            L += ['### %s (%s)' % (state, ns), '', '%s **[%s]**' % (ent['what'], state), '',
                  '- **Why it matters:** %s' % ent['why'], '- **Fix:** %s' % ent['fix'],
                  '- **More:** [%s](%s)' % (ent['link'], os.path.relpath(ent['link'], 'docs/errors').replace(os.sep, '/')), '']
    internal = sorted((ns, why) for ns, why in cat['scope'].items() if why.startswith('internal'))
    L += ['## Namespaces with no developer-facing failures', '',
          'These taxonomy namespaces hold vocabulary a developer never sees as a run outcome. Each says why.', '',
          '| namespace | why it is not here |', '|---|---|']
    L += ['| `%s` | %s |' % (ns, why.split(':', 1)[1].strip()) for ns, why in internal]
    return '\n'.join(L) + '\n'


def anchor(key):
    """GitHub's anchor for the heading `### STATE (namespace)`."""
    ns, state = key.split('.', 1)
    return '%s-%s' % (state.lower(), ns)


# ── the check ────────────────────────────────────────────────────────────────────────────────────
def taxonomy_values(path=TAXONOMY):
    import yaml
    with io.open(path, encoding='utf-8') as fh:
        doc = yaml.safe_load(fh)
    out = {}
    for ns, body in (doc.get('namespaces') or {}).items():
        vals = (body or {}).get('values') or {}
        out[ns] = set(vals) if isinstance(vals, dict) else set()
    return out


def problems(cat, tax, md_text=None, root=ROOT):
    probs = []
    extra = cat.get('extra_namespaces') or {}
    scope = cat.get('scope') or {}
    for ns in sorted(tax):
        how = scope.get(ns)
        if how is None:
            probs.append('C1 taxonomy namespace %s is not scoped (developer, or internal: <why>)' % ns)
        elif how != 'developer' and not (how.startswith('internal:') and len(how.split(':', 1)[1].split()) >= 5):
            probs.append('C1 %s: scope %r is neither developer nor "internal: <five or more words>"' % (ns, how))
    for ns in sorted(scope):
        if ns not in tax and ns not in extra:
            probs.append('C1 %s is scoped but is no taxonomy namespace (or extra namespace)' % ns)
    entries = cat.get('entries') or {}
    oks = cat.get('not_a_failure') or {}
    for ns, how in sorted(scope.items()):
        if how != 'developer' or ns not in tax:
            continue
        for v in sorted(tax[ns]):
            key = '%s.%s' % (ns, v)
            if key not in entries and v not in oks.get(ns, []):
                probs.append('C2 %s has no plain-English entry and is not listed as not a failure' % key)
    for key, ent in sorted(entries.items()):
        ns, _, v = key.partition('.')
        if scope.get(ns) != 'developer':
            probs.append('C3 %s: its namespace is not a developer namespace' % key)
        if ns in tax and v not in tax[ns]:
            probs.append('C3 %s: %s is not a value of %s in the taxonomy' % (key, v, ns))
        if 'same_as' in ent:
            tgt = entries.get(ent['same_as'])
            if not tgt or 'same_as' in tgt:
                probs.append('C3 %s: same_as %s is not a full entry' % (key, ent['same_as']))
            continue
        for f in ('what', 'why', 'fix', 'link'):
            if not str(ent.get(f) or '').strip():
                probs.append('C3 %s: no %s' % (key, f))
        w = str(ent.get('what') or '').strip()
        if w and (not w.endswith('.') or len(re.findall(r'[.!?](\s|$)', w)) > 1):
            probs.append('C3 %s: what must be ONE plain sentence ending in a full stop' % key)
        if ent.get('link') and not os.path.exists(os.path.join(root, *ent['link'].split('#')[0].split('/'))):
            probs.append('C3 %s: link %s does not exist' % (key, ent['link']))
    for ns, vals in sorted(oks.items()):
        for v in vals:
            if '%s.%s' % (ns, v) in entries:
                probs.append('C4 %s.%s is both an entry and not a failure' % (ns, v))
            if ns in tax and v not in tax[ns]:
                probs.append('C4 not_a_failure %s.%s is not a taxonomy value' % (ns, v))
    if md_text is not None and md_text != render(cat):
        probs.append('C5 docs/errors/ERRORS.md differs from the catalogue (run python3 scripts/plain_errors.py render --write)')
    return probs


def self_test():
    try:
        tax = taxonomy_values()
    except ImportError:
        print('UNKNOWN: PyYAML is needed for the check')
        return 2
    cat = load()
    base = problems(cat, tax)
    failures = []
    # M1 an entry removed -> C2 names it
    import copy
    key = next(k for k, v in cat['entries'].items() if 'same_as' not in v)
    m1 = copy.deepcopy(cat)
    del m1['entries'][key]
    if not any(key in p and p.startswith('C2') for p in problems(m1, tax)):
        failures.append('M1 a removed entry (%s) was not refused' % key)
    # M2 a new taxonomy value with no entry -> C2
    ns = next(n for n, h in cat['scope'].items() if h == 'developer' and n in tax)
    tax2 = dict(tax)
    tax2[ns] = set(tax[ns]) | {'SOME_NEW_REFUSAL'}
    if not any('SOME_NEW_REFUSAL' in p for p in problems(cat, tax2)):
        failures.append('M2 a taxonomy value with no entry was not refused')
    # M3 an unscoped namespace -> C1
    tax3 = dict(tax)
    tax3['brand_new_namespace'] = {'X'}
    if not any('brand_new_namespace' in p for p in problems(cat, tax3)):
        failures.append('M3 an unscoped namespace was not refused')
    # M4 an entry with no fix -> C3
    m4 = copy.deepcopy(cat)
    m4['entries'][key] = dict(m4['entries'][key], fix='')
    if not any(key in p and 'no fix' in p for p in problems(m4, tax)):
        failures.append('M4 an entry with no fix was not refused')
    # M5 a hand edit of ERRORS.md -> C5
    if not any(p.startswith('C5') for p in problems(cat, tax, render(cat) + 'x')):
        failures.append('M5 a drifted ERRORS.md was not refused')
    if failures:
        print('SELF-TEST FAILED: ' + '; '.join(failures))
        return 2
    print('PASS: plain_errors self-test (5 mutants refused; the catalogue itself has %d problem(s) now)' % len(base))
    return 0


def main(argv=None):
    ap = argparse.ArgumentParser(description='The plain-English error layer.')
    ap.add_argument('command', nargs='?', choices=['summary', 'explain', 'render', 'check'])
    ap.add_argument('rest', nargs='*')
    ap.add_argument('--states', default='')
    ap.add_argument('--source', default='')
    ap.add_argument('--write', action='store_true')
    ap.add_argument('--self-test', action='store_true')
    a = ap.parse_args(argv)
    if a.self_test:
        return self_test()
    try:
        cat = load()
    except (OSError, ValueError) as e:
        print('UNKNOWN: the catalogue %s could not be read: %s' % (CATALOGUE, e))
        return 0 if a.command == 'summary' else 2
    if a.command == 'summary':
        try:
            return summary(cat, parse_states(a.states), a.source)
        except Exception as e:  # noqa: BLE001 -- explaining a failure must never become one
            print('::warning title=Plain-English explanation unavailable::%s' % esc_data(str(e)))
            return 0
    if a.command == 'explain':
        for level, key, state, ent in explain_lines(cat, a.rest):
            if ent is None:
                print('%s [%s]: no plain-English entry yet' % (key, state))
            else:
                print('%s [%s]\n  Why it matters: %s\n  Fix: %s\n  More: %s' % (ent['what'], state, ent['why'], ent['fix'], ent['link']))
        return 0
    if a.command == 'render':
        text = render(cat)
        if a.write:
            with io.open(ERRORS_MD, 'w', encoding='utf-8', newline='\n') as fh:
                fh.write(text)
            print('wrote %s' % os.path.relpath(ERRORS_MD, ROOT))
        else:
            sys.stdout.write(text)
        return 0
    if a.command == 'check':
        try:
            tax = taxonomy_values()
        except ImportError:
            print('UNKNOWN: PyYAML is needed for the check')
            return 2
        md = io.open(ERRORS_MD, encoding='utf-8').read() if os.path.exists(ERRORS_MD) else ''
        probs = problems(cat, tax, md)
        for p in probs:
            print('FAIL: ' + p)
        if probs:
            return 1
        n = sum(1 for v in cat['entries'].values() if 'same_as' not in v)
        print('PASS: every refusal or failure state in the taxonomy has a plain-English entry (%d entries, %d namespaces '
              'scoped).' % (n, len(cat['scope'])))
        return 0
    ap.print_help()
    return 2


if __name__ == '__main__':
    sys.exit(main())

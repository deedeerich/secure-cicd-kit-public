#!/usr/bin/env python3
"""Run a pinned Semgrep over the seeded PHP corpus and measure the PHP releases it can read.

    python -I tests/corpora/probe_php_corpus.py --cmd semgrep --tool-version 1.90.0 \
        [--out result.json] [--check | --write]
    python -I tests/corpora/probe_php_corpus.py --from result.json [--check | --write]

THE MEASUREMENT (D-VF-4; tests/corpora/php_corpus.py says what a family is)

    Every family's file and the control are scanned in ONE Semgrep run with the corpus's local rule
    (no registry fetch), and the JSON it writes is read per file. A family is
      READ          the seed was reported against that file AND Semgrep reported no error for it
      PARSE_ERROR   Semgrep reported an error naming the file (a syntax error, or partial
                    parsing): it says it did not read all of it -- loud, and not a read
      MISSED        no seed and no error -- the silence that looks like a clean file
      COLLECTION_FAILED   no report it can be held to (a crash, an absent or unparseable JSON)
    The range is CONTIGUOUS FROM THE OLDEST FAMILY: min the oldest, max the newest family below the
    first one not READ. A family READ above a failure does not raise the ceiling.

    The probe REFUSES (exit 2, no range) when it cannot measure: the oldest family is not READ (the
    tool, the rule or the seed is broken, not the version), or the CONTROL drew no error -- then this
    Semgrep is silent about a file it cannot read, and silence cannot mean "could not read".

MODES
    (default)  print the measurement and the registry row it supports
    --out F    also write the measurement as JSON (the container that runs Semgrep has no PyYAML,
               so the hosted job measures inside it and compares outside it)
    --from F   compare or write a measurement taken elsewhere, without running Semgrep
    --check    compare with scanner-registry.yaml: a READ row claiming more than was measured, or a
               row that is not the measured one, fails (exit 1) -- the scheduled regression
    --write    write the measured row into scanner-registry.yaml version_support sast-semgrep/php
               AND the byte-equivalent JSON copy in .github/actions/resolve/action.yml

EXIT  0 measured (and, with --check, the registry agrees)  1 the registry disagrees  2 UNKNOWN
"""
import argparse
import datetime
import io
import json
import os
import re
import shlex
import shutil
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(os.path.dirname(HERE))
sys.path.insert(0, HERE)
import php_corpus as C  # noqa: E402

REG = os.path.join(ROOT, 'scanner-registry.yaml')
ACTION = os.path.join(ROOT, '.github', 'actions', 'resolve', 'action.yml')
JOB, CLS, TOOL = 'sast-semgrep', 'php', 'semgrep'
corpus_id = 'tests/corpora/php_corpus.py'


# ----------------------------------------------------------------------------- running the tool
def per_file(doc, files):
    """-> {family: (state, detail)} from one Semgrep JSON document."""
    def norm(p):
        return os.path.basename(str(p).replace('\\', '/'))
    hits, errs = {}, {}
    for r in doc.get('results') or []:
        if str(r.get('check_id', '')).split('.')[-1] == C.RULE_ID:
            hits.setdefault(norm(r.get('path')), r.get('start', {}).get('line'))
    for e in doc.get('errors') or []:
        named = [e.get('path')] + [s.get('file') for s in (e.get('spans') or []) if isinstance(s, dict)]
        for p in named:
            if p:
                t = e.get('type')
                kind = t[0] if isinstance(t, list) and t else t
                errs.setdefault(norm(p), '%s (%s)' % (kind, e.get('level')))
    out = {}
    for fam, path in files.items():
        name = os.path.basename(path)
        if name in errs:
            out[fam] = ('PARSE_ERROR', 'Semgrep reported %s%s' % (
                errs[name], '; the seed was reported anyway' if name in hits else ''))
        elif name in hits:
            out[fam] = ('READ', 'seed reported at line %s, no error' % hits[name])
        else:
            out[fam] = ('MISSED', 'no seed and no error -- silently dropped')
    return out


def measure(cmd):
    """-> dict: per-family outcome, the control, and the range (or a refusal)."""
    work = tempfile.mkdtemp(prefix='php-corpus-')
    try:
        files, rule = C.materialise(os.path.join(work, 'corpus'))
        report = os.path.join(work, 'report.json')
        order = C.family_names() + [C.CONTROL]
        argv = shlex.split(cmd) + ['scan', '--config', rule, '--metrics=off', '--json',
                                   '--json-output=' + report, '--no-git-ignore'] + \
            [files[f] for f in order]
        try:
            p = subprocess.run(argv, capture_output=True, text=True, encoding='utf-8',
                               errors='replace', timeout=900, cwd=work)
            rc, tail = p.returncode, (p.stderr or p.stdout or '').strip().splitlines()[-3:]
        except (OSError, subprocess.TimeoutExpired) as e:
            rc, tail = None, ['could not run %s: %s' % (argv[0], e)]
        doc = None
        if os.path.isfile(report):
            try:
                doc = json.load(io.open(report, encoding='utf-8'))
            except ValueError:
                doc = None
        if not isinstance(doc, dict):
            states = {f: ('COLLECTION_FAILED', 'exit %s, no report it can be held to: %s'
                          % (rc, ' | '.join(tail))) for f in order}
        else:
            states = per_file(doc, files)
    finally:
        shutil.rmtree(work, ignore_errors=True)
    per = []
    for fam in order:
        state, why = states[fam]
        per.append({'family': fam, 'state': state, 'detail': why})
        print('  %-8s %-20s %-17s %s' % (TOOL, fam, state, why))
    return summarise(per)


def summarise(per):
    fams = [p for p in per if p['family'] != C.CONTROL]
    control = next(p for p in per if p['family'] == C.CONTROL)
    result = {'tool': TOOL, 'families': per, 'corpus': corpus_id}
    if all(p['state'] == 'COLLECTION_FAILED' for p in per):
        result['refused'] = 'no family produced a report: the tool did not run'
        return result
    if control['state'] != 'PARSE_ERROR':
        result['refused'] = ('the control (an unparseable file) drew no error (%s): this Semgrep is '
                             'silent about a file it cannot read, so a missing seed cannot mean '
                             '"could not read"' % control['state'])
        return result
    if fams[0]['state'] != 'READ':
        result['refused'] = ('the oldest family %s is %s: the tool, the rule or the seed is broken, '
                             'not the version' % (fams[0]['family'], fams[0]['state']))
        return result
    top = fams[0]
    for p in fams:
        if p['state'] != 'READ':
            break
        top = p
    first_miss = next((p for p in fams if p['state'] != 'READ'), None)
    result['min'] = fams[0]['family']
    result['max'] = top['family']
    result['first_unread'] = first_miss['family'] if first_miss else None
    result['read_above_ceiling'] = [p['family'] for p in fams[fams.index(first_miss) + 1:]
                                    if p['state'] == 'READ'] if first_miss else []
    return result


# ----------------------------------------------------------------------------- the registry row
def basis(result, tool_version, date, where):
    if result['first_unread']:
        st = next(p['state'] for p in result['families'] if p['family'] == result['first_unread'])
        tail = '%s was %s, so the ceiling is the family below it' % (result['first_unread'], st)
        if result.get('read_above_ceiling'):
            tail += ' (%s read above it, which does not raise the ceiling)' % ', '.join(
                result['read_above_ceiling'])
    else:
        tail = ('every family in the corpus was read; no newer family is in it, so a newer release '
                'is outside what was measured')
    return ('MEASURED by the seeded PHP corpus (%s; D-VF-4): semgrep %s read the seed, with no '
            'parse error, in every family %s..%s (families: %s); %s. Releases with no new syntax '
            'are claimed through their neighbours. Measured %s (%s) by '
            'tests/corpora/probe_php_corpus.py.'
            % (corpus_id, tool_version, result['min'], result['max'],
               ', '.join(C.family_names()), tail, date, where))


def registry_row():
    import yaml
    reg = yaml.safe_load(io.open(REG, encoding='utf-8')) or {}
    for e in (((reg.get('version_support') or {}).get(JOB) or {}).get(CLS) or []):
        if e.get('tool') == TOOL:
            return e
    return None


def compare(result, row):
    bad = []
    if row is None:
        return ['scanner-registry.yaml has no version_support %s/%s/%s row' % (JOB, CLS, TOOL)]
    if 'refused' in result:
        if row.get('verified') == 'READ':
            bad.append('the registry says READ, and the measurement refused: %s' % result['refused'])
        return bad
    if row.get('verified') != 'READ':
        bad.append('measured %s..%s but the registry row is %s' % (result['min'], result['max'],
                                                                   row.get('verified')))
    if str(row.get('min')) != result['min'] or str(row.get('max')) != result['max']:
        bad.append('the registry declares %s..%s, the corpus measured %s..%s' % (
            row.get('min'), row.get('max'), result['min'], result['max']))
    if row.get('corpus') != corpus_id:
        bad.append('the registry row does not name its corpus (%s)' % corpus_id)
    return bad


def yq(s):
    return '"%s"' % s.replace('\\', '\\\\').replace('"', '\\"')


def write_registry(text, fields):
    """Rewrite the version_support sast-semgrep/php/semgrep entry's scalar fields in the registry
    TEXT, comments and every other byte untouched. -> new text, or raises ValueError."""
    lines = text.split('\n')
    i = lines.index('version_support:')
    j = next(k for k in range(i + 1, len(lines)) if lines[k] == '  %s:' % JOB)
    k = next(n for n in range(j + 1, len(lines)) if lines[n] == '    %s:' % CLS)
    start = next(n for n in range(k + 1, len(lines)) if lines[n] == '      - tool: %s' % TOOL)
    end = start + 1
    while end < len(lines) and lines[end].startswith('        ') and ':' in lines[end]:
        end += 1
    body = lines[start + 1:end]
    seen = set()
    for n, line in enumerate(body):
        key = line.strip().split(':', 1)[0]
        if key in fields:
            body[n] = '        %s: %s' % (key, fields[key])
            seen.add(key)
    for key in fields:
        if key not in seen:
            body.append('        %s: %s' % (key, fields[key]))
    return '\n'.join(lines[:start + 1] + body + lines[end:])


def write_action_copy(text, table):
    m = re.search(r"<<'JSON'\n(.*?)\n        JSON\n", text, re.S)
    if not m:
        raise ValueError('no version_support heredoc in the resolve composite')
    dumped = json.dumps(table, indent=2, sort_keys=True, ensure_ascii=False)
    body = '\n'.join(('        ' + ln) if ln else ln for ln in dumped.split('\n'))
    return text[:m.start(1)] + body + text[m.end(1):]


def write(result, tool_version, date, where):
    import yaml
    fields = {'min': yq(result['min']), 'max': yq(result['max']), 'verified': 'READ',
              'basis': yq(basis(result, tool_version, date, where)), 'corpus': corpus_id}
    raw = io.open(REG, 'rb').read().decode('utf-8')
    crlf = '\r\n' in raw
    text = write_registry(raw.replace('\r\n', '\n'), fields)
    io.open(REG, 'wb').write((text.replace('\n', '\r\n') if crlf else text).encode('utf-8'))
    table = (yaml.safe_load(text) or {}).get('version_support')
    araw = io.open(ACTION, 'rb').read().decode('utf-8')
    acrlf = '\r\n' in araw
    atext = write_action_copy(araw.replace('\r\n', '\n'), table)
    io.open(ACTION, 'wb').write((atext.replace('\n', '\r\n') if acrlf else atext).encode('utf-8'))


def main(argv=None):
    ap = argparse.ArgumentParser()
    src = ap.add_mutually_exclusive_group(required=True)
    src.add_argument('--cmd', help='how to invoke Semgrep, e.g. "semgrep"')
    src.add_argument('--from', dest='src', help='a measurement JSON written by --out')
    ap.add_argument('--tool-version', help='the pinned version being measured (with --cmd)')
    ap.add_argument('--out', help='write the measurement as JSON here')
    ap.add_argument('--where', default=None,
                    help='where the measurement ran, recorded in the basis (default: what the '
                         'measurement recorded, else "on a hosted runner")')
    mode = ap.add_mutually_exclusive_group()
    mode.add_argument('--check', action='store_true')
    mode.add_argument('--write', action='store_true')
    a = ap.parse_args(argv)
    date = datetime.date.today().isoformat()
    if a.src:
        result = json.load(io.open(a.src, encoding='utf-8'))
        date = result.get('measured_on') or date
        for p in result.get('families') or []:
            print('  %-8s %-20s %-17s %s' % (TOOL, p['family'], p['state'], p['detail']))
    else:
        if not a.tool_version:
            ap.error('--tool-version is required with --cmd')
        result = measure(a.cmd)
        result.update({'tool_version': a.tool_version, 'measured_on': date,
                       'where': a.where or 'on a hosted runner'})
    where = a.where or result.get('where') or 'on a hosted runner'
    if a.out:
        io.open(a.out, 'w', encoding='utf-8').write(json.dumps(result, indent=2, sort_keys=True) + '\n')
    version = result.get('tool_version') or '?'
    if 'refused' in result:
        print('UNKNOWN: no range for semgrep %s: %s' % (version, result['refused']))
        if a.check:
            bad = compare(result, registry_row())
            for b in bad:
                print('FAIL: %s' % b)
            return 1 if bad else 2
        return 2
    print('MEASURED: semgrep %s reads PHP %s..%s (first family not read: %s)'
          % (version, result['min'], result['max'], result['first_unread'] or 'none'))
    if a.check:
        bad = compare(result, registry_row())
        for b in bad:
            print('FAIL: %s' % b)
        if bad:
            return 1
        print('PASS: scanner-registry.yaml declares exactly the measured PHP range for semgrep.')
    elif a.write:
        write(result, version, date, where)
        print('WROTE: version_support %s/%s/%s and the resolve composite copy.' % (JOB, CLS, TOOL))
    return 0


if __name__ == '__main__':
    sys.exit(main())

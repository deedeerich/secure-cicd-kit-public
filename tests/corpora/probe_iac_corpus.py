#!/usr/bin/env python3
"""Run a pinned IaC scanner over the seeded Terraform corpus and measure the range it can read.

    python -I tests/corpora/probe_iac_corpus.py --tool checkov --cmd "checkov" \
        --tool-version 3.3.30 [--check | --write] [--out result.json]

THE MEASUREMENT (D-VF-4; tests/corpora/terraform_corpus.py says what a family is)

    Each family's file is scanned in its own directory. A family is
      READ        the scanner reported the seeded rule against that file
      MISSED      it wrote a report and the seed is not in it -- the file was dropped, the silence
                  that looks like a clean file
      COLLECTION_FAILED   it wrote no report it could be held to (a crash, an absent or unparseable file)
    The range is CONTIGUOUS FROM THE OLDEST FAMILY: min is the oldest family, max the newest family
    below the first one not READ. A family READ above a miss does not raise the ceiling.

    The probe REFUSES (exit 2, no range) when it cannot measure: the oldest family is not READ (the
    tool or the seed is broken, not the version), or the CONTROL (an unparseable file holding the
    same seed) is READ -- then this scanner does not drop unreadable files, and a missing seed
    could not mean "could not read".

MODES
    (default)  print the measurement and the registry row it supports
    --check    compare with scanner-registry.yaml: a READ row claiming more than was measured, or a
               row that is not the measured one, fails (exit 1). This is the scheduled regression:
               a scanner upgrade that loses a family turns the probe red before a deploy trusts it.
    --write    write the measured row into scanner-registry.yaml version_support iac-scan/iac/<tool>
               AND the byte-equivalent JSON copy in .github/actions/resolve/action.yml (the copy
               tests/test_resolve.py holds equal to the registry)

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
import terraform_corpus as C  # noqa: E402

REG = os.path.join(ROOT, 'scanner-registry.yaml')
ACTION = os.path.join(ROOT, '.github', 'actions', 'resolve', 'action.yml')
JOB, CLS = 'iac-scan', 'iac'
TOOLS = ('checkov', 'trivy-config')
corpus_id = 'tests/corpora/terraform_corpus.py'


# ----------------------------------------------------------------------------- running a tool
def command(tool, cmd, directory, out_file):
    base = shlex.split(cmd)
    if tool == 'checkov':
        # The flagship runs checkov over a directory with soft_fail; JSON here because the rule id
        # and the file are what is asked, and SARIF and JSON carry the same failed checks.
        return base + ['-d', directory, '--framework', 'terraform', '-o', 'json', '--quiet',
                       '--compact', '--soft-fail', '--skip-download'], None
    return base + ['config', '--format', 'json', '--output', out_file, '--exit-code', '0',
                   directory], out_file


def findings(tool, text):
    """-> set of (rule id, file basename) from a report, or None when it is not a report."""
    try:
        doc = json.loads(text)
    except (TypeError, ValueError):
        return None
    got = set()
    if tool == 'checkov':
        docs = doc if isinstance(doc, list) else [doc]
        if not all(isinstance(d, dict) for d in docs):
            return None
        for d in docs:
            res = d.get('results')
            if res is None and 'summary' not in d and 'passed' not in d:
                return None
            for c in ((res or {}).get('failed_checks') or []):
                got.add((c.get('check_id'), os.path.basename(c.get('file_path') or '')))
        return got
    if not isinstance(doc, dict) or 'SchemaVersion' not in doc:
        return None
    for r in doc.get('Results') or []:
        for m in r.get('Misconfigurations') or []:
            if (m.get('Status') or 'FAIL') == 'FAIL':
                for rid in (m.get('ID'), m.get('AVDID')):
                    if rid:
                        got.add((rid, os.path.basename(r.get('Target') or '')))
    return got


def scan(tool, cmd, directory, work):
    out_file = os.path.join(work, 'report-%s.json' % os.path.basename(directory))
    argv, report = command(tool, cmd, directory, out_file)
    try:
        # cwd = the family's own directory: a scanner relativising paths against a cwd on another
        # drive fails before it reads anything (checkov on Windows did).
        p = subprocess.run(argv, capture_output=True, text=True, encoding='utf-8',
                           errors='replace', timeout=600, cwd=directory)
    except (OSError, subprocess.TimeoutExpired) as e:
        return 'COLLECTION_FAILED', 'could not run %s: %s' % (argv[0], e)
    if report:
        text = io.open(report, encoding='utf-8').read() if os.path.isfile(report) else ''
    else:
        text = p.stdout
    got = findings(tool, text)
    if got is None:
        tail = (p.stderr or p.stdout or '').strip().splitlines()[-3:]
        return 'COLLECTION_FAILED', 'exit %s, no report it can be held to: %s' % (p.returncode, ' | '.join(tail))
    want = [x.lower() for x in C.EXPECTED[tool]]
    hit = sorted(r for r, f in got if (r or '').lower() in want and f == 'main.tf')
    if hit:
        return 'READ', 'reported %s against main.tf' % hit[0]
    return 'MISSED', 'exit %s; report holds %d finding(s), none of %s' % (
        p.returncode, len(got), '/'.join(C.EXPECTED[tool]))


def measure(tool, cmd):
    """-> dict: per-family outcome, the control, and the range (or a refusal)."""
    work = tempfile.mkdtemp(prefix='iac-corpus-')
    try:
        dirs = C.materialise(os.path.join(work, 'corpus'))
        per = []
        for fam in C.family_names() + [C.CONTROL]:
            state, why = scan(tool, cmd, dirs[fam], work)
            per.append({'family': fam, 'state': state, 'detail': why})
            print('  %-8s %-20s %-9s %s' % (tool, fam, state, why))
    finally:
        shutil.rmtree(work, ignore_errors=True)
    fams = [p for p in per if p['family'] != C.CONTROL]
    control = next(p for p in per if p['family'] == C.CONTROL)
    result = {'tool': tool, 'families': per, 'corpus': corpus_id}
    if control['state'] == 'READ':
        result['refused'] = ('the control (an unparseable file) was READ: this scanner does not drop '
                             'an unreadable file, so a missing seed cannot mean "could not read"')
        return result
    if control['state'] == 'COLLECTION_FAILED' and all(p['state'] == 'COLLECTION_FAILED' for p in fams):
        result['refused'] = 'no family produced a report: the tool did not run'
        return result
    if fams[0]['state'] != 'READ':
        result['refused'] = ('the oldest family %s is %s: the tool or the seed is broken, not the '
                             'version' % (fams[0]['family'], fams[0]['state']))
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
    tail = ('%s was %s, so the ceiling is the family below it' % (
        result['first_unread'], next(p['state'] for p in result['families']
                                     if p['family'] == result['first_unread']))
            if result['first_unread'] else
            'every family in the corpus was read; no newer family is in it, so a newer release is '
            'outside what was measured')
    return ('MEASURED by the seeded Terraform corpus (%s; D-VF-4): %s %s read the seed in every '
            'family %s..%s (families: %s); %s. Releases with no new .tf construct are claimed '
            'through their neighbours. Measured %s (%s) by tests/corpora/probe_iac_corpus.py.'
            % (corpus_id, result['tool'], tool_version, result['min'], result['max'],
               ', '.join(C.family_names()), tail, date, where))


def registry_row(tool):
    import yaml
    reg = yaml.safe_load(io.open(REG, encoding='utf-8')) or {}
    for e in (((reg.get('version_support') or {}).get(JOB) or {}).get(CLS) or []):
        if e.get('tool') == tool:
            return e
    return None


def compare(result, row):
    """-> list of disagreements between a measurement and the registry row."""
    bad = []
    if row is None:
        return ['scanner-registry.yaml has no version_support %s/%s/%s row' % (JOB, CLS, result['tool'])]
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


def write_registry(text, tool, fields):
    """Rewrite one version_support iac-scan/iac/<tool> entry's scalar fields in the registry TEXT,
    comments and every other byte untouched. -> new text, or raises ValueError."""
    lines = text.split('\n')
    i = lines.index('version_support:')
    j = next(k for k in range(i + 1, len(lines)) if lines[k] == '  %s:' % JOB)
    k = next(n for n in range(j + 1, len(lines)) if lines[n] == '    %s:' % CLS)
    start = next(n for n in range(k + 1, len(lines)) if lines[n] == '      - tool: %s' % tool)
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
    text = raw.replace('\r\n', '\n')
    text = write_registry(text, result['tool'], fields)
    io.open(REG, 'wb').write((text.replace('\n', '\r\n') if crlf else text).encode('utf-8'))
    table = (yaml.safe_load(text) or {}).get('version_support')
    araw = io.open(ACTION, 'rb').read().decode('utf-8')
    acrlf = '\r\n' in araw
    atext = write_action_copy(araw.replace('\r\n', '\n'), table)
    io.open(ACTION, 'wb').write((atext.replace('\n', '\r\n') if acrlf else atext).encode('utf-8'))


def main(argv=None):
    ap = argparse.ArgumentParser()
    ap.add_argument('--tool', required=True, choices=TOOLS)
    ap.add_argument('--cmd', required=True, help='how to invoke the scanner, e.g. "checkov"')
    ap.add_argument('--tool-version', required=True, help='the pinned version being measured')
    ap.add_argument('--out', help='write the measurement as JSON here')
    ap.add_argument('--where', default='on a hosted runner',
                    help='where the measurement ran, recorded in the basis')
    mode = ap.add_mutually_exclusive_group()
    mode.add_argument('--check', action='store_true')
    mode.add_argument('--write', action='store_true')
    a = ap.parse_args(argv)
    date = datetime.date.today().isoformat()
    result = measure(a.tool, a.cmd)
    result.update({'tool_version': a.tool_version, 'measured_on': date})
    if a.out:
        io.open(a.out, 'w', encoding='utf-8').write(json.dumps(result, indent=2, sort_keys=True) + '\n')
    if 'refused' in result:
        print('UNKNOWN: no range for %s %s: %s' % (a.tool, a.tool_version, result['refused']))
        if a.check:
            bad = compare(result, registry_row(a.tool))
            for b in bad:
                print('FAIL: %s' % b)
            return 1 if bad else 2
        return 2
    print('MEASURED: %s %s reads Terraform %s..%s (first family not read: %s)'
          % (a.tool, a.tool_version, result['min'], result['max'], result['first_unread'] or 'none'))
    if a.check:
        bad = compare(result, registry_row(a.tool))
        for b in bad:
            print('FAIL: %s' % b)
        if bad:
            return 1
        print('PASS: scanner-registry.yaml declares exactly the measured range for %s.' % a.tool)
    elif a.write:
        write(result, a.tool_version, date, a.where)
        print('WROTE: version_support %s/%s/%s and the resolve composite copy.' % (JOB, CLS, a.tool))
    return 0


if __name__ == '__main__':
    sys.exit(main())

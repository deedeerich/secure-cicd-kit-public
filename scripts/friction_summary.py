#!/usr/bin/env python3
"""Summarise pilot friction logs across teams (docs/adoption/PILOT_FRICTION_LOG_TEMPLATE.md).

WHY THIS EXISTS (owner, 2026-11-06)
    "How painful will adoption be?" is answered by measurement, not by opinion: each pilot team logs its
    time to first green at crawl (target: one hour), every stuck point (step, error state, minutes lost,
    fix) and its satisfaction. This turns those logs into one view the rollout plan's wave gates read
    (docs/adoption/ROLLOUT_PLAN.md): who met the hour, where the minutes went, which error states cost the
    most, and whether the plain-English entry for each one exists.

    A row it cannot read is listed with its reason and NEVER dropped silently: the summary exits 1 when
    there is one, because a half-counted log reads as less friction than there was.

USAGE
    python3 scripts/friction_summary.py LOG.csv [LOG2.csv | DIR ...] [--json OUT] [--target-minutes 60]
    python3 scripts/friction_summary.py --self-test

EXIT  0 every row read   1 at least one row refused (each named; the rest still summarised)
      2 no log given or none could be opened
"""
import argparse
import collections
import csv
import glob
import io
import json
import os
import re
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
COLUMNS = ['kind', 'team', 'repository', 'date', 'stack', 'deploy_shape', 'rung', 'step', 'error_state',
           'minutes', 'fix', 'fixed_by', 'satisfaction', 'note']
KINDS = ('first_green', 'stuck', 'satisfaction')
FIXED_BY = ('self', 'docs', 'platform', 'security', 'other', '')
TARGET = 60


def catalogue():
    try:
        import plain_errors as PE
        return PE, PE.load()
    except Exception:  # noqa: BLE001 -- the summary still works without the plain sentences
        return None, None


def read_rows(paths):
    """-> (rows, refused, files). Each refused item is (file, line, reason)."""
    rows, refused, files = [], [], []
    for p in paths:
        if os.path.isdir(p):
            files += sorted(glob.glob(os.path.join(p, '*.csv')))
        else:
            files.append(p)
    for f in files:
        try:
            fh = io.open(f, encoding='utf-8-sig', newline='')
        except OSError as e:
            refused.append((f, 0, 'could not open: %s' % e))
            continue
        with fh:
            r = csv.DictReader(fh)
            missing = [c for c in ('kind', 'team', 'repository', 'date', 'minutes') if c not in (r.fieldnames or [])]
            if missing:
                refused.append((f, 1, 'the header lacks %s (copy pilot-friction-log.template.csv)' % ', '.join(missing)))
                continue
            for i, row in enumerate(r, start=2):
                row = {k: (v or '').strip() for k, v in row.items() if k}
                why = validate(row)
                if why:
                    refused.append((f, i, why))
                else:
                    row['_file'] = f
                    rows.append(row)
    return rows, refused, files


def validate(row):
    k = row.get('kind', '')
    if k not in KINDS:
        return 'kind %r is not one of %s' % (k, ', '.join(KINDS))
    for c in ('team', 'repository'):
        if not row.get(c):
            return 'no %s' % c
    if not re.match(r'^\d{4}-\d{2}-\d{2}$', row.get('date', '')):
        return 'date %r is not YYYY-MM-DD' % row.get('date', '')
    if k in ('first_green', 'stuck'):
        m = row.get('minutes', '')
        if not re.match(r'^\d+$', m) or int(m) <= 0:
            return 'minutes %r is not a whole number above 0' % m
    if k == 'stuck':
        if not row.get('step'):
            return 'a stuck row needs the step it happened at'
        if row.get('fixed_by', '') not in FIXED_BY:
            return 'fixed_by %r is not one of %s' % (row.get('fixed_by'), ', '.join(x for x in FIXED_BY if x))
    if k == 'satisfaction':
        s = row.get('satisfaction', '')
        if not re.match(r'^[1-5]$', s):
            return 'satisfaction %r is not 1 to 5' % s
    return ''


def summarise(rows, refused, target=TARGET):
    PE, cat = catalogue()
    teams = collections.OrderedDict()
    for r in rows:
        t = teams.setdefault(r['team'], {'repositories': set(), 'first_green': {}, 'stuck_minutes': 0, 'stuck': 0,
                                         'satisfaction': []})
        t['repositories'].add(r['repository'])
        if r['kind'] == 'first_green':
            prev = t['first_green'].get(r['repository'])
            t['first_green'][r['repository']] = min(int(r['minutes']), prev) if prev else int(r['minutes'])
        elif r['kind'] == 'stuck':
            t['stuck_minutes'] += int(r['minutes'])
            t['stuck'] += 1
        else:
            t['satisfaction'].append(int(r['satisfaction']))
    by_state = collections.Counter()
    state_count = collections.Counter()
    by_step = collections.Counter()
    by_fixer = collections.Counter()
    for r in rows:
        if r['kind'] != 'stuck':
            continue
        st = r.get('error_state') or '(no state recorded)'
        by_state[st] += int(r['minutes'])
        state_count[st] += 1
        by_step[r['step']] += int(r['minutes'])
        by_fixer[r.get('fixed_by') or 'unrecorded'] += int(r['minutes'])
    states = []
    for st, mins in by_state.most_common():
        plain, gap = None, False
        if st != '(no state recorded)' and cat is not None:
            hits = PE.lookup(cat, st)
            ent = next((h[1] for h in hits if h[1]), None)
            plain = ent['what'] if ent else None
            gap = ent is None and not any(h[2] for h in hits)
        states.append({'state': st, 'minutes': mins, 'times': state_count[st], 'plain': plain, 'catalogue_gap': gap})
    out_teams = []
    all_green = []
    for name, t in teams.items():
        greens = t['first_green']
        all_green += list(greens.values())
        missing = sorted(t['repositories'] - set(greens))
        out_teams.append({
            'team': name, 'repositories': sorted(t['repositories']),
            'first_green_minutes': greens, 'met_target': sorted(r for r, m in greens.items() if m <= target),
            'missed_target': sorted(r for r, m in greens.items() if m > target), 'not_green_yet': missing,
            'stuck_points': t['stuck'], 'minutes_lost': t['stuck_minutes'],
            'satisfaction': (round(sum(t['satisfaction']) / len(t['satisfaction']), 1) if t['satisfaction'] else None),
            'low_satisfaction': any(s <= 2 for s in t['satisfaction'])})
    return {
        'target_minutes': target, 'teams': out_teams,
        'overall': {'repositories_green': len(all_green),
                    'met_target': sum(1 for m in all_green if m <= target),
                    'median_first_green': (sorted(all_green)[len(all_green) // 2] if all_green else None),
                    'minutes_lost': sum(by_state.values())},
        'error_states': states, 'steps': by_step.most_common(), 'fixed_by': by_fixer.most_common(),
        'refused_rows': [{'file': f, 'line': ln, 'reason': why} for f, ln, why in refused],
    }


def render(s):
    L = ['# Pilot friction summary', '', 'Target: first green security run at crawl in %d minutes or less.' % s['target_minutes'], '']
    o = s['overall']
    L += ['**Overall:** %d repositories green, %d within the target, median %s minutes to first green; %d minutes lost '
          'to stuck points.' % (o['repositories_green'], o['met_target'],
                                o['median_first_green'] if o['median_first_green'] is not None else 'n/a', o['minutes_lost']), '',
          '| team | repositories | first green (minutes) | met | missed | not green yet | stuck points | minutes lost | satisfaction |',
          '|---|---|---|---|---|---|---|---|---|']
    for t in s['teams']:
        L.append('| %s | %d | %s | %s | %s | %s | %d | %d | %s%s |' % (
            t['team'], len(t['repositories']), ', '.join('%s %d' % kv for kv in sorted(t['first_green_minutes'].items())) or '-',
            ', '.join(t['met_target']) or '-', ', '.join(t['missed_target']) or '-', ', '.join(t['not_green_yet']) or '-',
            t['stuck_points'], t['minutes_lost'], t['satisfaction'] if t['satisfaction'] is not None else '-',
            ' (a 2 or lower: talk to them this week)' if t['low_satisfaction'] else ''))
    L += ['', '## Where the minutes went, by error state (worst first)', '', '| state | minutes | times | in plain words |', '|---|---|---|---|']
    for e in s['error_states']:
        L.append('| `%s` | %d | %d | %s |' % (e['state'], e['minutes'], e['times'],
                                            e['plain'] or ('**no entry in docs/errors/ERRORS.md: a catalogue gap we owe**'
                                                           if e['catalogue_gap'] else '-')))
    L += ['', '## By step', '', '| step | minutes |', '|---|---|'] + ['| %s | %d |' % kv for kv in s['steps']]
    L += ['', '## Who fixed it', '', '| fixed by | minutes |', '|---|---|'] + ['| %s | %d |' % kv for kv in s['fixed_by']]
    if s['refused_rows']:
        L += ['', '## Rows NOT counted (fix them and re-run)', '', '| file | line | why |', '|---|---|---|']
        L += ['| %s | %d | %s |' % (r['file'], r['line'], r['reason']) for r in s['refused_rows']]
    return '\n'.join(L) + '\n'


def self_test():
    import tempfile
    d = tempfile.mkdtemp()
    p = os.path.join(d, 'a.csv')
    with io.open(p, 'w', encoding='utf-8', newline='') as fh:
        w = csv.writer(fh)
        w.writerow(COLUMNS)
        w.writerow(['first_green', 't1', 'r1', '2026-11-10', '', '', 'crawl', '', '', '45', '', '', '', ''])
        w.writerow(['stuck', 't1', 'r1', '2026-11-10', '', '', '', 'env', 'routing_result.BLOCKED', '10', 'x', 'self', '', ''])
        w.writerow(['stuck', 't1', 'r1', '2026-11-10', '', '', '', '', '', '-3', '', '', '', ''])
    rows, refused, _ = read_rows([p])
    s = summarise(rows, refused)
    ok = (len(rows) == 2 and len(refused) == 1 and s['teams'][0]['met_target'] == ['r1'] and
          s['error_states'][0]['state'] == 'routing_result.BLOCKED')
    os.remove(p)
    os.rmdir(d)
    print('PASS: friction_summary self-test' if ok else 'FAIL: friction_summary self-test')
    return 0 if ok else 2


def main(argv=None):
    ap = argparse.ArgumentParser(description='Summarise pilot friction logs.')
    ap.add_argument('paths', nargs='*')
    ap.add_argument('--json')
    ap.add_argument('--target-minutes', type=int, default=TARGET)
    ap.add_argument('--self-test', action='store_true')
    a = ap.parse_args(argv)
    if a.self_test:
        return self_test()
    if not a.paths:
        print('UNKNOWN: name at least one log file or folder')
        return 2
    rows, refused, files = read_rows(a.paths)
    if not files or (not rows and all(ln == 0 for _f, ln, _w in refused) and refused):
        print('UNKNOWN: no log could be opened')
        for f, ln, why in refused:
            print('  %s: %s' % (f, why))
        return 2
    s = summarise(rows, refused, a.target_minutes)
    sys.stdout.write(render(s))
    if a.json:
        with io.open(a.json, 'w', encoding='utf-8') as fh:
            fh.write(json.dumps(s, indent=1, default=list))
    return 1 if refused else 0


if __name__ == '__main__':
    sys.exit(main())

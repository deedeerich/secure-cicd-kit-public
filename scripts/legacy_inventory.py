#!/usr/bin/env python3
"""READ-ONLY inventory of the disposition register's LEGACY-KEYED decisions (KDEC-008 OD-6).

WHY THIS EXISTS

    The key migration window (scan_report.legacy_key_window_*) honours a decision keyed on the
    legacy fingerprint -- scanner, rule id, path and message, hashed to 12 hex characters -- for
    thirty days from 2026-10-14. On the day after it closes, every such decision STOPS
    SUPPRESSING. The reports name each one as it is hit, but only for the findings a given run
    happens to see. Nothing listed the register itself, so an owner could not know, before the
    deadline, how many decisions each consumer repository still keys the old way, who owns them,
    and what to re-key them to (independent review 2026-11-09, finding 10).

WHAT IT DOES

    Reads the register exactly as the report reads it (scan_report.load_dispositions) and, for
    every key of the legacy shape, says:
      * the durable identity it resolves to, read from a findings file the PRODUCTION report wrote
        (findings.json rows carry both `fp` and `identity`); never computed here, never guessed
      * the owner (approver_role), the expiry, and whether the record suppresses today
        (scan_report.not_suppressed_because -- the one rule, not a copy)
      * whether a person must reaffirm it on the durable identity before the window closes
    plus a count summary. A replacement record on the durable key counts as a migration only when
    it too suppresses today (same rule); otherwise the row is REKEYED_REPLACEMENT_NOT_EFFECTIVE
    and needs action. The output is an inventory of candidate migration obligations, not proof
    that any approval was safely migrated. Plain text, or --json.

WHAT IT NEVER DOES

    It writes nothing and re-keys nothing. Re-keying is a new approval by a person on a new key,
    and a tool that rewrote the register would be extending an approval nobody gave
    (tests/prove_legacy_inventory.py hashes every input before and after a run).

USAGE

    python scripts/legacy_inventory.py --register .security/dispositions.json \
        [--findings findings.json ...] [--today YYYY-MM-DD] [--json]

EXIT  0 the inventory was produced   2 the register could not be read
"""
import argparse
import datetime
import io
import json
import os
import re
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import scan_report  # noqa: E402  (the register loader, the suppression rule and the window)

LEGACY_SHAPE = re.compile(r'^[0-9a-f]{12}$')      # scan_report.fingerprint(): sha256[:12]
DURABLE_SHAPE = re.compile(r'^[0-9a-f]{64}$')     # finding_identity._h(): the full sha256

# Row states (assurance-taxonomy.yaml namespace legacy_inventory_state).
REKEY_REQUIRED = 'REKEY_REQUIRED'
REKEY_REQUIRED_IDENTITY_UNRESOLVED = 'REKEY_REQUIRED_IDENTITY_UNRESOLVED'
ALREADY_REKEYED = 'ALREADY_REKEYED'
REKEYED_REPLACEMENT_NOT_EFFECTIVE = 'REKEYED_REPLACEMENT_NOT_EFFECTIVE'
NOT_SUPPRESSING = 'NOT_SUPPRESSING'
STATES = (REKEY_REQUIRED, REKEY_REQUIRED_IDENTITY_UNRESOLVED, ALREADY_REKEYED,
          REKEYED_REPLACEMENT_NOT_EFFECTIVE, NOT_SUPPRESSING)
NEEDS_ACTION = (REKEY_REQUIRED, REKEY_REQUIRED_IDENTITY_UNRESOLVED, REKEYED_REPLACEMENT_NOT_EFFECTIVE)


def load_findings(paths):
    """-> ({legacy fp: set(durable identities)}, {legacy fp: [refusal reasons]}, notes)."""
    by_fp, refused, notes = {}, {}, []
    for p in paths or []:
        try:
            rows = json.load(io.open(p, encoding='utf-8', errors='replace'))
        except (ValueError, IOError) as exc:
            notes.append('findings file %s could not be read (%s): no identity resolved from it'
                         % (p, type(exc).__name__))
            continue
        if not isinstance(rows, list):
            notes.append('findings file %s is not a list of findings rows: no identity resolved from it' % p)
            continue
        n = 0
        for r in rows:
            if not isinstance(r, dict) or not r.get('fp'):
                continue
            n += 1
            fp = str(r['fp'])
            ident = str(r.get('identity') or '')
            if ident and r.get('state', 'FINGERPRINTED') == 'FINGERPRINTED':
                by_fp.setdefault(fp, set()).add(ident)
            else:
                refused.setdefault(fp, []).append('%s %s' % (r.get('state') or 'UNFINGERPRINTABLE',
                                                             r.get('reason') or ''))
        notes.append('findings file %s: %d row(s) read' % (p, n))
    return by_fp, refused, notes


def inventory(register_path, findings_paths=(), today=None):
    """-> the inventory dict. Pure: reads its inputs, writes nothing."""
    today = today or datetime.date.today()
    disp, disp_state = scan_report.load_dispositions(register_path)
    out = {
        'schema': 'legacy-inventory/1',
        'register': register_path,
        'register_state': disp_state,
        'today': today.isoformat(),
        'window_opened': scan_report.legacy_key_window_opened,
        'window_closes': scan_report.legacy_key_window_closes,
        'window_open': today.isoformat() <= scan_report.legacy_key_window_closes,
        'rows': [], 'unrecognised_keys': [], 'notes': [],
    }
    if disp_state != 'LOADED':
        out['notes'].append('the register is %s, so nothing could be inventoried; this is NOT '
                            '"no legacy keys"' % disp_state)
        out['summary'] = dict((s, 0) for s in STATES)
        out['summary'].update(legacy_keys=0, durable_keys=0, unrecognised_keys=0)
        return out
    by_fp, refused, notes = load_findings(findings_paths)
    out['notes'].extend(notes)
    if not findings_paths:
        out['notes'].append('no findings file given: no durable identity can be resolved, because '
                            'a legacy key is a hash and cannot be reversed. Pass the findings.json '
                            'of a recent run of this repository.')
    durable = 0
    for key in sorted(disp):
        rec = disp[key] if isinstance(disp[key], dict) else {}
        k = str(key)
        if DURABLE_SHAPE.match(k):
            durable += 1
            continue
        if not LEGACY_SHAPE.match(k):
            out['unrecognised_keys'].append(k)
            continue
        idents = sorted(by_fp.get(k, ()))
        ns = scan_report.not_suppressed_because(rec, today) if rec else 'record is not an object'
        row = {
            'legacy_key': k,
            'scanner': rec.get('scanner', ''), 'rule': rec.get('rule', ''),
            'scope_path': rec.get('scope_path', ''),
            'disposition_type': rec.get('disposition_type', ''), 'state': rec.get('state', ''),
            'owner': rec.get('approver_role') or rec.get('approved_by') or '',
            'expires': rec.get('expires', ''),
            'durable_identities': idents,
            'suppresses_on_its_own_terms': not ns,
            'not_suppressing_because': ns,
        }
        rekeyed = [i for i in idents if i in disp]
        # A record EXISTING on the durable key is not an approval that suppresses: ask the same
        # rule that was just asked of the legacy row (an expired, rejected or proposed replacement
        # buys nothing, and the legacy entry it would retire is the one still holding the finding).
        not_effective = dict((i, scan_report.not_suppressed_because(disp[i], today)
                              if isinstance(disp[i], dict) else 'record is not an object')
                             for i in rekeyed)
        not_effective = dict((i, w) for i, w in not_effective.items() if w)
        if ns:
            state = NOT_SUPPRESSING
            why = ('this record does not suppress even inside the window (%s); nothing is lost '
                   'when the window closes' % ns)
        elif idents and len(rekeyed) == len(idents) and not_effective:
            state = REKEYED_REPLACEMENT_NOT_EFFECTIVE
            why = ('a record exists on the durable identity but it does NOT suppress today (%s): it '
                   'is not an effective approval, so the migration is not done. Reaffirm it on the '
                   'durable key before %s, or this finding is unapproved when the window closes'
                   % ('; '.join('%s: %s' % (i[:12], w) for i, w in sorted(not_effective.items()))[:400],
                      scan_report.legacy_key_window_closes))
        elif idents and len(rekeyed) == len(idents):
            state = ALREADY_REKEYED
            why = ('an effective (approved, in-date) record keyed on the durable identity exists; '
                   'a person may retire the legacy entry')
        elif len(idents) == 1:
            state = REKEY_REQUIRED
            why = ('reaffirm this decision keyed on `%s` before %s, or it stops suppressing'
                   % (idents[0], scan_report.legacy_key_window_closes))
        else:
            state = REKEY_REQUIRED_IDENTITY_UNRESOLVED
            if len(idents) > 1:
                why = ('the legacy key matches %d different durable identities, so it names no one '
                       'finding: decide each identity on its own' % len(idents))
            elif k in refused:
                why = ('the finding was seen but no durable identity was computed for it (%s): '
                       'fix the extraction, or decide it under the identity a corrected run gives'
                       % '; '.join(sorted(set(refused[k])))[:300])
            else:
                why = ('no finding in the findings file(s) carries this legacy key: the finding '
                       'was not seen, or no findings file was given. Run a scan and inventory again')
        row['inventory_state'] = state
        row['reaffirmation_required'] = state in NEEDS_ACTION
        row['action'] = why
        out['rows'].append(row)
    summary = dict((s, 0) for s in STATES)
    for r in out['rows']:
        summary[r['inventory_state']] += 1
    summary.update(legacy_keys=len(out['rows']), durable_keys=durable,
                   unrecognised_keys=len(out['unrecognised_keys']),
                   reaffirmation_required=sum(1 for r in out['rows'] if r['reaffirmation_required']))
    out['summary'] = summary
    return out


def render_text(inv):
    L = ['LEGACY-KEY INVENTORY (read-only; nothing was written or re-keyed)',
         'register: %s (%s)' % (inv['register'], inv['register_state']),
         'window: opened %s, closes %s -- %s on %s'
         % (inv['window_opened'], inv['window_closes'],
            'OPEN' if inv['window_open'] else 'CLOSED (legacy keys no longer suppress)', inv['today'])]
    for r in inv['rows']:
        L.append('')
        L.append('%s  %s' % (r['legacy_key'], r['inventory_state']))
        L.append('  %s / %s at %s' % (r['scanner'] or '?', r['rule'] or '?', r['scope_path'] or '?'))
        L.append('  claim %s, state %s, owner %s, expires %s'
                 % (r['disposition_type'] or '?', r['state'] or '(proposed)', r['owner'] or 'NONE',
                    r['expires'] or 'NONE'))
        L.append('  durable identity: %s' % (', '.join(r['durable_identities']) or 'NOT RESOLVED'))
        L.append('  reaffirmation required: %s' % ('YES' if r['reaffirmation_required'] else 'no'))
        L.append('  %s' % r['action'])
    if inv['unrecognised_keys']:
        L.append('')
        L.append('keys of neither shape (not legacy, not durable): %s' % ', '.join(inv['unrecognised_keys']))
    for n in inv['notes']:
        L.append('note: %s' % n)
    s = inv['summary']
    L.append('')
    L.append('SUMMARY: %d legacy-keyed, %d need reaffirmation (%d resolved, %d identity unresolved), '
             '%d already re-keyed, %d re-keyed but the replacement is NOT effective (included in the '
             'need-reaffirmation count), %d not suppressing anyway; %d durable-keyed; %d unrecognised'
             % (s['legacy_keys'], s.get('reaffirmation_required', 0), s[REKEY_REQUIRED],
                s[REKEY_REQUIRED_IDENTITY_UNRESOLVED], s[ALREADY_REKEYED],
                s[REKEYED_REPLACEMENT_NOT_EFFECTIVE], s[NOT_SUPPRESSING],
                s['durable_keys'], s['unrecognised_keys']))
    return '\n'.join(L) + '\n'


def main(argv=None):
    ap = argparse.ArgumentParser(description='Read-only inventory of legacy-keyed dispositions.')
    ap.add_argument('--register', required=True, help='the disposition register (e.g. .security/dispositions.json)')
    ap.add_argument('--findings', action='append', default=[],
                    help='a findings.json the report wrote (repeatable); resolves durable identities')
    ap.add_argument('--today', default='', help='YYYY-MM-DD; default today')
    ap.add_argument('--json', action='store_true')
    a = ap.parse_args(argv)
    today = scan_report._date(a.today) if a.today else None
    if a.today and today is None:
        ap.error('--today must be YYYY-MM-DD')
    inv = inventory(a.register, a.findings, today)
    if a.json:
        sys.stdout.write(json.dumps(inv, indent=1, sort_keys=True) + '\n')
    else:
        sys.stdout.write(render_text(inv))
    return 0 if inv['register_state'] == 'LOADED' else 2


if __name__ == '__main__':
    sys.exit(main())

#!/usr/bin/env python3
"""The ticket ledger is persisted through the SAME reviewed pull request as the baseline (T-20).

WHY THIS EXISTS

    The completion audit (T-20 / B-15) found that reusable-ticket-reconcile.yml uploads
    `ticket-ledger-proposal.json` and nothing consumes it: propose-ledger had no ticket reference.
    So a hosted run never persisted a ticket reference or a predecessor, and the run after a
    successor ticket would read predecessor and successor as BINDING_AMBIGUOUS. TICKETING_CONTRACT.md
    section 7.2: ledger writes are "a separate reviewed change, merged under CODEOWNERS" -- section
    5.4's rule, one write path. So the ticket ledger proposal joins the baseline proposal's pull
    request; it never gets a second write path.

WHAT IT PROVES, BY RUNNING THE SHIPPED STEPS (the harness in prove_propose_ledger_establishment.py)

    static     the reusable declares an optional `ticket-ledger-artifact` input (no default), a
               download step that runs only when it is named, and hands the proposal to the
               composite.
    persisted  a changed ticket ledger proposal is committed, canonical, at .security/ticket-ledger.json
               on the proposal branch, beside the baseline ledger, in ONE pull request.
    no noise   a proposal identical to the default tip adds no file, and with nothing else to
               propose the run is `unchanged` (no branch, no PR).
    no baseline  with no baseline ledger and no approver role, a changed ticket ledger is still
               persisted, and the body says the baseline was not established and why.
    refused    a ticket ledger proposal that is not the reconciler's ledger shape refuses the run
               with the reason: an unreadable binding record must not be merged as if it were one.
    absent     an input naming an artifact with no proposal in it proposes nothing for tickets and
               says so -- the reconciler writes no proposal on a run that found no ledger.

EXIT  0 proven   1 a case failed (named)   2 could not be checked (UNKNOWN, never PASS)
"""
import io
import json
import os
import shutil
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, HERE)
sys.path.insert(0, os.path.join(ROOT, 'scripts'))
TICKETS = '.security/ticket-ledger.json'
LEDGER = '.security/finding-baseline.json'
ART = 'ticket-reconcile-1'


def canonical(doc):
    # The reconciler's own serialisation (reconcile_tickets.save_ledger).
    return json.dumps(doc, indent=2, sort_keys=True) + '\n'


def main():
    try:
        import yaml
        import prove_propose_ledger_establishment as h
        import prove_bootstrap_failure as pbf
        from finding_identity import identify
        import baseline_ledger as bl
    except ImportError as exc:
        print('UNKNOWN: %s' % exc)
        return 2
    doc = yaml.safe_load(io.open(h.WF, encoding='utf-8'))
    action = yaml.safe_load(io.open(os.path.join(h.action_dir, 'action.yml'), encoding='utf-8'))
    fails = []
    on = (doc.get(True) or doc.get('on') or {}).get('workflow_call') or {}
    spec = (on.get('inputs') or {}).get('ticket-ledger-artifact')
    if spec is None:
        fails.append('static: the reusable has no `ticket-ledger-artifact` input, so the ticket ledger '
                     'proposal reconcile uploads is consumed by nothing (T-20)')
    elif str(spec.get('default') or '') != '':
        fails.append('static: ticket-ledger-artifact has a default (%r)' % spec.get('default'))
    steps = (doc.get('jobs') or {}).get(h.JOB, {}).get('steps') or []
    dl = [s for s in steps if str(s.get('uses') or '').startswith('actions/download-artifact@')
          and 'ticket-ledger-artifact' in str((s.get('with') or {}).get('name'))]
    if not dl or "inputs.ticket-ledger-artifact != ''" not in str(dl[0].get('if') or ''):
        fails.append('static: no download step for the ticket ledger proposal, conditioned on the input')
    prop = next((s for s in steps if s.get('id') == 'propose'), {})
    if 'ticket-ledger-proposal' not in (prop.get('with') or {}):
        fails.append('static: the propose step does not hand a ticket ledger proposal to the composite')
    if 'ticket-ledger-proposal' not in (action.get('inputs') or {}):
        fails.append('static: the composite has no ticket-ledger-proposal input')

    bash, why = pbf.usable_bash()
    if not bash or not shutil.which('jq') or not shutil.which('python3'):
        for f in fails:
            print('FAIL: ' + f)
        print('UNKNOWN: bash, jq or python3 unavailable (%s)' % why)
        return 1 if fails else 2

    a = identify({'finding_subject': 'SOURCE', 'cwe': 'CWE-78', 'rule_family': 'cmd',
                  'canonical_path': 'app.py', 'symbol_path': 'm.a', 'construct': 'run(a)',
                  'language_family': 'hash'})
    prov = {'run_id': '41', 'observed_at': '2026-01-05T00:00:00Z', 'observed_at_source': 'SIDECAR'}
    header = {'established_on': '2026-01-05', 'established_commit': 'e' * 40, 'approver_role': 'security-lead'}
    baseline = bl.serialise(bl.new_ledger(header, [bl.entry_from_identity(a, 'prod', '2026-01-05', prov, True)]))
    tip_tickets = {'schema': 1, 'clusters': {'ck-1': {'ref': 'SEC-1', 'member_identities': [a['identity']]}}}
    moved_on = {'schema': 1, 'clusters': {'ck-1': {'ref': 'SEC-2', 'predecessors': ['SEC-1'],
                                                   'member_identities': [a['identity']]}}}
    owners = {'.github/CODEOWNERS': '/.security/ @example-org/security-leads\n'}
    work = tempfile.mkdtemp(prefix='propose-tickets-')

    def seed(files):
        remote = os.path.join(work, 'remote-%d.git' % len(os.listdir(work)))
        os.makedirs(remote)
        h.git(remote, 'init', '-q', '--bare')
        s = remote + '-seed'
        os.makedirs(s)
        h.git(s, 'init', '-q')
        h.write(os.path.join(s, 'README'), 'x\n')
        for rel, text in files.items():
            h.write(os.path.join(s, rel), text)
        h.git(s, 'add', '-A')
        h.git(s, 'commit', '-qm', 'seed')
        h.git(s, 'push', '-q', remote, 'HEAD:refs/heads/main')
        return remote

    def show(remote, path):
        return subprocess.run(['git', 'show', 'refs/heads/baseline-proposal/prod/4242:%s' % path],
                              cwd=remote, capture_output=True, text=True)

    inputs = {'environment': 'prod', 'ticket-ledger-artifact': ART}
    try:
        # ── persisted: a successor binding reaches the proposal branch, beside the baseline ──
        remote = seed(dict(owners, **{LEDGER: baseline, TICKETS: canonical(tip_tickets)}))
        r = h.run_reusable(doc, action, bash, work, remote, inputs, [a],
                           {ART: {'ticket-ledger-proposal.json': json.dumps(moved_on)}})
        got = show(remote, TICKETS)
        if r['status'] != 'proposed' or got.returncode != 0 or got.stdout != canonical(moved_on):
            fails.append('persisted: the changed ticket ledger did not reach the proposal branch '
                         '(status %r, why %r): %s' % (r['status'], r['why'], (got.stderr or r['log'])[-300:]))
        elif 'pr create' not in r['gh'] or 'ticket' not in r['body'].lower():
            fails.append('persisted: no pull request, or its body does not mention the ticket ledger')

        # ── no noise: identical to the tip -> nothing to propose ──────────────
        remote = seed(dict(owners, **{LEDGER: baseline, TICKETS: canonical(tip_tickets)}))
        r = h.run_reusable(doc, action, bash, work, remote, inputs, [a],
                           {ART: {'ticket-ledger-proposal.json': json.dumps(tip_tickets)}})
        if r['status'] != 'unchanged' or r['gh'].strip():
            fails.append('no noise: an unchanged ticket ledger gave %r (gh %r, why %r)'
                         % (r['status'], r['gh'], r['why']))

        # ── no baseline: tickets persist; the body says why the baseline did not ──
        remote = seed(dict(owners, **{TICKETS: canonical(tip_tickets)}))
        r = h.run_reusable(doc, action, bash, work, remote, inputs, [a],
                           {ART: {'ticket-ledger-proposal.json': json.dumps(moved_on)}})
        if r['status'] != 'proposed' or show(remote, TICKETS).stdout != canonical(moved_on):
            fails.append('no baseline: the ticket ledger was not persisted without a baseline (%r, %r)'
                         % (r['status'], r['why']))
        elif show(remote, LEDGER).returncode == 0 or 'approver role' not in r['body']:
            fails.append('no baseline: a baseline was written, or the body does not say why none was')

        # ── refused: not the reconciler's ledger shape ────────────────────────
        remote = seed(dict(owners, **{LEDGER: baseline}))
        r = h.run_reusable(doc, action, bash, work, remote, inputs, [a],
                           {ART: {'ticket-ledger-proposal.json': '{"clusters": ["not", "a", "map"]}'}})
        if r['status'] != 'refused' or 'ticket ledger' not in (r['why'] or ''):
            fails.append('refused: a malformed ticket ledger proposal gave %r (%r)' % (r['status'], r['why']))

        # ── absent: the artifact holds no proposal ────────────────────────────
        remote = seed(dict(owners, **{LEDGER: baseline}))
        r = h.run_reusable(doc, action, bash, work, remote, inputs, [a],
                           {ART: {'ticket-run-record.json': '{}'}})
        if r['status'] != 'unchanged' or r['rc'] != 0:
            fails.append('absent: an artifact with no ticket ledger proposal gave %r (exit %s): %s'
                         % (r['status'], r['rc'], r['log'][-300:]))
    except h.Unrenderable as exc:
        print('UNKNOWN: the harness cannot render %s' % exc)
        return 2
    except RuntimeError as exc:
        print('UNKNOWN: fixture could not be built: %s' % exc)
        return 2
    finally:
        shutil.rmtree(work, ignore_errors=True)

    if fails:
        for f in fails:
            print('FAIL: ' + f)
        return 1
    print('PASS: the ticket ledger proposal is persisted through the baseline proposal\'s pull request '
          '(one write path): a successor binding lands canonical at %s beside the baseline; an '
          'unchanged one adds nothing; with no baseline it still persists and the body says why; a '
          'malformed one refuses; an artifact without one proposes nothing for tickets.' % TICKETS)
    return 0


if __name__ == '__main__':
    sys.exit(main())

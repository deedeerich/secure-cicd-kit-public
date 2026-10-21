#!/usr/bin/env python3
"""propose-ledger: the ONLY write authority over the baseline ledger, and it writes a pull request.

(ETFB section 5.4; SINGLE_PIPELINE_TARGET.md section 6.1 and section 9.3; L45.)

WHAT THIS DOES

    Reads the ledger at the protected default branch's TIP, runs the cascade
    (scripts/finding_match.py) over the observations of a post-merge or nightly run on that same
    branch, and produces the PAYLOAD of a pull request carrying the proposed ledger: a branch name,
    a base, a path, the full proposed file, a title and a body that lists every change. It writes
    no file in the repository, makes no commit and calls no API. The job that runs it opens the
    pull request; branch protection and CODEOWNERS do the enforcing. A human merges it or does not.

    "If that job's authority ever grows to include the protected branch, the ledger has stopped
    being a governance artifact and the whole baseline becomes a scanner output."

WHEN IT REFUSES, AND PRODUCES NOTHING

    - the run is a pull_request / pull_request_target event, or is on any ref but the default
      branch. A PR run may only read; a ledger written from a PR is a PR grandfathering itself.
    - the ledger cannot be read. Proposing against an unreadable ledger would re-baseline the
      repository -- every inherited finding re-admitted with today's date.
    - there is no ledger and establishment was not explicitly requested with an approver role.
      A baseline nobody approved is not a baseline (ETFB section 10).
    - establishment was requested, but no CODEOWNERS rule at the default branch's tip covers the
      ledger path. The ledger is merged "under CODEOWNERS" (ETFB section 5.4, section 10); without
      that rule nothing makes the named approver role the one who merges (F-01).

    An approver role given when a ledger already EXISTS is ignored and said so in the body: the
    input establishes, it never re-baselines (ETFB section 8.8 rule 1).

WHAT A PROPOSAL MAY AND MAY NOT DO

    may    admit a NEW finding: first_seen = this observation, age_established only when the time
           source is claimable and this is not the establishing run.
    may    re-key a MOVED finding to its new identity, carrying first_seen and every other field,
           and record the move ONCE, as a lineage event (SUPERSEDES, PATH_MOVED) appended to
           .security/finding-lineage.jsonl in the same pull request (L51). A move is a recorded
           event, not a reset -- and one record, not two. A lineage ledger that is tampered with
           or unparseable at the tip is never extended: the proposal refuses.
    may    admit the cardinality SURPLUS of an ambiguous group as NEW entries, saying so.
    never  change an existing entry's first_seen (ETFB section 8.8 rule 1: a re-baseline may add
           entries, it may never reset one). Checked on the output, not merely avoided.
    never  remove an unobserved entry. It is POTENTIALLY_ABSENT -- absence of the scope is not
           absence of the thing -- and closing it needs demonstrated coverage, which is a separate
           reviewed act this kit does not build yet.
    never  admit an uncomputable identity. It is listed in the body as EVIDENCE_UNTRUSTED.
    never  admit a finding first reported by a scanner generation the alias table does not pin and
           no accepted reconciliation covers (L46, ETFB section 5.5). It is HELD, and the proposal
           opens ONE reconciliation report for that (scanner, from, to) under
           .security/reconciliations/ with a bounded window. Once a named approver role accepts it,
           exactly the findings it lists enter as detection changes with no established age.

    ESTABLISHMENT asserts no age at all: "first observed by us on <date>; the finding may be older"
    (ETFB section 8.3). Every entry it creates carries age_established false.

USAGE
    python3 propose_ledger.py --self-test
    python3 propose_ledger.py --repo . --default-ref origin/main --default-branch main \
        --event "$GITHUB_EVENT_NAME" --ref "$GITHUB_REF" --environment prod \
        --observations identities.json --run-id "$GITHUB_RUN_ID" --commit "$GITHUB_SHA" \
        --observed-at <ISO time> --observed-at-source SIDECAR --out proposal.json

EXIT  0 proposed or unchanged   1 refused (reason printed)   2 usage, or self-test failed
"""
import argparse
import io
import json
import os
import shutil
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import baseline_ledger as bl  # noqa: E402
import finding_lineage as fl  # noqa: E402
import finding_match as fm  # noqa: E402
import rule_family as rf  # noqa: E402

PROPOSED = 'proposed'
UNCHANGED = 'unchanged'
REFUSED = 'refused'

PR_EVENTS = ('pull_request', 'pull_request_target')

# ONE MOVE RECORD (L51 / B-08). A move used to be written twice: as `move_history` inside the
# baseline entry, and -- in design -- as a finding_lineage event, two records that could disagree.
# Now a move is ONE lineage event (SUPERSEDES, cause PATH_MOVED), hash-chained and head-anchored,
# carried in the same pull request as the re-keyed entry. The entry keeps first_seen; the lineage
# says what it moved from, when, and who asserted it. POSIX form: it is a path inside the repository.
LINEAGE_PATH = '.security/finding-lineage.jsonl'
LINEAGE_USABLE = (fl.LEDGER_INTACT, fl.LEDGER_EMPTY, fl.LEDGER_ABSENT)


def _refuse(why):
    return {'status': REFUSED, 'why': why, 'content': None, 'branch': None, 'base': None,
            'path': None, 'title': None, 'body': None, 'delta': None, 'files': []}


def read_lineage_at_ref(repo, ref, path, scratch):
    """Materialise the lineage ledger and its head anchor AT THE REF into `scratch`, never from a
    working tree, and load them the way every reader does. -> (events, integrity, notes, local path)."""
    local = os.path.join(scratch, 'finding-lineage.jsonl')
    for rel, dest in ((path, local), (path + '.head', fl.head_path(local))):
        rc, out, _err = bl._git(repo, 'show', '%s:%s' % (ref, rel))
        if rc == 0:
            with io.open(dest, 'wb') as fh:
                fh.write(out)
    events, integrity, notes = fl.load(local)
    return events, integrity, notes, local


def first_seen_violations(before, after, moved_from=None):
    """-> list of problems. An entry present before (by identity, or by the identity it moved
    from, as the lineage events of this proposal record it) must keep its first_seen exactly.
    ETFB section 8.8 rule 1, checked on the output."""
    out = []
    old = dict(((e['identity'], e['environment']), e) for e in before)
    for e in after:
        keys = [(e['identity'], e['environment'])]
        for src in (moved_from or {}).get(e['identity']) or []:
            keys.append((src, e['environment']))
        for k in keys:
            if k in old and old[k].get('first_seen') != e.get('first_seen'):
                out.append('%s: first_seen %r became %r' % (k[0][:16], old[k].get('first_seen'),
                                                             e.get('first_seen')))
            if k in old and old[k].get('age_established') is False and e.get('age_established') is True:
                out.append('%s: an unestablished age became established' % k[0][:16])
    return out


# Where GitHub looks for CODEOWNERS, in its own order; the first file found is the only one read.
CODEOWNERS_PATHS = ('.github/CODEOWNERS', 'CODEOWNERS', 'docs/CODEOWNERS')


def _codeowners_regex(pattern):
    """A CODEOWNERS (gitignore-style) pattern -> compiled regex over a repo-relative path."""
    import re
    anchored = pattern.startswith('/') or '/' in pattern.rstrip('/')
    pat = pattern.lstrip('/')
    directory = pat.endswith('/')
    pat = pat.rstrip('/')
    out, i = [], 0
    while i < len(pat):
        if pat.startswith('**/', i):
            out.append('(?:.*/)?')
            i += 3
        elif pat.startswith('**', i):
            out.append('.*')
            i += 2
        elif pat[i] == '*':
            out.append('[^/]*')
            i += 1
        elif pat[i] == '?':
            out.append('[^/]')
            i += 1
        else:
            out.append(re.escape(pat[i]))
            i += 1
    body = ''.join(out)
    prefix = '^' if anchored else '^(?:.*/)?'
    # A pattern names a file OR a directory; a directory covers everything beneath it.
    suffix = '/.*$' if directory else '(?:/.*)?$'
    return re.compile(prefix + body + suffix)


def codeowners_for(repo, ref, path):
    """-> (owners, why). The owners CODEOWNERS at `ref` assigns to `path` (last matching rule wins,
    as GitHub reads it); ([], reason) when no file exists or no rule with owners covers the path.
    Read from the git ref, never a working tree, like the ledger itself."""
    for loc in CODEOWNERS_PATHS:
        rc, out, _err = bl._git(repo, 'show', '%s:%s' % (ref, loc))
        if rc != 0:
            continue
        owners = []
        for line in out.decode('utf-8', 'replace').splitlines():
            line = line.split('#', 1)[0].strip()
            if not line:
                continue
            parts = line.split()
            if _codeowners_regex(parts[0]).match(path):
                owners = parts[1:]
        if not owners:
            return [], 'CODEOWNERS (%s at %s) assigns no owner to %s' % (loc, ref, path)
        return owners, 'CODEOWNERS (%s) assigns %s' % (loc, ' '.join(owners))
    return [], 'no CODEOWNERS file exists at %s (looked in %s)' % (ref, ', '.join(CODEOWNERS_PATHS))


# THE TICKET LEDGER JOINS THE SAME PULL REQUEST (T-20 / B-15). reusable-ticket-reconcile.yml uploads
# the ledger it updated as a PROPOSAL; TICKETING_CONTRACT.md section 7.2 says ledger writes are "a
# separate reviewed change, merged under CODEOWNERS" -- section 5.4's rule, one write path. Without
# this nothing consumed the proposal, so no hosted run ever persisted a ticket reference or a
# predecessor, and the run after a successor read the two as BINDING_AMBIGUOUS.
TICKET_LEDGER_PATH = '.security/ticket-ledger.json'


def _ticket_canonical(doc):
    # reconcile_tickets.save_ledger's own serialisation, so an unchanged ledger diffs as unchanged.
    return json.dumps(doc, indent=2, sort_keys=True) + '\n'


def ticket_part(repo, default_ref, proposal_path, ticket_path):
    """-> (result, refusal). result = {state, file, note}; state is one of `not supplied`,
    `absent`, `unchanged`, `updated`. A proposal that is not the reconciler's ledger shape is a
    REFUSAL: an unreadable binding record must not be merged as though it were one."""
    if not (proposal_path or '').strip():
        return {'state': 'not supplied', 'file': None, 'note': ''}, ''
    if unsafe_path(ticket_path):
        return None, 'the ticket ledger path %s' % unsafe_path(ticket_path)
    if not os.path.isfile(proposal_path):
        return {'state': 'absent', 'file': None,
                'note': 'no ticket ledger proposal at %s: the ticket job wrote none (it writes one only '
                        'when it read or created a ledger), so no ticket binding is proposed'
                        % proposal_path}, ''
    try:
        doc = json.load(io.open(proposal_path, encoding='utf-8'))
    except (IOError, ValueError) as exc:
        return None, 'the ticket ledger proposal %s cannot be read: %s' % (proposal_path, exc)
    if (not isinstance(doc, dict) or set(doc) - {'schema', 'clusters'} or doc.get('schema') != 1
            or not isinstance(doc.get('clusters'), dict)
            or not all(isinstance(k, str) and isinstance(v, dict) for k, v in doc['clusters'].items())):
        return None, ('the ticket ledger proposal %s is not the reconciler\'s ledger shape '
                      '({schema: 1, clusters: {cluster key: entry}}). An unreadable binding record '
                      'merged as one would bind clusters to tickets nobody can check' % proposal_path)
    text = _ticket_canonical(doc)
    rc, out, _err = bl._git(repo, 'show', '%s:%s' % (default_ref, ticket_path))
    if rc == 0:
        try:
            if _ticket_canonical(json.loads(out.decode('utf-8', 'replace'))) == text:
                return {'state': 'unchanged', 'file': None,
                        'note': 'the ticket ledger proposal equals %s at the default tip' % ticket_path}, ''
        except ValueError:
            pass        # an unreadable tip ledger is replaced by the readable proposal, under review
    return {'state': 'updated', 'file': {'path': ticket_path, 'content': text},
            'note': 'ticket bindings updated: %d cluster(s) in %s' % (len(doc['clusters']), ticket_path)}, ''


# A SCANNER UPGRADE IS A DECLARED EVENT ON THE WRITE PATH (L46, ETFB section 5.5). The alias table's
# pinned generation is read at the default tip; reconciliation reports live beside it, one file per
# (scanner, from, to), reviewed and accepted like every other governance file.
RECONCILIATION_DIR = '.security/reconciliations'
# ETFB section 13: every number in the design is a placeholder for an owner's decision (O-06). This is
# the default the composite passes until the owner sets one; it is never a constant in rule_family.
DEFAULT_RECONCILIATION_WINDOW_DAYS = 30


def _report_path(scanner, from_gen, to_gen):
    return '%s/%s-%s-%s.json' % (RECONCILIATION_DIR, scanner, from_gen, to_gen)


def generation_gate(repo, default_ref, observations):
    """-> (gate, reports, note). gate(obs) -> (decision, key, why) with decision one of
    'admit' (no pinned generation governs it), 'authoritative', 'accepted' (a reconciliation for
    exactly this change was accepted), 'hold' (DECISION_REQUIRED or EVIDENCE_UNTRUSTED).
    `reports` maps (scanner, from, to) -> the report document at the tip, if any."""
    table, tstate, tnotes = rf.read_table_at_ref(repo, default_ref)
    if tstate != rf.USABLE:
        note = ('no usable rule-family alias table at the default tip (%s), so no scanner generation '
                'is pinned and no upgrade can be declared' % '; '.join(tnotes[:1]))
        return (lambda o: ('admit', None, note)), {}, note
    reports = {}
    rc, out, _err = bl._git(repo, 'ls-tree', '--name-only', '%s:%s' % (default_ref, RECONCILIATION_DIR))
    for name in (out.decode('utf-8', 'replace').split() if rc == 0 else []):
        if not name.endswith('.json'):
            continue
        rc2, body, _e2 = bl._git(repo, 'show', '%s:%s/%s' % (default_ref, RECONCILIATION_DIR, name))
        try:
            doc = json.loads(body.decode('utf-8', 'replace')) if rc2 == 0 else None
        except ValueError:
            doc = None
        if isinstance(doc, dict) and doc.get('scanner'):
            reports[(doc['scanner'], doc.get('from_generation'), doc.get('to_generation'))] = doc
    accepted = []
    for doc in reports.values():
        acc = doc.get('acceptance') or {}
        if acc and not rf.validate_acceptance(dict(doc, acceptance=None), acc.get('approver_role'),
                                              acc.get('accepted_on')):
            accepted.append(doc)
    pins = (table.get('generations') or {})

    def gate(o):
        name = next((n for n in (str(o.get('scanner') or '').lower(), str(o.get('tool') or '').lower())
                     if n and n in pins), None)
        if not name:
            return 'admit', None, 'no generation is pinned for %s' % (o.get('tool') or o.get('scanner'))
        gc = rf.generation_check(table, name, o.get('scanner_version') or '', accepted)
        key = (name, gc['pinned'], gc['observed'])
        if gc['authoritative'] and gc['changed']:
            return 'accepted', key, gc['why']
        if gc['authoritative']:
            return 'authoritative', key, gc['why']
        return 'hold', key, '%s: %s' % (gc['routes_to'], gc['why'])
    return gate, reports, 'alias table read; %d pinned generation(s), %d accepted reconciliation(s)' % (
        len(pins), len(accepted))


def propose(repo, observations, path, event, ref, default_branch, default_ref, environment,
            run_id, commit, observed_at, observed_at_source, establish_approver_role='',
            ticket_proposal_path='', ticket_path=TICKET_LEDGER_PATH,
            reconciliation_window_days=DEFAULT_RECONCILIATION_WINDOW_DAYS):
    """-> payload dict with `status` PROPOSED, UNCHANGED or REFUSED. Writes nothing."""
    if not default_branch:
        return _refuse('no default branch was named, so it cannot be established that this run is '
                       'on the protected branch')
    if not event or event in PR_EVENTS:
        return _refuse('event %r: a pull-request run may only READ the ledger. A ledger written from '
                       'a PR is a PR grandfathering what it introduces' % (event or None))
    if ref != 'refs/heads/%s' % default_branch:
        return _refuse('ref %r is not refs/heads/%s. Only the protected branch\'s own post-merge '
                       'or nightly run may propose' % (ref, default_branch))
    for name, value in (('environment', environment), ('run_id', run_id), ('commit', commit),
                        ('observed_at', observed_at), ('observed_at_source', observed_at_source)):
        if not (value or '').strip():
            return _refuse('%s is empty; every admitted entry carries it as provenance' % name)
    if observed_at_source not in bl.observation_time_sources:
        return _refuse('observed_at_source %r is not a registered observation-time source'
                       % observed_at_source)

    tickets, ticket_refusal = ticket_part(repo, default_ref, ticket_proposal_path, ticket_path)
    if ticket_refusal:
        return _refuse(ticket_refusal)

    entries, state, notes, header, _sha = bl.read_at_ref(repo, default_ref, path)
    establishing = False
    role_ignored = False
    if state == bl.LEDGER_ABSENT:
        if not (establish_approver_role or '').strip():
            why = ('no ledger exists at %s:%s, and establishment was not requested with an '
                   'approver role. A baseline nobody approved is not a baseline' % (default_ref, path))
            if tickets['file']:
                # The ticket bindings still persist -- they do not depend on a baseline -- and the
                # body says plainly that the baseline was not established, and why.
                return {'status': PROPOSED, 'why': 'ticket bindings only; baseline: ' + why,
                        'content': None, 'branch': 'baseline-proposal/%s/%s' % (environment, run_id),
                        'base': default_branch, 'path': path,
                        'title': 'tickets (%s): ticket bindings updated; no baseline' % environment,
                        'body': '\n'.join([
                            'Proposed by propose-ledger from run %s at %s (%s), environment `%s`.'
                            % (run_id, commit[:12], observed_at, environment), '',
                            'This pull request carries the ticket ledger only: %s.' % tickets['note'], '',
                            '**No baseline is proposed:** %s.' % why]),
                        'delta': {'admitted': [], 'moved': [], 'potentially_absent': [],
                                  'evidence_untrusted': [], 'establishing': False,
                                  'ticket_ledger': tickets['state'], 'baseline_refused': why},
                        'files': [tickets['file']]}
            return _refuse(why)
        # ETFB section 5.4 and section 10: the ledger is merged "under CODEOWNERS". Without an owner
        # rule over the ledger path, nothing makes the NAMED ROLE the one who merges -- anyone with
        # write access could, and the header would record an approval that never happened.
        owners, why_owners = codeowners_for(repo, default_ref, path)
        if not owners:
            return _refuse('establishment requested for approver role %r, but %s. Add a CODEOWNERS '
                           'rule over %s naming the team that holds that role, then re-run: a header '
                           'naming an approver nothing enforces is a record of an approval that '
                           'never happened' % (establish_approver_role.strip(), why_owners, path))
        establishing = True
        state = bl.LEDGER_EMPTY
        header = {'established_on': observed_at[:10], 'established_commit': commit,
                  'approver_role': establish_approver_role.strip()}
    elif state not in bl.USABLE:
        return _refuse('%s: the ledger at %s is %s (%s). Proposing against it would re-baseline '
                       'the repository' % (fm.BASELINE_UNAVAILABLE, default_ref, state,
                                           '; '.join(notes[:3])))
    elif (establish_approver_role or '').strip():
        # The input ESTABLISHES; it never re-baselines (ETFB section 8.8 rule 1: a whole-repo
        # re-baseline is its own governance act). The header is carried unchanged.
        role_ignored = True

    result = fm.match(observations, [e for e in entries], state, environment)
    if result['baseline'] == fm.BASELINE_UNAVAILABLE:
        return _refuse('%s: %s' % (fm.BASELINE_UNAVAILABLE, result['why']))

    prov = {'run_id': run_id, 'observed_at': observed_at, 'observed_at_source': observed_at_source}
    claimable = observed_at_source in bl.CLAIMABLE and not establishing
    by_key = dict(((e['identity'], e['environment']), dict(e)) for e in entries)
    admitted, moved, untrusted = [], [], []
    gate, reports, generation_note = generation_gate(repo, default_ref, observations)
    held = {}           # (scanner, from, to) -> [(obs, why)]: owed a reconciliation, never admitted

    def admit(obs, why):
        decision, key, gwhy = gate(obs)
        if decision == 'hold':
            # ETFB section 5.5: "an upgrade may never, by itself, create a NEW finding", and the new
            # generation "is not authoritative ... until that report is reviewed and accepted".
            held.setdefault(key, []).append((obs, gwhy))
            return
        if decision == 'accepted' and obs['identity'] in [
                x.get('identity') for x in (reports.get(key) or {}).get('appeared') or []]:
            # Admitted by the ACCEPTED reconciliation: real findings, not the author's doing, whose
            # age is NOT established and is never asserted as the upgrade date.
            acc = reports[key]['acceptance']
            e = bl.entry_from_identity(obs, environment, observed_at[:10], prov, False,
                                       detection_change=True)
            e['admitted_by'] = ('reconciliation %s %s -> %s, accepted by %s on %s'
                                % (key[0], key[1], key[2], acc['approver_role'], acc['accepted_on']))
        else:
            e = bl.entry_from_identity(obs, environment, observed_at[:10], prov, claimable)
            e['admitted_by'] = why
        by_key[(e['identity'], environment)] = e
        admitted.append(e['identity'])

    for f in result['findings']:
        obs = observations[f['index']]
        if f['match'] == fm.IDENTITY_UNCOMPUTABLE:
            untrusted.append('observation %d: %s' % (f['index'], f['why']))
        elif f['match'] == fm.IDENTITY_UNMATCHED and (obs['identity'], environment) not in by_key:
            admit(obs, 'run %s: no ledger entry shared WHAT and CONTENT' % run_id)
    move_events, moved_from = [], {}
    for mv in result['moves']:
        old = by_key.pop((mv['ledger_identity'], environment))
        obs = observations[mv['observations'][0]]
        new = dict(old)
        for k in ('identity', 'what', 'where', 'content'):
            new[k] = obs[k]
        # The entry is re-keyed and keeps first_seen; the MOVE ITSELF is recorded once, below, as a
        # lineage event. Never a second copy in the entry (L51).
        new.pop('move_history', None)
        by_key[(new['identity'], environment)] = new
        moved.append(mv['ledger_identity'])
        moved_from.setdefault(new['identity'], []).append(mv['ledger_identity'])
        move_events.append({
            'relation': fl.SUPERSEDES, 'from_identities': [mv['ledger_identity']],
            'to_identities': [new['identity']], 'finding_subject': new.get('finding_subject'),
            'cause': fl.PATH_MOVED,
            'cause_detail': 'environment %s: WHAT and CONTENT agree with exactly one unmatched '
                            'ledger entry; WHERE %s -> %s (finding_match cascade, MOVED)'
                            % (environment, mv['from_where'][:16], mv['to_where'][:16]),
            'observed_at': observed_at, 'observed_at_source': observed_at_source,
            'asserted_by': {'actor': 'scripts/propose_ledger.py', 'actor_class': fl.TOOL,
                            'method': 'the matching cascade; confirmed only when a reviewer merges '
                                      'the pull request that carries it'},
            'provenance': {'commit_sha': commit, 'ref': ref, 'run_id': run_id}})
    for g in result['groups']:
        if g['new'] <= 0:
            continue
        candidates = sorted(observations[i]['identity'] for i in g['observations'])
        fresh = [c for c in candidates if (c, environment) not in by_key][-g['new']:]
        for ident in fresh:
            obs = next(observations[i] for i in g['observations']
                       if observations[i]['identity'] == ident)
            admit(obs, 'run %s: cardinality surplus of an ambiguous group (%d entr(y/ies), %d '
                       'observation(s)); WHICH observation is new is undecidable and recorded as '
                       'such' % (run_id, len(g['ledger_identities']), len(g['observations'])))

    # ── the reconciliation each held generation change owes, opened ONCE ────────────────────
    report_files, held_lines = [], []
    for key, items in sorted(held.items(), key=lambda kv: tuple(str(x) for x in kv[0])):
        scanner, from_gen, to_gen = key
        held_lines.append('- held, %d finding(s) from %s: %s' % (len(items), scanner, items[0][1]))
        if not to_gen:
            continue            # EVIDENCE_UNTRUSTED: no version, nothing a report could reconcile
        if key in reports:
            held_lines.append('  - the reconciliation %s is already open at the default tip (opened '
                              '%s, window closes %s); it is not re-opened'
                              % (_report_path(*key), reports[key].get('opened_on'),
                                 reports[key].get('window_expires')))
            continue
        ledger_ids = set(e['identity'] for e in entries if e.get('environment') == environment)
        same = [o for o in observations if o.get('state') in (None, 'FINGERPRINTED')
                and gate(o)[1] == key and o.get('identity')]
        continued = [dict(o, state='FINGERPRINTED') for o in same if o['identity'] in ledger_ids]
        # `appeared` is exactly what was held: a moved finding is continuity, not an appearance.
        rep = rf.reconciliation_report(
            continued, continued + [dict(o, state='FINGERPRINTED') for o, _w in items],
            scanner, from_gen, to_gen, observed_at[:10], int(reconciliation_window_days))
        rep['environment'] = environment
        rep['disappeared_basis'] = ('not established here: the ledger does not attribute entries to '
                                    'a scanner, so what this generation stopped reporting is the '
                                    'cascade\'s POTENTIALLY_ABSENT list in the pull request, not a '
                                    'list in this report')
        report_files.append({'path': _report_path(*key),
                             'content': json.dumps(rep, indent=2, sort_keys=True) + '\n'})
        held_lines.append('  - opened %s: accept it (approver_role, accepted_on, inside the window) '
                          'in a reviewed change, then update the pin' % _report_path(*key))

    proposed = list(by_key.values())
    problems = first_seen_violations(entries, proposed, moved_from)
    if problems:
        return _refuse('the proposal would re-date existing entries: %s' % '; '.join(problems[:5]))
    # ETFB section 8.8 rule 4. This run scanned the DEFAULT BRANCH'S SOURCE, not the artefact deployed
    # to `environment`, so presence there is an assumption of inheritance: declared and dated in the
    # header the first time this environment's entries are proposed, never silent. Kept unchanged
    # afterwards -- a later run does not re-date an earlier declaration.
    presence_declared = ''
    presence = dict((header or {}).get('environment_presence') or {})
    if (establishing or admitted or moved) and environment not in presence:
        presence[environment] = {'evidence': 'nightly' if event == 'schedule' else 'merge',
                                 'assumption': True, 'declared_on': observed_at[:10], 'run_id': run_id}
        header = dict(header, environment_presence=presence)
        presence_declared = ('Presence in `%s` is a DECLARED ASSUMPTION of inheritance, dated %s: this '
                             'run scanned the default branch (%s depth), not the artefact deployed '
                             'there (ETFB section 8.8 rule 4). A finding is grandfathered in `%s` on '
                             'that assumption, recorded in the header, never silently.'
                             % (environment, observed_at[:10], presence[environment]['evidence'],
                                environment))
    content = bl.serialise(bl.new_ledger(header, proposed))
    _e, check_state, check_notes, _h = bl.parse_ledger(content)
    if check_state not in bl.USABLE:
        return _refuse('the proposed ledger does not parse under the reader that would read it: %s'
                       % '; '.join(check_notes[:5]))
    files = [{'path': path, 'content': content}]

    # ── THE ONE MOVE RECORD: lineage events, appended by the lineage library's own writer ──────
    lineage_note = ''
    if move_events:
        scratch = tempfile.mkdtemp(prefix='propose-lineage-')
        try:
            events, integrity, lnotes, local = read_lineage_at_ref(repo, default_ref, LINEAGE_PATH, scratch)
            if integrity not in LINEAGE_USABLE:
                return _refuse('%d move(s) must be recorded in the lineage ledger, and the lineage '
                               'ledger at %s:%s is %s (%s). A chain nobody can verify is never '
                               'extended; repair it under review first'
                               % (len(move_events), default_ref, LINEAGE_PATH, integrity,
                                  '; '.join(lnotes[:2])))
            appended = 0
            for ev in move_events:
                src, dst = ev['from_identities'][0], ev['to_identities'][0]
                already = fl._successor_map(events).get(src) or []
                if already == [dst]:
                    continue        # the same move, already recorded (another environment's entry)
                _id, bad = fl.append_event(local, ev)
                if bad:
                    return _refuse('the lineage ledger refused the move %s -> %s: %s'
                                   % (src[:16], dst[:16], '; '.join(bad[:2])))
                events, _i, _n = fl.load(local)
                appended += 1
            if appended:
                for rel, src_file in ((LINEAGE_PATH, local), (LINEAGE_PATH + '.head', fl.head_path(local))):
                    files.append({'path': rel, 'content': io.open(src_file, encoding='utf-8').read()})
            lineage_note = ('%d move(s) recorded as lineage events in `%s` (%d already recorded)'
                            % (appended, LINEAGE_PATH, len(move_events) - appended))
        finally:
            shutil.rmtree(scratch, ignore_errors=True)

    unobserved = [u['identity'] for u in result['ledger_unobserved']]
    delta = {'admitted': admitted, 'moved': moved, 'potentially_absent': unobserved,
             'evidence_untrusted': untrusted, 'establishing': establishing,
             'ticket_ledger': tickets['state'],
             'held_generation': dict(('%s %s -> %s' % k, [o['identity'] for o, _w in v])
                                     for k, v in held.items()),
             'reconciliations_opened': [f['path'] for f in report_files]}
    baseline_changed = establishing or admitted or moved
    if not baseline_changed and not tickets['file'] and not report_files:
        return {'status': UNCHANGED, 'why': 'nothing to admit or move%s%s'
                % ('; ' + tickets['note'] if tickets['note'] else '',
                   ('; ' + ' '.join(held_lines)) if held_lines else ''), 'content': None,
                'branch': None, 'base': default_branch, 'path': path, 'title': None, 'body': None,
                'delta': delta, 'files': []}
    if not baseline_changed:
        files = []              # the baseline is unchanged: carry only what changed
    if tickets['file']:
        files.append(tickets['file'])
    files.extend(report_files)

    body = ['Proposed by propose-ledger from run %s at %s (%s), environment `%s`.'
            % (run_id, commit[:12], observed_at, environment), '',
            'This pull request is the ONLY way the baseline ledger changes. Review it as a '
            'governance decision: every admitted entry is grandfathered from the moment it merges.',
            '']
    if establishing:
        body += ['**Establishing the baseline.** Every entry says "first observed by us on %s; the '
                 'finding may be older" (age_established: false). Approver role: %s.'
                 % (observed_at[:10], establish_approver_role), '',
                 'This pull request must be merged by the approver role above (CODEOWNERS covers '
                 '`%s`). Merging it is the establishment decision; closing it establishes nothing.'
                 % path, '']
    if role_ignored:
        body += ['An approver role (%s) was supplied, and ignored: a ledger already exists, and '
                 'establishment never re-baselines one. Its header is unchanged.'
                 % establish_approver_role.strip(), '']
    body += ['| change | count |', '|---|---|',
             '| admitted (NEW) | %d |' % len(admitted), '| moved (first_seen carried) | %d |' % len(moved),
             '| unobserved, kept as POTENTIALLY_ABSENT | %d |' % len(unobserved),
             '| not admitted: EVIDENCE_UNTRUSTED | %d |' % len(untrusted), '']
    for u in untrusted[:50]:
        body.append('- untrusted: %s' % u)
    if lineage_note:
        body += ['', 'Moves: %s. Each is ONE record -- a SUPERSEDES event (cause PATH_MOVED) asserted '
                 'by the matching cascade; merging this pull request is the confirmation. The '
                 're-keyed entry keeps its first_seen.' % lineage_note]
    if presence_declared:
        body += ['', presence_declared]
    if held_lines:
        body += ['', '**Scanner generation (L46, ETFB section 5.5).** These findings were NOT admitted: '
                 'a scanner generation that is not authoritative may not create a NEW finding.'] + held_lines
    elif generation_note:
        body += ['', 'Scanner generation: %s.' % generation_note]
    if tickets['note']:
        body += ['', 'Ticket ledger: %s. It travels in this pull request because ledger writes have '
                 'one path (TICKETING_CONTRACT.md section 7.2).' % tickets['note']]
    return {'status': PROPOSED, 'why': 'see delta', 'content': content if baseline_changed else None,
            'branch': 'baseline-proposal/%s/%s' % (environment, run_id), 'base': default_branch,
            'path': path,
            'title': 'baseline (%s): %s%d admitted, %d moved%s' % (
                environment, 'ESTABLISH, ' if establishing else '', len(admitted), len(moved),
                ', ticket bindings updated' if tickets['file'] else ''),
            'body': '\n'.join(body), 'delta': delta, 'files': files}


# Every file a proposal carries lives here. The pushing step refuses anything else again, so a
# payload naming a workflow file -- by defect or by tampering -- writes nothing.
PROPOSAL_ROOT = '.security/'


def unsafe_path(rel):
    """-> reason, or '' when `rel` is a plain repository path under PROPOSAL_ROOT."""
    if not isinstance(rel, str) or not rel.startswith(PROPOSAL_ROOT) or rel.startswith('/') \
            or '\\' in rel or any(part in ('', '.', '..') for part in rel.split('/')):
        return '%r is not a plain path under %s' % (rel, PROPOSAL_ROOT)
    return ''


def write_tree(files, root):
    """Write each proposed file under `root` at its repository path. -> '' or the refusal."""
    for f in files:
        bad = unsafe_path(f.get('path'))
        if bad:
            return 'the proposal names a file outside the governance directory: %s. Nothing written' % bad
    for f in files:
        dest = os.path.join(root, *f['path'].split('/'))
        if not os.path.isdir(os.path.dirname(dest)):
            os.makedirs(os.path.dirname(dest))
        with io.open(dest, 'w', encoding='utf-8', newline='\n') as fh:
            fh.write(f['content'])
    return ''


def _selftest():
    fails = []
    if propose('.', [], bl.default_ledger_path, 'pull_request', 'refs/heads/main', 'main', 'main', 'prod',
               '1', 'c' * 40, '2026-01-01T00:00:00Z', 'SIDECAR')['status'] != REFUSED:
        fails.append('a pull_request event was not refused')
    if propose('.', [], bl.default_ledger_path, 'push', 'refs/heads/topic', 'main', 'main', 'prod',
               '1', 'c' * 40, '2026-01-01T00:00:00Z', 'SIDECAR')['status'] != REFUSED:
        fails.append('a non-default ref was not refused')
    if propose('.', [], bl.default_ledger_path, 'push', 'refs/heads/main', 'main', 'main', 'prod',
               '1', 'c' * 40, '2026-01-01T00:00:00Z', 'GUESSED')['status'] != REFUSED:
        fails.append('an unregistered time source was not refused')
    before = [{'identity': 'x', 'environment': 'p', 'first_seen': '2026-01-01', 'age_established': False}]
    if not first_seen_violations(before, [dict(before[0], first_seen='2026-05-01')]):
        fails.append('a re-dated first_seen was not detected')
    if not first_seen_violations(before, [dict(before[0], age_established=True)]):
        fails.append('an age upgraded to established was not detected')
    for rel, ok in (('.security/finding-baseline.json', True), ('.security/x/../../.github/w.yml', False),
                    ('.github/workflows/x.yml', False), ('/.security/a', False), ('.security\\a', False),
                    ('.security//a', False)):
        if (not unsafe_path(rel)) != ok:
            fails.append('unsafe_path(%r) was %s' % (rel, 'refused' if ok else 'accepted'))
    p = bl.default_ledger_path
    for pattern, want in (('*', True), ('/.security/', True), ('.security/', True),
                          ('/.security/finding-baseline.json', True), ('**/finding-baseline.json', True),
                          ('/.security/*.json', True), ('/docs/', False), ('/security/', False),
                          ('finding-baseline', False), ('/.sec*/', True)):
        if bool(_codeowners_regex(pattern).match(p)) != want:
            fails.append('CODEOWNERS pattern %r %s the ledger path' % (pattern, 'missed' if want else 'matched'))
    if fails:
        for f in fails:
            sys.stderr.write('FAIL: %s\n' % f)
        return 2
    print('propose_ledger selftest ok: PR events, non-default refs and unregistered time sources '
          'refuse; a re-dated first_seen or a laundered age is detected on the output; CODEOWNERS '
          'patterns cover (or miss) the ledger path as GitHub reads them. The '
          'end-to-end cases run in tests/prove_propose_ledger.py.')
    return 0


def main(argv=None):
    ap = argparse.ArgumentParser(description='Propose a baseline ledger change as a PR payload.')
    ap.add_argument('--self-test', action='store_true')
    ap.add_argument('--repo', default='.')
    ap.add_argument('--path', default=bl.default_ledger_path)
    ap.add_argument('--default-ref', default='')
    ap.add_argument('--default-branch', default='')
    ap.add_argument('--event', default='')
    ap.add_argument('--ref', default='')
    ap.add_argument('--environment', default='')
    ap.add_argument('--observations', default='')
    ap.add_argument('--run-id', default='')
    ap.add_argument('--commit', default='')
    ap.add_argument('--observed-at', default='')
    ap.add_argument('--observed-at-source', default='')
    ap.add_argument('--establish-approver-role', default='')
    ap.add_argument('--out', default='')
    ap.add_argument('--ticket-ledger-proposal', default='',
                    help='the ticket ledger the ticket job proposed (T-20); empty: none supplied')
    ap.add_argument('--ticket-ledger-path', default=TICKET_LEDGER_PATH)
    ap.add_argument('--reconciliation-window-days', type=int, default=DEFAULT_RECONCILIATION_WINDOW_DAYS,
                    help='the bounded window a newly opened scanner-generation reconciliation gets '
                         '(an owner number, O-06)')
    ap.add_argument('--tree-out', default='',
                    help='write every proposed file under this directory at its repository path, '
                         'for the job to copy into its proposal branch')
    a = ap.parse_args(argv)
    if a.self_test:
        return _selftest()
    if not a.observations or not a.out or not a.default_ref:
        print('--observations, --default-ref and --out are required', file=sys.stderr)
        return 2
    try:
        observations = json.load(io.open(a.observations, encoding='utf-8'))
    except (IOError, ValueError) as exc:
        print('cannot read observations %s: %s' % (a.observations, exc), file=sys.stderr)
        return 2
    if not isinstance(observations, list):
        print('observations must be a JSON list of identify() results', file=sys.stderr)
        return 2
    p = propose(a.repo, observations, a.path, a.event, a.ref, a.default_branch, a.default_ref,
                a.environment, a.run_id, a.commit, a.observed_at, a.observed_at_source,
                a.establish_approver_role, a.ticket_ledger_proposal, a.ticket_ledger_path,
                a.reconciliation_window_days)
    if p['status'] == PROPOSED and a.tree_out:
        bad = write_tree(p['files'], a.tree_out)
        if bad:
            p = _refuse(bad)
    with io.open(a.out, 'w', encoding='utf-8') as fh:
        json.dump(p, fh, indent=2, sort_keys=True)
    print('%s: %s' % (p['status'], p.get('title') or p.get('why')))
    return 1 if p['status'] == REFUSED else 0


if __name__ == '__main__':
    sys.exit(main())

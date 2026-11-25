#!/usr/bin/env python3
"""Scanner obligations: what a repository must be scanned for, and which providers may satisfy it. (KDEC-069)

THE OWNER'S RULE (2026-11-18, approved 2026-11-24)

    "Required should be identified by the discovery step based on what is in each of the repos and by
    what we are checking or have pushed." A scanner token says only whether a provider CAN run. Removing
    one (the tool was not renewed, retired or replaced) must not leave its findings impossible to close,
    and must not silently remove the control it served.

THE FOUR SEPARATE QUESTIONS (never collapsed into one)

    OBLIGATION    is the control owed?  Discovery (what the repository contains; what it pushes or deploys)
                  plus the versioned policy in scanner-obligations.json. A repository may DECLARE an extra
                  obligation (.kit/obligations.json `declare`); it can REMOVE one only with an exception the
                  GOVERNED policy records for it (`obligation_exceptions`: approved by someone other than the
                  requester, unexpired). A removal on the repository's own word is REMOVAL_REFUSED. No token,
                  no environment variable and no scanner run is ever read to decide this.
    PROVIDERS     which scanners may satisfy it, each with the coverage aspects it gives. A partial
                  replacement shows its exact gap.
    LIFECYCLE     per provider: ADOPTED (expected to run; core providers by default), RETIRED (a one-line
                  record: date, who, optionally why and what replaced it), or never adopted (an option; an
                  optional unfunded tool blocks nothing). An ADOPTED provider that did not run, with no
                  retirement record, is UNAVAILABLE -- whatever its token says -- routed by the stage.
    SATISFACTION  the aspects the providers that RAN cover. Missing aspects an adopted provider would have
                  covered: UNAVAILABLE. Missing aspects no adopted provider covers: COVERAGE_GAP (nothing
                  covered) or PARTIAL (some covered). A gap needs a time-bound acceptance by the risk owner
                  (GAP_ACCEPTED, named, never SATISFIED) or a control retirement whose residual risk the risk
                  owner accepted (CONTROL_RETIRED). Main-branch approval authorises the change to the policy;
                  the risk owner accepts the residual risk.

ROUTING (by the crawl / walk / run stage; unresolved is read at its strictest)

    UNAVAILABLE              crawl ADVISORY      walk, run REFUSED
    COVERAGE_GAP, PARTIAL    crawl ADVISORY      walk, run DECISION_REQUIRED (refused until decided)
    GAP_ACCEPTED             PROCEED_NAMED (the gap is named on the run; never a clean claim)
    SATISFIED, NOT_REQUIRED, CONTROL_RETIRED, REMOVED_BY_EXCEPTION   PROCEED

    Every obligation carries `outcome` (SATISFIED | NOT_SATISFIED | NOT_REQUIRED) and `cause` (null or
    PROVIDER_UNAVAILABLE | COVERAGE_GAP | PARTIAL_COVERAGE | GAP_ACCEPTED | CONTROL_RETIRED |
    REMOVED_BY_EXCEPTION) as separate fields, and `state`, the one word for display.

CLOSURE OF A RETIRED TOOL'S FINDINGS (closure_decision; used by scripts/ticket_completion.py)

    A finding keeps its identity. Its own tool's absence never closes it. A replacement's clean result
    closes it ONLY with shown equivalence: the same issue type, the same location (in the replacement's
    scope and its path inventory), the relevant version (the replacement completed, on a recorded commit or
    artifact digest), and detection capability (the policy says the replacement detects that issue type).
    Otherwise PENDING_VERIFICATION: a verifier who is not the fixer, or an authorised disposition.

WHERE IT RUNS

    .github/actions/scanner-obligations (the security gate, beside the capability floor) runs `evaluate`
    from the KIT (the action path), over the kit's scanner-obligations.json, the plan's discovery, the
    report's per-scanner state files and the checkout's optional .kit/obligations.json.

USAGE
    scanner_obligations.py evaluate --policy P --discovery JSON|@file --states DIR [--declaration F]
                                    [--source-root D] [--repository R] [--stage S] [--today D]
                                    [--json-out F] [--github-output F]
    scanner_obligations.py check --policy P
    scanner_obligations.py --self-test

EXIT  0 evaluated (the verdict is the gate's, from the outputs)   2 usage   3 the policy or a declaration
      could not be read or is malformed (refused: never an empty obligation list)
"""
import argparse
import datetime
import io
import json
import os
import re
import sys

SCHEMA = 'kit-scanner-obligations/1'
PHASE_GATE = 'security-gate'
PHASES = ('security-gate', 'promotion')
KINDS = ('core', 'external')
ADOPTED, RETIRED, NOT_ADOPTED = 'ADOPTED', 'RETIRED', 'NOT_ADOPTED'
LIFECYCLE_STATES = (ADOPTED, RETIRED)
# What a provider's state files say about this run (never its token).
RAN, FAILED, NOT_APPLICABLE, NOT_RUN = 'RAN', 'FAILED', 'NOT_APPLICABLE', 'NOT_RUN'
# Provider status, per obligation.
ACTIVE, UNAVAILABLE = 'ACTIVE', 'UNAVAILABLE'
# Obligation states (assurance-taxonomy.yaml :: scanner_obligation_state).
SATISFIED = 'SATISFIED'
PARTIAL = 'PARTIAL'
COVERAGE_GAP = 'COVERAGE_GAP'
GAP_ACCEPTED = 'GAP_ACCEPTED'
CONTROL_RETIRED = 'CONTROL_RETIRED'
REMOVED_BY_EXCEPTION = 'REMOVED_BY_EXCEPTION'
NOT_REQUIRED = 'NOT_REQUIRED'
EVALUATED_ELSEWHERE = 'EVALUATED_ELSEWHERE'
# Outcome and cause: separate fields.
OUT_SATISFIED, OUT_NOT_SATISFIED, OUT_NOT_REQUIRED = 'SATISFIED', 'NOT_SATISFIED', 'NOT_REQUIRED'
OUTCOMES = (OUT_SATISFIED, OUT_NOT_SATISFIED, OUT_NOT_REQUIRED)
CAUSE_UNAVAILABLE = 'PROVIDER_UNAVAILABLE'
CAUSE_GAP = 'COVERAGE_GAP'
CAUSE_PARTIAL = 'PARTIAL_COVERAGE'
CAUSE_ACCEPTED = 'GAP_ACCEPTED'
CAUSE_CONTROL_RETIRED = 'CONTROL_RETIRED'
CAUSE_REMOVED = 'REMOVED_BY_EXCEPTION'
# Routes.
ROUTE_PROCEED = 'PROCEED'
ROUTE_PROCEED_NAMED = 'PROCEED_NAMED'
ROUTE_ADVISORY = 'ADVISORY'
ROUTE_REFUSED = 'REFUSED'
ROUTE_DECISION = 'DECISION_REQUIRED'
STAGES = ('crawl', 'walk', 'run')
# Declaration problems.
REMOVAL_REFUSED = 'REMOVAL_REFUSED'
DECLARATION_UNKNOWN = 'DECLARATION_UNKNOWN_OBLIGATION'
# Closure.
CLOSE_EQUIVALENT = 'CLOSE_EQUIVALENT'
PENDING_VERIFICATION = 'PENDING_VERIFICATION'
SAME_PROVIDER = 'SAME_PROVIDER'
PENDING_ROUTE = 'a verifier who is not the fixer, or an authorised disposition'
DEFAULT_ACCEPTANCE_MAX_DAYS = 90
TRUE = ('true', '1', 'yes', 'on')


class Refused(Exception):
    """The policy or a declaration could not be read or is malformed: never an empty list."""


# ----------------------------------------------------------------------------------- small helpers
def _s(v):
    return v.strip() if isinstance(v, str) else ''


def _who(v):
    """Identities compare as the separation-of-duties rule compares them (SEPARATION-OF-DUTIES.md 2)."""
    v = _s(v).lower()
    v = re.sub(r'\[bot\]$', '', v)
    return v.split('@', 1)[0]


def _is_bot(v):
    return _s(v).lower().endswith('[bot]')


def _day(v):
    try:
        return datetime.date.fromisoformat(_s(v))
    except ValueError:
        return None


def _today(v):
    return _day(v) or datetime.date.today()


# ----------------------------------------------------------------------------------- the policy
def validate(pol):
    """-> [problem]. Empty means the policy can be evaluated."""
    p = []
    if not isinstance(pol, dict):
        return ['the policy is not an object']
    if pol.get('schema') != SCHEMA:
        p.append('schema is %r, not %s' % (pol.get('schema'), SCHEMA))
    if not _s(pol.get('policy_version')):
        p.append('policy_version is missing: the policy is versioned')
    obs = pol.get('obligations')
    if not isinstance(obs, list) or not obs:
        return p + ['obligations is not a non-empty list']
    seen, providers = set(), set()
    for o in obs:
        name = _s((o or {}).get('obligation'))
        if not name:
            p.append('an obligation has no name')
            continue
        if name in seen:
            p.append('obligation %s is defined twice' % name)
        seen.add(name)
        if o.get('phase', PHASE_GATE) not in PHASES:
            p.append('%s: phase %r is not one of %s' % (name, o.get('phase'), ', '.join(PHASES)))
        rw = o.get('required_when')
        if not isinstance(rw, list) or not rw or not all(isinstance(x, str) and x for x in rw):
            p.append('%s: required_when is not a non-empty list of discovery signals' % name)
        cov = o.get('coverage')
        if not isinstance(cov, list) or not cov:
            p.append('%s: coverage is not a non-empty list of aspects' % name)
            cov = []
        for pr in o.get('providers') or []:
            pn = _s((pr or {}).get('provider'))
            if not pn:
                p.append('%s: a provider has no name' % name)
                continue
            providers.add(pn)
            if pr.get('kind') not in KINDS:
                p.append('%s/%s: kind %r is not core or external' % (name, pn, pr.get('kind')))
            pc = pr.get('coverage')
            if not isinstance(pc, list) or not pc:
                p.append('%s/%s: coverage is not a non-empty list' % (name, pn))
            elif set(pc) - set(cov):
                p.append('%s/%s: claims coverage %s its obligation does not define' % (
                    name, pn, ', '.join(sorted(set(pc) - set(cov)))))
            if not isinstance(pr.get('detects'), list):
                p.append('%s/%s: detects (the issue types it can find) is not a list' % (name, pn))
            if pr.get('kind') == 'external' and not pn.startswith('ext-'):
                p.append('%s/%s: an external provider is named ext-<name> (its row name)' % (name, pn))
    for r in pol.get('provider_lifecycle') or []:
        if not isinstance(r, dict):
            p.append('a provider_lifecycle record is not an object')
            continue
        if _s(r.get('provider')) not in providers:
            p.append('provider_lifecycle names %r, which no obligation lists' % r.get('provider'))
        if r.get('state') not in LIFECYCLE_STATES:
            p.append('provider_lifecycle %s: state %r is not ADOPTED or RETIRED' % (r.get('provider'), r.get('state')))
        if not _day(r.get('on')):
            p.append('provider_lifecycle %s: on (the date) is missing or not YYYY-MM-DD' % r.get('provider'))
        if not _s(r.get('by')):
            p.append('provider_lifecycle %s: by (who) is missing' % r.get('provider'))
    for key in ('coverage_gap_acceptances', 'control_retirements', 'obligation_exceptions'):
        v = pol.get(key, [])
        if not isinstance(v, list):
            p.append('%s is not a list' % key)
            continue
        for r in v:
            if not isinstance(r, dict) or _s(r.get('obligation')) not in seen:
                p.append('%s: a record names %r, which is not an obligation' % (key, (r or {}).get('obligation')))
    m = pol.get('acceptance_max_days', DEFAULT_ACCEPTANCE_MAX_DAYS)
    if not isinstance(m, int) or m <= 0:
        p.append('acceptance_max_days must be a positive integer')
    return p


def load_policy(path):
    """-> (policy, problems). An unreadable file is (None, [why])."""
    try:
        pol = json.load(io.open(path, encoding='utf-8'))
    except (OSError, ValueError) as exc:
        return None, ['%s could not be read: %s' % (path, exc)]
    probs = validate(pol)
    return (pol if not probs else None), probs


def lifecycle(pol, provider, kind):
    """-> (state, record). The LAST record for the provider wins (the file is append-only history)."""
    rec = None
    for r in pol.get('provider_lifecycle') or []:
        if _s(r.get('provider')) == provider:
            rec = r
    if rec:
        return rec['state'], rec
    return (ADOPTED if kind == 'core' else NOT_ADOPTED), None


# ----------------------------------------------------------------------------------- discovery
def signals_of(discovery):
    """Discovery outputs -> the set of signals the policy's required_when may name. Only discovery and the
    run's own inputs (what it pushes, what it deploys) are read; never a token."""
    d = discovery if isinstance(discovery, dict) else {}
    out = {'always'}
    for k, v in d.items():
        if isinstance(v, bool):
            v = 'true' if v else 'false'
        if _s(str(v)).lower() in TRUE:
            out.add('discover.%s' % k)
    if _s(d.get('image_ref')):
        out.add('pushes.image')
    dt = _s(d.get('deploy_targets'))
    if dt and dt not in ('[]', '{}', 'null', 'none', 'NONE'):
        out.add('deploys.any')
    return out


WP_MARKERS = (('wp-includes', 'version.php'), ('wp-config.php',), ('wp-content', 'plugins'), ('wp-content', 'themes'))
WP_PACKAGES = ('johnpbloch/wordpress', 'roots/wordpress', 'wordpress/wordpress')


def discover_extra(root, max_depth=4):
    """Signals the kit's discovery does not compute yet, read from the tree: WordPress (KDEC-069).
    Bounded: at most max_depth levels below root, vendor and node_modules skipped."""
    found = False
    root = os.path.abspath(root or '.')
    for d, dirs, files in os.walk(root):
        depth = os.path.relpath(d, root).count(os.sep)
        dirs[:] = [x for x in dirs if x not in ('.git', 'node_modules', 'vendor') and depth < max_depth]
        for marker in WP_MARKERS:
            if os.path.exists(os.path.join(d, *marker)):
                found = True
        if 'composer.json' in files:
            try:
                txt = io.open(os.path.join(d, 'composer.json'), encoding='utf-8', errors='replace').read()
            except OSError:
                txt = ''
            if any('"%s"' % pkg in txt for pkg in WP_PACKAGES):
                found = True
        if found:
            break
    return {'wordpress': 'true' if found else 'false'}


# ----------------------------------------------------------------------------------- run evidence
def load_states(states_dir):
    """state-<identity>.json -> {identity: row}. A missing directory is no rows (every provider NOT_RUN)."""
    out = {}
    if not states_dir or not os.path.isdir(states_dir):
        return out
    for f in sorted(os.listdir(states_dir)):
        if not (f.startswith('state-') and f.endswith('.json')):
            continue
        try:
            row = json.load(io.open(os.path.join(states_dir, f), encoding='utf-8'))
        except (OSError, ValueError):
            row = {'execution': 'COLLECTION_FAILED', 'applicability': 'UNKNOWN'}
        name = _s((row or {}).get('scanner')) or f[len('state-'):-len('.json')]
        out[name] = row if isinstance(row, dict) else {}
    return out


def provider_ran(states, identities):
    """-> RAN | FAILED | NOT_APPLICABLE | NOT_RUN, from the provider's own state rows only."""
    rows = [states[i] for i in identities if i in states]
    if any(r.get('execution') == 'COMPLETE' and r.get('applicability') in ('APPLICABLE', 'UNKNOWN') for r in rows):
        return RAN
    if any(r.get('execution') in ('FAILED', 'COLLECTION_FAILED') for r in rows):
        return FAILED
    if rows and all(r.get('applicability') == 'NOT_APPLICABLE' for r in rows):
        return NOT_APPLICABLE
    return NOT_RUN


# ----------------------------------------------------------------------------------- decisions
def governed_exception(pol, repo, obligation, ref, today):
    """-> the governed exception record that lets `repo` remove `obligation`, or None."""
    for e in pol.get('obligation_exceptions') or []:
        if _s(e.get('obligation')) != obligation or _s(e.get('exception_ref')) != _s(ref) or not _s(ref):
            continue
        if _s(e.get('repository')) not in ('*', _s(repo)) or not _s(e.get('repository')):
            continue
        req, app = _who(e.get('requested_by')), _who(e.get('approved_by'))
        if not app or not req or app == req or _is_bot(e.get('approved_by')):
            continue
        exp = _day(e.get('expires'))
        if exp is None or exp < today:
            continue
        return e
    return None


def acceptance_valid(acc, pol, today):
    """-> (ok, why). Time-bound, by the risk owner, within the policy's maximum."""
    owner = _who(acc.get('risk_owner'))
    if not owner:
        return False, 'no risk owner named'
    if _who(acc.get('accepted_by')) != owner:
        return False, 'accepted by %r, not the risk owner %r' % (acc.get('accepted_by'), acc.get('risk_owner'))
    dec, exp = _day(acc.get('decided_on')), _day(acc.get('expires'))
    if dec is None or exp is None:
        return False, 'decided_on and expires must both be dates (time-bound)'
    if exp < today:
        return False, 'expired %s' % exp.isoformat()
    cap = pol.get('acceptance_max_days', DEFAULT_ACCEPTANCE_MAX_DAYS)
    if (exp - dec).days > cap:
        return False, 'lives %d days; the policy maximum is %d' % ((exp - dec).days, cap)
    if not _s(acc.get('reference')):
        return False, 'no reference (the risk record)'
    return True, ''


def retirement_valid(ret):
    """A control retirement is a security decision; the residual risk is the risk owner's."""
    owner = _who(ret.get('risk_owner'))
    return bool(_s(ret.get('decided_by')) and owner and _who(ret.get('residual_risk_accepted_by')) == owner
                and _day(ret.get('decided_on')) and _s(ret.get('reference')))


def covered_aspects(obligation, providers):
    """The aspects the providers that RAN cover (never the obligation's whole list)."""
    out = set()
    for p in providers:
        if p['status'] == ACTIVE:
            out.update(p['coverage'])
    return sorted(out & set(obligation['coverage']))


def route(state, stage):
    if state in (SATISFIED, NOT_REQUIRED, CONTROL_RETIRED, REMOVED_BY_EXCEPTION, EVALUATED_ELSEWHERE):
        return ROUTE_PROCEED
    if state == GAP_ACCEPTED:
        return ROUTE_PROCEED_NAMED
    if stage == 'crawl':
        return ROUTE_ADVISORY
    return ROUTE_REFUSED if state == UNAVAILABLE else ROUTE_DECISION


# ----------------------------------------------------------------------------------- the evaluation
def evaluate(pol, discovery, states, declaration, repo, today, stage=''):
    """-> {policy_version, signals, obligations [...], declaration_problems, gate {...}}. Pure."""
    today = _today(today) if not isinstance(today, datetime.date) else today
    sig = signals_of(discovery)
    decl = declaration if isinstance(declaration, dict) else {}
    names = [o['obligation'] for o in pol['obligations']]
    declared, removed, problems = {}, {}, []
    for d in decl.get('declare') or []:
        n = _s((d or {}).get('obligation'))
        if n in names:
            declared[n] = _s(d.get('why'))
        else:
            problems.append('%s: the repository declares %r, which the policy does not define' % (DECLARATION_UNKNOWN, n))
    for d in decl.get('remove') or []:
        n, ref = _s((d or {}).get('obligation')), _s((d or {}).get('exception_ref'))
        e = governed_exception(pol, repo, n, ref, today) if n in names else None
        if e:
            removed[n] = e
        else:
            problems.append('%s: %s cannot be removed by %s; only an exception the governed policy records for '
                            'this repository, approved by someone other than its requester and unexpired, removes '
                            'an obligation' % (REMOVAL_REFUSED, n or '(no name)', ref or 'no exception reference'))
    results = []
    for o in pol['obligations']:
        name = o['obligation']
        basis = sorted(s for s in o['required_when'] if s in sig)
        if name in declared:
            basis.append('DECLARED')
        rec = {'obligation': name, 'phase': o.get('phase', PHASE_GATE), 'required': bool(basis), 'basis': basis,
               'coverage': list(o['coverage']), 'covered': [], 'gap': [], 'providers': [],
               'policy_version': pol['policy_version']}
        ret = next((r for r in pol.get('control_retirements') or []
                    if _s(r.get('obligation')) == name and retirement_valid(r)), None)
        provs = []
        for pr in o.get('providers') or []:
            ids = pr.get('identities') or [pr['provider']]
            life, lrec = lifecycle(pol, pr['provider'], pr['kind'])
            run = provider_ran(states, ids)
            if life == RETIRED:
                status = RETIRED
            elif run == RAN:
                status = ACTIVE
            elif life == ADOPTED and run in (NOT_RUN, FAILED):
                status = UNAVAILABLE if run == NOT_RUN else FAILED
            elif run == NOT_APPLICABLE:
                status = NOT_APPLICABLE
            else:
                status = NOT_ADOPTED
            p = {'provider': pr['provider'], 'kind': pr['kind'], 'coverage': list(pr['coverage']),
                 'detects': list(pr.get('detects') or []), 'lifecycle': life, 'run': run, 'status': status}
            if life == RETIRED:
                p['retired'] = {k: lrec.get(k) for k in ('on', 'by', 'reason', 'replaced_by') if lrec.get(k)}
            provs.append(p)
        rec['providers'] = provs
        if ret:
            rec.update(required=False, state=CONTROL_RETIRED, outcome=OUT_NOT_REQUIRED, cause=CAUSE_CONTROL_RETIRED,
                       control_retirement={k: ret.get(k) for k in ('decided_by', 'risk_owner',
                                                                   'residual_risk_accepted_by', 'decided_on',
                                                                   'reference')})
        elif name in removed:
            rec.update(required=False, state=REMOVED_BY_EXCEPTION, outcome=OUT_NOT_REQUIRED, cause=CAUSE_REMOVED,
                       exception={k: removed[name].get(k) for k in ('exception_ref', 'approved_by', 'expires')})
        elif not rec['required']:
            rec.update(state=NOT_REQUIRED, outcome=OUT_NOT_REQUIRED, cause=None)
        elif rec['phase'] != PHASE_GATE:
            rec.update(state=EVALUATED_ELSEWHERE, outcome=OUT_NOT_REQUIRED, cause=None,
                       note='evaluated at %s against the deploy evidence, not at the pull-request gate' % rec['phase'])
        else:
            covered = covered_aspects(o, provs)
            missing = sorted(set(o['coverage']) - set(covered))
            waiting = set()
            for p in provs:
                if p['status'] in (UNAVAILABLE, FAILED):
                    waiting.update(set(p['coverage']) & set(missing))
            gap = sorted(set(missing) - waiting)
            rec['covered'], rec['gap'] = covered, gap
            rec['waiting_on'] = sorted(waiting)
            if not missing:
                rec.update(state=SATISFIED, outcome=OUT_SATISFIED, cause=None)
            elif gap:
                acc = None
                for a in pol.get('coverage_gap_acceptances') or []:
                    if _s(a.get('obligation')) != name:
                        continue
                    aspects = a.get('aspects') or o['coverage']
                    ok, why = acceptance_valid(a, pol, today)
                    if ok and set(gap) <= set(aspects):
                        acc = a
                    elif not ok:
                        rec.setdefault('acceptance_refused', []).append('%s: %s' % (a.get('reference') or '?', why))
                if acc and not waiting:
                    rec.update(state=GAP_ACCEPTED, outcome=OUT_NOT_SATISFIED, cause=CAUSE_ACCEPTED,
                               acceptance={k: acc.get(k) for k in ('accepted_by', 'risk_owner', 'decided_on',
                                                                   'expires', 'reference')})
                elif covered:
                    rec.update(state=PARTIAL, outcome=OUT_NOT_SATISFIED, cause=CAUSE_PARTIAL)
                else:
                    rec.update(state=COVERAGE_GAP, outcome=OUT_NOT_SATISFIED, cause=CAUSE_GAP)
                if waiting and rec['state'] == GAP_ACCEPTED:
                    rec.update(state=UNAVAILABLE, cause=CAUSE_UNAVAILABLE)
            else:
                rec.update(state=UNAVAILABLE, outcome=OUT_NOT_SATISFIED, cause=CAUSE_UNAVAILABLE)
        rec['route'] = route(rec['state'], stage if stage in STAGES else '')
        results.append(rec)
    return {'schema': 'kit-scanner-obligations-result/1', 'policy_version': pol['policy_version'],
            'decision': pol.get('decision'), 'today': today.isoformat(), 'stage': stage or 'unresolved',
            'repository': repo, 'signals': sorted(sig), 'obligations': results,
            'declaration_problems': problems, 'gate': gate_view(results, problems)}


RANK = {SATISFIED: 0, NOT_REQUIRED: 0, CONTROL_RETIRED: 0, REMOVED_BY_EXCEPTION: 0, EVALUATED_ELSEWHERE: 0,
        GAP_ACCEPTED: 1, UNAVAILABLE: 2, PARTIAL: 3, COVERAGE_GAP: 4}


def gate_view(results, problems):
    """What the security gate reads: space-separated name(STATE) tokens, the gate's own convention."""
    worst, unavailable, gaps, accepted, retired = SATISFIED, [], [], [], []
    for r in results:
        if RANK.get(r['state'], 4) > RANK.get(worst, 0):
            worst = r['state']
        for p in r['providers']:
            if p['kind'] == 'external' and p['status'] == UNAVAILABLE and r['required'] and r['phase'] == PHASE_GATE:
                tok = '%s(UNAVAILABLE)' % p['provider']
                if tok not in unavailable:
                    unavailable.append(tok)
            if p['status'] == RETIRED and p['provider'] not in retired:
                retired.append(p['provider'])
        if r['state'] in (COVERAGE_GAP, PARTIAL) or (r['state'] == UNAVAILABLE and r['gap']):
            gaps.append('%s(%s:%s)' % (r['obligation'], r['state'] if r['state'] != UNAVAILABLE else COVERAGE_GAP,
                                       ','.join(r['gap'])))
        if r['state'] == GAP_ACCEPTED:
            accepted.append('%s(GAP_ACCEPTED:%s:until-%s)' % (r['obligation'], ','.join(r['gap']),
                                                              r['acceptance']['expires']))
    if problems and worst in (SATISFIED, GAP_ACCEPTED):
        worst = 'DECLARATION_REFUSED'
    return {'obligation_state': worst, 'unavailable': ' '.join(unavailable), 'gaps': ' '.join(gaps),
            'accepted': ' '.join(accepted), 'retired_providers': ' '.join(retired),
            'declaration_problems': len(problems)}


# ----------------------------------------------------------------------------------- closure
def _scope_covers(scope, path):
    scope = _s(scope).strip('/')
    if scope in ('', '.'):
        return True
    return path == scope or path.startswith(scope + '/')


def location_matches(finding, rescan):
    path = _s(finding.get('path')).lstrip('./')
    inv = set(_s(p).lstrip('./') for p in rescan.get('path_inventory') or [])
    return bool(path) and path in inv and _scope_covers(rescan.get('scope'), path)


def closure_decision(finding, rescan, pol):
    """-> {decision, identity, missing [...], pending_route}. Pure. `finding` is the ledger's observation of a
    finding (identity, scanner, issue_type, cwe, path, seen_at_commit | seen_at_digest); `rescan` is one
    scanner's result on the current version (scanner, established, scope, commit | artifact_digest,
    path_inventory, present_identities, issue_types, cwes)."""
    ident, old, new = _s(finding.get('identity')), _s(finding.get('scanner')), _s(rescan.get('scanner'))
    out = {'identity': ident, 'retired_provider': old, 'replacement': new, 'missing': [], 'pending_route': ''}
    life, _ = lifecycle(pol, old, 'external' if old.startswith('ext-') else 'core')
    if new == old:
        if life == RETIRED:
            out['missing'].append('the provider that found it is retired: its own absence closes nothing')
        else:
            out.update(decision=SAME_PROVIDER)
            return out
    shared = [o for o in pol.get('obligations') or []
              if any(p['provider'] == old for p in o.get('providers') or [])]
    repl = None
    for o in shared:
        for p in o.get('providers') or []:
            if p['provider'] == new:
                repl = p
    if new != old and repl is None:
        out['missing'].append('capability: %s is not a provider of any obligation %s served' % (new, old))
    elif new != old and lifecycle(pol, new, repl['kind'])[0] == RETIRED:
        out['missing'].append('capability: the replacement %s is itself retired' % new)
    elif new != old and _s(finding.get('issue_type')) not in (repl.get('detects') or []):
        out['missing'].append('capability: the policy does not say %s detects %r' % (new, finding.get('issue_type')))
    itype, cwe = _s(finding.get('issue_type')), _s(finding.get('cwe'))
    if itype not in (rescan.get('issue_types') or []) and not (cwe and cwe in (rescan.get('cwes') or [])):
        out['missing'].append('issue_type: the replacement\'s run covers %s, not %r (%s)' % (
            ', '.join(rescan.get('issue_types') or []) or 'nothing', itype, cwe or 'no CWE'))
    if not location_matches(finding, rescan):
        out['missing'].append('location: %s is not in the replacement\'s path inventory and scope %r' % (
            finding.get('path'), rescan.get('scope')))
    if not rescan.get('established'):
        out['missing'].append('version: the replacement did not complete on this version')
    elif not (_s(rescan.get('commit')) or _s(rescan.get('artifact_digest'))):
        out['missing'].append('version: the replacement recorded no commit or artifact digest it scanned')
    elif _s(finding.get('seen_at_digest')) and not _s(rescan.get('artifact_digest')):
        out['missing'].append('version: an artifact finding needs the artifact digest the replacement scanned')
    if ident and ident in (rescan.get('present_identities') or []):
        out['missing'].append('absent: the replacement still reports this identity')
    if out['missing']:
        out.update(decision=PENDING_VERIFICATION, pending_route=PENDING_ROUTE)
    else:
        out.update(decision=CLOSE_EQUIVALENT,
                   equivalence={'issue_type': itype, 'location': finding.get('path'),
                                'version': _s(rescan.get('commit')) or _s(rescan.get('artifact_digest')),
                                'capability': new})
    return out


# ----------------------------------------------------------------------------------- CLI
def _json_arg(v):
    v = v or '{}'
    if v.startswith('@'):
        return json.load(io.open(v[1:], encoding='utf-8'))
    return json.loads(v)


def cmd_evaluate(a):
    pol, probs = load_policy(a.policy)
    if pol is None:
        print('REFUSED: the scanner obligations policy cannot be evaluated: %s' % '; '.join(probs))
        return 3
    try:
        disc = _json_arg(a.discovery)
    except (OSError, ValueError) as exc:
        print('REFUSED: the discovery could not be read: %s' % exc)
        return 3
    decl = None
    if a.declaration and os.path.exists(a.declaration):
        try:
            decl = json.load(io.open(a.declaration, encoding='utf-8'))
        except (OSError, ValueError) as exc:
            print('REFUSED: %s could not be read: %s' % (a.declaration, exc))
            return 3
    if a.source_root:
        for k, v in discover_extra(a.source_root).items():
            disc.setdefault(k, v)
    res = evaluate(pol, disc, load_states(a.states), decl, a.repository or '', _today(a.today), a.stage or '')
    if a.json_out:
        io.open(a.json_out, 'w', encoding='utf-8').write(json.dumps(res, indent=2, sort_keys=True) + '\n')
    g = res['gate']
    if a.github_output:
        with io.open(a.github_output, 'a', encoding='utf-8') as fh:
            for k in ('obligation_state', 'unavailable', 'gaps', 'accepted', 'retired_providers'):
                key = k if k == 'obligation_state' else 'obligation_' + k
                fh.write('%s=%s\n' % (key, re.sub(r'[\r\n]', ' ', str(g[k]))))
    print('Scanner obligations (policy %s, stage %s): %s' % (res['policy_version'], res['stage'], g['obligation_state']))
    for r in res['obligations']:
        if r['required'] or r['state'] not in (NOT_REQUIRED,):
            print('  %-22s %-20s outcome=%s cause=%s route=%s basis=%s%s' % (
                r['obligation'], r['state'], r['outcome'], r['cause'] or '-', r['route'], ','.join(r['basis']) or '-',
                (' gap=' + ','.join(r['gap'])) if r['gap'] else ''))
    for p in res['declaration_problems']:
        print('  %s' % p)
    return 0


def cmd_check(a):
    pol, probs = load_policy(a.policy)
    if pol is None:
        for p in probs:
            print('FAIL: %s' % p)
        return 3
    print('PASS: %s validates (policy %s, %d obligations).' % (a.policy, pol['policy_version'], len(pol['obligations'])))
    return 0


def self_test():
    pol = {'schema': SCHEMA, 'policy_version': 'st.1', 'obligations': [
        {'obligation': 'x', 'required_when': ['always'], 'coverage': ['a', 'b'],
         'providers': [{'provider': 'p1', 'kind': 'core', 'coverage': ['a'], 'detects': ['t']},
                       {'provider': 'ext-p2', 'kind': 'external', 'coverage': ['a', 'b'], 'detects': ['t']}]}],
        'provider_lifecycle': [{'provider': 'ext-p2', 'state': 'ADOPTED', 'on': '2026-01-01', 'by': 'o'}]}
    fails = []
    if validate(pol):
        fails.append('a valid policy did not validate: %s' % validate(pol))
    r = evaluate(pol, {}, {'p1': {'execution': 'COMPLETE', 'applicability': 'APPLICABLE'}}, None, 'r', '2026-11-25', 'walk')
    if r['obligations'][0]['state'] != UNAVAILABLE or r['gate']['unavailable'] != 'ext-p2(UNAVAILABLE)':
        fails.append('an adopted provider that did not run was not UNAVAILABLE: %s' % r['obligations'][0])
    pol['provider_lifecycle'].append({'provider': 'ext-p2', 'state': 'RETIRED', 'on': '2026-11-20', 'by': 'o'})
    r = evaluate(pol, {}, {'p1': {'execution': 'COMPLETE', 'applicability': 'APPLICABLE'}}, None, 'r', '2026-11-25', 'walk')
    if r['obligations'][0]['state'] != PARTIAL or r['obligations'][0]['gap'] != ['b']:
        fails.append('a partial replacement did not show its gap: %s' % r['obligations'][0])
    if fails:
        print('SELF-TEST FAILED:\n  - ' + '\n  - '.join(fails))
        return 1
    print('self-test ok: an adopted provider that did not run is UNAVAILABLE; a retired one leaves a named gap.')
    return 0


def main(argv=None):
    argv = sys.argv[1:] if argv is None else argv
    if argv[:1] == ['--self-test']:
        return self_test()
    ap = argparse.ArgumentParser(description=__doc__.split('\n')[0])
    sub = ap.add_subparsers(dest='cmd')
    e = sub.add_parser('evaluate')
    e.add_argument('--policy', required=True)
    e.add_argument('--discovery', default='{}', help='JSON object, or @file')
    e.add_argument('--states', default='')
    e.add_argument('--declaration', default='', help="the repository's .kit/obligations.json (optional)")
    e.add_argument('--source-root', default='')
    e.add_argument('--repository', default='')
    e.add_argument('--stage', default='', help='crawl | walk | run (unresolved is read at its strictest)')
    e.add_argument('--today', default='')
    e.add_argument('--json-out', default='')
    e.add_argument('--github-output', default='')
    c = sub.add_parser('check')
    c.add_argument('--policy', required=True)
    a = ap.parse_args(argv)
    if a.cmd == 'evaluate':
        return cmd_evaluate(a)
    if a.cmd == 'check':
        return cmd_check(a)
    ap.print_usage()
    return 2


if __name__ == '__main__':
    sys.exit(main())

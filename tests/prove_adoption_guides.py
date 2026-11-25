#!/usr/bin/env python3
"""The auto-merge and branch-protection guides say what the owner asked, and their rulesets would work.

WHY THIS EXISTS (owner, 2026-11-06): "which repos should automerge be turned on for? ... what are the risks?"
and "What branch protections am I turning on?" A guide whose ruleset requires a check nothing emits blocks
every pull request forever, and a risk without a mitigation is a worry, not a plan.

  POSITIVE
    A1  AUTOMERGE_RISKS_AND_ROLLOUT.md names all eleven risks, each followed by PROPOSED suggested
        mitigations; it says auto-merge is opt-in per repository; the rollout never includes a repository
        whose main deploys to production without an environment approval gate
    B1  BRANCH_PROTECTION_SETTINGS.md holds a ruleset for each of the four repository types; each parses,
        blocks deletion and force pushes, requires a pull request and status checks, has no bypass actor
    B2  every required check a ruleset names is a check the kit emits (the templates' derived names, or
        self-test's `Self-test required`)
    B3  only `main` needs approval (owner 2026-11-18, KDEC-073): the long-lived `dev` ruleset requires the
        same status checks and blocks deletion and force pushes, but requires NO approval (no approving
        review, no code-owner review, no last-push approval); START_HERE_KIT.md says the same
    R1  ROLLOUT_PLAN.md (owner, 2026-11-06, KDEC-041): the waves in order (greenfield and landing-zone-vended,
        existing at crawl report-only, walk only after the backlog is triaged, legacy never gated at walk
        until triaged); the approver SLA is the same business day with a backup approver; a missed SLA is
        escalated and never auto-approved; small teams' approvers come from platform or security outside
        the team; it links both guides and both guides link back to it
  NEGATIVE
    N1  a ruleset requiring a check nothing emits is refused (the B2 rule, on a seeded copy)
    N2  a ruleset with a bypass actor is refused (the B1 rule, on a seeded copy)
    N3  a risk section without its mitigations is refused (the A1 rule, on a seeded copy)
    N4  a rollout plan that lets a missed SLA auto-approve, or gates legacy at walk before triage, is refused
    N5  a `dev` ruleset that requires an approval, or one that drops the status checks, is refused

EXIT 0 all hold   1 any does not   2 PyYAML unavailable
"""
import io
import json
import os
import re
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, HERE)
AM = os.path.join(ROOT, 'docs', 'adoption', 'AUTOMERGE_RISKS_AND_ROLLOUT.md')
BP = os.path.join(ROOT, 'docs', 'adoption', 'BRANCH_PROTECTION_SETTINGS.md')
RISKS = ['compromised patch or minor release', 'Semver-violating breaking changes', 'Thin test coverage',
         'deploys to production without CAB', 'pull_request_target', 'Review fatigue', 'separation of duties',
         'grouped update hides', 'Transitive dependencies', 'Licence changes', 'Volume and noise']
RP = os.path.join(ROOT, 'docs', 'adoption', 'ROLLOUT_PLAN.md')
TYPES = ['main: kit', 'main: public mirror', 'main: application', 'main: infrastructure']
DEV = 'dev: long-lived branch (checks, no approval)'
START = os.path.join(ROOT, 'START_HERE_KIT.md')
FAILS = []


def check(cond, label, detail=''):
    print('  %s %s%s' % ('ok  ' if cond else 'FAIL', label, ('  -- ' + str(detail)[:400]) if detail and not cond else ''))
    if not cond:
        FAILS.append(label)


def automerge_problems(text):
    probs = []
    secs = re.split(r'\n### ', text)
    for r in RISKS:
        sec = [s for s in secs if r.lower() in s.split('\n', 1)[0].lower()]
        if not sec:
            probs.append('no risk section for %r' % r)
        elif '**Suggested mitigations** (PROPOSED)' not in sec[0] or not re.search(r'\n- \S', sec[0]):
            probs.append('the risk %r has no PROPOSED mitigations' % r)
    if 'opt-in' not in text or 'per repository' not in text:
        probs.append('does not say auto-merge is opt-in per repository')
    if not re.search(r'\*\*Never\*\*: a repository whose `main` deploys to production without an environment approval gate', text):
        probs.append('the rollout does not exclude repositories that auto-deploy to production without an approval gate')
    return probs


def rollout_problems(rp, am, bp):
    probs = []
    waves = ['**1. Greenfield and landing-zone-vended**', '**2. Existing repositories, at crawl**',
             '**3. Walk, then run**', '**Legacy**']
    pos = [rp.find(w) for w in waves]
    if any(x < 0 for x in pos) or pos != sorted(pos):
        probs.append('the waves are missing or out of order')
    for phrase, why in [('report-only for N weeks', 'existing repositories report-only for N weeks'),
                        ('never gated at walk until their backlog is triaged', 'legacy never gated at walk until triaged'),
                        ('same business day', 'the approver SLA is the same business day'),
                        ('a backup approver', 'a backup approver'),
                        ('A missed SLA never auto-approves anything', 'a missed SLA never auto-approves'),
                        ('small-teams', None), ('escalates', 'a missed SLA is escalated')]:
        if why is None:
            if not re.search(r'come from \*\*platform or security, outside the\s+team\*\*', rp):
                probs.append("small teams' approvers do not come from platform or security outside the team")
        elif phrase not in rp:
            probs.append('no: ' + why)
    for doc, name in ((rp, 'ROLLOUT_PLAN'),):
        for link in ('AUTOMERGE_RISKS_AND_ROLLOUT.md', 'BRANCH_PROTECTION_SETTINGS.md'):
            if link not in doc:
                probs.append('%s does not link %s' % (name, link))
    for doc, name in ((am, 'AUTOMERGE_RISKS_AND_ROLLOUT'), (bp, 'BRANCH_PROTECTION_SETTINGS')):
        if 'ROLLOUT_PLAN.md' not in doc:
            probs.append('%s does not link back to ROLLOUT_PLAN.md' % name)
    return probs


def rulesets(text):
    out = {}
    for block in re.findall(r'```json\n(.*?)```', text, re.S):
        try:
            d = json.loads(block)
        except ValueError:
            continue
        if isinstance(d, dict) and d.get('target') == 'branch':
            out[d.get('name')] = d
    return out


def ruleset_problems(rs, emitted):
    probs = []
    for t in TYPES:
        d = rs.get(t)
        if not d:
            probs.append('no ruleset for %s' % t)
            continue
        types = [r.get('type') for r in d.get('rules') or []]
        for need in ('deletion', 'non_fast_forward', 'pull_request', 'required_status_checks'):
            if need not in types:
                probs.append('%s lacks %s' % (t, need))
        if d.get('bypass_actors'):
            probs.append('%s has a bypass actor' % t)
        for r in d.get('rules') or []:
            if r.get('type') == 'required_status_checks':
                for c in r['parameters']['required_status_checks']:
                    if c['context'] not in emitted:
                        probs.append('%s requires %r, which nothing emits' % (t, c['context']))
    return probs


def dev_problems(rs, emitted, start_text):
    """KDEC-073: only main needs an approval; dev needs the checks, never an approval."""
    probs = []
    d = rs.get(DEV)
    if not d:
        return ['no %r ruleset' % DEV]
    inc = ((d.get('conditions') or {}).get('ref_name') or {}).get('include') or []
    if inc != ['refs/heads/dev']:
        probs.append('the dev ruleset targets %r, not refs/heads/dev only' % inc)
    types = [r.get('type') for r in d.get('rules') or []]
    for need in ('deletion', 'non_fast_forward', 'required_status_checks'):
        if need not in types:
            probs.append('the dev ruleset lacks %s' % need)
    if d.get('bypass_actors'):
        probs.append('the dev ruleset has a bypass actor')
    for r in d.get('rules') or []:
        if r.get('type') == 'pull_request':
            p = r.get('parameters') or {}
            if p.get('required_approving_review_count') or p.get('require_code_owner_review') or                     p.get('require_last_push_approval'):
                probs.append('the dev ruleset requires an approval: only main needs approval')
        if r.get('type') == 'required_status_checks':
            for c in r['parameters']['required_status_checks']:
                if c['context'] not in emitted:
                    probs.append('the dev ruleset requires %r, which nothing emits' % c['context'])
    if 'Only `main` needs an approval' not in start_text or 'never an approval' not in start_text:
        probs.append('START_HERE_KIT.md does not say that only main needs an approval and dev never does')
    return probs


def main():
    try:
        import yaml  # noqa: F401
    except ImportError:
        print('UNKNOWN: PyYAML unavailable')
        return 2
    import check_branch_protection_profiles as CB
    emitted = set(CB.emitted(ROOT)[0]) | {'Self-test required'}
    am = io.open(AM, encoding='utf-8').read()
    bp = io.open(BP, encoding='utf-8').read()
    print('Adoption guides (auto-merge risks, branch protection):')
    p = automerge_problems(am)
    check(not p, 'A1 eleven risks with PROPOSED mitigations; opt-in per repository; never auto-deploy without a gate', p)
    rs = rulesets(bp)
    p = ruleset_problems(rs, emitted)
    check(not p, 'B1/B2 four rulesets: each blocks deletion and force push, requires a PR and only emitted checks, no bypass', p)
    bad = json.loads(json.dumps(rs))
    bad['main: application']['rules'][-1]['parameters']['required_status_checks'].append({'context': 'lint'})
    check(any('nothing emits' in x for x in ruleset_problems(bad, emitted)), 'N1 a check nothing emits is refused')
    bad = json.loads(json.dumps(rs))
    bad['main: kit']['bypass_actors'] = [{'actor_id': 1, 'actor_type': 'Team', 'bypass_mode': 'always'}]
    check(any('bypass actor' in x for x in ruleset_problems(bad, emitted)), 'N2 a bypass actor is refused')
    start = io.open(START, encoding='utf-8').read()
    p = dev_problems(rs, emitted, start)
    check(not p, 'B3 only main needs approval: the dev ruleset requires the checks and no approval; START_HERE says so', p)
    bad = json.loads(json.dumps(rs))
    for r in (bad.get(DEV) or {}).get('rules') or []:
        if r.get('type') == 'pull_request':
            r['parameters']['required_approving_review_count'] = 1
    check(any('requires an approval' in x for x in dev_problems(bad, emitted, start)),
          'N5 a dev ruleset that requires an approval is refused')
    bad = json.loads(json.dumps(rs))
    if bad.get(DEV):
        bad[DEV]['rules'] = [r for r in bad[DEV]['rules'] if r.get('type') != 'required_status_checks']
    check(any('lacks required_status_checks' in x for x in dev_problems(bad, emitted, start)),
          'N5 a dev ruleset that drops the status checks is refused')
    rp = io.open(RP, encoding='utf-8').read()
    p = rollout_problems(rp, am, bp)
    check(not p, 'R1 the rollout plan: waves in order, report-only, legacy never at walk untriaged, same-day SLA, '
          'backup, escalation never auto-approval, small teams approved from outside; linked both ways', p)
    bad = rp.replace('A missed SLA never auto-approves anything', 'A missed SLA auto-approves after a day')
    check(bad != rp and any('auto-approves' in x for x in rollout_problems(bad, am, bp)),
          'N4 a missed SLA that auto-approves is refused')
    bad = rp.replace('never gated at walk until their backlog is triaged', 'moved to walk after N weeks')
    check(bad != rp and any('legacy' in x for x in rollout_problems(bad, am, bp)),
          'N4 legacy gated at walk before its backlog is triaged is refused')
    cut = am.replace('### 9. Transitive dependencies\n\nA small direct bump pulls in many indirect changes.\n**Suggested mitigations** (PROPOSED):',
                     '### 9. Transitive dependencies\n\nA small direct bump pulls in many indirect changes.\n')
    check(cut != am and any('Transitive' in x for x in automerge_problems(cut)), 'N3 a risk without mitigations is refused')
    if FAILS:
        print('FAIL: %d claim(s)' % len(FAILS))
        return 1
    print('PASS: the guides answer the owner, and every ruleset would require only checks the kit emits.')
    return 0


if __name__ == '__main__':
    sys.exit(main())

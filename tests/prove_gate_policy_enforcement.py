#!/usr/bin/env python3
"""The gate ENFORCES the resolved policy: by default only secrets block, every other finding is
PROCEED_WITH_ADVISORY with its cause, and a registered tightening or softening changes exactly what
it says -- run end to end through the shipped steps.

WHY THIS EXISTS (owner requirements 2026-10-22; ETFB sections 1-4; wiring/gate-rung.patch.md)

    tests/prove_gate_reads_rung.py proves the WIRING exists. This proves the BEHAVIOUR: the real
    resolver (scripts/policy_registration.py, CLI, against a throwaway git repository and a central
    register file) produces the policy step's outputs; the security-gate job's own `gate`,
    `posture` and `verdict` steps, extracted from the workflow as shipped, run on them with a seeded
    scanner result. Nothing here restates the gate's logic.

SCENARIOS (policy -> seeded result -> gate exit / enforcement, routing_result, causes, verdict exit)
    crawl_finding        kit default, a non-secret finding  -> ADVISORY, PROCEED_WITH_ADVISORY
                                                               (FINDINGS_NOT_BLOCKED), verdict 0
    crawl_secret         kit default, a secret               -> BLOCKED, BLOCKED, verdict 1
    crawl_clean          kit default, nothing found          -> PROCEED, verdict 0
    crawl_pick_blocks    crawl + deps-scan BLOCKED, a deps finding  -> BLOCKED
    crawl_pick_other     the same register, a bandit finding        -> PROCEED_WITH_ADVISORY
    walk_finding         org at walk, a finding              -> DECISION_REQUIRED (owes a decision)
    run_finding          org at run, a finding               -> BLOCKED
    softening            team softens org walk to crawl, attributed -> BLOCKED (KDEC-018,
                                                               POLICY_BELOW_AUTHORITY_FLOOR), verdict 1
    softening_authority_deploy_approval  the org softens the kit default deploy approval at prod,
                                                               attributed -> PROCEED_WITH_ADVISORY
                                                               (WEAKENING_ATTRIBUTED)
    expired              an expired tightening                -> DECISION_REQUIRED, walk kept
    conflict             two entries for one scope            -> BLOCKED, verdict 1
    unreadable           a register that does not parse       -> EVIDENCE_UNTRUSTED, verdict 1
    no_policy_step       the policy step emitted nothing, a finding -> the gate stays strict and
                                                               the finding BLOCKS (never crawl)
    crawl_crash_dev/prod kit default, a scanner crashed     -> gate BLOCKED, EVIDENCE_UNTRUSTED,
                                                               verdict 1 at EVERY tier (owner ruling
                                                               O-24: a scan that did not run blocks)
    crawl_collection_failed_dev, crawl_hollow_report_dev, crawl_bootstrap_dev -> blocked the same way
    crawl_failed_beside_findings_dev  a scanner job FAILED with findings on record -> EVIDENCE_UNTRUSTED
                                      (lane L-S: a job never fails on findings, so it could not finish)
    crawl_coverage_partial_dev  a version no carried scanner reads -> PROCEED_WITH_ADVISORY (a
                                                               coverage gap is advisory, not untrusted)
    crawl_parse_partial_clean / _finding  PHP Semgrep could not fully parse (lane L-P85) ->
                                                               COVERAGE_PARTIAL (and FINDINGS_NOT_BLOCKED
                                                               beside a softened finding); the summary
                                                               never calls it a version gap

THE SINGLE ENFORCEMENT POINT (lane L-S, 2026-10-22; owner ruling O-24)
    The scenarios above seed a job RESULT. These run the scanner jobs' own shipped `enforce` steps
    (composites expanded, as the runner sees them) on a seeded count, take the job's conclusion and
    its outputs from what those steps did, and hand THAT to the gate. A scanner job reports; it fails
    only when it could not scan or could not trust its own result. The gate alone enforces, by the
    resolved policy -- so the workflow's conclusion is the verdict, and a caller's `needs:` chain
    (templates/build-deploy.yml) builds on PROCEED_WITH_ADVISORY instead of skipping.
    sep_crawl_finding_<job>   kit default, an ordinary finding in <job> -> every scanner job
                              succeeds, publishes findings_state=FINDINGS, the gate succeeds,
                              PROCEED_WITH_ADVISORY (FINDINGS_NOT_BLOCKED), verdict 0
    sep_run_finding_<job>     the org at `run`, the same finding -> the scanner job STILL succeeds;
                              the gate fails, BLOCKED, verdict 1
    sep_no_policy_finding     no policy step, a finding -> the scanner job succeeds; the gate stays
                              strict and BLOCKS
    sep_crawl_secret          a secret -> the secret job SUCCEEDS and hands it over (a secret may be
                              excepted, owner 2026-10-22, and only the gate holds the policy); with
                              no exception the gate fails, BLOCKED

SECRET EXCEPTIONS (owner ruling 2026-10-22: "requested and logged with tickets that have explanations")
    sx_applied / _two / _repository_file  one finding each by fingerprint, ticketed, explained,
                              approved, unexpired, reviewers at prod -> secret_gate EXCEPTED,
                              PROCEED_WITH_ADVISORY (SECRET_EXCEPTION_ATTRIBUTED), logged (ticket,
                              approver, expiry) in the summary and secret_exceptions_applied
    sx_unticketed / _ticket_not_a_key / _ticket_outside_range  -> SECRET_EXCEPTION_UNTICKETED, BLOCKED
    sx_no_explanation / _no_approver / _no_reviewers_prod      -> SECRET_EXCEPTION_UNATTRIBUTED, BLOCKED
    sx_expired                -> SECRET_EXCEPTION_EXPIRED, BLOCKED
    sx_class_wide / _scanner_wide  -> SECRET_EXCEPTION_NOT_FINDING_SCOPED, BLOCKED
    sx_controls_softening     secrets softened as a control -> CHERRY_PICK_BELOW_FLOOR, BLOCKED
    sx_second_secret / _same_fingerprint_twice / _count_unaccounted  a secret not covered -> BLOCKED
    sx_no_policy_step         no resolved policy -> BLOCKED
    FAILS ON 7515088 (and on 5b06ccb): the register refuses `secret_exceptions` (an unknown field,
    REGISTRATION_UNAVAILABLE) and the gate has no notion of an exception.
    sep_crawl_collection_failed / _iac_advisory  COLLECTION_FAILED -> that scanner job FAILS (even
                              under advisory_mode); the gate fails, EVIDENCE_UNTRUSTED
    sep_crawl_clean_all       nothing found anywhere -> every scanner job succeeds, PROCEED

EXIT  0 every scenario as it must   1 a scenario did not   2 could not be checked
"""
import io
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, HERE)
import prove_bootstrap_failure as pbf  # noqa: E402
import prove_gate_routing as G  # noqa: E402

RESOLVER = os.path.join(ROOT, 'scripts', 'policy_registration.py')
# Two secret findings' fingerprints, as the security report computes them (scan_report fingerprint()).
fp_a, fp_b = 'a1b2c3d4e5f6', '0f1e2d3c4b5a'
TODAY = '2026-10-22'
REPOSITORY = 'acme/ledger-api'


def decision(**over):
    d = {'authority': 'Dana Example', 'reason': 'adoption plan', 'decided_on': '2026-10-20',
         'expires': '2099-01-31', 'environment_reviewers': ['platform-approvers']}
    d.update(over)
    return d


def central(policies):
    return {'schema_version': 2, 'register_id': 't',
            'sign_off': {'by': 'Dana Example', 'role': 'security-lead', 'date': '2026-10-21'},
            'repositories': {REPOSITORY: {'team': 'payments', 'product': 'ledger'}},
            'policies': [dict(p, decision=p.get('decision') or decision()) for p in policies]}


def policy_outputs(work, cen, environment='prod', event='push', text=None, repo_doc=None):
    """Run the real resolver CLI; -> {'steps.policy.outputs.<k>': v}. `repo_doc`: the repository's
    own registration, committed to its default branch (a fresh repository per call)."""
    g = ['git', '-c', 'user.name=t', '-c', 'user.email=t@example.invalid', '-c', 'commit.gpgsign=false',
         '-c', 'init.defaultBranch=main']
    repo = os.path.join(work, 'repo')
    if repo_doc is not None:
        n = 0
        while os.path.isdir(os.path.join(work, 'repo-file-%d' % n)):
            n += 1
        repo = os.path.join(work, 'repo-file-%d' % n)
        os.makedirs(os.path.join(repo, '.security'))
        subprocess.run(g + ['init', '-q'], cwd=repo, check=True)
        with io.open(os.path.join(repo, '.security', 'policy-registration.json'), 'w', encoding='utf-8') as fh:
            fh.write(json.dumps(repo_doc))
        subprocess.run(g + ['add', '-A'], cwd=repo, check=True)
        subprocess.run(g + ['commit', '-q', '-m', 'x'], cwd=repo, check=True)
    elif not os.path.isdir(repo):
        os.makedirs(repo)
        subprocess.run(g + ['init', '-q'], cwd=repo, check=True)
        subprocess.run(g + ['commit', '-q', '--allow-empty', '-m', 'x'], cwd=repo, check=True)
    # THE CENTRAL REGISTER IS COMMITTED, ONCE, in a fresh kit repository per call: its exceptions'
    # renewal histories come from git (KDEC-022 item 2), and a register in no git history is
    # EXCEPTION_HISTORY_UNVERIFIED. One commit is a first grant of everything in it.
    n = 0
    while os.path.isdir(os.path.join(work, 'kit-%d' % n)):
        n += 1
    kit = os.path.join(work, 'kit-%d' % n)
    cpath = os.path.join(kit, 'policy', 'policy-registration.json')
    if text is not None or cen is not None:
        os.makedirs(os.path.dirname(cpath))
        subprocess.run(g + ['init', '-q'], cwd=kit, check=True)
        with io.open(cpath, 'w', encoding='utf-8', newline='\n') as fh:
            fh.write(text if text is not None else json.dumps(cen))
        subprocess.run(g + ['add', '-A'], cwd=kit, check=True)
        subprocess.run(g + ['commit', '-q', '-m', 'central'], cwd=kit, check=True)
    out = os.path.join(work, 'gh_output')
    io.open(out, 'w').close()
    subprocess.run([sys.executable, RESOLVER, '--repo', repo, '--default-ref', 'main', '--central', cpath,
                    '--repository', REPOSITORY, '--environment', environment, '--event', event,
                    '--supplied-json', '{"language": "auto"}', '--today', TODAY, '--github-output', out],
                   capture_output=True, text=True)
    vals = {}
    for line in io.open(out, encoding='utf-8'):
        if '=' in line:
            k, v = line.rstrip('\n').split('=', 1)
            vals['steps.policy.outputs.%s' % k] = v
    return vals


def scanners(findings_in='', failed=()):
    """Every scanner succeeded; `findings_in` jobs have blocking findings on record -- handed to the
    gate as findings_state=FINDINGS by a job that SUCCEEDED (lane L-S: the single enforcement
    point) -- the secret scan included; a known-malicious package still fails its job; `failed`
    jobs crashed with no findings."""
    d = pbf.ctx()
    jobs = findings_in.split()
    for j in jobs:
        if j == 'malicious-deps':
            d['needs.%s.result' % j] = 'failure'
        elif j == 'secret-scan':
            # The secret scan hands its secrets over too (owner ruling 2026-10-22): the count,
            # and the report's fingerprint of each one -- here one secret, fp_a.
            d['needs.secret-scan.outputs.findings_state'] = 'FINDINGS'
            d['needs.secret-scan.outputs.secret_count'] = '1'
            d['needs.report.outputs.secret_findings'] = fp_a
        else:
            d['needs.%s.outputs.findings_state' % j] = 'FINDINGS'
    for j in failed:
        d['needs.%s.result' % j] = 'failure'
    d['needs.report.outputs.blocking_findings'] = str(3 * len(jobs))
    d['needs.report.outputs.jobs_with_findings'] = ' '.join(jobs)
    return d


def step(steps, sid):
    return next((s for s in steps if s.get('id') == sid), None)


# ── THE SINGLE ENFORCEMENT POINT: the scanner jobs' own enforce steps, run ─────────────────────
#
# Every scanner job whose own threshold can fire on an ordinary (non-secret) finding. code-quality
# is not here: its lint steps run the linters themselves (tests/prove_code_quality_enforces.py runs
# them, and asserts the same rule). codeql never failed on findings; sbom hands its licence verdict
# to the gate; malicious-deps is secret-class (a known-malicious package blocks in every mode).
FINDING_JOBS = ('sast-semgrep', 'sast-bandit', 'sast-go', 'deps-scan', 'iac-scan', 'sast-dotnet',
                'sast-java', 'sast-cpp', 'image-scan', 'sast-mobile')
SECRET_JOB = 'secret-scan'
STEP_OUT = re.compile(r'steps\.([A-Za-z0-9_-]+)\.outputs\.([A-Za-z0-9_-]+)')
SEP_INPUTS = {'inputs.soft_fail_sast': 'false', 'inputs.advisory_mode': 'false',
              'inputs.fail_on_severity': 'CRITICAL,HIGH'}


def enforce_steps(doc, job):
    """The job's shipped steps whose name says they enforce, composites expanded."""
    return [s for s in ((doc.get('jobs') or {}).get(job) or {}).get('steps') or []
            if 'enforce' in (s.get('name') or '').lower() and s.get('run')]


def seed_for(step_def, count, collection):
    """Every `steps.<id>.outputs.<k>` the enforce step reads, seeded. -> (values, unmodelled)."""
    text = json.dumps(step_def.get('env') or {}) + (step_def.get('run') or '')
    vals, unmodelled = {}, []
    for sid, key in STEP_OUT.findall(text):
        k = 'steps.%s.outputs.%s' % (sid, key)
        if key == 'count':
            vals[k] = str(count)
        elif key == 'collection':
            vals[k] = collection
        elif key == 'scan_state':
            vals[k] = 'COMPLETE'
        else:
            unmodelled.append(k)
    return vals, unmodelled


def job_outputs(doc, job, produced):
    """Evaluate the job's `outputs:` the way the runner does, over what its steps wrote.
    Supports `${{ steps.a.outputs.b }}` and `||` chains of them; anything else is unmodelled."""
    out, unmodelled = {}, []
    for name, expr in ((((doc.get('jobs') or {}).get(job) or {}).get('outputs')) or {}).items():
        m = re.fullmatch(r'\s*\$\{\{\s*(.*?)\s*\}\}\s*', str(expr), re.S)
        if not m:
            unmodelled.append('%s.outputs.%s' % (job, name))
            continue
        val = ''
        for term in m.group(1).split('||'):
            t = term.strip()
            tm = re.fullmatch(r'steps\.([A-Za-z0-9_-]+)\.outputs\.([A-Za-z0-9_-]+)', t)
            if re.fullmatch(r'steps\.[A-Za-z0-9_-]+\.outcome', t):
                # A step the scenario does not run (image-scan's secrets step): it found nothing.
                val = val or produced.get(t, 'success')
                continue
            if not tm:
                unmodelled.append('%s.outputs.%s (%s)' % (job, name, t))
                val = ''
                break
            if not val:
                val = produced.get(t, '')
        out[name] = val
    return out, unmodelled


def run_scanner_job(bash, doc, job, count=0, collection='COMPLETE', inputs=None):
    """Run the job's enforce steps on a seeded count. -> (result, outputs, log, unmodelled)."""
    steps = enforce_steps(doc, job)
    if not steps:
        return 'absent', {}, '%s has no enforce step' % job, []
    produced, unmodelled, failed, log = {}, [], False, ''
    for s in steps:
        seeded, um = seed_for(s, count, collection)
        unmodelled += um
        values = dict(SEP_INPUTS, **dict(inputs or {}, **seeded))
        body, _seen = pbf.substitute(pbf.with_kit_bundle(s.get('run') or ''), values)
        env, _u = pbf.resolve_env(s.get('env'), values)
        rc, emitted, slog, _summ = pbf.run(bash, body, env)
        log += '[%s] exit %d\n%s\n' % (s.get('name'), rc, slog[-300:])
        sid = s.get('id')
        for k, v in emitted.items():
            if sid:
                produced['steps.%s.outputs.%s' % (sid, k)] = v
        produced.update(seeded)
        failed = failed or rc != 0
    outs, um = job_outputs(doc, job, produced)
    return ('failure' if failed else 'success'), outs, log, unmodelled + um


def sep_case(bash, doc, steps, pol, seeded_job, count, collection='COMPLETE', inputs=None,
             all_jobs=False):
    """One single-enforcement-point scenario: scanner jobs RUN, then gate -> posture -> verdict."""
    d = pbf.ctx()
    jobs = list(FINDING_JOBS) + [SECRET_JOB] if all_jobs else [j for j in (seeded_job,) if j]
    results, notes = {}, []
    for j in jobs:
        n = count if j == seeded_job else 0
        res, outs, log, um = run_scanner_job(bash, doc, j, n, collection if j == seeded_job else 'COMPLETE',
                                             inputs)
        results[j] = (res, outs, log)
        notes += um
        d['needs.%s.result' % j] = res if res != 'absent' else 'success'
        for k, v in outs.items():
            d['needs.%s.outputs.%s' % (j, k)] = v
    if seeded_job and count:
        # The report reads the job's SARIF: the finding is on record whatever the job concluded.
        d['needs.report.outputs.jobs_with_findings'] = seeded_job
        d['needs.report.outputs.blocking_findings'] = str(count)
        if seeded_job == SECRET_JOB:
            d['needs.report.outputs.secret_findings'] = ' '.join([fp_a, fp_b][:count])
    if inputs:
        d.update(inputs)
    return results, run_job(bash, steps, pol, d), notes


def sep_scenarios(work):
    run_rung = central([{'id': 'r', 'scope': {'org': 'acme'}, 'rung': 'run'}])
    crawl = policy_outputs(work, None, environment='dev')
    strict = policy_outputs(work, run_rung, environment='dev')
    out = []
    # name, policy, seeded job, count, collection, inputs, all_jobs,
    #   expected: {job: result}, findings_state of the seeded job, gate exit 0?, route, cause, verdict 0?
    for j in FINDING_JOBS:
        out.append(('sep_crawl_finding_%s' % j, crawl, j, 3, 'COMPLETE', None, False,
                    {j: 'success'}, 'FINDINGS', True, 'PROCEED_WITH_ADVISORY', 'FINDINGS_NOT_BLOCKED', True))
        out.append(('sep_run_finding_%s' % j, strict, j, 3, 'COMPLETE', None, False,
                    {j: 'success'}, 'FINDINGS', False, 'BLOCKED', None, False))
    out += [
        ('sep_no_policy_finding', {}, 'sast-bandit', 3, 'COMPLETE', None, False,
         {'sast-bandit': 'success'}, 'FINDINGS', False, 'BLOCKED', None, False),
        # A secret: the secret job SUCCEEDS and hands it over (owner ruling 2026-10-22: a secret
        # may be excepted, and only the gate holds the policy); with no exception the gate BLOCKS.
        ('sep_crawl_secret', crawl, SECRET_JOB, 2, 'COMPLETE', None, False,
         {SECRET_JOB: 'success'}, 'FINDINGS', False, 'BLOCKED', None, False),
        ('sep_crawl_collection_failed', crawl, 'deps-scan', 0, 'COLLECTION_FAILED', None, False,
         {'deps-scan': 'failure'}, None, False, 'EVIDENCE_UNTRUSTED', None, False),
        ('sep_crawl_collection_failed_iac_advisory', crawl, 'iac-scan', 0, 'COLLECTION_FAILED',
         {'inputs.advisory_mode': 'true'}, False,
         {'iac-scan': 'failure'}, None, False, 'EVIDENCE_UNTRUSTED', None, False),
        ('sep_crawl_clean_all', crawl, None, 0, 'COMPLETE', None, True,
         dict((j, 'success') for j in FINDING_JOBS + (SECRET_JOB,)), None, True, 'PROCEED', None, True),
    ]
    return out


# ── SECRET EXCEPTIONS (owner ruling 2026-10-22): ticketed, attributed, finding-scoped ───────────

def sx_item(finding=fp_a, **over):
    item = {'finding': finding, 'ticket': 'SEC-1234', 'explanation': 'test credential in a fixture; '
            'rotated, removal tracked on the ticket', 'approver': 'Dana Example', 'expires': '2099-01-31',
            'environment_reviewers': ['platform-approvers']}
    for k, v in over.items():
        if v is None:
            item.pop(k, None)
        else:
            item[k] = v
    return item


def sx_central(items, numbers=None, extra=None, **dec):
    doc = central([dict({'id': 'sx', 'scope': {'org': 'acme'}, 'secret_exceptions': items},
                        decision=decision(**dec), **(extra or {}))])
    if numbers:
        doc['numbers'] = numbers
    return doc


def secret_seed(fps, count=None):
    d = pbf.ctx()
    d['needs.secret-scan.outputs.findings_state'] = 'FINDINGS'
    d['needs.secret-scan.outputs.secret_count'] = str(len(fps) if count is None else count)
    d['needs.report.outputs.secret_findings'] = ' '.join(fps)
    d['needs.report.outputs.jobs_with_findings'] = 'secret-scan'
    d['needs.report.outputs.blocking_findings'] = str(len(fps))
    return d


def sx_scenarios(work):
    """name, policy outputs, seeded, expected route, refusal code (or None), excepted?"""
    no_rv = dict(environment_reviewers=None)
    return [
        ('sx_applied', policy_outputs(work, sx_central([sx_item()])), secret_seed([fp_a]),
         'PROCEED_WITH_ADVISORY', None, True),
        ('sx_applied_two', policy_outputs(work, sx_central([sx_item(), sx_item(fp_b, ticket='SEC-1235')])),
         secret_seed([fp_a, fp_b]), 'PROCEED_WITH_ADVISORY', None, True),
        ('sx_repository_file', policy_outputs(work, None, repo_doc={
            'schema_version': 2, 'register_id': 'repo',
            'sign_off': {'by': 'Dana Example', 'role': 'security-lead', 'date': '2026-10-21'},
            'policies': [{'id': 'sx-repo', 'scope': {}, 'secret_exceptions': [sx_item()],
                          'decision': decision()}]}),
         secret_seed([fp_a]), 'PROCEED_WITH_ADVISORY', None, True),
        ('sx_unticketed', policy_outputs(work, sx_central([sx_item(ticket=None)])), secret_seed([fp_a]),
         'BLOCKED', 'SECRET_EXCEPTION_UNTICKETED', False),
        ('sx_ticket_not_a_key', policy_outputs(work, sx_central([sx_item(ticket='see the jira board')])),
         secret_seed([fp_a]), 'BLOCKED', 'SECRET_EXCEPTION_UNTICKETED', False),
        ('sx_ticket_outside_range', policy_outputs(work, sx_central([sx_item(ticket='SEC-12')], numbers={
            'ticket_min_digits': 3, 'ticket_max_digits': 4})), secret_seed([fp_a]),
         'BLOCKED', 'SECRET_EXCEPTION_UNTICKETED', False),
        # A malformed key is not a ticket (lane L-FX, after lane L-W's G10): a leading zero.
        ('sx_ticket_leading_zero', policy_outputs(work, sx_central([sx_item(ticket='SEC-0123')])),
         secret_seed([fp_a]), 'BLOCKED', 'SECRET_EXCEPTION_UNTICKETED', False),
        ('sx_no_explanation', policy_outputs(work, sx_central([sx_item(explanation=None)])), secret_seed([fp_a]),
         'BLOCKED', 'SECRET_EXCEPTION_UNATTRIBUTED', False),
        ('sx_no_approver', policy_outputs(work, sx_central([sx_item(approver=None)])), secret_seed([fp_a]),
         'BLOCKED', 'SECRET_EXCEPTION_UNATTRIBUTED', False),
        ('sx_no_reviewers_prod', policy_outputs(work, sx_central([sx_item(**no_rv)], **no_rv)),
         secret_seed([fp_a]), 'BLOCKED', 'SECRET_EXCEPTION_UNATTRIBUTED', False),
        ('sx_expired', policy_outputs(work, sx_central([sx_item(expires='2026-01-01')])), secret_seed([fp_a]),
         'BLOCKED', 'SECRET_EXCEPTION_EXPIRED', False),
        ('sx_class_wide', policy_outputs(work, sx_central([sx_item('secrets')])), secret_seed([fp_a]),
         'BLOCKED', 'SECRET_EXCEPTION_NOT_FINDING_SCOPED', False),
        ('sx_scanner_wide', policy_outputs(work, sx_central([sx_item('secret-scan')])), secret_seed([fp_a]),
         'BLOCKED', 'SECRET_EXCEPTION_NOT_FINDING_SCOPED', False),
        ('sx_controls_softening', policy_outputs(work, central([{'id': 'soft', 'scope': {'org': 'acme'},
                                                                 'controls': {'secret-scan': 'PROCEED_WITH_ADVISORY'}}])),
         secret_seed([fp_a]), 'BLOCKED', None, False),
        ('sx_second_secret', policy_outputs(work, sx_central([sx_item()])), secret_seed([fp_a, fp_b]),
         'BLOCKED', None, False),
        ('sx_same_fingerprint_twice', policy_outputs(work, sx_central([sx_item()])), secret_seed([fp_a, fp_a]),
         'BLOCKED', None, False),
        ('sx_count_unaccounted', policy_outputs(work, sx_central([sx_item()])), secret_seed([fp_a], count=2),
         'BLOCKED', None, False),
        ('sx_no_policy_step', {}, secret_seed([fp_a]), 'BLOCKED', None, False),
    ]


def check_sx(bash, steps, work):
    bad = []
    for name, pol, seeded, route, refusal, excepted in sx_scenarios(work):
        if name != 'sx_no_policy_step' and not pol.get('steps.policy.outputs.policy_state'):
            bad.append('%s: the resolver emitted no policy_state' % name)
            continue
        r = run_job(bash, steps, pol, seeded)
        refused = pol.get('steps.policy.outputs.policy_secret_exception_refusals', '')
        sg = r['gate'].get('secret_gate')
        print('  %-28s policy=%-26s gate exit=%d secret_gate=%-8s route=%-22s causes=%s'
              % (name, pol.get('steps.policy.outputs.policy_state', '(none)'), r['gate_rc'], sg, r['route'],
                 r['causes'] or '-'))
        if r['route'] != route:
            bad.append('%s: routing_result=%s, expected %s\n%s' % (name, r['route'], route, r['log']))
        if excepted:
            if r['gate_rc'] != 0 or r['verdict_rc'] != 0:
                bad.append('%s: gate exit %d / verdict exit %d, expected both 0 -- an excepted secret is '
                           'advisory' % (name, r['gate_rc'], r['verdict_rc']))
            if sg != 'EXCEPTED':
                bad.append('%s: secret_gate=%r, expected EXCEPTED (never PASS)' % (name, sg))
            if 'SECRET_EXCEPTION_ATTRIBUTED' not in r['causes'].split(','):
                bad.append('%s: advisory_causes=%r lack SECRET_EXCEPTION_ATTRIBUTED' % (name, r['causes']))
            applied = r['gate'].get('secret_exceptions_applied', '')
            if fp_a not in applied or 'SEC-1234' not in applied or 'Dana Example' not in applied:
                bad.append('%s: secret_exceptions_applied=%r does not record the finding, ticket and '
                           'approver (it feeds the run record)' % (name, applied))
            if 'SEC-1234' not in r['gate_summary'] or '2099-01-31' not in r['gate_summary']:
                bad.append('%s: the gate summary does not log the ticket and expiry' % name)
        else:
            if r['gate_rc'] == 0 and r['verdict_rc'] == 0:
                bad.append('%s: the gate and verdict passed a secret that is not excepted' % name)
            if r['verdict_rc'] == 0:
                bad.append('%s: verdict exit 0 on a secret that is not excepted' % name)
            if sg == 'EXCEPTED':
                bad.append('%s: secret_gate EXCEPTED without a valid exception for every secret' % name)
        if refusal and refusal not in refused:
            bad.append('%s: the register did not refuse the exception as %s (refusals %r)' % (name, refusal, refused))
        if refusal and refusal not in r['gate_summary']:
            bad.append('%s: the gate summary does not name the refusal %s' % (name, refusal))
    return bad


def check_sep(bash, doc, steps, work):
    """-> [failure]. Every single-enforcement-point scenario, run."""
    bad = []
    for (name, pol, job, count, coll, inputs, all_jobs, want_results, want_fs, gate_zero, route,
         cause, verdict_zero) in sep_scenarios(work):
        if name != 'sep_no_policy_finding' and not pol.get('steps.policy.outputs.policy_state'):
            bad.append('%s: the resolver emitted no policy_state' % name)
            continue
        results, r, notes = sep_case(bash, doc, steps, pol, job, count, coll, inputs, all_jobs)
        print('  %-42s jobs=%-40s gate exit=%d route=%-22s verdict exit=%d'
              % (name, ','.join('%s:%s' % (j, v[0]) for j, v in sorted(results.items()))[:40],
                 r['gate_rc'], r['route'], r['verdict_rc']))
        for n in notes:
            bad.append('%s: unmodelled %s' % (name, n))
        for j, want in want_results.items():
            got = results.get(j, ('(not run)', {}, ''))
            if got[0] != want:
                why = ('a scanner job FAILED on an ordinary finding: it must report and leave '
                       'enforcement to the gate' if want == 'success' else
                       'a scanner job that could not scan, or found a secret, must FAIL')
                bad.append('%s: job %s concluded %s, expected %s -- %s\n%s'
                           % (name, j, got[0], want, why, got[2]))
        if want_fs is not None:
            fs = results.get(job, (None, {}, ''))[1].get('findings_state', '')
            if fs != want_fs:
                bad.append('%s: job %s published findings_state=%r, expected %r -- the gate cannot '
                           'enforce a finding the job does not hand it' % (name, job, fs, want_fs))
        if (r['gate_rc'] == 0) != gate_zero:
            bad.append('%s: gate exit %d, expected %s\n%s' % (name, r['gate_rc'],
                                                             'exit 0' if gate_zero else 'non-zero', r['log']))
        if r['route'] != route:
            bad.append('%s: routing_result=%s, expected %s\n%s' % (name, r['route'], route, r['log']))
        for c in (cause or '').split(','):
            if c and c not in r['causes'].split(','):
                bad.append('%s: advisory_causes=%r, expected %s among them' % (name, r['causes'], c))
        if (r['verdict_rc'] == 0) != verdict_zero:
            bad.append('%s: verdict exit %d, expected %s' % (name, r['verdict_rc'],
                                                             'exit 0' if verdict_zero else 'non-zero'))
    return bad


def run_job(bash, steps, pol, seeded):
    """gate -> posture -> verdict, each extracted as shipped. -> dict of what happened."""
    gate = step(steps, 'gate')
    values = dict(seeded, **pol)
    body, _seen = pbf.substitute(gate.get('run') or '', values)
    genv, _unknown = pbf.resolve_env(gate.get('env'), values)
    grc, gout, glog, gsumm = pbf.run(bash, body, genv)
    post = step(steps, 'posture')
    penv, unknown = G.resolve_env(post.get('env'), G.BASELINE, gout, pol)
    prc, pout, plog, psumm = pbf.run(bash, post.get('run') or '', penv)
    ver = step(steps, 'verdict')
    vvals = dict(pol, **dict(('steps.posture.outputs.%s' % k, v) for k, v in pout.items()))
    venv, _u = pbf.resolve_env(ver.get('env') if ver else {}, vvals)
    vrc, _vo, vlog, _vs = pbf.run(bash, (ver or {}).get('run') or 'exit 99', venv)
    return {'gate_rc': grc, 'enforcement': gout.get('enforcement_state'), 'route': pout.get('routing_result'),
            'causes': pout.get('advisory_causes', ''), 'verdict_rc': vrc, 'posture_rc': prc,
            'unknown': unknown, 'log': glog[-400:] + plog[-400:] + vlog[-300:], 'posture': pout,
            'summary': psumm, 'gate': gout, 'gate_summary': gsumm}


def main():
    try:
        import yaml
    except ImportError:
        print('UNKNOWN: PyYAML unavailable.')
        return 2
    bash, why = pbf.usable_bash()
    if not bash:
        print('UNKNOWN: no usable bash (%s).' % why)
        return 2
    doc = yaml.safe_load(io.open(pbf.WF, encoding='utf-8'))
    steps = doc['jobs']['security-gate'].get('steps') or []
    missing = [s for s in ('policy', 'gate', 'posture', 'verdict') if not step(steps, s)]
    if missing:
        print('FAIL: security-gate has no step(s) %s: the policy is not wired into the gate '
              '(wiring/gate-rung.patch.md)' % ', '.join(missing))
        return 1
    bad = []
    work = tempfile.mkdtemp(prefix='gate-policy-')
    try:
        org_walk = central([{'id': 'w', 'scope': {'org': 'acme'}, 'rung': 'walk'}])
        cases = [
            # name, policy outputs, seeded, (gate exit 0?, enforcement), route, cause, verdict exit 0?
            ('crawl_finding', policy_outputs(work, None), scanners('sast-bandit'),
             (True, 'ADVISORY'), 'PROCEED_WITH_ADVISORY', 'FINDINGS_NOT_BLOCKED', True),
            ('crawl_secret', policy_outputs(work, None), scanners('secret-scan'),
             (False, 'BLOCKED'), 'BLOCKED', None, False),
            ('crawl_clean', policy_outputs(work, None), scanners(),
             (True, 'ALLOWED'), 'PROCEED', None, True),
            ('crawl_pick_blocks', policy_outputs(work, central([{'id': 'p', 'scope': {'org': 'acme'},
                                                                 'controls': {'deps-scan': 'BLOCKED'}}])),
             scanners('deps-scan'), (False, 'BLOCKED'), 'BLOCKED', None, False),
            ('crawl_pick_other', policy_outputs(work, central([{'id': 'p', 'scope': {'org': 'acme'},
                                                                'controls': {'deps-scan': 'BLOCKED'}}])),
             scanners('sast-bandit'), (True, 'ADVISORY'), 'PROCEED_WITH_ADVISORY', 'FINDINGS_NOT_BLOCKED', True),
            ('walk_finding', policy_outputs(work, org_walk), scanners('sast-semgrep'),
             (True, 'ADVISORY'), 'DECISION_REQUIRED', None, True),
            ('run_finding', policy_outputs(work, central([{'id': 'r', 'scope': {'org': 'acme'}, 'rung': 'run'}])),
             scanners('sast-semgrep'), (False, 'BLOCKED'), 'BLOCKED', None, False),
            # KDEC-018 (owner, 2026-10-22): the org's rung is the floor. A team entry softening it,
            # even with an unexpired decision, is POLICY_BELOW_AUTHORITY_FLOOR -- BLOCKED (lane L-FX).
            ('softening', policy_outputs(work, central([
                {'id': 'w', 'scope': {'org': 'acme'}, 'rung': 'walk'},
                {'id': 's', 'scope': {'org': 'acme', 'team': 'payments'}, 'rung': 'crawl'}])),
             scanners(), (True, 'ALLOWED'), 'BLOCKED', None, False),
            # The one softening left: the AUTHORITY (org scope) softening the kit default's deploy
            # approval, attributed -- recorded as a weakening, and never honoured by the deploy.
            ('softening_authority_deploy_approval', policy_outputs(work, central([
                {'id': 'da', 'scope': {'org': 'acme', 'environment_tier': 'prod'},
                 'deploy_approval': {'self_review_prevented': 'not_required'}}])),
             scanners(), (True, 'ALLOWED'), 'PROCEED_WITH_ADVISORY', 'WEAKENING_ATTRIBUTED', True),
            ('expired', policy_outputs(work, central([{'id': 'w', 'scope': {'org': 'acme'}, 'rung': 'walk',
                                                        'decision': decision(expires='2026-01-01')}])),
             scanners(), (True, 'ALLOWED'), 'DECISION_REQUIRED', None, True),
            ('conflict', policy_outputs(work, central([{'id': 'a', 'scope': {'org': 'acme'}, 'rung': 'walk'},
                                                        {'id': 'b', 'scope': {'org': 'acme'}, 'rung': 'run'}])),
             scanners(), (True, 'ALLOWED'), 'BLOCKED', None, False),
            ('unreadable', policy_outputs(work, None, text='{broken'), scanners(),
             (True, 'ALLOWED'), 'EVIDENCE_UNTRUSTED', None, False),
            ('no_policy_step', {}, scanners('sast-bandit'), (False, 'BLOCKED'), 'BLOCKED', None, False),
            # OWNER RULING O-24 (2026-10-22): at crawl the gate also BLOCKS when the kit could not
            # run or trust its own scan -- a crash, COLLECTION_FAILED, a hollow or unreadable scan,
            # a bootstrap failure -- at EVERY tier: a pipeline that silently did not scan cannot
            # count as "scanned, advisory". A coverage gap (a version no carried scanner reads) is
            # COVERAGE_PARTIAL / VERSION_GAP advisory, not untrusted evidence.
            ('crawl_crash_dev', policy_outputs(work, None, environment='dev'), scanners(failed=('sast-go',)),
             (False, 'BLOCKED'), 'EVIDENCE_UNTRUSTED', None, False),
            ('crawl_crash_prod', policy_outputs(work, None, environment='prod'), scanners(failed=('sast-go',)),
             (False, 'BLOCKED'), 'EVIDENCE_UNTRUSTED', None, False),
            ('crawl_crash_beside_finding', policy_outputs(work, None, environment='dev'),
             scanners('sast-bandit', failed=('sast-go',)), (False, 'BLOCKED'), 'EVIDENCE_UNTRUSTED', None, False),
            # Lane L-S: a scanner job never fails on findings, so one that FAILED with findings on
            # record (gosec with one module unanalysed) could not finish its scan -- untrusted.
            ('crawl_failed_beside_findings_dev', policy_outputs(work, None, environment='dev'),
             dict(scanners(failed=('sast-go',)), **{'needs.report.outputs.jobs_with_findings': 'sast-go',
                                                    'needs.report.outputs.blocking_findings': '2'}),
             (False, 'BLOCKED'), 'EVIDENCE_UNTRUSTED', None, False),
            ('crawl_collection_failed_dev', policy_outputs(work, None, environment='dev'),
             dict(scanners(), **{'needs.malicious-deps.result': 'failure',
                                 'needs.malicious-deps.outputs.malicious_state': 'COLLECTION_FAILED'}),
             (False, 'BLOCKED'), 'BLOCKED', None, False),   # malware evidence absent is secret-class
            ('crawl_hollow_report_dev', policy_outputs(work, None, environment='dev'),
             dict(scanners(), **{'needs.report.outputs.blocking_findings': ''}),
             (True, 'ALLOWED'), 'EVIDENCE_UNTRUSTED', None, False),
            ('crawl_bootstrap_dev', policy_outputs(work, None, environment='dev'),
             dict(scanners(), **{'needs.kit-scripts.result': 'failure'}),
             (False, 'BLOCKED'), 'EVIDENCE_UNTRUSTED', None, False),
            ('crawl_coverage_partial_dev', policy_outputs(work, None, environment='dev'),
             dict(scanners(), **{'needs.resolve.outputs.capped_jobs': 'sast-semgrep',
                                 'needs.resolve.outputs.capability_gaps': 'php@.:sast-semgrep',
                                 'needs.resolve.outputs.capability_gap_count': '1'}),
             (True, 'ALLOWED'), 'PROCEED_WITH_ADVISORY', 'VERSION_GAP_UNVERIFIED', True),
            # PHP Semgrep could not fully parse (lane L-P85, PARSE_PARTIAL_PHP_SYNTAX): the scanner
            # READS the version; specific files did not parse. COVERAGE_PARTIAL, advisory -- and
            # when findings coincide and are softened, BOTH causes are named.
            ('crawl_parse_partial_clean', policy_outputs(work, None, environment='dev'),
             dict(scanners(), **{'needs.sast-semgrep.outputs.scan_state': 'PARTIAL',
                                 'needs.sast-semgrep.outputs.parse_partial_files': '["a.php"]'}),
             (True, 'ALLOWED'), 'PROCEED_WITH_ADVISORY', 'COVERAGE_PARTIAL', True),
            ('crawl_parse_partial_finding', policy_outputs(work, None, environment='dev'),
             dict(scanners('sast-semgrep'), **{'needs.sast-semgrep.outputs.scan_state': 'PARTIAL',
                                               'needs.sast-semgrep.outputs.parse_partial_files': '["a.php"]'}),
             (True, 'ADVISORY'), 'PROCEED_WITH_ADVISORY', 'FINDINGS_NOT_BLOCKED,COVERAGE_PARTIAL', True),
            # C/C++ analysed without its build (KDEC-026, CPP_ANALYSIS_PARTIAL): the same visible
            # partial -- COVERAGE_PARTIAL, advisory, never a PASS.
            ('crawl_cpp_partial_clean', policy_outputs(work, None, environment='dev'),
             dict(scanners(), **{'needs.sast-cpp.outputs.scan_state': 'PARTIAL',
                                 'needs.sast-cpp.outputs.scan_reason': 'CPP_ANALYSIS_PARTIAL'}),
             (True, 'ALLOWED'), 'PROCEED_WITH_ADVISORY', 'COVERAGE_PARTIAL', True),
        ]
        for name, pol, seeded, (gate_zero, enf), route, cause, verdict_zero in cases:
            if name != 'no_policy_step' and not pol.get('steps.policy.outputs.policy_state'):
                bad.append('%s: the resolver emitted no policy_state' % name)
                continue
            r = run_job(bash, steps, pol, seeded)
            print('  %-18s policy=%-28s gate exit=%d %-8s route=%-22s causes=%-22s verdict exit=%d'
                  % (name, pol.get('steps.policy.outputs.policy_state', '(none)'), r['gate_rc'],
                     r['enforcement'], r['route'], r['causes'] or '-', r['verdict_rc']))
            if r['unknown']:
                bad.append('%s: the posture step reads %s, unmodelled here' % (name, r['unknown']))
            if (r['gate_rc'] == 0) != gate_zero or r['enforcement'] != enf:
                bad.append('%s: gate exit %d enforcement %s, expected %s / %s'
                           % (name, r['gate_rc'], r['enforcement'], 'exit 0' if gate_zero else 'non-zero', enf))
            if r['route'] != route:
                bad.append('%s: routing_result=%s, expected %s\n%s' % (name, r['route'], route, r['log']))
            for c in (cause or '').split(','):
                if c and c not in r['causes'].split(','):
                    bad.append('%s: advisory_causes=%r, expected %s among them' % (name, r['causes'], c))
            # The summary names the cause it has, not a version gap for every PARTIAL.
            version_words = 'no carried scanner can read the target version'
            if name.startswith('crawl_parse_partial') and version_words in r['summary']:
                bad.append('%s: the posture summary calls a PHP parse gap a version gap' % name)
            if name == 'crawl_coverage_partial_dev' and version_words not in r['summary']:
                bad.append('%s: the posture summary does not name the version gap' % name)
            if r['posture_rc'] != 0:
                bad.append('%s: the posture step exited %d; it records, it does not decide' % (name, r['posture_rc']))
            if (r['verdict_rc'] == 0) != verdict_zero:
                bad.append('%s: verdict exit %d, expected %s' % (name, r['verdict_rc'], 'exit 0' if verdict_zero else 'non-zero'))
            if name == 'expired' and r['posture'].get('rung_effective') != 'walk':
                bad.append('expired: an expired tightening lapsed to %r' % r['posture'].get('rung_effective'))
            if name.startswith('crawl') and pol and r['posture'].get('policy_source') != 'KIT_DEFAULT' \
                    and name not in ('crawl_pick_blocks', 'crawl_pick_other'):
                bad.append('%s: the kit default was not recorded as policy_source KIT_DEFAULT (%r)'
                           % (name, r['posture'].get('policy_source')))
        print('  -- the single enforcement point: scanner jobs RUN, then the gate --')
        bad += check_sep(bash, pbf._expand(doc), steps, work)
        print('  -- secret exceptions: ticketed, attributed, unexpired, one finding each --')
        bad += check_sx(bash, steps, work)
    except (OSError, subprocess.CalledProcessError) as exc:
        print('UNKNOWN: fixture could not be built: %s' % exc)
        return 2
    finally:
        shutil.rmtree(work, ignore_errors=True)
    if bad:
        for b in bad:
            print('FAIL: %s' % b)
        return 1
    print('PASS: with no register only secrets block and a non-secret finding is PROCEED_WITH_ADVISORY '
          '(FINDINGS_NOT_BLOCKED); a registered cherry-pick blocks exactly its control; walk owes a '
          'decision and run blocks; a narrower scope softening the authority floor is BLOCKED while the '
          'authority\'s attributed softening of the kit default is advisory with its cause; an expired, '
          'conflicting or unreadable policy is refused; no policy step leaves the gate strict; a scan the '
          'kit could not run or trust blocks at every tier (O-24) while a coverage gap stays advisory; '
          'and, with the scanner jobs\' own enforce steps run, a scanner job reports its findings and '
          'fails only when it could not scan or found a secret -- the gate is the single enforcement '
          'point, so the run concludes as its verdict.')
    return 0


if __name__ == '__main__':
    sys.exit(main())

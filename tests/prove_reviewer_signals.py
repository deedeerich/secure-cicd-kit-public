#!/usr/bin/env python3
"""What a reviewer could not see from the kit is now recorded, and refused where the policy says
(KDEC-036 PROPOSED; the security-review lane's gaps G1-G6, G8-G10, 2026-11-03).

WHY THIS EXISTS

    The security-review sheets (docs/security-review/) found signals a reviewer needs that the kit
    did not compute, or put only in a job summary. Each claim below is run through the code the run
    executes -- the composite step as shipped, the posture step as shipped, the deploy job as shipped
    against the stub cloud -- and each holds the four cases of docs/PROOF_RULE.md where it is a gate.

CLAIMS
    R1  WIRED. The security gate runs the reviewer-signals composite after the run record and before
        the verdict, always; resolve-policy checks the weakening record; discover names deploy
        coverage and the retention; the gate and the workflow expose capability_floor,
        token_preflight, leak_gate_alarm, policy_notices, no_kit_adapter, kit_watermark and
        security_record; the evidence artifacts keep the configured retention. Each deploy runs the
        composite before login (after the approval) and after the release (before the evidence is
        kept), grants deployments: write, registers the two new causes, and exposes the signals.
    R2  G2/G3 IN THE GATE (owner rulings 2026-11-03). A weakening is approved (WEAKENING_ATTRIBUTED) only
        with an evidence reference, a reason, a named owner, an expiry within the ceiling and an approver on
        a registered list (allowed); the requester or the release's author as owner or approver is
        WEAKENING_SELF_APPROVED, BLOCKED in every mode (attack); any field missing, an approver on no list,
        no list registered, the author unreadable is WEAKENING_NOT_APPROVED naming the field (missing
        evidence): the run proceeds at crawl with the control still counted weakened.
    R3  G8, G2/G3, G10 BEFORE LOGIN. Refused at uat/prod: a typed verdict (no record and no valid manual
        review), an unreadable record, the gate's WEAKENING_NOT_APPROVED, its own record not approved; at
        every tier: a self-approved record, a verdict more permissive than its gate's, one dropping a cause,
        a record for another commit, a hosting kind the adapter does not serve. A typed verdict with an
        AppSec reviewer (on the AppSec list, not the requester or author), a reference and a date is
        MANUAL_REVIEW_VERDICT (allowed), never over a gate's own record. Recovery: a refused typed verdict
        proceeds once the record exists.
    R4  G4/G9 RECORDED. The tier's source (TIER_VENDED only with the landing zone's marker) and the
        called kit copy's watermark (BOUND, DIRTY, ABSENT).
    R5  G6 DURABLE. With the lease off the release record is a GitHub deployment (task
        kit-release-record) and a status, its payload the record; refused by the API it is
        RELEASE_RECORD_NOT_KEPT and the step fails; with the lease on no deployment is written.
        G4: a custom domain under dev is TIER_MISMATCH_SUSPECTED, a warning, never a refusal.
    R6  G5/G9 THE SECURITY RECORD. kit-security-record.json carries every signal, the retention is
        floored at the audit minimum, and the watermark's source commit is in it.
    R7  G10 DISCOVERY. Kubernetes manifests, a Helm chart, VM infrastructure, a workflow deploying
        to AKS, a code-packaged Functions app: NO_KIT_ADAPTER:<kind>; a containerised Functions app
        and an ordinary app: none.
    R8  G10 THE FUNCTIONS ADAPTER. The App Service reusable with site_kind functionapp releases a
        containerised function app through `az functionapp` (healthy, by digest, slot first); a
        code-packaged one is refused before any change (NO_KIT_ADAPTER:function_app_code), as is a
        kind mismatch either way; an ordinary web app is unchanged.
    R9  G1 READINESS (owner ruling 2026-11-03). The landing zone's hand-off, or AppSec's attestation
        (.kit/zone-readiness.json, its latest change merged through a pull request an AppSec approver who
        is not its author approved, naming this environment, unexpired): permitted at prod; approved by its
        author, by someone off the AppSec list, pushed without a pull request, expired, for another
        environment, without evidence: refused; set by the repository for itself: self-set, refused at
        prod unless labelled a test fixture; nothing is read below uat. The zone step decides on it.

EXIT 0 proven   1 a claim failed   2 could not be checked
"""
import datetime
import http.server
import io
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import threading
import zipfile

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, HERE)
sys.path.insert(0, os.path.join(ROOT, 'scripts'))
SEC = os.path.join(ROOT, '.github', 'workflows', 'reusable-security.yml')
DEPLOYS = {n: os.path.join(ROOT, '.github', 'workflows', 'reusable-deploy-%s.yml' % n)
           for n in ('containerapp', 'appservice', 'staticwebapp')}
ACTION = os.path.join(ROOT, '.github', 'actions', 'reviewer-signals', 'action.yml')
POLICY_ACTION = os.path.join(ROOT, '.github', 'actions', 'resolve-policy', 'action.yml')
DISCOVER = os.path.join(ROOT, '.github', 'actions', 'discover', 'action.yml')
TODAY = datetime.date.today()
SHA = '5' * 40
LISTS = {'approver_lists': {'deployment-approvers': ['org/security', 'architects'], 'appsec': ['appsec-reviewer']}}
FAILS = []


def check(cond, msg):
    if not cond:
        FAILS.append(msg)
    return cond


def posix(p):
    return p.replace('\\', '/')


def yload(path):
    import yaml
    return yaml.safe_load(io.open(path, encoding='utf-8'))


def steps_of(doc, job=None):
    return (doc['jobs'][job] if job else doc['runs']).get('steps') or []


def by_id(steps, sid):
    return next((s for s in steps if s.get('id') == sid), None)


# ----------------------------------------------------------------------------- running steps
class World(object):
    """A kit root (the scripts a composite reaches through $/), a python3 on bash's PATH, a work dir."""

    def __init__(self, central=None, watermark=None, author='release-author'):
        self.dir = tempfile.mkdtemp(prefix='reviewer-signals-')
        self.kit = os.path.join(self.dir, 'kit')
        for d in ('scripts', 'policy', os.path.join('.github', 'actions', 'reviewer-signals'),
                  os.path.join('.github', 'actions', 'resolve-policy'), os.path.join('.github', 'actions', 'discover')):
            os.makedirs(os.path.join(self.kit, d))
        for f in ('reviewer_signals.py', 'rollback_hold.py'):
            shutil.copy(os.path.join(ROOT, 'scripts', f), os.path.join(self.kit, 'scripts', f))
        if central is not None:
            io.open(os.path.join(self.kit, 'policy', 'policy-registration.json'), 'w').write(json.dumps(central))
        if watermark is not None:
            io.open(os.path.join(self.kit, '.neutral-export-watermark.json'), 'w').write(json.dumps(watermark))
        self.bin = os.path.join(self.dir, 'bin')
        os.makedirs(self.bin)
        io.open(os.path.join(self.bin, 'python3'), 'w', newline='\n').write(
            '#!/bin/bash\nexec "%s" "$@"\n' % posix(sys.executable))
        os.chmod(os.path.join(self.bin, 'python3'), 0o755)
        self.temp = os.path.join(self.dir, 'runner-temp')
        os.makedirs(os.path.join(self.temp, 'deploy-evidence'))
        self.api = os.path.join(self.dir, 'api')
        os.makedirs(os.path.join(self.api, 'repos', 'o', 'r', 'actions', 'runs'))
        if author:
            self.commit(SHA, author)

    def close(self):
        shutil.rmtree(self.dir, ignore_errors=True)

    def api_url(self):
        return 'file:///' + posix(self.api).lstrip('/')

    def commit(self, sha, login):
        """The recorded API's answer for a commit: its author (who may never approve its exception)."""
        d = os.path.join(self.api, 'repos', 'o', 'r', 'commits')
        os.makedirs(d, exist_ok=True)
        io.open(os.path.join(d, sha), 'w').write(json.dumps({'author': {'login': login}, 'parents': [{'sha': '0' * 40}]}))

    def record_run(self, run_id, record):
        """The security record artifact of `run_id`, served by the recorded API."""
        runs = os.path.join(self.api, 'repos', 'o', 'r', 'actions', 'runs', str(run_id))
        os.makedirs(runs, exist_ok=True)
        arts = []
        if record is not None:
            buf = io.BytesIO()
            with zipfile.ZipFile(buf, 'w') as zf:
                zf.writestr('kit-security-record.json', json.dumps(record))
            z = os.path.join(self.api, 'zip-%s' % run_id)
            io.open(z, 'wb').write(buf.getvalue())
            arts = [{'id': 7, 'name': 'kit-security-record-1', 'expired': False,
                     'archive_download_url': 'file:///' + posix(z).lstrip('/')}]
        io.open(os.path.join(runs, 'artifacts'), 'w').write(json.dumps({'total_count': len(arts), 'artifacts': arts}))

    def run(self, step, action_dir, inputs=None, extra=None, cwd=None):
        """Run one composite (or workflow) step body as shipped. -> (rc, outputs, log, summary)."""
        import _deploy_steps as D
        bash, why = D.bash()
        if not bash:
            raise RuntimeError(why)
        env = {}
        for k, v in (step.get('env') or {}).items():
            env[k] = re.sub(r'\$\{\{\s*inputs\.([A-Za-z0-9_-]+)\s*\}\}',
                            lambda m: str((inputs or {}).get(m.group(1), '')), str(v))
        env.update({'GITHUB_ACTION_PATH': posix(os.path.join(self.kit, '.github', 'actions', action_dir)),
                    'RUNNER_TEMP': posix(self.temp), 'GITHUB_REPOSITORY': 'o/r', 'github_api_url': self.api_url(),
                    'GITHUB_RUN_ID': '4242', 'GITHUB_RUN_ATTEMPT': '1', 'github_sha': SHA,
                    'GITHUB_ACTOR': 'release-requester', 'GITHUB_TRIGGERING_ACTOR': 'release-requester'})
        # The kit root is found by `cd ... && pwd`, which Git Bash spells /tmp/...: a native python
        # needs its path conversion, so it is NOT switched off here (the deploy harness switches it
        # off for byte-exact values such as /health; nothing here passes one).
        # Names are written lower-case and upper-cased here: settings, not vocabulary.
        env.update(dict((k.upper(), v) for k, v in (extra or {}).items()))
        return run_body(bash, step['run'], env, cwd or self.dir, self.bin)


def run_body(bash, script, env_extra, cwd, path_prepend):
    """-> (rc, outputs, log, summary): one step body under bash, its outputs parsed."""
    out, summ, f = (os.path.join(cwd, n) for n in ('.gh_output', '.gh_summary', '.step.sh'))
    for p in (out, summ):
        io.open(p, 'w').close()
    io.open(f, 'w', encoding='utf-8', newline='\n').write(script)
    env = dict((k, v) for k, v in os.environ.items() if k not in ('MSYS_NO_PATHCONV', 'MSYS2_ENV_CONV_EXCL'))
    env.update(env_extra)
    env.update(GITHUB_OUTPUT=out, GITHUB_STEP_SUMMARY=summ,
               PATH=path_prepend + os.pathsep + os.environ.get('PATH', ''))
    p = subprocess.run([bash, f], capture_output=True, text=True, env=env, cwd=cwd, encoding='utf-8',
                       errors='replace', timeout=300)
    kv = {}
    for line in io.open(out, encoding='utf-8', errors='replace'):
        if '=' in line:
            k, v = line.rstrip('\n').split('=', 1)
            kv[k] = v
    text = io.open(summ, encoding='utf-8', errors='replace').read()
    for p_ in (out, summ, f):
        os.remove(p_)
    return p.returncode, kv, (p.stdout or '') + (p.stderr or ''), text


def composite_step():
    return by_id(yload(ACTION)['runs']['steps'], 'r')


# ----------------------------------------------------------------------------- R1
def r1_wiring():
    sec = yload(SEC)
    gate = sec['jobs']['security-gate']
    ids = [s.get('id') for s in gate['steps']]
    if check('reviewer' in ids, 'R1: the security gate has no reviewer step'):
        st = gate['steps'][ids.index('reviewer')]
        check(ids.index('record') < ids.index('reviewer') < ids.index('verdict'),
              'R1: the reviewer step is not between the run record and the verdict')
        check(str(st.get('if', '')).startswith('always()'), 'R1: the reviewer step is not if: always()')
        check(str(st.get('uses', '')).endswith('.github/actions/reviewer-signals'), 'R1: not the reviewer-signals composite')
        check((st.get('with') or {}).get('mode') == 'security', 'R1: the reviewer step is not mode security')
    on = sec.get('on', sec.get(True))
    wouts = on['workflow_call']['outputs']
    for o in ('capability_floor', 'token_preflight', 'leak_gate_alarm', 'policy_notices', 'no_kit_adapter',
              'kit_watermark', 'security_record'):
        check(o in (gate.get('outputs') or {}) and o in wouts, 'R1: the security workflow does not expose %s' % o)
    posture = by_id(gate['steps'], 'posture')
    check('p_weakening_check'.upper() in (posture.get('env') or {}), 'R1: the posture step does not read the weakening check')
    check(by_id(yload(POLICY_ACTION)['runs']['steps'], 'w') is not None, 'R1: resolve-policy does not check the weakening record')
    check(by_id(yload(DISCOVER)['runs']['steps'], 'rs') is not None, 'R1: discover does not name deploy coverage')
    plan = sec['jobs']['plan'].get('outputs') or {}
    check(all(k in plan for k in ('no_kit_adapter', 'deploy_targets', 'evidence_retention_days')),
          'R1: the plan job does not expose the deploy coverage and the retention')
    text = io.open(SEC, encoding='utf-8').read()
    check(text.count('retention-days: ${{ needs.plan.outputs.evidence_retention_days || 90 }}') == 2,
          'R1: the security report and the SBOM do not keep the configured retention')
    for name, path in DEPLOYS.items():
        doc = yload(path)
        job = doc['jobs']['deploy']
        sids = [s.get('id') or s.get('name') for s in job['steps']]
        names = [s.get('name') or '' for s in job['steps']]
        login = names.index('Azure login (OIDC)')
        if check('review_pre' in sids and 'review_post' in sids, 'R1 %s: no reviewer-signals steps' % name):
            check(sids.index('approval') < sids.index('review_pre') < login,
                  'R1 %s: review_pre is not after the approval and before login' % name)
            keep = names.index('Keep the run record (deploy evidence)')
            check(sids.index('promotion_record') < sids.index('review_post') < keep,
                  'R1 %s: review_post is not between the promotion record and the evidence' % name)
            check(str(job['steps'][sids.index('review_post')].get('if', '')) == 'always()',
                  'R1 %s: review_post is not if: always()' % name)
            check('if' not in job['steps'][sids.index('review_pre')],
                  'R1 %s: review_pre must run only on the success path before login' % name)
        check((doc.get('permissions') or {}).get('deployments') == 'write', 'R1 %s: no deployments: write' % name)
        won = doc.get('on', doc.get(True))['workflow_call']
        check('security_run_id' in won['inputs'], 'R1 %s: no security_run_id input' % name)
        for o in ('release_approval_by', 'verdict_provenance', 'tier_source', 'readiness_source', 'kit_watermark',
                  'tier_reality', 'release_record', 'lease_state', 'seam_state', 'review_signals'):
            check(o in won['outputs'], 'R1 %s: does not expose %s' % (name, o))
        t = io.open(path, encoding='utf-8').read()
        check('WEAKENING_NOT_APPROVED) ;;' in t,
              'R1 %s: the verdict step does not register WEAKENING_NOT_APPROVED' % name)
        check(t.count('retention-days: ${{ steps.review_pre.outputs.retention_days || 90 }}') == 2,
              'R1 %s: the evidence does not keep the configured retention' % name)
    check('site_kind' in yload(DEPLOYS['appservice']).get('on', {True: {}}).get('workflow_call', {}).get('inputs', {})
          or 'site_kind' in (yload(DEPLOYS['appservice']).get(True) or {}).get('workflow_call', {}).get('inputs', {}),
          'R1: the App Service reusable has no site_kind input (Functions)')


# ----------------------------------------------------------------------------- R2
def approved(**over):
    """A weakening record with every field the owner's rulings require; `over` takes one away or changes it."""
    r = {'weakening_reason': 'adoption baseline', 'weakening_authority': 'release-owner',
         'weakening_approver': 'security', 'weakening_exception_ref': 'EXC-1',
         'weakening_expires': (TODAY + datetime.timedelta(days=30)).isoformat()}
    r.update(over)
    return r


def r2_gate():
    step = by_id(yload(POLICY_ACTION)['runs']['steps'], 'w')
    if not check(step is not None, 'R2: resolve-policy has no weakening check'):
        return
    far = (TODAY + datetime.timedelta(days=200)).isoformat()
    cases = [
        ('allowed: every field, a listed approver', LISTS, approved(), 'WEAKENING_ATTRIBUTED', []),
        ('allowed: the approver named by list', LISTS, approved(weakening_approver='@deployment-approvers'), 'WEAKENING_ATTRIBUTED', []),
        ('attack: the approver is the requester', LISTS, approved(weakening_approver='release-requester'), 'WEAKENING_SELF_APPROVED', []),
        ('attack: the owner is the release author', LISTS, approved(weakening_authority='release-author'), 'WEAKENING_SELF_APPROVED', []),
        ('attack: an approver on no list', LISTS, approved(weakening_approver='shop-team'), 'WEAKENING_NOT_APPROVED', ['approver on a registered approver list']),
        ('missing: no list registered', {}, approved(), 'WEAKENING_NOT_APPROVED', ['approver on a registered approver list']),
        ('missing: no expiry', LISTS, approved(weakening_expires=''), 'WEAKENING_NOT_APPROVED', ['expiry']),
        ('missing: past the 90-day ceiling', LISTS, approved(weakening_expires=far), 'WEAKENING_NOT_APPROVED', ['expiry within the ceiling']),
        ('ceiling tightened to 20', dict(LISTS, numbers={'weakening_expiry_ceiling_days': 20}), approved(), 'WEAKENING_NOT_APPROVED', ['expiry within the ceiling']),
        ('missing: no evidence reference', LISTS, approved(weakening_exception_ref=''), 'WEAKENING_NOT_APPROVED', ['evidence reference']),
        ('missing: no approver', LISTS, approved(weakening_approver=''), 'WEAKENING_NOT_APPROVED', ['approver']),
        ('missing: the author unreadable', LISTS, approved(), 'WEAKENING_NOT_APPROVED', ['independence from the release author']),
    ]
    checks = {}
    for name, central, rec, want, want_missing in cases:
        w = World(central=central, author=None if 'unreadable' in name else 'release-author')
        try:
            rc, out, log, _ = w.run(step, 'resolve-policy', {'supplied-inputs': json.dumps(dict(rec, advisory_mode=True))})
            got = json.loads(out.get('weakening_check') or '{}')
            print('  R2  %-42s %s %s' % (name, got.get('state'), got.get('missing')))
            check(rc == 0 and got.get('state') == want, 'R2 %s: %r (rc %d), wanted %s\n%s' % (name, got.get('state'), rc, want, log[-400:]))
            for m in want_missing:
                check(m in (got.get('missing') or []), 'R2 %s: the missing field %r is not named: %r' % (name, m, got.get('missing')))
            checks[name] = out.get('weakening_check') or ''
        finally:
            w.close()
    # The posture step as shipped: self-approved blocks in every mode; not approved proceeds at crawl with
    # the control still counted weakened and the cause named; a check that did not answer is not approval.
    import prove_gate_routing as pgr
    CLEAN_GATE = pgr.CLEAN_GATE
    KIT_DEFAULT_POLICY = pgr.KIT_DEFAULT_POLICY
    pstep = pgr.posture_step()
    bash, _ = pgr.pbf.usable_bash()
    inputs = dict(pgr.DEFAULTS, advisory_mode='true', weakening_reason='adoption baseline',
                  weakening_authority='release-owner', weakening_approver='security', weakening_exception_ref='EXC-1',
                  weakening_expires=(TODAY + datetime.timedelta(days=30)).isoformat())
    for name, chk, want_route, want_auth, want_causes in (
            ('self-approved', checks.get('attack: the approver is the requester', ''), 'BLOCKED', 'WEAKENING_SELF_APPROVED', []),
            ('not approved: no expiry', checks.get('missing: no expiry', ''), 'PROCEED_WITH_ADVISORY', 'WEAKENING_NOT_APPROVED', ['WEAKENING_NOT_APPROVED']),
            ('missing: the check did not answer', '', 'PROCEED_WITH_ADVISORY', 'WEAKENING_NOT_APPROVED', ['WEAKENING_NOT_APPROVED']),
            ('approved', checks.get('allowed: every field, a listed approver', ''), 'PROCEED_WITH_ADVISORY', 'WEAKENING_ATTRIBUTED', [])):
        pol = dict(KIT_DEFAULT_POLICY, policy_weakening_check=chk, policy_notices='[]')
        env, unknown = pgr.resolve_env(pstep.get('env'), inputs, CLEAN_GATE, pol)
        rc, log, out = pgr.run(bash, pstep['run'], env)
        causes = (out.get('advisory_causes') or '').split(',')
        print('  R2  posture %-34s %s %s %s' % (name, out.get('routing_result'), out.get('weakening_attribution'), causes))
        check(rc == 0 and out.get('routing_result') == want_route, 'R2 posture %s: routing %r, wanted %s' % (name, out.get('routing_result'), want_route))
        check(out.get('weakening_attribution') == want_auth, 'R2 posture %s: attribution %r, wanted %s' % (name, out.get('weakening_attribution'), want_auth))
        check('security-gate' in (out.get('controls_reduced') or ''), 'R2 posture %s: the softened control is not counted weakened' % name)
        for c in want_causes:
            check(c in causes, 'R2 posture %s: cause %s missing from %r' % (name, c, causes))
        if not want_causes:
            check('WEAKENING_NOT_APPROVED' not in causes, 'R2 posture %s: carried WEAKENING_NOT_APPROVED' % name)
        check('"approver":"security"' in (out.get('weakening_record') or ''), 'R2 posture %s: the record omits the approver' % name)


# ----------------------------------------------------------------------------- R3, R4
GATE_RECORD = {'schema': 'kit-security-record/1', 'run': {'run_id': '4242', 'commit': SHA},
               'verdict': {'routing_result': 'PROCEED_WITH_ADVISORY', 'advisory_causes': ['FINDINGS_NOT_BLOCKED']}}


def pre(world, tier, record='same', extra=None, adapter='containerapp'):
    if record == 'same':
        world.record_run('4242', GATE_RECORD)
    elif record == 'none':
        world.record_run('4242', None)
    env = {'environment_tier': tier, 'routing_result': 'PROCEED_WITH_ADVISORY',
           'advisory_causes': 'FINDINGS_NOT_BLOCKED', 'deploy_environment': tier}
    env.update(extra or {})
    return world.run(composite_step(), 'reviewer-signals', {'mode': 'deploy-pre', 'adapter': adapter}, env)


def own(**over):
    return dict((k.lower(), v) for k, v in approved(**over).items())


def r3_r4_pre():
    day = TODAY.isoformat()
    manual = {'manual_review_by': 'appsec-reviewer', 'manual_review_ref': 'REV-9', 'manual_review_date': day}
    cases = [
        ('allowed: verdict from its gate, prod', 'prod', 'same', {}, 0, {'verdict_provenance': 'VERDICT_FROM_GATE'}),
        ('allowed: stricter than its gate', 'prod', 'same', {'routing_result': 'BLOCKED'}, 0, {'verdict_provenance': 'VERDICT_FROM_GATE'}),
        ('attack: typed verdict at prod', 'prod', 'none', {}, 1, {'verdict_provenance': 'TYPED_VERDICT'}),
        ('typed verdict at dev is warned', 'dev', 'none', {}, 0, {'verdict_provenance': 'TYPED_VERDICT'}),
        ('allowed: a manual AppSec review at prod', 'prod', 'none', manual, 0, {'verdict_provenance': 'MANUAL_REVIEW_VERDICT'}),
        ('attack: a manual review by the requester', 'prod', 'none', dict(manual, manual_review_by='release-requester'), 1, {'verdict_provenance': 'TYPED_VERDICT'}),
        ('attack: a manual review by the author', 'prod', 'none', dict(manual, manual_review_by='release-author'), 1, {'verdict_provenance': 'TYPED_VERDICT'}),
        ('attack: a manual reviewer not on the AppSec list', 'prod', 'none', dict(manual, manual_review_by='security'), 1, {'verdict_provenance': 'TYPED_VERDICT'}),
        ('missing: a manual review with no date', 'prod', 'none', dict(manual, manual_review_date=''), 1, {'verdict_provenance': 'TYPED_VERDICT'}),
        ('missing: a manual review with no reference', 'prod', 'none', dict(manual, manual_review_ref=''), 1, {'verdict_provenance': 'TYPED_VERDICT'}),
        ('a manual review never overrides its gate', 'dev', 'same', dict(manual, routing_result='PROCEED'), 1, {'verdict_provenance': 'VERDICT_CONTRADICTED'}),
        ('attack: more permissive, at dev', 'dev', 'same', {'routing_result': 'PROCEED'}, 1, {'verdict_provenance': 'VERDICT_CONTRADICTED'}),
        ('attack: a cause dropped', 'dev', 'same', {'advisory_causes': 'COVERAGE_PARTIAL'}, 1, {'verdict_provenance': 'VERDICT_CONTRADICTED'}),
        ('attack: another commit', 'dev', 'same', {'github_sha': '6' * 40}, 1, {'verdict_provenance': 'VERDICT_CONTRADICTED'}),
        ('missing: record unreadable at prod', 'prod', 'broken', {}, 1, {'verdict_provenance': 'VERDICT_RECORD_UNREADABLE'}),
        ('gate cause not approved at prod', 'prod', 'same', {'advisory_causes': 'FINDINGS_NOT_BLOCKED,WEAKENING_NOT_APPROVED'}, 1, {}),
        ('gate cause not approved at dev is recorded', 'dev', 'same', {'advisory_causes': 'FINDINGS_NOT_BLOCKED,WEAKENING_NOT_APPROVED'}, 0, {}),
        ('attack: own record self-approved, even at dev', 'dev', 'same', own(weakening_approver='release-requester'), 1,
         {'weakening_check': 'WEAKENING_SELF_APPROVED'}),
        ('attack: own record, the author as owner, at dev', 'dev', 'same', own(weakening_authority='release-author'), 1,
         {'weakening_check': 'WEAKENING_SELF_APPROVED'}),
        ('missing: own record without an expiry at prod', 'prod', 'same', own(weakening_expires=''), 1,
         {'weakening_check': 'WEAKENING_NOT_APPROVED'}),
        ('own record without an expiry at dev is recorded', 'dev', 'same', own(weakening_expires=''), 0,
         {'weakening_check': 'WEAKENING_NOT_APPROVED'}),
        ('allowed: own record approved at prod', 'prod', 'same', own(), 0, {'weakening_check': 'WEAKENING_ATTRIBUTED'}),
        ('attack: hosting kind aks', 'dev', 'same', {'kit_hosting_kind': 'aks'}, 1, {'hosting_kind': 'NO_KIT_ADAPTER:aks'}),
        ('allowed: hosting kind served', 'dev', 'same', {'kit_hosting_kind': 'container_app'}, 0, {'hosting_kind': 'container_app'}),
        ('tier vended by the landing zone', 'dev', 'same', {'kit_bound_environment_tier': 'dev', 'kit_handoff_issuer': 'landing-zone:lz-a'}, 0,
         {'tier_source': 'TIER_VENDED'}),
        ('tier set by the repository', 'dev', 'same', {'kit_bound_environment_tier': 'dev'}, 0, {'tier_source': 'TIER_SELF_DECLARED'}),
    ]
    for name, tier, record, extra, want_rc, want in cases:
        w = World(central=LISTS)
        try:
            rec = record
            if record == 'broken':
                runs = os.path.join(w.api, 'repos', 'o', 'r', 'actions', 'runs', '4242')
                os.makedirs(runs)
                io.open(os.path.join(runs, 'artifacts'), 'w').write('not json')
                rec = 'keep'
            rc, out, log, summ = pre(w, tier, rec, extra)
            print('  R3  %-50s rc=%d %s' % (name, rc, {k: out.get(k) for k in want} or out.get('verdict_provenance')))
            check(rc == want_rc, 'R3 %s: rc %d, wanted %d\n%s' % (name, rc, want_rc, log[-600:]))
            for k, v in want.items():
                check(out.get(k) == v, 'R3 %s: %s=%r, wanted %r' % (name, k, out.get(k), v))
            if want_rc == 1:
                check('Deploy refused before login (KDEC-036)' in log, 'R3 %s: refused without naming the reason' % name)
            check(os.path.exists(os.path.join(w.temp, 'deploy-evidence', 'review-pre.json')), 'R3 %s: no review-pre.json' % name)
        finally:
            w.close()
    # RECOVERY: the typed verdict refused at prod proceeds once the run's gate record exists.
    w = World(central=LISTS)
    try:
        rc1, out1, _, _ = pre(w, 'prod', 'none')
        rc2, out2, _, _ = pre(w, 'prod', 'same')
        print('  R3  recovery: typed (rc=%d) then a record (rc=%d %s)' % (rc1, rc2, out2.get('verdict_provenance')))
        check(rc1 == 1 and rc2 == 0 and out2.get('verdict_provenance') == 'VERDICT_FROM_GATE',
              'R3 recovery: a refused typed verdict did not proceed once the record existed')
    finally:
        w.close()
    # PROMOTION: the record of the promotion source run, for the source commit.
    w = World(central=LISTS)
    try:
        w.record_run('90', dict(GATE_RECORD, run={'run_id': '90', 'commit': '9' * 40}))
        w.commit('9' * 40, 'release-author')
        io.open(os.path.join(w.temp, 'deploy-evidence', 'promotion-gate.json'), 'w').write(
            json.dumps({'carried': {'provenance': {'source_sha': '9' * 40}}}))
        rc, out, log, _ = pre(w, 'prod', 'keep', {'promote_from_run_id': '90'})
        print('  R3  promotion source record: rc=%d %s' % (rc, out.get('verdict_provenance')))
        check(rc == 0 and out.get('verdict_provenance') == 'VERDICT_FROM_GATE',
              'R3 promotion: the promotion source run\'s record was not read\n%s' % log[-400:])
    finally:
        w.close()
    # R4: the watermark of the called kit copy.
    for name, wm, want in (('bound', {'source_commit': 'a' * 40, 'profile': 'neutral', 'source_dirty': False,
                                      'unresolved_conflicts': {}, 'exported_at_utc': '2026-11-01T00:00:00Z'}, 'WATERMARK_BOUND'),
                           ('dirty', {'source_commit': 'a' * 40, 'source_dirty': True}, 'WATERMARK_DIRTY'),
                           ('absent', None, 'WATERMARK_ABSENT')):
        w = World(central=LISTS, watermark=wm)
        try:
            rc, out, log, summ = pre(w, 'dev', 'same', {'github_action_repository': 'org/kit-host', 'github_action_ref': 'c' * 40})
            print('  R4  watermark %-8s %s %s' % (name, out.get('kit_watermark'), out.get('kit_source_commit')))
            check(out.get('kit_watermark') == want, 'R4 watermark %s: %r, wanted %s' % (name, out.get('kit_watermark'), want))
            if want == 'WATERMARK_BOUND':
                check(out.get('kit_source_commit') == 'a' * 40 and 'a' * 40 in summ and 'org/kit-host@' + 'c' * 40 in summ,
                      'R4: the source commit and the called kit ref are not in the summary')
        finally:
            w.close()


# ----------------------------------------------------------------------------- R9 readiness (owner ruling)
class ApiStub(http.server.BaseHTTPRequestHandler):
    routes, seen = {}, []

    def do_GET(self):
        ApiStub.seen.append(self.path)
        path = self.path.split('?', 1)[0]
        for prefix, body in ApiStub.routes.items():
            if path == prefix:
                self.send_response(200)
                self.end_headers()
                self.wfile.write(json.dumps(body).encode())
                return
        self.send_response(404)
        self.end_headers()
        self.wfile.write(b'{"message": "Not Found"}')

    def log_message(self, *a):
        pass


def attestation(**over):
    a = {'environment': 'prod', 'state': 'READY', 'issuer_role': 'appsec', 'issued_by': 'appsec-reviewer',
         'issued_on': TODAY.isoformat(), 'expires_on': (TODAY + datetime.timedelta(days=60)).isoformat(),
         'evidence_ref': 'SEC-READY-1', 'exceptions': []}
    a.update(over)
    return a


def routes(att=None, reviewer='appsec-reviewer', pr_author='platform-dev', merged=True):
    import base64
    r = {}
    if att is not None:
        r['/repos/o/r/contents/.kit/zone-readiness.json'] = {'content': base64.b64encode(json.dumps(att).encode()).decode()}
        r['/repos/o/r/commits'] = [{'sha': 'f' * 40}]
        r['/repos/o/r/commits/%s/pulls' % ('f' * 40)] = [{'number': 12, 'user': {'login': pr_author},
                                                          'merged_at': '2026-11-01T00:00:00Z' if merged else None}]
        r['/repos/o/r/pulls/12/reviews'] = [{'state': 'APPROVED', 'user': {'login': reviewer}}]
    return r


def r9_readiness():
    import release_gates as rg
    srv = http.server.HTTPServer(('127.0.0.1', 0), ApiStub)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    api = 'http://127.0.0.1:%d' % srv.server_address[1]
    cases = [
        ('the landing zone hand-off', 'prod', {'kit_handoff_issuer': 'landing-zone', 'kit_zone_readiness': 'READY'}, {},
         'READINESS_SOURCE_LZ_HANDOFF', '', True),
        ('allowed: an AppSec attestation, approved', 'prod', {}, routes(attestation()), 'READINESS_SOURCE_APPSEC_ATTESTATION', 'READY', True),
        ('allowed: READY_WITH_EXCEPTIONS with its list', 'prod', {}, routes(attestation(state='READY_WITH_EXCEPTIONS', exceptions=['WAF-1'])),
         'READINESS_SOURCE_APPSEC_ATTESTATION', 'READY_WITH_EXCEPTIONS', True),
        ('an attested NOT_READY refuses', 'prod', {}, routes(attestation(state='NOT_READY')), 'READINESS_SOURCE_APPSEC_ATTESTATION', 'NOT_READY', False),
        ('attack: approved by its own author', 'prod', {}, routes(attestation(), reviewer='platform-dev'), 'READINESS_ATTESTATION_REFUSED', '', False),
        ('attack: approved by someone not on the AppSec list', 'prod', {}, routes(attestation(), reviewer='security'), 'READINESS_ATTESTATION_REFUSED', '', False),
        ('attack: pushed, not merged through a pull request', 'prod', {}, routes(attestation(), merged=False), 'READINESS_ATTESTATION_REFUSED', '', False),
        ('missing: expired', 'prod', {}, routes(attestation(expires_on='2026-01-01')), 'READINESS_ATTESTATION_REFUSED', '', False),
        ('missing: another environment', 'prod', {}, routes(attestation(environment='uat')), 'READINESS_ATTESTATION_REFUSED', '', False),
        ('missing: no evidence reference', 'prod', {}, routes(attestation(evidence_ref='')), 'READINESS_ATTESTATION_REFUSED', '', False),
        ('attack: the repository set it for itself', 'prod', {'kit_zone_readiness': 'READY'}, {}, 'READINESS_SOURCE_SELF_SET_REFUSED', '', False),
        ('a labelled test fixture', 'prod', {'kit_zone_readiness': 'READY', 'kit_zone_readiness_test_fixture': 'true'}, {},
         'READINESS_SOURCE_TEST_FIXTURE', '', True),
        ('not set', 'prod', {}, {}, 'READINESS_NOT_SET', '', False),
        ('below uat: self-set is recorded, nothing read', 'dev', {'kit_zone_readiness': 'READY'}, {}, 'READINESS_SOURCE_SELF_SET_REFUSED', '', True),
    ]
    try:
        for name, tier, extra, rt, want_src, want_att, permits in cases:
            ApiStub.routes, ApiStub.seen = rt, []
            w = World(central=dict(LISTS))
            try:
                env = {'environment_tier': tier, 'deploy_environment': 'prod', 'default_branch': 'main', 'github_api_url': api}
                env.update(extra)
                rc, out, log, summ = w.run(composite_step(), 'reviewer-signals', {'mode': 'readiness', 'adapter': 'containerapp'}, env)
                print('  R9  %-50s %s %s' % (name, out.get('readiness_source'), out.get('attested_readiness')))
                check(rc == 0, 'R9 %s: the readiness step refused (rc %d); the zone step decides\n%s' % (name, rc, log[-400:]))
                check(out.get('readiness_source') == want_src and out.get('attested_readiness', '') == want_att,
                      'R9 %s: %r/%r, wanted %s/%s\n%s' % (name, out.get('readiness_source'), out.get('attested_readiness'), want_src, want_att, summ[-400:]))
                if tier == 'dev':
                    check(not ApiStub.seen, 'R9 %s: the API was read below uat (%r)' % (name, ApiStub.seen))
                # The zone step decides on what the readiness step said.
                zenv = dict(os.environ)
                for k in [n.upper() for n in ('kit_handoff_issuer', 'kit_zone_readiness', 'kit_zone_readiness_test_fixture', 'readiness_source', 'attested_readiness')]:
                    zenv.pop(k, None)
                zenv.update(dict((k.upper(), v) for k, v in extra.items()))
                zenv.update(dict((k.upper(), v) for k, v in {'environment_tier': tier, 'readiness_source': out.get('readiness_source', '')}.items()))
                zenv.update(KIT_RELEASE_BLOCK='none',
                            ATTESTED_READINESS=out.get('attested_readiness', ''), GITHUB_OUTPUT=os.path.join(w.dir, 'zo'),
                            GITHUB_STEP_SUMMARY=os.path.join(w.dir, 'zs'))
                old = dict(os.environ)
                os.environ.clear()
                os.environ.update(zenv)
                try:
                    zrc = rg.main(['zone'])
                finally:
                    os.environ.clear()
                    os.environ.update(old)
                zout = io.open(os.path.join(w.dir, 'zo'), encoding='utf-8').read()
                check((zrc == 0) == permits, 'R9 %s: the zone step %s (rc %d), wanted %s\n%s' % (
                    name, 'permitted' if zrc == 0 else 'refused', zrc, 'permit' if permits else 'refuse', zout))
                check('readiness_source=%s' % want_src in zout, 'R9 %s: the zone step did not record the source' % name)
            finally:
                w.close()
        # Derived when the readiness step did not answer: the marker, or self-set (refused at prod).
        for name, extra, permits in (('derived: the marker', {'KIT_HANDOFF_ISSUER': 'landing-zone', 'KIT_ZONE_READINESS': 'READY'}, True),
                                     ('derived: self-set at prod', {'KIT_ZONE_READINESS': 'READY'}, False)):
            old = dict(os.environ)
            tmp = tempfile.mkdtemp()
            try:
                for k in [n.upper() for n in ('kit_handoff_issuer', 'kit_zone_readiness', 'kit_zone_readiness_test_fixture', 'readiness_source', 'attested_readiness')]:
                    os.environ.pop(k, None)
                os.environ.update(extra, KIT_RELEASE_BLOCK='none', **{'environment_tier'.upper(): 'prod'})
                os.environ.update(
                                  GITHUB_OUTPUT=os.path.join(tmp, 'o'), GITHUB_STEP_SUMMARY=os.path.join(tmp, 's'))
                zrc = rg.main(['zone'])
            finally:
                os.environ.clear()
                os.environ.update(old)
                shutil.rmtree(tmp, ignore_errors=True)
            print('  R9  %-50s rc=%d' % (name, zrc))
            check((zrc == 0) == permits, 'R9 %s: rc %d' % (name, zrc))
    finally:
        srv.shutdown()
    # The shipped template, CODEOWNERS snippet and guide exist, and the template is a valid attestation.
    tpl = os.path.join(ROOT, 'templates', 'zone-readiness.example.json')
    if check(os.path.exists(tpl), 'R9: no attestation template'):
        import reviewer_signals as rs
        doc = json.load(io.open(tpl, encoding='utf-8'))
        check(set(doc) >= {'environment', 'state', 'issuer_role', 'issued_by', 'issued_on', 'expires_on', 'evidence_ref', 'exceptions'},
              'R9: the template lacks a field')
    check(os.path.exists(os.path.join(ROOT, 'developer-safety', 'codeowners', 'CODEOWNERS.zone-readiness')),
          'R9: no CODEOWNERS snippet')
    check(os.path.exists(os.path.join(ROOT, 'docs', 'adoption', 'ZONE_READINESS_ATTESTATION.md')), 'R9: no guide')
    for name, path in DEPLOYS.items():
        doc = yload(path)
        sids = [s.get('id') for s in doc['jobs']['deploy']['steps']]
        check('readiness' in sids and sids.index('bind') < sids.index('readiness') < sids.index('zone'),
              'R9 %s: the readiness step is not between the bind and the zone step' % name)
        check((doc.get('permissions') or {}).get('pull-requests') == 'read', 'R9 %s: no pull-requests: read' % name)


# ----------------------------------------------------------------------------- R5
class Stub(http.server.BaseHTTPRequestHandler):
    calls, answer = [], 201

    def do_POST(self):
        body = self.rfile.read(int(self.headers.get('Content-Length') or 0))
        Stub.calls.append((self.path, json.loads(body.decode('utf-8')), self.headers.get('Authorization')))
        code = Stub.answer
        self.send_response(code)
        self.end_headers()
        self.wfile.write(json.dumps({'id': 77} if code < 300 else {'message': 'Resource not accessible'}).encode())

    def log_message(self, *a):
        pass


def r5_post():
    srv = http.server.HTTPServer(('127.0.0.1', 0), Stub)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    api = 'http://127.0.0.1:%d' % srv.server_address[1]
    try:
        for name, lease, answer, snap, tier, want_rc, want in (
                ('allowed: lease off, the record is a deployment', '', 201, {}, 'prod', 0,
                 {'release_record': 'RELEASE_RECORD_KEPT_DEPLOYMENT', 'release_record_ref': '77'}),
                ('refused by the API: not kept, the step fails', '', 403, {}, 'prod', 1,
                 {'release_record': 'RELEASE_RECORD_NOT_KEPT'}),
                ('lease on: the lease store keeps it', 'leasestore', 201, {}, 'prod', 0,
                 {'release_record': 'RELEASE_RECORD_KEPT'}),
                ('dev with a custom domain: warned', '', 201, {'reality': {'custom_domains': ['shop.example'], 'public_ingress': True}},
                 'dev', 0, {'tier_reality': 'TIER_MISMATCH_SUSPECTED'}),
                ('prod with a custom domain: consistent', '', 201, {'reality': {'custom_domains': ['shop.example']}},
                 'prod', 0, {'tier_reality': 'TIER_CONSISTENT'})):
            Stub.calls, Stub.answer = [], answer
            w = World(central=LISTS)
            try:
                io.open(os.path.join(w.temp, 'deploy-evidence', 'snapshot.json'), 'w').write(json.dumps(snap))
                io.open(os.path.join(w.temp, 'deploy-evidence', 'review-pre.json'), 'w').write(
                    json.dumps({'verdict_provenance': {'state': 'VERDICT_FROM_GATE'}, 'tier_source': 'TIER_VENDED'}))
                rc, out, log, summ = w.run(composite_step(), 'reviewer-signals', {
                    'mode': 'deploy-post', 'adapter': 'containerapp', 'token': 'ghs_placeholder',
                    'routing-result': 'PROCEED', 'deployment-outcome': 'DEPLOY_HEALTHY',
                    'release-approval': 'RELEASE_APPROVAL_VERIFIED', 'release-approval-by': 'independent-reviewer'},
                    {'github_api_url': api, 'environment_tier': tier, 'deploy_environment': tier,
                     'kit_target_lease_account': lease, 'image_digest': 'sha256:' + 'b' * 64})
                print('  R5  %-46s rc=%d %s posts=%d' % (name, rc, {k: out.get(k) for k in want}, len(Stub.calls)))
                check(rc == want_rc, 'R5 %s: rc %d, wanted %d\n%s' % (name, rc, want_rc, log[-500:]))
                for k, v in want.items():
                    check(out.get(k) == v, 'R5 %s: %s=%r, wanted %r' % (name, k, out.get(k), v))
                rs = os.path.join(w.temp, 'deploy-evidence', 'review-signals.json')
                check(os.path.exists(rs), 'R5 %s: no review-signals.json in the deploy evidence' % name)
                if lease:
                    check(not Stub.calls, 'R5 %s: a deployment was written with the lease on' % name)
                elif answer == 201:
                    check(len(Stub.calls) == 2 and Stub.calls[0][0] == '/repos/o/r/deployments'
                          and Stub.calls[1][0] == '/repos/o/r/deployments/77/statuses',
                          'R5 %s: not a deployment and its status: %r' % (name, [c[0] for c in Stub.calls]))
                    dep = Stub.calls[0][1]
                    check(dep.get('task') == 'kit-release-record' and dep.get('required_contexts') == []
                          and (dep.get('payload') or {}).get('routing_result') == 'PROCEED'
                          and (dep.get('payload') or {}).get('verdict_provenance') == 'VERDICT_FROM_GATE'
                          and (dep.get('payload') or {}).get('digest') == 'sha256:' + 'b' * 64,
                          'R5 %s: the deployment does not carry the record: %r' % (name, dep))
                    check(Stub.calls[1][1].get('state') == 'success', 'R5 %s: the status is not success' % name)
            finally:
                w.close()
    finally:
        srv.shutdown()


# ----------------------------------------------------------------------------- R6
def r6_security():
    for name, days, want_days, want_state in (('unset', '', 90, 'EVIDENCE_RETENTION_DEFAULT'),
                                              ('below the floor', '30', 90, 'EVIDENCE_RETENTION_RAISED_TO_FLOOR'),
                                              ('set', '180', 180, 'EVIDENCE_RETENTION_SET'),
                                              ('past GitHub\'s cap', '900', 400, 'EVIDENCE_RETENTION_CAPPED')):
        w = World(central=LISTS, watermark={'source_commit': 'a' * 40, 'profile': 'consumer', 'source_dirty': False})
        try:
            rc, out, log, summ = w.run(composite_step(), 'reviewer-signals', {
                'mode': 'security', 'routing-result': 'PROCEED_WITH_ADVISORY', 'advisory-causes': 'WEAKENING_NOT_APPROVED',
                'weakening-check': json.dumps({'state': 'WEAKENING_NOT_APPROVED', 'missing': ['expiry'], 'why': ['no expiry']}),
                'floor-state': 'HELD', 'token-preflight': 'TOKEN_ACCEPTED', 'leak-gates': '{"push_ruleset":"OFF"}',
                'leak-gate-alarm': 'NO_LEAK_GATE_SHOWN', 'policy-notices': '[{"code":"ORG_UNMAPPED_RAN_AT_ENTERPRISE_FLOOR"}]',
                'no-kit-adapter': 'NO_KIT_ADAPTER:aks', 'retention-days': days})
            path = os.path.join(w.temp, 'kit-security-record', 'kit-security-record.json')
            rec = json.load(io.open(path)) if os.path.exists(path) else {}
            print('  R6  retention %-18s %s %s' % (name, out.get('retention_days'), (rec.get('evidence') or {}).get('retention')))
            check(rc == 0 and rec.get('schema') == 'kit-security-record/1', 'R6 %s: no security record\n%s' % (name, log[-400:]))
            check(str(out.get('retention_days')) == str(want_days) and (rec.get('evidence') or {}).get('retention') == want_state,
                  'R6 %s: retention %r/%r, wanted %d/%s' % (name, out.get('retention_days'), (rec.get('evidence') or {}).get('retention'), want_days, want_state))
            check(rec.get('token_preflight') == 'TOKEN_ACCEPTED' and rec.get('leak_gate_alarm') == 'NO_LEAK_GATE_SHOWN'
                  and (rec.get('capability_floor') or {}).get('state') == 'HELD'
                  and (rec.get('policy') or {}).get('notices') and (rec.get('kit') or {}).get('source_commit') == 'a' * 40
                  and (rec.get('deploy_coverage') or {}).get('no_kit_adapter') == ['NO_KIT_ADAPTER:aks']
                  and (rec.get('verdict') or {}).get('advisory_causes') == ['WEAKENING_NOT_APPROVED'],
                  'R6 %s: the record does not carry every signal: %r' % (name, rec))
            check(out.get('record_artifact') == 'kit-security-record-1', 'R6 %s: no record artifact name' % name)
        finally:
            w.close()
    w = World(central=LISTS)
    try:   # an unset floor state is never HELD
        rc, out, log, summ = w.run(composite_step(), 'reviewer-signals', {'mode': 'security'})
        rec = json.load(io.open(os.path.join(w.temp, 'kit-security-record', 'kit-security-record.json')))
        check(rec['capability_floor']['state'] == 'BREACHED', 'R6: an unanswered floor read as %r' % rec['capability_floor']['state'])
    finally:
        w.close()


# ----------------------------------------------------------------------------- R7
def r7_discover():
    step = by_id(yload(DISCOVER)['runs']['steps'], 'rs')
    if not check(step is not None, 'R7: discover has no deploy-coverage step'):
        return
    trees = [
        ('helm chart', {'deploy/chart/Chart.yaml': 'name: x\n'}, 'NO_KIT_ADAPTER:aks'),
        ('kubernetes manifest', {'k8s/web.yaml': 'apiVersion: apps/v1\nkind: Deployment\nmetadata: {name: w}\n'}, 'NO_KIT_ADAPTER:aks'),
        ('workflow deploying to AKS', {'.github/workflows/cd.yml': 'steps:\n  - uses: azure/k8s-deploy@v5\n'}, 'NO_KIT_ADAPTER:aks'),
        ('VM infrastructure', {'infra/vm.tf': 'resource "azurerm_linux_virtual_machine" "a" {}\n'}, 'NO_KIT_ADAPTER:vm'),
        ('code-packaged Functions', {'func/host.json': '{"version": "2.0"}'}, 'NO_KIT_ADAPTER:function_app_code'),
        ('containerised Functions', {'func/host.json': '{"version": "2.0"}', 'func/Dockerfile': 'FROM x\n'}, ''),
        ('an ordinary app', {'app.py': 'print(1)\n', 'Dockerfile': 'FROM x\n'}, ''),
    ]
    for name, files, want in trees:
        w = World()
        try:
            repo = os.path.join(w.dir, 'repo')
            for rel, text in files.items():
                p = os.path.join(repo, *rel.split('/'))
                os.makedirs(os.path.dirname(p), exist_ok=True)
                io.open(p, 'w', newline='\n').write(text)
            os.makedirs(repo, exist_ok=True)
            rc, out, log, summ = w.run(step, 'discover', {'evidence-retention-days': ''},
                                       {'github_workspace': posix(repo)}, cwd=repo)
            print('  R7  %-26s %r' % (name, out.get('no_kit_adapter')))
            check(rc == 0 and out.get('no_kit_adapter') == want, 'R7 %s: %r, wanted %r\n%s' % (name, out.get('no_kit_adapter'), want, log[-400:]))
            check(out.get('evidence_retention_days') == '90', 'R7 %s: retention %r' % (name, out.get('evidence_retention_days')))
        finally:
            w.close()


# ----------------------------------------------------------------------------- R8
def r8_functions():
    import _workflow_runner as W

    def inputs(**over):
        i = dict(github_environment='env', routing_result='PROCEED', environment_tier='dev', resource_group='rg-a',
                 webapp_name='web', acr_login_server=W.REG, image_repository=W.REPO, image_digest=W.NEW,
                 cloud='commercial', slot='staging', swap_on_healthy=True, health_path='/health', health_retries=2,
                 health_interval_seconds=0, version_metadata='', rollback_on_failure=True)
        i.update(over)
        return i
    for name, kind, over, healthy, refused_why in (
            ('allowed: containerised function app', 'functionapp,linux,container', {'site_kind': 'functionapp'}, True, ''),
            ('attack: code-packaged function app', 'functionapp,linux', {'site_kind': 'functionapp'}, False, 'NO_KIT_ADAPTER:function_app_code'),
            ('attack: a web app named as a function app', 'app,linux,container', {'site_kind': 'functionapp'}, False, 'not a function app'),
            ('attack: a function app named as a web app', 'functionapp,linux,container', {}, False, 'pass site_kind functionapp'),
            ('allowed: an ordinary web app, unchanged', 'app,linux,container', {}, True, '')):
        st = W.appservice_state()
        st['webapp']['kind'] = kind
        res, final, calls = W.run_world(W.D.APPSERVICE, inputs(**over), st)
        outcome = (res['evidence'].get('outcome.json') or {}).get('deployment_outcome', '')
        mutated = bool(final.get('mutated'))
        groups = sorted(set(c[1] for c in calls if c[0] == 'az' and c[1] in ('webapp', 'functionapp')))
        print('  R8  %-42s outcome=%s mutated=%s az groups=%s' % (name, outcome or '-', mutated, groups))
        if healthy:
            check(outcome == 'DEPLOY_HEALTHY', 'R8 %s: %r, wanted DEPLOY_HEALTHY\n%s' % (name, outcome, res['log'][-800:]))
            if over.get('site_kind') == 'functionapp':
                check('functionapp' in final.get('groups', []) and
                      any(c[:5] == ['az', 'functionapp', 'config', 'container', 'set'] and '--image' in c for c in calls),
                      'R8 %s: the image was not set through az functionapp --image' % name)
                check(not any(c[1] == 'webapp' and 'connection-string' not in c for c in calls if c[0] == 'az'),
                      'R8 %s: an az webapp call other than connection strings reached a function app' % name)
        else:
            check(not mutated and outcome != 'DEPLOY_HEALTHY', 'R8 %s: changed the target (outcome %r)' % (name, outcome))
            check(refused_why in res['log'], 'R8 %s: refused without naming %r' % (name, refused_why))


def main():
    try:
        import yaml  # noqa: F401
        import _deploy_steps as D
    except ImportError as exc:
        print('UNKNOWN: %s' % exc)
        return 2
    if not D.bash()[0]:
        print('UNKNOWN: no usable bash')
        return 2
    for part in (r1_wiring, r2_gate, r3_r4_pre, r5_post, r6_security, r7_discover, r8_functions, r9_readiness):
        try:
            part()
        except Exception as exc:  # noqa: BLE001 -- a claim that could not run is a failure here, named
            FAILS.append('%s could not run: %s: %s' % (part.__name__, type(exc).__name__, exc))
    if FAILS:
        for f in FAILS:
            print('FAIL: %s' % f)
        print('%d failure(s).' % len(FAILS))
        return 1
    print('PASS: the reviewer signals are recorded and refused where the policy says (KDEC-036).')
    return 0


if __name__ == '__main__':
    sys.exit(main())

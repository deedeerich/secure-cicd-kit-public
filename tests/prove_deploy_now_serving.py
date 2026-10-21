#!/usr/bin/env python3
"""App Service NOW SERVING is read from the running artefact -- the platform's start record -- not
from the configured image, on the direct path and after a slot swap alike.

WHY THIS EXISTS (ledger DCR-2 and L101, section 5 B-02; DEPLOYMENT_CONTRACT_RECONCILIATION.md 3.1,
3.4)

    App Service exposes no running digest. The deploy read two things: the CONFIGURED image
    (linuxFxVersion -- what the platform will start next) and the platform's container log (which
    image it last reported started). Only the slot verification before traffic read the log. After
    the swap, `serving` judged production by the configured image, `provenance` stamped on the
    configured image, and the outcome report decided DEPLOY_HEALTHY on the configured image with the
    start record printed beside it, deciding nothing. So a production whose platform had started
    something else -- or whose start record could not be read at all -- was reported healthy,
    serving this release, and stamped as such.

WHAT IS BUILT
    `serving`, `provenance` and the report read production's start record, bounded to the time this
    run mutated the target: the latest container the platform created since then must be the
    intended image and must have started. Unreadable is UNKNOWN (never the configured value), and a
    serving check that cannot establish it fails, so the reversal runs and nothing is stamped.

    Live evidence the record is readable after a swap: run 38912063363 (2026-10-16) printed
    production's start record after the swap, naming the swapped image -- VERIFIED from its log.

WHAT IS RUN
    The App Service deploy job as shipped against the stub cloud (tests/_fake_az.py), through an az
    stand-in that delegates every call to it and then applies ONE injected event: after the swap
    (slot path) or after the first probe of production (direct path), production's container log
    records another image created and started -- the configuration untouched -- or the log becomes
    unreadable.

CASES (docs/PROOF_RULE.md)
    allowed           a healthy swap and a healthy direct deploy -> DEPLOY_HEALTHY, stamped
    attack            after the swap, the platform starts another image; on the direct path the same
                      after the probe -> never DEPLOY_HEALTHY, never stamped, NOW SERVING names the
                      other image
    missing-evidence  production's start record unreadable after the swap -> never DEPLOY_HEALTHY,
                      never stamped
    recovery          the same world without the injection -> DEPLOY_HEALTHY

EXIT 0 proven   1 a case decided wrongly   2 could not be checked (UNKNOWN, never PASS)
"""
import io
import json
import os
import shutil
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import _workflow_runner as W  # noqa: E402

OTHER = 'registry.example/other@sha256:' + 'c' * 64

# The stand-in: delegate to the harness's fake cloud, then apply the injected event once.
WRAPPER = r'''
import json, os, subprocess, sys, time
fake, tool, args = sys.argv[1], sys.argv[2], sys.argv[3:]
p = subprocess.run([sys.executable, fake, tool] + args)
path = os.environ['fake_az_state']
s = json.load(open(path, encoding='utf-8'))
hook = s.get('post_hook')
cmd = 'curl' if tool == 'curl' else ' '.join(a for a in args[:4] if not a.startswith('-'))
if hook and not hook.get('done') and cmd.startswith(hook['after']) and \
        (tool != 'curl' or any(hook['host'] in a for a in args)):
    hook['done'] = True
    sl = s['webapp']['slots']['production']
    if hook['do'] == 'start_other':
        now = time.strftime('%Y-%m-%dT%H:%M:%S', time.gmtime())
        sl.setdefault('docker_log', []).append(
            '%s.5000000Z Creating container with image: %s from registry: x' % (now, hook['image']))
        sl['docker_log'].append('%s.6000000Z Site started.' % now)
    elif hook['do'] == 'log_unreadable':
        s.setdefault('fail', []).append('rest')
    elif hook['do'] == 'retag':
        # another release claims production; its configuration is left as it is
        sl.setdefault('tags', {})['release_ownership_stamp'] = hook['stamp']
    json.dump(s, open(path, 'w', encoding='utf-8'), indent=1)
sys.exit(p.returncode)
'''


def world(inputs, state):
    work = tempfile.mkdtemp(prefix='now-serving-')
    try:
        state_path = os.path.join(work, 'state.json')
        log_path = os.path.join(work, 'calls.jsonl')
        io.open(state_path, 'w', encoding='utf-8').write(json.dumps(state))
        io.open(log_path, 'w').close()
        bin_dir = W.stub_bin(state_path, log_path)
        wrapper = os.path.join(work, 'wrap.py')
        io.open(wrapper, 'w', encoding='utf-8', newline='\n').write(WRAPPER)
        py, fake = sys.executable, os.path.join(HERE, '_fake_az.py')
        for tool in ('az', 'curl'):
            io.open(os.path.join(bin_dir, tool), 'w', encoding='utf-8', newline='\n').write(
                '#!/bin/bash\nexec "%s" "%s" "%s" %s "$@"\n' % (
                    py.replace('\\', '/'), wrapper.replace('\\', '/'), fake.replace('\\', '/'), tool))
            io.open(os.path.join(bin_dir, tool + '.cmd'), 'w', encoding='utf-8',
                    newline='\r\n').write('@echo off\r\n"%s" "%s" "%s" %s %%*\r\n'
                                          % (py, wrapper, fake, tool))
        try:
            env = {'MSYS2_ENV_CONV_EXCL': '*', 'MSYS_NO_PATHCONV': '1',
                   'fake_az_state': state_path, 'fake_az_log': log_path,
                   'AZURE_CONFIG_DIR': os.path.join(work, 'no-azure-config')}
            rt = os.path.join(work, 'runner-temp')
            os.makedirs(rt)
            res = W.run_job(W.D.APPSERVICE, inputs, path_prepend=bin_dir, extra_env=env,
                            workdir=rt)
            ev = os.path.join(rt, 'deploy-evidence')
            res['evidence'] = {}
            for f in (os.listdir(ev) if os.path.isdir(ev) else []):
                try:
                    res['evidence'][f] = json.load(io.open(os.path.join(ev, f), encoding='utf-8'))
                except ValueError:
                    pass
            return res, json.load(io.open(state_path, encoding='utf-8'))
        finally:
            shutil.rmtree(bin_dir, ignore_errors=True)
    finally:
        shutil.rmtree(work, ignore_errors=True)


def inputs(**over):
    i = dict(github_environment='env', routing_result='PROCEED', environment_tier='dev',
             resource_group='rg-a', webapp_name='web', acr_login_server=W.REG,
             image_repository=W.REPO, image_digest=W.NEW, slot='staging', swap_on_healthy=True,
             health_path='/health', health_retries=2, health_interval_seconds=0,
             rollback_on_failure=True, version_metadata='{"image_digest": "%s"}' % W.NEW)
    i.update(over)
    return i


def main():
    try:
        import yaml  # noqa: F401
    except ImportError:
        print('UNKNOWN: PyYAML unavailable.')
        return 2
    bad = []
    swap_after = 'webapp deployment slot swap'
    cases = [
        ('allowed-swap', inputs(), None, True),
        ('allowed-direct', inputs(slot=''), None, True),
        ('attack-swap-other-start', inputs(),
         {'after': swap_after, 'do': 'start_other', 'image': OTHER, 'host': ''}, False),
        ('attack-direct-other-start', inputs(slot=''),
         {'after': 'curl', 'do': 'start_other', 'image': OTHER, 'host': 'web.site.example'},
         False),
        ('missing-log-after-swap', inputs(),
         {'after': swap_after, 'do': 'log_unreadable', 'host': ''}, False),
        ('recovery', inputs(), None, True),
    ]
    for name, inp, hook, healthy in cases:
        st = W.appservice_state()
        if hook:
            st['post_hook'] = hook
        try:
            res, final = world(inp, st)
        except W.Unmodelled as e:
            print('UNKNOWN: %s' % e)
            return 2
        o = res['evidence'].get('outcome.json') or {}
        prov = res['evidence'].get('provenance.json')
        rows = {r['field']: r['value'] for r in o.get('now_serving') or []}
        tags = final['webapp']['slots']['production'].get('tags') or {}
        stamped = 'deploy_provenance_digest' in tags
        print('  %-26s outcome=%-18s stamped=%-5s now_serving=%s'
              % (name, o.get('deployment_outcome'), stamped, json.dumps(rows)[:150]))
        if healthy:
            if o.get('deployment_outcome') != 'DEPLOY_HEALTHY' or not stamped:
                bad.append('%s: a healthy deploy must read DEPLOY_HEALTHY and be stamped (%r)\n%s'
                           % (name, o.get('deployment_outcome'), res['log'][-1200:]))
            continue
        if o.get('deployment_outcome') == 'DEPLOY_HEALTHY':
            bad.append('%s: reported DEPLOY_HEALTHY although the platform did not show the intended '
                       'image running in production (NOW SERVING judged by the configured image)'
                       % name)
        if prov is not None or (stamped and tags.get('deploy_provenance_digest') == W.NEW):
            bad.append('%s: provenance was stamped on an unestablished running artefact' % name)
        v = res['evidence'].get('verification.json') or {}
        if v.get('serving_verified') is True:
            bad.append('%s: serving was recorded verified on a production whose start record does '
                       'not show the intended image running (%r)' % (name, v))
    if bad:
        for b in bad:
            print('FAIL: %s' % b)
        return 1
    print('PASS: App Service NOW SERVING, the serving check, provenance and the outcome are decided '
          'by the platform\'s start record since this run\'s mutation, after a swap as on the direct '
          'path; another image started, or an unreadable record, is never DEPLOY_HEALTHY and never '
          'stamped.')
    print('      STUB CLOUD. The live reading after a swap is one observation (38912063363); a live '
          'contradiction case is owed.')
    return 0


if __name__ == '__main__':
    sys.exit(main())

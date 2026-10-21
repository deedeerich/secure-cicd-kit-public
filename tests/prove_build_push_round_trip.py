#!/usr/bin/env python3
"""The build job builds, SBOMs, pushes and asserts identity against a REAL registry; the stamp
carries the digest it actually pushed.

WHY THIS EXISTS (validation deferrals `image-build`, `image-push`, `version-metadata-wired`)

    Every step of reusable-build-docker.yml's build job had been run as shipped with `docker`
    SHIMMED (tests/prove_push_capability.py, tests/prove_build_routing.py): the registry's answer
    was the fixture. The deferrals asked for what a shim cannot give -- "build emits a digest and an
    SBOM containing known fixture components", "pushed image is retrievable by the digest the
    build emitted", "the rendered stamp carries the digest that workflow actually pushed" -- and
    they were held for want of a registry. A registry is a container (`registry:2`, the reference
    implementation of the OCI distribution API an ACR speaks). This proof runs one.

WHAT IS RUN
    In a throwaway workspace, against a local `registry:2` started on a free loopback port:
      build            `docker/build-push-action` cannot be extracted; its `with:` block is read
                       as shipped and translated flag for flag (context, file, load, tags) into one
                       `docker buildx build`, the way tests/prove_image_scan_enforces.py translates
                       trivy-action. An input this file cannot translate FAILS the proof.
      built, sbom, build_inputs, push_capability, push, assert_identity, provenance, posture
                       the job's own steps, extracted as shipped, under GitHub's shell, with the
                       real docker, buildx, jq and syft. Nothing is shimmed. On a non-Linux host
                       the sbom step's ACQUISITION lines (a linux tarball, `sudo mv`) are dropped
                       and the same pinned syft version must already be on PATH; on Linux the step
                       runs whole. The Trivy gate (a `uses:` step proven by
                       tests/prove_image_scan_enforces.py) is not run; posture reads it as skipped.
      the handoff      the job's `outputs:` map, the workflow's `outputs:` map and the shipped
                       caller template's `with:` map are read from the YAML and substituted the way
                       GitHub substitutes them, and the render-version-metadata step runs as
                       shipped on what arrives.
    The image is `FROM scratch` plus one file naming a fixture component, so no base image is
    pulled and the SBOM has exactly one thing to find.

CASES (docs/PROOF_RULE.md)
    allowed           config digest emitted; SBOM names kit-fixture-component 1.2.3 and sbom_sha256
                      is its hash; push_capability EMPTY/NO_PRIOR_STATE; the push's digest is served
                      by the registry at /v2/<repo>/manifests/<digest> with a matching
                      Docker-Content-Digest; assert_identity PASSES; class REGISTRY_IDENTITY_PROVEN;
                      posture PROCEED; the stamp's image_digest IS that digest, with the scanned
                      config and the build inputs
    attack            assert_identity handed the config digest of a DIFFERENT image (scanned bytes
                      are not the pushed bytes) -> MISMATCH, class IDENTITY_UNVERIFIED, posture
                      EVIDENCE_UNTRUSTED, and the stamp carries IDENTITY_UNVERIFIED, never PROVEN
    missing-evidence  the registry stopped -> push_capability reads UNKNOWN / UNAVAILABLE and
                      REFUSES before the push; a digest the registry never held is 404, not
                      manufactured
    recovery          the registry back -> a second push of the same tag reads EXISTING_DEPLOYMENT
                      with the first digest as its rollback point, and the chain proves again

EXIT 0 every case decided as it must; 1 a case decided wrongly; 2 could not be checked (UNKNOWN).
"""
import hashlib
import http.client
import io
import json
import os
import re
import shutil
import socket
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import _step_harness as H  # noqa: E402

WF = '.github/workflows/reusable-build-docker.yml'
TPL = 'templates/build-deploy.yml'
RENDER = '.github/actions/render-version-metadata/action.yml'
COMPONENT, CVERSION = 'kit-fixture-component', '1.2.3'
PROVEN = 'REGISTRY_IDENTITY_PROVEN'
MANIFEST_TYPES = ('application/vnd.docker.distribution.manifest.v2+json, '
                  'application/vnd.oci.image.manifest.v1+json')
# build-push-action inputs this file knows how to hand to `docker buildx build`.
BUILD_FLAGS = {'context': None, 'file': '--file', 'tags': '--tag', 'load': '--load'}


def sh(args, cwd=None, env=None, timeout=300):
    return subprocess.run(args, cwd=cwd, env=env, capture_output=True, text=True, encoding='utf-8',
                          errors='replace', timeout=timeout)


def free_port():
    s = socket.socket()
    s.bind(('127.0.0.1', 0))
    port = s.getsockname()[1]
    s.close()
    return port


def registry_get(url):
    """-> (status, Docker-Content-Digest or '') for a manifest URL; 404 is a measured absence."""
    req = urllib.request.Request(url, headers={'Accept': MANIFEST_TYPES})
    try:
        with urllib.request.urlopen(req, timeout=10) as r:
            return r.status, r.headers.get('Docker-Content-Digest', '')
    except urllib.error.HTTPError as e:
        return e.code, ''
    except (urllib.error.URLError, http.client.HTTPException, ConnectionError, socket.timeout):
        # Unreachable: refused, reset, or dropped mid-request (RemoteDisconnected is an
        # HTTPException AND a ConnectionError). Never a status, never a crash.
        return 0, ''


class Registry:
    def __init__(self, name):
        self.name, self.port = name, free_port()
        self.host = '127.0.0.1:%d' % self.port

    def start(self):
        p = sh(['docker', 'run', '-d', '--rm', '--name', self.name,
                '-p', '%s:5000' % self.host, 'registry:2'])
        if p.returncode != 0:
            return (p.stderr or p.stdout)[-300:]
        for _ in range(60):
            if registry_get('http://%s/v2/' % self.host)[0] in (200, 401):
                return None
            time.sleep(0.5)
        return 'registry did not answer /v2/ within 30s'

    def stop(self):
        sh(['docker', 'rm', '-f', self.name])


def translate_build(step, ctx):
    """build-push-action `with:` -> argv for `docker buildx build`, refusing unknown keys."""
    w = step.get('with') or {}
    argv, context = ['docker', 'buildx', 'build'], '.'
    for k, v in w.items():
        if k not in BUILD_FLAGS:
            raise ValueError('build-push-action input %r is not translated by this proof' % k)
        val = H.substitute(v, ctx)[0]
        if k == 'context':
            context = val
        elif k == 'load':
            if str(val).lower() == 'true':
                argv.append('--load')
        else:
            argv += [BUILD_FLAGS[k], val]
    return argv, context


def sbom_step_for_host(step):
    """The sbom step as shipped on Linux; elsewhere, without its acquisition lines, when the
    pinned syft is already on PATH. -> (step, note) or (None, why)."""
    text = step.get('run') or ''
    pin = re.search(r'syft_(\d+\.\d+\.\d+)_linux_amd64', text)
    if sys.platform.startswith('linux'):
        return step, 'sbom step run whole (acquires syft %s itself)' % (pin and pin.group(1))
    if not pin:
        return None, 'cannot read the pinned syft version from the sbom step'
    if not shutil.which('syft'):
        return None, ('non-Linux host: syft %s is not on PATH, so the sbom step cannot run here'
                      % pin.group(1))
    p = sh(['syft', 'version'])
    have = re.search(r'Version:\s+(\S+)', p.stdout or '')
    if p.returncode != 0 or not have or have.group(1) != pin.group(1):
        return None, ('non-Linux host: syft %s must be on PATH to run the sbom step without its '
                      'acquisition lines (found %s)' % (pin.group(1), have and have.group(1)))
    kept, dropped = [], []
    for line in text.split('\n'):
        s = line.strip()
        if s.startswith('s=') or '"$s"' in s or '$s"' in s:
            dropped.append(s)
        else:
            kept.append(line)
    out = dict(step, run='\n'.join(kept))
    return out, 'non-Linux host: syft %s on PATH; acquisition lines dropped: %s' % (
        pin.group(1), ' | '.join(d[:40] for d in dropped))


def self_check_disconnect():
    """A registry that drops the connection without answering is UNREACHABLE (0), never a crash.

    Found on hosted self-test (runs 38841240910 .. 38867742483, intermittent): on Linux a stopped
    registry:2 can close the socket mid-request, which urllib raises as RemoteDisconnected -- not a
    URLError -- so the missing-evidence scenario died with a traceback instead of measuring it.
    """
    import threading
    srv = socket.socket()
    srv.bind(('127.0.0.1', 0))
    srv.listen(1)
    port = srv.getsockname()[1]

    def accept_and_drop():
        c, _a = srv.accept()
        c.recv(1024)
        c.close()
    t = threading.Thread(target=accept_and_drop, daemon=True)
    t.start()
    try:
        got = registry_get('http://127.0.0.1:%d/v2/x/manifests/latest' % port)
    except Exception as exc:  # the defect: anything escaping here is a crash, not a measurement
        return False, 'registry_get raised %s on a dropped connection' % type(exc).__name__
    finally:
        t.join(timeout=5)
        srv.close()
    return got == (0, ''), 'a dropped connection read as %r, expected (0, \'\')' % (got,)


def main():
    ok_dc, why_dc = self_check_disconnect()
    if not ok_dc:
        print('FAIL: %s' % why_dc)
        return 1
    try:
        import yaml  # noqa: F401
    except ImportError:
        print('UNKNOWN: PyYAML unavailable.')
        return 2
    bash, why = H.usable_bash()
    if not bash:
        print('UNKNOWN: no usable bash (%s).' % why)
        return 2
    for tool in ('docker', 'jq'):
        if not shutil.which(tool):
            print('UNKNOWN: %s is required to RUN the steps.' % tool)
            return 2
    if sh(['docker', 'info', '--format', '{{.ServerVersion}}']).returncode != 0:
        print('UNKNOWN: no docker daemon; the build and the registry cannot run.')
        return 2
    if sh(['docker', 'buildx', 'version']).returncode != 0:
        print('UNKNOWN: docker buildx is required (the build step and imagetools).')
        return 2

    doc = H.load(WF)
    job = doc['jobs']['build']
    steps = {s.get('id'): s for s in job['steps'] if s.get('id')}
    build = steps.get('build')
    if not build or 'docker/build-push-action' not in str(build.get('uses', '')):
        print('FAIL: the build job has no `build` step using docker/build-push-action.')
        return 1
    want = ['built', 'sbom', 'build_inputs', 'push_capability', 'push', 'assert_identity',
            'provenance', 'posture']
    missing = [k for k in want if k not in steps]
    if missing:
        print('FAIL: build job lacks step id(s) %s.' % ', '.join(missing))
        return 1
    step = {k: H.step(WF, 'build', k) for k in want}
    sbom_step, note = sbom_step_for_host(step['sbom'])
    if sbom_step is None:
        print('UNKNOWN: %s' % note)
        return 2
    print('  %s' % note)
    job_outputs = job.get('outputs') or {}
    wf_outputs = ((doc.get('on') or doc.get(True))['workflow_call'].get('outputs') or {})
    tpl = H.load(TPL)
    render_with = None
    for s in (tpl['jobs']['verdict'].get('steps') or []):
        if 'render-version-metadata' in str(s.get('uses', '')):
            render_with = s.get('with') or {}
    if render_with is None:
        print('FAIL: templates/build-deploy.yml does not call render-version-metadata.')
        return 1
    rstep = H.load(RENDER)['runs']['steps'][0]

    bad = []
    tmp = tempfile.mkdtemp(prefix='build-round-trip-')
    tag = 'probe-%d' % os.getpid()
    reg = Registry('kit-build-probe-%d' % os.getpid())
    images = []
    try:
        err = reg.start()
        if err:
            print('UNKNOWN: could not start a local registry:2: %s' % err)
            return 2
        repo = '%s/kit/probe' % reg.host
        image = '%s:%s' % (repo, tag)
        images.append(image)
        ws = os.path.join(tmp, 'ws')
        os.makedirs(ws)
        runner_tmp = os.path.join(tmp, 'runner').replace('\\', '/')
        os.makedirs(runner_tmp)
        H.shim(os.path.join(tmp, 'noshim'), 'kit-noop', 'exit 0')   # a shim dir, holding no tool
        io.open(os.path.join(ws, 'package.json'), 'w', encoding='utf-8', newline='\n').write(
            json.dumps({'name': COMPONENT, 'version': CVERSION}) + '\n')
        io.open(os.path.join(ws, 'Dockerfile'), 'w', encoding='utf-8', newline='\n').write(
            'FROM scratch\nCOPY package.json /app/package.json\n')
        base_env = {'REPO': repo, 'IMAGE': image, 'RUNNER_TEMP': runner_tmp,
                    'GITHUB_RUN_ID': '7', 'GITHUB_RUN_ATTEMPT': '1',
                    'MSYS2_ENV_CONV_EXCL': '*', 'MSYS_NO_PATHCONV': '1'}
        inputs = {'inputs.context': '.', 'inputs.dockerfile': 'Dockerfile', 'inputs.push': 'true',
                  'inputs.trivy_severity': 'HIGH,CRITICAL', 'inputs.weakening_reason': '',
                  'inputs.weakening_authority': '', 'inputs.weakening_exception_ref': '',
                  'inputs.weakening_expires': '', 'env.IMAGE': image,
                  'github.sha': 'c' * 40, 'github.run_id': '7', 'github.ref_name': 'main',
                  'job.status': 'success', 'steps.trivy.outcome': 'skipped'}

        def run(s, ctx, extra=None):
            return H.run(bash, s, ctx, ws, None, dict(base_env, **(extra or {})))

        def do_build(ctx):
            argv, context = translate_build(build, ctx)
            iid = os.path.join(tmp, 'iid-%d' % len(os.listdir(tmp)))
            p = sh(argv + ['--iidfile', iid, context], cwd=ws, timeout=600)
            if p.returncode != 0:
                return None, (p.stderr or p.stdout)[-500:]
            return io.open(iid, encoding='utf-8').read().strip(), None

        def chain(name, scanned_override=None):
            """build -> built -> sbom -> build_inputs -> push_capability -> push -> assert ->
            provenance -> posture -> outputs -> template -> stamp. -> dict of everything."""
            ctx = dict(inputs)
            imageid, err = do_build(ctx)
            if imageid is None:
                bad.append('%s: the translated build failed\n%s' % (name, err))
                return None
            ctx['steps.build.outputs.imageid'] = imageid
            out = {'imageid': imageid}
            r = run(step['built'], ctx)
            out['built'] = r
            ctx['steps.built.outputs.config_digest'] = r['outputs'].get('config_digest', '')
            r = run(sbom_step, ctx)
            out['sbom'] = r
            ctx['steps.sbom.outputs.sha256'] = r['outputs'].get('sha256', '')
            r = run(step['build_inputs'], ctx)
            out['build_inputs'] = r
            ctx['steps.build_inputs.outputs.record'] = r['outputs'].get('record', '')
            r = run(step['push_capability'], ctx)
            out['cap'] = r
            ctx['steps.push_capability.outcome'] = 'success' if r['rc'] == 0 else 'failure'
            if r['rc'] == 0:
                r = run(step['push'], ctx)
                out['push'] = r
                ctx['steps.push.outputs.digest'] = r['outputs'].get('digest', '')
                ctx['steps.push.outputs.digest_id'] = r['outputs'].get('digest_id', '')
                actx = dict(ctx)
                if scanned_override:
                    actx['steps.built.outputs.config_digest'] = scanned_override
                r = run(step['assert_identity'], actx)
                out['assert'] = r
                ctx['steps.assert_identity.outcome'] = 'success' if r['rc'] == 0 else 'failure'
            else:
                ctx['steps.assert_identity.outcome'] = 'skipped'
            r = run(step['provenance'], ctx)
            out['prov'] = r
            ctx['steps.provenance.outputs.class'] = r['outputs'].get('class', '')
            r = run(step['posture'], ctx)
            out['posture'] = r
            for k, v in r['outputs'].items():
                ctx['steps.posture.outputs.' + k] = v
            # THE HANDOFF, as the YAML maps it: step -> job -> workflow -> template -> composite.
            jctx = {'jobs.build.outputs.' + k: H.substitute(v, ctx)[0] for k, v in job_outputs.items()}
            nctx = {'needs.build.outputs.' + k: H.substitute(v.get('value', ''), jctx)[0]
                    for k, v in wf_outputs.items()}
            rctx = {'github.sha': 'c' * 40, 'github.run_id': '7', 'github.ref_name': 'main'}
            for k, v in render_with.items():
                rctx['inputs.' + k] = H.substitute(v, nctx)[0]
            r = H.run(bash, rstep, rctx, ws, None, base_env, composite=True)
            out['render'] = r
            try:
                out['stamp'] = json.loads(r['outputs'].get('metadata', ''))
            except ValueError:
                out['stamp'] = {}
            out['ctx'] = ctx
            return out

        # ---- allowed
        a = chain('allowed')
        if a is None:
            return 1
        config = a['ctx']['steps.built.outputs.config_digest']
        digest = a['ctx'].get('steps.push.outputs.digest', '')
        sbom_path = os.path.join(ws, 'sbom.spdx.json')
        print('  %-18s config=%s... pushed=%s... class=%s route=%s'
              % ('allowed', config[7:19], digest[7:19], a['prov']['outputs'].get('class'),
                 a['posture']['outputs'].get('routing_result')))
        if a['built']['rc'] != 0 or not re.match(r'^sha256:[0-9a-f]{64}$', config) \
                or config != a['imageid']:
            bad.append('allowed: `built` did not establish the config digest the build reported '
                       '(exit %d, %r vs iid %r)\n%s' % (a['built']['rc'], config, a['imageid'],
                                                        a['built']['log'][-400:]))
        # image-build: an SBOM containing the known fixture component, and its hash reported
        comps = []
        if a['sbom']['rc'] == 0 and os.path.isfile(sbom_path):
            spdx = json.load(io.open(sbom_path, encoding='utf-8'))
            comps = [(p.get('name'), p.get('versionInfo')) for p in spdx.get('packages', [])]
            if hashlib.sha256(io.open(sbom_path, 'rb').read()).hexdigest() != \
                    a['ctx']['steps.sbom.outputs.sha256']:
                bad.append('allowed: sbom_sha256 is not the hash of sbom.spdx.json')
        else:
            bad.append('allowed: the sbom step failed (exit %d)\n%s' % (a['sbom']['rc'],
                                                                         a['sbom']['log'][-500:]))
        if (COMPONENT, CVERSION) not in comps:
            bad.append('allowed: the SBOM does not name %s %s (found %s)' % (COMPONENT, CVERSION,
                                                                            comps[:6]))
        if a['build_inputs']['rc'] != 0 or not a['ctx']['steps.build_inputs.outputs.record']:
            bad.append('allowed: build_inputs recorded nothing (exit %d)' % a['build_inputs']['rc'])
        # image-push: the registry serves the pushed digest, by digest
        if a['cap']['outputs'].get('previous_state') != 'EMPTY' \
                or a['cap']['outputs'].get('rollback_capability') != 'NO_PRIOR_STATE':
            bad.append('allowed: a fresh tag read %s / %s, want EMPTY / NO_PRIOR_STATE\n%s'
                       % (a['cap']['outputs'].get('previous_state'),
                          a['cap']['outputs'].get('rollback_capability'), a['cap']['log'][-400:]))
        if not re.match(r'^sha256:[0-9a-f]{64}$', digest):
            bad.append('allowed: the push emitted no digest (%r)\n%s'
                       % (digest, a.get('push', {}).get('log', '')[-500:]))
        else:
            status, served = registry_get('http://%s/v2/kit/probe/manifests/%s' % (reg.host, digest))
            print('  %-18s GET /v2/kit/probe/manifests/<digest> -> %s, Docker-Content-Digest %s'
                  % ('', status, served[7:19] + '...' if served else '(none)'))
            if status != 200 or served != digest:
                bad.append('allowed: the registry does not serve the pushed digest by digest '
                           '(HTTP %s, Docker-Content-Digest %r)' % (status, served))
        if a.get('assert', {}).get('rc') != 0:
            bad.append('allowed: assert_identity failed against a registry holding the scanned '
                       'bytes\n%s' % a.get('assert', {}).get('log', '')[-500:])
        if a['prov']['outputs'].get('class') != PROVEN:
            bad.append('allowed: class %r, want %s' % (a['prov']['outputs'].get('class'), PROVEN))
        po = a['posture']['outputs']
        if po.get('routing_result') != 'PROCEED' or 'artifact-identity' not in po.get(
                'controls_executed', '') or 'push-reversal' not in po.get('controls_executed', ''):
            bad.append('allowed: posture routing=%r executed=%r' % (po.get('routing_result'),
                                                                    po.get('controls_executed')))
        # version-metadata-wired: the stamp carries what the workflow pushed, through the maps
        st = a['stamp']
        print('  %-18s stamp image_digest=%s... identity=%s config=%s...'
              % ('stamp', str(st.get('image_digest', ''))[7:19], st.get('artifact_identity'),
                 str(st.get('scanned_config_digest', ''))[7:19]))
        if st.get('image_digest') != digest or st.get('scanned_config_digest') != config \
                or st.get('artifact_identity') != PROVEN \
                or st.get('sbom_sha256') != a['ctx']['steps.sbom.outputs.sha256'] \
                or not isinstance(st.get('build_inputs'), dict):
            bad.append('allowed: the stamp does not carry the pushed digest, the scanned config, '
                       'the identity class, the sbom hash and the build inputs: %s (exit %d)\n%s'
                       % (st, a['render']['rc'], a['render']['log'][-400:]))

        # ---- attack: the assertion is handed a different image's config (scanned != pushed)
        other_ws = os.path.join(tmp, 'other')
        os.makedirs(other_ws)
        io.open(os.path.join(other_ws, 'Dockerfile'), 'w', encoding='utf-8', newline='\n').write(
            'FROM scratch\nCOPY Dockerfile /other\n')
        other_tag = '%s:other-%d' % (repo, os.getpid())
        images.append(other_tag)
        p = sh(['docker', 'buildx', 'build', '--load', '-t', other_tag, '.'], cwd=other_ws, timeout=600)
        other = sh(['docker', 'image', 'inspect', '--format', '{{.Id}}', other_tag]).stdout.strip()
        if p.returncode != 0 or not other.startswith('sha256:'):
            bad.append('attack: could not build the second image\n%s' % (p.stderr or '')[-300:])
        else:
            inputs['inputs.push'] = 'true'
            atk = chain('attack', scanned_override=other)
            if atk is not None:
                print('  %-18s assertion exit=%s class=%s route=%s stamp identity=%s'
                      % ('attack', atk.get('assert', {}).get('rc'), atk['prov']['outputs'].get('class'),
                         atk['posture']['outputs'].get('routing_result'),
                         atk['stamp'].get('artifact_identity')))
                if atk.get('assert', {}).get('rc') == 0:
                    bad.append('attack: assert_identity PASSED with a scanned config the registry '
                               'does not hold under the pushed digest')
                elif 'ARTIFACT IDENTITY MISMATCH' not in atk.get('assert', {}).get('log', ''):
                    bad.append('attack: the assertion failed, but not as a MISMATCH\n%s'
                               % atk.get('assert', {}).get('log', '')[-400:])
                if atk['prov']['outputs'].get('class') != 'IDENTITY_UNVERIFIED':
                    bad.append('attack: class %r, want IDENTITY_UNVERIFIED'
                               % atk['prov']['outputs'].get('class'))
                if atk['posture']['outputs'].get('routing_result') != 'EVIDENCE_UNTRUSTED':
                    bad.append('attack: posture routed %r, want EVIDENCE_UNTRUSTED'
                               % atk['posture']['outputs'].get('routing_result'))
                if atk['stamp'].get('artifact_identity') != 'IDENTITY_UNVERIFIED':
                    bad.append('attack: the stamp carries %r; a failed round trip must never reach '
                               'the stamp as PROVEN' % atk['stamp'].get('artifact_identity'))

        # ---- missing-evidence: the registry is gone; the capability step must refuse, not guess
        reg.stop()
        ctx = dict(inputs)
        r = run(step['push_capability'], ctx)
        print('  %-18s capability exit=%d previous_state=%s rollback_capability=%s'
              % ('missing-evidence', r['rc'], r['outputs'].get('previous_state'),
                 r['outputs'].get('rollback_capability')))
        if r['rc'] == 0 or r['outputs'].get('previous_state') != 'UNKNOWN' \
                or r['outputs'].get('rollback_capability') != 'UNAVAILABLE':
            bad.append('missing-evidence: an unreachable registry must read UNKNOWN / UNAVAILABLE '
                       'and refuse (exit %d, %r)\n%s' % (r['rc'], r['outputs'], r['log'][-400:]))
        p = run(step['push'], ctx)
        if p['rc'] == 0:
            bad.append('missing-evidence: the push went ahead after the capability step refused')

        # ---- recovery: the registry back; the same tag is now a rollback point
        reg2 = Registry(reg.name + '-r')
        reg2.port, reg2.host = reg.port, reg.host     # same address: the same tag, the same repo
        err = reg2.start()
        if err:
            print('UNKNOWN: could not restart the registry: %s' % err)
            return 2
        reg = reg2
        # a fresh registry holds nothing: re-push the allowed image, then push the tag AGAIN
        first = chain('recovery-first')
        if first is None:
            return 1
        d1 = first['ctx'].get('steps.push.outputs.digest', '')
        status, served = registry_get('http://%s/v2/kit/probe/manifests/sha256:%s' % (reg.host, 'e' * 64))
        if status != 404:
            bad.append('recovery: a digest the registry never held answered HTTP %s, not 404' % status)
        second = chain('recovery-second')
        if second is None:
            return 1
        print('  %-18s previous_state=%s prior=%s... class=%s'
              % ('recovery', second['cap']['outputs'].get('previous_state'), d1[7:19],
                 second['prov']['outputs'].get('class')))
        if second['cap']['outputs'].get('previous_state') != 'EXISTING_DEPLOYMENT' \
                or second['cap']['outputs'].get('rollback_capability') != 'AVAILABLE':
            bad.append('recovery: a tag the registry holds read %s / %s, want EXISTING_DEPLOYMENT '
                       '/ AVAILABLE' % (second['cap']['outputs'].get('previous_state'),
                                        second['cap']['outputs'].get('rollback_capability')))
        man = os.path.join(runner_tmp, 'build-evidence', 'manifest.json')
        try:
            m = json.load(io.open(man, encoding='utf-8'))
        except (OSError, ValueError):
            m = {}
        if m.get('status') != 'applied' or (m.get('entries') or [{}])[0].get('prior') != '%s@%s' % (repo, d1):
            bad.append('recovery: the change manifest does not record the first digest as the '
                       'rollback point of the second push: %s' % m)
        if second['prov']['outputs'].get('class') != PROVEN or \
                second['stamp'].get('image_digest') != second['ctx'].get('steps.push.outputs.digest'):
            bad.append('recovery: the chain did not prove again after the registry returned')
    finally:
        try:
            reg.stop()
        except Exception:  # noqa: BLE001
            pass
        for im in images:
            sh(['docker', 'rmi', '-f', im])
        shutil.rmtree(tmp, ignore_errors=True)

    if bad:
        for b in bad:
            print('FAIL: %s' % b)
        return 1
    print('PASS: against a real local registry, the build job emits the scanned config digest and '
          'an SBOM naming the fixture component, pushes the scanned bytes, is served them back by '
          'digest, proves identity, routes PROCEED, and the stamp rendered through the job, '
          'workflow and template maps carries exactly the digest it pushed; a scanned/pushed '
          'mismatch is refused and reaches the stamp as IDENTITY_UNVERIFIED; an unreachable '
          'registry refuses before the push; a returned registry reads the prior digest as the '
          'rollback point.')
    return 0


if __name__ == '__main__':
    sys.exit(main())

#!/usr/bin/env python3
"""Run the image-scan job's Trivy configuration, as shipped, against seeded and clean images.

WHY THIS EXISTS (validation-registry gap `image-scan`: "NO validation probe -- and no deferral")

    The job is a single `aquasecurity/trivy-action` step. It cannot be extracted and run under bash
    like a `run:` step, so this probe reads the step's `with:` block from the workflow AS SHIPPED,
    translates each key to the Trivy CLI flag the action passes it as, and runs the real Trivy. An
    input key this file does not know how to translate FAILS the probe instead of being dropped:
    a probe that silently ignored a new input would go on proving last month's configuration.

    The ONE deliberate difference: the job scans `image-ref` (a registry reference); the probe
    scans a docker-save archive it builds itself (`--input`), so no daemon, no registry and no
    network beyond Trivy's vulnerability database are needed. Same scanner, same flags, same image
    content model.

    The images are built byte by byte here, so their content is exact and reviewable:
      vulnerable   Alpine 3.10 with an outdated openssl recorded in the apk database
      secret       an empty filesystem holding one credential-shaped token, assembled at runtime so
                   no credential-shaped literal sits in this repository for its own scanners to find
      clean        an empty filesystem holding one text file

SCENARIOS
    vuln_enforce     vulnerable image, advisory off  -> Trivy exits non-zero, CVE results
    vuln_advisory    vulnerable image, advisory on   -> exit 0, findings still in the SARIF
    secret_advisory  secret in the image, advisory on -> exit NON-ZERO. Secrets block in every mode
                     (START-HERE, ENFORCEMENT_TIERS section 1.1): advisory softens inherited
                     findings, never a live credential
    clean            clean image, advisory off      -> exit 0, zero results

EXIT
    0  every scenario decided as it must
    1  a scenario decided wrongly
    2  could not be checked (no trivy, no vulnerability database) -- UNKNOWN, never PASS
"""
import hashlib
import io
import json
import os
import shutil
import subprocess
import sys
import tarfile
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
WF = os.path.join(ROOT, '.github', 'workflows', 'reusable-security.yml')
JOB = 'image-scan'

# How trivy-action passes each `with:` key to the CLI. Keys that select WHAT to scan are handled by
# the probe itself (`scan-type`, `image-ref`); keys naming where output goes are rewritten into the
# scratch directory. Anything else must be listed here or the probe refuses to run.
FLAG = {'scanners': '--scanners', 'severity': '--severity', 'exit-code': '--exit-code',
        'format': '--format', 'ignore-unfixed': '--ignore-unfixed',
        'vuln-type': '--pkg-types', 'pkg-types': '--pkg-types', 'timeout': '--timeout',
        'limit-severities-for-sarif': None}
HANDLED = {'scan-type', 'image-ref', 'output'}

APK_INSTALLED = '''C:Q1placeholderchecksumplaceholderxx=
P:openssl
V:1.1.1a-r0
A:x86_64
o:openssl
m:Natanael Copa <ncopa@alpinelinux.org>

C:Q1placeholderchecksumplaceholderyy=
P:libssl1.1
V:1.1.1a-r0
A:x86_64
o:openssl
m:Natanael Copa <ncopa@alpinelinux.org>

'''


def token():
    """A credential-shaped string built at runtime, so the source holds no secret-shaped literal."""
    body = ''.join('abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789'[(i * 7 + 3) % 62]
                   for i in range(36))
    return 'gh' + 'p_' + body


def image(path, files, tag):
    """Write a docker-save archive holding one layer with `files` ({path: text})."""
    layer = io.BytesIO()
    with tarfile.open(fileobj=layer, mode='w') as t:
        for name, text in sorted(files.items()):
            data = text.encode('utf-8')
            info = tarfile.TarInfo(name.lstrip('/'))
            info.size, info.mode, info.mtime = len(data), 0o644, 0
            t.addfile(info, io.BytesIO(data))
    layer_bytes = layer.getvalue()
    diff_id = 'sha256:' + hashlib.sha256(layer_bytes).hexdigest()
    config = json.dumps({'architecture': 'amd64', 'os': 'linux', 'config': {},
                         'rootfs': {'type': 'layers', 'diff_ids': [diff_id]},
                         'history': [{'created_by': 'prove_image_scan_enforces.py'}]}).encode()
    manifest = json.dumps([{'Config': 'config.json', 'RepoTags': [tag],
                            'Layers': ['layer.tar']}]).encode()
    with tarfile.open(path, mode='w') as t:
        for name, data in (('layer.tar', layer_bytes), ('config.json', config),
                           ('manifest.json', manifest)):
            info = tarfile.TarInfo(name)
            info.size, info.mtime = len(data), 0
            t.addfile(info, io.BytesIO(data))


def trivy_step():
    import yaml
    doc = yaml.safe_load(io.open(WF, encoding='utf-8'))
    for s in (doc['jobs'][JOB].get('steps') or []):
        if 'trivy-action' in str(s.get('uses', '')):
            return s
    return None


def resolve(value, advisory):
    """Resolve the one expression shape the step uses: `${{ inputs.advisory_mode && 'A' || 'B' }}`
    and plain `${{ inputs.fail_on_severity }}`. Anything else is refused."""
    v = str(value).strip()
    if not v.startswith('${{'):
        return v
    inner = v[3:-2].strip()
    if inner == 'inputs.fail_on_severity':
        return 'CRITICAL,HIGH'
    if inner.startswith('inputs.advisory_mode &&'):
        a, b = [x.strip().strip("'") for x in inner[len('inputs.advisory_mode &&'):].split('||')]
        return a if advisory else b
    raise ValueError('unmodelled expression %r' % v)


def results(sarif):
    doc = json.load(io.open(sarif, encoding='utf-8'))
    return [r.get('ruleId', '') for run_ in doc.get('runs', []) for r in run_.get('results', [])]


def main():
    try:
        import yaml  # noqa: F401
    except ImportError:
        print('UNKNOWN: PyYAML unavailable.')
        return 2
    if not shutil.which('trivy'):
        print('UNKNOWN: trivy is required to RUN the configuration.')
        return 2
    steps = [s for s in (trivy_step(),) if s]
    if not steps:
        print('UNKNOWN: no trivy-action step in job %r.' % JOB)
        return 2

    tmp = tempfile.mkdtemp(prefix='image-scan-probe-')
    bad = []
    try:
        imgs = {
            'vulnerable': {'/etc/alpine-release': '3.10.9\n',
                           '/etc/os-release': 'NAME="Alpine Linux"\nID=alpine\nVERSION_ID=3.10.9\n',
                           '/lib/apk/db/installed': APK_INSTALLED},
            'secret': {'/app/settings.env': 'GITHUB_TOKEN=%s\n' % token()},
            'clean': {'/app/hello.txt': 'hello\n'},
        }
        for name, files in imgs.items():
            image(os.path.join(tmp, name + '.tar'), files, 'probe/%s:1' % name)

        scenarios = [
            ('vuln_enforce', 'vulnerable', False, 'fail', 'cve'),
            ('vuln_advisory', 'vulnerable', True, 'pass', 'cve'),
            ('secret_advisory', 'secret', True, 'fail', 'secret'),
            ('clean', 'clean', False, 'pass', None),
        ]
        for name, img, advisory, expect, finds in scenarios:
            all_rules, rcs = [], []
            # Every trivy-action step the job ships runs; the job fails if any of them fails.
            for i, s in enumerate(trivy_steps(), 1):
                w = s.get('with') or {}
                unknown = sorted(k for k in w if k not in FLAG and k not in HANDLED)
                if unknown:
                    print('FAIL: the probe cannot translate input(s) %s; refusing to prove a '
                          'configuration it would silently drop' % ', '.join(unknown))
                    return 1
                if str(w.get('scan-type', 'image')) != 'image':
                    bad.append('%s: step %d scan-type is %r, not image' % (name, i, w.get('scan-type')))
                    continue
                out = os.path.join(tmp, '%s-%d.sarif' % (name, i))
                cmd = ['trivy', 'image', '--quiet', '--input', os.path.join(tmp, img + '.tar'),
                       '--output', out]
                # THE ACTION'S OWN SARIF RULE (trivy-action@v0.36.0 entrypoint.sh): for a SARIF,
                # unless limit-severities-for-sarif is true, the severity filter is UNSET. This
                # probe used to pass `severity` straight to the CLI, modelling a configuration the
                # action never runs (ledger L17; tests/prove_trivy_threshold.py).
                sarif_all = (str(w.get('format', '')) == 'sarif' and
                             str(w.get('limit-severities-for-sarif', '')).lower() != 'true')
                for k, flag in FLAG.items():
                    if k in w and flag:
                        if k == 'severity' and sarif_all:
                            continue
                        val = resolve(w[k], advisory)
                        cmd += [flag] if val == 'true' and k == 'ignore-unfixed' else [flag, val]
                p = subprocess.run(cmd, capture_output=True, text=True, encoding='utf-8',
                                   errors='replace')
                if 'failed to download' in (p.stderr or '').lower() or \
                        'db error' in (p.stderr or '').lower():
                    print('UNKNOWN: Trivy could not obtain its vulnerability database.')
                    return 2
                rcs.append(p.returncode)
                if os.path.isfile(out):
                    all_rules += results(out)
                    # The job's own count and enforce steps read the report under its real name.
                    if str(w.get('output', '')) == 'trivy-image.sarif':
                        rcs += enforce_steps(out, advisory)
                elif p.returncode not in (0, 1):
                    bad.append('%s: trivy step %d errored (exit %d): %s'
                               % (name, i, p.returncode, (p.stderr or '')[-400:]))
            job_failed = any(rc != 0 for rc in rcs)
            print('  %-16s exits=%s results=%d %s' % (name, rcs, len(all_rules),
                                                     ','.join(sorted(set(all_rules)))[:120]))
            if finds == 'cve' and not any(r.upper().startswith('CVE-') for r in all_rules):
                bad.append('%s: no CVE result for the outdated openssl' % name)
            if finds == 'secret' and not any('github' in r.lower() or 'secret' in r.lower()
                                             for r in all_rules):
                bad.append('%s: the credential in the image was not reported' % name)
            if finds is None and all_rules:
                bad.append('%s: the clean image produced results: %s' % (name, all_rules))
            if expect == 'fail' and not job_failed:
                bad.append('%s: the job would PASS. %s' % (
                    name, 'A credential baked into an image is live exposure; advisory_mode '
                          'must never soften it.' if finds == 'secret'
                    else 'Findings at the configured severity must fail with advisory off.'))
            if expect == 'pass' and job_failed:
                bad.append('%s: the job would FAIL (exits %s) where it must pass' % (name, rcs))
    finally:
        shutil.rmtree(tmp, ignore_errors=True)

    if bad:
        for b in bad:
            print('FAIL: %s' % b)
        return 1
    print('PASS: the shipped image-scan configuration fails on CVEs at the configured severity with '
          'advisory off, reports them with it on, fails on a credential in every mode, and passes a '
          'clean image.')
    return 0


def enforce_steps(report, advisory):
    """Run the job's count + enforce steps over `report` -> [enforce exit code], or [] when the
    job has no such steps. The vulnerability block is decided there, not by Trivy (L17)."""
    import shutil as _sh
    sys.path.insert(0, HERE)
    import _scan_step_harness as hh
    import prove_bootstrap_failure as pbf
    steps = hh.steps_by_name(JOB)
    cnt = 'Trivy image — count findings at the blocking severities'
    enf = 'Trivy image — enforce'
    if cnt not in steps or enf not in steps:
        return []
    bash, _why = pbf.usable_bash()
    sb = hh.Sandbox('image-enforce-').with_bundle()
    try:
        ws = sb.workspace('ws')
        _sh.copyfile(report, os.path.join(ws, 'trivy-image.sarif'))
        vals = {'inputs.fail_on_severity': 'CRITICAL,HIGH',
                'inputs.advisory_mode': 'true' if advisory else 'false'}
        _rc, _log, out, _u = sb.run(bash, steps[cnt], vals, ws)
        vals.update({'steps.trivy_image_count.outputs.%s' % k: out.get(k, '')
                     for k in ('count', 'collection')})
        erc, _log, _o, _u = sb.run(bash, steps[enf], vals, ws)
        return [erc]
    finally:
        sb.close()


def trivy_steps():
    import yaml
    doc = yaml.safe_load(io.open(WF, encoding='utf-8'))
    return [s for s in (doc['jobs'][JOB].get('steps') or [])
            if 'trivy-action' in str(s.get('uses', ''))]


if __name__ == '__main__':
    sys.exit(main())

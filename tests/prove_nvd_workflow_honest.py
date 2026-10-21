#!/usr/bin/env python3
"""The NVD workflow's own steps, run as shipped: can it acquire its tool, write its evidence, keep its
cache honest, and say what actually ran?

WHY THIS EXISTS (ledger L90/L91; review G2-2; VALIDATION_DEBT.md "reusable-nvd-cve.yml")

    The workflow has run on a runner three times, never on the current code, and reading it found:
      acquisition  the Dependency-Check fitness check runs the tool BEFORE the download that installs
                   it, so on a fresh runner acquisition always fails ("will not run")
      outdir       both revalidation steps write to "$OUTDIR", which nothing defines; under set -u the
                   step dies, and continue-on-error hides it
      cache        a failed NVD update is swallowed (it sets NVD_UPDATE_FAILED and exits 0), so the
                   step's outcome is success and a STALE database is saved under the "good" key every
                   later run prefers -- a poisoned good cache
      posture      controls_executed is computed from INPUTS, so a scanner that crashed is reported as
                   executed; assurance_state is only PASS or UNDETERMINED, whatever the reports say

WHAT IS RUN
    Each step extracted from reusable-nvd-cve.yml as shipped, under GitHub's shell (`bash -e`).
    SHIMMED: java, sudo, wget, sleep, trivy and dependency-check.sh -- each scenario's tool answer is
    the fixture. Dependency-Check is fetched from a zip built here. ONE RELOCATION, declared: the
    literal `/opt/` in a step is rewritten to the scenario workspace, because the step installs into
    /opt and a probe must not write outside its own temp directory.

SECTIONS (run all, or name some on the command line -- the self-test names the ones fixed so far)
    acquisition  fresh runner -> installed and RUNS; a tool that will not run -> refused with
                 DEPENDENCY_ACQUISITION_UNAVAILABLE; a download that fails -> refused
    outdir       SBOM and image revalidation write their SARIF into nvd-scan-results/
    cache        update failed -> NOT saved as good, saved as partial; update ok -> saved as good
    posture      crashed scanners land in controls_unavailable and never in controls_executed;
                 assurance_state is PASS / FINDINGS / PARTIAL / UNDETERMINED from the evidence

EXIT 0 every scenario decided as it must; 1 a scenario decided wrongly; 2 could not be checked.
"""
import io
import json
import os
import shutil
import sys
import tempfile
import zipfile

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import _step_harness as H  # noqa: E402

WF = '.github/workflows/reusable-nvd-cve.yml'
JOB = 'nvd-cve-scan'
SECTIONS = ('acquisition', 'outdir', 'cache', 'posture')

JAVA = 'echo \'openjdk version "17.0.2" 2022-01-18\' >&2'
SUDO = 'exec "$@"'
SLEEP = 'exit 0'
WGET = '''
for a in "$@"; do url="$a"; done
[ "${SHIM_WGET:-ok}" = ok ] || { echo "wget: unable to resolve host" >&2; exit 4; }
cp "$SHIM_ZIP" "./${url##*/}"
'''
# trivy: writes a SARIF with $SHIM_RESULTS results to the --output path.
TRIVY = '''
out=""; prev=""
for a in "$@"; do [ "$prev" = "--output" ] && out="$a"; prev="$a"; done
[ "${SHIM_TRIVY:-ok}" = ok ] || { echo "FATAL trivy crashed" >&2; exit 2; }
n="${SHIM_RESULTS:-1}"; r=""
for i in $(seq 1 "$n"); do r="$r{\\"ruleId\\":\\"CVE-2024-000$i\\"},"; done
printf '{"runs":[{"results":[%s]}]}' "${r%,}" > "$out"
'''


def sarif(n):
    return json.dumps({'runs': [{'results': [{'ruleId': 'CVE-1-%d' % i} for i in range(n)]}]})


def write(path, text):
    os.makedirs(os.path.dirname(path) or '.', exist_ok=True)
    io.open(path, 'w', encoding='utf-8', newline='\n').write(text)


def relocate(step, ws):
    s = dict(step)
    s['run'] = (step.get('run') or '').replace('/opt/', ws.replace('\\', '/') + '/opt/')
    return s


def dc_zip(path, ok=True):
    with zipfile.ZipFile(path, 'w') as z:
        info = zipfile.ZipInfo('dependency-check/bin/dependency-check.sh')
        info.external_attr = 0o755 << 16
        z.writestr(info, '#!/usr/bin/env bash\n' + (
            'echo "Dependency-Check Core version 12.1.0"\n' if ok else
            'echo "Error: Could not find or load main class" >&2; exit 1\n'))


def section_acquisition(bash, tmp, shims, bad):
    st = H.step(WF, JOB, 'Install OWASP Dependency-Check')
    ctx = {'inputs.dependency_check_version': '12.1.0', 'inputs.enable_dependency_check': 'true'}
    for name, zip_ok, wget, want_ok, reason in (
            ('fresh-runner', True, 'ok', True, None),
            ('missing-tool-will-not-run', False, 'ok', False, 'DEPENDENCY_ACQUISITION_UNAVAILABLE'),
            ('missing-download-fails', True, 'fail', False, 'Could not fetch'),
            # L84: bytes that do not match the pinned digest are refused, never installed.
            ('attack-tampered-download', True, 'ok', False, 'does not match'),
            ('recovery-fresh-runner', True, 'ok', True, None)):
        ws = os.path.join(tmp, 'acq-' + name)
        os.makedirs(ws)
        z = os.path.join(tmp, 'dc-%s.zip' % name)
        dc_zip(z, zip_ok)
        import hashlib
        digest = hashlib.sha256(io.open(z, 'rb').read()).hexdigest()
        ctx['inputs.dependency_check_sha256'] = ('0' * 64 if name.startswith('attack-tampered')
                                                 else digest)
        r = H.run(bash, relocate(st, ws), ctx, ws, shims,
                  {'SHIM_ZIP': z.replace('\\', '/'), 'SHIM_WGET': wget})
        print('  acquisition %-26s exit=%d' % (name, r['rc']))
        if want_ok and r['rc'] != 0:
            bad.append('acquisition/%s: a fresh runner could not acquire Dependency-Check (exit %d):'
                       '\n%s' % (name, r['rc'], r['log'][-500:]))
        if not want_ok and (r['rc'] == 0 or reason not in r['log']):
            bad.append('acquisition/%s: exit %d; want a refusal naming %r\n%s'
                       % (name, r['rc'], reason, r['log'][-300:]))


def section_outdir(bash, tmp, shims, bad):
    for key, inp, val, out in (
            ('Re-scan recorded SBOM against current vulnerability data', 'inputs.sbom_path',
             'sbom.json', 'trivy-sbom-revalidation.sarif'),
            ('Re-scan deployed image', 'inputs.image_ref', 'reg.example/app@sha256:' + 'a' * 64,
             'trivy-image-revalidation.sarif')):
        st = H.step(WF, JOB, key)
        ws = os.path.join(tmp, 'outdir-' + out)
        os.makedirs(os.path.join(ws, 'nvd-scan-results'))
        write(os.path.join(ws, 'sbom.json'), '{"bomFormat":"CycloneDX"}')
        r = H.run(bash, st, {inp: val}, ws, shims, {'SHIM_RESULTS': '1'})
        path = os.path.join(ws, 'nvd-scan-results', out)
        print('  outdir      %-26s exit=%d sarif=%s' % (out[:26], r['rc'], os.path.exists(path)))
        if r['rc'] != 0 or not os.path.exists(path):
            bad.append('outdir/%s: the revalidation SARIF was not written to nvd-scan-results/ '
                       '(exit %d)\n%s' % (out, r['rc'], r['log'][-300:]))


def section_cache(bash, tmp, shims, bad):
    doc = H.load(WF)
    steps = {s.get('name'): s for s in doc['jobs'][JOB]['steps']}
    good = steps.get('Save NVD data cache (complete)') or {}
    part = steps.get('Save NVD data cache (partial — resume base only)') or {}
    upd = H.step(WF, JOB, 'nvd_update')
    gi, pi = ' '.join(str(good.get('if')).split()), ' '.join(str(part.get('if')).split())
    if "steps.nvd_update.outputs.complete == 'true'" not in gi:
        bad.append('cache: the GOOD save is not conditioned on the update having COMPLETED: %r -- '
                   'the update step swallows its own failure, so its outcome is always success' % gi)
    if "steps.nvd_update.outputs.complete != 'true'" not in pi:
        bad.append('cache: the PARTIAL save is not the complement of the good save: %r' % pi)
    for name, dc_ok, want in (('update-failed', False, ''), ('update-ok', True, 'true')):
        ws = os.path.join(tmp, 'cache-' + name)
        os.makedirs(ws)
        bin_ = os.path.join(ws, 'opt', 'dependency-check', 'bin')
        H.shim(bin_, 'dependency-check.sh', 'exit 0' if dc_ok else 'echo "NVD returned 403" >&2; exit 1')
        r = H.run(bash, relocate(upd, ws), {'inputs.enable_dependency_check': 'true'}, ws, shims,
                  {'NVD_API_KEY': ''})
        got = r['outputs'].get('complete', '')
        print('  cache       %-26s exit=%d complete=%r stale-flag=%s'
              % (name, r['rc'], got, r['env'].get('NVD_UPDATE_FAILED')))
        if got != want:
            bad.append('cache/%s: complete=%r, want %r' % (name, got, want))


def section_posture(bash, tmp, shims, bad):
    summ = H.step(WF, JOB, 'summary')
    post = H.step(WF, JOB, 'posture')
    base = {'inputs.enable_trivy': 'true', 'inputs.enable_dependency_check': 'true',
            'inputs.scan_dockerfiles': 'true', 'inputs.fail_on_cvss': '7',
            'inputs.trivy_fail_severities': 'CRITICAL,HIGH', 'inputs.scan_paths': '.',
            'inputs.trivy_severities': 'CRITICAL,HIGH,MEDIUM', 'inputs.sbom_path': '',
            'inputs.image_ref': '', 'inputs.weakening_reason': '', 'inputs.weakening_authority': '',
            'inputs.weakening_exception_ref': '', 'inputs.weakening_expires': '',
            'steps.trivy_fs.outcome': 'success', 'steps.dc_run.outcome': 'success',
            'steps.dockerfile.outcome': 'success', 'job.status': 'success'}
    # name, overrides, files {name: n_results or text}, want_state, must_be_unavailable
    cases = [
        ('allowed-clean', {}, {'trivy': 0, 'dc': 0, 'docker': 'ok'}, 'PASS', set()),
        ('allowed-findings', {}, {'trivy': 2, 'dc': 0, 'docker': 'ok'}, 'FINDINGS', set()),
        ('attack-trivy-crashed', {'steps.trivy_fs.outcome': 'failure'},
         {'dc': 0, 'docker': 'ok'}, 'PARTIAL', {'nvd-trivy'}),
        ('attack-dockerfile-crashed', {'steps.dockerfile.outcome': 'failure'},
         {'trivy': 0, 'dc': 0}, 'PARTIAL', {'nvd-dockerfile'}),
        ('missing-dc-no-report', {'steps.dc_run.outcome': 'failure'},
         {'trivy': 0, 'docker': 'ok'}, 'PARTIAL', {'nvd-dependency-check'}),
        ('missing-everything', {'steps.trivy_fs.outcome': 'failure', 'steps.dc_run.outcome': 'failure',
                                'steps.dockerfile.outcome': 'failure'}, {}, 'UNDETERMINED',
         {'nvd-trivy', 'nvd-dependency-check', 'nvd-dockerfile'}),
        ('recovery-clean', {}, {'trivy': 0, 'dc': 0, 'docker': 'ok'}, 'PASS', set()),
    ]
    for name, over, files, want, unav in cases:
        ws = os.path.join(tmp, 'posture-' + name)
        os.makedirs(os.path.join(ws, 'nvd-scan-results', 'dependency-check'))
        if 'trivy' in files:
            write(os.path.join(ws, 'nvd-scan-results', 'trivy-nvd.sarif'), sarif(files['trivy']))
        if 'dc' in files:
            write(os.path.join(ws, 'nvd-scan-results', 'dependency-check',
                               'dependency-check-report.sarif'), sarif(files['dc']))
        if 'docker' in files:
            write(os.path.join(ws, 'nvd-scan-results', 'trivy-dockerfile.txt'), 'Tests: 1\n')
        ctx = dict(base, **over)
        s = H.run(bash, summ, ctx, ws, shims)
        for k, v in s['outputs'].items():
            ctx['steps.summary.outputs.%s' % k] = v
        p = H.run(bash, post, ctx, ws, shims)
        o = p['outputs']
        exe = set(filter(None, o.get('controls_executed', '').split(',')))
        un = set(filter(None, o.get('controls_unavailable', '').split(',')))
        state = s['outputs'].get('assurance_state')
        print('  posture     %-26s assurance=%-12s unavailable=%s routing=%s'
              % (name, state, ','.join(sorted(un)) or '-', o.get('routing_result')))
        if state != want:
            bad.append('posture/%s: assurance_state=%r, want %s' % (name, state, want))
        if not unav <= un:
            bad.append('posture/%s: %s crashed and is not in controls_unavailable (%s)'
                       % (name, sorted(unav - un), sorted(un)))
        if unav & exe:
            bad.append('posture/%s: %s crashed and is REPORTED EXECUTED' % (name, sorted(unav & exe)))
        if unav and o.get('routing_result') != 'EVIDENCE_UNTRUSTED':
            bad.append('posture/%s: routing %r with an unavailable control'
                       % (name, o.get('routing_result')))
        if not unav and un:
            bad.append('posture/%s: nothing crashed, yet %s reported unavailable' % (name, sorted(un)))


def main(argv):
    try:
        import yaml  # noqa: F401
    except ImportError:
        print('UNKNOWN: PyYAML unavailable.')
        return 2
    bash, why = H.usable_bash()
    if not bash:
        print('UNKNOWN: no usable bash (%s).' % why)
        return 2
    if not shutil.which('jq') or not shutil.which('unzip'):
        print('UNKNOWN: jq and unzip are required to RUN the steps.')
        return 2
    wanted = [a for a in argv if a in SECTIONS] or list(SECTIONS)
    unknown = [a for a in argv if a not in SECTIONS]
    if unknown:
        print('UNKNOWN: no such section(s) %s; have %s' % (unknown, ', '.join(SECTIONS)))
        return 2
    bad = []
    tmp = tempfile.mkdtemp(prefix='nvd-honest-probe-')
    try:
        shims = os.path.join(tmp, 'shim')
        for n, b in (('java', JAVA), ('sudo', SUDO), ('wget', WGET), ('sleep', SLEEP),
                     ('trivy', TRIVY)):
            H.shim(shims, n, b)
        for sec in wanted:
            globals()['section_' + sec](bash, tmp, shims, bad)
    finally:
        shutil.rmtree(tmp, ignore_errors=True)
    if bad:
        for b in bad:
            print('FAIL: %s' % b)
        return 1
    print('PASS (%s): every scenario in these sections of the NVD workflow\'s own steps decided as '
          'it must. Sections not named were NOT run.' % ', '.join(wanted))
    return 0


if __name__ == '__main__':
    sys.exit(main(sys.argv[1:]))

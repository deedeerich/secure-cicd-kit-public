#!/usr/bin/env python3
"""Run the malicious-deps job's own steps, as shipped, with the real osv-scanner.

WHY THIS EXISTS (ledger L15, L84)

    VALIDATION_DEBT said `malicious-deps` "fails on MAL- advisories" and treats no output as
    UNKNOWN. The job did neither: both scans ended `|| true`, nothing counted a MAL- id, nothing
    enforced, and the scanner itself came from `releases/latest` with no checksum. A known-
    malicious package -- a typosquat, a hijacked release -- is live compromise, not inherited debt,
    so it must block in EVERY mode, the way a secret does.

    Each step is extracted from the workflow as shipped, its `env:` and `${{ }}` resolved from the
    scenario (tests/prove_bootstrap_failure.resolve_env), and run under bash with the REAL
    osv-scanner against a throwaway workspace. The scan step's outputs feed the count step, whose
    outputs feed the enforce step, exactly as the runner chains them.

MEASURED, NOT ASSUMED (osv-scanner v2.6.0, 2026-10-14)
    * A malicious crate (rustdecimal 1.23.1) is reported THREE times -- MAL-2022-1, its RUSTSEC id
      and its GHSA id -- and the MAL- id appears as an ALIAS on the other two. Counting `id` alone
      counts it once by luck; counting every record counts it three times. The count must look at
      ids AND aliases and dedupe.
    * Exit 128 means "No package sources found" -- and a lockfile that FAILED TO PARSE produces the
      same exit and the same final line, distinguished only by "Error during extraction" above it.
      A broken lockfile read as "no lockfiles here" is the hollow scan this kit exists to refuse.
    * Some malware is published under a GHSA id with no MAL- alias (crossenv: GHSA-c2m4-w5hm-vqjw,
      "crossenv is malware"). The MAL- rule does not see it; it is reported as an ordinary
      vulnerability. Stated, not hidden.

SCENARIOS (workspace, advisory_mode -> state, enforce)
    malicious           Cargo.lock with rustdecimal       -> FINDINGS, 1 package, enforce FAILS
    malicious_advisory  the same, advisory_mode on         -> FINDINGS, enforce FAILS (every mode)
    vulnerable_only     urllib3 1.24.1 (CVEs, no MAL-)     -> PASS, 0, enforce passes
    clean               left-pad 1.3.0                     -> PASS, 0, enforce passes
    no_lockfiles        README only                        -> NOT_APPLICABLE, enforce passes
    broken_lockfile     unparseable package-lock.json      -> COLLECTION_FAILED, enforce FAILS
    one_lockfile_broken a clean lockfile beside a broken one -> COLLECTION_FAILED, enforce FAILS
    scanner_missing     osv-scanner not on PATH            -> COLLECTION_FAILED, enforce FAILS
    garbage_output      osv.json that is not JSON          -> COLLECTION_FAILED, enforce FAILS
  plus, statically: the install step pins an exact release and verifies a sha256 written in the
  workflow; no `releases/latest`.

EXIT
    0  every scenario decided as it must
    1  a scenario decided wrongly
    2  could not be checked (no bash, no osv-scanner, no OSV database) -- UNKNOWN, never PASS
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
sys.path.insert(0, HERE)
import prove_bootstrap_failure as pbf  # noqa: E402  (shared extraction, env resolution, bash probe)

JOB = 'malicious-deps'
INSTALL, SCAN = 'Install OSV-Scanner', 'Scan lockfiles'
COUNT, ENFORCE = 'OSV — count malicious packages', 'OSV — enforce on malicious packages'

CARGO_MALICIOUS = '''version = 3

[[package]]
name = "probe"
version = "0.1.0"
dependencies = [
 "rustdecimal",
]

[[package]]
name = "rustdecimal"
version = "1.23.1"
source = "registry+https://github.com/rust-lang/crates.io-index"
checksum = "0000000000000000000000000000000000000000000000000000000000000000"
'''
NPM_CLEAN = json.dumps({
    'name': 'probe', 'version': '1.0.0', 'lockfileVersion': 3, 'requires': True,
    'packages': {'': {'name': 'probe', 'version': '1.0.0', 'dependencies': {'left-pad': '1.3.0'}},
                 'node_modules/left-pad': {'version': '1.3.0'}}})


def _expand(doc):
    """The workflow with every `$/` composite step expanded into its job, as the runner sees it.

    Scanner job bodies live in `.github/actions/<scanner>/` (ledger L64); this reads the steps a
    job actually runs. One rule, tests/_composite_expand.py, for every reader.
    """
    sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
    import _composite_expand
    return _composite_expand.expanded_doc(doc)


def job_steps():
    import yaml
    doc = _expand(yaml.safe_load(io.open(pbf.WF, encoding='utf-8')))
    return {s.get('name'): s for s in (doc['jobs'][JOB].get('steps') or [])}, doc['jobs'][JOB]


def write(path, text):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    io.open(path, 'w', encoding='utf-8', newline='\n').write(text)


def outputs(path):
    out = {}
    for line in io.open(path, encoding='utf-8', errors='replace'):
        if '=' in line:
            k, v = line.rstrip('\n').split('=', 1)
            out[k] = v
    return out


def run_step(bash, step, values, ws, path_prefix):
    """-> (rc, log, outputs, unmodelled). Runs one step's `run:` with its `env:` resolved."""
    body, seen = pbf.substitute(step.get('run') or '', values)
    env_extra, unknown = pbf.resolve_env(step.get('env'), values)
    unknown = sorted(set(unknown) | {k for k in seen if k not in values})
    out = os.path.join(ws, '..', '%s.gh_output_%d' % (os.path.basename(ws), len(os.listdir(ws))))
    io.open(out, 'w').close()
    summ = os.path.join(ws, '..', os.path.basename(ws) + '.gh_summary')
    io.open(summ, 'a').close()
    f = os.path.join(ws, '..', os.path.basename(ws) + '.step.sh')
    io.open(f, 'w', encoding='utf-8', newline='\n').write(body)
    env = dict(os.environ, GITHUB_OUTPUT=out, GITHUB_STEP_SUMMARY=summ, GITHUB_WORKSPACE=ws,
               PYTHONUTF8='1', PYTHONIOENCODING='utf-8', **env_extra)
    env['PATH'] = path_prefix + os.pathsep + os.environ.get('PATH', '')
    p = subprocess.run([bash, f], capture_output=True, text=True, encoding='utf-8',
                       errors='replace', env=env, cwd=ws)
    return p.returncode, (p.stdout or '') + (p.stderr or ''), outputs(out), unknown


def static_install_check(step):
    """The install step pins an exact release and checks a digest written in the workflow."""
    text = (step.get('run') or '') + '\n' + json.dumps(step.get('env') or {})
    bad = []
    if 'releases/latest' in text:
        bad.append('the install still fetches releases/latest -- unpinned, unreproducible')
    if not re.search(r'v\d+\.\d+\.\d+', text):
        bad.append('no exact vMAJOR.MINOR.PATCH version is pinned')
    if not re.search(r'\b[0-9a-f]{64}\b', text):
        bad.append('no sha256 digest is written in the workflow')
    if 'sha256sum -c' not in text and 'sha256sum --check' not in text:
        bad.append('the digest is never checked (sha256sum -c)')
    return bad


def main():
    try:
        import yaml  # noqa: F401
    except ImportError:
        print('UNKNOWN: PyYAML unavailable.')
        return 2
    bash, why = pbf.usable_bash()
    if not bash:
        print('UNKNOWN: no usable bash (%s).' % why)
        return 2
    osv = os.environ.get('OSV_SCANNER') or shutil.which('osv-scanner')
    if not osv:
        print('UNKNOWN: osv-scanner is required to RUN the steps (set OSV_SCANNER or put it on '
              'PATH).')
        return 2
    steps, job = job_steps()
    missing = [n for n in (INSTALL, SCAN, COUNT, ENFORCE) if n not in steps]
    bad = static_install_check(steps[INSTALL]) if INSTALL in steps else []
    if missing:
        bad.append('step(s) %s missing from job %r -- nothing counts or enforces MAL- ids'
                   % (missing, JOB))
    outs = (job.get('outputs') or {})
    if 'malicious_state' not in outs:
        bad.append('job %r publishes no `malicious_state` output, so the gate cannot tell a '
                   'malicious package from a crashed scanner' % JOB)
    if missing:
        for b in bad:
            print('FAIL: %s' % b)
        return 1

    tmp = tempfile.mkdtemp(prefix='malicious-deps-probe-')
    try:
        shim = os.path.join(tmp, 'shim')
        noscanner = os.path.join(tmp, 'noscanner')
        os.makedirs(noscanner)
        posix = osv.replace('\\', '/')
        write(os.path.join(shim, 'osv-scanner'), '#!/usr/bin/env bash\nexec "%s" "$@"\n' % posix)
        # `python3` on a Windows host is the Store stub; the runner's python3 is the interpreter.
        py = '#!/usr/bin/env bash\nexec "%s" "$@"\n' % sys.executable.replace('\\', '/')
        write(os.path.join(shim, 'python3'), py)
        write(os.path.join(noscanner, 'python3'), py)
        # "NOT ON PATH" MUST SHADOW AN INSTALLED COPY. The first hosted run (2026-10-15) had
        # osv-scanner installed system-wide on the runner, so an empty directory first in PATH still
        # found the real scanner, which then found the seeded malware: FINDINGS where the scenario
        # asserts COLLECTION_FAILED. A stub that behaves exactly like a missing command (exit 127)
        # makes the scenario mean the same thing on every machine.
        write(os.path.join(noscanner, 'osv-scanner'),
              '#!/usr/bin/env bash\necho "osv-scanner: command not found" >&2\nexit 127\n')
        for d in (shim, noscanner):
            for n in os.listdir(d):
                os.chmod(os.path.join(d, n), 0o755)

        scenarios = [
            # name, files, advisory, scanner?, expected state, expected malicious, enforce passes?
            ('malicious', {'Cargo.lock': CARGO_MALICIOUS}, 'false', True, 'FINDINGS', 1, False),
            ('malicious_advisory', {'Cargo.lock': CARGO_MALICIOUS}, 'true', True, 'FINDINGS', 1,
             False),
            ('vulnerable_only', {'requirements.txt': 'urllib3==1.24.1\n'}, 'false', True, 'PASS',
             0, True),
            ('clean', {'package-lock.json': NPM_CLEAN}, 'false', True, 'PASS', 0, True),
            ('no_lockfiles', {'README.md': 'nothing to resolve\n'}, 'false', True,
             'NOT_APPLICABLE', 0, True),
            ('broken_lockfile', {'package-lock.json': '{not json'}, 'false', True,
             'COLLECTION_FAILED', None, False),
            # One lockfile parsed, one did not: the second was never examined.
            ('one_lockfile_broken', {'package-lock.json': NPM_CLEAN,
                                     'sub/package-lock.json': '{not json'}, 'false', True,
             'COLLECTION_FAILED', None, False),
            ('scanner_missing', {'Cargo.lock': CARGO_MALICIOUS}, 'false', False,
             'COLLECTION_FAILED', None, False),
            ('garbage_output', None, 'false', True, 'COLLECTION_FAILED', None, False),
        ]
        for name, files, advisory, scanner, want_state, want_n, enforce_ok in scenarios:
            ws = os.path.join(tmp, name)
            os.makedirs(ws)
            base = {'inputs.advisory_mode': advisory, 'inputs.paths': '.'}
            if files is None:
                # The scan "ran" and left a file that is not JSON: run only count + enforce.
                write(os.path.join(ws, 'osv.json'), '{"results": [ truncated')
                scan_out = {'rc': '1'}
            else:
                for rel, text in files.items():
                    write(os.path.join(ws, rel), text)
                rc, log, scan_out, unk = run_step(bash, steps[SCAN], base, ws,
                                                  shim if scanner else noscanner)
                if unk:
                    bad.append('%s: scan step reads unmodelled %s' % (name, unk))
                low = log.lower()
                if scanner and ('no such host' in low or 'dial tcp' in low
                                or 'connection refused' in low or 'tls handshake' in low):
                    print('UNKNOWN: osv-scanner could not reach the OSV database.\n%s' % log[-400:])
                    return 2
            cvals = dict(base, **{'steps.osv_scan.outputs.%s' % k: v
                                  for k, v in scan_out.items()})
            crc, clog, cout, unk = run_step(bash, steps[COUNT], cvals, ws,
                                            shim if scanner else noscanner)
            if unk:
                bad.append('%s: count step reads unmodelled %s' % (name, unk))
            evals = dict(cvals, **{'steps.osv_count.outputs.%s' % k: v for k, v in cout.items()})
            erc, elog, _o, unk = run_step(bash, steps[ENFORCE], evals, ws,
                                          shim if scanner else noscanner)
            if unk:
                bad.append('%s: enforce step reads unmodelled %s' % (name, unk))
            st, n = cout.get('state', ''), cout.get('malicious', '')
            print('  %-20s scan_rc=%-4s state=%-18s malicious=%-3s ids=%-14s enforce exit=%d'
                  % (name, scan_out.get('rc', '-'), st or '(none)', n or '-',
                     cout.get('ids', '') or '-', erc))
            if crc != 0:
                bad.append('%s: the count step exited %d -- it must record, not decide\n%s'
                           % (name, crc, clog[-400:]))
            if st != want_state:
                bad.append('%s: state=%r, expected %r\n%s' % (name, st, want_state, clog[-400:]))
            if want_n is not None and n != str(want_n):
                bad.append('%s: malicious=%r, expected %d' % (name, n, want_n))
            if want_state == 'FINDINGS' and 'MAL-2022-1' not in cout.get('ids', ''):
                bad.append('%s: the MAL- id is not named in the ids output' % name)
            if enforce_ok and erc != 0:
                bad.append('%s: enforce failed (exit %d) where it must pass\n%s'
                           % (name, erc, elog[-400:]))
            if not enforce_ok and erc == 0:
                bad.append('%s: enforce PASSED. %s' % (name, (
                    'A known-malicious package is live compromise; advisory_mode must never '
                    'soften it.' if want_state == 'FINDINGS' else
                    'No evidence is not a clean supply chain -- COLLECTION_FAILED must not pass.')))
    finally:
        shutil.rmtree(tmp, ignore_errors=True)

    if bad:
        for b in bad:
            print('FAIL: %s' % b)
        return 1
    print('PASS: the shipped malicious-deps steps install a pinned, checksum-verified osv-scanner; '
          'count MAL- ids across ids and aliases, deduped; block on them in every mode; pass CVE-'
          'only and clean trees; read no lockfiles as NOT_APPLICABLE; and read a broken lockfile, '
          'a missing scanner or unparseable output as COLLECTION_FAILED, which blocks.')
    return 0


if __name__ == '__main__':
    sys.exit(main())

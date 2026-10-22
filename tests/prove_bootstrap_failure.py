#!/usr/bin/env python3
"""Force the bootstrap job to fail and prove the gate does not report a clean run.

THE FAILURE THIS FORCES, AND WHY READING THE FILE CANNOT SETTLE IT

    Every scanner in `reusable-security.yml` declares `needs: [discover, kit-scripts]`. If
    `kit-scripts` fails, GitHub SKIPS all thirteen of them -- and the gate's own loop projects
    `skipped` into `NOT_APPLICABLE`.

        thirteen scanners reading NOT_APPLICABLE, because a bootstrap job failed,
        over a repository in which nothing was scanned at all.

    That is the strongest-looking green this workflow can produce and it is a lie. It is also
    invisible to every static check in this repository: `check_gate.py` proves the gate DEPENDS
    on each job, `capability_inventory.py` proves a step exists that would call each tool. Neither
    can answer what the gate DECIDES when a dependency dies, because deciding is something the
    shell does and reading is something the checks do. Same gap that let a 608 KB workflow sit
    dead for six days while twelve checks parsed it happily.

HOW IT IS FORCED WITHOUT A RUNNER

    The gate's decision lives entirely in one `run:` script. This extracts that script from the
    workflow AS SHIPPED, substitutes the `${{ }}` expressions with the job results a real failure
    would produce, and RUNS it -- then reads `$GITHUB_OUTPUT` and the exit status. No mocking of
    the logic, only of its inputs, which is the only part a dispatch would supply anyway.

    FOUR SCENARIOS, AND THE CONTROL IS NOT OPTIONAL. A test that only asserts the failing case
    passes just as happily when the script always fails. `all_green` exists so a green result is
    known to be reachable; without it this file would prove nothing about the two that matter.

      all_green            everything succeeded                     -> PASS, exit 0
      bootstrap_failed     kit-scripts failed, scanners skipped     -> NOT PASS, exit non-zero
      bootstrap_advisory   the same, with advisory_mode ON          -> NOT PASS, exit non-zero
      report_failed        the evidence job failed                  -> NOT PASS, exit non-zero

    `bootstrap_advisory` is the one that actually shipped broken: advisory_mode is the switch a
    new adopter is most likely to have on, and it used to turn this exact case green.

    Later scenarios follow the same shape for the other jobs the gate reads as themselves:
    discover (discover_failed*), the image secret (image_secret_advisory), and resolve
    (resolve_failed*, resolve_skipped) -- the position between discover and the scanners,
    whose death leaves the scanners' results standing over an unestablished capability.

    KDEC-010 adds a THIRD outcome beside green and blocked: PARTIAL, warn-class. A job pointed
    at a capability no carried scanner can read (capability_gap_*) is PARTIAL, never PASS, and
    never a block; a default scanner substituted away (substitution_not_selected) is PARTIAL for
    that target while the selected scanner carries the claim and the run stays green with the
    substitution named; the resolver's fail-safe (version_gaps_undetermined) is not PASS.

WHAT IT CANNOT ESTABLISH
    That GitHub skips dependants the way the scenarios assume, or that the artifact reaches a
    consuming job. It settles what the gate DOES with the results, which is the half that does
    not need a runner -- and which nothing in this repository previously checked at all.

EXIT
    0  every scenario decided as it must
    1  a scenario decided wrongly -- including the control, which failing means this proves nothing
    2  could not be checked -- reported as UNKNOWN, never as PASS
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
WF = os.path.join(ROOT, '.github', 'workflows', 'reusable-security.yml')
GATE_JOB = 'security-gate'
GATE_STEP = 'Enforce required scans'

EXPR = re.compile(r'\$\{\{\s*(.*?)\s*\}\}')

SCANNERS = ['secret-scan', 'code-quality', 'sast-semgrep', 'sast-bandit', 'sast-dotnet',
            'sast-java', 'sast-go', 'sast-cpp', 'deps-scan', 'iac-scan', 'malicious-deps',
            'sbom', 'codeql', 'image-scan']
# The scanner jobs that hand the gate a findings_state output (lane L-S).
FINDINGS_STATE_JOBS = ['code-quality', 'sast-semgrep', 'sast-bandit', 'sast-dotnet', 'sast-java',
                       'sast-go', 'sast-cpp', 'deps-scan', 'iac-scan', 'image-scan']


def _expand(doc):
    """The workflow with every `$/` composite step expanded into its job, as the runner sees it.

    Scanner job bodies live in `.github/actions/<scanner>/` (ledger L64); this reads the steps a
    job actually runs. One rule, tests/_composite_expand.py, for every reader.
    """
    sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
    import _composite_expand
    return _composite_expand.expanded_doc(doc)


def ctx(scanner='success', kit='success', report='success', advisory='false',
        discovery='COMPLETE', discover_result='success', resolve_result='success',
        version_gaps='', version_gap_count=None, capped_jobs='', not_selected_jobs='',
        substitutions='', capability_gaps='', capability_gap_count=None, fitness_notes=''):
    if version_gap_count is None:
        version_gap_count = '0' if resolve_result == 'success' else ''
    if capability_gap_count is None:
        capability_gap_count = '0' if resolve_result == 'success' else ''
    d = {'needs.kit-scripts.result': kit,
         'needs.discover.result': discover_result,
         # The resolve job (versions, capability, coverage, plan), read by the gate as itself.
         # Its outputs are '' when the job did not complete, exactly as GitHub renders them;
         # a completed resolver with nothing unsupported publishes a positively counted '0',
         # and one that failed SAFE (exit 0, every answer unknown) publishes UNDETERMINED.
         'needs.resolve.result': resolve_result,
         'needs.resolve.outputs.version_gaps': version_gaps,
         'needs.resolve.outputs.version_gap_count': version_gap_count,
         # KDEC-010: the capability selection the gate consumes. Jobs pointed at a VERSION_GAP
         # (capped: PASS -> PARTIAL, claim unestablished), jobs not selected for a target another
         # scanner serves (PASS -> PARTIAL, claim carried by the selected one), the substitutions
         # and gaps by name, and the resolver's notes for the summary.
         'needs.resolve.outputs.capped_jobs': capped_jobs,
         'needs.resolve.outputs.not_selected_jobs': not_selected_jobs,
         'needs.resolve.outputs.substitutions': substitutions,
         'needs.resolve.outputs.capability_gaps': capability_gaps,
         'needs.resolve.outputs.capability_gap_count': capability_gap_count,
         'needs.resolve.outputs.fitness_notes': fitness_notes,
         # The findings evidence the report publishes (C3). Zero, positively counted, for the
         # control; tests/prove_gate_reads_findings.py varies it.
         'needs.report.outputs.blocking_findings': '0',
         'needs.report.outputs.jobs_with_findings': '',
         'needs.report.result': report,
         'inputs.advisory_mode': advisory,
         'needs.discover.outputs.state': discovery,
         'needs.discover.outputs.coverage_gaps': '',
         'needs.discover.outputs.coverage_gap_count': '0',
         # The image-scan job's secrets step outcome, published as a job output. '' when the job
         # did not run (no image), exactly as GitHub renders an absent output.
         'needs.image-scan.outputs.secret_state': '',
         # The malicious-deps job's typed state (PASS | FINDINGS | NOT_APPLICABLE |
         # COLLECTION_FAILED). '' when the job did not run, exactly as GitHub renders it.
         'needs.malicious-deps.outputs.malicious_state': '',
         # The sbom job's licence verdict (PASS | FINDINGS | NOT_APPLICABLE | COLLECTION_FAILED)
         # and denied count. '' when the job did not run.
         'needs.sbom.outputs.licence_state': '',
         'needs.sbom.outputs.licence_denied': '',
         # The sast-semgrep job's scan state (COMPLETE | PARTIAL, KDEC-016 2026-10-22) and the PHP
         # files Semgrep could not fully parse. '' when the job did not run.
         'needs.sast-semgrep.outputs.scan_state': '',
         'needs.sast-semgrep.outputs.parse_partial_files': ''}
    # What each scanner job HANDS the gate (lane L-S, O-24: the gate is the single enforcement
    # point): FINDINGS when its own threshold fired unsoftened, '' otherwise -- '' here, nothing.
    for s in FINDINGS_STATE_JOBS:
        d['needs.%s.outputs.findings_state' % s] = ''
    for s in SCANNERS:
        d['needs.%s.result' % s] = scanner
    return d


def image_secret(advisory):
    """A credential found inside the scanned image: the image-scan job failed on its secrets step."""
    d = ctx(advisory=advisory)
    d['needs.image-scan.result'] = 'failure'
    d['needs.image-scan.outputs.secret_state'] = 'failure'
    return d


SCENARIOS = [
    # name, context, must-pass?, what a wrong answer would mean
    ('all_green', ctx(), True,
     'the control. If this cannot go green, the two failing scenarios below prove nothing -- a '
     'script that always fails satisfies every assertion about failure.'),
    ('bootstrap_failed', ctx(scanner='skipped', kit='failure', report='skipped'), False,
     'thirteen scanners were SKIPPED because the job they all depend on failed. Reporting that '
     'as anything but a blocked, undetermined run publishes NOT_APPLICABLE over code nobody '
     'scanned.'),
    ('bootstrap_advisory', ctx(scanner='skipped', kit='failure', report='skipped',
                               advisory='true'), False,
     'advisory_mode softens enforcement on FINDINGS. A bootstrap failure produced no findings, '
     'so there is nothing for it to be lenient about -- and this is the switch a first-time '
     'adopter is most likely to have on.'),
    ('report_failed', ctx(report='failure'), False,
     'the evidence job assembles the artifact this gate NAMES in its own output. Green while it '
     'is absent asserts documentation that does not exist.'),
    # THE DISCOVER JOB DYING IS NOT THE SAME AS DISCOVERY REPORTING DISCOVERY_UNAVAILABLE. The
    # second is an output the job writes; the first writes no outputs at all, so `state` is '' and
    # the DISCOVERY_UNAVAILABLE checks never fire. Scanners gated on `needs.discover.outputs.<x>`
    # then skip -> NOT_APPLICABLE, the `if: always()` ones run, and the gate went green over a
    # run in which applicability was never established (H3 / N15).
    ('discover_failed', ctx(scanner='skipped', discover_result='failure', discovery=''), False,
     'the discover job failed, so it emitted no outputs. Language-gated scanners were skipped '
     'for want of an applicability answer, not because the language is absent.'),
    ('discover_failed_advisory', ctx(scanner='skipped', discover_result='failure', discovery='',
                                     advisory='true'), False,
     'the same, under advisory_mode. Not knowing what should have been scanned is not a '
     'finding, so a findings mode has nothing to be lenient about.'),
    # SECRETS BLOCK IN EVERY MODE -- INCLUDING ONE FOUND INSIDE AN IMAGE. The gate set secret_fail
    # only for the secret-scan job, so a credential baked into an image, found by image-scan,
    # arrived as an ordinary failed scanner and advisory_mode softened it.
    ('image_secret_advisory', image_secret('true'), False,
     'a credential is baked into the image this run would ship. That is live exposure, not '
     'inherited debt, and advisory_mode must not soften it any more than a secret in the source.'),
    # THE RESOLVE JOB DYING IS THE DISCOVER SHAPE, ONE POSITION LATER. It wrote no outputs, so
    # version_gap_count reads '' and no coverage row fires; no scanner waits for it to START, so
    # every scanner ran and reported -- over code whose versions nobody matched against their
    # declared ranges. A PASS here would be scoped by evidence that does not exist. `skipped`
    # is the same: the job has no `if:`, so a skip is a torn-down run, never NOT_APPLICABLE.
    ('resolve_failed', ctx(resolve_result='failure'), False,
     'the resolve job failed, so no version, capability or coverage answer exists. The '
     'scanners ran, and their silence over an unestablished capability is not coverage.'),
    ('resolve_failed_advisory', ctx(resolve_result='failure', advisory='true'), False,
     'the same, under advisory_mode. An unestablished capability is not a finding, so a '
     'findings mode has nothing to be lenient about.'),
    ('resolve_skipped', ctx(resolve_result='skipped'), False,
     'the resolve job was skipped. It has no `if:`, so a skip means the run was torn down; '
     'the gate must read it as tooling, never as NOT_APPLICABLE.'),
    # THE PER-TOOL GAPS RESOLVE DECLARED ARE SURFACED; WHAT MOVES THE VERDICT IS THE SELECTION.
    # A VERSION_UNSUPPORTED answer means the scanner ran over code at a version outside its
    # declared range: its findings are findings and its silence is not coverage. On its own it
    # changes no verdict -- the capability selection (KDEC-010) decides which jobs it caps, and
    # with no capped or not-selected job named the run stays green -- but the row must be in the
    # summary, because a gap declared four jobs upstream is silent to the reviewer who reads only
    # the gate. The resolver's own fail-safe (UNDETERMINED: no count exists) must never be printed
    # as zero gaps, and is PARTIAL below.
    ('version_gap_surfaced', ctx(version_gaps='python@.:sast-bandit/bandit', version_gap_count='1'),
     True,
     'a declared version gap is surfaced beside the coverage gaps. On its own it changes no '
     'verdict: the capability selection (KDEC-010) says which jobs it caps, and here it capped '
     'none.'),
    # KDEC-010: THE CAPABILITY SELECTS THE SCANNER, AND THE GATE CONSUMES IT. Three shapes:
    #
    #   capability_gap    no carried scanner can read the target. The job pointed at it ran; its
    #                     PASS is capped at PARTIAL, the claim is UNESTABLISHED, assurance_state is
    #                     PARTIAL -- never PASS -- and it does NOT block (scanner_state.PARTIAL:
    #                     warns; does not block). advisory_mode changes nothing about it.
    #   substitution      the default could not read the target and a later candidate can. The
    #                     default's PASS for it is PARTIAL (it reads nothing there), the SELECTED
    #                     scanner carries the claim, so the aggregate stays PASS -- and the summary
    #                     names the substitution as a substitution, never as equivalence.
    #   fail-safe         the resolver failed SAFE: no selection exists. Nothing is capped by a
    #                     count nobody took, and nothing is PASS over an unmatched capability.
    ('capability_gap_capped',
     ctx(capped_jobs='iac-scan', capability_gaps='iac@infra', capability_gap_count='1',
         fitness_notes='iac-scan: VERSION_GAP iac@infra (iac-scan/checkov VERSION_SUPPORT_UNDETERMINED) '
                       '-- PARTIAL, never PASS; closes: scanner-registry.yaml version_support iac-scan/checkov'),
     'PARTIAL',
     'no carried scanner can read the IaC target version. The job ran and its silence is not '
     'coverage: PARTIAL, never PASS, and never a block.'),
    ('capability_gap_advisory',
     ctx(capped_jobs='iac-scan', capability_gaps='iac@infra', capability_gap_count='1',
         advisory='true'),
     'PARTIAL',
     'the same under advisory_mode: PARTIAL is already warn-class, and advisory_mode must not '
     'turn an unestablished claim into PASS.'),
    ('substitution_not_selected',
     ctx(not_selected_jobs='sast-bandit',
         substitutions='python-sast@.:sast-bandit/bandit->codeql/codeql',
         fitness_notes='sast-bandit: not selected for python-sast@. (sast-bandit/bandit '
                       'VERSION_UNSUPPORTED); served by codeql/codeql (SUBSTITUTION, not equivalence)'),
     True,
     'bandit cannot read python 3.13 and CodeQL can: the claim moves to CodeQL, bandit reads '
     'PARTIAL for that target, and the run is PASS with the substitution named -- never '
     'presented as equivalent coverage.'),
    ('version_gaps_undetermined', ctx(version_gap_count='UNDETERMINED',
                                      capability_gap_count='UNDETERMINED'), 'PARTIAL',
     'the resolver failed SAFE (exit 0, every answer unknown). No count exists; the summary must '
     'say so rather than print zero gaps, and a PASS over an unmatched capability is not a PASS.'),
]


def gate_step():
    import yaml
    doc = _expand(yaml.safe_load(io.open(WF, encoding='utf-8')))
    for s in (doc['jobs'][GATE_JOB].get('steps') or []):
        if s.get('name') == GATE_STEP:
            return s
    return None


def gate_script():
    s = gate_step()
    return s.get('run') if s else None


def gate_env(values):
    """The gate step's `env:`, resolved from the scenario (ledger L38: caller input such as
    advisory_mode reaches the script as data, so a proof must supply it the same way)."""
    s = gate_step()
    return resolve_env((s or {}).get('env'), values)[0]


_BUNDLE = {}


def with_kit_bundle(script):
    """`script` with `/tmp/` repointed at a sandbox holding the workflow's OWN kit-scripts bundle.

    Count sites call /tmp/sarif_validity.py (ledger L02) -- a script the runner receives from the
    kit-scripts artifact. A proof that runs such a step must supply the same bundle, and may not
    write the host's /tmp (WP0), so the bundle is materialised once per process from the inlined
    copies and the prefix rewritten, exactly as tests/prove_redaction_chain.py does.
    """
    if 'dir' not in _BUNDLE:
        import atexit
        import _scan_step_harness as hh
        d = tempfile.mkdtemp(prefix='kit-bundle-')
        atexit.register(shutil.rmtree, d, True)
        prefix, missing = hh.materialise_bundle(d)
        if not prefix:
            raise RuntimeError('the workflow carries no inlined copy of %s' % missing)
        _BUNDLE['dir'] = prefix
    return script.replace('/tmp/', _BUNDLE['dir'])


def env_for_run(run_text, values):
    """`env:` of the shipped step whose `run:` is exactly `run_text`, resolved from `values`.

    For proofs that extract a step's script by name and pass the TEXT around: once a caller input
    moved from `${{ }}` in the script to `env:`, running the text alone would leave the variable
    unset and prove a step nobody ships. Unknown text resolves to no extra environment.
    """
    import yaml
    doc = _expand(yaml.safe_load(io.open(WF, encoding='utf-8')))
    for job in (doc.get('jobs') or {}).values():
        for s in (job or {}).get('steps') or []:
            if s.get('run') == run_text:
                return resolve_env(s.get('env'), values)[0]
    return {}


def substitute(script, values):
    """Replace every ${{ }} with its scenario value. An expression with no value becomes ''.

    Exactly what GitHub does with an expression naming something absent -- which is itself a
    defect this kit has shipped (the report rendered the container-image row from an empty
    string for weeks). Reproducing that behaviour rather than raising keeps the harness honest.
    """
    seen = set()

    def sub(m):
        key = m.group(1)
        seen.add(key)
        return values.get(key, '')
    return EXPR.sub(sub, script), seen


def resolve_env(env_map, values):
    """Resolve a step's `env:` block from the scenario, exactly as `substitute` resolves `run:`.

    -> (env dict of strings, sorted list of expressions the scenario did not model).

    CALLER INPUT ARRIVES AS DATA (ledger L38): a step that reads `inputs.x` through `env:` keeps
    the value out of the script text, so a proof that only substituted `run:` would run the step
    with that variable UNSET and prove a configuration nobody ships. Each value resolves the way
    GitHub resolves it -- an expression naming something absent becomes '' -- and the caller is
    told which expressions were unmodelled rather than left to discover it from a wrong verdict.
    Booleans render as GitHub renders them: `true` / `false`.
    """
    out, unknown = {}, set()
    for k, v in (env_map or {}).items():
        if isinstance(v, bool):
            v = 'true' if v else 'false'
        text, seen = substitute(str(v), values)
        unknown.update(s for s in seen if s not in values)
        out[str(k)] = text
    return out, sorted(unknown)


def usable_bash():
    """-> (path, None) or (None, why). A bash that cannot run a script is not a bash.

    WHY THIS IS NOT JUST `shutil.which('bash')`

        On Windows `shutil.which('bash')` resolves to `C:\\Windows\\system32\\bash.exe`, which is
        the WSL launcher stub. If no WSL distribution is installed -- or one is installed and its
        mounts are broken -- the stub exists, is executable, and fails every invocation with a
        non-zero exit and nothing on stdout.

        This file then ran all four scenarios through it, got exit 1 and empty `$GITHUB_OUTPUT`
        from each, and reported `FAIL: all_green -- the CONTROL did not go green` with exit 1.
        That is a DEFECT VERDICT on the gate. The gate was fine: pointed at Git Bash the control
        goes green and all three failure scenarios block, which is exactly what this file exists
        to establish.

        So the harness collapsed `nothing was looked at` into `the control is broken` -- two of
        the four states this kit refuses to merge, merged inside the file that enforces the
        refusal. Its own header already says exit 2 means "could not be checked -- reported as
        UNKNOWN, never as PASS"; it was honouring the never-as-PASS half and violating the
        report-as-UNKNOWN half, which is the more dangerous direction here because a false
        failure teaches a reader to ignore this file.

        The probe is therefore a PROOF OF CAPABILITY, not a path check: run a script that must
        exit 7 and write a known line, and require both. A stub that exits non-zero for its own
        reasons cannot satisfy it, and neither can a shell that runs but cannot write the file
        this harness reads its results from.
    """
    seen = []
    candidates = []
    first = shutil.which('bash')
    if first:
        candidates.append(first)
    # Git for Windows ships a working bash that is frequently not first on PATH. Named
    # explicitly rather than discovered, so a reader can see what is being reached for.
    for extra in (r'C:\Program Files\Git\bin\bash.exe',
                  r'C:\Program Files\Git\usr\bin\bash.exe',
                  '/bin/bash', '/usr/bin/bash'):
        if extra not in candidates and os.path.exists(extra):
            candidates.append(extra)
    if not candidates:
        return None, 'no bash on PATH and none at any known location'

    for cand in candidates:
        tmp = tempfile.mkdtemp(prefix='bashprobe-')
        try:
            out = os.path.join(tmp, 'probe_out')
            runner = os.path.join(tmp, 'probe.sh')
            io.open(runner, 'w', encoding='utf-8', newline='\n').write(
                'echo "probe=ok" >> "$GITHUB_OUTPUT"\nexit 7\n')
            try:
                p = subprocess.run([cand, runner], capture_output=True, text=True,
                                   env=dict(os.environ, GITHUB_OUTPUT=out), timeout=60)
            except (OSError, subprocess.SubprocessError) as exc:
                seen.append('%s: could not be executed (%s)' % (cand, exc))
                continue
            wrote = os.path.exists(out) and 'probe=ok' in io.open(
                out, encoding='utf-8', errors='replace').read()
            if p.returncode == 7 and wrote:
                return cand, None
            seen.append('%s: probe wanted exit 7 and a written output file, got exit %s and '
                        'wrote=%s%s' % (cand, p.returncode, wrote,
                                        ('; stderr: %s' % p.stderr.strip().split('\n')[0][:160])
                                        if p.stderr.strip() else ''))
        finally:
            shutil.rmtree(tmp, ignore_errors=True)
    return None, '; '.join(seen)


def run(bash, script, env_extra=None):
    tmp = tempfile.mkdtemp(prefix='gate-')
    try:
        out = os.path.join(tmp, 'gh_output')
        summary = os.path.join(tmp, 'gh_summary')
        io.open(out, 'w').close()
        io.open(summary, 'w').close()
        runner = os.path.join(tmp, 'gate.sh')
        io.open(runner, 'w', encoding='utf-8', newline='\n').write(script)
        env = dict(os.environ, GITHUB_OUTPUT=out, GITHUB_STEP_SUMMARY=summary, **(env_extra or {}))
        p = subprocess.run([bash, runner], capture_output=True, text=True, env=env)
        emitted = {}
        for line in io.open(out, encoding='utf-8', errors='replace'):
            if '=' in line:
                k, v = line.rstrip('\n').split('=', 1)
                emitted[k] = v
        return (p.returncode, emitted,
                (p.stdout or '') + (p.stderr or ''),
                io.open(summary, encoding='utf-8', errors='replace').read())
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


def main():
    try:
        import yaml                                        # noqa: F401
    except ImportError:
        print('UNKNOWN: PyYAML unavailable. Failure to observe is not an observation.')
        return 2
    bash, why = usable_bash()
    if not bash:
        print('UNKNOWN: no bash that can actually run a script. A check that could not execute '
              'is not a pass -- and it is not a failure either, which is the distinction this '
              'branch exists to keep.')
        print('  %s' % why)
        print('')
        print('  This is NOT a statement about the gate. Nothing was run, so nothing about the')
        print('  gate was established. On Windows, install Git for Windows or put a working')
        print('  bash first on PATH and re-run.')
        return 2
    script = gate_script()
    if not script:
        print('UNKNOWN: no step named %r in job %r. A proof with nothing to run is not a pass.'
              % (GATE_STEP, GATE_JOB))
        return 2

    print('=== the gate, RUN, with its dependencies forced ===')
    print('')
    bad = []
    for name, values, must_pass, why in SCENARIOS:
        body, seen = substitute(script, values)
        unknown = sorted(k for k in seen if k not in values)
        rc, emitted, log, summary = run(bash, body, gate_env(values))
        state = emitted.get('assurance_state', '(none)')
        enf = emitted.get('enforcement_state', '(none)')
        und = emitted.get('undetermined', '(none)')
        print('  %-20s exit=%-3d assurance=%-13s enforcement=%-9s undetermined=%s'
              % (name, rc, state, enf, und))
        if unknown:
            # An expression the harness does not model silently became ''. That is what GitHub
            # would do, but the reader must know the scenario was not fully specified.
            print('       unmodelled expression(s) resolved to empty: %s' % ', '.join(unknown))

        states = {}
        try:
            states = json.loads(emitted.get('scanner_states') or '{}')
        except ValueError:
            bad.append((name, 'scanner_states is not JSON: %r' % emitted.get('scanner_states')))
        if must_pass == 'PARTIAL':
            # KDEC-010: WARN-CLASS, NEVER PASS, NEVER A BLOCK. scanner_state.PARTIAL "warns; does
            # not block" and "MUST NOT be projected, summarised or rounded into PASS".
            if rc != 0 or enf != 'ALLOWED':
                bad.append((name, 'exit=%d enforcement=%s: a PARTIAL blocked. %s' % (rc, enf, why)))
            if state != 'PARTIAL':
                bad.append((name, 'assurance_state=%s, not PARTIAL. %s' % (state, why)))
            if und != 'true':
                bad.append((name, 'undetermined=%s: an unestablished claim read as established. %s'
                            % (und, why)))
            if name.startswith('capability_gap'):
                if states.get('iac-scan') != 'PARTIAL':
                    bad.append((name, 'scanner_states.iac-scan=%r: a job pointed at a VERSION_GAP '
                                      'is PARTIAL, never %r. %s' % (states.get('iac-scan'),
                                                                     states.get('iac-scan'), why)))
                if 'iac-scan(PARTIAL)' not in emitted.get('unestablished', ''):
                    bad.append((name, 'unestablished=%r does not name iac-scan(PARTIAL). %s'
                                % (emitted.get('unestablished'), why)))
                if 'VERSION_GAP' not in summary or 'iac@infra' not in summary:
                    bad.append((name, 'the summary does not name the capability gap. %s' % why))
            if name == 'version_gaps_undetermined':
                if 'VERSION_GAP_COUNT UNDETERMINED' not in summary:
                    bad.append((name, 'the summary does not say the version gap count is '
                                      'UNDETERMINED. %s' % why))
                if ' x0' in summary or 'VERSION_UNSUPPORTED x' in summary:
                    bad.append((name, 'a count nobody could take was printed as a count. %s' % why))
        elif must_pass:
            if rc != 0 or state != 'PASS' or enf != 'ALLOWED' or und != 'false':
                bad.append((name, 'the CONTROL did not go green. %s' % why))
            # The surfaced rows: green is necessary, and a green with no row is the silence those
            # rows exist to end.
            if name == 'version_gap_surfaced':
                if 'VERSION_UNSUPPORTED x1' not in summary or 'python@.:sast-bandit/bandit' not in summary:
                    bad.append((name, 'green, but the summary carries no VERSION_UNSUPPORTED row '
                                      'naming the gap. %s' % why))
            if name == 'substitution_not_selected':
                # The default's PASS for a target it cannot read is PARTIAL; the aggregate is
                # PASS because the SELECTED scanner carries the claim; the summary says which.
                if states.get('sast-bandit') != 'PARTIAL':
                    bad.append((name, 'scanner_states.sast-bandit=%r: a scanner not selected for '
                                      'a target it cannot read reported %r for it. %s'
                                % (states.get('sast-bandit'), states.get('sast-bandit'), why)))
                if 'sast-bandit(PARTIAL)' not in emitted.get('not_selected', ''):
                    bad.append((name, 'not_selected=%r does not name sast-bandit(PARTIAL). %s'
                                % (emitted.get('not_selected'), why)))
                if 'SUBSTITUTION' not in summary or 'not equivalence' not in summary \
                        or 'codeql/codeql' not in summary:
                    bad.append((name, 'the summary does not name the substitution as a '
                                      'substitution, not equivalence. %s' % why))
            elif any(v == 'PARTIAL' for v in states.values()):
                bad.append((name, 'a green control carries a PARTIAL scanner state: %s' % states))
        else:
            if rc == 0:
                bad.append((name, 'exited 0. %s' % why))
            if state == 'PASS':
                bad.append((name, 'reported assurance_state=PASS. %s' % why))
            if enf != 'BLOCKED':
                bad.append((name, 'enforcement_state=%s, not BLOCKED. %s' % (enf, why)))
            if und != 'true':
                bad.append((name, 'undetermined=%s. A run whose scanners never started has '
                                  'not established posture. %s' % (und, why)))
            if name.startswith('bootstrap'):
                # The rows really do say NOT_APPLICABLE -- that is GitHub's `skipped`, projected.
                # What must never happen is the AGGREGATE reading as coverage, so the proof is
                # that the summary names the cause rather than that the rows are absent.
                if 'Kit scripts NOT materialised' not in log:
                    bad.append((name, 'the log never named kit-scripts as the cause. Thirteen '
                                      'NOT_APPLICABLE rows with no explanation IS the defect.'))
                if 'the run did not happen' not in summary:
                    bad.append((name, 'the run summary does not say the run did not happen. A '
                                      'reader sees the rows, not this script.'))
            if name.startswith('resolve'):
                # The cause must be NAMED. Scanner rows all read success here, so a block with
                # no named cause is a block the reader cannot act on.
                if 'Resolve job did not complete' not in log:
                    bad.append((name, 'the log never named the resolve job as the cause. Every '
                                      'scanner row reads success; an unnamed block is unactionable.'))
                if 'the run did not happen' not in summary:
                    bad.append((name, 'the run summary does not say the run did not happen as '
                                      'specified. A reader sees the rows, not this script.'))

    print('')
    print('=' * 72)
    if bad:
        for name, msg in bad:
            print('FAIL: %s -- %s' % (name, msg))
        print('')
        print('A SKIPPED SCANNER IS NOT A CLEAN SCANNER.')
        return 1
    print('PASS: a green gate is reachable, and every forced failure of the bootstrap or')
    print('      evidence job blocks -- under advisory_mode as well as without it.')
    print('')
    print('      THIS RUNS THE GATE, IT DOES NOT RUN THE WORKFLOW. It settles what the gate')
    print('      decides given a set of job results; it cannot establish that GitHub produces')
    print('      those results, or that any scanner detects anything. Only a dispatch can.')
    return 0


if __name__ == '__main__':
    sys.exit(main())

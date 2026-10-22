#!/usr/bin/env python3
"""PHP is SCANNED by the sast-semgrep job: its seeds are found whatever the caller's rulesets, and
a PHP scan that examined nothing never reads as clean (lane L-PHP, 2026-10-21).

WHY THIS EXISTS

    Until lane L-PHP the kit declared PHP a COVERAGE_GAP. Semgrep ran on every repository with
    the OWASP rulesets, so PHP was scanned only INCIDENTALLY: nothing proved a PHP seed was found,
    and a caller who narrowed `semgrep_config` (the shipped python profile is
    "p/default p/owasp-top-ten p/python"; a caller can pass "p/python" alone) silently dropped
    every PHP rule. Measured locally on 2026-10-21 (Semgrep 1.178.0 by pip and the job's own
    semgrep/semgrep:1.90.0 container, both against the registry that day):

      * p/php (24 rules) detects all three seeds -- tainted-sql-string (SQL injection),
        echoed-request (XSS), tainted-exec (command injection) -- each at ERROR;
      * p/default + p/owasp-top-ten + p/xss detect them too, and p/php adds no rule beyond those
        three, so the shipped default's findings are unchanged (Semgrep deduplicates: 7 = 7);
      * p/python alone detects NONE of them; p/python + p/php detects all three.

    So p/php is a FLOOR, added whenever discovery finds PHP (or could not say), that a caller's
    `semgrep_config` cannot narrow away. And because a scan can run and read no PHP at all (every
    PHP file over Semgrep's size limit, a ruleset that never loaded), the job reads what Semgrep
    says it examined -- `paths.scanned` in the JSON it writes beside the SARIF (`--json-output`,
    measured on both versions) -- and refuses a PHP scan that examined none, or loaded no PHP rule,
    as COLLECTION_FAILED (KDEC-008: a per-tool witness, never a universal hollow rule).

WHAT IT PROVES (the job's scan step, extracted AS SHIPPED, run with the real Semgrep)
    S1  the step reads discover's php answer as data (env, never interpolated into the script)
    S2  NARROWED: semgrep_config "p/python", PHP discovered -> all three seeds are reported at
        ERROR against their own files, and the count the enforce step blocks on is >= 3
    S3  the shipped default rulesets, PHP discovered -> all three seeds at ERROR (control: the
        floor changes nothing the default already found)
    S4  HOLLOW: PHP discovered, the only PHP file is over Semgrep's size limit -> exit 1,
        collection=COLLECTION_FAILED, and the error names PHP -- never a count of zero
    S5  CONTROL: no PHP (discover php=false), python only -> p/php is not requested and the PHP
        witness does not fire

    FAILS ON 75d935c (KIT_PROOF_WORKFLOW=<that revision's flagship>) at S1 (no php answer read),
    S2 (no PHP ruleset: the seeds are undetected under a narrowed config) and S4 (the hollow PHP
    scan reads as a clean zero).

    S6  the Semgrep this runs is the release the sast-semgrep job's container pins by digest (the
        `# X.Y.Z` on its image line; tests/_semgrep_pin.py). FAILS ON 7fe3d54: the job ran the
        semgrep/semgrep 1.90.0 tag while this ran 1.178.0.

    NOT PROVEN HERE: the same release, not the same packaging -- this runs Semgrep from PATH (pip
    in self-test, pinned to the job's release), the job runs the image. Lane L-SG ran the image
    itself over these seeds (2026-10-21, locally: p/php, ERROR on all three files). The registry's
    rules can change; the weekly validate-scanners semgrep-php probe is where a lost PHP rule
    surfaces for the shipped image, and this for the job.

EXIT  0 all hold, 1 any does not, 2 could not be checked (no bash, no semgrep, no registry)
"""
import json
import os
import shlex
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import _scan_step_harness as h  # noqa: E402
import prove_bootstrap_failure as pbf  # noqa: E402

import make_fixture as mf  # noqa: E402

JOB, SCAN = 'sast-semgrep', 'Semgrep scan'

# The three seeded classes, one per file so each is graded on its own: the very files
# tests/make_fixture.py writes for the consumer path, read from it rather than copied.
SEEDS = {rel: body for rel, body, _sig, _tool in mf.FILES
         if rel.startswith('php/') and rel.endswith('.php')}
EXPECT = {'php/sqli.php': 'tainted-sql-string', 'php/xss.php': 'echoed-request',
          'php/cmd.php': 'tainted-exec'}
PY_ONLY = {'app/main.py': 'def add(a, b):\n    return a + b\n'}


def default_config():
    doc = h.load()
    on = doc.get('on', doc.get(True)) or {}
    return str(((on.get('workflow_call') or {}).get('inputs') or {})
               .get('semgrep_config', {}).get('default', ''))


def error_hits(sarif):
    """-> {file suffix: set(rule leaf names)} for ERROR-level results (effective level)."""
    doc = json.load(open(sarif, encoding='utf-8'))
    got = {}
    for run_ in doc.get('runs', []):
        lv = {r['id']: (r.get('defaultConfiguration') or {}).get('level', 'warning')
              for r in (run_.get('tool', {}).get('driver', {}).get('rules') or [])}
        for res in run_.get('results', []):
            level = res.get('level') or lv.get(res.get('ruleId'), 'warning')
            if level != 'error':
                continue
            uri = res['locations'][0]['physicalLocation']['artifactLocation']['uri'].replace('\\', '/')
            got.setdefault(uri, set()).add(res.get('ruleId', '').split('.')[-1])
    return got


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
    steps = h.steps_by_name(JOB)
    if SCAN not in steps:
        print('UNKNOWN: no step %r in job %r.' % (SCAN, JOB))
        return 2
    bad = []
    step = steps[SCAN]
    env = step.get('env') or {}
    reads = [k for k, v in env.items() if 'needs.discover.outputs.php' in str(v)]
    if not reads:
        bad.append('S1 the scan step does not read discover\'s php answer (no env carries '
                   'needs.discover.outputs.php)')
    if 'needs.discover.outputs.php' in str(step.get('run') or ''):
        bad.append('S1 discover\'s php answer is interpolated into the script, not passed as data')
    needs = h.job(JOB).get('needs') or []
    if 'discover' not in needs:
        bad.append('S1 sast-semgrep does not need discover (needs=%s)' % needs)

    sb = h.Sandbox('semgrep-php-').with_bundle()
    try:
        if not h.have(bash, 'semgrep', h.path_prefix(sb.shim)):
            print('UNKNOWN: semgrep is required to RUN the step.')
            return 2
        if not h.have(bash, 'jq', h.path_prefix(sb.shim)):
            print('UNKNOWN: jq is required to RUN the step.')
            return 2
        # S6 the Semgrep run here is the release the job's container pins, by digest (lane L-SG)
        import _semgrep_pin
        image, pinned, problem = _semgrep_pin.flagship(h.WF)
        local = _semgrep_pin.path_version(bash, h.path_prefix(sb.shim))
        print('  S6 job image %s (%s); Semgrep on PATH %s' % (image, pinned, local))
        if problem:
            bad.append('S6 %s' % problem)
        if not pinned or local != pinned:
            bad.append('S6 this ran Semgrep %s, but the job runs %s (%s): the seeds would be proved '
                       'found by a release the job does not run' % (local, pinned, image))

        def scan(name, files, config, php):
            ws = sb.workspace(name, files)
            vals = {'inputs.paths': '.', 'inputs.semgrep_config': config,
                    'needs.discover.outputs.php': php,
                    'inputs.soft_fail_sast': 'false', 'inputs.advisory_mode': 'false'}
            rc, log, out, _unk = sb.run(bash, step, vals, ws, env={'SEMGREP_APP_TOKEN': ''})
            if 'Failed to download' in log or 'ConnectionError' in log:
                raise LookupError('semgrep could not fetch its registry rules')
            sarif = os.path.join(ws, 'semgrep.sarif')
            hits = error_hits(sarif) if os.path.isfile(sarif) else None
            print('  %-10s config=%-34r php=%-5s rc=%d count=%s collection=%s'
                  % (name, config, php, rc, out.get('count', '-'), out.get('collection', '-')))
            return rc, log, out, hits, ws

        def seeds_found(hits):
            missing = []
            for f, rule in sorted(EXPECT.items()):
                rules = set().union(*[v for k, v in (hits or {}).items() if k.endswith(f)] or [set()])
                if rule not in rules:
                    missing.append('%s (%s)' % (f, rule))
            return missing

        try:
            rc, log, out, hits, _ws = scan('narrowed', SEEDS, 'p/python', 'true')
            miss = seeds_found(hits)
            if miss:
                bad.append('S2 a caller narrowing semgrep_config to p/python loses PHP: not reported '
                           'at ERROR -- %s' % ', '.join(miss))
            if out.get('count', '').isdigit() and int(out['count']) < 3:
                bad.append('S2 the blocking count is %s, below the three seeded ERROR findings'
                           % out['count'])
            cfg = default_config()
            rc, log, out, hits, _ws = scan('default', SEEDS, cfg, 'true')
            miss = seeds_found(hits)
            if miss:
                bad.append('S3 the shipped default (%s) misses PHP seeds: %s' % (cfg, ', '.join(miss)))
            if sorted(SEEDS) != sorted(EXPECT):
                bad.append('the generator\'s PHP seeds are %s, not the three this grades'
                           % sorted(SEEDS))
            big = {'web/huge.php': "<?php\n" + "$a = 1;\n" * 200000}
            rc, log, out, hits, _ws = scan('hollow', dict(big, **PY_ONLY), cfg, 'true')
            if rc == 0 or out.get('collection') != 'COLLECTION_FAILED' or 'PHP' not in log:
                bad.append('S4 a PHP scan that examined no PHP read as a completed scan (rc %d, '
                           'collection %r)' % (rc, out.get('collection')))
            argv_log = os.path.join(sb.root, 'argv.txt').replace(os.sep, '/')
            real = subprocess.run([bash, '-c', 'command -v semgrep'], capture_output=True, text=True,
                                  env=dict(os.environ, PATH=h.path_prefix(sb.shim) + os.pathsep
                                           + os.environ['PATH'])).stdout.strip()
            wrap = os.path.join(sb.root, 'wrap')
            h.write(os.path.join(wrap, 'semgrep'),
                    '#!/usr/bin/env bash\nprintf "%%s\\n" "$*" >> "%s"\nexec "%s" "$@"\n'
                    % (argv_log, real))
            os.chmod(os.path.join(wrap, 'semgrep'), 0o755)
            ws = sb.workspace('nophp', PY_ONLY)
            vals = {'inputs.paths': '.', 'inputs.semgrep_config': 'p/python',
                    'needs.discover.outputs.php': 'false',
                    'inputs.soft_fail_sast': 'false', 'inputs.advisory_mode': 'false'}
            rc, log, out, _unk = sb.run(bash, step, vals, ws, extra_path=wrap,
                                        env={'SEMGREP_APP_TOKEN': ''})
            argv = open(argv_log, encoding='utf-8').read() if os.path.exists(argv_log) else ''
            toks = shlex.split(argv.splitlines()[0]) if argv.strip() else []
            loaded = [toks[i + 1] for i, t in enumerate(toks[:-1]) if t == '--config']
            print('  %-10s config=%-34r php=%-5s rc=%d --config %s'
                  % ('nophp', 'p/python', 'false', rc, loaded))
            if 'p/php' in loaded or out.get('collection') == 'COLLECTION_FAILED' or rc != 0:
                bad.append('S5 CONTROL: no PHP, yet p/php was requested or the step refused '
                           '(rc %d, --config %s)' % (rc, loaded))
        except LookupError as e:
            print('UNKNOWN: %s.' % e)
            return 2
    finally:
        sb.close()
    for b in bad:
        print('FAIL %s' % b)
    if bad:
        return 1
    print('PASS: PHP seeds (SQL injection, XSS, command injection) are reported at ERROR under a')
    print('      narrowed and the default semgrep_config; a PHP scan that examined no PHP is')
    print('      COLLECTION_FAILED; without PHP nothing PHP-specific is requested.')
    return 0


if __name__ == '__main__':
    sys.exit(main())

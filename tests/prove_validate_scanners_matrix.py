#!/usr/bin/env python3
"""The weekly scanner validation can fail: every probe is expected, and a broken one fails the run.

WHY THIS EXISTS (completion ledger L76; the three items W4K-116 left open)

    validate-scanners.yml is the kit's only behavioural check of the scanners themselves. After
    W4K-116 fixed the versions it probed and its negative control, three things still kept it from
    ever going red:

      matrix     the probe matrix job was `continue-on-error: true`, so a probe that exited 1 (a
                 report that was never produced, a parse failure) still left the run green
      verdict    the capability-matrix step rendered whatever result files arrived, swallowed any it
                 could not parse, and could not exit non-zero: a probe that died before writing a
                 result simply vanished from the table, and a probe that ran and detected nothing
                 was a red cross in a green job
      container  the flagship's sast-semgrep job runs the semgrep/semgrep:1.90.0 CONTAINER, and no
                 probe ran that image -- the weekly green said nothing about the scanner that job
                 actually uses

WHAT IT PROVES
    M1  the scanners job is not continue-on-error, and keeps fail-fast off so one leg cannot hide
        another
    M2  a `semgrep-container` probe runs the exact image the flagship's sast-semgrep job pins --
        a tag or, since lane L-SG, a digest; a flagship whose image this cannot read fails, so the
        check never passes by matching nothing
    M3  the matrix step's roster (EXPECTED) equals the probe matrix's ids
    M4  the matrix step itself, run as shipped against seeded probe results:
          all present and proven                         -> rc 0
          a probe's result file absent                   -> rc 1 (UNKNOWN, named)
          a result file that does not parse              -> rc 1
          a probe that executed and detected nothing     -> rc 1
          the accepted, dated depcheck gap, unexpired    -> rc 0 and reported as accepted
    M5  the depcheck leg (and only it) receives the repository's NVD_API_KEY, updates the NVD
        database with it, has a longer time limit for that download, and reports DETECT only
        for a SARIF that holds a result -- never for the file merely existing
    M6  the depcheck leg builds its NVD database the way reusable-nvd-cve.yml does (2026-10-21,
        run 39668863606: the keyed leg sat silently for its whole 45 minutes, updating and
        scanning in ONE call, and was cancelled with nothing kept -- while the real scan's
        --updateonly cold updates had finished in 32 min 03 s and 9 min 17 s, runs 32190300370
        and 32382255986):
          restore /tmp/nvd-data from cache, a COMPLETE copy before a PARTIAL one, in the probe's
            own namespace (never the real scan's nvd-data-*), keyed by the Dependency-Check version
          an --updateonly --data /tmp/nvd-data phase with the key, before the scan, that runs the
            update in the background under its own budget and prints a heartbeat every 60 s
          save COMPLETE only on a finished update; save PARTIAL under always() so a budget expiry,
            a timeout or a cancellation still keeps the downloaded work for the next run to resume
          scan with --data /tmp/nvd-data --noupdate against that database
          limits from those measurements: an update budget of 1.5-2x the WORST cold update, the
            step limit outside it, the job limit outside that; every other leg keeps 15

    M7  a `semgrep-php` probe (lane L-SG; KDEC-016) runs that same image with --config p/php over
        fixture/php, keeps the absent-report and parse checks, and sets DETECT=ok only when the
        ERROR-level results name at least the three seeded PHP files (SQL injection, XSS, command
        injection). FAILS ON 7fe3d54: there was no semgrep-php probe, so nothing weekly showed the
        shipped image still finds a PHP seed.
    M8  a push never cancels a dispatched or scheduled run (lane L-SG), in validate-scanners.yml and
        probe-scanner-corpora.yml: the concurrency group names github.event_name, and
        cancel-in-progress, evaluated per event, is true for push and pull_request and false for
        workflow_dispatch and schedule. FAILS ON 7fe3d54: one group per ref with
        cancel-in-progress: true -- later pushes cancelled dispatch runs 39681385412 and
        39688249062, and the depcheck leg's cold NVD update alone can need 32+ minutes.
    M9  the probe tests what the real scan ships (lane L-NV, 2026-10-21): the depcheck leg installs
        the SAME Dependency-Check version, with the SAME sha256, as reusable-nvd-cve.yml's
        dependency_check_version / dependency_check_sha256 defaults; that digest is the one
        PUBLISHED for that version (PUBLISHED_SHA256 below, with its source); both download from
        the canonical dependency-check/DependencyCheck repository; and both build the database from
        the SAME datafeed (the probe's `feed=` equals the nvd_datafeed_url default, passed as
        --nvdDatafeed by the probe's update and by the real scan's update AND scan steps).
        FAILS ON 09a22a8: no datafeed anywhere -- both built the database from the NVD API, which
        now serves ~10-40 kB/s per response, so cold builds sat at 10,000-20,000 of ~413k records
        for 35+ minutes (runs 39688249062, 39701225219) -- and both downloaded from
        jeremylong/DependencyCheck, a separate repository whose releases stop at 12.1.0.
    M10 the depcheck leg's update step, RUN AS SHIPPED under GitHub's `bash -e` with a shimmed
        Dependency-Check, still reports when the update does not finish: the step completes,
        prints its warnings, records complete only on success, and puts the stall evidence (last
        progress line, retried-request count, HTTP statuses) into the database-state env value -- the
        probe's NOTE -- and the step summary, in a character set the JSON result can carry; the
        key reaches the tool as ONE argument. FAILS ON 09a22a8: `wait "$pid"; rc=$?` ended the step
        under `bash -e` the moment the update exited non-zero (run 39701225219: "exit code 124"
        right after the last heartbeat), so no evidence was ever printed or recorded.
    M11 the two semgrep container legs (semgrep-php, semgrep-container), RUN AS SHIPPED with a
        shimmed `docker`: when the registry refuses the image, the leg still ends COLLECTION_FAILED
        AND the refusal reaches the log; when one pull is refused and the next succeeds, the scan
        runs and detects. FAILS ON 109cff8: Release 3 candidate run 39801652917 -- the semgrep-php
        docker run ended in under 0.3 s (the sibling leg on the same image took 17 s) with no
        report, and `>/dev/null 2>&1` had discarded the only evidence of why.
    M12 validate-scanners.yml's push trigger is `branches: [main]` with its paths filter, and the
        weekly schedule and workflow_dispatch stay (lane L-DOC, cost). FAILS ON 19b5e1d: push had
        paths only, so any branch push touching tests/** ran the probe on metered private minutes
        (18 private runs on 2026-10-22); the free public mirror runs it on the release candidate.

EXIT  0 all hold   1 any does not   2 could not be checked
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
VALIDATE = os.path.join(ROOT, '.github', 'workflows', 'validate-scanners.yml')
FLAGSHIP = os.path.join(ROOT, '.github', 'workflows', 'reusable-security.yml')
STEP = 'Render matrix and name what is MISSING'


def _shipped(path):
    """The flagship's text plus the scanner composites it calls through `$/` (ledger L64): a
    scanner's commands live there now, and reading the workflow alone would count fewer sites."""
    sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
    import _composite_expand
    return _composite_expand.shipped_text(path)


def render_script(doc):
    job = (doc.get('jobs') or {}).get('capability-matrix') or {}
    for s in job.get('steps') or []:
        if s.get('name') == STEP:
            body = s.get('run') or ''
            m = re.search(r"python - <<'PY'\n(.*?)\nPY\s*$", body, re.S)
            return m.group(1) if m else None
    return None


def run_render(script, results, work):
    probes = os.path.join(work, 'probes')
    os.makedirs(probes)
    for pid, data in results.items():
        with open(os.path.join(probes, pid + '.json'), 'w', encoding='utf-8') as fh:
            fh.write(data if isinstance(data, str) else json.dumps(data))
    summary = os.path.join(work, 'summary.md')
    open(summary, 'w').close()
    p = subprocess.run([sys.executable, '-c', script], cwd=work, capture_output=True, text=True,
                       encoding='utf-8', errors='replace',
                       env=dict(os.environ, GITHUB_STEP_SUMMARY=summary, PYTHONUTF8='1'))
    return p.returncode, p.stdout + p.stderr


PROBE_CORPORA = os.path.join(ROOT, '.github', 'workflows', 'probe-scanner-corpora.yml')
SUPERSEDING = ('push', 'pull_request')
NEVER_CANCELLED = ('workflow_dispatch', 'schedule')


def cancels(value, event):
    """-> True/False: what `cancel-in-progress: value` evaluates to for this event, or None when
    the expression is anything but ||-joined, &&-joined `github.event_name ==/!= 'x'` terms."""
    if isinstance(value, bool):
        return value
    m = re.fullmatch(r'\s*\$\{\{(.*)\}\}\s*', str(value), re.S)
    if not m:
        return None
    any_true = False
    for disjunct in m.group(1).split('||'):
        all_true = True
        for term in disjunct.split('&&'):
            t = re.fullmatch(r"\s*\(?\s*github\.event_name\s*(==|!=)\s*'([a-z_]+)'\s*\)?\s*", term)
            if not t:
                return None
            all_true = all_true and ((event == t.group(2)) == (t.group(1) == '=='))
        any_true = any_true or all_true
    return any_true


def check_m8(path):
    import yaml
    doc = yaml.safe_load(io.open(path, encoding='utf-8')) or {}
    name = os.path.basename(path)
    conc = doc.get('concurrency') or {}
    bad = []
    if not isinstance(conc, dict):
        return ['M8 %s: concurrency is not a mapping (%r)' % (name, conc)]
    group = str(conc.get('group') or '')
    got = {ev: cancels(conc.get('cancel-in-progress', False), ev)
           for ev in SUPERSEDING + NEVER_CANCELLED}
    print('  M8 %s group %r cancels %s' % (name, group, got))
    if 'github.event_name' not in group:
        bad.append('M8 %s: the concurrency group does not name github.event_name, so a push shares '
                   'a group with a dispatched or scheduled run' % name)
    for ev in NEVER_CANCELLED:
        if got[ev] is not False:
            bad.append('M8 %s: cancel-in-progress is %r for %s -- a later run cancels it (runs '
                       '39681385412, 39688249062 were cancelled by pushes)' % (name, got[ev], ev))
    for ev in SUPERSEDING:
        if got[ev] is not True:
            bad.append('M8 %s: cancel-in-progress is %r for %s -- an obsolete push run would '
                       'finish at full cost' % (name, got[ev], ev))
    return bad


# M12 (lane L-DOC, 2026-10-23): the probe's push trigger is the default branch only. The private
# repository pays for every Actions minute, and a push to any branch touching tests/** started the
# whole probe (18 private runs on 2026-10-22 alone). Branch validation is the free public mirror's
# run on the release candidate, or a dispatch. Schedule, dispatch and the paths filter stay.
M12_PATHS = ('.github/workflows/reusable-security.yml', '.github/actions/**', 'tests/**')


def check_m12(doc):
    on = doc.get('on') or doc.get(True) or {}
    bad = []
    if not isinstance(on, dict):
        return ['M12 validate-scanners.yml `on:` is not a mapping (%r)' % (on,)]
    push = on.get('push')
    print('  M12 push=%r schedule=%s dispatch=%s pull_request=%s'
          % (push, 'schedule' in on, 'workflow_dispatch' in on, 'pull_request' in on))
    if not isinstance(push, dict) or push.get('branches') != ['main']:
        bad.append('M12 push is not limited to branches [main]: every branch push touching the paths '
                   'runs the probe on metered private minutes (%r)' % (push,))
    else:
        paths = push.get('paths') or []
        missing = [x for x in M12_PATHS if x not in paths]
        if missing:
            bad.append('M12 the push paths filter lost %s' % missing)
    if 'pull_request' in on or 'pull_request_target' in on:
        bad.append('M12 a pull_request trigger runs the probe on every PR branch')
    if not on.get('schedule'):
        bad.append('M12 the weekly schedule is gone')
    if 'workflow_dispatch' not in on:
        bad.append('M12 workflow_dispatch is gone: a branch could not be validated on demand')
    return bad


REAL_SCAN_NS = 'nvd-data-'          # reusable-nvd-cve.yml's cache namespace
# The real scan's keyed COLD updates, Dependency-Check 12.1.0, --updateonly --data /tmp/nvd-data,
# no cache restored: 32 min 03 s (hosted run 32190300370, 2026-08-18) and 9 min 17 s (run
# 32382255986, 2026-08-20). The WORST measured is the sizing base.
MEASURED_COLD_MIN = 32.05


def _uses(step, action):
    return str(step.get('uses') or '').startswith(action + '@')


def _is_depcheck_only(step):
    return "matrix.probe.id == 'depcheck'" in str(step.get('if') or '')


def check_m6(job, steps, branch, timeout):
    """The depcheck leg's NVD database design; returns the failures."""
    bad = []
    idx = {id(s): i for i, s in enumerate(steps)}
    probe = next((s for s in steps if s.get('id') == 'probe'), None)
    p_at = idx[id(probe)] if probe is not None else len(steps)

    def nvd(s):
        return str(((s.get('with') or {}).get('path')) or '').strip() == '/tmp/nvd-data'

    restore = [s for s in steps if _uses(s, 'actions/cache/restore') and nvd(s)]
    saves = [s for s in steps if _uses(s, 'actions/cache/save') and nvd(s)]
    upd = next((s for s in steps if s.get('id') == 'nvd_update'), None)
    print('  M6 restore %d, update %s, save %d' % (len(restore), upd is not None, len(saves)))

    if not restore:
        bad.append('M6 no actions/cache/restore of /tmp/nvd-data: every run builds the NVD '
                   'database from scratch (run 39668863606 ran out of time doing exactly that)')
    else:
        r = restore[0]
        w = r.get('with') or {}
        keys = [k.strip() for k in str(w.get('restore-keys') or '').splitlines() if k.strip()]
        allk = [str(w.get('key') or '')] + keys
        if not _is_depcheck_only(r):
            bad.append('M6 the NVD cache restore is not limited to the depcheck leg')
        if idx[id(r)] > p_at:
            bad.append('M6 the NVD cache is restored after the scan that needs it')
        good = [i for i, k in enumerate(keys) if '-good-' in k]
        part = [i for i, k in enumerate(keys) if '-partial-' in k]
        if not good or not part or min(good) > min(part):
            bad.append('M6 restore-keys must prefer a COMPLETE (-good-) copy, then a PARTIAL one: %s'
                       % keys)
        if any(k.startswith(REAL_SCAN_NS) for k in allk):
            bad.append("M6 the probe restores the real scan's %s* cache: the probe would validate a "
                       'database the system under test built' % REAL_SCAN_NS)
        inst = next((str(s.get('run') or '') for s in steps
                     if 'dependency-check-${VER}-release.zip' in str(s.get('run') or '')), '')
        vm = re.search(r'\bVER=([0-9][0-9.]*)', inst)
        tag = 'dc' + vm.group(1) if vm else None
        allkeys = allk + [str((s.get('with') or {}).get('key') or '') for s in saves]
        if tag is None or any(tag not in k for k in allkeys):
            bad.append('M6 every NVD cache key must name the installed Dependency-Check version '
                       '(%s): a bump would otherwise restore a database another release wrote'
                       % tag)

    if upd is None:
        bad.append('M6 no nvd_update step: no --updateonly phase before the scan')
    else:
        run = str(upd.get('run') or '')
        if not _is_depcheck_only(upd):
            bad.append('M6 the NVD update step is not limited to the depcheck leg')
        if probe is not None and idx[id(upd)] > p_at:
            bad.append('M6 the NVD update runs after the scan')
        for need in ('--updateonly', '--data /tmp/nvd-data', '--nvdApiKey'):
            if need not in run:
                bad.append('M6 the NVD update does not pass %s' % need)
        # HEARTBEAT: the update runs in the background and the step prints elapsed time and the
        # last [INFO] line at least every 60 s. Run 39668863606 sent everything to dc.log and
        # showed nothing for 45 minutes.
        if not re.search(r'&\s*\n\s*\w+=\$!', run):
            bad.append('M6 the NVD update is not backgrounded: no heartbeat can be printed')
        # Inside the wait loop itself, as executed lines -- not a word in a comment.
        loop = re.search(r'\n\s*while kill -0 "\$pid"[^\n]*; do\n(.*?)\n\s*done\n', run, re.S)
        body = '\n'.join(l for l in (loop.group(1) if loop else '').splitlines()
                         if not l.strip().startswith('#'))
        if not (re.search(r'seq 1 60\b|sleep 60\b', body)
                and re.search(r'echo[^\n]*elapsed', body) and '[INFO]' in body):
            bad.append('M6 no 60-second heartbeat (elapsed time + last [INFO] line) in the loop that '
                       'waits on the update')
        # Its own budget, inside the job's: the update must END in time for the saves to run in
        # the ordinary path, not only in the cancellation path.
        if not re.search(r'\btimeout\b[^\n]*--signal=TERM', run):
            bad.append('M6 the NVD update has no in-script budget (timeout --signal=TERM)')
        if 'complete=true' not in run:
            bad.append('M6 the NVD update never reports complete=true: the saves cannot tell good '
                       'from partial')
        if not upd.get('timeout-minutes'):
            bad.append('M6 the NVD update step has no step timeout-minutes backstop')

    good_s = [s for s in saves if '-good-' in str((s.get('with') or {}).get('key') or '')]
    part_s = [s for s in saves if '-partial-' in str((s.get('with') or {}).get('key') or '')]
    if not good_s:
        bad.append('M6 no save of a COMPLETE NVD database')
    for s in good_s:
        cond = str(s.get('if') or '')
        if "steps.nvd_update.outputs.complete == 'true'" not in cond or 'always()' not in cond:
            bad.append('M6 the COMPLETE save must be always() AND complete == true: %r' % cond)
    if not part_s:
        bad.append('M6 no PARTIAL save: a cancelled or timed-out update throws its download away')
    for s in part_s:
        cond = str(s.get('if') or '')
        if 'always()' not in cond or "steps.nvd_update.outputs.complete != 'true'" not in cond:
            bad.append('M6 the PARTIAL save must run under always() when the update did not '
                       'complete (cancelled, timed out, budget spent): %r' % cond)
    for s in saves:
        key = str((s.get('with') or {}).get('key') or '')
        if key.startswith(REAL_SCAN_NS):
            bad.append("M6 the probe saves into the real scan's %s* namespace" % REAL_SCAN_NS)
        if 'run_attempt' not in key:
            bad.append('M6 save key %r lacks github.run_attempt: a re-run cannot save' % key)
        if probe is not None and idx[id(s)] > p_at:
            bad.append('M6 an NVD save runs after the scan; a failing scan must not cost the database')
        if not _is_depcheck_only(s):
            bad.append('M6 an NVD cache save is not limited to the depcheck leg')

    # The scan command itself (continuation lines joined), not a comment that mentions the flags.
    cmd = re.search(r'\n\s*/opt/dependency-check/bin/dependency-check\.sh((?:[^\n]*\\\n)*[^\n]*)',
                    '\n' + branch)
    cmd = cmd.group(1) if cmd else ''
    if '--data /tmp/nvd-data' not in cmd or '--noupdate' not in cmd:
        bad.append('M6 the depcheck scan does not use the warm database (--data /tmp/nvd-data '
                   '--noupdate)')
    # LIMITS FROM EVIDENCE: the in-script budget fits the measured cold update about three times
    # over; the step limit sits outside the budget; the job limit outside the step limit with room
    # for install, restore, save and scan. Not "as long as possible": a limit that only grows
    # pays to hide a difference nobody explained (run 39668863606).
    m = re.search(r"'depcheck'\s*&&\s*(\d+)\s*\|\|\s*(\d+)", timeout)
    bm = re.search(r'\bbudget_s=(\d+)', str((upd or {}).get('run') or ''))
    st = (upd or {}).get('timeout-minutes')
    if not m or not bm or not isinstance(st, int):
        bad.append('M6 cannot read the job limit %r, the update budget (budget_s) or the update '
                   'step limit %r' % (timeout, st))
    else:
        dc, other = int(m.group(1)), int(m.group(2))
        budget = int(bm.group(1)) / 60.0
        print('  M6 limits: update budget %.0f min < step %d < job %d; other legs %d'
              % (budget, st, dc, other))
        if budget < 1.5 * MEASURED_COLD_MIN:
            bad.append('M6 update budget %.0f min is under 1.5x the worst measured %.1f-min cold '
                       'update' % (budget, MEASURED_COLD_MIN))
        if budget > 2 * MEASURED_COLD_MIN:
            bad.append('M6 update budget %.0f min is over 2x the worst measured cold update: sized '
                       'to hide a difference, not from evidence' % budget)
        if not budget + 2 <= st:
            bad.append('M6 the update step limit %d must sit outside the %.0f-min budget (+2 for '
                       'the TERM-then-KILL grace)' % (st, budget))
        if not st + 5 <= dc:
            bad.append('M6 the job limit %d must leave >= 5 min past the update step limit %d for '
                       'the saves and the scan' % (dc, st))
        if other != 15:
            bad.append('M6 the other legs must keep 15 minutes, not %d' % other)
    return bad


NVD_WF = os.path.join(ROOT, '.github', 'workflows', 'reusable-nvd-cve.yml')
CANONICAL_RELEASES = 'https://github.com/dependency-check/DependencyCheck/releases/download/'
# The digest PUBLISHED for each version this kit may pin, and where it was published. A version
# whose digest is not here fails M9: a digest computed from whatever a URL served once is a
# record of that download, not of the release.
PUBLISHED_SHA256 = {
    '12.2.2': ('bf07fefd81af3094c5f6850423b014df44db62ce2dbad0f79079a90df675e44a',
               'Maven Central dependency-check-cli-12.2.2-release.zip.sha256 (equal to the GitHub '
               'asset; asset PGP-signed by 259A55407DD6C00299E6607EFFDE55BE73A2D1ED), 2026-10-21'),
}


def _input_default(doc, name):
    on = doc.get('on') or doc.get(True) or {}
    inputs = ((on.get('workflow_call') or {}).get('inputs') or {})
    return str((inputs.get(name) or {}).get('default', '') or '')


def check_m9(steps, upd):
    """The probe installs and feeds Dependency-Check exactly as the real scan's defaults do."""
    import yaml
    bad = []
    nvd = yaml.safe_load(io.open(NVD_WF, encoding='utf-8')) or {}
    real_ver = _input_default(nvd, 'dependency_check_version')
    real_sha = _input_default(nvd, 'dependency_check_sha256')
    real_feed = _input_default(nvd, 'nvd_datafeed_url')
    inst = next((str(s.get('run') or '') for s in steps
                 if 'dependency-check-${VER}-release.zip' in str(s.get('run') or '')), '')
    vm = re.search(r'\bVER=([0-9][0-9.]*)', inst)
    sm = re.search(r'echo "([0-9a-f]{64})  dependency-check-\$\{VER\}-release\.zip"', inst)
    probe_ver = vm.group(1) if vm else None
    probe_sha = sm.group(1) if sm else None
    run = str((upd or {}).get('run') or '')
    fm = re.search(r'^\s*feed=(\S+)\s*$', run, re.M)
    probe_feed = fm.group(1).strip('"\'') if fm else None
    print('  M9 probe %s %s feed %s; real scan %s %s feed %s'
          % (probe_ver, (probe_sha or '-')[:12], probe_feed, real_ver, real_sha[:12], real_feed))
    if probe_ver is None or probe_ver != real_ver:
        bad.append('M9 the probe installs Dependency-Check %s and the real scan ships %s: the probe '
                   'would prove a different release' % (probe_ver, real_ver or '<no default>'))
    if probe_sha is None or probe_sha != real_sha:
        bad.append('M9 the probe pins sha256 %s and the real scan %s for the same release'
                   % (probe_sha, real_sha or '<no default>'))
    pub = PUBLISHED_SHA256.get(real_ver)
    if pub is None:
        bad.append('M9 no published digest is recorded for %s (PUBLISHED_SHA256): the pin is not '
                   'checked against the release' % real_ver)
    elif real_sha != pub[0]:
        bad.append('M9 the shipped digest for %s is %s, not the published %s (%s)'
                   % (real_ver, real_sha, pub[0], pub[1]))
    real_inst = str((H_step(NVD_WF, 'nvd-cve-scan', 'Install OWASP Dependency-Check') or {})
                    .get('run') or '')
    for label, text in (('probe', inst), ('real scan', real_inst)):
        urls = re.findall(r'https://github\.com/[^"\s]*releases/download/', text)
        if not urls or any(u != CANONICAL_RELEASES for u in urls):
            bad.append('M9 the %s downloads from %s, not the canonical %s (jeremylong/DependencyCheck '
                       'is a separate repository whose releases stop at 12.1.0)'
                       % (label, urls or '<no release URL>', CANONICAL_RELEASES))
    if not real_feed:
        bad.append('M9 reusable-nvd-cve.yml has no nvd_datafeed_url default: a cold build goes to '
                   'the NVD API, which cannot finish it at its 2026-10 throughput')
    if probe_feed is None or probe_feed != real_feed:
        bad.append('M9 the probe builds its database from %s and the real scan from %s'
                   % (probe_feed, real_feed or '<the NVD API>'))
    if not re.search(r'--nvdDatafeed "\$feed"', run):
        bad.append('M9 the probe update does not pass --nvdDatafeed "$feed"')
    for key in ('nvd_update', 'dc_run'):
        st = H_step(NVD_WF, 'nvd-cve-scan', key) or {}
        env = str((st.get('env') or {}).get('W_NVD_DATAFEED', ''))
        if 'inputs.nvd_datafeed_url' not in env or \
                '--nvdDatafeed "$W_NVD_DATAFEED"' not in str(st.get('run') or ''):
            bad.append('M9 the real scan step %s does not pass inputs.nvd_datafeed_url as '
                       '--nvdDatafeed (env W_NVD_DATAFEED): it would update from the NVD API' % key)
    return bad


def H_step(path, job, key):
    sys.path.insert(0, HERE)
    import _step_harness as H
    return H.step(os.path.relpath(path, ROOT), job, key)


M10_KEY = 'm10-fake-key-0000-0000-000000000000'   # 36 characters, inert
M10_STALL = '\n'.join((
    '[INFO] Checking for updates',
    '[INFO] NVD API has 412,851 records in this update',
    '[INFO] Downloaded 10,000/412,851 (2%)',
    '[WARN] Retrying request /rest/json/cves/2.0?resultsPerPage=2000&startIndex=20000 : 2nd time',
    '[WARN] Retrying request /rest/json/cves/2.0?resultsPerPage=2000&startIndex=22000 : 3rd time',
    '[INFO] Downloaded 20,000/412,851 (5%)',
    '[ERROR] NvdApiException: NVD Returned Status Code: 503 "quoted" \\ back',
))


def check_m10():
    """Run the depcheck leg's update step as shipped; -> (failures, could_not_run_reason)."""
    sys.path.insert(0, HERE)
    import _step_harness as H
    bash, why = H.usable_bash()
    if not bash:
        return [], 'no usable bash (%s)' % why
    upd = H.step(os.path.relpath(VALIDATE, ROOT), 'scanners', 'nvd_update')
    if upd is None:
        return ['M10 no nvd_update step to run'], None
    # The env name the step records its database state under, read from the step itself (the
    # line that records success), so this proof names no vocabulary of its own.
    sm = re.search(r'echo "([A-Za-z_]+)=complete: ', str(upd.get('run') or ''))
    if not sm:
        return ['M10 the update step records no database state on success'], None
    state_var = sm.group(1)
    bad = []
    tmp = tempfile.mkdtemp(prefix='vs-m10-')
    try:
        for name, rc, want_complete in (('stalled-budget-spent', 124, False),
                                        ('stalled-exit-1', 1, False),
                                        ('complete', 0, True)):
            ws = os.path.join(tmp, name)
            os.makedirs(ws)
            fwd = ws.replace('\\', '/')
            s = dict(upd)
            s['run'] = (upd.get('run') or '').replace('/opt/', fwd + '/opt/') \
                .replace('/tmp/nvd-data', fwd + '/nvd-data')
            io.open(os.path.join(ws, 'stall.txt'), 'w', encoding='utf-8',
                    newline='\n').write(M10_STALL + '\n')
            H.shim(os.path.join(ws, 'opt', 'dependency-check', 'bin'), 'dependency-check.sh',
                   'for a in "$@"; do printf \'%s\\n\' "$a"; done > "$M10_ARGS"\n'
                   'cat "$M10_LINES"\nexit "$M10_RC"')
            ctx = {'secrets.NVD_API_KEY': M10_KEY, 'steps.nvd_cache.outcome': 'success',
                   'steps.nvd_cache.outputs.cache-matched-key': ''}
            r = H.run(bash, s, ctx, ws, None, {
                'M10_ARGS': os.path.join(ws, 'args.txt'), 'M10_RC': str(rc),
                'M10_LINES': os.path.join(ws, 'stall.txt')})
            state = r['env'].get(state_var, '')
            args_path = os.path.join(ws, 'args.txt')
            args = io.open(args_path, encoding='utf-8').read().splitlines() \
                if os.path.exists(args_path) else []
            complete = r['outputs'].get('complete') == 'true'
            print('  M10 %-22s step rc=%d complete=%s state=%r'
                  % (name, r['rc'], complete, state[:90]))
            if r['rc'] != 0:
                bad.append('M10 %s: the update step itself exited %d -- under bash -e it died before '
                           'reporting anything:\n%s' % (name, r['rc'], r['log'][-400:]))
            if complete != want_complete:
                bad.append('M10 %s: complete=%s, want %s' % (name, complete, want_complete))
            if M10_KEY not in args or '--nvdApiKey' not in args or \
                    args[args.index('--nvdApiKey') + 1] != M10_KEY:
                bad.append('M10 %s: the key did not reach Dependency-Check as ONE argument after '
                           '--nvdApiKey: %r' % (name, [a for a in args if a != M10_KEY]))
            if '--nvdDatafeed' not in args or not args[args.index('--nvdDatafeed') + 1].startswith(
                    'https://'):
                bad.append('M10 %s: --nvdDatafeed <url> did not reach Dependency-Check' % name)
            if M10_KEY in r['log'] or M10_KEY in state or M10_KEY in r['summary']:
                bad.append('M10 %s: the key VALUE was printed or recorded' % name)
            if want_complete:
                if not state.startswith('complete'):
                    bad.append('M10 %s: %s=%r, want complete...' % (name, state_var, state))
                continue
            if '--- warnings and errors ---' not in r['log']:
                bad.append('M10 %s: the warnings and errors were never printed' % name)
            for need in ('PARTIAL', 'Downloaded 20,000/412,851', 'retried requests: 2',
                         'Status Code: 503'):
                if need not in state:
                    bad.append('M10 %s: %s (the probe NOTE) lacks %r: %r'
                               % (name, state_var, need, state))
                if need not in r['summary'] and need != 'PARTIAL':
                    bad.append('M10 %s: the step summary lacks %r' % (name, need))
            if '"' in state or '\\' in state:
                bad.append('M10 %s: %s carries a quote or backslash, which would break the '
                           'JSON result the NOTE is written into: %r' % (name, state_var, state))
    finally:
        shutil.rmtree(tmp, ignore_errors=True)
    return bad, None


M11_REFUSAL = 'm11-shim: toomanyrequests: You have reached your pull rate limit'
M11_OUT = ('{"results": [' + ', '.join(
    '{"path": "fixture/php/%s.php", "extra": {"severity": "ERROR"}}' % n
    for n in ('sqli', 'xss', 'cmd')) + '], "errors": []}')


def check_m11():
    """Run the Probe step's two semgrep container legs as shipped with `docker` shimmed;
    -> (failures, could_not_run_reason)."""
    sys.path.insert(0, HERE)
    import _step_harness as H
    bash, why = H.usable_bash()
    if not bash:
        return [], 'no usable bash (%s)' % why
    probe = H.step(os.path.relpath(VALIDATE, ROOT), 'scanners', 'probe')
    if probe is None:
        return ['M11 no probe step to run'], None
    # The leg is selected by the step's own env (the one key it declares), so this proof names no
    # vocabulary of its own.
    id_vars = [k for k, v in (probe.get('env') or {}).items() if 'matrix.probe.id' in str(v)]
    if len(id_vars) != 1:
        return ['M11 the probe step does not take the probe id from one env value: %s' % id_vars], None
    bad = []
    tmp = tempfile.mkdtemp(prefix='vs-m11-')
    try:
        # refused: every pull and run is refused the way a registry refuses (fast, on stderr).
        # flaky:   the first pull is refused, the second succeeds, and the scan writes a report.
        for pid in ('semgrep-php', 'semgrep-container'):
            for name, fail_pulls in (('refused', 99), ('flaky', 1)):
                ws = os.path.join(tmp, pid + '-' + name)
                shims = os.path.join(ws, '.shims')
                os.makedirs(ws)
                H.shim(shims, 'docker', '\n'.join((
                    'n=$(cat "$M11_COUNT" 2>/dev/null || echo 0)',
                    'if [ "$1" = pull ]; then',
                    '  n=$((n + 1)); echo "$n" > "$M11_COUNT"',
                    '  if [ "$n" -le "$M11_FAIL_PULLS" ]; then echo "$M11_REFUSAL" >&2; exit 1; fi',
                    '  echo pulled; exit 0',
                    'fi',
                    'if [ "$n" -le "$M11_FAIL_PULLS" ]; then echo "$M11_REFUSAL" >&2; exit 125; fi',
                    'cat "$M11_OUT" > out.json; echo "scan ran"; exit 1')))
                # The pull backoff is real time on a runner; here it is a no-op.
                H.shim(shims, 'sleep', 'exit 0')
                io.open(os.path.join(ws, 'report.json'), 'w', encoding='utf-8',
                        newline='\n').write(M11_OUT)
                r = H.run(bash, probe, {'matrix.probe.id': pid}, ws, shims, {
                    id_vars[0]: pid, 'M11_FAIL_PULLS': str(fail_pulls),
                    'M11_COUNT': os.path.join(ws, 'count.txt'),
                    'M11_OUT': os.path.join(ws, 'report.json'), 'M11_REFUSAL': M11_REFUSAL})
                out = r['outputs']
                print('  M11 %-17s %-7s rc=%d exec=%s detect=%s collection=%s'
                      % (pid, name, r['rc'], out.get('exec'), out.get('detect'),
                         out.get('collection', '')))
                if name == 'refused':
                    if r['rc'] == 0 or out.get('collection') != 'COLLECTION_FAILED':
                        bad.append('M11 %s refused: an image that never arrived did not end as '
                                   'COLLECTION_FAILED (rc=%d)' % (pid, r['rc']))
                    if 'toomanyrequests' not in r['log']:
                        bad.append("M11 %s refused: the registry's refusal never reached the log -- "
                                   'the step discarded the only evidence of why no report was '
                                   'produced (run 39801652917)' % pid)
                elif r['rc'] != 0 or out.get('detect') != 'ok':
                    bad.append('M11 %s flaky: one refused pull, then a good one, did not reach a '
                               'detecting scan (rc=%d detect=%s):\n%s'
                               % (pid, r['rc'], out.get('detect'), r['log'][-400:]))
    finally:
        shutil.rmtree(tmp, ignore_errors=True)
    return bad, None


def main():
    try:
        import yaml
    except ImportError:
        print('UNKNOWN: PyYAML unavailable.')
        return 2
    bad = []
    doc = yaml.safe_load(io.open(VALIDATE, encoding='utf-8'))
    job = (doc.get('jobs') or {}).get('scanners') or {}
    ids = [p.get('id') for p in (((job.get('strategy') or {}).get('matrix') or {}).get('probe') or [])]
    print('  M1 scanners continue-on-error=%r fail-fast=%r'
          % (job.get('continue-on-error'), (job.get('strategy') or {}).get('fail-fast')))
    if job.get('continue-on-error'):
        bad.append('M1 the probe matrix is continue-on-error: a probe that fails leaves the run green')
    if (job.get('strategy') or {}).get('fail-fast') is not False:
        bad.append('M1 the probe matrix must keep fail-fast off, so one leg cannot hide another')

    # M5 DEPCHECK DETECTS, OR SAYS IT DID NOT (2026-10-21, NVD_API_KEY now a repository secret).
    # The depcheck leg ran --noupdate with no key and set DETECT=ok whenever a SARIF FILE existed:
    # an output-shape check reported as detection. The key must reach that leg (and only it), the
    # leg must update the database with it, and DETECT may follow only a SARIF holding a result.
    # Since M6 the key reaches the depcheck-only update step, and the scan runs --noupdate; a
    # step limited to depcheck by its `if` is as narrow as an env guarded on the matrix id.
    vtext = io.open(VALIDATE, encoding='utf-8').read()
    steps = job.get('steps') or []
    upd = next((s for s in steps if s.get('id') == 'nvd_update'), {}) or {}
    m = re.search(r'\n\s*depcheck\)\n(.*?)\n\s*;;', vtext, re.S)
    branch = m.group(1) if m else ''
    holders = [s for s in steps if 'secrets.NVD_API_KEY' in str((s.get('env') or {}).get('NVD_API_KEY', ''))]
    print('  M5 NVD key reaches %s; branch found %s'
          % ([s.get('id') or s.get('name') for s in holders], bool(branch)))
    if not holders:
        bad.append('M5 no step receives secrets.NVD_API_KEY')
    for s in holders:
        expr = str((s.get('env') or {}).get('NVD_API_KEY', ''))
        if not _is_depcheck_only(s) and "matrix.probe.id == 'depcheck'" not in expr:
            bad.append('M5 the NVD key reaches every probe leg in step %r, not only depcheck'
                       % (s.get('id') or s.get('name')))
    if '--nvdApiKey' not in branch and '--nvdApiKey' not in str(upd.get('run') or ''):
        bad.append('M5 depcheck never passes --nvdApiKey: the database is never updated')
    if re.search(r'\.sarif \]; then\s*\n[^\n]*\n[^\n]*\n\s*DETECT=ok', branch):
        bad.append('M5 DETECT=ok follows the mere existence of a SARIF file, not a result in it')
    # Dependency-Check refuses an --out with no parent ("Invalid 'out' argument: 'dcout' - path
    # does not exist", run 39666134253; reproduced locally): a bare relative name. That refusal
    # was the leg's real failure on every run, keyed or not, and a usage dump hid it.
    outs = re.findall(r'--out\s+(\S+)', branch)
    if not outs or any('/' not in o.strip('"\'') for o in outs):
        bad.append('M5 depcheck --out is a bare name %s: Dependency-Check refuses it before scanning'
                   % outs)
    timeout = str(job.get('timeout-minutes', ''))
    if 'depcheck' not in timeout:
        bad.append('M5 depcheck shares the 15-minute limit; a keyed NVD download needs longer')
    bad.extend(check_m6(job, steps, branch, timeout))
    bad.extend(check_m9(steps, upd))
    m10, m10_why = check_m10()
    if m10_why:
        print('UNKNOWN: M10 could not run the update step: %s' % m10_why)
        return 2
    bad.extend(m10)
    m11, m11_why = check_m11()
    if m11_why:
        print('UNKNOWN: M11 could not run the probe step: %s' % m11_why)
        return 2
    bad.extend(m11)

    flagship = _shipped(FLAGSHIP)
    # A tag or a digest: since lane L-SG the job pins semgrep/semgrep@sha256:..., and a pattern
    # that read tags only would find no image and pass by checking nothing.
    images = sorted(set(re.findall(
        # The public branch of the mirror expression (KDEC-032) is quoted: `|| 'semgrep/semgrep@...'`.
        r"(?:image:\s*|')(semgrep/semgrep(?::[0-9.]+|@sha256:[0-9a-f]{64}))", flagship)))
    probe_body = io.open(VALIDATE, encoding='utf-8').read()
    print('  M2 flagship semgrep container(s) %s; probe ids %s' % (images, ids))
    if not images:
        bad.append('M2 no semgrep/semgrep image (tag or digest) found in the flagship: this check '
                   'would pass by matching nothing')
    if 'semgrep-container' not in ids:
        bad.append('M2 no semgrep-container probe: the image the flagship runs is never probed')
    branches = {}
    for pid in ('semgrep-container', 'semgrep-php'):
        bm = re.search(r'\n\s*%s\)\n(.*?)\n\s*;;' % re.escape(pid), probe_body, re.S)
        branches[pid] = bm.group(1) if bm else ''
    for img in images:
        if not re.search(r'docker run[^\n]*%s' % re.escape(img), branches['semgrep-container']):
            bad.append('M2 the flagship runs %s and the semgrep-container probe does not run that '
                       'image' % img)

    # M7 THE SHIPPED IMAGE STILL FINDS A PHP SEED (lane L-SG; KDEC-016). Comment lines are
    # dropped and continuation lines joined, so a flag named in a comment does not count.
    php = branches['semgrep-php']
    code = [ln.strip() for ln in php.splitlines() if not ln.strip().startswith('#')]
    php_cmd = ' '.join(ln[:-1] if ln.endswith('\\') else ln for ln in code)
    print('  M7 semgrep-php in matrix %s; branch found %s' % ('semgrep-php' in ids, bool(php)))
    if 'semgrep-php' not in ids:
        bad.append('M7 no semgrep-php probe: nothing weekly shows the shipped image finds a PHP seed')
    if not php:
        bad.append('M7 the probe step has no semgrep-php) branch')
    else:
        for img in images:
            if not re.search(r'docker run[^\n]*%s' % re.escape(img), php_cmd):
                bad.append('M7 the semgrep-php probe does not run the flagship image %s' % img)
        for need in ('--config p/php', 'fixture/php', '--json', '--output /src/out.json'):
            if need not in php_cmd:
                bad.append('M7 the semgrep-php scan does not pass %s' % need)
        if 'if [ ! -s out.json ]' not in php_cmd or 'COLLECTION_FAILED' not in php_cmd:
            bad.append('M7 the semgrep-php probe lacks the absent-report check (an absent report '
                       'would read as zero findings)')
        if not re.search(r'if ! n=\$\(jq [^;]*out\.json 2>&1\)', php_cmd):
            bad.append('M7 the semgrep-php probe lacks the parse check (a malformed report would '
                       'read as zero findings)')
        if '"ERROR"' not in php_cmd or 'unique' not in php_cmd or '.path' not in php_cmd:
            bad.append('M7 the semgrep-php count is not the unique paths with ERROR results')
        if not re.search(r'\[ "\$\{n:-0\}" -ge 3 \] && DETECT=ok', php_cmd):
            bad.append('M7 DETECT=ok is not conditioned on n >= 3 (the three seeded PHP files)')

    for wf_path in (VALIDATE, PROBE_CORPORA):
        bad.extend(check_m8(wf_path))
    bad.extend(check_m12(doc))

    script = render_script(doc)
    if script is None:
        bad.append('M3 no python heredoc in the %r step' % STEP)
    else:
        m = re.search(r'EXPECTED\s*=\s*\[(.*?)\]', script, re.S)
        roster = re.findall(r'"([a-z0-9-]+)"', m.group(1)) if m else []
        print('  M3 matrix roster %s' % roster)
        if sorted(roster) != sorted(ids):
            bad.append('M3 the matrix roster %s is not the probe matrix %s' % (roster, ids))
        good = {pid: {'id': pid, 'exec': 'ok', 'detect': 'ok', 'artifact': 'ok', 'note': 'seeded'}
                for pid in ids}
        cases = [
            ('all proven', dict(good), 0, None),
            ('a result file absent', {k: v for k, v in good.items() if k != 'gosec'}, 1, 'gosec'),
            ('a result file unparseable', dict(good, osv='{"id": "osv", "exec": '), 1, 'osv'),
            ('executed, detected nothing', dict(good, trivy=dict(good['trivy'], detect='fail')),
             1, 'trivy'),
            ('accepted depcheck gap', dict(good, depcheck=dict(good.get('depcheck', {}),
                                                               detect='fail', artifact='fail')),
             0, 'accepted'),
        ]
        work = tempfile.mkdtemp(prefix='vs-matrix-')
        try:
            for i, (label, results, want, named) in enumerate(cases):
                rc, out = run_render(script, results, os.path.join(work, str(i)))
                ok = rc == want and (named is None or named in out)
                print('  M4 %-30s rc=%s %s' % (label, rc, 'ok' if ok else 'WRONG'))
                if not ok:
                    bad.append('M4 %s: rc=%s (want %s)%s' % (label, rc, want,
                               '' if named is None or named in out else ', %r not named' % named))
        finally:
            shutil.rmtree(work, ignore_errors=True)
    for b in bad:
        print(('FAIL ' + b).encode('ascii', 'replace').decode('ascii'))
    if bad:
        return 1
    print('PASS: the probe matrix can fail, the shipped semgrep container is probed, and the matrix')
    print('      step fails on an absent, unparseable or undetecting probe -- except a dated acceptance.')
    return 0


if __name__ == '__main__':
    sys.exit(main())

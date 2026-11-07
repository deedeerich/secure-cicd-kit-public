#!/usr/bin/env python3
"""No developer is bitten by a missing manifest: discover, generate and check Dependabot config (2026-11-06).

WHY THIS EXISTS
    The owner: "How can we keep people from being bitten by a missing manifest, because this is a
    whole new way of them working?" scripts/dependabot_config.py finds every manifest, writes a correct
    .github/dependabot.yml and checks one; .github/workflows/reusable-dependabot-config-check.yml runs
    the check on pull requests (templates/dependabot-config-check.yml is the caller).

WHAT IT PROVES
  POSITIVE
    C1  a multi-ecosystem repository: `generate` writes a file that `check` passes -- every ecosystem
        has one entry listing its directories, minor+patch grouped, `rebase-strategy: auto`, the
        github-actions entry (workflows and composites), and the test fixture HELD (limit 0, every
        dependency ignored), never updated
    C2  the kit's own tree passes `check` (overlays are its consumers' to keep current)
    C3  a pull request that touches no manifest is answered NOTHING_TO_CHECK, rc 0
    C4  the workflow's check step, run as shipped, passes a clean repository (state OK)
  NEGATIVE
    N1  a manifest in a new folder no entry reads -> rc 1, the file named, the fix names the entry and
        the exact directory to add
    N2  an entry whose directory holds no manifest -> rc 1, dependency_file_not_found named, fix given
    N3  manifests and no dependabot.yml -> rc 1, the fix is the one-command `generate --write`
    N4  vendored code (node_modules, vendor) and build output are never required to be covered
    N5  a dependabot.yml that is not YAML -> a problem, never "OK"
    N6  an unreadable changed-files list checks EVERYTHING (the problem is still found)
    N7  the workflow's check step, run as shipped, fails a broken repository: state PROBLEMS, the
        summary lists each fix and a corrected dependabot.yml
    N8  the inlined copy in the workflow drifting from the script by one byte fails the inliner's --check
    N9  structure: the reusable reads only (contents, pull-requests), has no expression in a run:
        block; the template has NO `paths:` filter (a required check behind one never starts)

EXIT 0 all hold   1 any does not   2 could not run (PyYAML or bash missing)
"""
import contextlib
import io
import os
import shutil
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, HERE)
sys.path.insert(0, os.path.join(ROOT, 'scripts'))

try:
    import yaml
except ImportError:
    print('UNKNOWN: PyYAML not available.')
    sys.exit(2)

import dependabot_config as DC  # noqa: E402
import inline_dependabot_config as INL  # noqa: E402

WF_REL = '.github/workflows/reusable-dependabot-config-check.yml'
TPL_REL = 'templates/dependabot-config-check.yml'
FAILS = []

REPO_FILES = {
    'package.json': '{}',
    'services/api/package.json': '{}',
    'services/worker/go.mod': 'module x\n',
    'requirements.txt': 'flask==3.0.0\n',
    'infra/main.tf': 'terraform {}\n',
    'Dockerfile': 'FROM busybox:1.36\n',
    'src/App/App.csproj': '<Project/>\n',
    'node_modules/left-pad/package.json': '{}',
    'vendor/github.com/x/go.mod': 'module y\n',
    'dist/package.json': '{}',
    'tests/fixtures/vuln/requirements.txt': 'django==1.0\n',
    '.github/workflows/ci.yml': 'on: push\njobs: {}\n',
    '.github/actions/setup/action.yml': 'name: s\nruns: {using: composite, steps: []}\n',
    'README.md': '# x\n',
}


def check(cond, label, detail=''):
    print('  %s %s%s' % ('ok  ' if cond else 'FAIL', label, ('  -- ' + detail) if detail and not cond else ''))
    if not cond:
        FAILS.append(label)


def make_repo(files):
    d = tempfile.mkdtemp(prefix='depcfg-')
    for rel, body in files.items():
        p = os.path.join(d, *rel.split('/'))
        os.makedirs(os.path.dirname(p), exist_ok=True)
        io.open(p, 'w', encoding='utf-8', newline='\n').write(body)
    return d


def cli(argv):
    buf = io.StringIO()
    with contextlib.redirect_stdout(buf):
        rc = DC.main(argv)
    return rc, buf.getvalue()


def main():
    print('Dependabot configuration (scripts/dependabot_config.py):')
    # ---------------------------------------------------------------- C1 generate -> check passes
    d = make_repo(REPO_FILES)
    try:
        rc, out = cli(['generate', '--root', d, '--write'])
        gen = yaml.safe_load(io.open(os.path.join(d, '.github', 'dependabot.yml'), encoding='utf-8'))
        ents = gen.get('updates') or []
        by = {}
        for u in ents:
            by.setdefault(u['package-ecosystem'], []).append(u)
        live = {e: [u for u in us if u.get('open-pull-requests-limit') != 0] for e, us in by.items()}
        check(set(k for k, v in live.items() if v) == {'npm', 'gomod', 'pip', 'terraform', 'docker', 'nuget', 'github-actions'},
              'C1 one live entry per ecosystem found (%s)' % sorted(k for k, v in live.items() if v))
        check(sorted(live['npm'][0]['directories']) == ['/', '/services/api'], 'C1 the npm entry lists both directories')
        check(all(u.get('rebase-strategy') == 'auto' for us in live.values() for u in us), 'C1 every live entry rebases automatically')
        check('npm-minor-and-patch' in (live['npm'][0].get('groups') or {}), 'C1 minor and patch updates are grouped')
        check(live['github-actions'][0]['directories'] == ['/', '/.github/actions/*'],
              'C1 the github-actions entry reads workflows and composites')
        held = [u for u in by.get('pip', []) if u.get('open-pull-requests-limit') == 0]
        check(len(held) == 1 and held[0]['directory'] == '/tests/fixtures/vuln' and
              held[0].get('ignore') == [{'dependency-name': '*'}], 'C1 the test fixture is held, never updated')
        check(not any('node_modules' in str(u) or '/vendor' in str(u) or '/dist' in str(u) for u in ents),
              'N4 vendored code and build output are not given entries')
        rc, out = cli(['check', '--root', d])
        check(rc == 0 and out.startswith('OK'), 'C1 the generated file passes check', out[-300:])

        # N1: a new folder's manifest
        os.makedirs(os.path.join(d, 'web'))
        io.open(os.path.join(d, 'web', 'package.json'), 'w').write('{}')
        rc, out = cli(['check', '--root', d])
        check(rc == 1 and 'web/package.json is not read by any npm entry' in out and
              'add "/web" to the `directories:` list of the npm entry' in out,
              'N1 a manifest no entry reads: named, with the exact directory to add', out[-400:])
        # N6: an unreadable changed-files list checks everything
        rc, out = cli(['check', '--root', d, '--changed-files', os.path.join(d, 'no-such-list.txt')])
        check(rc == 1 and 'web/package.json' in out, 'N6 an unreadable changed-files list checks everything')
        # C3: a docs-only PR
        lst = os.path.join(d, 'changed.txt')
        io.open(lst, 'w').write('README.md\ndocs/x.md\n')
        rc, out = cli(['check', '--root', d, '--changed-files', lst])
        check(rc == 0 and out.startswith('NOTHING_TO_CHECK'), 'C3 a change touching no manifest: NOTHING_TO_CHECK')
        io.open(lst, 'w').write('web/package.json\n')
        rc, out = cli(['check', '--root', d, '--changed-files', lst])
        check(rc == 1, 'C3 a change touching a manifest IS checked')
        shutil.rmtree(os.path.join(d, 'web'))
        # N2: an entry whose directory lost its manifest
        os.remove(os.path.join(d, 'services', 'api', 'package.json'))
        rc, out = cli(['check', '--root', d])
        check(rc == 1 and 'reads "/services/api", where there is no npm manifest' in out and
              'dependency_file_not_found' in out and 'remove "/services/api"' in out,
              'N2 an entry with no manifest: named, dependency_file_not_found, the fix given', out[-400:])
        # N5: not YAML
        io.open(os.path.join(d, '.github', 'dependabot.yml'), 'w').write('version: 2\nupdates: [\n')
        rc, out = cli(['check', '--root', d])
        check(rc == 1 and 'not valid YAML' in out, 'N5 an unparseable dependabot.yml is a problem, never OK')
        # N3: no file at all
        os.remove(os.path.join(d, '.github', 'dependabot.yml'))
        rc, out = cli(['check', '--root', d])
        check(rc == 1 and 'generate --write' in out and 'no .github/dependabot.yml' in out,
              'N3 manifests and no dependabot.yml: the fix is the one-command generate')
    finally:
        shutil.rmtree(d, ignore_errors=True)

    # ---------------------------------------------------------------- C2 the kit's own tree
    rc, out = cli(['check', '--root', ROOT, '--exclude', 'overlays/**'])
    check(rc == 0, "C2 the kit's own tree passes check", out[-400:])

    # ---------------------------------------------------------------- N8 the inlined copy
    rc_sync = INL.main(['--check'])
    check(rc_sync == 0, 'N8 the inlined copy is byte-equal to the script now')
    tmpd = tempfile.mkdtemp(prefix='depcfg-inl-')
    try:
        mut = os.path.join(tmpd, 'wf.yml')
        txt = io.open(os.path.join(ROOT, *WF_REL.split('/')), encoding='utf-8').read()
        io.open(mut, 'w', encoding='utf-8', newline='\n').write(txt.replace("'TEST_FIXTURE': {'fixtures'", "'TEST_FIXTURE': {'fixturez'", 1))
        old = INL.WF
        INL.WF = mut
        try:
            with contextlib.redirect_stdout(io.StringIO()):
                rc_mut = INL.main(['--check'])
        finally:
            INL.WF = old
        check(rc_mut == 1, 'N8 a one-byte drift in the inlined copy fails --check')
    finally:
        shutil.rmtree(tmpd, ignore_errors=True)

    # ---------------------------------------------------------------- N9 structure
    doc = yaml.safe_load(io.open(os.path.join(ROOT, *WF_REL.split('/')), encoding='utf-8'))
    job = doc['jobs']['check']
    check(doc.get('permissions') == {} and job.get('permissions') == {'contents': 'read', 'pull-requests': 'read'},
          'N9 the reusable reads only')
    check(not [s for s in job['steps'] if '${{' in str(s.get('run', ''))], 'N9 no expression inside a run: block')
    tpl = yaml.safe_load(io.open(os.path.join(ROOT, *TPL_REL.split('/')), encoding='utf-8'))
    on = tpl.get('on', tpl.get(True)) or {}
    check('pull_request' in on and not ((on.get('pull_request') or {}).get('paths')), 'N9 the template has no paths filter')
    calls = [j for j in tpl['jobs'].values() if 'reusable-dependabot-config-check.yml@' in str(j.get('uses', ''))]
    check(len(calls) == 1 and calls[0].get('permissions') == job['permissions'],
          'N9 the template calls the reusable once, granting exactly what it requests')

    # ---------------------------------------------------------------- C4 / N7 the step as shipped
    import _step_harness as H
    bash, why = H.usable_bash()
    if not bash:
        print('UNKNOWN: no usable bash (%s); C4/N7 not run.' % why)
        return 2 if not FAILS else 1
    step = dict(next(s for s in job['steps'] if s.get('id') == 'check'))
    step['_job_env'] = {}
    for label, broken in (('C4', False), ('N7', True)):
        files = dict(REPO_FILES)
        d = make_repo(files)
        try:
            cli(['generate', '--root', d, '--write'])
            if broken:
                io.open(os.path.join(d, 'services', 'new.Dockerfile'), 'w').write('FROM busybox\n')
                os.makedirs(os.path.join(d, 'mobile'))
                io.open(os.path.join(d, 'mobile', 'package.json'), 'w').write('{}')
            ws_tmp = tempfile.mkdtemp(prefix='depcfg-rt-')
            r = H.run(bash, step, {}, d, extra_env={'RUNNER_TEMP': ws_tmp})
            shutil.rmtree(ws_tmp, ignore_errors=True)
            if not broken:
                check(r['rc'] == 0 and r['outputs'].get('state') == 'OK', 'C4 the shipped step passes a clean repository',
                      r['log'][-400:])
            else:
                s = r['summary']
                check(r['rc'] == 1 and r['outputs'].get('state') == 'PROBLEMS' and 'mobile/package.json' in s and
                      'Fix:' in s and '```yaml' in s and '"/mobile"' in s.split('```yaml', 1)[-1],
                      'N7 the shipped step fails a broken repository with each fix and a corrected file', r['log'][-400:])
        finally:
            shutil.rmtree(d, ignore_errors=True)

    if FAILS:
        print('FAIL: %d claim(s)' % len(FAILS))
        return 1
    print('PASS: every manifest is found, a correct dependabot.yml is generated, and a gap fails with its fix.')
    return 0


if __name__ == '__main__':
    sys.exit(main())

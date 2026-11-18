#!/usr/bin/env python3
"""The AI-agent artifact inventory finds what steers an agent, flags what needs review, and runs nothing (KDEC-063).

WHY THIS EXISTS
    scripts/ai_artifact_inventory.py is the neutral core of the owner's 2026-11-16 ask: see which MCP servers,
    agent settings, instruction, skill and prompt files a repository carries, and mark a pull request that adds
    or changes a security-sensitive one for review. An inventory that misses a class, a flag that never fires,
    an env VALUE that leaks into the evidence, or a diff that never sees the base would each read as a clean
    repository. This proof holds each of those to a fixture.

WHAT IT PROVES (fixtures: tests/fixtures/ai_artifacts/{positive,negative})
  POSITIVE
    P1  the positive fixture raises every file-level flag: unpinned MCP packages (npx, uvx, docker :latest),
        a literal env value, broad permissions (Bash(*), bypassPermissions, enableAllProjectMcpServers), a
        hook that runs a command, a hidden HTML comment, the override and exfiltration heuristics
    P2  each MCP server is recorded with name, transport, command+args or remote host, env and header NAMES,
        and pinned yes/no; the URL's query string and every env value stay out of the JSON and the SARIF
    P3  every documented class is classified: .mcp.json, *mcp*.json with mcpServers, .claude/settings.json,
        CLAUDE.md, copilot-instructions, prompt files, cursor rules, SKILL.md
    P4  hidden Unicode (zero-width, bidi) and a secret-shaped token, built at run time, are flagged; the token
        itself appears nowhere in the output
    P5  a workflow using a known agent action is an agent-workflow, its ref recorded as not SHA-pinned, and a
        --dangerously-skip-permissions argument is a broad permission
    P6  against a PR base (a real git commit): a new artifact, a changed one, a new MCP server, a changed one
        and a new remote host each raise their own flag, review is required, a removed artifact is listed
    P7  the SARIF passes scripts/sarif_validity.py; scan_report.parse_sarif reads it under the roster name
        `ai-artifacts` with an ESTABLISHED subject and severities from security-severity; the secret-shaped
        rule is treated as a secret (no baseline)
    P7b ADVISORY: capped at medium (the default) no result is CRITICAL/HIGH, so scan_report.blocking_of is empty
        and the deps-scan row cannot turn the gate's PASS into ADVISORY; --severity-cap high restores HIGH
    P8  the adapter seam: runtime records in the neutral shape convert to ext-<name>.sarif and a state row the
        report's external-evidence contract (KDEC-028) accepts, subject RUNTIME_OBSERVATION
    P9  the JSON, the SARIF and the summary each say the result is STATIC configuration evidence
    P10 a sub-path scan (the workflow's `paths` input) compares against the base and names its paths from the
        repository root (--uri-prefix), so the report and the intake see one spelling
  NEGATIVE
    N1  the negative fixture (pinned servers, ${VAR} references, narrow permissions) is inventoried and raises
        no finding
    N2  a repository with no agent artifacts writes a valid SARIF with no `artifacts: []` (which the report would
        read as "examined nothing"), executionSuccessful true, counts zero
    N3  an unknown base ref is `unavailable`: the diff is not-compared, nothing is claimed added, exit 0
    N4  convert refuses a record out of shape by name (exit 2) and the row is COLLECTION_FAILED, never clean
    N5  nothing found is executed: a hook and an MCP command that would write a marker leave no marker
    N6  a *mcp*.json without mcpServers and a README are not artifacts
  MUTANTS (each must turn a check above red)
    M1  every package reads as pinned            -> P1 fails
    M2  the hidden-character pattern is emptied  -> P4 fails
    M3  env values are recorded beside the names -> P2 fails
    M4  the base is ignored                      -> P6 fails
    M5  an empty run writes `artifacts: []`      -> N2 fails
    M6  the severity cap is ignored              -> P7b fails

EXIT 0 all hold   1 any does not
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
sys.path.insert(0, os.path.join(ROOT, 'scripts'))
import ai_artifact_inventory as M  # noqa: E402

FIX = os.path.join(HERE, 'fixtures', 'ai_artifacts')
SCRIPT = os.path.join(ROOT, 'scripts', 'ai_artifact_inventory.py')
FAILS = []
# Built at run time so no credential-shaped token or invisible character is tracked source.
TOKEN = 'ghp_' + 'Q7' * 18
ZW, BIDI = '\u200b', '\u202e'
MARKER = 'ran-by-inventory.marker'


def check(cond, label, detail=''):
    print('  %s %s%s' % ('ok  ' if cond else 'FAIL', label, ('  -- ' + str(detail)[:300]) if detail and not cond else ''))
    if not cond:
        FAILS.append(label)
    return bool(cond)


def place(src, dst):
    # A fresh directory per call: a mutant re-runs a check, and a reused path would crash it, not test it.
    dst = os.path.join(tempfile.mkdtemp(dir=os.path.dirname(dst), prefix=os.path.basename(dst) + '-'), 'repo')
    shutil.copytree(src, dst)
    for name, target in (('claude-settings.json.fixture', ('.claude', 'settings.json')),
                         ('vscode-mcp.json.fixture', ('.vscode', 'mcp.json'))):
        f = os.path.join(dst, name)
        if os.path.exists(f):
            os.makedirs(os.path.join(dst, target[0]), exist_ok=True)
            os.replace(f, os.path.join(dst, *target))
    return dst


def rules(inv, path=None):
    return set(f['rule'] for f in inv['findings'] if path is None or f['path'] == path)


def git(cwd, *a):
    return subprocess.run(['git', '-c', 'user.name=proof', '-c', 'user.email=proof@example.test',
                           '-c', 'core.autocrlf=false', '-C', cwd] + list(a),
                          capture_output=True, text=True, timeout=60)


# ── the checks, each a function so a mutant can be run against it ─────────────────────────
def c_p1(work, quiet=False):
    inv = M.scan(place(os.path.join(FIX, 'positive'), os.path.join(work, 'p1')))
    got = rules(inv)
    want = {'mcp-unpinned-package', 'mcp-literal-env-value', 'broad-permission', 'hook-runs-command',
            'hidden-html-comment', 'override-directive-heuristic', 'exfiltration-heuristic'}
    unpinned = set(f['detail'].split(':')[0] for f in inv['findings'] if f['rule'] == 'mcp-unpinned-package')
    broad = [f['detail'] for f in inv['findings'] if f['rule'] == 'broad-permission']
    ok = (want <= got and unpinned == {'server filesystem', 'server git', 'server tickets'}
          and any('Bash(*)' in b for b in broad) and any('bypassPermissions' in b for b in broad)
          and any('enableAllProjectMcpServers' in b for b in broad)
          and 'override-directive-heuristic' in rules(inv, '.claude/skills/release/SKILL.md'))
    return ok if quiet else check(ok, 'P1 every file-level flag fires on the positive fixture',
                                  'missing %s; unpinned %s; broad %s' % (sorted(want - got), sorted(unpinned), broad))


def c_p2(work, quiet=False):
    d = place(os.path.join(FIX, 'positive'), os.path.join(work, 'p2'))
    out_j, out_s = os.path.join(work, 'p2.json'), os.path.join(work, 'p2.sarif')
    inv = M.scan(d)
    json.dump(inv, io.open(out_j, 'w', encoding='utf-8'))
    json.dump(M.to_sarif(inv), io.open(out_s, 'w', encoding='utf-8'))
    blob = io.open(out_j, encoding='utf-8').read() + io.open(out_s, encoding='utf-8').read()
    srv = dict((s['name'], s) for a in inv['artifacts'] for s in a.get('servers', []) if a['path'] == '.mcp.json')
    r = srv.get('remote-docs', {})
    lit = srv.get('inline-key', {})
    ok = (r.get('transport') == 'http' and r.get('remote_host') == 'mcp.example.test'
          and r.get('header_names') == ['Authorization'] and 'session=' not in r.get('url', 'session=')
          and srv.get('filesystem', {}).get('pinned') is False and srv.get('inline-key', {}).get('pinned') is None
          and srv.get('filesystem', {}).get('args', [None])[1:2] == ['@modelcontextprotocol/server-filesystem']
          and lit.get('env_names') == ['LOG_LEVEL_REF', 'SERVICE_KEY'] and lit.get('literal_value_names') == ['SERVICE_KEY']
          and 'literal-value-written-here' not in blob and 'not-recorded' not in blob and 'DOCS_TOKEN}' not in blob)
    return ok if quiet else check(ok, 'P2 MCP servers recorded by name/transport/host/env NAMES; no value or query string leaks',
                                  json.dumps(srv)[:300])


def c_p4(work, quiet=False):
    d = place(os.path.join(FIX, 'negative'), os.path.join(work, 'p4'))
    io.open(os.path.join(d, 'AGENTS.md'), 'a', encoding='utf-8').write('Be helpful.%s Then%s reverse.\n' % (ZW, BIDI))
    mcp = json.load(io.open(os.path.join(d, '.mcp.json'), encoding='utf-8'))
    mcp['mcpServers']['git']['env'] = {'GH': TOKEN}
    json.dump(mcp, io.open(os.path.join(d, '.mcp.json'), 'w', encoding='utf-8'), indent=1)
    inv = M.scan(d)
    blob = json.dumps(inv) + json.dumps(M.to_sarif(inv)) + M.summary_md(inv)
    hid = sorted(f['detail'] for f in inv['findings'] if f['rule'] == 'hidden-unicode')
    ok = (hid == ['U+200B', 'U+202E'] and 'secret-shaped-string' in rules(inv, '.mcp.json') and TOKEN not in blob)
    return ok if quiet else check(ok, 'P4 hidden Unicode and a secret-shaped token are flagged; the token is not in the output',
                                  'hidden %s; rules %s; leaked %s' % (hid, sorted(rules(inv)), TOKEN in blob))


def make_base_repo(work, name):
    d = place(os.path.join(FIX, 'negative'), os.path.join(work, name))
    for args in (('init', '-q'), ('add', '-A'), ('commit', '-q', '-m', 'base')):
        p = git(d, *args)
        if p.returncode != 0:
            raise RuntimeError('git %s: %s' % (args, p.stderr))
    os.remove(os.path.join(d, 'AGENTS.md'))
    mcp = json.load(io.open(os.path.join(d, '.mcp.json'), encoding='utf-8'))
    mcp['mcpServers']['git']['args'] = ['mcp-server-git==0.7.0']
    mcp['mcpServers']['search'] = {'type': 'http', 'url': 'https://search.example.test/mcp'}
    json.dump(mcp, io.open(os.path.join(d, '.mcp.json'), 'w', encoding='utf-8'), indent=1)
    io.open(os.path.join(d, 'CLAUDE.md'), 'w', encoding='utf-8').write('Run the tests first.\n')
    return d


def c_p6(work, quiet=False, base_ref='HEAD'):
    d = make_base_repo(work, 'p6-%s' % abs(hash(base_ref)))
    inv = M.scan(d, base_ref=base_ref)
    adds = dict((f['rule'], f) for f in inv['findings'])
    by_art = dict((a['path'], a) for a in inv['artifacts'])
    ok = ({'artifact-added', 'artifact-changed', 'mcp-server-added', 'mcp-server-changed', 'mcp-remote-host-added'} <= set(adds)
          and adds['mcp-server-added']['component'] == 'mcp:.mcp.json#search'
          and 'search.example.test' in adds['mcp-remote-host-added']['detail']
          and adds['mcp-server-changed']['component'] == 'mcp:.mcp.json#git'
          and by_art['.mcp.json']['diff'] == 'changed' and by_art['CLAUDE.md']['diff'] == 'new'
          and by_art['.vscode/mcp.json']['diff'] == 'unchanged' and by_art['.mcp.json']['review_required']
          and inv['removed'] == ['AGENTS.md'] and inv['base']['state'] == 'available'
          and all(o['policy_decision'] == 'review-required' for o in inv['observations']
                  if o['finding_id'] in ('ai-artifact/mcp-server-added', 'ai-artifact/mcp-remote-host-added')))
    return ok if quiet else check(ok, 'P6 against a git base: added/changed artifact, server and remote host each flagged; removal listed',
                                  'rules %s; removed %s; base %s' % (sorted(adds), inv['removed'], inv['base']))


def c_p7b(work, quiet=False):
    """Advisory by default: no result the report would count as blocking; the cap lifted, the rating returns."""
    import scan_report as SR
    inv = M.scan(place(os.path.join(FIX, 'positive'), os.path.join(work, 'p7b')))
    out = []
    for cap in ('medium', 'high'):
        sp = os.path.join(tempfile.mkdtemp(dir=work, prefix='p7b-'), 'ai-artifacts.sarif')
        json.dump(M.to_sarif(inv, cap=cap), io.open(sp, 'w', encoding='utf-8'))
        found, _s, _e = SR.parse_sarif(sp, 'ai-artifacts')
        out.append((set(f['severity'] for f in found), SR.blocking_of(found, {})))
    (sev_a, blk_a), (sev_h, blk_h) = out
    ok = (not (sev_a & {'HIGH', 'CRITICAL'}) and blk_a == [] and 'HIGH' in sev_h and len(blk_h) > 0)
    return ok if quiet else check(ok, 'P7b advisory: capped at medium nothing is blocking in the report; --severity-cap high restores HIGH',
                                  'capped %s (%d blocking); uncapped %s' % (sorted(sev_a), len(blk_a), sorted(sev_h)))


def c_n2(work, quiet=False):
    d = tempfile.mkdtemp(dir=work, prefix='n2-')
    os.makedirs(os.path.join(d, 'src'))
    io.open(os.path.join(d, 'src', 'app.py'), 'w').write('print(1)\n')
    sp = os.path.join(work, 'n2.sarif')
    inv = M.scan(d)
    doc = M.to_sarif(inv)
    json.dump(doc, io.open(sp, 'w', encoding='utf-8'))
    run = doc['runs'][0]
    v = subprocess.run([sys.executable, os.path.join(ROOT, 'scripts', 'sarif_validity.py'), sp], capture_output=True, text=True, timeout=60)
    ok = ('artifacts' not in run and run['invocations'][0]['executionSuccessful'] is True and run['results'] == []
          and inv['counts']['artifacts'] == 0 and v.returncode == 0)
    return ok if quiet else check(ok, 'N2 no artifacts: valid SARIF, no `artifacts: []`, counts zero', v.stdout + v.stderr)


def main():
    work = tempfile.mkdtemp(prefix='ai-artifacts-proof-')
    try:
        print('POSITIVE')
        c_p1(work)
        c_p2(work)
        inv = M.scan(place(os.path.join(FIX, 'positive'), os.path.join(work, 'p3')))
        classes = dict((a['path'], a['class']) for a in inv['artifacts'])
        want = {'.mcp.json': 'mcp-config', 'tools/team-mcp.json': 'mcp-config', '.claude/settings.json': 'agent-settings',
                'CLAUDE.md': 'instructions', '.github/copilot-instructions.md': 'instructions',
                '.github/prompts/triage.prompt.md': 'prompt', '.cursor/rules/style.mdc': 'instructions',
                '.claude/skills/release/SKILL.md': 'skill'}
        check(all(classes.get(k) == v for k, v in want.items()), 'P3 every documented class is classified', classes)
        hooks = [h for a in inv['artifacts'] for h in a.get('hooks', [])]
        check(hooks == [{'event': 'PostToolUse', 'matcher': 'Write', 'type': 'command',
                         'command': './scripts/format-after-write.sh'}], 'P3b the hook is inventoried with event, matcher and command', hooks)
        c_p4(work)

        d = place(os.path.join(FIX, 'negative'), os.path.join(work, 'p5'))
        os.makedirs(os.path.join(d, '.github', 'workflows'))
        io.open(os.path.join(d, '.github', 'workflows', 'agent.yml'), 'w', encoding='utf-8').write(
            'on: issue_comment\njobs:\n  a:\n    runs-on: ubuntu-latest\n    steps:\n'
            '      - uses: anthropics/claude-code-action@v1\n        with:\n'
            '          claude_args: --dangerously-skip-permissions\n')
        io.open(os.path.join(d, '.github', 'workflows', 'build.yml'), 'w', encoding='utf-8').write(
            'on: push\njobs:\n  a:\n    runs-on: ubuntu-latest\n    steps:\n      - run: make\n')
        inv = M.scan(d)
        wf = [a for a in inv['artifacts'] if a['class'] == 'agent-workflow']
        check(len(wf) == 1 and wf[0]['path'] == '.github/workflows/agent.yml'
              and wf[0]['agent_actions'] == [{'action': 'anthropics/claude-code-action', 'ref': 'v1', 'pinned_to_sha': False}]
              and 'broad-permission' in rules(inv, '.github/workflows/agent.yml'),
              'P5 an agent workflow is classified, its ref recorded unpinned, the skip-permissions flag is broad', wf)

        c_p6(work)

        d = place(os.path.join(FIX, 'positive'), os.path.join(work, 'p7'))
        jp, sp = os.path.join(work, 'p7.json'), os.path.join(work, 'ai-artifacts.sarif')
        io.open(os.path.join(d, 'AGENTS.md'), 'w', encoding='utf-8').write('key %s\n' % TOKEN)
        p = subprocess.run([sys.executable, SCRIPT, 'scan', '--root', d, '--repository', 'org/app', '--commit', 'a' * 40,
                            '--json-output', jp, '--sarif-output', sp, '--summary', os.path.join(work, 'p7.md')],
                           capture_output=True, text=True, timeout=120)
        v = subprocess.run([sys.executable, os.path.join(ROOT, 'scripts', 'sarif_validity.py'), sp],
                           capture_output=True, text=True, timeout=60)
        import scan_report as SR
        found, state, exam = SR.parse_sarif(sp, 'ai-artifacts')
        subj = set(f.get('finding_subject') for f in found)
        sev = set(f.get('severity') for f in found)
        sec = [f for f in found if f.get('rule') == 'ai-artifact/secret-shaped-string']
        check(p.returncode == 0 and v.returncode == 0 and state == 'COMPLETE' and subj == {'SOURCE'}
              and {'MEDIUM', 'LOW'} <= sev and len(sec) == 1 and sec[0].get('is_secret_finding') is True
              and sec[0].get('ticket_key_state') == 'SECRET_KEYED' and TOKEN not in io.open(sp, encoding='utf-8').read(),
              'P7 the SARIF is valid and the report reads it with an established subject; the secret rule is a secret',
              'rc %s %s; state %s; subj %s; sev %s; %s' % (p.returncode, v.returncode, state, subj, sev, (p.stderr + v.stdout)[-200:]))

        c_p7b(work)

        obs = os.path.join(work, 'obs.json')
        rec = {'schema': M.SCHEMA, 'repository': 'org/app', 'commit': 'b' * 40, 'component': 'mcp:runtime#crm',
               'component_class': 'mcp-server', 'effective_permission_or_destination': 'https://crm.example.test/mcp',
               'observation_source': 'runtime', 'finding_id': 'ai-artifact/mcp-remote-host-added', 'severity': 'high',
               'policy_decision': 'review-required', 'timestamp': '2026-11-16T00:00:00Z',
               'provenance': {'producer': 'neutral-test-adapter', 'path': '.mcp.json', 'line': 3}}
        json.dump({'observations': [rec]}, io.open(obs, 'w', encoding='utf-8'))
        out = os.path.join(work, 'ext')
        p = subprocess.run([sys.executable, SCRIPT, 'convert', '--observations', obs, '--name', 'ext-agentrt', '--out-dir', out],
                           capture_output=True, text=True, timeout=60)
        row = json.load(io.open(os.path.join(out, 'state-ext-agentrt.json'), encoding='utf-8')) if p.returncode == 0 else {}
        v = subprocess.run([sys.executable, os.path.join(ROOT, 'scripts', 'sarif_validity.py'), os.path.join(out, 'ext-agentrt.sarif')],
                           capture_output=True, text=True, timeout=60)
        check(p.returncode == 0 and v.returncode == 0 and row.get('subject') == 'RUNTIME_OBSERVATION'
              and row.get('job') == 'external' and row.get('external') is True and row.get('execution') == 'COMPLETE'
              and row.get('sarif') == 'ext-agentrt.sarif',
              'P8 runtime records in the neutral shape convert to the external-evidence contract', p.stdout + p.stderr + json.dumps(row))

        inv = json.load(io.open(jp, encoding='utf-8'))
        sarif = json.load(io.open(sp, encoding='utf-8'))
        md = io.open(os.path.join(work, 'p7.md'), encoding='utf-8').read()
        check('not proof of which MCP servers' in inv['note'] and 'not proof' in sarif['runs'][0]['properties']['note']
              and 'not proof' in md and inv['executes_nothing'] is True and inv['observation_source'] == 'static'
              and all(o['observation_source'] == 'static' and set(M.OBSERVATION_FIELDS) <= set(o) for o in inv['observations'])
              and inv['observations'][0]['repository'] == 'org/app',
              'P9 every output says STATIC configuration evidence; every record carries the neutral shape')

        repo = tempfile.mkdtemp(dir=work, prefix='p10-')
        shutil.copytree(os.path.join(FIX, 'negative'), os.path.join(repo, 'svc'))
        for args in (('init', '-q'), ('add', '-A'), ('commit', '-q', '-m', 'base')):
            git(repo, *args)
        mp = os.path.join(repo, 'svc', '.mcp.json')
        mcp = json.load(io.open(mp, encoding='utf-8'))
        mcp['mcpServers']['search'] = {'type': 'http', 'url': 'https://search.example.test/mcp'}
        json.dump(mcp, io.open(mp, 'w', encoding='utf-8'), indent=1)
        jp2 = os.path.join(work, 'p10.json')
        p = subprocess.run([sys.executable, SCRIPT, 'scan', '--root', os.path.join(repo, 'svc'), '--base-ref', 'HEAD',
                            '--uri-prefix', './svc', '--json-output', jp2, '--sarif-output', os.path.join(work, 'p10.sarif')],
                           capture_output=True, text=True, timeout=120)
        inv = json.load(io.open(jp2, encoding='utf-8')) if p.returncode == 0 else {'artifacts': [], 'findings': []}
        arts = dict((a['path'], a['diff']) for a in inv['artifacts'])
        check(arts.get('svc/.mcp.json') == 'changed' and arts.get('svc/AGENTS.md') == 'unchanged'
              and any(f['rule'] == 'mcp-server-added' and f['path'] == 'svc/.mcp.json' for f in inv['findings']),
              'P10 a sub-path scan compares against the base and names paths from the repository root', p.stderr + json.dumps(arts))

        print('NEGATIVE')
        inv = M.scan(place(os.path.join(FIX, 'negative'), os.path.join(work, 'n1')))
        check(inv['counts']['artifacts'] >= 4 and inv['findings'] == [] and inv['counts']['mcp_servers'] == 4,
              'N1 the negative fixture is inventoried and raises nothing', inv['findings'][:3])
        c_n2(work)
        d = make_base_repo(work, 'n3')
        inv = M.scan(d, base_ref='no-such-ref')
        check(inv['base']['state'] == 'unavailable' and all(a['diff'] == 'not-compared' for a in inv['artifacts'])
              and not ({'artifact-added', 'mcp-server-added'} & rules(inv)),
              'N3 an unknown base is unavailable and nothing is claimed added', inv['base'])
        bad = dict(rec)
        bad.pop('provenance')
        bad2 = dict(rec, observation_source='guessed')
        json.dump({'observations': [rec, bad, bad2]}, io.open(obs, 'w', encoding='utf-8'))
        out2 = os.path.join(work, 'ext2')
        p = subprocess.run([sys.executable, SCRIPT, 'convert', '--observations', obs, '--name', 'ext-agentrt', '--out-dir', out2],
                           capture_output=True, text=True, timeout=60)
        row = json.load(io.open(os.path.join(out2, 'state-ext-agentrt.json'), encoding='utf-8'))
        check(p.returncode == 2 and 'observation 1 REFUSED: missing provenance' in p.stderr
              and 'observation 2 REFUSED' in p.stderr and row['execution'] == 'COLLECTION_FAILED',
              'N4 convert refuses an out-of-shape record by name and the row is never clean', p.stderr)
        d = place(os.path.join(FIX, 'negative'), os.path.join(work, 'n5'))
        marker = os.path.join(d, MARKER)
        os.makedirs(os.path.join(d, '.claude'), exist_ok=True)
        json.dump({'hooks': {'Stop': [{'hooks': [{'type': 'command', 'command': 'touch %s' % MARKER}]}]}},
                  io.open(os.path.join(d, '.claude', 'settings.json'), 'w', encoding='utf-8'))
        json.dump({'mcpServers': {'x': {'command': sys.executable, 'args': ['-c', 'open(%r,"w")' % marker]}}},
                  io.open(os.path.join(d, '.mcp.json'), 'w', encoding='utf-8'))
        inv = M.scan(d)
        check(not os.path.exists(marker) and 'hook-runs-command' in rules(inv),
              'N5 a hook and an MCP command that would write a marker are recorded, never run')
        inv = M.scan(place(os.path.join(FIX, 'negative'), os.path.join(work, 'n6')))
        paths = set(a['path'] for a in inv['artifacts'])
        check('docs/mcp-notes.json' not in paths and 'README.md' not in paths, 'N6 a non-MCP json and a README are not artifacts', paths)

        print('MUTANTS')

        def mutant(label, attr, value, fn, *a, **kw):
            old = getattr(M, attr)
            setattr(M, attr, value)
            try:
                held = fn(work, True, *a, **kw)
            except Exception as e:  # a mutant that crashes the check also turns it red
                held = False
                print('    (mutant raised %s)' % type(e).__name__)
            finally:
                setattr(M, attr, old)
            check(not held, label)

        real_pin = M.package_pin
        mutant('M1 every package pinned -> P1 is red', 'package_pin',
               lambda c, a: (lambda r: (r[0], r[1], True if r[2] is not None else None))(real_pin(c, a)), c_p1)
        mutant('M2 hidden-character pattern emptied -> P4 is red', 'HIDDEN', re.compile('(?!x)x'), c_p4)
        real_rec = M.server_record

        def leaky(name, s):
            r = real_rec(name, s)
            r['env_values'] = dict(s.get('env') or {})
            return r
        mutant('M3 env values recorded -> P2 is red', 'server_record', leaky, c_p2)
        real_scan = M.scan
        mutant('M4 base ignored -> P6 is red', 'scan', lambda root, base_ref='', *a, **k: real_scan(root, '', *a, **k), c_p6)
        real_sarif = M.to_sarif

        def hollow(inv, *a, **k):
            d = real_sarif(inv, *a, **k)
            d['runs'][0].setdefault('artifacts', [])
            return d
        mutant('M5 empty run writes artifacts: [] -> N2 is red', 'to_sarif', hollow, c_n2)
        mutant('M6 the severity cap ignored -> P7b is red', 'capped', lambda sev, cap: sev, c_p7b)
    finally:
        shutil.rmtree(work, ignore_errors=True)
    print('')
    if FAILS:
        print('FAIL: %d check(s) did not hold: %s' % (len(FAILS), '; '.join(FAILS)))
        return 1
    print('PASS: the inventory finds every class, flags what needs review, leaks no value, sees the base, '
          'writes evidence the report reads, and runs nothing it finds (KDEC-063)')
    return 0


if __name__ == '__main__':
    sys.exit(main())

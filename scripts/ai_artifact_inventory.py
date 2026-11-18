#!/usr/bin/env python3
"""Inventory the AI-agent steering artifacts in a repository, and flag the security-sensitive ones (KDEC-063).

WHY THIS EXISTS (owner, 2026-11-16)
    The owner wants to SEE which AI coding agents, MCP servers and agent configuration a repository carries,
    and wants a pull request that adds or changes one marked for review. That is not a code-vulnerability
    scan: an `.mcp.json` that launches an unpinned `npx` package, a `.claude/settings.json` hook that runs a
    shell command, or an instruction file with hidden text all steer an agent that has the developer's
    credentials, and none of them is source code any scanner the kit carries reads.

    This is the NEUTRAL core and it names no vendor. An employer overlay may later feed a runtime product's
    observations into the same intake through `convert` below (the record shape, OBSERVATION_FIELDS); this
    file builds no adapter for any product.

WHAT A RESULT HERE MEANS, AND WHAT IT DOES NOT
    STATIC CONFIGURATION EVIDENCE ONLY. A file's presence says what the repository ASKS an agent to load. It
    is not proof of which MCP servers or tools are actually connected or enabled at runtime: a client may
    prompt before it uses a project server (Claude Code does, for `.mcp.json`), a user or managed setting may
    override the file, and a developer's own machine may carry servers no repository shows. Every record says
    `observation_source: static`; only a runtime adapter may say `runtime`.

    NEVER EXECUTES OR FETCHES. Nothing found is run, imported, launched or resolved; no remote MCP server is
    contacted; no package registry is asked. Files are read as text and JSON. The only subprocess is `git`
    reading the BASE commit's tree (`git ls-tree`, `git show`) for the pull-request comparison.

    VALUES ARE NEVER RECORDED. An MCP server's `env` and `headers` are recorded by NAME only. A secret-shaped
    string is reported by rule and line; the matched text never reaches the inventory, the SARIF or a log.

THE ARTIFACT CLASSES, AND WHERE EACH CONVENTION IS DOCUMENTED (fetched 2026-11-16)
    mcp-config        `.mcp.json` at the project root, key `mcpServers`, stdio entries `command`/`args`/`env`,
                      remote entries `type` http|sse|ws + `url`/`headers` (code.claude.com/docs/en/mcp);
                      `.vscode/mcp.json`, key `servers`, `type` stdio|http|sse, `command`/`args`/`env`/
                      `envFile`/`url`/`headers` (code.visualstudio.com/docs/agents/reference/mcp-configuration);
                      `.cursor/mcp.json` and `claude_desktop_config.json` (key `mcpServers`; UNVERIFIED this
                      lane: cursor.com/docs did not show the MCP page, Claude Desktop's page was not fetched);
                      any other `*mcp*.json` that carries `mcpServers`
    agent-settings    `.claude/settings.json`, `.claude/settings.local.json`: `permissions` allow/ask/deny and
                      `defaultMode`, `hooks` event -> matcher group -> handlers of `type` command|http|
                      mcp_tool|prompt|agent (code.claude.com/docs/en/settings, /hooks); `.gemini/settings.json`
                      (its `mcpServers` read the same way; UNVERIFIED this lane)
    instructions      `.github/copilot-instructions.md`, `.github/instructions/**/*.instructions.md`, `AGENTS.md`
                      anywhere, `CLAUDE.md` / `GEMINI.md` (docs.github.com, add-repository-instructions);
                      `.cursor/rules/**` (cursor.com/docs/context/rules); `CLAUDE.local.md`, `.cursorrules`,
                      `.windsurfrules`, `.windsurf/rules/**` (legacy or vendor names, UNVERIFIED this lane)
    skill             any `SKILL.md` (`.claude/skills/<name>/SKILL.md` and the same shape elsewhere)
    agent-definition  `.claude/agents/*.md`, `.claude/commands/*.md`, `.github/agents/*.md`,
                      `.github/chatmodes/*.chatmode.md`
    prompt            `.github/prompts/*.prompt.md` (VS Code prompt files; UNVERIFIED this lane)
    agent-workflow    `.github/workflows/*.yml` that uses a known AI agent action or runs an agent CLI

THE RISK FLAGS (each a SARIF rule; RULES below carries the severity and the confidence)
    artifact-added / artifact-changed     new or changed versus the PR base; review required by class
    mcp-server-added / -changed, mcp-remote-host-added     the same, per server and per remote host
    mcp-unpinned-package                  npx/bunx/pnpm dlx/uvx/pipx run/docker run with no exact version
    mcp-literal-env-value                 an env or header VALUE written literally, not as ${VAR}
    hook-runs-command                     a hook handler of type command (it runs a shell command)
    broad-permission                      Bash / Bash(*) / a bare tool allow, bypassPermissions,
                                          enableAllProjectMcpServers, --dangerously-skip-permissions
    hidden-unicode                        zero-width, bidi control or tag characters
    hidden-html-comment                   an HTML comment in a markdown instruction (hidden when rendered)
    override-directive-heuristic          HEURISTIC, LOW CONFIDENCE: "ignore previous instructions" phrasing
    exfiltration-heuristic                HEURISTIC, LOW CONFIDENCE: send/upload near secret/token/.env
    secret-shaped-string                  a credential-shaped token (the report treats it as a secret)

    The heuristics are deliberately few and plain, each a regex below that can be read and argued with.
    They will miss a paraphrase and will flag a document that QUOTES an attack. They are review prompts.

ADVISORY BY DEFAULT
    The deps-scan step never sets findings_state from this tool, and the SARIF caps severity at MEDIUM
    (--severity-cap; the report counts only CRITICAL and HIGH as blocking, and a blocking finding in a row would
    turn the gate's PASS into ADVISORY). So nothing here moves a verdict. Results reach the report (row
    `ai-artifacts`) and the intake, where a match ENHANCES an existing ticket and never drops the finding
    (KDEC-049); each SARIF result keeps the tool's own rating as `native_severity`.

USAGE
    ai_artifact_inventory.py scan --root DIR [--base-ref REF] [--repository R] [--commit SHA]
                                  --json-output OUT.json --sarif-output OUT.sarif [--summary OUT.md]
                                  [--uri-prefix SUBPATH]
    ai_artifact_inventory.py convert --observations IN.json --name ext-NAME --out-dir DIR
EXIT
    0  written     2  bad usage or an input that could not be read (named)
"""
import argparse
import datetime
import hashlib
import io
import json
import os
import re
import subprocess
import sys
from urllib.parse import urlparse

TOOL = 'ai-artifact-inventory'
VERSION = '1.0.0'
SCHEMA = 'kit.ai-agent-observation/v1'
INVENTORY_SCHEMA = 'kit.ai-artifact-inventory/v1'
MAX_BYTES = 1024 * 1024
SKIP_DIRS = {'.git', 'node_modules', 'vendor', '.venv', 'venv', '__pycache__'}
STATIC_NOTE = ('STATIC configuration evidence: a file here is what the repository asks an agent to load, not '
               'proof of which MCP servers or tools are connected or enabled at runtime.')

# ── the vendor-neutral record shape (the interface a later adapter feeds) ───────────────────
OBSERVATION_FIELDS = ('schema', 'repository', 'commit', 'component', 'component_class',
                      'effective_permission_or_destination', 'observation_source', 'finding_id',
                      'severity', 'policy_decision', 'timestamp', 'provenance')
OBSERVATION_SOURCES = ('static', 'runtime')
SEVERITIES = ('high', 'medium', 'low', 'info')
POLICY_DECISIONS = ('review-required', 'advisory')
SECURITY_SEVERITY = {'high': '7.5', 'medium': '5.0', 'low': '3.0', 'info': '0.0'}
LEVEL = {'high': 'error', 'medium': 'warning', 'low': 'note', 'info': 'note'}

# rule -> (severity, confidence, description)
RULES = {
    'artifact-added': ('medium', 'high', 'A new AI-agent steering artifact versus the pull request base.'),
    'artifact-changed': ('medium', 'high', 'An AI-agent steering artifact changed versus the pull request base.'),
    'mcp-server-added': ('medium', 'high', 'An MCP server was added versus the pull request base.'),
    'mcp-server-changed': ('medium', 'high', 'An MCP server definition changed versus the pull request base.'),
    'mcp-remote-host-added': ('high', 'high', 'A remote MCP host the base did not reach was added.'),
    'mcp-unpinned-package': ('medium', 'high', 'An MCP server is launched from a package with no exact version.'),
    'mcp-literal-env-value': ('medium', 'medium', 'An MCP env or header value is written literally, not as ${VAR}.'),
    'hook-runs-command': ('medium', 'high', 'An agent hook runs a shell command.'),
    'broad-permission': ('high', 'high', 'A broad agent permission: unrestricted shell, bypass mode or auto-enabled MCP.'),
    'hidden-unicode': ('high', 'high', 'Zero-width, bidirectional control or tag characters in an agent artifact.'),
    'hidden-html-comment': ('low', 'medium', 'An HTML comment in a markdown instruction is hidden when rendered.'),
    'override-directive-heuristic': ('low', 'low', 'HEURISTIC, low confidence: text that reads as an instruction override.'),
    'exfiltration-heuristic': ('medium', 'low', 'HEURISTIC, low confidence: text that reads as sending secrets out.'),
    'secret-shaped-string': ('high', 'medium', 'A credential-shaped string in an agent artifact (value not recorded).'),
}
# Classes whose change always needs a reviewer; an instruction or prompt change needs one when it carries a flag.
SENSITIVE = {'mcp-config', 'agent-settings', 'agent-workflow', 'skill', 'agent-definition'}
MARKDOWN = {'instructions', 'skill', 'agent-definition', 'prompt'}

# ── classification ─────────────────────────────────────────────────────────────────────────
INSTRUCTION_NAMES = {'CLAUDE.md', 'CLAUDE.local.md', 'AGENTS.md', 'AGENT.md', 'GEMINI.md', '.cursorrules',
                     '.windsurfrules'}
PATTERNS = (
    ('mcp-config', re.compile(r'(^|/)(\.mcp\.json|\.vscode/mcp\.json|\.cursor/mcp\.json|claude_desktop_config\.json)$')),
    ('agent-settings', re.compile(r'(^|/)(\.claude/settings(\.local)?\.json|\.gemini/settings\.json)$')),
    ('instructions', re.compile(r'(^|/)(\.github/copilot-instructions\.md|\.github/instructions/.+\.instructions\.md'
                                r'|\.cursor/rules/.+|\.windsurf/rules/.+)$')),
    ('agent-definition', re.compile(r'(^|/)(\.claude/(agents|commands)/.+\.md|\.github/agents/.+\.md'
                                    r'|\.github/chatmodes/.+\.chatmode\.md)$')),
    ('prompt', re.compile(r'(^|/)\.github/prompts/.+\.prompt\.md$')),
)
WORKFLOW = re.compile(r'(^|/)\.github/workflows/[^/]+\.ya?ml$')
GENERIC_MCP = re.compile(r'mcp[^/]*\.json$', re.I)
AGENT_ACTION = re.compile(r'uses:\s*["\']?((?:anthropics/claude-code(?:-base)?-action|openai/codex-action'
                          r'|google-github-actions/run-gemini-cli|github/copilot-[\w.-]+|coderabbitai/[\w.-]+'
                          r'|cursor/[\w.-]+)(?:/[\w./-]+)?)@([^\s"\'#]+)')
AGENT_CLI = re.compile(r'(@anthropic-ai/claude-code|@openai/codex|@google/gemini-cli|\bclaude\s+-p\b'
                       r'|\bcodex\s+exec\b|\bgemini\s+-p\b)')


def classify(rel, read):
    base = rel.rsplit('/', 1)[-1]
    for cls, rx in PATTERNS:
        if rx.search(rel):
            return cls
    if base in INSTRUCTION_NAMES:
        return 'instructions'
    if base == 'SKILL.md':
        return 'skill'
    if WORKFLOW.search(rel):
        text = read(rel)
        return 'agent-workflow' if text and (AGENT_ACTION.search(text) or AGENT_CLI.search(text)) else None
    if GENERIC_MCP.search(base):
        doc = _json(read(rel))
        return 'mcp-config' if isinstance(doc, dict) and isinstance(doc.get('mcpServers'), dict) else None
    return None


def _json(text):
    if text is None:
        return None
    try:
        return json.loads(text)
    except ValueError:
        return None


# ── MCP servers ────────────────────────────────────────────────────────────────────────────
LAUNCHERS = {'npx': 'npm', 'bunx': 'npm', 'uvx': 'pypi', 'pipx': 'pypi', 'pnpm': 'npm', 'docker': 'image',
             'podman': 'image'}
_NPM_EXACT = re.compile(r'^(@[^/@\s]+/)?[^@\s]+@v?\d+\.\d+\.\d+([-+][\w.-]+)?$')
_PYPI_EXACT = re.compile(r'^[A-Za-z0-9._\[\],-]+(==|@)v?\d+(\.\d+)*([\w.+-]*)$')
_ENV_REF = re.compile(r'^\$\{[^}]+\}$|^\$[A-Za-z_][A-Za-z0-9_]*$|^\$\{input:[^}]+\}$|^\$\{env:[^}]+\}$')


def package_pin(command, args):
    """-> (launcher, package, pinned). pinned None: not a package launcher (a local path or binary)."""
    exe = os.path.basename(str(command or '')).lower()
    exe = re.sub(r'\.(cmd|exe)$', '', exe)
    a = [str(x) for x in (args or [])]
    if exe in ('cmd', 'sh', 'bash') and len(a) >= 2 and a[0] in ('/c', '-c'):
        parts = (' '.join(a[1:])).split()
        return package_pin(parts[0] if parts else '', parts[1:])
    if exe not in LAUNCHERS:
        return ('', '', None)
    rest = list(a)
    if exe == 'pnpm':
        if not rest or rest[0] != 'dlx':
            return ('', '', None)
        rest = rest[1:]
    if exe == 'pipx':
        if not rest or rest[0] != 'run':
            return ('', '', None)
        rest = rest[1:]
    if exe in ('docker', 'podman'):
        if not rest or rest[0] != 'run':
            return ('', '', None)
        rest = rest[1:]
        takes_value = {'-e', '--env', '-v', '--volume', '--name', '--network', '-p', '--publish', '-w',
                       '--workdir', '--entrypoint', '-u', '--user', '--env-file', '--mount', '--platform'}
        i = 0
        while i < len(rest):
            if rest[i] in takes_value:
                i += 2
                continue
            if rest[i].startswith('-'):
                i += 1
                continue
            img = rest[i]
            pinned = '@sha256:' in img or (':' in img.rsplit('/', 1)[-1] and not img.endswith(':latest'))
            return ('image', img, bool(pinned))
        return ('image', '', False)
    pkg = ''
    from_pkg = ''
    i = 0
    while i < len(rest):
        x = rest[i]
        if x in ('--from', '--package', '-p') and i + 1 < len(rest):
            from_pkg = rest[i + 1]
            i += 2
            continue
        if x.startswith('-'):
            i += 1
            continue
        pkg = x
        break
    pkg = from_pkg or pkg
    if not pkg:
        return (LAUNCHERS[exe], '', False)
    exact = _NPM_EXACT if LAUNCHERS[exe] == 'npm' else _PYPI_EXACT
    return (LAUNCHERS[exe], pkg, bool(exact.match(pkg)))


def mcp_servers(doc):
    if not isinstance(doc, dict):
        return {}
    for key in ('mcpServers', 'servers'):
        if isinstance(doc.get(key), dict):
            return dict((str(k), v) for k, v in doc[key].items() if isinstance(v, dict))
    return {}


def server_record(name, s):
    url = s.get('url') or s.get('serverUrl') or ''
    transport = (s.get('type') or s.get('transport') or ('stdio' if s.get('command') else ('http' if url else 'unknown')))
    env = s.get('env') if isinstance(s.get('env'), dict) else {}
    headers = s.get('headers') if isinstance(s.get('headers'), dict) else {}
    launcher, pkg, pinned = package_pin(s.get('command'), s.get('args') if isinstance(s.get('args'), list) else [])
    host = ''
    if url:
        try:
            host = (urlparse(str(url)).hostname or '').lower()
        except ValueError:
            host = ''
    literal = sorted([k for k, v in env.items() if isinstance(v, str) and v and not _ENV_REF.match(v)]
                     + ['header:' + k for k, v in headers.items() if isinstance(v, str) and v
                        and not re.search(r'\$\{[^}]+\}', v)])
    return {
        'name': name, 'transport': str(transport),
        'command': str(s.get('command') or ''),
        'args': [_redact(str(x)) for x in (s.get('args') or [])] if isinstance(s.get('args'), list) else [],
        'url': _strip_query(str(url)) if url else '', 'remote_host': host,
        'env_names': sorted(str(k) for k in env), 'header_names': sorted(str(k) for k in headers),
        'env_file': str(s.get('envFile') or ''),
        'launcher': launcher, 'package': pkg, 'pinned': pinned, 'literal_value_names': literal,
    }


def _strip_query(url):
    # A query string or userinfo can carry a token; the host and path are enough to review.
    try:
        p = urlparse(url)
        netloc = p.hostname or ''
        if p.port:
            netloc += ':%d' % p.port
        return '%s://%s%s' % (p.scheme, netloc, p.path) if p.scheme else url.split('?', 1)[0]
    except ValueError:
        return url.split('?', 1)[0]


def _server_digest(s):
    return hashlib.sha256(json.dumps(s, sort_keys=True).encode('utf-8')).hexdigest()


# ── text checks ────────────────────────────────────────────────────────────────────────────
HIDDEN = re.compile('[\u200b-\u200f\u202a-\u202e\u2060-\u2064\u2066-\u2069\ufeff\U000e0000-\U000e007f]')
HTML_COMMENT = re.compile(r'<!--(.*?)-->', re.S)
OVERRIDE = re.compile(r'(?i)\b(ignore|disregard|forget|override)\b[^.\n]{0,40}\b(previous|prior|above|earlier|all|system)'
                      r'\b[^.\n]{0,20}\b(instructions?|rules|prompts?|guidelines)\b'
                      r'|\b(do not|don\'t|never)\s+(tell|inform|mention|reveal|show)\b[^.\n]{0,30}\b(the )?user\b'
                      r'|\bwithout\s+(asking|telling|notifying|informing)\b[^.\n]{0,15}\b(the )?user\b')
EXFIL = re.compile(r'(?i)\b(curl|wget|fetch|send|post|upload|exfiltrate|transmit|base64)\b[^\n]{0,80}'
                   r'(\.env\b|\bsecrets?\b|\btokens?\b|\bcredentials?\b|api[_ -]?keys?|\.ssh\b|id_rsa|\.aws/credentials)')
SECRET_SHAPES = (
    re.compile(r'\b(ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{36}\b'),
    re.compile(r'\bgithub_pat_[A-Za-z0-9_]{60,}\b'),
    re.compile(r'\bAKIA[0-9A-Z]{16}\b'),
    re.compile(r'\bsk-ant-[A-Za-z0-9_-]{20,}'),
    re.compile(r'\bsk-(proj-)?[A-Za-z0-9]{32,}\b'),
    re.compile(r'\bxox[abprs]-[A-Za-z0-9-]{10,}'),
    re.compile(r'\bAIza[0-9A-Za-z_-]{35}\b'),
    re.compile(r'-----BEGIN [A-Z ]*PRIVATE KEY-----'),
)
BROAD_TEXT = re.compile(r'--dangerously-skip-permissions|--dangerously-bypass-approvals-and-sandbox|--yolo\b'
                        r'|\bbypassPermissions\b')
BROAD_ALLOW = re.compile(r'^(\*|(Bash|Shell|PowerShell|WebFetch|Write|Edit|MultiEdit)(\((\*|\*\*|:\*|\s*)\))?)$')


def _redact(s):
    out = s
    for rx in SECRET_SHAPES:
        out = rx.sub('<redacted>', out)
    return out


def _line(text, pos):
    return text.count('\n', 0, pos) + 1


def _line_of(text, needle):
    i = text.find(needle) if needle else -1
    return _line(text, i) if i >= 0 else 1


def _secret_fp(material, repository):
    """The kit's one non-reversible secret fingerprint (scripts/code_finding_key.py: PBKDF2, salted by the
    repository), so the ticket intake keys this secret as it keys the secret scanners' -- never the value."""
    try:
        sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
        import code_finding_key
        return code_finding_key.secret_fingerprint(material, repository)
    except ImportError:
        return ''


def text_flags(cls, text, repository=''):
    """-> [(rule, line, detail)] for one artifact's text. Details never carry a matched secret; a secret's
    detail carries only the pattern name and its salted fingerprint (after '|sfp=')."""
    out = []
    for m in HIDDEN.finditer(text):
        if m.start() == 0 and m.group() == '\ufeff':
            continue  # a byte-order mark at the start is an encoding marker, not hidden text
        out.append(('hidden-unicode', _line(text, m.start()), 'U+%04X' % ord(m.group())))
    for rx in SECRET_SHAPES:
        for m in rx.finditer(text):
            out.append(('secret-shaped-string', _line(text, m.start()),
                        'pattern %s|sfp=%s' % (rx.pattern[:24], _secret_fp(m.group(), repository))))
    for m in BROAD_TEXT.finditer(text):
        out.append(('broad-permission', _line(text, m.start()), m.group().strip()))
    if cls in MARKDOWN:
        for m in HTML_COMMENT.finditer(text):
            out.append(('hidden-html-comment', _line(text, m.start()), '%d characters hidden' % len(m.group(1))))
        for m in OVERRIDE.finditer(text):
            out.append(('override-directive-heuristic', _line(text, m.start()), _redact(m.group())[:80]))
        for m in EXFIL.finditer(text):
            out.append(('exfiltration-heuristic', _line(text, m.start()), _redact(m.group())[:80]))
    # one result per (rule, line, detail)
    seen, uniq = set(), []
    for f in out:
        if f not in seen:
            seen.add(f)
            uniq.append(f)
    return uniq


def settings_flags(doc, text):
    out = []
    if not isinstance(doc, dict):
        return out, []
    perms = doc.get('permissions') if isinstance(doc.get('permissions'), dict) else {}
    for rule in perms.get('allow') or []:
        if isinstance(rule, str) and BROAD_ALLOW.match(rule.strip()):
            out.append(('broad-permission', _line_of(text, json.dumps(rule)), 'allow %s' % rule))
    if perms.get('defaultMode') == 'bypassPermissions' or doc.get('defaultMode') == 'bypassPermissions':
        mode = perms.get('defaultMode') or doc.get('defaultMode')
        out.append(('broad-permission', _line_of(text, '"defaultMode"'),
                    'defaultMode %s (Claude Code ignores it from project files since v2.1.257; it still states intent)' % mode))
    if doc.get('enableAllProjectMcpServers') is True:
        out.append(('broad-permission', _line_of(text, '"enableAllProjectMcpServers"'),
                    'enableAllProjectMcpServers true: project MCP servers load without a per-server approval'))
    hooks = []
    for event, groups in (doc.get('hooks') or {}).items() if isinstance(doc.get('hooks'), dict) else []:
        for g in groups if isinstance(groups, list) else []:
            if not isinstance(g, dict):
                continue
            for h in g.get('hooks') or []:
                if not isinstance(h, dict):
                    continue
                kind = str(h.get('type') or '')
                rec = {'event': str(event), 'matcher': str(g.get('matcher') or '*'), 'type': kind}
                if kind == 'command':
                    cmd = _redact(str(h.get('command') or ''))
                    rec['command'] = cmd[:200]
                    out.append(('hook-runs-command', _line_of(text, str(h.get('command') or '')[:40]),
                                '%s/%s runs: %s' % (event, rec['matcher'], cmd[:120])))
                elif kind == 'http':
                    rec['destination'] = _strip_query(str(h.get('url') or ''))
                hooks.append(rec)
    return out, hooks


# ── reading a tree: the working tree, or the base commit through git ────────────────────────
class Tree(object):
    def __init__(self, root, ref=None):
        self.root, self.ref, self.state, self.why = root, ref, 'available', ''
        self._files = None

    def files(self):
        if self._files is not None:
            return self._files
        out = []
        if self.ref:
            p = subprocess.run(['git', '-C', self.root, 'ls-tree', '-r', '--name-only', self.ref],
                               capture_output=True, text=True)
            if p.returncode != 0:
                self.state, self.why = 'unavailable', (p.stderr.strip().splitlines() or ['git ls-tree failed'])[-1][:200]
                self._files = []
                return []
            out = [f for f in p.stdout.splitlines() if f and not (set(f.split('/')) & SKIP_DIRS)]
        else:
            for d, dirs, names in os.walk(self.root):
                dirs[:] = sorted(x for x in dirs if x not in SKIP_DIRS)
                for n in sorted(names):
                    rel = os.path.relpath(os.path.join(d, n), self.root).replace(os.sep, '/')
                    out.append(rel)
        self._files = sorted(out)
        return self._files

    def read(self, rel):
        try:
            if self.ref:
                # `REF:./path` is relative to the directory git runs in, as `ls-tree` above lists it.
                p = subprocess.run(['git', '-C', self.root, 'show', '%s:./%s' % (self.ref, rel)], capture_output=True)
                data = p.stdout if p.returncode == 0 else None
            else:
                path = os.path.join(self.root, rel)
                if os.path.islink(path) or os.path.getsize(path) > MAX_BYTES:
                    return None
                with io.open(path, 'rb') as fh:
                    data = fh.read()
        except OSError:
            return None
        if data is None or len(data) > MAX_BYTES:
            return None
        return data.decode('utf-8', errors='replace')


def collect(tree, repository=''):
    """-> {rel: artifact dict} for every steering artifact in the tree."""
    arts = {}
    cache = {}

    def read(rel):
        if rel not in cache:
            cache[rel] = tree.read(rel)
        return cache[rel]
    for rel in tree.files():
        cls = classify(rel, read)
        if not cls:
            continue
        text = read(rel)
        art = {'path': rel, 'class': cls, 'examined': text is not None,
               'sha256': hashlib.sha256(text.encode('utf-8')).hexdigest() if text is not None else ''}
        if text is None:
            art['not_examined_reason'] = 'unreadable, a symbolic link, or larger than %d bytes' % MAX_BYTES
            arts[rel] = art
            continue
        doc = _json(text) if rel.endswith('.json') else None
        if rel.endswith('.json') and doc is None:
            art['parse'] = 'not valid JSON (comments or a syntax error); MCP servers not read from it'
        art['servers'] = [server_record(n, s) for n, s in sorted(mcp_servers(doc).items())] if doc else []
        art['_server_digests'] = dict((n, _server_digest(s)) for n, s in mcp_servers(doc).items()) if doc else {}
        flags = text_flags(art['class'], text, repository)
        hooks = []
        if cls == 'agent-settings':
            sf, hooks = settings_flags(doc, text)
            flags += sf
        art['hooks'] = hooks
        if cls == 'agent-workflow':
            art['agent_actions'] = [{'action': m.group(1), 'ref': m.group(2),
                                     'pinned_to_sha': bool(re.match(r'^[0-9a-f]{40}$', m.group(2)))}
                                    for m in AGENT_ACTION.finditer(text)]
            art['agent_cli'] = sorted(set(m.group(1) for m in AGENT_CLI.finditer(text)))
        for s in art['servers']:
            ln = _line_of(text, '"%s"' % s['name'])
            if s['pinned'] is False:
                flags.append(('mcp-unpinned-package', ln, 'server %s: %s %s has no exact version'
                              % (s['name'], s['launcher'], s['package'] or '(no package named)')))
            if s['literal_value_names']:
                flags.append(('mcp-literal-env-value', ln, 'server %s: literal value for %s (value not recorded)'
                              % (s['name'], ', '.join(s['literal_value_names']))))
        art['_flags'] = flags
        art['_text'] = text
        arts[rel] = art
    return arts


# ── the inventory ──────────────────────────────────────────────────────────────────────────
def now():
    return datetime.datetime.now(datetime.timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')


def scan(root, base_ref='', repository='', commit='', timestamp=''):
    ts = timestamp or now()
    head = collect(Tree(root), repository)
    base, base_tree = None, None
    if base_ref:
        base_tree = Tree(root, base_ref)
        base = collect(base_tree, repository)
        if base_tree.state != 'available':
            base = None
    findings = []

    def add(art, rule, line, detail, component, dest=''):
        sev, conf, _ = RULES[rule]
        detail, _, sfp = detail.partition('|sfp=')
        f = {'rule': rule, 'path': art['path'], 'line': line, 'detail': detail,
             'component': component, 'component_class': art['class'], 'severity': sev,
             'confidence': conf, 'destination': dest}
        if sfp:
            f['secret_fingerprint'] = sfp
        findings.append(f)

    for rel, art in sorted(head.items()):
        b = base.get(rel) if base is not None else None
        if base is None:
            art['diff'] = 'not-compared'
        elif b is None:
            art['diff'] = 'new'
        elif b['sha256'] != art['sha256']:
            art['diff'] = 'changed'
        else:
            art['diff'] = 'unchanged'
        for rule, line, detail in art.get('_flags', []):
            add(art, rule, line, detail, 'artifact:%s' % rel)
        if art['diff'] in ('new', 'changed'):
            rule = 'artifact-added' if art['diff'] == 'new' else 'artifact-changed'
            add(art, rule, 1, '%s %s (%s)' % (art['class'], art['diff'], rel), 'artifact:%s' % rel)
            if art['class'] not in SENSITIVE:
                findings[-1]['severity'] = 'low'
            text = art.get('_text') or ''
            old = (b or {}).get('_server_digests', {})
            old_hosts = set(s['remote_host'] for a in base.values() for s in a.get('servers', []) if s['remote_host'])
            for s in art.get('servers', []):
                comp = 'mcp:%s#%s' % (rel, s['name'])
                dest = s['url'] or ' '.join([s['command']] + s['args'])
                if s['name'] not in old:
                    add(art, 'mcp-server-added', _line_of(text, '"%s"' % s['name']),
                        'server %s (%s) added' % (s['name'], s['transport']), comp, dest)
                elif old[s['name']] != art['_server_digests'].get(s['name']):
                    add(art, 'mcp-server-changed', _line_of(text, '"%s"' % s['name']),
                        'server %s definition changed' % s['name'], comp, dest)
                if s['remote_host'] and s['remote_host'] not in old_hosts:
                    add(art, 'mcp-remote-host-added', _line_of(text, '"%s"' % s['name']),
                        'server %s reaches %s, a host the base reached from no MCP config'
                        % (s['name'], s['remote_host']), comp, s['url'])
    removed = sorted(r for r in (base or {}) if r not in head)
    # review: a sensitive class with any flag, or any flag at medium or above, or a change to a sensitive class
    flagged_paths = set()
    for f in findings:
        f['review_required'] = (f['severity'] in ('high', 'medium') or f['component_class'] in SENSITIVE
                                or f['rule'] in ('hidden-unicode', 'hidden-html-comment'))
        if f['review_required']:
            flagged_paths.add(f['path'])
    artifacts = []
    for rel, art in sorted(head.items()):
        a = dict((k, v) for k, v in art.items() if not k.startswith('_'))
        a['flags'] = sorted(set(f['rule'] for f in findings if f['path'] == rel))
        a['review_required'] = rel in flagged_paths
        artifacts.append(a)
    observations = [observation(f, repository, commit, ts) for f in findings]
    inv = {
        'schema': INVENTORY_SCHEMA, 'tool': TOOL, 'version': VERSION, 'timestamp': ts,
        'repository': repository, 'commit': commit, 'observation_source': 'static', 'note': STATIC_NOTE,
        'base': {'ref': base_ref, 'state': ('not-requested' if not base_ref else base_tree.state),
                 'reason': (base_tree.why if base_tree else '')},
        'counts': {'artifacts': len(artifacts), 'mcp_servers': sum(len(a.get('servers', [])) for a in artifacts),
                   'findings': len(findings), 'review_required': len(flagged_paths), 'removed': len(removed)},
        'artifacts': artifacts, 'removed': removed, 'findings': findings, 'observations': observations,
        'executes_nothing': True, 'fetches_nothing': True,
    }
    return inv


def observation(f, repository, commit, ts, source='static', producer=TOOL):
    return {
        'schema': SCHEMA, 'repository': repository, 'commit': commit, 'component': f['component'],
        'component_class': f['component_class'],
        'effective_permission_or_destination': f.get('destination') or f.get('detail', ''),
        'observation_source': source, 'finding_id': 'ai-artifact/' + f['rule'], 'severity': f['severity'],
        'policy_decision': 'review-required' if f.get('review_required') else 'advisory', 'timestamp': ts,
        'provenance': {'producer': producer, 'version': VERSION, 'path': f['path'], 'line': f['line'],
                       'method': 'static file read; nothing executed or fetched', 'confidence': f['confidence']},
    }


# ── SARIF ──────────────────────────────────────────────────────────────────────────────────
RANK = {'info': 0, 'low': 1, 'medium': 2, 'high': 3}


def capped(sev, cap):
    """ADVISORY IS A SEVERITY CEILING IN THE REPORT. scan_report counts CRITICAL and HIGH as blocking, and a
    blocking finding in deps-scan's row turns the gate's PASS into ADVISORY (softened). Capped at medium (the
    default), these findings are filed and ticketed and never move the verdict. The inventory JSON and each
    result's `native_severity` keep the tool's own rating; lifting the cap is an owner decision (KDEC-063)."""
    return sev if RANK.get(sev, 2) <= RANK.get(cap, 2) else cap


def to_sarif(inv, driver=TOOL, uri='', cap='medium'):
    rules = [{'id': 'ai-artifact/' + r, 'name': r, 'shortDescription': {'text': d},
              'defaultConfiguration': {'level': LEVEL[capped(s, cap)]},
              'properties': {'security-severity': SECURITY_SEVERITY[capped(s, cap)], 'native_severity': s,
                             'confidence': c,
                             'tags': ['security', 'ai-agent-configuration'] + (['heuristic'] if c == 'low' else [])}}
             for r, (s, c, d) in sorted(RULES.items())]
    results = []
    for f, o in zip(inv['findings'], inv['observations']):
        sev = capped(f['severity'], cap)
        msg = '%s: %s.%s %s' % (f['rule'], f['detail'],
                                ' HEURISTIC, low confidence.' if f['confidence'] == 'low' else '',
                                'Review required.' if f['review_required'] else 'Advisory.')
        results.append({
            'ruleId': 'ai-artifact/' + f['rule'], 'level': LEVEL[sev],
            'message': {'text': _redact(msg) + ' Static configuration evidence, not runtime state.'},
            'locations': [{'physicalLocation': {'artifactLocation': {'uri': f['path']},
                                                'region': {'startLine': max(1, int(f['line'] or 1))}}}],
            'properties': dict({'security-severity': SECURITY_SEVERITY[sev], 'native_severity': f['severity'],
                                'observation': o},
                               **({'kit_secret_fingerprint': f['secret_fingerprint']} if f.get('secret_fingerprint') else {})),
        })
    run = {'tool': {'driver': {'name': driver, 'version': VERSION, 'semanticVersion': VERSION,
                               'informationUri': uri or 'https://example.invalid/kit/scripts/ai_artifact_inventory.py',
                               'rules': rules}},
           'invocations': [{'executionSuccessful': True}],
           'results': results,
           'properties': {'observation_source': inv.get('observation_source', 'static'), 'note': STATIC_NOTE,
                          'severity_cap': cap,
                          'base': inv.get('base', {}), 'counts': inv.get('counts', {})}}
    if inv.get('artifacts'):
        # Listed only when something was found: `artifacts: []` reads as "examined nothing" in the report,
        # and a repository with no agent artifacts was examined -- it simply has none.
        run['artifacts'] = [{'location': {'uri': a['path']}} for a in inv['artifacts']]
    return {'version': '2.1.0', '$schema': 'https://json.schemastore.org/sarif-2.1.0.json', 'runs': [run]}


def summary_md(inv):
    lines = ['### AI agent artifacts (static inventory, advisory)', '', STATIC_NOTE, '',
             'Base: %s (%s). %d artifact(s), %d MCP server(s), %d finding(s), %d artifact(s) need review.'
             % (inv['base']['ref'] or 'none', inv['base']['state'], inv['counts']['artifacts'],
                inv['counts']['mcp_servers'], inv['counts']['findings'], inv['counts']['review_required']), '']
    if inv['artifacts']:
        lines += ['| artifact | class | diff | flags | review |', '|---|---|---|---|---|']
        for a in inv['artifacts']:
            lines.append('| `%s` | %s | %s | %s | %s |' % (a['path'], a['class'], a.get('diff', ''),
                                                       ', '.join(a['flags']) or '-',
                                                       'REVIEW' if a['review_required'] else '-'))
    servers = [(a['path'], s) for a in inv['artifacts'] for s in a.get('servers', [])]
    if servers:
        lines += ['', '| MCP server | file | transport | command / host | pinned | env names |', '|---|---|---|---|---|---|']
        for p, s in servers:
            lines.append('| %s | `%s` | %s | %s | %s | %s |' % (
                s['name'], p, s['transport'], s['remote_host'] or (s['command'] + ' ' + s['package']).strip(),
                {True: 'yes', False: 'NO', None: 'n/a'}[s['pinned']], ', '.join(s['env_names']) or '-'))
    if inv['removed']:
        lines += ['', 'Removed versus the base: ' + ', '.join('`%s`' % r for r in inv['removed'])]
    return '\n'.join(lines) + '\n'


# ── convert: the adapter seam (runtime or static records -> the external evidence contract) ─
def validate_observation(o):
    why = []
    if not isinstance(o, dict):
        return ['not an object']
    for k in OBSERVATION_FIELDS:
        if k not in o:
            why.append('missing %s' % k)
    if 'schema' in o and o.get('schema') != SCHEMA:
        why.append('schema %r is not %s' % (o.get('schema'), SCHEMA))
    if o.get('observation_source') not in OBSERVATION_SOURCES:
        why.append('observation_source %r is not static|runtime' % o.get('observation_source'))
    if o.get('severity') not in SEVERITIES:
        why.append('severity %r is not high|medium|low|info' % o.get('severity'))
    if o.get('policy_decision') not in POLICY_DECISIONS:
        why.append('policy_decision %r is not review-required|advisory' % o.get('policy_decision'))
    if not isinstance(o.get('provenance'), dict) or not o['provenance'].get('producer'):
        why.append('provenance.producer missing')
    if not str(o.get('finding_id') or '').strip():
        why.append('finding_id empty')
    return why


def convert(path, name, out_dir, cap='medium'):
    """Records an adapter produced -> ext-<name>.sarif + state-ext-<name>.json (KDEC-028 contract).
    A record out of shape is REFUSED by name and not converted; it never becomes a clean row."""
    if not re.match(r'^ext-[a-z0-9][a-z0-9-]*$', name or ''):
        raise ValueError('name %r is not ext-<lowercase>' % name)
    doc = json.load(io.open(path, encoding='utf-8'))
    recs = doc.get('observations') if isinstance(doc, dict) else doc
    if not isinstance(recs, list):
        raise ValueError('no observations array in %s' % path)
    good, refused = [], []
    for i, o in enumerate(recs):
        why = validate_observation(o)
        (refused if why else good).append((i, o, why))
    findings, obs = [], []
    for _, o, _ in good:
        pv = o['provenance']
        findings.append({'rule': str(o['finding_id']).split('/', 1)[-1], 'path': str(pv.get('path') or o['component']),
                         'line': int(pv.get('line') or 1), 'detail': '%s: %s' % (o['component'], o['effective_permission_or_destination']),
                         'component': o['component'], 'component_class': o.get('component_class', ''),
                         'severity': o['severity'], 'confidence': pv.get('confidence', 'medium'),
                         'review_required': o['policy_decision'] == 'review-required'})
        obs.append(o)
    inv = {'findings': findings, 'observations': obs, 'artifacts': [],
           'observation_source': 'runtime' if any(o['observation_source'] == 'runtime' for o in obs) else 'static',
           'base': {}, 'counts': {'findings': len(findings), 'refused': len(refused)}}
    sarif = to_sarif(inv, driver=name, cap=cap)
    for r, f in zip(sarif['runs'][0]['results'], findings):
        r['ruleId'] = 'ai-artifact/' + f['rule']
        r['message']['text'] = _redact('%s: %s. %s' % (f['rule'], f['detail'], 'Review required.' if f['review_required'] else 'Advisory.'))
        if inv['observation_source'] == 'runtime':
            r['message']['text'] += ' Runtime observation from %s.' % name
    os.makedirs(out_dir, exist_ok=True)
    sp = os.path.join(out_dir, '%s.sarif' % name)
    json.dump(sarif, io.open(sp, 'w', encoding='utf-8'), indent=1)
    row = {'scanner': name, 'job': 'external', 'applicability': 'APPLICABLE',
           'execution': 'COMPLETE' if not refused else 'COLLECTION_FAILED',
           'scope': 'ai agent observations', 'sarif': '%s.sarif' % name, 'artifact': 'RETAINED', 'upload': 'COMPLETE',
           'gate': 'UNDETERMINED',
           'subject': 'RUNTIME_OBSERVATION' if inv['observation_source'] == 'runtime' else 'SOURCE',
           'external': True}
    json.dump(row, io.open(os.path.join(out_dir, 'state-%s.json' % name), 'w', encoding='utf-8'), indent=1)
    return len(good), [(i, why) for i, _, why in refused]


def reroot(inv, prefix):
    """Paths are relative to the scanned root; a scan of a sub-path names them from the repository root."""
    p = (prefix or '').strip().strip('/')
    if p.startswith('./'):
        p = p[2:]
    if not p or p == '.':
        return inv

    def j(x):
        return '%s/%s' % (p, x) if x else x
    for a in inv['artifacts']:
        a['path'] = j(a['path'])
    for f in inv['findings']:
        f['path'] = j(f['path'])
        f['component'] = re.sub(r'^(artifact|mcp):', lambda m: m.group(0) + p + '/', f['component'])
    for o in inv['observations']:
        o['provenance']['path'] = j(o['provenance']['path'])
        o['component'] = re.sub(r'^(artifact|mcp):', lambda m: m.group(0) + p + '/', o['component'])
    inv['removed'] = [j(r) for r in inv['removed']]
    return inv


def main(argv=None):
    ap = argparse.ArgumentParser(description='Inventory AI-agent steering artifacts (static, never executes).')
    sub = ap.add_subparsers(dest='cmd')
    s = sub.add_parser('scan')
    s.add_argument('--root', default='.')
    s.add_argument('--base-ref', default='')
    s.add_argument('--repository', default='')
    s.add_argument('--commit', default='')
    s.add_argument('--timestamp', default='')
    s.add_argument('--json-output', required=True)
    s.add_argument('--sarif-output', required=True)
    s.add_argument('--summary', default='')
    s.add_argument('--uri-prefix', default='', help='the scanned root relative to the repository, so paths are repository-relative')
    s.add_argument('--severity-cap', default='medium', choices=sorted(RANK),
                   help='the highest severity the SARIF carries; medium keeps the row advisory (KDEC-063)')
    c = sub.add_parser('convert')
    c.add_argument('--observations', required=True)
    c.add_argument('--name', required=True)
    c.add_argument('--out-dir', required=True)
    c.add_argument('--severity-cap', default='medium', choices=sorted(RANK))
    a = ap.parse_args(argv)
    if a.cmd == 'scan':
        if not os.path.isdir(a.root):
            sys.stderr.write('root %s is not a directory\n' % a.root)
            return 2
        inv = reroot(scan(a.root, a.base_ref, a.repository, a.commit, a.timestamp), a.uri_prefix)
        json.dump(inv, io.open(a.json_output, 'w', encoding='utf-8'), indent=1)
        json.dump(to_sarif(inv, cap=a.severity_cap), io.open(a.sarif_output, 'w', encoding='utf-8'), indent=1)
        if a.summary:
            io.open(a.summary, 'w', encoding='utf-8').write(summary_md(inv))
        print('ai-artifact-inventory: %d artifact(s), %d MCP server(s), %d finding(s), %d need review; base %s (%s). %s'
              % (inv['counts']['artifacts'], inv['counts']['mcp_servers'], inv['counts']['findings'],
                 inv['counts']['review_required'], a.base_ref or 'none', inv['base']['state'], STATIC_NOTE))
        return 0
    if a.cmd == 'convert':
        try:
            n, refused = convert(a.observations, a.name, a.out_dir, a.severity_cap)
        except (ValueError, OSError) as e:
            sys.stderr.write('convert refused: %s\n' % e)
            return 2
        for i, why in refused:
            sys.stderr.write('observation %d REFUSED: %s\n' % (i, '; '.join(why)))
        print('converted %d observation(s), refused %d' % (n, len(refused)))
        return 0 if not refused else 2
    ap.print_help()
    return 2


if __name__ == '__main__':
    sys.exit(main())

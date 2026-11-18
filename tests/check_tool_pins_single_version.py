#!/usr/bin/env python3
"""One tool, one version, one digest: everywhere in the kit, the one `.github/tool-pins.json` names.

WHY THIS EXISTS (kit-tools lane, 2026-11-07)

    The kit pinned syft 1.52.0 in the flagship's sbom job and the self-test tools, and 1.54.1 in both
    build paths, the static-site packager and the scanner probe; actionlint 1.7.7 in self-test and
    1.7.12 in deps-scan and the probe; osv-scanner 2.6.0 in the malicious-deps job and 2.7.0 in the
    probe; checkov 3.3.29 (pip, probe) beside the 3.3.30 image; PyYAML 6.0.2 beside 6.0.3. Every one
    was pinned and checksummed -- tests/check_pinned_installs.py passed -- and still the proof ran
    one release and the job another. A pin proves the bytes; only ONE pin makes "the proof measured
    what the job runs" true. The local battery could not prove the build round trip at all: it
    placed the self-test pin (1.52.0) and the build step asks for 1.54.1.

WHAT THIS CHECKS (static; every code file under the kit root except docs/, .context/ and the
seeded consumer fixtures, whose versions are deliberate vulnerable seeds)

    V1  A tool the registry names appears with any other version: an asset name (syft_1.52.0_...),
        a step name or message ("osv-scanner v2.6.0"), a pip/npm pin (semgrep==..., cli@...), a
        literal a test asserts (get('syft') == '1.52.0'). Comment lines are not read.
    V2  A release download (github.com/<repo>/releases/download/<tag>/) of a registered repo whose
        tag -- after substituting the shell variable, env key or workflow-input default it names --
        is another version. An unresolvable tag is a violation too (a pin nobody can read).
    V3  A sha256 next to a tool (the line or the four before it) that is not that tool's registered
        digest: another release's checksum, or a typo.
    V4  An image by digest (name[:tag]@sha256:...) whose digest or tag is not the registered one.
    V5  A release download or image digest of a tool the registry does not name, outside overlays/
        (an overlay is not the neutral core; its pins are held only to one version each).
    V6  The registry itself: every tool has a version; every digest is 64 hex; an exception names
        files and a reason, and is used.

    An EXCEPTION is a second version something else requires (mobsfscan 1.0.1 pins semgrep 1.172.0),
    scoped to the files it names. Anywhere else it is a V1.

EXIT 0 one version per tool everywhere; 1 a violation; 2 the registry could not be read.
"""
import io
import json
import os
import re
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
REGISTRY_REL = '.github/tool-pins.json'
SKIP_DIRS = {'.git', 'node_modules', '__pycache__', '.venv', 'venv'}
# Not code: prose that records what was measured on which release, and the history around it.
SKIP_PREFIXES = ('docs/', '.context/', 'tests/consumer-fixture/', 'tests/fixtures/', 'tests/corpora/sarif/')
CODE_EXT = ('.yml', '.yaml', '.py', '.sh', '.ps1', '.psm1', '.json', '.js', '.mjs', '.cjs', '.ts', '.toml',
            '.tf', '.bicep', '.cfg', '.ini')
SEMVER = re.compile(r'(?<![A-Za-z0-9.])v?(\d+\.\d+\.\d+(?:\.\d+)?)(?!\.?\d)')
HEX64 = re.compile(r'(?<![0-9a-f])([0-9a-f]{64})(?![0-9a-f])')
RELEASE = re.compile(r'github\.com/([\w.-]+/[\w.-]+)/releases/download/([^/\s"\']+)/')
IMAGE = re.compile(r'([a-z0-9][\w.-]*(?:/[\w.-]+)*)(?::([\w.-]+))?@sha256:([0-9a-f]{64})')
# Where the kit installs and runs tools: every version written near a tool's name there is a pin.
PIN_SURFACES = ('.github/', 'templates/', 'wiring/', 'tools/', 'overlays/')
# Everywhere else (scripts, tests, root data files) tools are named in prose and in fixture data
# (a SARIF driver version, a rule-family upgrade from 1.45.0 to 1.92.1) that are not pins; there a
# version is read only when it is written AS a pin: an asset name, a pip/npm pin, a tool-named
# version variable assignment, or a literal compared with the tool's pin.
PIN_SHAPED = re.compile(r'''^(?:[_-]v?|(?:\[[\w,]+\])?==|@v?|_VERSION\s*[=:]\s*['"]?v?|['"]\)\s*==\s*['"]v?|'''
                        r'''['"]\s*:\s*['"]v?)$''', re.IGNORECASE)
SELF_REL = 'tests/check_tool_pins_single_version.py'   # the rule: its mutants name old releases on purpose
# Not pins: records of what a copy received, one sha256 per FILE, named after the files (an exported
# copy's watermark lists tests/prove_trivy_*.py, scripts/sbom_licenses.py, ...). Found on the first
# neutral export of this check (2026-11-07): 50 V3s, every one a file digest beside a file name.
RECORD_FILES = ('.neutral-export-watermark.json',)
WINDOW = 50       # characters after a tool's name in which its version is read (V1)
HASH_CONTEXT = 4  # lines above a digest in which its tool is named (V3)


def load_registry(root=ROOT):
    with io.open(os.path.join(root, REGISTRY_REL), encoding='utf-8') as fh:
        return json.load(fh)


def check_registry(reg):
    bad = []
    tools = reg.get('tools')
    if not isinstance(tools, dict) or not tools:
        return ['V6 the registry has no tools']
    for name, t in tools.items():
        if not SEMVER.fullmatch(str(t.get('version') or '')):
            bad.append('V6 %s: version %r is not X.Y.Z' % (name, t.get('version')))
        if not t.get('aliases'):
            bad.append('V6 %s: no aliases (the names it is written under)' % name)
        if not t.get('source'):
            bad.append('V6 %s: no source (where the version and digest were published)' % name)
        digests = list((t.get('sha256') or {}).values()) + [(t.get('image') or {}).get('digest')]
        for e in t.get('exceptions') or []:
            digests += e.get('sha256') or []
            if not e.get('files') or not e.get('why') or not SEMVER.fullmatch(str(e.get('version') or '')):
                bad.append('V6 %s: an exception needs a version, the files it is limited to and why' % name)
            if e.get('version') == t.get('version'):
                bad.append('V6 %s: an exception for the pinned version itself' % name)
        for asset in t.get('sha256') or {}:
            m = SEMVER.search(asset)
            if m and m.group(1) != t.get('version'):
                bad.append('V6 %s: asset %s is not version %s' % (name, asset, t.get('version')))
        for d in digests:
            if d is not None and not re.fullmatch(r'[0-9a-f]{64}', str(d)):
                bad.append('V6 %s: digest %r is not 64 lowercase hex' % (name, d))
    for name, im in (reg.get('images') or {}).items():
        if not re.fullmatch(r'[0-9a-f]{64}', str(im.get('digest') or '')):
            bad.append('V6 image %s: digest is not 64 lowercase hex' % name)
    return bad


def iter_tree(root=ROOT):
    """-> {rel: text} for every code file in scope."""
    out = {}
    for d, dirs, files in os.walk(root):
        dirs[:] = sorted(x for x in dirs if x not in SKIP_DIRS)
        for f in sorted(files):
            p = os.path.join(d, f)
            rel = os.path.relpath(p, root).replace(os.sep, '/')
            if rel in (REGISTRY_REL, SELF_REL) or rel in RECORD_FILES or rel.startswith(SKIP_PREFIXES):
                continue
            if not (f.endswith(CODE_EXT) or f == 'Dockerfile'):
                continue
            try:
                with io.open(p, encoding='utf-8') as fh:
                    out[rel] = fh.read()
            except (OSError, UnicodeDecodeError):
                continue
    return out


def _alias_rx(alias):
    # Not part of a longer word: trivy-action, setup-trivy and checkov-action are other things; an
    # asset suffix (-12.2.2, -v0.11.0, _1.54.1) and a tool-named version variable are the tool's own.
    return re.compile(r'(?<![A-Za-z0-9.])(?<![A-Za-z0-9]-)%s(?![A-Za-z0-9])(?!-(?!v?\d))' % re.escape(alias),
                      re.IGNORECASE)


class Index(object):
    def __init__(self, reg):
        self.reg = reg
        self.tools = reg['tools']
        self.alias = []   # (rx, tool)
        for name, t in self.tools.items():
            for a in t.get('aliases') or []:
                self.alias.append((_alias_rx(a), name))
        self.by_repo = {t['repo'].lower(): n for n, t in self.tools.items() if t.get('repo')}
        self.images = {}
        for n, t in self.tools.items():
            if t.get('image'):
                self.images[t['image']['name']] = (n, t['image'].get('tag'), t['image']['digest'])
        for n, im in (reg.get('images') or {}).items():
            self.images[n] = (None, im.get('tag'), im['digest'])
        self.used_exceptions = set()

    def allowed(self, tool, version, rel, line=''):
        t = self.tools[tool]
        if version == t['version']:
            return True
        for i, e in enumerate(t.get('exceptions') or []):
            # `line_contains` narrows an exception to the lines that carry that text (a measurement
            # record inside a file that also holds the pin).
            if e['version'] == version and rel in e['files'] and e.get('line_contains', '') in line:
                self.used_exceptions.add((tool, i))
                return True
        return False

    def digests(self, tool, rel):
        t = self.tools[tool]
        ds = set((t.get('sha256') or {}).values())
        if t.get('image'):
            ds.add(t['image']['digest'])
        for i, e in enumerate(t.get('exceptions') or []):
            if rel in e['files'] and e.get('sha256'):
                ds.update(e['sha256'])
        return ds

    def mentions(self, text):
        """-> [(start, end, tool)] sorted by position."""
        hits = []
        for rx, tool in self.alias:
            for m in rx.finditer(text):
                hits.append((m.start(), m.end(), tool))
        return sorted(hits)

    def image_entry(self, name):
        for reg_name, entry in self.images.items():
            if name == reg_name or name.endswith('/' + reg_name):
                return reg_name, entry
        return None, None


def is_comment(line):
    s = line.lstrip()
    return s.startswith('#') or s.startswith('//')


def resolve_tag(tag, lines, i, depth=0):
    """Substitute the variables a release tag names, from the lines above it. -> [str], empty when
    it cannot be read. `${{ inputs.X }}` is X's default; `${{ matrix.X }}` every value the file's
    matrix lists for X (each leg is a pin)."""
    m = re.search(r'\$\{?([A-Za-z_][A-Za-z0-9_]*)\}?', tag)
    if not m:
        return [tag]
    if depth > 5:
        return []
    found = lookup(m.group(1), lines, i)
    if found is None:
        return []
    val, j = found
    vals = [val]
    ref = re.search(r'\$\{\{\s*(inputs|matrix)\.([\w-]+)\s*\}\}', val)
    if ref and ref.group(1) == 'inputs':
        d = input_default(lines, ref.group(2))
        vals = [d] if d is not None else []
    elif ref:
        vals = matrix_values(lines, ref.group(2))
    out = []
    for v in vals:
        out += resolve_tag(tag[:m.start()] + v + tag[m.end():], lines, j, depth + 1)
    return out


def matrix_values(lines, key):
    vals = []
    for line in lines:
        mm = re.match(r'''^\s*(?:-\s*)?%s:\s*(\[.*\]|["']?[^"'\s#]+["']?)\s*(?:#.*)?$''' % re.escape(key), line)
        if mm:
            raw = mm.group(1)
            if raw.startswith('['):
                vals += [x.strip(''' "''') for x in raw.strip('[]').split(',')]
            else:
                vals.append(raw.strip('''"\''''))
    return [v for v in vals if v and '$' not in v]


def lookup(var, lines, i):
    """The nearest `VAR=value` or `VAR: value` at or above line i. -> (value, line) or None."""
    assign = re.compile(r'(?:^|[\s;{(])(?:export\s+|local\s+)?%s\s*(?:=|:\s)\s*' % re.escape(var))
    for j in range(i, max(-1, i - 200), -1):
        line = lines[j]
        if is_comment(line):
            continue
        last = None
        for hm in assign.finditer(line):
            last = hm
        if last:
            rest = line[last.end():]
            m = (re.match(r'(\$\{\{[^}]*\}\})', rest) or re.match(r'["\']([^"\']*)["\']', rest) or
                 re.match(r'([^\s;]+)', rest))
            if m:
                return m.group(1), j - 1 if j > 0 else 0
    return None


def input_default(lines, name):
    for j, line in enumerate(lines):
        if re.match(r'^\s+%s:\s*$' % re.escape(name), line):
            for k in range(j + 1, min(len(lines), j + 40)):
                d = re.match(r'^\s+default:\s*["\']?([^"\'\s]+)', lines[k])
                if d:
                    return d.group(1)
                if re.match(r'^\s{0,%d}[\w-]+:\s*$' % (len(line) - len(line.lstrip())), lines[k]):
                    break
    return None


def scan(files, reg):
    """-> [violation]. `files` is {rel: text}."""
    ix = Index(reg)
    bad = []
    seen_unregistered = {}   # repo or image -> {version/digest: [where]}
    for rel in sorted(files):
        lines = files[rel].splitlines()
        overlay = rel.startswith('overlays/')
        surface = rel.startswith(PIN_SURFACES)
        for i, line in enumerate(lines):
            if is_comment(line):
                continue
            where = '%s:%d' % (rel, i + 1)
            hits = ix.mentions(line)
            # V1: the first version after each mention, before any other tool is named.
            for n, (s, e, tool) in enumerate(hits):
                stop = min([h[0] for h in hits[n + 1:] if h[2] != tool] + [e + WINDOW])
                m = SEMVER.search(line, e, stop)
                if m and not surface and (not PIN_SHAPED.match(line[e:m.start()]) or
                                          re.search(r'pkg:[a-z]+/$', line[:s])):
                    continue   # prose or fixture data; a purl names a package, not an install
                if m and not ix.allowed(tool, m.group(1), rel, line):
                    bad.append('V1 %s: %s %s, the registry pins %s -- `%s`'
                               % (where, tool, m.group(1), ix.tools[tool]['version'], line.strip()[:120]))
            # V2: release downloads.
            for m in RELEASE.finditer(line):
                repo, tag = m.group(1).lower(), m.group(2)
                tool = ix.by_repo.get(repo)
                vs = [SEMVER.search(r) for r in resolve_tag(tag, lines, i)]
                v = vs[0] if vs and all(vs) else None
                if tool is None:
                    key = 'release ' + repo
                    if surface:
                        seen_unregistered.setdefault(key, {}).setdefault(v.group(1) if v else tag, []).append(where)
                    if surface and not overlay:
                        bad.append('V5 %s: %s is downloaded but not in %s' % (where, repo, REGISTRY_REL))
                    continue
                if not v:
                    bad.append('V2 %s: the %s release tag %r cannot be read (a pin nobody can check)'
                               % (where, tool, tag))
                    continue
                for x in vs:
                    if not ix.allowed(tool, x.group(1), rel, line):
                        bad.append('V2 %s: downloads %s %s, the registry pins %s'
                                   % (where, tool, x.group(1), ix.tools[tool]['version']))
                # V3 for a matrix: a digest the step reads from `${{ matrix.K }}` is every K the
                # matrix lists, each of them a registered digest of the tool this step downloads.
                for k in sorted({mm.group(1) for x in lines[max(0, i - 15):i + 6]
                                 for mm in re.finditer(r'\$\{\{\s*matrix\.([\w-]+)\s*\}\}', x)}):
                    for d in matrix_values(lines, k):
                        if re.fullmatch(r'[0-9a-f]{64}', d) and d not in ix.digests(tool, rel):
                            bad.append('V3 %s: matrix.%s digest %s... for %s is not a registered digest'
                                       % (where, k, d[:12], tool))
            # V4: images by digest.
            image_digests = set()
            for m in IMAGE.finditer(line):
                name, tag, digest = m.group(1), m.group(2), m.group(3)
                image_digests.add(digest)
                reg_name, entry = ix.image_entry(name)
                if entry is None:
                    if surface:
                        seen_unregistered.setdefault('image ' + name, {}).setdefault(digest, []).append(where)
                    if surface and not overlay:
                        bad.append('V5 %s: image %s is pinned but not in %s' % (where, name, REGISTRY_REL))
                    continue
                _, want_tag, want = entry
                if digest != want:
                    bad.append('V4 %s: image %s@sha256:%s..., the registry pins %s...'
                               % (where, reg_name, digest[:12], want[:12]))
                if tag and want_tag and tag != want_tag:
                    bad.append('V4 %s: image %s:%s, the registry pins tag %s' % (where, reg_name, tag, want_tag))
            # V3: a digest beside a tool is that tool's registered digest.
            for m in HEX64.finditer(line):
                h = m.group(1)
                if h in image_digests or 'kit-scripts' in line:
                    continue
                # On a pin surface the tool may be named in a comment above its digest ("# osv-scanner
                # v2.7.0, ..."); elsewhere comments name tools beside unrelated digests (a composite's
                # canonical hash), so only code lines identify the tool.
                ctx = '\n'.join(x for x in lines[max(0, i - HASH_CONTEXT):i + 1] if surface or not is_comment(x))
                near = {t for _, _, t in ix.mentions(ctx)}
                if not near:
                    continue
                ok = set()
                for t in near:
                    ok |= ix.digests(t, rel)
                if h not in ok:
                    bad.append('V3 %s: sha256 %s... beside %s is not a registered digest (another release, '
                               'or a typo)' % (where, h[:12], ', '.join(sorted(near))))
    for key, vals in sorted(seen_unregistered.items()):
        if len(vals) > 1:
            bad.append('V5 %s: %d different pins (%s)' % (key, len(vals), '; '.join(
                '%s at %s' % (v[:16], w[0]) for v, w in sorted(vals.items()))))
    for name, t in ix.tools.items():
        for i, e in enumerate(t.get('exceptions') or []):
            if (name, i) not in ix.used_exceptions:
                bad.append('V6 %s: the exception for %s is used nowhere (remove it)' % (name, e['version']))
    return sorted(set(bad), key=bad.index)


# ── self-test: the rule on samples and on mutants of the real tree ────────────────────────────

SAMPLE_REG = {'tools': {
    'kitfake': {'version': '1.2.3', 'repo': 'example/kitfake', 'aliases': ['kitfake'], 'source': 'x',
                'sha256': {'kitfake_1.2.3_linux.tgz': 'a' * 64},
                'image': {'name': 'example/kitfake', 'tag': '1.2.3', 'digest': 'b' * 64},
                'exceptions': [{'version': '1.0.0', 'files': ['.github/needs-old.yml'], 'why': 'y'}]},
    'other': {'version': '2.0.0', 'aliases': ['other'], 'source': 'x', 'sha256': {}}}}
GOOD = {
    '.github/workflows/a.yml': ('      - name: kitfake 1.2.3 and other 2.0.0\n'
              '        run: |\n'
              '          v=1.2.3; t=kitfake_${v}_linux.tgz\n'
              '          curl -sSfLO "https://github.com/example/kitfake/releases/download/v${v}/${t}"\n'
              '          echo "' + 'a' * 64 + '  $t" | sha256sum -c -\n'
              '          # kitfake 0.9.9 was the release before (a comment is history, not a pin)\n'
              '      - uses: docker://example/kitfake:1.2.3@sha256:' + 'b' * 64 + '\n'),
    '.github/needs-old.yml': 'pip install kitfake==1.0.0\n',
    '.github/workflows/m.yml': ('    strategy:\n      matrix:\n        include:\n          - version: "1.2.3"\n'
                                '            sha256: "' + 'a' * 64 + '"\n'
                                '    steps:\n      - env:\n          V: ${{ matrix.version }}\n'
                                '          SHA: ${{ matrix.sha256 }}\n'
                                '        run: curl -sSfLO "https://github.com/example/kitfake/releases/download/v${V}/k"\n'),
    't.py': "assert pins.get('kitfake') == '1.2.3'\n",
}
MUTANTS = [
    ('M1 an asset name of another release', '.github/workflows/a.yml', 'kitfake_${v}_linux', 'kitfake_1.2.4_linux', 'V1'),
    ('M2 the version variable a release URL reads', '.github/workflows/a.yml', 'v=1.2.3', 'v=1.2.30', 'V2'),
    ('M3 one digit of the digest', '.github/workflows/a.yml', 'a' * 64, 'a' * 63 + 'c', 'V3'),
    ('M4 the image digest', '.github/workflows/a.yml', 'b' * 64, 'b' * 63 + 'c', 'V4'),
    ('M5 the image tag', '.github/workflows/a.yml', 'kitfake:1.2.3@', 'kitfake:1.2.4@', 'V4'),
    ('M6 a step name naming another release', '.github/workflows/a.yml', 'kitfake 1.2.3 and', 'kitfake 1.3.0 and', 'V1'),
    ('M7 the exception outside its file', 't.py', "'1.2.3'", "'1.0.0'", 'V1'),
    ('M8 a test asserting another release', 't.py', "'1.2.3'", "'1.2.2'", 'V1'),
    ('M9 a download of a tool nobody registered', '.github/workflows/a.yml', 'example/kitfake/releases', 'example/unlisted/releases', 'V5'),
    ('M10 a tag nobody can read', '.github/workflows/a.yml', 'v=1.2.3; ', '', 'V2'),
    ('M13 a matrix leg of another release', '.github/workflows/m.yml', 'version: "1.2.3"', 'version: "1.2.4"', 'V2'),
    ("M14 a matrix leg's digest", '.github/workflows/m.yml', 'sha256: "' + 'a' * 64, 'sha256: "' + 'a' * 63 + 'd', 'V3'),
]


def self_test():
    problems = []
    if scan(GOOD, SAMPLE_REG) or check_registry(SAMPLE_REG):
        problems.append('the good sample was refused: %r' % (scan(GOOD, SAMPLE_REG) + check_registry(SAMPLE_REG)))
    for label, f, old, new, code in MUTANTS:
        files = dict(GOOD)
        if old not in files[f]:
            problems.append('%s: the sample has no %r to mutate' % (label, old))
            continue
        files[f] = files[f].replace(old, new, 1)
        got = scan(files, SAMPLE_REG)
        if not any(g.startswith(code + ' ') for g in got):
            problems.append('%s: survived (want %s, got %r)' % (label, code, got))
    reg = json.loads(json.dumps(SAMPLE_REG))
    reg['tools']['kitfake']['exceptions'][0]['files'] = ['nowhere.yml']
    if not any(g.startswith('V6 ') for g in scan({k: v for k, v in GOOD.items() if k != '.github/needs-old.yml'}, reg)):
        problems.append('M11 an unused exception survived')
    reg = json.loads(json.dumps(SAMPLE_REG))
    reg['tools']['kitfake']['sha256'] = {'kitfake_1.2.3_linux.tgz': 'A' * 64}
    if not check_registry(reg):
        problems.append('M12 a registry digest that is not lowercase hex survived')
    problems += record_file_proof()
    return problems


def record_file_proof():
    """The export watermark is skipped by exact path only: a stale pin anywhere else in the same export is still refused."""
    import tempfile
    problems = []
    wm = '.neutral-export-watermark.json'
    record = '{"tests/kitfake_1.2.9_linux.py": "' + 'c' * 64 + '"}\n'
    with tempfile.TemporaryDirectory() as d:
        def put(rel, text):
            p = os.path.join(d, *rel.split('/'))
            os.makedirs(os.path.dirname(p), exist_ok=True)
            with io.open(p, 'w', encoding='utf-8', newline='') as fh:
                fh.write(text)
        put(wm, record)
        put('.github/workflows/a.yml', GOOD['.github/workflows/a.yml'].replace('kitfake_${v}_linux', 'kitfake_1.2.4_linux', 1))
        put('sub/' + wm, record)
        seen = iter_tree(d)
        if wm in seen:
            problems.append('W1 the root watermark was read, not skipped')
        if 'sub/' + wm not in seen:
            problems.append('W2 a watermark-named file in a subfolder was skipped (the skip must be by exact path)')
        if '.github/workflows/a.yml' not in seen:
            problems.append('W3 a workflow beside the watermark was not read')
        elif not any(g.startswith('V1 ') for g in scan({'.github/workflows/a.yml': seen['.github/workflows/a.yml']}, SAMPLE_REG)):
            problems.append('W4 a stale pin beside the watermark was not refused with V1')
        if not any(g.startswith('V') for g in scan({wm: record}, SAMPLE_REG)):
            problems.append('W5 the watermark sample is not pin-shaped, so skipping it proves nothing')
    return problems


def real_tree_mutants(files, reg):
    """The three divergences that made this check, put back one at a time, must each be refused."""
    out = []
    plan = [
        ('R1 syft 1.52.0 back in the sbom job', '.github/workflows/reusable-security.yml',
         'syft_1.54.1_linux_amd64', 'syft_1.52.0_linux_amd64'),
        ('R2 actionlint 1.7.7 back in self-test', '.github/workflows/self-test.yml', 'v=1.7.12;', 'v=1.7.7;'),
        ('R3 osv-scanner v2.6.0 back in the malicious-deps job', '.github/workflows/reusable-security.yml',
         'OSV_VERSION: v2.7.0', 'OSV_VERSION: v2.6.0'),
        ('R4 the 2.6.0 osv digest beside the 2.7.0 pin', '.github/actions/selftest-tools/action.yml',
         reg['tools']['osv-scanner']['sha256']['osv-scanner_linux_amd64'],
         'ca69b3d3cd08f889a49dc0a383122f71cc528b83803671df5fd874d97485b108'),
    ]
    for label, f, old, new in plan:
        if f not in files or old not in files[f]:
            out.append('%s: %s has no %r to put back (the mutant cannot run)' % (label, f, old))
            continue
        mutated = dict(files)
        mutated[f] = mutated[f].replace(old, new, 1)
        if not scan(mutated, reg):
            out.append('%s: survived' % label)
    return out


def main(argv):
    problems = self_test()
    if problems:
        for p in problems:
            print('SELF-TEST FAILED: ' + p)
        return 1
    try:
        reg = load_registry()
    except (OSError, ValueError) as e:
        print('UNKNOWN: %s could not be read: %s' % (REGISTRY_REL, e))
        return 2
    bad = check_registry(reg)
    files = iter_tree()
    bad += scan(files, reg)
    if '--inventory' in argv:
        for name, t in sorted(reg['tools'].items()):
            print('%-20s %-10s %s' % (name, t['version'], t['source']))
    if bad:
        for b in bad:
            print('FAIL: ' + b)
        print('FAIL: %d violation(s). One version per tool: change %s and every literal named above together.'
              % (len(bad), REGISTRY_REL))
        return 1
    mut = real_tree_mutants(files, reg)
    if mut:
        for m in mut:
            print('FAIL: ' + m)
        return 1
    print('PASS: %d tools and %d images, one version and one digest each, across %d code files; '
          '%d sample mutants and 4 old pins put back into the real tree were each refused.'
          % (len(reg['tools']), len(reg.get('images') or {}), len(files), len(MUTANTS) + 2))
    return 0


if __name__ == '__main__':
    sys.exit(main(sys.argv[1:]))

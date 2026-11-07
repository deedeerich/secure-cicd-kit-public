#!/usr/bin/env python3
"""Every Mermaid diagram in the repository parses, structurally, without node (owner, 2026-11-07).

WHY THIS EXISTS
    The architecture suite (docs/architecture/INDEX.md) is drawn in Mermaid so GitHub renders it in
    place. A diagram that does not parse renders as a red "Unable to render" box, and nothing in the
    battery would notice: the Markdown is valid, the file exists, every link resolves. The owner reads
    the picture, not the source, so a broken picture is a missing document that looks present.

    Installing node and the Mermaid CLI on every runner to parse a few dozen diagrams costs more than
    it buys. This is a PURE-PYTHON STRUCTURAL check of the subset the suite uses (00_NOTATION_AND_LEGEND.md):
    it does not render, and a diagram it passes can still render badly. What it catches is the class of
    break that actually happens when a diagram is edited by hand: an unbalanced bracket or quote, a
    subgraph with no `end`, a label with a raw parenthesis outside quotes, an edge to a node id that is
    a Mermaid keyword, a class used but never defined, a `style` for an id that does not exist, an
    `alt` with no `end` in a sequence diagram, a `state {` with no `}`.

RULES
    M1  every ```mermaid block declares a known diagram type on its first statement line
    M2  flowchart: quotes and edge-label pipes are balanced per line; brackets balance outside quotes;
        every statement is a node, an edge chain, subgraph/end, direction, classDef, class, style,
        linkStyle, click or a comment; subgraph and end balance; no node is called `end`;
        every `:::name` and `class ... name` names a classDef in the same block (or `default`);
        every `style ID` names a node or subgraph defined in the block
    M3  sequenceDiagram: every statement is a participant/actor, a message, a note, an
        activate/deactivate, autonumber, or a block keyword; alt/opt/loop/par/critical/break/rect
        balance with end; else/and only inside an open block
    M4  stateDiagram: braces balance; every statement is a transition, a state declaration, a note,
        direction, classDef/class, or a comment
    M5  the architecture suite (docs/architecture/[0-9][0-9]*_*.md, INDEX.md, code-walkthrough/):
        each file is at most 26000 bytes; every repository path it cites in backticks exists in the
        tree (tests/, scripts/, tools/, templates/, schemas/, api/, .github/, docs/), or is one the
        neutral export withholds (the public copy legitimately lacks it); INDEX.md links every suite
        document

    --self-test seeds one broken diagram per rule and a clean one, and requires each verdict.

EXIT  0 every diagram holds   1 a rule refused (each named, file and line)   2 could not be read
"""
import glob
import os
import re
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)

TYPES = ('flowchart', 'graph', 'sequenceDiagram', 'stateDiagram', 'stateDiagram-v2', 'classDiagram',
         'erDiagram', 'gantt', 'pie', 'journey', 'gitGraph', 'mindmap', 'timeline', 'quadrantChart',
         'C4Context', 'C4Container', 'C4Component', 'C4Dynamic', 'C4Deployment', 'block-beta',
         'sankey-beta', 'xychart-beta', 'requirementDiagram')
DIRS = ('TB', 'TD', 'BT', 'RL', 'LR')
SUITE_MAX = 26000

FENCE = re.compile(r'^\s*```mermaid\s*$')
QUOTED = re.compile(r'"[^"]*"')
ARROW = re.compile(r'\s*(?:<)?(?:-{2,}|={2,}|-\.+-)(?:[>xo])?\s*')
TEXT_ARROWS = [(re.compile(r'--\s*Q\s*--+>'), ' --> '), (re.compile(r'==\s*Q\s*==+>'), ' ==> '),
               (re.compile(r'-\.\s*Q\s*\.-+>'), ' -.-> '), (re.compile(r'--\s*Q\s*--+'), ' --- ')]
LABEL = r'(?:Q|[^\[\]\(\)\{\}"|<>]*)'
SHAPES = [r'\[\(' + LABEL + r'\)\]', r'\(\[' + LABEL + r'\]\)', r'\[\[' + LABEL + r'\]\]',
          r'\{\{' + LABEL + r'\}\}', r'\(\(' + LABEL + r'\)\)', r'\[/' + LABEL + r'/\]',
          r'\[\\' + LABEL + r'\\\]', r'\[/' + LABEL + r'\\\]', r'\[\\' + LABEL + r'/\]',
          r'\[' + LABEL + r'\]', r'\(' + LABEL + r'\)', r'\{' + LABEL + r'\}', r'>' + LABEL + r'\]']
NODE = re.compile(r'^([A-Za-z0-9_][\w-]*)\s*(' + '|'.join(SHAPES) + r')?\s*(?::::([\w-]+))?$')
KEYWORD_IDS = {'end', 'subgraph', 'graph', 'flowchart', 'class', 'classDef', 'style', 'click', 'linkStyle'}
SEQ_MSG = re.compile(r'^[^:]+?\s*(?:-->>|->>|-->|->|--x|-x|--\)|-\))\s*[+-]?[^:]+:.*$')
SEQ_PART = re.compile(r'^(?:participant|actor)\s+\S+(?:\s+as\s+.+)?$')
SEQ_NOTE = re.compile(r'^[Nn]ote\s+(?:over|left of|right of)\s+[^:]+:.*$')
SEQ_OPEN = ('alt', 'opt', 'loop', 'par', 'critical', 'break', 'rect')
STATE_LINE = [re.compile(p) for p in (
    r'^(?:\[\*\]|[\w.-]+)\s*-->\s*(?:\[\*\]|[\w.-]+)(?:\s*:.*)?$',
    r'^state\s+(?:"[^"]*"\s+as\s+)?[\w.-]+(?:\s+<<\w+>>)?\s*\{?$',
    r'^state\s+"[^"]*"\s+as\s+[\w.-]+$',
    r'^[\w.-]+\s*:\s*.+$', r'^\}$', r'^direction\s+(?:TB|TD|BT|RL|LR)$',
    r'^note\s+(?:left|right)\s+of\s+[\w.-]+\s*:.*$', r'^note\s+(?:left|right)\s+of\s+[\w.-]+$',
    r'^end note$', r'^classDef\s+\S+\s+.+$', r'^class\s+\S+\s+\S+$', r'^--$', r'^[\w.-]+$')]


def blocks(text):
    """Yield (start_line, [lines]) for every ```mermaid block."""
    lines = text.split('\n')
    i = 0
    while i < len(lines):
        if FENCE.match(lines[i]):
            start = i + 1
            body = []
            i += 1
            while i < len(lines) and not lines[i].strip().startswith('```'):
                body.append(lines[i])
                i += 1
            yield start + 1, body
        i += 1


def statements(body):
    """(line_offset, stripped statement) for each non-empty, non-comment line."""
    out = []
    for n, ln in enumerate(body):
        s = ln.strip()
        if not s or s.startswith('%%'):
            continue
        for part in s.split(';') if '"' not in s else [s]:
            part = part.strip()
            if part:
                out.append((n, part))
    return out


def balanced(s):
    pairs = {']': '[', ')': '(', '}': '{'}
    stack = []
    for ch in s:
        if ch in '[({':
            stack.append(ch)
        elif ch in '])}':
            if not stack or stack[-1] != pairs[ch]:
                return False
            stack.pop()
    return not stack


def check_flowchart(stmts):
    probs = []
    classdefs = {'default'}
    used = []
    ids = set()
    styles = []
    depth = 0
    for n, s in stmts[1:]:
        if s.count('"') % 2:
            probs.append((n, 'M2 unbalanced double quote'))
            continue
        q = QUOTED.sub('Q', s)
        head = q.split()[0] if q.split() else ''
        if head == 'subgraph':
            depth += 1
            m = re.match(r'^subgraph\s+([A-Za-z0-9_][\w-]*)', q)
            if m:
                ids.add(m.group(1))
            if not balanced(q):
                probs.append((n, 'M2 unbalanced brackets in subgraph title'))
            continue
        if q == 'end':
            depth -= 1
            if depth < 0:
                probs.append((n, 'M2 `end` with no open subgraph'))
                depth = 0
            continue
        if head == 'direction':
            if len(q.split()) != 2 or q.split()[1] not in DIRS:
                probs.append((n, 'M2 direction must be one of %s' % '/'.join(DIRS)))
            continue
        if head == 'classDef':
            parts = q.split()
            if len(parts) < 3:
                probs.append((n, 'M2 classDef needs a name and styles'))
            else:
                for nm in parts[1].split(','):
                    classdefs.add(nm)
            continue
        if head == 'class':
            parts = q.split()
            if len(parts) != 3:
                probs.append((n, 'M2 class statement is `class ID[,ID] name`'))
            else:
                used.append((n, parts[2]))
            continue
        if head == 'style':
            parts = q.split()
            if len(parts) < 3:
                probs.append((n, 'M2 style needs an id and styles'))
            else:
                styles.append((n, parts[1]))
            continue
        if head in ('linkStyle', 'click'):
            continue
        if q.count('|') % 2:
            probs.append((n, 'M2 unbalanced edge-label pipes'))
            continue
        q2 = re.sub(r'\|[^|]*\|', ' ', q)
        for rx, rep in TEXT_ARROWS:
            q2 = rx.sub(rep, q2)
        if not balanced(q2):
            probs.append((n, 'M2 unbalanced brackets outside quotes (quote a label that holds ( ) [ ] { })'))
            continue
        pieces = [p.strip() for p in ARROW.split(q2)]
        if any(p == '' for p in pieces):
            probs.append((n, 'M2 an edge with no node on one side'))
            continue
        for piece in pieces:
            for tok in [t.strip() for t in piece.split('&')]:
                m = NODE.match(tok)
                if not m:
                    probs.append((n, 'M2 not a node, edge or statement: %r' % tok[:60]))
                    continue
                if m.group(1) in KEYWORD_IDS:
                    probs.append((n, 'M2 a node may not be called %r' % m.group(1)))
                ids.add(m.group(1))
                if m.group(3):
                    used.append((n, m.group(3)))
    if depth:
        probs.append((stmts[-1][0], 'M2 %d subgraph(s) with no `end`' % depth))
    for n, nm in used:
        if nm not in classdefs:
            probs.append((n, 'M2 class %r is used and never defined by classDef' % nm))
    for n, sid in styles:
        if sid not in ids:
            probs.append((n, 'M2 style names %r, which no node or subgraph defines' % sid))
    return probs


def check_sequence(stmts):
    probs = []
    stack = []
    for n, s in stmts[1:]:
        head = s.split()[0]
        if head in SEQ_OPEN:
            stack.append(head)
            continue
        if head in ('else', 'and', 'option'):
            if not stack:
                probs.append((n, 'M3 %r outside an open block' % head))
            continue
        if s == 'end':
            if not stack:
                probs.append((n, 'M3 `end` with no open block'))
            else:
                stack.pop()
            continue
        if s == 'autonumber' or head in ('activate', 'deactivate', 'box', 'create', 'destroy', 'title'):
            continue
        if SEQ_PART.match(s) or SEQ_NOTE.match(s) or SEQ_MSG.match(s):
            continue
        probs.append((n, 'M3 not a sequence statement: %r' % s[:60]))
    if stack:
        probs.append((stmts[-1][0], 'M3 %s with no `end`' % ', '.join(stack)))
    return probs


def check_state(stmts):
    probs = []
    depth = 0
    for n, s in stmts[1:]:
        if s.endswith('{'):
            depth += 1
        if s == '}':
            depth -= 1
            if depth < 0:
                probs.append((n, 'M4 `}` with no open state'))
                depth = 0
            continue
        if not any(rx.match(s) for rx in STATE_LINE):
            probs.append((n, 'M4 not a state statement: %r' % s[:60]))
    if depth:
        probs.append((stmts[-1][0], 'M4 %d state block(s) with no `}`' % depth))
    return probs


def check_block(body):
    stmts = statements(body)
    if not stmts:
        return [(0, 'M1 an empty mermaid block')]
    first = stmts[0][1].split()
    kind = first[0]
    if kind not in TYPES:
        return [(stmts[0][0], 'M1 unknown diagram type %r' % kind)]
    if kind in ('flowchart', 'graph'):
        if len(first) > 1 and first[1] not in DIRS:
            return [(stmts[0][0], 'M1 unknown flowchart direction %r' % first[1])]
        return check_flowchart(stmts)
    if kind == 'sequenceDiagram':
        return check_sequence(stmts)
    if kind.startswith('stateDiagram'):
        return check_state(stmts)
    return []


def check_text(text):
    out = []
    for start, body in blocks(text):
        for off, why in check_block(body):
            out.append((start + off, why))
    return out


PATH_RX = re.compile(r'`((?:tests|scripts|tools|templates|schemas|api|docs|\.github|developer-safety|profiles|infra)/[^`*<>{}\s]+?)`')


def is_suite(rel):
    rel = rel.replace('\\', '/')
    if not rel.startswith('docs/architecture/'):
        return False
    base = rel[len('docs/architecture/'):]
    return base == 'INDEX.md' or re.match(r'^\d\d[a-z]?_[A-Z0-9_]+\.md$', base) is not None \
        or base.startswith('code-walkthrough/')


def withheld(root):
    """The neutral export's own rule (scripts/export_for_adoption.py `exportable`): a path it withholds
    may be cited and absent, because the public copy is exactly that tree. A fallback when absent."""
    p = os.path.join(root, 'scripts', 'export_for_adoption.py')
    if os.path.exists(p):
        try:
            import importlib.util
            spec = importlib.util.spec_from_file_location('_kit_export_rule_m5', p)
            mod = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(mod)
            return lambda rel: not mod.exportable(rel)
        except Exception:
            pass
    return lambda rel: (rel.split('/')[0] in ('overlays', '.context') or 'export-profiles' in rel.split('/')[:2]
                        or os.path.basename(rel) == 'export-deny.txt'
                        or rel == '.github/workflows/consumer-path-test.yml')


def suite_problems(root, files):
    probs = []
    is_withheld = withheld(root)
    index = os.path.join(root, 'docs', 'architecture', 'INDEX.md')
    index_text = open(index, encoding='utf-8').read() if os.path.exists(index) else None
    for rel in files:
        if not is_suite(rel):
            continue
        p = os.path.join(root, rel)
        data = open(p, 'rb').read()
        if len(data) > SUITE_MAX:
            probs.append('M5 %s is %d bytes, over the %d-byte suite ceiling (split it)' % (rel, len(data), SUITE_MAX))
        text = data.decode('utf-8', 'replace')
        for m in PATH_RX.finditer(text):
            cited = m.group(1).rstrip('.,;:)')
            cited = re.sub(r'#.*$', '', cited)
            if '...' in cited or cited.endswith('/'):
                continue
            if not os.path.exists(os.path.join(root, cited)) and not is_withheld(cited):
                probs.append('M5 %s cites %s, which does not exist' % (rel, cited))
        base = rel[len('docs/architecture/'):]
        if index_text is not None and base != 'INDEX.md' and '/' not in base and base not in index_text:
            probs.append('M5 INDEX.md does not list %s' % base)
    if index_text is None and any(is_suite(r) for r in files):
        probs.append('M5 docs/architecture/INDEX.md is missing')
    return probs


def tracked_md(root):
    """The tracked Markdown files (git ls-files, plus untracked new ones); a plain walk without git."""
    try:
        import subprocess
        res = subprocess.run(['git', '-C', root, 'ls-files', '--cached', '--others', '--exclude-standard',
                              '--', '*.md'], capture_output=True, text=True, timeout=60)
        if res.returncode == 0 and res.stdout.strip():
            return sorted(set(ln.strip() for ln in res.stdout.splitlines()
                              if ln.strip() and os.path.exists(os.path.join(root, ln.strip()))))
    except (OSError, ValueError):
        pass
    out = []
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in ('.git', 'node_modules', '__pycache__')]
        for f in filenames:
            if f.endswith('.md'):
                out.append(os.path.relpath(os.path.join(dirpath, f), root).replace('\\', '/'))
    return sorted(out)


def run(root):
    probs = []
    files = tracked_md(root)
    count = 0
    for rel in files:
        try:
            text = open(os.path.join(root, rel), encoding='utf-8').read()
        except (OSError, UnicodeDecodeError) as e:
            probs.append('M0 %s could not be read: %s' % (rel, e))
            continue
        for line, why in check_text(text):
            probs.append('%s:%d %s' % (rel, line, why))
        count += sum(1 for _ in blocks(text))
    probs.extend(suite_problems(root, files))
    return count, probs


CLEAN = '''```mermaid
flowchart LR
  A["start (C1)"]:::kit -->|"label"| B{"decide"}
  B --x|"refused"| C(("stop"))
  subgraph TB1["TB-1 · a boundary"]
    D[("store")]
  end
  B ==> D
  style TB1 stroke:#b91c1c
  classDef kit fill:#dbeafe,color:#000
```
```mermaid
sequenceDiagram
  participant A as Caller
  A->>B: ask
  alt refused
    B-->>A: no
  else accepted
    B-->>A: yes
  end
```
```mermaid
stateDiagram-v2
  [*] --> Open
  Open --> Closed: verified
```
'''
MUTANTS = {
    'M1 unknown type': '```mermaid\nflowchat LR\n  A --> B\n```\n',
    'M2 quote': '```mermaid\nflowchart LR\n  A["open --> B\n```\n',
    'M2 raw parenthesis': '```mermaid\nflowchart LR\n  A[call (x)] --> B\n```\n',
    'M2 subgraph end': '```mermaid\nflowchart LR\n  subgraph S["s"]\n  A --> B\n```\n',
    'M2 node end': '```mermaid\nflowchart LR\n  A --> end\n```\n',
    'M2 class undefined': '```mermaid\nflowchart LR\n  A["a"]:::nope --> B\n```\n',
    'M2 style id': '```mermaid\nflowchart LR\n  A --> B\n  style Z fill:#fff\n```\n',
    'M2 pipes': '```mermaid\nflowchart LR\n  A -->|"x" B\n```\n',
    'M3 alt end': '```mermaid\nsequenceDiagram\n  A->>B: x\n  alt y\n  B->>A: z\n```\n',
    'M3 stray else': '```mermaid\nsequenceDiagram\n  A->>B: x\n  else\n```\n',
    'M4 brace': '```mermaid\nstateDiagram-v2\n  state X {\n  [*] --> X\n```\n',
}


def self_test():
    ok = True
    if check_text(CLEAN):
        print('FAIL control: the clean diagrams were refused: %s' % check_text(CLEAN))
        ok = False
    else:
        print('PASS control: clean flowchart, sequence and state diagrams parse')
    for name, text in MUTANTS.items():
        got = check_text(text)
        rule = name.split()[0]
        if any(why.startswith(rule) for _, why in got):
            print('PASS %s refused: %s' % (name, got[0][1]))
        else:
            print('FAIL %s was not refused (%s)' % (name, got))
            ok = False
    with tempfile.TemporaryDirectory() as d:
        os.makedirs(os.path.join(d, 'docs', 'architecture'))
        os.makedirs(os.path.join(d, 'tests'))
        open(os.path.join(d, 'tests', 'real.py'), 'w').close()
        open(os.path.join(d, 'docs', 'architecture', 'INDEX.md'), 'w').write('[a](01_A.md)\n')
        open(os.path.join(d, 'docs', 'architecture', '01_A.md'), 'w').write('`tests/real.py` `tests/gone.py`\n')
        open(os.path.join(d, 'docs', 'architecture', '02_B.md'), 'w').write('x' * (SUITE_MAX + 1))
        probs = suite_problems(d, tracked_md(d))
        want = ('cites tests/gone.py', 'does not list 02_B.md', 'over the')
        for w in want:
            if any(w in p for p in probs):
                print('PASS M5 refused: %s' % w)
            else:
                print('FAIL M5 not refused: %s (%s)' % (w, probs))
                ok = False
        if any('tests/real.py' in p or 'export-deny' in p for p in probs) or any('01_A.md' in p and 'list' in p for p in probs):
            print('FAIL M5 control: an existing path or a listed document was refused: %s' % probs)
            ok = False
        else:
            print('PASS M5 control: an existing path, a path the neutral export withholds, and a listed document pass')
    return 0 if ok else 1


def main(argv):
    if '--self-test' in argv:
        return self_test()
    root = ROOT
    if '--root' in argv:
        root = argv[argv.index('--root') + 1]
    try:
        count, probs = run(root)
    except OSError as e:
        print('UNKNOWN could not read the tree: %s' % e)
        return 2
    for p in probs:
        print('FAIL ' + p)
    if probs:
        print('%d problem(s) across %d mermaid block(s)' % (len(probs), count))
        return 1
    print('PASS %d mermaid block(s) parse; the architecture suite cites only paths that exist' % count)
    return 0


if __name__ == '__main__':
    sys.exit(main(sys.argv[1:]))

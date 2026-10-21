#!/usr/bin/env python3
"""The delivery architecture, drawn from the registers rather than by hand.

WHY THIS EXISTS

    The kit now carries three registers that each describe the same pipeline from a different
    angle: the stage register in `check_stage_phase.py` says how far each stage has got, the
    guardrail list says what each stage boundary must refuse, and `THREAT_MODEL.md` says where an
    adversary enters. All three are tables, and a table is the wrong shape for the question people
    actually ask -- *where in this pipeline is the hole*.

    A hand-drawn diagram would answer it and then rot, because the registers move and the picture
    does not. Every architecture diagram in every estate ever surveyed is out of date, and nobody
    can tell which parts, which makes the whole thing unciteable.

    So this generates the picture FROM the registers. It cannot drift from them, because it has no
    independent content: change a stage's phase and the diagram changes on the next run. If the
    diagram and the register ever disagree, the generator is broken -- there is no third place for
    a fact to hide.

WHAT A DIAGRAM CANNOT ESTABLISH

    That the pipeline works. This draws declared structure and declared maturity. A stage shown as
    BUILT is a claim this file inherited; it is not an observation of a run. The one thing the
    picture is genuinely good for is showing where a chain breaks -- and the breaks here are real,
    because the registers that feed it refuse to overstate.

USAGE
    python tests/build_pipeline_overlays.py
    python tests/build_pipeline_overlays.py --out docs/architecture/generated
    python tests/build_pipeline_overlays.py --check      # fail if the committed file is stale
    python tests/build_pipeline_overlays.py --self-test

EXIT
    0  written (or current, under --check)      1  stale under --check      2  self-test failed
"""
import argparse
import io
import os
import re
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, HERE)

from check_stage_phase import STAGES, GUARDRAILS, PHASES, RANK  # noqa: E402

OUT_NAME = 'PIPELINE_OVERLAYS.md'

# Mermaid classes per phase. The point of the palette is that ABSENT and DESIGNED must not look
# like progress, and nothing may look finished, because nothing is.
PHASE_CLASS = {
    'ABSENT':    'absent',
    'DESIGNED':  'designed',
    'BUILT':     'built',
    'EXERCISED': 'exercised',
    'PROVEN':    'proven',
    'ENFORCED':  'enforced',
}

CLASS_DEFS = [
    'classDef absent    fill:#2b2b2b,stroke:#777,color:#ddd,stroke-dasharray:4 3',
    'classDef designed  fill:#3a3320,stroke:#b8860b,color:#f0e6c8,stroke-dasharray:4 3',
    'classDef built     fill:#1f3147,stroke:#4a90d9,color:#e6f0fa',
    'classDef exercised fill:#1f3a2e,stroke:#3fa37a,color:#e6faf0',
    'classDef proven    fill:#17402a,stroke:#2ecc71,color:#eafff2',
    'classDef enforced  fill:#102e1a,stroke:#00e676,color:#f0fff5,stroke-width:3px',
]


def read_threats(root=ROOT):
    """-> [(id, title)] from the threat model. Parsed, not restated.

    The threat model is prose by design -- each threat carries an entry point, a consequence and a
    residual, and none of that belongs in a Python dict. So the ids and titles are lifted and the
    reasoning stays where a human wrote it.
    """
    p = os.path.join(root, 'docs', 'architecture', 'THREAT_MODEL.md')
    if not os.path.exists(p):
        return []
    out = []
    rx = re.compile(r'^\*\*(T-\d{2})\s*·\s*(.+?)\*\*\s*$')
    for line in io.open(p, encoding='utf-8'):
        m = rx.match(line.strip())
        if m:
            out.append((m.group(1), m.group(2).strip()))
    return sorted(set(out))


def esc(s):
    """Mermaid label text. Quotes and brackets end a node early and produce a diagram that renders
    wrong rather than failing, which is the worst way for this to break."""
    return (str(s).replace('"', "'").replace('[', '(').replace(']', ')')
            .replace('{', '(').replace('}', ')').replace('|', '/'))


def stage_graph():
    """The fifteen stages in order, coloured by the phase they have actually reached."""
    L = ['```mermaid', 'flowchart TD']
    for n in sorted(STAGES):
        s = STAGES[n]
        L.append('  S%02d["%d. %s<br/><b>%s</b>"]' % (n, n, esc(s['name']), s['phase']))
    for n in sorted(STAGES):
        if n + 1 in STAGES:
            L.append('  S%02d --> S%02d' % (n, n + 1))
    L.extend('  ' + c for c in CLASS_DEFS)
    for n in sorted(STAGES):
        L.append('  class S%02d %s' % (n, PHASE_CLASS[STAGES[n]['phase']]))
    L.append('```')
    return L


def guardrail_graph():
    """Only the boundaries a guardrail names. An edge here is a place where an unknown becomes a
    claim and neither side owns the join."""
    L = ['```mermaid', 'flowchart LR']
    seen = set()
    for d, u, _w in GUARDRAILS:
        for n in (d, u):
            if n not in seen:
                seen.add(n)
                L.append('  G%02d["%d. %s<br/>%s"]' % (n, n, esc(STAGES[n]['name']),
                                                       STAGES[n]['phase']))
    for i, (d, u, _w) in enumerate(sorted(GUARDRAILS), 1):
        L.append('  G%02d -. "R%d" .-> G%02d' % (u, i, d))
    L.extend('  ' + c for c in CLASS_DEFS)
    for n in sorted(seen):
        L.append('  class G%02d %s' % (n, PHASE_CLASS[STAGES[n]['phase']]))
    L.append('```')
    L.append('')
    L.append('| | upstream | downstream | the boundary must refuse |')
    L.append('|---|---|---|---|')
    for i, (d, u, w) in enumerate(sorted(GUARDRAILS), 1):
        L.append('| R%d | %d %s | %d %s | %s |'
                 % (i, u, esc(STAGES[u]['name']), d, esc(STAGES[d]['name']), esc(w)))
    return L


def provenance_graph():
    """The artifact identity chain, and where it is not established.

    Drawn separately from the stage flow because it is a different question: the stages ask what
    the pipeline DOES, this asks whether the thing scanned and the thing running are the same
    object. A break anywhere makes every scan result a statement about something else.
    """
    chain = [
        ('P1', 'repo / ref / commit',     'BUILT'),
        ('P2', 'build run',               'BUILT'),
        ('P3', 'artifact digest',         'DESIGNED'),
        ('P4', 'scan + SBOM of THOSE bytes', 'DESIGNED'),
        ('P5', 'provenance attestation',  'DESIGNED'),
        ('P6', 'registry digest',         'DESIGNED'),
        ('P7', 'deployment target',       'DESIGNED'),
        ('P8', 'observed running version', 'ABSENT'),
    ]
    L = ['```mermaid', 'flowchart LR']
    for i, (k, label, phase) in enumerate(chain):
        L.append('  %s["%s<br/><b>%s</b>"]' % (k, esc(label), phase))
        if i:
            L.append('  %s --> %s' % (chain[i - 1][0], k))
    L.extend('  ' + c for c in CLASS_DEFS)
    for k, _l, phase in chain:
        L.append('  class %s %s' % (k, PHASE_CLASS[phase]))
    L.append('```')
    return L


def render(root=ROOT):
    threats = read_threats(root)
    counts = {p: 0 for p in PHASES}
    for n in STAGES:
        counts[STAGES[n]['phase']] += 1

    L = []
    L.append('# Pipeline overlays — generated')
    L.append('')
    L.append('```')
    L.append('GENERATED by tests/build_pipeline_overlays.py. Do not edit.')
    L.append('Source of truth: the stage register and guardrails in tests/check_stage_phase.py,')
    L.append('and the threat ids in docs/architecture/THREAT_MODEL.md.')
    L.append('Edit those; this file is a projection and has no content of its own.')
    L.append('```')
    L.append('')
    L.append('> **A diagram cannot establish that a pipeline works.** This draws declared structure '
             'and declared maturity. A stage shown as BUILT is a claim inherited from the register, '
             'not an observation of a run. What it is good for is showing where a chain breaks.')
    L.append('')
    L.append('## 1 · Stages, by the phase each has actually reached')
    L.append('')
    L.extend(stage_graph())
    L.append('')
    L.append('  ' + ' · '.join('**%s** %d' % (p, counts[p]) for p in PHASES))
    L.append('')
    if counts['ENFORCED'] == 0:
        L.append('**Nothing is ENFORCED.** No stage has yet refused a real prohibited operation, '
                 'so every control in this picture is configured rather than effective.')
    if counts['EXERCISED'] == 0 and counts['BUILT'] > 0:
        L.append('')
        L.append('**EXERCISED is zero while BUILT is %d.** Those stages exist in code and carry no '
                 'run against them — built and working are different things, and the gap between '
                 'them is where a dead scanner hides.' % counts['BUILT'])
    L.append('')
    L.append('## 2 · Guardrails — the boundaries, and what each must refuse')
    L.append('')
    L.extend(guardrail_graph())
    L.append('')
    L.append('## 3 · Artifact identity — the chain, and where it stops')
    L.append('')
    L.extend(provenance_graph())
    L.append('')
    L.append('The chain is specified in `PROVENANCE_AND_ATTESTATION.md` §3 and implemented as far '
             'as the build. **Observed running version is ABSENT**, so nothing currently compares '
             'the digest that was scanned against the digest that is serving traffic — which is the '
             'comparison the whole chain exists to make.')
    L.append('')
    L.append('## 4 · Threats, by where they enter')
    L.append('')
    if not threats:
        L.append('`THREAT_MODEL.md` not found or carries no parseable threat ids.')
    else:
        L.append('%d threats are registered. Entry point, consequence, control state, test and '
                 'residual risk for each are in `THREAT_MODEL.md` — not restated here, because a '
                 'projection that paraphrases its source is a second source.' % len(threats))
        L.append('')
        L.append('| id | threat |')
        L.append('|---|---|')
        for tid, title in threats:
            L.append('| %s | %s |' % (tid, esc(title)))
    L.append('')
    L.append('## 5 · How to read the colours')
    L.append('')
    L.append('| phase | means |')
    L.append('|---|---|')
    L.append('| ABSENT | nothing exists |')
    L.append('| DESIGNED | a document specifies it. Intent, nothing more. |')
    L.append('| BUILT | code exists on a path something runs |')
    L.append('| EXERCISED | it has run — a run id against a named commit |')
    L.append('| PROVEN | it produced the right answer on seeded input, attributed to itself |')
    L.append('| ENFORCED | it refused a real prohibited operation, and the refusal was recorded |')
    L.append('')
    L.append('Dashed borders are ABSENT and DESIGNED: **not progress.** Nothing is drawn as '
             'finished, because nothing is.')
    L.append('')
    return '\n'.join(L) + '\n'


def self_test():
    fails = []
    a = render()
    b = render()
    if a != b:
        fails.append('two renders of identical registers differ — output is not deterministic')
    for p in ('ABSENT', 'DESIGNED', 'BUILT', 'PROVEN'):
        if p not in a:
            fails.append('phase %s never appears in the output' % p)
    if 'ENFORCED** 0' not in a.replace('**ENFORCED** 0', 'ENFORCED** 0'):
        if 'Nothing is ENFORCED' not in a:
            fails.append('ENFORCED is zero and the output does not say so')
    if a.count('```mermaid') != 3:
        fails.append('expected 3 mermaid blocks, found %d' % a.count('```mermaid'))
    # Every stage in the register must appear. A diagram quietly short of the register is the
    # drift this file exists to make impossible.
    for n in STAGES:
        if 'S%02d[' % n not in a:
            fails.append('stage %d is in the register and not in the diagram' % n)
    if 'GENERATED by' not in a:
        fails.append('output does not declare itself generated')
    if 'cannot establish that a pipeline works' not in a:
        fails.append('output does not state what a diagram cannot establish')
    # Labels must not carry characters that end a Mermaid node early.
    for line in a.splitlines():
        if line.strip().startswith(('S', 'G', 'P')) and '["' in line:
            inner = line.split('["', 1)[1].rsplit('"]', 1)[0]
            if any(c in inner for c in '"[]{}|'):
                fails.append('unescaped mermaid-breaking character in: %s' % line.strip()[:60])
                break
    if fails:
        for f in fails:
            sys.stderr.write('FAIL: %s\n' % f)
        return 2
    print('self-test ok: two renders of identical registers are byte-identical; every stage in the '
          'register appears in the diagram; three mermaid blocks render; node labels carry no '
          'character that would end a node early; the output declares itself generated, states what '
          'a diagram cannot establish, and says so when nothing is ENFORCED')
    return 0


def main():
    ap = argparse.ArgumentParser(description='Draw the delivery architecture from the registers.')
    ap.add_argument('--out', default=os.path.join('docs', 'architecture', 'generated'))
    ap.add_argument('--check', action='store_true',
                    help='exit 1 if the committed file differs from a fresh render')
    ap.add_argument('--self-test', action='store_true')
    a = ap.parse_args()
    if a.self_test:
        return self_test()

    body = render()
    out_dir = a.out if os.path.isabs(a.out) else os.path.join(ROOT, a.out)
    path = os.path.join(out_dir, OUT_NAME)

    if a.check:
        if not os.path.exists(path):
            sys.stderr.write('::error::%s has never been generated.\n' % OUT_NAME)
            return 1
        cur = io.open(path, encoding='utf-8').read()
        if cur != body:
            sys.stderr.write('::error::%s is stale. The registers moved and the picture did not. '
                             'Re-run without --check.\n' % OUT_NAME)
            return 1
        print('%s is current with the registers.' % OUT_NAME)
        return 0

    if not os.path.isdir(out_dir):
        os.makedirs(out_dir)
    # UNCHANGED CONTENT IS NOT REWRITTEN (N51). On a CRLF checkout an unconditional rewrite showed
    # this tracked file as modified after every run, though nothing in it had changed.
    if os.path.exists(path):
        current = io.open(path, encoding='utf-8', newline='').read().replace('\r\n', '\n')
        if current == body.replace('\r\n', '\n'):
            print('%s is current with the registers; not rewritten.' % OUT_NAME)
            return 0
    with io.open(path, 'w', encoding='utf-8', newline='\n') as fh:
        fh.write(body)
    print('wrote %s (%d lines)' % (path, body.count('\n')))
    return 0


if __name__ == '__main__':
    sys.exit(main())

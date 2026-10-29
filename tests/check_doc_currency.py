#!/usr/bin/env python3
"""A prose document may not call a capability untested when the registry says it is observed.

WHY THIS EXISTS
    `tests/reconcile_validation.py` is machine-checked and gated. It knows `toolchain-python-version`
    is `observed`, cited to self-test run 35393378558.

    `docs/assurance/TEST_COVERAGE_AUDIT.md` is a hand-maintained table. It still said
    `setup-python` was UNTESTED. So did `setup-node`, and `render-version-metadata`, and
    `reusable-build-docker.yml`.

    Nothing was comparing them, so the registry moved and the prose did not. And the prose is
    what a person reads. A reader of that table would conclude the composites had never run, on
    the same day the ledger recorded the run id that proved they had.

    THIS IS THE DEFECT THE REGISTRY WAS BUILT TO REPLACE, RECURRING ONE LAYER OUT. A hand-kept
    table of a changing tree is a promise to do clerical work forever; the registry absorbed that
    promise for the machine-readable half and left the prose half exactly where it was. The same
    thing happened in the CISO packet -- `verify_env` gated the roadmap and nothing gated the
    maintenance index, which then reported a built tool as absent. A GATE WITH THE WRONG
    DENOMINATOR IS NOT A NARROWER GATE. IT IS A GATE THAT REPORTS CLEAN.

WHAT THIS CHECKS, AND WHAT IT DOES NOT
    ONE DIRECTION, deliberately: a capability the registry calls `observed` must not be described
    as untested/never-executed/unvalidated in prose. That is the direction that OVERSTATES the
    gap, which sounds harmless and is not -- it is how a proven control gets re-proven, or worse,
    quietly rebuilt.

    It does NOT check the other direction. Prose saying something is proven when the registry
    says otherwise would be worse, but prose describes things at a granularity the registry does
    not carry (a workflow, a scanner path, a job), and a matcher loose enough to catch it would
    fire constantly. That asymmetry is a known limit, not an oversight: see the GAPS note below.

THE CLAIMS LIST (added 2026-10-16, completion ledger L81 / B-11 / D-01)
    The check above was green while the consumer-facing documents told a builder three false
    things, none of which it could see because it read only three assurance tables:

      - START-HERE said advisory mode suppresses the secret gate. Secrets have blocked in every
        mode since 09f073e, and the flagship's own `secret_gate` output says so.
      - README, USAGE and the build-deploy starter configured the flagship with `enable_iac`, an
        input the workflow declares DEPRECATED AND IGNORED. A builder copying them believes it
        configured something it did not.
      - START-HERE, USAGE, SETUP, the rollback contract and two explainer parts called the deploy
        workflows provisional / never executed / proven against a stub cloud only, while the
        registry cites live runs for both adapters.

    So the consumer-facing documents are now read too, and each class is a CLAIM: a predicate read
    from the CODE (a workflow input's own description, an output's own description, the registry)
    and a pattern for a document line that asserts the opposite. A claim whose predicate does not
    hold is not checked -- if the code ever changes, the prose is free to follow it.

    History is exempt: the change log (`docs/explainer/10-CHANGE-LOG.md`) records what was true at
    each version, and a dated audit is not in scope.

    `--self-test` runs every claim against seeded lines (a failing and a passing form of each).

THE REST OF THE ESTATE (lane L-E, 2026-10-21, ledger L81 / B-11 / D-01)
    The architecture and assurance documents, the roadmap and the continuity record (AUDIT_DOCS)
    are now read too, by the registry direction AND every claim. Two claims were added, each a
    predicate read from the code: `fail_on_cvss` "defaults to 11" while the reusable ships 9.0, and
    "nothing is ENFORCED" while the stage register records an ENFORCED stage. What the first full
    run found is listed in known_stale -- reported every run, failing on a date, and failing if the
    document is fixed and the entry left behind. tests/prove_doc_currency_scope.py proves the scope
    and the register against a constructed tree.

EXIT
    0  no document contradicts the registry or the code in the directions this checks
    1  a document calls an observed capability untested, or asserts a refuted claim
    2  could not be checked -- reported as UNKNOWN, never as PASS
"""
import glob
import io
import os
import re
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, HERE)

DOCS = [
    'docs/assurance/TEST_COVERAGE_AUDIT.md',
    'docs/assurance/VALIDATION_DEBT.md',
    'docs/assurance/CAPABILITY_MATRIX.md',
]

# The documents a CONSUMER reads to wire the kit. The registry check above runs over these too, and
# so does the claims list. Globs, so a new adoption page or explainer part is in scope the day it
# exists rather than the day somebody remembers to list it.
CONSUMER_DOCS = [
    'README.md',
    'docs/START-HERE.md',
    'docs/adoption/*.md',
    'docs/explainer/*.md',
    'templates/*.yml',
    'docs/architecture/ROLLBACK_CONTRACT.md',
    'docs/architecture/LZ_KIT_HANDOFF_CONTRACT.md',
    # the evidence manifest, in three standalone parts (each under 20 KB)
    'docs/assurance/RELEASE_1_EVIDENCE_MANIFEST.md',
    'docs/assurance/RELEASE_1_EVIDENCE_MANIFEST_PART2.md',
    'docs/assurance/RELEASE_1_EVIDENCE_MANIFEST_PART3.md',
]
# History: true when written, and says so with a version and a date.
HISTORY = {'docs/explainer/10-CHANGE-LOG.md', 'docs/explainer/10b-CHANGE-LOG-EARLIER.md'}

# THE REST OF THE ESTATE (completion ledger L81 / B-11 / D-01, lane L-E, 2026-10-21). The consumer
# documents above were brought true by lane L-G; the architecture and assurance documents, the
# roadmap and the continuity record were never read by this gate, and the ledger's D-01 row lists the
# stale lines they carry ("deploy never executed", "nothing built", "0 ENFORCED", "defaults to 11").
# They are read now, by the registry direction AND the claims list.
AUDIT_DOCS = [
    'docs/*.md',
    'docs/architecture/*.md',
    'docs/assurance/*.md',
    'docs/roadmap/*.md',
    '.context/products/secure-cicd-kit/*.md',
]
# Dated records of what was true at a commit, by design. Not in scope; each says why.
DATED = {
    'docs/assurance/COMPLETION_LEDGER.md': 'a read-only audit dated to commit 53d2962',
}
# KNOWN STALE, DATED AND OWNED. A document listed here has contradictions the gate has FOUND and
# reports on every run without failing, until the date -- the deferral rule applied to prose: a
# permanently red gate is training, and silence must not renew an exception. An entry whose
# document no longer contradicts anything FAILS (delete it), and an expired one FAILS. A document
# NOT listed here fails on its first contradiction. Owner: the documentation lane (L-G), which owns
# docs/** and .context/**; this lane owns only the gate.
known_stale_expires = '2026-11-15'
known_stale = {
    # From the first full run, 2026-10-21. The reason says what the gate found, and whether the line
    # is wrong or only reads wrong (a quotation or a struck-through history the matcher cannot tell
    # from a claim -- reword it so it states the current fact).
    'README.md': 'fail_on_cvss "defaults to 11 (never blocks)"; it ships 9.0 since O-12',
    'docs/assurance/RELEASE_1_EVIDENCE_MANIFEST.md': 'row 32: "fail_on_cvss 11 never blocks"; ships 9.0',
    'docs/architecture/NVD_ABSTRACTION_ACCOUNTING.md': '"default changed to 11 (never fail)" is now '
                                                       'history; the default is 9.0',
    'docs/architecture/SINGLE_PIPELINE_TARGET.md': 'section 4.1 "fail_on_cvss defaults to 11"; ships 9.0',
    'docs/architecture/DEPLOYMENT_CONTRACT_RECONCILIATION.md': 'line 110 calls both deploy reusables '
                                                               'unexercised; both are observed live',
    'docs/architecture/PROVENANCE_AND_ATTESTATION.md': 'the attestation row reads reusable-build-docker '
                                                       'as not run; image-build/push are observed live',
    'docs/architecture/THREAT_MODEL.md': '"nothing is ENFORCED"; stage 15 is ENFORCED (live refusals)',
    '.context/products/secure-cicd-kit/continuation.md': 'quotes the claim this gate refuses ("advisory '
                                                         'mode covers secrets") -- reword the quotation',
    '.context/products/secure-cicd-kit/risks.md': 'R-04 "deploy workflows ... have never run"; both '
                                                  'are observed live',
}

# Words that assert a thing has NOT been exercised. Matched case-insensitively on the line.
UNTESTED_WORDS = re.compile(
    r'\bUNTESTED\b|\bnever executed\b|\bnever run\b|\bnot (?:yet )?(?:been )?(?:executed|run|validated|exercised)\b|'
    r'\bunvalidated\b|\bno probe\b|\bnot proven live\b|\bnever (?:been )?dispatched\b|'
    r'\bhave never executed\b|\bstub cloud only\b|\bagainst a stub cloud only\b|'
    r'\bonly against a stub cloud\b|\bneeds a hosted run\b|\bNOT PROVEN\b', re.I)

# Prose names an observed capability by a PHRASE as often as by its artifact. Each phrase is matched
# only on a line that also carries an untested word above, so a phrase here is not a ban on the
# phrase -- it is a ban on calling that capability unexercised.
ALIASES = {
    'deploy-appservice': ['deploy workflows', 'deploy reusables', 'deploy adapters',
                          'App Service deploy', 'deploy path'],
    'deploy-containerapp': ['deploy workflows', 'deploy reusables', 'deploy adapters',
                            'Container Apps deploy', 'deploy path'],
    'image-push': ['push to a cloud registry'],
    'codeql': ['CodeQL'],
}


# An observed capability is named in prose by its ARTIFACT, not by its registry key: the table
# says `setup-python`, the registry says `toolchain-python-version`. So each observed capability
# is mapped back to the artifacts that provide it.
def artifacts_for(capability, registry):
    out = []
    for artifact, caps in registry.items():
        if capability in caps:
            out.append(artifact.replace('action:', ''))
    return out


def untested_hits(lines, claims):
    """-> [(lineno, artifact, caps, line)] for each line calling an observed artifact untested."""
    out = []
    for lineno, line in enumerate(lines, 1):
        if not UNTESTED_WORDS.search(line):
            continue
        for art, caps in claims.items():
            # `art` is a workflow filename, a composite name or a phrase. Match it as a whole token
            # so `setup-node` does not fire on `setup-node-something-else`.
            if re.search(r'(?<![\w.-])%s(?![\w-])' % re.escape(art), line, re.I):
                out.append((lineno, art, caps, line))
    return out


# ---------------------------------------------------------------- the claims list

def _load_yaml(rel):
    import yaml
    with io.open(os.path.join(ROOT, rel), encoding='utf-8') as fh:
        return yaml.safe_load(fh) or {}


def _workflow_call(doc):
    on = doc.get(True) or doc.get('on') or {}
    return (on.get('workflow_call') or {}) if isinstance(on, dict) else {}


def dead_inputs():
    """-> {input name: workflow} for every reusable input whose OWN description says it is dead."""
    out = {}
    for path in sorted(glob.glob(os.path.join(ROOT, '.github', 'workflows', '*.yml'))):
        rel = os.path.relpath(path, ROOT).replace('\\', '/')
        for name, spec in (_workflow_call(_load_yaml(rel)).get('inputs') or {}).items():
            desc = str((spec or {}).get('description') or '')
            if re.match(r'\s*DEPRECATED\b', desc) and re.search(r'\bIGNORED\b', desc):
                out[name] = os.path.basename(path)
    return out


def secrets_never_softened():
    """True when the flagship's own secret_gate output says advisory_mode never suppresses it, AND
    the proof that runs the shipped Enforce step in advisory mode exists."""
    outs = _workflow_call(_load_yaml('.github/workflows/reusable-security.yml')).get('outputs') or {}
    desc = str((outs.get('secret_gate') or {}).get('description') or '')
    return (re.search(r'never suppressed by advisory_mode', desc) is not None
            and os.path.exists(os.path.join(ROOT, 'tests', 'prove_secrets_always_block.py')))


def dead_input_rule(dead):
    """A dead input SET in an example (a YAML key with a value, or an inline `key: value`). A line
    that says the input is deprecated, ignored or dead is describing it, not configuring it."""
    if not dead:
        return None
    names = '|'.join(re.escape(n) for n in sorted(dead))
    pat = re.compile(r'(?<![\w-])(%s)\s*:\s*\S' % names)
    describes = re.compile(r'deprecat|ignored|\bdead\b|CONTROL_SURFACE_DEAD|nothing reads', re.I)

    def rule(line):
        m = pat.search(line)
        if m and not describes.search(line):
            return ('sets `%s`, which %s declares DEPRECATED AND IGNORED -- a builder copying this '
                    'believes it configured something it did not' % (m.group(1), dead[m.group(1)]))
        return None
    return rule


ADVISORY_SECRET = re.compile(
    r'advisory[_ ]mode`?\s*\**\s*(?:currently\s+)?\**(?:suppresses|covers|softens|disables|'
    r'withholds)\b', re.I)
NEGATION = re.compile(r'\b(?:never|not|except|outside|other than|but not)\b', re.I)


def advisory_secret_rule(line):
    """A line saying advisory mode suppresses or covers the secret gate, with no negation AFTER the
    claim. The pattern already requires the verb straight after `advisory_mode`, so "advisory mode
    never covers" cannot match; a negation BEFORE it ("KNOWN DEFECT, not yet fixed: advisory_mode
    suppresses...") is the defect being announced, not a denial of it."""
    m = ADVISORY_SECRET.search(line)
    if m and re.search(r'secret', line[m.start():], re.I) and not NEGATION.search(line[m.end():]):
        return ('says advisory mode covers or suppresses secrets; the flagship\'s `secret_gate` is '
                'never suppressed by advisory_mode (tests/prove_secrets_always_block.py)')
    return None


def nvd_cvss_default():
    """The shipped `fail_on_cvss` default, read from the reusable's own input declaration."""
    spec = ((_workflow_call(_load_yaml('.github/workflows/reusable-nvd-cve.yml')).get('inputs') or {})
            .get('fail_on_cvss') or {})
    return spec.get('default')


NVD_ELEVEN = re.compile(r'fail_on_cvss[^\n]{0,60}?(?:default[^\n]{0,30}?\b11\b|\b11\b[^\n]{0,40}?'
                        r'(?:never|cannot|can never)[^\n]{0,10}?(?:block|fail))', re.I)


def nvd_default_rule(default):
    """A line saying `fail_on_cvss` defaults to 11 / 11 never blocks, while the code ships <= 10."""
    def rule(line):
        if NVD_ELEVEN.search(line):
            return ('says fail_on_cvss defaults to 11 (never blocks); reusable-nvd-cve.yml ships %s '
                    '(owner ruling O-12)' % default)
        return None
    return rule


def enforced_stages():
    """The stages tests/check_stage_phase.py records as ENFORCED, each citing its refusal run."""
    import check_stage_phase as S
    return sorted(n for n, s in S.STAGES.items() if s.get('phase') == 'ENFORCED')


NOTHING_ENFORCED = re.compile(r'\bNOTHING is ENFORCED\b|\b0 ENFORCED\b|\bENFORCED (?:is|=) 0\b|'
                              r'nothing in (?:this|the) kit has (?:yet )?refused', re.I)


def enforced_rule(stages):
    def rule(line):
        if NOTHING_ENFORCED.search(line):
            return ('says nothing is ENFORCED; the stage register records stage(s) %s ENFORCED with '
                    'the runs that refused (tests/check_stage_phase.py)' % ', '.join(map(str, stages)))
        return None
    return rule


def claim_rules():
    """-> [(claim id, rule)] for every claim whose code predicate HOLDS. UNKNOWN raises."""
    rules = []
    r = dead_input_rule(dead_inputs())
    if r:
        rules.append(('dead-input-in-example', r))
    if secrets_never_softened():
        rules.append(('advisory-suppresses-secrets', advisory_secret_rule))
    # B-11 (lane L-E): each further claim is a predicate read from the code.
    d = nvd_cvss_default()
    if isinstance(d, (int, float)) and d <= 10:
        rules.append(('nvd-cvss-default', nvd_default_rule(d)))
    stages = enforced_stages()
    if stages:
        rules.append(('nothing-enforced', enforced_rule(stages)))
    return rules


def claim_hits(lines, rules):
    out = []
    for lineno, line in enumerate(lines, 1):
        for cid, rule in rules:
            why = rule(line)
            if why:
                out.append((lineno, cid, why, line))
    return out


def consumer_files():
    seen = []
    for g in CONSUMER_DOCS:
        for p in sorted(glob.glob(os.path.join(ROOT, g))):
            rel = os.path.relpath(p, ROOT).replace('\\', '/')
            if rel not in seen and rel not in HISTORY:
                seen.append(rel)
    return seen


def audit_files(already):
    seen = []
    for g in AUDIT_DOCS:
        for p in sorted(glob.glob(os.path.join(ROOT, g))):
            rel = os.path.relpath(p, ROOT).replace('\\', '/')
            if rel in already or rel in seen or rel in HISTORY or rel in DATED:
                continue
            seen.append(rel)
    return seen


def ascii_line(line):
    # ASCII-folded: these tables are full of emoji status marks, and a checker that crashes on a
    # console codepage is a checker nobody runs on Windows.
    return line.strip().encode('ascii', 'replace').decode()[:110]


# ---------------------------------------------------------------- self-test

def self_test():
    fails = []
    claims = {'reusable-deploy-appservice.yml': {'deploy-appservice'},
              'deploy workflows': {'deploy-appservice'}, 'CodeQL': {'codeql'}}
    for bad in ['| **Can I use the deploy workflows?** | they are provisional and have never executed |',
                'Status: PROVEN AGAINST A STUB CLOUD only. Not proven live.  `reusable-deploy-appservice.yml`',
                '| `codeql` | CodeQL | found | findings | softened | **needs a hosted run** |']:
        if not untested_hits([bad], claims):
            fails.append('an observed capability called untested was not caught: %s' % bad[:60])
    for good in ['Both deploy workflows are proven live (runs 38878189985, 38858033863).',
                 'CodeQL is proven on the Level 2 consumer (runs 38817782084, 38820564939).']:
        if untested_hits([good], claims):
            fails.append('a true line was refused: %s' % good[:60])

    dead = dead_input_rule({'enable_iac': 'reusable-security.yml'})
    for bad in ['      enable_iac: true          # scan Terraform/IaC too',
                '      enable_iac: false',
                '| IaC | `enable_iac: true` **and** Terraform under `paths` | job skips |']:
        if not dead(bad):
            fails.append('a dead input set in an example was not caught: %s' % bad.strip()[:60])
    for good in ['| `enable_iac` | CONTROL_SURFACE_DEAD | `false` | -- | deprecated; read by nothing |',
                 '      iac_mode: auto',
                 '`enable_iac: true` is deprecated and ignored; use `iac_mode`.']:
        if dead(good):
            fails.append('a line describing (not setting) the dead input was refused: %s' % good[:60])

    for bad in ['> KNOWN DEFECT, not yet fixed: `advisory_mode` currently suppresses the secret gate too.',
                '`advisory_mode` covers **every** enforcement point - SAST, lint, deps and secret scanning.']:
        if not advisory_secret_rule(bad):
            fails.append('an advisory-covers-secrets claim was not caught: %s' % bad[:60])
    for good in ['`advisory_mode` covers every enforcement point except secrets, which block in every mode.',
                 'Secrets are never softened by advisory mode.']:
        if advisory_secret_rule(good):
            fails.append('a true advisory line was refused: %s' % good[:60])

    # B-11 claims (lane L-E): the NVD default and the stage register.
    nvd = nvd_default_rule(9.0)
    for bad in ['- **`fail_on_cvss` defaults to 11** in `reusable-nvd-cve.yml`',
                '| NVD | `fail_on_cvss` 11 never blocks (BLOCKED, O-12) |',
                '`fail_on_cvss` input -- **default changed to 11 (never fail)**']:
        if not nvd(bad):
            fails.append('a "fail_on_cvss defaults to 11" claim was not caught: %s' % bad[:60])
    for good in ['`fail_on_cvss` defaults to 9.0 (O-12); above 10 nothing can block.',
                 'Set `fail_on_cvss: 7` to block on HIGH.']:
        if nvd(good):
            fails.append('a true fail_on_cvss line was refused: %s' % good[:60])
    enf = enforced_rule([15])
    for bad in ['Across this entire file, **nothing is ENFORCED**.', 'stage 15 says 0 ENFORCED',
                'nothing in this kit has refused a real prohibited operation yet']:
        if not enf(bad):
            fails.append('a "nothing is enforced" claim was not caught: %s' % bad[:60])
    for good in ['Stage 15 is ENFORCED: 38853176286 refused a deploy on a BLOCKED verdict.']:
        if enf(good):
            fails.append('a true ENFORCED line was refused: %s' % good[:60])

    if fails:
        for f in fails:
            print('SELF-TEST FAIL: %s' % f)
        return 2
    print('self-test ok: an observed capability called untested by artifact or by phrase is caught '
          'and a line citing its runs is not; a dead input SET in an example (YAML key, inline) is '
          'caught and a line describing it as dead is not; "advisory mode covers/suppresses secrets" '
          'is caught and a negated line is not.')
    return 0


# ---------------------------------------------------------------- main

def main():
    if '--self-test' in sys.argv[1:]:
        return self_test()
    try:
        import reconcile_validation as R
    except Exception as e:
        print('UNKNOWN: could not import the validation registry (%s).' % e)
        print('Failure to observe is not an observation.')
        return 2
    try:
        rules = claim_rules()
    except Exception as e:  # PyYAML missing, a workflow unparseable: the predicates are unknown
        print('UNKNOWN: could not evaluate the claims list (%s). A predicate nobody could read is '
              'not a predicate that holds or fails.' % e)
        return 2

    observed = sorted(k for k, v in R.VALIDATION_REGISTRY.items()
                      if v.get('state') == 'observed')
    if not observed:
        print('UNKNOWN: the registry reports no observed capability. Nothing to reconcile, which '
              'is not the same as nothing wrong.')
        return 2

    # artifact name (or alias phrase) -> the observed capabilities it provides
    claims = {}
    for cap in observed:
        for art in artifacts_for(cap, R.CAPABILITY_REGISTRY) + ALIASES.get(cap, []):
            claims.setdefault(art, set()).add(cap)

    print('=== registry: %d observed capabilities across %d artifact(s) and phrase(s) ==='
          % (len(observed), len(claims)))
    print('=== claims list: %s ===' % (', '.join(c for c, _ in rules) or 'no predicate holds'))

    import datetime
    today = datetime.date.today()
    for i, arg in enumerate(sys.argv[1:]):
        if arg == '--today' and i + 2 < len(sys.argv):
            today = datetime.date.fromisoformat(sys.argv[i + 2])
    try:
        stale_until = datetime.date.fromisoformat(known_stale_expires)
    except ValueError:
        stale_until = datetime.date.min

    fails, checked, accepted, stale_entries = [], 0, [], []
    consumer = [rel for rel in consumer_files() if rel not in DOCS]
    targets = ([(rel, False) for rel in DOCS] + [(rel, True) for rel in consumer]
               + [(rel, True) for rel in audit_files(set(DOCS) | set(consumer))])
    for rel, claims_too in targets:
        path = os.path.join(ROOT, rel)
        if not os.path.exists(path):
            print('  %-50s ABSENT' % rel)
            continue
        checked += 1
        lines = io.open(path, encoding='utf-8', errors='replace').read().split('\n')
        found = []
        for lineno, art, caps, line in untested_hits(lines, claims):
            found.append('%s:%d calls `%s` untested; the registry records %s as observed\n'
                         '      %s' % (rel, lineno, art, ', '.join(sorted(caps)), ascii_line(line)))
        if claims_too:
            for lineno, cid, why, line in claim_hits(lines, rules):
                found.append('%s:%d [%s] %s\n      %s' % (rel, lineno, cid, why, ascii_line(line)))
        known = rel in known_stale
        if known and not found:
            stale_entries.append('%s is in known_stale and no longer contradicts anything: delete '
                                 'the entry' % rel)
        elif known and today <= stale_until:
            accepted.extend(found)
        else:
            if known:
                fails.append('%s: its known_stale acceptance EXPIRED %s -- fix the document, or '
                             'make a fresh dated decision' % (rel, known_stale_expires))
            fails.extend(found)
        state = 'agrees' if not found else ('%d KNOWN STALE (until %s, %s)'
                                            % (len(found), known_stale_expires,
                                               known_stale[rel]) if known and today <= stale_until
                                            else '%d CONTRADICTION(S)' % len(found))
        print('  %-50s %s' % (rel, state))
    fails.extend(stale_entries)
    if accepted:
        print('\n=== KNOWN STALE: found, reported, not failed until %s (owner: documentation lane) ==='
              % known_stale_expires)
        for a in accepted:
            print('  STALE %s' % a)

    if not checked:
        print('\nUNKNOWN: none of the listed documents exist. Nothing inspected is not nothing wrong.')
        return 2

    print('\n' + '=' * 72)
    if fails:
        for f in fails:
            print('FAIL: %s' % f)
        print('\nThe registry and the code are gated and the prose is what a person reads. When they')
        print('disagree, the reader believes the prose. Update the document, or correct the code --')
        print('but they do not get to disagree.')
        return 1
    print('PASS: no document calls an observed capability untested, and no document asserts a')
    print('      claim the code refutes (%d claim(s) checked over %d document(s)), outside the'
          % (len(rules), checked))
    print('      %d KNOWN STALE line(s) reported above, accepted until %s and no longer.'
          % (len(accepted), known_stale_expires))
    print('      ONE DIRECTION ONLY for the registry. Prose overstating what is proven is not checked')
    print('      here and would be worse; see this file\'s header for why, and do not read this pass')
    print('      as "the documentation is correct".')
    return 0


if __name__ == '__main__':
    sys.exit(main())

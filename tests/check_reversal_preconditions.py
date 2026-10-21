#!/usr/bin/env python3
"""A reversal may not delete anything it has not established it still owns.

WHY THIS EXISTS
    `ROLLBACK_CONTRACT.md` scopes reversal to a change manifest: remove what this run created,
    restore what it changed, leave everything else alone. That is right, and on its own it is not
    enough, because a change manifest is a record of the past and a reversal acts on the present.

        Release R1 creates resource X.
        Something else later modifies X, or takes a dependency on it.
        R1's manifest still says "I created X" -- still TRUE.
        It is no longer sufficient AUTHORITY to delete X.

    Stated by the owner of the design, and the sentence is the requirement:

        "You can't assume that the subscription remains empty and that you can have that
         destroy all without possibly destroying the new state for something that got
         onboarded in between."

    So every entry in a reversal manifest is a PROPOSAL, evaluated against live state at reversal
    time: does the object still carry this release's ownership stamp, is its current version the
    post-state this release recorded, has a later release or an external actor changed it, does
    anything introduced later depend on it, is this reversal happening in reverse-ancestry order.

    The row that matters most is the one where those questions cannot be answered.
    COULD-NOT-ESTABLISH MUST NEVER RESOLVE TOWARD A DESTRUCTIVE BRANCH. The contract already says
    that for a run whose previous state is unknown; this file is the same rule applied per object,
    which is where a run with a perfectly good previous state still meets an object it cannot
    vouch for.

    Design: docs/architecture/DEPLOYMENT_CONTRACT_RECONCILIATION.md section 8.
    Vocabulary: assurance-taxonomy.yaml -- release_ownership, reversal_conflict,
    reversal_disposition.

WHAT THIS CHECKS, AND WHAT IT DOES NOT
    SHAPE, NOT BEHAVIOUR. It reads the workflow graph and refuses the structures that make the
    defect possible. It cannot prove that an ownership comparison is CORRECT, that a stamp names
    the right release, or that any precondition is evaluated soundly -- only a run against a real
    target, with a real second actor modifying state between deploy and reversal, can do that, and
    that is acceptance work rather than this. A structural check claiming otherwise would be the
    same overstatement it exists to catch.

    Scope is deliberately narrow: a job is inspected only if it contains a DESTRUCTIVE step. The
    rule under test is "a reversal must not delete without establishing ownership", so a reversal
    that only restores prior values is out of scope here and is governed by the contract, not by
    this file.

    R1  A destructive step needs an      "I made this" is a claim about the past. Ownership is
        ownership read BEFORE it, in     read from the live object, or it is not read at all.
        the same job.
    R2  A destructive step must be       `if: always()` and `if: failure()` are not dispositions.
        guarded by a disposition.        A delete that runs regardless of what the preconditions
                                         found has preconditions for decoration.
    R3  The object's current version     Without it there is no way to ask whether the object is
        must be read before deleting.    still the post-state this release left behind.
    R4  A precondition read must not     A swallowed read error becomes an empty string, an empty
        be error-suppressed.             string becomes "nobody owns it", and that is one line of
                                         shell away from deleting somebody else's resource.

    R4 is the one R1 cannot catch: the read is present, and it cannot fail.

EXIT
    0  no reversal path in the tree deletes without establishing ownership
    1  a shape that permits an unowned or unchecked deletion is present
    2  the self-test could not run -- reported as UNKNOWN, never as PASS
"""
import glob
import io
import os
import re
import sys


def write_if_changed(path, content):
    """Write a tracked fixture only when its CONTENT differs (N51).

    These fixtures are committed so a reviewer can read them, and regenerated from the constants in
    this file so they cannot drift. Rewriting them unconditionally touched tracked files on every
    run -- on a CRLF checkout, every file showed modified -- and a test must leave the tree as it
    found it (tests/prove_tests_leave_tree_clean.py). Compared with line endings normalised, so a
    checkout's EOL convention is not mistaken for drift.
    """
    try:
        current = io.open(path, encoding='utf-8', newline='').read().replace('\r\n', '\n')
    except OSError:
        current = None
    if current != content.replace('\r\n', '\n'):
        io.open(path, 'w', encoding='utf-8', newline='\n').write(content)

try:
    import yaml
except ImportError:
    print('UNKNOWN: PyYAML not available; cannot read the workflow graph.')
    print('Failure to observe is not an observation.')
    sys.exit(2)

WORKFLOW_GLOBS = ['.github/workflows/*.yml', 'overlays/*/workflows/*.yml', 'templates/*.yml']
FIXTURES = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'fixtures')

# Removing a deployed object. Not file removal -- `rm` in a runner workspace destroys nothing a
# reversal is accountable for, and including it would produce noise that gets the check disabled.
DESTRUCTIVE_RUN = re.compile(
    r'\baz\s+[\w.-]+(?:\s+[\w.-]+)?\s+delete\b'
    r'|\bkubectl\s+delete\b'
    r'|\bterraform\s+destroy\b'
    r'|\bhelm\s+(?:uninstall|delete)\b'
    r'|\bpulumi\s+destroy\b'
    r'|\baws\s+[\w.-]+\s+delete-[\w.-]+\b'
    r'|\bgcloud\s+[\w.-]+(?:\s+[\w.-]+)?\s+delete\b')

# Asking the live target something, as opposed to asserting something about it from memory.
LIVE_READ = re.compile(r'\b(?:show|get|describe|list|inspect|read)\b')

# The ownership STAMP, not an ownership VERDICT. A step that emits `OWNED_EXCLUSIVE` has made a
# claim; a step that queries the stamp has made an observation, and only the second one is
# evidence. Requiring the observation is what stops a job satisfying R1 by asserting the answer.
OWNERSHIP_STAMP_READ = re.compile(r'release[_-]?ownership[_-]?stamp', re.I)

# The version handle that answers "is this still the post-state this release left behind".
VERSION_READ = re.compile(
    r'\betag\b|\bgeneration\b|\bresourceVersion\b|\bresource_version\b|\bpost_state_version\b',
    re.I)

# A guard that can actually refuse. The disposition vocabulary is registered in
# assurance-taxonomy.yaml; `always()` and `failure()` are conditions about the RUN, not about the
# OBJECT, and neither can withhold a delete because a precondition failed.
DISPOSITION_GUARD = re.compile(
    r'reversal_disposition|REVERSAL_REMOVE|OWNED_EXCLUSIVE|release_ownership')

# Idioms that turn a failed read into a successful empty answer. Note that `|| { ...; exit 1; }`
# is deliberately NOT here: that is a refusal, which is the remedy, and a check that flags the
# remedy teaches people to ignore it.
SUPPRESSED_READ = re.compile(
    r'\|\|\s*true\b'
    r'|\|\|\s*:\s*(?:$|\n)'
    r'|\|\|\s*echo\b'
    r'|2>\s*/dev/null'
    r'|\$\{[A-Za-z_][A-Za-z0-9_]*:-')


def step_text(step):
    """Everything a step might carry a command in, as one string.

    The step NAME is excluded on purpose. A step called "check ownership" that checks nothing
    would otherwise satisfy R1 by being named well.
    """
    parts = [str(step.get('run', '')), str(step.get('uses', ''))]
    with_ = step.get('with') or {}
    if isinstance(with_, dict):
        parts.extend(str(x) for x in with_.values())
    return '\n'.join(parts)


def classify(steps):
    """-> list of (index, label, set-of-roles). A step may hold more than one role."""
    out = []
    for i, step in enumerate(steps):
        if not isinstance(step, dict):
            continue
        body = step_text(step)
        roles = set()
        if DESTRUCTIVE_RUN.search(body):
            roles.add('destructive')
        if OWNERSHIP_STAMP_READ.search(body) and LIVE_READ.search(body):
            roles.add('ownership_read')
        if VERSION_READ.search(body) and LIVE_READ.search(body):
            roles.add('version_read')
        label = step.get('name') or str(step.get('uses', '')) or '(unnamed)'
        out.append((i, label, roles, body, str(step.get('if', ''))))
    return out


def check_job(wf_path, job_name, job):
    """-> list of failure strings."""
    steps = job.get('steps') or []
    if not isinstance(steps, list):
        return []
    roles = classify(steps)
    destructive = [r for r in roles if 'destructive' in r[2]]
    if not destructive:
        return []

    where = '%s :: job %s' % (wf_path, job_name)
    fails = []
    first_destructive = destructive[0][0]

    owners = [r for r in roles if 'ownership_read' in r[2] and r[0] < first_destructive]
    versions = [r for r in roles if 'version_read' in r[2] and r[0] < first_destructive]

    if not owners:
        fails.append(
            'R1 %s: step %r removes a deployed object and no step before it reads the\n'
            '     ownership stamp from live state.\n'
            '     The change manifest says this run created it. That is a statement about the\n'
            '     past. Something else may have modified it, adopted it or come to depend on it\n'
            '     since, and the manifest cannot know. Without a live ownership read the only\n'
            '     available answer is OWNERSHIP_UNESTABLISHED, which never licenses a removal.'
            % (where, destructive[0][1]))

    if not versions:
        fails.append(
            'R3 %s: step %r removes a deployed object and no step before it reads the object\'s\n'
            '     current version handle.\n'
            '     Ownership says who made it. The version says whether it is still what they\n'
            '     left. An object that is still stamped by this release and has been changed\n'
            '     since is MODIFIED_BY_EXTERNAL_ACTOR, and reversing it destroys a change\n'
            '     nobody in the release graph can describe.'
            % (where, destructive[0][1]))

    for idx, label, _roles, body, cond in destructive:
        if not DISPOSITION_GUARD.search(cond + '\n' + body):
            fails.append(
                'R2 %s: destructive step %r is not guarded by a reversal disposition (if: %r).\n'
                '     `always()` and `failure()` are conditions about the RUN. The question a\n'
                '     delete has to answer is about the OBJECT. A guard that cannot express\n'
                '     REVERSAL_WITHHELD_UNTRUSTED cannot withhold anything, and the preconditions\n'
                '     above it are decoration on the paths that happen to succeed.'
                % (where, label, cond or '(none)'))

    for idx, label, _roles, body, _cond in roles:
        if not ({'ownership_read', 'version_read'} & _roles):
            continue
        if idx > first_destructive:
            continue
        if SUPPRESSED_READ.search(body):
            fails.append(
                'R4 %s: precondition read %r suppresses its own failure.\n'
                '     A swallowed read error becomes an empty string; an empty string reads as\n'
                '     "no owner recorded"; and no owner recorded is one line of shell away from\n'
                '     deleting a resource this release does not own. PRECONDITION_UNESTABLISHED\n'
                '     is a distinct answer from "no conflict found" and must stay distinct --\n'
                '     the same defect as inferring an empty previous state from a swallowed\n'
                '     error, arriving one layer later.'
                % (where, label))

    return fails


def scan_file(path):
    try:
        doc = yaml.safe_load(io.open(path, encoding='utf-8', errors='replace'))
    except Exception as e:
        return ['UNREADABLE %s: %s' % (path, e)]
    if not isinstance(doc, dict):
        return []
    fails = []
    for job_name, job in (doc.get('jobs') or {}).items():
        if isinstance(job, dict):
            fails.extend(check_job(path, job_name, job))
    return fails


def reversal_jobs(path):
    """-> [job name] for jobs that remove a deployed object."""
    try:
        doc = yaml.safe_load(io.open(path, encoding='utf-8', errors='replace'))
    except Exception:
        return []
    if not isinstance(doc, dict):
        return []
    out = []
    for job_name, job in (doc.get('jobs') or {}).items():
        if not isinstance(job, dict):
            continue
        if any('destructive' in r[2] for r in classify(job.get('steps') or [])):
            out.append(job_name)
    return out


# ----------------------------------------------------------------------------- fixtures
#
# ONE GOOD FIXTURE, AND EVERY BAD FIXTURE DERIVED FROM IT BY A SINGLE TARGETED MUTATION.
#
# This repository has already shipped a fixture that "proved" a guard while the guard's regex was
# dead, because the fixture returned the expected value for an unrelated reason. Hand-writing a
# separate bad fixture per rule reproduces exactly that risk: the fixture drifts, starts tripping
# a different rule, and the assertion still passes.
#
# Mutating the CORRECT fixture removes the risk structurally. Each mutant differs from a passing
# shape by one substring, so the only thing that can explain a failure is the rule under test --
# and the self-test asserts the EXACT set of codes, not merely that the expected one appears.
# If a rule's regex goes dead, its mutant becomes clean and the self-test says so.

GOOD_FIXTURE = """\
# Fixture: a reversal that establishes ownership before it removes anything. It must PASS.
# Without this half the self-test cannot tell "the rules work" from "the rules reject everything".
name: fixture reversal with preconditions
on:
  workflow_call:
    inputs:
      release_id:
        description: The release being reversed.
        required: true
        type: string
permissions:
  contents: read
jobs:
  reverse:
    runs-on: ubuntu-latest
    steps:
      - name: P1 - read the ownership stamp off the live object
        id: ownership
        run: |
          set -euo pipefail
          STAMP="$(az resource show --ids "$TARGET" --query "tags.release_ownership_stamp" -o tsv)"
          [ -n "$STAMP" ] || { echo "the stamp on the live object could not be read"; exit 1; }
          echo "stamp=$STAMP" >> "$GITHUB_OUTPUT"

      - name: P2 - read the current version handle and compare it with the recorded post-state
        id: drift
        run: |
          set -euo pipefail
          CURRENT="$(az resource show --ids "$TARGET" --query etag -o tsv)"
          [ -n "$CURRENT" ] || { echo "the current version handle could not be read"; exit 1; }
          echo "current=$CURRENT" >> "$GITHUB_OUTPUT"

      - name: Derive the disposition from what live state actually said
        id: preconditions
        run: |
          set -euo pipefail
          python3 scripts/derive_reversal_disposition.py \\
            --stamp "${{ steps.ownership.outputs.stamp }}" \\
            --current-version "${{ steps.drift.outputs.current }}" \\
            --release "${{ inputs.release_id }}" >> "$GITHUB_OUTPUT"

      - name: Restore the recorded pre-state where this release still owns the change
        if: steps.preconditions.outputs.reversal_disposition == 'REVERSAL_RESTORE_PRIOR'
        run: |
          set -euo pipefail
          az resource update --ids "$TARGET" --set "$PRIOR"

      - name: Remove only what this release created and still exclusively owns
        if: steps.preconditions.outputs.reversal_disposition == 'REVERSAL_REMOVE'
        run: |
          set -euo pipefail
          az resource delete --ids "$TARGET"
"""

# (code, what the mutation does, substring in GOOD_FIXTURE, replacement)
MUTATIONS = [
    ('R1',
     'the ownership query stops asking for the stamp, so nothing reads ownership from live state',
     '--query "tags.release_ownership_stamp" -o tsv',
     '--query "name" -o tsv'),
    ('R2',
     'the delete keeps its preconditions and stops being gated on their answer',
     "if: steps.preconditions.outputs.reversal_disposition == 'REVERSAL_REMOVE'",
     'if: always()'),
    ('R3',
     'the version handle is no longer read, so drift since the recorded post-state is invisible',
     '--query etag -o tsv',
     '--query "name" -o tsv'),
    ('R4',
     'the ownership read swallows its own failure, so an unreadable stamp becomes an empty one',
     '--query "tags.release_ownership_stamp" -o tsv)"',
     '--query "tags.release_ownership_stamp" -o tsv 2>/dev/null || true)"'),
]

# The shape the owner's sentence describes, kept as a whole rather than as a mutation: a cleanup
# step that destroys a container scope on failure, having established nothing about who owns what
# is inside it. It must trip R1, R2 and R3 together.
NAIVE_TEARDOWN_FIXTURE = """\
# Fixture: "deployment failed, delete the scope". It must FAIL, on three rules at once.
name: fixture naive teardown
on:
  workflow_call: {}
permissions:
  contents: read
jobs:
  deploy:
    runs-on: ubuntu-latest
    steps:
      - name: Deploy
        run: az deployment group create --resource-group "$RG" --template-file main.bicep

      - name: Clean up on failure
        if: failure()
        run: |
          set -euo pipefail
          az group delete --name "$RG" --yes --no-wait
"""

EXPECTED_NAIVE = ('R1', 'R2', 'R3')


def codes(fails):
    return set(f.split()[0] for f in fails)


def self_test():
    """Both directions, and a differential. A checker proven only on its passing case proves
    nothing; a checker proven on a bad fixture that fails for an unrelated reason proves less
    than nothing, because it looks like evidence."""
    if not os.path.isdir(FIXTURES):
        print('UNKNOWN: %s missing; cannot run the self-test.' % FIXTURES)
        return 2

    good_path = os.path.join(FIXTURES, 'reversal_with_preconditions.sample')
    write_if_changed(good_path, GOOD_FIXTURE)
    good_fails = scan_file(good_path)

    ok = True
    if good_fails:
        print('SELF-TEST FAILED: the correct reversal fixture was rejected:')
        for f in good_fails:
            print('  ' + f.split('\n')[0])
        ok = False

    # A correct fixture that contains no destructive step would pass every rule vacuously and
    # prove nothing at all. Assert the fixture is actually in scope.
    if not reversal_jobs(good_path):
        print('SELF-TEST FAILED: the correct fixture contains no destructive step, so it is out')
        print('  of scope and its clean result is vacuous.')
        ok = False

    fired = []
    for code, what, old, new in MUTATIONS:
        if old not in GOOD_FIXTURE:
            print('SELF-TEST FAILED: the %s mutation anchor is not present in the correct '
                  'fixture.' % code)
            print('  A mutation that changes nothing produces a clean mutant, and a clean mutant')
            print('  would be read as "the rule passed".')
            ok = False
            continue
        mutant = GOOD_FIXTURE.replace(old, new, 1)
        if mutant == GOOD_FIXTURE:
            print('SELF-TEST FAILED: the %s mutation was a no-op.' % code)
            ok = False
            continue
        path = os.path.join(FIXTURES, 'reversal_mutant_%s.sample' % code.lower())
        write_if_changed(path, mutant)
        try:
            yaml.safe_load(io.open(path, encoding='utf-8'))
        except Exception as e:
            print('SELF-TEST FAILED: the %s mutant is not valid YAML (%s), so a failure could '
                  'be a parse error rather than the rule.' % (code, e))
            ok = False
            continue
        got = codes(scan_file(path))
        if got != {code}:
            print('SELF-TEST FAILED: the %s mutant tripped %s, expected exactly {%s}.'
                  % (code, sorted(got) or '{}', code))
            print('  Mutation: %s' % what)
            print('  A mutant that trips MORE than its rule is evidence for the wrong rule; one')
            print('  that trips nothing means this rule cannot fire at all.')
            ok = False
            continue
        fired.append(code)

    naive_path = os.path.join(FIXTURES, 'reversal_naive_teardown.sample')
    write_if_changed(naive_path, NAIVE_TEARDOWN_FIXTURE)
    naive = codes(scan_file(naive_path))
    if naive != set(EXPECTED_NAIVE):
        print('SELF-TEST FAILED: the naive-teardown fixture tripped %s, expected exactly %s.'
              % (sorted(naive) or '{}', sorted(EXPECTED_NAIVE)))
        ok = False

    if not ok:
        return 1

    print('self-test ok: one correct reversal fixture passes and is in scope; four single-token')
    print('              mutants of that same fixture trip %s and nothing else; the'
          % ', '.join(fired))
    print('              "delete the scope on failure" fixture trips %s together.'
          % ', '.join(EXPECTED_NAIVE))
    print('              Each bad fixture differs from a PASSING shape by one substring, so a')
    print('              failure cannot be explained by anything but the rule under test.')
    return 0


def main():
    st = self_test()
    if st:
        return st

    files = []
    for pat in WORKFLOW_GLOBS:
        files.extend(f for f in glob.glob(pat) if os.path.isfile(f))
    files = sorted(set(files))
    if not files:
        print('UNKNOWN: no workflows found. Nothing inspected is not nothing wrong.')
        return 2

    print('\n=== jobs that remove a deployed object ===')
    fails, found = [], 0
    for f in files:
        for job_name in reversal_jobs(f):
            found += 1
            print('  %s :: %s' % (f, job_name))
        fails.extend(scan_file(f))

    print('\n' + '=' * 72)
    if fails:
        for f in fails:
            print('FAIL: ' + f)
        print('\nA reversal may not delete anything it has not established it still owns.')
        return 1

    if not found:
        print('  none')
        print('')
        print('PASS, AND SAY WHY: %d workflow file(s) inspected and NOT ONE removes a deployed'
              % len(files))
        print('      object, so no reversal path was exercised against these rules. The rules')
        print('      themselves are proven by the fixtures above and by nothing in this tree.')
        print('      This is the expected result while state-aware reversal is unimplemented;')
        print('      it is reported rather than rendered as coverage, because a check with')
        print('      nothing to inspect and a clean repository produce the identical output.')
        return 0

    print('PASS: %d reversal job(s); each reads ownership and the current version from live' % found)
    print('      state before removing anything, gates the removal on a disposition, and does')
    print('      not suppress its own precondition reads.')
    print('')
    print('      SHAPE ONLY. That the ownership comparison is CORRECT, that the stamp names the')
    print('      right release, and that a second actor modifying state between deploy and')
    print('      reversal is actually detected, are all unproven here and need a live target.')
    return 0


if __name__ == '__main__':
    sys.exit(main())

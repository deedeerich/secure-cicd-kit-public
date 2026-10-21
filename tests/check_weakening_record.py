#!/usr/bin/env python3
"""A weakening input may not exist without appearing in the emitted control-posture record.

WHY THIS EXISTS

    `soft_fail_sast` appeared in no summary, no report, no annotation, and nowhere in
    assurance-taxonomy.yaml. A caller could soften the security gate and the run was reported
    IDENTICALLY to one that passed honestly.

    That is this kit's own thesis failing at its front door. Everywhere else it insists that
    `configured` is not `effective` and that an unrecorded weakening reads exactly like a clean
    result. Then it accepted a boolean and said nothing.

    A WEAKENING IS NOT A BOOLEAN PREFERENCE. IT IS A GOVERNED EXCEPTION, AND IT MUST BE VISIBLE
    IN THE EVIDENCE.

THE RULE THIS ENFORCES

    Every workflow that declares `workflow_call.inputs` emits a control-posture record, and the
    record's enumeration of those inputs is TOTAL. Totality is the whole control. A check that
    hunts for a hand-written list of weakening names -- soft_fail_sast, advisory_mode,
    trivy_severity -- is a list that goes stale the first time somebody adds an input, and a
    stale list reports clean on a narrower denominator. So the check never asks "is this input
    dangerous". It asks "is this input CLASSIFIED", and refuses the run when one is not.

    The escape hatch is the thing to guard. `NOT_A_CONTROL_SURFACE` exists because a Python
    version really does not weaken anything -- and a totality check is defeated the moment
    everything can be labelled that way. So W7 reads the input's OWN DESCRIPTION and refuses that
    class for any input whose documentation says it softens, skips, disables, suppresses, or
    reports without failing. The input's documentation is evidence against its classification.

WHAT IT CHECKS

    W1  TOTALITY            every declared input has exactly one `posture` declaration
    W2  NO PHANTOM          every `posture` declaration names a declared input
    W3  REGISTERED CLASS    every class is a term in assurance-taxonomy.yaml
    W4  DATA TRANSPORT      every control-surface input reaches the record through `env:`,
                            as `W_<INPUT>`, and the declaration reads that variable -- never
                            `${{ }}` inside the script body (tests/lint_injection.py's rule)
    W5  RECORD COMPLETE     all nine record rows are emitted as machine-readable outputs
    W6  ROUTING VOCABULARY  every routing value is one of the five registered outcomes, and all
                            five are reachable -- a routing model whose EVIDENCE_UNTRUSTED branch
                            cannot be reached is pass/fail wearing five names
    W7  NO LAUNDERING       an input whose description says it softens a control may not be
                            classified as governing no control

WHAT IT CANNOT ESTABLISH

    SHAPE, NOT BEHAVIOUR. It proves the record enumerates every input, transports it as data, and
    emits every row. It cannot prove that a BASELINE is the right baseline, that a control name
    corresponds to a scanner that exists, or that the emitted values are true of a real run. A
    check claiming otherwise would be the overstatement it exists to catch. Nor can it see
    whether a caller passed a value explicitly or inherited the default -- a workflow receives
    resolved inputs, so the record says a control is weakened and says nothing about who chose it.

EXIT
    0  every in-scope workflow records every input, and every exemption is dated and unexpired
    1  an input can be weakened without appearing in the record, or an exemption has expired
    2  the self-test could not run -- reported as UNKNOWN, never as PASS
"""
from __future__ import annotations

import argparse
import datetime
import glob
import io
import os
import re
import shlex
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

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
TAXONOMY = os.path.join(ROOT, 'assurance-taxonomy.yaml')
FIXTURES = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'fixtures')
WORKFLOW_GLOBS = ['.github/workflows/*.yml', 'overlays/*/workflows/*.yml']

# The nine rows the record owes a consumer. Named here rather than inferred, because a record
# that quietly loses a row is the failure mode -- `controls_unavailable` disappearing is how
# "could not be acquired" goes back to reading as "found nothing".
REQUIRED_EMISSIONS = (
    'routing_result',
    'controls_required',
    'controls_executed',
    'controls_unavailable',
    'controls_reduced',
    'controls_skipped',
    'weakenings',            # the per-input enumeration: class, baseline, value, state
    'weakening_attribution',  # reason and authority, as a state
    'weakening_record',      # reason, authority, exception reference, expiry
)

ROUTING_OUTCOMES = {
    'PROCEED', 'PROCEED_WITH_ADVISORY', 'DECISION_REQUIRED', 'BLOCKED', 'EVIDENCE_UNTRUSTED',
}

# The class that means "this governs no control". W7 refuses it for anything whose own
# description contradicts it.
INERT_CLASS = 'NOT_A_CONTROL_SURFACE'
# The class that carries the governance fields themselves. Their values are PRINTED into the
# record rather than COMPARED against a baseline, so they must reach the step as data like
# everything else -- but the declaration line carries no value to compare.
ATTRIBUTION_CLASS = 'EXCEPTION_ATTRIBUTION'
# Governs no control, so nothing about it is recorded and nothing needs transporting.
NO_TRANSPORT = {INERT_CLASS}
# Transported, but not compared -- so no `"$W_..."` argument on the declaration line.
NO_COMPARISON = {INERT_CLASS, ATTRIBUTION_CLASS}

# Language that says an input softens, disables, narrows or silences a control. Deliberately
# drawn from how THIS kit writes its own input descriptions, and deliberately not exhaustive:
# it is a floor on W7, not a classifier. Anything it misses is still caught by W1's totality --
# the input must be classified as SOMETHING, and mislabelling it is a reviewable diff.
SOFTENING_LANGUAGE = re.compile(
    r'soft[_ -]?fail'
    r'|advisory'
    r'|weaken'
    r'|do(?:es)? not fail'
    r'|never fail'
    r'|without failing'
    r'|not blocking'
    r'|report(?:s|ing)? (?:only|without)'
    r'|report violations without'
    r'|suppress'
    r'|disable'
    r'|deliberately skip'
    r'|turn(?:ed)? off',
    re.I)

# ─────────────────────────────────────────────────────────────────────────────────────────────
# EXEMPTIONS. Dated, owned, and printed on every run.
#
# A permanently red check is not a control, it is training: people learn red means "known
# backlog", stop reading it, and a real regression arrives wearing the same colour. That is why
# an unwired workflow is ACCOUNTED FOR rather than silently skipped -- and why the account
# EXPIRES. Silence must never renew an exemption, the same mechanism disposition_type and
# validation_debt_state already use.
#
# An expired exemption FAILS. An undeclared unwired workflow FAILS. Those are the two states that
# let a weakening go unrecorded.
EXEMPT: dict[str, dict] = {
    # `reusable-security.yml` CLOSED 2026-10-14 (ledger L30/L31): the file is under 500 KB again and
    # its security-gate job emits the posture record. Deleted, not extended, as this entry said.
    # Values, not just shape, are proven by tests/prove_gate_routing.py.
    #
    # `reusable-deploy-appservice.yml` and `reusable-deploy-containerapp.yml` CLOSED 2026-10-15:
    # the reversal contract is implemented (scripts/deploy_contract.py, proven against a stubbed
    # cloud by tests/prove_deploy_outcome.py) and both deploy jobs emit the posture record, whose
    # ROUTING is proven by tests/prove_deploy_posture.py -- a deploy that cannot be reversed at a
    # production tier is refused before the point of no return and routes BLOCKED over any
    # weakening the caller recorded. Deleted, not extended, as these entries said.
    # FOUND BY THIS CHECK, not by the brief that commissioned it — which is the enumeration
    # doing its job. Nobody named this workflow as having weakening inputs; totality did.
    # RE-DECIDED 2026-10-21 (lane L-E, owner ruling of 2026-10-16/21: "resolve per the ledger
    # rows, with a reason and expiry where a deferral stays"). Its old closing condition -- the
    # `authorization-boundary-isolation` and `context-integrity` deferrals closing -- was MET on
    # 2026-10-15 (both observed live), and the entry stayed, still saying the probe had never been
    # dispatched. The probe now has a model observed on the real tenant; what is still unbuilt is
    # the posture step itself, which belongs with ledger row L103 (fail on an UNAVAILABLE
    # calibration, hash the scope) in the same file. So the exemption stays, re-reasoned and
    # re-dated, never renewed by silence. tests/prove_registry_hygiene.py H4 refuses an exemption
    # whose named deferrals have all closed, and one past its expiry.
    'verify-azure-oidc.yml': {
        'reason': "its inputs are probe EXPECTATIONS rather than control settings, and two of "
                  "them weaken the probe by omission: a blank expect_repository derives the "
                  "claim from the run context instead of asserting it, and a blank "
                  "expect_job_workflow_ref_prefix records that claim UNASSERTED. The probe HAS "
                  "been dispatched and observed on the real tenant (runs 38826929579, "
                  "38832628162, 38832634828, 38850408850), so the model a posture record needs "
                  "now exists; the posture step is not built. It is owed with ledger L103 in "
                  "the same workflow, which no lane has taken yet",
        'owner': 'kit-maintainer',
        'weakening_inputs_unrecorded': ['expect_repository', 'expect_job_workflow_ref_prefix',
                                        'additional_reachable_resource_groups',
                                        'additional_refused_resource_groups',
                                        'subscription_probe_location', 'token_audience',
                                        # ADDED 2026-10-15: the context-integrity refusal fixture.
                                        # Blank keeps the comparison against the login's own
                                        # secrets; a value adds a second comparison and can only
                                        # make the step stricter. Listed here for totality, not
                                        # because any value of them softens anything.
                                        'expect_tenant_id', 'expect_subscription_id',
                                        'expect_client_id'],
        'closes': 'verify-azure-oidc.yml emits the control posture record over these inputs '
                  '(expect_repository and expect_job_workflow_ref_prefix as weakening-by-omission '
                  'rows), proven by running the shipped step; built with ledger L103. Not a '
                  'validation deferral: the ratchet does not move.',
        'expires': '2026-12-31',
    },
}

EXEMPT_FIELDS = ('reason', 'owner', 'weakening_inputs_unrecorded', 'closes', 'expires')

# Workflows whose EVERY input governs no control, so a posture record would record nothing. Not an
# exemption: they are checked for totality (W1/W2) and laundering (W7) like any other, and a new input
# that is not listed here fails W1 until it is classified or the workflow gains a posture step.
INERT_ONLY: dict[str, dict] = {
    # KDEC-013, 2026-10-16. Every input either names the reference shape or NARROWS what is
    # accepted; none can soften, skip or relax the gate. An empty host or key makes the gate FAIL as
    # unconfigured (tests/prove_ticket_reference_gate.py G5), and a range can only reject more.
    'reusable-ticket-reference.yml': {
        'tracker_host': 'names the Jira site the reference must point at; empty fails the gate as '
                        'unconfigured, it never passes it',
        'project_key': 'names the Jira project the reference must carry; empty fails the gate as '
                       'unconfigured, it never passes it',
        'min_digits': 'an optional lower bound on the issue number; it can only reject more '
                      'references, and half a range fails the gate as misconfigured',
        'max_digits': 'an optional upper bound on the issue number; it can only reject more '
                      'references, and half a range fails the gate as misconfigured',
    },
    'reusable-propose-ledger.yml': {
        'environment': 'names the baseline-ledger environment the proposal is for; it selects which '
                       'ledger is read, and no value of it softens, skips or narrows a control',
        'establish-approver-role': 'names the approver ROLE recorded in a first ledger\'s header (F-01). '
                                   'It decides nothing: with no ledger it turns a refusal into an '
                                   'establishment PULL REQUEST that CODEOWNERS must cover and a human '
                                   'must merge; with a ledger it is ignored. The role is itself the '
                                   'record, in the header and the PR body',
        'ticket-ledger-artifact': 'names the same-run artifact holding the ticket ledger proposal (T-20). '
                                  'It selects which file joins the reviewed pull request; a malformed '
                                  'proposal refuses, and nothing merges without review',
    },
}


# ─────────────────────────────────────────────────────────────────────────── taxonomy


def registered_classes():
    """-> set of control_weakening class terms, plus DEPTH_REDUCED reused from scan_depth.

    REUSE BEATS REGISTRATION. `scan_depth.DEPTH_REDUCED` already means "ran with a narrower
    suite or scope than its fullest setting", which is exactly what a reduced-depth input does.
    Registering a synonym beside it would be the drift the registry exists to catch, so it is
    admitted here from its own namespace instead.
    """
    doc = yaml.safe_load(io.open(TAXONOMY, encoding='utf-8')) or {}
    ns = doc.get('namespaces') or {}
    cw = (ns.get('control_weakening') or {}).get('values') or {}
    depth = (ns.get('scan_depth') or {}).get('values') or {}
    out = set(cw)
    if 'DEPTH_REDUCED' in depth:
        out.add('DEPTH_REDUCED')
    return out


def registered_routing():
    doc = yaml.safe_load(io.open(TAXONOMY, encoding='utf-8')) or {}
    ns = doc.get('namespaces') or {}
    return set((ns.get('routing_result') or {}).get('values') or {})


# ─────────────────────────────────────────────────────────────────────────── parsing


def load(path):
    return yaml.safe_load(io.open(path, encoding='utf-8', errors='replace'))


def call_inputs(doc):
    """-> {name: spec} for a workflow_call contract, or None when it is not callable.

    `on:` parses as the boolean True under YAML 1.1, which is why both spellings are read. A
    checker that silently sees no inputs because of a YAML quirk is a checker that reports clean
    on an empty denominator.
    """
    if not isinstance(doc, dict):
        return None
    on = doc.get('on', doc.get(True))
    if not isinstance(on, dict) or 'workflow_call' not in on:
        return None
    call = on['workflow_call'] or {}
    ins = call.get('inputs') or {}
    return ins if isinstance(ins, dict) else {}


def posture_step(doc):
    """-> the step whose id is `posture`, or None."""
    for job in (doc.get('jobs') or {}).values():
        if not isinstance(job, dict):
            continue
        for step in (job.get('steps') or []):
            if isinstance(step, dict) and step.get('id') == 'posture':
                return step
    return None


DECL = re.compile(r'^\s*posture\s+(\S.*?)\s*$', re.M)


def declarations(run_text):
    """-> [(input, class, baseline, control, value_token_or_None)] and a list of malformed lines."""
    out, bad = [], []
    for m in DECL.finditer(run_text or ''):
        try:
            parts = shlex.split(m.group(1))
        except ValueError as e:
            bad.append('%s (%s)' % (m.group(0).strip(), e))
            continue
        if len(parts) == 4:
            out.append((parts[0], parts[1], parts[2], parts[3], None))
        elif len(parts) == 5:
            out.append(tuple(parts))
        else:
            bad.append(m.group(0).strip())
    return out, bad


def emitted_keys(run_text):
    """-> set of output keys the step writes.

    Matches `emit <key> ...`, the idiom every emitter in this kit uses. A record that writes an
    output some other way is not recognised, which is deliberate: one spelling per boundary is
    the point of having a boundary.
    """
    return set(re.findall(r'^\s*emit\s+([a-z_]+)\b', run_text or '', re.M))


def without_routing_terms(desc, routes):
    """The description with the REGISTERED routing_result terms removed, for W7.

    A deploy's `routing_result` input is the gate verdict it was given, and its description has to
    name the values it accepts -- one of which is PROCEED_WITH_ADVISORY. That is a registered term
    naming an outcome, not language saying this input softens a control; matching `advisory`
    inside it would refuse the honest class for an input the verdict GUARD examines (as the digest
    guard examines image_digest). Only whole registered terms are removed, so `advisory_mode` and
    prose like "advisory only" are still read as the softening language they are.
    """
    out = desc
    for term in sorted(routes, key=len, reverse=True):
        out = re.sub(r'(?<![A-Za-z0-9_])%s(?![A-Za-z0-9_])' % re.escape(term), ' ', out)
    return out


def routing_values(run_text):
    """-> set of values assigned to the routing variable, and the set mentioned anywhere."""
    assigned = set(re.findall(r'\broute=([A-Z_]+)', run_text or ''))
    return assigned


# ─────────────────────────────────────────────────────────────────────────── rules


def check_workflow(path, doc, classes, routes):
    """-> list of failure strings for one wired workflow."""
    where = os.path.relpath(path, ROOT).replace('\\', '/')
    ins = call_inputs(doc) or {}
    step = posture_step(doc)
    inert = INERT_ONLY.get(os.path.basename(path))
    if step is None and inert is not None:
        # A workflow whose EVERY input governs no control has no posture to record. It is held to the
        # same two guards a posture record is: totality (every input listed, nothing phantom) and no
        # laundering (an input whose own text says it softens a control may not be called inert).
        fails = []
        for name in sorted(set(ins) - set(inert)):
            fails.append('W1 %s: input `%s` is not in INERT_ONLY and there is no posture record; '
                         'classify it, or give the workflow a posture step' % (where, name))
        for name in sorted(set(inert) - set(ins)):
            fails.append('W2 %s: INERT_ONLY lists `%s`, which the workflow does not declare'
                         % (where, name))
        for name in sorted(set(inert) & set(ins)):
            desc = str((ins[name] or {}).get('description') or '')
            m = SOFTENING_LANGUAGE.search(without_routing_terms(desc, routes))
            if m:
                fails.append('W7 %s: input `%s` is listed as governing no control, and its own '
                             'description says %r' % (where, name, m.group(0)))
        return fails
    if step is None:
        return ['W0 %s: declares %d workflow_call input(s) and emits no control-posture record '
                '(no step with `id: posture`).\n'
                '     A weakening that is not in the record did not happen as far as the evidence\n'
                '     is concerned, which is indistinguishable from a clean run.'
                % (where, len(ins))]

    run = step.get('run') or ''
    env = step.get('env') or {}
    if not isinstance(env, dict):
        env = {}
    decls, malformed = declarations(run)
    fails = []

    for line in malformed:
        fails.append('W2 %s: malformed posture declaration %r.\n'
                     '     A declaration the checker cannot read is a declaration nobody can\n'
                     '     audit, and it silently removes an input from the denominator.'
                     % (where, line))

    declared = {}
    for name, cls, base, ctl, val in decls:
        if name in declared:
            fails.append('W2 %s: input `%s` is declared more than once. Two classifications for\n'
                         '     one input means the record depends on evaluation order.'
                         % (where, name))
        declared[name] = (cls, base, ctl, val)

    # W1 TOTALITY -- the control. An input nobody classified is an input nobody recorded.
    for name in sorted(ins):
        if name not in declared:
            fails.append(
                'W1 %s: input `%s` is declared in workflow_call and has no `posture` line.\n'
                '     The enumeration must be TOTAL over the workflow\'s inputs. A check that\n'
                '     hunts for a hand-written list of weakening names is a list that goes\n'
                '     stale, and a stale list reports clean on a narrower denominator.'
                % (where, name))

    # W2 NO PHANTOM -- a declaration for an input that does not exist pads the denominator.
    for name in sorted(declared):
        if name not in ins:
            fails.append(
                'W2 %s: `posture %s` names an input this workflow does not declare.\n'
                '     A phantom row makes the record look more complete than it is.'
                % (where, name))

    for name in sorted(declared):
        if name not in ins:
            continue
        cls, base, ctl, val = declared[name]
        spec = ins[name] if isinstance(ins[name], dict) else {}
        desc = str(spec.get('description') or '')

        # W3 REGISTERED CLASS
        if cls not in classes:
            fails.append(
                'W3 %s: input `%s` is classified `%s`, which is not a registered term.\n'
                '     assurance-taxonomy.yaml :: control_weakening is the authority. An\n'
                '     undefined enforcement word is how PARTIAL quietly becomes PASS three\n'
                '     layers downstream.' % (where, name, cls))
            continue

        # W4 DATA TRANSPORT -- and the reason it is `env:` and not `${{ }}`.
        if cls not in NO_TRANSPORT:
            var = 'W_' + name.upper()
            if env.get(var) is None:
                fails.append(
                    'W4 %s: input `%s` is classified `%s` and does not reach the record through\n'
                    '     `env:` as `%s`.\n'
                    '     In `env:` it is DATA. Interpolated into the script it is CODE, it\n'
                    '     truncates on a quote, and the record it produces can be wrong for a\n'
                    '     reason nobody can see. tests/lint_injection.py holds the same line.'
                    % (where, name, cls, var))
            elif ('inputs.%s' % name) not in str(env.get(var)):
                fails.append(
                    'W4 %s: `%s` is mapped to %r rather than to `inputs.%s`.\n'
                    '     The record would report a value the caller never supplied.'
                    % (where, var, str(env.get(var)), name))
            if cls not in NO_COMPARISON and val != '$' + var:
                fails.append(
                    'W4 %s: the `posture %s` declaration reads %r instead of `"$%s"`.\n'
                    '     A declaration that compares something other than the caller\'s value\n'
                    '     produces a record about a value nobody passed.'
                    % (where, name, val, var))

        # W7 NO LAUNDERING -- the input's own documentation is evidence against its class.
        if cls == INERT_CLASS:
            m = SOFTENING_LANGUAGE.search(without_routing_terms(desc, routes))
            if m:
                fails.append(
                    'W7 %s: input `%s` is classified `%s`, and its own description says %r.\n'
                    '     An input that softens, skips, disables or silences a control governs a\n'
                    '     control. This class is the escape hatch and therefore the thing to\n'
                    '     guard: a totality check is defeated the moment everything can be\n'
                    '     labelled inert.' % (where, name, INERT_CLASS, m.group(0)))

    # W5 RECORD COMPLETE
    emitted = emitted_keys(run)
    for key in REQUIRED_EMISSIONS:
        if key not in emitted:
            fails.append(
                'W5 %s: the record does not emit `%s`.\n'
                '     Nine rows are owed: required, executed, unavailable, reduced, skipped,\n'
                '     reason, authority, exception reference, expiry, and the routing result.\n'
                '     `controls_unavailable` disappearing is how "could not be acquired" goes\n'
                '     back to reading as "found nothing".' % (where, key))

    # W6 ROUTING VOCABULARY
    assigned = routing_values(run)
    for v in sorted(assigned):
        if v not in routes:
            fails.append(
                'W6 %s: routing value `%s` is not one of the five registered outcomes %s.\n'
                '     A sixth outcome invented at the boundary is a second vocabulary, which is\n'
                '     the drift assurance-taxonomy.yaml exists to catch.'
                % (where, v, sorted(routes)))
    missing_routes = routes - assigned
    if missing_routes:
        fails.append(
            'W6 %s: routing outcome(s) %s can never be reached by this record.\n'
            '     Binary pass/fail is the collapse this kit refuses everywhere else. A routing\n'
            '     model whose EVIDENCE_UNTRUSTED branch is unreachable is pass/fail wearing five\n'
            '     names -- and EVIDENCE_UNTRUSTED is the one that matters, because a scanner\n'
            '     that could not be acquired is not a decision someone owes and is emphatically\n'
            '     not clean.' % (where, sorted(missing_routes)))

    return fails


# ─────────────────────────────────────────────────────────────────────────── fixtures
#
# ONE GOOD FIXTURE, AND EVERY BAD FIXTURE DERIVED FROM IT BY A SINGLE TARGETED MUTATION.
#
# This repository has already shipped a fixture that "proved" a guard whose regex was dead: the
# fixture returned the expected value for an unrelated reason, so the assertion passed while the
# rule could not fire. Hand-writing a separate bad fixture per rule reproduces exactly that risk.
#
# Mutating the CORRECT fixture removes it structurally. Each mutant differs from a PASSING shape
# by one substring, so the only thing that can explain a failure is the rule under test -- and
# the self-test asserts the EXACT set of codes, not merely that the expected one appears. If a
# rule's regex goes dead, its mutant comes back clean and the self-test says so.

GOOD_FIXTURE = """\
# Fixture: a workflow whose every input appears in the emitted control-posture record.
# It must PASS. Without this half the self-test cannot tell "the rules work" from "the rules
# reject everything".
name: fixture recorded weakenings
on:
  workflow_call:
    inputs:
      python_version:
        description: Interpreter version used for the scan runner.
        type: string
        default: "3.12"
      soft_fail_scan:
        description: Report findings without failing the build. Use for first adoption only.
        type: boolean
        default: false
      enable_depth_scan:
        description: Run the deep analyser.
        type: boolean
        default: true
      weakening_reason:
        description: Why a control on this invocation is weaker than baseline.
        type: string
        default: ""
permissions:
  contents: read
jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - name: Control posture
        id: posture
        if: always()
        env:
          W_SOFT_FAIL_SCAN: ${{ inputs.soft_fail_scan }}
          W_ENABLE_DEPTH_SCAN: ${{ inputs.enable_depth_scan }}
          W_WEAKENING_REASON: ${{ inputs.weakening_reason }}
        run: |
          set -u
          posture python_version    NOT_A_CONTROL_SURFACE - -
          posture soft_fail_scan    GATE_SOFTENED    false deep-scan "$W_SOFT_FAIL_SCAN"
          posture enable_depth_scan CONTROL_DISABLED true  deep-scan "$W_ENABLE_DEPTH_SCAN"
          posture weakening_reason  EXCEPTION_ATTRIBUTION - -
          route=PROCEED
          [ -n "$unav" ] && route=EVIDENCE_UNTRUSTED
          [ -n "$owed" ] && route=DECISION_REQUIRED
          [ -n "$soft" ] && route=PROCEED_WITH_ADVISORY
          [ -n "$stop" ] && route=BLOCKED
          emit routing_result "$route"
          emit controls_required "$REQ"
          emit controls_executed "$EXE"
          emit controls_unavailable "$UNAV"
          emit controls_reduced "$RED"
          emit controls_skipped "$SKP"
          emit weakenings "$WK"
          emit weakening_attribution "$auth"
          emit weakening_record "$rec"
"""

# (code, what the mutation does, substring in GOOD_FIXTURE, replacement)
MUTATIONS = [
    ('W1',
     'an input is added to the contract and left out of the record',
     '      weakening_reason:\n        description: Why a control on this invocation is weaker than baseline.',
     '      advisory_mode:\n        description: Report everything, block nothing.\n'
     '        type: boolean\n        default: false\n'
     '      weakening_reason:\n        description: Why a control on this invocation is weaker than baseline.'),
    ('W2',
     'the record declares an input the contract does not have',
     '          posture python_version    NOT_A_CONTROL_SURFACE - -',
     '          posture python_version    NOT_A_CONTROL_SURFACE - -\n'
     '          posture license_deny      NOT_A_CONTROL_SURFACE - -'),
    ('W3',
     'a class is used that assurance-taxonomy.yaml does not register',
     'posture soft_fail_scan    GATE_SOFTENED    false deep-scan',
     'posture soft_fail_scan    GATE_RELAXED     false deep-scan'),
    ('W4',
     'a weakening input stops reaching the record through env:, so nothing compares it',
     '          W_SOFT_FAIL_SCAN: ${{ inputs.soft_fail_scan }}\n',
     ''),
    ('W5',
     'the unavailable row is dropped, so "could not be acquired" reads as "found nothing"',
     '          emit controls_unavailable "$UNAV"\n',
     ''),
    ('W6',
     'the EVIDENCE_UNTRUSTED branch is removed, collapsing five outcomes toward pass/fail',
     '          [ -n "$unav" ] && route=EVIDENCE_UNTRUSTED\n',
     ''),
    ('W7',
     'a gate-softening input is relabelled as governing no control',
     'posture soft_fail_scan    GATE_SOFTENED    false deep-scan "$W_SOFT_FAIL_SCAN"',
     'posture soft_fail_scan    NOT_A_CONTROL_SURFACE - -'),
]

# The shape the defect actually had: a contract full of weakening inputs and no record at all.
# Kept whole rather than as a mutation, because W0 is the absence of the entire mechanism.
NO_RECORD_FIXTURE = """\
# Fixture: the state this kit shipped in. Inputs that soften the gate, and nothing anywhere
# records that they did. It must FAIL on W0.
name: fixture unrecorded weakenings
on:
  workflow_call:
    inputs:
      soft_fail_sast:
        description: If true, SAST findings report (SARIF) but do not fail the build.
        type: boolean
        default: true
permissions:
  contents: read
jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - name: Scan
        run: echo "scanning"
"""


def codes(fails):
    return set(f.split()[0] for f in fails)


def self_test(classes, routes):
    """Both directions, and a differential."""
    if not os.path.isdir(FIXTURES):
        print('UNKNOWN: %s missing; cannot run the self-test.' % FIXTURES)
        return 2

    ok = True

    # A checker whose vocabulary source is empty would pass everything. Assert the registry
    # actually loaded before trusting a single clean result.
    for need in ('GATE_SOFTENED', 'CONTROL_DISABLED', INERT_CLASS, 'EXCEPTION_ATTRIBUTION'):
        if need not in classes:
            print('SELF-TEST FAILED: `%s` is not registered in assurance-taxonomy.yaml ::'
                  ' control_weakening, so W3 cannot distinguish a real class from a typo.' % need)
            ok = False
    if routes != ROUTING_OUTCOMES:
        print('SELF-TEST FAILED: routing_result registers %s; this checker expects %s.'
              % (sorted(routes), sorted(ROUTING_OUTCOMES)))
        ok = False
    if not ok:
        return 1

    good_path = os.path.join(FIXTURES, 'weakening_recorded.sample')
    write_if_changed(good_path, GOOD_FIXTURE)
    good_doc = load(good_path)
    good_fails = check_workflow(good_path, good_doc, classes, routes)
    if good_fails:
        print('SELF-TEST FAILED: the correct fixture was rejected:')
        for f in good_fails:
            print('  ' + f.split('\n')[0])
        ok = False

    # A correct fixture with no inputs would pass every rule vacuously. Assert it is in scope.
    gi = call_inputs(good_doc)
    if not gi:
        print('SELF-TEST FAILED: the correct fixture declares no workflow_call inputs, so it is')
        print('  out of scope and its clean result is vacuous.')
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
        path = os.path.join(FIXTURES, 'weakening_mutant_%s.sample' % code.lower())
        write_if_changed(path, mutant)
        try:
            doc = load(path)
        except Exception as e:
            print('SELF-TEST FAILED: the %s mutant is not valid YAML (%s), so a failure could be '
                  'a parse error rather than the rule.' % (code, e))
            ok = False
            continue
        got = codes(check_workflow(path, doc, classes, routes))
        if got != {code}:
            print('SELF-TEST FAILED: the %s mutant tripped %s, expected exactly {%s}.'
                  % (code, sorted(got) or '{}', code))
            print('  Mutation: %s' % what)
            print('  A mutant that trips MORE than its rule is evidence for the wrong rule; one')
            print('  that trips nothing means this rule cannot fire at all.')
            ok = False
            continue
        fired.append(code)

    none_path = os.path.join(FIXTURES, 'weakening_unrecorded.sample')
    write_if_changed(none_path, NO_RECORD_FIXTURE)
    got = codes(check_workflow(none_path, load(none_path), classes, routes))
    if got != {'W0'}:
        print('SELF-TEST FAILED: the no-record fixture tripped %s, expected exactly {W0}.'
              % (sorted(got) or '{}'))
        ok = False

    # INERT_ONLY: the listed form passes; an unlisted input trips W1; laundering trips W7.
    INERT_ONLY['__selftest_inert.yml'] = {'env_name': 'names an environment'}
    try:
        def wf(desc, extra=False):
            ins = {'env_name': {'description': desc, 'type': 'string'}}
            if extra:
                ins['other'] = {'description': 'x', 'type': 'string'}
            return {'on': {'workflow_call': {'inputs': ins}}, 'jobs': {'a': {'steps': [{'run': 'x'}]}}}
        fake = os.path.join(ROOT, '__selftest_inert.yml')
        if check_workflow(fake, wf('Names the environment.'), classes, routes):
            print('SELF-TEST FAILED: a correctly listed all-inert workflow was refused')
            ok = False
        if codes(check_workflow(fake, wf('Names the environment.', extra=True), classes, routes)) != {'W1'}:
            print('SELF-TEST FAILED: an unlisted input on an all-inert workflow was not refused (W1)')
            ok = False
        if codes(check_workflow(fake, wf('Report findings without failing the build.'), classes, routes)) != {'W7'}:
            print('SELF-TEST FAILED: a softening input listed as inert was not refused (W7)')
            ok = False
    finally:
        INERT_ONLY.pop('__selftest_inert.yml', None)

    if not ok:
        return 1

    print('self-test ok: one correct fixture passes and is in scope; %d single-substring mutants'
          % len(fired))
    print('              of that same fixture trip %s and nothing else; the' % ', '.join(fired))
    print('              "inputs that soften the gate and no record anywhere" fixture -- the')
    print('              state this kit actually shipped in -- trips W0.')
    print('              Each bad fixture differs from a PASSING shape by one substring, so a')
    print('              failure cannot be explained by anything but the rule under test.')
    return 0


# ─────────────────────────────────────────────────────────────────────────── main


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument('--check', action='store_true',
                    help='treat every declared exemption as a failure. Use once the last '
                         'unwired workflow is wired, and record the switch as a ratchet.')
    ap.add_argument('--today', default=None, help='override today (YYYY-MM-DD) for expiry tests')
    args = ap.parse_args(argv)

    today = (datetime.date.fromisoformat(args.today) if args.today
             else datetime.datetime.now(datetime.timezone.utc).date())

    classes = registered_classes()
    routes = registered_routing()

    st = self_test(classes, routes)
    if st:
        return st

    files = []
    for pat in WORKFLOW_GLOBS:
        files.extend(f for f in glob.glob(os.path.join(ROOT, pat)) if os.path.isfile(f))
    files = sorted(set(files))
    if not files:
        print('UNKNOWN: no workflows found. Nothing inspected is not nothing wrong.')
        return 2

    wired, exempt_rows, fails = [], [], []
    for path in files:
        base = os.path.basename(path)
        try:
            doc = load(path)
        except Exception as e:
            fails.append('UNREADABLE %s: %s' % (base, e))
            continue
        ins = call_inputs(doc)
        if ins is None or not ins:
            continue                      # no workflow_call contract, so no caller can weaken it
        if base in EXEMPT:
            exempt_rows.append((base, EXEMPT[base]))
            continue
        wired.append(base)
        fails.extend(check_workflow(path, doc, classes, routes))

    print('=== workflows whose callers can weaken a control ===')
    for b in wired:
        print('  RECORDED   %s' % b)
    for b, d in exempt_rows:
        print('  UNRECORDED %s  (exempt until %s)' % (b, d.get('expires')))

    # Exemptions are accounted for OUT LOUD, every run. A gap nobody can see is the defect.
    if exempt_rows:
        print('')
        print('-' * 78)
        print('UNRECORDED WEAKENING SURFACES — declared, dated, and not silently skipped')
        print('-' * 78)
        for b, d in exempt_rows:
            missing = [f for f in EXEMPT_FIELDS if not d.get(f)]
            if missing:
                fails.append('EXEMPTION %s: incomplete — missing %s. An exemption without an '
                             'owner, a closing condition or an expiry is an exemption nobody '
                             'can review.' % (b, ', '.join(missing)))
                continue
            try:
                exp = datetime.date.fromisoformat(str(d['expires']))
            except ValueError:
                fails.append('EXEMPTION %s: unparseable expires %r.' % (b, d['expires']))
                continue
            days = (exp - today).days
            print('  %s' % b)
            print('    unrecorded inputs : %s' % ', '.join(d['weakening_inputs_unrecorded']))
            print('    reason            : %s' % d['reason'])
            print('    owner             : %s' % d['owner'])
            print('    closes when       : %s' % d['closes'])
            print('    expires           : %s (%+d days)' % (exp, days))
            if args.check:
                fails.append('EXEMPTION %s: --check treats every exemption as a failure, and this '
                             'one is still open.' % b)
            elif days < 0:
                fails.append('EXEMPTION %s EXPIRED %s. Silence must never renew an exemption — '
                             'wire the record, or re-decide it with a named owner and a new '
                             'date.' % (b, exp))
        print('')
        print('  These are ACCOUNTED FOR, not cleared. Every input listed above can still be')
        print('  weakened without appearing in any record. A permanently red check is not a')
        print('  control, it is training — so the gap is dated instead, and the date is the')
        print('  mechanism.')

    print('')
    print('=' * 78)
    if fails:
        for f in fails:
            print('FAIL: ' + f)
        print('')
        print('A weakening input may not exist without appearing in the emitted record.')
        return 1

    print('PASS: %d workflow(s) record every one of their declared inputs, transport every'
          % len(wired))
    print('      control surface as data, emit all nine record rows, and can reach all five')
    print('      routing outcomes. %d surface(s) remain unrecorded under a dated exemption.'
          % len(exempt_rows))
    print('')
    print('      SHAPE ONLY. That a BASELINE is the right baseline, that a control name')
    print('      corresponds to a scanner that exists, and that the emitted values are true of')
    print('      a real run are all unproven here and need an execution to establish.')
    return 0


if __name__ == '__main__':
    sys.exit(main())

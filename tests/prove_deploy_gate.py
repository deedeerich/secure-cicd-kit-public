#!/usr/bin/env python3
"""A deploy reads the gate's VERDICT, and refuses before login unless the verdict permits it.

WHY THIS EXISTS (L93, brief N35; SINGLE_PIPELINE_TARGET.md section 5.2, section 6.2 row 1)

    Neither deploy reusable took any input that bears on whether the release was cleared to
    ship. A caller could wire `needs: [security]` and inherit only a job result -- a boolean
    wearing four labels, which cannot tell DECISION_REQUIRED from BLOCKED and cannot express
    PROCEED_WITH_ADVISORY at all -- or wire no gate whatsoever. The design is explicit: "The
    deploy stage reads the verdict, not needs.gate.result." A deploy that merely depends on a gate
    job inherits the reference estate's defect in reverse: "if it produced a contradiction,
    nothing would notice."

THE INPUT CONTRACT
    routing_result   REQUIRED, no default. One of the five registered routing_result values
                     (assurance-taxonomy.yaml). Produced by the gate stage of the calling run;
                     the flagship emits it from another lane, so this file tests stub values.

        PROCEED, PROCEED_WITH_ADVISORY   the deploy may proceed
        DECISION_REQUIRED                refused: a decision is owed and nobody has made it
        EVIDENCE_UNTRUSTED               refused at EVERY tier: "a consumer must not convert this
                                         into any successful state without new collection", and
                                         a mutation that proceeds IS that conversion
        BLOCKED                          refused: a control said no
        ''  or anything unregistered     refused: no verdict is not a permissive verdict, and a
                                         near-miss spelling ("proceed", "PASS") is worse than a
                                         wild one because it reads like the real thing

    The refusal happens BEFORE `azure/login`, so a refused deploy never holds the deploy identity.

THE FOUR CASES (docs/PROOF_RULE.md), each run through the step AS SHIPPED
    allowed           PROCEED and PROCEED_WITH_ADVISORY exit 0
    attack            BLOCKED, DECISION_REQUIRED and EVIDENCE_UNTRUSTED exit non-zero AND name
                      the verdict in the refusal -- a refusal for an unrelated reason is a
                      coincidence
    missing-evidence  '' and near-miss spellings exit non-zero with the no-verdict reason
    recovery          the same step, re-run with a permitting verdict after a refusal, proceeds
                      (the gate keeps no state that wedges the next run)
    plus structure:   the input is required with no default; the gate step precedes login and
                      every step that calls `az`; the starter template passes the verdict.

EXIT  0 proven   1 a case decided wrongly   2 could not be checked (UNKNOWN, never PASS)
"""
import io
import os
import re
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import _deploy_steps as D  # noqa: E402

GATE_STEP = 'Gate verdict (refuse before login)'
TEMPLATE = os.path.join(D.ROOT, 'templates', 'build-deploy.yml')

# (scenario, routing_result, must_proceed, a phrase the refusal must contain)
SCENARIOS = [
    ('allowed/proceed', 'PROCEED', True, None),
    ('allowed/advisory', 'PROCEED_WITH_ADVISORY', True, None),
    ('attack/blocked', 'BLOCKED', False, 'BLOCKED'),
    ('attack/decision-required', 'DECISION_REQUIRED', False, 'DECISION_REQUIRED'),
    ('attack/evidence-untrusted', 'EVIDENCE_UNTRUSTED', False, 'EVIDENCE_UNTRUSTED'),
    ('missing/empty', '', False, 'no gate verdict'),
    ('missing/near-miss-lowercase', 'proceed', False, "'proceed' is not a registered routing_result"),
    ('missing/near-miss-pass', 'PASS', False, "'PASS' is not a registered routing_result"),
    ('missing/injection-shaped', "PROCEED'; echo pwned; '", False, 'not a registered routing_result'),
    # A value whose FIRST LINE is a plain token: a per-line check (grep) passed it, and the second
    # line reached the log as a workflow command of its own (found by lane L-D, 2026-10-21).
    ('missing/multi-line-command', 'PASS\n::warning title=injected::x', False,
     'not a registered routing_result'),
    ('recovery/proceed-after-refusal', 'PROCEED', True, None),
]


def structure(doc, name):
    bad = []
    spec = D.inputs_of(doc).get('routing_result')
    if not isinstance(spec, dict):
        return ['%s: no `routing_result` input. The deploy cannot read a verdict it is never '
                'given.' % name]
    if spec.get('required') is not True:
        bad.append('%s: routing_result is not required. An optional verdict defaults to no '
                   'verdict, and the defaulted path is the one nobody looks at.' % name)
    if 'default' in spec:
        bad.append('%s: routing_result declares a default (%r). A defaulted verdict is a verdict '
                   'the gate never issued.' % (name, spec['default']))
    gi, gate = D.step_named(doc, GATE_STEP)
    if gate is None:
        bad.append('%s: no step named %r.' % (name, GATE_STEP))
        return bad
    for i, s in enumerate(D.steps(doc)):
        if i >= gi:
            break
        uses = str(s.get('uses', ''))
        # Heredoc BODIES are file content written to disk, not commands; only the shell around
        # them runs (the materialise step writes the inlined scripts and does nothing else).
        shell = re.sub(r"<<'(\w+)'\n.*?\n\1\n", '\n', str(s.get('run', '')), flags=re.S)
        if 'azure/login' in uses or re.search(r'(^|\s)az\s', shell):
            bad.append('%s: step %r touches Azure BEFORE the gate verdict is read.'
                       % (name, s.get('name') or uses))
    login = [i for i, s in enumerate(D.steps(doc)) if 'azure/login' in str(s.get('uses', ''))]
    if not login or login[0] < gi:
        bad.append('%s: the gate step does not precede azure/login.' % name)
    return bad


def template_passes_verdict():
    try:
        doc = D.load(TEMPLATE)
    except Exception as e:  # noqa: BLE001
        return ['template unreadable: %s' % e]
    bad = []
    dep = (doc.get('jobs') or {}).get('deploy') or {}
    w = dep.get('with') or {}
    rr = str(w.get('routing_result', ''))
    # P-01: the COMBINED release verdict (security, build, identity), computed by the template's
    # verdict job -- never one stage's verdict alone (tests/prove_deploy_template.py).
    if 'needs.verdict.outputs.deploy_routing_result' not in rr:
        bad.append('templates/build-deploy.yml: the deploy job does not pass the combined '
                   "verdict job's deploy_routing_result (got %r)." % rr)
    needs = dep.get('needs') or []
    needs = [needs] if isinstance(needs, str) else needs
    if 'verdict' not in needs:
        bad.append('templates/build-deploy.yml: the deploy job does not need `verdict`, so '
                   'the combined verdict output is unreadable there.')
    return bad


def main():
    try:
        import yaml  # noqa: F401
    except ImportError:
        print('UNKNOWN: PyYAML unavailable.')
        return 2
    bash, why = D.bash()
    if not bash:
        print('UNKNOWN: no usable bash (%s).' % why)
        return 2
    fails = []
    for wf in D.deploy_workflows:
        name = os.path.basename(wf)
        doc = D.load(wf)
        s_bad = structure(doc, name)
        fails.extend(s_bad)
        _, gate = D.step_named(doc, GATE_STEP)
        if gate is None:
            continue
        for scen, verdict, must, phrase in SCENARIOS:
            env = D.step_env(doc, gate, {'inputs.routing_result': verdict})
            rc, _out, log, _summ = D.run_script(bash, gate['run'], env)
            print('  %-34s %-34s exit=%d' % (name, scen, rc))
            if must and rc != 0:
                fails.append('%s %s: a permitting verdict was refused (exit %d). A gate that '
                             'refuses everything is a broken pipeline.\n%s' % (name, scen, rc, log[-400:]))
            if not must:
                if rc == 0:
                    fails.append('%s %s: verdict %r PROCEEDED.' % (name, scen, verdict))
                elif phrase and phrase not in log:
                    fails.append('%s %s: refused, but not for the stated reason (wanted %r in the '
                                 'log). A refusal for an unrelated reason is a coincidence.\n%s'
                                 % (name, scen, phrase, log[-400:]))
                if 'pwned' in log and 'echo pwned' not in log:
                    fails.append('%s %s: the verdict executed as shell.' % (name, scen))
                if any(l.startswith('::warning title=injected') for l in log.splitlines()):
                    fails.append('%s %s: the caller\'s verdict text reached the log as a workflow '
                                 'command.' % (name, scen))
    fails.extend(template_passes_verdict())
    if fails:
        for f in fails:
            print('FAIL: ' + f)
        return 1
    print('PASS: both deploy reusables require routing_result, read it before login, proceed only '
          'on PROCEED/PROCEED_WITH_ADVISORY and refuse every other value for the named reason.')
    print('      STUB VERDICTS. The values are the five the flagship emits (trunk 9b2ea0f); this '
          'proves the deploy side of the contract, not the producer.')
    return 0


if __name__ == '__main__':
    sys.exit(main())

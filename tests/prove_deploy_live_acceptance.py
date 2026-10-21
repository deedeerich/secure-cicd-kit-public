#!/usr/bin/env python3
"""The live acceptance harness can drive every owed live cell without touching Azure settings.

WHY THIS EXISTS (ledger DCR-3, DCR-9, DCR-MATRIX; the release-1 evidence manifest, "what is not
yet proven live")

    .github/workflows/live-deploy-acceptance.yml is how a live run reaches the deploy reusables on
    the sandbox. It never passed `version_metadata`, so the provenance stamp step never ran live
    (DCR-3: "provenance tags written live" is unproven), and it never exposed
    `rollback_on_failure`, so the one capability refusal that needs no Azure change -- reversal
    authority withheld at a production tier, refused before the first mutation (DCR-9) -- could not
    be dispatched. Both are inputs of the reusables; the harness simply did not carry them.

WHAT IS CHECKED (static, the harness file as shipped)
    - dispatch inputs version_metadata and rollback_on_failure exist and reach BOTH deploy jobs;
    - the deploy jobs grant attestations: read and pin the signer (V1 runs inside the deploy, P-02);
    - attestation_rung is carried;
    - nothing here schedules the harness or runs it on push (dispatch only).

EXIT 0 proven   1 a gap   2 could not be checked
"""
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import _step_harness as H  # noqa: E402

WF = '.github/workflows/live-deploy-acceptance.yml'


def main():
    try:
        import yaml  # noqa: F401
    except ImportError:
        print('UNKNOWN: PyYAML unavailable.')
        return 2
    doc = H.load(WF)
    on = doc.get('on', doc.get(True)) or {}
    bad = []
    if set(on) != {'workflow_dispatch'}:
        bad.append('the harness is triggered by %r; it must be dispatch-only' % sorted(on))
    ins = (on.get('workflow_dispatch') or {}).get('inputs') or {}
    for i in ('version_metadata', 'rollback_on_failure', 'attestation_rung'):
        if i not in ins:
            bad.append('no dispatch input %s' % i)
    for job in ('containerapp', 'appservice'):
        j = (doc.get('jobs') or {}).get(job) or {}
        w = j.get('with') or {}
        for i in ('version_metadata', 'rollback_on_failure', 'attestation_rung'):
            if 'inputs.%s' % i not in str(w.get(i, '')):
                bad.append('%s: %s is not passed to the reusable' % (job, i))
        if str((j.get('permissions') or {}).get('attestations')) != 'read':
            bad.append('%s: attestations: read is not granted (startup_failure)' % job)
        if 'reusable-build-docker.yml' not in str(w.get('attestation_signer_workflow', '')):
            bad.append('%s: the V1 signer is not pinned' % job)
    if bad:
        for b in bad:
            print('FAIL: %s' % b)
        return 1
    print('PASS: the live acceptance harness carries version_metadata (DCR-3 provenance live), '
          'rollback_on_failure (DCR-9 capability refusal at a production tier) and the V1 inputs to '
          'both deploy reusables, and stays dispatch-only.')
    return 0


if __name__ == '__main__':
    sys.exit(main())

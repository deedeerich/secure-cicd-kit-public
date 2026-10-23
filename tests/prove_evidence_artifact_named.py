#!/usr/bin/env python3
"""Prove the gate's `evidence_artifact` output names the artifact the report job actually uploads (H5).

The gate publishes `evidence_artifact` so a consumer can fetch the run's evidence. It emitted the
literal `security-sarif`; the report job uploads `security-report-${{ github.run_attempt }}`. Every
consumer that followed the pointer found nothing -- and an evidence pointer to nothing is a claim of
documentation that does not exist.

This resolves both sides with the same run_attempt, runs the gate as shipped, and compares.

EXIT  0 they match   1 they do not   2 could not be checked
"""
import io
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import prove_bootstrap_failure as pbf  # noqa: E402

ATTEMPT = '3'   # not 1, so a hard-coded "-1" cannot pass by coincidence


def _expand(doc):
    """The workflow with every `$/` composite step expanded into its job, as the runner sees it.

    Scanner job bodies live in `.github/actions/<scanner>/` (ledger L64); this reads the steps a
    job actually runs. One rule, tests/_composite_expand.py, for every reader.
    """
    sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
    import _composite_expand
    return _composite_expand.expanded_doc(doc)


def report_upload_name(doc):
    for s in doc['jobs']['report'].get('steps') or []:
        if 'upload-artifact' in str(s.get('uses') or ''):
            name = str((s.get('with') or {}).get('name') or '')
            body, _ = pbf.substitute(name, {'github.run_attempt': ATTEMPT})
            return body
    return None


def main():
    try:
        import yaml
    except ImportError:
        print('UNKNOWN: PyYAML unavailable.')
        return 2
    bash, why = pbf.usable_bash()
    if not bash:
        print('UNKNOWN: no usable bash (%s).' % why)
        return 2
    doc = _expand(yaml.safe_load(io.open(pbf.WF, encoding='utf-8')))
    uploaded = report_upload_name(doc)
    if not uploaded:
        print('UNKNOWN: the report job uploads no artifact.')
        return 2
    values = dict(pbf.ctx(), **{'github.run_attempt': ATTEMPT})
    body, _ = pbf.substitute(pbf.gate_script(), values)
    rc, emitted, _log, _summ = pbf.run(bash, body, pbf.gate_env(values))
    named = emitted.get('evidence_artifact')
    print('  report uploads        : %s' % uploaded)
    print('  gate evidence_artifact: %s' % named)
    if named != uploaded:
        print('FAIL: the gate points consumers at an artifact that does not exist.')
        return 1
    print('PASS: the evidence pointer names the artifact the report actually uploads.')
    return 0


if __name__ == '__main__':
    sys.exit(main())

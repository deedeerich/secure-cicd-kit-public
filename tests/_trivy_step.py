"""Read a shipped Trivy step back as the `with:` block trivy-action@v0.36.0 would have been given.

Not a test: the leading underscore keeps tests/prove_tests_leave_tree_clean.py from running it.

WHY (KDEC-027)
    The kit no longer uses aquasecurity/trivy-action: its setup-trivy checks out
    `aquasecurity/trivy` against github.server_url, which a GHE.com tenant does not have. Each Trivy
    step is now `run: trivy <type> --quiet "$SCAN_REF"` (or "$IMAGE_REF") with its configuration
    in TRIVY_* environment variables -- the very variables trivy-action exported for each `with:`
    key. The proofs that reproduce "Trivy as the step runs it" (prove_trivy_threshold,
    prove_image_scan_enforces, prove_nvd_trivy_detects, prove_deps_scan_composer, ...) read the
    step through `trivy_with()`, so their translation tables did not have to change.
"""
import re

RUN = re.compile(r'^\s*trivy\s+(fs|image|config|repo|rootfs|filesystem)\b', re.M)
ENV_TO_WITH = {'TRIVY_SCANNERS': 'scanners', 'TRIVY_SEVERITY': 'severity',
               'TRIVY_EXIT_CODE': 'exit-code', 'TRIVY_FORMAT': 'format', 'TRIVY_OUTPUT': 'output',
               'TRIVY_IGNORE_UNFIXED': 'ignore-unfixed', 'TRIVY_TIMEOUT': 'timeout'}


def is_trivy(step):
    """A step that runs a Trivy scan: the shipped `run:` form, or a legacy trivy-action `uses:`."""
    if not isinstance(step, dict):
        return False
    if 'trivy-action' in str(step.get('uses') or ''):
        return True
    return bool(RUN.search(str(step.get('run') or '')))


def trivy_with(step):
    """-> the `with:` dict trivy-action would have received for this step."""
    if 'trivy-action' in str(step.get('uses') or ''):
        return dict(step.get('with') or {})
    m = RUN.search(str(step.get('run') or ''))
    kind = m.group(1) if m else 'image'
    kind = 'fs' if kind == 'filesystem' else kind
    env = step.get('env') or {}
    w = {'scan-type': kind}
    if 'SCAN_REF' in env:
        w['scan-ref'] = env['SCAN_REF']
    if 'IMAGE_REF' in env:
        w['image-ref'] = env['IMAGE_REF']
    for k, v in env.items():
        if k in ENV_TO_WITH:
            w[ENV_TO_WITH[k]] = v
    return w


def output_of(step):
    return str(trivy_with(step).get('output') or '')

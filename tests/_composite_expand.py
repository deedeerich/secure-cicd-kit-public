"""Expand a job's `$/` composite steps back into the job, exactly as the runner would see them.

Not a test: the leading underscore keeps tests/prove_tests_leave_tree_clean.py from running it.

WHY THIS EXISTS (completion ledger L64, decomposition plan section 7 step 12)

    Scanner job bodies move out of reusable-security.yml into `.github/actions/<scanner>/` and are
    reached through `$/`. Every proof that RUNS a scanner's own steps (prove_secret_denominator,
    prove_secrets_always_block, prove_cppcheck_collects, ...) and every check that READS them
    (redaction parity, injection, validity-before-upload) was written against `jobs.<job>.steps`.
    Pointing each of them at a second file would be N hand-kept copies of one resolution rule.
    This module is that rule, once: a step `uses: $/.github/actions/<name>` is replaced by the
    composite's own steps, with every `${{ inputs.X }}` replaced by the expression the job passes
    in `with: X:`. The steps a proof then runs are the shipped composite's steps, as a runner
    evaluates them -- never a copy.

WHAT A COMPOSITE CHANGES, AND HOW EACH IS HELD HERE
    * inputs are STRINGS. `${{ inputs.X }}` as an interpolation renders the same text the job's
      expression renders, so it is substituted. A bare `inputs.X` INSIDE a larger expression
      (an `if:`, `a && b`) is only equivalent when the job passes X straight through as
      `${{ inputs.X }}` of a STRING workflow input; anything else is reported as a problem,
      because a boolean `false` arriving as the string 'false' is TRUE in an expression.
    * `needs`, `secrets`, `matrix` and `strategy` do not exist inside a composite: any reference
      is a problem (it would evaluate to empty on the runner, silently).
    * a composite `run:` step must name its shell. The job default it replaces is `bash -e {0}`
      (GitHub: unspecified shell on Linux), so `normalise_shell` maps an absent shell to that
      before two step lists are compared.
    * the composite call step itself must carry no `if:` -- status functions inside a composite
      see the composite's own steps, so a guard on the call would change which steps run.
"""
import copy
import io
import os
import re

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
PREFIX = '$/.github/actions/'
DEFAULT_SHELL = 'bash -e {0}'

_INTERP = re.compile(r'\$\{\{\s*inputs\.([A-Za-z0-9_-]+)\s*\}\}')
_BARE = re.compile(r'(?<![\w.-])inputs\.([A-Za-z0-9_-]+)')
_FORBIDDEN = re.compile(r'(?<![\w.-])(needs|secrets|matrix|strategy)\.[A-Za-z0-9_-]+')
_EXPR = re.compile(r'\$\{\{(.*?)\}\}', re.S)


def action_file(name, root=ROOT):
    base = os.path.join(root, '.github', 'actions', name)
    for f in ('action.yml', 'action.yaml'):
        p = os.path.join(base, f)
        if os.path.isfile(p):
            return p
    return None


def load_action(name, root=ROOT):
    import yaml
    p = action_file(name, root)
    if not p:
        return None
    return yaml.safe_load(io.open(p, encoding='utf-8'))


def composite_name(step):
    uses = (step or {}).get('uses') or ''
    return uses[len(PREFIX):] if uses.startswith(PREFIX) else None


def _workflow_input_types(doc):
    on = (doc or {}).get('on') or (doc or {}).get(True) or {}
    wc = (on.get('workflow_call') or {}) if isinstance(on, dict) else {}
    return {k: (v or {}).get('type', 'string') for k, v in (wc.get('inputs') or {}).items()}


def _subst(value, passed, identity_ok, where, problems):
    """Substitute interpolations; police bare references inside expressions."""
    if isinstance(value, dict):
        return {k: _subst(v, passed, identity_ok, where, problems) for k, v in value.items()}
    if isinstance(value, list):
        return [_subst(v, passed, identity_ok, where, problems) for v in value]
    if not isinstance(value, str):
        return value
    for m in _FORBIDDEN.finditer(value):
        problems.append('%s: `%s` -- that context does not exist inside a composite'
                        % (where, m.group(0)))
    # Bare references: everything an expression holds after removing whole-value interpolations.
    stripped = _INTERP.sub('', value)
    bare_scope = [stripped] if where.endswith('.if') else [e for e in _EXPR.findall(stripped)]
    for chunk in bare_scope:
        for m in _BARE.finditer(chunk):
            n = m.group(1)
            if n not in passed:
                problems.append('%s: inputs.%s is referenced but the job does not pass it'
                                % (where, n))
            elif n not in identity_ok:
                problems.append('%s: inputs.%s is used INSIDE an expression, and the job does not '
                                'pass it straight through from a string input -- a composite '
                                'input is a string, so equivalence is not established' % (where, n))

    def rep(m):
        n = m.group(1)
        if n not in passed:
            problems.append('%s: ${{ inputs.%s }} is referenced but the job does not pass it'
                            % (where, n))
            return m.group(0)
        return passed[n]
    return _INTERP.sub(rep, value)


def expand_step(step, doc=None, root=ROOT):
    """-> (list of steps the call stands for, [problem]). A non-composite step is returned as is."""
    name = composite_name(step)
    if not name:
        return [step], []
    problems = []
    act = load_action(name, root)
    if act is None:
        return [step], ['%s: no action.yml under .github/actions/%s' % (step.get('uses'), name)]
    runs = act.get('runs') or {}
    if runs.get('using') != 'composite':
        return [step], ['%s: not a composite action' % name]
    if 'if' in step:
        problems.append('%s: the call carries `if:` -- a guard on the call changes which of the '
                        'composite\'s steps run' % name)
    declared = act.get('inputs') or {}
    passed = {}
    for k, v in (step.get('with') or {}).items():
        if k not in declared:
            problems.append('%s: the job passes %r, which the composite does not declare'
                            % (name, k))
        passed[k] = v if isinstance(v, str) else ('true' if v is True else
                                                  'false' if v is False else str(v))
    for k, spec in declared.items():
        if k not in passed:
            if (spec or {}).get('default') is None:
                problems.append('%s: input %r has no default and the job does not pass it'
                                % (name, k))
            else:
                passed[k] = str((spec or {}).get('default'))
    types = _workflow_input_types(doc)
    identity_ok = set()
    for k, v in passed.items():
        m = re.fullmatch(r'\$\{\{\s*inputs\.([A-Za-z0-9_-]+)\s*\}\}', v or '')
        if m and m.group(1) == k and types.get(k, 'string') == 'string':
            identity_ok.add(k)
    out = []
    for i, cs in enumerate(runs.get('steps') or []):
        where = '%s step %d (%s)' % (name, i + 1, (cs or {}).get('name') or (cs or {}).get('uses'))
        ns = {}
        for key, val in (cs or {}).items():
            ns[key] = _subst(val, passed, identity_ok, '%s.%s' % (where, key), problems)
        out.append(ns)
    return out, problems


def scanner_composites(root=ROOT):
    """Composites that ARE a scanner job's body: scanner-registry.yaml rows of class scanner."""
    import yaml
    try:
        reg = yaml.safe_load(io.open(os.path.join(root, 'scanner-registry.yaml'), encoding='utf-8'))
    except (IOError, OSError):
        return set()
    return {(r or {}).get('composite') for r in ((reg or {}).get('jobs') or {}).values()
            if (r or {}).get('class') == 'scanner' and (r or {}).get('composite')}


_WHOLE = re.compile(r'\s*\$\{\{\s*(.*?)\s*\}\}\s*', re.S)


def output_map(step, act):
    """-> ({'steps.<id>.outputs.<name>': inner expression}, [problem]) for a scanner composite
    called with an id. Each composite output's `value:` must be ONE `${{ }}` over the composite's
    own steps: after expansion the job reads that expression where it read the call's output."""
    sid, out, problems = step.get('id'), {}, []
    for name, spec in ((act or {}).get('outputs') or {}).items():
        m = _WHOLE.fullmatch(str((spec or {}).get('value') or ''))
        if not m:
            problems.append('%s: output %r is not a single ${{ }} expression -- not expandable'
                            % (composite_name(step), name))
            continue
        out['steps.%s.outputs.%s' % (sid, name)] = m.group(1)
    return out, problems


def rewrite_reads(value, mapping):
    """Every read of a call's output (`steps.<id>.outputs.<name>`) replaced by the composite's own
    expression: verbatim when it is the whole interpolation, parenthesised inside a larger one."""
    if isinstance(value, dict):
        return {k: rewrite_reads(v, mapping) for k, v in value.items()}
    if isinstance(value, list):
        return [rewrite_reads(v, mapping) for v in value]
    if not isinstance(value, str) or not mapping:
        return value
    m = _WHOLE.fullmatch(value)
    if m and m.group(1) in mapping:
        return '${{ %s }}' % mapping[m.group(1)]

    def inner(em):
        e = em.group(1)
        for k, v in mapping.items():
            e = re.sub(r'(?<![\w.-])%s(?![\w-])' % re.escape(k), '(%s)' % v, e)
        return '${{%s}}' % e
    return _EXPR.sub(inner, value)


def expand_steps(steps, doc=None, root=ROOT, names=None, reads=None):
    """`names`: expand only these composites (None = every `$/` composite). `reads`: a dict that
    collects, for every SCANNER composite called with an id, its outputs as the expressions the
    job reads after expansion (expanded_job rewrites the job's own reads with it)."""
    out, problems = [], []
    scanners = None
    for st in steps or []:
        n = composite_name(st)
        if n and names is not None and n not in names:
            out.append(st)
            continue
        if n and st.get('id'):
            act = load_action(n, root) or {}
            if act.get('outputs'):
                if scanners is None:
                    scanners = scanner_composites(root)
                if n in scanners and reads is not None:
                    # A SCANNER BODY that hands the gate its findings_state (lane L-S, O-24): its
                    # steps are what proofs must run, so it is expanded and the job's reads of the
                    # call's outputs are rewritten to the composite's own expression for them.
                    m, p = output_map(st, act)
                    reads.update(m)
                    problems.extend(p)
                else:
                    # The job reads the call's outputs through `steps.<id>.outputs`; replacing the
                    # call by its steps would orphan those reads. Not expanded, and said so.
                    problems.append('%s: called with id %r and declares outputs -- not expanded'
                                    % (n, st.get('id')))
                    out.append(st)
                    continue
        got, p = expand_step(st, doc, root)
        out.extend(got)
        problems.extend(p)
    return out, problems


def expanded_job(doc, job_name, root=ROOT, names=None):
    """A deep copy of one job whose `$/` steps are replaced by the composite's steps."""
    job = copy.deepcopy(((doc or {}).get('jobs') or {}).get(job_name) or {})
    if job.get('steps'):
        reads = {}
        job['steps'], _p = expand_steps(job['steps'], doc, root, names, reads)
        if reads:
            for key in ('outputs',):
                if key in job:
                    job[key] = rewrite_reads(job[key], reads)
            job['steps'] = [rewrite_reads(s, reads) for s in job['steps']]
    return job


def expanded_doc(doc, root=ROOT, names=None):
    """A deep copy of a workflow with its jobs' `$/` composite steps expanded in place.

    A call that has an id AND reads composite outputs is left as the call (expanding it would
    orphan `steps.<id>.outputs`), which today is discover, resolve, the report and the ledger
    proposal -- none of them a scanner body. `names` narrows expansion to a set of composites.
    """
    d = copy.deepcopy(doc or {})
    for name in list((d.get('jobs') or {})):
        d['jobs'][name] = expanded_job(doc, name, root, names)
    return d


def shipped_text(path, root=ROOT):
    """A workflow's TEXT followed by the text of every scanner composite it calls through `$/`.

    For the checks that read a scanner's commands as text (`semgrep scan ... --strict`, a
    `find -maxdepth` enumeration, a pinned `pip install`): after ledger L64 those lines live in
    the composite, and a check reading only the workflow would count fewer sites and still pass.
    Line numbers past the workflow's own end belong to the appended composites.
    """
    text = io.open(path, encoding='utf-8').read()
    names = scanner_composites(root)
    seen = []
    for m in re.finditer(r'uses:[ ]*\$/\.github/actions/([\w-]+)', text):
        n = m.group(1)
        if n in names and n not in seen:
            seen.append(n)
    for n in seen:
        p = action_file(n, root)
        if p:
            text += '\n' + io.open(p, encoding='utf-8').read()
    return text


def normalise_shell(step):
    """A `run:` step with no shell runs under the job default, `bash -e {0}`."""
    s = dict(step)
    if 'run' in s and not s.get('shell'):
        s['shell'] = DEFAULT_SHELL
    return s

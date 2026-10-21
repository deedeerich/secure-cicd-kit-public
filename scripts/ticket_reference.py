#!/usr/bin/env python3
"""Ticket-reference mechanism, lifted out of one consumer's overlay into the neutral core.

WHY THIS FILE EXISTS

    A consumer overlay's `workflows/validate-jira-reference.yml` carried a working
    reference-format validator inside a bash `run:` block. The MECHANISM there is not
    consumer-specific -- "find a work-item reference in a body of text, parse its key, and check it
    against an id-format policy" is a generic capability. Three things in that file were the
    consumer's: the `/browse/` URL shape (Jira's), the digit range 3-4 (their ticket numbering),
    and the `vars.JIRA_*` wiring (their site and project).

    The overlay said so itself, in a comment, and named the condition of extraction:

        "The generic capability -- enforce SOME id format, range supplied by configuration -- is
        neutral, and when it is extracted it MUST ship with enforcement OFF and no default range.
        A neutral kit that defaults to one employer's numbers has quietly adopted their policy."

    So that is the contract this module honours: `enforce` defaults to False, and `min_digits` and
    `max_digits` have NO defaults. A caller who wants a range states it.

WHAT MOVED, AND WHAT DID NOT

    MOVED HERE (neutral):   the literal-escaper, the reference pattern builder, candidate discovery
                            with a reported truncation cap, key/number parsing, and the
                            first-valid-wins selection with a rejection ledger.
    STAYED IN THE OVERLAY:  the `/browse/` path segment as a Jira adapter value, the 3/4 digit
                            defaults, the `vars.JIRA_*` wiring, the job id, and every occurrence of
                            the consumer's name.

    The overlay's bash validator is deliberately NOT rewired to call this module. Its meta-test
    (the overlay's `tests/run_jira_step.py`) extracts the step's `run:` text and executes it
    in a temp directory with no `cwd`, so a relative `python3 scripts/...` path would not resolve,
    and it asserts seven literal needles including the vendor noun. Rewiring it is a separate
    change with its own test migration; claiming it here would be claiming a move that did not
    happen. See the report accompanying this commit.

THE DISTINCTION THIS MODULE REFUSES TO COLLAPSE

    A reference being well-formed is not the ticket existing, and neither is the ticket being the
    right one. The overlay stated that boundary in words and this module keeps it: every function
    here answers a question about TEXT. Nothing here contacts a tracker, and nothing here may be
    read as evidence that a ticket exists. `reconcile_tickets.py` owns that, against a backend.

USAGE
    python3 scripts/ticket_reference.py --self-test
"""
import re
import sys

# The four outcomes of looking for a reference in a body of text. They are NOT one boolean: "the
# field was never configured" and "the field was configured and held nothing" are the first two of
# the four states this kit refuses to collapse, and a caller that cannot tell them apart will
# report an unconfigured gate as a clean one.
NOT_CONFIGURED = 'reference policy not configured'
NO_TEXT = 'no text supplied to search'
NO_CANDIDATE = 'no reference-shaped candidate in the text'
NO_CANDIDATE_PASSED = 'candidates found, none satisfied the id-format policy'
REFERENCE_FOUND = 'a candidate satisfied the policy'

# How many candidates are examined. The overlay capped at 50 via `head -50`; the cap is kept and,
# unlike a bare `head`, the fact that it truncated is RETURNED rather than discarded. A cap that
# silently drops the one valid reference in a long PR body would read as "no reference supplied".
CANDIDATE_CAP = 50


def escape_literal(s):
    """Escape `s` for use as a literal inside a regular expression.

    The overlay did this with a sed character class because it was building a `grep -oE` pattern
    from two values it did not control. In Python `re.escape` is the same guarantee, and the named
    wrapper is kept so the call site still says WHY the escape is there: a project key or host
    containing a regex metacharacter must match itself, not act as syntax.
    """
    return re.escape(s or '')


def build_reference_pattern(project, url_template=None):
    """-> a compiled pattern matching `<project>-<digits>`, optionally inside a URL shape.

    `url_template` carries the tracker-specific part and is supplied BY THE CALLER, not defaulted.
    Jira's browse URL is `https://<host>/browse/<KEY>-<n>`; GitHub's is
    `https://github.com/<owner>/<repo>/issues/<n>`. Baking either one in here would make the
    neutral core a Jira module wearing a general name.

    Pass the template with `{project}` where the key goes. With no template, the bare
    `<project>-<digits>` form is matched, which is what a commit message or a branch name carries.
    """
    proj_re = escape_literal(project)
    if url_template:
        # The template is a LITERAL except for the one placeholder. Escaping it and then restoring
        # the placeholder is what stops a host containing a dot from matching any character.
        body = escape_literal(url_template).replace(escape_literal('{project}'), proj_re)
        return re.compile(body + r'-([0-9]+)')
    return re.compile(r'\b' + proj_re + r'-([0-9]+)\b')


def find_candidates(text, pattern, cap=CANDIDATE_CAP):
    """-> (candidates, total_seen, truncated).

    `truncated` is returned rather than swallowed. The overlay's `head -50` could not say whether
    it had dropped anything, so a body with 60 references and the valid one at position 55 was
    indistinguishable from a body with none.
    """
    if not text:
        return [], 0, False
    found = [m.group(0) for m in pattern.finditer(text)]
    total = len(found)
    return found[:cap], total, total > cap


def parse_key(candidate, project):
    """-> (key, number) from one candidate, or (None, None) if it does not parse.

    The overlay used `${cand##*/}` then `${cand_id#${proj}-}`, which is a URL assumption. This
    reads the key out of the candidate structurally instead, so it works for a bare key as well as
    a URL.
    """
    if not candidate:
        return None, None
    tail = candidate.rsplit('/', 1)[-1]
    m = re.search(r'(' + escape_literal(project) + r')-([0-9]+)$', tail)
    if not m:
        return None, None
    return '%s-%s' % (m.group(1), m.group(2)), m.group(2)


def select_valid(candidates, project, enforce=False, min_digits=None, max_digits=None):
    """First candidate satisfying the id-format policy wins. -> (chosen_key, rejected).

    ENFORCEMENT IS OFF BY DEFAULT AND THE RANGE HAS NO DEFAULT. That is the condition the overlay
    attached to this code being extracted, and it is load-bearing rather than tidiness: a neutral
    kit shipping 3-4 digits would impose one employer's ticket numbering on every other consumer,
    and the imposition would be invisible because it would look like a sensible default.

    `rejected` is a ledger, not a count. A reference rejected for being the wrong length is a
    different event from no reference at all, and the caller is told which candidates lost and why.
    """
    rejected = []
    if enforce and (min_digits is None or max_digits is None):
        # A policy that says "enforce" without saying what to enforce is not a policy. Refusing is
        # the only answer that cannot be mistaken for a pass: picking a range here would be this
        # module inventing the consumer's numbering, which is the exact thing it exists not to do.
        raise ValueError('enforce=True requires both min_digits and max_digits; a range this '
                         'module chose for you would be a policy nobody registered')
    for cand in candidates:
        key, num = parse_key(cand, project)
        if key is None:
            rejected.append((cand, 'does not parse as %s-<digits>' % project))
            continue
        if enforce and not (min_digits <= len(num) <= max_digits):
            rejected.append((key, '%d digits, policy requires %d-%d'
                             % (len(num), min_digits, max_digits)))
            continue
        return key, rejected
    return None, rejected


def examine(text, project, url_template=None, enforce=False,
            min_digits=None, max_digits=None, cap=CANDIDATE_CAP):
    """The whole mechanism in one call. -> dict.

    `outcome` is one of the five module constants above. It is a STATE, never a boolean, because
    the caller has to be able to report "nothing was checked" differently from "checked and found
    nothing" -- and the overlay's exit code could not, which is recorded in its own comments as a
    known limitation.
    """
    if not project:
        return {'outcome': NOT_CONFIGURED, 'key': None, 'candidates': 0,
                'truncated': False, 'rejected': [],
                'detail': 'no project key supplied, so no reference shape is defined'}
    if not text:
        return {'outcome': NO_TEXT, 'key': None, 'candidates': 0,
                'truncated': False, 'rejected': [],
                'detail': 'nothing was searched'}

    pattern = build_reference_pattern(project, url_template)
    cands, total, truncated = find_candidates(text, pattern, cap)
    if not cands:
        return {'outcome': NO_CANDIDATE, 'key': None, 'candidates': 0,
                'truncated': truncated, 'rejected': [],
                'detail': 'no %s-<digits> reference in the text' % project}

    key, rejected = select_valid(cands, project, enforce, min_digits, max_digits)
    if key is None:
        return {'outcome': NO_CANDIDATE_PASSED, 'key': None, 'candidates': total,
                'truncated': truncated, 'rejected': rejected,
                'detail': '%d candidate(s), none satisfied the id-format policy' % total}
    return {'outcome': REFERENCE_FOUND, 'key': key, 'candidates': total,
            'truncated': truncated, 'rejected': rejected,
            'detail': 'selected %s' % key}


def _selftest():
    """Each assertion is a behaviour the overlay had and the extraction must not have lost."""
    fails = []

    # 1. THE POSITIVE CASE FIRST. Everything below asserts that something is refused, and a module
    #    that refused everything would satisfy all of them while being useless. This is what makes
    #    the refusals mean something.
    r = examine('fixes https://t.example.net/browse/WORK-1234 thanks', 'WORK',
                url_template='https://t.example.net/browse/{project}')
    if r['outcome'] != REFERENCE_FOUND or r['key'] != 'WORK-1234':
        fails.append('a well-formed reference in a URL was not found: %r' % r)

    # 1b. And the bare-key form, with no URL at all.
    r = examine('WORK-77 in the commit subject', 'WORK')
    if r['key'] != 'WORK-77':
        fails.append('a bare key reference was not found: %r' % r)

    # 2. ENFORCEMENT IS OFF BY DEFAULT. A 2-digit key passes when nobody asked for a range. This is
    #    the extraction condition the overlay attached, asserted rather than trusted.
    r = examine('WORK-12 here', 'WORK')
    if r['key'] != 'WORK-12':
        fails.append('default enforcement rejected a short key -- the neutral core has adopted a '
                     'digit policy nobody configured: %r' % r)

    # 3. WITH a range, the range is applied, and the rejection is recorded rather than counted.
    r = examine('WORK-12 and WORK-1234', 'WORK', enforce=True, min_digits=3, max_digits=4)
    if r['key'] != 'WORK-1234':
        fails.append('first-valid-wins did not skip the out-of-range candidate: %r' % r)
    if not any('2 digits' in why for _k, why in r['rejected']):
        fails.append('the rejected candidate was not recorded with its reason: %r' % r)

    # 4. enforce with no range REFUSES. A module that silently picked a range would be imposing a
    #    policy, which is the failure this file was extracted to prevent.
    try:
        select_valid(['WORK-1'], 'WORK', enforce=True)
        fails.append('enforce=True with no range did not refuse -- a default range would be one '
                     'consumer\'s numbering imposed on every other')
    except ValueError:
        pass

    # 5. THE FOUR STATES STAY APART. Not configured, nothing searched, nothing found, and found but
    #    rejected are four different facts, and collapsing any pair of them is how an unconfigured
    #    gate reports as a clean one.
    seen = {}
    for text, proj, label in ((None, 'WORK', 'no text'), ('body', '', 'no project'),
                              ('nothing here', 'WORK', 'no candidate')):
        seen[label] = examine(text, proj)['outcome']
    r = examine('WORK-1', 'WORK', enforce=True, min_digits=3, max_digits=4)
    seen['rejected'] = r['outcome']
    if len(set(seen.values())) != 4:
        fails.append('four distinct states collapsed into %d: %r' % (len(set(seen.values())), seen))
    if seen['no project'] != NOT_CONFIGURED:
        fails.append('an unconfigured policy did not report NOT_CONFIGURED: %r' % seen)

    # 6. A regex metacharacter in the project key matches itself. The overlay escaped both values
    #    it interpolated; losing that in translation would turn `A.B` into a wildcard.
    r = examine('AxB-123', 'A.B')
    if r['key'] is not None:
        fails.append('an unescaped metacharacter in the project key matched a different key: %r' % r)

    # 7. TRUNCATION IS REPORTED. The overlay's `head -50` could not say it had dropped anything.
    many = ' '.join('WORK-%d' % i for i in range(1, 60))
    r = examine(many, 'WORK', cap=50)
    if not r['truncated'] or r['candidates'] != 59:
        fails.append('a truncated candidate list did not report the truncation: %r' % r)

    for i, f in enumerate(fails, 1):
        print('  %d. %s' % (i, f))
    if fails:
        print('SELF-TEST FAILED: %d' % len(fails))
        return 2
    print('self-test ok: a well-formed reference is found in both URL and bare-key form;')
    print('              enforcement is OFF by default and a range has no default;')
    print('              enforce with no range refuses rather than inventing one;')
    print('              not-configured, nothing-searched, nothing-found and found-but-rejected')
    print('              stay four states; metacharacters are escaped; truncation is reported')
    return 0


def main(argv):
    if len(argv) == 2 and argv[1] in ('--self-test', '--selftest'):
        return _selftest()
    print('usage: ticket_reference.py --self-test', file=sys.stderr)
    print('', file=sys.stderr)
    print('This module is a library. It answers questions about TEXT and never contacts a',
          file=sys.stderr)
    print('tracker -- scripts/reconcile_tickets.py owns that.', file=sys.stderr)
    return 2


if __name__ == '__main__':
    sys.exit(main(sys.argv))

#!/usr/bin/env python3
"""SAST and secret findings are KEYED and TICKETED: bandit, semgrep, CodeQL and the secret scan. NO NETWORK.

FOUND HOSTED (Release 4 end-to-end, public runs 41945270732 and 41946786208, 2026-11-04)
    Every SAST finding was UNFINGERPRINTABLE, so nothing was ticketed: bandit had no rule family (its
    B-codes are not namespaced), semgrep and CodeQL had no symbol (neither emits logicalLocations), and
    under both lay KNOWN_DEFECTS D-8: the redactor strips the SARIF snippet before the report reads it,
    so CONTENT could not be derived either. Secret findings were withheld from tickets altogether: the
    baseline refuses them by design, and the ticket path had no other key.

THE OWNER (2026-11-06): "close the gap for bandit, semgrep and codeql, basically SAST and secrets tickets."

WHAT IT PROVES (scripts/code_finding_key.py; scan_report, finding_identity, finding_correlation,
reconcile_tickets, ticket_routing, ticket_templates)
  POSITIVE
    S1  a bandit B602 and a semgrep subprocess-shell-true finding on the SAME line are ONE identity and
        ONE ticket cluster naming both scanners; the rule family is the curated alias table's
        (os-command-injection, CWE-78), and corroboration RAISES the confidence (score and label).
    S2  CodeQL is keyed: py/command-line-injection on that line joins the same cluster (three scanners);
        a js/sql-injection finding in a JavaScript file is keyed with a file-scope anchor.
    S3  a line shift (lines inserted above the function and inside it) keeps every identity.
    S4  a secret finding (gitleaks, redacted) is a ticket cluster: keyed on detector family + path +
        a non-reversible fingerprint computed BEFORE redaction; class `secret`, severity critical, urgent
        (Jira priority at the top of the ladder, an `-urgent` label), and the body instructs ROTATION,
        not just removal. A history-mode finding is fingerprinted from the commit it was found in, not
        from whatever the working tree holds at that line. A secret ticket never closes on absence.
    S5  the ticket template path: an external semgrep finding gains the rule family and CWE; an external
        secret finding is class `secret` with the rotation instruction.
    S6  ticket routing reads the keys: a rule matching rule_family sql-injection (or cwe CWE-89) routes the
        SQL cluster to its project and nothing else; a secret cluster is never routed to "none".
  NEGATIVE
    N1  two different issues never merge: another family in the same function, the same family on
        another line, the same statement twice in one function, and the same code in another repository.
    N2  the secret value never appears anywhere: findings, clusters, ticket title and body, the Jira
        create payload, the annotated and redacted SARIF; and the fingerprint is not a plain hash of it.
    N3  an unknown rule refuses with a named reason (RULE_FAMILY_UNKNOWN, the tool and the rule named),
        never a bare rule id; a path outside the checkout refuses SOURCE_PATH_REFUSED.
  MUTANTS (each must make a check above fail, or the check proves nothing)
    M1  no ordinal in the code anchor            -> N1 (the same statement twice) merges
    M2  the anchor keyed on the line NUMBER      -> S3 breaks
    M3  the fingerprint a plain sha256           -> N2's oracle check catches it
    M4  bandit B602 aliased to another family    -> S1 is no longer one cluster
    M5  an unknown rule falls back to its id     -> N3 catches it
    M6  secret urgency removed                   -> S4 catches it
    M7  routing ignores rule_family              -> S6 catches it

EXIT  0 proven   1 a case failed (named)   2 could not be checked
"""
import copy
import hashlib
import io
import json
import os
import shutil
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, os.path.join(ROOT, 'scripts'))

FAILS = []
REPO = 'example-org/orders-api'
# A fixture credential, assembled at run time so this file never holds it whole.
SECRET = 'AKIA' + 'Q7XW3' + 'PLMZ2' + 'RT9VB'          # 19 chars: AKIA + 15
SECRET = SECRET + 'K'                                   # an AWS-shaped id, 20 chars


def check(cond, msg):
    print('  %s %s' % ('ok  ' if cond else 'FAIL', msg))
    if not cond:
        FAILS.append(msg)
    return bool(cond)


APP_PY = '''import subprocess


def handler(cmd):
    print("start")
    subprocess.run(cmd, shell=True)
    return 1


def other(cmd, user):
    query = "SELECT * FROM t WHERE u = '%s'" % user
    subprocess.run(cmd, shell=True)
    subprocess.run(cmd, shell=True)
    return query
'''
DB_JS = '''const db = require("db");
function find(req) {
  return db.query("SELECT * FROM t WHERE id = " + req.query.id);
}
'''
SETTINGS_PY = 'import os\n\naws_key_id = "%s"\nregion = "us-east-1"\n' % SECRET


def write(root, rel, text):
    p = os.path.join(root, *rel.split('/'))
    if not os.path.isdir(os.path.dirname(p)):
        os.makedirs(os.path.dirname(p))
    with io.open(p, 'w', encoding='utf-8', newline='\n') as fh:
        fh.write(text)


def line_of(text, needle, nth=1):
    n = 0
    for i, ln in enumerate(text.split('\n'), 1):
        if needle in ln:
            n += 1
            if n == nth:
                return i
    raise AssertionError('fixture: %r not found' % needle)


def result(rid, uri, line, msg='finding', col=None, endcol=None, props=None, pf=None):
    region = {'startLine': line, 'endLine': line}
    if col:
        region['startColumn'] = col
    if endcol:
        region['endColumn'] = endcol
    r = {'ruleId': rid, 'level': 'error', 'message': {'text': msg},
         'locations': [{'physicalLocation': {'artifactLocation': {'uri': uri}, 'region': region}}]}
    if props:
        r['properties'] = props
    if pf:
        r['partialFingerprints'] = pf
    return r


def sarif(tool, version, rules, results):
    return {'version': '2.1.0', 'runs': [{'tool': {'driver': {'name': tool, 'version': version, 'rules': rules}},
                                           'results': results}]}


def bandit_doc(results, rid='B602', cwe='78'):
    rules = [{'id': rid, 'name': 'subprocess_popen_with_shell_equals_true',
              'properties': {'tags': ['security', 'external/cwe/cwe-%s' % cwe], 'precision': 'high'}}]
    return sarif('Bandit', '1.7.10', rules, results)


SEMGREP_SHELL = 'python.lang.security.audit.subprocess-shell-true.subprocess-shell-true'


def semgrep_doc(results, rid=SEMGREP_SHELL, cwe='CWE-78: Improper Neutralization of Special Elements used in an OS Command'):
    rules = [{'id': rid, 'name': rid, 'properties': {'tags': [cwe, 'security']}}]
    return sarif('Semgrep OSS', '1.92.0', rules, results)


def codeql_doc(results, rid='py/command-line-injection', tags=('security', 'external/cwe/cwe-078', 'external/cwe/cwe-088')):
    rules = [{'id': rid, 'name': rid, 'properties': {'tags': list(tags), 'security-severity': '9.8'}}]
    return sarif('CodeQL', '2.19.3', rules, results)


def gitleaks_doc(results):
    rules = [{'id': 'aws-access-token', 'name': 'AWS Access Token', 'shortDescription': {'text': 'AWS'}}]
    return sarif('gitleaks', '8.21.2', rules, results)


def parse(doc, scanner, root, repository=REPO):
    import scan_report as sr
    d = tempfile.mkdtemp(prefix='sast-')
    try:
        p = os.path.join(d, '%s.sarif' % scanner)
        with io.open(p, 'w', encoding='utf-8') as fh:
            fh.write(json.dumps(doc))
        found, _st, _ex = sr.parse_sarif(p, scanner, source_root=root, repository=repository)
    finally:
        shutil.rmtree(d, ignore_errors=True)
    return found


def as_records(found, job):
    """What findings.json carries (scan_report.observation_of), so the reconciler reads a real report."""
    import scan_report as sr
    return [sr.observation_of(f, job, True) for f in found]


def clusters_of(records):
    import reconcile_tickets as rt
    cl, withheld = rt.build_clusters(records)
    return cl, withheld


def scenario(root):
    """-> dict of everything the checks read."""
    app = APP_PY
    h = line_of(app, 'subprocess.run', 1)
    o1 = line_of(app, 'subprocess.run', 2)
    o2 = line_of(app, 'subprocess.run', 3)
    q = line_of(app, 'SELECT')
    b = parse(bandit_doc([result('B602', 'app/run.py', h), result('B602', 'app/run.py', o1),
                          result('B602', 'app/run.py', o2)]), 'bandit', root)
    b_sql = parse(bandit_doc([result('B608', 'app/run.py', q)], rid='B608', cwe='89'), 'bandit', root)
    s = parse(semgrep_doc([result(SEMGREP_SHELL, 'app/run.py', h)]), 'semgrep', root)
    c = parse(codeql_doc([result('py/command-line-injection', 'app/run.py', h, col=20)]), 'codeql', root)
    cjs = parse(codeql_doc([result('js/sql-injection', 'web/db.js', line_of(DB_JS, 'db.query'))],
                           rid='js/sql-injection', tags=('security', 'external/cwe/cwe-089')), 'codeql', root)
    return dict(bandit=b, bandit_sql=b_sql, semgrep=s, codeql=c, codeql_js=cjs)


def main():
    try:
        import scan_report as sr  # noqa: F401
        import code_finding_key as cfk
        import reconcile_tickets as rt
        import finding_correlation as fc
        import ticket_model as tm
        import redact_sarif as rs
        import ticket_templates as tt
    except Exception as exc:  # noqa: BLE001
        print('UNKNOWN: a module could not be imported: %s: %s' % (type(exc).__name__, exc))
        return 1 if 'code_finding_key' in str(exc) or 'source_root' in str(exc) else 2
    git = shutil.which('git')
    work = tempfile.mkdtemp(prefix='kit-sast-')
    try:
        root = os.path.join(work, 'repo')
        write(root, 'app/run.py', APP_PY)
        write(root, 'web/db.js', DB_JS)
        write(root, 'config/settings.py', SETTINGS_PY)
        try:
            return run_all(root, work, git, sr_mod(), cfk, rt, fc, tm, rs, tt)
        except TypeError as exc:
            # parse_sarif without source_root/repository: the feature is not built yet (red).
            check(False, 'the reporter takes no source root / repository (%s): SAST findings cannot be keyed' % exc)
            return 1
    finally:
        shutil.rmtree(work, ignore_errors=True)


def sr_mod():
    import scan_report as sr
    return sr


def run_all(root, work, git, sr, cfk, rt, fc, tm, rs, tt):
    sc = scenario(root)
    b, s, c, cjs = sc['bandit'], sc['semgrep'], sc['codeql'], sc['codeql_js']
    # ── S1 ───────────────────────────────────────────────────────────────────────────────
    print('S1 bandit + semgrep on the same code are one identity and one ticket')
    check(all(f.get('identity_state') == 'FINGERPRINTED' for f in b + s),
          'S1 every bandit and semgrep finding is FINGERPRINTED (%s)' % [
              (f.get('identity_state'), f.get('identity_reason'), (f.get('identity_detail') or '')[:90]) for f in b + s
              if f.get('identity_state') != 'FINGERPRINTED'])
    check(b and s and b[0].get('identity') == s[0].get('identity') and b[0].get('identity'),
          'S1 bandit B602 and semgrep subprocess-shell-true on one line: ONE identity')
    check(b and b[0].get('rule_family') == 'os-command-injection' and b[0].get('cwe') == 'CWE-78',
          'S1 the family is the curated one (%s, %s)' % (b and b[0].get('rule_family'), b and b[0].get('cwe')))
    recs = as_records(b + s + c + sc['bandit_sql'] + cjs, 'sast')
    cl, withheld = clusters_of(recs)
    one = [x for x in cl if set(x['scanners']) >= {'bandit', 'semgrep'}]
    check(len(one) == 1 and len(one[0]['members']) >= 2, 'S1 one cluster carries both scanners (%d)' % len(one))
    if one:
        lone = [x for x in cl if x['scanners'] == ['bandit'] and x is not one[0]]
        idx_one = list(range(len(one[0]['members'])))
        sc_two, _b2 = fc.corroboration_score({'tier': 'anchored', 'members': idx_one, 'anchor': one[0]['anchor'],
                                               'identity_established': True}, one[0]['members'])
        sc_one, _b1 = fc.corroboration_score({'tier': 'singleton', 'members': [0], 'anchor': lone[0]['anchor'] if lone else '',
                                               'identity_established': True}, lone[0]['members'] if lone else [{}])
        check(sc_two is not None and sc_one is not None and sc_two > sc_one,
              'S1 corroboration raises the confidence score (%s > %s)' % (sc_two, sc_one))
        lab2, _ = tm.derive_confidence(one[0]['scanners'], True)
        lab1, _ = tm.derive_confidence(['bandit'], True)
        check(lab2 == tm.CORROBORATED_ANCHORED and lab1 == tm.SINGLE_SOURCE_ANCHORED,
              'S1 and the confidence label: %s (two tools) over %s (one)' % (lab2, lab1))
        body = rt.render_body(dict(one[0], tier=one[0]['tier']))
        check('os-command-injection' in body and 'CWE-78' in body and 'code location' in body,
              'S1 the ticket body names the rule family, the CWE and the code location')
    check(not [w for w in withheld if (w[0].get('scanner') in ('bandit', 'semgrep', 'codeql'))],
          'S1 no SAST finding is withheld (%s)' % [(w[0].get('scanner'), w[2][:60]) for w in withheld][:3])

    # ── S2 ───────────────────────────────────────────────────────────────────────────────
    print('S2 CodeQL is keyed')
    check(c and c[0].get('identity_state') == 'FINGERPRINTED' and c[0].get('identity') == b[0].get('identity'),
          'S2 CodeQL py/command-line-injection on that line joins the same identity (%s %s)'
          % (c and c[0].get('identity_state'), c and (c[0].get('identity_detail') or '')[:100]))
    check(one and 'codeql' in one[0]['scanners'], 'S2 the cluster names three scanners (%s)' % (one and one[0]['scanners']))
    check(cjs and cjs[0].get('identity_state') == 'FINGERPRINTED' and cjs[0].get('rule_family') == 'sql-injection'
          and 'file scope' in (cjs[0].get('locus_basis') or ''),
          'S2 a JavaScript CodeQL finding is keyed with a file-scope anchor (%s)' % (cjs and (cjs[0].get('locus_basis') or '')[-120:]))

    # ── S3 ───────────────────────────────────────────────────────────────────────────────
    print('S3 a line shift keeps the identity')
    shifted_root = os.path.join(work, 'shifted')
    shifted = '# a header\n# another\nimport os\n\n\n' + APP_PY.replace('    print("start")\n', '    print("start")\n\n    x = 1\n')
    write(shifted_root, 'app/run.py', shifted)
    write(shifted_root, 'web/db.js', '\n\n' + DB_JS)
    hs = line_of(shifted, 'subprocess.run', 1)
    b2 = parse(bandit_doc([result('B602', 'app/run.py', hs), result('B602', 'app/run.py', line_of(shifted, 'subprocess.run', 2)),
                           result('B602', 'app/run.py', line_of(shifted, 'subprocess.run', 3))]), 'bandit', shifted_root)
    s2 = parse(semgrep_doc([result(SEMGREP_SHELL, 'app/run.py', hs)]), 'semgrep', shifted_root)
    c2 = parse(codeql_doc([result('py/command-line-injection', 'app/run.py', hs, col=20)]), 'codeql', shifted_root)
    cjs2 = parse(codeql_doc([result('js/sql-injection', 'web/db.js', line_of('\n\n' + DB_JS, 'db.query'))],
                            rid='js/sql-injection', tags=('security', 'external/cwe/cwe-089')), 'codeql', shifted_root)
    s3_ok = check([f.get('identity') for f in b2] == [f.get('identity') for f in b] and
                  s2[0].get('identity') == s[0].get('identity') and c2[0].get('identity') == c[0].get('identity') and
                  cjs2[0].get('identity') == cjs[0].get('identity'),
                  'S3 every identity survives lines inserted above and inside the function')

    # ── S4 ───────────────────────────────────────────────────────────────────────────────
    print('S4 a secret finding is an urgent ticket that instructs rotation')
    sline = line_of(SETTINGS_PY, 'aws_key_id')
    col = SETTINGS_PY.split('\n')[sline - 1].index(SECRET) + 1
    gdoc = gitleaks_doc([result('aws-access-token', 'config/settings.py', sline, msg='aws-access-token has detected secret',
                                col=col, endcol=col + len(SECRET))])
    gdoc['runs'][0]['results'][0]['locations'][0]['physicalLocation']['region']['snippet'] = {'text': 'REDACTED'}
    ann = copy.deepcopy(gdoc)
    stats = cfk.annotate_secrets(ann, root, REPO)
    check(stats.get('fingerprinted') == 1, 'S4 the secret is fingerprinted before redaction (%s)' % stats)
    rs.scrub(ann)                        # the pipeline's redactor runs next
    g = parse(ann, 'gitleaks', root)
    check(g and g[0].get('ticket_key_state') == 'SECRET_KEYED' and g[0].get('secret_key'),
          'S4 the redacted finding still carries its ticket key (%s)' % (g and g[0].get('ticket_key_state')))
    check(g and g[0].get('identity_state') == 'UNFINGERPRINTABLE' and g[0].get('identity_reason') == 'SECRET_SUBJECT_NOT_BASELINEABLE',
          'S4 and still has NO baseline identity (the baseline has no authority over secrets)')
    srecs = as_records(g, 'secret-scan')
    scl, sw = clusters_of(srecs)
    check(len(scl) == 1 and not sw, 'S4 the secret is a ticket cluster, not withheld (%d clusters, %d withheld)' % (len(scl), len(sw)))
    s4_ok = True
    if scl:
        x = scl[0]
        facts = rt.routing_facts(x, REPO)
        s4_ok &= check(facts['class'] == 'secret', 'S4 routing class is `secret` (%s)' % facts['class'])
        s4_ok &= check(x.get('urgent') is True and str(x.get('severity')).lower() == 'critical',
                       'S4 the cluster is urgent and critical (%s, %s)' % (x.get('urgent'), x.get('severity')))
        body = rt.render_body(x)
        title = rt.render_title(x)
        s4_ok &= check('ROTATE' in body and 'removing it from the code does not' in body.lower(),
                       'S4 the body instructs rotation, not just removal')
        s4_ok &= check('secret' in title.lower() and title.startswith('[critical]'), 'S4 the title: %s' % title)
        j = rt.Jira('https://example.atlassian.net', 'e@example.invalid', 't', 'SEC', 'customfield_10001')
        sent = []
        j._req = lambda m, path, payload=None, **kw: (sent.append((m, path, payload)) or ({'id': '1', 'key': 'SEC-1'}, 201, None))
        x['extra_labels'] = rt.urgent_labels(j, x)
        ref, _why = j.create(x, body, title)
        fields = (sent[-1][2] or {}).get('fields', {}) if sent else {}
        s4_ok &= check(ref == '1' and (fields.get('priority') or {}).get('name') == 'Highest'
                       and any(l.endswith('-urgent') for l in fields.get('labels') or []),
                       'S4 Jira create: priority %s, labels %s' % ((fields.get('priority') or {}).get('name'), fields.get('labels')))
        # never closed by its absence
        gap = rt.secret_absence_gap({'member_identities': x['member_identities']})
        s4_ok &= check(bool(gap) and 'rotat' in gap.lower(), 'S4 a secret ticket never closes on absence: %s' % (gap or '')[:80])
        jtext = json.dumps(sent, default=str)
    else:
        body = title = jtext = ''
        s4_ok = False
    # history mode: the commit's content, not the working tree's
    if git:
        hroot = os.path.join(work, 'hist')
        write(hroot, 'config/settings.py', SETTINGS_PY)
        for args in (['init', '-q'], ['add', '-A'], ['commit', '-q', '-m', 'x']):
            subprocess.run([git, "-c", "core.autocrlf=false", "-c", "user.name=t", "-c", "user.email=t@example.invalid",
                            "-c", "commit.gpgsign=false", "-C", hroot] + args, check=True, stdout=subprocess.DEVNULL)
        sha = subprocess.run([git, '-C', hroot, 'rev-parse', 'HEAD'], stdout=subprocess.PIPE, check=True).stdout.decode().strip()
        write(hroot, 'config/settings.py', SETTINGS_PY.replace(SECRET, 'removed-from-the-tree'))
        hdoc = copy.deepcopy(gdoc)
        hdoc['runs'][0]['results'][0]['partialFingerprints'] = {'commitSha': sha, 'author': 't'}
        cfk.annotate_secrets(hdoc, hroot, REPO)
        fp_hist = ((hdoc['runs'][0]['results'][0].get('properties') or {}).get(cfk.secret_fp_property))
        fp_tree = ((ann['runs'][0]['results'][0].get('properties') or {}).get(cfk.secret_fp_property))
        check(fp_hist and fp_hist == fp_tree,
              'S4 a history-mode secret is fingerprinted from its commit, not the edited working tree')
    else:
        print('  UNKNOWN S4 history mode: no git on this host')

    # ── S5 ───────────────────────────────────────────────────────────────────────────────
    print('S5 the ticket templates carry the same keys')
    ext = tt.example_finding(source_tool='semgrep', identifier=SEMGREP_SHELL,
                             asset={'scheme': 'repo-path', 'repository': REPO, 'path': 'app/run.py', 'line': 6})
    rec = tt.normalize('finding', ext, {'submitted_by': 'tines-3b'})
    facts = dict(rec.get('template_facts') or [])
    check(rec.get('rule_family') == 'os-command-injection' and 'rule family' in facts,
          'S5 an external semgrep finding gains the rule family (%s)' % rec.get('rule_family'))
    ext_s = tt.example_finding(source_tool='gitleaks', identifier='aws-access-token', severity='high',
                               asset={'scheme': 'repo-path', 'repository': REPO, 'path': 'config/settings.py'})
    rec_s = tt.normalize('finding', ext_s, {'submitted_by': 'tines-3b'})
    facts_s = dict(rec_s.get('template_facts') or [])
    check(rec_s.get('kit_class') == 'secret' and 'ROTATE' in str(facts_s.get('remedy') or ''),
          'S5 an external secret finding is class secret with the rotation remedy (%s)' % rec_s.get('kit_class'))

    # ── S6 ───────────────────────────────────────────────────────────────────────────────
    print('S6 ticket routing reads the rule family and the CWE')
    import ticket_routing as trt
    routing = {'rules': [{'id': 'sqli', 'match': {'rule_family': ['sql-injection']}, 'project': 'APPSEC'},
                         {'id': 'by-cwe', 'match': {'cwe': 'CWE-78'}, 'project': 'PLATSEC'},
                         {'id': 'quiet', 'match': {'class': 'finding'}, 'project': 'none'}],
               'default': {'project': 'SEC'}}
    check(not trt.check_routing(routing, 'register', 'REGISTRATION_UNAVAILABLE'),
          'S6 a register naming rule_family and cwe validates')
    check(trt.check_routing({'rules': [{'match': {'rule_family': 'not-a-family'}, 'project': 'X1'}]}, 'r', 'U'),
          'S6 an unknown rule_family in a register is refused by name')
    by = {}
    for x in cl:
        by[tuple(sorted(set(m.get('rule_family') for m in x['members'])))] = trt.route(rt.routing_facts(x, REPO), routing, 'SEC')
    s6_ok = check((by.get(('sql-injection',)) or {}).get('project') == 'APPSEC', 'S6 the SQL cluster routes to APPSEC')
    s6_ok &= check((by.get(('os-command-injection',)) or {}).get('project') == 'PLATSEC',
                   'S6 the command-injection clusters route by CWE-78 to PLATSEC')
    if scl:
        tgt = trt.route(rt.routing_facts(scl[0], REPO), {'rules': [{'match': {'class': 'secret'}, 'project': 'none'}]}, 'SEC')
        check(tgt.get('project') == 'SEC' and any('TICKET_ROUTING_BELOW_FLOOR' in n for n in tgt.get('notes') or []),
              'S6 a secret is never routed to "none" (the rule is skipped, by name)')

    # ── N1 ───────────────────────────────────────────────────────────────────────────────
    print('N1 two different issues never merge')
    ids_b = [f.get('identity') for f in b]
    n1_dup = check(len(set(ids_b)) == 3, 'N1 three subprocess calls (two of them the same statement in one function) are three identities')
    check(sc['bandit_sql'][0].get('identity') not in ids_b, 'N1 SQL injection in the same function is another identity')
    check(len([x for x in cl if 'bandit' in x['scanners']]) == 4,
          'N1 four bandit clusters: handler (corroborated), two in other(), the SQL one (%d)'
          % len([x for x in cl if 'bandit' in x['scanners']]))
    other_repo = parse(bandit_doc([result('B602', 'app/run.py', line_of(APP_PY, 'subprocess.run', 1))]), 'bandit', root,
                       repository='other-org/other-app')
    check(other_repo and other_repo[0].get('ticket_anchor') and other_repo[0].get('ticket_anchor') != b[0].get('ticket_anchor'),
          'N1 the same code in another repository has another ticket anchor (the repository is in the key)')

    # ── N2 ───────────────────────────────────────────────────────────────────────────────
    print('N2 the secret value never appears anywhere')
    hay = json.dumps([g, srecs, [dict(x, members=x['members']) for x in scl], ann], default=str) + body + title + jtext
    tails = [SECRET, SECRET[4:], SECRET[-10:], hashlib.sha256(SECRET.encode()).hexdigest()[:16],
             hashlib.sha1(SECRET.encode()).hexdigest()[:16], hashlib.md5(SECRET.encode()).hexdigest()[:16]]
    n2_ok = check(not any(t in hay for t in tails), 'N2 neither the value, a fragment of it, nor a plain hash of it is in any output')
    fpv = str((ann['runs'][0]['results'][0].get('properties') or {}).get(cfk.secret_fp_property) or '')
    n2_ok &= check(fpv.startswith('sfp1:') and all(hashlib.new(a, SECRET.encode()).hexdigest()[:len(fpv) - 5] != fpv[5:]
                                                   for a in ('sha256', 'sha1', 'md5')),
                   'N2 the fingerprint is a slow keyed derivation, not a plain hash (%s...)' % fpv[:9])

    # ── N3 ───────────────────────────────────────────────────────────────────────────────
    print('N3 an unknown rule refuses with a named reason')
    unk = parse(bandit_doc([result('B999', 'app/run.py', 6)], rid='B999', cwe='99999'), 'bandit', root)
    n3_ok = check(unk and unk[0].get('identity_state') == 'UNFINGERPRINTABLE' and 'RULE_FAMILY_UNKNOWN' in (unk[0].get('identity_detail') or '')
                  and 'B999' in (unk[0].get('identity_detail') or ''),
                  'N3 bandit B999 refuses RULE_FAMILY_UNKNOWN naming the rule (%s: %s)'
                  % (unk and unk[0].get('identity_reason'), unk and (unk[0].get('identity_detail') or '')[:120]))
    unk_sg = parse(semgrep_doc([result('custom.rules.thing.my-rule', 'app/run.py', 6)], rid='custom.rules.thing.my-rule',
                               cwe='security'), 'semgrep', root)
    n3_ok &= check(unk_sg and unk_sg[0].get('identity_state') == 'UNFINGERPRINTABLE' and 'RULE_FAMILY_UNKNOWN' in (unk_sg[0].get('identity_detail') or ''),
                   'N3 a semgrep rule outside the table with no CWE refuses too (no namespace-prefix guess)')
    outside = parse(bandit_doc([result('B602', '../outside.py', 1)]), 'bandit', root)
    check(outside and 'SOURCE_PATH_REFUSED' in (outside[0].get('locus_basis') or ''),
          'N3 a path outside the checkout is refused, never read (%s)' % (outside and (outside[0].get('locus_basis') or '')[-80:]))

    # ── MUTANTS ──────────────────────────────────────────────────────────────────────────
    print('MUTANTS')
    mutant(cfk, 'anchor_ordinal', False, lambda: len(set(f.get('identity') for f in parse(bandit_doc(
        [result('B602', 'app/run.py', line_of(APP_PY, 'subprocess.run', 2)),
         result('B602', 'app/run.py', line_of(APP_PY, 'subprocess.run', 3))]), 'bandit', root))) == 2,
        'M1 no ordinal: the same statement twice in one function merges')
    mutant(cfk, 'anchor_on_line_number', True, lambda: parse(bandit_doc([result('B602', 'app/run.py', hs)]), 'bandit',
                                                             shifted_root)[0].get('identity') == b[0].get('identity'),
           'M2 the anchor on the line number: a line shift changes the identity')
    def fp_plain(material, repository):
        return 'sfp1:' + hashlib.sha256(material.encode('utf-8')).hexdigest()[:32]
    def m3_check():
        a2 = copy.deepcopy(gdoc)
        cfk.annotate_secrets(a2, root, REPO)
        v = str((a2['runs'][0]['results'][0].get('properties') or {}).get(cfk.secret_fp_property) or '')
        return v.startswith('sfp1:') and all(hashlib.new(a, SECRET.encode()).hexdigest()[:len(v) - 5] != v[5:]
                                             for a in ('sha256', 'sha1', 'md5'))
    mutant(cfk, 'secret_fingerprint', fp_plain, m3_check, 'M3 a plain sha256 fingerprint is caught as an oracle')
    def m4_check():
        bb = parse(bandit_doc([result('B602', 'app/run.py', h_line())]), 'bandit', root)
        return bb[0].get('identity') == s[0].get('identity')
    saved = dict(cfk.sast_aliases['bandit'])
    try:
        cfk.sast_aliases['bandit']['B602'] = 'code-injection'
        r = m4_check()
        check(not r, 'M4 bandit B602 aliased elsewhere: the two tools no longer merge (the alias is load-bearing)')
    finally:
        cfk.sast_aliases['bandit'].clear()
        cfk.sast_aliases['bandit'].update(saved)
    mutant(cfk, 'unknown_falls_back_to_rule_id', True, lambda: parse(bandit_doc([result('B999', 'app/run.py', 6)], rid='B999', cwe='99999'),
                                                                     'bandit', root)[0].get('identity_state') == 'UNFINGERPRINTABLE',
           'M5 an unknown rule falling back to its rule id is caught')
    def m6_check():
        cl6, _w = clusters_of(srecs)
        return bool(cl6) and cl6[0].get('urgent') is True
    mutant(rt, 'secret_urgent', False, m6_check, 'M6 secret urgency removed is caught')
    import ticket_routing as trt2
    real_matches = trt2.matches

    def blind(match, facts):
        return real_matches(dict((k, v) for k, v in (match or {}).items() if k not in ('rule_family', 'cwe')), facts)

    def m7_check():
        sql = [x for x in cl if set(m.get('rule_family') for m in x['members']) == {'sql-injection'}]
        return bool(sql) and trt2.route(rt.routing_facts(sql[0], REPO), {'rules': [
            {'match': {'rule_family': ['sql-injection']}, 'project': 'APPSEC'}], 'default': {'project': 'SEC'}},
            'SEC').get('project') == 'APPSEC' and trt2.route(rt.routing_facts(one[0], REPO), {'rules': [
                {'match': {'rule_family': ['sql-injection']}, 'project': 'APPSEC'}], 'default': {'project': 'SEC'}},
                'SEC').get('project') == 'SEC'
    mutant(trt2, 'matches', blind, m7_check, 'M7 routing that ignores rule_family is caught')
    print()
    if FAILS:
        print('FAIL: %d check(s): SAST and secret findings are not yet keyed and ticketed as the owner asked.' % len(FAILS))
        return 1
    print('PASS: bandit, semgrep and CodeQL findings are keyed by rule family + code location (one ticket for one issue, '
          'corroborated), line shifts keep identity, unknown rules refuse by name; secrets are urgent rotation tickets keyed '
          'on a non-reversible fingerprint and the value appears nowhere.')
    return 0


def h_line():
    return line_of(APP_PY, 'subprocess.run', 1)


def mutant(mod, attr, value, still_passes, label):
    """Apply a mutant; the guarded property must now FAIL (still_passes() returns False)."""
    if not hasattr(mod, attr):
        check(False, '%s (the module has no %s to mutate)' % (label, attr))
        return
    saved = getattr(mod, attr)
    try:
        setattr(mod, attr, value)
        try:
            survived = still_passes()
        except Exception as exc:  # noqa: BLE001 -- a crash under the mutant is a detection
            survived = False
            print('      (mutant raised %s)' % type(exc).__name__)
        check(not survived, label)
    finally:
        setattr(mod, attr, saved)


if __name__ == '__main__':
    sys.exit(main())

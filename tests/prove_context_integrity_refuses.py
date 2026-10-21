#!/usr/bin/env python3
"""The context-integrity step must HARD FAIL on a mismatched tenant, subscription or identity.

WHY THIS EXISTS

    verify-azure-oidc.yml asserts, after login, that the tenant, subscription and workload identity
    `az account show` reports equal the declared ones. The positive path was observed on a real
    tenant (run 31825375559). The refusal path had NO FIXTURE: the expectation was read from the
    same three secrets the login used, so the only way to make it differ from the session was to
    change a secret -- and a changed tenant, subscription or client id fails the LOGIN, one step
    earlier, before this assertion ever runs. The control could not be made to fail by any
    permitted means. An assertion that has never failed is decoration.

    So the step now also accepts a caller-DECLARED expectation (expect_tenant_id,
    expect_subscription_id, expect_client_id). Blank keeps the old behaviour -- the expectation is
    the secret the login used, recorded as FROM_SECRETS. A value is compared verbatim and recorded
    as DECLARED. The ambient comparison (session == login secrets) is never replaced: a declared
    value is a SECOND comparison, so a declaration can only make the step stricter. Passing a
    deliberately wrong value is how the refusal is proven on a hosted run without touching a
    secret, a variable or Azure.

WHAT THIS PROVES, LOCALLY

    The shipped step is EXTRACTED from the workflow (never re-implemented) and run under bash with
    a stub `az` on PATH that answers `account show` from env. Rows:

      R1  session == secrets, nothing declared      -> exit 0, every source FROM_SECRETS
      R2  declared tenant differs                   -> exit 1, "Context mismatch", names tenant
      R3  declared subscription differs             -> exit 1, names subscription
      R4  declared identity differs                 -> exit 1, names identity
      R5  declared values equal the session         -> exit 0, every source DECLARED
      R6  session differs from the secrets, nothing declared (a stale profile) -> exit 1
      R7  `az` answers nothing                      -> exit 1, UNRESOLVED, never a pass
      R8  no observed, expected or declared value is ever printed (R2..R4, R6)

WHAT IT CANNOT ESTABLISH
    That GitHub threads the inputs to the step, that azure/login yields the session this stub
    imitates, or that the job's conclusion is `failure` -- only a dispatched run can, and the
    `context-integrity` deferral in tests/reconcile_validation.py stays open until one is cited.

EXIT  0 every row holds   1 a row failed   2 the step could not be run (UNKNOWN, never PASS)
"""
import io
import os
import shutil
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
WF = os.path.join(ROOT, ".github", "workflows", "verify-azure-oidc.yml")
JOB = "verify"
STEP = "context"
INPUTS = ("expect_tenant_id", "expect_subscription_id", "expect_client_id")

# Shapes only. Nil and sequential GUIDs, nothing that denotes a real tenant or identity.
SESSION = {"tid": "11111111-1111-1111-1111-111111111111",
           "sid": "22222222-2222-2222-2222-222222222222",
           "cid": "33333333-3333-3333-3333-333333333333"}
WRONG = "00000000-0000-0000-0000-000000000000"

STUB_AZ = """#!/usr/bin/env bash
# Stub `az`: answers `account show --query <field> -o tsv` from env, nothing else.
case "$*" in
  *tenantId*)  printf '%s\\n' "${STUB_TID:-}" ;;
  *user.name*) printf '%s\\n' "${STUB_CID:-}" ;;
  *"--query id "*) printf '%s\\n' "${STUB_SID:-}" ;;
  *) echo "stub az: unexpected call: $*" >&2; exit 2 ;;
esac
"""


def bash():
    for c in (os.path.join("C:" + os.sep, "Program Files", "Git", "bin", "bash.exe"),
              os.path.join("C:" + os.sep, "Program Files (x86)", "Git", "bin", "bash.exe")):
        if os.path.exists(c):
            return c
    return shutil.which("bash") or "bash"


def load_step():
    """-> (the step's run text, its env mapping, the workflow's dispatch+call input names)."""
    import yaml
    doc = yaml.safe_load(io.open(WF, encoding="utf-8"))
    on = doc.get("on", doc.get(True)) or {}
    names = {}
    for trig in ("workflow_dispatch", "workflow_call"):
        names[trig] = set(((on.get(trig) or {}).get("inputs") or {}).keys())
    job = (doc.get("jobs") or {}).get(JOB) or {}
    for step in job.get("steps") or []:
        if step.get("id") == STEP:
            return step.get("run") or "", step.get("env") or {}, names
    return None, {}, names


def run_case(script, session, declared, secrets=None):
    """Run the extracted step; -> (rc, combined output, GITHUB_OUTPUT lines)."""
    secrets = secrets or SESSION
    work = tempfile.mkdtemp(prefix="ctx-")
    try:
        stub_dir = os.path.join(work, "stub")
        os.makedirs(stub_dir)
        az = os.path.join(stub_dir, "az")
        io.open(az, "w", encoding="utf-8", newline="\n").write(STUB_AZ)
        os.chmod(az, 0o755)
        out_file = os.path.join(work, "gh_output")
        io.open(out_file, "w").close()
        # The stub directory goes FIRST on PATH, in the form bash uses on this host.
        prelude = ('if command -v cygpath >/dev/null 2>&1; then _d=$(cygpath -u "$STUB_DIR"); '
                   'else _d="$STUB_DIR"; fi\nexport PATH="$_d:$PATH"\n')
        sh = os.path.join(work, "step.sh")
        io.open(sh, "w", encoding="utf-8", newline="\n").write(prelude + script)
        env = dict(os.environ, STUB_DIR=stub_dir, GITHUB_OUTPUT=out_file,
                   STUB_TID=session["tid"], STUB_SID=session["sid"], STUB_CID=session["cid"],
                   EXPECTED_TID=secrets["tid"], EXPECTED_SID=secrets["sid"],
                   EXPECTED_CID=secrets["cid"],
                   IN_EXPECT_TID=declared.get("tid", ""), IN_EXPECT_SID=declared.get("sid", ""),
                   IN_EXPECT_CID=declared.get("cid", ""))
        p = subprocess.run([bash(), sh], cwd=work, env=env, capture_output=True, text=True,
                           encoding="utf-8", errors="replace")
        outputs = io.open(out_file, encoding="utf-8").read().splitlines()
        return p.returncode, (p.stdout or "") + (p.stderr or ""), outputs
    finally:
        shutil.rmtree(work, ignore_errors=True)


def main():
    fails = []

    def row(name, ok, detail=""):
        print("  %s  %s%s" % ("ok  " if ok else "FAIL", name, ("  -- " + detail) if detail else ""))
        if not ok:
            fails.append(name)

    try:
        script, env, names = load_step()
    except Exception as e:  # noqa: BLE001
        print("UNKNOWN: could not read %s: %s" % (WF, e))
        return 2
    if script is None:
        print("FAIL: job %r has no step with id %r in verify-azure-oidc.yml -- the context-"
              "integrity step is not addressable, so nothing shipped can be run here." % (JOB, STEP))
        return 1

    # The fixture mechanism must be DECLARED on both triggers and reach the step as data.
    for trig in ("workflow_dispatch", "workflow_call"):
        missing = [n for n in INPUTS if n not in names[trig]]
        row("%s declares %s" % (trig, ", ".join(INPUTS)), not missing, "missing: %s" % missing)
    for var, inp in (("IN_EXPECT_TID", "expect_tenant_id"), ("IN_EXPECT_SID", "expect_subscription_id"),
                     ("IN_EXPECT_CID", "expect_client_id")):
        mapped = str(env.get(var) or "")
        row("step env %s carries inputs.%s" % (var, inp), ("inputs.%s" % inp) in mapped, mapped or "absent")
    for var, sec in (("EXPECTED_TID", "AZURE_TENANT_ID"), ("EXPECTED_SID", "AZURE_SUBSCRIPTION_ID"),
                     ("EXPECTED_CID", "AZURE_CLIENT_ID")):
        mapped = str(env.get(var) or "")
        row("step env %s still carries secrets.%s" % (var, sec), ("secrets.%s" % sec) in mapped, mapped or "absent")
    if "${{" in script:
        row("no expression inside the step body (data arrives through env:)", False)

    # R1
    rc, out, outputs = run_case(script, SESSION, {})
    row("R1 session == secrets, nothing declared -> exit 0", rc == 0, "rc=%s" % rc)
    row("R1 every source FROM_SECRETS", all(("%s_source=FROM_SECRETS" % k) in outputs
                                            for k in ("tenant", "subscription", "identity")),
        "outputs=%s" % outputs)
    row("R1 says verified", "Context integrity verified" in out)

    # R2..R4, R8
    for key, label in (("tid", "tenant"), ("sid", "subscription"), ("cid", "identity")):
        rc, out, outputs = run_case(script, SESSION, {key: WRONG})
        row("R%d declared %s differs -> exit 1" % (2 + ["tid", "sid", "cid"].index(key), label),
            rc != 0, "rc=%s" % rc)
        row("   names %s in a Context mismatch error" % label,
            "Context mismatch" in out and label in out)
        row("   records the declared source", ("%s_source=DECLARED" % label) in outputs,
            "outputs=%s" % outputs)
        leaked = [v for v in list(SESSION.values()) + [WRONG] if v in out]
        row("R8 prints no observed, expected or declared value", not leaked, "leaked: %s" % leaked)

    # R5
    rc, out, outputs = run_case(script, SESSION, dict(SESSION))
    row("R5 declared values equal the session -> exit 0", rc == 0, "rc=%s" % rc)
    row("R5 every source DECLARED", all(("%s_source=DECLARED" % k) in outputs
                                        for k in ("tenant", "subscription", "identity")),
        "outputs=%s" % outputs)

    # R6: the ORIGINAL control. A declaration equal to the session must not excuse a session
    # that differs from the secrets the login used.
    stale = dict(SESSION, sid=WRONG)
    rc, out, outputs = run_case(script, stale, {})
    row("R6 session differs from the secrets, nothing declared -> exit 1", rc != 0, "rc=%s" % rc)
    rc, out, outputs = run_case(script, stale, dict(stale))
    row("R6 a declaration matching a stale session does not excuse it -> exit 1", rc != 0,
        "rc=%s" % rc)
    leaked = [v for v in list(SESSION.values()) + [WRONG] if v in out]
    row("R8 (stale) prints no value", not leaked, "leaked: %s" % leaked)

    # R7
    rc, out, outputs = run_case(script, {"tid": "", "sid": "", "cid": ""}, {})
    row("R7 az answers nothing -> exit 1, UNRESOLVED", rc != 0 and "UNRESOLVED" in out, "rc=%s" % rc)

    if fails:
        print("\nFAIL: %d row(s): %s" % (len(fails), "; ".join(fails)))
        return 1
    print("\nPASS: the shipped context-integrity step refuses a declared mismatch on each of tenant, "
          "subscription and identity, keeps the ambient check, resolves nothing to a pass, and "
          "prints no value. A hosted dispatch is still owed (reconcile_validation: context-integrity).")
    return 0


if __name__ == "__main__":
    sys.exit(main())

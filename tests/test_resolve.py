#!/usr/bin/env python3
"""Prove the `resolve` position -- versions, capability, coverage, plan -- without a runner.

WHY THIS EXISTS

    PIPELINE_ORDERING_AND_SCAN_VALIDITY.md §1.6: "R2, R3 and R6 have nowhere to attach, because
    there is no position between `discover` and the scanners". SINGLE_PIPELINE_TARGET.md §5.1
    names that position `resolve`. This file is its contract, exercised the way discovery's is
    (tests/test_discovery.py): the shipped step is EXTRACTED from where it ships and RUN against
    fixture trees holding real version files, under bash, with the inputs fed as env exactly as
    the runner feeds them. A test that reimplements the probe proves the author can write the
    same bug twice.

WHERE THE STEP SHIPS
    In .github/actions/resolve/action.yml, the composite the job reaches through `$/`, since
    2026-10-15: inline, the two steps were 85 KB and took the flagship to 518 KB -- past the
    500 KB ceiling at which GitHub does not fail a workflow but never starts it. So this reads
    the job, requires that it USES the composite (a composite nobody uses is a file nobody
    ships), and takes the steps from the composite -- the way tests/prove_report_runs_as_shipped.py
    locates the reporter.

THE ROWS, in the order the design puts them (gap ledger §1B)

    L21  the position exists: needs discover, nothing scanner-shaped, emits job outputs
    L19  a target version per discovered class AND root, with the strength of the evidence.
         A constraint is not a version. Undetermined is a gap and the scanner still runs.
    L20  the per-tool supported range is DATA; matching yields SCANNER_SUPPORTS,
         VERSION_UNSUPPORTED or VERSION_SUPPORT_UNDETERMINED, and a COVERAGE_GAP is declared
         BEFORE the scan
    L24  class-and-count coverage: files_in_scope, enumeration, covered_by, coverage_basis.
         Never a percentage.
    L22  an advisory execution plan, emitted as data, that nothing enforces yet

    KDEC-010  the capability selects the scanner: per (capability, root), the first ORDERED
         candidate that can read the target. SERVED / SUBSTITUTION (labelled, never
         equivalence) / VERSION_GAP (PARTIAL, never PASS, the closing row named). UNVERIFIED
         is never capable.

WHAT IT CANNOT ESTABLISH
    That the gate and the report act on these outputs -- tests/prove_bootstrap_failure.py,
    tests/prove_gate_routing.py and tests/prove_capability_selection.py run those -- or that a
    runner produces them: only a dispatch can.
"""
import io
import json
import os
import shutil
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
WF = os.path.join(ROOT, ".github", "workflows", "reusable-security.yml")
REG = os.path.join(ROOT, "scanner-registry.yaml")
ACTION = os.path.join(ROOT, ".github", "actions", "resolve", "action.yml")
USES = "$/.github/actions/resolve"
# G1 (KDEC-033): the resolver is the third part of the `plan` job, after discovery.
JOB = "plan"
STEP = "r"
SCANNERS = ["secret-scan", "code-quality", "sast-semgrep", "sast-bandit", "codeql", "deps-scan",
            "iac-scan", "sast-dotnet", "sast-java", "sast-go", "sast-cpp", "sast-mobile", "image-scan",
            "malicious-deps", "sbom", "report", "security-gate"]


def load_workflow():
    import yaml
    return yaml.safe_load(io.open(WF, encoding="utf-8"))


def load_composite(doc):
    """-> (composite document, its steps). The job must USE the composite, or there is nothing
    shipped to run: reading the composite without that check would prove a file nobody ships,
    and reading the job's steps would find a `uses:` and nothing to run."""
    import yaml
    job = (doc.get("jobs") or {}).get(JOB)
    if not job:
        raise SystemExit("FAIL: no job named %r in reusable-security.yml -- the position between "
                         "discover and the scanners does not exist" % JOB)
    uses = [s.get("uses") for s in job.get("steps") or [] if s.get("uses")]
    if USES not in uses:
        raise SystemExit("FAIL: job %r does not use %s (uses: %s) -- its steps ship nowhere this "
                         "proof can run them" % (JOB, USES, uses or "none"))
    if not os.path.isfile(ACTION):
        raise SystemExit("FAIL: job %r uses %s but %s does not exist" % (JOB, USES, ACTION))
    comp = yaml.safe_load(io.open(ACTION, encoding="utf-8")) or {}
    return comp, (comp.get("runs") or {}).get("steps") or []


def extract_step(doc, step_id):
    for step in load_composite(doc)[1]:
        if step.get("id") == step_id:
            return step["run"]
    return None


def extract_resolve_shell(doc):
    shell = extract_step(doc, STEP)
    if shell is None:
        raise SystemExit("FAIL: composite %s has no step with id %r" % (ACTION, STEP))
    return shell


def _bash():
    gitbash = os.path.join("C:" + os.sep, "Program Files", "Git", "bin", "bash.exe")
    gitbash86 = os.path.join("C:" + os.sep, "Program Files (x86)", "Git", "bin", "bash.exe")
    for c in (gitbash, gitbash86):
        if os.path.exists(c):
            return c
    return shutil.which("bash") or "bash"


def make_tree(spec, base):
    """spec: {relative path: content}. Real version files, not placeholders."""
    for rel, content in spec.items():
        p = os.path.join(base, rel)
        os.makedirs(os.path.dirname(p), exist_ok=True)
        io.open(p, "w", encoding="utf-8", newline="\n").write(content)


# Lower-case on purpose: a harness constant, not vocabulary.
discover_all_false = {"python": "false", "node": "false", "go": "false", "dotnet": "false",
                      "java": "false", "cpp": "false", "php": "false", "iac": "false",
                      # lane L-SCAN-B (KDEC-026)
                      "kotlin": "false", "swift": "false", "mobile": "false"}


def run_case(shell, files, discover=None, inputs=None, event="push", break_python=False,
             prelude=""):
    """Run the real resolve step against a synthetic tree; return outputs, summary and log."""
    tmp = tempfile.mkdtemp(prefix="resolve-")
    rundir = tempfile.mkdtemp(prefix="resolve-run-")
    outfile = os.path.join(tmp, "gh_output")
    summary = os.path.join(tmp, "gh_summary")
    try:
        make_tree(files, tmp)
        io.open(outfile, "w").close()
        io.open(summary, "w").close()
        body = shell
        if break_python:
            # The resolver itself cannot run. Must NOT present as a tidy COMPLETE.
            body = "python3() { return 1; }\n" + body
        body = prelude + body
        script = os.path.join(rundir, "r.sh")
        io.open(script, "w", encoding="utf-8", newline="\n").write(body)
        d = dict(discover_all_false)
        d.update(discover or {})
        env = dict(os.environ, GITHUB_OUTPUT=outfile, GITHUB_STEP_SUMMARY=summary,
                   gh_event=event, IN_PATHS=".")
        for k, v in d.items():
            env["D_" + k.upper()] = v
        # Built from lower-case names so the env-variable names do not read as vocabulary.
        for k, v in (("state", "COMPLETE"), ("coverage_gaps", ""), ("unsupported", "")):
            env.setdefault("D_" + k.upper(), v)
        defaults = {"python_version": "3.12", "node_version": "20", "go_version": "1.22",
                    "dotnet_version": "8.0.x", "java_version": "17", "image_ref": "",
                    "enable_sbom": "true", "enable_malicious_pkg_scan": "true"}
        defaults.update(inputs or {})
        for k, v in defaults.items():
            env["IN_" + k.upper()] = v
        p = subprocess.run([_bash(), script], cwd=tmp, env=env, capture_output=True, text=True)
        out = {}
        for line in io.open(outfile, encoding="utf-8"):
            if "=" in line:
                k, v = line.rstrip("\n").split("=", 1)
                out[k] = v
        out["__summary__"] = io.open(summary, encoding="utf-8").read()
        out["__log__"] = (p.stdout or "") + (p.stderr or "")
        out["__rc__"] = p.returncode
        return out
    finally:
        shutil.rmtree(tmp, ignore_errors=True)
        shutil.rmtree(rundir, ignore_errors=True)


def check(name, ok, detail=""):
    print("  %-50s %s" % (name, "PASS" if ok else "FAIL"))
    if not ok and detail:
        for line in str(detail).splitlines()[:12]:
            print("      %s" % line)
    return bool(ok)


def jload(out, key):
    try:
        return json.loads(out.get(key, ""))
    except Exception:
        return None


def position_checks(doc):
    """L21: the position exists, between discover and the scanners, and is registered."""
    import yaml
    ok = True
    job = (doc.get("jobs") or {}).get(JOB) or {}
    needs = job.get("needs") or []
    needs = [needs] if isinstance(needs, str) else list(needs)
    # G1: the resolver follows discovery inside `plan` and runs only on a completed discovery.
    ids = [s.get("id") for s in job.get("steps") or []]
    rstep = next((s for s in job.get("steps") or [] if s.get("id") == "resolve"), {})
    ok &= check("L21 resolve runs after discovery, only on a completed one",
                "d" in ids and "resolve" in ids and ids.index("d") < ids.index("resolve")
                and "steps.disc_part.outputs.discover_result == 'success'" in " ".join(str(rstep.get("if", "")).split()),
                "steps=%s if=%r" % (ids, rstep.get("if")))
    ok &= check("L21 resolve waits for no scanner, report or gate",
                not (set(needs) & set(SCANNERS)), "needs=%s" % needs)
    outputs = job.get("outputs") or {}
    ok &= check("L21 resolve declares a state output (resolve_state in plan)",
                str(outputs.get("resolve_state", "")).strip() == "${{ steps.resolve.outputs.state }}",
                "outputs=%s" % sorted(outputs))
    perms = job.get("permissions") or {}
    ok &= check("L21 resolve declares least privilege (no write)",
                perms and all(v == "read" for v in perms.values()), "permissions=%s" % perms)
    reg = yaml.safe_load(io.open(REG, encoding="utf-8")) or {}
    row = (reg.get("jobs") or {}).get(JOB)
    ok &= check("L21 scanner-registry.yaml has a row for resolve (infrastructure)",
                (row or {}).get("class") == "infrastructure" and "resolve" in ((row or {}).get("parts") or []),
                "row=%s" % row)
    # ── the steps ship in the composite, and the job is wired to it completely ─────────────
    # The job's outputs are what every consumer reads (needs.plan.outputs.<name>); a composite
    # output the job does not map is an answer nobody can hear, and a composite input the job
    # does not pass is a value the step reads as "nobody said" -- an unknown, silently.
    comp, csteps = load_composite(doc)
    comps = (row or {}).get("composite")
    comps = [comps] if isinstance(comps, str) else list(comps or [])
    ok &= check("L21 the registry names the composite the job uses",
                "resolve" in comps, "row=%s" % row)
    use = next((s for s in job.get("steps") or [] if s.get("uses") == USES), {})
    passed = set((use.get("with") or {}))
    declared = set(comp.get("inputs") or {})
    ok &= check("L21 the job passes every composite input, and nothing the composite lacks",
                passed == declared, "missing=%s extra=%s" % (sorted(declared - passed),
                                                             sorted(passed - declared)))
    cout = set(comp.get("outputs") or {})
    # In `plan` the resolver's `state` is published as resolve_state (discovery owns `state`).
    jname = lambda k: "resolve_state" if k == "state" else k  # noqa: E731
    ok &= check("L21 every composite output is a job output of the same name",
                all(str(outputs.get(jname(k), "")).strip()
                    == "${{ steps.%s.outputs.%s }}" % (use.get("id"), k) for k in cout),
                "composite=%s job=%s" % (sorted(cout), sorted(outputs)))
    ok &= check("L21 every composite run step declares shell: bash (a composite runs nothing without it)",
                csteps and all(s.get("shell") == "bash" for s in csteps if s.get("run")),
                [s.get("id") for s in csteps if s.get("run") and s.get("shell") != "bash"])
    # The scanners still START on discover's outputs alone: every scanner runs whatever the
    # selection says (KDEC-010), so no scanner needs to wait for resolve. What consumes the
    # selection is the gate (tests/prove_bootstrap_failure.py, capability_gap_* and
    # substitution_not_selected) and the report (tests/prove_capability_selection.py); the gate's
    # reading of needs.plan.outputs.resolve_result is asserted by tests/check_scanner_registry.py.
    return ok


def records(out, **where):
    """The version records matching every given field."""
    recs = jload(out, "versions")
    if not isinstance(recs, list):
        return None
    return [r for r in recs if all(r.get(k) == v for k, v in where.items())]


def one(out, **where):
    rs = records(out, **where)
    return rs[0] if rs else {}


def version_checks(shell):
    """L19: a target version per discovered class AND root, with the strength of the evidence.

    PIPELINE_ORDERING §2.2 table, §2.2's three rules: a constraint is not a version; multiple
    answers do not average; a probe that cannot read a manifest sets its own sentinel.
    """
    ok = True
    py = {"python": "true"}

    # ── an exact pin IS a version ──────────────────────────────────────────────────────────
    r = run_case(shell, {".python-version": "3.13.1\n", "app/main.py": "x\n"}, discover=py)
    rec = one(r, **{"class": "python", "root": "."})
    ok &= check("L19 python .python-version -> exact 3.13.1",
                rec.get("version") == "3.13.1" and rec.get("strength") == "exact"
                and rec.get("source") == ".python-version", "rec=%s" % rec)
    ok &= check("L19 a discovered version is VERSION_DISCOVERED in the summary",
                "VERSION_DISCOVERED" in r["__summary__"], r["__summary__"][-600:])

    # ── A CONSTRAINT IS NOT A VERSION. `>=3.9` proves a floor, and a floor is not a target ──
    r = run_case(shell, {"pyproject.toml": '[project]\nname = "x"\nrequires-python = ">=3.9"\n'},
                 discover=py)
    rec = one(r, **{"class": "python", "root": "."})
    ok &= check("L19 requires-python >=3.9 -> floor, not a version",
                rec.get("version") is None and rec.get("strength") == "floor"
                and (rec.get("range") or {}).get("min") == "3.9"
                and (rec.get("range") or {}).get("max") is None, "rec=%s" % rec)

    r = run_case(shell, {"pyproject.toml": '[project]\nrequires-python = ">=3.9,<3.13"\n'},
                 discover=py)
    rec = one(r, **{"class": "python", "root": "."})
    ok &= check("L19 bounded constraint -> constraint with both bounds",
                rec.get("strength") == "constraint"
                and (rec.get("range") or {}).get("min") == "3.9"
                and (rec.get("range") or {}).get("max") == "3.13"
                and (rec.get("range") or {}).get("max_inclusive") is False, "rec=%s" % rec)

    # ── precedence: the stronger source wins, and the weaker one is recorded as checked ────
    r = run_case(shell, {".python-version": "3.12\n",
                         "pyproject.toml": '[project]\nrequires-python = ">=3.9"\n'}, discover=py)
    rec = one(r, **{"class": "python", "root": "."})
    ok &= check("L19 .python-version outranks requires-python; both are recorded",
                rec.get("version") == "3.12" and rec.get("strength") == "exact"
                and "pyproject.toml" in (rec.get("checked") or []), "rec=%s" % rec)

    # ── the weaker python sources ─────────────────────────────────────────────────────────
    r = run_case(shell, {"setup.cfg": "[options]\npython_requires = >=3.8\n"}, discover=py)
    ok &= check("L19 setup.cfg python_requires -> floor 3.8",
                one(r, **{"class": "python"}).get("strength") == "floor"
                and (one(r, **{"class": "python"}).get("range") or {}).get("min") == "3.8")
    r = run_case(shell, {"tox.ini": "[tox]\nenvlist = py39, py310, py311\n"}, discover=py)
    rec = one(r, **{"class": "python"})
    ok &= check("L19 tox envlist -> a set, recorded as constraint 3.9..3.11",
                rec.get("strength") == "constraint" and (rec.get("range") or {}).get("min") == "3.9"
                and (rec.get("range") or {}).get("max") == "3.11", "rec=%s" % rec)
    r = run_case(shell, {"Dockerfile": "FROM python:3.12-slim\nCOPY . .\n"}, discover=py)
    ok &= check("L19 Dockerfile base image tag -> exact 3.12",
                one(r, **{"class": "python"}).get("version") == "3.12")
    r = run_case(shell, {"runtime.txt": "python-3.11.4\n"}, discover=py)
    ok &= check("L19 runtime.txt -> exact 3.11.4",
                one(r, **{"class": "python"}).get("version") == "3.11.4")

    # ── MULTIPLE ANSWERS DO NOT AVERAGE. Two roots, two records ──────────────────────────
    r = run_case(shell, {"svc-a/.python-version": "3.11\n", "svc-b/.python-version": "3.13\n"},
                 discover=py)
    a = one(r, **{"class": "python", "root": "svc-a"})
    b = one(r, **{"class": "python", "root": "svc-b"})
    ok &= check("L19 two roots -> two records, never one repository-wide version",
                a.get("version") == "3.11" and b.get("version") == "3.13"
                and len(records(r, **{"class": "python"}) or []) == 2,
                "records=%s" % records(r, **{"class": "python"}))

    # ── UNDETERMINED IS A GAP, AND THE REPOSITORY IS TOLD WHICH FILE TO ADD ──────────────
    r = run_case(shell, {"app/main.py": "x\n"}, discover=py)
    rec = one(r, **{"class": "python"})
    ok &= check("L19 python present, no version source -> strength none, version null",
                rec.get("strength") == "none" and rec.get("version") is None, "rec=%s" % rec)
    ok &= check("L19 ...and the summary names the file that would close it",
                ".python-version" in r["__summary__"], r["__summary__"][-600:])

    # ── COULD NOT READ IS NOT FOUND NOTHING. A broken manifest is its own sentinel ───────
    r = run_case(shell, {"pyproject.toml": "[project\nrequires-python = \n"}, discover=py)
    rec = one(r, **{"class": "python"})
    ok &= check("L19 unparseable pyproject -> strength unreadable, state DISCOVERY_PARTIAL",
                rec.get("strength") == "unreadable" and r.get("state") == "DISCOVERY_PARTIAL",
                "rec=%s state=%s" % (rec, r.get("state")))

    # ── node ──────────────────────────────────────────────────────────────────────────────
    nd = {"node": "true"}
    r = run_case(shell, {"package.json": '{"name":"x","engines":{"node":">=20"}}\n'}, discover=nd)
    rec = one(r, **{"class": "node"})
    ok &= check("L19 package.json engines.node >=20 -> floor 20",
                rec.get("strength") == "floor" and (rec.get("range") or {}).get("min") == "20",
                "rec=%s" % rec)
    r = run_case(shell, {"package.json": '{"name":"x","engines":{"node":"^20"}}\n',
                         ".nvmrc": "v20.11.0\n",
                         "tsconfig.json": '{"compilerOptions":{"target":"ES2022"}}\n'}, discover=nd)
    rec = one(r, **{"class": "node", "kind": "language"})
    ok &= check("L19 .nvmrc outranks engines; tsconfig target carried as syntax level",
                rec.get("version") == "20.11.0" and rec.get("strength") == "exact"
                and rec.get("syntax_level") == "ES2022", "rec=%s" % rec)
    r = run_case(shell, {"package.json": '{"name":"x","engines":{"node":"^20.9.0"}}\n'}, discover=nd)
    rec = one(r, **{"class": "node"})
    ok &= check("L19 caret range ^20.9.0 -> >=20.9.0 <21",
                (rec.get("range") or {}).get("min") == "20.9.0"
                and (rec.get("range") or {}).get("max") == "21", "rec=%s" % rec)

    # ── go: the go directive is a language version and is mandatory ─────────────────────
    r = run_case(shell, {"go.mod": "module example.com/x\n\ngo 1.22\n\ntoolchain go1.22.3\n"},
                 discover={"go": "true"})
    rec = one(r, **{"class": "go", "kind": "language"})
    tc = one(r, **{"class": "go", "kind": "toolchain"})
    ok &= check("L19 go.mod go directive -> exact 1.22; toolchain recorded separately",
                rec.get("version") == "1.22" and rec.get("strength") == "exact"
                and tc.get("version") == "1.22.3", "lang=%s toolchain=%s" % (rec, tc))

    # ── dotnet: TargetFrameworks are exact and plural; LangVersion latest is a moving target
    dn = {"dotnet": "true"}
    r = run_case(shell, {"src/App.csproj": "<Project Sdk=\"Microsoft.NET.Sdk\">\n  <PropertyGroup>\n"
                                           "    <TargetFrameworks>net8.0;net9.0</TargetFrameworks>\n"
                                           "    <LangVersion>latest</LangVersion>\n"
                                           "  </PropertyGroup>\n</Project>\n",
                         "global.json": '{"sdk":{"version":"8.0.400"}}\n'}, discover=dn)
    tfms = sorted(x.get("version") for x in (records(r, **{"class": "dotnet", "root": "src",
                                                            "kind": "language"}) or []))
    lv = one(r, **{"class": "dotnet", "root": "src", "kind": "langversion"})
    sdk = one(r, **{"class": "dotnet", "kind": "sdk"})
    ok &= check("L19 csproj TargetFrameworks -> two exact records 8.0 and 9.0",
                tfms == ["8.0", "9.0"], "tfms=%s" % tfms)
    ok &= check("L19 LangVersion latest -> strength moving",
                lv.get("strength") == "moving", "lv=%s" % lv)
    ok &= check("L19 global.json sdk.version -> sdk 8.0.400 exact",
                sdk.get("version") == "8.0.400" and sdk.get("strength") == "exact", "sdk=%s" % sdk)

    # ── java ──────────────────────────────────────────────────────────────────────────────
    jv = {"java": "true"}
    r = run_case(shell, {"pom.xml": "<project>\n  <properties>\n"
                                    "    <maven.compiler.release>21</maven.compiler.release>\n"
                                    "  </properties>\n</project>\n"}, discover=jv)
    ok &= check("L19 pom.xml maven.compiler.release -> exact 21",
                one(r, **{"class": "java"}).get("version") == "21")
    r = run_case(shell, {"pom.xml": "<project><properties><maven.compiler.source>1.8"
                                    "</maven.compiler.source></properties></project>\n"}, discover=jv)
    ok &= check("L19 pom.xml source 1.8 -> exact 8",
                one(r, **{"class": "java"}).get("version") == "8")
    r = run_case(shell, {"build.gradle.kts": "java {\n  toolchain {\n"
                                             "    languageVersion.set(JavaLanguageVersion.of(21))\n"
                                             "  }\n}\n"}, discover=jv)
    ok &= check("L19 gradle toolchain languageVersion -> exact 21",
                one(r, **{"class": "java"}).get("version") == "21")
    r = run_case(shell, {"build.gradle": "sourceCompatibility = JavaVersion.VERSION_17\n"},
                 discover=jv)
    ok &= check("L19 gradle sourceCompatibility -> exact 17",
                one(r, **{"class": "java"}).get("version") == "17")
    r = run_case(shell, {".sdkmanrc": "java=21.0.2-tem\n", "build.gradle": "plugins {}\n"},
                 discover=jv)
    ok &= check("L19 .sdkmanrc -> exact 21.0.2",
                one(r, **{"class": "java"}).get("version") == "21.0.2")

    # ── cpp: several standards can coexist, and each is recorded ─────────────────────────
    r = run_case(shell, {"CMakeLists.txt": "cmake_minimum_required(VERSION 3.20)\n"
                                           "set(CMAKE_CXX_STANDARD 17)\nset(CMAKE_C_STANDARD 11)\n",
                         "legacy/Makefile": "CXXFLAGS=-std=c++20 -Wall\n"},
                 discover={"cpp": "true"})
    cxx = sorted((x.get("root"), x.get("version")) for x in
                 (records(r, **{"class": "cpp", "kind": "cxx"}) or []))
    c = one(r, **{"class": "cpp", "kind": "c"})
    ok &= check("L19 CMake CXX 17 and Makefile -std=c++20 are two records; C 11 is its own",
                cxx == [(".", "17"), ("legacy", "20")] and c.get("version") == "11",
                "cxx=%s c=%s" % (cxx, c))

    # ── iac: required_version is a constraint, not a pin ──────────────────────────────────
    ia = {"iac": "true"}
    r = run_case(shell, {"infra/main.tf": 'terraform {\n  required_version = ">= 1.5.0"\n}\n'},
                 discover=ia)
    rec = one(r, **{"class": "iac", "kind": "terraform"})
    ok &= check("L19 terraform required_version >= 1.5.0 -> floor",
                rec.get("strength") == "floor" and (rec.get("range") or {}).get("min") == "1.5.0",
                "rec=%s" % rec)
    r = run_case(shell, {"infra/versions.tf": 'terraform {\n  required_version = "~> 1.6"\n}\n',
                         "chart/Chart.yaml": "apiVersion: v2\nname: x\n"}, discover=ia)
    rec = one(r, **{"class": "iac", "kind": "terraform"})
    helm = one(r, **{"class": "iac", "kind": "helm"})
    ok &= check("L19 ~> 1.6 -> >=1.6 <2; Chart.yaml apiVersion v2 -> helm 2",
                (rec.get("range") or {}).get("min") == "1.6"
                and (rec.get("range") or {}).get("max") == "2"
                and helm.get("version") == "2", "tf=%s helm=%s" % (rec, helm))

    # ── NEVER a percentage, anywhere in the summary ───────────────────────────────────────
    ok &= check("L19 the summary never states a percentage", "%" not in r["__summary__"],
                r["__summary__"][-300:])
    return ok


def cap(out, **where):
    rows = jload(out, "capability")
    if not isinstance(rows, list):
        return []
    return [r for r in rows if all(r.get(k) == v for k, v in where.items())]


def cap_state(out, job, tool=None, **where):
    rows = cap(out, job=job, **where)
    if tool:
        rows = [r for r in rows if r.get("tool") == tool]
    return rows[0].get("state") if rows else None


def inlined_table(shell, marker="JSON"):
    """The version-support table as the step ships it: the JSON heredoc inside the composite's
    run body. `$/` would let the composite read scanner-registry.yaml directly; until it does,
    the copy is held byte-equivalent to the registry here. `marker` names the heredoc: JSON is
    version_support, SELECTION is capability_selection (KDEC-010)."""
    import re
    m = re.search(r"<<'%s'\n(.*?)\n%s\n" % (marker, marker), shell, re.S)
    if not m:
        return None
    try:
        return json.loads(m.group(1))
    except Exception:
        return None


def capability_checks(shell):
    """L20: the per-tool range is DATA, matching gives three answers, the gap is declared first.

    PIPELINE_ORDERING §2.4. The scanner still runs in every case; what changes is what its
    silence is allowed to mean.
    """
    import yaml
    ok = True
    py = {"python": "true"}

    # ── THE TABLE IS DATA, DECLARED PER SCANNER, AND THE SHIPPED COPY IS THE CANONICAL ONE ──
    reg = yaml.safe_load(io.open(REG, encoding="utf-8")) or {}
    canon = reg.get("version_support")
    ok &= check("L20 scanner-registry.yaml declares version_support per scanner",
                isinstance(canon, dict) and "sast-bandit" in canon and "codeql" in canon,
                "keys=%s" % sorted(canon or {}))
    shipped = inlined_table(shell)
    ok &= check("L20 the step carries the table as data, identical to the registry",
                shipped is not None and shipped == canon,
                "shipped=%s" % (None if shipped is None else sorted(shipped)))
    kitwide = [j for j, cls in (canon or {}).items() if not isinstance(cls, dict)]
    ok &= check("L20 no kit-wide range: every entry is (scanner, class)", not kitwide, kitwide)

    # ── bandit's ceiling IS the runner interpreter. 3.13 under a 3.12 runner is a gap ──────
    r = run_case(shell, {".python-version": "3.13\n", "app/main.py": "x\n"}, discover=py,
                 inputs={"python_version": "3.12"})
    ok &= check("L20 python 3.13 vs bandit on 3.12 -> VERSION_UNSUPPORTED",
                cap_state(r, "sast-bandit", "bandit") == "VERSION_UNSUPPORTED",
                "rows=%s" % cap(r, job="sast-bandit"))
    ok &= check("L20 ...codeql (python <= 3.14) -> SCANNER_SUPPORTS for the same file",
                cap_state(r, "codeql", **{"class": "python"}) == "SCANNER_SUPPORTS",
                "rows=%s" % cap(r, job="codeql"))
    # Two gaps, not one: mypy parses with the same interpreter bandit does. The harness found this
    # before the author did, which is what the harness is for.
    ok &= check("L20 ...the gap is declared BEFORE the scan: output, count, warning, summary",
                "python@.:sast-bandit/bandit" in (r.get("version_gaps") or "")
                and "python@.:code-quality/mypy" in (r.get("version_gaps") or "")
                and r.get("version_gap_count") == "2"
                and "::warning title=COVERAGE_GAP" in r["__log__"]
                and "VERSION_UNSUPPORTED" in r["__summary__"]
                and "before the scan" in r["__summary__"],
                "gaps=%s count=%s\n%s" % (r.get("version_gaps"), r.get("version_gap_count"),
                                          r["__log__"][-500:]))
    # ── and the same file under a 3.13 runner is supported -- the runner version is a control
    # surface now, which is what PO §7 said would happen the day §2.4 existed
    r = run_case(shell, {".python-version": "3.13\n"}, discover=py, inputs={"python_version": "3.13"})
    ok &= check("L20 python 3.13 vs bandit on 3.13 -> SCANNER_SUPPORTS, zero gaps",
                cap_state(r, "sast-bandit", "bandit") == "SCANNER_SUPPORTS"
                and r.get("version_gap_count") == "0", "rows=%s" % cap(r, job="sast-bandit"))

    # ── A CONSTRAINT SPANNING THE BOUNDARY IS UNDETERMINED, NOT SATISFIED ─────────────────
    r = run_case(shell, {"pyproject.toml": '[project]\nrequires-python = ">=3.9"\n'}, discover=py,
                 inputs={"python_version": "3.12"})
    ok &= check("L20 floor >=3.9 vs bandit <=3.12 -> VERSION_SUPPORT_UNDETERMINED",
                cap_state(r, "sast-bandit", "bandit") == "VERSION_SUPPORT_UNDETERMINED"
                and int(r.get("version_undetermined_count") or 0) >= 1
                and "::notice" in r["__log__"],
                "rows=%s" % cap(r, job="sast-bandit"))
    r = run_case(shell, {"pyproject.toml": '[project]\nrequires-python = ">=3.9,<3.12"\n'},
                 discover=py, inputs={"python_version": "3.12"})
    ok &= check("L20 the whole constraint set inside the range -> SCANNER_SUPPORTS",
                cap_state(r, "sast-bandit", "bandit") == "SCANNER_SUPPORTS",
                "rows=%s" % cap(r, job="sast-bandit"))
    r = run_case(shell, {"pyproject.toml": '[project]\nrequires-python = ">=3.14"\n'},
                 discover=py, inputs={"python_version": "3.12"})
    ok &= check("L20 no permitted version inside the range -> VERSION_UNSUPPORTED",
                cap_state(r, "sast-bandit", "bandit") == "VERSION_UNSUPPORTED",
                "rows=%s" % cap(r, job="sast-bandit"))

    # ── A RANGE NOBODY DECLARED IS A GAP, NOT A PASS, and says where to declare it ─────────
    r = run_case(shell, {".python-version": "3.12\n"}, discover=py, inputs={"python_version": "3.12"})
    rows = cap(r, job="sast-semgrep", **{"class": "python"})
    ok &= check("L20 semgrep python range undeclared -> VERSION_SUPPORT_UNDETERMINED naming the table",
                rows and rows[0].get("state") == "VERSION_SUPPORT_UNDETERMINED"
                and "scanner-registry.yaml" in (rows[0].get("reason") or ""), "rows=%s" % rows)

    # ── NO TARGET VERSION -> undetermined for every version-GATED tool that claims the class.
    # A lexical scanner supports an unknown version as well as a known one; it is not gated.
    r = run_case(shell, {"app/main.py": "x\n"}, discover=py)
    gated = [x for x in cap(r, **{"class": "python"}) if x.get("job") != "secret-scan"]
    states = {x.get("state") for x in gated}
    ok &= check("L20 python with no version source -> every version-gated python tool UNDETERMINED",
                states == {"VERSION_SUPPORT_UNDETERMINED"} and len(gated) >= 3,
                "states=%s rows=%d" % (states, len(gated)))

    # ── A CLASS THE SELECTOR EXCLUDED ASKS NO CAPABILITY QUESTION ───────────────────────────
    r = run_case(shell, {".python-version": "3.13\n"}, discover={"python": "false"})
    ok &= check("L20 discover python=false -> no capability rows for python",
                not cap(r, **{"class": "python"}), "rows=%s" % cap(r, **{"class": "python"}))

    # ── dotnet: the SDK on the runner bounds restore; net9.0 under 8.0.x is a gap ───────────
    dn = {"dotnet": "true"}
    csproj = ("<Project Sdk=\"Microsoft.NET.Sdk\"><PropertyGroup><TargetFramework>%s"
              "</TargetFramework></PropertyGroup></Project>\n")
    r = run_case(shell, {"src/App.csproj": csproj % "net9.0"}, discover=dn,
                 inputs={"dotnet_version": "8.0.x"})
    ok &= check("L20 net9.0 vs dotnet SDK 8.0.x -> sast-dotnet VERSION_UNSUPPORTED",
                cap_state(r, "sast-dotnet", "dotnet-sdk") == "VERSION_UNSUPPORTED",
                "rows=%s" % cap(r, job="sast-dotnet"))
    ok &= check("L20 net9.0 vs codeql csharp bounded by the same SDK -> VERSION_UNSUPPORTED",
                cap_state(r, "codeql", **{"class": "dotnet"}) == "VERSION_UNSUPPORTED",
                "rows=%s" % cap(r, job="codeql", **{"class": "dotnet"}))
    r = run_case(shell, {"src/App.csproj": csproj % "net8.0"}, discover=dn,
                 inputs={"dotnet_version": "8.0.x"})
    ok &= check("L20 net8.0 vs dotnet SDK 8.0.x -> SCANNER_SUPPORTS",
                cap_state(r, "sast-dotnet", "dotnet-sdk") == "SCANNER_SUPPORTS",
                "rows=%s" % cap(r, job="sast-dotnet"))

    # ── java: CodeQL reads 7..26, but autobuild compiles with the JDK the kit installed ────
    jv = {"java": "true"}
    pom = ("<project><properties><maven.compiler.release>%s</maven.compiler.release>"
           "</properties></project>\n")
    r = run_case(shell, {"pom.xml": pom % "21"}, discover=jv, inputs={"java_version": "17"})
    ok &= check("L20 java 21 vs JDK 17 -> codeql VERSION_UNSUPPORTED",
                cap_state(r, "codeql", **{"class": "java"}) == "VERSION_UNSUPPORTED",
                "rows=%s" % cap(r, job="codeql", **{"class": "java"}))
    r = run_case(shell, {"pom.xml": pom % "21"}, discover=jv, inputs={"java_version": "21"})
    ok &= check("L20 java 21 vs JDK 21 -> codeql SCANNER_SUPPORTS",
                cap_state(r, "codeql", **{"class": "java"}) == "SCANNER_SUPPORTS",
                "rows=%s" % cap(r, job="codeql", **{"class": "java"}))

    # ── go: CodeQL's ceiling is declared; gosec's container toolchain is not established ───
    r = run_case(shell, {"go.mod": "module x\n\ngo 1.22\n"}, discover={"go": "true"})
    ok &= check("L20 go 1.22 -> codeql SCANNER_SUPPORTS; gosec UNDETERMINED (toolchain unverified)",
                cap_state(r, "codeql", **{"class": "go"}) == "SCANNER_SUPPORTS"
                and cap_state(r, "sast-go", "gosec") == "VERSION_SUPPORT_UNDETERMINED",
                "rows=%s" % cap(r, **{"class": "go"}))

    # ── cpp: C89 is older than C23, not newer; flawfinder is lexical and unbounded ──────────
    cp = {"cpp": "true"}
    r = run_case(shell, {"CMakeLists.txt": "set(CMAKE_CXX_STANDARD 20)\nset(CMAKE_C_STANDARD 89)\n"},
                 discover=cp)
    ok &= check("L20 C++20 and C89 -> codeql SCANNER_SUPPORTS for both (standards are years)",
                {x.get("state") for x in cap(r, job="codeql", **{"class": "cpp"})} == {"SCANNER_SUPPORTS"},
                "rows=%s" % cap(r, job="codeql", **{"class": "cpp"}))
    ok &= check("L20 flawfinder unbounded -> SCANNER_SUPPORTS; cppcheck undeclared -> UNDETERMINED",
                cap_state(r, "sast-cpp", "flawfinder", kind="cxx") == "SCANNER_SUPPORTS"
                and cap_state(r, "sast-cpp", "cppcheck", kind="cxx") == "VERSION_SUPPORT_UNDETERMINED",
                "rows=%s" % cap(r, job="sast-cpp"))

    # ── the secret scanners are lexical: version-immune for every class ─────────────────────
    r = run_case(shell, {".python-version": "3.13\n"}, discover=py, inputs={"python_version": "3.12"})
    ok &= check("L20 secret-scan claims every class and is never version-gated",
                cap_state(r, "secret-scan", **{"class": "python"}) == "SCANNER_SUPPORTS",
                "rows=%s" % cap(r, job="secret-scan"))
    ok &= check("L20 the capability summary never states a percentage", "%" not in r["__summary__"])
    return ok


def sel(out, **where):
    rows = jload(out, "selection")
    if not isinstance(rows, list):
        return {}
    for r in rows:
        if all(r.get(k) == v for k, v in where.items()):
            return r
    return {}


def with_entry(shell, job, cls, tool, **fields):
    """The shipped step with ONE version_support entry rewritten -- the same heredoc the step
    reads, so the mutated table is read exactly as the registry copy is. Used to prove that a
    range nobody verified is never treated as a range: the registry carries no UNVERIFIED row
    with a declared range today, and a proof that waits for one proves nothing until then."""
    import re
    m = re.search(r"<<'JSON'\n(.*?)\nJSON\n", shell, re.S)
    table = json.loads(m.group(1))
    for entry in table[job][cls]:
        if entry["tool"] == tool:
            entry.update(fields)
    return shell[:m.start(1)] + json.dumps(table, indent=2, sort_keys=True) + shell[m.end(1):]


def plan_row(out, job):
    rows = {j.get("job"): j for j in (jload(out, "plan") or {}).get("jobs") or []}
    return rows.get(job) or {}


def selection_checks(shell):
    """KDEC-010: capability selects the scanner; PARTIAL only when no carried scanner can read it.

    For each (capability, root) the resolver picks, from the ORDERED candidates the registry
    declares for that capability (scanner-registry.yaml capability_selection), the first carried
    scanner whose declared range CAN read the target. The default cannot and another can: a
    SUBSTITUTION, labelled, never equivalence (PO section 6). None can: a VERSION_GAP, capped at
    PARTIAL, never PASS, naming the registry row that would close it. UNVERIFIED is not capable:
    a range nobody established is not a range (D-VF-4).
    """
    import yaml
    ok = True
    py = {"python": "true"}
    reg = yaml.safe_load(io.open(REG, encoding="utf-8")) or {}

    # ── THE SELECTION DATA IS IN THE REGISTRY, ORDERED, AND NAMES ONLY CARRIED SCANNERS ────
    table = reg.get("capability_selection")
    ok &= check("KDEC-010 scanner-registry.yaml declares capability_selection per capability",
                isinstance(table, dict) and "python-sast" in table and "iac" in table,
                "keys=%s" % sorted(table or {}))
    shipped = inlined_table(shell, "SELECTION")
    ok &= check("KDEC-010 the step carries the selection table as data, identical to the registry",
                shipped is not None and shipped == table,
                "shipped=%s" % (None if shipped is None else sorted(shipped)))
    vs = reg.get("version_support") or {}
    declared = {"%s/%s" % (job, e["tool"]) for job, classes in vs.items()
                for cls, entries in classes.items() for e in entries if cls != "*"}
    named = {c for row in (table or {}).values() for c in (row.get("candidates") or [])}
    ok &= check("KDEC-010 every candidate is a (job, tool) the registry declares a range for -- no invented tools",
                table and named <= declared, "unknown=%s" % sorted(named - declared))
    ok &= check("KDEC-010 every version-gated (job, tool) is a candidate for some capability",
                table and declared <= named, "unplaced=%s" % sorted(declared - named))

    # ── (a) DEFAULT UNSUPPORTED, SUBSTITUTE SUPPORTED -> THE SUBSTITUTE, LABELLED ──────────
    r = run_case(shell, {".python-version": "3.13\n", "app/main.py": "x\n"}, discover=py,
                 inputs={"python_version": "3.12"})
    row = sel(r, capability="python-sast", root=".")
    ok &= check("KDEC-010a python 3.13 on a 3.12 runner -> python-sast selects codeql/codeql in place of sast-bandit/bandit",
                row.get("default") == "sast-bandit/bandit" and row.get("selected") == "codeql/codeql"
                and row.get("state") == "SUBSTITUTION", "row=%s" % row)
    ok &= check("KDEC-010a ...the substitution is an output, labelled SUBSTITUTION, never equivalence",
                "python-sast@.:sast-bandit/bandit->codeql/codeql" in (r.get("substitutions") or "")
                and "SUBSTITUTION" in r["__summary__"] and "not equivalence" in r["__summary__"],
                "substitutions=%s" % r.get("substitutions"))
    ok &= check("KDEC-010a ...the plan routes it: codeql selected_for python-sast@., sast-bandit not_selected_for it",
                "python-sast@." in (plan_row(r, "codeql").get("selected_for") or [])
                and "python-sast@." in (plan_row(r, "sast-bandit").get("not_selected_for") or []),
                "codeql=%s bandit=%s" % (plan_row(r, "codeql"), plan_row(r, "sast-bandit")))
    # mypy parses with the same interpreter bandit does and python-quality has no other candidate,
    # so that capability is a genuine gap on the same tree: code-quality is capped, and nothing
    # else is. A proof that expected "nothing capped" here was wrong, and the harness said so.
    ok &= check("KDEC-010a ...sast-bandit is a not-selected job; only python-quality (mypy, no substitute) is a gap",
                "sast-bandit" in (r.get("not_selected_jobs") or "").split()
                and (r.get("capped_jobs") or "").split() == ["code-quality"]
                and r.get("capability_gaps") == "python-quality@." and r.get("capability_gap_count") == "1",
                "not_selected=%s capped=%s gaps=%s" % (r.get("not_selected_jobs"), r.get("capped_jobs"),
                                                       r.get("capability_gaps")))
    # control: the default CAN read it -> SERVED by the default, no substitution at all
    r = run_case(shell, {".python-version": "3.12\n", "app/main.py": "x\n"}, discover=py,
                 inputs={"python_version": "3.12"})
    row = sel(r, capability="python-sast", root=".")
    ok &= check("KDEC-010a control: python 3.12 on 3.12 -> SERVED by sast-bandit/bandit, no substitution",
                row.get("selected") == "sast-bandit/bandit" and row.get("state") == "SERVED"
                and not r.get("substitutions"), "row=%s" % row)

    # ── (b) NO CARRIED SCANNER CAN READ IT -> VERSION_GAP, PARTIAL, NEVER PASS, ROW NAMED ────
    # Terraform 9.0.0 sits above both corpus-measured IaC ranges (0.12..1.14 since D-VF-4; 1.6.0
    # was the case here while both ranges were UNVERIFIED).
    r = run_case(shell, {"infra/main.tf": 'terraform {\n  required_version = "= 9.0.0"\n}\n'},
                 discover={"iac": "true"})
    row = sel(r, capability="iac", root="infra")
    ok &= check("KDEC-010b terraform 9.0.0 -> iac has no capable scanner: VERSION_GAP, nothing selected",
                row.get("selected") is None and row.get("state") == "VERSION_GAP", "row=%s" % row)
    ok &= check("KDEC-010b ...the gap is an output, iac-scan is capped, and the summary says PARTIAL never PASS",
                "iac@infra" in (r.get("capability_gaps") or "").split(",")
                and r.get("capability_gap_count") == "1"
                and "iac-scan" in (r.get("capped_jobs") or "").split()
                and "PARTIAL" in r["__summary__"] and "never PASS" in r["__summary__"],
                "gaps=%s capped=%s" % (r.get("capability_gaps"), r.get("capped_jobs")))
    ok &= check("KDEC-010b ...and names the registry row that would close it",
                "scanner-registry.yaml" in (row.get("closes") or "")
                and "iac-scan/checkov" in (row.get("closes") or ""), "closes=%s" % row.get("closes"))
    # D-10: CODE SCANNING GOVERNS PUBLICATION, NOT ANALYSIS. On the first Level 2 dispatch
    # (run 38817782084) the probe read UNAVAILABLE and CodeQL analysed anyway: nine retained
    # results, only upload-sarif refused. So the pre-flight does not withdraw the candidate; it is
    # recorded against publication, and the gate's CodeQL rows follow the job's own evidence.
    for cs in ("UNAVAILABLE", "NOT_CONFIGURED"):
        r = run_case(shell, {".python-version": "3.13\n", "app/main.py": "x\n"}, discover=py,
                     inputs={"python_version": "3.12", "code_scanning": cs})
        row = sel(r, capability="python-sast", root=".")
        cq = next((c for c in row.get("candidates") or [] if c.get("scanner") == "codeql/codeql"), {})
        ok &= check("D-10 code scanning %s -> codeql still the substitute (analysis runs; publication refused)" % cs,
                    row.get("state") == "SUBSTITUTION" and row.get("selected") == "codeql/codeql"
                    and cq.get("state") == "SCANNER_SUPPORTS" and cq.get("publication") == cs
                    and "publication" in (cq.get("reason") or ""), "row=%s" % row)
        ok &= check("D-10 ...nothing is capped on the pre-flight: python-sast is no gap (%s)" % cs,
                    "python-sast@." not in (r.get("capability_gaps") or "").split(",")
                    and "sast-semgrep" not in (r.get("capped_jobs") or "").split()
                    and "cannot run here" not in r["__log__"] + r["__summary__"],
                    "gaps=%s capped=%s" % (r.get("capability_gaps"), r.get("capped_jobs")))
    # control: no pre-flight answer -> no publication note on the candidate
    r = run_case(shell, {".python-version": "3.13\n", "app/main.py": "x\n"}, discover=py,
                 inputs={"python_version": "3.12", "code_scanning": "ENABLED"})
    row = sel(r, capability="python-sast", root=".")
    cq = next((c for c in row.get("candidates") or [] if c.get("scanner") == "codeql/codeql"), {})
    ok &= check("D-10 control: code scanning ENABLED -> codeql selected, no publication caveat",
                row.get("selected") == "codeql/codeql" and cq.get("publication") is None, "row=%s" % row)

    # ── (c) UNVERIFIED IS NOT CAPABLE, even with a range written in ─────────────────────────
    mutant = with_entry(shell, "sast-semgrep", "python", "semgrep", min="3.0", max="3.99",
                        verified="UNVERIFIED")
    r = run_case(mutant, {".python-version": "3.13\n", "app/main.py": "x\n"}, discover=py,
                 inputs={"python_version": "3.12"})
    row = sel(r, capability="python-sast", root=".")
    ok &= check("KDEC-010c an UNVERIFIED range covering the target -> VERSION_SUPPORT_UNDETERMINED, not selected",
                cap_state(r, "sast-semgrep", "semgrep", **{"class": "python"}) == "VERSION_SUPPORT_UNDETERMINED"
                and row.get("selected") == "codeql/codeql"
                and "UNVERIFIED" in (cap(r, job="sast-semgrep", **{"class": "python"}) or [{}])[0].get("reason", ""),
                "rows=%s sel=%s" % (cap(r, job="sast-semgrep", **{"class": "python"}), row))
    verified = with_entry(shell, "sast-semgrep", "python", "semgrep", min="3.0", max="3.99",
                          verified="READ")
    r = run_case(verified, {".python-version": "3.13\n", "app/main.py": "x\n"}, discover=py,
                 inputs={"python_version": "3.12"})
    row = sel(r, capability="python-sast", root=".")
    ok &= check("KDEC-010c ...the same range READ -> selected ahead of codeql (order is preference)",
                row.get("selected") == "sast-semgrep/semgrep" and row.get("state") == "SUBSTITUTION",
                "row=%s" % row)
    # undetermined is not capable: gosec's range is undeclared, so go is served by codeql or not at all
    r = run_case(shell, {"go.mod": "module x\n\ngo 1.22\n"}, discover={"go": "true"})
    row = sel(r, capability="go-sast", root=".")
    ok &= check("KDEC-010c go 1.22, gosec undeclared -> codeql substitutes; gosec never SERVES undetermined",
                row.get("state") == "SUBSTITUTION" and row.get("selected") == "codeql/codeql",
                "row=%s" % row)
    r = run_case(shell, {"go.mod": "module x\n\ngo 1.99\n"}, discover={"go": "true"})
    row = sel(r, capability="go-sast", root=".")
    ok &= check("KDEC-010c go 1.99 above codeql's 1.27, gosec undeclared -> VERSION_GAP, sast-go capped",
                row.get("state") == "VERSION_GAP" and "sast-go" in (r.get("capped_jobs") or "").split(),
                "row=%s capped=%s" % (row, r.get("capped_jobs")))

    # ── the resolver's own fail-safe: no selection is not an empty selection ──────────────
    broken = run_case(shell, {"app/main.py": "x\n"}, discover=py, break_python=True)
    ok &= check("KDEC-010 resolver failure -> capability_gap_count UNDETERMINED, no job capped by a count nobody took",
                broken.get("capability_gap_count") == "UNDETERMINED" and broken.get("selection") == "[]"
                and (broken.get("capped_jobs") or "") == "", "out=%s" % {k: v for k, v in broken.items() if "cap" in k})
    ok &= check("KDEC-010 the selection summary never states a percentage", "%" not in r["__summary__"])
    return ok


def proven_gap_checks(shell):
    """KDEC-014 / D-VF-4: the IaC ranges are corpus-proven, and only a MEASURED gap is enforced.

    tests/corpora/probe_iac_corpus.py ran the pinned checkov and trivy over the seeded Terraform
    corpus and wrote READ ranges. From then on a target ABOVE both ranges is a gap the ranges
    establish -- proven_gap_jobs names iac-scan and uat/prod refuse it. A gap whose cause is the
    TARGET, not the ranges -- no required_version anywhere, or a floor (">= 1.5.0") that spans the
    measured ceiling -- is VERSION_SUPPORT_UNDETERMINED for every candidate; nothing measured that
    no scanner can read the code, so it is recorded, never enforced. Were it enforced, every
    Terraform repository without an exact pin, and every repository with a Dockerfile and no
    Terraform, would be refused at prod: the permanently-red failure the ledger names (B-03).
    """
    import yaml
    ok = True
    ia = {"iac": "true"}
    reg = yaml.safe_load(io.open(REG, encoding="utf-8")) or {}
    rows = {e.get("tool"): e for e in (((reg.get("version_support") or {}).get("iac-scan") or {})
                                         .get("iac") or [])}
    ok &= check("D-VF-4 checkov and trivy-config IaC ranges are READ and name their corpus",
                all((rows.get(t) or {}).get("verified") == "READ"
                    and (rows.get(t) or {}).get("corpus") == "tests/corpora/terraform_corpus.py"
                    and (rows.get(t) or {}).get("min") and (rows.get(t) or {}).get("max")
                    for t in ("checkov", "trivy-config")),
                "rows=%s" % rows)
    # inside the measured range -> SERVED by the default, no gap at all
    r = run_case(shell, {"infra/main.tf": 'terraform {\n  required_version = "= 1.6.0"\n}\n'},
                 discover=ia)
    row = sel(r, capability="iac", root="infra")
    ok &= check("D-VF-4 terraform = 1.6.0 inside the measured range -> SERVED by checkov",
                row.get("state") == "SERVED" and row.get("selected") == "iac-scan/checkov"
                and "iac-scan" not in (r.get("capped_jobs") or "").split(), "row=%s" % row)
    # above every measured range -> a gap the READ ranges establish: enforced at uat/prod
    r = run_case(shell, {"infra/main.tf": 'terraform {\n  required_version = "= 9.0.0"\n}\n'},
                 discover=ia)
    row = sel(r, capability="iac", root="infra")
    ok &= check("KDEC-014 terraform = 9.0.0 above both measured ranges -> VERSION_GAP, READ, proven",
                row.get("state") == "VERSION_GAP" and row.get("gap_ranges") == "READ"
                and row.get("established") is True
                and (r.get("proven_gap_jobs") or "").split() == ["iac-scan"],
                "row=%s proven=%r" % (row, r.get("proven_gap_jobs")))
    # a floor spanning the ceiling: the TARGET is undetermined, the ranges are not the cause
    r = run_case(shell, {"infra/main.tf": 'terraform {\n  required_version = ">= 1.5.0"\n}\n'},
                 discover=ia)
    row = sel(r, capability="iac", root="infra")
    ok &= check("KDEC-014 terraform >= 1.5.0 spans the ceiling -> a recorded gap, NOT proven",
                row.get("state") == "VERSION_GAP" and row.get("established") is False
                and "iac-scan" in (r.get("capped_jobs") or "").split()
                and "iac-scan" not in (r.get("proven_gap_jobs") or "").split(),
                "row=%s proven=%r" % (row, r.get("proven_gap_jobs")))
    # no version declared anywhere: the repository, not the scanner, is the gap
    r = run_case(shell, {"infra/main.tf": 'resource "x" "y" {}\n', "Dockerfile": "FROM scratch\n"},
                 discover=ia)
    row = sel(r, capability="iac", root=".")
    ok &= check("KDEC-014 IaC with no required_version -> a recorded gap, NOT proven",
                row.get("state") == "VERSION_GAP" and row.get("established") is False
                and "iac-scan" not in (r.get("proven_gap_jobs") or "").split(),
                "row=%s proven=%r" % (row, r.get("proven_gap_jobs")))
    # the same rule where a READ range already existed before the corpus: mypy's ceiling is the
    # runner interpreter, and a Python tree with no version source is not a proven gap either
    r = run_case(shell, {"app/main.py": "x\n"}, discover={"python": "true"},
                 inputs={"python_version": "3.12"})
    ok &= check("KDEC-014 python with no version source -> code-quality capped, NOT proven",
                "code-quality" in (r.get("capped_jobs") or "").split()
                and "code-quality" not in (r.get("proven_gap_jobs") or "").split(),
                "capped=%r proven=%r" % (r.get("capped_jobs"), r.get("proven_gap_jobs")))
    r = run_case(shell, {"pyproject.toml": '[project]\nrequires-python = ">=3.9"\n'},
                 discover={"python": "true"}, inputs={"python_version": "3.12"})
    ok &= check("KDEC-014 requires-python >=3.9 on a 3.12 runner -> NOT a proven gap",
                "code-quality" not in (r.get("proven_gap_jobs") or "").split(),
                "proven=%r" % r.get("proven_gap_jobs"))
    # control: a definite answer from a READ range IS proven (python 3.13 on a 3.12 runner, mypy)
    r = run_case(shell, {".python-version": "3.13\n", "app/main.py": "x\n"}, discover={"python": "true"},
                 inputs={"python_version": "3.12"})
    ok &= check("KDEC-014 control: python 3.13 on a 3.12 runner -> python-quality is a proven gap",
                "code-quality" in (r.get("proven_gap_jobs") or "").split(),
                "proven=%r" % r.get("proven_gap_jobs"))
    return ok


def php_checks(doc, shell):
    """PHP, an ecosystem (lane L-PHP, 2026-10-21): its version sources feed resolution like every
    other class, its capability rows are DATA in the registry with an honest `verified:` level,
    and an UNVERIFIED range is never capable (KDEC-010) and never enforced (KDEC-014).

    Sources, strongest first: .php-version (exact); composer.json config.platform.php (exact --
    the version Composer resolves FOR); composer.json require.php (a constraint, never rounded to a
    version); composer.lock platform-overrides.php / platform.php (the same two, as the lock
    recorded them, read only where composer.json said nothing); a Dockerfile FROM php:<v> (exact).
    """
    import yaml
    ok = True
    ph = {"php": "true"}
    job = (doc.get("jobs") or {}).get(JOB) or {}
    use = next((s for s in job.get("steps") or [] if s.get("uses") == USES), {})
    ok &= check("PHP the resolve job passes discover's php answer",
                str((use.get("with") or {}).get("discovered-php", "")).strip()
                == "${{ steps.d.outputs.php }}", "with=%s" % (use.get("with") or {}))

    r = run_case(shell, {"web/composer.json": '{"require": {"php": "^8.1"}}\n',
                         "web/index.php": "<?php echo 1;\n"}, discover=ph)
    rec = one(r, **{"class": "php", "root": "web"})
    rg = rec.get("range") or {}
    ok &= check("PHP composer.json require.php ^8.1 -> constraint 8.1 .. <9, never a version",
                rec.get("strength") == "constraint" and rec.get("version") is None
                and rg.get("min") == "8.1" and rg.get("max") == "9" and rg.get("max_inclusive") is False
                and rec.get("source") == "web/composer.json:require.php", "rec=%s" % rec)
    r = run_case(shell, {"composer.json": '{"require": {"php": ">=7.4"},'
                                          ' "config": {"platform": {"php": "8.2.12"}}}\n'},
                 discover=ph)
    rec = one(r, **{"class": "php"})
    ok &= check("PHP config.platform.php 8.2.12 outranks require.php -> exact 8.2.12",
                rec.get("strength") == "exact" and rec.get("version") == "8.2.12"
                and rec.get("source") == "composer.json:config.platform.php", "rec=%s" % rec)
    r = run_case(shell, {".php-version": "8.3\n", "composer.json": '{"require": {"php": "^8.1"}}\n'},
                 discover=ph)
    recs = records(r, **{"class": "php"}) or []
    ok &= check("PHP .php-version outranks composer.json -> exact 8.3, one record",
                len(recs) == 1 and recs[0].get("version") == "8.3"
                and recs[0].get("source") == ".php-version", "recs=%s" % recs)
    r = run_case(shell, {"composer.lock": '{"packages": [], "platform": {"php": ">=8.0 <8.4"}}\n'},
                 discover=ph)
    rec = one(r, **{"class": "php"})
    ok &= check("PHP composer.lock platform.php, no composer.json -> constraint from the lock",
                rec.get("strength") == "constraint" and (rec.get("range") or {}).get("min") == "8.0"
                and rec.get("source") == "composer.lock:platform.php", "rec=%s" % rec)
    r = run_case(shell, {"Dockerfile": "FROM php:8.2-apache\n", "index.php": "<?php\n"}, discover=ph)
    rec = one(r, **{"class": "php"})
    ok &= check("PHP Dockerfile FROM php:8.2-apache -> exact 8.2",
                rec.get("version") == "8.2" and rec.get("source") == "Dockerfile:FROM", "rec=%s" % rec)
    r = run_case(shell, {"a/composer.json": '{"require": {"php": "8.1.*"}}\n',
                         "b/composer.json": '{"config": {"platform": {"php": "8.3.0"}}}\n'}, discover=ph)
    roots = sorted((x.get("root"), x.get("strength")) for x in (records(r, **{"class": "php"}) or []))
    ok &= check("PHP two composer roots -> two records, never one repository-wide version",
                roots == [("a", "constraint"), ("b", "exact")], "roots=%s" % roots)

    # COULD NOT READ IS NOT FOUND NOTHING; NOTHING DECLARED IS A GAP THAT NAMES ITS REMEDY.
    r = run_case(shell, {"composer.json": '{"require": {"php": '}, discover=ph)
    rec = one(r, **{"class": "php"})
    ok &= check("PHP unparseable composer.json -> unreadable, state DISCOVERY_PARTIAL",
                rec.get("strength") == "unreadable" and r.get("state") == "DISCOVERY_PARTIAL",
                "rec=%s state=%s" % (rec, r.get("state")))
    r = run_case(shell, {"src/index.php": "<?php echo 1;\n",
                         "composer.json": '{"require": {"monolog/monolog": "^3"}}\n'}, discover=ph)
    rec = one(r, **{"class": "php"})
    ok &= check("PHP present, no PHP version declared -> strength none, remedy named",
                rec.get("strength") == "none" and ".php-version" in (rec.get("remediation") or "")
                and "require.php" in (rec.get("remediation") or ""), "rec=%s" % rec)
    r = run_case(shell, {".php-version": "8.3\n"}, discover={"php": "false"})
    ok &= check("PHP discover php=false -> no capability rows for php",
                not cap(r, **{"class": "php"}), "rows=%s" % cap(r, **{"class": "php"}))

    # THE CAPABILITY ROW IS DATA, HONEST ABOUT WHAT ESTABLISHED IT.
    reg = yaml.safe_load(io.open(REG, encoding="utf-8")) or {}
    row = (((reg.get("version_support") or {}).get("sast-semgrep") or {}).get("php") or [{}])[0]
    ok &= check("PHP registry: sast-semgrep/semgrep declares a php row with a verified level",
                row.get("tool") == "semgrep" and row.get("verified") in ("READ", "UNVERIFIED")
                and (row.get("verified") != "READ" or row.get("corpus")), "row=%s" % row)
    capsel = (reg.get("capability_selection") or {}).get("php-sast") or {}
    ok &= check("PHP registry: php-sast is a capability, served by sast-semgrep/semgrep",
                capsel.get("class") == "php" and capsel.get("candidates") == ["sast-semgrep/semgrep"],
                "row=%s" % capsel)
    r = run_case(shell, {"composer.json": '{"config": {"platform": {"php": "8.2.0"}}}\n',
                         "index.php": "<?php\n"}, discover=ph)
    s = sel(r, capability="php-sast", root=".")
    st = cap_state(r, "sast-semgrep", "semgrep", **{"class": "php"})
    if row.get("verified") != "READ":
        ok &= check("PHP 8.2 on an UNVERIFIED semgrep row -> UNDETERMINED, VERSION_GAP, capped, NOT proven",
                    st == "VERSION_SUPPORT_UNDETERMINED" and s.get("state") == "VERSION_GAP"
                    and s.get("gap_ranges") == "UNVERIFIED" and s.get("established") is False
                    and "sast-semgrep" in (r.get("capped_jobs") or "").split()
                    and "sast-semgrep" not in (r.get("proven_gap_jobs") or "").split(),
                    "state=%s sel=%s capped=%r" % (st, s, r.get("capped_jobs")))
    else:
        # A READ row (tests/corpora/php_corpus.py) is a range resolve can hold a target against:
        # inside it -> SERVED; above it -> a gap the READ range ESTABLISHES (KDEC-014: enforced at
        # uat/prod); a floor spanning its ceiling -> the TARGET is undetermined, recorded only.
        lo, hi = str(row.get("min")), str(row.get("max"))
        above = "%d.0" % (int(hi.split(".")[0]) + 1)
        r = run_case(shell, {".php-version": lo + "\n", "index.php": "<?php\n"}, discover=ph)
        s = sel(r, capability="php-sast", root=".")
        ok &= check("PHP %s inside the measured %s..%s -> SERVED by sast-semgrep, not capped" % (lo, lo, hi),
                    s.get("state") == "SERVED" and s.get("selected") == "sast-semgrep/semgrep"
                    and "sast-semgrep" not in (r.get("capped_jobs") or "").split(), "sel=%s" % s)
        r = run_case(shell, {".php-version": above + "\n", "index.php": "<?php\n"}, discover=ph)
        s = sel(r, capability="php-sast", root=".")
        ok &= check("PHP %s above the measured ceiling %s -> VERSION_GAP, READ, proven" % (above, hi),
                    s.get("state") == "VERSION_GAP" and s.get("gap_ranges") == "READ"
                    and s.get("established") is True
                    and "sast-semgrep" in (r.get("proven_gap_jobs") or "").split(),
                    "sel=%s proven=%r" % (s, r.get("proven_gap_jobs")))
        # PHP 8.5: SCAN WHAT PARSES, FLAG THE REST (owner, 2026-10-22; KDEC-016 amended). Above
        # the read ceiling and up to the row's MEASURED parse_evidence_max, Semgrep reports what it
        # cannot parse per file (PartialParsing), so the job's parse evidence decides coverage:
        # SERVED here, never a VERSION_GAP by declaration alone, and never proven at uat/prod. Above
        # parse_evidence_max (9.0, checked above) KDEC-014 stands. FAILS ON 2cd078e: 8.5 was a
        # proven VERSION_GAP refused at uat/prod.
        pe = str(row.get("parse_evidence_max") or "")
        ok &= check("PHP registry: the row's parse_evidence_max is above its read ceiling %s (8.5 "
                    "is handled by parse evidence)" % hi,
                    bool(pe) and tuple(int(x) for x in pe.split(".")) > tuple(int(x) for x in hi.split("."))
                    and "parse evidence" in (row.get("basis") or ""), "row=%s" % row)
        for target in ("8.5", "8.5.12"):
            r = run_case(shell, {".php-version": target + "\n", "index.php": "<?php\n"}, discover=ph)
            s = sel(r, capability="php-sast", root=".")
            st = cap_state(r, "sast-semgrep", "semgrep", **{"class": "php"})
            ok &= check("PHP %s above the read ceiling %s, inside parse evidence %s -> SERVED, not "
                        "capped, not proven (the job's parse evidence decides)" % (target, hi, pe),
                        s.get("state") == "SERVED" and st == "SCANNER_SUPPORTS"
                        and "sast-semgrep" not in (r.get("capped_jobs") or "").split()
                        and "sast-semgrep" not in (r.get("proven_gap_jobs") or "").split()
                        and "parse evidence" in json.dumps(s),
                        "sel=%s state=%s capped=%r" % (s, st, r.get("capped_jobs")))
        r = run_case(shell, {"composer.json": '{"require": {"php": ">=%s"}}\n' % lo,
                             "index.php": "<?php\n"}, discover=ph)
        s = sel(r, capability="php-sast", root=".")
        ok &= check("PHP require >=%s spans the ceiling -> a recorded gap, NOT proven" % lo,
                    s.get("state") == "VERSION_GAP" and s.get("established") is False
                    and "sast-semgrep" in (r.get("capped_jobs") or "").split()
                    and "sast-semgrep" not in (r.get("proven_gap_jobs") or "").split(),
                    "sel=%s proven=%r" % (s, r.get("proven_gap_jobs")))
    c = cov(r, "php")
    ok &= check("PHP coverage: .php files counted as class php, never a percentage",
                c.get("files_in_scope") == 1 and "%" not in r["__summary__"], "row=%s" % c)
    ok &= check("PHP is no longer an unclaimed class in coverage",
                not cov(r, "PHP"), "row=%s" % cov(r, "PHP"))
    return ok


def cov(out, cls):
    rows = jload(out, "coverage")
    if not isinstance(rows, list):
        return {}
    for r in rows:
        if r.get("class") == cls:
            return r
    return {}


def coverage_checks(shell):
    """L24: class-and-count coverage. PIPELINE_ORDERING §5.3: files_in_scope, enumeration,
    covered_by, coverage_basis -- and NEVER a percentage, because a percentage over a
    class-level denominator is a number whose units nobody can name."""
    ok = True
    tree = {".python-version": "3.12\n", "app/a.py": "x\n", "app/b.py": "x\n", "lib/c.py": "x\n",
            "native/core.rs": "x\n", "native/util.rs": "x\n",
            "node_modules/dep/index.js": "x\n",
            ".github/workflows/ci.yml": "on: push\n",
            "infra/main.tf": "x\n", "build/Dockerfile": "FROM scratch\n"}
    r = run_case(shell, tree, discover={"python": "true", "iac": "true"},
                 inputs={"python_version": "3.12"})
    p = cov(r, "python")
    ok &= check("L24 python: files_in_scope is a count (3), enumeration COMPLETE",
                p.get("files_in_scope") == 3 and p.get("enumeration") == "COMPLETE", "row=%s" % p)
    ok &= check("L24 python: covered_by lists the tools whose version check passed",
                "sast-bandit/bandit" in (p.get("covered_by") or [])
                and "codeql/codeql" in (p.get("covered_by") or []), "row=%s" % p)
    ok &= check("L24 python: coverage_basis is scope inference, never named-in-output",
                p.get("coverage_basis") == "scope-inference", "row=%s" % p)
    rs = cov(r, "Rust")
    ok &= check("L24 Rust: counted (2), covered by nothing, basis none -- a COVERAGE_GAP with a count",
                rs.get("files_in_scope") == 2 and rs.get("covered_by") == []
                and rs.get("coverage_basis") == "none", "row=%s" % rs)
    ok &= check("L24 node_modules is excluded from every count", not cov(r, "node"),
                "row=%s" % cov(r, "node"))
    ok &= check("L24 workflow YAML is a counted class",
                cov(r, "GitHubActionsWorkflow").get("files_in_scope") == 1,
                "row=%s" % cov(r, "GitHubActionsWorkflow"))
    # LANE L-SCAN-A (KDEC-025): workflows, shell and PowerShell are no longer gaps. A class with no
    # version to discover is covered by the registry's READ rows for it, on scope inference.
    r2 = run_case(shell, dict(tree, **{"ops/a.sh": "x\n", "ops/b.ps1": "x\n"}),
                  discover={"python": "true", "iac": "true", "workflows": "true", "shell": "true",
                            "powershell": "true"}, inputs={"python_version": "3.12"})
    for cls, tools in (("GitHubActionsWorkflow", ["deps-scan/actionlint", "deps-scan/zizmor"]),
                       ("Shell", ["deps-scan/shellcheck"]),
                       ("PowerShell", ["deps-scan/psscriptanalyzer"])):
        row = cov(r2, cls)
        ok &= check("L-SCAN-A %s covered by %s, scope inference, never a COVERAGE_GAP" % (cls, tools),
                    row.get("covered_by") == tools and row.get("coverage_basis") == "scope-inference"
                    and "COVERAGE_GAP" not in (row.get("note") or ""), "row=%s" % row)
    ok &= check("L24 iac counts .tf and Dockerfile", cov(r, "iac").get("files_in_scope") == 2,
                "row=%s" % cov(r, "iac"))
    rows = jload(r, "coverage") or []
    forbidden = {"percent", "percentage", "pct", "ratio", "fraction", "coverage_percent"}
    ok &= check("L24 no row carries a percentage or a ratio",
                all(not (set(row) & forbidden) and not any(isinstance(v, float) for v in row.values())
                    for row in rows)
                and "%" not in r["__summary__"], "keys=%s" % sorted({k for row in rows for k in row}))

    # ── a version gap removes the tool from covered_by and names it in not_covered_by ──────
    r = run_case(shell, {".python-version": "3.13\n", "app/a.py": "x\n"}, discover={"python": "true"},
                 inputs={"python_version": "3.12"})
    p = cov(r, "python")
    ok &= check("L24 VERSION_UNSUPPORTED -> not in covered_by, named in not_covered_by",
                "sast-bandit/bandit" not in (p.get("covered_by") or [])
                and any(x.startswith("sast-bandit/bandit") and "VERSION_UNSUPPORTED" in x
                        for x in (p.get("not_covered_by") or []))
                and "codeql/codeql" in (p.get("covered_by") or []), "row=%s" % p)

    # ── ENUMERATION IS PARTIAL WHEN THE WALK DID NOT REACH EVERYTHING, and says how much ───
    deep = {"a/b/c/d/e/f/g/h/i/deep.py": "x\n", "top.py": "x\n"}
    r = run_case(shell, deep, discover={"python": "true"})
    p = cov(r, "python")
    ok &= check("L24 a file beyond the walk depth -> enumeration PARTIAL with the unreached count",
                p.get("enumeration") == "PARTIAL" and p.get("files_in_scope") == 1
                and int(p.get("unreached_dirs") or 0) >= 1, "row=%s" % p)
    ok &= check("L24 ...and the summary says PARTIAL, not a percentage",
                "PARTIAL" in r["__summary__"] and "%" not in r["__summary__"])
    return ok


def toolchain_checks(shell):
    """V-03 (PIPELINE_ORDERING 1.4), the resolve half: the toolchain is chosen FROM THE TARGET.

    The runner toolchain is a caller input, and resolve only compared against it -- so python 3.13
    code on the 3.12 default was a gap the kit itself created. resolve now names, per runner input
    that bounds a scanner (max_from_input), the version the discovered targets need, and says
    loudly when the input is below it. Exact pins only: a floor or a range is not a version to
    install (a constraint is not a version). The setup steps USING it are the flagship's half.
    """
    ok = True
    py = {"python": "true"}
    r = run_case(shell, {".python-version": "3.13\n", "app/main.py": "x\n",
                         "svc/.python-version": "3.11\n"}, discover=py, inputs={"python_version": "3.12"})
    tc = ((jload(r, "plan") or {}).get("toolchain") or {}).get("python_version") or {}
    ok &= check("V-03 python 3.13 and 3.11 roots on a 3.12 runner -> recommend 3.13, below target",
                tc.get("runner") == "3.12" and tc.get("recommended") == "3.13"
                and tc.get("below_target") is True and ".python-version" in (tc.get("from") or [])
                and "::warning title=Runner toolchain below the target" in r["__log__"], "tc=%s" % tc)
    r = run_case(shell, {".python-version": "3.12\n"}, discover=py, inputs={"python_version": "3.12"})
    tc = ((jload(r, "plan") or {}).get("toolchain") or {}).get("python_version") or {}
    ok &= check("V-03 control: python 3.12 on 3.12 -> recommended 3.12, not below, no warning",
                tc.get("recommended") == "3.12" and tc.get("below_target") is False
                and "Runner toolchain below the target" not in r["__log__"], "tc=%s" % tc)
    r = run_case(shell, {"pyproject.toml": '[project]\nrequires-python = ">=3.9"\n'}, discover=py,
                 inputs={"python_version": "3.12"})
    tc = ((jload(r, "plan") or {}).get("toolchain") or {}).get("python_version") or {}
    ok &= check("V-03 a floor (>=3.9) is not a version to install -> no recommendation, said so",
                tc.get("recommended") is None and tc.get("below_target") is None
                and "exact" in (tc.get("why") or ""), "tc=%s" % tc)
    csproj = ("<Project Sdk=\"Microsoft.NET.Sdk\"><PropertyGroup><TargetFramework>net9.0"
              "</TargetFramework></PropertyGroup></Project>\n")
    r = run_case(shell, {"src/App.csproj": csproj}, discover={"dotnet": "true"},
                 inputs={"dotnet_version": "8.0.x"})
    tc = ((jload(r, "plan") or {}).get("toolchain") or {}).get("dotnet_version") or {}
    ok &= check("V-03 net9.0 on SDK 8.0.x -> recommend 9.0, below target",
                tc.get("recommended") == "9.0" and tc.get("below_target") is True, "tc=%s" % tc)
    return ok


def plan_checks(shell):
    """L22: an ADVISORY execution plan, emitted as data before anything runs, that nothing
    enforces. docs/architecture/EXECUTION_PLANNING.md §3 (shape), §4 (refusals), §6 (what the
    advisory object proves)."""
    import yaml
    ok = True
    reg = yaml.safe_load(io.open(REG, encoding="utf-8")) or {}
    scanners = sorted(j for j, row in (reg.get("jobs") or {}).items()
                      if (row or {}).get("class") == "scanner")

    r = run_case(shell, {".python-version": "3.13\n", "app/main.py": "x\n"},
                 discover={"python": "true", "node": "", "go": "false"},
                 inputs={"python_version": "3.12", "image_ref": "", "enable_sbom": "false"},
                 event="push")
    plan = jload(r, "plan")
    ok &= check("L22 a plan object is emitted", isinstance(plan, dict), r.get("plan", "")[:200])
    if not isinstance(plan, dict):
        return False
    ok &= check("L22 the plan says it is advisory and enforced by nothing",
                plan.get("advisory") is True and plan.get("enforced_by") == "nothing",
                "advisory=%s enforced_by=%s" % (plan.get("advisory"), plan.get("enforced_by")))
    rows = {j.get("job"): j for j in plan.get("jobs") or []}
    ok &= check("L22 every scanner-class job in the registry has a row (refusal 3)",
                sorted(rows) == scanners, "missing=%s extra=%s" % (sorted(set(scanners) - set(rows)),
                                                                   sorted(set(rows) - set(scanners))))
    ok &= check("L22 push -> depth merge, with the protected-branch assumption stated",
                (plan.get("context") or {}).get("depth") == "merge"
                and "protected" in str((plan.get("context") or {}).get("depth_basis")),
                "context=%s" % plan.get("context"))
    ok &= check("L22 python true -> sast-bandit run, reason RUN",
                rows.get("sast-bandit", {}).get("decision") == "run"
                and rows.get("sast-bandit", {}).get("reason") == "RUN", rows.get("sast-bandit"))
    ok &= check("L22 go false -> sast-go skip, reason NOT_APPLICABLE",
                rows.get("sast-go", {}).get("decision") == "skip"
                and rows.get("sast-go", {}).get("reason") == "NOT_APPLICABLE", rows.get("sast-go"))
    # code-quality's real condition is python OR node (the ESLint-behind-a-Python-gate fix). With
    # python present the JOB runs whatever node is; "any true wins" at job granularity.
    ok &= check("L22 python true, node unknown -> code-quality run (any true wins, rule python|node)",
                rows.get("code-quality", {}).get("decision") == "run"
                and rows.get("code-quality", {}).get("applies") == "discover.python|discover.node",
                rows.get("code-quality"))
    r2 = run_case(shell, {"app/main.py": "x\n"}, discover={"python": ""}, event="push")
    rows2 = {j.get("job"): j for j in (jload(r2, "plan") or {}).get("jobs") or []}
    ok &= check("L22 python unknown -> sast-bandit forced, reason UNDETERMINED_PRESENT (refusal 2)",
                rows2.get("sast-bandit", {}).get("decision") == "forced"
                and rows2.get("sast-bandit", {}).get("reason") == "UNDETERMINED_PRESENT"
                and (jload(r2, "plan") or {}).get("decisions", {}).get("sast-bandit") == "forced",
                rows2.get("sast-bandit"))
    ok &= check("L22 VERSION_UNSUPPORTED rides on the row and the decision stays run (refusal 1)",
                "VERSION_UNSUPPORTED" in (rows.get("sast-bandit", {}).get("capability_states") or [])
                and rows.get("sast-bandit", {}).get("decision") == "run", rows.get("sast-bandit"))
    ok &= check("L22 empty image_ref -> image-scan skip NOT_APPLICABLE; enable_sbom false -> sbom skip DISABLED",
                rows.get("image-scan", {}).get("reason") == "NOT_APPLICABLE"
                and rows.get("sbom", {}).get("decision") == "skip"
                and rows.get("sbom", {}).get("reason") == "DISABLED",
                "image=%s sbom=%s" % (rows.get("image-scan"), rows.get("sbom")))
    ok &= check("L22 a flat decisions map exists for a workflow if: expression",
                (plan.get("decisions") or {}).get("sast-bandit") == "run"
                and (plan.get("decisions") or {}).get("sast-go") == "skip", plan.get("decisions"))
    ok &= check("L22 declared gaps travel with the plan",
                "python@.:sast-bandit/bandit" in ((plan.get("declared_gaps") or {}).get("version_gaps") or []),
                plan.get("declared_gaps"))
    ok &= check("L22 every job carries its JOB_TOPOLOGY group",
                all(j.get("group") for j in rows.values()), [j for j in rows.values() if not j.get("group")])

    for event, depth in (("pull_request", "pr"), ("schedule", "nightly")):
        r = run_case(shell, {"app/main.py": "x\n"}, discover={"python": "true"}, event=event)
        p = jload(r, "plan") or {}
        ok &= check("L22 %s -> depth %s with its depth_settings row" % (event, depth),
                    (p.get("context") or {}).get("depth") == depth
                    and isinstance(p.get("depth_settings"), dict), p.get("context"))
    r = run_case(shell, {"app/main.py": "x\n"}, discover={"python": "true"}, event="workflow_dispatch")
    p = jload(r, "plan") or {}
    ok &= check("L22 workflow_dispatch -> depth null, basis names the owner decision",
                (p.get("context") or {}).get("depth") is None
                and "EXECUTION_PLANNING" in str((p.get("context") or {}).get("depth_basis")),
                p.get("context"))
    r = run_case(shell, {"app/main.py": "x\n"}, discover={"python": "true", "state": "DISCOVERY_UNAVAILABLE"})
    p = jload(r, "plan") or {}
    ok &= check("L22 DISCOVERY_UNAVAILABLE -> every job forced, nothing is coverage",
                p.get("survey") == "DISCOVERY_UNAVAILABLE"
                and all(j.get("decision") == "forced" for j in p.get("jobs") or []),
                [(j.get("job"), j.get("decision")) for j in p.get("jobs") or []][:6])
    ok &= check("L22 the design document exists and is marked for owner review",
                os.path.exists(os.path.join(ROOT, "docs", "architecture", "EXECUTION_PLANNING.md"))
                and "owner review" in io.open(os.path.join(ROOT, "docs", "architecture",
                                                            "EXECUTION_PLANNING.md"), encoding="utf-8").read())
    return ok


def extract_platform_shell(doc):
    return extract_step(doc, "platform")


# A stand-in for `gh` so the step can be run without a repository or a token. The real step
# calls exactly one endpoint; the stand-in answers it the way GitHub does in each situation and
# leaves a marker in the log so a test can prove the call did or did not happen.
FAKE_GH = """
gh() {
  # The marker goes to a FILE, not stderr: the real step captures stderr with stdout on purpose,
  # because the refusal text is the evidence when the endpoint says no.
  echo "fake-gh-called $*" >> "$fake_gh_log"
  case "${fake_gh:-}" in
    list)     printf '[{"number":1,"state":"open"},{"number":2,"state":"open"}]' ;;
    empty)    printf '[]' ;;
    disabled) echo "gh: Dependabot alerts are disabled for this repository. (HTTP 403)" >&2; return 1 ;;
    refuse)   echo "gh: Resource not accessible by integration (HTTP 403)" >&2; return 1 ;;
    garbage)  printf 'not json' ;;
    # Two pages, the way `gh api --paginate` prints them (one JSON array per page, concatenated);
    # without --paginate only the first page comes back.
    pages)    printf '[{"number":1,"state":"open"},{"number":2,"state":"open"}]'
              case " $* " in *" --paginate "*) printf '[{"number":3,"state":"open"}]' ;; esac ;;
    *)        echo "gh: no fake mode set" >&2; return 1 ;;
  esac
}
"""


def run_platform_case(shell, platform=None, fake_gh="refuse", prelude=""):
    """Run the real platform step with discover's platform outputs fed as env."""
    tmp = tempfile.mkdtemp(prefix="resolve-platform-")
    outfile = os.path.join(tmp, "gh_output")
    summary = os.path.join(tmp, "gh_summary")
    try:
        io.open(outfile, "w").close()
        io.open(summary, "w").close()
        script = os.path.join(tmp, "p.sh")
        io.open(script, "w", encoding="utf-8", newline="\n").write(FAKE_GH + prelude + shell)
        p = dict(ghas_available="true", code_scanning="ENABLED", secret_scanning="ENABLED",
                 push_protection="ENABLED", dependabot_alerts="ENABLED", dependabot_updates="ENABLED",
                 dependabot_config="PRESENT", visibility="private", platform_source="security_and_analysis")
        p.update(platform or {})
        ghlog = os.path.join(tmp, "gh_calls")
        io.open(ghlog, "w").close()
        env = dict(os.environ, GITHUB_OUTPUT=outfile, GITHUB_STEP_SUMMARY=summary,
                   GITHUB_REPOSITORY="example/repo", fake_gh=fake_gh, fake_gh_log=ghlog)
        for k, v in p.items():
            env["p_" + k] = v
        r = subprocess.run([_bash(), script], cwd=tmp, env=env, capture_output=True, text=True)
        out = {}
        for line in io.open(outfile, encoding="utf-8"):
            if "=" in line:
                k, v = line.rstrip("\n").split("=", 1)
                out[k] = v
        out["__summary__"] = io.open(summary, encoding="utf-8").read()
        out["__log__"] = (r.stdout or "") + (r.stderr or "")
        out["__gh_calls__"] = io.open(ghlog, encoding="utf-8").read()
        out["__rc__"] = r.returncode
        return out
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


def platform_checks(doc):
    """L25: the platform-probe values get consumers. PIPELINE_ORDERING §6.1-6.4.

    Dependabot alerts are read into scanner_state where the platform allows; NOT_CONFIGURED and
    UNAVAILABLE are reported against a named OWNER ROLE with a named action; a private
    unlicensed repository is a declared COVERAGE_GAP for interprocedural dataflow, never a
    substitution presented as parity.
    """
    ok = True
    shell = extract_platform_shell(doc)
    ok &= check("L25 the resolve composite has a platform step", bool(shell))
    if not shell:
        return False
    outputs = ((doc.get("jobs") or {}).get(JOB) or {}).get("outputs") or {}
    ok &= check("L25 dependabot_state and platform_owners are job outputs",
                "dependabot_state" in outputs and "platform_owners" in outputs, sorted(outputs))

    # ── alerts read into scanner_state, in the same words as every other scanner ─────────
    r = run_platform_case(shell, fake_gh="list")
    ok &= check("L25 two open alerts -> dependabot_state FINDINGS, count 2",
                r.get("dependabot_state") == "FINDINGS" and r.get("dependabot_open_alerts") == "2",
                "out=%s" % {k: v for k, v in r.items() if not k.startswith("__")})
    ok &= check("L25 ...the basis records that there is no SARIF behind it",
                "no SARIF" in (r.get("dependabot_basis") or ""), r.get("dependabot_basis"))
    # every page, not the first: the first page alone undercounts past 100 open alerts (RES:1803)
    r = run_platform_case(shell, fake_gh="pages")
    ok &= check("L25 alerts across two pages -> all counted (3), not the first page's 2",
                r.get("dependabot_state") == "FINDINGS" and r.get("dependabot_open_alerts") == "3"
                and "first page" not in (r.get("dependabot_basis") or ""),
                "count=%s basis=%s" % (r.get("dependabot_open_alerts"), r.get("dependabot_basis")))
    r = run_platform_case(shell, fake_gh="empty")
    ok &= check("L25 zero open alerts, endpoint answered -> PASS, count 0",
                r.get("dependabot_state") == "PASS" and r.get("dependabot_open_alerts") == "0",
                "out=%s" % r.get("dependabot_state"))

    # ── A REFUSAL IS NEVER PASS ───────────────────────────────────────────────────────────
    r = run_platform_case(shell, fake_gh="refuse")
    ok &= check("L25 endpoint refused -> UNAVAILABLE with the refusal quoted, never PASS",
                r.get("dependabot_state") == "UNAVAILABLE" and "not accessible" in (r.get("dependabot_basis") or ""),
                "state=%s basis=%s" % (r.get("dependabot_state"), r.get("dependabot_basis")))
    r = run_platform_case(shell, fake_gh="disabled")
    ok &= check("L25 endpoint says disabled -> UNAVAILABLE, owner role repository administrator",
                r.get("dependabot_state") == "UNAVAILABLE"
                and r.get("dependabot_owner_role") == "repository administrator",
                "state=%s role=%s" % (r.get("dependabot_state"), r.get("dependabot_owner_role")))
    r = run_platform_case(shell, fake_gh="garbage")
    ok &= check("L25 endpoint answered unparseably -> COLLECTION_FAILED, never PASS",
                r.get("dependabot_state") == "COLLECTION_FAILED", r.get("dependabot_state"))

    # ── NOT_CONFIGURED is reported against a named owner role, and nothing is called ──────
    r = run_platform_case(shell, platform={"dependabot_alerts": "NOT_CONFIGURED"}, fake_gh="list")
    ok &= check("L25 discover says NOT_CONFIGURED -> UNAVAILABLE, no API call, owner role named",
                r.get("dependabot_state") == "UNAVAILABLE"
                and "fake-gh-called" not in r["__gh_calls__"]
                and r.get("dependabot_owner_role") == "repository administrator"
                and "NOT_CONFIGURED" in r["__summary__"] and "repository administrator" in r["__summary__"],
                "state=%s role=%s calls=%s" % (r.get("dependabot_state"), r.get("dependabot_owner_role"),
                                                r["__gh_calls__"][-300:]))
    owners = jload(r, "platform_owners") or []
    ok &= check("L25 platform_owners names a role and an action for every platform-owned state",
                any(o.get("capability") == "dependabot_alerts" and o.get("state") == "NOT_CONFIGURED"
                    and o.get("owner_role") == "repository administrator" and o.get("action")
                    for o in owners), "owners=%s" % owners)
    ok &= check("L25 an owner is a ROLE, never a person or an account",
                owners and all("@" not in str(o.get("owner_role")) for o in owners), "owners=%s" % owners)

    # ── the CodeQL half: unlicensed refuses PUBLICATION; it does not establish a dataflow gap ──
    # D-10: run 38817782084 read code scanning UNAVAILABLE and CodeQL analysed anyway. So the
    # pre-flight cannot say dataflow is missing (that was COVERAGE_GAP and "No CodeQL runs"); the
    # CodeQL job's own evidence decides. UNKNOWN here, owner still the organisation (licensing).
    r = run_platform_case(shell, platform={"ghas_available": "false", "code_scanning": "UNAVAILABLE"},
                          fake_gh="empty")
    ok &= check("D-10 code_scanning UNAVAILABLE -> dataflow_capability UNKNOWN (the job decides), owner organisation",
                r.get("dataflow_capability") == "UNKNOWN"
                and "No CodeQL runs" not in r["__log__"] + r["__summary__"]
                and "publication" in r["__log__"]
                and any(o.get("capability") == "code_scanning" and "organisation" in str(o.get("owner_role"))
                        for o in (jload(r, "platform_owners") or [])),
                "cap=%s owners=%s" % (r.get("dataflow_capability"), jload(r, "platform_owners")))
    ok &= check("D-10 ...and the summary still says substitution is not parity",
                "not parity" in r["__summary__"] or "not equivalence" in r["__summary__"],
                r["__summary__"][-500:])
    r = run_platform_case(shell, platform={"code_scanning": "UNKNOWN", "ghas_available": "unknown",
                                           "platform_source": "none"}, fake_gh="empty")
    ok &= check("L25 code_scanning UNKNOWN -> dataflow_capability UNKNOWN, owner workflow maintainer",
                r.get("dataflow_capability") == "UNKNOWN"
                and any(o.get("capability") == "code_scanning" and "maintainer" in str(o.get("owner_role"))
                        for o in (jload(r, "platform_owners") or [])),
                "cap=%s" % r.get("dataflow_capability"))
    r = run_platform_case(shell, platform={"code_scanning": "ENABLED"}, fake_gh="empty")
    ok &= check("L25 code_scanning ENABLED -> dataflow_capability ordinary",
                r.get("dataflow_capability") == "ordinary", r.get("dataflow_capability"))

    # ── the config file's absence has an owner too ─────────────────────────────────────────
    r = run_platform_case(shell, platform={"dependabot_config": "ABSENT"}, fake_gh="empty")
    ok &= check("L25 dependabot.yml ABSENT -> owner repository maintainer, action names the file",
                any(o.get("capability") == "dependabot_config" and "maintainer" in str(o.get("owner_role"))
                    and "dependabot.yml" in str(o.get("action")) for o in (jload(r, "platform_owners") or [])),
                "owners=%s" % jload(r, "platform_owners"))

    # ── the step cannot fail the job: a broken jq is COLLECTION_FAILED, exit 0 ───────────
    r = run_platform_case(shell, fake_gh="list", prelude="jq() { return 1; }\n")
    ok &= check("L25 count tooling broken -> COLLECTION_FAILED, exit 0 (the scanners still run)",
                r.get("dependabot_state") == "COLLECTION_FAILED" and r["__rc__"] == 0,
                "state=%s rc=%s" % (r.get("dependabot_state"), r["__rc__"]))
    ok &= check("L25 the platform summary never states a percentage", "%" not in r["__summary__"])
    return ok


def main():
    try:
        doc = load_workflow()
    except ImportError:
        print("UNKNOWN: PyYAML unavailable. Failure to observe is not an observation.")
        return 2
    ok = position_checks(doc)
    shell = extract_resolve_shell(doc)

    # ── L21 · the step runs, and says so ─────────────────────────────────────────────────
    plain = run_case(shell, {"README.md": "x\n"})
    ok &= check("L21 plain tree -> state COMPLETE, exit 0",
                plain.get("state") == "COMPLETE" and plain["__rc__"] == 0,
                "state=%s rc=%s\n%s" % (plain.get("state"), plain["__rc__"], plain["__log__"][-800:]))

    # THE ONE THAT MATTERS MOST. If the resolver cannot run, nothing it would have established
    # is established -- and the scanners must still run. Fail SAFE, loudly, exit 0.
    broken = run_case(shell, {"app/main.py": "x\n"}, discover={"python": "true"}, break_python=True)
    ok &= check("L21 resolver failure -> DISCOVERY_UNAVAILABLE, exit 0, never COMPLETE",
                broken.get("state") == "DISCOVERY_UNAVAILABLE" and broken["__rc__"] == 0,
                "state=%s rc=%s" % (broken.get("state"), broken["__rc__"]))
    ok &= check("L21 resolver failure is announced as an error",
                "::error" in broken["__log__"], broken["__log__"][-400:])

    ok &= version_checks(shell)
    ok &= capability_checks(shell)
    ok &= selection_checks(shell)
    ok &= proven_gap_checks(shell)
    ok &= php_checks(doc, shell)
    ok &= coverage_checks(shell)
    ok &= platform_checks(doc)
    ok &= plan_checks(shell)
    ok &= toolchain_checks(shell)

    print()
    if not ok:
        print("::error title=Resolve contract violated::The position between discover and the "
              "scanners does not do what the design says. A version that is never asked is a "
              "zero that is never readable.")
        return 1
    print("resolve: all cases hold")
    return 0


if __name__ == "__main__":
    sys.exit(main())

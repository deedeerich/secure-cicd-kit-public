#!/usr/bin/env bash
# Short per-job result block. Runs at the end of every scanner job.
#
# WHY THIS EXISTS ALONGSIDE THE CONSOLIDATED REPORT
#     The consolidated `report` job owns normalisation, cross-scanner dedupe, correlation,
#     remediation detail and disposition, because those are only possible where every finding is
#     visible at once. That is not a reason for a scanner job to stay silent.
#
#     Someone debugging Semgrep is IN the Semgrep job. Making them leave it to discover whether it
#     found anything is how "the pipeline is noise" becomes true. So the scanner prints what it
#     alone knows -- did it run, how many findings, was SARIF produced -- and points at the
#     consolidated job for what it cannot know.
#
# DELIBERATELY NOT A SECOND COPY OF THE CONTRACT
#     No severity interpretation, no remediation, no gate verdict, no disposition. Those live in
#     exactly one place. A contract implemented twice drifts twice, and this kit has the scars:
#     fourteen Azure gitleaks rules and a flawfinder fix both lost to a second copy.
#
# THE ZERO RULE APPLIES HERE TOO
#     A job that did not run, or produced no parseable SARIF, prints NOT ESTABLISHED. It never
#     prints 0. Zero says someone looked.
#
# USAGE   scan_status <name> <execution> <sarif-or-empty> [scope]
scan_status() {
  _name="$1"; _exec="$2"; _sarif="${3:-}"; _scope="${4:-}"
  _out="${GITHUB_STEP_SUMMARY:-/dev/stdout}"

  _n="NOT ESTABLISHED"; _sar="NOT GENERATED"
  if [ -n "$_sarif" ] && [ -s "$_sarif" ]; then
    # suppression: FAILURE_ISOLATION_WITH_STATE_CAPTURE -- jq's failure IS the signal here, and
    # it is captured rather than swallowed: a non-zero exit takes the else branch and reports
    # INVALID plus "count unavailable from current parser". stderr is silenced because the parse
    # error text is not useful in a summary block; the STATE survives and is published. If this
    # fails in a way other than "not valid SARIF" -- jq missing, file unreadable -- the result is
    # the same and is still not a clean zero, which is the outcome that matters.
    # A PARSEABLE REPORT IS NOT YET A REPORT THAT SOMEONE LOOKED (ledger L05). Before a count
    # may be printed, the SARIF must evidence a run that attempted and did not fail -- the same
    # reading the validity rows apply (PIPELINE_ORDERING section 4.5, rows 3-6):
    #   no runs                                    the tool reported nothing about a run
    #   a run with `results` absent or null        "did not attempt" (SARIF 3.14.23)
    #   an error-level tool notification           "SHALL mean that the run failed" (3.20.21);
    #                                              bandit writes exactly this, exit 0, for a
    #                                              file it could not parse
    #   executionSuccessful false                  (3.20.14)
    # Each prints NOT ESTABLISHED, never 0. tests/prove_scan_status_zero.py.
    _why=""
    if _v=$(jq -r '
        if (.runs | type) != "array" or (.runs | length) == 0 then "no run is recorded in the report"
        elif any(.runs[]; (.results | type) != "array") then "a run has no results array -- it did not attempt"
        elif any(.runs[]; any((.invocations // [])[]; ((.toolExecutionNotifications // []) + (.toolConfigurationNotifications // [])) | any(.level == "error"))) then "the tool reported an error-level notification -- the run failed"
        elif any(.runs[]; any((.invocations // [])[]; .executionSuccessful == false)) then "the tool reported executionSuccessful false"
        else "" end' "$_sarif" 2>/dev/null); then
      _why="$_v"
    fi
    if [ -n "$_why" ]; then
      _sar="GENERATED -- $_why"
      _n="NOT ESTABLISHED"
    elif _c=$(jq '[.runs[].results[]] | length' "$_sarif" 2>/dev/null); then
      _sar="GENERATED"
      # Only a scanner that actually completed may report a count. A crashed run that happens to
      # have left a partial report behind must not publish a number from it.
      case "$_exec" in
        COMPLETE) _n="$_c" ;;
        *)        _n="NOT ESTABLISHED" ;;
      esac
    else
      # A file that is not valid SARIF is a collection failure wearing a report's clothes.
      _sar="INVALID"
      _n="PRESENT -- count unavailable from current parser"
    fi
  fi

  {
    printf '### %s\n\n' "$_name"
    printf '| | |\n|---|---|\n'
    printf '| Execution | %s |\n' "$_exec"
    [ -n "$_scope" ] && printf '| Scope | %s |\n' "$_scope"
    printf '| Findings | %s |\n' "$_n"
    printf '| SARIF | %s |\n' "$_sar"
    printf '\n'
    if [ "$_n" = "NOT ESTABLISHED" ]; then
      printf 'This is not zero. Nothing usable was collected for this scope in this run.\n\n'
    fi
    printf 'Severity breakdown, remediation, gate impact and disposition are in the\n'
    printf '**Security scan report** job, which sees every scanner at once and can tell\n'
    printf 'when two tools are describing the same condition.\n\n'
  } >> "$_out"

  printf '%s: execution=%s findings=%s sarif=%s\n' "$_name" "$_exec" "$_n" "$_sar"
}

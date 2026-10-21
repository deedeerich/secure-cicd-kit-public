#!/usr/bin/env bash
# PER-STEP state capture. ONE RECORD PER SCANNER, NEVER ONE PER JOB.
#
# WHY THIS EXISTS
#     scripts/scan_status.sh reported once per JOB, from `job.status`, because one job held
#     exactly one scanner. Grouping SAST by LANGUAGE breaks that identity: sast-python holds
#     ruff/mypy, bandit and the CodeQL Python analysis, and a single verdict for three
#     scanners is the collapse this kit exists to refuse. The registered taxonomy already
#     says so outright, in scanner_state.rule:
#
#         "Every scanner reports its OWN state. After job consolidation job != scanner, so a
#          job-level result must never stand in for one of these."
#
#     So state is captured per STEP, written to one file per scanner, and consolidated by the
#     report and the gate from those files rather than from `needs.<job>.result`.
#
# FOUR OUTCOMES THAT MUST NEVER COLLAPSE INTO EACH OTHER
#     NOT_APPLICABLE          the artefact class is not present. Evidence-backed absence.
#     UNAVAILABLE / selector  the artefact IS present and the consumer turned this scanner
#                             off. discovery_state=EXCLUDED_BY_SELECTOR. Nothing looked, and
#                             that was a decision somebody made.
#     PASS                    a scanner ran, completed, and found nothing. Somebody looked.
#     COLLECTION_FAILED       a scanner ran and produced no usable report -- an empty but
#                             well-formed nothing, indistinguishable from clean unless said.
#
#     COVERAGE_GAP IS DELIBERATELY NOT IN THAT LIST. It is a coverage_state/discovery_state
#     fact about an artefact class for which this kit ships NO capable scanner, established
#     once by `discover` and surfaced by the gate. A scanner cannot report it about itself,
#     and this function REFUSES to write it, because a scanner-level COVERAGE_GAP would be
#     the same collapse in the other direction.
#
# TOLERANCE IS RECORDED, OR IT IS NOT TOLERATED
#     Every scanner step in a merged job carries `continue-on-error: true`, because one
#     scanner's crash must not deny its siblings the chance to produce evidence, and because
#     an `enforce` step that exits 1 would otherwise abort every scanner queued behind it.
#     Bare `continue-on-error: true` is EXACTLY the shape of the soft_fail_sast defect this
#     kit already shipped once, where a softened run "was reported identically to one that
#     passed honestly". The difference here is that the outcome is CAPTURED as explicit state
#     that propagates to the gate, and ANNOUNCED on the step summary and as a workflow
#     annotation. Suppression class: FAILURE_ISOLATION_WITH_STATE_CAPTURE.
#
#     And the recording is MANDATORY, not incidental: `assert_states` below refuses to let a
#     job finish while any scanner it declared has no record, because a scanner with no record
#     is indistinguishable from a scanner that was never meant to run.
#
# ONLY COMPLETE MAY CARRY A FINDING COUNT -- the execution_state rule. A scanner that did not
# finish cannot report 0, and cannot report a number scraped from a partial report.
#
# USAGE
#     record_state <scanner> <scope> [sarif-path-or-empty]
#
# ENVIRONMENT (all optional; defaults are the safe direction, never the clean one)
#     SELECTED    true|false    the consumer's selector for THIS scanner. Default true.
#     APPLICABLE  true|false|unknown  did discovery find this artefact class. Default true.
#                               unknown == discovery could not establish it; run and say so.
#     OUTCOME     the scanner step's `outcome` -- success|failure|skipped|cancelled|empty
#     ENFORCED    the paired enforce step's `outcome`, where one exists. empty means none.
#     PRESET      a scanner_state this scanner established for itself (CodeQL does), which
#                 overrides the derivation below. Must be a registered scanner_state value.
#     D_STATE     the discover job's discovery_state.
STATE_DIR="${STATE_DIR:-/tmp/_scanstate}"

record_state() {
  _sc="$1"; _scope="${2:-}"; _sarif="${3:-}"
  _sel="${SELECTED:-true}"; _appl="${APPLICABLE:-true}"; _oc="${OUTCOME:-}"
  _enf="${ENFORCED:-}"; _pre="${PRESET:-}"; _ds="${D_STATE:-COMPLETE}"
  _sum="${GITHUB_STEP_SUMMARY:-/dev/stdout}"
  mkdir -p "$STATE_DIR"

  # Defaults are the UNESTABLISHED direction on purpose. If none of the branches below fires,
  # the record says "nothing was established here", which is the only safe thing an unfinished
  # derivation may say.
  _st=UNAVAILABLE          # scanner_state
  _exec=NOT_RUN            # execution_state
  _pa=APPLICABLE           # platform_applicability
  _disc=RUN                # discovery_state
  _why=INFRASTRUCTURE_UNKNOWN   # execution_unavailable_reason, or empty
  _n="NOT ESTABLISHED"     # findings, NEVER 0 unless somebody looked
  _pub=NONE                # publication_state
  _looked=false            # did any tool actually examine this artefact class
  _tol=none                # was a failure tolerated here, and recorded

  if [ "$_sel" != "true" ]; then
    # TURNED OFF IS NOT CLEAN AND IS NOT INAPPLICABLE. The artefact may well be sitting
    # there; a decision was made not to look at it, and that decision is the record.
    _st=UNAVAILABLE; _exec=NOT_RUN; _pa=NOT_CONFIGURED
    _disc=EXCLUDED_BY_SELECTOR; _why=POLICY_REFUSED
    echo "::warning title=${_sc}: EXCLUDED_BY_SELECTOR::This scanner was switched off by the"
    echo "caller's configuration. Nothing looked at ${_scope:-this scope}. That is NOT a clean"
    echo "result and NOT NOT_APPLICABLE -- the artefact class may be present and unexamined."
  elif [ "$_appl" = "false" ]; then
    # Evidence-backed absence. discover searched and found nothing of this kind.
    _st=NOT_APPLICABLE; _exec=NOT_RUN; _pa=NOT_APPLICABLE
    _disc=NOT_APPLICABLE; _why=""
  elif [ "$_appl" = "unknown" ] || [ "$_ds" = "DISCOVERY_UNAVAILABLE" ]; then
    # UNKNOWN IS NOT FALSE. Applicability could not be established, so this is run anyway and
    # whatever happened is reported as unestablished scope rather than as absence.
    _pa=UNKNOWN; _disc=UNDETERMINED_PRESENT
    case "$_oc" in
      success) _st=PASS; _exec=COMPLETE; _looked=true; _why="" ;;
      failure) _st=FAILED; _exec=FAILED; _looked=true; _why=""; _tol=recorded ;;
      *)       _st=UNAVAILABLE; _exec=NOT_RUN; _why=DISCOVERY_UNAVAILABLE ;;
    esac
  else
    case "$_oc" in
      success)   _st=PASS;        _exec=COMPLETE; _looked=true; _why="" ;;
      failure)   _st=FAILED;      _exec=FAILED;   _looked=true; _why=""; _tol=recorded ;;
      cancelled) _st=UNAVAILABLE; _exec=NOT_RUN;  _why=INFRASTRUCTURE_UNKNOWN ;;
      skipped)   _st=UNAVAILABLE; _exec=NOT_RUN;  _why=INFRASTRUCTURE_UNKNOWN ;;
      "")        _st=UNAVAILABLE; _exec=NOT_RUN;  _why=INFRASTRUCTURE_UNKNOWN ;;
      *)         _st=UNAVAILABLE; _exec=NOT_RUN;  _why=INFRASTRUCTURE_UNKNOWN ;;
    esac
  fi

  # CODEQL ESTABLISHES ITS OWN STATE, because "GHAS is not licensed on this repository" is a
  # platform fact that no step outcome distinguishes from a crash, and all four of UNAVAILABLE,
  # NOT_CONFIGURED, NOT_APPLICABLE and a genuine failure render as the same thing in the UI.
  # This lived in a 37-line `CodeQL — declare state` step. With CodeQL now folded into six
  # language jobs, that step would have been SIX copies of one contract -- the exact duplication
  # that took this file over GitHub's ceiling. It is one branch of the canonical recorder instead.
  if [ -n "${CQ_INIT:-}" ]; then
    if [ "$CQ_INIT" != "success" ]; then
      _pre=UNAVAILABLE
      echo "::warning title=${_sc}: UNAVAILABLE::CodeQL did NOT run. On a private repository this"
      echo "normally means GitHub Advanced Security is not enabled. The build is NOT failed for"
      echo "that -- but this is unestablished scope, not a clean result. Nothing here proves the"
      echo "absence of what CodeQL would have found."
    elif [ "${CQ_ANALYZE:-}" != "success" ]; then
      _pre=COLLECTION_FAILED
      echo "::warning title=${_sc}: COLLECTION_FAILED::CodeQL initialised and analysis did not"
      echo "complete. Treat as unestablished, not as zero findings."
    fi
    # WHICH QUERIES RAN IS PART OF THE RESULT. "CodeQL: 0 findings" means something different
    # under the precision-tuned default suite than under security-extended, and a reader who
    # cannot see which one ran cannot tell those apart.
    printf '| Query suite | `%s` |\n' "${CQ_QUERIES:-NOT ESTABLISHED}" >> "$_sum"
    printf '| Taint tracking | included in security-extended and security-and-quality |\n' >> "$_sum"
  fi

  # A scanner that establishes its own state overrides the derivation above. It may only widen
  # the claim downwards, never upwards to PASS.
  case "$_pre" in
    "") : ;;
    PASS) : ;;
    FINDINGS|PARTIAL|NOT_APPLICABLE|FAILED|UNAVAILABLE|COLLECTION_FAILED)
      _st="$_pre"
      case "$_pre" in
        FAILED)            _exec=FAILED ;;
        COLLECTION_FAILED) _exec=COLLECTION_FAILED; _looked=true ;;
        UNAVAILABLE)       _exec=NOT_RUN ;;
      esac
      ;;
    *)
      echo "::error title=${_sc}: unregistered state::PRESET='${_pre}' is not a scanner_state"
      echo "value in assurance-taxonomy.yaml. Recorded as UNAVAILABLE rather than invented."
      _st=UNAVAILABLE; _exec=NOT_RUN
      ;;
  esac

  # THE COUNT, AND ONLY WHERE A COUNT IS LEGITIMATE.
  if [ "$_exec" = "COMPLETE" ]; then
    if [ -n "$_sarif" ] && [ -s "$_sarif" ]; then
      # suppression: FAILURE_ISOLATION_WITH_STATE_CAPTURE -- jq's failure IS the signal, and it
      # is captured: the else branch records COLLECTION_FAILED rather than a clean zero.
      # discards: jq's stderr text, which is not useful in a summary block
      # preserved_by: the COLLECTION_FAILED state written below and carried to the gate
      if _c=$(jq '[.runs[].results[]] | length' "$_sarif" 2>/dev/null); then
        _pub=REPORT_STRUCTURALLY_VALID
        _n="$_c"
        if [ "$_c" = "0" ]; then _st=PASS; else _st=FINDINGS; fi
      else
        # A file that is not valid SARIF is a collection failure wearing a report's clothes.
        _st=COLLECTION_FAILED; _exec=COLLECTION_FAILED
        _pub=REPORT_PRODUCED
        _n="PRESENT -- count unavailable from current parser"
        echo "::warning title=${_sc}: COLLECTION_FAILED::A report exists at '${_sarif}' and does"
        echo "not parse as SARIF. This is NOT zero findings; nothing usable was collected."
      fi
    elif [ -n "$_sarif" ]; then
      # The scanner said it completed and produced no report. An EMPTY BUT WELL-FORMED
      # nothing is the single most dangerous output in this kit.
      _st=COLLECTION_FAILED; _exec=COLLECTION_FAILED; _pub=NONE
      echo "::warning title=${_sc}: COLLECTION_FAILED::The scanner completed and no report was"
      echo "produced at '${_sarif}'. Not a clean result -- there is nothing to have been clean."
    else
      # Scanners with no SARIF channel at all (linters, `dotnet list --vulnerable`, SBOM
      # generation). Their own exit status IS the result, and it was success.
      _pub=ANALYSIS_COMPLETE
      _n="0 (no SARIF channel; scanner exited clean)"
    fi
  fi

  # ENFORCEMENT IS A SEPARATE AXIS FROM DETECTION, and always has been in this kit. The
  # scanner says what it found; the paired enforce step says whether policy blocks on it.
  # soft_fail_sast and advisory_mode act HERE and nowhere else, so a softened run records
  # FINDINGS with gate=ALLOWED -- visibly different from a run that recorded PASS.
  _gate=UNDETERMINED
  case "$_st" in
    PASS|NOT_APPLICABLE) _gate=ALLOWED ;;
    FINDINGS)
      case "$_enf" in
        failure) _gate=BLOCKED; _tol=recorded ;;
        success) _gate=ALLOWED ;;
        *)       _gate=ALLOWED ;;
      esac
      ;;
    FAILED) _gate=BLOCKED ;;
    *)      _gate=UNDETERMINED ;;
  esac
  # An enforce step that failed is a block even when the detection channel produced no count.
  if [ "$_enf" = "failure" ]; then _gate=BLOCKED; _tol=recorded; fi

  # SURFACED, NOT ONLY RECORDED. A state written to a file nobody reads until the gate is a
  # state the engineer standing in this job cannot see.
  if [ "$_tol" = "recorded" ]; then
    echo "::error title=${_sc}: failure TOLERATED and RECORDED::This step was allowed to fail so"
    echo "its siblings could still produce evidence. scanner_state=${_st} gate=${_gate}. The run"
    echo "is NOT reported as one that passed honestly -- the gate reads this record."
  fi

  jq -n --arg sc "$_sc" --arg st "$_st" --arg ex "$_exec" --arg pa "$_pa" \
        --arg ds "$_disc" --arg wh "$_why" --arg sp "$_scope" --arg sa "$_sarif" \
        --arg fn "$_n" --arg pb "$_pub" --arg gt "$_gate" --arg tl "$_tol" \
        --arg lk "$_looked" \
    '{scanner:$sc, scanner_state:$st, execution:$ex, applicability:$pa,
      discovery:$ds, unavailable_reason:$wh, scope:$sp, sarif:$sa,
      findings:$fn, publication:$pb, gate:$gt, tolerated:$tl, looked:$lk,
      artifact:(if $sa == "" then "NONE" else "RETAINED" end),
      upload:(if $pb == "NONE" then "NONE" else "COMPLETE" end)}' \
    > "$STATE_DIR/state-$_sc.json"

  {
    printf '### %s\n\n' "$_sc"
    printf '| | |\n|---|---|\n'
    printf '| scanner_state | %s |\n' "$_st"
    printf '| execution_state | %s |\n' "$_exec"
    printf '| applicability | %s |\n' "$_pa"
    printf '| discovery_state | %s |\n' "$_disc"
    [ -n "$_scope" ] && printf '| Scope | %s |\n' "$_scope"
    printf '| Findings | %s |\n' "$_n"
    printf '| Enforcement | %s |\n' "$_gate"
    [ -n "$_why" ] && printf '| Unavailable because | %s |\n' "$_why"
    printf '\n'
    case "$_st" in
      NOT_APPLICABLE) printf 'Searched and none found. Evidence-backed absence, not silence.\n\n' ;;
      UNAVAILABLE)    printf 'This is not zero and not inapplicable. Nothing looked.\n\n' ;;
      COLLECTION_FAILED) printf 'A scanner ran and produced nothing usable. Not a clean result.\n\n' ;;
    esac
    printf 'Severity, correlation, remediation and disposition are in the **Security scan\n'
    printf 'report** job, which sees every scanner at once.\n\n'
  } >> "$_sum"

  printf '%s: scanner_state=%s execution=%s applicability=%s findings=%s gate=%s\n' \
    "$_sc" "$_st" "$_exec" "$_pa" "$_n" "$_gate"
}

# assert_states <scanner> [scanner...]
#
# THE RECORDING IS MANDATORY, NOT INCIDENTAL. Each merged job declares the scanners it owns
# and this runs last. A declared scanner with no record is not a scanner that was skipped --
# it is a hole in the evidence, and it is written down as COLLECTION_FAILED and then failed,
# because a silent hole is the one failure mode that reads as green.
#
# It runs AFTER the state artifact is uploaded, deliberately: failing before the upload would
# destroy the very records that explain the failure.
assert_states() {
  _missing=""
  mkdir -p "$STATE_DIR"
  for _want in "$@"; do
    if [ ! -s "$STATE_DIR/state-$_want.json" ]; then
      _missing="${_missing}${_missing:+ }${_want}"
      jq -n --arg sc "$_want" \
        '{scanner:$sc, scanner_state:"COLLECTION_FAILED", execution:"COLLECTION_FAILED",
          applicability:"UNKNOWN", discovery:"UNDETERMINED_PRESENT",
          unavailable_reason:"INFRASTRUCTURE_UNKNOWN", scope:"", sarif:"",
          findings:"NOT ESTABLISHED", publication:"NONE", gate:"UNDETERMINED",
          tolerated:"none", looked:"false", artifact:"NONE", upload:"NONE"}' \
        > "$STATE_DIR/state-$_want.json"
    fi
  done
  if [ -n "$_missing" ]; then
    echo "::error title=Scanner state NOT RECORDED::This job declared scanners that wrote no"
    echo "state: ${_missing}. A declared scanner with no record is a hole in the evidence, and"
    echo "a hole reads as green. Each is recorded COLLECTION_FAILED and this job fails."
    return 1
  fi
  echo "every declared scanner recorded a state: $*"
  return 0
}

# coverage_note <applicability> <artefact-class> <scanner> [scanner...]
#
# A GREEN JOB IS NOT COVERAGE. Within a merged job, the artefact class can be PRESENT while
# every scanner pointed at it failed, was unlicensed, or was switched off -- a row of records
# that are each individually honest and collectively mean nobody looked. Said here, in the job
# the engineer is already standing in, using coverage_state vocabulary.
coverage_note() {
  _appl="$1"; _class="$2"; shift 2
  [ "$_appl" = "true" ] || return 0
  _any=false
  for _s in "$@"; do
    if [ -s "$STATE_DIR/state-$_s.json" ]; then
      if [ "$(jq -r '.looked' "$STATE_DIR/state-$_s.json")" = "true" ]; then _any=true; fi
    fi
  done
  if [ "$_any" = "false" ]; then
    echo "::warning title=COVERAGE_UNDETERMINED for ${_class}::This artefact class IS present and"
    echo "not one scanner in this job examined it. Each record above is honest on its own and"
    echo "together they mean nothing looked. Not blocked, and not clean."
    printf '| (coverage) | %s | COVERAGE_UNDETERMINED -- present, nothing examined it |\n' \
      "$_class" >> "${GITHUB_STEP_SUMMARY:-/dev/stdout}"
  fi
}

#!/usr/bin/env bash
# One named cause for a GitHub API answer the job's own token got (2026-11-02, KNOWN_DEFECTS D-11).
#
# Sourced by the kit's own workflows; INLINED, byte-identical between the two marker lines, into the
# steps that run where scripts/ is not on disk (the discover and resolve composites, the consumer
# path's preflight steps). tests/prove_job_token_named.py T3 refuses a copy that differs.
#
# Nothing an API server sent is ever echoed, written to $GITHUB_OUTPUT or put in an annotation:
# only the cause word, the HTTP status the text names, and fixed text.
# >>> kit api token cause
# kit_api_cause TEXT -> one word for what gh/curl/git said when a call failed (taxonomy: api_token_preflight).
kit_api_cause() {
  local t="${1,,}"
  case "$t" in
    *"ip allow list"*|*"ip allowlist"*) echo ORG_IP_ALLOW_LIST_BLOCKS_RUNNER ;;
    *"saml"*|*"single sign-on"*) echo ORG_SSO_BLOCKS_TOKEN ;;
    *"rate limit"*|*"http 429"*) echo RATE_LIMITED ;;
    *"bad credentials"*|*"http 401"*|*"requires authentication"*) echo JOB_TOKEN_REJECTED ;;
    *"http 4"[0-9][0-9]*|*"http 5"[0-9][0-9]*) echo TOKEN_PREFLIGHT_UNCLASSIFIED ;;
    *"could not resolve"*|*"no such host"*|*"name resolution"*|*"getaddrinfo"*|*"connection refused"*|\
    *"timed out"*|*"timeout"*|*"error connecting"*|*"dial tcp"*|*"network is unreachable"*|\
    *"connection reset"*|*"failed to connect"*|*"proxyconnect"*|*"urlopen error"*) echo API_UNREACHABLE ;;
    *) echo TOKEN_PREFLIGHT_UNCLASSIFIED ;;
  esac
}
# kit_api_cause_advice CAUSE -> sets KIT_CAUSE_ROLE and KIT_CAUSE_CHECK (fixed text, one line each).
kit_api_cause_advice() {
  case "$1" in
    TOKEN_ACCEPTED) KIT_CAUSE_ROLE="-"; KIT_CAUSE_CHECK="nothing to do" ;;
    JOB_TOKEN_REJECTED) KIT_CAUSE_ROLE="organisation owner, then workflow maintainer"
      KIT_CAUSE_CHECK="GitHub answered 401 Bad credentials to this job's own github.token. Check: (1) GITHUB_SERVER_URL and the API host gh used are the same deployment -- a <tenant>.ghe.com job token is refused by the github.com API (KDEC-027); (2) organisation settings, IP allow list: if enabled it must admit this runner's egress address, and GitHub-hosted runners have no fixed address unless they are larger runners with static IPs; (3) Settings, Actions, General, Workflow permissions, and that Actions is allowed for this repository; (4) a self-hosted runner's proxy or TLS inspection must not strip or replace the Authorization header; (5) no step overrides GH_TOKEN or GITHUB_TOKEN with an expired secret." ;;
    ORG_IP_ALLOW_LIST_BLOCKS_RUNNER) KIT_CAUSE_ROLE="organisation owner"
      KIT_CAUSE_CHECK="The organisation's IP allow list refuses this runner's address. Add the runner's static egress range (self-hosted runners, or larger GitHub-hosted runners with static IPs), or review the allow-list setting for installed GitHub Apps. GITHUB_SERVER_URL and the API host gh used must also be the same deployment (KDEC-027)." ;;
    ORG_SSO_BLOCKS_TOKEN) KIT_CAUSE_ROLE="organisation owner"
      KIT_CAUSE_CHECK="The organisation's SAML single sign-on refuses this token. The job's own github.token is exempt from SSO, so a step put a personal or app token in GH_TOKEN/GITHUB_TOKEN: authorise that token for SSO, or use github.token." ;;
    RATE_LIMITED) KIT_CAUSE_ROLE="workflow maintainer"
      KIT_CAUSE_CHECK="The API rate limit for this token is spent. Not a token fault: re-run after the reset, or reduce concurrent runs that share the installation's limit." ;;
    API_UNREACHABLE) KIT_CAUSE_ROLE="runner administrator"
      KIT_CAUSE_CHECK="No HTTP answer from the API host (DNS, connect, TLS or timeout). Check the runner's egress to GITHUB_API_URL, its proxy and its DNS." ;;
    *) KIT_CAUSE_ROLE="workflow maintainer"
      KIT_CAUSE_CHECK="The API refused this call for a reason the kit does not classify; read the step log above the annotation. GITHUB_SERVER_URL and the API host gh used must be the same deployment (KDEC-027)." ;;
  esac
}
# kit_token_preflight -> GET /repos/{owner}/{repo} once with this job's token, on this run's host.
# Sets KIT_TOKEN_CAUSE, KIT_TOKEN_HTTP and, on success, KIT_TOKEN_BODY (the repository JSON).
# Writes one summary block and, when refused, one annotation titled with the cause. Returns 1 unless
# TOKEN_ACCEPTED. Never fails on its own account: callers decide (`|| true` or `|| exit 1`).
kit_token_preflight() {
  local host ans err errf rc=0
  host="${GITHUB_SERVER_URL:-https://github.com}"; host="${host#*://}"; host="${host%%/*}"
  errf="$(mktemp)"
  ans="$(GH_HOST="$host" gh api "repos/${GITHUB_REPOSITORY}" 2>"$errf")" || rc=$?
  err="$(cat "$errf" 2>/dev/null || true)"; rm -f "$errf"
  KIT_TOKEN_BODY=""; KIT_TOKEN_HTTP="no HTTP answer"
  if [ "$rc" = 0 ]; then
    KIT_TOKEN_CAUSE=TOKEN_ACCEPTED; KIT_TOKEN_HTTP="HTTP 200"; KIT_TOKEN_BODY="$ans"
  else
    KIT_TOKEN_CAUSE="$(kit_api_cause "$ans $err")"
    if [[ "$err $ans" =~ HTTP\ ([0-9][0-9][0-9]) ]]; then KIT_TOKEN_HTTP="HTTP ${BASH_REMATCH[1]}"; fi
  fi
  kit_api_cause_advice "$KIT_TOKEN_CAUSE"
  if [ -n "${GITHUB_STEP_SUMMARY:-}" ]; then
    {
      echo ""
      echo "#### Job token preflight"
      echo ""
      echo "| call | answer | cause | owner role |"
      echo "|---|---|---|---|"
      echo "| GET /repos/{owner}/{repo} on ${host}, with this job's github.token | ${KIT_TOKEN_HTTP} | **${KIT_TOKEN_CAUSE}** | ${KIT_CAUSE_ROLE} |"
      echo ""
      if [ "$KIT_TOKEN_CAUSE" != TOKEN_ACCEPTED ]; then
        echo "${KIT_CAUSE_CHECK}"
        echo ""
        echo "Every later step that calls the API reports this same cause. None of their failures is a separate defect, and none of them is a scan result."
      fi
    } >> "$GITHUB_STEP_SUMMARY"
  fi
  case "$KIT_TOKEN_CAUSE" in
    TOKEN_ACCEPTED) echo "job token preflight: TOKEN_ACCEPTED on ${host}"; return 0 ;;
    RATE_LIMITED|API_UNREACHABLE)
      echo "::warning title=${KIT_TOKEN_CAUSE}: the GitHub API did not answer this job::${KIT_TOKEN_HTTP} on ${host}. Owner: ${KIT_CAUSE_ROLE}. ${KIT_CAUSE_CHECK}" ;;
    *)
      echo "::error title=${KIT_TOKEN_CAUSE}: GitHub refused this job's own token::${KIT_TOKEN_HTTP} on ${host} (GITHUB_SERVER_URL=${GITHUB_SERVER_URL:-unset}). Owner: ${KIT_CAUSE_ROLE}. ${KIT_CAUSE_CHECK}" ;;
  esac
  return 1
}
# <<< kit api token cause

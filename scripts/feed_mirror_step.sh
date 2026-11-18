#!/usr/bin/env bash
# One feed, read from the organisation mirror or refused by name (Release 4, KDEC-032).
#
# The run step of .github/actions/feed-mirror, and the step the deps-scan and docker-build-push
# composites run for the Trivy database. Environment (data, never script text): M_FEED (nvd | kev |
# trivy | trivy-checks | osv), M_URL (the mirror; empty is NOT_CONFIGURED), M_MAX_AGE (hours; the 48 h policy is a
# ceiling), M_FALLBACK (`upstream` or anything else = none), M_OSV_ECOSYSTEMS (feed osv). Writes the mirror_* outputs, Trivy's
# environment, the step summary and an evidence file. scripts/feed_mirror.py decides; this only
# guarantees that a check which could not run is never mistaken for a current mirror.
set -uo pipefail
here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
out="${RUNNER_TEMP:-/tmp}/feed-mirror-${M_FEED}"
cache="${TRIVY_CACHE_DIR:-${RUNNER_TEMP:-/tmp}/trivy-cache}"
# M_NOW is a proof's clock (tests/prove_feed_mirror.py); a run leaves it unset and reads the time.
now=(); [ -n "${M_NOW:-}" ] && now=(--now "$M_NOW")
if ! python3 "$here/feed_mirror.py" consume --feed "$M_FEED" --mirror-url "${M_URL:-}" \
    --max-age-hours "${M_MAX_AGE:-}" --fallback "${M_FALLBACK:-none}" "${now[@]}" --out-dir "$out" \
    --trivy-cache-dir "$cache" --osv-dir "${RUNNER_TEMP:-/tmp}/osv-db" \
    --osv-ecosystems "$(printf '%s' "${M_OSV_ECOSYSTEMS:-}" | tr -s ' \n' '  ')" --github-output "$GITHUB_OUTPUT" --github-env "$GITHUB_ENV" \
    --summary "${GITHUB_STEP_SUMMARY:-/dev/null}" --evidence "$out/evidence.json"; then
  # A CHECK THAT DID NOT RUN IS NOT A CURRENT MIRROR. With a mirror named it is refused.
  if [ -n "${M_URL:-}" ]; then
    echo "::error title=MIRROR_UNREACHABLE::scripts/feed_mirror.py did not complete for feed ${M_FEED}."
    { echo "mirror_state=MIRROR_UNREACHABLE"; echo "mirror_usable=false"
      echo "mirror_why=the mirror check did not complete"; } >> "$GITHUB_OUTPUT"
    case "$M_FEED" in
      trivy)
        rm -rf "$cache/db" "$cache/java-db"
        { echo "TRIVY_CACHE_DIR=$cache"; echo "TRIVY_SKIP_DB_UPDATE=true"; echo "TRIVY_SKIP_JAVA_DB_UPDATE=true"; } >> "$GITHUB_ENV" ;;
      trivy-checks)
        rm -rf "$cache/policy"
        { echo "TRIVY_CACHE_DIR=$cache"; echo "TRIVY_SKIP_CHECK_UPDATE=true"
          echo "TRIVY_CONFIG_CHECK=$cache/policy-refused-MIRROR_UNREACHABLE"; } >> "$GITHUB_ENV" ;;
      osv)
        rm -rf "${RUNNER_TEMP:-/tmp}/osv-db/osv-scalibr"
        { echo "OSV_SCANNER_LOCAL_DB_CACHE_DIRECTORY=${RUNNER_TEMP:-/tmp}/osv-db"; echo "KIT_OSV_OFFLINE=true"; } >> "$GITHUB_ENV" ;;
    esac
  fi
fi
exit 0

#!/usr/bin/env bash
# Apply the kit's push ruleset (push-ruleset-secret-files.json) to one repository.
#
#   apply-push-ruleset.sh OWNER/REPO [--host HOST] [--dry-run]
#
# A push ruleset refuses a push that adds a file by PATH or EXTENSION (.env, keys, certificates,
# tfstate, HAR captures, credentials JSON). It works on paths, not content, so it needs no secret
# scanning licence; GitHub documents push rulesets for PRIVATE and INTERNAL repositories (Team and
# Enterprise plans). It runs server-side, so it also covers pushes no local hook sees -- Tines
# GitSync among them. docs/adoption/LEAK_GATES.md.
#
# Needs a token with repository administration (gh auth login, or GH_TOKEN). Idempotent: an
# existing ruleset of the same name is updated (PUT), otherwise one is created (POST).
#
# KDEC-027: the token goes only to the repository's own host. HOST is --host, else GH_HOST, else
# the host of GITHUB_SERVER_URL, else github.com. On a <tenant>.ghe.com estate pass
# --host <tenant>.ghe.com (gh then calls api.<tenant>.ghe.com).
#
# The dry run and the real run check the same prerequisites, in this order, before any plan is
# printed or anything is written: bash; gh and jq on PATH; `gh auth status --hostname HOST`; the
# repository readable (GET repos/OWNER/REPO); the ruleset lookup answered. Only a lookup that
# succeeded prints existing_id. Each failure names its reason on stderr and has its own exit code.
# The reasons are registered in assurance-taxonomy.yaml: PREREQUISITE_UNAVAILABLE under
# prerequisite_readiness, the rest under leak_gate_setup_refusal. The code tells apart which
# prerequisite was unavailable; the message names it.
#
#   0   applied; or, with --dry-run, every prerequisite held and the plan is printed
#   1   NOT_APPLIED               GitHub refused the PUT or POST (see the message)
#   2   USAGE                     bad or missing argument
#   10  PREREQUISITE_UNAVAILABLE  bash: run by a shell that is not bash (`sh apply-push-ruleset.sh`)
#   11  PREREQUISITE_UNAVAILABLE  gh (GitHub CLI) is not on PATH
#   12  PREREQUISITE_UNAVAILABLE  jq is not on PATH
#   13  PREREQUISITE_UNAVAILABLE  gh login: `gh auth status --hostname HOST` failed; log in, or set GH_TOKEN
#   14  REPO_NOT_READABLE         GET repos/OWNER/REPO failed: no such repo, no access, wrong host
#   15  RULESET_LOOKUP_FAILED     GET repos/OWNER/REPO/rulesets failed or answered nonsense
#   16  TEMPLATE_UNREADABLE       push-ruleset-secret-files.json is missing or has no name
if [ -z "${BASH_VERSION:-}" ]; then
  echo "PREREQUISITE_UNAVAILABLE: this script needs bash; run it as: bash $0 OWNER/REPO ..." >&2
  exit 10
fi
set -euo pipefail

usage() { echo "USAGE: $1. usage: apply-push-ruleset.sh OWNER/REPO [--host HOST] [--dry-run]" >&2; exit 2; }
refuse() {  # refuse CODE REASON MESSAGE: nothing was planned or applied
  echo "$2: $3" >&2
  echo "Nothing was planned or applied. docs/adoption/LEAK_GATES.md lists the exit codes." >&2
  exit "$1"
}

repo=""; host=""; dry=0
while [ $# -gt 0 ]; do
  case "$1" in
    --host) { [ $# -ge 2 ] && [ -n "$2" ]; } || usage "--host needs a value"; host="$2"; shift 2 ;;
    --dry-run) dry=1; shift ;;
    -h|--help) while IFS= read -r l; do case "$l" in '#!'*) ;; '#'*) l="${l%$'\r'}"; echo "${l#'#'}" ;; *) break ;; esac; done < "$0"; exit 0 ;;
    */*) repo="$1"; shift ;;
    *) usage "unknown argument: $1" ;;
  esac
done
[ -n "$repo" ] || usage "OWNER/REPO is required"

if [ -z "$host" ]; then
  host="${GH_HOST:-}"
fi
if [ -z "$host" ]; then
  host="${GITHUB_SERVER_URL:-https://github.com}"
  host="${host#*://}"
fi
export GH_HOST="${host%%/*}"

# Prerequisites. Nothing below this block runs, and nothing is printed to stdout, until all hold.
command -v gh >/dev/null 2>&1 \
  || refuse 11 PREREQUISITE_UNAVAILABLE "gh (GitHub CLI) is not on PATH; install it from https://cli.github.com"
command -v jq >/dev/null 2>&1 \
  || refuse 12 PREREQUISITE_UNAVAILABLE "jq is not on PATH; install it from https://jqlang.org"
gh auth status --hostname "$GH_HOST" >/dev/null 2>&1 \
  || refuse 13 PREREQUISITE_UNAVAILABLE "gh is not authenticated to $GH_HOST; run 'gh auth login --hostname $GH_HOST' or set GH_TOKEN"

case "$0" in */*) dir="${0%/*}" ;; *) dir=. ;; esac
here="$(cd "$dir" && pwd)"
body="$here/push-ruleset-secret-files.json"
name="$(jq -r '.name // empty' "$body" 2>/dev/null)" || name=""
[ -n "$name" ] || refuse 16 TEMPLATE_UNREADABLE "$body is missing, is not JSON, or has no name"

gh api "repos/$repo" --jq .full_name >/dev/null \
  || refuse 14 REPO_NOT_READABLE "GET repos/$repo on $GH_HOST failed (gh's message above): no such repository, no access, or the wrong host"

ids="$(gh api "repos/$repo/rulesets?includes_parents=false&per_page=100" \
  --jq ".[] | select(.name == \"$name\") | .id")" \
  || refuse 15 RULESET_LOOKUP_FAILED "GET repos/$repo/rulesets on $GH_HOST failed (gh's message above), so whether \"$name\" exists is unknown"
existing="${ids%%$'\n'*}"
existing="${existing%$'\r'}"
case "$existing" in
  *[!0-9]*) refuse 15 RULESET_LOOKUP_FAILED "the ruleset lookup answered a non-numeric id: $existing" ;;
esac

if [ "$dry" = 1 ]; then
  echo "dry run: prerequisites hold: bash, gh, jq present; gh authenticated to $GH_HOST; repos/$repo readable; ruleset lookup answered"
  echo "dry run: host=$GH_HOST repo=$repo ruleset=\"$name\" existing_id=${existing:-none}"
  echo "would ${existing:+PUT repos/$repo/rulesets/$existing}${existing:-POST repos/$repo/rulesets}"
  exit 0
fi

if [ -n "$existing" ]; then
  gh api --method PUT "repos/$repo/rulesets/$existing" --input "$body" --jq '"updated ruleset \(.id): \(.name) (\(.target), \(.enforcement))"' \
    && exit 0
else
  gh api --method POST "repos/$repo/rulesets" --input "$body" --jq '"created ruleset \(.id): \(.name) (\(.target), \(.enforcement))"' \
    && exit 0
fi
{
  echo "NOT_APPLIED: ${existing:+PUT repos/$repo/rulesets/$existing}${existing:-POST repos/$repo/rulesets} on $GH_HOST was refused." >&2
  echo "A 403 means the token lacks repository administration. A 422 \"Source only" >&2
  echo "org-owned repos can have push rules\" means the repository is owned by a personal account:" >&2
  echo "push rulesets need an organisation-owned private or internal repository (verified live" >&2
  echo "2026-10-26). Any other 422 on target 'push' usually means a public repository or a plan" >&2
  echo "without them. The layer is then MISSING and the security gate's" >&2
  echo "leak-gate posture will say so. docs/adoption/LEAK_GATES.md." >&2
  exit 1
}

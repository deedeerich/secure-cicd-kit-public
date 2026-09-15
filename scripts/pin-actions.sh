#!/usr/bin/env bash
# Resolve tag-based GitHub Action references to immutable commit SHAs.
#
#   ./scripts/pin-actions.sh            # dry run — show the rewrites
#   ./scripts/pin-actions.sh --apply    # rewrite files in place
#
# Skips ./-relative references, docker:// references, already-pinned SHAs, and any owner
# listed in TRUSTED_ORGS. Requires: curl, jq, and GITHUB_TOKEN (public repo read is enough).
set -euo pipefail

APPLY=0
[ "${1:-}" = "--apply" ] && APPLY=1

TRUSTED_ORGS="${TRUSTED_ORGS:-actions,github,azure,docker,hashicorp}"
SEARCH_PATHS="${SEARCH_PATHS:-.github}"
API="${GITHUB_API_URL:-https://api.github.com}"

if [ -z "${GITHUB_TOKEN:-}" ]; then
  echo "GITHUB_TOKEN is not set — the API will rate-limit almost immediately." >&2
  echo "  export GITHUB_TOKEN=<token with public repo read>" >&2
  exit 1
fi
command -v jq >/dev/null || { echo "jq is required." >&2; exit 1; }

is_trusted() {
  local owner="$1"
  IFS=',' read -ra orgs <<< "$TRUSTED_ORGS"
  for o in "${orgs[@]}"; do
    [ "${o,,}" = "${owner,,}" ] && return 0
  done
  return 1
}

resolve_sha() {
  # /commits/<ref> dereferences lightweight tags, annotated tags, and branches alike.
  local repo="$1" ref="$2"
  curl -sS -H "Authorization: Bearer ${GITHUB_TOKEN}" \
       -H "Accept: application/vnd.github+json" \
       "${API}/repos/${repo}/commits/${ref}" | jq -r '.sha // empty'
}

changes=0
skipped=0
failed=0

mapfile -t files < <(find $SEARCH_PATHS -type f \( -name '*.yml' -o -name '*.yaml' \) | sort)
[ "${#files[@]}" -eq 0 ] && { echo "No workflow files under ${SEARCH_PATHS}."; exit 0; }

for file in "${files[@]}"; do
  # Collect distinct action references in this file.
  mapfile -t refs < <(grep -oE '^[[:space:]-]*uses:[[:space:]]*[^[:space:]#]+' "$file" \
                      | sed -E 's/.*uses:[[:space:]]*//' | sort -u)
  for uses in "${refs[@]}"; do
    case "$uses" in
      ./*|docker://*) continue ;;
    esac
    [[ "$uses" != *"@"* ]] && { echo "  !! $file: '$uses' has no ref at all — pin it manually"; failed=$((failed+1)); continue; }

    repo="${uses%@*}"
    ref="${uses##*@}"
    owner="${repo%%/*}"

    # Reusable workflows are referenced as owner/repo/path@ref — resolve against owner/repo.
    api_repo="$(echo "$repo" | cut -d/ -f1,2)"

    [[ "$ref" =~ ^[0-9a-f]{40}$ ]] && { skipped=$((skipped+1)); continue; }
    if is_trusted "$owner"; then skipped=$((skipped+1)); continue; fi

    sha="$(resolve_sha "$api_repo" "$ref" || true)"
    if [ -z "$sha" ]; then
      echo "  !! $file: could not resolve ${api_repo}@${ref}"
      failed=$((failed+1))
      continue
    fi

    echo "  $file"
    echo "      - $uses"
    echo "      + ${repo}@${sha}   # ${ref}"
    changes=$((changes+1))

    if [ "$APPLY" = "1" ]; then
      # Replace the reference and append the version comment, unless one is already present.
      python3 - "$file" "$uses" "${repo}@${sha}" "$ref" <<'PYEOF'
import re, sys
path, old, new, ver = sys.argv[1:5]
src = open(path, encoding="utf-8").read()
def sub(m):
    line = m.group(0)
    line = line.replace(old, new)
    return line if "#" in line.split(new, 1)[-1] else f"{line}   # {ver}"
src = re.sub(rf"^.*uses:\s*{re.escape(old)}\s*$", sub, src, flags=re.M)
open(path, "w", encoding="utf-8").write(src)
PYEOF
    fi
  done
done

echo
echo "${changes} reference(s) to pin · ${skipped} skipped (trusted or already pinned) · ${failed} unresolved"
if [ "$APPLY" = "1" ]; then
  echo "Files rewritten. Review the diff before committing."
else
  echo "Dry run — re-run with --apply to rewrite."
fi
[ "$failed" -gt 0 ] && exit 1
exit 0

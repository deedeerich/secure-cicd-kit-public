#!/usr/bin/env bash
# Resolve tag-based GitHub Action references to immutable commit SHAs.
#
#   ./scripts/pin-actions.sh            # dry run — show the rewrites
#   ./scripts/pin-actions.sh --apply    # rewrite files in place
#
# Searches all of .github, composites included (SEARCH_PATHS widens it, e.g. ".github overlays").
# Skips ./-relative and $/ self-repository references, docker:// references, already-pinned SHAs,
# and any owner listed in TRUSTED_ORGS -- EMPTY by default: the kit pins every owner
# (docs/assurance/PINNING.md); exempting one is a decision you set, not a default you inherit.
#
# The comment written beside each SHA is the EXACT release at that commit (`# v7.0.1`), found among
# the repository's tags -- never the moving major that was resolved (`@v7`). A commit with no
# vX.Y.Z tag is refused and its line left alone: pin it by hand, with a reviewed comment.
# tests/prove_pin_actions_names_release.py; the output must pass tests/check_action_pins.py.
#
# Requires: curl, jq, GITHUB_TOKEN (public repo read is enough), and Python (PYTHON, else python3).
set -euo pipefail

APPLY=0
[ "${1:-}" = "--apply" ] && APPLY=1

TRUSTED_ORGS="${TRUSTED_ORGS:-}"
PY="${PYTHON:-python3}"
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
       "${API}/repos/${repo}/commits/${ref}" | jq -r '.sha // empty' | tr -d '\r'
}

exact_release() {
  # The highest vX.Y.Z tag whose commit is this SHA. An exact ref names itself: it is what was
  # resolved. Otherwise every page of tags is read (a major's release is rarely on page one).
  local repo="$1" sha="$2" ref="$3" page=1 body n found=""
  if [[ "$ref" =~ ^v[0-9]+\.[0-9]+\.[0-9]+$ ]]; then echo "$ref"; return 0; fi
  while [ "$page" -le 50 ]; do
    body="$(curl -sS -H "Authorization: Bearer ${GITHUB_TOKEN}" \
                 -H "Accept: application/vnd.github+json" \
                 "${API}/repos/${repo}/tags?per_page=100&page=${page}")" || return 0
    n="$(printf '%s' "$body" | jq -r 'if type == "array" then length else 0 end' | tr -d '\r')"
    [ "${n:-0}" -gt 0 ] 2>/dev/null || break
    found="${found}$(printf '%s' "$body" \
      | jq -r --arg s "$sha" '.[] | select(.commit.sha == $s) | .name' | tr -d '\r')"$'\n'
    page=$((page+1))
  done
  printf '%s' "$found" | grep -E '^v[0-9]+\.[0-9]+\.[0-9]+$' | sort -V | tail -n 1 || true
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
      # `$/` resolves to this repository at the commit the CALLER pinned (decomposition plan §7
      # step 8, measured cross-repo). It is pinned by construction, like `./`.
      ./*|'$/'*|docker://*) continue ;;
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

    ver="$(exact_release "$api_repo" "$sha" "$ref")"
    if [ -z "$ver" ]; then
      echo "  !! $file: ${api_repo}@${ref} is commit ${sha}, and no vX.Y.Z tag names that commit"
      echo "     -- not written with a moving-major comment; pin it by hand"
      failed=$((failed+1))
      continue
    fi

    echo "  $file"
    echo "      - $uses"
    echo "      + ${repo}@${sha} # ${ver}"
    changes=$((changes+1))

    if [ "$APPLY" = "1" ]; then
      # Replace the reference on its own `uses:` lines only, and write ` # vX.Y.Z` after it. Any
      # comment the line already had is kept AFTER the version, which must come first. Line
      # endings are preserved (newline=''), so a CRLF checkout is not rewritten wholesale.
      "$PY" - "$file" "$uses" "${repo}@${sha}" "$ver" <<'PYEOF'
import re, sys
path, old, new, ver = sys.argv[1:5]
src = open(path, encoding="utf-8", newline="").read()
pat = re.compile(r"^(?P<pre>[ \t-]*uses:[ \t]*)" + re.escape(old)
                 + r"(?P<sp>[ \t]*)(?:#(?P<c>[^\r\n]*))?(?P<cr>\r?)$", re.M)
def sub(m):
    c = (m.group("c") or "").strip()
    return m.group("pre") + new + " # " + ver + ((" " + c) if c else "") + m.group("cr")
open(path, "w", encoding="utf-8", newline="").write(pat.sub(sub, src))
PYEOF
    fi
  done
done

echo
echo "${changes} reference(s) to pin · ${skipped} skipped (trusted or already pinned) · ${failed} unresolved or without an exact release"
if [ "$APPLY" = "1" ]; then
  echo "Files rewritten. Review the diff before committing."
else
  echo "Dry run — re-run with --apply to rewrite."
fi
[ "$failed" -gt 0 ] && exit 1
exit 0

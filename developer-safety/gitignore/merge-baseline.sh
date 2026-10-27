#!/usr/bin/env bash
# Merge the kit's baseline .gitignore into a repository's own .gitignore -- never replace it.
#
#   merge-baseline.sh [REPO_DIR]        (default: the current directory)
#
# Every baseline pattern the repository's .gitignore does not already carry (exact line) is
# appended, in baseline order, under one marker line, so negations such as `!.env.example` still
# follow the rule they negate. The repository's own lines are kept first and unchanged. Running it
# again appends nothing. Adoption step 1 (docs/adoption/LEAK_GATES.md);
# tests/prove_baseline_gitignore.py G3 and G4 run it.
#
# REPO_DIR must exist and be inside a git work tree (it holds .git, or git says so). After writing,
# the script re-reads .gitignore and requires every baseline pattern in it. It never reports
# success it has not checked. Each failure names its reason on stderr and has its own exit code.
# The reasons are registered in assurance-taxonomy.yaml: PREREQUISITE_UNAVAILABLE and
# FITNESS_FAILED under prerequisite_readiness, the rest under leak_gate_setup_refusal.
#
#   0   merged, or already carried every baseline pattern (verified by re-reading)
#   2   USAGE                     more than one argument, or an unknown option
#   10  PREREQUISITE_UNAVAILABLE  bash: run by a shell that is not bash (`sh merge-baseline.sh`)
#   11  PREREQUISITE_UNAVAILABLE  grep or tail is not on PATH
#   12  BASELINE_UNREADABLE       baseline.gitignore is missing, unreadable, or holds no pattern
#   13  REPO_DIR_MISSING          REPO_DIR does not exist or is not a directory (nothing is created)
#   14  NOT_A_GIT_REPO            REPO_DIR is not inside a git work tree (nothing is written)
#   15  TARGET_NOT_WRITABLE       REPO_DIR/.gitignore is not a readable, writable file
#   16  MERGE_NOT_VERIFIED        after the merge, .gitignore does not carry every baseline pattern
#   17  FITNESS_FAILED            grep -Fxq fails its self-test, or fails while comparing lines
if [ -z "${BASH_VERSION:-}" ]; then
  echo "PREREQUISITE_UNAVAILABLE: this script needs bash; run it as: bash $0 [REPO_DIR]" >&2
  exit 10
fi
set -euo pipefail

refuse() {  # refuse CODE REASON MESSAGE
  echo "$2: $3" >&2
  echo "merge-baseline: not merged. docs/adoption/LEAK_GATES.md lists the exit codes." >&2
  exit "$1"
}

case "${1:-}" in
  -h|--help) while IFS= read -r l; do case "$l" in '#!'*) ;; '#'*) l="${l%$'\r'}"; echo "${l#'#'}" ;; *) break ;; esac; done < "$0"; exit 0 ;;
  -*) echo "USAGE: unknown option $1. usage: merge-baseline.sh [REPO_DIR]" >&2; exit 2 ;;
esac
[ $# -le 1 ] || { echo "USAGE: one REPO_DIR at most. usage: merge-baseline.sh [REPO_DIR]" >&2; exit 2; }
repo="${1:-.}"

for tool in grep tail; do
  command -v "$tool" >/dev/null 2>&1 || refuse 11 PREREQUISITE_UNAVAILABLE "$tool is not on PATH"
done
# A grep that cannot answer turns "already present" into "missing" (or back): prove it answers.
needle=__merge_baseline_selftest__
yes_rc=0; grep -Fxq -- "$needle" <<<"$needle" 2>/dev/null || yes_rc=$?
no_rc=0; grep -Fxq -- "$needle" <<<"x$needle" 2>/dev/null || no_rc=$?
{ [ "$yes_rc" = 0 ] && [ "$no_rc" = 1 ]; } \
  || refuse 17 FITNESS_FAILED "grep -Fxq answered rc=$yes_rc for a match and rc=$no_rc for a non-match (want 0 and 1)"

has_line() {  # has_line LINE TEXT -> 0 present, 1 absent; any other answer is fatal
  local rc=0
  grep -Fxq -- "$1" <<<"$2" 2>/dev/null || rc=$?
  case "$rc" in
    0|1) return "$rc" ;;
    *) refuse 17 FITNESS_FAILED "grep -Fxq failed (rc=$rc) comparing: $1" ;;
  esac
}

read_lines() {  # read_lines FILE -> its lines, CR stripped, each ending in a newline
  local l out=""
  while IFS= read -r l || [ -n "$l" ]; do out+="${l%$'\r'}"$'\n'; done < "$1"
  printf '%s' "$out"
}

[ -d "$repo" ] || refuse 13 REPO_DIR_MISSING "$repo does not exist or is not a directory"
if [ ! -e "$repo/.git" ]; then
  { command -v git >/dev/null 2>&1 && git -C "$repo" rev-parse --is-inside-work-tree >/dev/null 2>&1; } \
    || refuse 14 NOT_A_GIT_REPO "$repo is not inside a git work tree (no .git there, and git does not place it in one)"
fi

case "$0" in */*) dir="${0%/*}" ;; *) dir=. ;; esac
here="$(cd "$dir" && pwd)"
base="$here/baseline.gitignore"
{ [ -f "$base" ] && [ -r "$base" ]; } || refuse 12 BASELINE_UNREADABLE "$base is missing or unreadable"
patterns=()
while IFS= read -r line || [ -n "$line" ]; do
  line="${line%$'\r'}"
  case "$line" in ''|'#'*) continue ;; esac
  patterns+=("$line")
done < "$base"
[ "${#patterns[@]}" -gt 0 ] || refuse 12 BASELINE_UNREADABLE "$base holds no pattern"

target="$repo/.gitignore"
if [ -e "$target" ]; then
  { [ -f "$target" ] && [ -r "$target" ] && [ -w "$target" ]; } \
    || refuse 15 TARGET_NOT_WRITABLE "$target is not a readable, writable file"
  have="$(read_lines "$target")"
else
  [ -w "$repo" ] || refuse 15 TARGET_NOT_WRITABLE "$repo is not writable, so $target cannot be created"
  have=""
fi

# Exact-line comparison against the file's own lines (CR stripped) and what is queued.
add=""; count=0
for line in "${patterns[@]}"; do
  if ! has_line "$line" "$have" && ! has_line "$line" "$add"; then
    add="${add}${line}"$'\n'
    count=$((count + 1))
  fi
done

if [ "$count" -gt 0 ]; then
  # A file that does not end in a newline would glue its last line to the marker.
  if [ -s "$target" ] && [ -n "$(tail -c1 "$target")" ]; then
    printf '\n' >> "$target" || refuse 15 TARGET_NOT_WRITABLE "could not append to $target"
  fi
  {
    printf '\n# ---- secure-cicd-kit baseline (developer-safety/gitignore/baseline.gitignore) ----\n'
    printf '%s' "$add"
  } >> "$target" || refuse 15 TARGET_NOT_WRITABLE "could not append to $target"
fi

# Re-read what is on disk: success is claimed only for what the file now carries.
now="$(read_lines "$target")"
missing=0
for line in "${patterns[@]}"; do
  if ! has_line "$line" "$now"; then
    missing=$((missing + 1))
    echo "  not in $target after the merge: $line" >&2
  fi
done
[ "$missing" = 0 ] \
  || refuse 16 MERGE_NOT_VERIFIED "$missing of ${#patterns[@]} baseline pattern(s) are not in $target after the merge"

if [ "$count" = 0 ]; then
  echo "merge-baseline: $target already carries every baseline pattern (${#patterns[@]}, verified)"
else
  echo "merge-baseline: appended $count pattern(s) to $target; it now carries all ${#patterns[@]} (verified)"
fi

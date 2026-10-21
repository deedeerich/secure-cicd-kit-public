#!/usr/bin/env bash
# CANONICAL pre-upload redaction sweep. Scrub every SARIF in the workspace, then let the job
# publish. Sourced by nothing; invoked as `bash /tmp/redact_all.sh` from the generated
# "Redact credential material before upload" step in every job that uploads scanner output.
#
# WHY THIS IS A FILE AND NOT SHELL IN THE WORKFLOW
#   It used to be shell in the workflow -- fourteen byte-identical copies of it, 47 KB of one
#   wrapper repeated per job, sitting inside the file that had just been rescued from GitHub's
#   500 KB limit for exactly that reason. Duplicated prose drifts the same way duplicated code
#   does; the kit has already lost a flawfinder fix and 14 Azure gitleaks rules that way. One
#   canonical copy, generated into the bootstrap job, fetched everywhere, checked by
#   scripts/inline_normalizer.py --check.
#
# ORDER IS THE WHOLE CONTROL. This runs BEFORE the first upload step of its job. A redactor that
# runs after the upload protects nothing while looking exactly like protection, and
# tests/check_redaction_parity.py fails the build if any job publishes before it redacts.
#
# EXIT
#   0  nothing to redact, or everything at risk was redacted or withheld
#   1  a report could be neither redacted nor withheld -- credential material may reach an
#      artifact, which is the only redaction outcome worth a red job

set -uo pipefail

if [ ! -s /tmp/redact_sarif.py ]; then
  echo "::error title=Redaction could not be guaranteed::/tmp/redact_sarif.py is absent, so the"
  echo "kit-scripts artifact did not reach this job and no SARIF can be scrubbed. A MISSING TOOL"
  echo "IS NOT A CLEAN RESULT -- publication must not proceed on the strength of a tool that was"
  echo "never acquired. That conflation is this kit's founding defect."
  exit 1
fi

shopt -s nullglob globstar

# A PATH ENDING .sarif IS NOT ALWAYS A SARIF FILE.
#
# checkov-action treats `output_file_path` as a DIRECTORY and writes
# checkov.sarif/results_sarif.sarif inside it. `*.sarif` therefore matched the DIRECTORY, the
# redactor raised IsADirectoryError and exited 1, and a job whose scan had SUCCEEDED went red --
# taking the second IaC scanner behind it with it, because that step had no if: always(). A
# housekeeping step decided a security verdict. Keep regular files only; **/*.sarif still finds
# the real report inside.
files=()
for _f in *.sarif **/*.sarif; do
  if [ -f "$_f" ]; then files+=( "$_f" ); fi
done

if [ ${#files[@]} -eq 0 ]; then
  echo "no SARIF produced by this job -- nothing to redact"
  exit 0
fi

# READABLE IS NOT WRITABLE.
#
# checkov-action is a CONTAINER action: it runs as root, so checkov.sarif/results_sarif.sarif
# arrives owned by root at 0644. The redactor could read and scrub it and then died on the write
# back with PermissionError -- a job whose scan had SUCCEEDED went red in its housekeeping for
# the second time. Take ownership where the runner is allowed to. Never fatal: the redactor
# defends itself if this cannot help.
for _f in "${files[@]}"; do
  if [ ! -w "$_f" ]; then
    chmod u+w "$_f" 2>/dev/null \
      || sudo -n chown "$(id -u):$(id -g)" "$_f" 2>/dev/null \
      || true
  fi
done

_rc=0
python3 /tmp/redact_sarif.py "${files[@]}" || _rc=$?

# 4 alone means a report could be neither redacted nor moved off the upload path, so credential
# material may reach an artifact. That is the only redaction outcome worth a red job. 1, 2 and 3
# mean the reports at risk are already withheld, the scan's verdict stands, and nothing leaks.
if [ "$_rc" -eq 4 ]; then
  echo "::error title=Redaction could not be guaranteed::A SARIF could not be redacted and could not be withheld. See above."
  exit 1
fi
exit 0

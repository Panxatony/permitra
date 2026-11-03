#!/bin/bash
# Permitra – wait for the GitHub checks of a pull request and print them.
#
# Usage:  ./scripts/wait_pr_checks.sh <pr-number> [timeout-seconds]
#
# Needs the gh CLI, signed in. Exit code 0 when every check passed, 1 when one
# failed or the timeout was reached. Like wait_gitlab_pipeline.sh it is meant to
# run in the background.
set -u
pr="${1:?pull request number}"
timeout="${2:-1800}"
repo="${GITHUB_REPO:-Panxatony/permitra}"
deadline=$((SECONDS + timeout))
out=""
while (( SECONDS < deadline )); do
  out=$(gh pr checks "$pr" --repo "$repo" 2>&1)
  if ! echo "$out" | grep -qiE 'pending|queued|in_progress|expected'; then
    echo "$out"
    ! echo "$out" | grep -qiE '\bfail'
    exit $?
  fi
  sleep 20
done
echo "timeout after ${timeout}s" >&2
echo "$out"
exit 1

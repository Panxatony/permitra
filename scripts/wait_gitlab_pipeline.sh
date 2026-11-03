#!/bin/bash
# Permitra – wait for the newest GitLab pipeline of a branch and print its jobs.
#
# Usage:  GITLAB_TOKEN_FILE=~/gitlab-token.txt ./scripts/wait_gitlab_pipeline.sh <branch> [timeout-seconds]
#
# Environment:
#   GITLAB_TOKEN_FILE  file holding a read_api token (required; the value is never printed)
#   GITLAB_URL         base URL of the GitLab instance, e.g. https://gitlab.example.org (required)
#   GITLAB_PROJECT     URL-encoded project path, e.g. group%2Fpermitra (required)
#
# Exit code 0 when the pipeline succeeded, 1 otherwise (failed, canceled,
# timeout). Written for sessions that cannot sleep in the foreground: run it in
# the background and read its output when it finishes.
set -u
branch="${1:?branch name}"
timeout="${2:-1800}"
token_file="${GITLAB_TOKEN_FILE:?set GITLAB_TOKEN_FILE to the token file}"
url="${GITLAB_URL:?set GITLAB_URL}/api/v4/projects/${GITLAB_PROJECT:?set GITLAB_PROJECT (url-encoded)}"
token=$(<"$token_file")
api() { curl -s -H "PRIVATE-TOKEN: $token" "$url/$1"; }

pid=$(api "pipelines?ref=$branch&per_page=1" | python3 -c 'import json,sys; d=json.load(sys.stdin); print(d[0]["id"] if d else "")')
[[ -n "$pid" ]] || { echo "no pipeline for $branch" >&2; exit 1; }
echo "pipeline $pid"
deadline=$((SECONDS + timeout))
status=unknown
while (( SECONDS < deadline )); do
  status=$(api "pipelines/$pid" | python3 -c 'import json,sys; print(json.load(sys.stdin)["status"])')
  case "$status" in
    success|failed|canceled|skipped|manual) break ;;
  esac
  sleep 20
done
echo "pipeline $pid: $status"
api "pipelines/$pid/jobs?per_page=50" | python3 -c '
import json, sys
for j in json.load(sys.stdin):
    print(j["name"], j["status"])'
[[ "$status" == success ]]

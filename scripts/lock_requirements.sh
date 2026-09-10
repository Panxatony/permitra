#!/usr/bin/env bash
# Compiles backend/requirements*.in into fully pinned requirements*.txt.
#
#   ./scripts/lock_requirements.sh             # after editing an .in file
#   ./scripts/lock_requirements.sh --upgrade   # pull newer versions in
#
# Without --upgrade this is idempotent: pip-compile keeps the pins already in
# the output file wherever they still satisfy the .in constraints. That is what
# lets CI recompile and compare - the check reacts to a forgotten regeneration,
# not to some package having published a release this morning.
#
# It runs inside the SAME image the backend is built from. Resolution depends
# on the interpreter (markers like python_version < "3.11" select different
# packages), so a lock compiled against whatever Python sits on a maintainer's
# laptop would pin for the wrong one. pip-compile writes the version into the
# file header, which is how the CI comparison notices if it ever happens.
#
# Run this after editing an .in file and commit both halves together.
set -euo pipefail

# Pinned so the CI comparison stays deterministic: a new pip-tools may format
# its output differently, and that must not read as "somebody forgot to
# regenerate". Keep this in step with the version in .github/workflows/ci.yml.
PIP_TOOLS_VERSION="7.6.1"

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
IMAGE="$(awk '/^FROM /{print $2; exit}' "$ROOT/backend/Dockerfile")"
UPGRADE=""
[ "${1:-}" = "--upgrade" ] && UPGRADE="--upgrade"

docker run --rm -v "$ROOT/backend:/w" -w /w -e UPGRADE="$UPGRADE" \
  -e PIP_TOOLS_VERSION="$PIP_TOOLS_VERSION" "$IMAGE" sh -eu -c '
  pip install --quiet --no-cache-dir --root-user-action=ignore \
    "pip-tools==$PIP_TOOLS_VERSION"
  for f in requirements requirements-dev; do
    # --allow-unsafe pins pip/setuptools too. The name is historical: with
    # hashes in the file pip refuses to install anything unpinned, and
    # pip-audit depends on pip - so leaving them out is what is unsafe here.
    pip-compile --strip-extras --generate-hashes --allow-unsafe $UPGRADE \
      --output-file "$f.txt" "$f.in"
  done
'
echo "requirements.txt and requirements-dev.txt regenerated"

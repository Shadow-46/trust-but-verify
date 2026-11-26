#!/usr/bin/env bash
# Run the test suite and the official toolkit validator inside a container that
# mirrors the judging runtime: Node 24.11.1, no network, read-only root and
# repository, writable /tmp only.
#
# Usage: tools/judge-parity.sh <path-to-Track-4-Toolkit>
set -euo pipefail

TOOLKIT="${1:?usage: tools/judge-parity.sh <path-to-Track-4-Toolkit>}"
REPO="$(cd "$(dirname "$0")/.." && pwd)"
TOOLKIT="$(cd "$TOOLKIT" && pwd)"

# Git Bash on Windows needs Windows paths for volume mounts and no path mangling.
if command -v cygpath >/dev/null 2>&1; then
  REPO="$(cygpath -w "$REPO")"
  TOOLKIT="$(cygpath -w "$TOOLKIT")"
  export MSYS_NO_PATHCONV=1
fi

docker run --rm \
  --network none \
  --read-only \
  --tmpfs /tmp:rw,exec \
  -e HOME=/tmp \
  -v "$REPO:/app:ro" \
  -v "$TOOLKIT:/toolkit:ro" \
  -w /app \
  node:24.11.1 \
  sh -c '
    set -e
    echo "== runtime: node $(node --version), openssl $(node -p process.versions.openssl)"
    echo "== unit and integration tests"
    node --test "tests/**/*.test.ts"
    echo "== official toolkit validator"
    python3 /toolkit/validate.py --entry /app/track4_service.mjs
  '

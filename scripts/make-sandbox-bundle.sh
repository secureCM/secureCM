#!/usr/bin/env bash
# Assemble the minimal runtime bundle for Code Mode: the only files that need
# to live inside your sandbox (gVisor / Firecracker / Aegis / nsjail / ...).
#
# Stdlib-only, no pip install. NOT included (not needed at runtime):
#   docs/  tests/  examples/  fixtures/  attack_coverage/report.py
#
# Usage:  scripts/make-sandbox-bundle.sh [OUT_DIR]   (default: ./sandbox-bundle)
set -euo pipefail

SRC="$(cd "$(dirname "$0")/.." && pwd)"
OUT="${1:-$SRC/sandbox-bundle}"

rm -rf "$OUT"
mkdir -p "$OUT/attack_coverage"

# The agent imports these two packages from within run_script.
cp -r "$SRC/gcp_policy_analyzer" "$OUT/"
cp -r "$SRC/codemode" "$OUT/"

# attack_coverage: catalog + registry + the pinned catalog JSON only.
# report.py is the CI/coverage gate (reads fixtures) and is NOT a runtime dep.
cp "$SRC/attack_coverage/__init__.py" \
   "$SRC/attack_coverage/catalog.py" \
   "$SRC/attack_coverage/signatures.py" \
   "$SRC/attack_coverage/attack_catalog.json" \
   "$OUT/attack_coverage/"

find "$OUT" -name __pycache__ -type d -prune -exec rm -rf {} +

echo "Minimal runtime bundle: $OUT"
echo "Contents:"; (cd "$OUT" && find . -type f | sort | sed 's/^/  /')
echo
echo "Start the Code Mode MCP server (stdio JSON-RPC) with:"
echo "  PYTHONPATH=$OUT python $OUT/codemode/mcp_server.py"
echo
echo "The bundle holds NO credentials. Deny-by-default egress and real"
echo "isolation are the sandbox's responsibility."

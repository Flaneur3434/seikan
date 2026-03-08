#!/usr/bin/env bash
# ── VeriGuard container entrypoint ──────────────────────────────────────────
# Sources the ESP-IDF environment, then delegates to build.py.
set -euo pipefail

# Activate ESP-IDF toolchains
. "$IDF_PATH/export.sh" 2>/dev/null

exec python3 /work/build.py "$@"

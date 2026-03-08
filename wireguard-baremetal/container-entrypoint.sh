#!/usr/bin/env bash

# Sources the ESP-IDF environment, then delegates to build.py.
set -euo pipefail

cd /work

# Verify we are inside a git repository
git rev-parse --show-toplevel

# Resolve submodule difference between remote and working tree
git submodule sync --recursive
git submodule update --init --recursive --progress

# Activate ESP-IDF toolchains
. "$IDF_PATH/export.sh"

cd /work/wireguard-baremetal
exec python3 /work/wireguard-baremetal/build.py "$@"

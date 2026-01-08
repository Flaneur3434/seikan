#!/bin/bash
# VeriGuard Build Script
#
# Builds Ada crates first, then ESP-IDF firmware.

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

echo "=========================================="
echo "VeriGuard Build"
echo "=========================================="

# Step 1: Build Ada crates
echo ""
echo "[1/2] Building Ada crates with Alire..."
echo ""

for crate in crypto wireguard net bindings; do
    echo "  Building $crate..."
    cd "$SCRIPT_DIR/$crate"
    alr build --release 2>&1 | grep -E "(Success|Error|Warning)" || true
done

echo ""
echo "[2/2] Building ESP-IDF firmware..."
echo ""

cd "$SCRIPT_DIR"

# Check if IDF_PATH is set
if [ -z "$IDF_PATH" ]; then
    echo "ERROR: IDF_PATH not set. Run: source /opt/esp-idf/export.sh"
    exit 1
fi

# Build with idf.py
idf.py build

echo ""
echo "=========================================="
echo "Build Complete!"
echo "=========================================="
echo "Firmware: $SCRIPT_DIR/build/VeriGuard.elf"

#!/bin/bash
set -e

echo "========================================"
echo "Mimic Cleanup/Uninstall"
echo "========================================"

# Ensure script dir
cd "$(dirname "$0")"

if [ "$EUID" -ne 0 ]; then
    echo "This script must be run as root."
    exit 1
fi

echo "Removing Mimic Alpine Rescue System..."
cargo run --bin mimic-apply -- clean
echo "Done."

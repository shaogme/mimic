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

MIMIC_APPLY_URL="https://github.com/shaogme/mimic/releases/download/v0.1.2/mimic-apply"

if [ ! -f "mimic-apply" ]; then
    echo "Downloading mimic-apply for cleanup..."
    curl -L -o "mimic-apply" "$MIMIC_APPLY_URL"
    chmod +x "mimic-apply"
fi

echo "Removing Mimic Alpine Rescue System..."
./mimic-apply clean
echo "Done."

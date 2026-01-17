#!/bin/bash
set -e

echo "========================================"
echo "Alpine Deployment"
echo "========================================"

# Ensure script dir
cd "$(dirname "$0")"

if [ "$EUID" -ne 0 ]; then
    echo "This script must be run as root to configure bootloaders."
    exit 1
fi

# 1. Run mimic-gen (Deployment Generator)
echo "----------------------------------------"
echo "Running mimic-gen (Configuration)..."

if [ ! -f "Cargo.lock" ]; then
    cargo generate-lockfile
fi

cargo run --bin mimic-gen -- --output deployment.json

echo "----------------------------------------"

if [ -f "deployment.json" ]; then
    echo "Configuration ready. Installing boot entry..."
    # 2. Run mimic-apply (Install Boot Entry)
    cargo run --bin mimic-apply
else
    echo "Deployment generation cancelled."
fi

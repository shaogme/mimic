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

MIMIC_GEN_URL="https://github.com/shaogme/mimic/releases/download/pre-release/mimic-gen"
MIMIC_APPLY_URL="https://github.com/shaogme/mimic/releases/download/pre-release/mimic-apply"

# Helper to download if missing
download_if_missing() {
    local file="$1"
    local url="$2"
    if [ ! -f "$file" ]; then
        echo "Downloading $file..."
        curl -L -o "$file" "$url"
        chmod +x "$file"
    fi
}

# 1. Run mimic-gen (Deployment Generator)
echo "----------------------------------------"
echo "Running mimic-gen (Configuration)..."

download_if_missing "mimic-gen" "$MIMIC_GEN_URL"

./mimic-gen --output deployment.json

echo "----------------------------------------"

if [ -f "deployment.json" ]; then
    echo "Configuration ready. Installing boot entry..."
    # 2. Run mimic-apply (Install Boot Entry)
    download_if_missing "mimic-apply" "$MIMIC_APPLY_URL"
    ./mimic-apply
else
    echo "Deployment generation cancelled."
fi

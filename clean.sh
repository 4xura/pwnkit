#!/usr/bin/env bash
set -Eeuo pipefail

echo "[*] Cleaning build artifacts"

# Standard build dirs
rm -rf dist build

# Egg metadata dirs (sometimes with version suffix)
rm -rf ./*.egg-info ./*.egg ./.eggs

# Python caches
find . -type d -name "__pycache__" -exec rm -rf {} + 2>/dev/null || true
find . -type d -name "*.egg-info" -exec rm -rf {} + 2>/dev/null || true
find . -type f -name "*.pyc" -delete 2>/dev/null || true
find . -type f -name "*.pyo" -delete 2>/dev/null || true

echo "[+] Clean complete"


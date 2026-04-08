#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

echo "Step 1/3: checking mandatory files..."
[[ -f "${ROOT_DIR}/inference.py" ]] || { echo "Missing inference.py at project root"; exit 1; }
[[ -f "${ROOT_DIR}/openenv.yaml" ]] || { echo "Missing openenv.yaml"; exit 1; }
if [[ ! -f "${ROOT_DIR}/Dockerfile" && ! -f "${ROOT_DIR}/server/Dockerfile" ]]; then
  echo "Missing Dockerfile (root or server/)"
  exit 1
fi
echo "OK"

echo "Step 2/3: running docker build..."
if [[ -f "${ROOT_DIR}/Dockerfile" ]]; then
  docker build -t kernel_env:prevalidate "${ROOT_DIR}"
else
  docker build -t kernel_env:prevalidate -f "${ROOT_DIR}/server/Dockerfile" "${ROOT_DIR}"
fi
echo "OK"

echo "Step 3/3: running openenv validate..."
"${ROOT_DIR}/.venv/bin/openenv" validate
echo "OK"

echo "All checks passed."

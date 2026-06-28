#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BUILD_DIR="${ROOT_DIR}/build/lambda"
ZIP_PATH="${ROOT_DIR}/build/context-firewall-lambda.zip"

rm -rf "${BUILD_DIR}" "${ZIP_PATH}"
mkdir -p "${BUILD_DIR}" "$(dirname "${ZIP_PATH}")"

python3 -m pip install \
  --disable-pip-version-check \
  --no-compile \
  --platform manylinux2014_x86_64 \
  --implementation cp \
  --python-version 3.12 \
  --abi cp312 \
  --only-binary=:all: \
  --target "${BUILD_DIR}" \
  -r "${ROOT_DIR}/api/requirements-lambda.txt"

cp -R "${ROOT_DIR}/api/app" "${BUILD_DIR}/app"
cp -R "${ROOT_DIR}/api/policies" "${BUILD_DIR}/policies"
find "${BUILD_DIR}" -type d -name "__pycache__" -prune -exec rm -rf {} +

(
  cd "${BUILD_DIR}"
  zip -qr "${ZIP_PATH}" .
)

echo "${ZIP_PATH}"

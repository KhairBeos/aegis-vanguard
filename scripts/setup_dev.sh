#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

echo "[1/3] Preparing env file"
if [ ! -f "${ROOT_DIR}/deploy/env/.env" ]; then
	cp "${ROOT_DIR}/deploy/env/.env.example" "${ROOT_DIR}/deploy/env/.env"
fi

echo "[2/3] Starting infrastructure"
docker compose --env-file "${ROOT_DIR}/deploy/env/.env" -f "${ROOT_DIR}/deploy/docker-compose.yml" up -d

echo "[3/3] Local stack is ready"
echo "Next: configure CMake preset and start module development."
#!/usr/bin/env bash
set -e

AEGIS_VERSION="1.0.0"
AEGIS_DIR="$(cd "$(dirname "$0")" && pwd)"

if ! command -v docker &> /dev/null; then
    echo "[ERROR] Docker is required but not installed."
    exit 1
fi

if ! docker compose version &> /dev/null && ! docker-compose version &> /dev/null; then
    echo "[ERROR] Docker Compose is required but not installed."
    exit 1
fi

echo "============================================================"
echo "     Cybersecurity-AEGIS Installer v${AEGIS_VERSION}          "
echo "============================================================"

cd "$AEGIS_DIR"

if [ ! -f .env ]; then
    echo "[1/5] Creating .env from template..."
    cp .env.example .env
else
    echo "[1/5] .env already exists, preserving."
fi

echo "[2/5] Pulling base images..."
docker compose --profile full pull 2>/dev/null || true

echo "[3/5] Building AEGIS services..."
docker compose --profile full build

echo "[4/5] Starting core services..."
docker compose --profile core up -d

echo "[5/5] Starting full defensive stack..."
docker compose --profile full up -d

echo ""
echo "AEGIS installation complete!"
echo "Dashboard:  http://localhost:8080/dashboard/"
echo "Health:     curl http://localhost:8080/health"
echo "Metrics:    curl http://localhost:8080/api/v1/metrics"
echo ""
echo "To stop:    docker compose --profile full down"
echo "To update:  docker compose --profile full pull && docker compose --profile full up --build -d"

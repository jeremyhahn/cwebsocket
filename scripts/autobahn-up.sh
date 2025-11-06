#!/usr/bin/env bash
set -euo pipefail

# Start Autobahn fuzzing server in a Docker container
# Mounts test/autobahn as /config so it picks up fuzzingserver.json

PROJECT_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
CFG_DIR="$PROJECT_ROOT/test/autobahn"
IMAGE="crossbario/autobahn-testsuite:latest"
NAME="cwebsocket-autobahn"

if ! command -v docker >/dev/null 2>&1; then
  echo "Docker is required to run the Autobahn fuzzing server." >&2
  exit 1
fi

mkdir -p "$CFG_DIR/reports/clients"

# Optionally use a lighter fuzzing server config excluding compression suites
SPEC_FILE="fuzzingserver.json"
if [ "${WS_EXCLUDE_COMPRESS:-0}" != "0" ] && [ -f "$CFG_DIR/fuzzingserver-nocompress.json" ]; then
  cp -f "$CFG_DIR/fuzzingserver-nocompress.json" "$CFG_DIR/fuzzingserver.json"
  SPEC_FILE="fuzzingserver.json"
fi

echo "Starting Autobahn fuzzing server container ($NAME) ..."
docker rm -f "$NAME" >/dev/null 2>&1 || true
# Host port configuration (defaults avoid common conflicts)
HOST_WS_PORT=${AUTOBahn_WS_PORT:-8111}
HOST_UI_PORT=${AUTOBahn_UI_PORT:-8112}

# Allow skipping the web UI port mapping (set AUTOBahn_MAP_UI=0)
MAP_UI=${AUTOBahn_MAP_UI:-1}
PORT_ARGS=(-p "${HOST_WS_PORT}:9001")
if [ "$MAP_UI" != "0" ]; then
  PORT_ARGS+=( -p "${HOST_UI_PORT}:8080" )
fi

docker run -d --rm \
  --name "$NAME" \
  -v "$CFG_DIR":/config \
  "${PORT_ARGS[@]}" \
  "$IMAGE" >/dev/null

# Wait for port 9001 to accept connections (best-effort)
echo -n "Waiting for fuzzing server on 127.0.0.1:${HOST_WS_PORT} ..."
for i in {1..60}; do
  if (exec 3<>/dev/tcp/127.0.0.1/${HOST_WS_PORT}) 2>/dev/null; then
    exec 3>&-
    echo " up"
    exit 0
  fi
  sleep 0.5
  echo -n "."
done
echo " timeout"
exit 1

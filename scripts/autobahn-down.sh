#!/usr/bin/env bash
set -euo pipefail

NAME="cwebsocket-autobahn"

if ! command -v docker >/dev/null 2>&1; then
  echo "Docker is required to manage the Autobahn fuzzing server." >&2
  exit 1
fi

echo "Stopping Autobahn fuzzing server container ($NAME) ..."
docker rm -f "$NAME" >/dev/null 2>&1 || true


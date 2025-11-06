#!/usr/bin/env bash
set -euo pipefail

PROJECT_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$PROJECT_ROOT"

REPORT_DIR="test/autobahn/reports/clients"

# Ensure fuzzing server is up
"$PROJECT_ROOT/scripts/autobahn-up.sh"

# Build testsuite binary if missing
if [[ ! -x "$PROJECT_ROOT/websocket-testsuite" ]]; then
  echo "Building websocket-testsuite ..."
  if [[ -x ./autogen.sh && ! -f ./Makefile ]]; then
    ./autogen.sh
    ./configure
  fi
  make -j$(nproc) websocket-testsuite
fi

# Clean previous client reports
mkdir -p "$REPORT_DIR"
find "$REPORT_DIR" -mindepth 1 -maxdepth 1 -type f -delete || true

HOST_WS_PORT=${AUTOBahn_WS_PORT:-8111}
HOST_UI_PORT=${AUTOBahn_UI_PORT:-8112}
MAP_UI=${AUTOBahn_MAP_UI:-1}

export CWS_SYNC_CALLBACKS=${CWS_SYNC_CALLBACKS:-1}
echo "Running Autobahn client tests (CWS_SYNC_CALLBACKS=$CWS_SYNC_CALLBACKS) ..."
set +e
"$PROJECT_ROOT/websocket-testsuite" > testsuite.log 2>&1
status=$?
set -e

"$PROJECT_ROOT/scripts/autobahn-down.sh" || true

echo "Tests complete. Reports at: $REPORT_DIR"
if [ "$MAP_UI" != "0" ]; then
  echo "web UI: http://127.0.0.1:${HOST_UI_PORT}/clients/"
else
  echo "web UI not mapped (set AUTOBahn_MAP_UI=1 and AUTOBahn_UI_PORT to enable)"
fi

exit $status

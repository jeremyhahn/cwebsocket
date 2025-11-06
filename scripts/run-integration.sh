#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.."

REPORT_DIR="test/autobahn/reports/clients"
mkdir -p "$REPORT_DIR"

echo "Starting Autobahn fuzzing server in background..."
set +e
wstest -m fuzzingserver -s test/autobahn/fuzzingserver.json >/tmp/fuzzingserver.log 2>&1 &
WS_PID=$!
set -e

# Wait for port 9001
echo -n "Waiting for 127.0.0.1:9001 ..."
for i in {1..60}; do
  if (exec 3<>/dev/tcp/127.0.0.1/9001) 2>/dev/null; then
    exec 3>&-
    echo " up"
    break
  fi
  sleep 0.5
  echo -n "."
done

echo "Running websocket-testsuite against fuzzing server..."
./websocket-testsuite

echo "Stopping fuzzing server (pid=$WS_PID) ..."
kill "$WS_PID" >/dev/null 2>&1 || true
wait "$WS_PID" 2>/dev/null || true

echo "Reports available in $REPORT_DIR"


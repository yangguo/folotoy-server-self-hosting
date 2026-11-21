#!/bin/sh
# Start the pinned xiaozhi-server as a local process (demo mode) and run both
# the tightened contract test and the full regression suite.
# Docker is optional; this path does not call xiaozhi.me or a paid model API.
set -eu

ROOT=$(CDPATH= cd -- "$(dirname "$0")/.." && pwd)
RUNTIME="$ROOT/runtime"
SHA=8f2dda09cf18f1c1ece0f906eee4cc2fabb7fb58
SRC="$RUNTIME/xiaozhi-esp32-server"
SERVER="$SRC/main/xiaozhi-server"
VENV="$RUNTIME/venv"
UPSTREAM_REPO="${PASSPORT_UPSTREAM_REPO:-https://github.com/xinnan-tech/xiaozhi-esp32-server.git}"
mkdir -p "$RUNTIME"

pick_python() {
  if [ -n "${PASSPORT_PYTHON:-}" ] && [ -x "${PASSPORT_PYTHON}" ]; then
    echo "$PASSPORT_PYTHON"
    return
  fi
  for cand in python3.10 python3.11 python3.12; do
    if command -v "$cand" >/dev/null 2>&1; then
      command -v "$cand"
      return
    fi
  done
  for cand in "$HOME"/.local/share/uv/python/cpython-3.1[012]*/bin/python3*; do
    if [ -x "$cand" ]; then
      echo "$cand"
      return
    fi
  done
  command -v python3
}

PY_BIN=$(pick_python)

if [ ! -d "$SRC/.git" ]; then
  git clone --depth 1 --branch v0.9.8 "$UPSTREAM_REPO" "$SRC"
fi
ACTUAL=$(git -C "$SRC" rev-parse HEAD)
if [ "$ACTUAL" != "$SHA" ]; then
  echo "upstream checkout is $ACTUAL, expected $SHA" >&2
  exit 1
fi
if ! git -C "$SRC" diff --quiet || ! git -C "$SRC" diff --cached --quiet; then
  echo "upstream checkout at $SRC has modified tracked files; refusing to run" >&2
  exit 1
fi

if [ ! -x "$VENV/bin/python" ]; then
  "$PY_BIN" -m venv "$VENV"
fi
if [ "${PASSPORT_SKIP_PIP:-0}" != "1" ]; then
  "$VENV/bin/pip" install --disable-pip-version-check -r "$ROOT/requirements-runtime.txt"
fi

ONNX_DEST="$SERVER/models/snakers4_silero-vad/src/silero_vad/data/silero_vad.onnx"
"$VENV/bin/python" - <<PY
import hashlib, pathlib
p = pathlib.Path("$ONNX_DEST")
digest = hashlib.sha256(p.read_bytes()).hexdigest()
expected = "2623a2953f6ff3d2c1e61740c6cdb7168133479b267dfef114a4a3cc5bdd788f"
assert digest == expected, f"unexpected silero_vad.onnx sha256: {digest} != {expected}"
print("silero verified:", p, digest[:12])
PY

export XIAOZHI_HOME="$SERVER"
export PASSPORT_MODE=demo
export PASSPORT_AUTH_FILE="$RUNTIME/auth_key"
export PASSPORT_DEVICES_FILE="$RUNTIME/devices.yaml"
export PASSPORT_BIND="${PASSPORT_BIND:-127.0.0.1}"
export PASSPORT_WS_BIND_PORT="${PASSPORT_WS_BIND_PORT:-18010}"
export PASSPORT_HTTP_BIND_PORT="${PASSPORT_HTTP_BIND_PORT:-18013}"
export PASSPORT_PUBLIC_WS="${PASSPORT_PUBLIC_WS:-ws://127.0.0.1:18010/xiaozhi/v1/}"
export PASSPORT_PUBLIC_HTTP="${PASSPORT_PUBLIC_HTTP:-http://127.0.0.1:18013/mcp/vision/explain}"
export PASSPORT_FAKE_BASE="${PASSPORT_FAKE_BASE:-http://127.0.0.1:18019}"

# Provision a fresh ephemeral contract-test device without leaving credentials in git.
rm -f "$PASSPORT_DEVICES_FILE"
CONTRACT_SECRET=$("$VENV/bin/python" - <<'PY'
import secrets
print("ctr_" + secrets.token_urlsafe(18))
PY
)
"$VENV/bin/python" "$ROOT/scripts/provision_device.py" add \
  --devices-file "$PASSPORT_DEVICES_FILE" \
  --device-id "aa:bb:cc:dd:ee:10" \
  --client-id "passport-contract-client" \
  --name "contract-test-device" \
  --secret "$CONTRACT_SECRET" >/dev/null

"$VENV/bin/python" "$ROOT/scripts/write_config.py"

cleanup() {
  if [ -n "${SERVER_PID:-}" ]; then kill "$SERVER_PID" 2>/dev/null || true; fi
  if [ -n "${FAKE_PID:-}" ]; then kill "$FAKE_PID" 2>/dev/null || true; fi
}
trap cleanup EXIT INT TERM

"$VENV/bin/python" "$ROOT/fake_provider.py" --host 127.0.0.1 --port 18019 \
  > "$RUNTIME/fake-provider.log" 2>&1 &
FAKE_PID=$!
"$VENV/bin/python" "$ROOT/passport_server/runner.py" > "$RUNTIME/xiaozhi-server.log" 2>&1 &
SERVER_PID=$!

ready=0
i=0
while [ "$i" -lt 60 ]; do
  if curl -fsS http://127.0.0.1:18013/xiaozhi/ota/ >/dev/null 2>&1; then
    ready=1
    break
  fi
  if ! kill -0 "$SERVER_PID" 2>/dev/null; then
    echo "xiaozhi-server exited during startup" >&2
    tail -n 80 "$RUNTIME/xiaozhi-server.log" >&2 || true
    exit 1
  fi
  i=$((i + 1))
  sleep 1
done
if [ "$ready" -ne 1 ]; then
  echo "OTA port did not become ready" >&2
  tail -n 80 "$RUNTIME/xiaozhi-server.log" >&2 || true
  exit 1
fi

PASSPORT_TEST_OTA_SECRET="$CONTRACT_SECRET" \
  "$VENV/bin/python" "$ROOT/scripts/contract_test.py" \
    --ota http://127.0.0.1:18013 \
    --fake-control http://127.0.0.1:18019

# Stop demo server cleanly so regression_test.py can verify end-to-end logs and run isolated checks.
kill -TERM "$SERVER_PID" 2>/dev/null || true
wait "$SERVER_PID" 2>/dev/null || true
SERVER_PID=""
kill -TERM "$FAKE_PID" 2>/dev/null || true
wait "$FAKE_PID" 2>/dev/null || true
FAKE_PID=""

"$VENV/bin/python" "$ROOT/scripts/regression_test.py"
echo "server log: $RUNTIME/xiaozhi-server.log"

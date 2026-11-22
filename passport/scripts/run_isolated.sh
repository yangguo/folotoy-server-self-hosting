#!/bin/sh
# Start the pinned xiaozhi-server as a local process (demo mode) and run both
# the tightened contract test and the full regression suite.
# Docker is optional; this path does not call xiaozhi.me or a paid model API.
set -eu

ROOT=$(CDPATH= cd -- "$(dirname "$0")/.." && pwd)
RUNTIME="$ROOT/runtime"
DEMO_RUNTIME="${PASSPORT_DEMO_RUNTIME:-$ROOT/runtime-demo}"
DEMO_HOME="$DEMO_RUNTIME/xiaozhi-home"
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

# Refuse before creating any demo directory if demo paths point inside real runtime/.
"$PY_BIN" - "$RUNTIME" "$DEMO_RUNTIME" "$DEMO_HOME" "$DEMO_RUNTIME/devices.yaml" "$DEMO_RUNTIME/auth_key" "$DEMO_HOME/tmp" <<'PY'
import pathlib, sys
real_runtime = pathlib.Path(sys.argv[1]).resolve()
for raw in sys.argv[2:]:
    cand = pathlib.Path(raw).resolve()
    if cand == real_runtime or real_runtime in cand.parents:
        sys.exit(f"Refusing demo run with path inside real runtime directory: {cand}")
PY

mkdir -p "$DEMO_RUNTIME" "$DEMO_HOME/data" "$DEMO_HOME/tmp"

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

for item in app.py config core models plugins_func config.yaml; do
  if [ -e "$SERVER/$item" ]; then
    ln -sfn "$SERVER/$item" "$DEMO_HOME/$item"
  fi
done

export XIAOZHI_HOME="$DEMO_HOME"
export PASSPORT_MODE=demo
export PASSPORT_CONFIG_FILE="$ROOT/config/demo.config.yaml"
export PASSPORT_AUTH_FILE="$DEMO_RUNTIME/auth_key"
export PASSPORT_DEVICES_FILE="$DEMO_RUNTIME/devices.yaml"
export PASSPORT_LOG_DIR="$DEMO_HOME/tmp"
export PASSPORT_BIND="${PASSPORT_BIND:-127.0.0.1}"
export PASSPORT_WS_BIND_PORT="${PASSPORT_WS_BIND_PORT:-18010}"
export PASSPORT_HTTP_BIND_PORT="${PASSPORT_HTTP_BIND_PORT:-18013}"
export PASSPORT_FAKE_PORT="${PASSPORT_FAKE_PORT:-18019}"
export PASSPORT_PUBLIC_WS="${PASSPORT_PUBLIC_WS:-ws://${PASSPORT_BIND}:${PASSPORT_WS_BIND_PORT}/xiaozhi/v1/}"
export PASSPORT_PUBLIC_HTTP="${PASSPORT_PUBLIC_HTTP:-http://${PASSPORT_BIND}:${PASSPORT_HTTP_BIND_PORT}/mcp/vision/explain}"
export PASSPORT_FAKE_BASE="${PASSPORT_FAKE_BASE:-http://127.0.0.1:${PASSPORT_FAKE_PORT}}"

# Provision a fresh ephemeral contract-test device inside DEMO_RUNTIME only.
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

"$VENV/bin/python" "$ROOT/fake_provider.py" --host 127.0.0.1 --port "$PASSPORT_FAKE_PORT" \
  > "$DEMO_RUNTIME/fake-provider.log" 2>&1 &
FAKE_PID=$!
"$VENV/bin/python" "$ROOT/passport_server/runner.py" > "$DEMO_RUNTIME/xiaozhi-server.log" 2>&1 &
SERVER_PID=$!

ready=0
i=0
while [ "$i" -lt 60 ]; do
  if curl -fsS "http://${PASSPORT_BIND}:${PASSPORT_HTTP_BIND_PORT}/xiaozhi/ota/" >/dev/null 2>&1; then
    ready=1
    break
  fi
  if ! kill -0 "$SERVER_PID" 2>/dev/null; then
    echo "xiaozhi-server exited during startup" >&2
    tail -n 80 "$DEMO_RUNTIME/xiaozhi-server.log" >&2 || true
    exit 1
  fi
  i=$((i + 1))
  sleep 1
done
if [ "$ready" -ne 1 ]; then
  echo "OTA port did not become ready" >&2
  tail -n 80 "$DEMO_RUNTIME/xiaozhi-server.log" >&2 || true
  exit 1
fi

PASSPORT_TEST_OTA_SECRET="$CONTRACT_SECRET" \
  "$VENV/bin/python" "$ROOT/scripts/contract_test.py" \
    --ota "http://${PASSPORT_BIND}:${PASSPORT_HTTP_BIND_PORT}" \
    --fake-control "http://127.0.0.1:${PASSPORT_FAKE_PORT}"

# Stop demo server cleanly so regression_test.py can verify end-to-end logs and run isolated checks.
kill -TERM "$SERVER_PID" 2>/dev/null || true
wait "$SERVER_PID" 2>/dev/null || true
SERVER_PID=""
kill -TERM "$FAKE_PID" 2>/dev/null || true
wait "$FAKE_PID" 2>/dev/null || true
FAKE_PID=""

if [ "${PASSPORT_SKIP_REGRESSION:-0}" != "1" ]; then
  XIAOZHI_HOME="$SERVER" "$VENV/bin/python" "$ROOT/scripts/regression_test.py"
fi
echo "demo runtime: $DEMO_RUNTIME"
echo "server log: $DEMO_RUNTIME/xiaozhi-server.log"

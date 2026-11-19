#!/bin/sh
# Start the pinned xiaozhi-server as a local process and run the contract test.
# Docker is optional; this path does not call xiaozhi.me or a paid model API.
set -eu

ROOT=$(CDPATH= cd -- "$(dirname "$0")/.." && pwd)
RUNTIME="$ROOT/runtime"
SHA=8f2dda09cf18f1c1ece0f906eee4cc2fabb7fb58
SRC="$RUNTIME/xiaozhi-esp32-server"
SERVER="$SRC/main/xiaozhi-server"
VENV="$RUNTIME/venv"
mkdir -p "$RUNTIME"

if [ ! -d "$SRC/.git" ]; then
  git clone --depth 1 --branch v0.9.8 \
    https://github.com/xinnan-tech/xiaozhi-esp32-server.git "$SRC"
fi
ACTUAL=$(git -C "$SRC" rev-parse HEAD)
if [ "$ACTUAL" != "$SHA" ]; then
  echo "upstream checkout is $ACTUAL, expected $SHA" >&2
  exit 1
fi

if [ ! -x "$VENV/bin/python" ]; then
  python3 -m venv "$VENV"
fi
"$VENV/bin/pip" install --disable-pip-version-check -r "$ROOT/requirements-runtime.txt"

"$VENV/bin/python" - <<PY
import pathlib, shutil, silero_vad
src = pathlib.Path(silero_vad.__file__).parent
hits = list(src.rglob("silero_vad.onnx"))
if not hits:
    raise SystemExit(f"silero_vad.onnx not found under {src}")
dest = pathlib.Path("$SERVER") / "models/snakers4_silero-vad/src/silero_vad/data"
dest.mkdir(parents=True, exist_ok=True)
shutil.copy(hits[0], dest / "silero_vad.onnx")
print("silero", hits[0], "->", dest)
PY

export XIAOZHI_HOME="$SERVER"
export PASSPORT_AUTH_FILE="$RUNTIME/auth_key"
export PASSPORT_BIND="${PASSPORT_BIND:-127.0.0.1}"
export PASSPORT_WS_BIND_PORT="${PASSPORT_WS_BIND_PORT:-18010}"
export PASSPORT_HTTP_BIND_PORT="${PASSPORT_HTTP_BIND_PORT:-18013}"
export PASSPORT_PUBLIC_WS="${PASSPORT_PUBLIC_WS:-ws://127.0.0.1:18010/xiaozhi/v1/}"
export PASSPORT_PUBLIC_HTTP="${PASSPORT_PUBLIC_HTTP:-http://127.0.0.1:18013/mcp/vision/explain}"
export PASSPORT_FAKE_BASE="${PASSPORT_FAKE_BASE:-http://127.0.0.1:18019}"
"$VENV/bin/python" "$ROOT/scripts/write_config.py"

cleanup() {
  if [ -n "${SERVER_PID:-}" ]; then kill "$SERVER_PID" 2>/dev/null || true; fi
  if [ -n "${FAKE_PID:-}" ]; then kill "$FAKE_PID" 2>/dev/null || true; fi
}
trap cleanup EXIT INT TERM

"$VENV/bin/python" "$ROOT/fake_provider.py" --host 127.0.0.1 --port 18019 \
  > "$RUNTIME/fake-provider.log" 2>&1 &
FAKE_PID=$!
cd "$SERVER"
"$VENV/bin/python" app.py > "$RUNTIME/xiaozhi-server.log" 2>&1 &
SERVER_PID=$!
cd "$ROOT"

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

"$VENV/bin/python" "$ROOT/scripts/contract_test.py"
echo "server log: $RUNTIME/xiaozhi-server.log"

#!/bin/sh
# Start the pinned xiaozhi-server as a local process (demo mode) and run both
# the tightened contract test and the full regression suite.
# Docker is optional; this path does not call xiaozhi.me or a paid model API.
#
# Isolation boundary: every writable output (state, logs, generated config) and
# every dependency install goes under $DEMO_RUNTIME. An existing real
# runtime/venv and upstream checkout are only reused read-only.
set -eu

ROOT=$(CDPATH= cd -- "$(dirname "$0")/.." && pwd)
RUNTIME="$ROOT/runtime"
DEMO_RUNTIME="${PASSPORT_DEMO_RUNTIME:-$ROOT/runtime-demo}"
DEMO_HOME="$DEMO_RUNTIME/xiaozhi-home"
DEMO_VENV="$DEMO_RUNTIME/venv"
SHARED_VENV="$RUNTIME/venv"
SHA=8f2dda09cf18f1c1ece0f906eee4cc2fabb7fb58
if [ -d "$RUNTIME/xiaozhi-esp32-server/.git" ]; then
  # Read-only reuse of an existing pinned checkout (verified clean below).
  SRC="$RUNTIME/xiaozhi-esp32-server"
else
  SRC="$DEMO_RUNTIME/xiaozhi-esp32-server"
fi
SERVER="$SRC/main/xiaozhi-server"
UPSTREAM_REPO="${PASSPORT_UPSTREAM_REPO:-https://github.com/xinnan-tech/xiaozhi-esp32-server.git}"

# The demo must never inherit the real signing key or redirect pip elsewhere.
unset PASSPORT_AUTH_KEY PIP_CONFIG_FILE PIP_TARGET PIP_PREFIX PIP_ROOT PIP_USER PIP_PYTHON
# Never write bytecode into the read-only shared venv / upstream checkout, and
# never load per-user site-packages outside the demo venv.
export PYTHONDONTWRITEBYTECODE=1
export PYTHONNOUSERSITE=1

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

guard_paths() {
  "$PY_BIN" - "$RUNTIME" "$@" <<'PY'
import pathlib, sys
real_runtime = pathlib.Path(sys.argv[1]).resolve()
for raw in sys.argv[2:]:
    cand = pathlib.Path(raw).resolve()
    if cand == real_runtime or real_runtime in cand.parents:
        sys.exit(f"Refusing demo run with path inside real runtime directory: {cand}")
PY
}

# Refuse before creating any demo directory if demo dirs point inside real runtime/.
guard_paths "$DEMO_RUNTIME" "$DEMO_HOME" "$DEMO_HOME/tmp" "$DEMO_HOME/data" "$DEMO_VENV"

mkdir -p "$DEMO_RUNTIME" "$DEMO_HOME/data" "$DEMO_HOME/tmp"

# Writable outputs (and their sidecar lock files) are recreated on every run.
# `rm -f` unlinks a pre-existing symlink / hard link at that path without
# touching its target, so redirects, writers, and sidecar fchmod() can never
# truncate, rewrite, or re-chmod real files.
set -- "$DEMO_RUNTIME/fake-provider.log" "$DEMO_RUNTIME/xiaozhi-server.log" \
  "$DEMO_RUNTIME/devices.yaml" "$DEMO_RUNTIME/auth_key" \
  "$DEMO_RUNTIME/.devices.yaml.lock" "$DEMO_RUNTIME/.auth_key.lock" \
  "$DEMO_HOME/tmp/server.log" "$DEMO_HOME/data/.config.yaml"
for out in "$@"; do
  rm -f "$out"
done
guard_paths "$@"

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

# Demo-only venv. When a shared runtime/venv exists, its site-packages are
# exposed read-only via a .pth file; pip can only install into $DEMO_VENV.
if [ ! -x "$DEMO_VENV/bin/python" ]; then
  if [ -x "$SHARED_VENV/bin/python" ]; then
    "$SHARED_VENV/bin/python" -m venv "$DEMO_VENV"
  else
    "$PY_BIN" -m venv "$DEMO_VENV"
  fi
fi
if [ -x "$SHARED_VENV/bin/python" ]; then
  SHARED_INFO=$("$SHARED_VENV/bin/python" -c 'import sys, sysconfig; print("%d.%d" % sys.version_info[:2]); print(sysconfig.get_paths()["purelib"])')
  "$DEMO_VENV/bin/python" - "$SHARED_INFO" "$DEMO_VENV" "$RUNTIME" <<'PY'
import os, pathlib, sys, sysconfig, tempfile
shared_ver, shared_site = sys.argv[1].splitlines()[:2]
demo_venv = pathlib.Path(sys.argv[2]).resolve()
real_runtime = pathlib.Path(sys.argv[3]).resolve()
purelib = pathlib.Path(sysconfig.get_paths()["purelib"]).resolve()
if demo_venv not in purelib.parents or purelib == real_runtime or real_runtime in purelib.parents:
    sys.exit(f"Refusing demo venv purelib outside demo venv: {purelib}")
target = purelib / "zz_passport_shared_readonly.pth"
if shared_ver == "%d.%d" % sys.version_info[:2]:
    content = f"import site; site.addsitedir({shared_site!r})\n"
    fd, tmp_name = tempfile.mkstemp(
        prefix=".zz_passport_shared_readonly.",
        suffix=".pth.tmp",
        dir=str(purelib),
    )
    try:
        os.fchmod(fd, 0o644)
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            handle.write(content)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(tmp_name, target)
    except BaseException:
        try:
            os.unlink(tmp_name)
        except OSError:
            pass
        raise
elif target.is_symlink() or target.exists():
    target.unlink()
PY
fi
if [ "${PASSPORT_SKIP_PIP:-0}" != "1" ]; then
  PIP_CONFIG_FILE=/dev/null "$DEMO_VENV/bin/python" - "$DEMO_VENV" "$RUNTIME" \
    --isolated --disable-pip-version-check -r "$ROOT/requirements-runtime.txt" <<'PY'
import os, pathlib, sys, sysconfig
from pip._internal.commands.install import InstallCommand
from pip._internal.locations import get_scheme

demo_venv = pathlib.Path(sys.argv[1]).resolve()
real_runtime = pathlib.Path(sys.argv[2]).resolve()
pip_args = sys.argv[3:]

def _assert_inside_demo(label: str, raw_path: str) -> pathlib.Path:
    resolved = pathlib.Path(raw_path).resolve()
    if resolved == real_runtime or real_runtime in resolved.parents:
        sys.exit(f"Refusing pip {label} inside real runtime: {resolved}")
    if resolved != demo_venv and demo_venv not in resolved.parents:
        sys.exit(f"Refusing pip {label} outside demo venv ({demo_venv}): {resolved}")
    return resolved

if os.environ.get("PIP_CONFIG_FILE") != os.devnull:
    sys.exit(f"Refusing demo pip without PIP_CONFIG_FILE={os.devnull}")

_assert_inside_demo("sys.prefix", sys.prefix)
sys_paths = sysconfig.get_paths()
for key in ("purelib", "platlib", "scripts", "data"):
    _assert_inside_demo(f"sysconfig.{key}", sys_paths[key])

cmd = InstallCommand("install", "demo-isolation-check")
options, _ = cmd.parse_args(pip_args)
if not options.isolated_mode:
    sys.exit("Refusing demo pip without isolated_mode")
if options.target_dir or options.prefix_path or options.root_path or getattr(options, "python", None):
    sys.exit(
        "Refusing demo pip with redirected install target: "
        f"target={options.target_dir!r} prefix={options.prefix_path!r} "
        f"root={options.root_path!r} python={getattr(options, 'python', None)!r}"
    )
if options.use_user_site:
    sys.exit("Refusing demo pip with user site-packages enabled")

scheme = get_scheme(
    "passport-demo-isolation-check",
    user=bool(options.use_user_site),
    root=options.root_path,
    isolated=bool(options.isolated_mode),
    prefix=options.prefix_path,
)
for attr in ("purelib", "platlib", "headers", "scripts", "data"):
    _assert_inside_demo(f"scheme.{attr}", getattr(scheme, attr))
PY
  PIP_CONFIG_FILE=/dev/null "$DEMO_VENV/bin/python" -m pip install \
    --isolated --disable-pip-version-check -r "$ROOT/requirements-runtime.txt"
fi
PYV="$DEMO_VENV/bin/python"

ONNX_DEST="$SERVER/models/snakers4_silero-vad/src/silero_vad/data/silero_vad.onnx"
"$PYV" - <<PY
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
CONTRACT_SECRET=$("$PYV" - <<'PY'
import secrets
print("ctr_" + secrets.token_urlsafe(18))
PY
)
"$PYV" "$ROOT/scripts/provision_device.py" add \
  --devices-file "$PASSPORT_DEVICES_FILE" \
  --device-id "aa:bb:cc:dd:ee:10" \
  --client-id "passport-contract-client" \
  --name "contract-test-device" \
  --secret "$CONTRACT_SECRET" >/dev/null

"$PYV" "$ROOT/scripts/write_config.py"

cleanup() {
  if [ -n "${SERVER_PID:-}" ]; then kill "$SERVER_PID" 2>/dev/null || true; fi
  if [ -n "${FAKE_PID:-}" ]; then kill "$FAKE_PID" 2>/dev/null || true; fi
}
trap cleanup EXIT INT TERM

"$PYV" "$ROOT/fake_provider.py" --host 127.0.0.1 --port "$PASSPORT_FAKE_PORT" \
  > "$DEMO_RUNTIME/fake-provider.log" 2>&1 &
FAKE_PID=$!
"$PYV" "$ROOT/passport_server/runner.py" > "$DEMO_RUNTIME/xiaozhi-server.log" 2>&1 &
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
  "$PYV" "$ROOT/scripts/contract_test.py" \
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
  XIAOZHI_HOME="$SERVER" "$PYV" "$ROOT/scripts/regression_test.py"
fi
echo "demo runtime: $DEMO_RUNTIME"
echo "server log: $DEMO_RUNTIME/xiaozhi-server.log"

#!/bin/sh
set -eu

ROOT=$(CDPATH= cd -- "$(dirname "$0")/.." && pwd)
PYTHON_BIN="${PASSPORT_PYTHON:-python}"

"$PYTHON_BIN" "$ROOT/scripts/write_config.py"
exec "$PYTHON_BIN" "$ROOT/passport_server/runner.py"

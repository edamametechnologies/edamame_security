#!/usr/bin/env bash
# Build a self-contained Linux bundle of the EDAMAME Attack Simulator that
# embeds its own standalone CPython (fetched with uv) plus the EDAMAME trigger
# scripts, their catalog.json, and a run.sh launcher. Recipients do not need
# Python installed. No code signing on Linux.
#
# Usage: build_linux.sh [OUTPUT_DIR]
#
# Required:
#   EDAMAME_TRIGGERS_DIR   the edamame_posture trigger scripts
#                          (tests/security/triggers), which carry catalog.json.
# Optional:
#   EDAMAME_EMBED_PYTHON_VERSION  embedded CPython version (default 3.11)
#
# The asset version is read from ./VERSION. Prints "ARTIFACT=<path>" as its
# last stdout line (the produced .tar.gz).
set -euo pipefail

PANEL_DIR="$(cd "$(dirname "$0")" && pwd)"
DIST_DIR="${1:-$PANEL_DIR/dist}"
PYTHON_VERSION="${EDAMAME_EMBED_PYTHON_VERSION:-3.11}"
APP_NAME="edamame-attack-simulator"
BUNDLE_DIR="$DIST_DIR/$APP_NAME"

if [[ -f "$PANEL_DIR/VERSION" ]]; then
  VERSION="$(tr -d ' \t\n\r' < "$PANEL_DIR/VERSION")"
else
  VERSION="${EDAMAME_SIMULATOR_VERSION:-dev}"
fi
[[ -n "$VERSION" ]] || VERSION="dev"

TRIGGERS_SRC="${EDAMAME_TRIGGERS_DIR:-}"
if [[ -z "$TRIGGERS_SRC" ]]; then
  echo "EDAMAME_TRIGGERS_DIR is required (path to edamame_posture/tests/security/triggers)." >&2
  exit 1
fi
if [[ ! -d "$TRIGGERS_SRC" ]]; then
  echo "EDAMAME_TRIGGERS_DIR is not a directory: $TRIGGERS_SRC" >&2
  exit 1
fi
if ! ls "$TRIGGERS_SRC"/trigger_*.py >/dev/null 2>&1; then
  echo "No trigger_*.py scripts found in $TRIGGERS_SRC" >&2
  exit 1
fi
if [[ ! -f "$TRIGGERS_SRC/catalog.json" ]]; then
  echo "catalog.json not found in $TRIGGERS_SRC (the simulator catalog ships with the triggers)." >&2
  exit 1
fi

if ! command -v uv >/dev/null 2>&1; then
  echo "uv is required to fetch a relocatable CPython (https://github.com/astral-sh/uv)" >&2
  exit 1
fi

export UV_PYTHON_PREFERENCE=only-managed
echo "Installing relocatable CPython ${PYTHON_VERSION} (x86_64)..."
uv python install "$PYTHON_VERSION"

PY_BIN="$(uv python find "$PYTHON_VERSION" 2>/dev/null || true)"
if [[ -z "$PY_BIN" || ! -x "$PY_BIN" ]]; then
  echo "Could not resolve CPython ${PYTHON_VERSION} via uv" >&2
  exit 1
fi
PY_HOME="$(cd "$(dirname "$PY_BIN")/.." && pwd)"
echo "Using Python home: $PY_HOME"
if [[ ! -x "$PY_HOME/bin/python3" ]]; then
  echo "Could not resolve Python home from $PY_BIN" >&2
  exit 1
fi
if ! "$PY_HOME/bin/python3" -c "import tkinter" >/dev/null 2>&1; then
  echo "Embedded Python at $PY_HOME has no tkinter; pick another version." >&2
  exit 1
fi

echo "Assembling $BUNDLE_DIR"
rm -rf "$BUNDLE_DIR"
mkdir -p "$BUNDLE_DIR/python" "$BUNDLE_DIR/triggers"

rsync -a \
  --exclude 'include' \
  --exclude 'share' \
  --exclude 'lib/python*/test' \
  --exclude 'lib/python*/idlelib' \
  --exclude 'lib/python*/turtledemo' \
  --exclude 'lib/python*/ensurepip' \
  --exclude '__pycache__' \
  --exclude '*.pyc' \
  "$PY_HOME/" "$BUNDLE_DIR/python/"

if [[ ! -x "$BUNDLE_DIR/python/bin/python3" ]]; then
  echo "Failed to assemble python/bin/python3" >&2
  exit 1
fi

cp "$PANEL_DIR/app.py" "$BUNDLE_DIR/app.py"
cp "$PANEL_DIR/app_texts.json" "$BUNDLE_DIR/app_texts.json"
cp "$PANEL_DIR/run_linux.sh" "$BUNDLE_DIR/run.sh"
chmod +x "$BUNDLE_DIR/run.sh"
rsync -a \
  --exclude '__pycache__' \
  --exclude '*.pyc' \
  --exclude '.DS_Store' \
  "$TRIGGERS_SRC/" "$BUNDLE_DIR/triggers/"
if [[ ! -f "$BUNDLE_DIR/triggers/catalog.json" ]]; then
  echo "catalog.json did not make it into the bundle." >&2
  exit 1
fi

"$BUNDLE_DIR/python/bin/python3" - <<'PY'
import tkinter, sys
print(f"embedded python ok: {sys.version.split()[0]} tk={tkinter.TkVersion}")
PY

TAR_NAME="edamame-attack-simulator-linux-x64-${VERSION}.tar.gz"
TAR_PATH="$DIST_DIR/$TAR_NAME"
rm -f "$TAR_PATH"
tar -C "$DIST_DIR" -czf "$TAR_PATH" "$APP_NAME"

SIZE="$(du -sh "$BUNDLE_DIR" | awk '{print $1}')"
echo "Built: $BUNDLE_DIR ($SIZE)"
echo "Tar:   $TAR_PATH"
ABS_TAR="$(cd "$(dirname "$TAR_PATH")" && pwd)/$(basename "$TAR_PATH")"
echo "ARTIFACT=$ABS_TAR"

#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
VIDSEC_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

# Preserve caller's working directory so the TUI file explorer opens where the user invoked the script.
export VIDSEC_CALLER_PWD="${VIDSEC_CALLER_PWD:-$PWD}"

export PATH="/opt/zig:/usr/local/bin:$PATH"

# Load .env if present
if [ -f "$VIDSEC_ROOT/configs/.env" ]; then
    set -a
    # shellcheck disable=SC1091
    source "$VIDSEC_ROOT/configs/.env"
    set +a
fi

# Ensure plugin directory points to vidsec's locally compiled drivers & extensions
export PARABELLUM_PLUGIN_DIR="${PARABELLUM_PLUGIN_DIR:-$VIDSEC_ROOT/zig-out/lib}"

ENGINE_BIN="${PARABELLUM_ENGINE_BIN:-$VIDSEC_ROOT/../engine/zig-out/bin/parabellum-engine}"
PIPELINE="${PIPELINE_PATH:-$VIDSEC_ROOT/configs/pipeline.yaml}"

cd "$VIDSEC_ROOT"

REBUILD=false
if [[ "${1:-}" == "--rebuild" || "${1:-}" == "-b" ]]; then
    REBUILD=true
    shift
fi

if [[ "$REBUILD" == "true" || ! -f "$VIDSEC_ROOT/zig-out/lib/libext_opentelemetry.so" ]]; then
    if [ -f "$SCRIPT_DIR/build.sh" ]; then
        echo "==> Building external drivers & extensions..."
        "$SCRIPT_DIR/build.sh"
    fi
fi

if [[ "$REBUILD" == "true" || ! -f "$VIDSEC_ROOT/zig-out/lib/libanalyzer.so" || ! -f "$VIDSEC_ROOT/zig-out/lib/libext_vidsec_tui.so" ]]; then
    echo "==> Building VidSec plugin & TUI..."
    zig build
fi

chmod 755 "$VIDSEC_ROOT"/zig-out/lib/*.so 2>/dev/null || true

CMD="${1:-tui}"
if [[ "$CMD" == "tui" || "$CMD" == "-t" || "$CMD" == "--tui" || "$CMD" == "serve" || "$CMD" == "-s" || "$CMD" == "--serve" ]]; then
    shift || true
    echo "==> Starting Parabellum Engine with VidSec TUI ('$PIPELINE')..."
    echo "==> Caller directory -> $VIDSEC_CALLER_PWD"
    exec "$ENGINE_BIN" --plugin-dir "$PARABELLUM_PLUGIN_DIR" \
        --serve --transport vidsec_tui --pipeline "$PIPELINE" "$@"
elif [[ "$CMD" == "validate" || "$CMD" == "-v" || "$CMD" == "--validate" ]]; then
    shift || true
    echo "==> Validating pipeline '$PIPELINE'..."
    exec "$ENGINE_BIN" --plugin-dir "$PARABELLUM_PLUGIN_DIR" validate "$PIPELINE" "$@"
elif [[ "$CMD" == "run" ]]; then
    shift || true
    echo "==> Running Parabellum pipeline '$PIPELINE'..."
    exec "$ENGINE_BIN" --plugin-dir "$PARABELLUM_PLUGIN_DIR" run "$PIPELINE" "$@"
else
    exec "$ENGINE_BIN" --plugin-dir "$PARABELLUM_PLUGIN_DIR" run "$@"
fi

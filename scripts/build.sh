#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
VIDSEC_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
PARABELLUM_ROOT="$(cd "$VIDSEC_ROOT/.." && pwd)"

export PATH="/opt/zig:/usr/local/bin:$PATH"

TARGET_DIR="$VIDSEC_ROOT/zig-out/lib"
mkdir -p "$TARGET_DIR"

COMPONENTS=(
    "$PARABELLUM_ROOT/engine"
    "$PARABELLUM_ROOT/driver"
    "$PARABELLUM_ROOT/extension"
)

shopt -s nullglob

for COMP_DIR in "${COMPONENTS[@]}"; do
    NAME="$(basename "$COMP_DIR")"
    if [ ! -d "$COMP_DIR" ]; then
        echo "==> Warning: Directory $COMP_DIR not found, skipping..."
        continue
    fi

    echo "==> Building $NAME with zig build..."
    (
        cd "$COMP_DIR"
        zig build "$@"
    )

    SO_FILES=("$COMP_DIR/zig-out/lib/"*.so)
    if [ ${#SO_FILES[@]} -gt 0 ]; then
        echo "==> Copying *.so from $NAME to $TARGET_DIR/..."
        cp "${SO_FILES[@]}" "$TARGET_DIR/"
        chmod 755 "$TARGET_DIR"/*.so 2>/dev/null || true
    else
        echo "==> Warning: No .so files found in $COMP_DIR/zig-out/lib/"
    fi
done

echo "==> Done!"

#!/usr/bin/env bash
set -euo pipefail

# Assemble a portable VidSec release bundle (vidsec CLI + vidsec_tui + configs/)
# using `hive package`.
# Usage: ./scripts/package-release.sh [linux|macos|windows|all]

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
VIDSEC_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
cd "$VIDSEC_ROOT"

HIVE_BIN="${HIVE_BIN:-$(command -v hive || echo "$VIDSEC_ROOT/../hive/zig-out/bin/hive")}"
if [ ! -x "$HIVE_BIN" ]; then
    echo "error: hive binary not found (set HIVE_BIN or add hive to PATH)" >&2
    exit 1
fi

VERSION="$(sed -nE 's/.*"version":[[:space:]]*"([^"]+)".*/\1/p' hive.json | head -n1)"
REQ_PROFILE="${1:-linux}"

package_one() {
    local profile="$1"
    local suffix exe_ext archive_ext
    case "$profile" in
        linux)
            suffix="linux-x86_64"
            exe_ext=""
            archive_ext="tar.gz"
            ;;
        macos)
            suffix="macos-aarch64"
            exe_ext=""
            archive_ext="tar.gz"
            ;;
        windows)
            suffix="windows-x86_64"
            exe_ext=".exe"
            archive_ext="zip"
            ;;
        *)
            echo "error: unsupported profile '$profile' (expected linux|macos|windows|all)" >&2
            exit 1
            ;;
    esac

    echo "==> Packaging vidsec-cli & vidsec-tui ($profile) via hive..."
    (cd "$VIDSEC_ROOT/vidsec-cli" && "$HIVE_BIN" package --profile "$profile" -x test)
    (cd "$VIDSEC_ROOT/vidsec-tui" && "$HIVE_BIN" package --profile "$profile" -x test)

    local pkg_name="vidsec-v${VERSION}-${suffix}"
    local stage_dir="$VIDSEC_ROOT/zig-out/release/${pkg_name}"
    local out_archive="$VIDSEC_ROOT/zig-out/release/${pkg_name}.${archive_ext}"

    rm -rf "$stage_dir" "$out_archive" "${out_archive}.sha256"
    mkdir -p "${stage_dir}/configs/pipelines"

    cp "$VIDSEC_ROOT/vidsec-cli/zig-out/dist/vidsec${exe_ext}" "${stage_dir}/"
    cp "$VIDSEC_ROOT/vidsec-tui/zig-out/dist/vidsec_tui${exe_ext}" "${stage_dir}/"

    cp "$VIDSEC_ROOT/configs/pipeline.yaml" \
       "$VIDSEC_ROOT/configs/schemas.yaml" \
       "$VIDSEC_ROOT/configs/capabilities.yaml" \
       "${stage_dir}/configs/"
    cp "$VIDSEC_ROOT/configs/.env.example" "${stage_dir}/configs/.env"
    cp "$VIDSEC_ROOT/configs/pipelines/"*.yaml "${stage_dir}/configs/pipelines/"
    [ -f "$VIDSEC_ROOT/README.md" ] && cp "$VIDSEC_ROOT/README.md" "${stage_dir}/"

    (
        cd "$VIDSEC_ROOT/zig-out/release"
        if [ "$archive_ext" = "tar.gz" ]; then
            tar -czf "${pkg_name}.tar.gz" "${pkg_name}"
        elif command -v zip >/dev/null 2>&1; then
            zip -rq "${pkg_name}.zip" "${pkg_name}"
        else
            python3 -m zipfile -c "${pkg_name}.zip" "${pkg_name}"
        fi

        if command -v sha256sum >/dev/null 2>&1; then
            sha256sum "${pkg_name}.${archive_ext}" > "${pkg_name}.${archive_ext}.sha256"
        else
            shasum -a 256 "${pkg_name}.${archive_ext}" > "${pkg_name}.${archive_ext}.sha256"
        fi
    )
    echo "==> Portable release ready: zig-out/release/${pkg_name}.${archive_ext}"
}

if [ "$REQ_PROFILE" = "all" ]; then
    for p in linux macos windows; do
        package_one "$p"
    done
else
    package_one "$REQ_PROFILE"
fi

(
    cd "$VIDSEC_ROOT/zig-out/release"
    cat *.sha256 > SHA256SUMS.txt
)
ls -lh "$VIDSEC_ROOT/zig-out/release/"*.{tar.gz,zip} 2>/dev/null || true

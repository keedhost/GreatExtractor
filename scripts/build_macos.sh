#!/usr/bin/env bash
# Збирає реліз greatie під macOS для x86_64 та arm64.
# Xcode-тулчейн підтримує обидві архітектури "з коробки" — окремих
# cross-компіляторів для macOS->macOS не потрібно.
set -euo pipefail

cd "$(dirname "${BASH_SOURCE[0]}")/.."

BIN_NAME="greatie"
DIST_DIR="dist"
TARGETS=("x86_64-apple-darwin" "aarch64-apple-darwin")

rm -rf "$DIST_DIR"
mkdir -p "$DIST_DIR"

for target in "${TARGETS[@]}"; do
    echo "==> Очищення попередньої збірки для $target"
    cargo clean --release --target "$target" 2>/dev/null || true

    echo "==> Збірка для $target"
    rustup target add "$target" >/dev/null 2>&1 || true

    if cargo build --release --target "$target"; then
        arch="${target%%-*}"
        out_path="$DIST_DIR/${BIN_NAME}-macos-${arch}"
        cp "target/$target/release/$BIN_NAME" "$out_path"
        echo "    -> $out_path"
    else
        echo "    !! Збірка для $target не вдалася — пропускаю" >&2
    fi
done

echo "Готово. Бінарники у $DIST_DIR/"

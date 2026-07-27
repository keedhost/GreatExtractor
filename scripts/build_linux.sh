#!/usr/bin/env bash
# Збирає реліз greatie під Linux для поточної архітектури хоста (x86_64 або
# arm64/aarch64) як статичний musl-бінарник.
#
# Цей скрипт НЕ виконує крос-компіляцію між операційними системами чи
# архітектурами — Linux/musl-цілі вимагають справжнього musl cross-лінкера,
# якого немає в стандартному тулчейні macOS/Windows. Спроба зібрати
# aarch64/x86_64-unknown-linux-musl системним `cc` на macOS падає з
# помилками на кшталт "ld: unknown options --as-needed -Bstatic ..." —
# це GNU-специфічні прапорці лінкера, яких Apple ld64 просто не розуміє.
#
# Правильний спосіб отримати ОБИДВА Linux-бінарники — запустити цей скрипт
# двічі, кожного разу НА відповідному Linux-хості:
#   - на x86_64 Linux (локально або GitHub Actions runner `ubuntu-latest`)
#   - на arm64 Linux (локально або runner `ubuntu-24.04-arm` чи новіший)
# Кожен запуск нативно збирає лише свою архітектуру, без жодного
# cross-тулчейну.
set -euo pipefail

if [ "$(uname -s)" != "Linux" ]; then
    echo "Цей скрипт призначений для запуску НА Linux (локально або в CI runner'і)." >&2
    echo "Поточна ОС: $(uname -s). Крос-компіляція Linux-цілей з іншої ОС тут не підтримується —" >&2
    echo "системний лінкер хоста не вміє створювати статичні musl/ELF-бінарники." >&2
    exit 1
fi

cd "$(dirname "${BASH_SOURCE[0]}")/.."

BIN_NAME="greatie"
DIST_DIR="dist"

case "$(uname -m)" in
    x86_64) target="x86_64-unknown-linux-musl" ;;
    aarch64|arm64) target="aarch64-unknown-linux-musl" ;;
    *)
        echo "Невідома архітектура хоста: $(uname -m)" >&2
        exit 1
        ;;
esac

rm -rf "$DIST_DIR"
mkdir -p "$DIST_DIR"

echo "==> Очищення попередньої збірки для $target"
cargo clean --release --target "$target" 2>/dev/null || true

echo "==> Збірка для $target (нативно)"
rustup target add "$target" >/dev/null 2>&1 || true
cargo build --release --target "$target"

arch="${target%%-*}"
out_path="$DIST_DIR/${BIN_NAME}-linux-${arch}"
cp "target/$target/release/$BIN_NAME" "$out_path"
echo "    -> $out_path"

echo "Готово. Бінарник у $DIST_DIR/"
echo "Порада: щоб отримати ОБИДВІ Linux-архітектури, запустіть цей скрипт окремо"
echo "на x86_64 та на arm64 Linux-хостах (напр. у CI-матриці з runner'ами"
echo "ubuntu-latest і ubuntu-24.04-arm)."

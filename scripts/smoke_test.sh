#!/usr/bin/env bash
# Sanity/smoke-тести вже зібраного бінарника greatie перед деплоєм
# артифакту. Використовується в CI для Linux/macOS/FreeBSD, але однаково
# придатний і для локальної перевірки.
#
# Перевіряє:
#   1. Архітектуру/тип файлу (`file`).
#   2. Задоволеність динамічних залежностей (`ldd`/`otool -L`) відповідно
#      до очікуваного типу лінкування (static/dynamic).
#   3. Що бінарник реально запускається (--version/--help/--formats).
#   4. Базову працездатність команд scan/entropy на штучно склеєному
#      мультиформатному тестовому файлі.
#
# Використання: smoke_test.sh <шлях-до-бінарника> <static|dynamic> [лог-файл]
set -uo pipefail

BIN="${1:?потрібен шлях до бінарника}"
LINKING="${2:?потрібно вказати 'static' або 'dynamic'}"
LOG="${3:-smoke-test.log}"

: > "$LOG"
FAILED=0

log() {
    printf '%s\n' "$*" | tee -a "$LOG"
}

step() {
    local name="$1"
    shift
    log "==> ${name}"
    if "$@" >>"$LOG" 2>&1; then
        log "    OK"
    else
        log "    FAIL (exit $?)"
        FAILED=1
    fi
}

log "=== Smoke test: ${BIN} (linking=${LINKING}) — $(date -u +%Y-%m-%dT%H:%M:%SZ) ==="

if [ ! -f "$BIN" ]; then
    log "!! Бінарник не знайдено: ${BIN}"
    exit 1
fi
chmod +x "$BIN"

log "==> file(1) — перевірка типу/архітектури"
file "$BIN" | tee -a "$LOG"

OS="$(uname -s)"
case "$OS" in
    Linux|FreeBSD)
        log "==> ldd — перевірка задоволеності динамічних залежностей"
        LDD_OUT="$(ldd "$BIN" 2>&1 || true)"
        printf '%s\n' "$LDD_OUT" | tee -a "$LOG"
        if [ "$LINKING" = "static" ]; then
            if ! printf '%s' "$LDD_OUT" | grep -qi "not a dynamic executable\|statically linked"; then
                log "!! Очікувався статичний бінарник, але ldd повідомляє про динамічні залежності"
                FAILED=1
            fi
        else
            if printf '%s' "$LDD_OUT" | grep -qi "not found"; then
                log "!! Незадоволені динамічні залежності (позначено 'not found')"
                FAILED=1
            fi
        fi
        ;;
    Darwin)
        log "==> otool -L — перевірка задоволеності динамічних залежностей"
        otool -L "$BIN" 2>&1 | tee -a "$LOG"
        ;;
    *)
        log "!! Невідома ОС '${OS}' — пропускаю перевірку залежностей"
        ;;
esac

TMP_DIR="$(mktemp -d)"
trap 'rm -rf "$TMP_DIR"' EXIT

step "--version" "$BIN" --version
step "--help" "$BIN" --help
step "--formats" "$BIN" --formats

# Штучно склеєний мультиформатний файл (PNG-сигнатура + ZIP-сигнатура) —
# достатньо, щоб scan/entropy мали що знаходити, без залежності від
# зовнішніх тестових фікстур.
SAMPLE="${TMP_DIR}/sample.bin"
{
    printf '\x89PNG\r\n\x1a\n'
    dd if=/dev/zero bs=4096 count=1 2>/dev/null
    printf 'PK\x03\x04'
    dd if=/dev/zero bs=2048 count=1 2>/dev/null
} > "$SAMPLE"

step "scan --format json" "$BIN" scan "$SAMPLE" --format json
step "scan --format table" "$BIN" scan "$SAMPLE" --format table
step "entropy --format json" "$BIN" entropy "$SAMPLE" --format json

if [ "$FAILED" -eq 0 ]; then
    log "=== Підсумок: PASS ==="
else
    log "=== Підсумок: FAIL ==="
fi
exit "$FAILED"

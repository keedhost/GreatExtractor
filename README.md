# Great Extractor (`greatie`)

[![Release](https://github.com/keedhost/GreatExtractor/actions/workflows/release.yml/badge.svg)](https://github.com/keedhost/GreatExtractor/actions/workflows/release.yml)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](#license)

A cross-platform CLI/TUI utility for finding and extracting files embedded inside an arbitrary binary file, by magic signatures — a `binwalk` analogue written in Rust.

## How it works

1. **Scan** — the file is read (`mmap`, or streamed with an overlap buffer for very large files) and checked in parallel (`rayon`) against a database of 200+ magic signatures. Each match gets a confidence score (0-100%): structural validators (ZIP, GZIP, PNG, JPEG, TAR, ELF, PE, PDF, and others) produce exact boundaries and a higher confidence, while formats without a validator fall back to a heuristic boundary (an end signature, or up to the next finding) and a lower confidence.
2. **Extract** — the byte range `[offset_start, offset_end]` of each finding is copied into a separate file in the output directory. Extraction is recursive by default: every extracted fragment is re-scanned for nested findings, bounded by a max depth (`--max-depth`) and a max file count (`--max-files`) as a safeguard against explosive growth.
3. **Entropy** — optionally detect compressed/encrypted regions that have no known signature via a sliding-window Shannon entropy analysis (`--entropy`).

## Features

- Fast, multithreaded scanning (`rayon`) with a configurable thread count.
- Chunked, overlap-aware I/O so files of hundreds of GB can be scanned without loading them fully into memory.
- Structural validators for ZIP, GZIP, PNG, JPEG, TAR, ELF, PE, and PDF, giving precise boundaries and higher confidence than the generic heuristic fallback.
- Recursive extraction of nested embedded files, with depth and file-count limits.
- Shannon entropy analysis to flag suspicious high-entropy regions even without a known signature.
- Output as a human-readable table, JSON, or CSV.
- An interactive TUI (`greatie tui`) for browsing findings, a hex view, selective extraction, and switchable color themes.

## Installation

### Prebuilt binaries (GitHub Releases)

Each [release](https://github.com/keedhost/GreatExtractor/releases) ships statically-linked binaries built and smoke-tested in CI for:

| Platform | Architecture | Format |
|---|---|---|
| Linux | x86_64, aarch64 (e.g. Raspberry Pi) | static binary, `.deb`, `.rpm` |
| Windows | x86_64, aarch64 | static binary (`.exe`) |
| macOS | aarch64 (Apple Silicon) | binary |
| FreeBSD | x86_64 | binary |

On Debian/Ubuntu or Fedora/RHEL, prefer the `.deb`/`.rpm` package — its runtime dependencies (glibc, etc.) are resolved by the package manager instead of being statically bundled:

```sh
# Debian/Ubuntu
sudo apt install ./greatie_<version>_amd64.deb

# Fedora/RHEL
sudo dnf install ./greatie-<version>.x86_64.rpm
```

### From crates.io

```sh
cargo install great-extractor
```

This installs the `greatie` binary (the crate is named `great-extractor`; the executable is the shorter `greatie`).

### From source

```sh
git clone https://github.com/keedhost/GreatExtractor.git
cd GreatExtractor
cargo build --release
# binary at target/release/greatie
```

See `scripts/build_linux.sh`, `scripts/build_macos.sh`, and `scripts/build_windows.ps1` for the per-platform release-build scripts used locally and in CI.

## Usage

```sh
greatie scan <file> [--format table|json|csv] [--min-confidence N] [--threads N] [--entropy]
greatie extract <file> [--output DIR] [--recursive] [--max-depth N] [--dry-run]
greatie entropy <file> [--window N] [--format table|json]
greatie tui <file>
greatie --formats
```

### Examples

```sh
# Scan a file and print a table of findings
greatie scan firmware.bin

# Same, as JSON, only findings with confidence >= 60
greatie scan firmware.bin --format json --min-confidence 60

# Recursively extract everything found into ./firmware.bin_extracted/
greatie extract firmware.bin

# Preview what would be extracted, without writing anything
greatie extract firmware.bin --dry-run

# Shannon entropy over 4096-byte windows, as JSON
greatie entropy firmware.bin --window 4096 --format json

# Interactive TUI: browse findings, hex view, selective extraction
greatie tui firmware.bin

# List every supported signature/format
greatie --formats
```

Run `greatie <command> --help` for the full list of options for a given command.

### Configuration

The TUI persists your chosen color theme to `~/.GreatExtractor/config.yaml`. The file is optional — a missing or corrupted config silently falls back to defaults instead of failing.

## Supported formats

The full reference of all 200 supported signatures, grouped by category, with extension and boundary-detection method for each:

- [`formats.md`](formats.md) — English
- [`formats_ukr.md`](formats_ukr.md) — Ukrainian

## CI/CD

`.github/workflows/release.yml` builds and **smoke-tests** every artifact before it is published:

- Architecture and file-type checks (`file`, PE header inspection on Windows).
- Dependency checks — `ldd`/`otool -L`, plus running the static Linux binaries inside a `FROM scratch` container to prove they need nothing from the host.
- For `.deb`/`.rpm`: installing the freshly built package into a clean `debian:bookworm-slim`/`fedora:latest` container via `apt`/`dnf` and verifying the package manager resolved every dynamic dependency on its own.
- Running `--version`, `--help`, `--formats`, `scan`, and `entropy` against a synthetic multi-format sample file, with the full execution log uploaded as an artifact.

A push of a `v*` tag builds the full matrix and publishes every artifact to a GitHub Release; `workflow_dispatch` runs the same pipeline on demand without publishing.

## Non-goals (MVP scope)

- Unpacking container contents during extraction (raw carve only — a `.zip`/`.gz`/`.tar` fragment is extracted as-is, still compressed).
- Decrypting encrypted/password-protected archives.
- Full compatibility with `file(1)`/`libmagic`'s magic-file syntax (only ported signatures for the most common formats).

See `SPEC.md` for the full design specification.

## License

MIT.

## Author

Andrii Kondratiev
Email: h0st@ukr.net
LinkedIn: https://www.linkedin.com/in/andriy-kondratyev

#!/usr/bin/env bash
set -euo pipefail

usage() {
    echo "Usage: $0 -i <interp_path> -r <rpath_dir> -o <out_file> <binary>" >&2
    echo "Example: $0 -i /opt/glibc-2.35/lib/ld-linux-x86-64.so.2 -r /opt/glibc-2.35/lib -o ./pwn ./chall" >&2
    exit 1
}

INTERP=""
RPATH_DIR=""
OUT_FILE=""

while getopts "i:r:o:" opt; do
    case "$opt" in
        i) INTERP="$OPTARG" ;;
        r) RPATH_DIR="$OPTARG" ;;
        o) OUT_FILE="$OPTARG" ;;
        *) usage ;;
    esac
done
shift $((OPTIND - 1))

# Remaining arg: original binary
if [[ $# -ne 1 ]]; then
    usage
fi

ORIG_BIN="$1"

# Basic checks
if [[ -z "$INTERP" || -z "$RPATH_DIR" || -z "$OUT_FILE" ]]; then
    usage
fi

if [[ ! -x "$ORIG_BIN" ]]; then
    echo "[-] Binary '$ORIG_BIN' does not exist or is not executable." >&2
    exit 1
fi

if [[ ! -x "$INTERP" ]]; then
    echo "[-] Interpreter '$INTERP' does not exist or is not executable." >&2
    exit 1
fi

if ! command -v patchelf >/dev/null 2>&1; then
    echo "[-] patchelf not found. Install it (e.g. 'sudo pacman -S patchelf')." >&2
    exit 1
fi

# Ensure output directory exists (if there is one)
OUT_DIR="$(dirname -- "$OUT_FILE")"
if [[ -n "$OUT_DIR" && "$OUT_DIR" != "." ]]; then
    mkdir -p "$OUT_DIR"
fi

echo "[*] Copying '$ORIG_BIN' -> '$OUT_FILE'"
cp --preserve=mode "$ORIG_BIN" "$OUT_FILE"

echo "[*] Setting interpreter to '$INTERP'"
patchelf --set-interpreter "$INTERP" "$OUT_FILE"

# RPATH = <rpath_dir>:$ORIGIN  (escape $ so shell doesn't expand it)
NEW_RPATH="${RPATH_DIR}:\$ORIGIN"
echo "[*] Setting RPATH to '$NEW_RPATH'"
patchelf --set-rpath "$NEW_RPATH" "$OUT_FILE"

echo "[+] Patched: $OUT_FILE"


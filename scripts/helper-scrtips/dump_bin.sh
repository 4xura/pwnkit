#!/usr/bin/env bash
# Author: Axura - https://4xura.com
#
# dump_bin.sh — extract instruction bytes from a binary's objdump output
#
# Usage:
#   ./dump_bin.sh <binary>                 # full hexstring (no spaces)
#   ./dump_bin.sh -f symbol <binary>       # bytes from a function/symbol
#   ./dump_bin.sh -o spaced <binary>       # spaced hex: "48 83 ec 08 ..."
#   ./dump_bin.sh -o python <binary>       # python bytes literal: b"\x48\x83..."
#   ./dump_bin.sh -o c <binary>            # C array: {0x48,0x83,...}
#
set -euo pipefail

print_usage() {
  cat <<EOF
Usage: $0 [ -f SYMBOL ] [ -o fmt ] <binary>
Formats (fmt): hex (default), spaced, python, c
Examples:
  $0 /path/to/bin
  $0 -f main /path/to/bin
  $0 -o python -f vuln_func ./binary
EOF
  exit 1
}

symbol=""
outfmt="hex"

# parse options with getopts 
while getopts ":f:o:h" opt; do
  case "$opt" in
    f) symbol="$OPTARG" ;;
    o) outfmt="$OPTARG" ;;
    h) print_usage ;;
    \?) echo "Invalid option -$OPTARG" >&2; print_usage ;;
  esac
done
shift $((OPTIND-1))

bin=""
for a in "$@"; do
  if [ -f "$a" ]; then
    bin="$a"
    break
  fi
done

[ -n "$bin" ] || { echo "No binary found. Provide path to binary." >&2; print_usage; }

# prepare objdump command
if [ -n "$symbol" ]; then
  # run objdump for the symbol
  objdump_out="$(objdump -d --disassemble="$symbol" "$bin" 2>/dev/null || true)"
  # make sure symbol exists in objdump output as a label like "<symbol>:"
  if ! grep -qE "^[[:space:]]*[0-9a-fA-F]+ <${symbol}>:" <<<"$objdump_out"; then
    echo "Symbol '$symbol' not found in objdump output for $bin" >&2
    exit 2
  fi
  objdump_input="$objdump_out"
else
  objdump_input="$(objdump -d "$bin" 2>/dev/null || true)"
fi

# parse bytes out of objdump output
hexstr="$(awk '
/^[[:space:]]*[0-9a-fA-F]+:/{ 
  for(i=2;i<=NF;i++){
    if ($i ~ /^[0-9a-fA-F]{2}$/) {
      printf "%s", tolower($i)
    } else {
      break
    }
  }
}
END { printf "\n" }' <<<"$objdump_input")"

if [ -z "${hexstr//[[:space:]]/}" ]; then
  echo "No instruction bytes found (objdump output empty or parsing failed)" >&2
  exit 3
fi

# helper: count bytes
bytes_len=$(( ${#hexstr} / 2 ))

case "$outfmt" in
  hex)
    printf '%s\n' "$hexstr"
    ;;
  spaced)
    echo "$hexstr" | sed 's/../& /g' | sed 's/ $//'
    ;;
  python)
    # b"\x.."
    echo -n 'b"'
    echo -n "$hexstr" | sed 's/../\\x&/g'
    echo '"'
    ;;
  c)
    # produce C friendly declaration + length
    arr="$(echo -n "$hexstr" | sed 's/../0x&,/g' | sed 's/,$//')"
    printf 'unsigned char bytes[] = {%s};\nsize_t bytes_len = %d;\n' "$arr" "$bytes_len"
    ;;
  *)
    echo "Unknown format: $outfmt" >&2
    print_usage
    ;;
esac

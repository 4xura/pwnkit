#!/bin/bash
# -----------------------------------------------------------------------------
#  Script: find_gadget_start.sh
#  Author: Axura (https://4xura.com)
#  Description:
#    Filters gadgets from a ROP gadget list file (e.g., gadgets.txt),
#    returning only those where the *first instruction* starts with the
#    specified pattern (e.g., "mov rdi, rax").
#
#  Usage:
#    ./find_gadget_start.sh "<start-instruction>" <gadgets-file>
#
#  Example:
#    ./find_gadget_start.sh "mov rdi, rax" gadgets.txt
#
#  Requirements:
#    - grep (with Perl-compatible regex support: grep -P)
# -----------------------------------------------------------------------------

set -euo pipefail

if [ $# -ne 2 ]; then
    echo "Usage: $0 \"<start-instruction>\" <gadgets-file>"
    exit 1
fi

start_instr="$1"
gadgets_file="$2"

# Escape special characters and compress spacing
pattern=$(echo "$start_instr" | sed -E 's/[[:space:]]+/\\s+/g')

# Match gadgets where the instruction *starts with* this pattern (right after the colon)
grep -P ":\s*${pattern}" "$gadgets_file"

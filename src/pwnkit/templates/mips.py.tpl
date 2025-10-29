#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
# Title : Linux Pwn Exploit
# Author: {author} - {blog}
#
# Description:
# ------------
# A Python exp for Linux binex interaction
#
# Usage:
# ------
# - Local mode  : ./xpl.py
# - Remote mode : ./xpl.py [ <HOST> <PORT> | <HOST:PORT> ]
#

from pwnkit import *
from pwn import *
import sys

# CONFIG
# ---------------------------------------------------------------------------
BIN_PATH   = {file_path!r}
LIBC_PATH  = {libc_path!r}
elf  = ELF(BIN_PATH, checksec=False)
libc = ELF(LIBC_PATH) if LIBC_PATH else None

Context('mips', 'linux', 'little', {log!r}, {term!r}).push()
init_pr("debug", "%(asctime)s - %(levelname)s - %(message)s", "%H:%M:%S")

QEMU = 'qemu-mipsel'

# GDB
# ---------------------------------------------------------------------------
# - GDB script: force arch/endianness/ABI, then connect to QEMU stub
GDBSCRIPT = '''
set pagination off
set confirm off
set disassemble-next-line on

# Force correct target semantics (useful if auto-detect fails)
set architecture mips:isa32r2
set endian little
set mips abi o32
set mipsfpu none

file {{bin}}
# handy: show pc and regs each step
define hook-stop
  x/5i $pc
  i r
end

# breakpoints (adjust to your binary; if PIE, see notes below)
b *main
# If stripped/no symbols, pick an offset: b *0x4007c0

# Connect to QEMU's gdbstub
target remote :1234
# continue to first breakpoint
c
'''.format(bin=BIN_PATH).strip()

# STARTUP
# ---------------------------------------------------------------------------
def start():
    """
    Start the target under qemu-mipsel. If GDB=1, open gdb and connect to :1234.
    We keep pwntools' tube 'io' talking to the program's stdin/stdout (not to GDB).
    """
    # -g 1234: QEMU opens a TCP gdb stub on localhost:1234 and *pauses at entry*.
    argv = [QEMU, '-g', '1234', BIN] if args.GDB else [QEMU, BIN]
    io = process(argv)

    if args.GDB:
        # Spawn gdb in a separate terminal and run our script.
        # exe=BIN_PATH gives symbols to GDB; pwntools won’t “attach PID” here,
        # it just launches gdb and feeds the script (which does target remote).
        gdb.debug([], gdbscript=GDBSCRIPT, exe=BIN_PATH)

    return io

# EXPLOIT
# ---------------------------------------------------------------------------
def exploit(*args, **kwargs):
	io = start()
	alias(io)	# s, sa, sl, sla, r, rl, ru, uu64, g, gp
   
    # TODO: exploit chain


    io.interactive()

# PIPELINE
# ---------------------------------------------------------------------------
if __name__ == "__main__":
    exploit()


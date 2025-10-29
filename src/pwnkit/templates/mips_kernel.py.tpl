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

KERNEL = 'vmlinux'           # uncompressed vmlinux with symbols
INITRD = 'rootfs.cpio.gz'    # optional
QEMU   = 'qemu-system-mipsel'

# GDB
# ---------------------------------------------------------------------------
# - GDB script: force arch/endianness/ABI, then connect to QEMU stub
GDBSCRIPT = f'''
set pagination off
set confirm off
set architecture mips:isa32r2
set endian little
set mips abi o32
set mipsfpu none

file {{KERNEL}}
target remote :1234
# Typical kernel entry
b start_kernel
c
'''.strip()

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
def start_vm():
    # -S: stop CPU at reset; -s: gdb stub at :1234
    args = [
        QEMU, '-M', 'malta', '-m', '256M',
        '-kernel', KERNEL, '-initrd', INITRD,
        '-append', 'console=ttyS0',
        '-nographic',
        '-S', '-s'
    ]
    return process(args)

# EXPLOIT
# ---------------------------------------------------------------------------
def exploit(*args, **kwargs):
	vm = start_vm()
    if args.GDB:
        gdb.debug([], gdbscript=GDBSCRIPT, exe=KERNEL)
    # If we have a serial console/login, interact:
    vm.interactive()


# PIPELINE
# ---------------------------------------------------------------------------
if __name__ == "__main__":
    exploit()


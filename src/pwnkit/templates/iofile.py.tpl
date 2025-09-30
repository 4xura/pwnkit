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
host, port = load_argv(sys.argv[1:])
ssl  = {ssl}
env  = {{}}
elf  = ELF(BIN_PATH, checksec=False)
libc = ELF(LIBC_PATH) if LIBC_PATH else None

Context({arch!r}, {os!r}, {endian!r}, {log!r}, {term!r}).push()
io = Config(BIN_PATH, LIBC_PATH, host, port, ssl, env).run()
alias(io)	# s, sa, sl, sla, r, rl, ru, uu64, g, gp
init_pr("debug", "%(asctime)s - %(levelname)s - %(message)s", "%H:%M:%S")

# HEAP 
# ------------------------------------------------------------------------
@argx(by_name={{"n":itoa}})
def menu(n: int):
    pass

@argx(by_type={{int:itoa}})
def allo():
    pass

def free():
    pass

def edit():
    pass

def show():
    pass

# EXPLOIT
# ------------------------------------------------------------------------
def exploit(*args, **kwargs):
    f = IOFilePlus("amd64")
    ff = {
        "_flags":        0xfbad0000,          # 0x00
        "_IO_read_ptr":  0,                   # 0x08
        "_IO_read_end":  0,                   # 0x10
        "_IO_read_base": 0,                   # 0x18
        "_IO_write_base":0x404300,            # 0x20
        "_IO_write_ptr": 0x404308,            # 0x28
        "_IO_write_end": 0,                   # 0x30
        "_IO_buf_base":  0,                   # 0x38
        "_IO_buf_end":   0,                   # 0x40
        "_IO_save_base": 0,                   # 0x48
        "_IO_backup_base": 0,                 # 0x50
        "_IO_save_end":  0,                   # 0x58
        "_markers":      0,                   # 0x60
        "_chain":        0,                   # 0x68
        "_fileno":       1,                   # 0x70
        "_flags2":       0,                   # 0x74
        "_old_offset":   0,                   # 0x78
        "_cur_column":   0,                   # 0x80
        "_vtable_offset":0,                   # 0x82
        "_shortbuf":     0,                   # 0x83
        "_lock":         0,                   # 0x88
        "_offset":       0,                   # 0x90
        "_codecvt":      0,                   # 0x98
        "_wide_data":    0,                   # 0xa0
        "_freeres_list": 0,                   # 0xa8
        "_freeres_buf":  0,                   # 0xb0
        "__pad5":        0,                   # 0xb8
        "_mode":         0,                   # 0xc0
        "_unused2":      b"\x00"*0x14,        # 0xc4
        "vtable":        0xdeadbeefcafebabe,  # 0xd8
    }
    f.load(ff, strict=True)
    blob = f.bytes
   
    # TODO: exploit chain


    io.interactive()

# PIPELINE
# ------------------------------------------------------------------------
if __name__ == "__main__":
    exploit()


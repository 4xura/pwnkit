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

# EXPLOIT
# ------------------------------------------------------------------------
def setcontext:
    """int setcontext(const ucontext_t *ucp);"""
    pass

def exploit(*args, **kwargs):
    uc = UContext("amd64")
    uc.load({
        "R8":  0,		# 0x28
        "R9":  0,		# 0x30
        "R12": 0,		# 0x48
        "R13": 0,		# 0x50
        "R14": 0,		# 0x58
        "R15": 0,		# 0x60
        "RDI": 0,		# 0x68
        "RSI": 0,		# 0x70
        "RBP": 0,		# 0x78
        "RBX": 0,		# 0x80
        "RDX": 0,		# 0x88
        "RAX": 0,		# 0x90
        "RCX": 0,		# 0x98
        "RSP": 0x7fffffff0000,	# 0xA0
        "RHOST": 0xdeadbeef,     	# 0xA8
        # floating point stuff
        "FPREGS": 0x404000,    	# 0xB0: fldenv pointer
        "MXCSR":  0x1F80,      	# 0x1C0: default safe SSE state
    })
    uc.dump()
    blob = uc.bytes   
   
    # TODO: exploit chain


    io.interactive()

# PIPELINE
# ------------------------------------------------------------------------
if __name__ == "__main__":
    exploit()


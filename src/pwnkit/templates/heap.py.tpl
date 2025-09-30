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
   
    # TODO: exploit chain


    io.interactive()

# PIPELINE
# ------------------------------------------------------------------------
if __name__ == "__main__":
    exploit()


#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
# Title : Linux Pwn Exploit
# Author: Axura (@4xura) - https://4xura.com
#
# Description:
# ------------
# A Python exp for Linux binex interaction
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
BIN_PATH   = '/home/Axura/pwn/pwnkit/examples/heap-house-of-apple/travelgraph/travelgraph'
LIBC_PATH  = '/home/Axura/pwn/pwnkit/examples/heap-house-of-apple/travelgraph/libc.so.6'
elf        = ELF(BIN_PATH, checksec=False)
libc       = ELF(LIBC_PATH) if LIBC_PATH else None
host, port = parse_argv(sys.argv[1:], None, None)

ctx = Context(
    arch      = 'amd64',
    os        = 'linux',
    endian    = 'little',
    log_level = 'debug',
    terminal  = ('tmux', 'splitw', '-h')
).push()

io = Tube(
    file_path = BIN_PATH,
    libc_path = LIBC_PATH,
    host      = host,
    port      = port,
    env       = {}
).init().alias()
set_global_io(io)	# s, sa, sl, sla, r, ru, uu64

init_pr("debug", "%(asctime)s - %(levelname)s - %(message)s", "%H:%M:%S")

# HEAP 
# ------------------------------------------------------------------------
def menu(n: int):
    opt = itoa(n)
    pass

def alloc():
    pass

def dele():
    pass

def edit():
    pass

def show():
    pass

# EXPLOIT
# ------------------------------------------------------------------------
def xpl(**kwargs):
   
    # TODO: exploit chain


    io.interactive()

# PIPELINE
# ------------------------------------------------------------------------
if __name__ == "__main__":
    xpl()


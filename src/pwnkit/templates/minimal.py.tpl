#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from pwnkit import *
from pwn import *
import sys

BIN_PATH   = {file_path!r}
LIBC_PATH  = {libc_path!r}
host, port = load_argv(sys.argv[1:])
ssl  = {ssl}
env  = {{}}
elf  = ELF(BIN_PATH, checksec=False)
libc = ELF(LIBC_PATH) if LIBC_PATH else None

Context({arch!r}, {os!r}, {endian!r}, {log!r}, {term!r}).run()
io = Config(BIN_PATH, LIBC_PATH, host, port, ssl, env).init()
alias(io)	# s, sa, sl, sla, r, rl, ru, uu64, g, gp

def exploit(*args, **kwargs):
   
    # TODO: exploit chain


    io.interactive()

if __name__ == "__main__":
    exploit()


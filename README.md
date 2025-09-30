# pwnkit

[![PyPI version](https://img.shields.io/pypi/v/pwnkit.svg)](https://pypi.org/project/pwnkit/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Python Versions](https://img.shields.io/pypi/pyversions/pwnkit.svg)](https://pypi.org/project/pwnkit/)

Exploitation toolkit for pwn CTFs & Linux binary exploitation research.  
Includes exploit templates, I/O helpers, ROP gadget mappers, pointer mangling utilities, curated shellcodes, exploit gadgets, House of Maleficarum, gdb/helper scripts, etc.

---

## Installation

From [PyPI](https://pypi.org/project/pwnkit/):

**Method 1**. Install into **current Python environment** (could be system-wide, venv, conda env, etc.). use it both as CLI and Python API:

```bash
pip install pwnkit
```

**Method 2**. Install using `pipx` as standalone **CLI tools**:

```bash
pipx install pwnkit
```

**Method 3.** Install from source (dev):

```bash
git clone https://github.com/4xura/pwnkit.git
cd pwnkit
#
# Edit source code
#
pip install -e .
```

---

## Quick Start

### CLI

All options:
```bash
pwnkit -h
```
Create an exploit script template:
```bash
# Minimal setup to fill up by yourself
pwnkit xpl.py

# specify bin paths
pwnkit xpl.py --file ./pwn --libc ./libc.so.6 
# run target with args
pwnkit xpl.py -f "./pwn args1 args2 ..." -l ./libc.so.6 

# Override default preset with individual flags
pwnkit xpl.py -A aarch64 -E big

# Custom author signatures
pwnkit xpl.py -a john,doe -b https://johndoe.com
```
Example using default template:
```bash
$ pwnkit exp.py -f ./evil-corp -l ./libc.so.6 \
                -A aarch64 -E big \
                -a john.doe -b https://johndoe.com

[+] Wrote exp.py (template: pkg:default.py.tpl)

$ cat exp.py
#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
# Title : Linux Pwn Exploit
# Author: john.doe - https://johndoe.com
#
# Description:
# ------------
# A Python exploit for Linux binex interaction
#
# Usage:
# ------
# - Local mode  : python3 xpl.py
# - Remote mode : python3 [ <HOST> <PORT> | <HOST:PORT> ]
#

from pwnkit import *
from pwn import *
import sys

BIN_PATH   = './evil-corp'
LIBC_PATH  = './libc.so.6'
host, port = load_argv(sys.argv[1:])
ssl  = False
env  = {}
elf  = ELF(BIN_PATH, checksec=False)
libc = ELF(LIBC_PATH) if LIBC_PATH else None

Context('amd64', 'linux', 'little', 'debug', ('tmux', 'splitw', '-h')).push()
io = Config(BIN_PATH, LIBC_PATH, host, port, ssl, env).run()
alias(io)   # s, sa, sl, sla, r, rl, ru, uu64, g, gp
init_pr("debug", "%(asctime)s - %(levelname)s - %(message)s", "%H:%M:%S")

def exploit():

    # exploit chain here

    io.interactive()

if __name__ == "__main__":
    exploit()
```
List available built-in templates:
```bash
$ pwnkit -lt
[*] Bundled templates:
   - default
   - full
   - got
   - heap
   - minimal
   - ret2libc
   - ret2syscall
   - setcontext
   - srop
   ...
```
Use a built-in template:
```bash
pwnkit exp.py -t heap
```

### Python API

We can use `pwnkit` as Python API, by import the project as a Python module.

Using the pwnkit CLI introduced earlier, we generate a ready-to-use exploit template that automatically loads the target binaries:

```py 
from pwnkit import *
from pwn import *

# - Loading (can be created by pwnkit cli)
BIN_PATH   = './vuln'
LIBC_PATH  = './libc.so.6'
host, port = load_argv(sys.argv[1:])    # return None for local pwn
ssl        = False                      # set True for SSL remote pwn
elf        = ELF(BIN_PATH, checksec=False)
libc       = ELF(LIBC_PATH) if LIBC_PATH else None	

io = Config(
    file_path = BIN_PATH,
    libc_path = LIBC_PATH,
    host      = host,
    port      = port,
    ssl       = ssl,
    env       = {},
).run()

# for IO
io.sendlineafter(b'\n', 0xdeadbeef)
io.sla(b'\n', 0xdeadbeef)

# This enable alias for: s, sa, sl, sla, r, ru, uu64
alias(io)

sla(b'\n', 0xdeadbeef)
```

#### Context Initialization

The first step is to initialize the exploitation context:

```py
Context(
    arch	  = "amd64"
    os		  = "linux"
    endian	  = "little"
    log_level = "debug"
    terminal  = ("tmux", "splitw", "-h")	# remove when no tmux
).push()
```

Or we can use the preset built-in contexts:

```py
ctx = Context.preset("linux-amd64-debug")
ctx.push()
```

A few preset options:

```
linux-amd64-debug
linux-amd64-quiet
linux-i386-debug
linux-i386-quiet
linux-arm-debug
linux-arm-quiet
linux-aarch64-debug
linux-aarch64-quiet
freebsd-amd64-debug
freebsd-amd64-quiet
...
```

#### ROP Gadgets

To leverage ROP gadgets, we first need to disclose the binary’s base address when it is dynamically linked, PIE enabled or ASLR in effect. For example, when chaining gadgets from `libc.so.6`, leak libc base:

```py
...
libc_base = 0x???
libc.address = libc_base
```

At this stage, with the `pwnkit` module, we are able to:

```py
ggs 	= ROPGadgets(libc)
p_rdi_r = ggs['p_rdi_r']
p_rsi_r = ggs['p_rsi_r']
p_rax_r = ggs['p_rax_r']
p_rsp_r = ggs['p_rsp_r']
p_rdx_rbx_r = ggs['p_rdx_rbx_r']
leave_r = ggs['leave_r']
ret 	= ggs['ret']
ggs.dump()  # dump all gadgets to stdout
```

The `dump()` method in the `ROPGadget` class allows us to validate gadget addresses dynamically at runtime:

![dump](images/ROPGadgets_dump.jpg)

#### Pointer Protection

In newer glibc versions, singly linked pointers (e.g., the `fd` pointers of tcache and fastbin chunks) are protected by Safe-Linking. The `SafeLinking` class can be used to perform the corresponding encrypt/decrypt operations:

```py
# e.g., after leaking heap_base for tcache
slk = SafeLinking(heap_base)
fd = 0x55deadbeef
enc_fd = slk.encrypt(fd)
dec_fd = slk.decrypt(enc_fd)

# Verify
assert fd == dec_fd
```

And the Pointer Guard mechanism applies to function pointers and C++ vtables, introducing per-process randomness to protect against direct overwrites. After leaking or overwriting the guard value, the `PointerGuard` class can be used to perform the required mangle/detangle operations:

```py
guard = 0xdeadbeef	# leak it or overwrite it
pg = PointerGuard(guard)
ptr = 0xcafebabe
enc_ptr = pg.mangle(ptr)
dec_ptr = pg.demangle(enc_ptr)

# Verify
assert ptr == dec_ptr
```

#### Shellcode Generation

The `pwnkit` module also provides a shellcode generation framework. It comes with a built-in registry of ready-made payloads across architectures, along with flexible builders for crafting custom ones. Below are some examples of listing, retrieving, and constructing shellcode:

```py
# 1) List all built-in available shellcodes
for name in list_shellcodes():
    print(" -", name)
    
print("")

# 2) Retrieve by arch + name, default variant (min)
sc = ShellcodeReigstry.get("amd64", "execve_bin_sh")
print(f"[+] Got shellcode: {sc.name} ({sc.arch}), {len(sc.blob)} bytes")
print(hex_shellcode(sc.blob))   # output as hex

print("")

sc.dump()   # pretty dump

print("")

# 3) Retrieve explicit variant
sc = ShellcodeReigstry.get("i386", "execve_bin_sh", variant=33)
print(f"[+] Got shellcode: {sc.name} ({sc.arch}), {len(sc.blob)} bytes")
print(hex_shellcode(sc.blob))

print("")

# 4) Retrieve via composite key
sc = ShellcodeReigstry.get(None, "amd64:execveat_bin_sh:29")
print(f"[+] Got shellcode: {sc.name}")
print(hex_shellcode(sc.blob))

print("")

# 5) Fuzzy lookup
sc = ShellcodeReigstry.get("amd64", "ls_")
print(f"[+] Fuzzy match: {sc.name}")
print(hex_shellcode(sc.blob))

print("")

# 6) Builder demo: reverse TCP shell (amd64)
builder = ShellcodeBuilder("amd64")
rev = builder.build_reverse_tcp_shell("127.0.0.1", 4444)
print(f"[+] Built reverse TCP shell ({len(rev)} bytes)")
print(hex_shellcode(rev))
```

Example output:

![shellcode](images/shellcode.jpg)

#### IO FILE Exploit

The `pwnkit` module also provides a helper for targeting glibc’s internal `_IO_FILE_plus` structures. The `IOFilePlus` class allows us to conveniently craft fake FILE objects:

```py
# By default, it honors `context.bits` to decide architecture
# e.g., we set Context(arch="amd64")
f = IOFilePlus()

# Or, we can specify one
f = IOFilePlus("i386")
```

Iterate fields of the FILE object:

```py
for field in f.fields:	# or f.iter_fileds()
    print(field)
```

Inspect its members offsets, names and sizes:

![iofile_fields](images/iofile_fields.jpg)

Set FILE members via names or aliases:

```py
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
```

We can also use the built-in `set()` method:

```py
# Set field via name 
f.set('_lock', 0x41414141)

# Set via a specific offset
f.set(116, 0x42424242)	# _flags2
```

Inspect the resulting layout in a structured dump for debugging:

```py
f.dump()

# Custom settings
f.dump(
    title = "your title",
    only_nonzero = True,		# default: False, so we also check Null slots
    show_bytes = True,			# default: True, "byte" column displayed
    highlight_ptrs = True,		# default: True, pointer members are highlighted
    color = True,				# default: True, turn off if you don't want colorful output
)
```

Dumping them in a pretty and readable format to screen:

![iofile_dump](images/iofile_dump.jpg)

Use the built-in `get()` method to retrieve a field value:

```py
# retrieve via name
vtable = f.get("vtable")

# via offset
vtable = f.get(0xd8)
```

Create a snapshot:

```py
snapshot = f.bytes	# or: f.to_bytes()

# Or use the `data` bytearray class member
snapshot2 = f.data

print(f"[+] IO FILE snapshot in bytes:\n{snapshot}\n{snapshot2})
```

![iofile_bytes](images/iofile_bytes.jpg)

Create an `IOFilePlus` object by importing a snapshot:

```py
f2 = IOFilePlus.from_bytes(blob=snapshot, arch="amd64")
```

> For example, we can dump an `IO_FILE_plus` structure data via pwndbg's `dump memory` command

Create a quick IO FILE struct template using the `load()` method:

```py
f = IOFilePlus("amd64")

# common fake _IO_FILE_plus for stdout-like layout
ff = {
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
}

f.load(ff, strict=True)

# dump bytes for injection
blob = f.bytes
```

Or use raw-offset template (1:1 with glibc layout):

```py
f = IOFilePlus("amd64")
f.load([
    (0x00, 0xfbad0000),           # _flags (4)
    (0x08, 0x404100),             # _IO_read_ptr
    (0x10, 0x404200),             # _IO_read_end
    (0x18, 0x0),                  # _IO_read_base
    (0x20, 0x404300),             # _IO_write_base
    (0x28, 0x404308),             # _IO_write_ptr
    (0x30, 0x0),                  # _IO_write_end
    (0x38, 0x0),                  # _IO_buf_base
    (0x40, 0x0),                  # _IO_buf_end
    (0x48, 0x0),                  # _IO_save_base
    (0x50, 0x0),                  # _IO_backup_base
    (0x58, 0x0),                  # _IO_save_end
    (0x60, 0x0),                  # _markers
    (0x68, 0x0),                  # _chain
    (0x70, 0x1),                  # _fileno
    (0x74, 0x0),                  # _flags2
    (0x78, 0x0),                  # _old_offset
    (0x80, 0x0),                  # _cur_column (2B)
    (0x82, 0x0),                  # _vtable_offset (1B, signed)
    (0x83, 0x0),                  # _shortbuf (1B)
    (0x88, 0x0),                  # _lock
    (0x90, 0x0),                  # _offset
    (0x98, 0x0),                  # _codecvt
    (0xa0, 0x0),                  # _wide_data
    (0xa8, 0x0),                  # _freeres_list
    (0xb0, 0x0),                  # _freeres_buf
    (0xb8, 0x0),                  # __pad5 (4B)
    (0xc0, 0x0),                  # _mode (4B)
    (0xd8, 0xdeadbeefcafebabe),   # vtable
], strict=True)
```

#### Ucontext Buffering

We are not here to discuss how to exploit with the `ucontext_t` buffer in glibc. This involves:

```c
extern int setcontext (const ucontext_t *__ucp)
```

Usually we leverage its runtime gadgets in `setcontext+61` ([example](https://4xura.com/binex/orw-open-read-write-pwn-a-sandbox-using-magic-gadgets/#toc-head-7)) or `setcontext+32` ([example](https://4xura.com/binex/pwn-got-hijack-libcs-internal-got-plt-as-rce-primitives/#toc-head-22))

Using `pwnkit` we can quickly initiate a `ucontext_t` struct buffer:

```py
uc = UContext("amd64")          # defaults to amd64 if context.bits==64 anyway
print(hex(uc.size))             # 0x3c8
```

Set a few GPRs + RIP/RSP (aliases or full names):

```py
# full dotted name (case sensitive)
uc.set("uc_mcontext.gregs.RIP", 0x4011d0)         

# sugars (case sensitive)
uc.set_reg("rdi", 0x1337)	    	# set registers                     
uc.set_stack(						# set signal stack
    sp    = 0x7fffffff0000,
    size  = 0x1111,
    flags = 0xdeadbeef
)    

# aliases (case insensitive)
uc.set("RSP", 0x7fffffff0000)		# field name alias 
uc.rsi = 0x2222						# property alias 

# same via bulk
uc.load({
    "RAX": 0, "RBX": 0, "RCX": 0, "RDX": 0,
    # "RSI": 0x2222,
    "efl": 0x202,                                 # (case insensitive)
})
uc.dump(only_nonzero=True)
```

![ucontext_set](images/ucontext_set.jpg)

Set/unset signals (sigset_t @ 0x128, 128 bytes in x86_64):

```py
# block SIGALRM (14) + SIGINT (2)
uc.set_sigmask_block([14, 2])

# OR explicit by bytes
raw_mask = b"\x00" * 0x80
uc.set("uc_sigmask[128]", raw_mask)
```

FPU: fldenv pointer + MXCSR:

```py
# build a classic 28-byte FSAVE environment and place it somewhere in mem you control
env28 = fsave_env_28(fcw=0x037F)  # sane default
fake_env_addr = 0x404000          # wherever your R/W buffer will live

# write env28 there via your exploit (not shown); now point fpregs to it:
uc.set_fpu_env_ptr(fake_env_addr)
# or use alias
uc.fldenv_ptr = fake_env_addr

# set MXCSR inside the inline __fpregs_mem (FXSAVE blob inside ucontext)
uc.mxcsr = 0x1F80
# or explicitly:
uc.set("__fpregs_mem.mxcsr", 0x1F80)

uc.dump()
```

![ucontext_fsave](images/ucontext_fsave.jpg)

Absolute offsets when you’re speedrunning:

```py
# write RIP via absolute offset (0xA8 inside ucontext)
uc.set(0xA8, 0xdeadbeefcafebabe)

# patch arbitrary blob (raw write; no name resolution)
uc.patch(0x1A8, (0x037F).to_bytes(2, "little"))  # fcw in __fpregs_mem
```

Bulk load (dict or list of pairs):

```py
uc.load({
    "rdi": 0xdeadbeef,
    "rsi": 0xcafebabe,
    "rsp": 0x7fffffeee000,
    "rip": 0x4011d0,
    "mxcsr": 0x1F80,
})

# or: list of [(field, value)] with mixed names/offsets
uc.load([
    ("rbx", 0),
    (0x128, b"\x00"*0x80),          # sigmask
])
```

Serialize → payload glue:

```py
payload = b"A"*0x100
payload += uc.bytes                # or uc.to_bytes()

# drop into whatever vector you have (overwrite on stack, heap chunk, etc.)
# e.g. send(payload) or write to file
```

Parse from an existing blob (read–modify–write):

```py
blob = b"\x00"*0x3C8
uc2 = UContext.from_bytes(blob, arch="amd64")
```

Quick template — instantiate `UContext` and feed it your dict straight into `.load()`:

```py
uc = UContext("amd64")

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
})

# dump bytes for injection
blob = uc.bytes   
```

Or if you prefer positional offset style:

```py
uc = UContext("amd64")
uc.load([
    (0x28, 0),         # R8
    (0x30, 0),         # R9
    (0x48, 0),         # R12
    (0x50, 0),         # R13
    (0x58, 0),         # R14
    (0x60, 0),         # R15
    (0x68, 0),         # RDI
    (0x70, 0),         # RSI
    (0x78, 0),         # RBP
    (0x80, 0),         # RBX
    (0x88, 0),         # RDX
    (0x90, 0),         # RAX
    (0x98, 0),         # RCX
    (0xA0, 0x7fffffff0000), # RSP
    (0xA8, 0xdeadbeef),     # RIP
    (0xE0, 0x404000),       # fpregs ptr
    (0x1C0, 0x1F80),        # mxcsr
])
blob = uc.bytes
```

#### Function Decorators

See examples in [src/pwnkit/decors.py](https://github.com/4xura/pwnkit/blob/main/src/pwnkit/decors.py).

##### Common function helpers

```python
# - Coerce funtion arguments with transformers
#   e.g., for a heap exploitation menu I/O:
@argx(by_name={"n":itoa})
def menu(n: int):
    sla(b"choice: ", opt)       # convert arg `n` to string bytes

@argx(by_type={int:itoa})
def alloc(idx: int, sz: int, ctx: bytes): 
    menu(1)                     # convert 1 to b"1"
    sla(b"index: ", idx)        # convert integer arg `idx` to string bytes
    sla(b"size: ", sz)          # convert integer arg `sz` to string bytes
    sla(b"content: ", ctx)		# this is not affected


# - Print the fully-qualified function name and raw args/kwargs
#   this can be helpful in fuzzing tasks, that we know when func is called
@pr_call
def fuzz(x, y=2):
	return x ** y

fuzz(7, y=5)	# call __main__.fuzz args=(7,) kwargs={'y': 5}


# - Count how many times a function is called 
#   exposes .calls and .reset()
@counter
def f(a, b): 
    print(f"{a}+{b}={a+b}")

f(1,2)			# Call 1 of f ... 1+2=3
f(5,5)			# Call 2 of f ... 5+5=10
print(f.calls)  # 2
f.reset()
print(f.calls)  # 0


# - Sleep before and after the call (seconds).
@sleepx(before=0.10, after=0.10)
def poke():
	...

@sleepx(before=0.2)
async def task():


# - Print how long the call took (ms)
@timer
def fuzz(x, y=2):
	return x ** y

fuzz(7, y=5)	# __main__.fuzz took 0.001 ms

...

```
##### Bruteforcer

When we need brute forcing (TODO: improve this decorator!):

```python
# 1) Simple repeat n times (sequential)
@bruteforcer(times=5)
def probe():
    print("probing")
    return False

# returns [False, False, False, False, False]
res = probe()


# 2) Pass attempt index to function (useful for permutations)
@bruteforcer(times=3, pass_index=True)
def try_pin(i):
    print("attempt", i)

try_pin()
# prints:
# attempt 0
# attempt 1
# attempt 2


# 3) Use a list of candidate inputs (typical bruteforce passwords)
candidates = ["admin", "1234", "password", "letmein"]

# build inputs as iterable of (args, kwargs) pairs
inputs = (( (pw,), {} ) for pw in candidates)

@bruteforcer(inputs=inputs, until=lambda r: r is True)
def attempt_login(password):
    # attempt_login returns True on success, False/None on failure
    return fake_try_login(password)

result = attempt_login()
# result will be True (stops early) or None if no candidate worked


# 4) Parallel bruteforce (threads)
@bruteforcer(inputs=((pw,) for pw in candidates), until=lambda r: r is True, parallel=8)
def attempt_login(password):
    return fake_try_login(password)
```

#### Others

More modules are included in the `pwnkit` source, but some of them are currently for personal scripting conventions, or are under beta tests. You can add your own modules under `src/pwnkit`, then embed them into `src/pwnkit/__init__.py`. 

When we want module symbols to be parsed via code editors (e.g., vim, vscode) for auto grammar suggestion, we can run this to export symbols all-at-once:

```bash
python3 tools/gen_type_hints.py
```

---

## Custom Templates

Templates (`*.tpl` or `*.py.tpl`) are rendered with a context dictionary.
Inside your template file you can use Python format placeholders (`{var}`) corresponding to:

 | Key           | Meaning                                                      |
 | ------------- | ------------------------------------------------------------ |
 | `{arch}`      | Architecture string (e.g. `"amd64"`, `"i386"`, `"arm"`, `"aarch64"`) |
 | `{os}`        | OS string (currently `"linux"` or `"freebsd"`)               |
 | `{endian}`    | Endianness (`"little"` or `"big"`)                           |
 | `{log}`       | Log level (e.g. `"debug"`, `"info"`)                         |
 | `{term}`      | Tuple of terminal program args (e.g. `("tmux", "splitw", "-h")`) |
 | `{file_path}` | Path to target binary passed with `-f/--file`                |
 | `{libc_path}` | Path to libc passed with `-l/--libc`                         |
 | `{host}`      | Remote host (if set via `-i/--host`)                         |
 | `{port}`      | Remote port (if set via `-p/--port`)                         |
 | `{io_line}`   | Pre-rendered code line that initializes the `Tube`           |
 | `{author}`    | Author name from `-a/--author`                               |
 | `{blog}`      | Blog URL from `-b/--blog`                                    |

Use your own custom template (`*.tpl` or `*.py.tpl`):
```bash
pwnkit exp.py -t ./mytpl.py.tpl
```
Or put it in a directory and point `PWNKIT_TEMPLATES` to it:
```bash
export PWNKIT_TEMPLATES=~/templates
pwnkit exploit.py -t mytpl
```
For devs, you can also place your exploit templates (which is just a Python file of filename ending with `tpl` suffix) into [`src/pwnkit/templates`](https://github.com/4xura/pwnkit/tree/main/src/pwnkit/templates), before cloning and building to make a built-in. You are also welcome to submit a custom template there in this repo for a pull request!

---

## TODO

* Move the template feature under mode `template`
* Create other modes (when needed)
* Fill up built-in exploit tempaltes
* More Python exloit modules, e.g., decorators, heap exploit, etc.


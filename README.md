# pwnkit

**[!] Under construction.Developing and fixing bugs**

[![PyPI version](https://img.shields.io/pypi/v/pwnkit.svg)](https://pypi.org/project/pwnkit/)

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
---

## Installation

From [PyPI](https://pypi.org/project/pwnkit/):

*Method 1*. Install into **current Python environment** (could be system-wide, venv, conda env, etc.). use it both as CLI and Python API:

```bash
pip install pwnkit
```

*Method 2*. Install using `pipx` as standalone **CLI tools**:

```bash
pipx install pwnkit
```

*Method 3.* Install from source (dev):

```bash
git clone https://github.com/4xura/pwnkit.git
cd pwnkit
pip install -e .
```

---

## Quick Start

### CLI

```bash
pwnkit --help
```
Create an exploit script template:
```bash
# local pwn
pwnkit xpl.py --file ./pwn --libc ./libc.so.6 

# remote pwn
pwnkit xpl.py --file ./pwn --host 10.10.10.10 --port 31337

# Override default preset with individual flags
pwnkit xpl.py -f ./pwn -i 10.10.10.10 -p 31337 -A aarch64 -E big
```
Example:
```bash
$ pwnkit exp.py -f ./evil-corp -l ./libc.so.6 \
                -A aarch64 -E big \
                -a john.doe -b https://johndoe.com
[+] Wrote exp.py

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
    terminal  = ('tmux', 'splitw', '-h')
).push()

io = Tube(
    file_path = BIN_PATH,
    libc_path = LIBC_PATH,
    host      = host,
    port      = port,
    env       = {}
).init().alias()
set_global_io(io._t())  # s, sa, sl, sla, r, ru, uu64

init_pr("debug", "%(asctime)s - %(levelname)s - %(message)s", "%H:%M:%S")

def xpl():

    # exploit chain here

    io.interactive()

if __name__ == "__main__":
    xpl()
```

### Python API

```python
from pwnkit import *
from pwn import *

# push a context preset
ctx = Context.preset("linux-amd64-debug")
"""
ctx = Context(
    arch	  = "amd64"
    os		  = "linux"
    endian	  = "little"
    log_level = "debug"
    terminal  = ("tmux", "splitw", "-h")
)
"""
ctx.push()   # applies to pwntools' global context

# simple I/O stream
io = Tube(
    file_path = "/usr/bin/sudoedit",
    libc_path = "./libc.so.6",
    host      = "127.0.0.1",
    port	  = 123456,
    env		  = {}
).alias()
io.sl(b"hello")
print(io.r(5))   # b'hello'

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




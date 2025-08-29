# pwnkit

**Under construction, bugs not fixed**

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
❯ pwnkit exp.py -f evil-corp
[+] Wrote exp.py

❯ cat exp.py
#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
# Title : Linux Pwn Exploit
# Author: Axura (@4xura) - https://4xura.com
#
# Description:
# ------------
# A Python exploit for Linux binex interaction
#
# Usage:
# ------
# - Local mode  : ./xpl.py
# - Remote mode : ./xpl.py [ <IP> <PORT> | <IP:PORT> ]
#

from pwn import *
from pwnkit import *

ctx = Context(
    arch      = 'amd64',
    os        = 'linux',
    endian    = 'little',
    log_level = 'debug',
    terminal  = ('tmux', 'splitw', '-h')
)
ctx.push()

io = Tube(
    file_path = '/home/Axura/ctf/pwn/linux-user/evilcorp/evil-corp',
    libc_path = None,
    host      = None,
    port      = None,
    env       = {}
).alias()
# io = process('/home/Axura/ctf/pwn/linux-user/evilcorp/evil-corp')

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




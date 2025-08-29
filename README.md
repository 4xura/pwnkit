# pwnkit

Under construction, bugs not fixed
[![PyPI version](https://img.shields.io/pypi/v/pwnkit.svg)](https://pypi.org/project/pwnkit/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
---

## Installation

From [PyPI](https://pypi.org/project/pwnkit/):

```bash
# install into your environment
pip install pwnkit

# or as a standalone CLI tool
pipx install pwnkit
````

From source (development):

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

### Python API

```python
from pwnkit import PwnStream
from pwnkit.ctx import Context

# simple I/O stream
io = PwnStream("/bin/cat").alias()
io.sl(b"hello")
print(io.r(5))   # b'hello'
io.close()

# push a context preset
ctx = Context.preset("linux-amd64-debug")
ctx.push()   # applies to pwntools' global context
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





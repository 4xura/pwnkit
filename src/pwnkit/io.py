from __future__ import annotations
from dataclasses import dataclass, field
from typing import Optional, Union, Dict
from pwn import tube, u64   # type: ignore
import os

__all__ = [
    "Tube",
    # optional global helpers:
    "set_global_io", "s", "sa", "sl", "sla", "r", "ru", "uu64", 
]

Chars = Union[str, bytes]

# Init a Tube for IO stream
# ------------------------------------------------------------------------
@dataclass(slots=True)
class Tube:
    """
    Usage:
        # local
        io = Tube("./vuln", libc_path="./libc.so.6").alias()
        io.s(b"AAAA"); io.sla(b"> ", b"1"); data = io.r(); io.interactive()

        # remote
        io = Tube("./vuln", host="10.10.10.10", port=31337).alias()

        # custom env (merged with libc preload if local)
        io = Tube("./vuln", env={"ASAN_OPTIONS":"detect_leaks=0"}).alias()
    """
    file_path   : Optional[str] = None
    libc_path   : Optional[str] = None
    host        : Optional[str] = None
    port        : Optional[int] = None
    env         : Dict[str, str] = field(default_factory=dict)

    # - Runtime handle
    _io         : Optional[tube] = field(default=None, init=False, repr=False, compare=False)
    _aliased    : bool = field(default=False, init=False, repr=False, compare=False)

    def __post_init__(self):
        if (self.host is None) ^ (self.port is None):
            raise ValueError("Both host and port must be set for remote mode.")
        if self.file_path:
            self.file_path = os.path.abspath(self.file_path)
        if self.libc_path:
            self.libc_path = os.path.abspath(self.libc_path)

    # - Lazily open tube
    def init(self):
        if self._io is not None:
            raise RuntimeError("Tube already initialized.")
        self._io = self._open()
        return self

    # - Config helpers
    def is_remote(self) -> bool:
        return self.host is not None and self.port is not None

    def build_env(self) -> Optional[Dict[str, str]]:
        """Merge user env + (optional) libc preload for local exec."""
        if self.is_remote():
            return None
        if not self.libc_path and not self.env:
            return None
        merged = dict(self.env) if self.env else {}
        if self.libc_path:
            libc_abs = os.path.abspath(self.libc_path)
            libdir   = os.path.dirname(libc_abs) or "."
            # user-provided values win; only set if missing
            merged.setdefault("LD_PRELOAD", libc_abs)
            merged.setdefault("LD_LIBRARY_PATH", libdir)
        return merged or None

    def as_code(self) -> str:
        """String form of how we'd open the tube (for debugging/scaffolds)."""
        if self.is_remote():
            return f"remote({self.host!r}, {self.port})"
        if self.libc_path:
            libc_abs = os.path.abspath(self.libc_path)
            libdir   = os.path.dirname(libc_abs) or "."
            env_code = {**self.env, "LD_PRELOAD": libc_abs, "LD_LIBRARY_PATH": libdir} if self.env else \
                       {"LD_PRELOAD": libc_abs, "LD_LIBRARY_PATH": libdir}
            return f"process({self.file_path!r}, env={env_code!r})"
        return f"process({self.file_path!r}{', env='+repr(self.env) if self.env else ''})"

    # - Open tube
    def _open(self) -> tube:
        from pwn import process, remote
        if self.is_remote():
            return remote(self.host, self.port)
        env = self.build_env()
        return process(self.file_path, env=env) if env else process(self.file_path)

    # - Alias
    def alias(self) -> "Tube":
        """Enable io.s/io.sla/io.r/io.ru/io.uu64; chainable."""
        if self._io is None:
            raise RuntimeError("Call io.init() before io.alias().")
        self._aliased = True
        return self

    def __getattr__(self, name: str):
        """Forward unknown attributes (interactive, recvline, ...) to the tube."""
        if name.startswith("_"):
            raise AttributeError(name)
        if self._io is None:
            raise AttributeError("IO has no tube yet.")
        return getattr(self._io, name)

    def _t(self) -> tube:
        if self._io is None:
            raise RuntimeError("Tube not opened.")
        return self._io

    def s(self, data: Chars) -> None:
        assert self._aliased, "Call io.alias() to enable shortcuts."
        self._t().send(data)

    def sa(self, delim: Chars, data: Chars) -> None:
        assert self._aliased, "Call io.alias() to enable shortcuts."
        self._t().sendafter(delim, data)

    def sl(self, data: Chars) -> None:
        assert self._aliased, "Call io.alias() to enable shortcuts."
        self._t().sendline(data)

    def sla(self, delim: Chars, data: Chars) -> None:
        assert self._aliased, "Call io.alias() to enable shortcuts."
        self._t().sendlineafter(delim, data)

    def r(self, n: int = 4096) -> bytes:
        assert self._aliased, "Call io.alias() to enable shortcuts."
        return self._t().recv(n)

    def ru(self, delim: Chars, drop: bool = True) -> bytes:
        assert self._aliased, "Call io.alias() to enable shortcuts."
        return self._t().recvuntil(delim, drop=drop)

    def uu64(self, data: bytes) -> int:
        assert self._aliased, "Call io.alias() to enable shortcuts."
        return u64(data.ljust(8, b"\x00"))

# Global short aliases (optional)
# ------------------------------------------------------------------------
_global_io: tube | None = None

def set_global_io(obj) -> None:
    """
    Register the default IO used by the global shorthands (s, sa, sl, sla, r, ru, uu64).
    Accepts either:
      - Tube (wrapper): we'll call ._t() to get the underlying pwntools tube
      - pwntools tube directly
    """
    global _global_io
    # Tube wrapper?
    if hasattr(obj, "_t"):
        _global_io = obj._t()
        return
    # Raw pwntools tube?
    if hasattr(obj, "send") and hasattr(obj, "recv"):
        _global_io = obj
        return
    raise TypeError("set_global_io() expects a Tube or a pwntools tube")

def _io() -> tube:
    assert _global_io is not None, "Global io not set; call set_global_io(io)."
    return _global_io

def s(x: Chars) -> None: return _io().send(x)
def sa(d: Chars, x: Chars) -> None: return _io().sendafter(d, x)
def sl(x: Chars) -> None: return _io().sendline(x)
def sla(d: Chars, x: Chars) -> None: return _io().sendlineafter(d, x)
def r(n: int = 4096) -> bytes: return _io().recv(n)
def ru(d: Chars, drop: bool = True) -> bytes: return _io().recvuntil(d, drop=drop)
def uu64(x: bytes) -> int: return u64(x.ljust(8, b"\x00"))



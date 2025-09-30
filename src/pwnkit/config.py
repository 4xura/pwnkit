from __future__ import annotations
from dataclasses import dataclass, field
from typing import Optional, Union, Dict
from types import MethodType

from pwnlib.term.key import get
from .gdbx import ga
from pwn import pause, tube, u64, gdb, warn   # type: ignore
import os

__all__ = [
    "Config",
    "alias", "s", "sa", "sl", "sla", "r", "rl", "ru", "uu64", 
    "g", "gp",
]

Chars = Union[str, bytes]

@dataclass
class Config:
    """
    Usage:
        # local
        io = Config("./vuln", libc_path="./libc.so.6").run()

        # remote
        io = Config("./vuln", host="10.10.10.10", port=31337).run()
        io = Config("./vuln", host="4xura.com", port=1337, ssl=True).run()

        # custom env (merged with libc preload if local)
        io = Config("./vuln", env={"ASAN_OPTIONS":"detect_leaks=0"}).run()

        cfg = Config("./vuln", libc_path="./libc.so.6")
        io = cfg.run()
        io.ru(b"\n")  
        io.sl(b"cmd")
    """
    file_path   : Optional[str] = None
    libc_path   : Optional[str] = None
    host        : Optional[str] = None
    port        : Optional[int] = None
    ssl         : Optional[bool] = False
    env         : Dict[str, str] = field(default_factory=dict)

    def __post_init__(self):
        if (self.host is None) ^ (self.port is None):
            raise ValueError("Both host and port must be set for remote mode.")
        if not self.file_path:
            warn("Must provide a target binary to pwn!")
            os._exit(111)
        if self.libc_path:
            if not os.path.exists(self.libc_path):
                warn("supplied libc not exist")
                os._exit(222)

    def _is_remote(self) -> bool:
        return self.host is not None and self.port is not None

    def _build_env(self) -> Optional[Dict[str, str]]:
        """Merge user env + (optional) libc preload for local exec."""
        if self._is_remote():
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
        if self._is_remote():
            return f"remote({self.host!r}, {self.port}, ssl={self.ssl})"
        if self.libc_path:
            libc_abs = os.path.abspath(self.libc_path)
            libdir   = os.path.dirname(libc_abs) or "."
            env_code = {**self.env, "LD_PRELOAD": libc_abs, "LD_LIBRARY_PATH": libdir} if self.env else \
                       {"LD_PRELOAD": libc_abs, "LD_LIBRARY_PATH": libdir}
            return f"process({self.file_path!r}, env={env_code!r})"
        return f"process({self.file_path!r}{', env='+repr(self.env) if self.env else ''})"

    # - Start IO
    def run(self, *args, **kwargs) -> tube:
        from pwn import process, remote
        if self._is_remote():
            io = remote(self.host, self.port, *args, ssl=self.ssl, **kwargs)
        else:
            env = self._build_env()
            if env:
                io = process(self.file_path, *args, env=env, **kwargs)
            else:
                io = process(self.file_path, *args, **kwargs)

        _ALIASES: Dict[str, str] = {
            "ru"    : "recvuntil",
            "rn"    : "recvn",
            "rl"    : "recvline",
            "r"     : "recv",
            "s"     : "send",
            "sa"    : "sendafter",
            "sl"    : "sendline",
            "sla"   : "sendlineafter",
        }

        for short, real in _ALIASES.items():
            if hasattr(io, short):
                continue
            if not hasattr(io, real):
                continue
            attr = getattr(io, real)
            if getattr(attr, "__self__", None) is not None:
                setattr(io, short, attr)
            else:
                setattr(io, short, MethodType(attr, io))
        io.uu64 = lambda d: u64(d.ljust(8, b"\x00"))

        return io


# Global short aliases
# ------------------------------------------------------------------------
_global_io: tube | None = None

def alias(io: tube) -> None:
    """
    Register the initialized tube object to use global shorthands:
        s, sa, sl, sla, r, ru, uu64, g, ga, gp, etc.
    """
    global _global_io
    if hasattr(io, "send") and hasattr(io, "recv"):
        _global_io = io
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
def rl(ke: bool = True) -> bytes: return _io().recvline(ke)
def ru(d: Chars, drop: bool = True) -> bytes: return _io().recvuntil(d, drop=drop)
def uu64(x: bytes) -> int: return u64(x.ljust(8, b"\x00"))

def g(script: str = "") -> None:
    """
    Attach GDB to the globally bound tube.
    Examples:
        g("b main\\ncontinue")
    """
    ga(target=_io(), script=script)

def gp(script: str = "") -> None:
    ga(target=_io(), script=script)
    pause()

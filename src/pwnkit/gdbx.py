from __future__ import annotations
from typing import Optional, Tuple
from pwn import gdb, tube, warn  
from pwnlib.tubes.process import process as PwntoolsProcess  

__all__ = [
        "ga", "g",
        ]

GdbServer = Tuple[str, int]

def ga(io: tube, script: str = "", server: Optional[GdbServer] = None) -> None:
    """
    Attach GDB to a pwntools tube.

    - Local (process()):    gdb.attach(io, gdbscript=script)
    - Remote (remote()):    require gdbserver=(HOST, PORT) or we warn.

    Examples:
        ga(io, "b main\\ncontinue")
        ga(io, "b *0x401234\\ncontinue", server=("127.0.0.1", 1234))
    """
    try:
        if isinstance(io, PwntoolsProcess):
            gdb.attach(io, gdbscript=script)
            return
        if server is not None:
            gdb.attach(server, gdbscript=script)
            return
        warn("ga(): remote tube detected; pass server=(HOST, PORT) to attach to gdbserver.")
    except Exception as e:
        warn(f"ga(): GDB attach failed: {e}")

# Alias
# ------------------------------------------------------------------------
g = ga
__all__ = ["ga", "g"]

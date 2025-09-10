from __future__ import annotations
from typing import Tuple, Union
from pwn import gdb, tube, warn  
from pwnlib.tubes.tube import tube as PwntoolsTube

__all__ = [
        "ga",
        ]

GdbServer = Tuple[str, int]
AttachTarget = Union[PwntoolsTube, GdbServer, int]

def ga(target: AttachTarget, script: str = "") -> None:
    """
    Wrapper over pwntools' gdb.attach.
    - target: pwntools tube, (host, port) for gdbserver, or PID (int)
    - script: gdb commands
    """
    return gdb.attach(target, gdbscript=script)

"""
We set global shortcut alias g(...) in io.py
1. When alias() method is called via a pwnkit.io.Tube object
    then we can run io.g(...)
2. Use set_global_io(io) to use global shortcut
    then we can run g(...)
"""

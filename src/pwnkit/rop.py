from __future__ import annotations
from dataclasses import dataclass, field
from typing import Optional, Iterable, Dict
from pwn import ROP, ELF

__all__ = [
        "ROPGadgets",
        ]

@dataclass
class ROPGadgets:
    libc: ELF
    _rop: ROP = field(init=False, repr=False)
    gadgets: Dict[str, Optional[int]] = field(init=False, default_factory=dict)

    def __post_init__(self) -> None:
        self._rop = ROP(self.libc)
        def addr(pats: Iterable[str]) -> Optional[int]:
            found = self._rop.find_gadget(list(pats))
            return (self.libc.address + found[0]) if found else None

        self.gadgets = {
            "p_rdi_r"     : addr(["pop rdi", "ret"]),
            "p_rsi_r"     : addr(["pop rsi", "ret"]),
            "p_rdx_rbx_r" : addr(["pop rdx", "pop rbx", "ret"]),
            "p_rax_r"     : addr(["pop rax", "ret"]),
            "p_rsp_r"     : addr(["pop rsp", "ret"]),
            "leave_r"     : addr(["leave", "ret"]),
            "ret"         : addr(["ret"]),
            "syscall_r"   : addr(["syscall", "ret"]),
        }

    def __getitem__(self, k: str) -> Optional[int]:
        return self.gadgets.get(k)


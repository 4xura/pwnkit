from __future__ import annotations
from dataclasses import dataclass, field
from typing import Optional, Iterable, Dict
from pwn import ROP, ELF

__all__ = [
        "ROPGadgets",
        ]

@dataclass
class ROPGadgets:
    """
    ggs = ROPGadgets(elf)
    ggs.dump()  # debug print
    p_rdi_r = ggs['p_rdi_r']
    """
    elf: ELF
    _rop: ROP = field(init=False, repr=False)
    gadgets: Dict[str, Optional[int]] = field(init=False, default_factory=dict)

    def __post_init__(self) -> None:
        self._rop = ROP(self.elf)
        def addr(pats: Iterable[str]) -> Optional[int]:
            found = self._rop.find_gadget(list(pats))
            return (self.elf.address + found[0]) if found else None

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

    def dump(self) -> None:
        """
        Gadget       Address
        -----------------------------------
        p_rdi_r      0x000000000040123a
        p_rsi_r      0x000000000040124b
        p_rdx_rbx_r  None
        p_rax_r      0x00000000004012ab
        p_rsp_r      None
        leave_r      0x00000000004011ff
        ret          0x0000000000401005
        syscall_r    0x00000000004012cd
        """
        print(f"{'Gadget':<12} {'Address'}")
        print("-" * 35)
        for name, addr in self.gadgets.items():
            if addr is None:
                addr_str = "None".ljust(18)
            else:
                addr_str = f"0x{addr:016x}"
            print(f"{name:<12} {addr_str}")


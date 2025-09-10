#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from __future__ import annotations
from dataclasses import dataclass, field
from typing import Dict, Iterable, List, Tuple, Union
from pwn import args, context, pack, unpack, error

from pwnkit.FILE import Key  # type: ignore

"""
Naming:
    UCONTEXT:   ucontext_t
    MCONTEXT:   mcontext_t
    SetContext: setcontext
"""

__all__ = [
    "GREG_INDEX", "NGREG",
    "UCONTEXT", "UCONTEXT_MAPS", "UCONTEXT_SIZE", 
    "MCONTEXT", "MCONTEXT_MAPS", "MCONTEXT_SIZE",
    "FPSTATE", "FPSTATE_MAPS", "FPSTATE_SIZE",
    "SetContext",
    "fsave_env_28", "find_uc_offset",
]

# Global structs for setcontext
# ---------------------------------------------------------------------------
from .ctx import Arch   # Arch = Literal["amd64", "i386", "arm", "aarch64"]
PTR = object()          # "pointer-sized"

GREG_INDEX: Dict[str, Dict[str, int]] = {
    "amd64": {
        "R8":      0x00,
        "R9":      0x01,
        "R10":     0x02,
        "R11":     0x03,
        "R12":     0x04,
        "R13":     0x05,
        "R14":     0x06,
        "R15":     0x07,
        "RDI":     0x08,
        "RSI":     0x09,
        "RBP":     0x0A,
        "RBX":     0x0B,
        "RDX":     0x0C,
        "RAX":     0x0D,
        "RCX":     0x0E,
        "RSP":     0x0F,
        "RIP":     0x10,
        "EFL":     0x11,  # RFLAGS
        "CSGSFS":  0x12,  # packed CS,GS,FS (glibc ABI slot)
        "ERR":     0x13,  # error code (faults)
        "TRAPNO":  0x14,  # trap number
        "OLDMASK": 0x15,  # blocked signals mask (legacy)
        "CR2":     0x16,  # faulting address on page fault
    },
    # "i386": {...}, "arm": {...}, "aarch64": {...}  # TODO
}

NGREG: Dict[str, int] = {
        "amd64": 0x17,  # 23
}

MCONTEXT: dict[str, dict[int, tuple[str, int | object]]] = {
    """part of UCONTEXT (ucontext_t)."""
    "amd64": {
        # gregset_t gregs[23], 8 bytes each
        0x00: ("gregs.R8",      8),
        0x08: ("gregs.R9",      8),
        0x10: ("gregs.R10",     8),
        0x18: ("gregs.R11",     8),
        0x20: ("gregs.R12",     8),
        0x28: ("gregs.R13",     8),
        0x30: ("gregs.R14",     8),
        0x38: ("gregs.R15",     8),
        0x40: ("gregs.RDI",     8),
        0x48: ("gregs.RSI",     8),
        0x50: ("gregs.RBP",     8),
        0x58: ("gregs.RBX",     8),
        0x60: ("gregs.RDX",     8),
        0x68: ("gregs.RAX",     8),
        0x70: ("gregs.RCX",     8),
        0x78: ("gregs.RSP",     8),
        0x80: ("gregs.RIP",     8),
        0x88: ("gregs.EFL",     8),
        0x90: ("gregs.CSGSFS",  8),
        0x98: ("gregs.ERR",     8),
        0xA0: ("gregs.TRAPNO",  8),
        0xA8: ("gregs.OLDMASK", 8),
        0xB0: ("gregs.CR2",     8),

        # fpregset_t *fpregs
        0xB8: ("fpregs", PTR),

        # unsigned long int oldmask (scalar view)
        0xC0: ("oldmask", 8),

        # unsigned long int cr2 (scalar view)
        0xC8: ("cr2", 8),
    },

    # "i386": {
        # # TODO: fill in from dump_ucontext_offsets on 32-bit
    # },

    # "arm": {
        # # TODO
    # },

    # "aarch64": {
        # # TODO
    # },
}

MCONTEXT_SIZE: dict[str, int|None] = {
    "amd64": 0x100,
    "i386":  None,      # TODO
    "arm":   None,      # TODO
    "aarch64": None,    # TODO
}

MCONTEXT_MAPS: Dict[str, Dict[int, Tuple[str, int | object]]] = {
    "amd64": MCONTEXT["amd64"],
    # "i386": {...}, "arm": {...}, "aarch64": {...}  # TODO
}

UCONTEXT: Dict[str, Dict[int, Tuple[str, int | object]]] = {
    "amd64": {
        ## https://elixir.bootlin.com/glibc/glibc-2.35/source/sysdeps/unix/sysv/linux/x86/sys/ucontext.h#L235
        # typedef struct ucontext_t {
        #   unsigned long int uc_flags;
        0x00: ("uc_flags", 8),

        #   struct ucontext_t *uc_link;
        0x08: ("uc_link", PTR),

        #   stack_t uc_stack; (signal stack) // { void *ss_sp; int ss_flags; size_t ss_size; }
        0x10: ("uc_stack.ss_sp",    PTR),
        0x18: ("uc_stack.ss_size",  8),
        0x20: ("uc_stack.ss_flags", 4),

        #   mcontext_t uc_mcontext; // we expose gregs and fpregs pointer
        #   gregs base = 0x28 + 0x00; each entry is 8 bytes
        0x28: ("uc_mcontext.gregs.R8",      8),
        0x30: ("uc_mcontext.gregs.R9",      8),
        0x38: ("uc_mcontext.gregs.R10",     8),
        0x40: ("uc_mcontext.gregs.R11",     8),
        0x48: ("uc_mcontext.gregs.R12",     8),
        0x50: ("uc_mcontext.gregs.R13",     8),
        0x58: ("uc_mcontext.gregs.R14",     8),
        0x60: ("uc_mcontext.gregs.R15",     8),
        0x68: ("uc_mcontext.gregs.RDI",     8),
        0x70: ("uc_mcontext.gregs.RSI",     8),
        0x78: ("uc_mcontext.gregs.RBP",     8),
        0x80: ("uc_mcontext.gregs.RBX",     8),
        0x88: ("uc_mcontext.gregs.RDX",     8),
        0x90: ("uc_mcontext.gregs.RAX",     8),
        0x98: ("uc_mcontext.gregs.RCX",     8),
        0xA0: ("uc_mcontext.gregs.RSP",     8),
        0xA8: ("uc_mcontext.gregs.RIP",     8),
        0xB0: ("uc_mcontext.gregs.EFL",     8),
        0xB8: ("uc_mcontext.gregs.CSGSFS",  8),
        0xC0: ("uc_mcontext.gregs.ERR",     8),
        0xC8: ("uc_mcontext.gregs.TRAPNO",  8),
        0xD0: ("uc_mcontext.gregs.OLDMASK", 8),
        0xD8: ("uc_mcontext.gregs.CR2",     8),
        # fpregset_t *fpregs and scalar views (still INSIDE mcontext)
        # Structure to describe FPU registers { typedef struct _libc_fpstate *fpregset_t; }
        0xE0: ("uc_mcontext.fpregs", PTR),
        0xE8: ("uc_mcontext.oldmask", 8),
        0xF0: ("uc_mcontext.cr2",     8),
        # 0x0F8..0x127 would be padding up to 0x128 (start of uc_sigmask)

        #   sigset_t uc_sigmask; // 1024-bit = 128 bytes
        0x128: ("uc_sigmask[128]", 0x80),

        #   struct _libc_fpstate __fpregs_mem; // inline FXSAVE area (512 bytes)
        # 0x1A8: ("__fpregs_mem[512]", 0x200),     # whole blob
        # expose key header fields for convenience (what setcontext.S uses)
        0x1A8: ("__fpregs_mem.fcw", 2),
        0x1AA: ("__fpregs_mem.fsw", 2),
        0x1AC: ("__fpregs_mem.ftw", 1),
        0x1AE: ("__fpregs_mem.fop", 2),
        0x1B0: ("__fpregs_mem.rip", 8),
        0x1B8: ("__fpregs_mem.rdp", 8),
        0x1C0: ("__fpregs_mem.mxcsr", 4),       # <-- ldmxcsr reads here
        0x1C4: ("__fpregs_mem.mxcsr_mask", 4), 

        #   unsigned long int __ssp[4]; // CET shadow stack scratch
        0x3A8: ("__ssp[4]", 0x20),
        # } ucontext_t;
    },

    # "i386": {  # TODO
    #     ...
    # },
    # "arm": {   # TODO
    #     ...
    # },
    # "aarch64": {  # TODO
    #     ...
    # },
}

UCONTEXT_SIZE: dict[str, int|None] = {
    "amd64": 0x3C8,     # 968
    "i386":  None,      # TODO
    "arm":   None,      # TODO
    "aarch64": None,    # TODO
}

UCONTEXT_MAPS: Dict[str, Dict[int, Tuple[str, int | object]]] = {
    "amd64": UCONTEXT["amd64"],
    # "i386": {...}, "arm": {...}, "aarch64": {...}  # TODO
}

FPSTATE: dict[str, dict[int, tuple[str, int]]] = {
    """Inline FP area inside ucontext_t"""
    "amd64": {
        # __fpregs_mem (FXSAVE on amd64)
        # FXSAVE header
        0x000: ("fx.cwd", 2),          # FCW
        0x002: ("fx.swd", 2),          # FSW
        0x004: ("fx.twd", 1),          # FTW (compressed)
        0x005: ("fx.pad1", 1),         # reserved
        0x006: ("fx.fop", 2),          # FOP
        0x008: ("fx.rip", 8),          # FPU instruction pointer (RIP)
        0x010: ("fx.rdp", 8),          # FPU data pointer (RDP)
        0x018: ("fx.mxcsr", 4),        # MXCSR
        0x01C: ("fx.mxcsr_mask", 4),   # MXCSR_MASK

        # x87 ST/MM regs (8 regs × 16 bytes) — raw 128 bytes
        0x020: ("fx.st_space[128]", 0x80),

        # XMM regs (16 regs × 16 bytes) — raw 256 bytes
        0x0A0: ("fx.xmm_space[256]", 0x100),

        # Reserved to 512 total
        0x1A0: ("fx.reserved[96]", 0x60),
    },
    # "i386": # TODO
}

FPSTATE_SIZE: Dict[str, int | None] = {"amd64": 0x200, "i386": None}

FPSTATE_MAPS: Dict[str, Dict[int, Tuple[str, int | object]]] = {
    "amd64": FPSTATE["amd64"],
    # "i386": {...}, "arm": {...}, "aarch64": {...}  # TODO
}

# Aliases
# ---------------------------------------------------------------------------
_FIELD_ALIASES = {
    # Optional convenience aliases (amd64)
    "R8":"uc_mcontext.gregs.R8","R9":"uc_mcontext.gregs.R9","R10":"uc_mcontext.gregs.R10","R11":"uc_mcontext.gregs.R11",
    "R12":"uc_mcontext.gregs.R12","R13":"uc_mcontext.gregs.R13","R14":"uc_mcontext.gregs.R14","R15":"uc_mcontext.gregs.R15",
    "RDI":"uc_mcontext.gregs.RDI","RSI":"uc_mcontext.gregs.RSI","RBP":"uc_mcontext.gregs.RBP","RBX":"uc_mcontext.gregs.RBX",
    "RDX":"uc_mcontext.gregs.RDX","RAX":"uc_mcontext.gregs.RAX","RCX":"uc_mcontext.gregs.RCX",
    "RSP":"uc_mcontext.gregs.RSP","RIP":"uc_mcontext.gregs.RIP",
    "EFL":"uc_mcontext.gregs.EFL","CSGSFS":"uc_mcontext.gregs.CSGSFS","ERR":"uc_mcontext.gregs.ERR",
    "TRAPNO":"uc_mcontext.gregs.TRAPNO","OLDMASK":"uc_mcontext.gregs.OLDMASK","CR2":"uc_mcontext.gregs.CR2",
    # fx header convenience
    "MXCSR": "__fpregs_mem.mxcsr",  
    "FPREGS": "uc_mcontext.fpregs",
}

# Helpers
# ---------------------------------------------------------------------------
def _ptr_width(arch: str) -> int:
    return 8 if arch.lower() in ("amd64", "x86_64", "aarch64", "arm64") else 4

def _resolve_key(
    uc_map: Dict[int, Tuple[str, int | object]],
    key: Union[str, int],
    *,
    aliases: Dict[str, str] = _FIELD_ALIASES,
) -> Tuple[int, int | object, str]:
    """
    Resolve a field-name (str) or absolute offset (int) against a flat UCONTEXT map.
    No special cases; aliases are just sugar (e.g., 'RIP' → 'uc_mcontext.gregs.RIP').
    Returns (offset, size|PTR, canonical_name).
    """
    # 1) absolute offset
    if isinstance(key, int):
        try:
            nm, sz = uc_map[key]
            return key, sz, nm
        except KeyError:
            raise KeyError(f"Unknown absolute offset: {hex(key)}")

    # 2) name / alias
    if isinstance(key, str):
        name = aliases.get(key.upper(), key)
        for off, (nm, sz) in uc_map.items():
            if nm == name:
                return off, sz, nm

    raise KeyError(f"Unknown field: {key!r}")

# Setcontext with ucontext_t
# ---------------------------------------------------------------------------
@dataclass
class SetContext:
    arch: Arch = field(default_factory=lambda: ("amd64") if context.bits == 64 else "i386")
    size: int = field(init=False)
    data: bytearray = field(init=False)
    _map: Dict[int, Tuple[str, int | object]] = field(init=False, repr=False)
    _ptr_fields: Tuple[str, ...] = field(init=False, repr=False)

    def __post_init__(self):
        self.arch = self.arch.lower()
        if self.arch not in UCONTEXT:
            raise NotImplementedError(f"{self.arch}: is not implemented yet.")
        self.size = UCONTEXT_SIZE[self.arch]
        if self.size is None:
            raise NotImplementedError(f"{self.arch}: missing UCONTEXT_SIZE.")
        self._map = UCONTEXT[self.arch]
        self._ptr_fields = tuple(name for _, (name, sz) in self._map.items() if sz is PTR)
        self.data = bytearray(self.size)

    def set(self, field: Union[str, int], value: int | bytes) -> None:
        """Generic setter by field *name* or absolute *offset*."""
        off, sz, nm = _resolve_key(self._map, field, aliases=_FIELD_ALIASES)
        width = _ptr_width(self.arch) if sz is PTR else sz
        if isinstance(value, int):
            if not isinstance(width, int):
                raise ValueError(f"Cannot write int to pointer-sized field without width (field {nm})")
            self.data[off:off+width] = (value & ((1 << (8*width)) - 1)).to_bytes(width, "little")
        else:
            if not isinstance(width, int):
                raise ValueError(f"bytes assignment requires concrete size: {nm}")
            if len(value) != width:
                raise ValueError(f"{nm} expects {hex(width)} bytes, got {hex(len(value))}")
            self.data[off:off+width] = value

    def get(self, field: Union[str, int]) -> int | bytes:
        """Generic getter by field *name* or absolute *offset*.
           Returns int for integer-sized fields, bytes for blob fields (e.g., sigmask)."""
        off, sz, nm = _resolve_key(self._map, field, aliases=_FIELD_ALIASES)
        width = _ptr_width(self.arch) if sz is PTR else sz
        if isinstance(width, int) and width in (1, 2, 4, 8):
            return int.from_bytes(self.data[off:off+width], "little")
        if isinstance(width, int):
            return bytes(self.data[off:off+width])
        raise ValueError(f"Unsupported field width for {nm}: {width}")

    # - sugar: regs / stack / sigmask / fpstate
    def set_reg(self, reg: str, value: int) -> None:
        self.set(f"uc_mcontext.gregs.{reg.upper()}", value)

    def set_stack(self, sp: int, size: int, flags: int = 0) -> None:
        self.set("uc_stack.ss_sp", sp)
        self.set("uc_stack.ss_size", size)
        self.set("uc_stack.ss_flags", flags)

    def set_sigmask_block(self, sigs: Iterable[int]) -> None:
        # 1024-bit sigset_t: 16 x u64 little-endian
        words = [0]*16
        for signo in sigs:
            if signo <= 0: 
                continue
            idx = (signo - 1) // 64
            bit = (signo - 1) % 64
            words[idx] |= (1 << bit)
        blob = b"".join((w & ((1<<64)-1)).to_bytes(8, "little") for w in words)
        self.set("uc_sigmask[128]", blob)

    def set_fpu_env_ptr(self, ptr: int) -> None:
        # Points uc_mcontext.fpregs to any fxsave-compatible buffer
        self.set("uc_mcontext.fpregs", ptr)

    @property
    def fldenv_ptr(self) -> int:
        """
        FSAVE env pointer (fldenv)
        alias for uc_mcontext.fpregs
        """
        return self.get("uc_mcontext.fpregs")

    @fldenv_ptr.setter
    def fldenv_ptr(self, value: int) -> None:
        self.set("uc_mcontext.fpregs", value)

    def set_mxcsr(self, value: int = 0x1F80) -> None:
        """
        Write MXCSR inside the inline fxsave area.
        On amd64 glibc, MXCSR is at ucontext + 0x1C0 (i.e., __fpregs_mem + 0x18).
        0x1F80 is the default safe value
        0 is acceptable if the payload doesn't rely on SSE or floating-point behavior.
        """
        self.set("__fpregs_mem.mxcsr", value)

    @property
    def mxcsr(self) -> int:
        return self.get("__fpregs_mem.mxcsr")

    @mxcsr.setter
    def mxcsr(self, value: int) -> None:
        self.set("__fpregs_mem.mxcsr", value)


# Fpstate env
# ---------------------------------------------------------------------------
def fsave_env_28(fcw=0x037F, fsw=0, ftw=0, fip=0, fcs=0, fdp=0, fds=0) -> bytes:
    """
    28-byte x87 environment for FLDENV in 32/64-bit modes
    In x86-64 glibc, mcontext_t.fpregs (the thing setcontext.S uses with fldenv) 
    must point to an FSAVE-style x87 environment, 
    i.e., the classic 28-byte “env” (not the 512-byte FXSAVE block).

    Make fldenv ptr point at a 28-byte FSAVE x87 environment (aka “m14/28-byte env” per Intel). 
    Minimal, sane values:
        @FCW (control) = 0x037F (mask all, 64-bit precision default)
        @FSW, FTW = 0
        @FIP/FCS/FDP/FDS = 0 (you’re not returning to x87 code)
        pad out to 28 bytes (0x1C)
    """
    parts = [
        fcw.to_bytes(2, 'little'),
        fsw.to_bytes(2, 'little'),
        ftw.to_bytes(2, 'little'),
        fip.to_bytes(4, 'little'),
        fcs.to_bytes(2, 'little'),
        fdp.to_bytes(4, 'little'),
        fds.to_bytes(2, 'little'),
    ]
    env = b"".join(parts)
    return env.ljust(0x1C, b"\x00")

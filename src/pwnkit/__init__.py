from __future__ import annotations
from typing import Tuple, List
import importlib

# --- Version ---
try:
    from ._version import __version__ 
except ImportError:
    __version__ = "0.0.0"

# --- Submodules ---
_modules: tuple[str, ...] = (
    "io",
    "encrypt",
    "rop",
    "gdbx",
    "utils",
    "ctx",
    "shellcode",
    "hashpow",
    "FILE",
    "ucontext"
)

# --- Exports ---
__all__: List[str] = ["__version__"]

for name in _modules:
    mod = importlib.import_module(f".{name}", __name__)
    globals()[name] = mod
    for sym in getattr(mod, "__all__", ()):
        globals()[sym] = getattr(mod, sym)
        __all__.append(sym)
    __all__.append(name)

# --- TYPE_CHECKING BEGIN (auto-generated; do not edit) ---
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from .io import (
        Tube, g, gp, r, ru, s, sa, set_global_io, sl, sla, uu64,
    )
    from .encrypt import (
        PointerGuard, SafeLinking,
    )
    from .rop import ROPGadgets
    from .gdbx import ga
    from .utils import (
        init_pr, itoa, leak, logger, pa, parse_argv, pr_critical, pr_debug, pr_error, pr_exception,
        pr_info, pr_warn,
    )
    from .ctx import Context
    from .shellcode import (
        Arch, SHELLCODES, Shellcode, ShellcodeBuilder, ShellcodeReigstry, build_sockaddr_in,
        hex_shellcode, list_shellcodes,
    )
    from .hashpow import (
        BruteForcer, solve_pow, solve_pow_mt,
    )
    from .FILE import (
        IOFilePlus, IO_FILE_MAPS, _IO_FILE_AMD64, _IO_FILE_I386,
    )
    from .ucontext import (
        FPSTATE, FPSTATE_MAPS, FPSTATE_SIZE, GREG_INDEX, MCONTEXT, MCONTEXT_MAPS, MCONTEXT_SIZE, NGREG,
        UCONTEXT, UCONTEXT_MAPS, UCONTEXT_SIZE, UContext, find_uc_offset, fsave_env_28,
    )
# --- TYPE_CHECKING END (auto-generated) ---

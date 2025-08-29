from __future__ import annotations
import inspect
from pwn import success  
from typing import Literal, Optional, Tuple, Sequence
import logging, sys

__all__ = [
        "leak", "pa",
        "itoa",
        "init_pr",
        "pr_debug", "pr_info", "pr_warn", "pr_error", "pr_critical", "pr_exception",
        "parse_argv",
        ]

# Data format transform
# ------------------------------------------------------------------------
def itoa(a: int) -> bytes:
    return str(a).encode()

# Leak (print) memory addresses
# ------------------------------------------------------------------------
def leak(addr: int) -> None:
    """
    Pretty-print a leaked address with variable name if possible.

    Example:
        buf = 0xdeadbeef
        leak(buf)  # prints "Leak buf addr: 0xdeadbeef"
    """
    frame = inspect.currentframe().f_back
    desc = "unknown"
    try:
        # Try to find which local variable equals this address
        variables = {k: v for k, v in frame.f_locals.items() if isinstance(v, int) and v == addr}
        if variables:
            desc = next(iter(variables.keys()))
    except Exception:
        pass

    c_addr = f"\033[1;33m{addr:#x}\033[0m"
    success(f"Leak {desc:<16} addr: {c_addr}")

pa = leak

# Logging
# ------------------------------------------------------------------------
class ColorFormatter(logging.Formatter):
    COLORS = {
        'DEBUG':    "\033[32m",     # Green
        'INFO':     "\033[94m",     # blue
        'WARNING':  "\033[33m",     # Yellow
        'ERROR':    "\033[31m",     # Red
        'CRITICAL': "\033[1;33;41m" # Bold yellow text red bg
    }
    RESET = "\033[0m"

    def format(self, record):
        orig = record.levelname
        try:
            color = self.COLORS.get(orig, self.RESET)
            record.levelname = f"{color}{orig}{self.RESET}"
            return super().format(record)
        finally:
            record.levelname = orig

logger = logging.getLogger("pwnkit")

def init_pr(
        level: Literal["debug","info","warning","error","critical"]="info",
        fmt: str = "%(asctime)s - %(levelname)s - %(message)s",
        datefmt: str = "%H:%M:%S",
    ) -> None:
    """
    Configure colored logging.

        @level   : log level name (default: "info")
        @fmt     : log format string (default: "%(asctime)s - %(levelname)s - %(message)s")
        @datefmt : datetime format string (default: "%H:%M:%S")
    """
    formatter = ColorFormatter(fmt=fmt, datefmt=datefmt)
    handler = logging.StreamHandler()
    handler.setFormatter(formatter)

    try:
        logging.basicConfig(
            level=getattr(logging, level.upper(), logging.INFO),
            handlers=[handler],
            force=True,  # Python 3.8+
        )
    except TypeError:
        logger.handlers.clear()
        logger.addHandler(handler)
        logger.setLevel(getattr(logging, level.upper(), logging.INFO))

def pr_debug(msg):
    logging.debug(msg)

def pr_info(msg):
    logging.info(msg)

def pr_warn(msg):
    logging.warning(msg)

def pr_error(msg):
    logging.error(msg)

def pr_critical(msg):
    logging.critical(msg)

def pr_exception(msg):
    logging.exception(msg)

# Usage
# ------------------------------------------------------------------------
def _usage(argv: Sequence[str]) -> Tuple[None, None]:
    prog = sys.argv[0] if sys.argv else "xpl.py"
    print(f"Usage: {prog} [IP PORT] | [IP:PORT]\n"
          f"Examples:\n"
          f"  {prog}\n"
          f"  {prog} 10.10.10.10 31337\n"
          f"  {prog} 10.10.10.10:31337\n")
    sys.exit(1)

# Parse argv (ip, host)
# ------------------------------------------------------------------------
def parse_argv(argv: Sequence[str],
				default_host: Optional[str] = None,
				default_port: Optional[int] = None
				) -> Tuple[Optional[str], Optional[int]]:
    """
    Accepts:
      []
      [IP PORT]
      [IP:PORT]
    Returns (host, port) where either may be None (local mode).
    """
    host, port = default_host, default_port
    if len(argv) == 0:
        return host, port

    if len(argv) == 1 and ":" in argv[0]:
        h, p = argv[0].split(":", 1)
        if not h or not p.isdigit():
            return _usage(argv)
        return h, int(p)

    if len(argv) == 2:
        h, p = argv[0], argv[1]
        if not p.isdigit():
            return _usage(argv)
        return h, int(p)

    return _usage(argv)


from __future__ import annotations
from pwn import success  
from typing import Any, Literal, Optional, Tuple, Sequence, Union
from urllib.parse import quote, quote_plus, unquote, urlencode
import binascii, inspect, logging, sys, os

__all__ = [
        "print_addr", "leak", "pa",
        "print_data", "pd",
        "itoa", "i2a", "bytex", "hex2b", "b2hex", "url_qs",
        "init_pr",
        "logger", "pr_debug", "pr_info", "pr_warn", "pr_error", "pr_critical", "pr_exception",
        "load_argv",
        "colorize",
        ]

# Helpers
# ------------------------------------------------------------------------
def colorize(enable: bool | None = None) -> dict:
    """
    Return a mapping of color/style names -> ANSI sequences (or empty strings when disabled).

    - enable: if True/False, force enable/disable. If None (default), auto-detect:
        enabled iff sys.stdout.isatty() and NO_COLOR env var is not set.
    - Always returns the same set of keys so callers can use mapping['red'] safely.

    Example:
        COL = colorize()                # auto
        print(f"{COL['bold']}{COL['red']}leak{COL['clr']}")
        # or explicitly enable/disable:
        COL = colorize(enable=True)     # force on (useful in tests)
    """
    palette = {
        # styles
        "bold":   "\033[1m",
        "dim":    "\033[2m",
        "italic": "\033[3m",
        "ul":     "\033[4m",
        "blink":  "\033[5m",
        "rev":    "\033[7m",
        "hide":   "\033[8m",
        # reset
        "clr":    "\033[0m",
        # normal fg
        "blk":    "\033[30m",
        "red":    "\033[31m",
        "grn":    "\033[32m",
        "yel":    "\033[33m",
        "blu":    "\033[34m",
        "mag":    "\033[35m",
        "cya":    "\033[36m",
        "wht":    "\033[37m",
        # bright fg
        "bblk":   "\033[90m",
        "bred":   "\033[91m",
        "bgrn":   "\033[92m",
        "byel":   "\033[93m",
        "bblu":   "\033[94m",
        "bmag":   "\033[95m",
        "bcya":   "\033[96m",
        "bwht":   "\033[97m",
        # backgrounds
        "bg_blk": "\033[40m",
        "bg_red": "\033[41m",
        "bg_grn": "\033[42m",
        "bg_yel": "\033[43m",
        "bg_blu": "\033[44m",
        "bg_mag": "\033[45m",
        "bg_cya": "\033[46m",
        "bg_wht": "\033[47m",
    }
    if enable is None:
        enabled = sys.stdout.isatty() and (os.environ.get("NO_COLOR") is None)
    else:
        enabled = bool(enable)

    if enabled:
        return palette
    return {k: "" for k in palette}

def _get_caller_varname(obj: Any, depth: int = 2) -> str:
    """
    Return the 1st local variable name in the caller frame
    whose identity matches `obj` (id equal). If none found, return '<expr>'.

      @depth: how many frames to walk up (default 2 => caller of caller).
    """
    try:
        frame = inspect.currentframe()
        for _ in range(depth):
            if frame is None:
                return "<expr>"
            frame = frame.f_back
        if frame is None:
            return "<expr>"
        for name, val in frame.f_locals.items():
            try:
                if id(val) == id(obj):
                    return name
            except Exception:
                continue
    except Exception:
        pass
    return "<expr>"

# - Internals
COL = colorize(enable=True)

# Data Transformers
# ------------------------------------------------------------------------
def itoa(a: int) -> bytes:
    return str(a).encode()

i2a = itoa

def bytex(x) -> bytes:
    if isinstance(x, bytes): return x
    if isinstance(x, bytearray): return bytes(x)
    if isinstance(x, memoryview): return x.tobytes()
    if isinstance(x, str): return x.encode()
    if isinstance(x, int): return str(x).encode()  # like itoa()
    raise TypeError(f"cannot bytes(): {type(x)}")

def hex2b(s: Union[str, bytes]) -> bytes:
    if isinstance(s, (bytes, bytearray)): s = s.decode()
    s = s.strip().lower()
    if s.startswith('0x'): s = s[2:]
    s = re.sub(r'[^0-9a-f]', '', s)  # drop spaces/colons
    if len(s) % 2: s = '0' + s
    try: return binascii.unhexlify(s)
    except binascii.Error as e: raise ValueError(f"bad hex: {e}")

def b2hex(b: Union[bytes, bytearray, memoryview]) -> str:
    """
    b2hex(b"aaa") # '0x616161'
    """
    hexstr = "0x" + binascii.hexlify(bytex(b)).decode()
    return hexstr

def url_qs(params, *, rfc3986=True, doseq=True):
    """
    dict / list[tuples] -> query string.
    rfc3986=True: spaces -> %20 ; False: spaces -> '+'

    e.g.,
    url_qs({"q": "a b", "tag": ["x/y", "z"]})   # "q=a%20b&tag=x%2Fy&tag=z"
    """
    qv = quote if rfc3986 else quote_plus
    return urlencode(params, doseq=doseq, quote_via=qv, safe="-._~")

# Pretty prints
# ------------------------------------------------------------------------
# - Print memory address in hex given a symbol name 
def print_addr(addr: int, *, name: Optional[str] = None, depth: int = 2) -> None:
    """
    Pretty-print a leaked address with variable name auto extracted.

    Examples:
        backdoor = 0xdeadbeef
        print_addr(backdoor)        # prints    "Leaked address of backdoor: 0xdeadbeef"
        leak(buf, name="gooddoor")  # override: "Leaked address of gooddoor: 0xdeadbeef"
        pa(buf, depth: 4)           # if varanme not found in frame, better keep default
    """
    # allow explicit override
    if not isinstance(addr, int):
        raise TypeError("leak() expects an int address")
    desc = name if name is not None else _get_caller_varname(addr, depth=depth)
    c_desc = f"\033[1;31m{desc}\033[0m"     # red
    c_addr = f"\033[1;33m{addr:#x}\033[0m"  # yellow
    text = f"Leaked address of {c_desc}: {c_addr}"

    try:
        success(text)
    except NameError:
        print(f"[{COL['grn']}+{COL['clr']}] {text}")

# - Print data with various data format dumps
def _pad_hex(b: bytes, bits: Literal[64, 32] = 64, lsb_first: bool = True) -> str:
    padded = b.ljust(int(bits/8), b"\x00")
    data = padded[::-1] if lsb_first else padded
    return "0x" + binascii.hexlify(data).decode()

def _qword_hexdump(buf: bytes):
    if not buf:
        return ["(empty)"]
    out = ["[*] memoryview:"]
    for off in range(0, len(buf), 16):
        chunk = buf[off:off+16]
        page, offset = (off // 0x10000), (off % 0x10000)
        label = f"{page:02x}:{offset:04x}"
        q1, q2 = chunk[0:8], chunk[8:16]
        q1_hex = _pad_hex(q1.ljust(8, b"\x00"))
        q2_hex = _pad_hex(q2.ljust(8, b"\x00")) if q2 else ""
        ascii_col = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)
        if q2:
            out.append(f"{label}│ {q1_hex}  {q2_hex} │ {ascii_col}")
        else:
            out.append(f"{label}│ {q1_hex}                  │ {ascii_col}")
    return out

def _byte2bits(buf: bytes) -> str:
    return "".join(f"{b:08b}" for b in buf) if buf else "(empty)"

def _byte2oct(buf: bytes) -> str:
    return "".join(f"\\{b:03o}" for b in buf) if buf else "(empty)"

def _u_bytes(x: int, w: int) -> bytes:
    mask = (1 << (w*8)) - 1
    return (x & mask).to_bytes(w, "little", signed=False)

def _s_bytes(x: int, w: int) -> bytes:
    return int.to_bytes(x, w, "little", signed=True)

def print_data(x, name: Optional[str] = None, *,
               int_widths: Optional[list] = None,
               encoding: str = "utf-8",
               errors: str = "replace"):
    """
    print_data(x, name=None, encoding='utf-8', errors='replace')

    - For str: show type, repr, len (chars), bytes (len of encoded bytes),
               bin/oct of encoded bytes, per-char codepoints + utf8 bytes, then hexdump
    - For bytes: as before (len, bin, oct, hexdump)
    - For int: bin, oct, dec, hex, then [1/2/4/8B] LE/BE with numeric interpretations
    """
    label = name if name is not None else _get_caller_varname(x)
    title = f"[{COL['grn']}+{COL['clr']}] Print data: {COL['grn']}{label}{COL['clr']}"
    print(title)
    tname = type(x).__name__
    print(f"    type : {tname}")
    print(f"    repr : {repr(x)}")

    # - STR: treat as Unicode text, encode to bytes with chosen encoding
    if isinstance(x, str):
        chars = len(x)
        b = x.encode(encoding, errors=errors)
        print(f"    len  : {chars}")
        print(f"    bytes: {len(b)}")
        # binary / octal of the encoded bytes
        print(f"    bin  : {_byte2bits(b)}")
        print(f"    oct  : {_byte2oct(b)}")
        print("    hex  :", "".join(f"\\x{byte:02x}" for byte in b))
        # per-character table
        if chars > 0:
            print("[*] chars:")
            for i, ch in enumerate(x):
                cp = f"U+{ord(ch):04X}"
                utf8_hex = binascii.hexlify(ch.encode(encoding, errors=errors)).decode()
                # show char repr, codepoint, and hex of its encoded bytes
                print(f"  [{i}] {repr(ch)} {cp} utf8=0x{utf8_hex}")
        # hexdump of the encoded bytes last
        for line in _qword_hexdump(b):
            print(line)
        return

    # - BYTES / bytearray / memoryview
    if isinstance(x, (bytes, bytearray, memoryview)):
        b = bytes(x)
        print(f"    len  : {len(b)}")
        print(f"    bin  : {_byte2bits(b)}")
        print(f"    oct  : {_byte2oct(b)}")
        print("    hex  :", "".join(f"\\x{byte:02x}" for byte in b))
        for line in _qword_hexdump(b):
            print(line)
        return

    # - INT
    if isinstance(x, int):
        widths = [1, 2, 4, 8] if int_widths is None else sorted(set(int_widths))
        print(f"    bin  : {bin(x)}")
        print(f"    oct  : {oct(x)}")
        print(f"    dec  : {x}")
        print(f"    hex  : {hex(x)}")
        print("[*] memoryview")
        for w in widths:
            ule = _u_bytes(x, w); ube = ule[::-1]
            u_le_hex = _pad_hex(ule); u_be_hex = _pad_hex(ube)
            u_le_val = int.from_bytes(ule, "little", signed=False)
            u_be_val = int.from_bytes(ube, "big", signed=False)
            try:
                sle = _s_bytes(x, w); sbe = sle[::-1]
                s_le_hex = _pad_hex(sle); s_be_hex = _pad_hex(sbe)
                s_le_val = int.from_bytes(sle, "little", signed=True)
                s_be_val = int.from_bytes(sbe, "big", signed=True)
            except OverflowError:
                s_le_hex = s_be_hex = "signed:overflow"
                s_le_val = s_be_val = "overflow"
            print(f"  [{w}B] unsignedLE={u_le_hex} (u={u_le_val}) unsignedBE={u_be_hex} (u={u_be_val})  "
                  f"signedLE={s_le_hex} (s={s_le_val}) signedBE={s_be_hex} (s={s_be_val})")
        return

    # - FALLBACK: if convertible to bytes
    try:
        b = bytes(x)
        if b:
            print(f"    len  : {len(b)}")
            print(f"    bin  : {_byte2bits(b)}")
            print(f"    oct  : {_byte2oct(b)}")
            for l in _qword_hexdump(b):
                print(l)
            return
    except Exception:
        pass

# - Aliases
pa      = print_addr
leak    = print_addr
pd      = print_data

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
    level: Literal["debug","info","warning","error","critical"] = "info",
    fmt: str = "%(asctime)s - %(levelname)s - %(message)s",
    datefmt: str = "%H:%M:%S",
) -> None:
    """
    Initialize logging for the 'pwnkit' namespace.

    - Configures only the 'pwnkit' logger (not root), so pwntools' own logging
      remains intact.
    - Installs a single StreamHandler with colored output.
    - Allows switching level at runtime: "debug", "info", etc.
    """
    lvl = getattr(logging, level.upper(), logging.INFO)

    logger.propagate = False    # avoids duplicate messages
    logger.setLevel(lvl)
    logger.handlers = [h for h in logger.handlers if not isinstance(h, logging.StreamHandler)]

    h = logging.StreamHandler()
    h.setFormatter(ColorFormatter(fmt=fmt, datefmt=datefmt))
    h.setLevel(lvl)  # optional
    logger.addHandler(h)

    plog = logging.getLogger("pwnlib")  # Align pwntools' logging level
    if lvl <= logging.DEBUG:
        plog.setLevel(logging.DEBUG)
    plog.propagate = False

def pr_debug(msg):
    logger.debug(msg)

def pr_info(msg):
    logger.info(msg)

def pr_warn(msg):
    logger.warning(msg)

def pr_error(msg):
    logger.error(msg)

def pr_critical(msg):
    logger.critical(msg)

def pr_exception(msg):
    logger.exception(msg)

# Usage
# ------------------------------------------------------------------------
def _usage(argv: Sequence[str]) -> Tuple[None, None]:
    prog = sys.argv[0] if sys.argv else "xpl.py"
    print(f"Usage: {prog} [HOST PORT] | [HOST:PORT]\n"
          f"Examples:\n"
          f"  {prog}\n"
          f"  {prog} 10.10.10.10 31337\n"
          f"  {prog} 10.10.10.10:31337\n"
          f"  {prog} pwn.4xura.com:31337\n")
    sys.exit(1)

# Parse argv to retrieve (host, port)
# ------------------------------------------------------------------------
def load_argv(argv: Sequence[str]) -> Tuple[Optional[str], Optional[int]]:
    """
    Accepts:
      []
      [HOST PORT]
      [HOST:PORT]
    Returns (host, port) where either may be None (local mode).
    """
    host, port = None, None
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


from __future__ import annotations
from pathlib import Path
from argparse import ArgumentParser, Namespace, RawTextHelpFormatter
from pwnkit import *
import importlib.resources as ir
import os, string


# Exp Templates
# ------------------------------------------------------------------------
ENV_TPL_DIR = "PWNKIT_TEMPLATES"   # directory for custom templates
ENV_TPL_SEL = "PWNKIT_TEMPLATE"    # env var selecting default name/path

# - Helpers
def _read(p: Path) -> str:
    return p.read_text(encoding="utf-8")

def _load_from_fs(name_or_path: str) -> tuple[str, str] | None:
    # 1) explicit path
    p = Path(name_or_path)
    if p.is_file():
        return _read(p), f"fs:{p}"
    # 2) bare name under ENV dir
    env_dir = os.environ.get(ENV_TPL_DIR)
    if env_dir:
        base = Path(env_dir)
        for cand in (name_or_path, f"{name_or_path}.py.tpl", f"{name_or_path}.tpl"):
            q = base / cand
            if q.is_file():
                return _read(q), f"env:{q}"
    return None

def _bundled_root() -> Path | None:
    try:
        root = ir.files("pwnkit") / "templates"
        with ir.as_file(root) as base:
            return Path(base)
    except Exception:
        return None

def _bundled_templates() -> list[str]:
    base = _bundled_root()
    if not base or not base.is_dir():
        return []
    names: set[str] = set()
    for p in base.glob("*.tpl"):
        if p.name.endswith(".py.tpl"):
            names.add(p.name[:-7])   # strip .py.tpl
        else:
            names.add(p.stem)        # strip .tpl
    return sorted(names)

# - Load templates
def _load_bundled(name: str) -> tuple[str, str] | None:
    base = _bundled_root()
    if not base:
        return None
    for cand in (name, f"{name}.py.tpl", f"{name}.tpl"):
        q = base / cand
        if q.is_file():
            return _read(q), f"pkg:{cand}"
    return None

def load_template(name_or_path: str) -> tuple[str, str]:
    """
    Resolve in order:
      1) explicit path or ENV dir (PWNKIT_TEMPLATES)
      2) bundled under pwnkit/templates by name
    Else: hard error.
    """
    got = _load_from_fs(name_or_path)
    if got is not None:
        return got
    got = _load_bundled(name_or_path)
    if got is not None:
        return got
    raise FileNotFoundError(f"No template found for: {name_or_path!r}. "
                            f"Checked filesystem (and ${ENV_TPL_DIR}) and bundled templates.")

# - Render with str.format
def _required_fields(tpl: str) -> set[str]:
    fields = set()
    for _, field, _, _ in string.Formatter().parse(tpl):
        if field:
            # strip !r / :... format spec
            core = field.split("!")[0].split(":")[0]
            fields.add(core)
    return fields

def render_format(tpl: str, ctx: dict) -> str:
    missing = _required_fields(tpl) - set(ctx.keys())
    if missing:
        raise ValueError(f"Template requires missing keys: {sorted(missing)}")
    return tpl.format(**ctx)

# - Render with jinja2?
#   Less lightweight...

# Argument Parsing
# ------------------------------------------------------------------------
def init_args() -> Namespace:
    ap = ArgumentParser(
        prog="pwnkit",
        usage="pwnkit [options] <exp.py>",
        description=(
            "Generate a clean exploit scaffold with embedded Context config.\n"
            "Examples:\n"
            "  pwnkit xpl.py    (fill manually)\n"
            "  pwnkit xpl.py --file ./vuln --libc ./libc.so.6\n"
            "  pwnkit xpl.py -f ./vuln -l ./libc.so.6 -t heap\n"
            "  pwnkit xpl.py -a Pwner -b https://pwners.com\n"
            "  pwnkit xpl.py -f ./vuln -A aarch64 -E big\n"
            "  (default context preset: Linux amd64 little debug\n)"
        ),
        epilog=(
            "Author: Axura (@4xura) - https://4xura.com\n"
        ),
        formatter_class=RawTextHelpFormatter,
    )

    ap.add_argument(
        "out",
        metavar="exp.py",
        type=Path,
        nargs="?",
        help="output exploit path (e.g., xpl.py)"
    )

    # - Paths
    paths = ap.add_argument_group("Paths")
    paths.add_argument(
        "-f", "--file", 
        dest="file_path",
        default="",
        metavar="target",
        help="target binary path to pwn (default: ./vuln)"
    )
    paths.add_argument(
        "-l", "--libc", dest="libc_path",
        default="",
        metavar="libc",
        help="optional target libc to preload"
    )

    # - Context
    ctx = ap.add_argument_group("Pwntools context")
    ctx.add_argument(
        "-P", "--preset",
        choices=list(Context.presets()),
        default="linux-amd64-debug",
        help=(
            "context preset; individual flags below override this\n"
            "(default: linux-amd64-debug)"
        ),
    )

    ctx.add_argument(
        "-A", "--arch",
        default=None,
        choices=["amd64", "i386", "arm", "aarch64"],
        help=(
            "target architecture for pwntools context (default: amd64)"
        ),
    )

    ctx.add_argument(
        "-O", "--os",
        dest="os_name",
        metavar="os",
        default=None,
        choices=["linux", "freebsd"],
        help=(
            "target operating system (default: linux)"
        ),
    )

    ctx.add_argument(
        "-E", "--endian",
        metavar="endianness",
        default=None,
        choices=["little", "big"],
        help=(
            "endianness of the target (default: little)"
        ),
    )

    ctx.add_argument(
        "-L", "--log",
        default=None,
        metavar="log_level",
        choices=["debug", "info", "warning", "error"],
        help=(
            "pwntools logging level (default: \"debug\" from preset)"
        ),
    )

    ctx.add_argument(
        "-T", "--term",
        nargs="*",
        default=None,
        metavar="cmd",
        help=(
            "terminal command to use when spawning GDB (default: tmux splitw -h).\n"
        ),
    )

    # - Templates
    tpl = ap.add_argument_group("Template")
    tpl.add_argument(
        "-t", "--template",
        dest="template",
        metavar="name|path",
        default="default", 
        help=(
            "template name (bundled) or file path\n"
            f"if omitted, uses ${ENV_TPL_SEL} (default: 'default')"
        ),
    )
    
    tpl.add_argument(
        "-lt", "--list-templates",
        action="store_true",
        help="list bundled template names and exit"
    )

    # - Personel
    ps = ap.add_argument_group("Personel")
    ps.add_argument(
        "-a", "--author",
        metavar="name",
        dest="author",
        default="Axura (@4xura)",
        help=(
            "author name in exploit template"
        ),
    )

    ps.add_argument(
        "-b", "--blog",
        metavar="link",
        dest="blog",
        default="https://4xura.com",
        help=(
            "blog link in exploit template"
        ),
    )

    return ap.parse_args()

def cli():
    args = init_args()

    # - Args behavior
    if args.list_templates:
        names = _bundled_templates()
        print("[*] Bundled templates:")
        for n in names or ["(none found)"]:
            print("   -", n)
        return

    if args.out is None:
        """Require positional arguments"""
        ap.error("[!] Oops, no output specified. Check: pwnkit -h")

    # - Context selection
    ctx = Context.preset(args.preset)
    if args.arch is not None:      ctx.arch = args.arch
    if args.os_name is not None:   ctx.os = args.os_name
    if args.endian is not None:    ctx.endian = args.endian
    if args.log is not None:       ctx.log_level = args.log
    if args.term is not None:      ctx.terminal = tuple(args.term)

    # - IO wiring
    io = Config(
        file_path=args.file_path or None,
        libc_path=args.libc_path or None,
    )
    io_line = io.as_code()

    # - Template output
    #   default resolution: CLI → ENV → "default"
    if args.list_templates:
        names = _bundled_templates()
        print("[*] Bundled templates:")
        for n in names:
            print("   -", n)
        return

    tpl = args.template or os.environ.get(ENV_TPL_SEL) or "default"
    tpl_text, orig = load_template(tpl)

    render_ctx = dict(
        arch=ctx.arch,
        os=ctx.os,
        endian=ctx.endian,
        log=ctx.log_level,
        term=tuple(ctx.terminal),
        file_path=io.file_path,
        libc_path=io.libc_path,
        ssl=io.ssl,
        io_line=io.as_code(),
        author=args.author,
        blog=args.blog,
    )
    content = render_format(tpl_text, render_ctx)

    out = Path(args.out)
    out.write_text(content, encoding="utf-8")
    out.chmod(0o755)
    print(f"[+] Wrote {out} (template: {orig})")


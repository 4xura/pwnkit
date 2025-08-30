#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
# Title		: Hash PoW brute-force helpers for pwnkit
# Date		: 2025-08-30
# Author	: Axura (@4xura) - https://4xura.com
#
# Description:
# ------------
# Find a short string s so that:
#    hexd = HASH(prefix + s + suffix).hexdigest()
# satisfies a user-supplied predicate, e.g. hexd.startswith("000000")
#
# Public API (kept compatible with previous version):
#    - solve_pow(...)
#    - solve_pow_mt(...)
#
# Notes:
# ------
# - Uses hashlib; supports any algorithm in hashlib.algorithms_available
# - Accepts prefix/suffix as str or bytes
# - Default alphabet: printable.strip()
# - Encoding (when prefix/suffix are str) defaults to latin-1 to match prior behavior
##

from __future__ import annotations
from dataclasses import dataclass
from typing import Callable, Optional, Iterable, Union
from string import printable
from .utils import init_pr, pr_error, pr_exception
import hashlib, itertools, time, threading, concurrent.futures as cf

try:
    # optional: if present, can wire true parallel search later
    from pwnlib.util.iters import bruteforce as _pwnt_bruteforce, mbruteforce as _pwnt_mbruteforce  # type: ignore
    _HAS_PWNT = True
except Exception:
    _HAS_PWNT = False

__all__ = [
    "BruteForcer",
    "solve_pow",
    "solve_pow_mt",
]

init_pr("debug", "%(asctime)s - %(levelname)s - %(message)s", "%H:%M:%S")

Predicate = Callable[[str], bool]
Chars = Union[bytes, str]

# CONFIG
# ------------------------------------------------------------------------
@dataclass
class BruteForcer:
    alphabet	: str = printable.strip()
    start_length: int = 4
    max_length	: int = 6
    encoding	: str = "latin-1"			# used if prefix/suffix are str
    timeout_sec	: Optional[float] = None 	# None = no timeout

# INTERNALS
# ------------------------------------------------------------------------
def _to_bytes(x: Chars, enc: str) -> bytes:
    if isinstance(x, bytes):
        return x
    return x.encode(enc, errors="strict")

def _fail(msg: str) -> None:
    pr_exception(msg)
    raise ValueError(msg)

def _validate(hash_algo: str, cfg: BruteForcer) -> None:
    if cfg.max_length < cfg.start_length:
        _fail("max_length must be >= start_length")
    if not isinstance(cfg.alphabet, str) or not cfg.alphabet:
        _fail("alphabet must be a non-empty str")
    algo = hash_algo.lower()
    if algo not in hashlib.algorithms_available:
        _fail(f"Unknown hash algo: {hash_algo!r}. "
              f"Available core: {sorted(hashlib.algorithms_guaranteed)}")

def _search_iter(alphabet: str, length: int) -> Iterable[str]:
    # deterministic cartesian product (lexicographic)
    yield from (''.join(t) for t in itertools.product(alphabet, repeat=length))

# - Core single-thread runner
def _run(prefix: Chars,
         suffix: Chars,
         hash_algo: str,
         check: Predicate,
         cfg: BruteForcer) -> Optional[str]:
    _validate(hash_algo, cfg)
    algo = hash_algo.lower()
    pfx, sfx = _to_bytes(prefix, cfg.encoding), _to_bytes(suffix, cfg.encoding)
    t0 = time.time()

    for L in range(cfg.start_length, cfg.max_length + 1):
        for s in _search_iter(cfg.alphabet, L):
            if cfg.timeout_sec and (time.time() - t0) > cfg.timeout_sec:
                return None
            h = hashlib.new(algo)
            h.update(pfx); h.update(s.encode(cfg.encoding)); h.update(sfx)
            if check(h.hexdigest()):
                return s
    return None

# - Shard worker for MT
def _worker_shard(first_chars: str, rest_len: int, cfg: BruteForcer,
                  algo: str, pfx: bytes, sfx: bytes,
                  check: Predicate, stop: threading.Event,
                  deadline: Optional[float]) -> Optional[str]:
    enc = cfg.encoding
    if rest_len == 0:
        for ch in first_chars:
            if stop.is_set() or (deadline and time.time() > deadline): return None
            s = ch
            h = hashlib.new(algo); h.update(pfx); h.update(s.encode(enc)); h.update(sfx)
            if check(h.hexdigest()):
                stop.set(); return s
        return None

    for ch in first_chars:
        if stop.is_set() or (deadline and time.time() > deadline): return None
        for tail in itertools.product(cfg.alphabet, repeat=rest_len):
            if stop.is_set() or (deadline and time.time() > deadline): return None
            s = ch + ''.join(tail)
            h = hashlib.new(algo); h.update(pfx); h.update(s.encode(enc)); h.update(sfx)
            if check(h.hexdigest()):
                stop.set(); return s
    return None

def _split_chunks(s: str, n: int) -> List[str]:
    if n <= 1 or len(s) <= 1:
        return [s]
    k = max(1, len(s) // n)
    return [s[i:i+k] for i in range(0, len(s), k)]

# Public APIs
# ---------------------------------------------------------------------------
def solve_pow(hash_algo: str,
              prefix_str: Chars,
              suffix_str: Chars,
              check_res_func: Predicate,
              alphabet: str = printable.strip(),
              start_length: int = 4,
              max_length: int = 6,
              timeout_sec: Optional[float] = None) -> Optional[str]:
    """
	Single-threaded: find s such that HASH(prefix + s + suffix).hexdigest() 
	satisfies predicate.

        @hash_algo: hashlib algorithm name (e.g., 'sha256', 'md5', ...)
        @prefix_str: prefix, str or bytes
        @suffix_str: suffix, str or bytes
        @check_res_func: predicate on hex digest, e.g. lambda h: h.startswith('000000')
        @alphabet: candidate characters
        @start_length: minimum length of s
        @max_length: maximum length of s

    Returns:
        str or None
    """
    cfg = BruteForcer(alphabet=alphabet, start_length=start_length, max_length=max_length, timeout_sec=timeout_sec)
    return _run(prefix_str, suffix_str, hash_algo, check_res_func, cfg)

def solve_pow_mt(hash_algo: str,
                 prefix_str: Chars,
                 suffix_str: Chars,
                 check_res_func: Predicate,
                 alphabet: str = printable.strip(),
                 start_length: int = 4,
                 max_length: int = 6,
                 timeout_sec: Optional[float] = None,
                 max_workers: Optional[int] = None) -> Optional[str]:
    """
    Multi-threaded: shards by first character; cancels others on first hit.
    Result equals solve_pow; order is non-deterministic, typically faster.
    """
    cfg = BruteForcer(alphabet=alphabet, start_length=start_length, max_length=max_length, timeout_sec=timeout_sec)
    _validate(hash_algo, cfg)
    algo = hash_algo.lower()
    pfx, sfx = _to_bytes(prefix_str, cfg.encoding), _to_bytes(suffix_str, cfg.encoding)
    stop = threading.Event()
    deadline = (time.time() + timeout_sec) if timeout_sec else None

    if max_workers is None or max_workers < 1:
        # cap to alphabet size and a reasonable upper bound
        max_workers = min(32, max(1, len(cfg.alphabet)))

    for L in range(cfg.start_length, cfg.max_length + 1):
        if deadline and time.time() > deadline:
            return None
        shards = _split_chunks(cfg.alphabet, max_workers)
        with cf.ThreadPoolExecutor(max_workers=len(shards)) as ex:
            futs = [
                ex.submit(_worker_shard, shard, L - 1, cfg, algo, pfx, sfx, check_res_func, stop, deadline)
                for shard in shards if shard
            ]
            for f in cf.as_completed(futs):
                res = f.result()
                if res is not None:
                    stop.set()
                    # best-effort cancellation
                    for other in futs:
                        if other is not f:
                            other.cancel()
                    return res
    return None

# Self-test 
# ---------------------------------------------------------------------------
if __name__ == "__main__":
    # quick smoke tests
    s1 = solve_pow("sha256", "eRt<", "", lambda h: h.startswith("0000"), max_length=4, timeout_sec=5)
    print("sha256 pow (ST):", s1)
    s2 = solve_pow_mt("sha256", "eRt<", "", lambda h: h.startswith("0000"), max_length=4, timeout_sec=5)
    print("sha256 pow (MT):", s2)

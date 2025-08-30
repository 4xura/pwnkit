#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
count_heap.py.py
Parse GDB heap trace logs (malloc/calloc/realloc/free) and summarize sizes.
Target output from `heap_trace.gdb`

- Works with lines like:
    >>> malloc(0x591)
    >>> calloc(1169, 0x1)
    >>> realloc(0xdeadbeef, 0x140)
  and also without the leading ">>> ".

- Reports:
  * Total call counts per API
  * Distribution of requested sizes
  * Distribution of glibc 64-bit chunk sizes (request + 0x10 header, 0x10 aligned, min 0x20)
  * Per-API distributions (malloc/calloc/realloc)
  * Optional CSV dump

Usage:
  python3 count_heap.py.py heap.log
  python3 count_heap.py.py heap.log --top 30
  python3 count_heap.py.py heap.log --csv out.csv
"""

import re
import sys
import argparse
from collections import Counter, defaultdict

# --- Regexes that tolerate ">>> " prefix and hex/dec arguments
RE_MALLOC  = re.compile(r'(?:>>> \s*)?malloc\(\s*(0x[0-9a-fA-F]+|\d+)\s*\)')
RE_CALLOC  = re.compile(r'(?:>>> \s*)?calloc\(\s*(0x[0-9a-fA-F]+|\d+)\s*,\s*(0x[0-9a-fA-F]+|\d+)\s*\)')
RE_REALLOC = re.compile(r'(?:>>> \s*)?realloc\(\s*[^,]+,\s*(0x[0-9a-fA-F]+|\d+)\s*\)')
RE_FREE    = re.compile(r'(?:>>> \s*)?free\(')
# Fallback for logs that print "Request size     : 1425"
RE_REQLINE = re.compile(r'Request size\s*:\s*(0x[0-9a-fA-F]+|\d+)')


def parse_num(s: str) -> int:
    """Parse hex (0x...) or decimal string to int."""
    s = s.strip()
    return int(s, 16) if s.lower().startswith('0x') else int(s)


def align_up(x: int, a: int) -> int:
    """Round x up to multiple of a (a power-of-two expected)."""
    return (x + (a - 1)) & ~(a - 1)


def chunk_size_glibc64(req: int) -> int:
    """
    Compute the malloc chunk 'size field' (header) for glibc on x86-64:
      - add 0x10 user/header gap
      - align to 0x10
      - enforce minimum chunk size 0x20
    """
    if req < 0:
        return 0
    total = req + 0x10
    total = align_up(total, 0x10)
    if total < 0x20:
        total = 0x20
    return total


def fmt_size(n: int) -> str:
    return f"{n} (0x{n:x})"


def main():
    ap = argparse.ArgumentParser(description="Summarize heap sizes from GDB trace logs.")
    ap.add_argument("logfile", help="Path to heap trace log")
    ap.add_argument("--top", type=int, default=20, help="Show top-N sizes (default: 20)")
    ap.add_argument("--csv", help="Optional CSV output of <api,request,chunk,count>")
    args = ap.parse_args()

    # Counters
    totals = Counter()  # per API counts
    req_all = Counter()  # all requests (bytes), any API
    chunk_all = Counter()  # all rounded chunk sizes

    # Per-API distributions
    req_by_api = defaultdict(Counter)
    chunk_by_api = defaultdict(Counter)

    # Some logs only have "Request size : N" lines following the call.
    # We keep a tiny state to attribute such a line if needed.
    pending_api = None

    with open(args.logfile, "r", errors="ignore") as f:
        for line in f:
            s = line.strip()

            # malloc
            m = RE_MALLOC.search(s)
            if m:
                size = parse_num(m.group(1))
                totals["malloc"] += 1
                req_all[size] += 1
                req_by_api["malloc"][size] += 1

                cs = chunk_size_glibc64(size)
                chunk_all[cs] += 1
                chunk_by_api["malloc"][cs] += 1

                pending_api = None
                continue

            # calloc
            m = RE_CALLOC.search(s)
            if m:
                nmemb = parse_num(m.group(1))
                esize = parse_num(m.group(2))
                size = nmemb * esize
                totals["calloc"] += 1
                req_all[size] += 1
                req_by_api["calloc"][size] += 1

                cs = chunk_size_glibc64(size)
                chunk_all[cs] += 1
                chunk_by_api["calloc"][cs] += 1

                pending_api = None
                continue

            # realloc
            m = RE_REALLOC.search(s)
            if m:
                size = parse_num(m.group(1))
                totals["realloc"] += 1
                req_all[size] += 1
                req_by_api["realloc"][size] += 1

                cs = chunk_size_glibc64(size)
                chunk_all[cs] += 1
                chunk_by_api["realloc"][cs] += 1

                pending_api = None
                continue

            # free
            if RE_FREE.search(s):
                totals["free"] += 1
                pending_api = None
                continue

            # Fallback: "Request size : N" (rarely needed if we already parsed args)
            m = RE_REQLINE.search(s)
            if m and pending_api:
                size = parse_num(m.group(1))
                totals[pending_api] += 1
                req_all[size] += 1
                req_by_api[pending_api][size] += 1
                cs = chunk_size_glibc64(size)
                chunk_all[cs] += 1
                chunk_by_api[pending_api][cs] += 1
                pending_api = None

    # --- Print summary ---
    print("== Totals ==")
    for k in ("malloc", "calloc", "realloc", "free"):
        if totals[k]:
            print(f"{k:7s}: {totals[k]}")

    def print_counter(title: str, ctr: Counter, topn: int, label="bytes"):
        if not ctr:
            return
        print(f"\n== {title} (top {topn}) ==")
        for val, cnt in ctr.most_common(topn):
            print(f"{fmt_size(val):>14s}  ->  {cnt}")

    # Combined views
    print_counter("Requested sizes (all APIs)", req_all, args.top)
    print_counter("Chunk-size headers (all APIs)", chunk_all, args.top, label="chunk")

    # Per-API views
    for api in ("malloc", "calloc", "realloc"):
        if req_by_api[api]:
            print_counter(f"Requested sizes [{api}]", req_by_api[api], args.top)
        if chunk_by_api[api]:
            print_counter(f"Chunk-size headers [{api}]", chunk_by_api[api], args.top)

    # Optional CSV
    if args.csv:
        import csv
        rows = []
        for api, ctr in req_by_api.items():
            for req_sz, count in ctr.items():
                rows.append((api, req_sz, chunk_size_glibc64(req_sz), count))
        rows.sort(key=lambda r: (-r[3], r[0], r[1]))
        with open(args.csv, "w", newline="") as fp:
            w = csv.writer(fp)
            w.writerow(["api", "request_bytes", "chunk_header_size", "count"])
            w.writerows(rows)
        print(f"\n[+] CSV written to {args.csv}")

if __name__ == "__main__":
    main()


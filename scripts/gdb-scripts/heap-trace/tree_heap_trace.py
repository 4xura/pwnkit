#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
# Title     : Build a call-tree from a GDB heap-trace log
# Date      : 2025-08-08
# Author    : Axura (@4xura) - https://4xura.com
# Version   : Python 3.5+
#
# Description:
# ------------
# Build a per-operation call tree from a GDB heap_trace.log produced by
#  • heap_trace.gdb    
#    https://github.com/4xura/pwnhub/blob/main/gdb-scripts/heap_trace.gdb
# 
#  • Groups by allocator op  (MALLOC / CALLOC / REALLOC / FREE)
#  • Drops everything above main()   (_start, __libc_start_main …)
#  • Collapses identical call-paths and shows hit-counts
#
# TODO:
# -----
# - Improve regex
#
# Usage:
# ------
# python3 tree_heap_trace.py heap_trace.log  > calltree.txt
#

from __future__ import print_function
import re, sys, collections, pathlib                 

# 1. Check input
# ──────────────────────────────────────────────────────────────────────
if len(sys.argv) != 2 or not pathlib.Path(sys.argv[1]).is_file():
    sys.exit("usage: tree_heap_trace.py <heap_trace.log>")
LOG = sys.argv[1]

# 2. Regex helpers
# ──────────────────────────────────────────────────────────────────────
OP_HDR = re.compile(r'^========= \[([A-Z]+)\]')          # allocator banner
"""
one line of a back-trace:
    #0  0x1234abcd in foo () at …      ← has “in”
    #2  bar (arg=42) at …              ← no  “in”
"""
FRAME  = re.compile(
    r'^#\d+\s+(?:\S+\s+in\s+)?'        # optional “addr  in ”
    r'([^( \t]+)'                      # function name   (capture-group 1)
)

# 3. Generator      heap-ops  →  [frames …]
# ──────────────────────────────────────────────────────────────────────
# heap-ops  →  [frames …]
def events(lines):
    op, frames = None, []
    for ln in lines:
        m = OP_HDR.match(ln)
        if m:                                       # new allocator section
            if op is not None:
                yield op, frames
            op, frames = m.group(1), []
            continue

        m = FRAME.match(ln)
        if m:
            frames.append(m.group(1))
    if op is not None:
        yield op, frames

# 4. Tree model
# ──────────────────────────────────────────────────────────────────────
class Node(object):
    __slots__ = ('name', 'count', 'kids')
    def __init__(self, name):
        self.name  = name
        self.count = 0
        self.kids  = collections.OrderedDict()      # preserve first-seen order

def add_stack(root, stack):
    """insert one call-path (root→leaf) and bump counters"""
    node = root
    node.count += 1
    for frame in stack:
        node = node.kids.setdefault(frame, Node(frame))
        node.count += 1

def print_tree(node, indent=''):
    """depth-first pretty-printer (skips the artificial ROOT)"""
    last = len(node.kids) - 1
    for i, (name, kid) in enumerate(node.kids.items()):
        branch = '└─ ' if i == last else '├─ '
        print(indent + branch + '{} [{}]'.format(name, kid.count))
        print_tree(kid, indent + ('   ' if i == last else '│  '))

# 5. Build tree
# ──────────────────────────────────────────────────────────────────────
# one tree per allocator op
roots = collections.defaultdict(lambda: Node('ROOT'))

with open(LOG, encoding='utf-8', errors='replace') as fp:
    for op, frames in events(fp):

        if 'main' not in frames:        # ignore pre-main loader noise
            continue

        # - keep   #0 … main   (drop __libc_start_main / _start / etc.)
        keep = frames[: frames.index('main') + 1]

        # - store as  main → … → leaf
        add_stack(roots[op], reversed(keep))

# 6. Output
# ──────────────────────────────────────────────────────────────────────
for op in sorted(roots):
    root = roots[op]
    print('\n{}   ({} calls)'.format(op, root.count))
    print_tree(root)


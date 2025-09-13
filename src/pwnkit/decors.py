#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from __future__ import annotations
from dataclasses import dataclass, field
from functools import wraps
from typing import Callable, Iterable, List, Optional, Tuple, Dict, Type
from inspect import signature, Parameter, iscoroutinefunction
from pwn import logging
import time, os, asyncio

__all__ = [
        "argx",
        "pr_call", "timer",
        "sleepx",
        ]

# Function Arguments 
# ------------------------------------------------------------------------
def argx(
    *,
    by_name: Optional[Dict[str, Callable]] = None,
    by_type: Optional[Dict[Type, Callable]] = None,
):
    """
    Coerce call-time arguments before the function executes.
        @by_name:  {"param_name": transformer}
        @by_type:  {Type: transformer}
    Priority: by_name overrides by_type for the same parameter.

    Examples:
        @argx(by_name={"idx": itoa})
        @argx(by_type={int: itoa})
    """
    by_name = by_name or {}
    by_type = by_type or {}

    def decor(func):
        sig = signature(func)

        @wraps(func)
        def wrapper(*args, **kwargs):
            # Use bind() for stricter arity checks; bind_partial() for leniency
            bound = sig.bind_partial(*args, **kwargs)
            bound.apply_defaults()

            for nm, val in list(bound.arguments.items()):
                param = sig.parameters[nm]
                if param.kind in (Parameter.VAR_POSITIONAL, Parameter.VAR_KEYWORD):
                    continue

                # 1) by_name takes precedence
                if nm in by_name:
                    bound.arguments[nm] = by_name[nm](val)
                    continue

                #2) by_type fallback (first match wins)
                for t, xf in by_type.items():
                    if isinstance(val, t):
                        bound.arguments[nm] = xf(val)
                        break

            return func(*bound.args, **bound.kwargs)
        return wrapper
    return decor

# Function Helpers
# ------------------------------------------------------------------------
def pr_call(func):
    """
    Print the fully-qualified function name and raw args/kwargs.

    e.g., 
        @pr_call
        def crunch(x, y=2):
            return x ** y
        crunch(7, y=5)

    # call __main__.crunch args=(7,) kwargs={'y': 5}
    """
    @wraps(func)
    def wrapper(*args, **kwargs):
        info(f"call {func.__module__}.{func.__qualname__} args={args} kwargs={kwargs}")
        return func(*args, **kwargs)
    return wrapper

def counter(show: bool = True):
    """
    Count how many times a function is called. Exposes .calls and .reset().

    e.g.,
        @counter()
        def f(x): return x*x

        f(2); f(3)
        print(f.calls)  # 2
        f.reset()
        print(f.calls)  # 0
    """
    def deco(func):
        if inspect.iscoroutinefunction(func):
            @wraps(func)
            async def aw(*args, **kwargs):
                aw.calls += 1
                if show:
                    info(f"Call {aw.calls} of {func.__name__}")
                return await func(*args, **kwargs)
            aw.calls = 0
            aw.reset = lambda: setattr(aw, "calls", 0)
            return aw

        @wraps(func)
        def w(*args, **kwargs):
            w.calls += 1
            if show:
                info(f"Call {w.calls} of {func.__name__}")
            return func(*args, **kwargs)
        w.calls = 0
        w.reset = lambda: setattr(w, "calls", 0)
        return w
    return deco

def timer(func):
    """
    Print how long the call took (ms).
    
    e.g.,
        @timer
        def crunch(x, y=2):
            return x ** y
        crunch(7, y=5)

    # __main__.crunch took 0.001 ms
    """
    @wraps(func)
    def wrapper(*args, **kwargs):
        t0 = time.perf_counter()
        try:
            return func(*args, **kwargs)
        finally:
            dt_ms = (time.perf_counter() - t0) * 1e3
            info(f"{func.__module__}.{func.__qualname__} took {dt_ms:.3f} ms")
    return wrapper

def sleepx(*, before: float = 0.0, after: float = 0.0):
    """
    Sleep before and after the call (seconds).

    e.g.,
        @sleepx(before=0.10, after=0.10)
        def poke():
            ...

        @sleepx(before=0.2)
        async def task():
            ...
    """
    def deco(func):
        if inspect.iscoroutinefunction(func):
            @wraps(func)
            async def aw(*a, **k):
                if before:  await asyncio.sleep(before)
                try:
                    return await func(*a, **k)
                finally:
                    if after: await asyncio.sleep(after)
            return aw
        @wraps(func)
        def w(*a, **k):
            if before:  time.sleep(before)
            try:
                return func(*a, **k)
            finally:
                if after: time.sleep(after)
        return w
    return deco

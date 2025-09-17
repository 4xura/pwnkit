#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from __future__ import annotations
from dataclasses import dataclass, field
from functools import wraps
from typing import Callable, Iterable, List, Optional, Tuple, Dict, Type, Any
from inspect import signature, Parameter, iscoroutinefunction
from concurrent.futures import ThreadPoolExecutor, as_completed
from pwn import logging
import time, os, asyncio

__all__ = [
        "argx",
        "pr_call", "timer",
        "sleepx",
        "bruteforcer",
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

def counter(func):
    """
    Count how many times a function is called. Exposes .calls and .reset().

    e.g.,
        @counter
        def f(a, b): 
            print(f"{a}+{b}={a+b}")

        f(1,2)          # Call 1 of f ... 1+2=3
        f(5,5)          # Call 2 of f ... 5+5=10
        print(f.calls)  # 2
        f.reset()
        print(f.calls)  # 0
    """
    if inspect.iscoroutinefunction(func):
        @wraps(func)
        async def aw(*args, **kwargs):
            aw.calls += 1
            print(f"Call {aw.calls} of {func.__name__}")
            return await func(*args, **kwargs)
        aw.calls = 0
        aw.reset = lambda: setattr(aw, "calls", 0)
        return aw

    @wraps(func)
    def w(*args, **kwargs):
        w.calls += 1
        print(f"Call {w.calls} of {func.__name__}")
        return func(*args, **kwargs)
    w.calls = 0
    w.reset = lambda: setattr(w, "calls", 0)
    return w

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

# Brute Force
# ------------------------------------------------------------------------
def bruteforcer(
    *,
    times: Optional[int] = None,
    inputs: Optional[Iterable[Tuple[tuple, dict]]] = None,
    pass_index: bool = False,
    until: Optional[Callable[[Any], bool]] = None,
    threads: int = 1,
    delay: float = 0.0,
):
    """
    Run the decorated function multiple times in a bruteforce style.

    @times:
        If `inputs` is None, run the function `times` times.
        If both are None, raises ValueError.
    @inputs:
        Iterable of (args_tuple, kwargs_dict). If supplied, `times` is ignored.
        For convenience we can also pass an iterable of single values; it'll be normalised.
    @pass_index:
        If True, the wrapper will inject an extra positional argument as the attempt index
        (0-based) before the supplied args.
    @until:
        Callable(result) -> bool. If provided, stop early and return the first result
        for which until(result) is truthy.
    @threads:
        Number of worker threads. 1 = run sequentially. >1 enables concurrency.
    @delay:
        Seconds to sleep between sequential attempts (ignored for threads>1).

    If `until` is provided: the first result for which `until(result)` is True, or None.
    Otherwise: list of results from all attempts (in order if sequential; unspecified order if threads).

    Usage examples:
    ---------------
    1) Simple repeat n times (sequential)
        @bruteforcer(times=5)
        def probe():
            print("probing")
            return False

        # returns [False, False, False, False, False]
        res = probe()

    2) Pass attempt index to function (useful for permutations)
        @bruteforcer(times=3, pass_index=True)
        def try_pin(i):
            print("attempt", i)

        try_pin()
        # prints:
        # attempt 0
        # attempt 1
        # attempt 2

    3) Use a list of candidate inputs (typical bruteforce passwords)
        candidates = ["admin", "1234", "password", "letmein"]

        # build inputs as iterable of (args, kwargs) pairs
        inputs = (( (pw,), {} ) for pw in candidates)

        @bruteforcer(inputs=inputs, until=lambda r: r is True)
        def attempt_login(password):
            # attempt_login returns True on success, False/None on failure
            return fake_try_login(password)

        result = attempt_login()
        # result will be True (stops early) or None if no candidate worked

    4) Parallel bruteforce (threads)
        @bruteforcer(inputs=((pw,) for pw in candidates), until=lambda r: r is True, parallel=8)
        def attempt_login(password):
            return fake_try_login(password)
    """

    if inputs is None and times is None:
        raise ValueError("Either 'times' or 'inputs' must be provided")

    def _normalise_inputs():
        # Yield normalized (args, kwargs) pairs.
        if inputs is not None:
            for item in inputs:
                if isinstance(item, tuple) and len(item) == 2 and isinstance(item[1], dict):
                    yield item
                else:
                    # treat single value as single positional arg
                    yield ( (item,), {} )
        else:
            for i in range(times):
                yield ( (), {} )

    def deco(func):
        @wraps(func)
        def wrapper(*call_args, **call_kwargs):
            # Two modes:
            # - if inputs provided: ignore call_args/call_kwargs and use inputs.
            # - otherwise, if times provided: call func(*call_args, **call_kwargs) repeatedly.
            iterator = _normalise_inputs()

            # Sequential execution
            if threads <= 1:
                results = []
                for idx, (base_args, base_kwargs) in enumerate(iterator):
                    # Compose args
                    args = ()
                    if pass_index:
                        args = (idx,) + tuple(base_args)
                    else:
                        args = tuple(base_args)

                    # If caller supplied args/kwargs to wrapper, merge them (useful for partial context)
                    final_args = call_args + args
                    final_kwargs = {**base_kwargs, **call_kwargs}

                    res = func(*final_args, **final_kwargs)
                    results.append(res)

                    if until is not None and until(res):
                        return res
                    if delay:
                        time.sleep(delay)

                return results

            # Parallel execution
            else:
                results = []
                with ThreadPoolExecutor(max_workers=threads) as ex:
                    futures = {}
                    for idx, (base_args, base_kwargs) in enumerate(iterator):
                        if pass_index:
                            args = (idx,) + tuple(base_args)
                        else:
                            args = tuple(base_args)

                        final_args = call_args + args
                        final_kwargs = {**base_kwargs, **call_kwargs}
                        fut = ex.submit(func, *final_args, **final_kwargs)
                        futures[fut] = idx

                    # If we have `until`, we want to stop as soon as one future matches.
                    if until is not None:
                        for fut in as_completed(futures):
                            try:
                                res = fut.result()
                            except Exception as e:
                                results.append(e)
                                continue

                            results.append(res)
                            if until(res):
                                for pending in futures:
                                    if not pending.done():
                                        pending.cancel()
                                return res
                        return None
                    else:
                        for fut in as_completed(futures):
                            try:
                                results.append(fut.result())
                            except Exception as e:
                                results.append(e)
                        return results

        return wrapper
    return deco

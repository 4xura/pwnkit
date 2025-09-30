# tests/conftest.py
from __future__ import annotations
import logging
import os
import pytest
import sys

@pytest.fixture(autouse=True, scope="session")
def silence_pwnlib_logging():
    """
    Pwntools emits INFO logs (e.g., 'Stopped process ...') in atexit handlers.
    When pytest closes its capture stream first, those writes crash.
    We nuke pwnlib log output for the whole session.
    """
    # Raise level & disable propagation for all pwnlib loggers (incl. children)
    for name, logger in logging.root.manager.loggerDict.items():
        if isinstance(logger, logging.Logger) and (name == "pwnlib" or name.startswith("pwnlib.")):
            logger.setLevel(logging.CRITICAL)
            logger.propagate = False
            # harden existing handlers
            for h in list(logger.handlers):
                try:
                    h.setLevel(logging.CRITICAL)
                except Exception:
                    pass
                # decouple from pytest's closed stderr by redirecting to /dev/null
                if hasattr(h, "stream"):
                    try:
                        h.stream = open(os.devnull, "w")
                    except Exception:
                        pass
    yield
    # optional: we could close any /dev/null streams we opened,
    # but it's safe to let the OS reclaim at process exit.


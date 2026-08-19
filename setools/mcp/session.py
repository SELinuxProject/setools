# SPDX-License-Identifier: LGPL-2.1-only

from dataclasses import dataclass, field
from functools import lru_cache
import threading
from typing import Callable

from setools import FileContexts, SELinuxPolicy


class PolicyCache(dict):
    """Simple cache for loaded policies"""
    def __missing__(self, key: str | None) -> SELinuxPolicy:
        self[key] = SELinuxPolicy(key)
        return self[key]


class FileContextsCache(dict):
    """Simple cache for loaded file_contexts"""
    def __missing__(self, key: str | None) -> FileContexts:
        self[key] = FileContexts(None, key)
        return self[key]


@dataclass
class SessionData:

    """Policy data owned by one MCP session."""

    policies: PolicyCache = field(default_factory=PolicyCache)
    file_contexts: FileContextsCache = field(default_factory=FileContextsCache)
    lock: threading.RLock = field(default_factory=threading.RLock)


class SessionCache:

    """Bounded least-recently-used cache of session data."""

    def __init__(self, max_sessions: int) -> None:
        if max_sessions < 1:
            raise ValueError("max_sessions must be at least 1")

        self.max_sessions: int = max_sessions
        self._get: Callable[[str], SessionData] = \
            lru_cache(maxsize=max_sessions)(lambda _session_id: SessionData())
        self._lock: threading.RLock = threading.RLock()

    def get(self, session_id: str) -> SessionData:
        """Return the data for a session and mark it recently used."""
        with self._lock:
            return self._get(session_id)

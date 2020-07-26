# -*- coding: utf-8 -*-
"""
ldap0.lock -- specific lock class with logging
"""

import logging
import threading


class LDAPLock:
    """
    Mainly a wrapper class to log all locking events.
    Note that this cumbersome approach with _lock attribute was taken
    since threading.Lock is not suitable for sub-classing.
    """
    __slots__ = (
        '_desc',
        '_lock',
        '_trace_level',
    )
    _min_trace_level: int = 3

    def __init__(self, desc: str, trace_level: int = 0):
        """
        desc
            Description shown in debug log messages
        """
        self._desc = desc
        self._lock = threading.Lock()
        self._trace_level = trace_level

    def __repr__(self) -> str:
        return '%s(%r, %r)' % (self.__class__.__name__, self._desc, self._trace_level)

    def __enter__(self):
        return self._lock.__enter__()

    def __exit__(self, *args):
        return self._lock.__exit__(*args)

    def acquire(self):
        """
        acquire lock and log
        """
        if __debug__:
            if self._trace_level >= self._min_trace_level:
                logging.debug(
                    '%s[%x] acquire %s',
                    self.__class__.__name__,
                    id(self),
                    self._desc,
                )
        return self._lock.acquire()

    def release(self):
        """
        release lock and log
        """
        if __debug__:
            if self._trace_level >= self._min_trace_level:
                logging.debug(
                    '%s[%x] release %s',
                    self.__class__.__name__,
                    id(self),
                    self._desc,
                )
        return self._lock.release()

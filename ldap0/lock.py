# -*- coding: utf-8 -*-
"""
ldap0.lock -- specific lock class with logging
"""

import logging
import threading

import ldap0
from .__about__ import __version__, __author__, __license__


class LDAPLock:
    """
    Mainly a wrapper class to log all locking events.
    Note that this cumbersome approach with _lock attribute was taken
    since threading.Lock is not suitable for sub-classing.
    """
    _min_trace_level = 3

    def __init__(self, desc, trace_level=0):
        """
        desc
            Description shown in debug log messages
        """
        self._desc = desc
        self._lock = threading.Lock()
        self._trace_level = trace_level

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

# -*- coding: utf-8 -*-
"""
ldap0.lock -- specific lock class with logging
"""

from __future__ import absolute_import

import threading

import ldap0
from .__about__ import __version__, __author__, __license__


class LDAPLock(object):
    """
    Mainly a wrapper class to log all locking events.
    Note that this cumbersome approach with _lock attribute was taken
    since threading.Lock is not suitable for sub-classing.
    """
    _min_trace_level = 3

    def __init__(
            self,
            lock_class=None,
            desc='',
            trace_level=0,
            trace_file=None,
        ):
        """
        lock_class
            Class compatible to threading.Lock
        desc
            Description shown in debug log messages
        """
        self._desc = desc
        self._lock = (lock_class or threading.Lock)()
        self._trace_level = trace_level
        self._trace_file = trace_file or ldap0._trace_file

    def acquire(self):
        """
        acquire lock and log
        """
        if __debug__:
            if self._trace_level >= self._min_trace_level:
                self._trace_file.write('***%s.acquire() %r %s\n' % (
                    self.__class__.__name__, self, self._desc
                ))
        return self._lock.acquire()

    def release(self):
        """
        release lock and log
        """
        if __debug__:
            if self._trace_level >= self._min_trace_level:
                self._trace_file.write('***%s.release() %r %s\n' % (
                    self.__class__.__name__, self, self._desc
                ))
        return self._lock.release()

# -*- coding: utf-8 -*-
"""
ldap0 - base module
"""

from __future__ import absolute_import

import sys

from ldap0.pkginfo import __version__, __author__, __license__

if __debug__:
    # Tracing is only supported in debugging mode
    import traceback
    _trace_level = 0
    _trace_file = sys.stderr
    _trace_stack_limit = None

import _libldap0
from _libldap0 import *
assert _libldap0.__version__ == __version__, ImportError(
    'ldap %s and _libldap0 %s version mismatch!' % (__version__, _libldap0.__version__)
)

from functions import get_option, set_option
from functions import escape_str, strf_secs, strp_secs
from ldapobject.simple import SimpleLDAPObject
from ldapobject.reconnect import ReconnectLDAPObject
from ldapobject import NO_UNIQUE_ENTRY
from ldap0.dn import explode_dn, explode_rdn

# call into libldap to initialize it right now
LIBLDAP_API_INFO = _libldap0.get_option(_libldap0.OPT_API_INFO)

OPT_NAMES_DICT = {}
for key, val in vars(_libldap0).items():
    if key.startswith('OPT_'):
        OPT_NAMES_DICT[val] = key


class DummyLock:
    """
    Define dummy class with methods compatible to threading.Lock
    """

    def __init__(self):
        pass

    def acquire(self):
        """
        dummy
        """
        pass

    def release(self):
        """
        dummy
        """
        pass


try:
    # Check if Python installation was build with thread support
    import thread
except ImportError:
    LDAPLockBaseClass = DummyLock
else:
    import threading
    LDAPLockBaseClass = threading.Lock


class LDAPLock(object):
    """
    Mainly a wrapper class to log all locking events.
    Note that this cumbersome approach with _lock attribute was taken
    since threading.Lock is not suitable for sub-classing.
    """
    _min_trace_level = 3

    def __init__(self, lock_class=None, desc='', trace_level=None):
        """
        lock_class
            Class compatible to threading.Lock
        desc
            Description shown in debug log messages
        """
        self._desc = desc
        self._lock = (lock_class or LDAPLockBaseClass)()
        if trace_level is not None:
            self._min_trace_level = trace_level

    def acquire(self):
        """
        acquire lock and log
        """
        if __debug__:
            global _trace_level
            if _trace_level >= self._min_trace_level:
                _trace_file.write('***%s.acquire() %r %s\n' % (
                    self.__class__.__name__, self, self._desc
                ))
        return self._lock.acquire()

    def release(self):
        """
        release lock and log
        """
        if __debug__:
            global _trace_level
            if _trace_level >= self._min_trace_level:
                _trace_file.write('***%s.release() %r %s\n' % (
                    self.__class__.__name__, self, self._desc
                ))
        return self._lock.release()


# Create module-wide lock for serializing all calls into underlying LDAP lib
_ldap_module_lock = LDAPLock(desc='Module wide')

# More constants

# For compability of 2.3 and 2.4 OpenLDAP API
OPT_DIAGNOSTIC_MESSAGE = _libldap0.OPT_ERROR_STRING

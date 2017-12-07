# -*- coding: utf-8 -*-
"""
ldap0 - base module
"""

from __future__ import absolute_import

import sys
import threading

import _libldap0
from _libldap0 import *

from .pkginfo import __version__, __author__, __license__
from .functions import get_option, set_option
from .functions import escape_str, strf_secs, strp_secs
from .ldapobject import LDAPObject, ReconnectLDAPObject, NO_UNIQUE_ENTRY
from .dn import explode_dn, explode_rdn

assert _libldap0.__version__ == __version__, ImportError(
    'ldap %s and _libldap0 %s version mismatch!' % (__version__, _libldap0.__version__)
)

if __debug__:
    # Tracing is only supported in debugging mode
    _trace_level = 0
    _trace_file = sys.stderr
    _trace_stack_limit = None

# call into libldap to initialize it right now
LIBLDAP_API_INFO = _libldap0.get_option(_libldap0.OPT_API_INFO)
# set reasonable global defaults for various options
_libldap0.set_option(_libldap0.OPT_PROTOCOL_VERSION, _libldap0.VERSION3)
_libldap0.set_option(_libldap0.OPT_RESTART, _libldap0.OPT_OFF)
_libldap0.set_option(_libldap0.OPT_DEREF, _libldap0.OPT_OFF)
_libldap0.set_option(_libldap0.OPT_REFERRALS, _libldap0.OPT_OFF)

OPT_NAMES_DICT = {}
for key, val in vars(_libldap0).items():
    if key.startswith('OPT_'):
        OPT_NAMES_DICT[val] = key


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
        self._lock = (lock_class or threading.Lock)()
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

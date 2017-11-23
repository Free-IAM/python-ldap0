# -*- coding: utf-8 -*-
"""
ldap0.functions - wraps functions of module _ldap
"""

__all__ = [
    'escape_str',
    'explode_dn',
    'explode_rdn',
    'get_option',
    'init',
    'initialize',
    'open',
    'set_option',
    'strf_secs',
    'strp_secs',
]

import sys
import pprint
import time
from calendar import timegm

from ldap0.pkginfo import __version__, __author__, __license__

import _libldap0
assert _libldap0.__version__ == __version__, ImportError(
    'ldap %s and _ldap %s version mismatch!' % (__version__, _libldap0.__version__)
)

import ldap0
from ldap0 import LDAPError
from ldap0.dn import explode_dn, explode_rdn
from ldap0.ldapobject import LDAPObject

if __debug__:
    # Tracing is only supported in debugging mode
    import traceback


def _ldap_function_call(lock, func, *args, **kwargs):
    """
    Wrapper function which locks and logs calls to function

    lock
        Instance of threading.Lock or compatible
    func
        Function to call with arguments passed in via *args and **kwargs
    """
    if __debug__ and ldap0._trace_level >= 1:
        ldap0._trace_file.write('*** %s.%s %s\n' % (
            '_ldap',
            func.__name__,
            pprint.pformat((args, kwargs))
        ))
        if ldap0._trace_level >= 9:
            traceback.print_stack(
                limit=ldap0._trace_stack_limit,
                file=ldap0._trace_file,
            )
    if lock:
        lock.acquire()
    try: # finally
        try: # error / result logging
            result = func(*args, **kwargs)
        except LDAPError as err:
            if __debug__ and ldap0._trace_level >= 2:
                ldap0._trace_file.write('=> LDAPError: %s\n' % (err))
            raise
        else:
            if __debug__ and ldap0._trace_level >= 2:
                ldap0._trace_file.write('=> result:\n%s\n' % (pprint.pformat(result)))
    finally:
        if lock:
            lock.release()
    return result # end of _ldap_function_call()


def get_option(option):
    """
    get_option(name) -> value

    Get the value of an LDAP global option.
    """
    return _ldap_function_call(None, _ldap0.get_option, option)


def set_option(option, invalue):
    """
    set_option(name, value)

    Set the value of an LDAP global option.
    """
    return _ldap_function_call(None, _ldap0.set_option, option, invalue)


def escape_str(escape_func, val, *args):
    """
    Applies escape_func() to all items of `args' and returns a string based
    on format string `val'.
    """
    escape_args = map(escape_func, args)
    return val % tuple(escape_args)


def strf_secs(secs):
    """
    Convert seconds since epoch to a string compliant to LDAP syntax GeneralizedTime
    """
    return time.strftime('%Y%m%d%H%M%SZ', time.gmtime(secs))


def strp_secs(dt_str):
    """
    Convert LDAP syntax GeneralizedTime to seconds since epoch
    """
    return timegm(time.strptime(dt_str, '%Y%m%d%H%M%SZ'))

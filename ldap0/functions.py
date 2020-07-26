# -*- coding: utf-8 -*-
"""
ldap0.functions - wraps functions of module _ldap
"""

from typing import Optional, Set, Union

__all__ = [
    'escape_str',
    'get_option',
    'set_option',
    'strf_secs',
    'strp_secs',
]

import datetime
import pprint
import time
import logging
from calendar import timegm

import _libldap0
from _libldap0 import LDAPError

from .lock import LDAPLock
import ldap0

global _LIBLDAP0_MODULE_LOCK
_LIBLDAP0_MODULE_LOCK = LDAPLock(desc='Module lock', trace_level=ldap0._trace_level)

# format string used for Generalized Time attributes values with UTC
DATETIME_FORMAT_UTC = r'%Y%m%d%H%M%SZ'


def _libldap0_function_call(func, *args, **kwargs):
    """
    Wrapper function which locks and logs calls to function

    lock
        Instance of threading.Lock or compatible
    func
        Function to call with arguments passed in via *args and **kwargs
    """
    if __debug__ and ldap0._trace_level >= 1:
        logging.debug(
            '_libldap0.%s %s\n',
            func.__name__,
            pprint.pformat((args, kwargs)),
            exc_info=(ldap0._trace_level >= 9),
        )
    _LIBLDAP0_MODULE_LOCK.acquire()
    try: # finally
        try: # error / result logging
            result = func(*args, **kwargs)
        except LDAPError as err:
            if __debug__ and ldap0._trace_level >= 2:
                result_log_msg = str(err)
            raise
        else:
            if __debug__ and ldap0._trace_level >= 2:
                result_log_msg = pprint.pformat(result)
    finally:
        _LIBLDAP0_MODULE_LOCK.release()
    if __debug__ and ldap0._trace_level >= 2:
        logging.debug('-> %s', result_log_msg)
    return result # end of _libldap0_function_call()


def get_option(option):
    """
    get_option(name) -> value

    Get the value of an LDAP global option.
    """
    return _libldap0_function_call(_libldap0.get_option, option)


def set_option(option, invalue):
    """
    set_option(name, value)

    Set the value of an LDAP global option.
    """
    return _libldap0_function_call(_libldap0.set_option, option, invalue)


def escape_str(escape_str_func, fmt: str, *args) -> str:
    """
    Applies escape_func() to all items of `args' and returns a string based
    on format string `val'.
    """
    escaped_args = map(escape_str_func, args)
    return fmt % tuple(escaped_args)


def escape_format(escape_str_func, fmt: str, *args, **kwargs) -> str:
    escaped_args = [
        escape_str_func(val)
        for val in args
    ]
    escaped_kwargs = dict([
        (key, escape_str_func(val))
        for key, val in kwargs.items()
    ])
    return fmt.format(*escaped_args, **escaped_kwargs)


def strf_secs(secs: float) -> str:
    """
    Convert seconds since epoch to a string compliant to LDAP syntax GeneralizedTime
    """
    return time.strftime(DATETIME_FORMAT_UTC, time.gmtime(secs))


def strp_secs(dt_str: str) -> float:
    """
    Convert LDAP syntax GeneralizedTime to seconds since epoch
    """
    return timegm(time.strptime(dt_str, DATETIME_FORMAT_UTC))


def str2datetime(time_str: str):
    """
    Parse GeneralizedTime (UTC) string to datetime.datetime instance
    """
    return datetime.datetime.strptime(time_str, DATETIME_FORMAT_UTC)


def datetime2str(time_dt) -> str:
    """
    Return datetime as string formatted as GeneralizedTime (UTC)
    """
    return datetime.datetime.strftime(time_dt, DATETIME_FORMAT_UTC)


def is_expired(
        start: Union[str, bytes, datetime.datetime],
        max_age: Union[str, bytes, int, float, datetime.timedelta],
        now: Optional[datetime.datetime] = None,
        disable_secs: Union[int, float] = 0,
    ) -> bool:
    """
    Check expiry of something based on start date and time
    and a timespan.

    Returns True if start + max_age > now
    """
    if isinstance(start, bytes):
        start = str2datetime(start.decode('utf-8'))
    elif isinstance(start, str):
        start = str2datetime(start)
    elif isinstance(start, (int, float)):
        start = datetime.datetime.fromtimestamp(start)
    if isinstance(max_age, (str, bytes, float)):
        max_age = datetime.timedelta(seconds=int(max_age))
    elif isinstance(max_age, int):
        max_age = datetime.timedelta(seconds=max_age)
    if max_age.seconds <= disable_secs or not start:
        # nothing to check
        return False
    return (start + max_age) < (now or datetime.datetime.utcnow())


def attr_set(attrs_str: str) -> Set[str]:
    """
    Splits string with space or comma-separated list of attribute names
    and returns a set with white-space stripped values
    """
    res = set()
    for attr in (attrs_str or '').strip().replace(' ', ',').split(','):
        attr = attr.strip()
        if attr:
            res.add(attr)
    return res

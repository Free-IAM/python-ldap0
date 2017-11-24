# -*- coding: utf-8 -*-
"""
ldap0.ldapobject - wrapper classes above _libldap0.LDAPObject
"""

from __future__ import absolute_import

if __debug__:
    # Tracing is only supported in debugging mode
    import pprint
    import traceback

from ldap0.pkginfo import __version__, __author__, __license__

import _libldap0
from _libldap0 import LDAPError

__all__ = [
    'NO_UNIQUE_ENTRY',
    'LDAPObject',
    'SimpleLDAPObject',
    'ReconnectLDAPObject',
]

from .simple import SimpleLDAPObject, NO_UNIQUE_ENTRY
from .reconnect import ReconnectLDAPObject
LDAPObject = SimpleLDAPObject

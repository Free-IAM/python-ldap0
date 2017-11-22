# -*- coding: utf-8 -*-
"""
ldap0.ldapobject - wrapper classes above _libldap0.LDAPObject
"""

import sys
import time
from os import strerror

if __debug__:
    # Tracing is only supported in debugging mode
    import pprint
    import traceback

from ldap0.pkginfo import __version__, __author__, __license__

import _libldap0
import ldap0
import ldap0.sasl
import ldap0.functions
from ldap0 import LDAPError

from ldap0.schema import SCHEMA_ATTRS
from ldap0.controls import DecodeControlTuples, RequestControlTuples


__all__ = [
    'NO_UNIQUE_ENTRY',
    'LDAPObject',
    'SimpleLDAPObject',
    'ReconnectLDAPObject',
]


class NO_UNIQUE_ENTRY(_libldap0.NO_SUCH_OBJECT):
    """
    Exception raised if a LDAP search returned more than entry entry
    although assumed to return a unique single search result.
    """

# For back-ward compability import ReconnectLDAPObject here
from simple import SimpleLDAPObject
from reconnect import ReconnectLDAPObject
# Used as default for ldap.open() and ldap.initialize()
LDAPObject = SimpleLDAPObject

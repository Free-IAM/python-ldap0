# -*- coding: utf-8 -*-
"""
ldap0 - base module
"""

from __future__ import absolute_import

import sys
import threading

import _libldap0
from _libldap0 import *

from .__about__ import __version__, __author__, __license__

# Tracing is only supported in debugging mode
_trace_level = 0
_trace_file = sys.stderr
_trace_stack_limit = None

from .functions import get_option, set_option
from .functions import escape_str, strf_secs, strp_secs
from .ldapobject import LDAPObject, ReconnectLDAPObject, NO_UNIQUE_ENTRY
from .dn import explode_dn, explode_rdn

assert _libldap0.__version__ == __version__, ImportError(
    'ldap %s and _libldap0 %s version mismatch!' % (__version__, _libldap0.__version__)
)

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

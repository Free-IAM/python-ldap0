# -*- coding: utf-8 -*-
"""
ldap0 - base module
"""

import _libldap0
from _libldap0 import *

from .__about__ import __version__, __author__, __license__

# Tracing is only supported in debugging mode
_trace_level = 0

from .functions import get_option, set_option
from .functions import strf_secs, strp_secs

import _libldap0
if _libldap0.__version__.decode('ascii') != __version__:
    raise ImportError(
        'ldap0 %s and _libldap0 %s version mismatch!' % (
            __version__,
            _libldap0.__version__.decode('ascii'),
        )
    )

# call into libldap to initialize it right now
LIBLDAP_API_INFO = get_option(_libldap0.OPT_API_INFO)
# set reasonable global defaults for various options
set_option(_libldap0.OPT_PROTOCOL_VERSION, _libldap0.VERSION3)
set_option(_libldap0.OPT_RESTART, False)
set_option(_libldap0.OPT_DEREF, False)
set_option(_libldap0.OPT_REFERRALS, False)
set_option(_libldap0.OPT_X_TLS_REQUIRE_CERT, _libldap0.OPT_X_TLS_HARD)
# name of crypto library libldap is linked with
LIBLDAP_TLS_PACKAGE = _libldap0.get_option(_libldap0.OPT_X_TLS_PACKAGE).decode('ascii')

OPT_NAMES = {
    val: key
    for key, val in vars(_libldap0).items()
    if key.startswith('OPT_')
}

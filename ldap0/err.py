# -*- coding: utf-8 -*-
"""
ldap0.err - error classes
"""

from __future__ import absolute_import

import _libldap0

LIMIT_EXCEPTIONS = (
    _libldap0.TIMEOUT,
    _libldap0.TIMELIMIT_EXCEEDED,
    _libldap0.SIZELIMIT_EXCEEDED,
    _libldap0.ADMINLIMIT_EXCEEDED,
)

# -*- coding: utf-8 -*-
"""
ldap0.compat - compability layer for Python 2.x
"""

from __future__ import absolute_import
from __future__ import unicode_literals

import sys

try:
    from collections import UserDict as User_Dict
except ImportError:
    from UserDict import IterableUserDict as User_Dict

__all__ = [
    'UserDict',
]

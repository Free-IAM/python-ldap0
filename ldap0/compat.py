# -*- coding: utf-8 -*-
"""
ldap0.compat - compability layer for Python 2.x
"""

from __future__ import absolute_import
from __future__ import unicode_literals

import sys

if sys.version_info.major >= 3:
    # Python 3+
    from collections import UserDict as User_Dict
    from urllib.request import quote as url_quote
    from urllib.request import unquote as url_unquote
    unicode = str
else:
    # Python 2.7
    from UserDict import IterableUserDict as User_Dict
    from urllib import quote as url_quote
    from urllib import unquote as url_unquote
    unicode = unicode

__all__ = [
    'UserDict',
]

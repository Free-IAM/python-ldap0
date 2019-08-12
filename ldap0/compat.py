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
    from urllib.request import urlopen as url_open
    from urllib.parse import urlparse as url_parse
    from io import StringIO
    unicode = str
else:
    # Python 2.7
    from UserDict import IterableUserDict as User_Dict
    from urllib import quote as url_quote
    from urllib import unquote as url_unquote
    from urllib import urlopen as url_open
    from urlparse import urlparse as url_parse
    try:
        from cStringIO import StringIO
    except ImportError:
        from StringIO import StringIO
    unicode = unicode

__all__ = [
    'UserDict',
    'url_quote',
    'url_unquote',
    'url_open',
    'url_parse',
    'StringIO',
    'unicode',
]

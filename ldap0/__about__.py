# -*- coding: utf-8 -*-
"""
ldap0.__about__ - Meta information
"""

import collections

VersionInfo = collections.namedtuple('version_info', ('major', 'minor', 'micro'))
__version_info__ = VersionInfo(
    major=0,
    minor=5,
    micro=9,
)
__version__ = '.'.join(str(val) for val in __version_info__)
__author__ = u'Michael Stroeder'
__mail__ = u'michael@stroeder.com'
__copyright__ = u'(C) 2017-2019 by Michael Ströder <michael@stroeder.com>'
__license__ = 'Apache-2.0'

__all__ = [
    '__version_info__',
    '__version__',
    '__author__',
    '__mail__',
    '__license__',
    '__copyright__',
]

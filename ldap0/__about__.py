# -*- coding: utf-8 -*-
"""
ldap0.__about__ - Meta information
"""

import collections

VersionInfo = collections.namedtuple('VersionInfo', ('major', 'minor', 'micro'))
__version_info__ = VersionInfo(
    major=1,
    minor=3,
    micro=0,
)
__version__ = '.'.join(str(val) for val in __version_info__)
__author__ = 'Michael Stroeder'
__mail__ = 'michael@stroeder.com'
__copyright__ = '(C) 2017-2021 by Michael Ströder <michael@stroeder.com>'
__license__ = 'Apache-2.0'

__all__ = [
    '__version_info__',
    '__version__',
    '__author__',
    '__mail__',
    '__license__',
    '__copyright__',
]

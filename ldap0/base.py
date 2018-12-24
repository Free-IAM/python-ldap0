# -*- coding: utf-8 -*-
"""
ldap0.base - basic classes and functions
"""

from __future__ import absolute_import


class LDAPResult(object):
    """
    base class for LDAP result objects
    """

    def __init__(self, rtype, data, msgid, ctrls):
        self._res = (rtype, data, msgid, ctrls)

    def __repr__(self):
        return '%s%r' % (self.__class__.__name__, self._res)

    def __getitem__(self, index):
        return self._res[index]

    @property
    def rtype(self):
        return self._res[0]

    @property
    def data(self):
        return self._res[1]

    @property
    def msgid(self):
        return self._res[2]

    @property
    def ctrls(self):
        return self._res[3]

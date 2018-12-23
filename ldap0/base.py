# -*- coding: utf-8 -*-
"""
ldap0.base - basic classes and functions
"""

from __future__ import absolute_import


class LDAPResult(tuple):
    """
    base class for LDAP result objects
    """

    def __init__(self, res):
        tuple.__init__(self, res)

    def __repr__(self):
        return '%s(%s)' % (self.__class__.__name__, tuple.__repr__(self))

    @property
    def rtype(self):
        return self[0]

    @property
    def data(self):
        return self[1]

    @property
    def msgid(self):
        return self[2]

    @property
    def ctrls(self):
        return self[3]

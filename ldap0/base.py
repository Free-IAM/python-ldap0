# -*- coding: utf-8 -*-
"""
ldap0.base - basic classes and functions
"""

from __future__ import absolute_import
from __future__ import unicode_literals


def decode_entry_dict(entry, encoding='utf-8'):
    """
    decode an LDAP entry dict containing only
    byte-strings in keys and values with given encoding
    """
    return dict([
        (at.decode(encoding), [av.decode(encoding) for av in avs])
        for at, avs in entry.items()
    ])


def encode_entry_dict(entry, encoding='utf-8'):
    """
    encode an LDAP entry dict containing only
    Unicode-strings in keys and values with given encoding
    """
    return dict([
        (at.encode(encoding), [av.encode(encoding) for av in avs])
        for at, avs in entry.items()
    ])


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

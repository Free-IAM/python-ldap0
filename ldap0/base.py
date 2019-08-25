# -*- coding: utf-8 -*-
"""
ldap0.base - basic classes and functions
"""

__all__ = [
    'LDAPResult',
    'decode_list',
    'decode_entry_dict',
    'encode_list',
    'encode_entry_dict',
]


def decode_list(lst, encoding='utf-8'):
    """
    decode a list containing only byte-strings with given encoding
    """
    return [item.decode(encoding) for item in lst]


def decode_entry_dict(entry, encoding='utf-8'):
    """
    decode an LDAP entry dict containing only
    byte-strings in keys and values with given encoding
    """
    return dict([
        (at.decode(encoding), decode_list(avs, encoding=encoding))
        for at, avs in entry.items()
    ])


def encode_list(lst, encoding='utf-8'):
    """
    encode a list containing only Unicode-strings with given encoding
    """
    return [item.encode(encoding) for item in lst]


def encode_entry_dict(entry, encoding='utf-8'):
    """
    encode an LDAP entry dict containing only
    Unicode-strings in keys and values with given encoding
    """
    return dict([
        (at.encode(encoding), encode_list(avs, encoding=encoding))
        for at, avs in entry.items()
    ])


class LDAPResult:
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

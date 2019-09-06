# -*- coding: utf-8 -*-
"""
ldap0.base - basic classes and functions
"""

__all__ = [
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

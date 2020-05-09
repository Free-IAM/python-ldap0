# -*- coding: utf-8 -*-
"""
ldap0.base - basic classes and functions
"""

from typing import Sequence

from .typehints import BytesList, StrList, EntryBytes, EntryStr

__all__ = [
    'decode_list',
    'decode_entry_dict',
    'encode_list',
    'encode_entry_dict',
]


def decode_list(lst: Sequence[bytes], encoding: str = 'utf-8') -> StrList:
    """
    decode a sequence containing only byte-strings with given encoding
    and return a list of strings
    """
    return [item.decode(encoding) for item in lst]


def decode_entry_dict(entry: EntryBytes, encoding: str = 'utf-8') -> EntryStr:
    """
    decode an LDAP entry dict containing only
    byte-strings in keys and values with given encoding
    """
    return {
        at.decode(encoding): decode_list(avs, encoding=encoding)
        for at, avs in entry.items()
    }


def encode_list(lst: Sequence[str], encoding: str = 'utf-8') -> BytesList:
    """
    encode a sequence containing only Unicode-strings with given encoding
    and return a list of bytes
    """
    return [item.encode(encoding) for item in lst]


def encode_entry_dict(entry: EntryStr, encoding: str = 'utf-8') -> EntryBytes:
    """
    encode an LDAP entry dict containing only
    Unicode-strings in keys and values with given encoding
    """
    return {
        at.encode(encoding): encode_list(avs, encoding=encoding)
        for at, avs in entry.items()
    }

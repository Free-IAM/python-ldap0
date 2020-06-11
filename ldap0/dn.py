# -*- coding: utf-8 -*-
"""
ldap0.dn - misc stuff for handling distinguished names (see RFC 4514)
"""

from typing import List, Union, Sequence, Tuple

import _libldap0

from .__about__ import __version__, __author__, __license__
from .functions import _libldap0_function_call
from .typehints import StrList, EntryStr


# to be used with str.translate in escape_str()
BASIC_ESCAPE_MAP = {
    ord('\\'): '\\\\',
    ord(','): '\\,',
    ord('+'): '\\+',
    ord('"'): '\\"',
    ord('<'): '\\<',
    ord('>'): '\\>',
    ord(';'): '\\;',
    ord('='): '\\=',
    0: '\\\000',
}


def escape_str(val: str) -> str:
    """
    Escape all DN special characters found in val
    according to rules defined in RFC 4514, section 2.4
    """
    assert isinstance(val, str), TypeError('Expected str (unicode) for val, got %r' % (val,))
    if not val:
        return val
    val = val.translate(BASIC_ESCAPE_MAP)
    if val[-1:] == ' ':
        val = ''.join((val[:-1], '\\ '))
    if val[0:1] == '#' or val[0:1] == ' ':
        val = ''.join(('\\', val))
    return val


def is_dn(val: str, flags: int = 0) -> bool:
    """
    Returns True is `s' can be parsed by _libldap0.str2dn() like as a
    distinguished host_name (DN), otherwise False is returned.
    """
    assert isinstance(val, str), TypeError('Expected str (unicode) for val, got %r' % (val,))
    if not val:
        # _libldap0.str2dn() seg faults on empty bytes sequence
        # => return immediaetly here
        return True
    try:
        _libldap0_function_call(_libldap0.str2dn, val.encode('utf-8'), flags)
    except Exception:
        return False
    else:
        return True


class DNObj(tuple):
    """
    Class for handling LDAPv3 distinguished name string representations
    """
    encoding = 'utf-8'

    def __init__(self, dn_t: Sequence[Tuple[Tuple[str, str]]]):
        tuple.__init__(self)
        self = tuple(dn_t)

    @classmethod
    def from_str(cls, dn: str, flags=0, at_sanitizer=(lambda at: at)):
        """
        create a new DNObj instance from DN string representation
        """
        if not dn:
            return cls([])
        return cls([
            tuple([
                (at_sanitizer(at.decode('ascii')), av.decode(cls.encoding))
                for at, av, _ in dn_comp
            ])
            for dn_comp in _libldap0_function_call(_libldap0.str2dn, dn.encode(cls.encoding), flags)
        ])

    @classmethod
    def from_domain(cls, domain: str):
        """
        create a new DNObj instance from dot-separated DNS domain name
        """
        domain = domain.encode('idna').decode('ascii')
        return cls([(('dc', d),) for d in domain.split('.')])

    def encode(self, encoding=None, errors='strict') -> bytes:
        return self.__str__().encode(encoding or self.encoding, errors=errors)

    def __str__(self) -> str:
        return ','.join([
            '+'.join([
                '='.join((atype, escape_str(avalue or '')))
                for atype, avalue in rdn
            ])
            for rdn in self
        ])

    def __bytes__(self) -> bytes:
        return self.encode()

    def __hash__(self):
        return hash(self.__str__())

    def __repr__(self) -> str:
        return '%s(%s)' % (self.__class__.__name__, tuple.__repr__(self))

    def __eq__(self, other) -> bool:
        res = isinstance(other, self.__class__) and len(self) == len(other)
        i = 0
        while res and i < len(self):
            res = len(self[i]) == len(other[i])
            j = 0
            while res and j < len(self[i]):
                res = (
                    self[i][j][0].lower() == other[i][j][0].lower()
                    and
                    self[i][j][1] == other[i][j][1]
                )
                j += 1
            i += 1
        return res

    def __add__(self, other):
        return self.__class__(tuple.__add__(self, other))

    def slice(self, ind1: Union[int, None], ind2: Union[int, None]):
        return self.__class__(self[ind1:ind2])

    def __reversed__(self):
        return self.__class__(reversed(tuple(self)))

    def rdn(self):
        """
        returns the RDN as DNObj instance
        """
        return self.__class__(self[:1])

    def rdn_attrs(self) -> EntryStr:
        """
        returns the RDN attributes as string-keyed dict
        """
        if not self:
            return {}
        return dict([(at, av) for at, av in self[0]])

    def parent(self):
        """
        returns the parent's DN as DNObj instance
        """
        return self.__class__(self[1:])

    def parents(self) -> List:
        """
        returns the parent's DN as DNObj instance
        """
        if len(self) <= 0:
            return []
        if len(self) == 1:
            return [self.__class__((()))]
        return [
            self.__class__(self[i:])
            for i in range(1, len(self))
        ]

    def match(self, dn_list: StrList):
        """
        returns best matching parent DN found in dn_list
        """
        max_match_level = 0
        max_match_dn = self.__class__((()))
        if not self or not dn_list:
            return max_match_dn
        self_len = len(self)
        for dn_obj in dn_list:
            dn_len = len(dn_obj)
            if dn_len > self_len:
                # can't match
                continue
            match_level = 0
            while (
                    match_level <= self_len
                    and (
                        self.slice(self_len-match_level-1, self_len-match_level)
                        == dn_obj.slice(dn_len-match_level-1, dn_len-match_level)
                    )
                ):
                match_level += 1
            if match_level > max_match_level:
                max_match_level = match_level
                max_match_dn = self.slice(-match_level, None)
        return max_match_dn

    def domain(self, only_dc: bool = True) -> str:
        """
        Convert dc-style DN to DNS domain name (see RFC 2247)
        """
        dns_labels = []
        for ind in range(len(self)-1, -1, -1):
            dn_comp = self[ind]
            if len(dn_comp) != 1:
                raise ValueError('multi-valued RDN not allowed for domain, was %r' % (dn_comp,))
            attr_type, attr_value = dn_comp[0]
            if attr_type.lower() != 'dc':
                if only_dc:
                    raise ValueError('Only dc allowed as RDN attribute, was %r' % (attr_type,))
                break
            dns_labels.append(attr_value.strip())
        dns_labels.reverse()
        return '.'.join(dns_labels)

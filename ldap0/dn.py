# -*- coding: utf-8 -*-
"""
ldap0.dn - misc stuff for handling distinguished names (see RFC 4514)
"""

import _libldap0

from .__about__ import __version__, __author__, __license__
from .functions import _libldap0_function_call


def escape_str(val):
    """
    Escape all DN special characters found in s
    with a back-slash (see RFC 4514, section 2.4)
    """
    assert isinstance(val, str), TypeError('Expected str (unicode) for val, got %r' % (val,))
    if not val:
        return val
    val = val.replace('\\', '\\\\')
    val = val.replace(',', '\\,')
    val = val.replace('+', '\\+')
    val = val.replace('"', '\\"')
    val = val.replace('<', '\\<')
    val = val.replace('>', '\\>')
    val = val.replace(';', '\\;')
    val = val.replace('=', '\\=')
    val = val.replace('\000', '\\\000')
    if val[-1:] == ' ':
        val = ''.join((val[:-1], '\\ '))
    if val[0:1] == '#' or val[0:1] == ' ':
        val = ''.join(('\\', val))
    return val


def is_dn(val, flags=0):
    """
    Returns True is `s' can be parsed by _libldap0.str2dn() like as a
    distinguished host_name (DN), otherwise False is returned.
    """
    assert isinstance(val, str), TypeError('Expected str (unicode) for val, got %r' % (val,))
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
    charset = 'utf-8'

    def __init__(self, dn_t):
        tuple.__init__(self)
        self = dn_t

    @classmethod
    def fromstring(cls, dn, flags=0):
        """
        create a new DNObj instance from DN string representation
        """
        if not dn:
            dn_t = (())
        else:
            dn_t = tuple([
                tuple([
                    (at.decode('ascii'), av.decode(cls.charset))
                    for at, av, _ in dn_comp
                ])
                for dn_comp in _libldap0_function_call(_libldap0.str2dn, dn.encode(cls.charset), flags)
            ])
        return cls(dn_t)

    @classmethod
    def fromdomain(cls, domain):
        """
        create a new DNObj instance from dot-separated DNS domain name
        """
        domain = domain.encode('idna').decode('ascii')
        return cls([(('dc', d),) for d in domain.split('.')])

    def encode(self, charset=None):
        return self.__str__().encode(charset or self.charset)

    def __str__(self):
        return ','.join([
            '+'.join([
                '='.join((atype, escape_str(avalue or '')))
                for atype, avalue in rdn
            ])
            for rdn in self
        ])

    def __bytes__(self):
        return self.encode()

    def __hash__(self):
        return hash(self.__str__())

    def __repr__(self):
        return '%s(%s)' % (self.__class__.__name__, tuple.__repr__(self))

    def __eq__(self, other):
        return isinstance(other, self.__class__) and tuple.__eq__(self, other)

    def __add__(self, other):
        return self.__class__(tuple.__add__(self, other))

    def slice(self, ind1, ind2):
        return self.__class__(self[ind1:ind2])

    def __reversed__(self):
        return self.__class__(reversed(tuple(self)))

    def rdn(self):
        """
        returns the RDN as DNObj instance
        """
        return self.__class__(self[:1])

    def rdn_attrs(self):
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

    def parents(self):
        """
        returns the parent's DN as DNObj instance
        """
        if len(self) <= 0:
            return []
        elif len(self) == 1:
            return [self.__class__((()))]
        return [
            self.__class__(self[i:])
            for i in range(1, len(self))
        ]

    def match(self, dn_list) -> str:
        """
        returns best matching parent DN found in dn_list
        """
        max_match_level = 0
        max_match_dn = self.__class__((()))
        if not self or not dn_list:
            return max_match_dn
        self_len = len(self)
        for dn_obj in dn_list:
            if len(dn_obj) > self_len:
                # can't match
                continue
            match_level = 0
            dn_len = len(dn_obj)
            while match_level <= self_len and self[self_len-match_level-1] == dn_obj[dn_len-match_level-1]:
                match_level += 1
            if match_level > max_match_level:
                max_match_level = match_level
                max_match_dn = self.slice(-match_level, None)
        return max_match_dn

    def domain(self, only_dc=True):
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
                else:
                    break
            dns_labels.append(attr_value.strip())
        dns_labels.reverse()
        return '.'.join(dns_labels)

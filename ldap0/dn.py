# -*- coding: utf-8 -*-
"""
ldap0.dn - misc stuff for handling distinguished names (see RFC 4514)
"""

from __future__ import absolute_import

import _libldap0

from .__about__ import __version__, __author__, __license__
from .functions import _libldap0_function_call


def escape_dn_chars(val):
    """
    Escape all DN special characters found in s
    with a back-slash (see RFC 4514, section 2.4)
    """
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
    if val[-1] == ' ':
        val = ''.join((val[:-1], '\\ '))
    if val[0] == '#' or val[0] == ' ':
        val = ''.join(('\\', val))
    return val


def str2dn(dn, flags=0):
    """
    This function takes a DN as string as parameter and returns
    a decomposed DN. It's the inverse to dn2str().

    flags describes the format of the dn

    See also the OpenLDAP man-page ldap_str2dn(3)
    """
    if not dn:
        return ()
    return tuple([
        tuple(item)
        for item in _libldap0_function_call(_libldap0.str2dn, dn, flags)
    ])


def dn2str(dn):
    """
    This function takes a decomposed DN as parameter and returns
    a single string. It's the inverse to str2dn() but will always
    return a DN in LDAPv3 format compliant to RFC 4514.
    """
    return ','.join([
        '+'.join([
            '='.join((atype, escape_dn_chars(avalue or '')))
            for atype, avalue, _ in rdn
        ])
        for rdn in dn
    ])

def explode_dn(dn, notypes=False, flags=0):
    """
    explode_dn(dn [, notypes=False [, flags=0]]) -> list

    This function takes a DN and breaks it up into its component parts.
    The notypes parameter is used to specify that only the component's
    attribute values be returned and not the attribute types.
    """
    if not dn:
        return []
    dn_decomp = str2dn(dn, flags)
    rdn_list = []
    for rdn in dn_decomp:
        if notypes:
            rdn_list.append('+'.join([
                escape_dn_chars(avalue or '')
                for atype, avalue, _ in rdn
            ]))
        else:
            rdn_list.append('+'.join([
                '='.join((atype, escape_dn_chars(avalue or '')))
                for atype, avalue, _ in rdn
            ]))
    return tuple(rdn_list)


def explode_rdn(rdn, notypes=False, flags=0):
    """
    explode_rdn(dn [, notypes=False [, flags=0]]) -> list

    This function takes a RDN and breaks it up into its component parts
    if it is a multi-valued RDN.
    The notypes parameter is used to specify that only the component's
    attribute values be returned and not the attribute types.
    """
    if not rdn:
        return ()
    rdn_decomp = str2dn(rdn, flags)[0]
    if notypes:
        return tuple([
            avalue or ''
            for atype, avalue, _ in rdn_decomp
        ])
    return tuple([
        '='.join((atype, escape_dn_chars(avalue or '')))
        for atype, avalue, _ in rdn_decomp
    ])


def is_dn(val, flags=0):
    """
    Returns True is `s' can be parsed by ldap0.dn.str2dn() like as a
    distinguished host_name (DN), otherwise False is returned.
    """
    try:
        str2dn(val, flags)
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
        tuple.__init__(self, dn_t)

    @classmethod
    def fromstring(cls, dn, flags=0):
        """
        create a new DNObj instance from DN string representation
        """
        if isinstance(dn, unicode):
            dn = dn.encode(cls.charset)
        return cls(str2dn(dn, flags=flags))

    @classmethod
    def fromdomain(cls, domain):
        """
        create a new DNObj instance from dot-separated DNS domain name
        """
        if isinstance(domain, unicode):
            domain = domain.encode('idna')
        return cls([(('dc', d, 1),) for d in domain.split('.')])

    def __bytes__(self):
        return dn2str(self)

    def __str__(self):
        return self.__bytes__()

    def __unicode__(self):
        return dn2str(self).decode(self.charset)

    def __repr__(self):
        return '%s(%s)' % (self.__class__.__name__, tuple.__repr__(self))

    def __eq__(self, other):
        return isinstance(other, self.__class__) and tuple.__eq__(self, other)

    def __add__(self, other):
        return self.__class__(tuple.__add__(self, other))

    def __getslice__(self, ind1, ind2):
        return self.__class__(tuple.__getslice__(self, ind1, ind2))

    def __reversed__(self):
        return self.__class__(reversed(tuple(self)))

    def rdn(self):
        """
        returns the RDN as DNObj instance
        """
        return self[:1]

    def parent(self):
        """
        returns the parent's DN as DNObj instance
        """
        return self[1:]

    def domain(self, only_dc=True):
        """
        Convert dc-style DN to DNS domain name (see RFC 2247)
        """
        dns_labels = []
        for ind in range(len(self)-1, -1, -1):
            dn_comp = self[ind]
            if len(dn_comp) != 1:
                raise ValueError('multi-valued RDN not allowed for domain, was %s' % repr(dn_comp))
            attr_type, attr_value, _ = dn_comp[0]
            if attr_type.lower() != 'dc':
                if only_dc:
                    raise ValueError('Only dc allowed as RDN attribute, was %s' % repr(attr_type))
                else:
                    break
            dns_labels.append(attr_value.strip())
        dns_labels.reverse()
        return '.'.join(dns_labels)

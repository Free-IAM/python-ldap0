# -*- coding: utf-8 -*-
"""
ldap0.dn - misc stuff for handling distinguished names (see RFC 4514)
"""

from __future__ import absolute_import

from ldap0.pkginfo import __version__, __author__, __license__

import _libldap0
assert _libldap0.__version__ == __version__, ImportError(
    'ldap0 %s and _libldap0 %s version mismatch!' % (__version__, _libldap0.__version__)
)

import ldap0.functions


def escape_dn_chars(val):
    """
    Escape all DN special characters found in s
    with a back-slash (see RFC 4514, section 2.4)
    """
    if val:
        val = val.replace('\\', '\\\\')
        val = val.replace(',', '\\,')
        val = val.replace('+', '\\+')
        val = val.replace('"', '\\"')
        val = val.replace('<', '\\<')
        val = val.replace('>', '\\>')
        val = val.replace(';', '\\;')
        val = val.replace('=', '\\=')
        val = val.replace('\000', '\\\000')
        if val[0] == '#' or val[0] == ' ':
            val = ''.join(('\\', val))
        if val[-1] == ' ':
            val = ''.join((val[:-1], '\\ '))
    return val


def str2dn(dn, flags=0):
    """
    This function takes a DN as string as parameter and returns
    a decomposed DN. It's the inverse to dn2str().

    flags describes the format of the dn

    See also the OpenLDAP man-page ldap_str2dn(3)
    """
    if not dn:
        return []
    return ldap0.functions._ldap_function_call(None, _libldap0.str2dn, dn, flags)


def dn2str(dn):
    """
    This function takes a decomposed DN as parameter and returns
    a single string. It's the inverse to str2dn() but will always
    return a DN in LDAPv3 format compliant to RFC 4514.
    """
    return ','.join([
        '+'.join([
            '='.join((atype, escape_dn_chars(avalue or '')))
            for atype, avalue, _ in rdn])
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
    return rdn_list


def explode_rdn(rdn, notypes=False, flags=0):
    """
    explode_rdn(dn [, notypes=False [, flags=0]]) -> list

    This function takes a RDN and breaks it up into its component parts
    if it is a multi-valued RDN.
    The notypes parameter is used to specify that only the component's
    attribute values be returned and not the attribute types.
    """
    if not rdn:
        return []
    rdn_decomp = str2dn(rdn, flags)[0]
    if notypes:
        return [
            avalue or ''
            for atype, avalue, _ in rdn_decomp
        ]
    return [
        '='.join((atype, escape_dn_chars(avalue or '')))
        for atype, avalue, _ in rdn_decomp
    ]


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

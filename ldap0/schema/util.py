# -*- coding: utf-8 -*-
"""
ldap0.schema.util -  misc. subschema utility stuff
"""

from __future__ import absolute_import

from urllib import urlopen

from ..__about__ import __version__, __author__, __license__
from ..cidict import cidict
from ..ldapurl import LDAPUrl
from ..ldapobject import LDAPObject
from ..ldif import LDIFParser
from ..schema import SubSchema, SCHEMA_ATTRS, SCHEMA_CLASS_MAPPING


def urlfetch(uri, trace_level=0, check_uniqueness=True):
    """
    Fetches a parsed schema entry by uri.

    If :uri: is a LDAP URL the LDAP server is queried directly.
    Otherwise :uri: is assumed to point to a LDIF file which
    is loaded with urllib.

    :trace_level: is passed to class LDAPObject for debugging.

    :check_uniqueness: is passed to class SubSchema.
    """
    uri = uri.strip()
    if uri.startswith('ldap:') or uri.startswith('ldaps:') or uri.startswith('ldapi:'):
        ldap_url = LDAPUrl(uri)
        ldap_conn = LDAPObject(ldap_url.initializeUrl(), trace_level)
        ldap_conn.simple_bind_s(ldap_url.who or '', ldap_url.cred or '')
        subschemasubentry_dn = ldap_conn.search_subschemasubentry_s(ldap_url.dn)
        if subschemasubentry_dn is None:
            s_temp = None
        else:
            if ldap_url.attrs is None:
                schema_attrs = SCHEMA_ATTRS
            else:
                schema_attrs = ldap_url.attrs
            s_temp = ldap_conn.read_subschemasubentry_s(
                subschemasubentry_dn,
                attrs=schema_attrs,
            )
        ldap_conn.unbind_s()
        del ldap_conn
    else:
        ldif_file = urlopen(uri)
        ldif_parser = LDIFParser(ldif_file, max_entries=1)
        ldif_res = ldif_parser.list_entry_records()
        subschemasubentry_dn, s_temp = ldif_res[0]
    # Work-around for mixed-cased attribute names
    subschemasubentry_entry = cidict()
    s_temp = s_temp or {}
    for atype, aval in s_temp.items():
        if atype in SCHEMA_CLASS_MAPPING:
            try:
                subschemasubentry_entry[atype].extend(aval)
            except KeyError:
                subschemasubentry_entry[atype] = aval
    # Finally parse the schema
    if subschemasubentry_dn != None:
        parsed_sub_schema = SubSchema(
            subschemasubentry_entry,
            check_uniqueness=check_uniqueness,
        )
    else:
        parsed_sub_schema = None
    return subschemasubentry_dn, parsed_sub_schema

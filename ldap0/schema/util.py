# -*- coding: utf-8 -*-
"""
ldap0.schema.util -  misc. subschema utility stuff
"""

from ldap0.pkginfo import __version__, __author__, __license__
from ldap0.cidict import cidict
from ldap0.ldapurl import LDAPUrl
from ldap0.ldapobject.simple import SimpleLDAPObject
from urllib import urlopen
from ldap0.ldif import LDIFRecordList
from ldap0.schema import SubSchema, SCHEMA_ATTRS, SCHEMA_CLASS_MAPPING


def urlfetch(uri, trace_level=0, check_uniqueness=1):
    """
    Fetches a parsed schema entry by uri.

    If uri is a LDAP URL the LDAP server is queried directly.
    Otherwise uri is assumed to point to a LDIF file which
    is loaded with urllib.
    """
    uri = uri.strip()
    if uri.startswith('ldap:') or uri.startswith('ldaps:') or uri.startswith('ldapi:'):
        ldap_url = LDAPUrl(uri)
        ldap_conn = SimpleLDAPObject(ldap_url.initializeUrl(), trace_level)
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
        ldif_parser = LDIFRecordList(ldif_file, max_entries=1)
        ldif_parser.parse()
        subschemasubentry_dn, s_temp = ldif_parser.all_records[0]
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

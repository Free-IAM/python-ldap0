# -*- coding: utf-8 -*-
"""
ldap0.schema.util -  misc. subschema utility stuff
"""

from urllib.request import urlopen

from _libldap0 import MOD_DELETE, MOD_ADD

from ..cidict import CIDict
from ..ldapurl import LDAPUrl, is_ldapurl
from ..ldapobject import LDAPObject
from ..ldif import LDIFParser

from ..schema import SubSchema, SCHEMA_ATTRS, SCHEMA_CLASS_MAPPING
from .models import AttributeType, SchemaElementOIDSet
from . import subentry, models


def urlfetch(uri, trace_level=0, check_uniqueness=True, rootdse=True):
    """
    Fetches a parsed schema entry by uri.

    If :uri: is a LDAP URL the LDAP server is queried directly.
    Otherwise :uri: is assumed to point to a LDIF file which
    is loaded with urllib.

    :trace_level: is passed to class LDAPObject for debugging.

    :check_uniqueness: is passed to SubSchema().

    :rootdse: is passed to LDAPObject.search_subschemasubentry_s()
    """
    uri = uri.strip()
    if is_ldapurl(uri):
        ldap_url = LDAPUrl(uri)
        ldap_conn = LDAPObject(ldap_url, trace_level)
        ldap_conn.simple_bind_s(
            ldap_url.who or '',
            (ldap_url.cred or '').encode(ldap_conn.encoding),
        )
        subschemasubentry_dn = ldap_conn.search_subschemasubentry_s(
            ldap_url.dn,
            rootdse=rootdse,
        )
        if subschemasubentry_dn is None:
            s_temp = None
        else:
            if ldap_url.attrs is None:
                schema_attrs = SCHEMA_ATTRS
            else:
                schema_attrs = ldap_url.attrs
            s_temp = ldap_conn.read_subschemasubentry_s(subschemasubentry_dn, attrs=schema_attrs)
        ldap_conn.unbind_s()
        del ldap_conn
    else:
        with urlopen(uri) as ldif_file:
            ldif_parser = LDIFParser(ldif_file, max_entries=1)
            ldif_res = ldif_parser.list_entry_records()
        subschemasubentry_dn, s_temp = ldif_res[0]
        s_temp = {
            at.decode('ascii'): [av.decode('utf-8') for av in avs]
            for at, avs in (s_temp or {}).items()
        }
    # Work-around for mixed-cased schema attribute names
    subschemasubentry_entry = CIDict()
    subschemasubentry_entry.update({
        at: avs
        for at, avs in s_temp.items()
        if at in SCHEMA_CLASS_MAPPING
    })
    del s_temp
    # Finally parse the schema
    if subschemasubentry_dn is not None:
        parsed_sub_schema = SubSchema(
            subschemasubentry_entry,
            check_uniqueness=check_uniqueness,
        )
    else:
        parsed_sub_schema = None
    return subschemasubentry_dn, parsed_sub_schema


def modify_modlist(
        sub_schema,
        old_entry,
        new_entry,
        ignore_attr_types=None,
        ignore_oldexistent=0,
        order_max=3,
    ):
    """
    Build differential modify list for calling LDAPObject.modify()/modify_s()
    with schema knowledge

    sub_schema
        Instance of ldaputil.schema.SubSchema
    old_entry
        Dictionary holding the old entry
    new_entry
        Dictionary holding what the new entry should be
    ignore_attr_types
        Sequence of attribute type names to be ignored completely
    ignore_oldexistent
        If non-zero attribute type names which are in old_entry
        but are not found in new_entry at all are not deleted.
        This is handy for situations where your application
        sets attribute value to '' for deleting an attribute.
        In most cases leave zero.
    order_max
        Max. number of attribute values to be reordered to match
        order in new_entry
    """
    # Type checking
    assert isinstance(sub_schema, subentry.SubSchema), TypeError(
        'Expected sub_schema to be instance of SubSchema, got %r' % (sub_schema,)
    )
    assert isinstance(old_entry, models.Entry), TypeError(
        'Expected old_entry to be instance of models.Entry, got %r' % (old_entry,)
    )
    assert isinstance(new_entry, models.Entry), TypeError(
        'Expected new_entry to be instance of models.Entry, got %r' % (new_entry,)
    )

    if isinstance(ignore_attr_types, SchemaElementOIDSet):
        ignore_attr_type_set = ignore_attr_types
    else:
        ignore_attr_type_set = SchemaElementOIDSet(
            sub_schema,
            AttributeType,
            ignore_attr_types,
        )

    # Performance optimization
    at_cls = models.AttributeType
    mr_cls = models.MatchingRule

    # Start building the modlist result
    modlist = []

    # Sanitize new_entry
    for attr_type in list(new_entry):
        # Filter away list items which are empty strings or None
        new_entry[attr_type] = [av for av in new_entry[attr_type] if av]
        # Check for attributes with empty value lists
        if not new_entry[attr_type]:
            # Remove the empty attribute
            del new_entry[attr_type]

    for attr_type in new_entry.keys():

        attr_type_b = attr_type.encode('ascii')

        if attr_type in ignore_attr_type_set:
            # This attribute type is ignored
            continue

        # Check whether there's an equality matching rule defined
        # for the attribute type and the matching rule is announced in subschema
        try:
            at_eq_mr = sub_schema.get_inheritedattr(
                at_cls,
                attr_type,
                'equality',
            )
        except KeyError:
            mr_obj = None
        else:
            if at_eq_mr:
                mr_obj = sub_schema.get_obj(mr_cls, at_eq_mr)
            else:
                mr_obj = None

        # Filter away list items which are empty strings or None
        new_value = new_entry[attr_type]
        old_value = [av for av in old_entry.get(attr_type, []) if av]

        # We have to check if attribute value lists differs
        old_value_set = set(old_value)
        new_value_set = set(new_value)

        if mr_obj:
            # for attributes with equality matching rule try to
            # generate a fine-grained diff
            if len(old_value) > order_max or len(new_value) > order_max:
                # for "many" values be less invasive but not order-preserving
                del_values = [v for v in old_value if not v in new_value_set]
                add_values = [v for v in new_value if not v in old_value_set]
                if old_value and del_values:
                    modlist.append((MOD_DELETE, attr_type_b, del_values))
                if new_value and add_values:
                    modlist.append((MOD_ADD, attr_type_b, add_values))
            else:
                # for few values be order-preserving
                if new_value and old_value != new_value:
                    if old_value:
                        modlist.append((MOD_DELETE, attr_type_b, old_value))
                    modlist.append((MOD_ADD, attr_type_b, new_value))
        elif new_value and old_value != new_value:
            if old_value:
                modlist.append((MOD_DELETE, attr_type_b, None))
            modlist.append((MOD_ADD, attr_type_b, new_value))

    # Remove all attributes of old_entry which are not present
    # in new_entry at all
    if not ignore_oldexistent:
        for attr_type, old_values in old_entry.items():

            attr_type_b = attr_type.encode('ascii')

            if (
                    old_values and
                    old_values != [b''] and
                    not attr_type in new_entry and
                    not sub_schema.get_oid(at_cls, attr_type) in ignore_attr_type_set
                ):
                try:
                    at_eq_mr = sub_schema.get_inheritedattr(
                        at_cls,
                        attr_type,
                        'equality',
                    )
                except KeyError:
                    at_eq_mr = None
                if at_eq_mr:
                    mr_obj = sub_schema.get_obj(mr_cls, at_eq_mr)
                    if mr_obj:
                        modlist.append((MOD_DELETE, attr_type_b, old_values))
                    else:
                        modlist.append((MOD_DELETE, attr_type_b, None))
                else:
                    modlist.append((MOD_DELETE, attr_type_b, None))

    return modlist
    # end of modify_modlist()

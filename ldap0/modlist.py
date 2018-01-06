# -*- coding: utf-8 -*-
"""
ldap0.modlist - create add/modify modlist's
"""

from __future__ import absolute_import

from _libldap0 import MOD_DELETE, MOD_ADD

from .__about__ import __version__, __author__, __license__
from .schema import subentry as schema_subentry
from .schema import models as schema_models


def add_modlist(entry, ignore_attr_types=None):
    """Build modify list for call of method LDAPObject.add()"""
    ignore_attr_types = set(map(str.lower, ignore_attr_types or []))
    modlist = []
    for attrtype in entry:
        if attrtype.lower() in ignore_attr_types:
            # This attribute type is ignored
            continue
        # Eliminate empty attr value strings in list
        attrvaluelist = [
            val
            for val in entry[attrtype]
            if val is not None
        ]
        if attrvaluelist:
            modlist.append((attrtype, entry[attrtype]))
    return modlist # add_modlist()


def modify_modlist(
        old_entry,
        new_entry,
        ignore_attr_types=None,
        ignore_oldexistent=0,
        case_ignore_attr_types=None
    ):
    """
    Build differential modify list for calling LDAPObject.modify()/modify_s()

    old_entry
        Dictionary holding the old entry
    new_entry
        Dictionary holding what the new entry should be
    ignore_attr_types
        List of attribute type names to be ignored completely
    ignore_oldexistent
        If non-zero attribute type names which are in old_entry
        but are not found in new_entry at all are not deleted.
        This is handy for situations where your application
        sets attribute value to '' for deleting an attribute.
        In most cases leave zero.
    case_ignore_attr_types
        List of attribute type names for which comparison will be made
        case-insensitive
    """
    ignore_attr_types = set(map(str.lower, ignore_attr_types or []))
    case_ignore_attr_types = set(map(str.lower, case_ignore_attr_types or []))
    modlist = []
    attrtype_lower_map = {}
    for attr_type in old_entry:
        attrtype_lower_map[attr_type.lower()] = attr_type
    for attrtype in new_entry:
        attrtype_lower = attrtype.lower()
        if attrtype_lower in ignore_attr_types:
            # This attribute type is ignored
            continue
        # Filter away null-strings
        new_value = [
            val
            for val in new_entry[attrtype]
            if val is not None
        ]
        if attrtype_lower in attrtype_lower_map:
            old_value = [
                val
                for val in old_entry.get(attrtype_lower_map[attrtype_lower], [])
                if val is not None
            ]
            del attrtype_lower_map[attrtype_lower]
        else:
            old_value = []
        if not old_value and new_value:
            # Add a new attribute to entry
            modlist.append((MOD_ADD, attrtype, new_value))
        elif old_value and new_value:
            # Replace existing attribute
            replace_attr_value = len(old_value) != len(new_value)
            if not replace_attr_value:
                if attrtype_lower in case_ignore_attr_types:
                    old_value_set = set(map(str.lower, old_value))
                    new_value_set = set(map(str.lower, new_value))
                else:
                    old_value_set = set(old_value)
                    new_value_set = set(new_value)
                replace_attr_value = new_value_set != old_value_set
            if replace_attr_value:
                modlist.append((MOD_DELETE, attrtype, None))
                modlist.append((MOD_ADD, attrtype, new_value))
        elif old_value and not new_value:
            # Completely delete an existing attribute
            modlist.append((MOD_DELETE, attrtype, None))
    if not ignore_oldexistent:
        # Remove all attributes of old_entry which are not present
        # in new_entry at all
        for atl in attrtype_lower_map:
            if atl in ignore_attr_types:
                # This attribute type is ignored
                continue
            attrtype = attrtype_lower_map[atl]
            modlist.append((MOD_DELETE, attrtype, None))
    return modlist # modify_modlist()


def modify_modlist2(
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
        List of attribute type names to be ignored completely
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
    assert isinstance(sub_schema, schema_subentry.SubSchema)
    assert isinstance(old_entry, schema_models.Entry)
    assert isinstance(new_entry, schema_models.Entry)

    # Performance optimization
    at_class = schema_models.AttributeType
    mr_class = schema_models.MatchingRule

    # Start building the modlist result
    modlist = []

    # Sanitize new_entry
    for attr_type in new_entry:
        # Filter away list items which are empty strings or None
        new_entry[attr_type] = filter(None, new_entry[attr_type])
        # Check for attributes with empty value lists
        if not new_entry[attr_type]:
            # Remove the empty attribute
            del new_entry[attr_type]

    for attrtype in new_entry:
        if sub_schema.getoid(at_class, attrtype) in ignore_attr_types:
            # This attribute type is ignored
            continue

        # Check whether there's an equality matching rule defined
        # for the attribute type and the matching rule is announced in subschema
        try:
            at_eq_mr = sub_schema.get_inheritedattr(
                at_class,
                attrtype,
                'equality',
            )
        except KeyError:
            mr_obj = None
        else:
            if at_eq_mr:
                mr_obj = sub_schema.get_obj(mr_class, at_eq_mr)
            else:
                mr_obj = None

        # Filter away list items which are empty strings or None
        new_value = new_entry[attrtype]
        old_value = filter(None, old_entry.get(attrtype, []))

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
                    modlist.append((MOD_DELETE, attrtype, del_values))
                if new_value and add_values:
                    modlist.append((MOD_ADD, attrtype, add_values))
            else:
                # for few values be order-preserving
                if new_value and old_value != new_value:
                    if old_value:
                        modlist.append((MOD_DELETE, attrtype, old_value))
                    modlist.append((MOD_ADD, attrtype, new_value))
        elif new_value and old_value != new_value:
            if old_value:
                modlist.append((MOD_DELETE, attrtype, None))
            modlist.append((MOD_ADD, attrtype, new_value))

    # Remove all attributes of old_entry which are not present
    # in new_entry at all
    if not ignore_oldexistent:
        for attrtype, old_values in old_entry.items():
            if old_values and \
               old_values != [''] and \
               not attrtype in new_entry and \
               not sub_schema.getoid(at_class, attrtype) in ignore_attr_types:
                try:
                    at_eq_mr = sub_schema.get_inheritedattr(
                        at_class,
                        attrtype,
                        'equality',
                    )
                except KeyError:
                    at_eq_mr = None
                if at_eq_mr:
                    mr_obj = sub_schema.get_obj(mr_class, at_eq_mr)
                    if mr_obj:
                        modlist.append((MOD_DELETE, attrtype, old_values))
                    else:
                        modlist.append((MOD_DELETE, attrtype, None))
                else:
                    modlist.append((MOD_DELETE, attrtype, None))

    return modlist # modify_modlist2()

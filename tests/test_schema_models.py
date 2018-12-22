# -*- coding: utf-8 -*-
"""
Automatic tests for class ldap0.schema.SubSchema
"""

from __future__ import absolute_import

import unittest

import ldap0.ldif
from ldap0.schema.models import AttributeType
from ldap0.schema.models import ObjectClass
from ldap0.schema.models import LDAPSyntax
from ldap0.schema.models import MatchingRule
from ldap0.schema.models import MatchingRuleUse
from ldap0.schema.models import DITContentRule
from ldap0.schema.models import DITStructureRule
from ldap0.schema.models import NameForm


# class attribute names of ObjectClass instances
OC_CLASS_ATTRS = ()


class SchemaDescriptionTest(unittest.TestCase):
    """
    Base class for testing parsing and unparsing of schema description classes
    """
    schema_class = None
    class_attrs = ()
    test_cases = ()

    def test_parse(self):
        for schema_desc_str, res in self.test_cases:
            if not schema_desc_str:
                # skip empty strings
                continue
            at = self.schema_class(schema_desc_str)
            for class_attr in self.class_attrs:
                self.assertEqual(
                    getattr(at, class_attr),
                    res.get(class_attr, None),
                    'Test-case %r class attribute %r: %r != %r' % (
                        schema_desc_str,
                        class_attr,
                        getattr(at, class_attr),
                        res.get(class_attr, None),
                    ),
                )

    def test_unparse(self):
        for schema_desc_str, res in self.test_cases:
            if not schema_desc_str:
                # skip empty strings
                continue
            at1 = self.schema_class(schema_desc_str)
            at2 = self.schema_class(str(at1))
            for class_attr in self.class_attrs:
                self.assertEqual(
                    getattr(at1, class_attr),
                    getattr(at2, class_attr),
                    'Test-case %r class attribute %r: %r != %r' % (
                        schema_desc_str,
                        class_attr,
                        getattr(at1, class_attr),
                        getattr(at2, class_attr),
                    ),
                )


class TestAttributeType(SchemaDescriptionTest):
    """
    test ldap0.schema.models.AttributeType
    """
    schema_class = AttributeType
    class_attrs = (
        'oid',
        'names',
        'desc',
        'obsolete',
        'sup',
        'equality',
        'ordering',
        'substr',
        'x_origin',
        'x_ordered',
        'syntax',
        'syntax_len',
        'single_value',
        'collective',
        'no_user_mod',
        'usage',
    )
    test_cases = (
        (
            "( 2.5.4.3 NAME ( 'cn' 'commonName' ) DESC 'RFC4519: common name(s) for which the entity is known by' SUP name )",
            {
                'oid': '2.5.4.3',
                'names': ('cn', 'commonName'),
                'desc': 'RFC4519: common name(s) for which the entity is known by',
                'obsolete': False,
                'sup': ('name',),
                'single_value': False,
                'collective': False,
                'no_user_mod': False,
                'usage': 0,
            },
        ),
        (
            "( 1.3.6.1.1.1.1.0 NAME 'uidNumber' DESC 'RFC2307: An integer uniquely identifying a user in an administrative domain' EQUALITY integerMatch ORDERING integerOrderingMatch SYNTAX 1.3.6.1.4.1.1466.115.121.1.27 SINGLE-VALUE )",
            {
                'oid': '1.3.6.1.1.1.1.0',
                'names': ('uidNumber',),
                'desc': 'RFC2307: An integer uniquely identifying a user in an administrative domain',
                'obsolete': False,
                'sup': (),
                'equality': 'integerMatch',
                'ordering': 'integerOrderingMatch',
                'syntax': '1.3.6.1.4.1.1466.115.121.1.27',
                'single_value': True,
                'collective': False,
                'no_user_mod': False,
                'usage': 0,
            },
        ),
        (
            "( 1.3.6.1.4.1.4203.1.12.2.3.2.3.2 NAME 'olcDbACLAuthcDn' DESC 'Remote ACL administrative identity' OBSOLETE SYNTAX 1.3.6.1.4.1.1466.115.121.1.12 SINGLE-VALUE )",
            {
                'oid': '1.3.6.1.4.1.4203.1.12.2.3.2.3.2',
                'names': ('olcDbACLAuthcDn',),
                'desc': 'Remote ACL administrative identity',
                'obsolete': True,
                'sup': (),
                'syntax': '1.3.6.1.4.1.1466.115.121.1.12',
                'single_value': True,
                'collective': False,
                'no_user_mod': False,
                'usage': 0,
            },
        ),
        (
            "( 2.5.18.1 NAME 'createTimestamp' DESC 'RFC4512: time which object was created' EQUALITY generalizedTimeMatch ORDERING generalizedTimeOrderingMatch SYNTAX 1.3.6.1.4.1.1466.115.121.1.24 SINGLE-VALUE NO-USER-MODIFICATION USAGE directoryOperation )",
            {
                'oid': '2.5.18.1',
                'names': ('createTimestamp',),
                'desc': 'RFC4512: time which object was created',
                'obsolete': False,
                'sup': (),
                'equality': 'generalizedTimeMatch',
                'ordering': 'generalizedTimeOrderingMatch',
                'syntax': '1.3.6.1.4.1.1466.115.121.1.24',
                'single_value': True,
                'collective': False,
                'no_user_mod': True,
                'usage': 1,
            },
        ),
    )
                

class TestObjectClass(SchemaDescriptionTest):
    """
    test ldap0.schema.models.ObjectClass
    """
    schema_class = ObjectClass
    class_attrs = (
        'oid',
        'obsolete',
        'names',
        'desc',
        'must',
        'may',
        'kind',
        'sup',
    )
    test_cases = (
    )
                

class TestLDAPSyntax(SchemaDescriptionTest):
    """
    test ldap0.schema.models.LDAPSyntax
    """
    schema_class = LDAPSyntax
    class_attrs = (
        'oid',
        'desc',
        'x_subst',
        'not_human_readable',
        'x_binary_transfer_required',
    )
    test_cases = (
        (
            "( 1.3.6.1.4.1.1466.115.121.1.4 DESC 'Audio' X-NOT-HUMAN-READABLE 'TRUE' )",
            {
                'oid': '1.3.6.1.4.1.1466.115.121.1.4',
                'desc': 'Audio',
                'not_human_readable': True,
                'x_binary_transfer_required': False,
            },
        ),
        (
            "( 1.3.6.1.4.1.1466.115.121.1.6 DESC 'Bit String' )",
            {
                'oid': '1.3.6.1.4.1.1466.115.121.1.6',
                'desc': 'Bit String',
                'not_human_readable': False,
                'x_binary_transfer_required': False,
            },
        ),
        (
            "( 1.3.6.1.4.1.1466.115.121.1.8 DESC 'Certificate' X-BINARY-TRANSFER-REQUIRED 'TRUE' X-NOT-HUMAN-READABLE 'TRUE' )",
            {
                'oid': '1.3.6.1.4.1.1466.115.121.1.8',
                'desc': 'Certificate',
                'x_subst': None,
                'not_human_readable': True,
                'x_binary_transfer_required': True,
            },
        ),
        (
            "( 1.2.3.4 DESC 'Weirdest test äöüÄÖÜß' X-SUBST blurbBlabber X-BINARY-TRANSFER-REQUIRED 'FALSE' X-NOT-HUMAN-READABLE 'FALSE' )",
            {
                'oid': '1.2.3.4',
                'desc': 'Weirdest test äöüÄÖÜß',
                'x_subst': 'blurbBlabber',
                'not_human_readable': False,
                'x_binary_transfer_required': False,
            },
        ),
    )


class TestMatchingRule(SchemaDescriptionTest):
    """
    test ldap0.schema.models.MatchingRule
    """
    schema_class = MatchingRule
    class_attrs = (
        'oid',
        'names',
        'desc',
        'obsolete',
        'syntax',
    )
    test_cases = (
    )
                

class TestMatchingRuleUse(SchemaDescriptionTest):
    """
    test ldap0.schema.models.MatchingRuleUse
    """
    schema_class = MatchingRuleUse
    class_attrs = (
        'oid',
        'names',
        'desc',
        'obsolete',
        'applies',
    )
    test_cases = (
    )
                

class TestDITContentRule(SchemaDescriptionTest):
    """
    test ldap0.schema.models.DITContentRule
    """
    schema_class = DITContentRule
    class_attrs = (
        'oid',
        'names',
        'desc',
        'obsolete',
        'aux',
        'must',
        'may',
        'nots',
    )
    test_cases = (
    )
                

class TestDITStructureRule(SchemaDescriptionTest):
    """
    test ldap0.schema.models.DITStructureRule
    """
    schema_class = DITStructureRule
    class_attrs = (
        'ruleid',
        'names',
        'desc',
        'obsolete',
        'form',
        'sup',
    )
    test_cases = (
    )
                

class TestNameForm(SchemaDescriptionTest):
    """
    test ldap0.schema.models.NameForm
    """
    schema_class = NameForm
    class_attrs = (
        'oid',
        'names',
        'desc',
        'obsolete',
        'oc',
        'must',
        'may',
    )
    test_cases = (
    )


if __name__ == '__main__':
    unittest.main()

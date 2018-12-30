# -*- coding: utf-8 -*-
"""
Automatic tests for class ldap0.schema.SubSchema
"""

from __future__ import absolute_import

import unittest

import ldap0.ldif
import ldap0.schema.util
from ldap0.schema.models import SchemaElement
from ldap0.schema.models import AttributeType
from ldap0.schema.models import ObjectClass
from ldap0.schema.models import LDAPSyntax
from ldap0.schema.models import MatchingRule
from ldap0.schema.models import MatchingRuleUse
from ldap0.schema.models import DITContentRule
from ldap0.schema.models import DITStructureRule
from ldap0.schema.models import NameForm
from ldap0.schema.models import Entry


# class attribute names of ObjectClass instances
OC_CLASS_ATTRS = ()


class SchemaDescriptionTest(unittest.TestCase):
    """
    Base class for testing parsing and unparsing of schema description classes
    """
    schema_class = SchemaElement
    class_attrs = (
        'oid',
        'desc',
    )
    test_cases = (
        (
            "( 1.2.3.4.5.6.7.8 DESC 'something weird: äöüÄÖÜß' )",
            {
                'oid': '1.2.3.4.5.6.7.8',
                'desc': 'something weird: äöüÄÖÜß',
            },
        ),
    )

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
        'names',
        'obsolete',
        'desc',
        'must',
        'may',
        'kind',
        'sup',
    )
    test_cases = (
        (
            "( 2.16.840.1.113730.3.2.2 NAME 'inetOrgPerson' DESC 'RFC2798: Internet Organizational Person' SUP organizationalPerson STRUCTURAL MAY ( audio $ businessCategory $ carLicense $ departmentNumber $ displayName $ employeeNumber $ employeeType $ givenName $ homePhone $ homePostalAddress $ initials $ jpegPhoto $ labeledURI $ mail $ manager $ mobile $ o $ pager $ photo $ roomNumber $ secretary $ uid $ userCertificate $ x500uniqueIdentifier$ preferredLanguage $ userSMIMECertificate $ userPKCS12 ) )",
            {
                'oid': '2.16.840.1.113730.3.2.2',
                'names': ('inetOrgPerson', ),
                'obsolete': False,
                'desc': 'RFC2798: Internet Organizational Person',
                'must': (),
                'may': (
                    'audio', 'businessCategory', 'carLicense',
                    'departmentNumber', 'displayName', 'employeeNumber',
                    'employeeType', 'givenName', 'homePhone',
                    'homePostalAddress', 'initials', 'jpegPhoto',
                    'labeledURI', 'mail', 'manager', 'mobile', 'o',
                    'pager', 'photo', 'roomNumber', 'secretary', 'uid',
                    'userCertificate', 'x500uniqueIdentifier',
                    'preferredLanguage', 'userSMIMECertificate',
                    'userPKCS12',
                ),
                'kind': 0,
                'sup': ('organizationalPerson',),
            },
        ),
        (
            "( 1.2.3.4 NAME ( foo $ bar ) DESC 'äöüÄÖÜß' ABSTRACT OBSOLETE )",
            {
                'oid': '1.2.3.4',
                'names': ('foo', 'bar'),
                'obsolete': True,
                'desc': 'äöüÄÖÜß',
                'must': (),
                'may': (),
                'kind': 1,
                'sup': (),
            },
        ),
        (
            "( 1.2.3.4 NAME ( foobar ) AUXILIARY OBSOLETE )",
            {
                'oid': '1.2.3.4',
                'names': ('foobar', ),
                'obsolete': True,
                'must': (),
                'may': (),
                'kind': 2,
                'sup': (),
            },
        ),
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
        (
            "( 1.3.6.1.1.16.3 NAME 'UUIDOrderingMatch' SYNTAX 1.3.6.1.1.16.1 )",
            {
                'oid': '1.3.6.1.1.16.3',
                'names': ('UUIDOrderingMatch', ),
                'obsolete': False,
                'syntax': '1.3.6.1.1.16.1',
            },
        ),
        (
            "( 12.34.56.78.90 NAME ( fooBarMatch $ barFooMatch ) OBSOLETE SYNTAX 1.2.3.4.5.6.7.8.9 )",
            {
                'oid': '12.34.56.78.90',
                'names': ('fooBarMatch', 'barFooMatch'),
                'obsolete': True,
                'syntax': '1.2.3.4.5.6.7.8.9',
            },
        ),
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
        (
            "( 1.3.6.1.4.1.4203.666.11.2.5 NAME 'CSNSIDMatch' APPLIES ( entryCSN $ namingCSN $ contextCSN ) )",
            {
                'oid': '1.3.6.1.4.1.4203.666.11.2.5',
                'names': ('CSNSIDMatch', ),
                'desc': None,
                'obsolete': False,
                'applies': ('entryCSN', 'namingCSN', 'contextCSN'),
            },
        ),
        (
            "( 1.3.6.1.4.1.4203.666.11.2.5 NAME 'CSNSIDMatch' DESC 'äöüÄÖÜß' OBSOLETE )",
            {
                'oid': '1.3.6.1.4.1.4203.666.11.2.5',
                'names': ('CSNSIDMatch', ),
                'desc': 'äöüÄÖÜß',
                'obsolete': True,
                'applies': (),
            },
        ),
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
        (
            "( 2.16.840.1.113730.3.2.2 NAME 'inetOrgPerson-dcr' DESC 'content of inetOrgPerson entries' AUX ( pkiUser $ posixAccount $ inetLocalMailRecipient $ shadowAccount$ simpleSecurityObject ) NOT x121Address )",
            {
                'oid': '2.16.840.1.113730.3.2.2',
                'names': ('inetOrgPerson-dcr', ),
                'desc': 'content of inetOrgPerson entries',
                'obsolete': False,
                'aux': ('pkiUser', 'posixAccount', 'inetLocalMailRecipient', 'shadowAccount', 'simpleSecurityObject'),
                'must': (),
                'may': (),
                'nots': ('x121Address',),
            },
        ),
        (
            "( 1.2.3.4 NAME 'weird-oc-dcr' DESC 'äöüÄÖÜß' OBSOLETE MUST ( a $ b ) MAY ( c $ d ) )",
            {
                'oid': '1.2.3.4',
                'names': ('weird-oc-dcr', ),
                'desc': 'äöüÄÖÜß',
                'obsolete': True,
                'aux': (),
                'must': ('a', 'b'),
                'may': ('c', 'd'),
                'nots': (),
            },
        ),
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
        (
            "( 104 NAME 'aeRoot-top-SR-o' FORM aeRoot-top-NF-o )",
            {
                'ruleid': '104',
                'names': ('aeRoot-top-SR-o', ),
                'desc': None,
                'obsolete': False,
                'form': 'aeRoot-top-NF-o',
                'sup': (),
            },
        ),
        (
            "( 999 NAME ( rule999 $ ruleName ) DESC 'äöüÄÖÜß' FORM 'foobar' SUP ( 1 2 3 4 ) )",
            {
                'ruleid': '999',
                'names': ('rule999', 'ruleName'),
                'desc': 'äöüÄÖÜß',
                'obsolete': False,
                'form': 'foobar',
                'sup': ('1', '2', '3', '4'),
            },
        ),
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
        (
            "( 1.3.6.1.4.1.5427.1.389.42.15.103 NAME 'aeRoot-top-NF-o' OC aeRoot MUST ( o ) )",
            {
                'oid': '1.3.6.1.4.1.5427.1.389.42.15.103',
                'names': ('aeRoot-top-NF-o', ),
                'desc': None,
                'obsolete': False,
                'oc': 'aeRoot',
                'must': ('o',),
                'may': (),
            },
        ),
        (
            "( 1.2.3.4.5.6 NAME 'testNameForm' OC testObjectClass DESC 'äöüÄÖÜß' OBSOLETE MUST ( cn ) MAY ( mail $ uniqueIdentifier ) )",
            {
                'oid': '1.2.3.4.5.6',
                'names': ('testNameForm', ),
                'desc': 'äöüÄÖÜß',
                'obsolete': True,
                'oc': 'testObjectClass',
                'must': ('cn',),
                'may': ('mail', 'uniqueIdentifier'),
            },
        ),
    )


class SubschemaTest(unittest.TestCase):
    schema_uri = 'file:tests/ldif/subschema-openldap-all.ldif'
    maxDiff = 10000

    @classmethod
    def setUpClass(cls):
        super(SubschemaTest, cls).setUpClass()
        cls.sub_schema = ldap0.schema.util.urlfetch(cls.schema_uri, check_uniqueness=True)[1]


class TestEntry(SubschemaTest):
    def test001_correct_entry(self):
        ldap_entry =             {
            'objectClass':['person','pilotPerson'],
            'cn':['Michael Str\303\266der','Michael Stroeder'],
            'sn':['Str\303\266der'],
            'givenName':['Michael'],
            'c':['DE'],
        }
        e1 = Entry(
            self.sub_schema,
            'cn=Michael Str\303\266der,ou=test',
            ldap_entry,
        )
        self.assertEqual(e1.keys(), ['sn', 'givenName', 'c', 'cn', 'objectClass'])
        self.assertEqual('2.5.4.3' in e1, True)
        self.assertEqual('cn' in e1, True)
        self.assertEqual(e1['cn'], ['Michael Str\xc3\xb6der', 'Michael Stroeder'])
        self.assertEqual(e1['cn'], e1['2.5.4.3'])
        self.assertEqual(e1['cn'], e1['commonName'])
        self.assertEqual('mail' in e1, False)
        with self.assertRaises(KeyError):
            e1['mail']
        e1.update({'mail': ['michael@example.com']})
        self.assertEqual('mail' in e1, True)
        self.assertEqual(e1['mail'], e1['0.9.2342.19200300.100.1.3'])
        del e1['mail']
        with self.assertRaises(KeyError):
            e1['mail']
        must, may = e1.attribute_types()
        self.assertEqual(sorted(must.keys()), ['2.5.4.0', '2.5.4.3', '2.5.4.4'])
        self.assertEqual(
            sorted(may.keys()),
            [
                '0.9.2342.19200300.100.1.1', '0.9.2342.19200300.100.1.2',
                '0.9.2342.19200300.100.1.20', '0.9.2342.19200300.100.1.21',
                '0.9.2342.19200300.100.1.22', '0.9.2342.19200300.100.1.3',
                '0.9.2342.19200300.100.1.39', '0.9.2342.19200300.100.1.40',
                '0.9.2342.19200300.100.1.41', '0.9.2342.19200300.100.1.42',
                '0.9.2342.19200300.100.1.45', '0.9.2342.19200300.100.1.46',
                '0.9.2342.19200300.100.1.47', '0.9.2342.19200300.100.1.5',
                '0.9.2342.19200300.100.1.53', '0.9.2342.19200300.100.1.6',
                '0.9.2342.19200300.100.1.8',
                '2.5.4.13', '2.5.4.15', '2.5.4.20', '2.5.4.28', '2.5.4.34', '2.5.4.35'
            ],
        )


if __name__ == '__main__':
    unittest.main()

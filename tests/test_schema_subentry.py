# -*- coding: utf-8 -*-
"""
Automatic tests for class ldap0.schema.SubSchema
"""

from __future__ import absolute_import

import unittest

import ldap0.ldif
from ldap0.schema.util import urlfetch
from ldap0.schema.subentry import SCHEMA_ATTR_MAPPING, SCHEMA_CLASS_MAPPING
from ldap0.schema.models import AttributeType, SchemaElementOIDSet

class TestBasics(unittest.TestCase):

    def test_constants(self):
        self.assertEqual(len(SCHEMA_ATTR_MAPPING), 8)
        self.assertEqual(len(SCHEMA_CLASS_MAPPING), 8)


class SubschemaTest(unittest.TestCase):
    """
    Base class for implementing checks based on local schema files
    """
    maxDiff = 10000
    schema_file = 'file:tests/ldif/subschema-openldap-all.ldif'

    @classmethod
    def setUpClass(cls):
        super(SubschemaTest, cls).setUpClass()
        cls.schema_dn, cls.sub_schema = urlfetch(cls.schema_file, check_uniqueness=True)


class TestSubschema(SubschemaTest):
    """
    test ldap0.schema.SubSchema with subschema subentries read from LDIF files
    """

    def test001_basics(self):
        self.assertEqual(self.schema_dn, 'cn=Subschema')
        self.assertEqual(
            len(SCHEMA_CLASS_MAPPING),
            len(self.sub_schema.name2oid),
        )
        self.assertEqual(
            len(SCHEMA_CLASS_MAPPING),
            len(self.sub_schema.sed),
        )

    def test002_attribute_cn(self):
        # check the attribute type 'cn' alias 'commonName'
        oid = self.sub_schema.name2oid[ldap0.schema.models.AttributeType]['cn']
        self.assertEqual(oid, '2.5.4.3')
        self.assertEqual(oid, self.sub_schema.name2oid[ldap0.schema.models.AttributeType]['commonName'])
        cn_at = self.sub_schema.sed[ldap0.schema.models.AttributeType][oid]
        self.assertEqual(cn_at.names, ('cn', 'commonName'))
        self.assertEqual(cn_at.desc, 'RFC4519: common name(s) for which the entity is known by')
        self.assertEqual(cn_at.sup, ('name',))
        self.assertEqual(cn_at.syntax, None)
        self.assertEqual(cn_at.equality, None)
        self.assertEqual(cn_at.substr, None)
        self.assertEqual(cn_at.ordering, None)

    def test003_objectclass_inetorgperson(self):
        # check the object class 'inetOrgPerson'
        oid = self.sub_schema.name2oid[ldap0.schema.models.ObjectClass]['inetOrgPerson']
        self.assertEqual(oid, '2.16.840.1.113730.3.2.2')
        inop_oc = self.sub_schema.sed[ldap0.schema.models.ObjectClass][oid]
        self.assertEqual(inop_oc.names, ('inetOrgPerson',))
        self.assertEqual(inop_oc.desc, 'RFC2798: Internet Organizational Person')
        self.assertEqual(inop_oc.sup, ('organizationalPerson',))
        self.assertEqual(inop_oc.must, ())
        self.assertEqual(
            inop_oc.may,
            (
                'audio', 'businessCategory', 'carLicense',
                'departmentNumber', 'displayName', 'employeeNumber',
                'employeeType', 'givenName', 'homePhone',
                'homePostalAddress', 'initials', 'jpegPhoto',
                'labeledURI', 'mail', 'manager', 'mobile', 'o',
                'pager', 'photo', 'roomNumber', 'secretary', 'uid',
                'userCertificate', 'x500uniqueIdentifier',
                'preferredLanguage', 'userSMIMECertificate',
                'userPKCS12'
            ),
        )

    def test004_attribute_inheritance(self):
        # check SubSchema.get_syntax()
        self.assertEqual(self.sub_schema.get_syntax('does_not_exist_in_self.sub_schema'), None)
        self.assertEqual(self.sub_schema.get_syntax('cn'), '1.3.6.1.4.1.1466.115.121.1.15')
        # check some class attributes inherited by attribute type 'name'
        self.assertEqual(
            self.sub_schema.get_inheritedattr(AttributeType, 'cn', 'syntax'),
            '1.3.6.1.4.1.1466.115.121.1.15',
        )
        self.assertEqual(
            self.sub_schema.get_inheritedattr(AttributeType, 'cn', 'equality'),
            'caseIgnoreMatch',
        )
        self.assertEqual(
            self.sub_schema.get_inheritedattr(AttributeType, 'cn', 'substr'),
            'caseIgnoreSubstringsMatch',
        )
        cn_i_at = self.sub_schema.get_inheritedobj(
            AttributeType,
            'cn',
            ('syntax', 'equality', 'substr', 'ordering'),
        )
        self.assertEqual(cn_i_at.sup, ('name',))
        self.assertEqual(cn_i_at.syntax, '1.3.6.1.4.1.1466.115.121.1.15')
        self.assertEqual(cn_i_at.equality, 'caseIgnoreMatch')
        self.assertEqual(cn_i_at.substr, 'caseIgnoreSubstringsMatch')
        self.assertEqual(cn_i_at.ordering, None)

    def test005_determine_no_user_mod_attrs(self):
        """
        test SubSchema.determine_no_user_mod_attrs()
        """
        no_user_mod_attrs = self.sub_schema.determine_no_user_mod_attrs()
        self.assertEqual(len(no_user_mod_attrs), 54)
        self.assertIn('2.5.18.4', no_user_mod_attrs) # modifiersName
        no_user_mod_attrs_set = SchemaElementOIDSet(self.sub_schema, AttributeType, no_user_mod_attrs)
        self.assertIn('2.5.18.4', no_user_mod_attrs_set)
        self.assertIn('modifiersName', no_user_mod_attrs_set)
        # test SubSchema.determine_no_user_mod_attrs()
        op_attrs = self.sub_schema.get_all_operational_attributes()
        self.assertIn('2.5.18.4', op_attrs)
        self.assertIn('modifiersName', op_attrs)
        # check SubSchema.get_applicable_aux_classes()
        aux_classes = self.sub_schema.get_applicable_aux_classes('aeUser-dcr')
        self.assertEqual(
            sorted(aux_classes),
            [
                'inetLocalMailRecipient', 'ldapPublicKey', 'msPwdResetObject',
                'oathHOTPUser', 'oathTOTPUser', 'pkiUser', 'posixAccount'
            ],
        )

    def test006_get_structural_oc(self):
        """
        check SubSchema.get_structural_oc()
        """
        self.assertEqual(self.sub_schema.get_structural_oc([]), None)
        self.assertEqual(self.sub_schema.get_structural_oc(['posixAccount']), None)
        self.assertEqual(
            self.sub_schema.get_structural_oc(['inetOrgPerson']),
            '2.16.840.1.113730.3.2.2',
        )
        self.assertEqual(
            self.sub_schema.get_structural_oc(['inetOrgPerson', 'posixAccount']),
            '2.16.840.1.113730.3.2.2',
        )
        self.assertEqual(
            self.sub_schema.get_structural_oc([
                'person', 'organizationalPerson', 'inetOrgPerson', 'posixAccount'
            ]),
            '2.16.840.1.113730.3.2.2',
        )


if __name__ == '__main__':
    unittest.main()

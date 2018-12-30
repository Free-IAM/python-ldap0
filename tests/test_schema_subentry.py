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


class TestSubschemaLDIF(unittest.TestCase):
    """
    test ldap0.schema.SubSchema with subschema subentries read from LDIF files
    """
    maxDiff = 10000
    schema_files = (
        'file:tests/ldif/subschema-openldap-all.ldif',
    )

    def test_subschema_file(self):
        for test_file in self.schema_files:
            schema_dn, sub_schema = urlfetch(test_file, check_uniqueness=True)
            self.assertEqual(schema_dn, 'cn=Subschema')
            self.assertEqual(
                len(SCHEMA_CLASS_MAPPING),
                len(sub_schema.name2oid),
            )
            self.assertEqual(
                len(SCHEMA_CLASS_MAPPING),
                len(sub_schema.sed),
            )
            # check the attribute type 'cn' alias 'commonName'
            oid = sub_schema.name2oid[ldap0.schema.models.AttributeType]['cn']
            self.assertEqual(oid, '2.5.4.3')
            self.assertEqual(oid, sub_schema.name2oid[ldap0.schema.models.AttributeType]['commonName'])
            cn_at = sub_schema.sed[ldap0.schema.models.AttributeType][oid]
            self.assertEqual(cn_at.names, ('cn', 'commonName'))
            self.assertEqual(
                cn_at.desc,
                'RFC4519: common name(s) for which the entity is known by',
            )
            self.assertEqual(cn_at.sup, ('name',))
            self.assertEqual(cn_at.syntax, None)
            self.assertEqual(cn_at.equality, None)
            self.assertEqual(cn_at.substr, None)
            self.assertEqual(cn_at.ordering, None)
            # check the object class 'inetOrgPerson'
            oid = sub_schema.name2oid[ldap0.schema.models.ObjectClass]['inetOrgPerson']
            self.assertEqual(oid, '2.16.840.1.113730.3.2.2')
            inop_oc = sub_schema.sed[ldap0.schema.models.ObjectClass][oid]
            self.assertEqual(
                inop_oc.names,
                ('inetOrgPerson',),
            )
            self.assertEqual(
                inop_oc.desc,
                'RFC2798: Internet Organizational Person',
            )
            self.assertEqual(
                inop_oc.sup,
                ('organizationalPerson',),
            )
            self.assertEqual(
                inop_oc.must,
                (),
            )
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
            # check SubSchema.get_syntax()
            self.assertEqual(sub_schema.get_syntax('does_not_exist_in_sub_schema'), None)
            self.assertEqual(sub_schema.get_syntax('cn'), '1.3.6.1.4.1.1466.115.121.1.15')
            # check some class attributes inherited by attribute type 'name'
            self.assertEqual(
                sub_schema.get_inheritedattr(AttributeType, 'cn', 'syntax'),
                '1.3.6.1.4.1.1466.115.121.1.15',
            )
            self.assertEqual(
                sub_schema.get_inheritedattr(AttributeType, 'cn', 'equality'),
                'caseIgnoreMatch',
            )
            self.assertEqual(
                sub_schema.get_inheritedattr(AttributeType, 'cn', 'substr'),
                'caseIgnoreSubstringsMatch',
            )
            cn_i_at = sub_schema.get_inheritedobj(
                AttributeType,
                'cn',
                ('syntax', 'equality', 'substr', 'ordering'),
            )
            self.assertEqual(cn_i_at.sup, ('name',))
            self.assertEqual(cn_i_at.syntax, '1.3.6.1.4.1.1466.115.121.1.15')
            self.assertEqual(cn_i_at.equality, 'caseIgnoreMatch')
            self.assertEqual(cn_i_at.substr, 'caseIgnoreSubstringsMatch')
            self.assertEqual(cn_i_at.ordering, None)
            # test SubSchema.determine_no_user_mod_attrs()
            no_user_mod_attrs = sub_schema.determine_no_user_mod_attrs()
            self.assertEqual(len(no_user_mod_attrs), 54)
            self.assertIn('2.5.18.4', no_user_mod_attrs) # modifiersName
            no_user_mod_attrs_set = SchemaElementOIDSet(sub_schema, AttributeType, no_user_mod_attrs)
            self.assertIn('2.5.18.4', no_user_mod_attrs_set)
            self.assertIn('modifiersName', no_user_mod_attrs_set)
            # test SubSchema.determine_no_user_mod_attrs()
            op_attrs = sub_schema.get_all_operational_attributes()
            self.assertIn('2.5.18.4', op_attrs)
            self.assertIn('modifiersName', op_attrs)
            # check SubSchema.get_applicable_aux_classes()
            aux_classes = sub_schema.get_applicable_aux_classes('aeUser-dcr')
            self.assertEqual(
                sorted(aux_classes),
                [
                    'inetLocalMailRecipient', 'ldapPublicKey', 'msPwdResetObject',
                    'oathHOTPUser', 'oathTOTPUser', 'pkiUser', 'posixAccount'
                ],
            )
            # check SubSchema.get_structural_oc()
            self.assertEqual(sub_schema.get_structural_oc([]), None)
            self.assertEqual(sub_schema.get_structural_oc(['posixAccount']), None)
            self.assertEqual(
                sub_schema.get_structural_oc(['inetOrgPerson']),
                '2.16.840.1.113730.3.2.2',
            )
            self.assertEqual(
                sub_schema.get_structural_oc(['inetOrgPerson', 'posixAccount']),
                '2.16.840.1.113730.3.2.2',
            )
            self.assertEqual(
                sub_schema.get_structural_oc([
                    'person', 'organizationalPerson', 'inetOrgPerson', 'posixAccount'
                ]),
                '2.16.840.1.113730.3.2.2',
            )


if __name__ == '__main__':
    unittest.main()

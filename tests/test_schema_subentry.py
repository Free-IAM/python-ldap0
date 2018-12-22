# -*- coding: utf-8 -*-
"""
Automatic tests for class ldap0.schema.SubSchema
"""

from __future__ import absolute_import

import unittest

import ldap0.ldif
from ldap0.schema import SubSchema
from ldap0.schema.util import urlfetch
from ldap0.schema.subentry import SCHEMA_ATTR_MAPPING, SCHEMA_CLASS_MAPPING

TEST_SUBSCHEMA_FILES = (
    'file:tests/ldif/subschema-openldap-all.ldif',
)

class TestSubschemaLDIF(unittest.TestCase):
    """
    test ldap.schema.SubSchema with subschema subentries read from LDIF files
    """

    def test_subschema_file(self):
        for test_file in TEST_SUBSCHEMA_FILES:
            _, sub_schema = urlfetch(test_file, check_uniqueness=True)
            self.assertEqual(len(SCHEMA_ATTR_MAPPING), 8)
            self.assertEqual(len(SCHEMA_CLASS_MAPPING), 8)
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
            self.assertEqual(
                cn_at.names,
                ('cn', 'commonName'),
            )
            self.assertEqual(
                cn_at.desc,
                'RFC4519: common name(s) for which the entity is known by',
            )
            self.assertEqual(
                cn_at.sup,
                ('name',),
            )
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


if __name__ == '__main__':
    unittest.main()

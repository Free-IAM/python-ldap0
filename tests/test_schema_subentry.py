# -*- coding: utf-8 -*-
"""
Automatic tests for class ldap0.schema.SubSchema
"""

import unittest

import ldap0.ldif
import ldap0.schema

TEST_SUBSCHEMA_FILES = (
    'tests/ldif/subschema-ipa.demo1.freeipa.org.ldif',
    'tests/ldif/subschema-openldap-all.ldif',
)

class TestSubschemaLDIF(unittest.TestCase):
    """
    test ldap.schema.SubSchema with subschema subentries read from LDIF files
    """

    def test_subschema_file(self):
        for test_file in TEST_SUBSCHEMA_FILES:
            # Read and parse LDIF file
            ldif_file = open(test_file, 'rb')
            ldif_parser = ldap0.ldif.LDIFRecordList(ldif_file, max_entries=1)
            ldif_parser.parse()
            _, subschema_subentry = ldif_parser.all_records[0]
            sub_schema = ldap0.schema.SubSchema(subschema_subentry)


if __name__ == '__main__':
    unittest.main()

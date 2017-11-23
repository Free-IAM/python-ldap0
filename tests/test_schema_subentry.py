# -*- coding: utf-8 -*-
"""
Automatic tests for class ldap0.schema.SubSchema
"""

import unittest

import ldap0.ldif
from ldap0.schema import SubSchema
from ldap0.schema.subentry import SCHEMA_CLASS_MAPPING

TEST_SUBSCHEMA_FILES = (
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
            sub_schema = SubSchema(
                subschema_subentry,
                check_uniqueness=1,
            )
            self.assertEqual(
                len(SCHEMA_CLASS_MAPPING),
                len(sub_schema.name2oid),
            )
            self.assertEqual(
                len(SCHEMA_CLASS_MAPPING),
                len(sub_schema.sed),
            )
            # check whether all schema descriptions were added to SubSchema instance
            for schema_attribute, schema_class in SCHEMA_CLASS_MAPPING.items():
                self.assertEqual(
                    len(subschema_subentry.get(schema_attribute, [])),
                    len(sub_schema.sed[schema_class]),
                )


if __name__ == '__main__':
    unittest.main()

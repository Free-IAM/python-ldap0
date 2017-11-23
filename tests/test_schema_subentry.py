# -*- coding: utf-8 -*-
"""
Automatic tests for class ldap0.schema.SubSchema
"""

import unittest

import ldap0.ldif
from ldap0.schema import SubSchema
from ldap0.schema.util import urlfetch
from ldap0.schema.subentry import SCHEMA_CLASS_MAPPING

TEST_SUBSCHEMA_FILES = (
    'file:tests/ldif/subschema-openldap-all.ldif',
)

class TestSubschemaLDIF(unittest.TestCase):
    """
    test ldap.schema.SubSchema with subschema subentries read from LDIF files
    """

    def test_subschema_file(self):
        for test_file in TEST_SUBSCHEMA_FILES:
            _, sub_schema = urlfetch(test_file, check_uniqueness=1)
            self.assertEqual(
                len(SCHEMA_CLASS_MAPPING),
                len(sub_schema.name2oid),
            )
            self.assertEqual(
                len(SCHEMA_CLASS_MAPPING),
                len(sub_schema.sed),
            )


if __name__ == '__main__':
    unittest.main()

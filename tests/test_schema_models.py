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


class TestSchemaDescriptionClasses(unittest.TestCase):
    """
    test classes in ldap0.schema.models used for parsing and unparsing schema description
    """

    def test_attribute_type(self):
        """
        Test class AttributeType
        """

    def test_object_class(self):
        """
        Test class ObjectClass
        """

    def test_ldap_syntax(self):
        """
        Test class LDAPSyntax
        """

    def test_matching_rule(self):
        """
        Test class MatchingRule
        """

    def test_matching_rule_use(self):
        """
        Test class MatchingRuleUse
        """

    def test_dit_content_rule(self):
        """
        Test class DITContentRule
        """

    def test_dit_structure_rule(self):
        """
        Test class DITStructureRule
        """

    def test_name_form(self):
        """
        Test class NameForm
        """


if __name__ == '__main__':
    unittest.main()

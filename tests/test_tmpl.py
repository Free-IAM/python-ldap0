# -*- coding: utf-8 -*-
"""
Automatic tests for module ldap0.tmpl
"""

from __future__ import absolute_import

# from Python's standard lib
import unittest

from ldap0.tmpl import TemplateEntry


class TestTemplateEntry(unittest.TestCase):
    """
    test ldap0.tmpl.TemplateEntry
    """

    def test_inetorgperson(self):

        class InetOrgPerson(TemplateEntry):
            dn_template = 'cn={first_name} {last_name},ou=People,dc=example,dc=com'
            entry_template = {
                'objectClass': ['top', 'person', 'organizationalPerson', 'inetOrgPerson'],
                'cn': ['{first_name} {last_name}', '{last_name}, {first_name}'],
                'sn': ['{last_name}'],
                'mail': ['{mail_addr}'],
            }

        self.assertEqual(
            InetOrgPerson({
                'first_name': 'Theo',
                'last_name': 'Tester',
                'mail_addr': 'theo.tester@example.com',
            }).ldap_entry(),
            (
                'cn=Theo Tester,ou=People,dc=example,dc=com',
                {
                    'objectClass': ['top', 'person', 'organizationalPerson', 'inetOrgPerson'],
                    'cn': ['Theo Tester', 'Tester, Theo'],
                    'sn': ['Tester'],
                    'mail': ['theo.tester@example.com'],
                }
            )
        )
        # missing mail_addr
        self.assertEqual(
            InetOrgPerson({
                'first_name': 'Theo',
                'last_name': 'Tester',
            }).ldap_entry(),
            (
                'cn=Theo Tester,ou=People,dc=example,dc=com',
                {
                    'objectClass': ['top', 'person', 'organizationalPerson', 'inetOrgPerson'],
                    'cn': ['Theo Tester', 'Tester, Theo'],
                    'sn': ['Tester'],
                }
            )
        )


if __name__ == '__main__':
    unittest.main()

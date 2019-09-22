# -*- coding: utf-8 -*-
"""
Automatic tests for module ldap0.tmpl
"""

# from Python's standard lib
import unittest

from ldap0.tmpl import TemplateEntry


class TestTemplateEntry(unittest.TestCase):
    """
    test ldap0.tmpl.TemplateEntry
    """

    def test001_inetorgperson_bytes(self):
        inet_org_person = TemplateEntry(
            t_dn = 'cn={first_name} {last_name},ou=People,dc=example,dc=com',
            t_entry = {
                'objectClass': ['top', 'person', 'organizationalPerson', 'inetOrgPerson'],
                'cn': ['{first_name} {last_name}', '{last_name}, {first_name}'],
                'sn': ['{last_name}'],
                'mail': ['{mail_addr}'],
            },
        )
        self.assertEqual(
            inet_org_person.ldap_entry({
                b'first_name': b'Theo',
                b'last_name': b'Tester',
                b'mail_addr': b'theo.tester@example.com',
            }),
            (
                'cn=Theo Tester,ou=People,dc=example,dc=com',
                {
                    b'objectClass': [b'top', b'person', b'organizationalPerson', b'inetOrgPerson'],
                    b'cn': [b'Theo Tester', b'Tester, Theo'],
                    b'sn': [b'Tester'],
                    b'mail': [b'theo.tester@example.com'],
                }
            )
        )
        # missing mail_addr
        self.assertEqual(
            inet_org_person.ldap_entry({
                b'first_name': b'Theo',
                b'last_name': b'T\xc3\xa4ster',
            }),
            (
                'cn=Theo Täster,ou=People,dc=example,dc=com',
                {
                    b'objectClass': [b'top', b'person', b'organizationalPerson', b'inetOrgPerson'],
                    b'cn': [b'Theo T\xc3\xa4ster', b'T\xc3\xa4ster, Theo'],
                    b'sn': [b'T\xc3\xa4ster'],
                }
            )
        )

    def test002_unicode(self):
        inet_org_person = TemplateEntry(
            t_dn = 'cn={first_name} {last_name},ou=People,dc=example,dc=com',
            t_entry = {
                'objectClass': ['top', 'person', 'organizationalPerson', 'inetOrgPerson'],
                'cn': ['{first_name} {last_name}', '{last_name}, {first_name}'],
                'sn': ['{last_name}'],
                'mail': ['{mail_addr}'],
                'description': ['Tästuser'],
            },
        )
        self.assertEqual(
            inet_org_person.ldap_entry({
                b'first_name': b'Theo',
                b'last_name': b'Tester',
                b'mail_addr': b'theo.tester@example.com',
            }),
            (
                'cn=Theo Tester,ou=People,dc=example,dc=com',
                {
                    b'objectClass': [b'top', b'person', b'organizationalPerson', b'inetOrgPerson'],
                    b'cn': [b'Theo Tester', b'Tester, Theo'],
                    b'sn': [b'Tester'],
                    b'mail': [b'theo.tester@example.com'],
                    b'description': [b'T\xc3\xa4stuser'],
                }
            )
        )
        # missing mail_addr
        self.assertEqual(
            inet_org_person.ldap_entry({
                b'first_name': b'Theo',
                b'last_name': b'T\xc3\xa4ster',
            }),
            (
                'cn=Theo Täster,ou=People,dc=example,dc=com',
                {
                    b'objectClass': [b'top', b'person', b'organizationalPerson', b'inetOrgPerson'],
                    b'cn': [b'Theo T\xc3\xa4ster', b'T\xc3\xa4ster, Theo'],
                    b'sn': [b'T\xc3\xa4ster'],
                    b'description': [b'T\xc3\xa4stuser'],
                }
            )
        )


if __name__ == '__main__':
    unittest.main()

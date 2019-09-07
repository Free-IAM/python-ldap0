# -*- coding: utf-8 -*-
"""
Automatic tests for module ldap0.modlist
"""

import unittest

import ldap0
import ldap0.schema.models
import ldap0.schema.util

from ldap0.modlist import add_modlist, modify_modlist

class Test001AddModlist(unittest.TestCase):

    add_modlist_tests = [
        (
            {
                'objectClass':[b'person', b'pilotPerson'],
                'cn':[b'Michael Str\303\266der', b'Michael Stroeder'],
                'sn':[b'Str\303\266der'],
                'dummy1':[],
                'dummy2':[b'2'],
                'dummy3':[b''],
            },
            [
                (b'objectClass', [b'person', b'pilotPerson']),
                (b'cn', [b'Michael Str\303\266der', b'Michael Stroeder']),
                (b'sn', [b'Str\303\266der']),
                (b'dummy2', [b'2']),
                (b'dummy3', [b'']),
            ],
            None,
        ),
        (
            {
                'objectClass':[b'person', b'pilotPerson'],
                'cn':[b'Michael Str\303\266der', b'Michael Stroeder'],
                'sn':[b'Str\303\266der'],
                'dummy1':[],
                'dummy2':[b'2'],
                'dummy3':[b''],
            },
            [
                (b'objectClass', [b'person', b'pilotPerson']),
                (b'sn', [b'Str\303\266der']),
                (b'dummy2', [b'2']),
                (b'dummy3', [b'']),
            ],
            ('cn',),
        ),
    ]

    def test_add_modlist(self):
        for entry, test_modlist, ignore_attr_types in self.add_modlist_tests:
            test_modlist.sort()
            result_modlist = add_modlist(entry, ignore_attr_types=ignore_attr_types)
            result_modlist.sort()
            self.assertEqual(
                test_modlist, result_modlist,
                'add_modlist(%s) returns\n%s\ninstead of\n%s.' % (
                    repr(entry),repr(result_modlist),repr(test_modlist)
                )
            )

class Test002ModifyModlist(unittest.TestCase):

    modify_modlist_tests = [
        (
            {
                'objectClass':[b'person', b'pilotPerson'],
                'cn':[b'Michael Str\303\266der', b'Michael Stroeder'],
                'sn':[b'Str\303\266der'],
                'enum':[b'a', b'b', b'c'],
                'c':[b'DE'],
            },
            {
                'objectClass':[b'person', b'inetOrgPerson'],
                'cn':[b'Michael Str\303\266der', b'Michael Stroeder'],
                'sn':[],
                'enum':[b'a', b'b', b'd'],
                'mail':[b'michael@stroeder.com'],
            },
            [],
            [],
            [
                (ldap0.MOD_DELETE, b'objectClass', None),
                (ldap0.MOD_ADD, b'objectClass', [b'person', b'inetOrgPerson']),
                (ldap0.MOD_DELETE, b'c', None),
                (ldap0.MOD_DELETE, b'sn', None),
                (ldap0.MOD_ADD, b'mail', [b'michael@stroeder.com']),
                (ldap0.MOD_DELETE, b'enum', None),
                (ldap0.MOD_ADD, b'enum', [b'a', b'b', b'd']),
            ]
        ),

        (
            {
                'c':[b'DE'],
            },
            {
                'c':[b'FR'],
            },
            [],
            [],
            [
                (ldap0.MOD_DELETE, b'c', None),
                (ldap0.MOD_ADD, b'c', [b'FR']),
            ]
        ),

        # Now a weird test-case for catching all possibilities
        # of removing an attribute with MOD_DELETE,attr_type, None
        (
            {
                'objectClass':[b'person'],
                'cn':[None],
                'sn':[b''],
                'c':[b'DE'],
            },
            {
                'objectClass':[],
                'cn':[],
                'sn':[None],
            },
            [],
            [],
            [
                (ldap0.MOD_DELETE, b'c', None),
                (ldap0.MOD_DELETE, b'objectClass', None),
                (ldap0.MOD_DELETE, b'sn', None),
            ]
        ),

        (
            {
                'objectClass':[b'person'],
                'cn':[b'Michael Str\303\266der', b'Michael Stroeder'],
                'sn':[b'Str\303\266der'],
                'enum':[b'a', b'b', b'C'],
            },
            {
                'objectClass':[b'Person'],
                'cn':[b'Michael Str\303\266der', b'Michael Stroeder'],
                'sn':[],
                'enum':[b'a', b'b', b'c'],
            },
            [],
            ['objectClass'],
            [
                (ldap0.MOD_DELETE, b'sn', None),
                (ldap0.MOD_DELETE, b'enum', None),
                (ldap0.MOD_ADD, b'enum', [b'a', b'b', b'c']),
            ]
        ),

        (
            {
                'objectClass':[b'person'],
                'cn':[b'Michael Str\303\266der', b'Michael Stroeder'],
                'sn':[b'Str\303\266der'],
                'enum':[b'a', b'b', b'C'],
            },
            {
                'objectClass':[b'inetOrgPerson'],
                'cn':[b'Michael Str\303\266der', b'Michael Stroeder'],
                'sn':[],
                'enum':[b'a', b'b', b'c'],
            },
            ['objectClass'],
            [],
            [
                (ldap0.MOD_DELETE, b'sn', None),
                (ldap0.MOD_DELETE, b'enum', None),
                (ldap0.MOD_ADD, b'enum', [b'a', b'b', b'c']),
            ]
        ),

    ]

    def test_modify_modlist(self):
        for old_entry, new_entry, ignore_attr_types, case_ignore_attr_types, test_modlist in self.modify_modlist_tests:
            test_modlist.sort()
            result_modlist = modify_modlist(
                old_entry, new_entry,
                ignore_attr_types=ignore_attr_types,
                case_ignore_attr_types=case_ignore_attr_types
            )
            result_modlist.sort()

            self.assertEqual(
                test_modlist, result_modlist,
                'modify_modlist(%s,%s) returns\n%s\ninstead of\n%s.' % (
                    repr(old_entry),
                    repr(new_entry),
                    repr(result_modlist),
                    repr(test_modlist),
                )
            )


if __name__ == '__main__':
    unittest.main()

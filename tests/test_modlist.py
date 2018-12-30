# -*- coding: utf-8 -*-
"""
Automatic tests for module ldap0.modlist
"""

from __future__ import absolute_import

import unittest

import ldap0

from ldap0.modlist import add_modlist, modify_modlist

class TestAddModlist(unittest.TestCase):

    add_modlist_tests = [
        (
            {
                'objectClass':['person','pilotPerson'],
                'cn':['Michael Str\303\266der','Michael Stroeder'],
                'sn':['Str\303\266der'],
                'dummy1':[],
                'dummy2':['2'],
                'dummy3':[''],
            },
            [
                ('objectClass',['person','pilotPerson']),
                ('cn',['Michael Str\303\266der','Michael Stroeder']),
                ('sn',['Str\303\266der']),
                ('dummy2',['2']),
                ('dummy3',['']),
            ],
            None,
        ),
        (
            {
                'objectClass':['person','pilotPerson'],
                'cn':['Michael Str\303\266der','Michael Stroeder'],
                'sn':['Str\303\266der'],
                'dummy1':[],
                'dummy2':['2'],
                'dummy3':[''],
            },
            [
                ('objectClass',['person','pilotPerson']),
                ('sn',['Str\303\266der']),
                ('dummy2',['2']),
                ('dummy3',['']),
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

class TestModifyModlist(unittest.TestCase):

    modify_modlist_tests = [
        (
            {
                'objectClass':['person','pilotPerson'],
                'cn':['Michael Str\303\266der','Michael Stroeder'],
                'sn':['Str\303\266der'],
                'enum':['a','b','c'],
                'c':['DE'],
            },
            {
                'objectClass':['person','inetOrgPerson'],
                'cn':['Michael Str\303\266der','Michael Stroeder'],
                'sn':[],
                'enum':['a','b','d'],
                'mail':['michael@stroeder.com'],
            },
            [],
            [],
            [
                (ldap0.MOD_DELETE,'objectClass',None),
                (ldap0.MOD_ADD,'objectClass',['person','inetOrgPerson']),
                (ldap0.MOD_DELETE,'c',None),
                (ldap0.MOD_DELETE,'sn',None),
                (ldap0.MOD_ADD,'mail',['michael@stroeder.com']),
                (ldap0.MOD_DELETE,'enum',None),
                (ldap0.MOD_ADD,'enum',['a','b','d']),
            ]
        ),

        (
            {
                'c':['DE'],
            },
            {
                'c':['FR'],
            },
            [],
            [],
            [
                (ldap0.MOD_DELETE,'c',None),
                (ldap0.MOD_ADD,'c',['FR']),
            ]
        ),

        # Now a weird test-case for catching all possibilities
        # of removing an attribute with MOD_DELETE,attr_type,None
        (
            {
                'objectClass':['person'],
                'cn':[None],
                'sn':[''],
                'c':['DE'],
            },
            {
                'objectClass':[],
                'cn':[],
                'sn':[None],
            },
            [],
            [],
            [
                (ldap0.MOD_DELETE,'c',None),
                (ldap0.MOD_DELETE,'objectClass',None),
                (ldap0.MOD_DELETE,'sn',None),
            ]
        ),

        (
            {
                'objectClass':['person'],
                'cn':['Michael Str\303\266der','Michael Stroeder'],
                'sn':['Str\303\266der'],
                'enum':['a','b','C'],
            },
            {
                'objectClass':['Person'],
                'cn':['Michael Str\303\266der','Michael Stroeder'],
                'sn':[],
                'enum':['a','b','c'],
            },
            [],
            ['objectClass'],
            [
                (ldap0.MOD_DELETE,'sn',None),
                (ldap0.MOD_DELETE,'enum',None),
                (ldap0.MOD_ADD,'enum',['a','b','c']),
            ]
        ),

        (
            {
                'objectClass':['person'],
                'cn':['Michael Str\303\266der','Michael Stroeder'],
                'sn':['Str\303\266der'],
                'enum':['a','b','C'],
            },
            {
                'objectClass':['inetOrgPerson'],
                'cn':['Michael Str\303\266der','Michael Stroeder'],
                'sn':[],
                'enum':['a','b','c'],
            },
            ['objectClass'],
            [],
            [
                (ldap0.MOD_DELETE,'sn',None),
                (ldap0.MOD_DELETE,'enum',None),
                (ldap0.MOD_ADD,'enum',['a','b','c']),
            ]
        ),

    ]

    def test_modify_modlist(self):
        for old_entry, new_entry, ignore_attr_types, case_ignore_attr_types, test_modlist in self.modify_modlist_tests:
            test_modlist.sort()
            result_modlist = modify_modlist(
                old_entry, new_entry,
                ignore_attr_types=ignore_attr_types,
                case_ignore_attr_types=case_ignore_attr_types)
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

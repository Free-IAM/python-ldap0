# -*- coding: utf-8 -*-
"""
Automatic tests for module ldap0.dn
"""

from __future__ import absolute_import

# from Python's standard lib
import unittest

import ldap0.dn
from ldap0.dn import DNObj


class TestDNFunctions(unittest.TestCase):
    """
    test functions in ldap0.dn
    """

    def test_is_dn(self):
        """
        test function is_dn()
        """
        self.assertEqual(ldap0.dn.is_dn('foobar,dc=example,dc=com'), False)
        self.assertEqual(ldap0.dn.is_dn('-cn=foobar,dc=example,dc=com'), False)
        self.assertEqual(ldap0.dn.is_dn(';cn=foobar,dc=example,dc=com'), False)
        self.assertEqual(ldap0.dn.is_dn(',cn=foobar,dc=example,dc=com'), False)
        self.assertEqual(ldap0.dn.is_dn('cn=foobar,dc=example,dc=com,'), False)
        self.assertEqual(ldap0.dn.is_dn('uid=xkcd,cn=foobar,dc=example,dc=com'), True)
        self.assertEqual(
            ldap0.dn.is_dn(
                'cn=\xc3\xa4\xc3\xb6\xc3\xbc\xc3\x84\xc3\x96\xc3\x9c.o=\xc3\xa4\xc3\xb6\xc3\xbc\xc3\x84\xc3\x96\xc3\x9c\xc3\x9f'
            ),
            True
        )

    def test_escape_dn_chars(self):
        """
        test function escape_dn_chars()
        """
        self.assertEqual(ldap0.dn.escape_dn_chars('foobar'), 'foobar')
        self.assertEqual(ldap0.dn.escape_dn_chars('foo,bar'), 'foo\\,bar')
        self.assertEqual(ldap0.dn.escape_dn_chars('foo=bar'), 'foo\\=bar')
        self.assertEqual(ldap0.dn.escape_dn_chars('foo#bar'), 'foo#bar')
        self.assertEqual(ldap0.dn.escape_dn_chars('#foobar'), '\\#foobar')
        self.assertEqual(ldap0.dn.escape_dn_chars('foo bar'), 'foo bar')
        self.assertEqual(ldap0.dn.escape_dn_chars(' foobar'), '\\ foobar')
        self.assertEqual(ldap0.dn.escape_dn_chars('  foobar'), '\\  foobar')
        self.assertEqual(ldap0.dn.escape_dn_chars('foobar  '), 'foobar \\ ')
        self.assertEqual(ldap0.dn.escape_dn_chars(' '), '\\ ')

    def test_str2dn(self):
        """
        test function str2dn()
        """
        self.assertEqual(ldap0.dn.str2dn(''), ())
        self.assertEqual(
            ldap0.dn.str2dn('uid=test42,ou=Testing,dc=example,dc=com'),
            (
                (('uid', 'test42', 1),),
                (('ou', 'Testing', 1),),
                (('dc', 'example', 1),),
                (('dc', 'com', 1),)
            )
        )
        self.assertEqual(
            ldap0.dn.str2dn('uid=test42+uidNumber=42,ou=Testing,dc=example,dc=com'),
            (
                (('uid', 'test42', 1), ('uidNumber', '42', 1),),
                (('ou', 'Testing', 1),),
                (('dc', 'example', 1),),
                (('dc', 'com', 1),)
            )
        )
        self.assertEqual(
            ldap0.dn.str2dn('uid=test42,ou=Testing,dc=example,dc=com', flags=0),
            (
                (('uid', 'test42', 1),),
                (('ou', 'Testing', 1),),
                (('dc', 'example', 1),),
                (('dc', 'com', 1),)
            )
        )
        self.assertEqual(
            ldap0.dn.str2dn('uid=test42; ou=Testing; dc=example; dc=com', flags=ldap0.DN_FORMAT_LDAPV2),
            (
                (('uid', 'test42', 1),),
                (('ou', 'Testing', 1),),
                (('dc', 'example', 1),),
                (('dc', 'com', 1),)
            )
        )
        self.assertEqual(
            ldap0.dn.str2dn('uid=test\\, 42,ou=Testing,dc=example,dc=com', flags=0),
            (
                (('uid', 'test, 42', 1),),
                (('ou', 'Testing', 1),),
                (('dc', 'example', 1),),
                (('dc', 'com', 1),)
            )
        )
        self.assertEqual(
            ldap0.dn.str2dn('cn=\xc3\xa4\xc3\xb6\xc3\xbc\xc3\x84\xc3\x96\xc3\x9c\xc3\x9f,dc=example,dc=com', flags=0),
            (
                (('cn', '\xc3\xa4\xc3\xb6\xc3\xbc\xc3\x84\xc3\x96\xc3\x9c\xc3\x9f', 4),),
                (('dc', 'example', 1),),
                (('dc', 'com', 1),)
            )
        )
        self.assertEqual(
            ldap0.dn.str2dn('cn=\\c3\\a4\\c3\\b6\\c3\\bc\\c3\\84\\c3\\96\\c3\\9c\\c3\\9f,dc=example,dc=com', flags=0),
            (
                (('cn', '\xc3\xa4\xc3\xb6\xc3\xbc\xc3\x84\xc3\x96\xc3\x9c\xc3\x9f', 4),),
                (('dc', 'example', 1),),
                (('dc', 'com', 1),)
            )
        )

    def test_dn2str(self):
        """
        test function dn2str()
        """
        self.assertEqual(ldap0.dn.str2dn(''), ())
        self.assertEqual(
            ldap0.dn.dn2str((
                (('uid', 'test42', 1),),
                (('ou', 'Testing', 1),),
                (('dc', 'example', 1),),
                (('dc', 'com', 1),)
            )),
            'uid=test42,ou=Testing,dc=example,dc=com',
        )
        self.assertEqual(
            ldap0.dn.dn2str((
                (('uid', 'test42', 1),),
                (('ou', 'Testing', 1),),
                (('dc', 'example', 1),),
                (('dc', 'com', 1),)
            )),
            'uid=test42,ou=Testing,dc=example,dc=com'
        )
        self.assertEqual(
            ldap0.dn.dn2str((
                (('uid', 'test42', 1), ('uidNumber', '42', 1),),
                (('ou', 'Testing', 1),),
                (('dc', 'example', 1),),
                (('dc', 'com', 1),),
            )),
            'uid=test42+uidNumber=42,ou=Testing,dc=example,dc=com'
        )
        self.assertEqual(
            ldap0.dn.dn2str((
                (('uid', 'test, 42', 1),),
                (('ou', 'Testing', 1),),
                (('dc', 'example', 1),),
                (('dc', 'com', 1),),
            )),
            'uid=test\\, 42,ou=Testing,dc=example,dc=com'
        )
        self.assertEqual(
            ldap0.dn.dn2str((
                (('cn', '\xc3\xa4\xc3\xb6\xc3\xbc\xc3\x84\xc3\x96\xc3\x9c\xc3\x9f', 4),),
                (('dc', 'example', 1),),
                (('dc', 'com', 1),),
            )),
            'cn=\xc3\xa4\xc3\xb6\xc3\xbc\xc3\x84\xc3\x96\xc3\x9c\xc3\x9f,dc=example,dc=com'
        )
        self.assertEqual(
            ldap0.dn.dn2str((
                (('cn', '\xc3\xa4\xc3\xb6\xc3\xbc\xc3\x84\xc3\x96\xc3\x9c\xc3\x9f', 4),),
                (('dc', 'example', 1),),
                (('dc', 'com', 1),),
            )),
            'cn=\xc3\xa4\xc3\xb6\xc3\xbc\xc3\x84\xc3\x96\xc3\x9c\xc3\x9f,dc=example,dc=com'
        )

    def test_explode_dn(self):
        """
        test function explode_dn()
        """
        self.assertEqual(ldap0.dn.explode_dn(''), [])
        self.assertEqual(
            ldap0.dn.explode_dn('uid=test42,ou=Testing,dc=example,dc=com'),
            ('uid=test42', 'ou=Testing', 'dc=example', 'dc=com')
        )
        self.assertEqual(
            ldap0.dn.explode_dn('uid=test42,ou=Testing,dc=example,dc=com', flags=0),
            ('uid=test42', 'ou=Testing', 'dc=example', 'dc=com')
        )
        self.assertEqual(
            ldap0.dn.explode_dn('uid=test42; ou=Testing; dc=example; dc=com', flags=ldap0.DN_FORMAT_LDAPV2),
            ('uid=test42', 'ou=Testing', 'dc=example', 'dc=com')
        )
        self.assertEqual(
            ldap0.dn.explode_dn('uid=test42,ou=Testing,dc=example,dc=com', notypes=True),
            ('test42', 'Testing', 'example', 'com')
        )
        self.assertEqual(
            ldap0.dn.explode_dn('uid=test\\, 42,ou=Testing,dc=example,dc=com', flags=0),
            ('uid=test\\, 42', 'ou=Testing', 'dc=example', 'dc=com')
        )
        self.assertEqual(
            ldap0.dn.explode_dn('cn=\xc3\xa4\xc3\xb6\xc3\xbc\xc3\x84\xc3\x96\xc3\x9c\xc3\x9f,dc=example,dc=com', flags=0),
            ('cn=\xc3\xa4\xc3\xb6\xc3\xbc\xc3\x84\xc3\x96\xc3\x9c\xc3\x9f', 'dc=example', 'dc=com')
        )
        self.assertEqual(
            ldap0.dn.explode_dn('cn=\\c3\\a4\\c3\\b6\\c3\\bc\\c3\\84\\c3\\96\\c3\\9c\\c3\\9f,dc=example,dc=com', flags=0),
            ('cn=\xc3\xa4\xc3\xb6\xc3\xbc\xc3\x84\xc3\x96\xc3\x9c\xc3\x9f', 'dc=example', 'dc=com')
        )

    def test_explode_rdn(self):
        """
        test function explode_rdn()
        """
        self.assertEqual(ldap0.dn.explode_rdn(''), ())
        self.assertEqual(
            ldap0.dn.explode_rdn('uid=test42',),
            ('uid=test42',)
        )
        self.assertEqual(
            ldap0.dn.explode_rdn('uid=test42', notypes=False, flags=0),
            ('uid=test42',)
        )
        self.assertEqual(
            ldap0.dn.explode_rdn('uid=test42', notypes=0, flags=0),
            ('uid=test42',)
        )
        self.assertEqual(
            ldap0.dn.explode_rdn('uid=test42+uidNumber=42', flags=0),
            ('uid=test42', 'uidNumber=42')
        )
        self.assertEqual(
            ldap0.dn.explode_rdn('uid=test42', notypes=True),
            ('test42',)
        )
        self.assertEqual(
            ldap0.dn.explode_rdn('uid=test42', notypes=1),
            ('test42',)
        )
        self.assertEqual(
            ldap0.dn.explode_rdn('uid=test\\+ 42', flags=0),
            ('uid=test\\+ 42',)
        )
        self.assertEqual(
            ldap0.dn.explode_rdn('cn=\xc3\xa4\xc3\xb6\xc3\xbc\xc3\x84\xc3\x96\xc3\x9c\xc3\x9f', flags=0),
            ('cn=\xc3\xa4\xc3\xb6\xc3\xbc\xc3\x84\xc3\x96\xc3\x9c\xc3\x9f',)
        )
        self.assertEqual(
            ldap0.dn.explode_rdn('cn=\\c3\\a4\\c3\\b6\\c3\\bc\\c3\\84\\c3\\96\\c3\\9c\\c3\\9f', flags=0),
            ('cn=\xc3\xa4\xc3\xb6\xc3\xbc\xc3\x84\xc3\x96\xc3\x9c\xc3\x9f',)
        )


class TestDNObj(unittest.TestCase):
    """
    test class ldap0.dn.DNObj
    """

    def test_dnobj_simple(self):
        self.assertEqual(list(DNObj.fromstring('')), [])
        self.assertEqual(len(DNObj.fromstring('')), 0)
        self.assertEqual(len(DNObj.fromstring('ou=dept1  ,  dc=example, dc=com')), 3)
        self.assertEqual(list(DNObj.fromstring('').rdn()), [])
        self.assertEqual(
            str(DNObj.fromstring('ou=dept1  ,  dc=example, dc=com').rdn()),
            'ou=dept1'
        )
        self.assertEqual(
            str(DNObj.fromstring('ou=dept1,  dc=example, dc=com').parent()),
            'dc=example,dc=com'
        )
        for dn_str in (
                '',
                'dc=example,dc=com',
                'ou=dept1,dc=example,dc=com',
                'cn=\xc3\xa4\xc3\xb6\xc3\xbc\xc3\x84\xc3\x96\xc3\x9c\xc3\x9f,ou=\xc3\xa4\xc3\xb6\xc3\xbc\xc3\x84\xc3\x96\xc3\x9c\xc3\x9f',
            ):
            self.assertEqual(str(DNObj.fromstring(dn_str, flags=0)), dn_str)

    def test_weird_whitespaces(self):
        self.assertEqual(
            DNObj.fromstring('uid = test42 + uidNumber = 42, dc = example , dc = com'),
            DNObj((
                (
                    ('uid', 'test42', 1),
                    ('uidNumber', '42', 1)
                ),
                (('dc', 'example', 1),),
                (('dc', 'com', 1),)
            ))
        )

    def test_repr(self):
        self.assertEqual(
            repr(DNObj((
                (
                    ('uid', 'test42', 1),
                    ('uidNumber', '42', 1)
                ),
                (('dc', 'example', 1),),
                (('dc', 'com', 1),)
            ))),
            "DNObj(((('uid', 'test42', 1), ('uidNumber', '42', 1)), (('dc', 'example', 1),), (('dc', 'com', 1),)))"
        )

    def test_hashable(self):
        dn = DNObj((
            (
                ('uid', 'test42', 1),
                ('uidNumber', '42', 1)
            ),
            (('dc', 'example', 1),),
            (('dc', 'com', 1),)
        ))
        data = {dn: 'foo'}
        self.assertEqual(data[dn], 'foo')

    def test_dnobj_slicing(self):
        dn = DNObj.fromstring('ou=dept1  ,  dc=example, dc=com')
        self.assertEqual(dn[0], (('ou', 'dept1', 1),))
        self.assertEqual(dn[1], (('dc', 'example', 1),))
        self.assertEqual(dn[2], (('dc', 'com', 1),))
        self.assertEqual(dn[:], dn)
        with self.assertRaises(IndexError):
            self.assertEqual(dn[3], ())
        self.assertEqual(
            reversed(DNObj.fromstring('ou=dept1,dc=example,dc=com')),
            DNObj.fromstring('dc=com,dc=example,ou=dept1')
        )
        self.assertEqual(
            DNObj.fromstring('ou=dept1,dc=example,dc=com')[1:],
            DNObj.fromstring('dc=example,dc=com')
        )
        self.assertEqual(
            DNObj.fromstring('ou=dept1,dc=example,dc=com')[:2],
            DNObj.fromstring('ou=dept1,dc=example')
        )
        domain = 'sub3.sub2.sub1.example.com'
        dns_labels = domain.split('.')
        dno = DNObj.fromdomain(domain)
        for i, dn_comp in enumerate(dno):
            self.assertEqual(dn_comp[0][0], 'dc')
            self.assertEqual(dn_comp[0][1], dns_labels[i])
            self.assertEqual(dno[i], dn_comp)

    def test_dnobj_domain(self):
        self.assertEqual(
            str(DNObj.fromdomain('example.com')),
            'dc=example,dc=com'
        )
        self.assertEqual(
            DNObj.fromdomain('example.com').domain(),
            'example.com'
        )
        self.assertEqual(
            DNObj.fromstring('ou=dept1,  dc=example, dc=com').domain(only_dc=False),
            'example.com'
        )
        with self.assertRaises(ValueError):
            self.assertEqual(
                DNObj.fromstring('ou=dept1,  dc=example, dc=com').domain(only_dc=True),
                'example.com'
            )
        with self.assertRaises(ValueError):
            self.assertEqual(
                DNObj.fromstring('ou=dept1,  dc=example, dc=com+dc=net').domain(),
                'example.com'
            )


    def test_dnobj_add(self):
        self.assertEqual(
            DNObj.fromdomain('dept1')+DNObj.fromdomain('example.com'),
            DNObj.fromdomain('dept1.example.com'),
        )
        self.assertEqual(
            str(DNObj.fromdomain('dept1')+DNObj.fromdomain('example.com')),
            'dc=dept1,dc=example,dc=com',
        )
        self.assertEqual(
            (DNObj.fromdomain('dept1')+DNObj.fromdomain('example.com')).domain(),
            'dept1.example.com',
        )


if __name__ == '__main__':
    unittest.main()

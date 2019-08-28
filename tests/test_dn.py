# -*- coding: utf-8 -*-
"""
Automatic tests for module ldap0.dn
"""

# from Python's standard lib
import sys
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
        self.assertEqual(ldap0.dn.is_dn('cn=äöüÄÖÜß'), True)

    def test_escape_str(self):
        """
        test function escape_str()
        """
        self.assertEqual(ldap0.dn.escape_str(''), '')
        self.assertEqual(ldap0.dn.escape_str('foobar'), 'foobar')
        self.assertEqual(ldap0.dn.escape_str('foo,bar'), 'foo\\,bar')
        self.assertEqual(ldap0.dn.escape_str('foo=bar'), 'foo\\=bar')
        self.assertEqual(ldap0.dn.escape_str('foo#bar'), 'foo#bar')
        self.assertEqual(ldap0.dn.escape_str('#foobar'), '\\#foobar')
        self.assertEqual(ldap0.dn.escape_str('foo bar'), 'foo bar')
        self.assertEqual(ldap0.dn.escape_str(' foobar'), '\\ foobar')
        self.assertEqual(ldap0.dn.escape_str('  foobar'), '\\  foobar')
        self.assertEqual(ldap0.dn.escape_str('foobar  '), 'foobar \\ ')
        self.assertEqual(ldap0.dn.escape_str(' '), '\\ ')
        self.assertEqual(ldap0.dn.escape_str('  '), '\\ \\ ')


class TestDNObj(unittest.TestCase):
    """
    test class ldap0.dn.DNObj
    """

    def test_simple(self):
        self.assertEqual(DNObj.fromstring(''), DNObj((())))
        self.assertEqual(DNObj.fromstring('').rdn(), DNObj((())))
        self.assertEqual(DNObj.fromstring('').rdn_attrs(), {})
        self.assertEqual(len(DNObj.fromstring('')), 0)
        self.assertEqual(len(DNObj.fromstring('ou=dept1  ,  dc=example, dc=com')), 3)
        self.assertEqual(
            str(DNObj.fromstring('ou=dept1  ,  dc=example, dc=com').rdn()),
            'ou=dept1'
        )
        self.assertEqual(
            DNObj.fromstring('ou=dept1  ,  dc=example, dc=com').rdn_attrs(),
            {'ou': 'dept1'}
        )
        self.assertEqual(
            DNObj.fromstring('ou=dept1 + mail=test@example.com ,  dc=example, dc=com').rdn_attrs(),
            {'mail': 'test@example.com', 'ou': 'dept1'}
        )
        self.assertEqual(
            str(DNObj.fromstring('ou=dept1,  dc=example, dc=com').parent()),
            'dc=example,dc=com'
        )
        for dn_str in (
                '',
                'dc=example,dc=com',
                'ou=dept1,dc=example,dc=com',
                'cn=äöüÄÖÜß',
                'cn=Michael Ströder,dc=example,dc=com',
            ):
            dn_obj = DNObj.fromstring(dn_str, flags=0)
            self.assertEqual(bytes(dn_obj), dn_str.encode('utf-8'))
            self.assertEqual(dn_obj.__str__(), dn_str)

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
        if sys.version_info.major >= 3:
            correct_repr = "DNObj(((('uid', 'test42', 1), ('uidNumber', '42', 1)), (('dc', 'example', 1),), (('dc', 'com', 1),)))"
        else:
            correct_repr = "DNObj(((('uid', 'test42', 1), ('uidNumber', '42', 1)), (('dc', 'example', 1),), (('dc', 'com', 1),)))"
        self.assertEqual(
            repr(DNObj((
                (
                    ('uid', 'test42', 1),
                    ('uidNumber', '42', 1)
                ),
                (('dc', 'example', 1),),
                (('dc', 'com', 1),)
            ))),
            correct_repr
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

    def test_slicing(self):
        dn = DNObj.fromstring('ou=dept1  ,  dc=example, dc=com')
        self.assertEqual(dn[0], (('ou', 'dept1', 1),))
        self.assertEqual(dn[1], (('dc', 'example', 1),))
        self.assertEqual(dn[2], (('dc', 'com', 1),))
        self.assertEqual(DNObj(dn[:]), dn)
        with self.assertRaises(IndexError):
            self.assertEqual(dn[3], ())
        self.assertEqual(
            reversed(DNObj.fromstring('ou=dept1,dc=example,dc=com')),
            DNObj.fromstring('dc=com,dc=example,ou=dept1')
        )
        self.assertEqual(
            DNObj.fromstring('ou=dept1,dc=example,dc=com')[1:],
            DNObj.fromstring('dc=example,dc=com')[:]
        )
        self.assertEqual(
            DNObj.fromstring('ou=dept1,dc=example,dc=com')[:2],
            DNObj.fromstring('ou=dept1,dc=example')[:]
        )
        self.assertEqual(
            DNObj.fromstring('ou=dept1,dc=example,dc=com').slice(1, None),
            DNObj.fromstring('dc=example,dc=com')
        )
        self.assertEqual(
            DNObj.fromstring('ou=dept1,dc=example,dc=com').slice(None, 2),
            DNObj.fromstring('ou=dept1,dc=example')
        )
        domain = 'sub3.sub2.sub1.example.com'
        dns_labels = domain.split('.')
        dno = DNObj.fromdomain(domain)
        for i, dn_comp in enumerate(dno):
            self.assertEqual(dn_comp[0][0], 'dc')
            self.assertEqual(dn_comp[0][1], dns_labels[i])
            self.assertEqual(dno[i], dn_comp)

    def test_domain(self):
        self.assertEqual(
            str(DNObj.fromdomain('example.com')),
            'dc=example,dc=com'
        )
        self.assertEqual(
            DNObj.fromdomain('example.com').domain(),
            'example.com'
        )
        self.assertEqual(
            DNObj.fromdomain(u'ströder.de').domain(),
            u'ströder.de'.encode('idna').decode('ascii')
        )
        self.assertEqual(
            DNObj.fromstring('ou=dept1,  dc=example, dc=com').domain(only_dc=False),
            'example.com'
        )
        with self.assertRaises(ValueError):
            DNObj.fromstring('ou=dept1,dc=example,dc=com').domain(only_dc=True)
        with self.assertRaises(ValueError):
            DNObj.fromstring('ou=dept1,dc=example,dc=com+dc=net').domain()
        with self.assertRaises(ValueError):
            DNObj.fromstring('ou=foo+dc=example,dc=com').domain()


    def test_add(self):
        self.assertEqual(
            DNObj.fromdomain('dept1')+DNObj.fromdomain('example.com'),
            DNObj.fromdomain('dept1.example.com'),
        )
        self.assertEqual(
            bytes(DNObj.fromdomain('dept1')+DNObj.fromdomain('example.com')),
            b'dc=dept1,dc=example,dc=com',
        )
        self.assertEqual(
            (DNObj.fromdomain('dept1')+DNObj.fromdomain('example.com')).domain(),
            'dept1.example.com',
        )

    def test_match(self):
        dn_obj = DNObj.fromdomain('example.com')
        self.assertEqual(
            dn_obj.match([DNObj.fromdomain('example.com')]),
            DNObj.fromdomain('example.com')
        )
        self.assertEqual(
            dn_obj.match([DNObj.fromdomain('sub1.example.com')]),
            DNObj((()))
        )
        self.assertEqual(
            dn_obj.match([
                DNObj.fromdomain('example.com'),
                DNObj.fromdomain('example.net'),
            ]),
            DNObj.fromdomain('example.com')
        )
        # sub entry match
        dn_obj = DNObj.fromdomain('sub1.example.com')
        self.assertEqual(
            dn_obj.match([DNObj.fromdomain('example.com')]),
            DNObj.fromdomain('example.com')
        )
        # no match
        dn_obj = DNObj.fromdomain('example.net')
        self.assertEqual(
            dn_obj.match([DNObj.fromdomain('example.com')]),
            DNObj((()))
        )
        # empty
        self.assertEqual(
            DNObj((())).match([DNObj((()))]),
            DNObj((()))
        )

if __name__ == '__main__':
    unittest.main()

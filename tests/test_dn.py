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
        self.assertEqual(ldap0.dn.is_dn('-'), False)
        self.assertEqual(ldap0.dn.is_dn(''), True)

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

    def test001_simple(self):
        self.assertEqual(DNObj.from_str(''), DNObj((())))
        self.assertEqual(DNObj.from_str('').rdn(), DNObj((())))
        self.assertEqual(DNObj.from_str('').rdn_attrs(), {})
        self.assertEqual(len(DNObj.from_str('')), 0)
        self.assertEqual(len(DNObj.from_str('ou=dept1  ,  dc=example, dc=com')), 3)
        self.assertEqual(
            str(DNObj.from_str('ou=dept1  ,  dc=example, dc=com').rdn()),
            'ou=dept1'
        )
        self.assertEqual(
            DNObj.from_str('ou=dept1  ,  dc=example, dc=com').rdn_attrs(),
            {'ou': 'dept1'}
        )
        self.assertEqual(
            DNObj.from_str('ou=dept1 + mail=test@example.com ,  dc=example, dc=com').rdn_attrs(),
            {'mail': 'test@example.com', 'ou': 'dept1'}
        )
        self.assertEqual(
            str(DNObj.from_str('ou=dept1,  dc=example, dc=com').parent()),
            'dc=example,dc=com'
        )
        for dn_str in (
                '',
                'dc=example,dc=com',
                'ou=dept1,dc=example,dc=com',
                'cn=äöüÄÖÜß',
                'cn=Michael Ströder,dc=example,dc=com',
            ):
            dn_obj = DNObj.from_str(dn_str, flags=0)
            self.assertEqual(bytes(dn_obj), dn_str.encode('utf-8'))
            self.assertEqual(dn_obj.__str__(), dn_str)

    def test002_weird_whitespaces(self):
        self.assertEqual(
            DNObj.from_str('uid = test42 + uidNumber = 42, dc = example , dc = com'),
            DNObj((
                (
                    ('uid', 'test42'),
                    ('uidNumber', '42')
                ),
                (('dc', 'example'),),
                (('dc', 'com'),)
            ))
        )

    def test003_repr(self):
        if sys.version_info.major >= 3:
            correct_repr = "DNObj(((('uid', 'test42'), ('uidNumber', '42')), (('dc', 'example'),), (('dc', 'com'),)))"
        else:
            correct_repr = "DNObj(((('uid', 'test42'), ('uidNumber', '42')), (('dc', 'example'),), (('dc', 'com'),)))"
        self.assertEqual(
            repr(DNObj((
                (
                    ('uid', 'test42'),
                    ('uidNumber', '42')
                ),
                (('dc', 'example'),),
                (('dc', 'com'),)
            ))),
            correct_repr
        )

    def test004_hashable(self):
        dn = DNObj((
            (
                ('uid', 'test42'),
                ('uidNumber', '42')
            ),
            (('dc', 'example'),),
            (('dc', 'com'),)
        ))
        data = {dn: 'foo'}
        self.assertEqual(data[dn], 'foo')
        self.assertEqual(set([dn]), set([dn, dn]))

    def test005_slicing(self):
        dn = DNObj.from_str('ou=dept1  ,  dc=example, dc=com')
        self.assertEqual(dn[0], (('ou', 'dept1'),))
        self.assertEqual(dn[1], (('dc', 'example'),))
        self.assertEqual(dn[2], (('dc', 'com'),))
        self.assertEqual(DNObj(dn[:]), dn)
        with self.assertRaises(IndexError):
            self.assertEqual(dn[3], ())
        self.assertEqual(
            reversed(DNObj.from_str('ou=dept1,dc=example,dc=com')),
            DNObj.from_str('dc=com,dc=example,ou=dept1')
        )
        self.assertEqual(
            DNObj.from_str('ou=dept1,dc=example,dc=com')[1:],
            DNObj.from_str('dc=example,dc=com')[:]
        )
        self.assertEqual(
            DNObj.from_str('ou=dept1,dc=example,dc=com')[:2],
            DNObj.from_str('ou=dept1,dc=example')[:]
        )
        self.assertEqual(
            DNObj.from_str('ou=dept1,dc=example,dc=com').slice(1, None),
            DNObj.from_str('dc=example,dc=com')
        )
        self.assertEqual(
            DNObj.from_str('ou=dept1,dc=example,dc=com').slice(None, 2),
            DNObj.from_str('ou=dept1,dc=example')
        )
        domain = 'sub3.sub2.sub1.example.com'
        dns_labels = domain.split('.')
        dno = DNObj.from_domain(domain)
        for i, dn_comp in enumerate(dno):
            self.assertEqual(dn_comp[0][0], 'dc')
            self.assertEqual(dn_comp[0][1], dns_labels[i])
            self.assertEqual(dno[i], dn_comp)

    def test006_domain(self):
        self.assertEqual(
            str(DNObj.from_domain('example.com')),
            'dc=example,dc=com'
        )
        self.assertEqual(
            DNObj.from_domain('example.com').domain(),
            'example.com'
        )
        self.assertEqual(
            DNObj.from_domain(u'ströder.de').domain(),
            u'ströder.de'.encode('idna').decode('ascii')
        )
        self.assertEqual(
            DNObj.from_str('ou=dept1,  dc=example, dc=com').domain(only_dc=False),
            'example.com'
        )
        with self.assertRaises(ValueError):
            DNObj.from_str('ou=dept1,dc=example,dc=com').domain(only_dc=True)
        with self.assertRaises(ValueError):
            DNObj.from_str('ou=dept1,dc=example,dc=com+dc=net').domain()
        with self.assertRaises(ValueError):
            DNObj.from_str('ou=foo+dc=example,dc=com').domain()


    def test007_add(self):
        self.assertEqual(
            DNObj.from_domain('dept1')+DNObj.from_domain('example.com'),
            DNObj.from_domain('dept1.example.com'),
        )
        self.assertEqual(
            bytes(DNObj.from_domain('dept1')+DNObj.from_domain('example.com')),
            b'dc=dept1,dc=example,dc=com',
        )
        self.assertEqual(
            (DNObj.from_domain('dept1')+DNObj.from_domain('example.com')).domain(),
            'dept1.example.com',
        )

    def test008_match(self):
        dn_obj = DNObj.from_domain('example.com')
        self.assertEqual(
            dn_obj.match([DNObj.from_domain('example.com')]),
            DNObj.from_domain('example.com')
        )
        self.assertEqual(
            dn_obj.match([DNObj.from_domain('sub1.example.com')]),
            DNObj((()))
        )
        self.assertEqual(
            dn_obj.match([
                DNObj.from_domain('example.com'),
                DNObj.from_domain('example.net'),
            ]),
            DNObj.from_domain('example.com')
        )
        self.assertEqual(
            dn_obj.match([
                DNObj.from_str('CN=Michael, dc=example, dc=com'),
                DNObj.from_str('DC=example, DC=com'),
            ]),
            DNObj.from_domain('example.com'),
        )
        self.assertEqual(
            DNObj.from_str('cn=Person,dc=foo,dc=example,dc=com').match([
                DNObj.from_domain('foo.example.com'),
                DNObj.from_domain('bar.example.com'),
            ]),
            DNObj.from_domain('foo.example.com'),
        )
        # sub entry match
        dn_obj = DNObj.from_domain('sub1.example.com')
        self.assertEqual(
            dn_obj.match([
                DNObj.from_domain('sub2.example.com'),
                DNObj.from_domain('example.com'),
                DNObj.from_domain('example.net'),
            ]),
            DNObj.from_domain('example.com')
        )
        self.assertEqual(
            dn_obj.match([
                DNObj.from_domain('sub1.example.com'),
                DNObj.from_domain('example.com'),
            ]),
            DNObj.from_domain('sub1.example.com')
        )
        # no match
        dn_obj = DNObj.from_domain('example.net')
        self.assertEqual(
            dn_obj.match([
                DNObj.from_domain('example.com'),
            ]),
            DNObj((()))
        )
        self.assertEqual(
            dn_obj.match([
                DNObj.from_domain('sub2.example.net'),
                DNObj.from_domain('example.com'),
            ]),
            DNObj((()))
        )
        # empty
        self.assertEqual(
            DNObj((())).match([DNObj((()))]),
            DNObj((()))
        )

    def test009_parents(self):
        self.assertEqual(
            DNObj.from_domain('example.com').parents(),
            [DNObj.from_domain('com')]
        )
        self.assertEqual(
            DNObj.from_domain('sub1.example.com').parents(),
            [
                DNObj.from_domain('example.com'),
                DNObj.from_domain('com'),
            ]
        )

    def test010_equals(self):
        self.assertTrue(
            DNObj.from_str('cn=Michael, dc=example, dc=com')==DNObj.from_str('CN=Michael, DC=example, DC=com')
        )
        self.assertFalse(
            DNObj.from_str('uid=Michael, dc=example, dc=com')==DNObj.from_str('CN=Michael, DC=example, DC=com')
        )
        self.assertFalse(
            DNObj.from_str('cn=Michael, dc=example, dc=com')==DNObj.from_str('CN=Mike, DC=example, DC=com')
        )


if __name__ == '__main__':
    unittest.main()

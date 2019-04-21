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
        self.assertEqual(ldap0.dn.is_dn(b'foobar,dc=example,dc=com'), False)
        self.assertEqual(ldap0.dn.is_dn(b'-cn=foobar,dc=example,dc=com'), False)
        self.assertEqual(ldap0.dn.is_dn(b';cn=foobar,dc=example,dc=com'), False)
        self.assertEqual(ldap0.dn.is_dn(b',cn=foobar,dc=example,dc=com'), False)
        self.assertEqual(ldap0.dn.is_dn(b'cn=foobar,dc=example,dc=com,'), False)
        self.assertEqual(ldap0.dn.is_dn(b'uid=xkcd,cn=foobar,dc=example,dc=com'), True)
        self.assertEqual(
            ldap0.dn.is_dn(
                b'cn=\xc3\xa4\xc3\xb6\xc3\xbc\xc3\x84\xc3\x96\xc3\x9c.o=\xc3\xa4\xc3\xb6\xc3\xbc\xc3\x84\xc3\x96\xc3\x9c\xc3\x9f'
            ),
            True
        )

    def test_escape_dn_chars(self):
        """
        test function escape_dn_chars()
        """
        self.assertEqual(ldap0.dn.escape_dn_chars(b''), b'')
        self.assertEqual(ldap0.dn.escape_dn_chars(b'foobar'), b'foobar')
        self.assertEqual(ldap0.dn.escape_dn_chars(b'foo,bar'), b'foo\\,bar')
        self.assertEqual(ldap0.dn.escape_dn_chars(b'foo=bar'), b'foo\\=bar')
        self.assertEqual(ldap0.dn.escape_dn_chars(b'foo#bar'), b'foo#bar')
        self.assertEqual(ldap0.dn.escape_dn_chars(b'#foobar'), b'\\#foobar')
        self.assertEqual(ldap0.dn.escape_dn_chars(b'foo bar'), b'foo bar')
        self.assertEqual(ldap0.dn.escape_dn_chars(b' foobar'), b'\\ foobar')
        self.assertEqual(ldap0.dn.escape_dn_chars(b'  foobar'), b'\\  foobar')
        self.assertEqual(ldap0.dn.escape_dn_chars(b'foobar  '), b'foobar \\ ')
        self.assertEqual(ldap0.dn.escape_dn_chars(b' '), b'\\ ')
        self.assertEqual(ldap0.dn.escape_dn_chars(b'  '), b'\\ \\ ')

    def test_str2dn(self):
        """
        test function str2dn()
        """
        self.assertEqual(ldap0.dn.str2dn(b''), ())
        self.assertEqual(
            ldap0.dn.str2dn(b'uid=test42,ou=Testing,dc=example,dc=com'),
            (
                ((b'uid', b'test42', 1),),
                ((b'ou', b'Testing', 1),),
                ((b'dc', b'example', 1),),
                ((b'dc', b'com', 1),)
            )
        )
        self.assertEqual(
            ldap0.dn.str2dn(b'uid=test42+uidNumber=42,ou=Testing,dc=example,dc=com'),
            (
                ((b'uid', b'test42', 1), (b'uidNumber', b'42', 1),),
                ((b'ou', b'Testing', 1),),
                ((b'dc', b'example', 1),),
                ((b'dc', b'com', 1),)
            )
        )
        self.assertEqual(
            ldap0.dn.str2dn(b'uid=test42,ou=Testing,dc=example,dc=com', flags=0),
            (
                ((b'uid', b'test42', 1),),
                ((b'ou', b'Testing', 1),),
                ((b'dc', b'example', 1),),
                ((b'dc', b'com', 1),)
            )
        )
        self.assertEqual(
            ldap0.dn.str2dn(b'uid=test42; ou=Testing; dc=example; dc=com', flags=ldap0.DN_FORMAT_LDAPV2),
            (
                ((b'uid', b'test42', 1),),
                ((b'ou', b'Testing', 1),),
                ((b'dc', b'example', 1),),
                ((b'dc', b'com', 1),)
            )
        )
        self.assertEqual(
            ldap0.dn.str2dn(b'uid=test\\, 42,ou=Testing,dc=example,dc=com', flags=0),
            (
                ((b'uid', b'test, 42', 1),),
                ((b'ou', b'Testing', 1),),
                ((b'dc', b'example', 1),),
                ((b'dc', b'com', 1),)
            )
        )
        self.assertEqual(
            ldap0.dn.str2dn(b'cn=\xc3\xa4\xc3\xb6\xc3\xbc\xc3\x84\xc3\x96\xc3\x9c\xc3\x9f,dc=example,dc=com', flags=0),
            (
                ((b'cn', b'\xc3\xa4\xc3\xb6\xc3\xbc\xc3\x84\xc3\x96\xc3\x9c\xc3\x9f', 4),),
                ((b'dc', b'example', 1),),
                ((b'dc', b'com', 1),)
            )
        )
        self.assertEqual(
            ldap0.dn.str2dn(b'cn=\\c3\\a4\\c3\\b6\\c3\\bc\\c3\\84\\c3\\96\\c3\\9c\\c3\\9f,dc=example,dc=com', flags=0),
            (
                ((b'cn', b'\xc3\xa4\xc3\xb6\xc3\xbc\xc3\x84\xc3\x96\xc3\x9c\xc3\x9f', 4),),
                ((b'dc', b'example', 1),),
                ((b'dc', b'com', 1),)
            )
        )

    def test_dn2str(self):
        """
        test function dn2str()
        """
        self.assertEqual(ldap0.dn.str2dn(b''), ())
        self.assertEqual(
            ldap0.dn.dn2str((
                ((b'uid', b'test42', 1),),
                ((b'ou', b'Testing', 1),),
                ((b'dc', b'example', 1),),
                ((b'dc', b'com', 1),)
            )),
            b'uid=test42,ou=Testing,dc=example,dc=com',
        )
        self.assertEqual(
            ldap0.dn.dn2str((
                ((b'uid', b'test42', 1),),
                ((b'ou', b'Testing', 1),),
                ((b'dc', b'example', 1),),
                ((b'dc', b'com', 1),)
            )),
            b'uid=test42,ou=Testing,dc=example,dc=com'
        )
        self.assertEqual(
            ldap0.dn.dn2str((
                ((b'uid', b'test42', 1), (b'uidNumber', b'42', 1),),
                ((b'ou', b'Testing', 1),),
                ((b'dc', b'example', 1),),
                ((b'dc', b'com', 1),),
            )),
            b'uid=test42+uidNumber=42,ou=Testing,dc=example,dc=com'
        )
        self.assertEqual(
            ldap0.dn.dn2str((
                ((b'uid', b'test, 42', 1),),
                ((b'ou', b'Testing', 1),),
                ((b'dc', b'example', 1),),
                ((b'dc', b'com', 1),),
            )),
            b'uid=test\\, 42,ou=Testing,dc=example,dc=com'
        )
        self.assertEqual(
            ldap0.dn.dn2str((
                ((b'cn', b'\xc3\xa4\xc3\xb6\xc3\xbc\xc3\x84\xc3\x96\xc3\x9c\xc3\x9f', 4),),
                ((b'dc', b'example', 1),),
                ((b'dc', b'com', 1),),
            )),
            b'cn=\xc3\xa4\xc3\xb6\xc3\xbc\xc3\x84\xc3\x96\xc3\x9c\xc3\x9f,dc=example,dc=com'
        )
        self.assertEqual(
            ldap0.dn.dn2str((
                ((b'cn', b'\xc3\xa4\xc3\xb6\xc3\xbc\xc3\x84\xc3\x96\xc3\x9c\xc3\x9f', 4),),
                ((b'dc', b'example', 1),),
                ((b'dc', b'com', 1),),
            )),
            b'cn=\xc3\xa4\xc3\xb6\xc3\xbc\xc3\x84\xc3\x96\xc3\x9c\xc3\x9f,dc=example,dc=com'
        )

    def test_explode_dn(self):
        """
        test function explode_dn()
        """
        self.assertEqual(ldap0.dn.explode_dn(b''), [])
        self.assertEqual(
            ldap0.dn.explode_dn(b'uid=test42,ou=Testing,dc=example,dc=com'),
            (b'uid=test42', b'ou=Testing', b'dc=example', b'dc=com')
        )
        self.assertEqual(
            ldap0.dn.explode_dn(b'uid=test42,ou=Testing,dc=example,dc=com', flags=0),
            (b'uid=test42', b'ou=Testing', b'dc=example', b'dc=com')
        )
        self.assertEqual(
            ldap0.dn.explode_dn(b'uid=test42; ou=Testing; dc=example; dc=com', flags=ldap0.DN_FORMAT_LDAPV2),
            (b'uid=test42', b'ou=Testing', b'dc=example', b'dc=com')
        )
        self.assertEqual(
            ldap0.dn.explode_dn(b'uid=test42,ou=Testing,dc=example,dc=com', notypes=True),
            (b'test42', b'Testing', b'example', b'com')
        )
        self.assertEqual(
            ldap0.dn.explode_dn(b'uid=test\\, 42,ou=Testing,dc=example,dc=com', flags=0),
            (b'uid=test\\, 42', b'ou=Testing', b'dc=example', b'dc=com')
        )
        self.assertEqual(
            ldap0.dn.explode_dn(b'cn=\xc3\xa4\xc3\xb6\xc3\xbc\xc3\x84\xc3\x96\xc3\x9c\xc3\x9f,dc=example,dc=com', flags=0),
            (b'cn=\xc3\xa4\xc3\xb6\xc3\xbc\xc3\x84\xc3\x96\xc3\x9c\xc3\x9f', b'dc=example', b'dc=com')
        )
        self.assertEqual(
            ldap0.dn.explode_dn(b'cn=\\c3\\a4\\c3\\b6\\c3\\bc\\c3\\84\\c3\\96\\c3\\9c\\c3\\9f,dc=example,dc=com', flags=0),
            (b'cn=\xc3\xa4\xc3\xb6\xc3\xbc\xc3\x84\xc3\x96\xc3\x9c\xc3\x9f', b'dc=example', b'dc=com')
        )

    def test_explode_rdn(self):
        """
        test function explode_rdn()
        """
        self.assertEqual(ldap0.dn.explode_rdn(b''), ())
        self.assertEqual(
            ldap0.dn.explode_rdn(b'uid=test42',),
            (b'uid=test42',)
        )
        self.assertEqual(
            ldap0.dn.explode_rdn(b'uid=test42', notypes=False, flags=0),
            (b'uid=test42',)
        )
        self.assertEqual(
            ldap0.dn.explode_rdn(b'uid=test42', notypes=0, flags=0),
            (b'uid=test42',)
        )
        self.assertEqual(
            ldap0.dn.explode_rdn(b'uid=test42+uidNumber=42', flags=0),
            (b'uid=test42', b'uidNumber=42')
        )
        self.assertEqual(
            ldap0.dn.explode_rdn(b'uid=test42', notypes=True),
            (b'test42',)
        )
        self.assertEqual(
            ldap0.dn.explode_rdn(b'uid=test42', notypes=1),
            (b'test42',)
        )
        self.assertEqual(
            ldap0.dn.explode_rdn(b'uid=test\\+ 42', flags=0),
            (b'uid=test\\+ 42',)
        )
        self.assertEqual(
            ldap0.dn.explode_rdn(b'cn=\xc3\xa4\xc3\xb6\xc3\xbc\xc3\x84\xc3\x96\xc3\x9c\xc3\x9f', flags=0),
            (b'cn=\xc3\xa4\xc3\xb6\xc3\xbc\xc3\x84\xc3\x96\xc3\x9c\xc3\x9f',)
        )
        self.assertEqual(
            ldap0.dn.explode_rdn(b'cn=\\c3\\a4\\c3\\b6\\c3\\bc\\c3\\84\\c3\\96\\c3\\9c\\c3\\9f', flags=0),
            (b'cn=\xc3\xa4\xc3\xb6\xc3\xbc\xc3\x84\xc3\x96\xc3\x9c\xc3\x9f',)
        )


class TestDNObj(unittest.TestCase):
    """
    test class ldap0.dn.DNObj
    """

    def test_dnobj_simple(self):
        self.assertEqual(list(DNObj.fromstring(b'')), [])
        self.assertEqual(len(DNObj.fromstring(b'')), 0)
        self.assertEqual(len(DNObj.fromstring(b'ou=dept1  ,  dc=example, dc=com')), 3)
        self.assertEqual(list(DNObj.fromstring(b'').rdn()), [])
        self.assertEqual(
            str(DNObj.fromstring(b'ou=dept1  ,  dc=example, dc=com').rdn()),
            b'ou=dept1'
        )
        self.assertEqual(
            str(DNObj.fromstring(b'ou=dept1,  dc=example, dc=com').parent()),
            b'dc=example,dc=com'
        )
        for dn_str in (
                b'',
                b'dc=example,dc=com',
                b'ou=dept1,dc=example,dc=com',
                b'cn=\xc3\xa4\xc3\xb6\xc3\xbc\xc3\x84\xc3\x96\xc3\x9c\xc3\x9f,ou=\xc3\xa4\xc3\xb6\xc3\xbc\xc3\x84\xc3\x96\xc3\x9c\xc3\x9f',
            ):
            self.assertEqual(str(DNObj.fromstring(dn_str, flags=0)), dn_str)

    def test_dnobj_unicode(self):
        # test Unicode strings
        self.assertEqual(list(DNObj.fromstring(u'')), [])
        self.assertEqual(len(DNObj.fromstring(u'')), 0)
        self.assertEqual(
            str(DNObj.fromstring(u'ou=dept1  ,  dc=example, dc=com').rdn()),
            'ou=dept1'
        )
        for dn_str in (
                u'',
                u'dc=example,dc=com',
                u'ou=dept1,dc=example,dc=com',
                u'cn=Michael Ströder,dc=example,dc=com',
            ):
            dn_obj = DNObj.fromstring(dn_str, flags=0)
            self.assertEqual(bytes(dn_obj), dn_str.encode('utf-8'))
            self.assertEqual(str(dn_obj), dn_str.encode('utf-8'))
            self.assertEqual(unicode(dn_obj), dn_str)
        self.assertEqual(str(DNObj.fromdomain(u'example.com')), u'dc=example,dc=com')

    def test_weird_whitespaces(self):
        self.assertEqual(
            DNObj.fromstring(b'uid = test42 + uidNumber = 42, dc = example , dc = com'),
            DNObj((
                (
                    (b'uid', b'test42', 1),
                    (b'uidNumber', b'42', 1)
                ),
                ((b'dc', b'example', 1),),
                ((b'dc', b'com', 1),)
            ))
        )

    def test_repr(self):
        self.assertEqual(
            repr(DNObj((
                (
                    (b'uid', b'test42', 1),
                    (b'uidNumber', b'42', 1)
                ),
                ((b'dc', b'example', 1),),
                ((b'dc', b'com', 1),)
            ))),
            "DNObj(((('uid', 'test42', 1), ('uidNumber', '42', 1)), (('dc', 'example', 1),), (('dc', 'com', 1),)))"
        )

    def test_hashable(self):
        dn = DNObj((
            (
                (b'uid', b'test42', 1),
                (b'uidNumber', b'42', 1)
            ),
            ((b'dc', b'example', 1),),
            ((b'dc', b'com', 1),)
        ))
        data = {dn: 'foo'}
        self.assertEqual(data[dn], 'foo')

    def test_dnobj_slicing(self):
        dn = DNObj.fromstring(b'ou=dept1  ,  dc=example, dc=com')
        self.assertEqual(dn[0], ((b'ou', b'dept1', 1),))
        self.assertEqual(dn[1], ((b'dc', b'example', 1),))
        self.assertEqual(dn[2], ((b'dc', b'com', 1),))
        self.assertEqual(dn[:], dn)
        with self.assertRaises(IndexError):
            self.assertEqual(dn[3], ())
        self.assertEqual(
            reversed(DNObj.fromstring(b'ou=dept1,dc=example,dc=com')),
            DNObj.fromstring(b'dc=com,dc=example,ou=dept1')
        )
        self.assertEqual(
            DNObj.fromstring(b'ou=dept1,dc=example,dc=com')[1:],
            DNObj.fromstring(b'dc=example,dc=com')
        )
        self.assertEqual(
            DNObj.fromstring(b'ou=dept1,dc=example,dc=com')[:2],
            DNObj.fromstring(b'ou=dept1,dc=example')
        )
        domain = b'sub3.sub2.sub1.example.com'
        dns_labels = domain.split(b'.')
        dno = DNObj.fromdomain(domain)
        for i, dn_comp in enumerate(dno):
            self.assertEqual(dn_comp[0][0], b'dc')
            self.assertEqual(dn_comp[0][1], dns_labels[i])
            self.assertEqual(dno[i], dn_comp)

    def test_dnobj_domain(self):
        self.assertEqual(
            str(DNObj.fromdomain(b'example.com')),
            b'dc=example,dc=com'
        )
        self.assertEqual(
            DNObj.fromdomain(b'example.com').domain(),
            b'example.com'
        )
        self.assertEqual(
            DNObj.fromdomain(u'ströder.de').domain(),
            u'ströder.de'.encode('idna')
        )
        self.assertEqual(
            DNObj.fromstring(b'ou=dept1,  dc=example, dc=com').domain(only_dc=False),
            b'example.com'
        )
        with self.assertRaises(ValueError):
            DNObj.fromstring(b'ou=dept1,dc=example,dc=com').domain(only_dc=True)
        with self.assertRaises(ValueError):
            DNObj.fromstring(b'ou=dept1,dc=example,dc=com+dc=net').domain()
        with self.assertRaises(ValueError):
            DNObj.fromstring(b'ou=foo+dc=example,dc=com').domain()


    def test_dnobj_add(self):
        self.assertEqual(
            DNObj.fromdomain(b'dept1')+DNObj.fromdomain(b'example.com'),
            DNObj.fromdomain(b'dept1.example.com'),
        )
        self.assertEqual(
            str(DNObj.fromdomain(b'dept1')+DNObj.fromdomain(b'example.com')),
            'dc=dept1,dc=example,dc=com',
        )
        self.assertEqual(
            (DNObj.fromdomain(b'dept1')+DNObj.fromdomain(b'example.com')).domain(),
            'dept1.example.com',
        )


if __name__ == '__main__':
    unittest.main()

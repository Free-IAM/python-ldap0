# -*- coding: utf-8 -*-
"""
Automatic tests for module ldap0.base
"""

# from Python's standard lib
import unittest

from ldap0.dn import DNObj
from ldap0.base import decode_entry_dict
from ldap0.res import SearchReference, SearchResultEntry, LDAPResult
from ldap0.ldapurl import LDAPUrl


class Test001SearchReference(unittest.TestCase):
    """
    tests for class ldap0.res.SearchReference
    """

    def test001_simple(self):
        ref_urls = ['ldap://ldap.example.com/dc=example,dc=com']
        sere = SearchReference([ref_urls[0].encode('ascii')], [])
        self.assertEqual(sere.ctrls, [])
        self.assertEqual(sere.ref_url_strings, ref_urls)
        self.assertEqual(sere.ref_ldap_urls, [LDAPUrl(ref_urls[0])])
        sere = SearchReference([ref_urls[0].encode('ascii')], [], encoding='ascii')
        self.assertEqual(sere.ctrls, [])
        self.assertEqual(sere.ref_url_strings, ref_urls)
        self.assertEqual(sere.ref_ldap_urls, [LDAPUrl(ref_urls[0])])

    def test002_unicode(self):
        # default encoding UTF-8
        sere = SearchReference(['ldap://ldap.example.com/o=äöüÄÖÜß'.encode('utf-8')], [])
        self.assertEqual(sere.ref_url_strings,['ldap://ldap.example.com/o=äöüÄÖÜß'])
        self.assertEqual(sere.ref_ldap_urls, [LDAPUrl(sere.ref_url_strings[0])])
        # explicit encoding ISO-8859-1
        sere = SearchReference(['ldap://ldap.example.com/o=ÄÖÜßäöü'.encode('iso-8859-1')], [], encoding='iso-8859-1')
        self.assertEqual(sere.ref_url_strings,['ldap://ldap.example.com/o=ÄÖÜßäöü'])
        self.assertEqual(sere.ref_ldap_urls, [LDAPUrl(sere.ref_url_strings[0])])


    def test003_unicode_errors(self):
        sere = SearchReference(['ldap://ldap.example.com/o=äöüÄÖÜß'.encode('utf-8')], [], encoding='ascii')
        with self.assertRaises(UnicodeDecodeError):
            sere.ref_url_strings
        sere = SearchReference(['ldap://ldap.example.com/o=äöüÄÖÜß'.encode('iso-8859-1')], [])
        with self.assertRaises(UnicodeDecodeError):
            sere.ref_url_strings


class Test002SearchResultEntry(unittest.TestCase):
    """
    tests for class ldap0.res.SearchResultEntry
    """

    def test001_simple(self):
        dn_b = 'o=äöüÄÖÜß,dc=example,dc=com'.encode('utf-8')
        entry_b = {
            b'objectClass': [b'organization'],
            b'o': ['äöüÄÖÜß'.encode('utf-8')],
            b'description': ['ÄÖÜßäöü'.encode('utf-8')],
        }
        sere = SearchResultEntry(dn_b, entry_b, [])
        self.assertEqual(sere.dn_b, dn_b)
        self.assertEqual(sere.entry_b, entry_b)
        self.assertEqual(sere.dn_s, dn_b.decode('utf-8'))
        self.assertEqual(sere.entry_as, {at.decode('ascii'): avs for at, avs in entry_b.items()})
        self.assertEqual(sere.entry_s, decode_entry_dict(entry_b, encoding='utf-8'))
        self.assertEqual(sere.dn_o, DNObj.from_str(dn_b.decode('utf-8')))
        sere = SearchResultEntry('o=äöüÄÖÜß,dc=example,dc=com'.encode('iso-8859-1'), {}, [], encoding='iso-8859-1')
        self.assertEqual(sere.dn_s, sere.dn_b.decode('iso-8859-1'))

    def test002_dn_unicode_error(self):
        sere = SearchResultEntry(
            'o=äöüÄÖÜß,dc=example,dc=com'.encode('iso-8859-1'),
            {
                b'objectClass': [b'organization'],
                b'o': ['äöüÄÖÜß'.encode('iso-8859-1')],
                b'description': ['ÄÖÜßäöü'.encode('iso-8859-1')],
            },
            []
        )
        with self.assertRaises(UnicodeDecodeError):
            sere.dn_s
        with self.assertRaises(UnicodeDecodeError):
            sere.entry_s


class Test004LDAPResult(unittest.TestCase):
    """
    tests for class ldap0.res.LDAPResult
    """

    def test001_simple(self):
        r = LDAPResult(None, None, None, None)
        self.assertEqual(r.rtype, None)
        self.assertEqual(r.rdata, [])
        self.assertEqual(r.msgid, None)
        self.assertEqual(r.ctrls, [])

    def test002_repr(self):
        self.assertEqual(
            repr(LDAPResult(None, None, None, None)),
            'LDAPResult(None, [], None, [])',
        )
        self.assertEqual(
            repr(LDAPResult(None, [], None, [])),
            'LDAPResult(None, [], None, [])',
        )


if __name__ == '__main__':
    unittest.main()

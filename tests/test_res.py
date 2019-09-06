# -*- coding: utf-8 -*-
"""
Automatic tests for module ldap0.base
"""

# from Python's standard lib
import unittest

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
        pass



class Test004LDAPResult(unittest.TestCase):
    """
    tests for class ldap0.res.LDAPResult
    """

    def test001_simple(self):
        r = LDAPResult(None, None, None, None)
        self.assertEqual(r.rtype, None)
        self.assertEqual(r.rdata, None)
        self.assertEqual(r.msgid, None)
        self.assertEqual(r.ctrls, None)

    def test002_repr(self):
        self.assertEqual(
            repr(LDAPResult(None, [], None, [])),
            'LDAPResult(None, [], None, [])',
        )


if __name__ == '__main__':
    unittest.main()

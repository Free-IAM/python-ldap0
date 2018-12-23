# -*- coding: utf-8 -*-
"""
Automatic tests for module ldap0.base
"""

from __future__ import absolute_import

# from Python's standard lib
import unittest

import ldap0.base


class TestLDAPResult(unittest.TestCase):
    """
    test ldap0.base
    """

    def test_simple_tuple(self):
        r = ldap0.base.LDAPResult((None, None, None, None))
        self.assertEqual(r, (None, None, None, None))
        self.assertEqual(r.rtype, None)
        self.assertEqual(r.data, None)
        self.assertEqual(r.msgid, None)
        self.assertEqual(r.ctrls, None)
        i1, i2, i3, i4 = r
        self.assertEqual((i1, i2, i3, i4), (None, None, None, None))
        r = ldap0.base.LDAPResult((None, [], None, []))
        self.assertEqual(r, (None, [], None, []))
        self.assertEqual(r.data, [])
        self.assertEqual(r.ctrls, [])
        i1, i2, i3, i4 = r
        self.assertEqual((i1, i2, i3, i4), (None, [], None, []))

    def test_repr(self):
        self.assertEqual(
            repr(ldap0.base.LDAPResult((None, [], None, []))),
            'LDAPResult((None, [], None, []))',
        )


if __name__ == '__main__':
    unittest.main()

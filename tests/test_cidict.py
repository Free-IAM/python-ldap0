# -*- coding: utf-8 -*-
"""
Automatic tests for module ldap0.cidict
"""

from __future__ import absolute_import

# from Python's standard lib
import unittest

import ldap0, ldap0.cidict


class TestCidict(unittest.TestCase):
    """
    test ldap0.cidict.cidict
    """

    def test_cidict(self):
        """
        test function is_dn()
        """
        data = {
            'AbCDeF':123,
        }
        cix = ldap0.cidict.cidict(data)
        self.assertEqual(cix["ABCDEF"], 123)
        self.assertEqual(cix.get("ABCDEF", None), 123)
        self.assertEqual(cix.get("not existent", None), None)
        self.assertEqual(cix.get("not existent", 42), 42)
        cix["xYZ"] = 987
        self.assertEqual(cix["XyZ"], 987)
        self.assertEqual(cix.get("xyz", None), 987)
        cix_keys = cix.keys()
        cix_keys.sort()
        self.assertEqual(cix_keys, ['AbCDeF','xYZ'])
        cix_items = cix.items()
        cix_items.sort()
        self.assertEqual(cix_items, [('AbCDeF',123), ('xYZ',987)])
        del cix["abcdEF"]
        self.assertEqual("abcdef" in cix, False)
        self.assertEqual("AbCDef" in cix._keys, False)
        self.assertEqual(cix.has_key("abcdef"), False)


if __name__ == '__main__':
    unittest.main()

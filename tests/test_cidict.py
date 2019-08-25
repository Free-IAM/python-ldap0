# -*- coding: utf-8 -*-
"""
Automatic tests for module ldap0.cidict
"""

# from Python's standard lib
import unittest

import ldap0.cidict


class TestCidict(unittest.TestCase):
    """
    test ldap0.cidict.CIDict
    """

    def test_cidict(self):
        data = {
            'AbCDeF':123,
        }
        cix = ldap0.cidict.CIDict(data)
        self.assertEqual(cix["ABCDEF"], 123)
        self.assertEqual(cix.get("ABCDEF", None), 123)
        self.assertEqual(cix.get("not existent", None), None)
        self.assertEqual(cix.get("not existent", 42), 42)
        cix["xYZ"] = 987
        self.assertEqual(cix["XyZ"], 987)
        self.assertEqual(cix.get("xyz", None), 987)
        with self.assertRaises(NotImplementedError):
            cix.has_key("xyz")
        self.assertTrue("xyz" in cix)
        self.assertTrue("Xyz" in cix)
        self.assertEqual(sorted(cix.keys()), ['AbCDeF', 'xYZ'])
        self.assertEqual(sorted(cix.items()), [('AbCDeF', 123), ('xYZ', 987)])
        del cix["abcdEF"]
        self.assertFalse("abcdef" in cix)
        self.assertFalse("AbCDef" in cix._keys)
        self.assertFalse("abcdef" in cix)
        self.assertFalse("abcdef" in cix)

    def test_mixed_type_fail(self):
        data = {
            'AbCDeF':123,
        }
        cix = ldap0.cidict.CIDict(data)
        with self.assertRaises(TypeError):
            cix[b'foo'] = 42
        with self.assertRaises(TypeError):
            cix = ldap0.cidict.CIDict(data, keytype=bytes)

class TestSingleValueDict(unittest.TestCase):
    """
    test ldap0.cidict.SingleValueDict
    """

    def test001_getitem(self):
        data = {
            'foo':['bar1', 'bar2', 'bar3'],
        }
        svd = ldap0.cidict.SingleValueDict(data)
        self.assertEqual(svd['foo'], 'bar1')
        self.assertEqual(list(svd.values()), ['bar1'])
        self.assertEqual(list(svd.items()), [('foo', 'bar1')])


if __name__ == '__main__':
    unittest.main()

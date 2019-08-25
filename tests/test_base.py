# -*- coding: utf-8 -*-
"""
Automatic tests for module ldap0.base
"""

# from Python's standard lib
import unittest

from ldap0.base import decode_list, encode_list, decode_entry_dict, encode_entry_dict

from ldap0.base import LDAPResult


class Test001Functions(unittest.TestCase):

    def test001_decode_list(self):
          self.assertEqual(
              decode_list(
                  [b'foo', b'Theo T\xc3\xa4ster', b'T\xc3\xa4ster, Theo'],
              ),
              [u'foo', u'Theo Täster', u'Täster, Theo'],
          )

    def test002_decode_entry_dict(self):
          self.assertEqual(
              decode_entry_dict({
                    b'objectClass': [b'top', b'person', b'organizationalPerson', b'inetOrgPerson'],
                    b'cn': [b'Theo T\xc3\xa4ster', b'T\xc3\xa4ster, Theo'],
                    b'sn': [b'T\xc3\xa4ster'],
                    b'inv\xc3\xa4lid': [],
              }),
              {
                    u'objectClass': [u'top', u'person', u'organizationalPerson', u'inetOrgPerson'],
                    u'cn': [u'Theo Täster', u'Täster, Theo'],
                    u'sn': [u'Täster'],
                    u'invälid': [],
              },
          )
          with self.assertRaises(UnicodeDecodeError):
              decode_entry_dict(
                  {
                        b'objectClass': [b'top', b'person', b'organizationalPerson', b'inetOrgPerson'],
                        b'cn': [b'Theo T\xc3\xa4ster', b'T\xc3\xa4ster, Theo'],
                        b'sn': [b'T\xc3\xa4ster'],
                        b'inv\xc3\xa4lid': [],
                  },
                  'ascii'
              )

    def test003_encode_list(self):
          self.assertEqual(
              encode_list(
                  [u'foo', u'Theo Täster', u'Täster, Theo'],
              ),
              [b'foo', b'Theo T\xc3\xa4ster', b'T\xc3\xa4ster, Theo'],
          )

    def test004_encode_entry_dict(self):
          self.assertEqual(
              encode_entry_dict({
                    u'objectClass': [u'top', u'person', u'organizationalPerson', u'inetOrgPerson'],
                    u'cn': [u'Theo Täster', u'Täster, Theo'],
                    u'sn': [u'Täster'],
                    u'invälid': [],
              }),
              {
                    b'objectClass': [b'top', b'person', b'organizationalPerson', b'inetOrgPerson'],
                    b'cn': [b'Theo T\xc3\xa4ster', b'T\xc3\xa4ster, Theo'],
                    b'sn': [b'T\xc3\xa4ster'],
                    b'inv\xc3\xa4lid': [],
              },
          )
          with self.assertRaises(UnicodeEncodeError):
              encode_entry_dict(
                  {
                        u'objectClass': [u'top', u'person', u'organizationalPerson', u'inetOrgPerson'],
                        u'cn': [u'Theo Täster', u'Täster, Theo'],
                        u'sn': [u'Täster'],
                        u'invälid': [],
                  },
                  'ascii'
              )


class Test002LDAPResult(unittest.TestCase):
    """
    tests for class ldap0.base.LDAPResult
    """

    def test_simple_tuple(self):
        r = LDAPResult(None, None, None, None)
        self.assertEqual(tuple(r), (None, None, None, None))
        self.assertEqual(r.rtype, None)
        self.assertEqual(r.data, None)
        self.assertEqual(r.msgid, None)
        self.assertEqual(r.ctrls, None)
        i1, i2, i3, i4 = r
        self.assertEqual((i1, i2, i3, i4), (None, None, None, None))
        r = LDAPResult(None, [], None, [])
        self.assertEqual(tuple(r), (None, [], None, []))
        self.assertEqual(r.data, [])
        self.assertEqual(r.ctrls, [])
        i1, i2, i3, i4 = r
        self.assertEqual((i1, i2, i3, i4), (None, [], None, []))

    def test_repr(self):
        self.assertEqual(
            repr(LDAPResult(None, [], None, [])),
            'LDAPResult(None, [], None, [])',
        )


if __name__ == '__main__':
    unittest.main()

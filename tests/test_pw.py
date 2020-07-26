# -*- coding: utf-8 -*-
"""
Automatic tests for module ldap0.dn
"""

# from Python's standard lib
import hashlib
import unittest

from ldap0.pw import *


class TestPasswordFunctions(unittest.TestCase):
    """
    test functions in ldap0.dn
    """

    def test_random_string(self):
        self.assertEqual(len(random_string()), PWD_LENGTH)
        self.assertEqual(random_string(b'1', 4), 4*b'1')
        self.assertEqual(random_string('1', 4), 4*'1')
        self.assertEqual(len(random_string(None)), PWD_LENGTH)

    def test_unicode_pwd(self):
        self.assertEqual(len(unicode_pwd()), (PWD_LENGTH+2)*2)
        self.assertEqual(len(unicode_pwd(length=10)), (10+2)*2)
        for pw in (
                b'foo',
                b'bar',
                b'\xc3\xa4\xc3\xb6\xc3\xbc\xc3\x84\xc3\x96\xc3\x9c\xc3\x9f',
            ):
            self.assertEqual(
                unicode_pwd(pw),
                u'"{}"'.format(pw.decode('utf-8')).encode('utf-16-le')
            )

    def test_ntlm_password_hash(self):
        ntlm_password_hash_hex_size = 2 * hashlib.new('md4').digest_size
        for pw, pw_hash in (
                (b'foo', b'AC8E657F83DF82BEEA5D43BDAF7800CC'),
                (b'bar', b'86C156FC198B358CCCF6278D8BD49B6A'),
                (b'\xc3\xa4\xc3\xb6\xc3\xbc\xc3\x84\xc3\x96\xc3\x9c\xc3\x9f', b'F4B08969FAAC3D4A52924FA91944261E'),
            ):
            res = ntlm_password_hash(pw)
            self.assertEqual(len(res), ntlm_password_hash_hex_size)
            self.assertEqual(res, pw_hash)


if __name__ == '__main__':
    unittest.main()

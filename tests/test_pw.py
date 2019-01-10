# -*- coding: utf-8 -*-
"""
Automatic tests for module ldap0.dn
"""

from __future__ import absolute_import

# from Python's standard lib
import hashlib
import unittest

import ldap0.pw
from ldap0.pw import *


class TestBasics(unittest.TestCase):

    def test_constants(self):
        self.assertEqual(
            ldap0.pw.PWD_OCTETS_ALPHABET,
            ''.join([ chr(i) for i in range(256)])
        )


class TestPasswordFunctions(unittest.TestCase):
    """
    test functions in ldap0.dn
    """

    def test_random_string(self):
        self.assertEqual(len(random_string()), PWD_LENGTH)
        self.assertEqual(random_string('1', 4), 4*'1')

    def test_unicode_pwd(self):
        self.assertEqual(len(unicode_pwd()), (PWD_LENGTH+2)*2)
        self.assertEqual(len(unicode_pwd(length=10)), (10+2)*2)
        for pw in (
                'foo',
                'bar',
                '\xc3\xa4\xc3\xb6\xc3\xbc\xc3\x84\xc3\x96\xc3\x9c\xc3\x9f',
            ):
            self.assertEqual(
                unicode_pwd(pw),
                u'"{}"'.format(pw.decode('utf-8')).encode('utf-16-le')
            )

    def test_ntlm_password_hash(self):
        ntlm_password_hash_hex_size = 2 * hashlib.new('md4').digest_size
        for pw, pw_hash in (
                ('foo', 'AC8E657F83DF82BEEA5D43BDAF7800CC'),
                ('bar', '86C156FC198B358CCCF6278D8BD49B6A'),
                ('\xc3\xa4\xc3\xb6\xc3\xbc\xc3\x84\xc3\x96\xc3\x9c\xc3\x9f', 'F4B08969FAAC3D4A52924FA91944261E'),
            ):
            res = ntlm_password_hash(pw)
            self.assertEqual(len(res), ntlm_password_hash_hex_size)
            self.assertEqual(res, pw_hash)


if __name__ == '__main__':
    unittest.main()

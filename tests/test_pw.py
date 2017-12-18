# -*- coding: utf-8 -*-
"""
Automatic tests for module ldap0.dn
"""

from __future__ import absolute_import

# from Python's standard lib
import unittest

from ldap0.pw import PWD_LENGTH, random_string, unicode_pwd


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


if __name__ == '__main__':
    unittest.main()

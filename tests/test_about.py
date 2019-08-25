# -*- coding: utf-8 -*-
"""
test consistency of meta information
"""

# from Python's standard lib
import unittest

import ldap0.__about__

class TestVersionInfo(unittest.TestCase):

    def test_version(self):
        self.assertEqual(
            ldap0.__about__.__version_info__.major, ldap0.__about__.__version_info__[0],
        )
        self.assertEqual(
            ldap0.__about__.__version_info__.minor, ldap0.__about__.__version_info__[1],
        )
        self.assertEqual(
            ldap0.__about__.__version_info__.micro, ldap0.__about__.__version_info__[2],
        )
        self.assertEqual(
            tuple(int(val) for val in ldap0.__about__.__version__.split('.', 3)),
            ldap0.__about__.__version_info__,
        )


if __name__ == '__main__':
    unittest.main()

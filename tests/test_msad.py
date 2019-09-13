# -*- coding: utf-8 -*-
"""
Automatic tests for module ldap0.msad
"""

# from Python's standard lib
import unittest

from ldap0.msad import sid2sddl, sddl2sid


class Test001Functions(unittest.TestCase):

    test_vectors = (
        (
            b'\x01\x05\x00\x00\x00\x00\x00\x05\x15\x00\x00\x00\xbaZ\x17^U\xdf\x83a)XU\x0eP\x04\x00\x00',
            'S-1-5-21-1578588858-1636032341-240474153-1104'
        ),
        (
            b'\x01\x04\x00\x00\x00\x00\x00\x05\x15\x00\x00\x00\xbaZ\x17^U\xdf\x83a)XU\x0e',
            'S-1-5-21-1578588858-1636032341-240474153'
        ),
    )

    def test001_sid2sddl(self):
        for sid_b, sddl_s in self.test_vectors:
            self.assertEqual(sid2sddl(sid_b), sddl_s)

    def test002_sddl2sid(self):
        for sid_b, sddl_s in self.test_vectors:
            self.assertEqual(sddl2sid(sddl_s), sid_b)

    def test003_inverse(self):
        for sid_b, sddl_s in self.test_vectors:
            self.assertEqual(sid2sddl(sddl2sid(sddl_s)), sddl_s)
            self.assertEqual(sddl2sid(sid2sddl(sid_b)), sid_b)


if __name__ == '__main__':
    unittest.main()

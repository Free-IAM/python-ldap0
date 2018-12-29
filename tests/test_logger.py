# -*- coding: utf-8 -*-
"""
Automatic tests for module ldap0.logger
"""

from __future__ import absolute_import

# from Python's standard lib
import unittest
import logging

from ldap0.logger import LoggerFileObj


class TestLogger(unittest.TestCase):
    """
    test ldap0.base
    """

    def test_standard_logger(self):
        fl = LoggerFileObj()
        fl.flush()
        fl.write('test')
        with self.assertRaises(IOError):
            fl.read()

    def test_get_logger(self):
        fl = LoggerFileObj(logger=logging.getLogger())
        fl.flush()
        fl.write('test')
        with self.assertRaises(IOError):
            fl.read()


if __name__ == '__main__':
    unittest.main()

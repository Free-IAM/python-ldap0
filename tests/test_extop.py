# -*- coding: utf-8 -*-
"""
Simple tests for module ldap0.extop
"""

# from Python's standard lib
import unittest

from ldap0.extop import ExtendedRequest, ExtendedResponse
from ldap0.extop.passmod import PassmodResponse


class TestExtOpRequest(unittest.TestCase):
    """
    test classes for encoding extended operation requests
    """

    def test_basic(self):
        er = ExtendedRequest('1.2.3.4')
        self.assertEqual(er.requestName, '1.2.3.4')
        self.assertEqual(er.requestValue, None)
        self.assertEqual(repr(er), "ExtendedRequest(requestName='1.2.3.4', requestValue=None)")
        er = ExtendedRequest(requestName='1.2.3.4')
        self.assertEqual(er.requestName, '1.2.3.4')
        self.assertEqual(er.requestValue, None)
        self.assertEqual(repr(er), "ExtendedRequest(requestName='1.2.3.4', requestValue=None)")
        er = ExtendedRequest('1.2.3.4', 'foobar')
        self.assertEqual(er.requestName, '1.2.3.4')
        self.assertEqual(er.requestValue, 'foobar')
        self.assertEqual(repr(er), "ExtendedRequest(requestName='1.2.3.4', requestValue='foobar')")
        self.assertEqual(er.encodedRequestValue(), 'foobar')


class TestExtOpResponse(unittest.TestCase):
    """
    test classes for decoding extended operation responses
    """

    def test_basic(self):
        er = ExtendedResponse('1.2.3.4')
        self.assertEqual(er.responseName, '1.2.3.4')
        self.assertEqual(er.responseValue, None)
        self.assertEqual(repr(er), "ExtendedResponse(responseName='1.2.3.4', responseValue=None)")
        er = ExtendedResponse(responseName='1.2.3.4')
        self.assertEqual(er.responseName, '1.2.3.4')
        self.assertEqual(er.responseValue, None)
        self.assertEqual(repr(er), "ExtendedResponse(responseName='1.2.3.4', responseValue=None)")
        er = ExtendedResponse('1.2.3.4', 'foobar')
        self.assertEqual(er.responseName, '1.2.3.4')
        self.assertEqual(er.responseValue, 'foobar')
        self.assertEqual(repr(er), "ExtendedResponse(responseName='1.2.3.4', responseValue='foobar')")
        er.decodeResponseValue('foobar42')
        self.assertEqual(er.responseValue, 'foobar42')

    def test_passmod(self):
        er = PassmodResponse()
        er.decodeResponseValue(None)
        self.assertEqual(er.responseValue, None)


if __name__ == '__main__':
    unittest.main()

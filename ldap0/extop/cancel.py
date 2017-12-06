# -*- coding: utf-8 -*-
"""
ldap0.extop.cancel - Classes for Cancel Operation
(see RFC 3909)
"""

from __future__ import absolute_import

from ldap0.pkginfo import __version__, __author__, __license__
from ldap0.extop import ExtendedRequest, ExtendedResponse

# Imports from pyasn1
from pyasn1.type import namedtype, univ
from pyasn1.codec.der import encoder
from pyasn1_modules.rfc2251 import MessageID


class CancelRequest(ExtendedRequest):
    """
    Cancel Operation Request
    """

    requestName = '1.3.6.1.1.8'

    class CancelRequestValue(univ.Sequence):
        """
        Cancel request value
        """
        componentType = namedtype.NamedTypes(
            namedtype.NamedType(
                'cancelID',
                MessageID()
            ),
        )

    def __init__(self, cancelID):
        ExtendedRequest.__init__(self)
        self.cancelID = cancelID

    def encodedRequestValue(self):
        req_value = self.CancelRequestValue()
        req_value.setComponentByName(
            'cancelID',
            self.cancelID
        )
        return encoder.encode(req_value)


class CancelResponse(ExtendedResponse):
    """
    Cancel Operation Response (only dummy)
    """

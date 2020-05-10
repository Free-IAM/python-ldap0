# -*- coding: utf-8 -*-
"""
ldap0.extop.cancel - Classes for Cancel Operation
(see RFC 3909)
"""

# Imports from pyasn1
from pyasn1.type import namedtype, univ
from pyasn1.codec.der import encoder
from pyasn1_modules.rfc2251 import MessageID

from ..__about__ import __version__, __author__, __license__
from . import ExtendedRequest, ExtendedResponse


class CancelRequest(ExtendedRequest):
    """
    Cancel Operation Request
    """
    __slots__ = (
        'cancelID',
    )
    requestName: str = '1.3.6.1.1.8'
    cancelID: int

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

    def __init__(self, cancelID: int):
        ExtendedRequest.__init__(self)
        self.cancelID = cancelID

    def encode(self) -> bytes:
        req_value = self.CancelRequestValue()
        req_value.setComponentByName(
            'cancelID',
            str(self.cancelID).encode('ascii')
        )
        return encoder.encode(req_value)


class CancelResponse(ExtendedResponse):
    """
    Cancel Operation Response (only dummy)
    """

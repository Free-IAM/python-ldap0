# -*- coding: utf-8 -*-
"""
ldap0.extop - support classes for LDAPv3 extended operations
"""

from typing import Optional

from ..__about__ import __version__, __author__, __license__


class ExtendedRequest:
    """
    Generic base class for a LDAPv3 extended operation request

    requestName
        OID as string of the LDAPv3 extended operation request
    requestValue
        value of the LDAPv3 extended operation request
        (here it is the BER-encoded ASN.1 request value)
    """
    encoding: str = 'utf-8'

    def __init__(self, requestName=None, requestValue=None):
        if requestName is not None:
            self.requestName = requestName
        self.requestValue = requestValue

    def __repr__(self):
        return '%s(requestName=%r, requestValue=%r)' % (
            self.__class__.__name__,
            self.requestName,
            self.requestValue,
        )

    def encode(self) -> bytes:
        """
        returns the BER-encoded ASN.1 request value composed by class attributes
        set before
        """
        return self.requestValue


class ExtendedResponse:
    """
    Generic base class for a LDAPv3 extended operation response

    requestName
        OID as string of the LDAPv3 extended operation response
    encodedResponseValue
        BER-encoded ASN.1 value of the LDAPv3 extended operation response
    """
    encoding = 'utf-8'

    responseName = None

    def __init__(self, responseName=None, encodedResponseValue=None):
        if responseName is not None:
            self.responseName = responseName
        self.responseValue = encodedResponseValue
        if encodedResponseValue is not None:
            self.decode(encodedResponseValue)

    def __repr__(self):
        return '%s(responseName=%r, responseValue=%r)' % (
            self.__class__.__name__,
            self.responseName,
            self.responseValue,
        )

    @classmethod
    def check_resp_name(cls, name):
        """
        returns True if :name: is the correct expected responseName
        """
        return name == cls.responseName

    def decode(self, value: bytes):
        """
        decodes the BER-encoded ASN.1 extended operation response value and
        sets the appropriate class attributes
        """
        self.responseValue = value

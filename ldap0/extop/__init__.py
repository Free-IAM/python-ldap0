# -*- coding: utf-8 -*-
"""
ldap0.extop - support classes for LDAPv3 extended operations
"""

from __future__ import absolute_import

from ..pkginfo import __version__, __author__, __license__


class ExtendedRequest(object):
    """
    Generic base class for a LDAPv3 extended operation request

    requestName
        OID as string of the LDAPv3 extended operation request
    requestValue
        value of the LDAPv3 extended operation request
        (here it is the BER-encoded ASN.1 request value)
    """

    def __init__(self, requestName=None, requestValue=None):
        if requestName is not None:
            self.requestName = requestName
        self.requestValue = requestValue

    def __repr__(self):
        return '%s(%s,%s)' % (self.__class__.__name__, self.requestName, self.requestValue)

    def encodedRequestValue(self):
        """
        returns the BER-encoded ASN.1 request value composed by class attributes
        set before
        """
        return self.requestValue


class ExtendedResponse(object):
    """
    Generic base class for a LDAPv3 extended operation response

    requestName
        OID as string of the LDAPv3 extended operation response
    encodedResponseValue
        BER-encoded ASN.1 value of the LDAPv3 extended operation response
    """

    responseName = None

    def __init__(self, responseName=None, encodedResponseValue=None):
        if responseName is not None:
            self.responseName = responseName
        self.responseValue = encodedResponseValue
        if encodedResponseValue is not None:
            self.decodeResponseValue(encodedResponseValue)

    def __repr__(self):
        return '%s(%r, %r)' % (self.__class__.__name__, self.responseName, self.responseValue)

    def decodeResponseValue(self, value):
        """
        decodes the BER-encoded ASN.1 extended operation response value and
        sets the appropriate class attributes
        """
        self.responseValue = value

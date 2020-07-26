# -*- coding: utf-8 -*-
"""
ldap0.extop.passmod - Classes for Password Modify extended operation
(see RFC 3062)
"""

# Imports from pyasn1
from pyasn1.type import namedtype, univ, tag
from pyasn1.codec.der import encoder, decoder
from pyasn1_modules.rfc2251 import LDAPString

from . import ExtendedRequest, ExtendedResponse


class UserIdentity(LDAPString):
    """
    userIdentity [0] OCTET STRING OPTIONAL
    """
    tagSet = LDAPString.tagSet.tagImplicitly(
        tag.Tag(
            tag.tagClassContext,
            tag.tagFormatSimple,
            0
        )
    )

class OldPasswd(LDAPString):
    """
    oldPasswd [1] OCTET STRING OPTIONAL
    """
    tagSet = LDAPString.tagSet.tagImplicitly(
        tag.Tag(
            tag.tagClassContext,
            tag.tagFormatSimple,
            1
        )
    )

class NewPasswd(LDAPString):
    """
    newPasswd [2] OCTET STRING OPTIONAL
    """
    tagSet = LDAPString.tagSet.tagImplicitly(
        tag.Tag(
            tag.tagClassContext,
            tag.tagFormatSimple,
            2
        )
    )


class PassmodRequest(ExtendedRequest):
    """
    Password Modify extended request
    """
    __slots__ = (
        'userIdentity',
        'oldPasswd',
        'newPasswd',
    )
    requestName: str = '1.3.6.1.4.1.4203.1.11.1'

    class PasswdModifyRequestValue(univ.Sequence):
        """
        PasswdModifyRequestValue ::= SEQUENCE {
          userIdentity    [0]  OCTET STRING OPTIONAL,
          oldPasswd       [1]  OCTET STRING OPTIONAL,
          newPasswd       [2]  OCTET STRING OPTIONAL }
        """
        componentType = namedtype.NamedTypes(
            namedtype.OptionalNamedType('userIdentity', UserIdentity()),
            namedtype.OptionalNamedType('oldPasswd', OldPasswd()),
            namedtype.OptionalNamedType('newPasswd', NewPasswd()),
        )

    def __init__(self, userIdentity=None, oldPasswd=None, newPasswd=None):
        ExtendedRequest.__init__(self)
        self.userIdentity = userIdentity
        self.oldPasswd = oldPasswd
        self.newPasswd = newPasswd

    def encode(self) -> bytes:
        req_value = self.PasswdModifyRequestValue()
        req_value.setComponentByName(
            'userIdentity',
            UserIdentity(self.userIdentity.encode(self.encoding)),
        )
        if self.oldPasswd is not None:
            req_value.setComponentByName(
                'oldPasswd',
                OldPasswd(self.oldPasswd),
            )
        if self.newPasswd is not None:
            req_value.setComponentByName(
                'newPasswd',
                NewPasswd(self.newPasswd),
            )
        return encoder.encode(req_value)


class GenPasswd(LDAPString):
    """
    genPasswd       [0]     OCTET STRING OPTIONAL
    """
    tagSet = LDAPString.tagSet.tagImplicitly(
        tag.Tag(
            tag.tagClassContext,
            tag.tagFormatSimple,
            0
        )
    )
    encoding = 'utf-8'


class PasswdModifyResponseValue(univ.Sequence):
    """
    PasswdModifyResponseValue ::= SEQUENCE {
       genPasswd [0] OCTET STRING OPTIONAL }
    """
    componentType = namedtype.NamedTypes(
        namedtype.OptionalNamedType(
            'genPasswd',
            GenPasswd(),
        )
    )


class PassmodResponse(ExtendedResponse):
    """
    Password Modify extended response
    """
    __slots__ = (
        'genPasswd',
    )
    responseName = None

    def decode(self, value: bytes):
        self.genPasswd = None
        if value is None:
            return
        passmod_resp, _ = decoder.decode(
            value,
            asn1Spec=PasswdModifyResponseValue(),
        )
        if 'genPasswd' in passmod_resp:
            self.genPasswd = bytes(passmod_resp.getComponentByName('genPasswd'))

# -*- coding: utf-8 -*-
"""
ldap0.controls.simple - classes for some very simple LDAP controls
"""

import struct

import _libldap0

from ..__about__ import __version__, __author__, __license__
from . import RequestControl, ResponseControl, LDAPControl, KNOWN_RESPONSE_CONTROLS


__all__ = [
    'AuthorizationIdentityRequestControl',
    'AuthorizationIdentityResponseControl',
    'BooleanControl',
    'ManageDSAITControl',
    'OctetStringInteger',
    'ProxyAuthzControl',
    'RelaxRulesControl',
    'ValueLessRequestControl',
]


class ValueLessRequestControl(RequestControl):
    """
    Base class for controls without a controlValue.
    The presence of the control in a LDAPv3 request changes the server's
    behaviour when processing the request simply based on the controlType.

    controlType
      OID of the request control
    criticality
      criticality request control
    """

    def __init__(self, controlType=None, criticality=False):
        RequestControl.__init__(
            self,
            controlType=controlType,
            criticality=criticality,
        )

    def encode(self):
        return None


class OctetStringInteger(LDAPControl):
    """
    Base class with controlValue being unsigend integer values

    integerValue
      Integer to be sent as OctetString
    """

    def __init__(self, controlType=None, criticality=False, integerValue=None):
        LDAPControl.__init__(
            self,
            controlType=controlType,
            criticality=criticality,
        )
        self.integerValue = integerValue

    def encode(self):
        return struct.pack('!Q', self.integerValue)

    def decode(self, encodedControlValue):
        self.integerValue = struct.unpack('!Q', encodedControlValue)[0]


class BooleanControl(LDAPControl):
    """
    Base class for simple request controls with boolean control value.

    Constructor argument and class attribute:

    booleanValue
      Boolean (True/False or 1/0) which is the boolean controlValue.
    """
    boolean2ber = {
        1: b'\x01\x01\xFF',
        0: b'\x01\x01\x00',
    }
    ber2boolean = {
        b'\x01\x01\xFF': 1,
        b'\x01\x01\x00': 0,
    }

    def __init__(self, controlType=None, criticality=False, booleanValue=False):
        LDAPControl.__init__(
            self,
            controlType=controlType,
            criticality=criticality,
        )
        self.booleanValue = booleanValue

    def encode(self):
        return self.boolean2ber[int(self.booleanValue)]

    def decode(self, encodedControlValue):
        self.booleanValue = bool(self.ber2boolean[encodedControlValue])


class ManageDSAITControl(ValueLessRequestControl):
    """
    Manage DSA IT Control
    """
    controlType = _libldap0.CONTROL_MANAGEDSAIT

    def __init__(self, criticality=False):
        ValueLessRequestControl.__init__(
            self,
            criticality=criticality,
        )

KNOWN_RESPONSE_CONTROLS.reg(ManageDSAITControl)


class RelaxRulesControl(ValueLessRequestControl):
    """
    Relax Rules Control
    """
    controlType = _libldap0.CONTROL_RELAX

    def __init__(self, criticality=False):
        ValueLessRequestControl.__init__(
            self,
            criticality=criticality,
        )

KNOWN_RESPONSE_CONTROLS.reg(RelaxRulesControl)


class ProxyAuthzControl(RequestControl):
    """
    Proxy Authorization Control

    authzId
      string containing the authorization ID indicating the identity
      on behalf which the server should process the request
    """
    controlType = _libldap0.CONTROL_PROXY_AUTHZ

    def __init__(self, criticality=False, authzId=''):
        RequestControl.__init__(
            self,
            criticality=criticality,
            encodedControlValue=authzId,
        )


class AuthorizationIdentityRequestControl(ValueLessRequestControl):
    """
    Authorization Identity Request and Response Controls
    """
    controlType = b'2.16.840.1.113730.3.4.16'

    def __init__(self, criticality=False):
        ValueLessRequestControl.__init__(
            self,
            criticality=criticality,
        )


class AuthorizationIdentityResponseControl(ResponseControl):
    """
    Authorization Identity Request and Response Controls

    Class attributes:

    authzId
        decoded authorization identity
    """
    controlType = b'2.16.840.1.113730.3.4.15'

    def decode(self, encodedControlValue):
        self.authzId = encodedControlValue

KNOWN_RESPONSE_CONTROLS.reg(AuthorizationIdentityResponseControl)


class SubentriesControl(BooleanControl):
    """
    Subentries Control (RFC 3672)
    https://tools.ietf.org/html/rfc3672#section-3
    """
    controlType = b'1.3.6.1.4.1.4203.1.10.1'

    def __init__(self, criticality=False, booleanValue=False):
        BooleanControl.__init__(
            self,
            controlType=None,
            criticality=criticality,
            booleanValue=booleanValue
        )

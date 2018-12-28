# -*- coding: utf-8 -*-
"""
ldap0.controls.sessiontrack - class for session tracking control
(see draft-wahl-ldap-session)
"""

from __future__ import absolute_import

from ..__about__ import __version__, __author__, __license__
from . import RequestControl

from pyasn1.type import namedtype, univ
from pyasn1.codec.ber import encoder
from pyasn1_modules.rfc2251 import LDAPString, LDAPOID

__all__ = [
    'SessionTrackingControl',
    'SESSION_TRACKING_CONTROL_OID',
    'SESSION_TRACKING_FORMAT_OID_RADIUS_ACCT_SESSION_ID',
    'SESSION_TRACKING_FORMAT_OID_RADIUS_ACCT_MULTI_SESSION_ID',
    'SESSION_TRACKING_FORMAT_OID_USERNAME',
]

# OID constants
SESSION_TRACKING_CONTROL_OID = "1.3.6.1.4.1.21008.108.63.1"
SESSION_TRACKING_FORMAT_OID_RADIUS_ACCT_SESSION_ID = SESSION_TRACKING_CONTROL_OID+".1"
SESSION_TRACKING_FORMAT_OID_RADIUS_ACCT_MULTI_SESSION_ID = SESSION_TRACKING_CONTROL_OID+".2"
SESSION_TRACKING_FORMAT_OID_USERNAME = SESSION_TRACKING_CONTROL_OID+".3"


class SessionTrackingControl(RequestControl):
    """
    Class for Session Tracking Control

    Because criticality MUST be false for this control it cannot be set
    from the application.

    sessionSourceIp
      IP address of the request source as string
    sessionSourceName
      Name of the request source as string
    formatOID
      OID as string specifying the format
    sessionTrackingIdentifier
      String containing a specific tracking ID
    """
    controlType = SESSION_TRACKING_CONTROL_OID

    class SessionIdentifierControlValue(univ.Sequence):
        componentType = namedtype.NamedTypes(
            namedtype.NamedType('sessionSourceIp', LDAPString()),
            namedtype.NamedType('sessionSourceName', LDAPString()),
            namedtype.NamedType('formatOID', LDAPOID()),
            namedtype.NamedType('sessionTrackingIdentifier', LDAPString()),
        )


    def __init__(
            self,
            sessionSourceIp,
            sessionSourceName,
            formatOID,
            sessionTrackingIdentifier
        ):
        # criticality MUST be false for this control
        RequestControl.__init__(self, criticality=False)
        self.sessionSourceIp = sessionSourceIp
        self.sessionSourceName = sessionSourceName
        self.formatOID = formatOID
        self.sessionTrackingIdentifier = sessionTrackingIdentifier

    def encodeControlValue(self):
        scv = self.SessionIdentifierControlValue()
        scv.setComponentByName(
            'sessionSourceIp',
            LDAPString(self.sessionSourceIp)
        )
        scv.setComponentByName(
            'sessionSourceName',
            LDAPString(self.sessionSourceName)
        )
        scv.setComponentByName(
            'formatOID',
            LDAPOID(self.formatOID))
        scv.setComponentByName(
            'sessionTrackingIdentifier',
            LDAPString(self.sessionTrackingIdentifier)
        )
        return encoder.encode(scv)

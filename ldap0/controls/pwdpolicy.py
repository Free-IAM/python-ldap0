# -*- coding: utf-8 -*-
"""
ldap0.controls.pwdpolicy - classes for Password Policy controls
(see https://tools.ietf.org/html/draft-vchu-ldap-pwd-policy)
"""

from ..__about__ import __version__, __author__, __license__
from . import ResponseControl, KNOWN_RESPONSE_CONTROLS

__all__ = [
    'PasswordExpiringControl',
    'PasswordExpiredControl',
]


class PasswordExpiringControl(ResponseControl):
    """
    Indicates time in seconds when password will expire
    """
    controlType = '2.16.840.1.113730.3.4.5'

    def decode(self, encodedControlValue: bytes):
        self.gracePeriod = int(encodedControlValue)

KNOWN_RESPONSE_CONTROLS.reg(PasswordExpiringControl)


class PasswordExpiredControl(ResponseControl):
    """
    Indicates that password is expired
    """
    controlType = '2.16.840.1.113730.3.4.4'

    def decode(self, encodedControlValue: bytes):
        self.passwordExpired = (encodedControlValue == b'0')

KNOWN_RESPONSE_CONTROLS.reg(PasswordExpiredControl)

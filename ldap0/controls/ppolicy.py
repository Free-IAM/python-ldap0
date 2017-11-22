# -*- coding: utf-8 -*-
"""
ldap0.controls.ppolicy - classes for Password Policy controls
(see https://tools.ietf.org/html/draft-behera-ldap-password-policy)
"""

from ldap0.pkginfo import __version__, __author__, __license__
from ldap0.controls import ResponseControl, ValueLessRequestControl, KNOWN_RESPONSE_CONTROLS

# Imports from pyasn1
from pyasn1.type import tag, namedtype, namedval, univ, constraint
from pyasn1.codec.ber import decoder


__all__ = [
    'PasswordPolicyControl'
]


class PasswordPolicyWarning(univ.Choice):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType(
            'timeBeforeExpiration',
            univ.Integer().subtype(
                implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 0)
            )
        ),
        namedtype.NamedType(
            'graceAuthNsRemaining', univ.Integer().subtype(
                implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 1)
            )
        ),
    )


class PasswordPolicyError(univ.Enumerated):
    namedValues = namedval.NamedValues(
        ('passwordExpired', 0),
        ('accountLocked', 1),
        ('changeAfterReset', 2),
        ('passwordModNotAllowed', 3),
        ('mustSupplyOldPassword', 4),
        ('insufficientPasswordQuality', 5),
        ('passwordTooShort', 6),
        ('passwordTooYoung', 7),
        ('passwordInHistory', 8)
    )
    subtypeSpec = univ.Enumerated.subtypeSpec + constraint.SingleValueConstraint(
        0, 1, 2, 3, 4, 5, 6, 7, 8
    )


class PasswordPolicyResponseValue(univ.Sequence):
    componentType = namedtype.NamedTypes(
        namedtype.OptionalNamedType(
            'warning',
            PasswordPolicyWarning().subtype(
                implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 0)
            ),
        ),
        namedtype.OptionalNamedType(
            'error',
            PasswordPolicyError().subtype(
                implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 1)
            )
        ),
    )


class PasswordPolicyControl(ValueLessRequestControl, ResponseControl):
    controlType = '1.3.6.1.4.1.42.2.27.8.5.1'

    def __init__(self, criticality=False):
        ValueLessRequestControl.__init__(self, criticality=criticality)

    def decodeControlValue(self, encodedControlValue):
        ppolicy_value, _ = decoder.decode(
            encodedControlValue,
            asn1Spec=PasswordPolicyResponseValue(),
        )
        warning = ppolicy_value.getComponentByName('warning')
        if not warning.hasValue():
            self.timeBeforeExpiration, self.graceAuthNsRemaining = None, None
        else:
            timeBeforeExpiration = warning.getComponentByName('timeBeforeExpiration')
            if timeBeforeExpiration.hasValue():
                self.timeBeforeExpiration = int(timeBeforeExpiration)
            else:
                self.timeBeforeExpiration = None
            graceAuthNsRemaining = warning.getComponentByName('graceAuthNsRemaining')
            if graceAuthNsRemaining.hasValue():
                self.graceAuthNsRemaining = int(graceAuthNsRemaining)
            else:
                self.graceAuthNsRemaining = None
        error = ppolicy_value.getComponentByName('error')
        if error.hasValue():
            self.error = int(error)
        else:
            self.error = None


KNOWN_RESPONSE_CONTROLS.reg(PasswordPolicyControl)

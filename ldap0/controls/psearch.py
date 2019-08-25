# -*- coding: utf-8 -*-
"""
ldap0.controls.psearch - classes for Persistent Search Control
(see https://tools.ietf.org/html/draft-ietf-ldapext-psearch)
"""

# Imports from pyasn1
from pyasn1.type import namedtype, namedval, univ, constraint
from pyasn1.codec.ber import encoder, decoder
from pyasn1_modules.rfc2251 import LDAPDN

from ..__about__ import __version__, __author__, __license__
from . import RequestControl, ResponseControl, KNOWN_RESPONSE_CONTROLS

__all__ = [
    'PersistentSearchControl',
    'EntryChangeNotificationControl',
    'CHANGE_TYPES_INT',
    'CHANGE_TYPES_STR',
]

#---------------------------------------------------------------------------
# Constants and classes for Persistent Search Control
#---------------------------------------------------------------------------

CHANGE_TYPES_INT = {
    'add': 1,
    'delete': 2,
    'modify': 4,
    'modDN': 8,
}
CHANGE_TYPES_STR = {
    (v, k) for k, v in CHANGE_TYPES_INT.items()
}


class PersistentSearchControl(RequestControl):
    """
    Implements the request control for persistent search.

    changeTypes
      List of strings specifiying the types of changes returned by the server.
      Setting to None requests all changes.
    changesOnly
      Boolean which indicates whether only changes are returned by the server.
    returnECs
      Boolean which indicates whether the server should return an
      Entry Change Notication response control
    """
    controlType = b'2.16.840.1.113730.3.4.3'

    class PersistentSearchControlValue(univ.Sequence):
        """
        PersistentSearch ::= SEQUENCE {
                changeTypes INTEGER,
                changesOnly BOOLEAN,
                returnECs BOOLEAN
        }
        """
        componentType = namedtype.NamedTypes(
            namedtype.NamedType('changeTypes', univ.Integer()),
            namedtype.NamedType('changesOnly', univ.Boolean()),
            namedtype.NamedType('returnECs', univ.Boolean()),
        )

    def __init__(
            self,
            criticality=True,
            changeTypes=None,
            changesOnly=False,
            returnECs=True,
        ):
        RequestControl.__init__(self, criticality=criticality)
        self.changesOnly = changesOnly
        self.returnECs = returnECs
        if isinstance(changeTypes, int):
            self.changeTypes = changeTypes
        else:
            # Assume a sequence type of integers to be OR-ed
            self.changeTypes = 0
            for chtype in changeTypes or CHANGE_TYPES_INT.values():
                self.changeTypes = self.changeTypes|CHANGE_TYPES_INT.get(chtype, chtype)
        return

    def encodeControlValue(self):
        pval = self.PersistentSearchControlValue()
        pval.setComponentByName('changeTypes', univ.Integer(self.changeTypes))
        pval.setComponentByName('changesOnly', univ.Boolean(self.changesOnly))
        pval.setComponentByName('returnECs', univ.Boolean(self.returnECs))
        return encoder.encode(pval)


class ChangeType(univ.Enumerated):
    """
    changeType ENUMERATED {
        add             (1),
        delete          (2),
        modify          (4),
        modDN           (8)
    }
    """
    namedValues = namedval.NamedValues(
        ('add', 1),
        ('delete', 2),
        ('modify', 4),
        ('modDN', 8),
    )
    subtypeSpec = univ.Enumerated.subtypeSpec + constraint.SingleValueConstraint(1, 2, 4, 8)


class EntryChangeNotificationValue(univ.Sequence):
    """
    EntryChangeNotification ::= SEQUENCE {
        changeType <see ChangeType above>,
        previousDN   LDAPDN OPTIONAL,     -- modifyDN ops. only
        changeNumber INTEGER OPTIONAL     -- if supported
    }
    """
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('changeType', ChangeType()),
        namedtype.OptionalNamedType('previousDN', LDAPDN()),
        namedtype.OptionalNamedType('changeNumber', univ.Integer()),
    )


class EntryChangeNotificationControl(ResponseControl):
    """
    Implements the response control for persistent search.

    Class attributes with values extracted from the response control:

    changeType
      String indicating the type of change causing this result to be
      returned by the server
    previousDN
      Old DN of the entry in case of a modrdn change
    changeNumber
      A change serial number returned by the server (optional).
    """
    controlType = b'2.16.840.1.113730.3.4.7'

    def decodeControlValue(self, encodedControlValue):
        ecncValue, _ = decoder.decode(
            encodedControlValue,
            asn1Spec=EntryChangeNotificationValue(),
        )
        self.changeType = int(ecncValue.getComponentByName('changeType'))
        previousDN = ecncValue.getComponentByName('previousDN')
        if previousDN.hasValue():
            self.previousDN = bytes(previousDN)
        else:
            self.previousDN = None
        changeNumber = ecncValue.getComponentByName('changeNumber')
        if changeNumber.hasValue():
            self.changeNumber = int(changeNumber)
        else:
            self.changeNumber = None
        return (self.changeType, self.previousDN, self.changeNumber)

KNOWN_RESPONSE_CONTROLS.reg(EntryChangeNotificationControl)

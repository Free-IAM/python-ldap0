# -*- coding: utf-8 -*-
"""
ldap0.controls.readentry - classes for the Read Entry controls
(see RFC 4527)
"""

from ldap0.pkginfo import __version__, __author__, __license__
from ldap0.controls import LDAPControl, KNOWN_RESPONSE_CONTROLS
import _libldap0

from pyasn1.codec.ber import encoder, decoder
from pyasn1_modules.rfc2251 import AttributeDescriptionList, SearchResultEntry


class ReadEntryControl(LDAPControl):
    """
    Base class for read entry control described in RFC 4527

    attrList
        list of attribute type names requested

    Class attributes with values extracted from the response control:

    dn
        string holding the distinguished name of the LDAP entry
    entry
        dictionary holding the LDAP entry
    """

    def __init__(self, criticality=False, attrList=None):
        LDAPControl.__init__(self, criticality=criticality)
        self.attrList = attrList or []
        self.entry = None

    def encodeControlValue(self):
        attributeSelection = AttributeDescriptionList()
        for ind in range(len(self.attrList)):
            attributeSelection.setComponentByPosition(ind, self.attrList[ind])
        return encoder.encode(attributeSelection)

    def decodeControlValue(self, encodedControlValue):
        decodedEntry, _ = decoder.decode(
            encodedControlValue,
            asn1Spec=SearchResultEntry(),
        )
        self.dn = str(decodedEntry[0])
        self.entry = {}
        for attr in decodedEntry[1]:
            self.entry[str(attr[0])] = [
                str(attr_value)
                for attr_value in attr[1]
            ]


class PreReadControl(ReadEntryControl):
    """
    Class for pre-read control described in RFC 4527
    """
    controlType = _libldap0.CONTROL_PRE_READ

KNOWN_RESPONSE_CONTROLS.reg(PreReadControl)


class PostReadControl(ReadEntryControl):
    """
    Class for post-read control described in RFC 4527
    """
    controlType = _libldap0.CONTROL_POST_READ

KNOWN_RESPONSE_CONTROLS.reg(PostReadControl)

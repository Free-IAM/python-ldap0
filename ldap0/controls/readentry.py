# -*- coding: utf-8 -*-
"""
ldap0.controls.readentry - classes for the Read Entry controls
(see RFC 4527)
"""

from pyasn1.type import namedtype, univ
from pyasn1.codec.ber import encoder, decoder
from pyasn1.error import PyAsn1Error

from pyasn1_modules.rfc2251 import AttributeDescriptionList, SearchResultEntry
from pyasn1_modules.rfc2251 import LDAPDN, PartialAttributeList

from ..__about__ import __version__, __author__, __license__
from ..base import encode_list
from ..res import SearchResultEntry as LDAPResultSearchResultEntry
from . import LDAPControl, KNOWN_RESPONSE_CONTROLS


class OpenLDAPITS6899SearchResultEntry(univ.Sequence):
    """
    This is an ASN.1 description of SearchResultEntry not compliant to LDAPv3
    which implements a work-around for OpenLDAP's ITS#6899
    """
    tagSet = univ.Sequence.tagSet # work-around: instead of implicit tagging
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('objectName', LDAPDN()),
        namedtype.NamedType('attributes', PartialAttributeList())
    )


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
        self.attrList = encode_list(attrList or [], encoding='ascii')

    def encode(self):
        attributeSelection = AttributeDescriptionList()
        for ind in range(len(self.attrList)):
            attributeSelection.setComponentByPosition(ind, self.attrList[ind])
        return encoder.encode(attributeSelection)

    def decode(self, encodedControlValue: bytes):
        try:
            decodedEntry, _ = decoder.decode(
                encodedControlValue,
                asn1Spec=SearchResultEntry(),
            )
        except PyAsn1Error:
            decodedEntry, _ = decoder.decode(
                encodedControlValue,
                asn1Spec=OpenLDAPITS6899SearchResultEntry(),
            )
        self.res = LDAPResultSearchResultEntry(
            bytes(decodedEntry[0]),
            {
                bytes(attr[0]): [
                    bytes(attr_value)
                    for attr_value in attr[1]
                ]
                for attr in decodedEntry[1]
            },
        )

class PreReadControl(ReadEntryControl):
    """
    Class for pre-read control described in RFC 4527
    """
    controlType = '1.3.6.1.1.13.1'

KNOWN_RESPONSE_CONTROLS.reg(PreReadControl)


class PostReadControl(ReadEntryControl):
    """
    Class for post-read control described in RFC 4527
    """
    controlType = '1.3.6.1.1.13.2'

KNOWN_RESPONSE_CONTROLS.reg(PostReadControl)

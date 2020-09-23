# -*- coding: utf-8 -*-
"""
ldap0.controls.deref - classes for
(see https://tools.ietf.org/html/draft-masarati-ldap-deref)
"""

from pyasn1.type import namedtype, univ, tag
from pyasn1.codec.ber import encoder, decoder
from pyasn1_modules.rfc2251 import \
    LDAPDN, AttributeDescription, AttributeDescriptionList, AttributeValue

from . import LDAPControl, KNOWN_RESPONSE_CONTROLS
from ..res import SearchResultEntry

__all__ = [
    'DereferenceControl',
]

# Request types
#---------------------------------------------------------------------------

# For compability with ASN.1 declaration in I-D
AttributeList = AttributeDescriptionList

class DerefSpec(univ.Sequence):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('derefAttr', AttributeDescription()),
        namedtype.NamedType('attributes', AttributeList()),
    )

class DerefSpecs(univ.SequenceOf):
    componentType = DerefSpec()

# Response types
#---------------------------------------------------------------------------


class AttributeValues(univ.SetOf):
    componentType = AttributeValue()


class PartialAttribute(univ.Sequence):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('type', AttributeDescription()),
        namedtype.NamedType('vals', AttributeValues()),
    )


class PartialAttributeList(univ.SequenceOf):
    componentType = PartialAttribute()
    tagSet = univ.Sequence.tagSet.tagImplicitly(
        tag.Tag(tag.tagClassContext, tag.tagFormatConstructed, 0)
    )


class DerefRes(univ.Sequence):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('derefAttr', AttributeDescription()),
        namedtype.NamedType('derefVal', LDAPDN()),
        namedtype.OptionalNamedType('attrVals', PartialAttributeList()),
    )


class DerefResultControlValue(univ.SequenceOf):
    componentType = DerefRes()


class DereferenceControl(LDAPControl):
    controlType: str = '1.3.6.1.4.1.4203.666.5.16'

    def __init__(self, criticality=False, derefSpecs=None):
        LDAPControl.__init__(self, criticality=criticality)
        self.derefSpecs = derefSpecs or {}

    def _deref_specs(self):
        deref_specs = DerefSpecs()
        i = 0
        for deref_attr, deref_attribute_names in self.derefSpecs.items():
            deref_spec = DerefSpec()
            deref_attributes = AttributeList()
            for j, deref_attribute_name in enumerate(deref_attribute_names):
                deref_attributes.setComponentByPosition(
                    j,
                    deref_attribute_name.encode(self.encoding)
                )
            deref_spec.setComponentByName(
                'derefAttr',
                AttributeDescription(deref_attr.encode(self.encoding))
            )
            deref_spec.setComponentByName('attributes', deref_attributes)
            deref_specs.setComponentByPosition(i, deref_spec)
            i += 1
        return deref_specs

    def encode(self) -> bytes:
        return encoder.encode(self._deref_specs())

    def decode(self, encodedControlValue: bytes):
        decoded_value, _ = decoder.decode(
            encodedControlValue,
            asn1Spec=DerefResultControlValue()
        )
        self.derefRes = {}
        for deref_res in decoded_value:
            deref_attr = bytes(deref_res[0])
            deref_dn = bytes(deref_res[1])
            deref_vals = deref_res[2]
            deref_res_entry = SearchResultEntry(
                deref_dn,
                {
                    bytes(tv[0]): [bytes(tv1) for tv1 in tv[1]]
                    for tv in deref_vals or []
                },
                None,
            )
            try:
                self.derefRes[deref_attr.decode(self.encoding)].append(deref_res_entry)
            except KeyError:
                self.derefRes[deref_attr.decode(self.encoding)] = [deref_res_entry]

KNOWN_RESPONSE_CONTROLS.reg(DereferenceControl)

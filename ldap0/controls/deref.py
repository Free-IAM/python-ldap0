# -*- coding: utf-8 -*-
"""
ldap0.controls.deref - classes for
(see https://tools.ietf.org/html/draft-masarati-ldap-deref)
"""

from __future__ import absolute_import

from ..__about__ import __version__, __author__, __license__

from . import LDAPControl, KNOWN_RESPONSE_CONTROLS

from pyasn1.type import namedtype, univ, tag
from pyasn1.codec.ber import encoder, decoder
from pyasn1_modules.rfc2251 import \
    LDAPDN, AttributeDescription, AttributeDescriptionList, AttributeValue

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
    controlType = b'1.3.6.1.4.1.4203.666.5.16'

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
                deref_attributes.setComponentByPosition(j, deref_attribute_name)
            deref_spec.setComponentByName('derefAttr', AttributeDescription(deref_attr))
            deref_spec.setComponentByName('attributes', deref_attributes)
            deref_specs.setComponentByPosition(i, deref_spec)
            i += 1
        return deref_specs

    def encodeControlValue(self):
        return encoder.encode(self._deref_specs())

    def decodeControlValue(self, encodedControlValue):
        decoded_value, _ = decoder.decode(
            encodedControlValue,
            asn1Spec=DerefResultControlValue()
        )
        self.derefRes = {}
        for deref_res in decoded_value:
            deref_attr = str(deref_res[0])
            deref_val = str(deref_res[1])
            deref_vals = deref_res[2]
            deref_attrs = {}
            for tv in deref_vals or []:
                deref_attrs[str(tv[0])] = map(str, tv[1])
            try:
                self.derefRes[deref_attr].append((deref_val, deref_attrs))
            except KeyError:
                self.derefRes[deref_attr] = [(deref_val, deref_attrs)]

KNOWN_RESPONSE_CONTROLS.reg(DereferenceControl)

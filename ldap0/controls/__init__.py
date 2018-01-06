# -*- coding: utf-8 -*-
"""
ldap0.controls - support classes for LDAP controls

The ldap.controls module provides LDAPControl classes.
Each class provides support for a certain control.
"""

from __future__ import absolute_import

from ..__about__ import __version__, __author__, __license__

import _libldap0

from pyasn1.error import PyAsn1Error


__all__ = [
    'KNOWN_RESPONSE_CONTROLS',
    # Classes
    'AssertionControl',
    'BooleanControl',
    'LDAPControl',
    'ManageDSAITControl',
    'MatchedValuesControl',
    'RelaxRulesControl',
    'RequestControl',
    'ResponseControl',
    'SimplePagedResultsControl',
    'ValueLessRequestControl',
    # Functions
    'RequestControlTuples',
    'DecodeControlTuples',
]


class ControlRegistry(object):
    """
    A simple registry for extended controls and their handler class
    """

    def __init__(self):
        self.cmap = {}

    def reg(self, control_class):
        self.cmap[control_class.controlType] = control_class

    def get(self, control_type):
        return self.cmap[control_type]


# response control OID to class registry
KNOWN_RESPONSE_CONTROLS = ControlRegistry()


class RequestControl(object):
    """
    Base class for all request controls

    controlType
        OID as string of the LDAPv3 extended request control
    criticality
        sets the criticality of the control (boolean)
    encodedControlValue
        control value of the LDAPv3 extended request control
        (here it is the BER-encoded ASN.1 control value)
    """
    controlType = None

    def __init__(self, controlType=None, criticality=False, encodedControlValue=None):
        if controlType is not None:
            self.controlType = controlType
        self.criticality = criticality
        self.encodedControlValue = encodedControlValue

    def encodeControlValue(self):
        """
        sets class attribute encodedControlValue to the BER-encoded ASN.1
        control value composed by class attributes set before
        """
        return self.encodedControlValue


class ResponseControl(object):
    """
    Base class for all response controls

    controlType
        OID as string of the LDAPv3 extended response control
    criticality
        sets the criticality of the received control (boolean)
    """

    def __init__(self, controlType=None, criticality=False):
        if controlType is not None:
            self.controlType = controlType
        self.criticality = criticality

    def decodeControlValue(self, encodedControlValue):
        """
        decodes the BER-encoded ASN.1 control value and sets the appropriate
        class attributes
        """
        self.controlValue = encodedControlValue


class LDAPControl(RequestControl, ResponseControl):
    """
    Base class for combined request/response controls
    """

    def __init__(self, controlType=None, criticality=False, encodedControlValue=None):
        RequestControl.__init__(
            self,
            controlType=controlType,
            criticality=criticality,
            encodedControlValue=encodedControlValue,
        )


def RequestControlTuples(ldapControls):
    """
    Return list of readily encoded 3-tuples which can be directly
    passed to C module _ldap

    ldapControls
        sequence-type of RequestControl objects
    """
    if ldapControls is None:
        return None
    result = [
        (c.controlType, c.criticality, c.encodeControlValue())
        for c in ldapControls
    ]
    return result


def DecodeControlTuples(ldapControlTuples, knownLDAPControls=None):
    """
    Returns list of readily decoded ResponseControl objects

    ldapControlTuples
        Sequence-type of 3-tuples returned by _ldap.result() containing
        the encoded ASN.1 control values of response controls.
    knownLDAPControls
        Dictionary mapping extended control's OID to ResponseControl class
        of response controls known by the application. If None
        ldap.controls.KNOWN_RESPONSE_CONTROLS is used here.
    """
    if knownLDAPControls is None:
        knownLDAPControls = KNOWN_RESPONSE_CONTROLS
    result = []
    for controlType, criticality, encodedControlValue in ldapControlTuples or []:
        try:
            control = knownLDAPControls.get(controlType)(criticality=criticality)
        except KeyError:
            if criticality:
                raise _libldap0.UNAVAILABLE_CRITICAL_EXTENSION(
                    'Unknown critical response control, controlType %r' % (controlType)
                )
        else:
            try:
                control.decodeControlValue(encodedControlValue)
            except PyAsn1Error as err:
                if criticality:
                    raise err
            else:
                result.append(control)
    return result

# Import the standard sub-modules
from .simple import *
from .libldap import *

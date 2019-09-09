# -*- coding: utf-8 -*-
"""
ldap0.controls - support classes for LDAP controls

The ldap0.controls module provides LDAPControl classes.
Each class provides support for a certain control.
"""

from pyasn1.error import PyAsn1Error

import _libldap0

from ..__about__ import __version__, __author__, __license__


__all__ = [
    'KNOWN_RESPONSE_CONTROLS',
    # Classes
    'LDAPControl',
    'RequestControl',
    'ResponseControl',
    # Functions
    'encode_request_ctrls',
    'decode_response_ctrls',
]


class ControlRegistry:
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


class RequestControl:
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
    encoding = 'utf-8'
    controlType = None

    def __init__(self, controlType=None, criticality=False, encodedControlValue=None):
        if controlType is not None:
            self.controlType = controlType
        self.criticality = criticality
        self.encodedControlValue = encodedControlValue

    def encode(self):
        """
        sets class attribute encodedControlValue to the BER-encoded ASN.1
        control value composed by class attributes set before
        """
        return self.encodedControlValue


class ResponseControl:
    """
    Base class for all response controls

    controlType
        OID as string of the LDAPv3 extended response control
    criticality
        sets the criticality of the received control (boolean)
    """
    encoding = 'utf-8'

    def __init__(self, controlType=None, criticality=False):
        if controlType is not None:
            self.controlType = controlType
        self.criticality = criticality

    def decode(self, encodedControlValue):
        """
        decodes the BER-encoded ASN.1 control value and sets the appropriate
        class attributes
        """
        self.controlValue = encodedControlValue


class LDAPControl(RequestControl, ResponseControl):
    """
    Base class for combined request/response controls
    """
    encoding = 'utf-8'

    def __init__(self, controlType=None, criticality=False, encodedControlValue=None):
        RequestControl.__init__(
            self,
            controlType=controlType,
            criticality=criticality,
            encodedControlValue=encodedControlValue,
        )


def encode_request_ctrls(ctrls):
    """
    Return list of readily encoded 3-tuples which can be directly
    passed to C module _ldap

    ctrls
        sequence-type of RequestControl objects
    """
    if ctrls is None:
        return None
    return [
        (c.controlType.encode('ascii'), c.criticality, c.encode())
        for c in ctrls
    ]
    # end of encode_request_ctrls()


def decode_response_ctrls(ldapControlTuples, ctrl_reg=None):
    """
    Returns list of readily decoded ResponseControl objects

    ldapControlTuples
        Sequence-type of 3-tuples returned by _libldap0.result() containing
        the encoded ASN.1 control values of response controls.
    ctrl_reg
        Dictionary mapping extended control's OID to ResponseControl class
        of response controls known by the application. If None
        ldap0.controls.KNOWN_RESPONSE_CONTROLS is used here.
    """
    if ctrl_reg is None:
        ctrl_reg = KNOWN_RESPONSE_CONTROLS
    result = []
    for controlType, criticality, encodedControlValue in ldapControlTuples or []:
        controlType = controlType.decode('ascii')
        try:
            control_class = ctrl_reg.get(controlType)
        except KeyError:
            if criticality:
                raise _libldap0.UNAVAILABLE_CRITICAL_EXTENSION(
                    'Unknown critical response control, controlType %r' % (controlType)
                )
        else:
            control = control_class(criticality=criticality)
            try:
                control.decode(encodedControlValue)
            except PyAsn1Error as err:
                if criticality:
                    raise err
            else:
                result.append(control)
    return result
    # end of decode_response_ctrls()

# -*- coding: utf-8 -*-
"""
ldap0.controls - support classes for LDAP controls

The ldap0.controls module provides LDAPControl classes.
Each class provides support for a certain control.
"""

from typing import Dict, Optional, Sequence, Tuple

from pyasn1.error import PyAsn1Error

import _libldap0


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
    encoding: str = 'utf-8'
    controlType: Optional[str] = None

    def __init__(
            self,
            controlType: Optional[str] = None,
            criticality: bool = False,
            encodedControlValue: Optional[bytes] = None
        ):
        if controlType is not None:
            self.controlType = controlType
        self.criticality = criticality
        self.encodedControlValue = encodedControlValue

    def encode(self) -> bytes:
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
    encoding: str = 'utf-8'

    def __init__(
            self,
            controlType: Optional[str] = None,
            criticality: bool = False,
        ):
        if controlType is not None:
            self.controlType = controlType
        self.criticality = criticality

    def decode(self, encodedControlValue: bytes):
        """
        decodes the BER-encoded ASN.1 control value and sets the appropriate
        class attributes
        """
        self.controlValue = encodedControlValue


class LDAPControl(RequestControl, ResponseControl):
    """
    Base class for combined request/response controls
    """
    encoding: str = 'utf-8'
    controlType: Optional[str] = None

    def __init__(
            self,
            controlType: Optional[str] = None,
            criticality: bool = False,
            encodedControlValue: Optional[bytes] = None
        ):
        RequestControl.__init__(
            self,
            controlType=controlType,
            criticality=criticality,
            encodedControlValue=encodedControlValue,
        )


def encode_request_ctrls(
        ctrls: Sequence[RequestControl]
    ) -> Tuple[str, bool, bytes]:
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


def decode_response_ctrls(
        ctrls: Sequence[ResponseControl],
        ctrl_reg: Optional[Dict[str, ResponseControl]] = None,
    ):
    """
    Returns list of readily decoded ResponseControl objects

    ctrls
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
    for ctrl_type, ctrl_criticality, ctrl_val in ctrls or []:
        ctrl_type = ctrl_type.decode('ascii')
        try:
            control_class = ctrl_reg.get(ctrl_type)
        except KeyError:
            if ctrl_criticality:
                raise _libldap0.UNAVAILABLE_CRITICAL_EXTENSION(
                    'Unknown critical response control, ctrl_type %r' % (ctrl_type)
                )
        else:
            control = control_class(criticality=ctrl_criticality)
            try:
                control.decode(ctrl_val)
            except PyAsn1Error as err:
                if ctrl_criticality:
                    raise err
            else:
                result.append(control)
    return result
    # end of decode_response_ctrls()


class ControlRegistry:
    """
    A simple registry for extended controls and their handler class
    """

    cmap: Dict[str, ResponseControl]

    def __init__(self):
        self.cmap = {}

    def reg(self, control_class):
        self.cmap[control_class.controlType] = control_class

    def get(self, control_type):
        return self.cmap[control_type]


# response control OID to class registry
KNOWN_RESPONSE_CONTROLS = ControlRegistry()

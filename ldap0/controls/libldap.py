# -*- coding: utf-8 -*-
"""
ldap0.controls.libldap - LDAP controls wrapper classes with en-/decoding done
by OpenLDAP functions
"""

import _libldap0

from . import RequestControl


class AssertionControl(RequestControl):
    """
    LDAP Assertion control, as defined in RFC 4528

    filterstr
      LDAP filter string specifying which assertions have to match
      so that the server processes the operation
    """
    controlType: str = '1.3.6.1.1.12'

    def __init__(self, criticality: bool = True, filterstr: str = '(objectClass=*)'):
        RequestControl.__init__(self, criticality=criticality)
        self.filterstr = filterstr

    def encode(self) -> bytes:
        return _libldap0.encode_assertion_control(self.filterstr.encode(self.encoding))


class MatchedValuesControl(RequestControl):
    """
    LDAP Matched Values control, as defined in RFC 3876

    filterstr
      LDAP filter string specifying which attribute values
      should be returned
    """
    controlType: str = '1.2.826.0.1.3344810.2.3'

    def __init__(self, criticality: bool = False, filterstr: str = '(objectClass=*)'):
        RequestControl.__init__(self, criticality=criticality)
        self.filterstr = filterstr

    def encode(self) -> bytes:
        return _libldap0.encode_valuesreturnfilter_control(self.filterstr.encode(self.encoding))

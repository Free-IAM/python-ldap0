# -*- coding: utf-8 -*-
"""
ldap0.controls.libldap - LDAP controls wrapper classes with en-/decoding done
by OpenLDAP functions
"""

from __future__ import absolute_import

from ldap0.pkginfo import __version__, __author__, __license__
from ldap0.controls import RequestControl, LDAPControl, KNOWN_RESPONSE_CONTROLS
import _libldap0


class AssertionControl(RequestControl):
    """
    LDAP Assertion control, as defined in RFC 4528

    filterstr
      LDAP filter string specifying which assertions have to match
      so that the server processes the operation
    """
    controlType = _libldap0.CONTROL_ASSERT

    def __init__(self, criticality=True, filterstr='(objectClass=*)'):
        RequestControl.__init__(self, criticality=criticality)
        self.filterstr = filterstr

    def encodeControlValue(self):
        return _libldap0.encode_assertion_control(self.filterstr)


class MatchedValuesControl(RequestControl):
    """
    LDAP Matched Values control, as defined in RFC 3876

    filterstr
      LDAP filter string specifying which attribute values
      should be returned
    """
    controlType = _libldap0.CONTROL_VALUESRETURNFILTER

    def __init__(self, criticality=False, filterstr='(objectClass=*)'):
        RequestControl.__init__(self, criticality=criticality)
        self.filterstr = filterstr

    def encodeControlValue(self):
        return _libldap0.encode_valuesreturnfilter_control(self.filterstr)


class SimplePagedResultsControl(LDAPControl):
    """
    LDAP Control Extension for Simple Paged Results Manipulation

    size
      Page size requested (number of entries to be returned)
    cookie
      Cookie string received with last page
    """
    controlType = _libldap0.CONTROL_PAGEDRESULTS

    def __init__(self, criticality=False, size=None, cookie=None):
      self.criticality = criticality
      self.size = size
      self.cookie = cookie

    def encodeControlValue(self):
      return _libldap0.encode_page_control(self.size, self.cookie)

    def decodeControlValue(self,encodedControlValue):
      self.size,self.cookie = _libldap0.decode_page_control(encodedControlValue)

KNOWN_RESPONSE_CONTROLS.reg(SimplePagedResultsControl)

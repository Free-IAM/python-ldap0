# -*- coding: utf-8 -*-
"""
ldap0.extop.whoami - Classes for "Who am I?" extended operation
(see RFC 4532)
"""

from __future__ import absolute_import

from ldap0.pkginfo import __version__, __author__, __license__
from ldap0.extop import ExtendedRequest, ExtendedResponse

# Imports from pyasn1
from pyasn1.type import namedtype, univ, tag
from pyasn1.codec.der import encoder, decoder
from pyasn1_modules.rfc2251 import LDAPString


class WhoAmIRequest(ExtendedRequest):

    requestName = '1.3.6.1.4.1.4203.1.11.3'


class WhoAmIResponse(ExtendedResponse):

    responseName = None

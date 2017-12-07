# -*- coding: utf-8 -*-
"""
ldap0.extop.whoami - Classes for "Who am I?" extended operation
(see RFC 4532)
"""

from __future__ import absolute_import

from ..pkginfo import __version__, __author__, __license__
from . import ExtendedRequest, ExtendedResponse


class WhoAmIRequest(ExtendedRequest):
    """
    Who Am I? extended request
    """

    requestName = '1.3.6.1.4.1.4203.1.11.3'


class WhoAmIResponse(ExtendedResponse):
    """
    Who Am I? extended response
    """

    responseName = None

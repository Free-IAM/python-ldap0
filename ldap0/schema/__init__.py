# -*- coding: utf-8 -*-
"""
ldap0.schema -  LDAPv3 schema handling
"""

from __future__ import absolute_import

from ldap0.pkginfo import __version__, __author__, __license__

from .subentry import SCHEMA_ATTRS, SCHEMA_CLASS_MAPPING, SCHEMA_ATTR_MAPPING
from .subentry import SubSchema

"""
ldap.schema -  LDAPv3 schema handling

See https://www.stroeder.com/python-ldap0 for details.
"""

from ldap0.pkginfo import __version__, __author__, __license__

from ldap0.schema.subentry import SCHEMA_ATTRS, SCHEMA_CLASS_MAPPING, SCHEMA_ATTR_MAPPING
from ldap0.schema.subentry import SubSchema, urlfetch
from ldap0.schema.models import *

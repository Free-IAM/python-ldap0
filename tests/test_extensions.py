# -*- coding: utf-8 -*-
"""
Automatic tests for module ldap0.controls for extended controls and
extended operations only usable with certain slapd overlays not
available in all OpenLDAP builds
"""

from __future__ import absolute_import

import os
import unittest
from slapdtest import SlapdTestCase

# Switch off processing .ldaprc or ldap0.conf before importing _ldap
os.environ['LDAPNOINIT'] = '1'

import _libldap0
from ldap0 import LDAPError
from ldap0.ldapobject import LDAPObject
from ldap0.filter import escape_filter_chars
from ldap0.modlist import addModlist

from ldap0.controls.deref import DereferenceControl
from ldap0.controls.openldap import SearchNoOpControl
from ldap0.controls.ppolicy import PasswordPolicyControl
from ldap0.controls.sss import SSSRequestControl, SSSResponseControl
from ldap0.controls.vlv import VLVRequestControl, VLVResponseControl

LDIF_TEMPLATE = """dn: %(suffix)s
objectClass: dcObject
objectClass: organization
dc: %(dc)s
o: %(dc)s

dn: %(rootdn)s
objectClass: applicationProcess
objectClass: simpleSecurityObject
cn: %(rootcn)s
userPassword: %(rootpw)s

dn: cn=user1,%(suffix)s
objectClass: applicationProcess
objectClass: simpleSecurityObject
cn: user1
userPassword: user1_pw

dn: cn=Foo2,%(suffix)s
objectClass: organizationalRole
cn: Foo2

dn: cn=Foo1,%(suffix)s
objectClass: organizationalRole
cn: Foo1

dn: cn=Foo3,%(suffix)s
objectClass: organizationalRole
cn: Foo3
roleOccupant: cn=user1,%(suffix)s

dn: ou=Container,%(suffix)s
objectClass: organizationalUnit
ou: Container

dn: cn=Foo5,ou=Container,%(suffix)s
objectClass: organizationalRole
cn: Foo5
roleOccupant: cn=user1,%(suffix)s

dn: cn=Foo4,ou=Container,%(suffix)s
objectClass: organizationalRole
cn: Foo4

dn: cn=Foo7,ou=Container,%(suffix)s
objectClass: organizationalRole
cn: Foo7
roleOccupant: cn=user1,%(suffix)s
roleOccupant: cn=Foo1,%(suffix)s
roleOccupant: cn=Foo6,ou=Container,%(suffix)s

dn: cn=Foo6,ou=Container,%(suffix)s
objectClass: organizationalRole
cn: Foo6

"""


class Test00_SimpleLDAPObject(SlapdTestCase):
    """
    test LDAP search operations
    """
    ldap_object_class = LDAPObject
    maxDiff = None
    trace_level = 0

    @classmethod
    def setUpClass(cls):
        super(Test00_SimpleLDAPObject, cls).setUpClass()
        # insert some Foo* objects via ldapadd
        cls.server.ldapadd(
            LDIF_TEMPLATE % {
                'suffix':cls.server.suffix,
                'rootdn':cls.server.root_dn,
                'rootcn':cls.server.root_cn,
                'rootpw':cls.server.root_pw,
                'dc': cls.server.suffix.split(',')[0][3:],
            }
        )

    def setUp(self):
        try:
            self._ldap_conn
        except AttributeError:
            # open local LDAP connection
            self._ldap_conn = self._open_ldap_conn()
            self.mdb_config_dn, _ = self._ldap_conn.search_s(
                'cn=config',
                _libldap0.SCOPE_SUBTREE,
                '(olcSuffix={0})'.format(
                    escape_filter_chars(self.server.suffix)
                ),
            )[0]

    def _add_overlay(self, slapo_entry):
        olc_overlay = slapo_entry['olcOverlay'][0]
        try:
            self._ldap_conn.modify_s(
                'cn=module{0},cn=config',
                [(_libldap0.MOD_ADD, 'olcModuleLoad', [olc_overlay])]
            )
            self._ldap_conn.add_s(
                'olcOverlay={{0}}{0},{1}'.format(
                    olc_overlay,
                    self.mdb_config_dn,
                ),
                addModlist(slapo_entry),
            )
            self._ldap_conn.add_s(
                'olcOverlay={{0}}{0},{1}'.format(
                    olc_overlay,
                    self.mdb_config_dn,
                ),
                addModlist(slapo_entry),
            )
        except _libldap0.OTHER as ldap_err:
            self.skipTest(
                'installing slapo-%s failed: %s' % (
                    olc_overlay,
                    ldap_err,
                )
            )

    def test_deref(self):
        self._add_overlay({
            'olcOverlay': ['deref'],
            'objectClass': ['olcOverlayConfig'],
        })

    def test_noopsrch(self):
        self._add_overlay({
            'olcOverlay': ['noopsrch'],
            'objectClass': ['olcOverlayConfig'],
        })

    def test_dds(self):
        self._add_overlay({
            'olcOverlay': ['dds'],
            'objectClass': ['olcOverlayConfig', 'olcDDSConfig'],
            'olcDDSdefaultTtl': '1h',
            'olcDDSmaxTtl': '1d',
            'olcDDSminTtl': '1m',
            'olcDDSstate': 'TRUE',
        })

    def test_ppolicy(self):
        self._add_overlay({
            'olcOverlay': ['ppolicy'],
            'objectClass': ['olcOverlayConfig', 'olcPPolicyConfig'],
            'olcPPolicyDefault': 'cn=ppolicy-default,'+self.server.suffix,
            'olcPPolicyForwardUpdates': 'FALSE',
            'olcPPolicyHashCleartext': 'FALSE',
            'olcPPolicyUseLockout': 'TRUE',
            'olcPPolicyUseLockout': 'TRUE',
        })


if __name__ == '__main__':
    unittest.main()

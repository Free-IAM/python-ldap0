# -*- coding: utf-8 -*-
"""
Automatic tests for module ldap0.controls for extended controls and
extended operations only usable with certain slapd overlays not
available in all OpenLDAP builds
"""

from __future__ import absolute_import

import os
import unittest
from ldap0.test import SlapdTestCase

# Switch off processing .ldaprc or ldap0.conf before importing _ldap
os.environ['LDAPNOINIT'] = '1'

import _libldap0
import ldap0
from ldap0 import LDAPError
from ldap0.ldapobject import LDAPObject

from ldap0.controls.simple import ManageDSAITControl
from ldap0.controls.deref import DereferenceControl
from ldap0.controls.openldap import SearchNoOpControl
from ldap0.controls.ppolicy import PasswordPolicyControl
from ldap0.controls.sss import SSSRequestControl, SSSResponseControl
from ldap0.controls.vlv import VLVRequestControl, VLVResponseControl

from ldap0.extop.dds import RefreshRequest, RefreshResponse


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

dn: dc=ref1,%(suffix)s
objectClass: referral
objectClass: dcObject
dc: ref1
ref: ldap://ldap.example.com/dc=example,dc=com??one?(objectClass=*)

dn: dc=ref2,%(suffix)s
objectClass: referral
objectClass: dcObject
dc: ref2
ref: ldap://ldap.example.net/

"""


class ExtensionTestCase(SlapdTestCase):
    """
    test LDAP search operations
    """
    ldap_object_class = LDAPObject
    maxDiff = None
    trace_level = 0

    @classmethod
    def setUpClass(cls):
        super(ExtensionTestCase, cls).setUpClass()
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


class TestDeRef(ExtensionTestCase):

    def test_deref(self):
        self.enable_overlay({
            'olcOverlay': ['deref'],
            'objectClass': ['olcOverlayConfig'],
        })
        ldap_result = self._ldap_conn.search_s(
            'cn=Foo7,ou=Container,%s' % (self.server.suffix),
            ldap0.SCOPE_BASE,
            serverctrls=[
                DereferenceControl(
                    True,
                    {'roleOccupant': ['cn', 'uid']},
                )
            ],
            add_ctrls=True,
        )
        import pprint
        dn, entry, crtls = ldap_result[0]
        self.assertEqual(dn, 'cn=Foo7,ou=Container,%s' % (self.server.suffix))
        self.assertEqual(
            entry,
            {
                'cn': ['Foo7'],
                'objectClass': ['organizationalRole'],
                'roleOccupant': [
                    'cn=user1,%s' % (self.server.suffix),
                    'cn=Foo1,%s' % (self.server.suffix),
                    'cn=Foo6,ou=Container,%s' % (self.server.suffix)
                ],
            },
        )
        deref_crtl = crtls[0]
        self.assertEqual(isinstance(deref_crtl, DereferenceControl), True)
        self.assertEqual(
            deref_crtl.derefRes,
            {
                'roleOccupant': [
                    ('cn=user1,%s' % (self.server.suffix), {'cn': ['user1']}),
                    ('cn=Foo1,%s' % (self.server.suffix), {'cn': ['Foo1']}),
                    ('cn=Foo6,ou=Container,%s' % (self.server.suffix), {'cn': ['Foo6']}),
                ]
            }
        )


class TestNoopSrch(ExtensionTestCase):

    def test_noopsrch(self):
        self.enable_overlay({
            'olcOverlay': ['noopsrch'],
            'objectClass': ['olcOverlayConfig'],
        })
        expected_num_refs = LDIF_TEMPLATE.count('objectClass: referral')
        expected_num_entries = LDIF_TEMPLATE.count('dn: ') - expected_num_refs
        num_entries, num_refs = self._ldap_conn.noop_search(
            self.server.suffix,
            ldap0.SCOPE_SUBTREE,
        )
        self.assertEqual(num_entries, expected_num_entries)
        self.assertEqual(num_refs, expected_num_refs)
        num_entries, num_refs = self._ldap_conn.noop_search(
            self.server.suffix,
            ldap0.SCOPE_SUBTREE,
            '(objectClass=organizationalRole)',
        )
        self.assertEqual(num_entries, LDIF_TEMPLATE.count('objectClass: organizationalRole'))
        self.assertEqual(num_refs, LDIF_TEMPLATE.count('objectClass: referral'))
        num_entries, num_refs = self._ldap_conn.noop_search(
            self.server.suffix,
            ldap0.SCOPE_SUBTREE,
            serverctrls=[ManageDSAITControl()]
        )
        self.assertEqual(num_entries, LDIF_TEMPLATE.count('dn: '))
        self.assertEqual(num_refs, 0)


class TestDDS(ExtensionTestCase):

    def test_dds(self):
        self.enable_overlay({
            'olcOverlay': ['dds'],
            'objectClass': ['olcOverlayConfig', 'olcDDSConfig'],
            'olcDDSdefaultTtl': ['1h'],
            'olcDDSmaxTtl': ['1d'],
            'olcDDSminTtl': ['1m'],
            'olcDDSstate': ['TRUE'],
        })
        root_dse = self._ldap_conn.read_rootdse_s(attrlist=['dynamicSubtrees'])
        if 'dynamicSubtrees' not in root_dse:
            self.skipTest('slapo-dds not enabled in rootDSE')
        self.assertEqual(root_dse['dynamicSubtrees'][0], self.server.suffix)
        dds_entry_dn = 'cn=dds-1,'+self.server.suffix
        self._ldap_conn.add_s(
            dds_entry_dn,
            {
                'objectClass': ['applicationProcess', 'dynamicObject'],
                'cn': ['dds-1'],
            },
        )
        refresh_response = self._ldap_conn.extop_s(
            RefreshRequest(
                entryName=dds_entry_dn,
                requestTtl=247,
            ),
            extop_resp_class=RefreshResponse,
        )
        self.assertEqual(refresh_response.responseTtl, 247)
        self.assertEqual(self._ldap_conn.refresh_s(dds_entry_dn, ttl=178), 178)
        self.assertEqual(self._ldap_conn.refresh_s(dds_entry_dn, ttl=42), 60)
        self.assertEqual(self._ldap_conn.refresh_s(dds_entry_dn), 86400)


class TestPPolicy(ExtensionTestCase):

    def test_ppolicy(self):
        ppolicy_default_dn = 'cn=ppolicy-default,'+self.server.suffix
        self.enable_overlay(
            {
                'olcOverlay': ['ppolicy'],
                'objectClass': ['olcOverlayConfig', 'olcPPolicyConfig'],
                'olcPPolicyDefault': [ppolicy_default_dn],
                'olcPPolicyForwardUpdates': ['FALSE'],
                'olcPPolicyHashCleartext': ['FALSE'],
                'olcPPolicyUseLockout': ['TRUE'],
                'olcPPolicyUseLockout': ['TRUE'],
            },
            ['ppolicy.ldif'],
        )
        self._ldap_conn.add_s(
            ppolicy_default_dn,
            {
                'objectClass': ['applicationProcess', 'pwdPolicy'],
                'cn': ['ppolicy-default'],
                'pwdAttribute': ['userPassword'],
            },
        )


class TestSssVlv(ExtensionTestCase):

    def test_sssvlv(self):
        self.enable_overlay(
            {
                'olcOverlay': ['sssvlv'],
                'objectClass': ['olcOverlayConfig', 'olcSssVlvConfig'],
                'olcSssVlvMax': ['0'],
                'olcSssVlvMaxKeys': ['5'],
                'olcSssVlvMaxPerConn': ['5'],
            },
        )
        ldap_result = self._ldap_conn.search_s(
            self.server.suffix,
            ldap0.SCOPE_SUBTREE,
            '(objectClass:=organizationalRole)',
            attrlist=['cn'],
            serverctrls=[
                SSSRequestControl(
                    criticality=True,
                    ordering_rules=['-cn:caseExactOrderingMatch']
                )
            ],
        )
        self.assertEqual(
            ldap_result,
            [
                ('cn=Foo7,ou=Container,dc=slapd-test,dc=example,dc=org', {'cn': ['Foo7']}),
                ('cn=Foo6,ou=Container,dc=slapd-test,dc=example,dc=org', {'cn': ['Foo6']}),
                ('cn=Foo5,ou=Container,dc=slapd-test,dc=example,dc=org', {'cn': ['Foo5']}),
                ('cn=Foo4,ou=Container,dc=slapd-test,dc=example,dc=org', {'cn': ['Foo4']}),
                ('cn=Foo3,dc=slapd-test,dc=example,dc=org', {'cn': ['Foo3']}),
                ('cn=Foo2,dc=slapd-test,dc=example,dc=org', {'cn': ['Foo2']}),
                ('cn=Foo1,dc=slapd-test,dc=example,dc=org', {'cn': ['Foo1']}),
            ]
        )
        msg_id = self._ldap_conn.search(
            self.server.suffix,
            ldap0.SCOPE_SUBTREE,
            '(objectClass:=organizationalRole)',
            attrlist=['cn'],
            serverctrls=[
                SSSRequestControl(
                    criticality=True,
                    ordering_rules=['cn:caseExactOrderingMatch']
                )
            ],
            sizelimit=1,
        )
        ldap_result = []
        try:
            for _, res_data, _, res_controls in self._ldap_conn.results(msg_id):
                ldap_result.extend(res_data)
        except ldap0.SIZELIMIT_EXCEEDED:
            pass
        self.assertEqual(
            ldap_result,
            [
                ('cn=Foo1,dc=slapd-test,dc=example,dc=org', {'cn': ['Foo1']}),
            ]
        )


if __name__ == '__main__':
    unittest.main()

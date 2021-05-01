# -*- coding: utf-8 -*-
"""
Automatic tests for module ldap0.controls for extended controls and
extended operations only usable with certain slapd overlays not
available in all OpenLDAP builds
"""

import os
import unittest

from ldap0.test import SlapdTestCase

# Switch off processing .ldaprc or ldap0.conf before importing _ldap
os.environ['LDAPNOINIT'] = '1'

import ldap0
from ldap0.ldapobject import LDAPObject
from ldap0.res import SearchResultEntry
from ldap0.controls.simple import ManageDSAITControl
from ldap0.controls.deref import DereferenceControl
from ldap0.controls.openldap import SearchNoOpControl
from ldap0.controls.sss import SSSRequestControl, SSSResponseControl
from ldap0.controls.vlv import VLVRequestControl, VLVResponseControl
from ldap0.controls.simple import (
    AuthorizationIdentityRequestControl,
    AuthorizationIdentityResponseControl,
)

from ldap0.extop.dds import RefreshRequest, RefreshResponse


LDIF_TEMPLATE = """dn: %(suffix)s
objectClass: organization
o: %(o)s

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

dn: ou=Groups,%(suffix)s
objectClass: organizationalUnit
ou: Container

dn: cn=Bar1,ou=Groups,%(suffix)s
objectClass: posixGroup
cn: Bar1
gidNumber: 10001

dn: cn=Bar3,ou=Groups,%(suffix)s
objectClass: posixGroup
cn: Bar3
gidNumber: 10003

dn: cn=Bar4,ou=Groups,%(suffix)s
objectClass: posixGroup
cn: Bar4
gidNumber: 10004

dn: cn=Bar2,ou=Groups,%(suffix)s
objectClass: posixGroup
cn: Bar2
gidNumber: 10002

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
            (LDIF_TEMPLATE % {
                'suffix':cls.server.suffix,
                'rootdn':cls.server.root_dn,
                'rootcn':cls.server.root_cn,
                'rootpw':cls.server.root_pw,
                'o': cls.server.suffix.split(',')[0][3:],
            }).encode('utf-8')
        )


class TestDeRef(ExtensionTestCase):

    def test001_deref_search_s(self):
        self.enable_overlay({
            'olcOverlay': ['deref'],
            'objectClass': ['olcOverlayConfig'],
        })
        ldap_result = self._ldap_conn.search_s(
            'cn=Foo7,ou=Container,%s' % (self.server.suffix),
            ldap0.SCOPE_BASE,
            req_ctrls=[
                DereferenceControl(
                    True,
                    {'roleOccupant': ['cn', 'uid']},
                )
            ],
            cache_ttl=1.0,
        )

        self.assertEqual(
            ldap_result[0].dn_s,
            'cn=Foo7,ou=Container,%s' % (self.server.suffix)
        )
        self.assertEqual(
            ldap_result[0].entry_as,
            {
                'cn': [b'Foo7'],
                'objectClass': [b'organizationalRole'],
                'roleOccupant': [
                    b'cn=user1,%s' % (self.server.suffix.encode('utf-8')),
                    b'cn=Foo1,%s' % (self.server.suffix.encode('utf-8')),
                    b'cn=Foo6,ou=Container,%s' % (self.server.suffix.encode('utf-8'))
                ],
            },
        )
        deref_ctrl = ldap_result[0].ctrls[0]
        self.assertEqual(isinstance(deref_ctrl, DereferenceControl), True)
        self.assertEqual(
            deref_ctrl.derefRes,
            {
                'roleOccupant': [
                    SearchResultEntry(b'cn=user1,%s' % (self.server.suffix.encode('utf-8')), {b'cn': [b'user1']}),
                    SearchResultEntry(b'cn=Foo1,%s' % (self.server.suffix.encode('utf-8')), {b'cn': [b'Foo1']}),
                    SearchResultEntry(b'cn=Foo6,ou=Container,%s' % (self.server.suffix.encode('utf-8')), {b'cn': [b'Foo6']}),
                ]
            }
        )
        del ldap_result; del deref_ctrl
        ldap_result = self._ldap_conn.find_unique_entry(
            self.server.suffix,
            ldap0.SCOPE_SUBTREE,
            '(cn=Foo7)',
            req_ctrls=[
                DereferenceControl(
                    True,
                    {'roleOccupant': ['cn', 'uid']},
                )
            ],
        )
        self.assertEqual(ldap_result.dn_s, 'cn=Foo7,ou=Container,%s' % (self.server.suffix))
        self.assertEqual(
            ldap_result.entry_as,
            {
                'cn': [b'Foo7'],
                'objectClass': [b'organizationalRole'],
                'roleOccupant': [
                    b'cn=user1,%s' % (self.server.suffix.encode('utf-8')),
                    b'cn=Foo1,%s' % (self.server.suffix.encode('utf-8')),
                    b'cn=Foo6,ou=Container,%s' % (self.server.suffix.encode('utf-8'))
                ],
            },
        )
        deref_ctrl = ldap_result.ctrls[0]
        self.assertEqual(isinstance(deref_ctrl, DereferenceControl), True)
        self.assertEqual(
            deref_ctrl.derefRes,
            {
                'roleOccupant': [
                    SearchResultEntry(b'cn=user1,%s' % (self.server.suffix.encode('utf-8')), {b'cn': [b'user1']}),
                    SearchResultEntry(b'cn=Foo1,%s' % (self.server.suffix.encode('utf-8')), {b'cn': [b'Foo1']}),
                    SearchResultEntry(b'cn=Foo6,ou=Container,%s' % (self.server.suffix.encode('utf-8')), {b'cn': [b'Foo6']}),
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
            req_ctrls=[ManageDSAITControl()]
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
        if 'dynamicSubtrees' not in root_dse.entry_s:
            self.skipTest('slapo-dds not enabled in rootDSE')
        self.assertEqual(root_dse.entry_s['dynamicSubtrees'][0], self.server.suffix)
        dds_entry_dn = 'cn=dds-1,'+self.server.suffix
        self._ldap_conn.add_s(
            dds_entry_dn,
            {
                'objectClass': [b'applicationProcess', b'dynamicObject'],
                'cn': [b'dds-1'],
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
        wanted_results = [
            (
                'cn=Bar%d,ou=Groups,%s' % (i, self.server.suffix),
                {'cn': [b'Bar%d' % i]},
            )
            for i in range(4, 0, -1)
        ]

        for ordr in (
            ('-cn:caseExactOrderingMatch',),
            ('-cn:caseExactOrderingMatch',),
            ('-gidNumber:integerOrderingMatch',),
            ('-gidNumber',),
            ('-gidNumber', 'createTimestamp',),
        ):
            ldap_result = self._ldap_conn.search_s(
                self.server.suffix,
                ldap0.SCOPE_SUBTREE,
                '(objectClass=posixGroup)',
                attrlist=['cn'],
                req_ctrls=[SSSRequestControl(criticality=True, ordering_rules=ordr)],
            )
            self.assertEqual([(lr.dn_s, lr.entry_as) for lr in ldap_result], wanted_results)
        msg_id = self._ldap_conn.search(
            self.server.suffix,
            ldap0.SCOPE_SUBTREE,
            '(objectClass:=organizationalRole)',
            attrlist=['cn'],
            req_ctrls=[
                SSSRequestControl(
                    criticality=True,
                    ordering_rules=['cn:caseExactOrderingMatch']
                )
            ],
            sizelimit=1,
        )
        ldap_result = []
        try:
            for ldap_res in self._ldap_conn.results(msg_id):
                ldap_result.extend(ldap_res.rdata)
        except ldap0.SIZELIMIT_EXCEEDED:
            pass
        self.assertEqual(
            [(lr.dn_s, lr.entry_as) for lr in ldap_result],
            [
                (
                    'cn=Foo1,%s' % (self.server.suffix),
                    {'cn': [b'Foo1']}
                ),
            ]
        )


class TestAuthzID(ExtensionTestCase):

    def test001_authz_id(self):
        root_dse = self._ldap_conn.read_rootdse_s(attrlist=['supportedControl'])
        self.assertNotIn(AuthorizationIdentityRequestControl.controlType, root_dse.entry_s['supportedControl'])
        self.enable_overlay(
            {
                'olcOverlay': ['authzid'],
                'objectClass': ['olcOverlayConfig'],
            },
            config_dn='olcDatabase={-1}frontend,cn=config',
        )
        root_dse = self._ldap_conn.read_rootdse_s(attrlist=['supportedControl'])
        self.assertIn(AuthorizationIdentityRequestControl.controlType, root_dse.entry_s['supportedControl'])
        bind_dn = 'cn=user1,'+self.server.suffix
        bind_pw = 'user1_pw'.encode('ascii')
        with self.ldap_object_class(self.server.ldap_uri) as l:
            bind_res = l.simple_bind_s(bind_dn, bind_pw)
            whoami_dn = l._whoami_dn
        self.assertEqual(whoami_dn, None)
        with self.ldap_object_class(self.server.ldap_uri) as l:
            bind_res = l.simple_bind_s(
                bind_dn,
                bind_pw,
                req_ctrls=[AuthorizationIdentityRequestControl()],
            )
            whoami_dn = l._whoami_dn
        self.assertEqual(len(bind_res.ctrls), 1)
        self.assertIsInstance(bind_res.ctrls[0], AuthorizationIdentityResponseControl)
        self.assertEqual(
            bind_res.ctrls[0].authzId.decode('utf-8'),
            'dn:'+bind_dn
        )
        self.assertEqual(whoami_dn, bind_dn)


if __name__ == '__main__':
    unittest.main()

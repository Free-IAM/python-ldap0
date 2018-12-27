# -*- coding: utf-8 -*-
"""
Automatic tests for module ldap0.controls for extended controls and
extended operations only usable with certain slapd overlays not
available in all OpenLDAP builds
"""

from __future__ import absolute_import

import os
import time
import unittest

from ldap0.test import SlapdTestCase
from ldap0.functions import strp_secs
from ldap0.err import PasswordPolicyExpirationWarning

# Switch off processing .ldaprc or ldap0.conf before importing _ldap
os.environ['LDAPNOINIT'] = '1'

import ldap0
from ldap0 import LDAPError
from ldap0.ldapobject import LDAPObject
from ldap0.controls.ppolicy import PasswordPolicyControl


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


class TestPPolicy(ExtensionTestCase):

    def _add_ppolicy_entry(self, name, **ppolicy_attrs):
        """
        add a new
        """
        ppolicy_cn = 'ppolicy-%s' % (name)
        ppolicy_dn = 'cn=%s,%s' % (ppolicy_cn, self.server.suffix)
        ppolicy_entry = {
            'objectClass': ['applicationProcess', 'pwdPolicy'],
            'cn': [ppolicy_cn],
            'pwdAttribute': ['userPassword'],
        }
        for at, av in ppolicy_attrs.items():
            ppolicy_entry[at] = [str(av)]
        self._ldap_conn.add_s(ppolicy_dn, ppolicy_entry)
        read_entry = self._ldap_conn.read_s(ppolicy_dn, attrlist=ppolicy_entry.keys())
        self.assertEqual(read_entry['cn'], [ppolicy_cn])
        for at, av in ppolicy_attrs.items():
            self.assertEqual(read_entry[at], [str(av)])

    def test_ppolicy(self):
        self.enable_overlay(
            {
                'olcOverlay': ['ppolicy'],
                'objectClass': ['olcOverlayConfig', 'olcPPolicyConfig'],
                'olcPPolicyDefault': ['cn=ppolicy-default,'+self.server.suffix],
                'olcPPolicyForwardUpdates': ['FALSE'],
                'olcPPolicyHashCleartext': ['FALSE'],
                'olcPPolicyUseLockout': ['TRUE'],
                'olcPPolicyUseLockout': ['TRUE'],
            },
            ['ppolicy.ldif'],
        )
        self._add_ppolicy_entry(
            'default',
            pwdMaxAge=5,
            pwdExpireWarning=3,
            pwdGraceAuthNLimit=3,
        )
        user_dn = 'cn=user1,' + self.server.suffix
        # let slapd set new random user password
        user_password = self._ldap_conn.passwd_s(user_dn, None, None)
        # determine the exact password change time
        pwd_changed_time = strp_secs(
            self._ldap_conn.read_s(
                user_dn,
                attrlist=['pwdChangedTime'],
            )['pwdChangedTime'][0]
        )
        with self.ldap_object_class(self.server.ldap_uri) as l:
            l.simple_bind_s(user_dn, user_password)
        # wait until grace period
        time.sleep(3.0-(time.time()-pwd_changed_time-1.0))
        with self.ldap_object_class(self.server.ldap_uri) as l:
            try:
                l.simple_bind_s(
                    user_dn,
                    user_password,
                    serverctrls=[PasswordPolicyControl()],
                )
            except PasswordPolicyExpirationWarning as ppolicy_err:
                self.assertEqual(ppolicy_err.timeBeforeExpiration, 1)
            except ldap0.INVALID_CREDENTIALS as ldap_err:
                self.fail('Simple bind failed: %s' % (ldap_err))
            else:
                self.fail('Expected PasswordPolicyExpirationWarning raised!')


if __name__ == '__main__':
    unittest.main()

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
from ldap0.err import \
    PasswordPolicyChangeAfterReset, \
    PasswordPolicyExpirationWarning, \
    PasswordPolicyExpiredError

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

"""


class TestPPolicy(SlapdTestCase):
    """
    test LDAP search operations
    """
    ldap_object_class = LDAPObject
    maxDiff = None
    trace_level = 0
    pwd_max_age = 4
    pwd_expire_warning = 2
    pwd_graceauthn_limit = 2

    @classmethod
    def setUpClass(cls):
        super(TestPPolicy, cls).setUpClass()
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
        super(TestPPolicy, self).setUp()
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
        try:
            self._add_ppolicy_entry(
                'default',
                pwdMaxAge=self.pwd_max_age,
                pwdExpireWarning=self.pwd_expire_warning,
                pwdGraceAuthNLimit=self.pwd_graceauthn_limit,
                pwdAllowUserChange='TRUE',
                pwdMustChange='TRUE',
            )
        except ldap0.ALREADY_EXISTS:
            pass
        return # end of setUp()

    @property
    def user_dn(self):
        return 'cn=user1,' + self.server.suffix

    def _add_ppolicy_entry(self, name, **ppolicy_attrs):
        """
        add a new password policy entry
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

    def _set_user_password(self, user_password, pwd_reset=False):
        modlist = [(ldap0.MOD_REPLACE, 'userPassword', [user_password])]
        if pwd_reset:
            modlist.append((ldap0.MOD_REPLACE, 'pwdReset', ['TRUE']))
        else:
            modlist.append((ldap0.MOD_DELETE, 'pwdReset', None))
        self._ldap_conn.modify_s(
            self.user_dn,
            [
                (ldap0.MOD_REPLACE, 'userPassword', [user_password]),
                (ldap0.MOD_REPLACE, 'pwdReset', ['TRUE']),
            ]
        )
        return self._ldap_conn.read_s(
            self.user_dn,
            attrlist=['pwdChangedTime', 'pwdReset'],
        )

    def test001_pwd_reset(self):
        user_password = 'supersecret1'
        user_entry = self._set_user_password(user_password, pwd_reset=True)
        self.assertEqual(user_entry['pwdReset'], ['TRUE'])
        pwd_changed_time = strp_secs(user_entry['pwdChangedTime'][0])
        # check a normal simple bind first
        with self.ldap_object_class(self.server.ldap_uri) as l:
            with self.assertRaises(PasswordPolicyChangeAfterReset):
                l.simple_bind_s(
                    self.user_dn,
                    user_password,
                    serverctrls=[PasswordPolicyControl()],
                )
            # let the user change his own password
            l.passwd_s(self.user_dn, None, 'supersecret2')
        return # end of test001_pwd_reset()

    def test002_pwd_expiry_warning(self):
        user_password = 'supersecret2'
        user_entry = self._ldap_conn.read_s(
            self.user_dn,
            attrlist=['pwdChangedTime', 'pwdReset'],
        )
        pwd_changed_time = strp_secs(user_entry['pwdChangedTime'][0])
        self.assertEqual('pwdReset' not in user_entry, True)
        # wait until grace period and check for PasswordPolicyExpirationWarning
        time.sleep(self.pwd_expire_warning-(time.time()-pwd_changed_time-1.0))
        with self.ldap_object_class(self.server.ldap_uri) as l:
            with self.assertRaises(PasswordPolicyExpirationWarning) as ctx:
                l.simple_bind_s(
                    self.user_dn,
                    user_password,
                    serverctrls=[PasswordPolicyControl()],
                )
            self.assertEqual(ctx.exception.timeBeforeExpiration, 1)
        return # test002_pwd_expiry_warning()

    @unittest.expectedFailure
    def test003_pwd_grace_logins(self):
        user_password = 'supersecret2'
        user_entry = self._ldap_conn.read_s(
            self.user_dn,
            attrlist=['pwdChangedTime', 'pwdReset'],
        )
        pwd_changed_time = strp_secs(user_entry['pwdChangedTime'][0])
        self.assertEqual('pwdReset' not in user_entry, True)
        # wait until password expired and check for PasswordPolicyExpiredError
        time.sleep(self.pwd_max_age+1.0-(time.time()-pwd_changed_time))
        with self.ldap_object_class(self.server.ldap_uri) as l:
            with self.assertRaises(PasswordPolicyExpiredError) as ctx:
                l.simple_bind_s(
                    self.user_dn,
                    user_password,
                    serverctrls=[PasswordPolicyControl()],
                )
            self.assertEqual(ctx.exception.graceAuthNsRemaining, self.pwd_graceauthn_limit)


if __name__ == '__main__':
    unittest.main()

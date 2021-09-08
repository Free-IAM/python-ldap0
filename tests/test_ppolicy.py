# -*- coding: utf-8 -*-
"""
Automatic tests for module ldap0.controls for extended controls and
extended operations only usable with certain slapd overlays not
available in all OpenLDAP builds
"""

import os
import time
import unittest
import logging

# Switch off processing .ldaprc or ldap0.conf before importing _ldap
os.environ['LDAPNOINIT'] = '1'

import ldap0
from ldap0.schema.models import AttributeType
from ldap0.schema.subentry import SubSchema
from ldap0.ldapobject import LDAPObject
from ldap0.controls.ppolicy import PasswordPolicyControl
from ldap0.controls.pwdpolicy import PasswordExpiringControl, PasswordExpiredControl
from ldap0.test import SlapdTestCase
from ldap0.functions import strp_secs
from ldap0.err import (
    PasswordPolicyChangeAfterReset,
    PasswordPolicyExpirationWarning,
    PasswordPolicyExpiredError,
)


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

"""


class SlapoPPolicyTestCase(SlapdTestCase):
    """
    base-class for tests with slapo-ppolicy
    """
    ldap_object_class = LDAPObject
    maxDiff = None
    pwd_max_age = 4
    pwd_expire_warning = 2
    pwd_graceauthn_limit = 2

    @classmethod
    def setUpClass(cls):
        super(SlapoPPolicyTestCase, cls).setUpClass()
        # insert some Foo* objects via ldapadd
        cls.server.ldapadd(
            (LDIF_TEMPLATE % {
                'suffix':cls.server.suffix,
                'rootdn':cls.server.root_dn,
                'rootcn':cls.server.root_cn,
                'rootpw':cls.server.root_pw,
                'o': cls.server.suffix.split(',')[0][2:],
            }).encode('utf-8')
        )

    def setUp(self):
        super(SlapoPPolicyTestCase, self).setUp()
        sub_schema = SubSchema(
            self._ldap_conn.read_subschemasubentry_s('cn=Subschema'),
        )
        # determine whether loading a separate schema file is needed
        # by checking presence of object class pwdPolicy
        if os.path.exists(os.path.join(self.server.SCHEMADIR, 'ppolicy.ldif')):
            slapo_ppolicy_schema = ['ppolicy.ldif']
        else:
            slapo_ppolicy_schema = None
        slapo_ppolicy_cfg = dict(
            olcOverlay=['ppolicy'],
            objectClass=['olcOverlayConfig', 'olcPPolicyConfig'],
            olcPPolicyDefault=['cn=ppolicy-default,'+self.server.suffix],
            olcPPolicyForwardUpdates=['FALSE'],
            olcPPolicyHashCleartext=['FALSE'],
            olcPPolicyUseLockout=['TRUE'],
        )
        self.enable_overlay(slapo_ppolicy_cfg, slapo_ppolicy_schema)
        # check whether attribute type olcPPolicySendNetscapeControls is present in subschema
        sub_schema = SubSchema(
            self._ldap_conn.read_subschemasubentry_s('cn=Subschema'),
        )
        self.send_netscape_controls = ('1.3.6.1.4.1.4203.1.12.2.3.3.12.6' in sub_schema.sed[AttributeType])
        if self.send_netscape_controls:
            # enable ppolicy_send_send_netscape_controls available since OpenLDAP ITS#9279
            slapo_ppolicy_cfg.update(olcPPolicySendNetscapeControls=['TRUE'])
            self._ldap_conn.modify_s(
                'olcOverlay={0}ppolicy,olcDatabase={1}mdb,cn=config',
                [(ldap0.MOD_REPLACE, b'olcPPolicySendNetscapeControls', [b'TRUE'])]
            )
            logging.debug('Set olcPPolicySendNetscapeControls: TRUE')
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
        # end of setUp()

    @property
    def user_dn(self):
        return 'cn=user1,' + self.server.suffix

    def _add_ppolicy_entry(self, name, **ppolicy_attrs):
        """
        add a new password policy entry
        """
        logging.debug('ppolicy_attrs = %r', ppolicy_attrs)
        ppolicy_cn = 'ppolicy-%s' % (name)
        ppolicy_dn = 'cn=%s,%s' % (ppolicy_cn, self.server.suffix)
        ppolicy_entry = {
            'objectClass': [b'applicationProcess', b'pwdPolicy'],
            'cn': [ppolicy_cn.encode('utf-8')],
            'pwdAttribute': [b'userPassword'],
        }
        for at, av in ppolicy_attrs.items():
            if av is not None:
                ppolicy_entry[at] = [str(av).encode('utf-8')]
        self._ldap_conn.add_s(
            ppolicy_dn,
            ppolicy_entry,
        )
        read_entry = self._ldap_conn.read_s(
            ppolicy_dn,
            attrlist=list(ppolicy_entry.keys()),
        ).entry_as
        self.assertEqual(read_entry, ppolicy_entry)

    def _set_user_password(self, user_password, pwd_reset=None):
        modlist = [(ldap0.MOD_REPLACE, b'userPassword', [user_password.encode('utf-8')])]
        if pwd_reset is not None:
            modlist.append(
                (
                    ldap0.MOD_REPLACE,
                    b'pwdReset',
                    [str(pwd_reset).upper().encode('ascii')]
                )
            )
        self._ldap_conn.modify_s(self.user_dn, modlist)
        return self._ldap_conn.read_s(
            self.user_dn,
            attrlist=['pwdChangedTime', 'pwdReset'],
        )


class TestPPolicy(SlapoPPolicyTestCase):
    """
    tests for ldap0.controls.ppolicy
    """

    def test001_ppolicy_reset(self):
        user_password = 'supersecret1'
        user = self._set_user_password(user_password, pwd_reset=True)
        self.assertEqual(user.entry_s['pwdReset'], ['TRUE'])
        # check a normal simple bind first
        with self.ldap_object_class(self.server.ldap_uri, trace_level=self.trace_level) as l:
            with self.assertRaises(PasswordPolicyChangeAfterReset) as ctx:
                l.simple_bind_s(
                    self.user_dn,
                    user_password.encode('utf-8'),
                    req_ctrls=[PasswordPolicyControl()],
                )
            self.assertEqual(str(ctx.exception), 'Password change is needed after reset!')
            # let the user change his own password
            l.passwd_s(self.user_dn, None, 'supersecret2')
        # end of test001_pwd_reset()

    def test002_ppolicy_expiry_warning(self):
        user_password = b'supersecret2'
        user = self._ldap_conn.read_s(
            self.user_dn,
            attrlist=['pwdChangedTime', 'pwdReset'],
        )
        pwd_changed_time = strp_secs(user.entry_s['pwdChangedTime'][0])
        self.assertTrue('pwdReset' not in user.entry_s)
        # wait until grace period and check for PasswordPolicyExpirationWarning
        sleep_time = pwd_changed_time + self.pwd_max_age - self.pwd_expire_warning + 1.0 - time.time()
        logging.debug('Wait for %s seconds', sleep_time)
        time.sleep(sleep_time)
        with self.ldap_object_class(self.server.ldap_uri, trace_level=self.trace_level) as l:
            with self.assertRaises(PasswordPolicyExpirationWarning) as ctx:
                l.simple_bind_s(
                    self.user_dn,
                    user_password,
                    req_ctrls=[PasswordPolicyControl()],
                )
            expected_time_left = int(self.pwd_max_age-self.pwd_expire_warning-1)
            self.assertEqual(ctx.exception.timeBeforeExpiration, expected_time_left)
            self.assertEqual(
                str(ctx.exception),
                'Password will expire in %d seconds!' % (expected_time_left,),
            )
        # end of test002_pwd_expiry_warning()

    def test003_ppolicy_grace_logins(self):
        user_password = 'supersecret2'
        user_entry = self._ldap_conn.read_s(
            self.user_dn,
            attrlist=['pwdChangedTime', 'pwdReset'],
        ).entry_s
        pwd_changed_time = strp_secs(user_entry['pwdChangedTime'][0])
        self.assertTrue('pwdReset' not in user_entry)
        # wait until password expired and check for PasswordPolicyExpiredError
        sleep_time = pwd_changed_time + self.pwd_max_age + 1.0 - time.time()
        logging.debug('Wait for %s seconds', sleep_time)
        time.sleep(sleep_time)
        # change in slapo-ppolicy 2.5.x (see ITS#7596)
        ol25_offset = int(not self.server.slapd_version.startswith('2.4.'))
        for pwd_graceauthn_limit in range(self.pwd_graceauthn_limit-ol25_offset, -ol25_offset, -1):
            with self.ldap_object_class(self.server.ldap_uri, trace_level=self.trace_level) as l:
                with self.assertRaises(PasswordPolicyExpiredError) as ctx:
                    l.simple_bind_s(
                        self.user_dn,
                        user_password.encode('utf-8'),
                        req_ctrls=[PasswordPolicyControl()],
                    )
                self.assertEqual(
                    str(ctx.exception),
                    'Password expired! {0:d} grace logins left.'.format(pwd_graceauthn_limit)
                )
                self.assertEqual(ctx.exception.graceAuthNsRemaining, pwd_graceauthn_limit)
                del ctx
                # OpenLDAP's slapd derives graceAuthNsRemaining from number
                # of pwdGraceUseTime values, which are only stored with
                # a granularity of a second
                # => sleep for a bit more than second to be on the safe side
                time.sleep(1.1)
        with self.ldap_object_class(self.server.ldap_uri, trace_level=self.trace_level) as l:
            with self.assertRaises(ldap0.INVALID_CREDENTIALS) as ctx:
                l.simple_bind_s(
                    self.user_dn,
                    user_password.encode('utf-8'),
                    req_ctrls=[PasswordPolicyControl()],
                )
            self.assertEqual(len(ctx.exception.ctrls), 1)
            self.assertIsInstance(ctx.exception.ctrls[0], PasswordPolicyControl)
            self.assertEqual(ctx.exception.ctrls[0].error, 0)
        # end of test003_pwd_grace_logins()


class TestPwdPolicy(SlapoPPolicyTestCase):
    """
    tests for ldap0.controls.pwdpolicy
    """
    pwd_max_age = 5
    pwd_expire_warning = 3
    pwd_graceauthn_limit = None

    def setUp(self):
        super(TestPwdPolicy, self).setUp()
        # FIX ME! Running these tests on OpenLDAP 2.5+ needs clarification.
        if not self.server.slapd_version.startswith('2.4.'):
            self.skipTest(
                '{} known to fail with slapd {}'.format(
                    self.__class__.__name__,
                    self.server.slapd_version,
                )
            )

    def test001_pwdpolicy_expiration(self):
        if not self.send_netscape_controls:
            self.skipTest('slapd has no support for ITS#9279')
        user_password = 'supersecret2'
        user = self._set_user_password(user_password)
        user = self._ldap_conn.read_s(
            self.user_dn,
            attrlist=['pwdChangedTime'],
        )
        pwd_changed_time = strp_secs(user.entry_s['pwdChangedTime'][0])
        # wait until grace period and check for PasswordPolicyExpirationWarning
        sleep_time = pwd_changed_time + self.pwd_max_age - self.pwd_expire_warning + 1.0 - time.time()
        logging.debug('Wait for %s seconds', sleep_time)
        time.sleep(sleep_time)
        with self.ldap_object_class(self.server.ldap_uri, trace_level=self.trace_level) as l:
            bind_res = l.simple_bind_s(self.user_dn, user_password.encode('utf-8'))
            logging.debug('bind_res = %r', bind_res)
        self.assertEqual(len(bind_res.ctrls), 1)
        self.assertIsInstance(bind_res.ctrls[0], PasswordExpiringControl)
        self.assertTrue(
            bind_res.ctrls[0].gracePeriod <= self.pwd_expire_warning
        )
        # end of test004_pwdpolicy_expiration()

    def test002_pwdpolicy_expired(self):
        if not self.send_netscape_controls:
            self.skipTest('slapd has no support for ITS#9279')
        user_password = 'supersecret2'
        user = self._ldap_conn.read_s(
            self.user_dn,
            attrlist=['pwdChangedTime'],
        )
        pwd_changed_time = strp_secs(user.entry_s['pwdChangedTime'][0])
        # wait until grace period and check for PasswordPolicyExpirationWarning
        sleep_time = pwd_changed_time + self.pwd_max_age + 1.0 - time.time()
        logging.debug('Wait for %s seconds', sleep_time)
        time.sleep(sleep_time)
        with self.ldap_object_class(self.server.ldap_uri, trace_level=self.trace_level) as l:
            with self.assertRaises(ldap0.INVALID_CREDENTIALS) as ctx:
                l.simple_bind_s(self.user_dn, user_password.encode('utf-8'))
            self.assertEqual(len(ctx.exception.ctrls), 1)
            self.assertIsInstance(ctx.exception.ctrls[0], PasswordExpiredControl)
            self.assertTrue(ctx.exception.ctrls[0].passwordExpired)
        # end of test005_pwdpolicy_expired()


if __name__ == '__main__':
    unittest.main()

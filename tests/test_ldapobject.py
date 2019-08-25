# -*- coding: utf-8 -*-
"""
Automatic tests for module ldap0.ldapobject
"""

import os
import platform
import unittest
import pickle
import time
from errno import ENOTCONN

# Switch off processing .ldaprc or ldap0.conf before importing _ldap
os.environ['LDAPNOINIT'] = '1'

import _libldap0

import ldap0
import ldap0.schema.util
from ldap0.base import LDAPResult
from ldap0.ldapurl import LDAPUrl
from ldap0.sasl import SaslPasswordAuth
from ldap0.test import SlapdTestCase
from ldap0.ldapobject import LDAPObject, ReconnectLDAPObject
from ldap0.controls.sessiontrack import SessionTrackingControl, SESSION_TRACKING_FORMAT_OID_USERNAME
from ldap0.controls.readentry import PreReadControl, PostReadControl
from ldap0.controls.pagedresults import SimplePagedResultsControl
from ldap0.controls.simple import ProxyAuthzControl, RelaxRulesControl, ManageDSAITControl
from ldap0.controls.libldap import AssertionControl, MatchedValuesControl
from ldap0.extop.whoami import WhoAmIRequest, WhoAmIResponse

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

dn: ou=Container,%(suffix)s
objectClass: organizationalUnit
ou: Container

dn: cn=Foo5,ou=Container,%(suffix)s
objectClass: organizationalRole
cn: Foo5

dn: cn=Foo4,ou=Container,%(suffix)s
objectClass: organizationalRole
cn: Foo4

dn: cn=Foo7,ou=Container,%(suffix)s
objectClass: organizationalRole
cn: Foo7

dn: cn=Foo6,ou=Container,%(suffix)s
objectClass: organizationalRole
cn: Foo6

dn: ou=äöüÄÖUß,ou=Container,%(suffix)s
objectClass: organizationalUnit
ou: äöüÄÖUß

"""


class Test00_LDAPObject(SlapdTestCase):
    """
    test LDAP search operations
    """
    ldap_object_class = LDAPObject
    maxDiff = None

    @classmethod
    def setUpClass(cls):
        super(Test00_LDAPObject, cls).setUpClass()
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

    def setUp(self):
        try:
            self._ldap_conn
        except AttributeError:
            # open local LDAP connection
            self._ldap_conn = self._open_ldap_conn()

    def test000_basics(self):
        self.assertEqual(self._ldap_conn.protocol_version, 3)
        self.assertIsInstance(self._ldap_conn.fileno(), int)
        with self.assertRaises(TypeError):
            self.ldap_object_class(0)
        with self.assertRaises(ValueError):
            self.ldap_object_class('ldap.example.com')
        with self.ldap_object_class(LDAPUrl(self.server.ldap_uri)) as l:
            self.assertEqual(
                l.uri,
                LDAPUrl(self.server.ldap_uri).connect_uri().encode('ascii')
            )

    def test001_search_subtree(self):
        result = self._ldap_conn.search_s(
            self.server.suffix.encode('utf-8'),
            ldap0.SCOPE_SUBTREE,
            b'(cn=Foo*)',
            attrlist=[b'*'],
        )
        result.sort()
        self.assertEqual(
            result,
            [
                (
                    b'cn=Foo%d,%s' % (i, self.server.suffix.encode('utf-8')),
                    {b'cn': [b'Foo%d' % i], b'objectClass': [b'organizationalRole']}
                )
                for i in range(1, 4)
            ] + [
                (
                    b'cn=Foo%d,ou=Container,%s' % (i, self.server.suffix.encode('utf-8')),
                    {b'cn': [b'Foo%d' % i], b'objectClass': [b'organizationalRole']}
                )
                for i in range(4, 8)
            ]
        )

    def test002_search_onelevel(self):
        result = self._ldap_conn.search_s(
            self.server.suffix.encode('utf-8'),
            ldap0.SCOPE_ONELEVEL,
            b'(cn=Foo*)',
            [b'*'],
        )
        result.sort()
        self.assertEqual(
            result,
            [
                (
                    b'cn=Foo1,'+self.server.suffix.encode('utf-8'),
                    {b'cn': [b'Foo1'], b'objectClass': [b'organizationalRole']}
                ),
                (
                    b'cn=Foo2,'+self.server.suffix.encode('utf-8'),
                    {b'cn': [b'Foo2'], b'objectClass': [b'organizationalRole']}
                ),
                (
                    b'cn=Foo3,'+self.server.suffix.encode('utf-8'),
                    {b'cn': [b'Foo3'], b'objectClass': [b'organizationalRole']}
                ),
            ]
        )

    def test003_search_oneattr(self):
        result = self._ldap_conn.search_s(
            self.server.suffix.encode('utf-8'),
            ldap0.SCOPE_SUBTREE,
            b'(cn=Foo4)',
            [b'cn'],
        )
        result.sort()
        self.assertEqual(
            result,
            [(b'cn=Foo4,ou=Container,'+self.server.suffix.encode('utf-8'), {b'cn': [b'Foo4']})]
        )

    def test004_errno107(self):
        with self.ldap_object_class('ldap://127.0.0.1:42') as l:
            try:
                m = l.simple_bind_s(b'', b'')
                r = l.result(m, ldap0.MSG_ALL, 1.0)
            except ldap0.SERVER_DOWN as ldap_err:
                err_no = ldap_err.args[0]['errno']
                if err_no != ENOTCONN:
                    self.fail("expected err_no=%d, got %d" % (ENOTCONN, err_no))
                info = ldap_err.args[0]['info']
                if info != os.strerror(ENOTCONN):
                    self.fail("expected info=%r, got %d" % (os.strerror(ENOTCONN), info))
            else:
                self.fail("expected SERVER_DOWN, got %r" % r)

    def test005_invalid_credentials(self):
        with self.ldap_object_class(self.server.ldap_uri) as l:
            # search with invalid filter
            try:
                m = l.simple_bind(
                    self.server.root_dn.encode('utf-8'),
                    (self.server.root_pw+'wrong').encode('utf-8'),
                )
                r = l.result(m, ldap0.MSG_ALL)
            except ldap0.INVALID_CREDENTIALS:
                pass
            else:
                self.fail("expected INVALID_CREDENTIALS, got %r" % r)

    def test006_sasl_external(self):
        with self.ldap_object_class(self.server.ldapi_uri) as l:
            l.sasl_non_interactive_bind_s(b'EXTERNAL')
            self.assertEqual(l.whoami_s().decode('utf-8'), 'dn:'+self.server.root_dn.lower())
        authz_id = 'dn:cn=Foo2,%s' % (self.server.suffix)
        with self.ldap_object_class(self.server.ldapi_uri) as l:
            l.sasl_non_interactive_bind_s(b'EXTERNAL', authz_id=authz_id.encode('utf-8'))
            self.assertEqual(l.whoami_s().decode('utf-8'), authz_id.lower())

    @unittest.skipIf(platform.linux_distribution()[0].lower()=='debian', 'SASL password mechs not working on Debian')
    def test006_sasl_password_mechs(self):
        authz_id = 'dn:cn=user1,%s' % (self.server.suffix)
        for sasl_mech in (
                b'PLAIN',
                b'CRAM-MD5',
                b'DIGEST-MD5',
                b'SCRAM-SHA-1',
            ):
            with self.ldap_object_class(self.server.ldapi_uri) as l:
                l.sasl_interactive_bind_s(
                    sasl_mech,
                    SaslPasswordAuth(b'user1', b'user1_pw'),
                )
                self.assertEqual(l.whoami_s().decode('utf-8'), authz_id.lower())

    @unittest.skipIf(platform.linux_distribution()[0].lower()=='debian', 'SASL password mechs not working on Debian')
    def test006_sasl_password_mechs_bad(self):
        for sasl_mech in (
                b'PLAIN',
                b'CRAM-MD5',
                b'DIGEST-MD5',
#                b'SCRAM-SHA-1',
            ):
            with self.ldap_object_class(self.server.ldapi_uri) as l:
                with self.assertRaises(ldap0.INVALID_CREDENTIALS):
                    l.sasl_interactive_bind_s(
                        sasl_mech,
                        SaslPasswordAuth(b'user1', b'badpassword'),
                    )

    def test007_timeout(self):
        with self.ldap_object_class(self.server.ldap_uri) as l:
            m = l.search(
                self.server.suffix.encode('utf-8'),
                ldap0.SCOPE_SUBTREE,
                b'(objectClass=*)',
            )
            l.abandon(m)
            with self.assertRaises(ldap0.TIMEOUT):
                result = l.result(m, timeout=0.001)

    def test008_sessiontrack_control(self):
        self._ldap_conn.search_s(
            b'',
            ldap0.SCOPE_BASE,
            req_ctrls=[
                SessionTrackingControl(
                    b'192.0.2.1',
                    b'app.example.com',
                    SESSION_TRACKING_FORMAT_OID_USERNAME,
                    b'bloggs'
                )
            ],
        )

    def test009_readentry_control(self):
        attr_list = sorted([
            b'entryUUID',
            b'entryDN',
            b'createTimestamp',
            b'modifyTimestamp',
        ])
        new_dn = 'cn=Anna Blume,'+self.server.suffix
        # add a new entry and return operational attributes with post-read control
        add_result = self._ldap_conn.add_s(
            new_dn.encode('utf-8'),
            [
                (b'objectClass', [b'applicationProcess']),
                (b'cn', [b'Anna Blume']),
            ],
            req_ctrls=[
                PostReadControl(
                    criticality=True,
                    attrList=attr_list,
                )
            ],
        )
        self.assertEqual(add_result.ctrls[0].dn.decode('utf-8'), new_dn)
        self.assertEqual(add_result.ctrls[0].entry[b'entryDN'], [new_dn.encode('utf-8')])
        self.assertEqual(len(add_result.ctrls[0].entry), len(attr_list))
        self.assertEqual(sorted(add_result.ctrls[0].entry.keys()), attr_list)
        _, _, _, add_resp_ctrls = add_result
        self.assertEqual(add_resp_ctrls[0].dn.decode('utf-8'), new_dn)
        self.assertEqual(add_resp_ctrls[0].entry[b'entryDN'], [new_dn.encode('utf-8')])
        self.assertEqual(len(add_resp_ctrls[0].entry), len(attr_list))
        self.assertEqual(sorted(add_resp_ctrls[0].entry.keys()), attr_list)
        # modify existing entry and return old operational attributes with pre-read control
        _, _, _, mod_resp_ctrls = self._ldap_conn.modify_s(
            new_dn.encode('utf-8'),
            [
                (ldap0.MOD_ADD, b'description', [b'testing...']),
            ],
            req_ctrls=[
                PreReadControl(
                    criticality=True,
                    attrList=attr_list,
                )
            ],
        )
        self.assertEqual(add_resp_ctrls[0].entry, mod_resp_ctrls[0].entry)

    def test010_pagedresults(self):
        expected_ldap_result = sorted(
            self._ldap_conn.search_s(
                self.server.suffix.encode('utf-8'),
                ldap0.SCOPE_SUBTREE,
                attrlist=[b'1.1'],
            )
        )
        expected_num_results = len(expected_ldap_result)
        self.assertTrue(expected_num_results >= 10)
        page_size = 3
        expected_num_pages = expected_num_results // page_size + \
                            (expected_num_results % page_size > 0)
        paged_results_control = SimplePagedResultsControl(
            True,
            size=page_size,
            cookie=''
        )
        result_pages = 0
        all_paged_results = []
        msg_id = self._ldap_conn.search(
            self.server.suffix.encode('utf-8'),
            ldap0.SCOPE_SUBTREE,
            attrlist=[b'1.1'],
            req_ctrls=[paged_results_control],
        )
        while True:
            rtype, rdata, rmsgid, rctrls = self._ldap_conn.result(msg_id)
            self.assertEqual(rmsgid, msg_id)
            all_paged_results.extend(rdata)
            result_pages += 1
            self.assertEqual(rctrls[0].controlType, SimplePagedResultsControl.controlType)
            if rctrls[0].cookie:
                # Copy cookie from response control to request control
                paged_results_control.cookie = rctrls[0].cookie
                msg_id = self._ldap_conn.search(
                    self.server.suffix.encode('utf-8'),
                    ldap0.SCOPE_SUBTREE,
                    attrlist=[b'1.1'],
                    req_ctrls=[paged_results_control],
                )
            else:
                break # no more pages available
        self.assertEqual(sorted(all_paged_results), expected_ldap_result)
        self.assertEqual(result_pages, expected_num_pages)

    def test011_add_dict(self):
        new_dn = 'cn=Kurt Schwitters,'+self.server.suffix
        new_entry = {
            b'objectClass': [b'applicationProcess'],
            b'cn': [b'Kurt Schwitters'],
            b'description': [b'Dada!'],
        }
        self._ldap_conn.add_s(new_dn.encode('utf-8'), new_entry)
        entry = self._ldap_conn.read_s(new_dn.encode('utf-8'), attrlist=new_entry.keys())
        self.assertEqual(entry, new_entry)
        self._ldap_conn.delete_s(new_dn.encode('utf-8'))

    def test012_results(self):
        msg_id = self._ldap_conn.search(
            self.server.suffix.encode('utf-8'),
            ldap0.SCOPE_SUBTREE,
            b'(cn=Foo*)',
            attrlist=[b'*'],
        )
        result = []
        for result_type, result_list, result_msgid, result_req_ctrls in self._ldap_conn.results(msg_id):
            for dn, entry in result_list:
                result.append((dn, entry))
        result.sort()
        self.assertEqual(
            result,
            [
                (
                    ('cn=Foo%d,%s' % (i, self.server.suffix)).encode('utf-8'),
                    {b'cn': [b'Foo%d' % i], b'objectClass': [b'organizationalRole']}
                )
                for i in range(1, 4)
            ] + [
                (
                    ('cn=Foo%d,ou=Container,%s' % (i, self.server.suffix)).encode('utf-8'),
                    {b'cn': [b'Foo%d' % i], b'objectClass': [b'organizationalRole']}
                )
                for i in range(4, 8)
            ]
        )

    def test013_search_cache(self):
        with self.ldap_object_class(
            self.server.ldapi_uri,
            trace_level=self.trace_level,
            cache_ttl=10.0,
        ) as l:
            l.sasl_non_interactive_bind_s(b'EXTERNAL')
            self.assertEqual(l.whoami_s().decode('utf-8'), 'dn:'+self.server.root_dn.lower())
            new_dn = 'cn=Cache Tester,'+self.server.suffix
            new_entry = {
                b'objectClass': [b'applicationProcess'],
                b'cn': [b'Cache Tester'],
            }
            l.add_s(new_dn.encode('utf-8'), new_entry)
            for i in range(5):
                dn, entry = l.search_s(new_dn.encode('utf-8'), ldap0.SCOPE_BASE)[0]
                self.assertEqual(dn.decode('utf-8'), new_dn)
                self.assertEqual(entry, new_entry)
                self.assertEqual(l._cache_misses, 1)
                self.assertEqual(l._cache_hits, i)
                self.assertEqual(len(l._cache), 1)
            cache_hits = l._cache_hits
            cache_misses = l._cache_misses
            l.modify_s(new_dn.encode('utf-8'), [(ldap0.MOD_ADD, b'description', [b'cache test'])])
            l.modify_s(new_dn.encode('utf-8'), [(ldap0.MOD_DELETE, b'description', [b'cache test'])])
            self.assertEqual(l._cache_misses, cache_misses)
            self.assertEqual(l._cache_hits, cache_hits)
            self.assertEqual(len(l._cache), 0)
            self.assertEqual(l.cache_hit_ratio(), 80.0)
            l.flush_cache()
            self.assertEqual(l._cache_misses, 0)
            self.assertEqual(l._cache_hits, 0)
            self.assertEqual(len(l._cache), 0)
            self.assertEqual(l.cache_hit_ratio(), None)
            for i in range(5):
                dn, entry = l.search_s(new_dn.encode('utf-8'), ldap0.SCOPE_BASE)[0]
                self.assertEqual(dn.decode('utf-8'), new_dn)
                self.assertEqual(entry, new_entry)
                self.assertEqual(l._cache_misses, 1)
                self.assertEqual(l._cache_hits, i)
                self.assertEqual(len(l._cache), 1)
            _ = l.search_s(
                self.server.suffix.encode('utf-8'),
                ldap0.SCOPE_SUBTREE,
                ('(entryDN=%s)' % (new_dn,)).encode('utf-8'),
            )
            self.assertEqual(len(l._cache), 2)
            l.uncache(new_dn.encode('utf-8'))
            self.assertEqual(l._cache_misses, 2)
            self.assertEqual(l._cache_hits, i)
            self.assertEqual(len(l._cache), 0)
            l.flush_cache()
            for i in range(4):
                dn, entry = l.search_s(
                    new_dn.encode('utf-8'),
                    ldap0.SCOPE_BASE,
                    cache_ttl=0.05
                )[0]
                self.assertEqual(dn.decode('utf-8'), new_dn)
                self.assertEqual(entry, new_entry)
                self.assertEqual(l._cache_misses, i+1)
                self.assertEqual(l._cache_hits, 0)
                self.assertEqual(len(l._cache), 1)
                time.sleep(0.1)

    def test014_extop_whoami(self):
        with self.ldap_object_class(self.server.ldapi_uri) as l:
            l.sasl_non_interactive_bind_s(b'EXTERNAL')
            wai = l.extop_s(
                WhoAmIRequest(),
                extop_resp_class=WhoAmIResponse,
            )
            self.assertEqual(wai.responseValue.decode('utf-8'), 'dn:'+self.server.root_dn.lower())
            self.assertEqual(l.whoami_s().decode('utf-8'), 'dn:'+self.server.root_dn.lower())
        authz_id = 'dn:cn=Foo2,%s' % (self.server.suffix)
        with self.ldap_object_class(self.server.ldapi_uri) as l:
            l.sasl_non_interactive_bind_s(b'EXTERNAL')
            self.assertEqual(
                l.whoami_s([ProxyAuthzControl(authzId=b'')]),
                b'',
            )
            self.assertEqual(
                l.whoami_s(
                    [ProxyAuthzControl(authzId=authz_id.encode('utf-8'))]
                ).decode('utf-8'),
                authz_id.lower(),
            )
        with self.ldap_object_class(self.server.ldapi_uri) as l:
            l.simple_bind_s(b'', b'')
            wai = l.extop_s(
                WhoAmIRequest(),
                extop_resp_class=WhoAmIResponse,
            )
            self.assertEqual(wai.responseValue, b'')
            self.assertEqual(l.whoami_s().decode('utf-8'), '')

    def test015_passwd(self):
        # first, create a user to change password on
        dn = "cn=PasswordTest," + self.server.suffix
        self._ldap_conn.add_s(
            dn.encode('utf-8'),
            [
                (b'objectClass', [b'person']),
                (b'sn', [b'PasswordTest']),
                (b'cn', [b'PasswordTest']),
                (b'userPassword', [b'initial']),
            ]
        )
        # try changing password with a wrong old-pw
        with self.assertRaises(ldap0.UNWILLING_TO_PERFORM):
            res = self._ldap_conn.passwd_s(dn.encode('utf-8'), b'bogus', b'ignored')
        # try changing password with a correct old-pw
        new_pwd = self._ldap_conn.passwd_s(dn.encode('utf-8'), b'initial', b'changed')
        self.assertEqual(new_pwd, None)
        with self.ldap_object_class(self.server.ldapi_uri) as l:
            l.simple_bind_s(dn.encode('utf-8'), 'changed')
        # let server set new random password
        new_pwd = self._ldap_conn.passwd_s(dn.encode('utf-8'), b'changed', None)
        self.assertIsInstance(new_pwd, bytes)
        self.assertTrue(len(new_pwd)>0)
        with self.ldap_object_class(self.server.ldapi_uri) as l:
            l.simple_bind_s(dn.encode('utf-8'), new_pwd)

    def test016_cancel(self):
        try:
            res = self._ldap_conn.cancel_s(999999999)
        except ldap0.NO_SUCH_OPERATION:
            pass
        else:
            self.fail("expected ldap0.NO_SUCH_OPERATION to be raised")
        # start a "long-lasting" search
        msg_id = self._ldap_conn.search(
            self.server.suffix.encode('utf-8'),
            ldap0.SCOPE_SUBTREE,
            b'(objectClass=*)',
            attrlist=[b'*', b'+'],
        )
        time.sleep(1.0)
        try:
            res = self._ldap_conn.cancel_s(msg_id)
        except ldap0.NO_SUCH_OPERATION:
            pass
        else:
            self.fail("expected ldap0.NO_SUCH_OPERATION to be raised")

    def test017_relax_rules(self):
        dn = "cn=RelaxRules," + self.server.suffix
        entry = {
            b'objectClass': [b'person'],
            b'sn': [b'RelaxRules'],
            b'cn': [b'RelaxRules'],
            b'createTimestamp': [b'19680208115125Z'],
        }
        try:
            self._ldap_conn.add_s(dn.encode('utf-8'), entry)
        except ldap0.CONSTRAINT_VIOLATION:
            pass
        else:
            self.fail("should have raised ldap0.CONSTRAINT_VIOLATION")
        self._ldap_conn.add_s(
            dn.encode('utf-8'),
            entry,
            req_ctrls=[RelaxRulesControl()],
        )

    def test018_referrals(self):
        opt_ref_old = self._ldap_conn.get_option(ldap0.OPT_REFERRALS)
        self._ldap_conn.set_option(ldap0.OPT_REFERRALS, False)
        dn = "dc=relax-rules," + self.server.suffix
        entry = {
            b'objectClass': [b'dcObject', b'referral'],
            b'dc': [b'relax-rules'],
            b'ref': [b'ldap://ldap.uninett.no/dc=uninett,dc=no??one?objectClass=*)'],
        }
        self._ldap_conn.add_s(dn.encode('utf-8'), entry)
        try:
            ldap_result = self._ldap_conn.search_s(
                dn.encode('utf-8'),
                ldap0.SCOPE_BASE,
                attrlist=[b'*', b'ref']
            )
        except ldap0.REFERRAL as ldap_ref:
            self.assertEqual(
                ldap_ref.args[0]['desc'],
                b'Referral'
            )
            self.assertEqual(
                ldap_ref.args[0]['matched'],
                dn.encode('utf-8')
            )
            self.assertEqual(
                ldap_ref.args[0]['info'],
                b'Referral:\nldap://ldap.uninett.no/dc=uninett,dc=no??one?objectClass=*)'
            )
        else:
            self.fail("should have raised ldap0.REFERRAL")
        ldap_result = self._ldap_conn.search_s(
            dn.encode('utf-8'),
            ldap0.SCOPE_BASE,
            attrlist=[b'*', b'ref'],
            req_ctrls=[ManageDSAITControl()],
        )
        self.assertEqual(ldap_result, [(dn.encode('utf-8'), entry)])
        ldap_result = self._ldap_conn.search_s(
            self.server.suffix.encode('utf-8'),
            ldap0.SCOPE_SUBTREE,
            b'(dc=relax-rules)',
            attrlist=[b'*', b'ref'],
        )
        self.assertEqual(
            ldap_result,
            [(None, [b'ldap://ldap.uninett.no/dc=uninett,dc=no??one?objectClass=*)'])]
        )
        ldap_result = self._ldap_conn.search_s(
            self.server.suffix.encode('utf-8'),
            ldap0.SCOPE_SUBTREE,
            b'(dc=relax-rules)',
            attrlist=[b'*', b'ref'],
            req_ctrls=[ManageDSAITControl()],
        )
        self.assertEqual(ldap_result, [(dn.encode('utf-8'), entry)])
        self._ldap_conn.set_option(ldap0.OPT_REFERRALS, opt_ref_old)
        self._ldap_conn.delete_s(
            dn.encode('utf-8'),
            req_ctrls=[ManageDSAITControl()],
        )

    def test019_assertion_control(self):
        dn = "cn=AssertionControl," + self.server.suffix
        entry = {
            b'objectClass': [b'person'],
            b'sn': [b'AssertionControl'],
            b'cn': [b'AssertionControl'],
        }
        self._ldap_conn.add_s(dn.encode('utf-8'), entry)
        old_entry = self._ldap_conn.read_s(
            dn.encode('utf-8'),
            attrlist=[b'modifyTimestamp', b'entryCSN'],
        )
        assertion_filter = b'(&(modifyTimestamp=%s)(entryCSN=%s))' % (
            old_entry[b'modifyTimestamp'][0],
            old_entry[b'entryCSN'][0],
        )
        self._ldap_conn.modify_s(
            dn.encode('utf-8'),
            [(ldap0.MOD_REPLACE, b'description', [b'test modification #1'])],
            req_ctrls=[AssertionControl(filterstr=assertion_filter)],
        )
        with self.assertRaises(ldap0.ASSERTION_FAILED):
            self._ldap_conn.modify_s(
                dn.encode('utf-8'),
                [(ldap0.MOD_REPLACE, b'description', [b'test modification #2'])],
                req_ctrls=[AssertionControl(filterstr=assertion_filter)],
            )

    def test020_matched_values(self):
        dn = "sn=MatchedValues," + self.server.suffix
        entry = {
            b'objectClass': [b'person', b'dcObject'],
            b'dc': [b'matched-values'],
            b'sn': [b'MatchedValues'],
            b'cn': [
                b'MatchedValues0',
                b'MatchedValues1',
                b'MatchedValues2',
                b'MatchedValues3',
                b'MatchedValues4',
                b'MatchedValues5',
            ],
        }
        self._ldap_conn.add_s(dn.encode('utf-8'), entry)
        for val in entry[b'cn']:
            mv_entry = self._ldap_conn.read_s(
                dn.encode('utf-8'),
                attrlist=[b'objectClass', b'cn'],
                req_ctrls=[
                    MatchedValuesControl(
                        filterstr=b'((objectClass=person)(cn=%s))' % (val,)
                    ),
                ]
            )
            self.assertEqual(
                mv_entry,
                {b'cn': [val], b'objectClass': [b'person']}
            )

    def test021_compare(self):
        self.assertTrue(
            self._ldap_conn.compare_s(
                self.server.root_dn.encode('utf-8'),
                b'userPassword',
                self.server.root_pw.encode('utf-8'),
            )
        )
        self.assertFalse(
            self._ldap_conn.compare_s(
                self.server.root_dn.encode('utf-8'),
                b'userPassword',
                (self.server.root_pw+'1').encode('utf-8'),
            )
        )
        with self.assertRaises(ldap0.NO_SUCH_OBJECT):
            self._ldap_conn.compare_s(b'cn=foobar', b'cn', b'foobar')
        with self.assertRaises(ldap0.UNDEFINED_TYPE):
            self._ldap_conn.compare_s(b'cn=foobar', b'foo', b'bar')

    def test022_get_whoami_dn(self):
        self.assertEqual(
            self._ldap_conn.get_whoami_dn().decode('utf-8'),
            self.server.root_dn,
        )
        # repeated (cached)
        self.assertEqual(
            self._ldap_conn.get_whoami_dn().decode('utf-8'),
            self.server.root_dn,
        )
        with self.ldap_object_class(self.server.ldapi_uri) as l:
            self.assertEqual(l._whoami_dn, None)
            l.simple_bind_s(b'', b'')
            self.assertEqual(l.whoami_s().decode('utf-8'), '')
            self.assertEqual(l.get_whoami_dn().decode('utf-8'), '')
            bind_dn = 'cn=user1,'+self.server.suffix
            l.simple_bind_s(bind_dn.encode('utf-8'), b'user1_pw')
            self.assertEqual(
                l.get_whoami_dn().decode('utf-8'),
                bind_dn,
            )

    def test023_find_unique_entry(self):
        dn, entry = self._ldap_conn.find_unique_entry(
            self.server.suffix.encode('utf-8'),
            ldap0.SCOPE_SUBTREE,
            b'(cn=user1)',
        )
        self.assertEqual(dn, b'cn=user1,o=\xc3\xb6\xc3\xa4\xc3\xbc,dc=example,dc=org')
        self.assertEqual(
            entry,
            {
                b'cn': [b'user1'],
                b'userPassword': [b'user1_pw'],
                b'objectClass': [b'applicationProcess', b'simpleSecurityObject'],
            }
        )
        dn, entry = self._ldap_conn.find_unique_entry(
            self.server.suffix.encode('utf-8'),
            ldap0.SCOPE_SUBTREE,
            b'(cn=user1)',
            attrlist=[b'1.1'],
        )
        self.assertEqual(dn, b'cn=user1,o=\xc3\xb6\xc3\xa4\xc3\xbc,dc=example,dc=org')
        self.assertEqual(entry, {})
        dn, entry = self._ldap_conn.find_unique_entry(
            self.server.suffix.encode('utf-8'),
            ldap0.SCOPE_SUBTREE,
            b'(cn=user1)',
            attrlist=[b'cn', b'userPassword'],
        )
        self.assertEqual(dn, b'cn=user1,o=\xc3\xb6\xc3\xa4\xc3\xbc,dc=example,dc=org')
        self.assertEqual(entry, {b'cn': [b'user1'], b'userPassword': [b'user1_pw']})
        with self.assertRaises(ldap0.NO_UNIQUE_ENTRY):
            self._ldap_conn.find_unique_entry(
                self.server.suffix.encode('utf-8'),
                ldap0.SCOPE_SUBTREE,
                b'(objectClass=foobar)',
            )
        with self.assertRaises(ldap0.NO_UNIQUE_ENTRY):
            self._ldap_conn.find_unique_entry(
                self.server.suffix.encode('utf-8'),
                ldap0.SCOPE_SUBTREE,
                b'(objectClass=*)',
            )

    def test024_umlauts(self):
        result = self._ldap_conn.search_s(
            self.server.suffix.encode('utf-8'),
            ldap0.SCOPE_SUBTREE,
            '(ou=*ö*)'.encode('utf-8'),
            attrlist=[b'ou'],
        )
        self.assertEqual(
            result,
            [
                (
                    ('ou=äöüÄÖUß,ou=Container,%s' % (self.server.suffix)).encode('utf-8'),
                    {b'ou': ['äöüÄÖUß'.encode('utf-8')]}
                )
            ]
        )
        self.assertTrue(
            self._ldap_conn.compare_s(
                ('ou=äöüÄÖUß,ou=Container,%s' % (self.server.suffix)).encode('utf-8'),
                b'ou',
                'äöüÄÖUß'.encode('utf-8'),
            )
        )
        add_dn = 'ou=ßÜÖÄüöä,ou=Container,%s' % (self.server.suffix)
        self._ldap_conn.add_s(
            add_dn.encode('utf-8'),
            {
                b'objectClass': [b'organizationalUnit'],
                b'ou': ['ßÜÖÄüöä'.encode('utf-8')],
            },
        )
        self.assertTrue(
            self._ldap_conn.compare_s(
                add_dn.encode('utf-8'),
                b'ou',
                'ßÜÖÄüöä'.encode('utf-8'),
            )
        )
        self._ldap_conn.delete_s(add_dn.encode('utf-8'))

    def test025_search_subschemasubentry_s(self):
        self.assertEqual(
            self._ldap_conn.search_subschemasubentry_s(),
            b'cn=Subschema',
        )
        self.assertEqual(
            self._ldap_conn.search_subschemasubentry_s(dn=b''),
            b'cn=Subschema',
        )
        self.assertEqual(
            self._ldap_conn.search_subschemasubentry_s(dn=self.server.suffix.encode('utf-8')),
            b'cn=Subschema',
        )
        # this will cause fall back reading attribute subschemaSubentry from rootDSE
        self.assertEqual(
            self._ldap_conn.search_subschemasubentry_s(b'cn=doesnotexist'),
            b'cn=Subschema',
        )
        # DN of subschema subentry cannot be determined and will return None
        self.assertEqual(
            self._ldap_conn.search_subschemasubentry_s(b'cn=doesnotexist', rootdse=False),
            None,
        )

    def test001_add_rename_delete(self):
        dn1 = 'cn=äöüÄÖÜß,'+self.server.suffix
        rdn2 = 'cn=LaLeLu4711'
        dn2 = ','.join((rdn2, self.server.suffix))
        entry = {
            b'objectClass': [b'applicationProcess'],
            b'cn': ['äöüÄÖÜß'.encode('utf-8')],
        }
        add_result = self._ldap_conn.add_s(dn1.encode('utf-8'), entry)
        self.assertEqual(tuple(add_result), (_libldap0.RES_ADD, [], 2, []))
        with self.assertRaises(_libldap0.ALREADY_EXISTS):
            self._ldap_conn.add_s(dn1.encode('utf-8'), entry)
        rename_result = self._ldap_conn.rename_s(
            dn1.encode('utf-8'),
            rdn2.encode('utf-8'),
            newsuperior=self.server.suffix.encode('utf-8'),
        )
        self.assertEqual(tuple(rename_result), (_libldap0.RES_MODRDN, [], 4, []))
        read_result = self._ldap_conn.read_s(dn2.encode('utf-8'))
        self.assertEqual(read_result, {b'cn': [b'LaLeLu4711'], b'objectClass': [b'applicationProcess']})
        with self.assertRaises(_libldap0.NO_SUCH_OBJECT):
            self._ldap_conn.rename_s(dn1.encode('utf-8'), rdn2.encode('utf-8'))
        delete_result = self._ldap_conn.delete_s(dn2.encode('utf-8'))
        self.assertEqual(tuple(delete_result), (_libldap0.RES_DELETE, [], 7, []))
        with self.assertRaises(_libldap0.NO_SUCH_OBJECT):
            self._ldap_conn.delete_s(dn2.encode('utf-8'))

class Test01_ReconnectLDAPObject(Test00_LDAPObject):
    """
    test ReconnectLDAPObject by restarting slapd
    """

    ldap_object_class = ReconnectLDAPObject

    def test101_reconnect_sasl_external(self):
        with self.ldap_object_class(self.server.ldapi_uri) as l:
            l.sasl_non_interactive_bind_s(b'EXTERNAL')
            authz_id = l.whoami_s().decode('utf-8')
            self.assertEqual(authz_id, 'dn:'+self.server.root_dn.lower())
            self.server.restart()
            self.assertEqual(l.whoami_s().decode('utf-8'), authz_id)

    def test102_reconnect_simple_bind(self):
        with self.ldap_object_class(self.server.ldapi_uri) as l:
            bind_dn = 'cn=user1,'+self.server.suffix
            l.simple_bind_s(bind_dn.encode('utf-8'), b'user1_pw')
            self.assertEqual(l.whoami_s().decode('utf-8'), 'dn:'+bind_dn)
            self.server.restart()
            self.assertEqual(l.whoami_s().decode('utf-8'), 'dn:'+bind_dn)

    def test103_reconnect_get_state(self):
        bind_dn = 'cn=user1,'+self.server.suffix
        expected_state = {
            '_cache': {},
            '_cache_hits': 0,
            '_cache_misses': 0,
            '_last_bind': (
                'simple_bind_s',
                (bind_dn.encode('utf-8'), b'user1_pw'),
                {}
            ),
            '_options': [
                # default options set in LDAPObject.__init__()
                (_libldap0.OPT_PROTOCOL_VERSION, _libldap0.VERSION3),
                (_libldap0.OPT_RESTART, False),
                (_libldap0.OPT_DEREF, False),
                (_libldap0.OPT_REFERRALS, False),
                (_libldap0.OPT_X_TLS_REQUIRE_CERT, _libldap0.OPT_X_TLS_HARD),
            ],
            '_reconnects_done': 0,
            '_retry_delay': 60.0,
            '_retry_max': 1,
            '_start_tls': 0,
            '_uri': self.server.ldapi_uri.encode('ascii'),
            'uri': self.server.ldapi_uri.encode('ascii'),
            'cache_ttl': 0.0,
            'timeout': -1,
            '_trace_level': 0,
            '_whoami_dn': bind_dn.encode('utf-8'),
        }
        with self.ldap_object_class(self.server.ldapi_uri) as l1:
            l1.simple_bind_s(bind_dn.encode('utf-8'), b'user1_pw')
            self.assertEqual(l1.whoami_s().decode('utf-8'), 'dn:'+bind_dn)
            self.assertEqual(l1.get_whoami_dn().decode('utf-8'), bind_dn)
            self.assertEqual(l1.__getstate__(), expected_state)

    def test104_reconnect_restore(self):
        with self.ldap_object_class(self.server.ldapi_uri) as l1:
            l1 = self.ldap_object_class(self.server.ldapi_uri)
            bind_dn = 'cn=user1,'+self.server.suffix
            l1.simple_bind_s(bind_dn.encode('utf-8'), 'user1_pw')
            self.assertEqual(l1.whoami_s().decode('utf-8'), 'dn:'+bind_dn)
            l1_state = pickle.dumps(l1)
        with pickle.loads(l1_state) as l2:
            self.assertEqual(l2.whoami_s().decode('utf-8'), 'dn:'+bind_dn)

    def test105_null_reconnect(self):
        with self.ldap_object_class(self.server.ldapi_uri, retry_max=0) as l:
            l.sasl_non_interactive_bind_s(b'EXTERNAL')
            authz_id = l.whoami_s()
            self.assertEqual(authz_id.decode('utf-8'), 'dn:'+self.server.root_dn.lower())
            self.server.restart()
            with self.assertRaises(_libldap0.SERVER_DOWN):
                self.assertEqual(l.whoami_s().decode('utf-8'), authz_id)

    def test106_reconnect_reset_last_bind(self):
        with self.ldap_object_class(self.server.ldapi_uri, retry_max=1) as l:
            l.sasl_non_interactive_bind_s(b'EXTERNAL')
            self.assertEqual(l.whoami_s().decode('utf-8'), 'dn:'+self.server.root_dn.lower())
            # now force reconnect with anon bind
            l.reconnect(l.uri, reset_last_bind=True)
            self.assertEqual(l.whoami_s(), b'')


class TestSchemaUrlFetchLDAP(SlapdTestCase):

    def test_schema_urlfetch(self):
        """
        test ldap0.schema.util.urlfetch() which requires a running slapd instance
        """
        schema_dn, sub_schema = ldap0.schema.util.urlfetch(self.server.ldapi_uri, check_uniqueness=True)
        self.assertEqual(schema_dn, b'cn=Subschema')
        oid = sub_schema.name2oid[ldap0.schema.models.AttributeType]['cn']
        self.assertEqual(oid, '2.5.4.3')
        self.assertEqual(oid, sub_schema.name2oid[ldap0.schema.models.AttributeType]['commonName'])


if __name__ == '__main__':
    unittest.main()

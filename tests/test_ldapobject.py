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
from ldap0.res import LDAPResult
from ldap0.ldapurl import LDAPUrl
from ldap0.sasl import SaslPasswordAuth
from ldap0.test import SlapdTestCase
from ldap0.ldapobject import LDAPObject, ReconnectLDAPObject
from ldap0.err import NoUniqueEntry
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
                LDAPUrl(self.server.ldap_uri).connect_uri()
            )

    def test001_search_subtree(self):
        result = self._ldap_conn.search_s(
            self.server.suffix,
            ldap0.SCOPE_SUBTREE,
            '(cn=Foo*)',
            attrlist=['*'],
        )
        result.sort(key=lambda x: x.dn_s)
        self.assertEqual(
            [(lr.dn_s, lr.entry_as) for lr in result],
            [
                (
                    'cn=Foo%d,%s' % (i, self.server.suffix),
                    {'cn': [b'Foo%d' % i], 'objectClass': [b'organizationalRole']}
                )
                for i in range(1, 4)
            ] + [
                (
                    'cn=Foo%d,ou=Container,%s' % (i, self.server.suffix),
                    {'cn': [b'Foo%d' % i], 'objectClass': [b'organizationalRole']}
                )
                for i in range(4, 8)
            ]
        )

    def test002_search_onelevel(self):
        result = self._ldap_conn.search_s(
            self.server.suffix,
            ldap0.SCOPE_ONELEVEL,
            '(cn=Foo*)',
            ['*'],
        )
        result.sort(key=lambda x: x.dn_s)
        self.assertEqual(
            [(lr.dn_s, lr.entry_as) for lr in result],
            [
                (
                    'cn=Foo1,'+self.server.suffix,
                    {'cn': [b'Foo1'], 'objectClass': [b'organizationalRole']}
                ),
                (
                    'cn=Foo2,'+self.server.suffix,
                    {'cn': [b'Foo2'], 'objectClass': [b'organizationalRole']}
                ),
                (
                    'cn=Foo3,'+self.server.suffix,
                    {'cn': [b'Foo3'], 'objectClass': [b'organizationalRole']}
                ),
            ]
        )

    def test003_search_oneattr(self):
        result = self._ldap_conn.search_s(
            self.server.suffix,
            ldap0.SCOPE_SUBTREE,
            '(cn=Foo4)',
            ['cn'],
        )
        result.sort()
        self.assertEqual(
            [(lr.dn_s, lr.entry_as) for lr in result],
            [('cn=Foo4,ou=Container,'+self.server.suffix, {'cn': [b'Foo4']})]
        )

    def test004_errno107(self):
        with self.ldap_object_class('ldap://127.0.0.1:42') as l:
            try:
                ldap_res = l.simple_bind_s('', b'')
            except ldap0.SERVER_DOWN as ldap_err:
                err_no = ldap_err.args[0]['errno']
                if err_no != ENOTCONN:
                    self.fail("expected err_no=%d, got %d" % (ENOTCONN, err_no))
                info = ldap_err.args[0]['info']
                info_expected = os.strerror(ENOTCONN).encode('ascii')
                if info != info_expected:
                    self.fail("expected info=%r, got %r" % (info_expected, info))
            else:
                self.fail("expected SERVER_DOWN, got %r" % ldap_res)

    def test005_invalid_credentials(self):
        with self.ldap_object_class(self.server.ldap_uri) as l:
            try:
                ldap_res = l.simple_bind_s(
                    self.server.root_dn,
                    (self.server.root_pw+'wrong').encode('utf-8'),
                )
            except ldap0.INVALID_CREDENTIALS:
                pass
            else:
                self.fail("expected INVALID_CREDENTIALS, got %r" % ldap_res)

    def test006_sasl_external(self):
        with self.ldap_object_class(self.server.ldapi_uri) as l:
            l.sasl_non_interactive_bind_s('EXTERNAL')
            self.assertEqual(l.whoami_s(), 'dn:'+self.server.root_dn.lower())
        authz_id = 'dn:cn=Foo2,%s' % (self.server.suffix)
        with self.ldap_object_class(self.server.ldapi_uri) as l:
            l.sasl_non_interactive_bind_s('EXTERNAL', authz_id=authz_id)
            self.assertEqual(l.whoami_s(), authz_id.lower())

    def test006_sasl_password_mechs(self):
        authz_id = 'dn:cn=user1,%s' % (self.server.suffix)
        for sasl_mech in (
                'PLAIN',
                'CRAM-MD5',
                'DIGEST-MD5',
#                'SCRAM-SHA-1',
            ):
            with self.ldap_object_class(self.server.ldapi_uri) as l:
                l.sasl_interactive_bind_s(
                    sasl_mech,
                    SaslPasswordAuth('user1', b'user1_pw'),
                )
                self.assertEqual(l.whoami_s(), authz_id.lower())

    def test006_sasl_password_mechs_bad(self):
        for sasl_mech in (
                'PLAIN',
                'CRAM-MD5',
                'DIGEST-MD5',
#                b'SCRAM-SHA-1',
            ):
            with self.ldap_object_class(self.server.ldapi_uri) as l:
                with self.assertRaises(ldap0.INVALID_CREDENTIALS):
                    l.sasl_interactive_bind_s(
                        sasl_mech,
                        SaslPasswordAuth('user1', b'badpassword'),
                    )

    @unittest.skip('Too timing dependent')
    def test007_timeout(self):
        test_timeout = 0.00001
        with self.ldap_object_class(self.server.ldap_uri) as l:
            with self.assertRaises(ldap0.TIMEOUT):
                msg_id = l.search(
                    self.server.suffix,
                    ldap0.SCOPE_SUBTREE,
                    '(objectClass=*)',
                )
                l.result(msg_id, all_results=ldap0.MSG_ALL, timeout=test_timeout)
            l.abandon(msg_id)
            with self.assertRaises(ldap0.TIMEOUT):
                l.search_s(
                    self.server.suffix,
                    ldap0.SCOPE_SUBTREE,
                    '(objectClass=*)',
                    timeout=test_timeout,
                )

    def test008_sessiontrack_control(self):
        self._ldap_conn.search_s(
            '',
            ldap0.SCOPE_BASE,
            req_ctrls=[
                SessionTrackingControl(
                    '192.0.2.1',
                    'app.example.com',
                    SESSION_TRACKING_FORMAT_OID_USERNAME,
                    'bloggs'
                )
            ],
        )

    def test009_readentry_control(self):
        attr_list = sorted([
            'entryUUID',
            'entryDN',
            'createTimestamp',
            'modifyTimestamp',
        ])
        new_dn = 'cn=Anna Blume,'+self.server.suffix
        # add a new entry and return operational attributes with post-read control
        add_result = self._ldap_conn.add_s(
            new_dn,
            {
                'objectClass': [b'applicationProcess'],
                'cn': [b'Anna Blume'],
            },
            req_ctrls=[
                PostReadControl(
                    criticality=True,
                    attrList=attr_list,
                )
            ],
        )
        self.assertEqual(add_result.ctrls[0].res.dn_s, new_dn)
        self.assertEqual(add_result.ctrls[0].res.entry_as['entryDN'][0].decode('utf-8'), new_dn)
        self.assertEqual(len(add_result.ctrls[0].res.entry_as), len(attr_list))
        self.assertEqual(sorted(add_result.ctrls[0].res.entry_as.keys()), attr_list)
        # modify existing entry and return old operational attributes with pre-read control
        modify_result = self._ldap_conn.modify_s(
            new_dn,
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
        self.assertEqual(add_result.ctrls[0].res, modify_result.ctrls[0].res)

    def test010_pagedresults(self):
        expected_ldap_result = []
        expected_ldap_result = self._ldap_conn.search_s(
            self.server.suffix,
            ldap0.SCOPE_SUBTREE,
            attrlist=['1.1'],
        )
        expected_ldap_result.sort(key=lambda x: x.dn_s)
        expected_num_results = len(expected_ldap_result)
        self.assertGreaterEqual(expected_num_results, 10)
        page_size = 3
        expected_num_pages = expected_num_results // page_size + \
                            (expected_num_results % page_size > 0)
        paged_results_control = SimplePagedResultsControl(
            True,
            size=page_size,
            cookie=b''
        )
        result_pages = 0
        all_paged_results = []
        # do the paged search as long as a cookie is received in response control
        paging_continues = True
        while paging_continues:
            msg_id = self._ldap_conn.search(
                self.server.suffix,
                ldap0.SCOPE_SUBTREE,
                attrlist=['1.1'],
                req_ctrls=[paged_results_control],
            )
            ldap_results = list(self._ldap_conn.results(msg_id))
#            self.assertEqual(len(ldap_results), page_size+1)
            for res in ldap_results:
                self.assertEqual(res.msgid, msg_id)
                if res.rtype == ldap0.RES_SEARCH_ENTRY and res.rdata:
                    all_paged_results.extend(res.rdata)
                elif res.rtype == ldap0.RES_SEARCH_RESULT:
                    result_pages += 1
                    if not res.ctrls or not res.ctrls[0].cookie:
                        paging_continues = False
                    self.assertEqual(res.ctrls[0].controlType, SimplePagedResultsControl.controlType)
                    # Copy cookie from response control to request control
                    paged_results_control.cookie = res.ctrls[0].cookie
        self.assertEqual(result_pages, expected_num_pages)
        self.assertEqual(sorted(all_paged_results, key=lambda x: x.dn_s), expected_ldap_result)

    def test011_add_dict(self):
        new_dn = 'cn=Kurt Schwitters,'+self.server.suffix
        new_entry = {
            'objectClass': [b'applicationProcess'],
            'cn': [b'Kurt Schwitters'],
            'description': [b'Dada!'],
        }
        self._ldap_conn.add_s(new_dn, new_entry)
        read = self._ldap_conn.read_s(new_dn, attrlist=new_entry.keys())
        self.assertEqual(read.entry_as, new_entry)
        self._ldap_conn.delete_s(new_dn)

    def test012_results(self):
        msg_id = self._ldap_conn.search(
            self.server.suffix,
            ldap0.SCOPE_SUBTREE,
            '(cn=Foo*)',
            attrlist=['*'],
        )
        result = []
        for ldap_res in self._ldap_conn.results(msg_id):
            for search_res in ldap_res.rdata:
                result.append((search_res.dn_s, search_res.entry_as))
        result.sort()
        self.assertEqual(
            result,
            [
                (
                    ('cn=Foo%d,%s' % (i, self.server.suffix)),
                    {'cn': [b'Foo%d' % i], 'objectClass': [b'organizationalRole']}
                )
                for i in range(1, 4)
            ] + [
                (
                    ('cn=Foo%d,ou=Container,%s' % (i, self.server.suffix)),
                    {'cn': [b'Foo%d' % i], 'objectClass': [b'organizationalRole']}
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
            self.assertEqual(l.cache_ttl, 10.0)
            l.sasl_non_interactive_bind_s('EXTERNAL')
            self.assertEqual(l.whoami_s(), 'dn:'+self.server.root_dn.lower())
            new_dn = 'cn=Cache Tester,'+self.server.suffix
            new_entry = {
                'objectClass': [b'applicationProcess'],
                'cn': [b'Cache Tester'],
            }
            l.add_s(new_dn, new_entry)
            for i in range(5):
                ldap_res = l.search_s(new_dn, ldap0.SCOPE_BASE)[0]
                self.assertEqual(ldap_res.dn_s, new_dn)
                self.assertEqual(ldap_res.entry_as, new_entry)
                self.assertEqual(l._cache_misses, 1)
                self.assertEqual(l._cache_hits, i)
                self.assertEqual(len(l._cache), 1)
            cache_hits = l._cache_hits
            cache_misses = l._cache_misses
            l.modify_s(new_dn, [(ldap0.MOD_ADD, b'description', [b'cache test'])])
            l.modify_s(new_dn, [(ldap0.MOD_DELETE, b'description', [b'cache test'])])
            self.assertEqual(l._cache_misses, cache_misses)
            self.assertEqual(l._cache_hits, cache_hits)
            self.assertEqual(len(l._cache), 0)
            self.assertEqual(l.cache_hit_ratio(), 80.0)
            l.flush_cache()
            self.assertEqual(l._cache_misses, 0)
            self.assertEqual(l._cache_hits, 0)
            self.assertEqual(len(l._cache), 0)
            self.assertEqual(l.cache_hit_ratio(), 0.0)
            for i in range(5):
                ldap_res = l.search_s(new_dn, ldap0.SCOPE_BASE)[0]
                self.assertEqual(ldap_res.dn_s, new_dn)
                self.assertEqual(ldap_res.entry_as, new_entry)
                self.assertEqual(l._cache_misses, 1)
                self.assertEqual(l._cache_hits, i)
                self.assertEqual(len(l._cache), 1)
            _ = l.search_s(
                self.server.suffix,
                ldap0.SCOPE_SUBTREE,
                ('(entryDN=%s)' % (new_dn,)),
            )
            self.assertEqual(len(l._cache), 2)
            l.uncache(new_dn)
            self.assertEqual(l._cache_misses, 2)
            self.assertEqual(l._cache_hits, i)
            self.assertEqual(len(l._cache), 0)
            l.flush_cache()
            for i in range(4):
                ldap_res = l.search_s(new_dn, ldap0.SCOPE_BASE, cache_ttl=0.0001)[0]
                self.assertEqual(ldap_res.dn_s, new_dn)
                self.assertEqual(ldap_res.entry_as, new_entry)
                self.assertEqual(l._cache_misses, i+1)
                self.assertEqual(l._cache_hits, 0)
                self.assertEqual(len(l._cache), 1)
                time.sleep(0.1)

    def test014_extop_whoami(self):
        with self.ldap_object_class(self.server.ldapi_uri) as l:
            l.sasl_non_interactive_bind_s('EXTERNAL')
            wai = l.extop_s(
                WhoAmIRequest(),
                extop_resp_class=WhoAmIResponse,
            )
            self.assertEqual(wai.responseValue, 'dn:'+self.server.root_dn.lower())
            self.assertEqual(l.whoami_s(), 'dn:'+self.server.root_dn.lower())
        authz_id = 'dn:cn=Foo2,%s' % (self.server.suffix)
        with self.ldap_object_class(self.server.ldapi_uri) as l:
            l.sasl_non_interactive_bind_s('EXTERNAL')
            self.assertEqual(
                l.whoami_s([ProxyAuthzControl(authzId='')]),
                '',
            )
            self.assertEqual(
                l.whoami_s(
                    [ProxyAuthzControl(authzId=authz_id)]
                ),
                authz_id.lower(),
            )
        with self.ldap_object_class(self.server.ldapi_uri) as l:
            l.simple_bind_s('', b'')
            wai = l.extop_s(
                WhoAmIRequest(),
                extop_resp_class=WhoAmIResponse,
            )
            self.assertEqual(wai.responseValue, '')
            self.assertEqual(l.whoami_s(), '')

    def test015_passwd(self):
        # first, create a user to change password on
        dn = "cn=PasswordTest," + self.server.suffix
        self._ldap_conn.add_s(
            dn,
            {
                'objectClass': [b'person'],
                'sn': [b'PasswordTest'],
                'cn': [b'PasswordTest'],
                'userPassword': [b'initial'],
            }
        )
        # try changing password with a wrong old-pw
        with self.assertRaises(ldap0.UNWILLING_TO_PERFORM):
            res = self._ldap_conn.passwd_s(dn, b'bogus', b'ignored')
        # try changing password with a correct old-pw
        new_pwd = self._ldap_conn.passwd_s(dn, b'initial', b'changed')
        self.assertEqual(new_pwd, None)
        with self.ldap_object_class(self.server.ldapi_uri) as l:
            l.simple_bind_s(dn, 'changed')
        # let server set new random password
        new_pwd = self._ldap_conn.passwd_s(dn, b'changed', None)
        self.assertIsInstance(new_pwd, bytes)
        self.assertTrue(len(new_pwd)>0)
        with self.ldap_object_class(self.server.ldapi_uri) as l:
            l.simple_bind_s(dn, new_pwd)

    def test016_cancel(self):
        try:
            res = self._ldap_conn.cancel_s(999999999)
        except ldap0.NO_SUCH_OPERATION:
            pass
        else:
            self.fail("expected ldap0.NO_SUCH_OPERATION to be raised")
        # start a "long-lasting" search
        msg_id = self._ldap_conn.search(
            self.server.suffix,
            ldap0.SCOPE_SUBTREE,
            '(objectClass=*)',
            attrlist=['*', '+'],
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
            'objectClass': [b'person'],
            'sn': [b'RelaxRules'],
            'cn': [b'RelaxRules'],
            'createTimestamp': [b'19680208115125Z'],
        }
        try:
            self._ldap_conn.add_s(dn, entry)
        except ldap0.CONSTRAINT_VIOLATION:
            pass
        else:
            self.fail("should have raised ldap0.CONSTRAINT_VIOLATION")
        self._ldap_conn.add_s(
            dn,
            entry,
            req_ctrls=[RelaxRulesControl()],
        )

    def test018_referrals(self):
        opt_ref_old = self._ldap_conn.get_option(ldap0.OPT_REFERRALS)
        self._ldap_conn.set_option(ldap0.OPT_REFERRALS, False)
        dn = "dc=relax-rules," + self.server.suffix
        entry = {
            'objectClass': [b'dcObject', b'referral'],
            'dc': [b'relax-rules'],
            'ref': [b'ldap://ldap.uninett.no/dc=uninett,dc=no??one?objectClass=*)'],
        }
        self._ldap_conn.add_s(dn, entry)
        try:
            ldap_result = self._ldap_conn.search_s(
                dn,
                ldap0.SCOPE_BASE,
                attrlist=['*', 'ref']
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
            dn,
            ldap0.SCOPE_BASE,
            attrlist=['*', 'ref'],
            req_ctrls=[ManageDSAITControl()],
        )
        self.assertEqual(ldap_result[0].dn_s, dn)
        self.assertEqual(ldap_result[0].entry_as, entry)
        ldap_result = self._ldap_conn.search_s(
            self.server.suffix,
            ldap0.SCOPE_SUBTREE,
            '(dc=relax-rules)',
            attrlist=['*', 'ref'],
        )
        self.assertEqual(
            ldap_result[0].ref_url_strings,
            ['ldap://ldap.uninett.no/dc=uninett,dc=no??one?objectClass=*)']
        )
        ldap_result = self._ldap_conn.search_s(
            self.server.suffix,
            ldap0.SCOPE_SUBTREE,
            '(dc=relax-rules)',
            attrlist=['*', 'ref'],
            req_ctrls=[ManageDSAITControl()],
        )
        self.assertEqual(ldap_result[0].dn_s, dn)
        self.assertEqual(ldap_result[0].entry_as, entry)
        self._ldap_conn.set_option(ldap0.OPT_REFERRALS, opt_ref_old)
        # clean up
        self._ldap_conn.delete_s(dn, req_ctrls=[ManageDSAITControl()])
        # end of test018_referrals()

    def test019_assertion_control(self):
        dn = "cn=AssertionControl," + self.server.suffix
        entry = {
            'objectClass': [b'person'],
            'sn': [b'AssertionControl'],
            'cn': [b'AssertionControl'],
        }
        self._ldap_conn.add_s(dn, entry)
        old = self._ldap_conn.read_s(
            dn,
            attrlist=['entryDN', 'modifyTimestamp', 'entryCSN', 'entryUUID'],
        )
        assertion_filter = (
            '(&'
              '(entryCSN={entryCSN})'
              '(entryDN={entryDN})'
              '(entryUUID={entryUUID})'
              '(modifyTimestamp={modifyTimestamp})'
            ')'
        ).format(
            entryDN=old.entry_s['entryDN'][0],
            entryUUID=old.entry_s['entryUUID'][0],
            modifyTimestamp=old.entry_s['modifyTimestamp'][0],
            entryCSN=old.entry_s['entryCSN'][0],
        )
        self._ldap_conn.modify_s(
            dn,
            [(ldap0.MOD_REPLACE, b'description', [b'test modification #1'])],
            req_ctrls=[AssertionControl(criticality=False, filterstr=assertion_filter)],
        )
        with self.assertRaises(ldap0.ASSERTION_FAILED):
            self._ldap_conn.modify_s(
                dn,
                [(ldap0.MOD_REPLACE, b'description', [b'test modification #2'])],
                req_ctrls=[AssertionControl(filterstr=assertion_filter)],
            )

    def test020_matched_values(self):
        dn = "sn=MatchedValues," + self.server.suffix
        entry = {
            'objectClass': [b'person', b'dcObject'],
            'dc': [b'matched-values'],
            'sn': [b'MatchedValues'],
            'cn': [
                b'MatchedValues0',
                b'MatchedValues1',
                b'MatchedValues2',
                b'MatchedValues3',
                b'MatchedValues4',
                b'MatchedValues5',
            ],
        }
        self._ldap_conn.add_s(dn, entry)
        for val in entry['cn']:
            mv = self._ldap_conn.read_s(
                dn,
                attrlist=['objectClass', 'cn'],
                req_ctrls=[
                    MatchedValuesControl(
                        filterstr='((objectClass=person)(cn=%s))' % (val.decode('utf-8'),)
                    ),
                ]
            )
            self.assertEqual(
                mv.entry_as,
                {'cn': [val], 'objectClass': [b'person']}
            )

    def test021_compare(self):
        self.assertTrue(
            self._ldap_conn.compare_s(
                self.server.root_dn,
                'userPassword',
                self.server.root_pw.encode('utf-8'),
            )
        )
        self.assertFalse(
            self._ldap_conn.compare_s(
                self.server.root_dn,
                'userPassword',
                (self.server.root_pw+'1').encode('utf-8'),
            )
        )
        with self.assertRaises(ldap0.NO_SUCH_OBJECT):
            self._ldap_conn.compare_s('cn=foobar', 'cn', b'foobar')
        with self.assertRaises(ldap0.UNDEFINED_TYPE):
            self._ldap_conn.compare_s('cn=foobar', 'foo', b'bar')

    def test022_get_whoami_dn(self):
        self.assertEqual(
            self._ldap_conn.get_whoami_dn(),
            self.server.root_dn,
        )
        # repeated (cached)
        self.assertEqual(
            self._ldap_conn.get_whoami_dn(),
            self.server.root_dn,
        )
        with self.ldap_object_class(self.server.ldapi_uri) as l:
            self.assertEqual(l._whoami_dn, None)
            l.simple_bind_s('', b'')
            self.assertEqual(l.whoami_s(), '')
            self.assertEqual(l.get_whoami_dn(), '')
            bind_dn = 'cn=user1,'+self.server.suffix
            l.simple_bind_s(bind_dn, b'user1_pw')
            self.assertEqual(
                l.get_whoami_dn(),
                bind_dn,
            )

    def test023_find_unique_entry(self):
        ldap_res = self._ldap_conn.find_unique_entry(
            self.server.suffix,
            ldap0.SCOPE_SUBTREE,
            '(cn=user1)',
        )
        self.assertEqual(ldap_res.dn_s, 'cn=user1,'+self.server.suffix)
        self.assertEqual(
            ldap_res.entry_as,
            {
                'cn': [b'user1'],
                'userPassword': [b'user1_pw'],
                'objectClass': [b'applicationProcess', b'simpleSecurityObject'],
            }
        )
        ldap_res = self._ldap_conn.find_unique_entry(
            self.server.suffix,
            ldap0.SCOPE_SUBTREE,
            '(cn=user1)',
            attrlist=['1.1'],
        )
        self.assertEqual(ldap_res.dn_s, 'cn=user1,'+self.server.suffix)
        self.assertEqual(ldap_res.entry_as, {})
        ldap_res = self._ldap_conn.find_unique_entry(
            self.server.suffix,
            ldap0.SCOPE_SUBTREE,
            '(cn=user1)',
            attrlist=['cn', 'userPassword'],
        )
        self.assertEqual(ldap_res.dn_s, 'cn=user1,'+self.server.suffix)
        self.assertEqual(ldap_res.entry_as, {'cn': [b'user1'], 'userPassword': [b'user1_pw']})
        with self.assertRaises(NoUniqueEntry):
            self._ldap_conn.find_unique_entry(
                self.server.suffix,
                ldap0.SCOPE_SUBTREE,
                '(objectClass=foobar)',
            )
        with self.assertRaises(NoUniqueEntry):
            self._ldap_conn.find_unique_entry(
                self.server.suffix,
                ldap0.SCOPE_SUBTREE,
                '(objectClass=*)',
            )

    def test024_umlauts(self):
        result = self._ldap_conn.search_s(
            self.server.suffix,
            ldap0.SCOPE_SUBTREE,
            '(ou=*ö*)',
            attrlist=['ou'],
        )
        self.assertEqual(len(result), 1)
        self.assertEqual(result[0].dn_s, 'ou=äöüÄÖUß,ou=Container,%s' % (self.server.suffix))
        self.assertEqual(result[0].entry_s, {'ou': ['äöüÄÖUß']})
        self.assertTrue(
            self._ldap_conn.compare_s(
                'ou=äöüÄÖUß,ou=Container,%s' % (self.server.suffix),
                'ou',
                'äöüÄÖUß'.encode('utf-8'),
            )
        )
        add_dn = 'ou=ßÜÖÄüöä,ou=Container,%s' % (self.server.suffix)
        self._ldap_conn.add_s(
            add_dn,
            {
                'objectClass': [b'organizationalUnit'],
                'ou': ['ßÜÖÄüöä'.encode('utf-8')],
            },
        )
        self.assertTrue(
            self._ldap_conn.compare_s(
                add_dn,
                'ou',
                'ßÜÖÄüöä'.encode('utf-8'),
            )
        )
        self._ldap_conn.delete_s(add_dn)

    def test025_search_subschemasubentry_s(self):
        self.assertEqual(
            self._ldap_conn.search_subschemasubentry_s(),
            'cn=Subschema',
        )
        self.assertEqual(
            self._ldap_conn.search_subschemasubentry_s(dn=''),
            'cn=Subschema',
        )
        self.assertEqual(
            self._ldap_conn.search_subschemasubentry_s(dn=self.server.suffix),
            'cn=Subschema',
        )
        # this will cause fall back reading attribute subschemaSubentry from rootDSE
        self.assertEqual(
            self._ldap_conn.search_subschemasubentry_s('cn=doesnotexist'),
            'cn=Subschema',
        )
        # DN of subschema subentry cannot be determined and will return None
        self.assertEqual(
            self._ldap_conn.search_subschemasubentry_s('cn=doesnotexist', rootdse=False),
            None,
        )

    def test001_add_modify_rename_delete(self):
        dn1 = 'cn=äöüÄÖÜß,'+self.server.suffix
        rdn2 = 'cn=LaLeLu4711'
        dn2 = ','.join((rdn2, self.server.suffix))
        entry = {
            'objectClass': [b'applicationProcess'],
            'cn': ['äöüÄÖÜß'.encode('utf-8')],
        }
        add_result = self._ldap_conn.add_s(dn1, entry)
        self.assertEqual(
            (add_result.rtype, add_result.rdata, add_result.msgid, add_result.ctrls),
            (_libldap0.RES_ADD, [], 2, [])
        )
        with self.assertRaises(_libldap0.ALREADY_EXISTS):
            self._ldap_conn.add_s(dn1, entry)
        modify_result = self._ldap_conn.modify_s(dn1, [(ldap0.MOD_ADD, b'description', ['äöüÄÖÜß'.encode('utf-8')])])
        self.assertEqual(
            (modify_result.rtype, modify_result.rdata, modify_result.msgid, modify_result.ctrls),
            (_libldap0.RES_MODIFY, [], 4, [])
        )
        with self.assertRaises(_libldap0.TYPE_OR_VALUE_EXISTS):
            self._ldap_conn.modify_s(dn1, [(ldap0.MOD_ADD, b'description', ['äöüÄÖÜß'.encode('utf-8')])])
        modify_result = self._ldap_conn.modify_s(dn1, [(ldap0.MOD_DELETE, b'description', ['äöüÄÖÜß'.encode('utf-8')])])
        self.assertEqual(
            (modify_result.rtype, modify_result.rdata, modify_result.msgid, modify_result.ctrls),
            (_libldap0.RES_MODIFY, [], 6, [])
        )
        with self.assertRaises(_libldap0.NO_SUCH_ATTRIBUTE):
            self._ldap_conn.modify_s(dn1, [(ldap0.MOD_DELETE, b'description', ['äöüÄÖÜß'.encode('utf-8')])])
        rename_result = self._ldap_conn.rename_s(
            dn1,
            rdn2,
            newsuperior=self.server.suffix,
        )
        self.assertEqual(
            (rename_result.rtype, rename_result.rdata, rename_result.msgid, rename_result.ctrls),
            (_libldap0.RES_MODRDN, [], 8, [])
        )
        read_result = self._ldap_conn.read_s(dn2)
        self.assertEqual(read_result.entry_s, {'cn': ['LaLeLu4711'], 'objectClass': ['applicationProcess']})
        with self.assertRaises(_libldap0.NO_SUCH_OBJECT):
            self._ldap_conn.rename_s(dn1, rdn2)
        delete_result = self._ldap_conn.delete_s(dn2)
        self.assertEqual(
            (delete_result.rtype, delete_result.rdata, delete_result.msgid, delete_result.ctrls),
            (_libldap0.RES_DELETE, [], 11, [])
        )
        with self.assertRaises(_libldap0.NO_SUCH_OBJECT):
            self._ldap_conn.delete_s(dn2)

    def test026_ensure_entry(self):
        dn1 = 'cn=äöüÄÖÜß,'+self.server.suffix
        rdn2 = 'cn=LaLeLu4711'
        dn2 = ','.join((rdn2, self.server.suffix))
        entry1 = {
            'objectClass': [b'applicationProcess'],
            'cn': ['äöüÄÖÜß'.encode('utf-8')],
        }
        entry2 = {
            'objectClass': [b'applicationProcess'],
            'cn': [b'LaLeLu4711'],
            'description': [b'Now you see it...'],
        }
        # add
        ldap_res = self._ldap_conn.ensure_entry(dn1, entry1)
        self.assertEqual(len(ldap_res), 1)
        self.assertEqual(ldap_res[0].rtype, ldap0.RES_ADD)
        # nothing to be done
        ldap_res = self._ldap_conn.ensure_entry(dn1, entry1)
        self.assertEqual(ldap_res, [])
        # delete
        ldap_res = self._ldap_conn.ensure_entry(dn1, None)
        self.assertEqual(len(ldap_res), 1)
        self.assertEqual(ldap_res[0].rtype, ldap0.RES_DELETE)
        # nothing to be done
        ldap_res = self._ldap_conn.ensure_entry(dn1, None)
        self.assertEqual(ldap_res, [])
        with self.assertRaises(_libldap0.NO_SUCH_OBJECT):
            ldap_res = self._ldap_conn.ensure_entry(dn1, None, del_ignore=False)
        # add
        ldap_res = self._ldap_conn.ensure_entry(dn2, entry1)
        self.assertEqual(len(ldap_res), 1)
        self.assertEqual(ldap_res[0].rtype, ldap0.RES_ADD)
        # modify
        ldap_res = self._ldap_conn.ensure_entry(dn2, entry2)
        self.assertEqual(len(ldap_res), 1)
        self.assertEqual(ldap_res[0].rtype, ldap0.RES_MODIFY)
        # rename and modify
        ldap_res = self._ldap_conn.ensure_entry(
            dn1,
            entry1,
            old_base=dn2,
            old_filter='(objectClass=applicationProcess)',
        )
        self.assertEqual(len(ldap_res), 2)
        self.assertEqual(ldap_res[0].rtype, ldap0.RES_MODRDN)
        self.assertEqual(ldap_res[1].rtype, ldap0.RES_MODIFY)
        # clean up
        self._ldap_conn.delete_s(dn1)
        # now some errors....
        with self.assertRaises(ValueError) as ctx:
            self._ldap_conn.ensure_entry(None, None)
        self.assertEqual(str(ctx.exception), 'Expected either dn or old_base to be not None!')

    def test027_res_call_args(self):
        with self.ldap_object_class(self.server.ldapi_uri) as l:
            l.res_call_args = True
            bind_res = l.simple_bind_s('', b'')
            self.assertEqual(l.whoami_s(), '')
            func, args, kwargs = bind_res.call_args
            self.assertEqual(func.__name__, self.ldap_object_class.simple_bind.__name__)
            self.assertEqual(args, (b'', b'', None))
            self.assertEqual(kwargs, {})


class Test01_ReconnectLDAPObject(Test00_LDAPObject):
    """
    test ReconnectLDAPObject by restarting slapd
    """

    ldap_object_class = ReconnectLDAPObject

    def test101_reconnect_sasl_external(self):
        with self.ldap_object_class(self.server.ldapi_uri) as l:
            l.sasl_non_interactive_bind_s('EXTERNAL')
            authz_id = l.whoami_s()
            self.assertEqual(authz_id, 'dn:'+self.server.root_dn.lower())
            self.server.restart()
            self.assertEqual(l.whoami_s(), authz_id)

    def test102_reconnect_simple_bind(self):
        with self.ldap_object_class(self.server.ldapi_uri) as l:
            bind_dn = 'cn=user1,'+self.server.suffix
            l.simple_bind_s(bind_dn, b'user1_pw')
            self.assertEqual(l.whoami_s(), 'dn:'+bind_dn)
            self.server.restart()
            self.assertEqual(l.whoami_s(), 'dn:'+bind_dn)

    def test103_reconnect_get_state(self):
        bind_dn = 'cn=user1,'+self.server.suffix
        expected_state = {
            '_last_bind': (
                'simple_bind_s',
                (bind_dn, b'user1_pw'),
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
            'uri': self.server.ldapi_uri,
            'cache_ttl': 0.0,
            'timeout': -1,
            '_trace_level': 0,
            'res_call_args': False,
            'encoding': 'utf-8',
        }
        with self.ldap_object_class(self.server.ldapi_uri) as l1:
            l1.simple_bind_s(bind_dn, b'user1_pw')
            self.assertEqual(l1.whoami_s(), 'dn:'+bind_dn)
            self.assertEqual(l1.get_whoami_dn(), bind_dn)
            self.assertEqual(l1.__getstate__(), expected_state)

    def test104_reconnect_restore(self):
        with self.ldap_object_class(self.server.ldapi_uri) as l1:
            l1 = self.ldap_object_class(self.server.ldapi_uri)
            bind_dn = 'cn=user1,'+self.server.suffix
            l1.simple_bind_s(bind_dn, 'user1_pw')
            self.assertEqual(l1.whoami_s(), 'dn:'+bind_dn)
            l1_state = pickle.dumps(l1)
        with pickle.loads(l1_state) as l2:
            self.assertEqual(l2.whoami_s(), 'dn:'+bind_dn)

    def test105_null_reconnect(self):
        with self.ldap_object_class(self.server.ldapi_uri, retry_max=0) as l:
            l.sasl_non_interactive_bind_s('EXTERNAL')
            authz_id = l.whoami_s()
            self.assertEqual(authz_id, 'dn:'+self.server.root_dn.lower())
            self.server.restart()
            with self.assertRaises(_libldap0.SERVER_DOWN):
                self.assertEqual(l.whoami_s(), authz_id)

    def test106_reconnect_reset_last_bind(self):
        with self.ldap_object_class(self.server.ldapi_uri, retry_max=1) as l:
            l.sasl_non_interactive_bind_s('EXTERNAL')
            self.assertEqual(l.whoami_s(), 'dn:'+self.server.root_dn.lower())
            # now force reconnect with anon bind
            l.reconnect(l.uri, reset_last_bind=True)
            self.assertEqual(l.whoami_s(), '')

    def test107_reconnect_failure(self):
        with self.ldap_object_class(self.server.ldapi_uri, retry_max=2, retry_delay=0.1) as l:
            l.sasl_non_interactive_bind_s('EXTERNAL')
            authz_id = l.whoami_s()
            self.assertEqual(authz_id, 'dn:'+self.server.root_dn.lower())
            self.server.stop()
            with self.assertRaises(ldap0.SERVER_DOWN):
                l.whoami_s()
            self.server.start()
            l.reconnect(l.uri)
            l.sasl_non_interactive_bind_s('EXTERNAL')
            self.assertEqual(l.whoami_s(), authz_id)


class TestSchemaUrlFetchLDAP(SlapdTestCase):

    def test_schema_urlfetch(self):
        """
        test ldap0.schema.util.urlfetch() which requires a running slapd instance
        """
        schema_dn, sub_schema = ldap0.schema.util.urlfetch(self.server.ldapi_uri, check_uniqueness=True)
        self.assertEqual(schema_dn, 'cn=Subschema')
        oid = sub_schema.name2oid[ldap0.schema.models.AttributeType]['cn']
        self.assertEqual(oid, '2.5.4.3')
        self.assertEqual(oid, sub_schema.name2oid[ldap0.schema.models.AttributeType]['commonName'])


if __name__ == '__main__':
    unittest.main()

# -*- coding: utf-8 -*-
"""
Automatic tests for module ldap0.ldapobject
"""

from __future__ import absolute_import

import os
import unittest
import pickle
import time

# Switch off processing .ldaprc or ldap0.conf before importing _ldap
os.environ['LDAPNOINIT'] = '1'

import ldap0
from ldap0.sasl import SaslPasswordAuth
from ldap0.test import SlapdTestCase
from ldap0.ldapobject import LDAPObject, ReconnectLDAPObject
from ldap0.controls.sessiontrack import SessionTrackingControl, SESSION_TRACKING_FORMAT_OID_USERNAME
from ldap0.controls.readentry import PostReadControl
from ldap0.controls.pagedresults import SimplePagedResultsControl
from ldap0.controls.simple import ProxyAuthzControl, RelaxRulesControl, ManageDSAITControl
from ldap0.controls.libldap import AssertionControl, MatchedValuesControl
from ldap0.extop.whoami import WhoAmIRequest, WhoAmIResponse

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

    def test000_basics(self):
        self.assertEqual(self._ldap_conn.protocol_version, 3)
        self.assertIsInstance(self._ldap_conn.fileno(), int)

    def test001_search_subtree(self):
        result = self._ldap_conn.search_s(
            self.server.suffix,
            ldap0.SCOPE_SUBTREE,
            '(cn=Foo*)',
            attrlist=['*'],
        )
        result.sort()
        self.assertEqual(
            result,
            [
                (
                    'cn=Foo%d,%s' % (i, self.server.suffix),
                    {'cn': ['Foo%d' % i], 'objectClass': ['organizationalRole']}
                )
                for i in range(1, 4)
            ] + [
                (
                    'cn=Foo%d,ou=Container,%s' % (i, self.server.suffix),
                    {'cn': ['Foo%d' % i], 'objectClass': ['organizationalRole']}
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
        result.sort()
        self.assertEqual(
            result,
            [
                (
                    'cn=Foo1,'+self.server.suffix,
                    {'cn': ['Foo1'], 'objectClass': ['organizationalRole']}
                ),
                (
                    'cn=Foo2,'+self.server.suffix,
                    {'cn': ['Foo2'], 'objectClass': ['organizationalRole']}
                ),
                (
                    'cn=Foo3,'+self.server.suffix,
                    {'cn': ['Foo3'], 'objectClass': ['organizationalRole']}
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
            result,
            [('cn=Foo4,ou=Container,'+self.server.suffix, {'cn': ['Foo4']})]
        )

    def test004_errno107(self):
        with self.ldap_object_class('ldap://127.0.0.1:42') as l:
            try:
                m = l.simple_bind_s("", "")
                r = l.result(m, ldap0.MSG_ALL, 1.0)
            except ldap0.SERVER_DOWN as ldap_err:
                errno = ldap_err.args[0]['errno']
                if errno != 107:
                    self.fail("expected errno=107, got %d" % errno)
                info = ldap_err.args[0]['info']
                if info != os.strerror(107):
                    self.fail("expected info=%r, got %d" % (os.strerror(107), info))
            else:
                self.fail("expected SERVER_DOWN, got %r" % r)

    def test005_invalid_credentials(self):
        with self.ldap_object_class(self.server.ldap_uri) as l:
            # search with invalid filter
            try:
                m = l.simple_bind(self.server.root_dn, self.server.root_pw+'wrong')
                r = l.result(m, ldap0.MSG_ALL)
            except ldap0.INVALID_CREDENTIALS:
                pass
            else:
                self.fail("expected INVALID_CREDENTIALS, got %r" % r)

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
                'SCRAM-SHA-1',
            ):
            sasl_auth = SaslPasswordAuth(sasl_mech, 'user1', 'user1_pw')
            with self.ldap_object_class(self.server.ldapi_uri) as l:
                l.sasl_interactive_bind_s('', sasl_auth)
                self.assertEqual(l.whoami_s(), authz_id.lower())

    def test007_timeout(self):
        with self.ldap_object_class(self.server.ldap_uri) as l:
            m = l.search(self.server.suffix, ldap0.SCOPE_SUBTREE, '(objectClass=*)')
            l.abandon(m)
            with self.assertRaises(ldap0.TIMEOUT):
                result = l.result(m, timeout=0.001)

    def test008_sessiontrack_control(self):
        self._ldap_conn.search_s(
            '',
            ldap0.SCOPE_BASE,
            serverctrls=[
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
        _, _, _, resp_ctrls = self._ldap_conn.add_s(
            new_dn,
            [
                ('objectClass', ['applicationProcess']),
                ('cn', ['Anna Blume']),
            ],
            serverctrls=[
                PostReadControl(
                    criticality=True,
                    attrList=attr_list,
                )
            ],
        )
        self.assertEqual(resp_ctrls[0].dn, new_dn)
        self.assertEqual(resp_ctrls[0].entry['entryDN'], [new_dn])
        self.assertEqual(len(resp_ctrls[0].entry), len(attr_list))
        self.assertEqual(sorted(resp_ctrls[0].entry.keys()), attr_list)

    def test010_pagedresults(self):
        expected_ldap_result = sorted(
            self._ldap_conn.search_s(
                self.server.suffix,
                ldap0.SCOPE_SUBTREE,
                attrlist=['1.1'],
            )
        )
        expected_num_results = len(expected_ldap_result)
        self.assertEqual(expected_ldap_result >= 10, True)
        page_size = 3
        expected_num_pages = expected_num_results / page_size + \
                            (expected_num_results % page_size > 0)
        paged_results_control = SimplePagedResultsControl(
            True,
            size=page_size,
            cookie=''
        )
        result_pages = 0
        all_paged_results = []
        msg_id = self._ldap_conn.search(
            self.server.suffix,
            ldap0.SCOPE_SUBTREE,
            attrlist=['1.1'],
            serverctrls=[paged_results_control],
        )
        while True:
            rtype, rdata, rmsgid, rctrls, _, _ = self._ldap_conn.result(msg_id)
            self.assertEqual(rmsgid, msg_id)
            all_paged_results.extend(rdata)
            result_pages += 1
            self.assertEqual(rctrls[0].controlType, SimplePagedResultsControl.controlType)
            if rctrls[0].cookie:
                # Copy cookie from response control to request control
                paged_results_control.cookie = rctrls[0].cookie
                msg_id = self._ldap_conn.search(
                    self.server.suffix,
                    ldap0.SCOPE_SUBTREE,
                    attrlist=['1.1'],
                    serverctrls=[paged_results_control],
                )
            else:
                break # no more pages available
        self.assertEqual(sorted(all_paged_results), expected_ldap_result)
        self.assertEqual(result_pages, expected_num_pages)

    def test011_add_dict(self):
        new_dn = 'cn=Kurt Schwitters,'+self.server.suffix
        new_entry = {
            'objectClass': ['applicationProcess'],
            'cn': ['Kurt Schwitters'],
            'description': ['Dada!'],
        }
        self._ldap_conn.add_s(new_dn, new_entry)
        entry = self._ldap_conn.read_s(new_dn, attrlist=new_entry.keys())
        self.assertEqual(entry, new_entry)
        self._ldap_conn.delete_s(new_dn)

    def test012_results(self):
        msg_id = self._ldap_conn.search(
            self.server.suffix,
            ldap0.SCOPE_SUBTREE,
            '(cn=Foo*)',
            attrlist=['*'],
        )
        result = []
        for result_type, result_list, result_msgid, result_serverctrls in self._ldap_conn.results(msg_id):
            for dn, entry in result_list:
                result.append((dn, entry))
        result.sort()
        self.assertEqual(
            result,
            [
                (
                    'cn=Foo%d,%s' % (i, self.server.suffix),
                    {'cn': ['Foo%d' % i], 'objectClass': ['organizationalRole']}
                )
                for i in range(1, 4)
            ] + [
                (
                    'cn=Foo%d,ou=Container,%s' % (i, self.server.suffix),
                    {'cn': ['Foo%d' % i], 'objectClass': ['organizationalRole']}
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
            l.sasl_non_interactive_bind_s('EXTERNAL')
            self.assertEqual(l.whoami_s(), 'dn:'+self.server.root_dn.lower())
            new_dn = 'cn=Cache Tester,'+self.server.suffix
            new_entry = {
                'objectClass': ['applicationProcess'],
                'cn': ['Cache Tester'],
            }
            l.add_s(new_dn, new_entry)
            for i in range(5):
                dn, entry = l.search_s(new_dn, ldap0.SCOPE_BASE)[0]
                self.assertEqual(dn, new_dn)
                self.assertEqual(entry, new_entry)
                self.assertEqual(l._cache_misses, 1)
                self.assertEqual(l._cache_hits, i)
                self.assertEqual(len(l._cache), 1)
            cache_hits = l._cache_hits
            cache_misses = l._cache_misses
            l.modify_s(new_dn, [(ldap0.MOD_ADD, 'description', ['cache test'])])
            l.modify_s(new_dn, [(ldap0.MOD_DELETE, 'description', ['cache test'])])
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
                dn, entry = l.search_s(new_dn, ldap0.SCOPE_BASE)[0]
                self.assertEqual(dn, new_dn)
                self.assertEqual(entry, new_entry)
                self.assertEqual(l._cache_misses, 1)
                self.assertEqual(l._cache_hits, i)
                self.assertEqual(len(l._cache), 1)
            _ = l.search_s(
                self.server.suffix,
                ldap0.SCOPE_SUBTREE,
                '(entryDN={0})'.format(new_dn),
            )
            self.assertEqual(len(l._cache), 2)
            l.uncache(new_dn)
            self.assertEqual(l._cache_misses, 2)
            self.assertEqual(l._cache_hits, i)
            self.assertEqual(len(l._cache), 0)
            l.flush_cache()
            for i in range(4):
                dn, entry = l.search_s(new_dn, ldap0.SCOPE_BASE, cache_ttl=0.05)[0]
                self.assertEqual(dn, new_dn)
                self.assertEqual(entry, new_entry)
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
                l.whoami_s([ProxyAuthzControl(authzId=authz_id)]),
                authz_id.lower(),
            )
        with self.ldap_object_class(self.server.ldapi_uri) as l:
            l.simple_bind_s('', '')
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
            [
                ('objectClass', 'person'),
                ('sn', 'PasswordTest'),
                ('cn', 'PasswordTest'),
                ('userPassword', 'initial'),
            ]
        )
        # try changing password with a wrong old-pw
        try:
            res = self._ldap_conn.passwd_s(dn, 'bogus', 'ignored')
        except ldap0.UNWILLING_TO_PERFORM:
            pass
        else:
            self.fail('expected UNWILLING_TO_PERFORM, got %r' % (res))
        # try changing password with a correct old-pw
        new_pwd = self._ldap_conn.passwd_s(dn, 'initial', 'changed')
        self.assertEqual(new_pwd, None)
        with self.ldap_object_class(self.server.ldapi_uri) as l:
            l.simple_bind_s(dn, 'changed')
        # let server set new random password
        new_pwd = self._ldap_conn.passwd_s(dn, 'changed', None)
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
            'objectClass': ['person'],
            'sn': ['RelaxRules'],
            'cn': ['RelaxRules'],
            'createTimestamp': ['19680208115125Z'],
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
            serverctrls=[RelaxRulesControl()],
        )

    def test018_referrals(self):
        opt_ref_old = self._ldap_conn.get_option(ldap0.OPT_REFERRALS)
        self._ldap_conn.set_option(ldap0.OPT_REFERRALS, ldap0.OPT_OFF)
        dn = "dc=relax-rules," + self.server.suffix
        entry = {
            'objectClass': ['dcObject', 'referral'],
            'dc': ['relax-rules'],
            'ref': ['ldap://ldap.uninett.no/dc=uninett,dc=no??one?objectClass=*)'],
        }
        self._ldap_conn.add_s(dn, entry)
        try:
            ldap_result = self._ldap_conn.search_s(dn, ldap0.SCOPE_BASE, attrlist=['*', 'ref'])
        except ldap0.REFERRAL as ldap_ref:
            self.assertEqual(
                ldap_ref.args[0]['desc'],
                'Referral'
            )
            self.assertEqual(
                ldap_ref.args[0]['matched'],
                'dc=relax-rules,dc=slapd-test,dc=example,dc=org'
            )
            self.assertEqual(
                ldap_ref.args[0]['info'],
                'Referral:\nldap://ldap.uninett.no/dc=uninett,dc=no??one?objectClass=*)'
            )
        else:
            self.fail("should have raised ldap0.REFERRAL")
        ldap_result = self._ldap_conn.search_s(
            dn,
            ldap0.SCOPE_BASE,
            attrlist=['*', 'ref'],
            serverctrls=[ManageDSAITControl()],
        )
        self.assertEqual(ldap_result, [(dn, entry)])
        ldap_result = self._ldap_conn.search_s(
            self.server.suffix,
            ldap0.SCOPE_SUBTREE,
            '(dc=relax-rules)',
            attrlist=['*', 'ref'],
        )
        self.assertEqual(
            ldap_result,
            [(None, ['ldap://ldap.uninett.no/dc=uninett,dc=no??one?objectClass=*)'])]
        )
        ldap_result = self._ldap_conn.search_s(
            self.server.suffix,
            ldap0.SCOPE_SUBTREE,
            '(dc=relax-rules)',
            attrlist=['*', 'ref'],
            serverctrls=[ManageDSAITControl()],
        )
        self.assertEqual(ldap_result, [(dn, entry)])
        self._ldap_conn.set_option(ldap0.OPT_REFERRALS, opt_ref_old)

    def test019_assertion_control(self):
        dn = "cn=AssertionControl," + self.server.suffix
        entry = {
            'objectClass': ['person'],
            'sn': ['AssertionControl'],
            'cn': ['AssertionControl'],
        }
        self._ldap_conn.add_s(dn, entry)
        old_entry = self._ldap_conn.read_s(dn, attrlist=['modifyTimestamp', 'entryCSN'])
        assertion_filter = '(&(modifyTimestamp={0})(entryCSN={1}))'.format(
            old_entry['modifyTimestamp'][0],
            old_entry['entryCSN'][0],
        )
        self._ldap_conn.modify_s(
            dn,
            [(ldap0.MOD_REPLACE, 'description', ['test modification #1'])],
            serverctrls=[AssertionControl(filterstr=assertion_filter)],
        )
        try:
            self._ldap_conn.modify_s(
                dn,
                [(ldap0.MOD_REPLACE, 'description', ['test modification #2'])],
                serverctrls=[AssertionControl(filterstr=assertion_filter)],
            )
        except ldap0.ASSERTION_FAILED:
            pass
        else:
            self.fail("should have raised ldap0.ASSERTION_FAILED")

    def test020_matched_values(self):
        dn = "sn=MatchedValues," + self.server.suffix
        entry = {
            'objectClass': ['person', 'dcObject'],
            'dc': ['matched-values'],
            'sn': ['MatchedValues'],
            'cn': [
                'MatchedValues0',
                'MatchedValues1',
                'MatchedValues2',
                'MatchedValues3',
                'MatchedValues4',
                'MatchedValues5',
            ],
        }
        self._ldap_conn.add_s(dn, entry)
        for val in entry['cn']:
            mv_entry = self._ldap_conn.read_s(
                dn,
                attrlist=['objectClass', 'cn'],
                serverctrls=[
                    MatchedValuesControl(
                        filterstr='((objectClass=person)(cn={0}))'.format(val)
                    ),
                ]
            )
            self.assertEqual(
                mv_entry,
                {'cn': [val], 'objectClass': ['person']}
            )

    def test021_compare(self):
        self.assertTrue(
            self._ldap_conn.compare_s(
                self.server.root_dn,
                'userPassword',
                self.server.root_pw,
            )
        )
        self.assertFalse(
            self._ldap_conn.compare_s(
                self.server.root_dn,
                'userPassword',
                self.server.root_pw+'1',
            )
        )
        with self.assertRaises(ldap0.NO_SUCH_OBJECT):
            self._ldap_conn.compare_s('cn=foobar', 'cn', 'foobar')
        with self.assertRaises(ldap0.UNDEFINED_TYPE):
            self._ldap_conn.compare_s('cn=foobar', 'foo', 'bar')


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
            l.simple_bind_s(bind_dn, 'user1_pw')
            self.assertEqual(l.whoami_s(), 'dn:'+bind_dn)
            self.server.restart()
            self.assertEqual(l.whoami_s(), 'dn:'+bind_dn)

    def test103_reconnect_get_state(self):
        bind_dn = 'cn=user1,'+self.server.suffix
        expected_state = {
            '_cache': {},
            '_cache_hits': 0,
            '_cache_misses': 0,
            '_last_bind': (
                'simple_bind_s',
                (bind_dn, 'user1_pw'),
                {}
            ),
            '_options': [(17, 3), (9, 0), (2, 0), (8, 0)],
            '_reconnects_done': 0,
            '_retry_delay': 60.0,
            '_retry_max': 1,
            '_start_tls': 0,
            '_uri': self.server.ldapi_uri,
            'uri': self.server.ldapi_uri,
            'cache_ttl': 0.0,
            'timeout': -1,
            '_trace_level': 0,
            '_trace_stack_limit': 5,
        }
        with self.ldap_object_class(self.server.ldapi_uri) as l1:
            l1.simple_bind_s(bind_dn, 'user1_pw')
            self.assertEqual(l1.whoami_s(), 'dn:'+bind_dn)
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


if __name__ == '__main__':
    unittest.main()

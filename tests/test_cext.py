# -*- coding: utf-8 -*-
"""
Automatic tests for C wrapper module _libldap0
"""

from __future__ import absolute_import

import os
import logging
import unittest
from errno import ENOTCONN

from ldap0.test import SlapdTestCase

# Switch off processing .ldaprc or ldap.conf before importing _ldap
os.environ['LDAPNOINIT'] = '1'

# import the plain C wrapper module
import _libldap0


class TestLdapCExtension(SlapdTestCase):
    """
    These tests apply only to the _ldap module and therefore bypass the
    LDAPObject wrapper completely.
    """

    timeout = 5

    @classmethod
    def setUpClass(cls):
        super(TestLdapCExtension, cls).setUpClass()
        # add two initial objects after server was started and is still empty
        suffix_dc = cls.server.suffix.split(',')[0][3:]
        logging.debug(
            "adding %s and %s",
            cls.server.suffix,
            cls.server.root_dn,
        )
        cls.server.ldapadd(
            "\n".join([
                'dn: '+cls.server.suffix,
                'objectClass: dcObject',
                'objectClass: organization',
                'dc: '+suffix_dc,
                'o: '+suffix_dc,
                '',
                'dn: '+cls.server.root_dn,
                'objectClass: applicationProcess',
                'cn: '+cls.server.root_cn,
                ''
            ])
        )

    def _open_conn(self, bind=True):
        """
        Starts a server, and returns a LDAPObject bound to it
        """
        l = _libldap0.initialize(self.server.ldap_uri)
        if bind:
            # Perform a simple bind
            l.set_option(_libldap0.OPT_PROTOCOL_VERSION, _libldap0.VERSION3)
            m = l.simple_bind(self.server.root_dn, self.server.root_pw)
            result, pmsg, msgid, ctrls = l.result(m, _libldap0.MSG_ONE, self.timeout)
            self.assertEqual(result, _libldap0.RES_BIND)
            self.assertEqual(type(msgid), type(0))
        return l

    # Test for the existence of a whole bunch of constants
    # that the C module is supposed to export
    def test_constants(self):
        """
        Test whether all libldap-derived constants are correct
        """
        self.assertEqual(_libldap0.PORT, 389)
        self.assertEqual(_libldap0.VERSION1, 1)
        self.assertEqual(_libldap0.VERSION2, 2)
        self.assertEqual(_libldap0.VERSION3, 3)

        # constants for result()
        self.assertEqual(_libldap0.RES_BIND, 0x61)
        self.assertEqual(_libldap0.RES_SEARCH_ENTRY, 0x64)
        self.assertEqual(_libldap0.RES_SEARCH_RESULT, 0x65)
        self.assertEqual(_libldap0.RES_MODIFY, 0x67)
        self.assertEqual(_libldap0.RES_ADD, 0x69)
        self.assertEqual(_libldap0.RES_DELETE, 0x6b)
        self.assertEqual(_libldap0.RES_MODRDN, 0x6d)
        self.assertEqual(_libldap0.RES_COMPARE, 0x6f)
        self.assertEqual(_libldap0.RES_SEARCH_REFERENCE, 0x73) # v3
        self.assertEqual(_libldap0.RES_EXTENDED, 0x78)         # v3
        #self.assertEqual(_libldap0.RES_INTERMEDIATE, 0x79)     # v3
        self.assertIsNotNone(_libldap0.RES_ANY)
        self.assertIsNotNone(_libldap0.RES_UNSOLICITED)

        self.assertIsNotNone(_libldap0.AUTH_NONE)
        self.assertIsNotNone(_libldap0.AUTH_SIMPLE)

        self.assertIsNotNone(_libldap0.SCOPE_BASE)
        self.assertIsNotNone(_libldap0.SCOPE_ONELEVEL)
        self.assertIsNotNone(_libldap0.SCOPE_SUBTREE)

        self.assertIsNotNone(_libldap0.MOD_ADD)
        self.assertIsNotNone(_libldap0.MOD_DELETE)
        self.assertIsNotNone(_libldap0.MOD_REPLACE)
        self.assertIsNotNone(_libldap0.MOD_INCREMENT)
        self.assertIsNotNone(_libldap0.MOD_BVALUES)

        # for result()
        self.assertIsNotNone(_libldap0.MSG_ONE)
        self.assertIsNotNone(_libldap0.MSG_ALL)
        self.assertIsNotNone(_libldap0.MSG_RECEIVED)

        # for OPT_DEFEF
        self.assertIsNotNone(_libldap0.DEREF_NEVER)
        self.assertIsNotNone(_libldap0.DEREF_SEARCHING)
        self.assertIsNotNone(_libldap0.DEREF_FINDING)
        self.assertIsNotNone(_libldap0.DEREF_ALWAYS)

        # for OPT_SIZELIMIT, OPT_TIMELIMIT
        self.assertIsNotNone(_libldap0.NO_LIMIT)

        # standard options
        self.assertIsNotNone(_libldap0.OPT_API_INFO)
        self.assertIsNotNone(_libldap0.OPT_DEREF)
        self.assertIsNotNone(_libldap0.OPT_SIZELIMIT)
        self.assertIsNotNone(_libldap0.OPT_TIMELIMIT)
        self.assertIsNotNone(_libldap0.OPT_REFERRALS)
        self.assertIsNotNone(_libldap0.OPT_RESTART)
        self.assertIsNotNone(_libldap0.OPT_PROTOCOL_VERSION)
        self.assertIsNotNone(_libldap0.OPT_SERVER_CONTROLS)
        self.assertIsNotNone(_libldap0.OPT_API_FEATURE_INFO)
        self.assertIsNotNone(_libldap0.OPT_HOST_NAME)
        self.assertIsNotNone(_libldap0.OPT_ERROR_NUMBER)   # = OPT_RESULT_CODE
        self.assertIsNotNone(_libldap0.OPT_ERROR_STRING)   # = OPT_DIAGNOSITIC_MESSAGE
        self.assertIsNotNone(_libldap0.OPT_MATCHED_DN)

        # OpenLDAP specific
        self.assertIsNotNone(_libldap0.OPT_DEBUG_LEVEL)
        self.assertIsNotNone(_libldap0.OPT_TIMEOUT)
        self.assertIsNotNone(_libldap0.OPT_REFHOPLIMIT)
        self.assertIsNotNone(_libldap0.OPT_NETWORK_TIMEOUT)
        self.assertIsNotNone(_libldap0.OPT_URI)
        #self.assertIsNotNone(_libldap0.OPT_REFERRAL_URLS)
        #self.assertIsNotNone(_libldap0.OPT_SOCKBUF)
        #self.assertIsNotNone(_libldap0.OPT_DEFBASE)
        #self.assertIsNotNone(_libldap0.OPT_CONNECT_ASYNC)

        # str2dn()
        self.assertIsNotNone(_libldap0.DN_FORMAT_LDAP)
        self.assertIsNotNone(_libldap0.DN_FORMAT_LDAPV3)
        self.assertIsNotNone(_libldap0.DN_FORMAT_LDAPV2)
        self.assertIsNotNone(_libldap0.DN_FORMAT_DCE)
        self.assertIsNotNone(_libldap0.DN_FORMAT_UFN)
        self.assertIsNotNone(_libldap0.DN_FORMAT_AD_CANONICAL)
        self.assertIsNotNone(_libldap0.DN_FORMAT_MASK)
        self.assertIsNotNone(_libldap0.DN_PRETTY)
        self.assertIsNotNone(_libldap0.DN_SKIP)
        self.assertIsNotNone(_libldap0.DN_P_NOLEADTRAILSPACES)
        self.assertIsNotNone(_libldap0.DN_P_NOSPACEAFTERRDN)
        self.assertIsNotNone(_libldap0.DN_PEDANTIC)
        self.assertIsNotNone(_libldap0.AVA_NULL)
        self.assertIsNotNone(_libldap0.AVA_STRING)
        self.assertIsNotNone(_libldap0.AVA_BINARY)
        self.assertIsNotNone(_libldap0.AVA_NONPRINTABLE)

        # these two constants are pointless? XXX
        self.assertEqual(_libldap0.OPT_ON, 1)
        self.assertEqual(_libldap0.OPT_OFF, 0)

        # these constants useless after ldap_url_parse() was dropped XXX
        self.assertIsNotNone(_libldap0.URL_ERR_BADSCOPE)
        self.assertIsNotNone(_libldap0.URL_ERR_MEM)

    def test_simple_bind(self):
        l = self._open_conn()

    def test_simple_anonymous_bind(self):
        l = self._open_conn(bind=False)
        m = l.simple_bind("", "")
        self.assertEqual(type(m), type(0))
        result, pmsg, msgid, ctrls = l.result(m, _libldap0.MSG_ALL, self.timeout)
        self.assertEqual(result, _libldap0.RES_BIND)
        self.assertEqual(msgid, m)
        self.assertEqual(pmsg, [])
        self.assertEqual(ctrls, [])

    def test_anon_rootdse_search(self):
        l = self._open_conn(bind=False)
        # see if we can get the rootdse with anon search (without prior bind)
        m = l.search_ext(
            '',
            _libldap0.SCOPE_BASE,
            '(objectClass=*)',
            ['objectClass', 'namingContexts'],
        )
        self.assertEqual(type(m), type(0))
        result, pmsg, msgid, ctrls = l.result(m, _libldap0.MSG_ALL, self.timeout)
        self.assertEqual(result, _libldap0.RES_SEARCH_RESULT)
        self.assertEqual(pmsg[0][0], "") # rootDSE has no dn
        self.assertEqual(msgid, m)
        self.assertEqual(ctrls, [])
        root_dse = pmsg[0][1]
        self.assertTrue('objectClass' in root_dse)
        self.assertTrue('OpenLDAProotDSE' in root_dse['objectClass'])
        self.assertTrue('namingContexts' in root_dse)
        self.assertEqual(root_dse['namingContexts'], [self.server.suffix])

    def test_unbind(self):
        l = self._open_conn()
        m = l.unbind_ext()
        self.assertIsNone(m)
        # Second attempt to unbind should yield an exception
        try:
            l.unbind_ext()
        except _libldap0.error:
            pass

    def test_search_ext_individual(self):
        l = self._open_conn()
        # send search request
        m = l.search_ext(
            self.server.suffix,
            _libldap0.SCOPE_SUBTREE,
            '(objectClass=dcObject)'
        )
        self.assertEqual(type(m), type(0))
        result, pmsg, msgid, ctrls = l.result(m, _libldap0.MSG_ONE, self.timeout)
        # Expect to get just one object
        self.assertEqual(result, _libldap0.RES_SEARCH_ENTRY)
        self.assertEqual(len(pmsg), 1)
        self.assertEqual(len(pmsg[0]), 2)
        self.assertEqual(pmsg[0][0], self.server.suffix)
        self.assertEqual(pmsg[0][0], self.server.suffix)
        self.assertTrue('dcObject' in pmsg[0][1]['objectClass'])
        self.assertTrue('organization' in pmsg[0][1]['objectClass'])
        self.assertEqual(msgid, m)
        self.assertEqual(ctrls, [])

        result, pmsg, msgid, ctrls = l.result(m, _libldap0.MSG_ONE, self.timeout)
        self.assertEqual(result, _libldap0.RES_SEARCH_RESULT)
        self.assertEqual(pmsg, [])
        self.assertEqual(msgid, m)
        self.assertEqual(ctrls, [])

    def test_abandon(self):
        l = self._open_conn()
        m = l.search_ext(self.server.suffix, _libldap0.SCOPE_SUBTREE, '(objectClass=*)')
        ret = l.abandon_ext(m)
        self.assertIsNone(ret)
        try:
            r = l.result(m, _libldap0.MSG_ALL, 0.3)  # (timeout /could/ be longer)
        except _libldap0.TIMEOUT as e:
            pass
        else:
            self.fail("expected TIMEOUT, got %r" % r)

    def test_search_ext_all(self):
        l = self._open_conn()
        # send search request
        m = l.search_ext(self.server.suffix, _libldap0.SCOPE_SUBTREE, '(objectClass=*)')
        self.assertEqual(type(m), type(0))
        result, pmsg, msgid, ctrls = l.result(m, _libldap0.MSG_ALL, self.timeout)
        # Expect to get some objects
        self.assertEqual(result, _libldap0.RES_SEARCH_RESULT)
        self.assertTrue(len(pmsg) >= 2)
        self.assertEqual(msgid, m)
        self.assertEqual(ctrls, [])

    def test_add(self):
        """
        test add operation
        """
        l = self._open_conn()
        m = l.add_ext(
            "cn=Foo," + self.server.suffix,
            [
                ('objectClass', ['organizationalRole']),
                ('cn', ['Foo']),
                ('description', ['testing']),
            ]
        )
        self.assertEqual(type(m), type(0))
        result, pmsg, msgid, ctrls = l.result(m, _libldap0.MSG_ALL, self.timeout)
        self.assertEqual(result, _libldap0.RES_ADD)
        self.assertEqual(pmsg, [])
        self.assertEqual(msgid, m)
        self.assertEqual(ctrls, [])
        # search for it back
        m = l.search_ext(self.server.suffix, _libldap0.SCOPE_SUBTREE, '(cn=Foo)')
        result, pmsg, msgid, ctrls = l.result(m, _libldap0.MSG_ALL, self.timeout)
        # Expect to get the objects
        self.assertEqual(result, _libldap0.RES_SEARCH_RESULT)
        self.assertEqual(len(pmsg), 1)
        self.assertEqual(msgid, m)
        self.assertEqual(ctrls, [])
        self.assertEqual(
            pmsg[0],
            (
                'cn=Foo,'+self.server.suffix,
                {
                    'objectClass': ['organizationalRole'],
                    'cn': ['Foo'],
                    'description': ['testing'],
                }
            )
        )

    def test_compare(self):
        """
        test compare operation
        """
        l = self._open_conn()
        # first, add an object with a field we can compare on
        dn = "cn=CompareTest," + self.server.suffix
        m = l.add_ext(
            dn,
            [
                ('objectClass', ['person']),
                ('sn', ['CompareTest']),
                ('cn', ['CompareTest']),
                ('userPassword', ['the_password']),
            ],
        )
        self.assertEqual(type(m), type(0))
        result, pmsg, msgid, ctrls = l.result(m, _libldap0.MSG_ALL, self.timeout)
        self.assertEqual(result, _libldap0.RES_ADD)
        # try a false compare
        m = l.compare_ext(dn, "userPassword", "bad_string")
        try:
            r = l.result(m, _libldap0.MSG_ALL, self.timeout)
        except _libldap0.COMPARE_FALSE:
            pass
        else:
            self.fail("expected COMPARE_FALSE, got %r" % r)
        # try a true compare
        m = l.compare_ext(dn, "userPassword", "the_password")
        try:
            r = l.result(m, _libldap0.MSG_ALL, self.timeout)
        except _libldap0.COMPARE_TRUE:
            pass
        else:
            self.fail("expected COMPARE_TRUE, got %r" % r)
        # try a compare on bad attribute
        m = l.compare_ext(dn, "badAttribute", "ignoreme")
        try:
            r = l.result(m, _libldap0.MSG_ALL, self.timeout)
        except _libldap0.error:
            pass
        else:
            self.fail("expected LDAPError, got %r" % r)

    def test_delete_no_such_object(self):
        """
        try deleting an object that doesn't exist
        """
        l = self._open_conn()
        m = l.delete_ext("cn=DoesNotExist,"+self.server.suffix)
        try:
            r = l.result(m, _libldap0.MSG_ALL, self.timeout)
        except _libldap0.NO_SUCH_OBJECT:
            pass
        else:
            self.fail("expected NO_SUCH_OBJECT, got %r" % r)

    def test_delete(self):
        l = self._open_conn()
        # first, add an object we will delete
        dn = "cn=Deleteme,"+self.server.suffix
        m = l.add_ext(
            dn,
            [
                ('objectClass', ['organizationalRole']),
                ('cn', ['Deleteme']),
            ]
        )
        self.assertEqual(type(m), type(0))
        result, pmsg, msgid, ctrls = l.result(m, _libldap0.MSG_ALL, self.timeout)
        self.assertEqual(result, _libldap0.RES_ADD)

        m = l.delete_ext(dn)
        result, pmsg, msgid, ctrls = l.result(m, _libldap0.MSG_ALL, self.timeout)
        self.assertEqual(result, _libldap0.RES_DELETE)
        self.assertEqual(msgid, m)
        self.assertEqual(pmsg, [])
        self.assertEqual(ctrls, [])

    def test_modify_no_such_object(self):
        l = self._open_conn()

        # try deleting an object that doesn't exist
        m = l.modify_ext(
            "cn=DoesNotExist,"+self.server.suffix,
            [
                (_libldap0.MOD_ADD, 'description', ['blah']),
            ]
        )
        try:
            r = l.result(m, _libldap0.MSG_ALL, self.timeout)
        except _libldap0.NO_SUCH_OBJECT:
            pass
        else:
            self.fail("expected NO_SUCH_OBJECT, got %r" % r)

    def test_modify_no_such_object_empty_attrs(self):
        """
        try deleting an object that doesn't exist
        """
        l = self._open_conn()
        m = l.modify_ext(
            "cn=DoesNotExist,"+self.server.suffix,
            [
                (_libldap0.MOD_ADD, 'description', ['dummy']),
            ]
        )
        self.assertTrue(isinstance(m, int))
        try:
            r = l.result(m, _libldap0.MSG_ALL, self.timeout)
        except _libldap0.NO_SUCH_OBJECT:
            pass
        else:
            self.fail("expected NO_SUCH_OBJECT, got %r" % r)

    def test_modify(self):
        """
        test modify operation
        """
        l = self._open_conn()
        # first, add an object we will delete
        dn = "cn=AddToMe,"+self.server.suffix
        m = l.add_ext(
            dn,
            [
                ('objectClass', ['person']),
                ('cn', ['AddToMe']),
                ('sn', ['Modify']),
                ('description', ['a description']),
            ]
        )
        self.assertEqual(type(m), type(0))
        result, pmsg, msgid, ctrls = l.result(m, _libldap0.MSG_ALL, self.timeout)
        self.assertEqual(result, _libldap0.RES_ADD)

        m = l.modify_ext(
            dn,
            [
                (_libldap0.MOD_ADD, 'description', ['b desc', 'c desc']),
            ]
        )
        result, pmsg, msgid, ctrls = l.result(m, _libldap0.MSG_ALL, self.timeout)
        self.assertEqual(result, _libldap0.RES_MODIFY)
        self.assertEqual(pmsg, [])
        self.assertEqual(msgid, m)
        self.assertEqual(ctrls, [])
        # search for it back
        m = l.search_ext(self.server.suffix, _libldap0.SCOPE_SUBTREE, '(cn=AddToMe)')
        result, pmsg, msgid, ctrls = l.result(m, _libldap0.MSG_ALL, self.timeout)
        # Expect to get the objects
        self.assertEqual(result, _libldap0.RES_SEARCH_RESULT)
        self.assertEqual(len(pmsg), 1)
        self.assertEqual(msgid, m)
        self.assertEqual(ctrls, [])
        self.assertEqual(pmsg[0][0], dn)
        d = list(pmsg[0][1]['description'])
        d.sort()
        self.assertEqual(d, ['a description', 'b desc', 'c desc'])

    def test_rename(self):
        l = self._open_conn()
        dn = "cn=RenameMe,"+self.server.suffix
        m = l.add_ext(
            dn,
            [
                ('objectClass', ['organizationalRole']),
                ('cn', ['RenameMe']),
            ]
        )
        self.assertEqual(type(m), type(0))
        result, pmsg, msgid, ctrls = l.result(m, _libldap0.MSG_ALL, self.timeout)
        self.assertEqual(result, _libldap0.RES_ADD)

        # do the rename with same parent
        m = l.rename(dn, "cn=IAmRenamed")
        result, pmsg, msgid, ctrls = l.result(m, _libldap0.MSG_ALL, self.timeout)
        self.assertEqual(result, _libldap0.RES_MODRDN)
        self.assertEqual(msgid, m)
        self.assertEqual(pmsg, [])
        self.assertEqual(ctrls, [])

        # make sure the old one is gone
        m = l.search_ext(self.server.suffix, _libldap0.SCOPE_SUBTREE, '(cn=RenameMe)')
        result, pmsg, msgid, ctrls = l.result(m, _libldap0.MSG_ALL, self.timeout)
        self.assertEqual(result, _libldap0.RES_SEARCH_RESULT)
        self.assertEqual(len(pmsg), 0) # expect no results
        self.assertEqual(msgid, m)
        self.assertEqual(ctrls, [])

        # check that the new one looks right
        dn2 = "cn=IAmRenamed,"+self.server.suffix
        m = l.search_ext(self.server.suffix, _libldap0.SCOPE_SUBTREE, '(cn=IAmRenamed)')
        result, pmsg, msgid, ctrls = l.result(m, _libldap0.MSG_ALL, self.timeout)
        self.assertEqual(result, _libldap0.RES_SEARCH_RESULT)
        self.assertEqual(msgid, m)
        self.assertEqual(ctrls, [])
        self.assertEqual(len(pmsg), 1)
        self.assertEqual(pmsg[0][0], dn2)
        self.assertEqual(pmsg[0][1]['cn'], ['IAmRenamed'])

        # create the container
        containerDn = "ou=RenameContainer,"+self.server.suffix
        m = l.add_ext(
            containerDn,
            [
                ('objectClass', ['organizationalUnit']),
                ('ou', ['RenameContainer']),
            ]
        )
        result, pmsg, msgid, ctrls = l.result(m, _libldap0.MSG_ALL, self.timeout)
        self.assertEqual(result, _libldap0.RES_ADD)

        # now rename from dn2 to the conater
        dn3 = "cn=IAmRenamedAgain," + containerDn

        # Now try renaming dn2 across container (simultaneous name change)
        m = l.rename(dn2, "cn=IAmRenamedAgain", containerDn)
        result, pmsg, msgid, ctrls = l.result(m, _libldap0.MSG_ALL, self.timeout)
        self.assertEqual(result, _libldap0.RES_MODRDN)
        self.assertEqual(msgid, m)
        self.assertEqual(pmsg, [])
        self.assertEqual(ctrls, [])

        # make sure dn2 is gone
        m = l.search_ext(self.server.suffix, _libldap0.SCOPE_SUBTREE, '(cn=IAmRenamed)')
        result, pmsg, msgid, ctrls = l.result(m, _libldap0.MSG_ALL, self.timeout)
        self.assertEqual(result, _libldap0.RES_SEARCH_RESULT)
        self.assertEqual(len(pmsg), 0) # expect no results
        self.assertEqual(msgid, m)
        self.assertEqual(ctrls, [])

        m = l.search_ext(self.server.suffix, _libldap0.SCOPE_SUBTREE, '(objectClass=*)')
        result, pmsg, msgid, ctrls = l.result(m, _libldap0.MSG_ALL, self.timeout)

        # make sure dn3 is there
        m = l.search_ext(self.server.suffix, _libldap0.SCOPE_SUBTREE, '(cn=IAmRenamedAgain)')
        result, pmsg, msgid, ctrls = l.result(m, _libldap0.MSG_ALL, self.timeout)
        self.assertEqual(result, _libldap0.RES_SEARCH_RESULT)
        self.assertEqual(msgid, m)
        self.assertEqual(ctrls, [])
        self.assertEqual(len(pmsg), 1)
        self.assertEqual(pmsg[0][0], dn3)
        self.assertEqual(pmsg[0][1]['cn'], ['IAmRenamedAgain'])

    def test_options(self):
        oldval = _libldap0.get_option(_libldap0.OPT_PROTOCOL_VERSION)
        try:

            try:
                _libldap0.set_option(_libldap0.OPT_PROTOCOL_VERSION, "3")
            except TypeError:
                pass
            else:
                self.fail("expected string value to raise a TypeError")

            _libldap0.set_option(_libldap0.OPT_PROTOCOL_VERSION, _libldap0.VERSION2)
            v = _libldap0.get_option(_libldap0.OPT_PROTOCOL_VERSION)
            self.assertEqual(v, _libldap0.VERSION2)
            _libldap0.set_option(_libldap0.OPT_PROTOCOL_VERSION, _libldap0.VERSION3)
            v = _libldap0.get_option(_libldap0.OPT_PROTOCOL_VERSION)
            self.assertEqual(v, _libldap0.VERSION3)
        finally:
            _libldap0.set_option(_libldap0.OPT_PROTOCOL_VERSION, oldval)

        l = self._open_conn()

        # Try changing some basic options and checking that they took effect

        l.set_option(_libldap0.OPT_PROTOCOL_VERSION, _libldap0.VERSION2)
        v = l.get_option(_libldap0.OPT_PROTOCOL_VERSION)
        self.assertEqual(v, _libldap0.VERSION2)

        l.set_option(_libldap0.OPT_PROTOCOL_VERSION, _libldap0.VERSION3)
        v = l.get_option(_libldap0.OPT_PROTOCOL_VERSION)
        self.assertEqual(v, _libldap0.VERSION3)

        # Try setting options that will yield a known error.
        try:
            _libldap0.get_option(_libldap0.OPT_MATCHED_DN)
        except ValueError:
            pass
        else:
            self.fail("expected ValueError")

    def _require_attr(self, obj, attrname):
        """Returns true if the attribute exists on the object.
           This is to allow some tests to be optional, because
           _ldap is compiled with different properties depending
           on the underlying C library.
           This could me made to thrown an exception if you want the
           tests to be strict."""
        if hasattr(obj, attrname):
            return True
        #self.fail("required attribute '%s' missing" % attrname)
        return False

    def test_sasl(self):
        l = self._open_conn()
        if not self._require_attr(l, 'sasl_interactive_bind_s'): # HAVE_SASL
            return
        # TODO

    def test_tls(self):
        l = self._open_conn()
        if not self._require_attr(l, 'start_tls_s'):    # HAVE_TLS
            return
        # TODO

    def test_enotconn(self):
        l = _libldap0.initialize('ldap://127.0.0.1:42')
        try:
            m = l.simple_bind("", "")
            r = l.result(m, _libldap0.MSG_ALL, self.timeout)
        except _libldap0.SERVER_DOWN as ldap_err:
            err_no = ldap_err.args[0]['errno']
            if err_no != ENOTCONN:
                self.fail("expected err_no=%d, got %d" % (ENOTCONN, err_no))
        else:
            self.fail("expected SERVER_DOWN, got %r" % r)

    def test_invalid_filter(self):
        l = self._open_conn(bind=False)
        # search with invalid filter
        try:
            m = l.search_ext(
                "",
                _libldap0.SCOPE_BASE,
                '(|(objectClass=*)',
            )
            self.assertEqual(type(m), type(0))
            r = l.result(m, _libldap0.MSG_ALL, self.timeout)
        except _libldap0.FILTER_ERROR:
            pass
        else:
            self.fail("expected FILTER_ERROR, got %r" % r)

    def test_invalid_credentials(self):
        l = self._open_conn(bind=False)
        # search with invalid filter
        try:
            m = l.simple_bind(self.server.root_dn, self.server.root_pw+'wrong')
            r = l.result(m, _libldap0.MSG_ALL, self.timeout)
        except _libldap0.INVALID_CREDENTIALS:
            pass
        else:
            self.fail("expected INVALID_CREDENTIALS, got %r" % r)


if __name__ == '__main__':
    unittest.main()

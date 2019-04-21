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
            'adding %s and %s',
            cls.server.suffix,
            cls.server.root_dn,
        )
        cls.server.ldapadd(
            b'\n'.join([
                b'dn: '+cls.server.suffix,
                b'objectClass: dcObject',
                b'objectClass: organization',
                b'dc: '+suffix_dc,
                b'o: '+suffix_dc,
                b'',
                b'dn: '+cls.server.root_dn,
                b'objectClass: applicationProcess',
                b'cn: '+cls.server.root_cn,
                b'',
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
        m = l.simple_bind(b'', b'')
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
            b'',
            _libldap0.SCOPE_BASE,
            b'(objectClass=*)',
            [b'objectClass', b'namingContexts'],
        )
        self.assertEqual(type(m), type(0))
        result, pmsg, msgid, ctrls = l.result(m, _libldap0.MSG_ALL, self.timeout)
        self.assertEqual(result, _libldap0.RES_SEARCH_RESULT)
        self.assertEqual(pmsg[0][0], b'') # rootDSE has no dn
        self.assertEqual(msgid, m)
        self.assertEqual(ctrls, [])
        root_dse = pmsg[0][1]
        self.assertTrue(b'objectClass' in root_dse)
        self.assertTrue(b'OpenLDAProotDSE' in root_dse[b'objectClass'])
        self.assertTrue(b'namingContexts' in root_dse)
        self.assertEqual(root_dse[b'namingContexts'], [self.server.suffix])

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
            b'(objectClass=dcObject)'
        )
        self.assertEqual(type(m), type(0))
        result, pmsg, msgid, ctrls = l.result(m, _libldap0.MSG_ONE, self.timeout)
        # Expect to get just one object
        self.assertEqual(result, _libldap0.RES_SEARCH_ENTRY)
        self.assertEqual(len(pmsg), 1)
        self.assertEqual(len(pmsg[0]), 2)
        self.assertEqual(pmsg[0][0], self.server.suffix)
        self.assertEqual(pmsg[0][0], self.server.suffix)
        self.assertTrue(b'dcObject' in pmsg[0][1][b'objectClass'])
        self.assertTrue(b'organization' in pmsg[0][1][b'objectClass'])
        self.assertEqual(msgid, m)
        self.assertEqual(ctrls, [])

        result, pmsg, msgid, ctrls = l.result(m, _libldap0.MSG_ONE, self.timeout)
        self.assertEqual(result, _libldap0.RES_SEARCH_RESULT)
        self.assertEqual(pmsg, [])
        self.assertEqual(msgid, m)
        self.assertEqual(ctrls, [])

    def test_abandon(self):
        l = self._open_conn()
        m = l.search_ext(self.server.suffix, _libldap0.SCOPE_SUBTREE, b'(objectClass=*)')
        ret = l.abandon_ext(m)
        self.assertIsNone(ret)
        with self.assertRaises(_libldap0.TIMEOUT):
            r = l.result(m, _libldap0.MSG_ALL, 0.3)  # (timeout /could/ be longer)

    def test_search_ext_all(self):
        l = self._open_conn()
        # send search request
        m = l.search_ext(self.server.suffix, _libldap0.SCOPE_SUBTREE, b'(objectClass=*)')
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
            b'cn=Foo,' + self.server.suffix,
            [
                (b'objectClass', [b'organizationalRole']),
                (b'cn', [b'Foo']),
                (b'description', [b'testing']),
            ]
        )
        self.assertEqual(type(m), type(0))
        result, pmsg, msgid, ctrls = l.result(m, _libldap0.MSG_ALL, self.timeout)
        self.assertEqual(result, _libldap0.RES_ADD)
        self.assertEqual(pmsg, [])
        self.assertEqual(msgid, m)
        self.assertEqual(ctrls, [])
        # search for it back
        m = l.search_ext(self.server.suffix, _libldap0.SCOPE_SUBTREE, b'(cn=Foo)')
        result, pmsg, msgid, ctrls = l.result(m, _libldap0.MSG_ALL, self.timeout)
        # Expect to get the objects
        self.assertEqual(result, _libldap0.RES_SEARCH_RESULT)
        self.assertEqual(len(pmsg), 1)
        self.assertEqual(msgid, m)
        self.assertEqual(ctrls, [])
        self.assertEqual(
            pmsg[0],
            (
                b'cn=Foo,'+self.server.suffix,
                {
                    b'objectClass': [b'organizationalRole'],
                    b'cn': [b'Foo'],
                    b'description': [b'testing'],
                }
            )
        )

    def test_compare(self):
        """
        test compare operation
        """
        l = self._open_conn()
        # first, add an object with a field we can compare on
        dn = b'cn=CompareTest,' + self.server.suffix
        m = l.add_ext(
            dn,
            [
                (b'objectClass', [b'person']),
                (b'sn', [b'CompareTest']),
                (b'cn', [b'CompareTest']),
                (b'userPassword', [b'the_password']),
            ],
        )
        self.assertEqual(type(m), type(0))
        result, pmsg, msgid, ctrls = l.result(m, _libldap0.MSG_ALL, self.timeout)
        self.assertEqual(result, _libldap0.RES_ADD)
        # try a false compare
        m = l.compare_ext(dn, b'userPassword', b'bad_string')
        with self.assertRaises(_libldap0.COMPARE_FALSE):
            r = l.result(m, _libldap0.MSG_ALL, self.timeout)
        # try a true compare
        m = l.compare_ext(dn, b'userPassword', b'the_password')
        with self.assertRaises(_libldap0.COMPARE_TRUE):
            r = l.result(m, _libldap0.MSG_ALL, self.timeout)
        # try a compare on bad attribute
        m = l.compare_ext(dn, b'badAttribute', b'ignoreme')
        with self.assertRaises(_libldap0.error):
            r = l.result(m, _libldap0.MSG_ALL, self.timeout)

    def test_delete_no_such_object(self):
        """
        try deleting an object that doesn't exist
        """
        l = self._open_conn()
        m = l.delete_ext(b'cn=DoesNotExist,'+self.server.suffix)
        with self.assertRaises(_libldap0.NO_SUCH_OBJECT):
            r = l.result(m, _libldap0.MSG_ALL, self.timeout)

    def test_delete(self):
        l = self._open_conn()
        # first, add an object we will delete
        dn = b'cn=Deleteme,'+self.server.suffix
        m = l.add_ext(
            dn,
            [
                (b'objectClass', [b'organizationalRole']),
                (b'cn', [b'Deleteme']),
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
            b'cn=DoesNotExist,'+self.server.suffix,
            [
                (_libldap0.MOD_ADD, b'description', [b'blah']),
            ]
        )
        with self.assertRaises(_libldap0.NO_SUCH_OBJECT):
            r = l.result(m, _libldap0.MSG_ALL, self.timeout)

    def test_modify_no_such_object_empty_attrs(self):
        """
        try deleting an object that doesn't exist
        """
        l = self._open_conn()
        m = l.modify_ext(
            b'cn=DoesNotExist,'+self.server.suffix,
            [
                (_libldap0.MOD_ADD, b'description', [b'dummy']),
            ]
        )
        self.assertTrue(isinstance(m, int))
        with self.assertRaises(_libldap0.NO_SUCH_OBJECT):
            r = l.result(m, _libldap0.MSG_ALL, self.timeout)

    def test_modify(self):
        """
        test modify operation
        """
        l = self._open_conn()
        # first, add an object we will delete
        dn = b'cn=AddToMe,'+self.server.suffix
        m = l.add_ext(
            dn,
            [
                (b'objectClass', [b'person']),
                (b'cn', [b'AddToMe']),
                (b'sn', [b'Modify']),
                (b'description', [b'a description']),
            ]
        )
        self.assertEqual(type(m), type(0))
        result, pmsg, msgid, ctrls = l.result(m, _libldap0.MSG_ALL, self.timeout)
        self.assertEqual(result, _libldap0.RES_ADD)

        m = l.modify_ext(
            dn,
            [(_libldap0.MOD_ADD, b'description', [b'b desc', b'c desc'])],
        )
        result, pmsg, msgid, ctrls = l.result(m, _libldap0.MSG_ALL, self.timeout)
        self.assertEqual(result, _libldap0.RES_MODIFY)
        self.assertEqual(pmsg, [])
        self.assertEqual(msgid, m)
        self.assertEqual(ctrls, [])
        # search for it back
        m = l.search_ext(self.server.suffix, _libldap0.SCOPE_SUBTREE, b'(cn=AddToMe)')
        result, pmsg, msgid, ctrls = l.result(m, _libldap0.MSG_ALL, self.timeout)
        # Expect to get the objects
        self.assertEqual(result, _libldap0.RES_SEARCH_RESULT)
        self.assertEqual(len(pmsg), 1)
        self.assertEqual(msgid, m)
        self.assertEqual(ctrls, [])
        self.assertEqual(pmsg[0][0], dn)
        d = list(pmsg[0][1][b'description'])
        d.sort()
        self.assertEqual(d, [b'a description', 'b desc', 'c desc'])

    def test_rename(self):
        l = self._open_conn()
        dn = b'cn=RenameMe,'+self.server.suffix
        m = l.add_ext(
            dn,
            [
                (b'objectClass', [b'organizationalRole']),
                (b'cn', [b'RenameMe']),
            ]
        )
        self.assertEqual(type(m), type(0))
        result, pmsg, msgid, ctrls = l.result(m, _libldap0.MSG_ALL, self.timeout)
        self.assertEqual(result, _libldap0.RES_ADD)

        # do the rename with same parent
        m = l.rename(dn, b'cn=IAmRenamed')
        result, pmsg, msgid, ctrls = l.result(m, _libldap0.MSG_ALL, self.timeout)
        self.assertEqual(result, _libldap0.RES_MODRDN)
        self.assertEqual(msgid, m)
        self.assertEqual(pmsg, [])
        self.assertEqual(ctrls, [])

        # make sure the old one is gone
        m = l.search_ext(self.server.suffix, _libldap0.SCOPE_SUBTREE, b'(cn=RenameMe)')
        result, pmsg, msgid, ctrls = l.result(m, _libldap0.MSG_ALL, self.timeout)
        self.assertEqual(result, _libldap0.RES_SEARCH_RESULT)
        self.assertEqual(len(pmsg), 0) # expect no results
        self.assertEqual(msgid, m)
        self.assertEqual(ctrls, [])

        # check that the new one looks right
        dn2 = b'cn=IAmRenamed,'+self.server.suffix
        m = l.search_ext(self.server.suffix, _libldap0.SCOPE_SUBTREE, b'(cn=IAmRenamed)')
        result, pmsg, msgid, ctrls = l.result(m, _libldap0.MSG_ALL, self.timeout)
        self.assertEqual(result, _libldap0.RES_SEARCH_RESULT)
        self.assertEqual(msgid, m)
        self.assertEqual(ctrls, [])
        self.assertEqual(len(pmsg), 1)
        self.assertEqual(pmsg[0][0], dn2)
        self.assertEqual(pmsg[0][1][b'cn'], [b'IAmRenamed'])

        # create the container
        containerDn = b'ou=RenameContainer,'+self.server.suffix
        m = l.add_ext(
            containerDn,
            [
                (b'objectClass', [b'organizationalUnit']),
                (b'ou', [b'RenameContainer']),
            ]
        )
        result, pmsg, msgid, ctrls = l.result(m, _libldap0.MSG_ALL, self.timeout)
        self.assertEqual(result, _libldap0.RES_ADD)

        # now rename from dn2 to the conater
        dn3 = b'cn=IAmRenamedAgain,' + containerDn

        # Now try renaming dn2 across container (simultaneous name change)
        m = l.rename(dn2, b'cn=IAmRenamedAgain', containerDn)
        result, pmsg, msgid, ctrls = l.result(m, _libldap0.MSG_ALL, self.timeout)
        self.assertEqual(result, _libldap0.RES_MODRDN)
        self.assertEqual(msgid, m)
        self.assertEqual(pmsg, [])
        self.assertEqual(ctrls, [])

        # make sure dn2 is gone
        m = l.search_ext(self.server.suffix, _libldap0.SCOPE_SUBTREE, b'(cn=IAmRenamed)')
        result, pmsg, msgid, ctrls = l.result(m, _libldap0.MSG_ALL, self.timeout)
        self.assertEqual(result, _libldap0.RES_SEARCH_RESULT)
        self.assertEqual(len(pmsg), 0) # expect no results
        self.assertEqual(msgid, m)
        self.assertEqual(ctrls, [])

        m = l.search_ext(self.server.suffix, _libldap0.SCOPE_SUBTREE, b'(objectClass=*)')
        result, pmsg, msgid, ctrls = l.result(m, _libldap0.MSG_ALL, self.timeout)

        # make sure dn3 is there
        m = l.search_ext(self.server.suffix, _libldap0.SCOPE_SUBTREE, b'(cn=IAmRenamedAgain)')
        result, pmsg, msgid, ctrls = l.result(m, _libldap0.MSG_ALL, self.timeout)
        self.assertEqual(result, _libldap0.RES_SEARCH_RESULT)
        self.assertEqual(msgid, m)
        self.assertEqual(ctrls, [])
        self.assertEqual(len(pmsg), 1)
        self.assertEqual(pmsg[0][0], dn3)
        self.assertEqual(pmsg[0][1][b'cn'], [b'IAmRenamedAgain'])

    def test_options(self):
        oldval = _libldap0.get_option(_libldap0.OPT_PROTOCOL_VERSION)
        try:
            with self.assertRaises(TypeError):
                _libldap0.set_option(_libldap0.OPT_PROTOCOL_VERSION, b'3')
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

        # Try getting options that will yield a known error.
        with self.assertRaises(ValueError):
            _libldap0.get_option(_libldap0.OPT_MATCHED_DN)

    def test_enotconn(self):
        l = _libldap0.initialize(b'ldap://127.0.0.1:42')
        try:
            m = l.simple_bind(b'', b'')
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
        with self.assertRaises(_libldap0.FILTER_ERROR):
            m = l.search_ext(
                b'',
                _libldap0.SCOPE_BASE,
                b'(|(objectClass=*)',
            )
            self.assertEqual(isinstance(m), int)
            r = l.result(m, _libldap0.MSG_ALL, self.timeout)

    def test_invalid_credentials(self):
        l = self._open_conn(bind=False)
        # search with invalid filter
        with self.assertRaises(_libldap0.INVALID_CREDENTIALS):
            m = l.simple_bind(self.server.root_dn, self.server.root_pw+b'wrong')
            r = l.result(m, _libldap0.MSG_ALL, self.timeout)


if __name__ == '__main__':
    unittest.main()

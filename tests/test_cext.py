# -*- coding: utf-8 -*-
"""
Automatic tests for C wrapper module _libldap0
"""

import os
import logging
import unittest
from errno import ENOTCONN

# Switch off processing .ldaprc or ldap0.conf before importing _ldap
os.environ['LDAPNOINIT'] = '1'

import _libldap0

from ldap0.test import SlapdTestCase
from ldap0.sasl import SaslNoninteractiveAuth
from ldap0.functions import escape_format
from ldap0.filter import escape_str as escape_filter_str


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
            '\n'.join([
                'dn: '+cls.server.suffix,
                'objectClass: organization',
                'o:'+suffix_dc,
                '',
                'dn: '+cls.server.root_dn,
                'objectClass: applicationProcess',
                'cn: '+cls.server.root_cn,
                '',
            ]).encode('utf-8')
        )

    def setUp(self):
        try:
            self._ldap_conn
        except AttributeError:
            # open local LDAP connection
            self._ldap_conn = self._open_ldap_conn()
            msg_id = self._ldap_conn.search_ext(
                'cn=config'.encode('utf-8'),
                _libldap0.SCOPE_SUBTREE,
                escape_format(escape_filter_str, '(olcSuffix={0})', self.server.suffix).encode('utf-8'),
            )
            ldap_res = self._ldap_conn.result(msg_id)
            logging.debug('ldap_res = %r', ldap_res)

    def _open_ldap_conn(self, bind=True):
        """
        Starts a server, and returns a LDAPObject bound to it
        """
        ldap_conn = _libldap0.initialize(self.server.ldap_uri.encode('ascii'))
        ldap_conn.set_option(_libldap0.OPT_PROTOCOL_VERSION, _libldap0.VERSION3)
        if bind:
            # Perform a simple bind
            msg_id = ldap_conn.simple_bind(
                self.server.root_dn.encode('utf-8'),
                self.server.root_pw.encode('utf-8')
            )
            result, pmsg, msgid, ctrls = ldap_conn.result(msg_id, _libldap0.MSG_ONE, self.timeout)
            self.assertEqual(result, _libldap0.RES_BIND)
            self.assertEqual(type(msgid), type(0))
        return ldap_conn

    # Test for the existence of a whole bunch of constants
    # that the C module is supposed to export
    def test001_constants(self):
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

    def test002_simple_bind(self):
        ldap_conn = self._open_ldap_conn()

    def test003_simple_anonymous_bind(self):
        ldap_conn = self._open_ldap_conn(bind=False)
        msg_id = ldap_conn.simple_bind(b'', b'')
        self.assertIsInstance(msg_id, int)
        result, pmsg, msgid, ctrls = ldap_conn.result(msg_id, _libldap0.MSG_ALL, self.timeout)
        self.assertEqual(result, _libldap0.RES_BIND)
        self.assertEqual(msgid, msg_id)
        self.assertEqual(pmsg, [])
        self.assertEqual(ctrls, [])

    def test004_anon_rootdse_search(self):
        ldap_conn = self._open_ldap_conn(bind=False)
        # see if we can get the rootdse with anon search (without prior bind)
        msg_id = ldap_conn.search_ext(
            b'',
            _libldap0.SCOPE_BASE,
            b'(objectClass=*)',
            [b'objectClass', b'namingContexts'],
        )
        self.assertIsInstance(msg_id, int)
        result, pmsg, msgid, ctrls = ldap_conn.result(msg_id, _libldap0.MSG_ALL, self.timeout)
        self.assertEqual(result, _libldap0.RES_SEARCH_RESULT)
        self.assertEqual(pmsg[0][0], b'') # rootDSE has no dn
        self.assertEqual(msgid, msg_id)
        self.assertEqual(ctrls, [])
        root_dse = pmsg[0][1]
        self.assertTrue(b'objectClass' in root_dse)
        self.assertIn(b'OpenLDAProotDSE', root_dse[b'objectClass'])
        self.assertTrue(b'namingContexts' in root_dse)
        self.assertEqual(
            root_dse[b'namingContexts'],
            [self.server.suffix.encode('utf-8')]
        )

    def test005_unbind(self):
        ldap_conn = self._open_ldap_conn()
        msg_id = ldap_conn.unbind_ext()
        self.assertIsNone(msg_id)
        # Second attempt to unbind should yield an exception
        with self.assertRaises(_libldap0.LDAPError):
            ldap_conn.unbind_ext()

    def test006_search_ext_individual(self):
        ldap_conn = self._open_ldap_conn()
        # send search request
        msg_id = ldap_conn.search_ext(
            self.server.suffix.encode('utf-8'),
            _libldap0.SCOPE_SUBTREE,
            b'(objectClass=organization)'
        )
        self.assertIsInstance(msg_id, int)
        ldap_res = ldap_conn.result(
            msg_id,
            _libldap0.MSG_ONE,
            self.timeout
        )
        result, pmsg, msgid, ctrls = ldap_res
        # Expect to get just one object
        self.assertEqual(result, _libldap0.RES_SEARCH_ENTRY)
        self.assertEqual(len(pmsg), 1)
        self.assertEqual(len(pmsg[0]), 2)
        self.assertEqual(pmsg[0][0], self.server.suffix.encode('utf-8'))
        self.assertEqual(pmsg[0][0], self.server.suffix.encode('utf-8'))
        self.assertIn(b'organization', pmsg[0][1][b'objectClass'])
        self.assertEqual(msgid, msg_id)
        self.assertEqual(ctrls, [])

        result, pmsg, msgid, ctrls = ldap_conn.result(msg_id, _libldap0.MSG_ONE, self.timeout)
        self.assertEqual(result, _libldap0.RES_SEARCH_RESULT)
        self.assertEqual(pmsg, [])
        self.assertEqual(msgid, msg_id)
        self.assertEqual(ctrls, [])

    def test007_abandon(self):
        ldap_conn = self._open_ldap_conn()
        msg_id = ldap_conn.search_ext(self.server.suffix.encode('utf-8'), _libldap0.SCOPE_SUBTREE, b'(objectClass=*)')
        ret = ldap_conn.abandon_ext(msg_id)
        self.assertIsNone(ret)
        with self.assertRaises(_libldap0.TIMEOUT):
            r = ldap_conn.result(msg_id, _libldap0.MSG_ALL, 0.3)  # (timeout /could/ be longer)

    def test008_search_ext_all(self):
        ldap_conn = self._open_ldap_conn()
        # send search request
        msg_id = ldap_conn.search_ext(
            self.server.suffix.encode('utf-8'),
            _libldap0.SCOPE_SUBTREE,
            b'(objectClass=*)'
        )
        self.assertIsInstance(msg_id, int)
        result, pmsg, msgid, ctrls = ldap_conn.result(msg_id, _libldap0.MSG_ALL, self.timeout)
        # Expect to get some objects
        self.assertEqual(result, _libldap0.RES_SEARCH_RESULT)
        self.assertTrue(len(pmsg) >= 2)
        self.assertEqual(msgid, msg_id)
        self.assertEqual(ctrls, [])

    def test009_add(self):
        """
        test add operation
        """
        ldap_conn = self._open_ldap_conn()
        msg_id = ldap_conn.add_ext(
            ('cn=Foo,'+self.server.suffix).encode('utf-8'),
            [
                (b'objectClass', [b'organizationalRole']),
                (b'cn', [b'Foo']),
                (b'description', [b'testing']),
            ]
        )
        self.assertIsInstance(msg_id, int)
        result, pmsg, msgid, ctrls = ldap_conn.result(msg_id, _libldap0.MSG_ALL, self.timeout)
        self.assertEqual(result, _libldap0.RES_ADD)
        self.assertEqual(pmsg, [])
        self.assertEqual(msgid, msg_id)
        self.assertEqual(ctrls, [])
        # search for it back
        msg_id = ldap_conn.search_ext(self.server.suffix.encode('utf-8'), _libldap0.SCOPE_SUBTREE, b'(cn=Foo)')
        result, pmsg, msgid, ctrls = ldap_conn.result(msg_id, _libldap0.MSG_ALL, self.timeout)
        # Expect to get the objects
        self.assertEqual(result, _libldap0.RES_SEARCH_RESULT)
        self.assertEqual(len(pmsg), 1)
        self.assertEqual(msgid, msg_id)
        self.assertEqual(ctrls, [])
        self.assertEqual(
            pmsg[0],
            (
                ('cn=Foo,'+self.server.suffix).encode('utf-8'),
                {
                    b'objectClass': [b'organizationalRole'],
                    b'cn': [b'Foo'],
                    b'description': [b'testing'],
                }
            )
        )

    def test010_compare(self):
        """
        test compare operation
        """
        ldap_conn = self._open_ldap_conn()
        # first, add an object with a field we can compare on
        dn = 'cn=CompareTest,' + self.server.suffix
        msg_id = ldap_conn.add_ext(
            dn.encode('utf-8'),
            [
                (b'objectClass', [b'person']),
                (b'sn', [b'CompareTest']),
                (b'cn', [b'CompareTest']),
                (b'userPassword', [b'the_password']),
            ],
        )
        self.assertIsInstance(msg_id, int)
        result, pmsg, msgid, ctrls = ldap_conn.result(msg_id, _libldap0.MSG_ALL, self.timeout)
        self.assertEqual(result, _libldap0.RES_ADD)
        # try a false compare
        msg_id = ldap_conn.compare_ext(dn.encode('utf-8'), b'userPassword', b'bad_string')
        with self.assertRaises(_libldap0.COMPARE_FALSE):
            r = ldap_conn.result(msg_id, _libldap0.MSG_ALL, self.timeout)
        # try a true compare
        msg_id = ldap_conn.compare_ext(dn.encode('utf-8'), b'userPassword', b'the_password')
        with self.assertRaises(_libldap0.COMPARE_TRUE):
            r = ldap_conn.result(msg_id, _libldap0.MSG_ALL, self.timeout)
        # try a compare on bad attribute
        msg_id = ldap_conn.compare_ext(dn.encode('utf-8'), b'badAttribute', b'ignoreme')
        with self.assertRaises(_libldap0.error):
            r = ldap_conn.result(msg_id, _libldap0.MSG_ALL, self.timeout)

    def test011_delete_no_such_object(self):
        """
        try deleting an object that doesn't exist
        """
        ldap_conn = self._open_ldap_conn()
        msg_id = ldap_conn.delete_ext(('cn=DoesNotExist,'+self.server.suffix).encode('utf-8'))
        with self.assertRaises(_libldap0.NO_SUCH_OBJECT):
            r = ldap_conn.result(msg_id, _libldap0.MSG_ALL, self.timeout)

    def test012_delete(self):
        ldap_conn = self._open_ldap_conn()
        # first, add an object we will delete
        dn = 'cn=Deleteme,'+self.server.suffix
        msg_id = ldap_conn.add_ext(
            dn.encode('utf-8'),
            [
                (b'objectClass', [b'organizationalRole']),
                (b'cn', [b'Deleteme']),
            ]
        )
        self.assertIsInstance(msg_id, int)
        result, pmsg, msgid, ctrls = ldap_conn.result(msg_id, _libldap0.MSG_ALL, self.timeout)
        self.assertEqual(result, _libldap0.RES_ADD)
        msg_id = ldap_conn.delete_ext(dn.encode('utf-8'))
        result, pmsg, msgid, ctrls = ldap_conn.result(msg_id, _libldap0.MSG_ALL, self.timeout)
        self.assertEqual(result, _libldap0.RES_DELETE)
        self.assertEqual(msgid, msg_id)
        self.assertEqual(pmsg, [])
        self.assertEqual(ctrls, [])

    def test013_modify_no_such_object(self):
        ldap_conn = self._open_ldap_conn()
        # try to modify an object that doesn't exist
        msg_id = ldap_conn.modify_ext(
            ('cn=DoesNotExist,'+self.server.suffix).encode('utf-8'),
            [
                (_libldap0.MOD_ADD, b'description', [b'blah']),
            ]
        )
        with self.assertRaises(_libldap0.NO_SUCH_OBJECT):
            r = ldap_conn.result(msg_id, _libldap0.MSG_ALL, self.timeout)

    def test014_modify_no_such_object_empty_attrs(self):
        """
        try deleting an object that doesn't exist
        """
        ldap_conn = self._open_ldap_conn()
        msg_id = ldap_conn.modify_ext(
            ('cn=DoesNotExist,'+self.server.suffix).encode('utf-8'),
            [
                (_libldap0.MOD_ADD, b'description', [b'dummy']),
            ]
        )
        self.assertIsInstance(msg_id, int)
        with self.assertRaises(_libldap0.NO_SUCH_OBJECT):
            r = ldap_conn.result(msg_id, _libldap0.MSG_ALL, self.timeout)

    def test015_modify(self):
        """
        test modify operation
        """
        ldap_conn = self._open_ldap_conn()
        # first, add an object we will delete
        dn = 'cn=AddToMe,'+self.server.suffix
        msg_id = ldap_conn.add_ext(
            dn.encode('utf-8'),
            [
                (b'objectClass', [b'person']),
                (b'cn', [b'AddToMe']),
                (b'sn', [b'Modify']),
                (b'description', [b'a description']),
            ]
        )
        self.assertIsInstance(msg_id, int)
        result, pmsg, msgid, ctrls = ldap_conn.result(msg_id, _libldap0.MSG_ALL, self.timeout)
        self.assertEqual(result, _libldap0.RES_ADD)
        msg_id = ldap_conn.modify_ext(
            dn.encode('utf-8'),
            [(_libldap0.MOD_ADD, b'description', [b'b desc', b'c desc'])],
        )
        result, pmsg, msgid, ctrls = ldap_conn.result(msg_id, _libldap0.MSG_ALL, self.timeout)
        self.assertEqual(result, _libldap0.RES_MODIFY)
        self.assertEqual(pmsg, [])
        self.assertEqual(msgid, msg_id)
        self.assertEqual(ctrls, [])
        # search for it back
        msg_id = ldap_conn.search_ext(
            self.server.suffix.encode('utf-8'),
            _libldap0.SCOPE_SUBTREE,
            b'(cn=AddToMe)'
        )
        result, pmsg, msgid, ctrls = ldap_conn.result(msg_id, _libldap0.MSG_ALL, self.timeout)
        # Expect to get the objects
        self.assertEqual(result, _libldap0.RES_SEARCH_RESULT)
        self.assertEqual(len(pmsg), 1)
        self.assertEqual(msgid, msg_id)
        self.assertEqual(ctrls, [])
        self.assertEqual(pmsg[0][0], dn.encode('utf-8'))
        d = list(pmsg[0][1][b'description'])
        d.sort()
        self.assertEqual(d, [b'a description', b'b desc', b'c desc'])

    def test016_rename(self):
        ldap_conn = self._open_ldap_conn()
        dn = 'cn=RenameMe,'+self.server.suffix
        msg_id = ldap_conn.add_ext(
            dn.encode('utf-8'),
            [
                (b'objectClass', [b'organizationalRole']),
                (b'cn', [b'RenameMe']),
            ]
        )
        self.assertIsInstance(msg_id, int)
        result, pmsg, msgid, ctrls = ldap_conn.result(msg_id, _libldap0.MSG_ALL, self.timeout)
        self.assertEqual(result, _libldap0.RES_ADD)

        # do the rename with same parent
        msg_id = ldap_conn.rename(dn.encode('utf-8'), b'cn=IAmRenamed')
        result, pmsg, msgid, ctrls = ldap_conn.result(msg_id, _libldap0.MSG_ALL, self.timeout)
        self.assertEqual(result, _libldap0.RES_MODRDN)
        self.assertEqual(msgid, msg_id)
        self.assertEqual(pmsg, [])
        self.assertEqual(ctrls, [])

        # make sure the old one is gone
        msg_id = ldap_conn.search_ext(
            self.server.suffix.encode('utf-8'),
            _libldap0.SCOPE_SUBTREE,
            b'(cn=RenameMe)'
        )
        result, pmsg, msgid, ctrls = ldap_conn.result(msg_id, _libldap0.MSG_ALL, self.timeout)
        self.assertEqual(result, _libldap0.RES_SEARCH_RESULT)
        self.assertEqual(len(pmsg), 0) # expect no results
        self.assertEqual(msgid, msg_id)
        self.assertEqual(ctrls, [])

        # check that the new one looks right
        dn2 = 'cn=IAmRenamed,'+self.server.suffix
        msg_id = ldap_conn.search_ext(
            self.server.suffix.encode('utf-8'),
            _libldap0.SCOPE_SUBTREE,
            b'(cn=IAmRenamed)'
        )
        result, pmsg, msgid, ctrls = ldap_conn.result(msg_id, _libldap0.MSG_ALL, self.timeout)
        self.assertEqual(result, _libldap0.RES_SEARCH_RESULT)
        self.assertEqual(msgid, msg_id)
        self.assertEqual(ctrls, [])
        self.assertEqual(len(pmsg), 1)
        self.assertEqual(pmsg[0][0].decode('utf-8'), dn2)
        self.assertEqual(pmsg[0][1][b'cn'], [b'IAmRenamed'])

        # create the container
        containerDn = 'ou=RenameContainer,'+self.server.suffix
        msg_id = ldap_conn.add_ext(
            containerDn.encode('utf-8'),
            [
                (b'objectClass', [b'organizationalUnit']),
                (b'ou', [b'RenameContainer']),
            ]
        )
        result, pmsg, msgid, ctrls = ldap_conn.result(msg_id, _libldap0.MSG_ALL, self.timeout)
        self.assertEqual(result, _libldap0.RES_ADD)

        # now rename from dn2 to the conater
        dn3 = 'cn=IAmRenamedAgain,' + containerDn

        # Now try renaming dn2 across container (simultaneous name change)
        msg_id = ldap_conn.rename(
            dn2.encode('utf-8'),
            b'cn=IAmRenamedAgain',
            containerDn.encode('utf-8'),
            True
        )
        result, pmsg, msgid, ctrls = ldap_conn.result(msg_id, _libldap0.MSG_ALL, self.timeout)
        self.assertEqual(result, _libldap0.RES_MODRDN)
        self.assertEqual(msgid, msg_id)
        self.assertEqual(pmsg, [])
        self.assertEqual(ctrls, [])

        # make sure dn2 is gone
        msg_id = ldap_conn.search_ext(
            self.server.suffix.encode('utf-8'),
            _libldap0.SCOPE_SUBTREE,
            b'(cn=IAmRenamed)'
        )
        ldap_res = ldap_conn.result(msg_id, _libldap0.MSG_ALL, self.timeout)
        logging.debug('ldap_res = %r', ldap_res)
        result, pmsg, msgid, ctrls = ldap_res
        self.assertEqual(result, _libldap0.RES_SEARCH_RESULT)
        self.assertEqual(len(pmsg), 0) # expect no results
        self.assertEqual(msgid, msg_id)
        self.assertEqual(ctrls, [])

        msg_id = ldap_conn.search_ext(
            self.server.suffix.encode('utf-8'),
            _libldap0.SCOPE_SUBTREE,
            b'(objectClass=*)'
        )
        ldap_res = ldap_conn.result(msg_id, _libldap0.MSG_ALL, self.timeout)
        logging.debug('ldap_res = %r', ldap_res)
        result, pmsg, msgid, ctrls = ldap_res

        # make sure dn3 is there
        msg_id = ldap_conn.search_ext(
            self.server.suffix.encode('utf-8'),
            _libldap0.SCOPE_SUBTREE,
            b'(cn=IAmRenamedAgain)'
        )
        ldap_res = ldap_conn.result(msg_id, _libldap0.MSG_ALL, self.timeout)
        logging.debug('ldap_res = %r', ldap_res)
        result, pmsg, msgid, ctrls = ldap_res
        self.assertEqual(result, _libldap0.RES_SEARCH_RESULT)
        self.assertEqual(msgid, msg_id)
        self.assertEqual(ctrls, [])
        self.assertEqual(len(pmsg), 1)
        self.assertEqual(pmsg[0][0].decode('utf-8'), dn3)
        self.assertEqual(pmsg[0][1][b'cn'], [b'IAmRenamedAgain'])

    def test017_options(self):
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

        ldap_conn = self._open_ldap_conn()

        # Try changing some basic options and checking that they took effect

        ldap_conn.set_option(_libldap0.OPT_PROTOCOL_VERSION, _libldap0.VERSION2)
        v = ldap_conn.get_option(_libldap0.OPT_PROTOCOL_VERSION)
        self.assertEqual(v, _libldap0.VERSION2)

        ldap_conn.set_option(_libldap0.OPT_PROTOCOL_VERSION, _libldap0.VERSION3)
        v = ldap_conn.get_option(_libldap0.OPT_PROTOCOL_VERSION)
        self.assertEqual(v, _libldap0.VERSION3)

        # Try getting options that will yield a known error.
        with self.assertRaises(ValueError):
            _libldap0.get_option(_libldap0.OPT_MATCHED_DN)

    def test018_enotconn(self):
        ldap_conn = _libldap0.initialize(b'ldap://127.0.0.1:42')
        try:
            msg_id = ldap_conn.simple_bind(b'', b'')
            r = ldap_conn.result(msg_id, _libldap0.MSG_ALL, self.timeout)
        except _libldap0.SERVER_DOWN as ldap_err:
            err_no = ldap_err.args[0]['errno']
            if err_no != ENOTCONN:
                self.fail("expected err_no=%d, got %d" % (ENOTCONN, err_no))
        else:
            self.fail("expected SERVER_DOWN, got %r" % r)

    def test019_invalid_filter(self):
        ldap_conn = self._open_ldap_conn(bind=False)
        # search with invalid filter
        with self.assertRaises(_libldap0.FILTER_ERROR):
            msg_id = ldap_conn.search_ext(
                b'',
                _libldap0.SCOPE_BASE,
                b'(|(objectClass=*)',
            )
            self.assertIsInstance(msg_id, int)
            r = ldap_conn.result(msg_id, _libldap0.MSG_ALL, self.timeout)

    def test020_invalid_credentials(self):
        ldap_conn = self._open_ldap_conn(bind=False)
        # search with invalid filter
        with self.assertRaises(_libldap0.INVALID_CREDENTIALS):
            msg_id = ldap_conn.simple_bind(
                self.server.root_dn.encode('utf-8'),
                b'wrong_password',
            )
            r = ldap_conn.result(msg_id, _libldap0.MSG_ALL, self.timeout)

    @unittest.skip('Skipped because of unclarified timeouts')
    def test021_sasl_bind_s(self):
        ldap_conn = _libldap0.initialize(self.server.ldapi_uri.encode('ascii'))
        ldap_conn.set_option(_libldap0.OPT_PROTOCOL_VERSION, _libldap0.VERSION3)
        msg_id = ldap_conn.sasl_bind_s(b'EXTERNAL', b'', None)
        self.assertIsInstance(msg_id, int)
        result, pmsg, msgid, ctrls = ldap_conn.result(msg_id, _libldap0.MSG_ALL, self.timeout)

    @unittest.skip('Skipped because of unclarified timeouts')
    def test022_sasl_interactive_bind_s(self):
        ldap_conn = _libldap0.initialize(self.server.ldapi_uri.encode('ascii'))
        ldap_conn.set_option(_libldap0.OPT_PROTOCOL_VERSION, _libldap0.VERSION3)
        msg_id = ldap_conn.sasl_interactive_bind_s(b'EXTERNAL', SaslNoninteractiveAuth(), None, 0)
        self.assertIsInstance(msg_id, int)
        result, pmsg, msgid, ctrls = ldap_conn.result(msg_id, _libldap0.MSG_ALL, self.timeout)


if __name__ == '__main__':
    unittest.main()

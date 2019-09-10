# -*- coding: utf-8 -*-
"""
Automatic tests for module ldap0.syncrepl
"""

import os
import unittest
import shelve

from ldap0.test import SlapdObject, SlapdTestCase
from ldap0.controls.simple import SubentriesControl

# Switch off processing .ldaprc or ldap.conf before importing _ldap
os.environ['LDAPNOINIT'] = '1'

import ldap0
from ldap0.ldapobject import LDAPObject
from ldap0.syncrepl import SyncreplConsumer

# a template string for generating simple slapd.conf file
SLAPD_CONF_PROVIDER_TEMPLATE = r"""
serverID %(serverid)s
moduleload back_%(database)s
moduleload syncprov
include "%(schema_prefix)s/core.schema"
loglevel %(loglevel)s
allow bind_v2

authz-regexp
  "gidnumber=%(root_gid)s\\+uidnumber=%(root_uid)s,cn=peercred,cn=external,cn=auth"
  "%(rootdn)s"

database %(database)s
directory "%(directory)s"
suffix "%(suffix)s"
rootdn "%(rootdn)s"
rootpw "%(rootpw)s"
overlay syncprov
syncprov-checkpoint 100 10
syncprov-sessionlog 100
index objectclass,entryCSN,entryUUID eq
sync_use_subentry
"""

# Define initial data load, both as an LDIF and as a dictionary.
LDIF_TEMPLATE = """dn: %(suffix)s
objectClass: organization
o: %(o)s

dn: %(rootdn)s
objectClass: applicationProcess
objectClass: simpleSecurityObject
cn: %(rootcn)s
userPassword: %(rootpw)s

dn: cn=Foo1,%(suffix)s
objectClass: organizationalRole
cn: Foo1

dn: cn=Foo2,%(suffix)s
objectClass: organizationalRole
cn: Foo2

dn: cn=Foo3,%(suffix)s
objectClass: organizationalRole
cn: Foo3

dn: ou=Container,%(suffix)s
objectClass: organizationalUnit
ou: Container

dn: cn=Foo4,ou=Container,%(suffix)s
objectClass: organizationalRole
cn: Foo4

"""

# NOTE: For the dict, it needs to be kept up-to-date as we make changes!
LDAP_ENTRIES = {
    'ou=Container,o=öäü,dc=example,dc=org': {
        b'objectClass': [b'organizationalUnit'],
        b'ou': ['Container']
    },
    'cn=Foo2,o=öäü,dc=example,dc=org': {
        b'objectClass': [b'organizationalRole'],
        b'cn': ['Foo2']
    },
    'cn=Foo4,ou=Container,o=öäü,dc=example,dc=org': {
        b'objectClass': [b'organizationalRole'],
        b'cn': ['Foo4']
    },
    'cn=Mänager,o=öäü,dc=example,dc=org': {
        b'objectClass': [b'applicationProcess', b'simpleSecurityObject'],
        b'userPassword': ['password'],
        b'cn': ['Manager']
    },
    'cn=Foo3,o=öäü,dc=example,dc=org': {
        b'objectClass': [b'organizationalRole'],
        b'cn': ['Foo3']
    },
    'cn=Foo1,o=öäü,dc=example,dc=org': {
        b'objectClass': [b'organizationalRole'],
        b'cn': ['Foo1']
    },
    'o=öäü,dc=example,dc=org': {
        b'objectClass': [b'dcObject', b'organization'],
        b'o': [b'xc3xb6xc3xa4xc3xbc']
    }
}


class SyncreplProvider(SlapdObject):
    slapd_conf_template = SLAPD_CONF_PROVIDER_TEMPLATE


class SyncreplClient(LDAPObject, SyncreplConsumer):
    """
    This is a very simple class to start up the syncrepl search
    and handle callbacks that come in.

    Needs to be separate, because once an LDAP client starts a syncrepl
    search, it can't be used for anything else.
    """
    server_class = SyncreplProvider

    def __init__(self, uri, dn, password, storage=None):
        """
        Set up our object by creating a search client, connecting, and binding.
        """
        if storage is not None:
            self.data = shelve.open(storage)
            self.uuid_dn = shelve.open(storage + 'uuid_dn')
            self.dn_attrs = shelve.open(storage + 'dn_attrs')
            self.using_shelve = True
        else:
            self.data = {}
            self.uuid_dn = {}
            self.dn_attrs = {}
            self.using_shelve = False
        self.data['cookie'] = None
        self.present = []
        self.refresh_done = False
        LDAPObject.__init__(self, uri, trace_level=int(os.environ.get('LDAP0_TRACE_LEVEL', '0')))
        self.simple_bind_s(dn, password.encode('utf-8'))

    def unbind_s(self):
        """
        In addition to unbinding from LDAP, we need to close the shelf.
        """
        if self.using_shelve is True:
            self.data.close()
            self.uuid_dn.close()
            self.dn_attrs.close()
        LDAPObject.unbind_s(self)

    def start_search(self, search_base, search_mode):
        """
        Start a syncrepl search operation, given a base DN and search mode.
        """
        return self.syncrepl_search(
            search_base,
            ldap0.SCOPE_SUBTREE,
            mode=search_mode,
            filterstr='(objectClass=*)'
        )

    def cancel_search(self, search_id):
        """
        A simple wrapper to call parent class with syncrepl search ID.
        """
        return LDAPObject.cancel_s(self, search_id)

    def poll(self, search_id, timeout=-1, all_results=ldap0.MSG_ONE):
        """
        Take the params, add the syncrepl search ID, and call the proper poll.
        """
        return self.syncrepl_poll(
            search_id,
            timeout=timeout,
            all_results=all_results
        )

    def syncrepl_get_cookie(self):
        """
        Pull cookie from storage, if one exists.
        """
        return self.data['cookie']

    def syncrepl_set_cookie(self, cookie):
        """
        Update stored cookie.
        """
        self.data['cookie'] = cookie

    def syncrepl_refreshdone(self):
        """
        Just update a variable.
        """
        self.refresh_done = True

    def syncrepl_delete(self, uuids):
        """
        Delete the given items from both maps.
        """
        for uuid in uuids:
            del self.dn_attrs[self.uuid_dn[uuid]]
            del self.uuid_dn[uuid]

    def syncrepl_entry(self, dn, attrs, uuid):
        """
        Handles adds and changes (including DN changes).
        """
        if uuid in self.uuid_dn:
            # Catch changing DNs.
            if dn != self.uuid_dn[uuid]:
                # Delete data associated with old DN.
                del self.dn_attrs[self.uuid_dn[uuid]]
        # Update both maps
        self.uuid_dn[uuid] = dn
        self.dn_attrs[dn] = attrs

    def syncrepl_present(self, uuids, refreshDeletes=False):
        """
        The 'present' message from the LDAP server is the most complicated
        part of the refresh phase.  Suggest looking here for more info:
        http://syncrepl-client.readthedocs.io/en/latest/client.html
        """
        if (uuids is not None) and (refreshDeletes is False):
            self.present.extend(uuids)
        elif (uuids is None) and (refreshDeletes is False):
            deleted_uuids = list()
            for uuid in self.uuid_dn.keys():
                if uuid not in self.present:
                    deleted_uuids.append(uuid)
            if len(deleted_uuids) > 0:
                self.syncrepl_delete(deleted_uuids)
        elif (uuids is not None) and (refreshDeletes is True):
            self.syncrepl_delete(uuids)
        elif (uuids is None) and (refreshDeletes is True):
            pass


class Test00_Syncrepl(SlapdTestCase):
    """
    This is a test of all the basic Syncrepl operations.  It covers starting a
    search (both types of search), doing the refresh part of the search,
    and checking that we got everything that we expected.  We also test that
    timeouts and cancellation are working properly.
    """
    server_class = SyncreplProvider
    maxDiff = None

    @classmethod
    def setUpClass(cls):
        super(Test00_Syncrepl, cls).setUpClass()
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

    def _syncrepl_client(self):
        return SyncreplClient(self.server.ldap_uri, self.server.root_dn, self.server.root_pw)

    def test000_syncrepl_subentry(self):
        self.assertEqual(
            self._ldap_conn.search_s(
                self.server.suffix,
                ldap0.SCOPE_SUBTREE,
                '(objectClass=subentry)',
            ),
            []
        )
        self.assertEqual(
            [
                (res.dn_s, res.entry_b)
                for res in self._ldap_conn.search_s(
                    self.server.suffix,
                    ldap0.SCOPE_SUBTREE,
                    '(objectClass=subentry)',
                    req_ctrls=[SubentriesControl(True, True)],
                )
            ],
            [(
                'cn=ldapsync,o=öäü,dc=example,dc=org',
                {
                    b'objectClass': [b'top', b'subentry', b'syncProviderSubentry'],
                    b'cn': [b'ldapsync'],
                }
            )]
        )

    def test_refreshOnly_search(self):
        """
        Test to see if we can initialize a syncrepl search.
        """
        with self._syncrepl_client() as ldap_conn:
            search_id = ldap_conn.start_search(
                self.server.suffix,
                'refreshOnly'
            )


    @unittest.skip('hangs')
    def test_refreshAndPersist_search(self):
        with self._syncrepl_client() as ldap_conn:
            search_id = ldap_conn.start_search(
                self.server.suffix,
                'refreshAndPersist'
            )

    @unittest.skip('hangs')
    def test_refreshOnly_poll_full(self):
        """
        Test doing a full refresh cycle, and check what we got.
        """
        with self._syncrepl_client() as ldap_conn:
            search_id = search_id = ldap_conn.start_search(
                self.server.suffix,
                'refreshOnly'
            )
            poll_result = ldap_conn.poll(search_id, all_results=ldap0.MSG_ALL)
            self.assertFalse(poll_result)
            self.assertEqual(
                sorted(ldap_conn.dn_attrs),
                sorted(LDAP_ENTRIES)
            )

    @unittest.skip('hangs')
    def test_refreshAndPersist_poll_only(self):
        """
        Test the refresh part of refresh-and-persist, and check what we got.
        """
        with self._syncrepl_client() as ldap_conn:
            search_id = ldap_conn.start_search(self.server.suffix, 'refreshAndPersist')
            # Make sure to stop the test before going into persist mode.
            while not ldap_conn.refresh_done:
                poll_result = ldap_conn.poll(search_id, all_results=ldap0.MSG_ONE)
                self.assertTrue(poll_result)
            self.assertEqual(
                sorted(ldap_conn.dn_attrs),
                sorted(LDAP_ENTRIES)
            )

    @unittest.skip('hangs')
    def test_refreshAndPersist_timeout(self):
        """
        Make sure refreshAndPersist can handle a search with timeouts.
        """
        with self._syncrepl_client() as ldap_conn:
            search_id = ldap_conn.start_search(self.server.suffix, 'refreshAndPersist')
            # Run a quick refresh, that shouldn't have any changes.
            while not ldap_conn.refresh_done:
                poll_result = ldap_conn.poll(search_id, all_results=ldap0.MSG_ONE)
                self.assertTrue(poll_result)
            # Again, server data should not have changed.
            self.assertEqual(
                sorted(ldap_conn.dn_attrs),
                sorted(LDAP_ENTRIES)
            )
            # Run a search with timeout.
            # Nothing is changing the server, so it shoud timeout.
            with self.assertRaises(ldap0.TIMEOUT):
                ldap_conn.poll(search_id, timeout=1, all_results=ldap0.MSG_ONE)

    @unittest.skip('hangs')
    def test_refreshAndPersist_cancelled(self):
        """
        Make sure refreshAndPersist can handle cancelling a syncrepl search.
        """
        with self._syncrepl_client() as ldap_conn:
            search_id = ldap_conn.start_search(
                self.server.suffix,
                'refreshAndPersist'
            )
            # Run a quick refresh, that shouldn't have any changes.
            while not ldap_conn.refresh_done:
                poll_result = ldap_conn.poll(search_id, all_results=ldap0.MSG_ONE)
                self.assertTrue(poll_result)
            # Again, server data should not have changed.
            self.assertEqual(
                sorted(ldap_conn.dn_attrs),
                sorted(LDAP_ENTRIES)
            )
            # Request cancellation.
            ldap_conn.cancel_search(search_id)
            # Run another poll, without timeout, but which should cancel out.
            with self.assertRaises(ldap0.CANCELLED):
                ldap_conn.poll(search_id, all_results=ldap0.MSG_ALL)
            # Server data should still be intact.
            self.assertEqual(
                sorted(ldap_conn.dn_attrs),
                sorted(LDAP_ENTRIES)
            )

    @unittest.skip('not yet implemented')
    def test_data_store1(self):
        """
        Make a new client, with a data store, and close.  Then, load a new
        client with the same datastore, and see if the data store loads OK.
        """

    @unittest.skip('not yet implemented')
    def test_data_store2(self):
        """
        Make a new client, with a data store, and close.  Then, load a new
        client with the same datastore.  Delete an entry, and the cookie.
        Start the sync, and everything should sync up OK.
        """

    @unittest.skip('not yet implemented')
    def test_data_store3(self):
        """
        Load the refreshOnly client, using existing data.  Make a change
        on the server, and the client should pick it up in the refresh phase.
        """

    @unittest.skip('not yet implemented')
    def test_data_store4(self):
        """
        Load the refreshAndPersist client, using existing data.  Make a change
        on the server, and the client should pick it up in the refresh phase.
        """

    @unittest.skip('not yet implemented')
    def test_data_store5(self):
        """
        Load the refreshAndPersist client, using existing data.  Let the
        refresh phase complete.  Make a change on the server, and the client
        should pick it up during the persist phase.
        """


if __name__ == '__main__':
    unittest.main()

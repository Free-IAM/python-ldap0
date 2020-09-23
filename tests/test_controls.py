# -*- coding: utf-8 -*-
"""
Simple tests for module ldap0.controls
"""

# from Python's standard lib
import unittest

from pyasn1.error import PyAsn1Error

import _libldap0
import ldap0.res
import ldap0.controls
from ldap0.controls import encode_request_ctrls, ResponseControl, decode_response_ctrls, ControlRegistry
from ldap0.controls.sessiontrack import *
from ldap0.controls.psearch import *
from ldap0.controls.ppolicy import *
from ldap0.controls.pwdpolicy import *
from ldap0.controls.readentry import *
from ldap0.controls.syncrepl import *
from ldap0.controls.vlv import *
from ldap0.controls.libldap import *
from ldap0.controls.deref import *


# re-raise pyasn1 decoding exceptions
ldap0.controls.STRICT_DECODE = True


class TestRequestControls(unittest.TestCase):
    """
    test classes for encoding request controls
    """

    def test_sessiontrack(self):
        stc = SessionTrackingControl(
            '12.34.56.78',
            'tracking-NAME',
            SESSION_TRACKING_FORMAT_OID_RADIUS_ACCT_SESSION_ID,
            'tracking-ID',
        )
        stc_encoded = b'0G\x04\x0b12.34.56.78\x04\rtracking-NAME\x04\x1c1.3.6.1.4.1.21008.108.63.1.1\x04\x0btracking-ID'
        self.assertEqual(stc.encode(), stc_encoded)
        self.assertEqual(
            encode_request_ctrls([stc]),
            [(
                SessionTrackingControl.controlType.encode('ascii'),
                False,
                stc_encoded,
            )],
        )

    def test_psearch(self):
        psc = PersistentSearchControl(
            criticality=True,
            changeTypes=None,
            changesOnly=False,
            returnECs=True,
        )
        psc_encoded = b'0\t\x02\x01\x0f\x01\x01\x00\x01\x01\x01'
        self.assertEqual(psc.encode(), psc_encoded)
        self.assertEqual(
            encode_request_ctrls([psc]),
            [(
                PersistentSearchControl.controlType.encode('ascii'),
                True,
                psc_encoded,
            )],
        )


class TestResponseControls(unittest.TestCase):
    """
    test classes for decoding response controls
    """

    def test_base(self):
        rc = ResponseControl()
        rc.decode(b'foo')
        self.assertEqual(rc.controlValue, b'foo')
        with self.assertRaises(_libldap0.UNAVAILABLE_CRITICAL_EXTENSION):
            decode_response_ctrls(
                [(b'1.2.3.4', True, b'')],
            )
        with self.assertRaises(ValueError):
            decode_response_ctrls(
                [(PasswordExpiringControl.controlType.encode('ascii'), False, b'')],
            )
        with self.assertRaises(PyAsn1Error):
            decode_response_ctrls(
                [(PasswordPolicyControl.controlType.encode('ascii'), True, b'\xFF\x00\x00\x00\x00\x01')],
            )
        self.assertEqual(
            decode_response_ctrls(
                [(PasswordExpiringControl.controlType.encode('ascii'), False, b'')],
                ctrl_reg=ControlRegistry(),
            ),
            [],
        )

    def test_pwdpolicy(self):
        pec = PasswordExpiringControl()
        pec.decode(b'0')
        self.assertEqual(pec.gracePeriod, 0)
        with self.assertRaises(ValueError):
            pec.decode(b'x')
        pec = PasswordExpiredControl()
        pec.decode(b'0')
        self.assertEqual(pec.passwordExpired, True)
        pec.decode(b'x')
        self.assertEqual(pec.passwordExpired, False)

    def test_readentry(self):
        # test fall-back decoding caused by old OpenLDAP issue ITS#6899
        broken_ber = b'0c\x043cn=Samba Unix UID Pool,ou=Testing,dc=stroeder,dc=de0,0\x14\x04\tuidNumber1\x07\x04\x05100050\x14\x04\tgidNumber1\x07\x04\x0510005'
        rec = ReadEntryControl()
        rec.decode(broken_ber)
        self.assertEqual(rec.res.dn_s, 'cn=Samba Unix UID Pool,ou=Testing,dc=stroeder,dc=de')
        self.assertEqual(rec.res.entry_as, {'gidNumber': [b'10005'], 'uidNumber': [b'10005']})
        with self.assertRaises(PyAsn1Error):
            rec.decode(b'\xFF')


class TestVirtualListView(unittest.TestCase):
    """
    test class for ldap0.controls.vlv
    """

    @unittest.skip('Test vectors not verified')
    def test001_vlv_request_control(self):
        vrc = VLVRequestControl(
            criticality=True,
            before_count=10,
            after_count=20,
            offset=10,
            content_count=10,
            greater_than_or_equal=None,
            context_id=None,
        )
        self.assertEqual(vrc.encode(), b'0\x0e\x02\x01\n\x02\x01\x14\xa0\x06\x02\x01\n\x02\x01\n')
        vrc = VLVRequestControl(
            criticality=True,
            before_count=10,
            after_count=20,
            offset=10,
            content_count=None,
            greater_than_or_equal=10,
            context_id=None,
        )
        self.assertEqual(vrc.encode(), b'0\n\x02\x01\n\x02\x01\x14\x81\x0210')

    def test002_vlv_response_control(self):
        vrc = VLVResponseControl(criticality=True)
        with self.assertRaises(PyAsn1Error):
            vrc.decode(b'\xFF')


class TestAssertionControl(unittest.TestCase):

    def test001_assertion_control(self):
        self.assertEqual(
            AssertionControl(True, '(entryDN=uid=foo,cn=ae,ou=ae-dir)').encode(),
            b'\xa3"\x04\x07entryDN\x04\x17uid=foo,cn=ae,ou=ae-dir'
        )
        self.assertEqual(
            AssertionControl(
                True,
                (
                    '(&(entryCSN=20190917170703.426971Z#000000#000#000000)(entryDN=cn=Schwitters\\5c2C Kurt,ou=Testing,dc=stroeder,dc=de)(entryUUID=58e450f6-b2e0-1038-8849-9fc73698254c)(createTimestamp=20190122222520Z)(modifyTimestamp=20190917170703Z)(creatorsName=cn=michael ströder+mail=michael@stroeder.com,ou=private,dc=stroeder,dc=de)(modifiersName=cn=michael ströder+mail=michael@stroeder.com,ou=private,dc=stroeder,dc=de))'
                )
            ).encode(),
            b'\xa0\x82\x01\xa9\xa34\x04\x08'
            b'entryCSN\x04(20190917170703.426971Z#000000#000#000000'
            b'\xa3=\x04\x07entryDN\x042cn=Schwitters\\2C Kurt,ou=Testing,dc=stroeder,dc=de'
            b'\xa31\x04\tentryUUID\x04$58e450f6-b2e0-1038-8849-9fc73698254c\xa3"'
            b'\x04\x0fcreateTimestamp\x04\x0f20190122222520Z\xa3"'
            b'\x04\x0fmodifyTimestamp\x04\x0f20190917170703Z\xa3Z'
            b'\x04\x0ccreatorsName\x04Jcn=michael str\xc3\xb6der+mail=michael@stroeder.com,ou=private,dc=stroeder,dc=de'
            b'\xa3[\x04\rmodifiersName\x04Jcn=michael str\xc3\xb6der+mail=michael@stroeder.com,ou=private,dc=stroeder,dc=de'
        )


class TestSyncRepl(unittest.TestCase):
    """
    test class for ldap0.controls.syncrepl
    """

    #@unittest.skip('Test vectors not verified')
    def test001_syncrepl_request_control(self):
        src = SyncRequestControl(
            criticality=True,
        )
        self.assertEqual(src.encode(), b'0\x03\n\x01\x01')

        src = SyncRequestControl(
            criticality=True,
            cookie="rid=000,csn=20190917170703.426971Z#000000#000#000000",
            mode='refreshAndPersist',
            reloadHint=False
        )
        self.assertEqual(src.encode(), b'09\n\x01\x03\x044rid=000,csn=20190917170703.426971Z#000000#000#000000')

    def _check_state_decoded_val(self, buf, state=None, entryUUID=None, cookie=None):
        ssc = SyncStateControl()
        ssc.decode(buf)
        self.assertEqual(ssc.state, state)
        self.assertEqual(ssc.entryUUID, entryUUID)
        self.assertEqual(ssc.cookie, cookie)

    def test002_syncrepl_state_response_control(self):
        self._check_state_decoded_val(
            b'0K\x0a\x01\x01\x04\x10\xefg\x1dwU\tJ\xb5\xbb\xd3j\xb8~&\x1b;\x044rid=000,csn=20200414133753.354835Z#000000#000#000000',
            state='add',
            entryUUID='ef671d77-5509-4ab5-bbd3-6ab87e261b3b',
            cookie=b'rid=000,csn=20200414133753.354835Z#000000#000#000000',
        )

    def _check_done_decoded_val(self, buf, cookie=None, refreshDeletes=None):
        sdc = SyncDoneControl()
        sdc.decode(buf)
        self.assertEqual(sdc.cookie, cookie)
        self.assertEqual(sdc.refreshDeletes, refreshDeletes)

    def test003_syncrepl_done_response_control(self):
        self._check_done_decoded_val(
            b'09\x044rid=000,csn=20200414133753.354835Z#000000#000#000000\x01\x01\xff',
            cookie=b'rid=000,csn=20200414133753.354835Z#000000#000#000000',
            refreshDeletes=True,
        )


class TestPPolicy(unittest.TestCase):

    def _check_decoded_val(self, pp_buf, timeBeforeExpiration=None, graceAuthNsRemaining=None, error=None):
        pp = PasswordPolicyControl()
        pp.decode(pp_buf)
        self.assertEqual(pp.timeBeforeExpiration, timeBeforeExpiration)
        self.assertEqual(pp.graceAuthNsRemaining, graceAuthNsRemaining)
        self.assertEqual(pp.error, error)

    def test_ppolicy_graceauth(self):
        self._check_decoded_val(
            b'0\x84\x00\x00\x00\t\xa0\x84\x00\x00\x00\x03\x81\x01\x02',
            graceAuthNsRemaining=2,
        )

    def test_ppolicy_timebefore(self):
        self._check_decoded_val(
            b'0\x84\x00\x00\x00\t\xa0\x84\x00\x00\x00\x03\x80\x012',
            timeBeforeExpiration=50,
        )


class TestDeref(unittest.TestCase):

    def test_deref(self):
        deref = DereferenceControl(criticality=False)
        deref.decode(
            b'0\x81\xae0U\x04\x06member\x04\x1auid=rqei,cn=test,ou=ae-dir\xa0/0'
            b'-\x04\x0bdisplayName1\x1e\x04\x1cFred Feuerstein (rqei/30054)0U'
            b'\x04\x06member\x04\x1auid=tmar,cn=test,ou=ae-dir\xa0/0-\x04\x0b'
            b'displayName1\x1e\x04\x1cHorst R\xc3\xbcbezahl (tmar/30082)'
        )
        self.assertIsInstance(deref.derefRes, dict)
        self.assertIsInstance(deref.derefRes['member'][0], ldap0.res.SearchResultEntry)
        self.assertEqual(
            deref.derefRes['member'][0].dn_s,
            'uid=rqei,cn=test,ou=ae-dir'
        )
        self.assertEqual(
            deref.derefRes['member'][0].entry_s,
            {'displayName': ['Fred Feuerstein (rqei/30054)']}
        )
        self.assertEqual(
            deref.derefRes['member'][1].dn_s,
            'uid=tmar,cn=test,ou=ae-dir'
        )
        self.assertEqual(
            deref.derefRes['member'][1].entry_s,
            {'displayName': ['Horst Rübezahl (tmar/30082)']}
        )
        deref = DereferenceControl(criticality=False)
        deref.decode(
            b'0\x81\x9e0U\x04\x06member\x04\x1auid=wjcg,cn=test,ou=ae-dir\xa0/0'
            b'-\x04\x0bdisplayName1\x1e\x04\x1cFred Feuerstein (wjcg/30039)0E'
            b'\x04\x06member\x04;uid=sys-test-service-1,cn=test-services-1,cn=test,ou=ae-dir'
        )
        self.assertIsInstance(deref.derefRes, dict)
        self.assertIsInstance(deref.derefRes['member'][0], ldap0.res.SearchResultEntry)
        self.assertEqual(
            deref.derefRes['member'][0].dn_s,
            'uid=wjcg,cn=test,ou=ae-dir'
        )
        self.assertEqual(
            deref.derefRes['member'][0].entry_s,
            {'displayName': ['Fred Feuerstein (wjcg/30039)']}
        )
        self.assertEqual(
            deref.derefRes['member'][1].dn_s,
            'uid=sys-test-service-1,cn=test-services-1,cn=test,ou=ae-dir'
        )
        self.assertEqual(
            deref.derefRes['member'][1].entry_s,
            {}
        )


if __name__ == '__main__':
    unittest.main()

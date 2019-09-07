# -*- coding: utf-8 -*-
"""
Simple tests for module ldap0.controls
"""

# from Python's standard lib
import unittest

from pyasn1.error import PyAsn1Error

import _libldap0
from ldap0.res import SearchResultEntry
from ldap0.controls import encode_request_ctrls, ResponseControl, decode_response_ctrls, ControlRegistry
from ldap0.controls.sessiontrack import *
from ldap0.controls.psearch import *
from ldap0.controls.ppolicy import *
from ldap0.controls.pwdpolicy import *
from ldap0.controls.readentry import *
from ldap0.controls.vlv import *


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
                knownLDAPControls=ControlRegistry(),
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


if __name__ == '__main__':
    unittest.main()

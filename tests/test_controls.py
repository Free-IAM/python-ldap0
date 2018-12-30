# -*- coding: utf-8 -*-
"""
Simple tests for module ldap0.controls
"""

from __future__ import absolute_import

# from Python's standard lib
import unittest

from pyasn1.error import PyAsn1Error

import _libldap0
from ldap0.controls import RequestControlTuples, ResponseControl, DecodeControlTuples, ControlRegistry
from ldap0.controls.sessiontrack import *
from ldap0.controls.psearch import *
from ldap0.controls.ppolicy import *
from ldap0.controls.pwdpolicy import *
from ldap0.controls.readentry import *


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
        self.assertEqual(stc.encodeControlValue(), stc_encoded)
        self.assertEqual(
            RequestControlTuples([stc]),
            [(
                SessionTrackingControl.controlType,
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
        self.assertEqual(psc.encodeControlValue(), psc_encoded)
        self.assertEqual(
            RequestControlTuples([psc]),
            [(
                PersistentSearchControl.controlType,
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
        rc.decodeControlValue(b'foo')
        self.assertEqual(rc.controlValue, b'foo')
        with self.assertRaises(_libldap0.UNAVAILABLE_CRITICAL_EXTENSION):
            DecodeControlTuples(
                [('1.2.3.4', True, b'')],
            )
        with self.assertRaises(ValueError):
            DecodeControlTuples(
                [(PasswordExpiringControl.controlType, False, b'')],
            )
        with self.assertRaises(PyAsn1Error):
            DecodeControlTuples(
                [(PasswordPolicyControl.controlType, True, b'\xFF\x00\x00\x00\x00\x01')],
            )
        self.assertEqual(
            DecodeControlTuples(
                [(PasswordExpiringControl.controlType, False, b'')],
                knownLDAPControls=ControlRegistry(),
            ),
            [],
        )

    def test_pwdpolicy(self):
        pec = PasswordExpiringControl()
        pec.decodeControlValue('0')
        self.assertEqual(pec.gracePeriod, 0)
        pec = PasswordExpiredControl()
        pec.decodeControlValue('0')
        self.assertEqual(pec.passwordExpired, True)

    def test_readentry(self):
        # test fall-back decoding caused by old OpenLDAP issue ITS#6899
        broken_ber = b'0c\x043cn=Samba Unix UID Pool,ou=Testing,dc=stroeder,dc=de0,0\x14\x04\tuidNumber1\x07\x04\x05100050\x14\x04\tgidNumber1\x07\x04\x0510005'
        rec = ReadEntryControl()
        rec.decodeControlValue(broken_ber)
        self.assertEqual(rec.dn, 'cn=Samba Unix UID Pool,ou=Testing,dc=stroeder,dc=de')
        self.assertEqual(rec.entry, {'gidNumber': ['10005'], 'uidNumber': ['10005']})


if __name__ == '__main__':
    unittest.main()

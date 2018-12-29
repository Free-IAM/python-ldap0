# -*- coding: utf-8 -*-
"""
Simple tests for module ldap0.controls
"""

from __future__ import absolute_import

# from Python's standard lib
import unittest

from ldap0.controls import RequestControlTuples
from ldap0.controls.sessiontrack import *
from ldap0.controls.psearch import *
from ldap0.controls.pwdpolicy import *


class TestRequestControls(unittest.TestCase):

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

    def test_pwdpolicy(self):
        pec = PasswordExpiringControl()
        pec.decodeControlValue('0')
        self.assertEqual(pec.gracePeriod, 0)
        pec = PasswordExpiredControl()
        pec.decodeControlValue('0')
        self.assertEqual(pec.passwordExpired, True)


if __name__ == '__main__':
    unittest.main()

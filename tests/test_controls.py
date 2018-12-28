# -*- coding: utf-8 -*-
"""
Simple tests for module ldap0.controls
"""

from __future__ import absolute_import

# from Python's standard lib
import unittest

from ldap0.controls.sessiontrack import *


class TestRequestControls(unittest.TestCase):

    def test_session_tracking(self):
        self.assertEqual(
            SessionTrackingControl(
                '12.34.56.78',
                'tracking-NAME',
                SESSION_TRACKING_FORMAT_OID_RADIUS_ACCT_SESSION_ID,
                'tracking-ID',
            ).encodeControlValue(),
            b'0G\x04\x0b12.34.56.78\x04\rtracking-NAME\x04\x1c1.3.6.1.4.1.21008.108.63.1.1\x04\x0btracking-ID',
        )


if __name__ == '__main__':
    unittest.main()

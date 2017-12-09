# -*- coding: utf-8 -*-
"""
Automatic tests for module ldap0.syncrepl
"""

from __future__ import absolute_import

# from Python's standard lib
import unittest

from ldap0.openldap import SyncReplDesc
from ldap0.ldapurl import LDAPUrl


class TestSyncReplDesc(unittest.TestCase):
    """
    test ldap0.openldap.SyncReplDesc
    """

    def test_syncrepldesc_class(self):
        srd_str_list = [
            'rid=042',
            'provider=ldaps://ae-dir-deb-p2.snet1.example.com',
            'bindmethod=sasl',
            'timeout=5',
            'network-timeout=5',
            'saslmech=EXTERNAL',
            'keepalive=240:10:30',
            'starttls=no',
            'tls_cert="/opt/ae-dir/etc/tls/ae-dir-deb-p1.snet1.example.com.crt"',
            'tls_key="/opt/ae-dir/etc/tls/ae-dir-deb-p1.snet1.example.com.key"',
            'tls_cacert="/opt/ae-dir/etc/tls/my-ae-dir-testca-2017-06.pem"',
            'tls_reqcert=demand',
            'tls_cipher_suite=ECDHE-RSA-AES256-GCM-SHA384:DHE-RSA-AES256-GCM-SHA384:ECDH-RSA-AES256-GCM-SHA384:!ADH',
            'tls_protocol_min=3.3',
            'tls_crlcheck=none',
            'filter="(objectClass=*)"',
            'searchbase="dc=ae-dir,dc=example,dc=org"',
            'scope=sub',
            'schemachecking=on',
            'type=refreshAndPersist',
            'retry="30 +"'
        ]
        print '***', repr(' '.join(srd_str_list))
        srd = SyncReplDesc(' '.join(srd_str_list))
        self.assertEqual(srd.rid, '042')
        self.assertEqual(srd.provider, 'ldaps://ae-dir-deb-p2.snet1.example.com')
        self.assertEqual(srd.bindmethod, 'sasl')
        self.assertEqual(srd.timeout, '5')
        self.assertEqual(srd.network_timeout, '5')
        self.assertEqual(srd.saslmech, 'EXTERNAL')
        self.assertEqual(srd.keepalive, '240:10:30')
        self.assertEqual(srd.starttls, 'no')
        self.assertEqual(srd.tls_cert, '/opt/ae-dir/etc/tls/ae-dir-deb-p1.snet1.example.com.crt')
        self.assertEqual(srd.tls_key, '/opt/ae-dir/etc/tls/ae-dir-deb-p1.snet1.example.com.key')
        self.assertEqual(srd.tls_cacert, '/opt/ae-dir/etc/tls/my-ae-dir-testca-2017-06.pem')
        self.assertEqual(srd.tls_reqcert, 'demand')
        #self.assertEqual(srd.tls_cipher_suite, 'ECDHE-RSA-AES256-GCM-SHA384:DHE-RSA-AES256-GCM-SHA384:ECDH-RSA-AES256-GCM-SHA384:!ADH')
        self.assertEqual(srd.tls_protocol_min, '3.3')
        self.assertEqual(srd.tls_crlcheck, 'none')
        self.assertEqual(srd.filter, '(objectClass=*)')
        self.assertEqual(srd.searchbase, 'dc=ae-dir,dc=example,dc=org')
        self.assertEqual(srd.scope, 'sub')
        self.assertEqual(srd.schemachecking, 'on')
        self.assertEqual(srd.type, 'refreshAndPersist')
        self.assertEqual(srd.retry, '30 +')
        self.assertEqual(
            str(srd.ldap_url()),
            'ldaps://ae-dir-deb-p2.snet1.example.com/dc%3Dae-dir%2Cdc%3Dexample%2Cdc%3Dorg?*,+?sub?%28objectClass%3D%2A%29'
        )


if __name__ == '__main__':
    unittest.main()

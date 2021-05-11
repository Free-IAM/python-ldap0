# -*- coding: utf-8 -*-
"""
Automatic tests for module ldap0.syncrepl
"""

# from Python's standard lib
import unittest

from ldap0 import SCOPE_SUBTREE, SCOPE_ONELEVEL
from ldap0.ldapurl import LDAPUrl
from ldap0.openldap import SyncReplDesc, ldapsearch_cmd


class TestSyncReplDesc(unittest.TestCase):
    """
    test ldap0.openldap.SyncReplDesc
    """

    def test001_syncrepldesc_class(self):
        srd_str_list = [
            'rid=042',
            'provider=ldaps://ae-dir-deb-p2.snet1.example.com',
            'bindmethod=Sasl',
            'timeout=5',
            'network-timeout=5',
            'saslmech=external',
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
        srd = SyncReplDesc(' '.join(srd_str_list))
        self.assertEqual(srd.rid, '042')
        self.assertEqual(srd.provider, 'ldaps://ae-dir-deb-p2.snet1.example.com')
        self.assertEqual(srd.bindmethod, 'sasl')
        self.assertEqual(srd.timeout, 5)
        self.assertEqual(srd.network_timeout, 5)
        self.assertEqual(srd.saslmech, 'EXTERNAL')
        self.assertEqual(srd.keepalive, '240:10:30')
        self.assertEqual(srd.starttls, 'no')
        self.assertEqual(srd.tls_cert, '/opt/ae-dir/etc/tls/ae-dir-deb-p1.snet1.example.com.crt')
        self.assertEqual(srd.tls_key, '/opt/ae-dir/etc/tls/ae-dir-deb-p1.snet1.example.com.key')
        self.assertEqual(srd.tls_cacert, '/opt/ae-dir/etc/tls/my-ae-dir-testca-2017-06.pem')
        self.assertEqual(srd.tls_reqcert, 'demand')
        self.assertEqual(srd.tls_cipher_suite, 'ECDHE-RSA-AES256-GCM-SHA384:DHE-RSA-AES256-GCM-SHA384:ECDH-RSA-AES256-GCM-SHA384:!ADH')
        self.assertEqual(srd.tls_protocol_min, '3.3')
        self.assertEqual(srd.tls_crlcheck, 'none')
        self.assertEqual(srd.filter, '(objectClass=*)')
        self.assertEqual(srd.searchbase, 'dc=ae-dir,dc=example,dc=org')
        self.assertEqual(srd.scope, SCOPE_SUBTREE)
        self.assertEqual(srd.schemachecking, 'on')
        self.assertEqual(srd.type, 'refreshAndPersist')
        self.assertEqual(srd.retry, '30 +')
        self.assertEqual(
            str(srd.ldap_url()),
            'ldaps://ae-dir-deb-p2.snet1.example.com/dc%3Dae-dir%2Cdc%3Dexample%2Cdc%3Dorg?*,+?sub?%28objectClass%3D%2A%29'
        )

    def test002_syncrepldesc_class(self):
        srd_str_list = [
            '',
            '',
            'rid=23',
            'provider=ldap://ldap-23.example.com',
            'bindmethod=simple',
            'timeout="5"',
            'network-timeout=5',
            'saslmech=EXTERNAL',
            'keepalive=240:10:30',
            'starttls=critical',
            'tls_cacert="/etc/ssl/ca-certs.pem"',
            'tls_reqcert=try',
            'tls_crlcheck=peer',
            'filter="(cn=*FooBar*)"',
            'searchbase="ou=äöüÄÖÜß"',
            'scope=one',
            'schemachecking=on',
            'type=refreshAndPersist',
            '',
            '',
        ]
        srd = SyncReplDesc('  '.join(srd_str_list))
        self.assertEqual(repr(srd), 'SyncReplDesc(rid=23)')
        self.assertEqual(srd.rid, '23')
        self.assertEqual(srd.provider, 'ldap://ldap-23.example.com')
        self.assertEqual(srd.bindmethod, 'simple')
        self.assertEqual(srd.timeout, 5)
        self.assertEqual(srd.network_timeout, 5)
        self.assertEqual(srd.saslmech, 'EXTERNAL')
        self.assertEqual(srd.keepalive, '240:10:30')
        self.assertEqual(srd.starttls, 'critical')
        self.assertEqual(srd.tls_cert, None)
        self.assertEqual(srd.tls_key, None)
        self.assertEqual(srd.tls_cacert, '/etc/ssl/ca-certs.pem')
        self.assertEqual(srd.tls_reqcert, 'try')
        self.assertEqual(srd.tls_protocol_min, None)
        self.assertEqual(srd.tls_crlcheck, 'peer')
        self.assertEqual(srd.filter, '(cn=*FooBar*)')
        self.assertEqual(srd.searchbase, 'ou=äöüÄÖÜß')
        self.assertEqual(srd.scope, SCOPE_ONELEVEL)
        self.assertEqual(srd.schemachecking, 'on')
        self.assertEqual(srd.type, 'refreshAndPersist')
        self.assertEqual(srd.retry, None)
        srd_url_obj = srd.ldap_url()
        self.assertEqual(srd_url_obj.dn, 'ou=äöüÄÖÜß')
        self.assertEqual(srd_url_obj.scope, SCOPE_ONELEVEL)
        self.assertEqual(
            str(srd_url_obj),
            'ldap://ldap-23.example.com/ou%3D%C3%A4%C3%B6%C3%BC%C3%84%C3%96%C3%9C%C3%9F?*,+?one?%28cn%3D%2AFooBar%2A%29'
        )

    def test003_value_error(self):
        for invalid_val in (
            'timeout=1x2',
            'bindmethod=foo',
            'scope=foo',
            'starttls=foo',
        ):
            try:
                SyncReplDesc(invalid_val)
            except ValueError:
                pass
            else:
                self.fail('%r should have raised ValueError' % (invalid_val))


class TestLdapSearchCmd(unittest.TestCase):
    """
    test ldap0.openldap.ldapsearch_cmd()
    """
    maxDiff = None

    def test001_ldapsearch_cmd(self):
        self.assertEqual(
            ldapsearch_cmd(
                LDAPUrl(
                    'ldap://127.0.0.1:1234/'
                    'dc=example,dc=com'
                    '?attr1,attr2,attr3'
                    '?sub'
                    '?%28objectClass%3D%2A%29'
                    '?'
                    'bindname=cn%3Dfred%2Cc%3Dau,'
                    'X-BINDPW=%3F%3F%3F,'
                    'trace=8,'
                    'x-saslmech=DIGEST-MD5,'
                    'x-saslrealm=example.com,'
                    'x-saslauthzid=u:anna,'
                    'x-starttls=2,'
                )
            ),
            ' '.join((
                'ldapsearch',
                '-LL',
                '-H "ldap://127.0.0.1:1234"',
                '-ZZ','-b "dc=example,dc=com"',
                '-s sub',
                '-Y "DIGEST-MD5"',
                '-X "u:anna"',
                '"(objectClass=*)"',
                'attr1 attr2 attr3',
            ))
        )
        self.assertEqual(
            ldapsearch_cmd(
                LDAPUrl(
                    'ldaps://ldap.example.com/'
                    'dc=example,dc=com'
                    '?'
                    '?one'
                    '?(uid=foo)'
                )
            ),
            'ldapsearch -LL -H "ldaps://ldap.example.com"  -b "dc=example,dc=com" -s one -x -D "" -w ""  "(uid=foo)"'
        )


if __name__ == '__main__':
    unittest.main()

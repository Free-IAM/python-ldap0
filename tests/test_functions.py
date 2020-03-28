# -*- coding: utf-8 -*-
"""
Automatic tests for module ldap0.functions
"""

# from Python's standard lib
import unittest
import datetime

import ldap0
from ldap0.functions import attr_set, escape_str
from ldap0.dn import escape_str as escape_dn_str
from ldap0.filter import escape_str as escape_filter_str


class TestFunction(unittest.TestCase):
    """
    test simple functions in ldap0.functions
    """

    def test_ldap_strf_secs(self):
        """
        test function ldap_strf_secs()
        """
        self.assertEqual(ldap0.strf_secs(0), '19700101000000Z')
        self.assertEqual(ldap0.strf_secs(1466947067), '20160626131747Z')

    def test_ldap_strp_secs(self):
        """
        test function ldap_strp_secs()
        """
        self.assertEqual(ldap0.strp_secs('19700101000000Z'), 0)
        self.assertEqual(ldap0.strp_secs('20160626131747Z'), 1466947067)

    def test_escape_str(self):
        """
        test function escape_string_tmpl()
        """
        self.assertEqual(
            escape_str(
                escape_filter_str,
                '(&(objectClass=aeUser)(uid=%s))',
                'foo'
            ),
            '(&(objectClass=aeUser)(uid=foo))'
        )
        self.assertEqual(
            escape_str(
                escape_filter_str,
                '(&(objectClass=aeUser)(uid=%s))',
                'foo)bar'
            ),
            '(&(objectClass=aeUser)(uid=foo\\29bar))'
        )
        self.assertEqual(
            escape_str(
                escape_dn_str,
                'uid=%s',
                'foo=bar'
            ),
            'uid=foo\\=bar'
        )
        self.assertEqual(
            escape_str(
                escape_dn_str,
                'uid=%s,cn=%s,cn=%s,dc=example,dc=com',
                'foo=bar',
                'foo+',
                '+bar',
            ),
            'uid=foo\\=bar,cn=foo\\+,cn=\\+bar,dc=example,dc=com'
        )

    def test_attr_set(self):
        self.assertEqual(
            attr_set('foo bar foobar'),
            {'foobar', 'foo', 'bar'}
        )
        self.assertEqual(
            attr_set('foo,bar,foobar'),
            {'foobar', 'foo', 'bar'}
        )
        self.assertEqual(
            attr_set('    foo, bar, foobar'),
            {'foobar', 'foo', 'bar'}
        )
        self.assertEqual(
            attr_set('    foo, bar, foo bar'),
            {'foo', 'bar'}
        )

    def test_str2datetime(self):
        self.assertEqual(
            ldap0.functions.str2datetime('19700101000000Z'),
            datetime.datetime(1970, 1, 1)
        )
        self.assertEqual(
            ldap0.functions.str2datetime('20200328123456Z'),
            datetime.datetime(2020, 3, 28, 12, 34, 56)
        )

    def test_datetime2str(self):
        self.assertEqual(
            '19700101000000Z',
            ldap0.functions.datetime2str(datetime.datetime(1970, 1, 1))
        )
        self.assertEqual(
            '20200328123456Z',
            ldap0.functions.datetime2str(datetime.datetime(2020, 3, 28, 12, 34, 56))
        )


class TestOptions(unittest.TestCase):
    """
    test LDAP option functions in ldap0.functions
    """

    def test_protocol_version(self):
        # default should be LDAPv3
        self.assertEqual(ldap0.functions.get_option(ldap0.OPT_PROTOCOL_VERSION), 3)
        # switch to LDAPv2
        ldap0.functions.set_option(ldap0.OPT_PROTOCOL_VERSION, 2)
        self.assertEqual(ldap0.functions.get_option(ldap0.OPT_PROTOCOL_VERSION), 2)
        # set back to LDAPv3
        ldap0.functions.set_option(ldap0.OPT_PROTOCOL_VERSION, 3)
        self.assertEqual(ldap0.functions.get_option(ldap0.OPT_PROTOCOL_VERSION), 3)

    def test_ca_cert(self):
        ldap0.functions.set_option(ldap0.OPT_X_TLS_CACERTFILE, b'/etc/ssl/ca-bundle.pem')
        self.assertEqual(ldap0.functions.get_option(ldap0.OPT_X_TLS_CACERTFILE), b'/etc/ssl/ca-bundle.pem')
        ldap0.functions.set_option(ldap0.OPT_X_TLS_CACERTDIR, b'/etc/ssl/cacerts')
        self.assertEqual(ldap0.functions.get_option(ldap0.OPT_X_TLS_CACERTDIR), b'/etc/ssl/cacerts')


if __name__ == '__main__':
    unittest.main()

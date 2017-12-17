# -*- coding: utf-8 -*-
"""
Automatic tests for module ldap0.filter
"""

from __future__ import absolute_import

# from Python's standard lib
import unittest

from ldap0.filter import \
    escape_filter_chars, \
    negate_filter, \
    map_filter_parts, \
    compose_filter, \
    dict_filter


class TestFilter(unittest.TestCase):
    """
    test ldap.filter
    """

    def test_escape_filter_chars_mode0(self):
        """
        test function escape_filter_chars() with escape_mode=0
        """
        self.assertEqual(
            escape_filter_chars(r'foobar'),
            'foobar'
        )
        self.assertEqual(
            escape_filter_chars(r'foo\bar'),
            r'foo\5cbar'
        )
        self.assertEqual(
            escape_filter_chars(
                r'foo\bar',
                escape_mode=0
            ),
            r'foo\5cbar'
        )

    def test_escape_filter_chars_mode1(self):
        """
        test function escape_filter_chars() with escape_mode=1
        """
        self.assertEqual(
            escape_filter_chars(
                '\xc3\xa4\xc3\xb6\xc3\xbc\xc3\x84\xc3\x96\xc3\x9c\xc3\x9f',
                escape_mode=1
            ),
            r'\c3\a4\c3\b6\c3\bc\c3\84\c3\96\c3\9c\c3\9f'
        )

    def test_escape_filter_chars_mode2(self):
        """
        test function escape_filter_chars() with escape_mode=2
        """
        self.assertEqual(
            escape_filter_chars(
                'foobar',
                escape_mode=2
            ),
            r'\66\6f\6f\62\61\72'
        )

    def test_negate_filter(self):
        self.assertEqual(negate_filter('(objectClass=*)'), '(!(objectClass=*))')
        self.assertEqual(negate_filter('(!(objectClass=*))'), '(objectClass=*)')
        self.assertEqual(negate_filter('(!(!(objectClass=*)))'), '(!(objectClass=*))')

    def test_map_filter_parts(self):
        self.assertEqual(map_filter_parts('foo', []), [])
        self.assertEqual(
            map_filter_parts('foo', ['1', '2']),
            ['(foo=1)', '(foo=2)']
        )
        self.assertEqual(
            map_filter_parts('foo', ['1', '2'], escape_mode=2),
            ['(foo=\\31)', '(foo=\\32)']
        )

    def test_compose_filter(self):
        self.assertEqual(compose_filter('', []), '')
        self.assertEqual(compose_filter('&', []), '')
        self.assertEqual(compose_filter('|', []), '')
        self.assertEqual(
            compose_filter('|', map_filter_parts('foo', ['1'])),
            '(foo=1)'
        )
        self.assertEqual(
            compose_filter('|', map_filter_parts('foo', ['1', '2'])),
            '(|(foo=1)(foo=2))'
        )
        self.assertEqual(
            compose_filter(
                '|',
                map_filter_parts('foo', ['1', '2'], escape_mode=2)
            ),
            '(|(foo=\\31)(foo=\\32))'
        )

    def test_dict_filter(self):
        self.assertEqual(dict_filter({}), '')
        self.assertEqual(dict_filter({'foo': ['bar']}), '(foo=bar)')
        self.assertEqual(
            dict_filter({'foo': ['bar1', 'bar2']}),
            '(&(foo=bar1)(foo=bar2))'
        )
        self.assertEqual(
            dict_filter({'foo': ['bar1', 'bar2']}, iop='|'), '(|(foo=bar1)(foo=bar2))'
        )
        self.assertEqual(
            dict_filter({'foo1': ['bar1', 'bar2'], 'foo2': ['bar1', 'bar2']}, iop='|'),
            '(&(|(foo1=bar1)(foo1=bar2))(|(foo2=bar1)(foo2=bar2)))'
        )
        self.assertEqual(
            dict_filter({'foo1': ['bar1', 'bar2'], 'foo2': ['bar1', 'bar2']}, oop='|'),
            '(|(&(foo1=bar1)(foo1=bar2))(&(foo2=bar1)(foo2=bar2)))'
        )


if __name__ == '__main__':
    unittest.main()

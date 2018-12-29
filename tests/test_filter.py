# -*- coding: utf-8 -*-
"""
Automatic tests for module ldap0.filter
"""

from __future__ import absolute_import

# from Python's standard lib
import time
import unittest
from collections import OrderedDict

from ldap0.functions import strf_secs
from ldap0.filter import \
    escape_filter_chars, \
    negate_filter, \
    map_filter_parts, \
    compose_filter, \
    time_span_filter, \
    filter_format, \
    dict_filter


class TestFilter(unittest.TestCase):
    """
    test ldap0.filter
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
        self.assertEqual(
            escape_filter_chars('(foo*bar)', escape_mode=1),
            r'\28foo\2abar\29'
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

    def test_escape_filter_chars_mode666(self):
        """
        test function escape_filter_chars() with escape_mode=2
        """
        with self.assertRaises(ValueError):
            escape_filter_chars('foobar', escape_mode=666)

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
            dict_filter(
                OrderedDict([('foo1', ['bar1', 'bar2']), ('foo2', ['bar1', 'bar2'])]),
                iop='|'
            ),
            '(&(|(foo1=bar1)(foo1=bar2))(|(foo2=bar1)(foo2=bar2)))'
        )
        self.assertEqual(
            dict_filter(
                OrderedDict([('foo1', ['bar1', 'bar2']), ('foo2', ['bar1', 'bar2'])]),
                oop='|'
            ),
            '(|(&(foo1=bar1)(foo1=bar2))(&(foo2=bar1)(foo2=bar2)))'
        )

    def test_filter_format(self):
        self.assertEqual(filter_format('', ()), '')
        self.assertEqual(filter_format('(%s=%s)', ('foo', 'bar')), '(foo=bar)')
        self.assertEqual(filter_format('(|(cn=%s)(cn=%s))', ('foo', 'bar')), '(|(cn=foo)(cn=bar))')
        with self.assertRaises(TypeError):
            filter_format('', ('foo', 'bar'))

    def test_time_span_filter(self):
        self.assertEqual(
            time_span_filter(until_timestamp=0),
            '(&(modifyTimestamp>=19700101000000Z)(!(modifyTimestamp>=19700101000000Z)))',
        )
        self.assertEqual(
            time_span_filter(
                from_timestamp=1000000,
                until_timestamp=1546101638,
                delta_attr='foo',
            ),
            '(&(foo>=19700112134640Z)(!(foo>=20181229164038Z)))',
        )
        with self.assertRaises(ValueError):
            time_span_filter(from_timestamp=1, until_timestamp=0)
        # test time.time() based filter
        before = time.time()
        flt = time_span_filter(delta_attr='foo')
        after = time.time()
        results = set([
            '(&(foo>=19700101000000Z)(!(foo>=%s)))' % (strf_secs(before)),
            '(&(foo>=19700101000000Z)(!(foo>=%s)))' % (strf_secs(after)),
        ])
        self.assertIn(flt, results)
        # test time.time() based filter with relative from_timestamp
        fts = -10
        before = time.time()
        flt = time_span_filter(from_timestamp=fts, delta_attr='foo')
        after = time.time()
        results = set([
            '(&(foo>=%s)(!(foo>=%s)))' % (strf_secs(before+fts), strf_secs(before)),
            '(&(foo>=%s)(!(foo>=%s)))' % (strf_secs(after+fts), strf_secs(after)),
        ])
        self.assertIn(flt, results)


if __name__ == '__main__':
    unittest.main()

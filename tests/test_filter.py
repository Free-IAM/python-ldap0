# -*- coding: utf-8 -*-
"""
Automatic tests for module ldap0.filter
"""

from __future__ import absolute_import
from __future__ import unicode_literals

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
            escape_filter_chars(b'foobar'),
            b'foobar'
        )
        self.assertEqual(
            escape_filter_chars(b'foo\\bar'),
            b'foo\\5cbar'
        )
        self.assertEqual(
            escape_filter_chars(
                b'foo\\bar',
                escape_mode=0
            ),
            b'foo\\5cbar'
        )
        self.assertEqual(
            escape_filter_chars(
                b'T\xc3\xa4ster',
                escape_mode=0
            ),
            b'T\xc3\xa4ster'
        )

    def test_escape_filter_chars_mode1(self):
        """
        test function escape_filter_chars() with escape_mode=1
        """
        self.assertEqual(
            escape_filter_chars(
                b'\xc3\xa4\xc3\xb6\xc3\xbc\xc3\x84\xc3\x96\xc3\x9c\xc3\x9f',
                escape_mode=1
            ),
            b'\\c3\\a4\\c3\\b6\\c3\\bc\\c3\\84\\c3\\96\\c3\\9c\\c3\\9f'
        )
        self.assertEqual(
            escape_filter_chars(b'(foo*bar)', escape_mode=1),
            b'\\28foo\\2abar\\29'
        )

    def test_escape_filter_chars_mode2(self):
        """
        test function escape_filter_chars() with escape_mode=2
        """
        self.assertEqual(
            escape_filter_chars(
                b'foobar',
                escape_mode=2
            ),
            b'\\66\\6f\\6f\\62\\61\\72'
        )

    def test_escape_filter_chars_mode666(self):
        """
        test function escape_filter_chars() with escape_mode=2
        """
        with self.assertRaises(ValueError):
            escape_filter_chars(b'foobar', escape_mode=666)

    def test_negate_filter(self):
        self.assertEqual(negate_filter(b'(objectClass=*)'), b'(!(objectClass=*))')
        self.assertEqual(negate_filter(b'(!(objectClass=*))'), b'(objectClass=*)')
        self.assertEqual(negate_filter(b'(!(!(objectClass=*)))'), b'(!(objectClass=*))')

    def test_map_filter_parts(self):
        self.assertEqual(map_filter_parts(b'foo', []), [])
        self.assertEqual(
            map_filter_parts(b'foo', [b'1', b'2']),
            [b'(foo=1)', b'(foo=2)']
        )
        self.assertEqual(
            map_filter_parts(b'sn', [b'T\xc3\xa4ster', b'M\xc3\xbcller'], escape_mode=1),
            [b'(sn=T\\c3\\a4ster)', b'(sn=M\\c3\\bcller)']
        )
        self.assertEqual(
            map_filter_parts(b'foo', [b'1', b'2'], escape_mode=2),
            [b'(foo=\\31)', b'(foo=\\32)']
        )
        self.assertEqual(
            map_filter_parts(b'sn', [b'T\xc3\xa4ster', b'M\xc3\xbcller'], escape_mode=2),
            [b'(sn=\\54\\c3\\a4\\73\\74\\65\\72)', b'(sn=\\4d\\c3\\bc\\6c\\6c\\65\\72)']
        )

    def test_compose_filter(self):
        self.assertEqual(compose_filter(b'', []), b'')
        self.assertEqual(compose_filter(b'&', []), b'')
        self.assertEqual(compose_filter(b'|', []), b'')
        self.assertEqual(
            compose_filter(b'|', map_filter_parts(b'foo', [b'1'])),
            b'(foo=1)'
        )
        self.assertEqual(
            compose_filter(b'|', map_filter_parts(b'foo', [b'1', b'2'])),
            b'(|(foo=1)(foo=2))'
        )
        self.assertEqual(
            compose_filter(
                b'|',
                map_filter_parts(b'foo', [b'1', b'2'], escape_mode=2)
            ),
            b'(|(foo=\\31)(foo=\\32))'
        )

    def test_dict_filter(self):
        self.assertEqual(dict_filter({}), b'')
        self.assertEqual(dict_filter({b'foo': [b'bar']}), b'(foo=bar)')
        self.assertEqual(
            dict_filter({b'foo': [b'bar1', b'bar2']}),
            b'(&(foo=bar1)(foo=bar2))'
        )
        self.assertEqual(
            dict_filter({b'foo': [b'bar1', b'bar2']}, iop='|'), b'(|(foo=bar1)(foo=bar2))'
        )
        self.assertEqual(
            dict_filter(
                OrderedDict([(b'foo1', [b'bar1', b'bar2']), (b'foo2', [b'bar1', b'bar2'])]),
                iop='|'
            ),
            b'(&(|(foo1=bar1)(foo1=bar2))(|(foo2=bar1)(foo2=bar2)))'
        )
        self.assertEqual(
            dict_filter(
                OrderedDict([(b'foo1', [b'bar1', b'bar2']), (b'foo2', [b'bar1', b'bar2'])]),
                oop='|'
            ),
            b'(|(&(foo1=bar1)(foo1=bar2))(&(foo2=bar1)(foo2=bar2)))'
        )
        self.assertEqual(
            dict_filter(
                OrderedDict([(b'foo1', [b'T\xc3\xa4ster', b'M\xc3\xbcller']), (b'foo2', [b'T\xc3\xa4ster', b'M\xc3\xbcller'])]),
                oop=b'|'
            ),
            b'(|(&(foo1=T\xc3\xa4ster)(foo1=M\xc3\xbcller))(&(foo2=T\xc3\xa4ster)(foo2=M\xc3\xbcller)))'
        )

    def test_filter_format(self):
        self.assertEqual(filter_format(b'', ()), b'')
        self.assertEqual(filter_format(b'(%s=%s)', (b'foo', b'bar')), b'(foo=bar)')
        self.assertEqual(filter_format(b'(|(cn=%s)(cn=%s))', (b'foo', b'bar')), b'(|(cn=foo)(cn=bar))')
        with self.assertRaises(TypeError):
            filter_format(b'', (b'foo', b'bar'))

    def test_time_span_filter(self):
        self.assertEqual(
            time_span_filter(until_timestamp=0),
            b'(&(modifyTimestamp>=19700101000000Z)(!(modifyTimestamp>=19700101000000Z)))',
        )
        self.assertEqual(
            time_span_filter(
                from_timestamp=1000000,
                until_timestamp=1546101638,
                delta_attr=b'foo',
            ),
            b'(&(foo>=19700112134640Z)(!(foo>=20181229164038Z)))',
        )
        with self.assertRaises(ValueError):
            time_span_filter(from_timestamp=1, until_timestamp=0)
        # test time.time() based filter
        before = time.time()
        flt = time_span_filter(delta_attr=b'foo')
        after = time.time()
        results = set([
            b'(&(foo>=19700101000000Z)(!(foo>=%s)))' % (strf_secs(before)),
            b'(&(foo>=19700101000000Z)(!(foo>=%s)))' % (strf_secs(after)),
        ])
        self.assertIn(flt, results)
        # test time.time() based filter with relative from_timestamp
        fts = -10
        before = time.time()
        flt = time_span_filter(from_timestamp=fts, delta_attr=b'foo')
        after = time.time()
        results = set([
            b'(&(foo>=%s)(!(foo>=%s)))' % (strf_secs(before+fts), strf_secs(before)),
            b'(&(foo>=%s)(!(foo>=%s)))' % (strf_secs(after+fts), strf_secs(after)),
        ])
        self.assertIn(flt, results)


if __name__ == '__main__':
    unittest.main()

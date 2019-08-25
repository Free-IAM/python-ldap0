# -*- coding: utf-8 -*-
"""
Automatic tests for module ldap0.filter
"""

# from Python's standard lib
import time
import unittest
from collections import OrderedDict

from ldap0.functions import strf_secs, escape_format
from ldap0.filter import \
    escape_str, \
    escape_bytes, \
    negate_filter, \
    map_filter_parts, \
    compose_filter, \
    time_span_filter, \
    dict_filter


class TestFilter(unittest.TestCase):
    """
    test ldap0.filter
    """

    def test000_escape_str(self):
        """
        test function ldap0.filter.escape_str()
        """
        self.assertEqual(escape_str('foobar'), 'foobar')
        self.assertEqual(escape_str('foo\\bar'), 'foo\\5cbar')
        self.assertEqual(escape_str('foo*bar'), 'foo\\2abar')
        self.assertEqual(escape_str('Täster'), 'Täster')

    def test001_escape_bytes(self):
        """
        test function ldap0.filter.escape_bytes()
        """
        self.assertEqual(
            escape_bytes(b'\xc3\xa4\xc3\xb6\xc3\xbc\xc3\x84\xc3\x96\xc3\x9c\xc3\x9f'),
            '\\c3\\a4\\c3\\b6\\c3\\bc\\c3\\84\\c3\\96\\c3\\9c\\c3\\9f'
        )

    def test004_negate_filter(self):
        self.assertEqual(negate_filter('(objectClass=*)'), '(!(objectClass=*))')
        self.assertEqual(negate_filter('(!(objectClass=*))'), '(objectClass=*)')
        self.assertEqual(negate_filter('(!(!(objectClass=*)))'), '(!(objectClass=*))')

    def test005_map_filter_parts(self):
        self.assertEqual(map_filter_parts('foo', []), [])
        self.assertEqual(
            map_filter_parts('foo', ['1', '2']),
            ['(foo=1)', '(foo=2)']
        )
        self.assertEqual(
            map_filter_parts('sn', ['Täster', 'Müller']),
            ['(sn=Täster)', '(sn=Müller)']
        )

    def test007_compose_filter(self):
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

    def test008_dict_filter(self):
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
        self.assertEqual(
            dict_filter(
                OrderedDict([('foo1', ['T\xc3\xa4ster', 'M\xc3\xbcller']), ('foo2', ['T\xc3\xa4ster', 'M\xc3\xbcller'])]),
                oop='|'
            ),
            '(|(&(foo1=T\xc3\xa4ster)(foo1=M\xc3\xbcller))(&(foo2=T\xc3\xa4ster)(foo2=M\xc3\xbcller)))'
        )

    def test009_escape_format_with_filter(self):
        self.assertEqual(escape_format(escape_str, ''), '')
        self.assertEqual(escape_format(escape_str, '', 'foo', 'bar'), '')
        self.assertEqual(escape_format(escape_str, '({}={})', 'foo', 'bar'), '(foo=bar)')
        self.assertEqual(escape_format(escape_str, '(|(cn={})(cn={}))', 'foo', 'bar'), '(|(cn=foo)(cn=bar))')
        self.assertEqual(escape_format(escape_str, '(|(cn={})(cn={}))', 'fo*o', 'ba\\r'), '(|(cn=fo\\2ao)(cn=ba\\5cr))')
        self.assertEqual(escape_format(escape_str, '(|(cn={arg1})(cn={arg2}))', arg1='foo', arg2='bar'), '(|(cn=foo)(cn=bar))')
        self.assertEqual(escape_format(escape_str, '(|(cn={arg1})(cn={arg2}))', arg1='fo*o', arg2='ba\\r'), '(|(cn=fo\\2ao)(cn=ba\\5cr))')
        self.assertEqual(escape_format(escape_str, '(|({0}={arg1})({1}={arg2}))', 'foo', 'bar', arg1='fo*o', arg2='ba\\r'), '(|(foo=fo\\2ao)(bar=ba\\5cr))')

    def test010_time_span_filter(self):
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

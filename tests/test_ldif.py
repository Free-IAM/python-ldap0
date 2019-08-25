# -*- coding: utf-8 -*-
"""
Automatic tests for module ldap0.ldif
"""

# from Python's standard lib
import unittest
import textwrap

from io import BytesIO

import ldap0.ldif
from ldap0.ldif import LDIFParser, LDIFWriter, MOD_OP_INTEGER


class TestLDIFParser(unittest.TestCase):
    """
    Various LDIF test cases
    """

    def _parse_records(
            self,
            ldif_string,
            ignored_attr_types=None,
            max_entries=None,
        ):
        """
        Parse LDIF data in `ldif_string' into list of records
        """
        ldif_parser = LDIFParser.frombuf(
            ldif_string,
            ignored_attr_types=ignored_attr_types,
            max_entries=max_entries,
        )
        parser_method = getattr(
            ldif_parser,
            'list_%s_records' % self.record_type
        )
        return parser_method()

    def _unparse_records(self, records):
        """
        Returns LDIF string with entry records from list `records'
        """
        ldif_file = BytesIO()
        ldif_writer = LDIFWriter(ldif_file)
        if self.record_type == 'entry':
            for dn, entry in records:
                ldif_writer.unparse(dn, entry)
        elif self.record_type == 'change':
            for dn, modops, controls in records:
                ldif_writer.unparse(dn, modops)
        return ldif_file.getvalue()

    def check_records(
            self,
            ldif_string,
            records,
            ignored_attr_types=None,
            max_entries=None,
    ):
        """
        Checks whether entry records in `ldif_string' gets correctly parsed
        and matches list of unparsed `records'.
        """
        ldif_string = textwrap.dedent(ldif_string).lstrip()
        parsed_records = self._parse_records(
            ldif_string.encode('utf-8'),
            ignored_attr_types=ignored_attr_types,
            max_entries=max_entries,
        )
        generated_ldif = self._unparse_records(records)
        parsed_records2 = self._parse_records(
            generated_ldif,
            ignored_attr_types=ignored_attr_types,
            max_entries=max_entries,
        )
        self.assertEqual(records, parsed_records)
        self.assertEqual(records, parsed_records2)


class TestEntryRecords(TestLDIFParser):
    """
    Various LDIF test cases
    """
    record_type='entry'

    def test_yield(self):
        ldif_string = \
            """
            # comment #1
             with line-folding
            dn: cn=x1,cn=y1,cn=z1
            b1: value_b1
            c1: value_c1
            a1: value_a1

            # comment #2.1
            # comment #2.2
            dn: cn=x2,cn=y2,cn=z2
            b2: value_b2
            c2: value_c2
            a2: value_a2

            """
        ldif_string = textwrap.dedent(ldif_string).lstrip()
        result = LDIFParser.frombuf(ldif_string.encode('utf-8')).list_entry_records()

    def test_empty(self):
        self.check_records(
            """
            version: 1

            """,
            []
        )

    def test_simple(self):
        self.check_records(
            """
            version: 1

            dn: cn=x,cn=y,cn=z
            attrib: value
            attrib: value2

            """,
            [
                (
                    b'cn=x,cn=y,cn=z',
                    {
                        b'attrib': [b'value', b'value2'],
                    },
                ),
            ]
        )

    def test_simple2(self):
        self.check_records(
            """
            dn:cn=x,cn=y,cn=z
            attrib:value
            attrib:value2

            """,
            [
                (
                    b'cn=x,cn=y,cn=z',
                    {
                        b'attrib': [b'value', b'value2'],
                    },
                ),
            ]
        )

    def test_multiple(self):
        self.check_records(
            """
            dn: cn=x,cn=y,cn=z
            a: v
            attrib: value
            attrib: value2

            dn: cn=a,cn=b,cn=c
            attrib: value2
            attrib: value3
            b: v

            """,
            [
                (
                    b'cn=x,cn=y,cn=z',
                    {
                        b'attrib': [b'value', b'value2'],
                        b'a': [b'v'],
                    },
                ),
                (
                    b'cn=a,cn=b,cn=c',
                    {
                        b'attrib': [b'value2', b'value3'],
                        b'b': [b'v'],
                    },
                ),
            ]
        )

    def test_folded(self):
        self.check_records(
            """
            dn: cn=x,cn=y,cn=z
            attrib: very\x20
             long
              line-folded\x20
             value
            attrib2: %s

            """ % ('asdf.'*20),
            [
                (
                    b'cn=x,cn=y,cn=z',
                    {
                        b'attrib': [b'very long line-folded value'],
                        b'attrib2': [b'asdf.'*20],
                    }
                ),
            ]
        )

    def test_empty_attr_values(self):
        self.check_records(
            """
            dn: cn=x,cn=y,cn=z
            attrib1:
            attrib1: foo
            attrib2:
            attrib2: foo

            """,
            [
                (
                    b'cn=x,cn=y,cn=z',
                    {
                        b'attrib1': [b'', b'foo'],
                        b'attrib2': [b'', b'foo'],
                    },
                ),
            ]
        )

    def test_binary(self):
        self.check_records(
            """
            dn: cn=x,cn=y,cn=z
            attrib:: CQAKOiVA

            """,
            [
                (
                    b'cn=x,cn=y,cn=z',
                    {
                        b'attrib': [b'\t\0\n:%@'],
                    },
                ),
            ]
        )

    def test_binary2(self):
        self.check_records(
            """
            dn: cn=x,cn=y,cn=z
            attrib::CQAKOiVA

            """,
            [
                (
                    b'cn=x,cn=y,cn=z',
                    {b'attrib': [b'\t\0\n:%@']},
                ),
            ]
        )

    def test_big_binary(self):
        self.check_records(
            """
            dn: cn=x,cn=y,cn=z
            attrib:: AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
             AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
             AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
             AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
             AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
             AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
             AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
             AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
             AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
             =

            """,
            [
                (
                    b'cn=x,cn=y,cn=z',
                    {b'attrib': [500*b'\0']},
                ),
            ]
        )

    def test_unicode(self):
        self.check_records(
            """
            dn: cn=Michael Ströder,dc=stroeder,dc=com
            cn: Michael Ströder
            sn: Ströder

            """,
            [
                (
                    b'cn=Michael Str\xc3\xb6der,dc=stroeder,dc=com',
                    {
                        b'cn': [b'Michael Str\xc3\xb6der'],
                        b'sn': [b'Str\xc3\xb6der'],
                    },
                ),
            ]
        )

    def test_sorted(self):
        self.check_records(
            """
            dn: cn=x,cn=y,cn=z
            b: value_b
            c: value_c
            a: value_a

            """,
            [
                (
                    b'cn=x,cn=y,cn=z',
                    {
                        b'a': [b'value_a'],
                        b'b': [b'value_b'],
                        b'c': [b'value_c'],
                    }
                ),
            ]
        )

    def test_ignored_attr_types(self):
        self.check_records(
            """
            dn: cn=x,cn=y,cn=z
            a: value_a
            b: value_b
            c: value_c

            """,
            [
                (
                    b'cn=x,cn=y,cn=z',
                    {
                        b'a': [b'value_a'],
                        b'c': [b'value_c'],
                    }
                ),
            ],
            ignored_attr_types=[b'b'],
        )

    def test_comments(self):
        self.check_records(
            """
            # comment #1
             with line-folding
            dn: cn=x1,cn=y1,cn=z1
            b1: value_b1
            c1: value_c1
            a1: value_a1

            # comment #2.1
            # comment #2.2
            dn: cn=x2,cn=y2,cn=z2
            b2: value_b2
            c2: value_c2
            a2: value_a2

            """,
            [
                (
                    b'cn=x1,cn=y1,cn=z1',
                    {
                        b'a1': [b'value_a1'],
                        b'b1': [b'value_b1'],
                        b'c1': [b'value_c1'],
                    }
                ),
                (
                    b'cn=x2,cn=y2,cn=z2',
                    {
                        b'a2': [b'value_a2'],
                        b'b2': [b'value_b2'],
                        b'c2': [b'value_c2'],
                    }
                ),
            ]
        )

    def test_max_entries(self):
        self.check_records(
            """
            dn: cn=x1,cn=y1,cn=z1
            b1: value_b1
            a1: value_a1

            dn: cn=x2,cn=y2,cn=z2
            b2: value_b2
            a2: value_a2

            dn: cn=x3,cn=y3,cn=z3
            b3: value_b3
            a3: value_a3

            dn: cn=x4,cn=y4,cn=z4
            b2: value_b4
            a2: value_a4

            """,
            [
                (
                    b'cn=x1,cn=y1,cn=z1',
                    {
                        b'a1': [b'value_a1'],
                        b'b1': [b'value_b1'],
                    }
                ),
                (
                    b'cn=x2,cn=y2,cn=z2',
                    {
                        b'a2': [b'value_a2'],
                        b'b2': [b'value_b2'],
                    }
                ),
            ],
            max_entries=2
        )

    def test_missing_trailing_line_separator(self):
        self.check_records(
            """
            dn: cn=x1,cn=y1,cn=z1
            first: value_a1
            middle: value_b1
            last: value_c1

            dn: cn=x2,cn=y2,cn=z2
            first: value_a2
            middle: value_b2
            last: value_c2""",
            [
                (
                    b'cn=x1,cn=y1,cn=z1',
                    {
                        b'first': [b'value_a1'],
                        b'middle': [b'value_b1'],
                        b'last': [b'value_c1'],
                    }
                ),
                (
                    b'cn=x2,cn=y2,cn=z2',
                    {
                        b'first': [b'value_a2'],
                        b'middle': [b'value_b2'],
                        b'last': [b'value_c2'],
                    }
                ),
            ],
        )

    def test_weird_empty_lines(self):
        self.check_records(
            """

            # comment before version

            version: 1


            dn: cn=x1,cn=y1,cn=z1
            first: value_a1
            middle: value_b1
            last: value_c1


            dn: cn=x2,cn=y2,cn=z2
            first: value_a2
            middle: value_b2
            last: value_c2""",
            [
                (
                    b'cn=x1,cn=y1,cn=z1',
                    {
                        b'first': [b'value_a1'],
                        b'middle': [b'value_b1'],
                        b'last': [b'value_c1'],
                    }
                ),
                (
                    b'cn=x2,cn=y2,cn=z2',
                    {
                        b'first': [b'value_a2'],
                        b'middle': [b'value_b2'],
                        b'last': [b'value_c2'],
                    }
                ),
            ],
        )

    def test_multiple_empty_lines(self):
        """
        test malformed LDIF with multiple empty lines
        """
        self.check_records(
            """
            # normal
            dn: uid=one,dc=tld
            uid: one



            # after extra empty line
            dn: uid=two,dc=tld
            uid: two

            """,
            [
                (
                    b'uid=one,dc=tld',
                    {b'uid': [b'one']}
                ),
                (
                    b'uid=two,dc=tld',
                    {b'uid': [b'two']}
                ),
            ],
        )


class TestChangeRecords(TestLDIFParser):
    """
    Various LDIF test cases
    """
    record_type='change'

    def test_empty(self):
        self.check_records(
            """
            version: 1
            """,
            [],
        )

    def test_simple(self):
        self.check_records(
            """
            version: 1

            dn: cn=x,cn=y,cn=z
            changetype: modify
            replace: attrib
            attrib: value
            attrib: value2
            -
            add: attrib2
            attrib2: value
            attrib2: value2
            -
            delete: attrib3
            attrib3: value
            -
            delete: attrib4
            -

            """,
            [
                (
                    b'cn=x,cn=y,cn=z',
                    [
                        (MOD_OP_INTEGER[b'replace'], b'attrib', [b'value', b'value2']),
                        (MOD_OP_INTEGER[b'add'], b'attrib2', [b'value', b'value2']),
                        (MOD_OP_INTEGER[b'delete'], b'attrib3', [b'value']),
                        (MOD_OP_INTEGER[b'delete'], b'attrib4', None),
                    ],
                    [],
                ),
            ],
        )

    def test_weird_empty_lines(self):
        self.check_records(
            """

            # comment before version

            version: 1


            dn: cn=x,cn=y,cn=z
            changetype: modify
            replace: attrib
            attrib: value
            attrib: value2
            -
            add: attrib2
            attrib2: value
            attrib2: value2
            -
            delete: attrib3
            attrib3: value
            -
            delete: attrib4
            -


            dn: cn=foo,cn=bar
            changetype: modify
            replace: attrib
            attrib: value
            attrib: value2
            -
            add: attrib2
            attrib2: value
            attrib2: value2
            -
            delete: attrib3
            attrib3: value
            -
            delete: attrib4""",
            [
                (
                    b'cn=x,cn=y,cn=z',
                    [
                        (MOD_OP_INTEGER[b'replace'], b'attrib', [b'value', b'value2']),
                        (MOD_OP_INTEGER[b'add'], b'attrib2', [b'value', b'value2']),
                        (MOD_OP_INTEGER[b'delete'], b'attrib3', [b'value']),
                        (MOD_OP_INTEGER[b'delete'], b'attrib4', None),
                    ],
                    [],
                ),
                (
                    b'cn=foo,cn=bar',
                    [
                        (MOD_OP_INTEGER[b'replace'], b'attrib', [b'value', b'value2']),
                        (MOD_OP_INTEGER[b'add'], b'attrib2', [b'value', b'value2']),
                        (MOD_OP_INTEGER[b'delete'], b'attrib3', [b'value']),
                        (MOD_OP_INTEGER[b'delete'], b'attrib4', None),
                    ],
                    [],
                ),
            ],
        )

    def test_missing_trailing_dash_separator(self):
        self.check_records(
            """
            version: 1

            dn: cn=x,cn=y,cn=z
            changetype: modify
            replace: attrib
            attrib: value
            attrib: value2
            -
            add: attrib2
            attrib2: value
            attrib2: value2

            """,
            [
                (
                    b'cn=x,cn=y,cn=z',
                    [
                        (MOD_OP_INTEGER[b'replace'], b'attrib', [b'value', b'value2']),
                        (MOD_OP_INTEGER[b'add'], b'attrib2', [b'value', b'value2']),
                    ],
                    [],
                ),
            ],
        )

    def test_bad_change_records(self):
        for bad_ldif_string in (
            """
            changetype: modify
            replace: attrib
            attrib: value
            attrib: value2

            """,
            """
            dn: cn=foobar
            changetype: modify
            foo: attrib
            attrib: value
            attrib: value2

            """,
            """
            dn: cn=foobar
            changetype: modify
            add: attrib
            attrib: value
            attrib: value2
            \t-

            """,
        ):
            ldif_string = textwrap.dedent(bad_ldif_string).lstrip() + '\n'
            with self.assertRaises(ValueError):
                self._parse_records(ldif_string.encode('utf-8'))

    def test_mod_increment(self):
        self.check_records(
            """
            version: 1

            dn: cn=x,cn=y,cn=z
            changetype: modify
            increment: gidNumber
            gidNumber: 1
            -

            """,
            [
                (
                    b'cn=x,cn=y,cn=z',
                    [
                        (MOD_OP_INTEGER[b'increment'], b'gidNumber', [b'1']),
                    ],
                    [],
                ),
            ],
        )


if __name__ == '__main__':
    unittest.main()

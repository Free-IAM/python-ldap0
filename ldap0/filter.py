# -*- coding: utf-8 -*-
"""
ldap0.filters - misc stuff for handling LDAP filter strings (see RFC 4515)
"""

import time
from typing import List, Sequence, Union

from .functions import strf_secs

FILTER_SPECIAL_CHARS = set('\\*()')

# map for escaping special chars in LDAP filters expect back-slash
BASIC_ESCAPE_MAP = {
    ord('*'): '\\2a',
    ord('('): '\\28',
    ord(')'): '\\29',
    ord('\x00'): '\\00',
}


def escape_bytes(assertion_value: bytes) -> str:
    """
    escape all bytes and return str (unicode)
    """
    return ''.join(['\\%02x' % char_code for char_code in assertion_value])


def escape_str(assertion_value: str) -> str:
    """
    Replace all special characters found in assertion_value
    by quoted notation.
    """
    assert isinstance(assertion_value, str), TypeError(
        'Expected assertion_value to be unicode (str), got %r' % (assertion_value,)
    )
    return assertion_value.replace('\\', '\\5c').translate(BASIC_ESCAPE_MAP)


def negate_filter(flt: str) -> str:
    """
    Returns the simple negation of flt
    """
    assert isinstance(flt, str), TypeError(
        'Expected flt to be unicode (str), got %r' % (flt,)
    )
    if flt.startswith('(!') and flt.endswith(')'):
        return flt[2:-1]
    return '(!{0})'.format(flt)


def map_filter_parts(assertion_type: str, assertion_values: Sequence[str]) -> List[str]:
    """
    returns filter parts all with same asserton type but different values
    """
    return [
        '(%s=%s)' % (assertion_type, escape_str(av))
        for av in assertion_values
    ]


def compose_filter(operand: str, filter_parts: Sequence[str]):
    """
    returns filter string composed by operand and list of sub-filters
    """
    if not filter_parts:
        return ''
    if len(filter_parts) == 1:
        return filter_parts[0]
    return '(%s%s)' % (
        operand,
        ''.join(filter_parts),
    )


def dict_filter(
        entry,
        iop: str = '&',
        oop: str = '&',
    ) -> str:
    """
    returns a filter compose from an entry dictionary

    iop
       inner operand used for attribute value list
    oop
       outer operand used for all attributes
    """
    filter_parts = []
    for attr_type, attr_values in entry.items():
        filter_parts.append(
            compose_filter(
                iop,
                map_filter_parts(attr_type, attr_values)
            )
        )
    if len(filter_parts) == 1:
        return filter_parts[0]
    return compose_filter(oop, filter_parts)


def time_span_filter(
        filterstr: str = '',
        from_timestamp: Union[int, float] = 0,
        until_timestamp: Union[int, float, None] = None,
        delta_attr: str = 'modifyTimestamp',
    ):
    """
    If last_run_timestr is non-zero filterstr will be extended
    """
    if until_timestamp is None:
        until_timestamp = time.time()
        if from_timestamp < 0:
            from_timestamp = until_timestamp + from_timestamp
    if from_timestamp > until_timestamp:
        raise ValueError('from_timestamp %r must not be greater than until_timestamp %r' % (
            from_timestamp, until_timestamp
        ))
    return (
        '(&'
        '{filterstr}'
        '({delta_attr}>={from_timestr})'
        '(!({delta_attr}>={until_timestr}))'
        ')'
    ).format(
        filterstr=filterstr,
        delta_attr=delta_attr,
        from_timestr=strf_secs(from_timestamp),
        until_timestr=strf_secs(until_timestamp),
    )
    # end of time_span_filter()

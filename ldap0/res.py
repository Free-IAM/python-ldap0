# -*- coding: utf-8 -*-
"""
ldap0.res - basic classes for LDAP results
"""

from typing import List, Optional, Union

import _libldap0

from .dn import DNObj
from .base import decode_list
from .ldapurl import LDAPUrl
from .typehints import EntryBytes, EntryMixed, EntryStr
from .controls import ResponseControl
from .extop import IntermediateResponse, INTERMEDIATE_RESPONSE_REGISTRY

__all__ = [
    'LDAPResult',
    'SearchReference',
    'SearchResultEntry',
]


class SearchReference:
    """
    LDAP search continuation objects
    """
    __slots__ = (
        'ctrls',
        'encoding',
        '_ref_urls_b',
        '_ref_urls_o',
        '_ref_urls_s',
    )
    _ref_urls_s: Optional[List[str]]
    _ref_urls_o: Optional[List[LDAPUrl]]

    def __init__(self, entry: List[bytes], ctrls=None, encoding: str = 'utf-8'):
        self.encoding = encoding
        self._ref_urls_b = entry
        self._ref_urls_s = self._ref_urls_o = None
        self.ctrls = ctrls

    def __repr__(self) -> str:
        return '%s(%r, %r, encoding=%r)' % (
            self.__class__.__name__,
            self._ref_urls_b,
            self.ctrls,
            self.encoding,
        )

    @property
    def ref_url_strings(self) -> List[str]:
        if self._ref_urls_s is None:
            self._ref_urls_s = decode_list(self._ref_urls_b, encoding=self.encoding)
        return self._ref_urls_s

    @property
    def ref_ldap_urls(self) -> List[LDAPUrl]:
        if self._ref_urls_o is None:
            self._ref_urls_o = [LDAPUrl(url) for url in self.ref_url_strings]
        return self._ref_urls_o


class SearchResultEntry:
    """
    LDAP search result objects
    """
    __slots__ = (
        'ctrls',
        'dn_b',
        '_dn_o',
        '_dn_s',
        'encoding',
        '_entry_as',
        '_entry_b',
        '_entry_s',
    )
    dn_b: bytes
    _dn_s: Optional[str]
    _dn_o: Optional[DNObj]
    _entry_b: EntryBytes
    _entry_as: Optional[EntryMixed]
    _entry_s: Optional[EntryStr]

    def __init__(self, dn: bytes, entry: EntryBytes, ctrls=None, encoding: str = 'utf-8'):
        self.encoding = encoding
        self.dn_b = dn
        self._dn_s = self._dn_o = None
        self._entry_b = entry
        self._entry_as = self._entry_s = None
        self.ctrls = ctrls or []

    def __repr__(self) -> str:
        return '%s(%r, %r, %r, encoding=%r)' % (
            self.__class__.__name__,
            self.dn_b,
            self._entry_b,
            self.ctrls,
            self.encoding,
        )

    def __eq__(self, other):
        return (
            self.dn_s == other.dn_s
            and self.entry_as == other.entry_as
            and self.ctrls == other.ctrls
        )

    @property
    def dn_s(self):
        if self._dn_s is None:
            self._dn_s = self.dn_b.decode(self.encoding)
        return self._dn_s

    @property
    def dn_o(self):
        if self._dn_o is None:
            self._dn_o = DNObj.from_str(self.dn_s)
        return self._dn_o

    @property
    def entry_b(self) -> EntryBytes:
        return self._entry_b

    @property
    def entry_as(self) -> EntryMixed:
        if self._entry_as is None:
            self._entry_as: EntryMixed = {
                at.decode('ascii'): avs
                for at, avs in self._entry_b.items()
            }
        return self._entry_as

    @property
    def entry_s(self) -> EntryStr:
        if self._entry_s is None:
            self._entry_s: EntryStr = {
                at.decode('ascii'): [av.decode(self.encoding) for av in avs]
                for at, avs in self._entry_b.items()
            }
        return self._entry_s


class LDAPResult:
    """
    base class for LDAP result objects
    """
    __slots__ = (
        'rtype',
        'rdata',
        'msgid',
        'ctrls',
        'call_args',
    )
    rtype: int
    rdata: List[Union[SearchReference, SearchResultEntry, IntermediateResponse]]
    msgid: int
    ctrls: List[ResponseControl]

    def __init__(self, rtype: int, rdata, msgid: int, ctrls, encoding: str = 'utf-8', call_args=None):
        self.rtype = rtype
        self.rdata = []
        self.msgid = msgid
        self.ctrls = ctrls or []
        self.call_args = call_args
        for dn, entry, ctrls in rdata or []:
            if rtype == _libldap0.RES_SEARCH_REFERENCE:
                self.rdata.append(SearchReference(entry, ctrls, encoding=encoding))
            elif rtype == _libldap0.RES_SEARCH_ENTRY:
                self.rdata.append(SearchResultEntry(dn, entry, ctrls, encoding=encoding))
            elif rtype == _libldap0.RES_INTERMEDIATE:
                respoid = dn.decode(encoding)
                resp_class = INTERMEDIATE_RESPONSE_REGISTRY.get(respoid, IntermediateResponse)
                response = resp_class(respoid, encodedResponseValue=entry, ctrls=ctrls)
                self.rdata.append(response)
            else:
                raise NotImplementedError

    def __repr__(self) -> str:
        return '%s(%r, %r, %r, %r)' % (
            self.__class__.__name__,
            self.rtype,
            self.rdata,
            self.msgid,
            self.ctrls,
        )

# -*- coding: utf-8 -*-
"""
ldap0.res - basic classes for LDAP results
"""

from .dn import DNObj
from .base import decode_list
from .ldapurl import LDAPUrl


__all__ = [
    'LDAPResult',
    'SearchReference',
    'SearchResultEntry',
]


class SearchReference:
    """
    LDAP search continuation objects
    """

    def __init__(self, entry, ctrls=None, encoding='utf-8'):
        self.encoding = encoding
        self._ref_urls_b = entry
        self._ref_urls_s = self._ref_urls_o = None
        self.ctrls = ctrls

    def __repr__(self):
        return '%s(%r, %r, encoding=%r)' % (
            self.__class__.__name__,
            self._ref_urls_b,
            self.ctrls,
            self.encoding,
        )

    @property
    def ref_url_strings(self):
        if self._ref_urls_s is None:
            self._ref_urls_s = decode_list(self._ref_urls_b, encoding=self.encoding)
        return self._ref_urls_s

    @property
    def ref_ldap_urls(self):
        if self._ref_urls_o is None:
            self._ref_urls_o = [LDAPUrl(url) for url in self.ref_url_strings]
        return self._ref_urls_o


class SearchResultEntry:
    """
    LDAP search result objects
    """

    def __init__(self, dn, entry, ctrls=None, encoding='utf-8'):
        self.encoding = encoding
        self.dn_b = dn
        self._dn_s = self._dn_o = None
        self._entry_b = entry
        self._entry_as = self._entry_s = None
        self.ctrls = ctrls

    def __repr__(self):
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
    def entry_b(self):
        return self._entry_b

    @property
    def entry_as(self):
        if self._entry_as is None:
            self._entry_as =  {
                at.decode('ascii'): avs
                for at, avs in self._entry_b.items()
            }
        return self._entry_as

    @property
    def entry_s(self):
        if self._entry_s is None:
            self._entry_s =  {
                at.decode('ascii'): [av.decode(self.encoding) for av in avs]
                for at, avs in self._entry_b.items()
            }
        return self._entry_s


class LDAPResult:
    """
    base class for LDAP result objects
    """
    
    def __init__(self, rtype, rdata, msgid, ctrls, encoding='utf-8'):
        if rdata is None:
            data = None
        else:
            data = []
            for dn, entry, ctrls in rdata:
                if dn is None:                    
                    data.append(SearchReference(entry, ctrls, encoding=encoding))
                else:
                    data.append(SearchResultEntry(dn, entry, ctrls, encoding=encoding))
        self.rtype = rtype
        self.rdata = data
        self.msgid = msgid
        self.ctrls = ctrls

    def __repr__(self):
        return '%s(%r, %r, %r, %r)' % (self.__class__.__name__, self.rtype, self.rdata, self.msgid, self.ctrls)

# -*- coding: utf-8 -*-
"""
ldap0.ldapurl - handling of LDAP URLs as described in RFC 4516
"""

from typing import List, Optional

from urllib.parse import (
    quote as url_quote,
    unquote as url_unquote,
)
from collections import UserDict

__all__ = [
    # constants
    'SEARCH_SCOPE',
    'SEARCH_SCOPE_STR',
    'LDAP_SCOPE_BASE',
    'LDAP_SCOPE_ONELEVEL',
    'LDAP_SCOPE_SUBTREE',
    # functions
    'is_ldapurl',
    # classes
    'LDAPUrlExtension',
    'LDAPUrlExtensions',
    'LDAPUrl'
]

LDAP_SCOPE_BASE = 0
LDAP_SCOPE_ONELEVEL = 1
LDAP_SCOPE_SUBTREE = 2
LDAP_SCOPE_SUBORDINATES = 3

LDAPURL_SCHEMES = {
    'ldap',
    'ldaps',
    'ldapi',
}

SEARCH_SCOPE_STR = {
    None: '',
    LDAP_SCOPE_BASE: 'base',
    LDAP_SCOPE_ONELEVEL: 'one',
    LDAP_SCOPE_SUBTREE: 'sub',
    LDAP_SCOPE_SUBORDINATES: 'subordinates',
}

SEARCH_SCOPE = {
    '': None,
    # the search scope strings defined in RFC 4516
    'base': LDAP_SCOPE_BASE,
    'one': LDAP_SCOPE_ONELEVEL,
    'sub': LDAP_SCOPE_SUBTREE,
    # from draft-sermersheim-ldap-subordinate-scope
    'subordinates': LDAP_SCOPE_SUBORDINATES,
}


def is_ldapurl(val):
    """
    Returns True if s is a LDAP URL, False else
    """
    try:
        scheme, _ = val.split('://', 1)
    except ValueError:
        return False
    return scheme.lower() in LDAPURL_SCHEMES


def escape_str(val: str) -> str:
    """
    Returns URL encoding of val
    """
    return url_quote(val, safe='', encoding='utf-8').replace('/', '%2F')


class LDAPUrlExtension:
    """
    Class for parsing and unparsing LDAP URL extensions
    as described in RFC 4516.

    Usable class attributes:
      critical
            Boolean integer marking the extension as critical
      extype
            Type of extension
      exvalue
            Value of extension
    """
    critical: bool
    extype: Optional[str]
    exvalue: Optional[str]

    def __init__(
            self,
            extensionStr: Optional[str] = None,
            critical: bool = False,
            extype: Optional[str] = None,
            exvalue: Optional[str] = None
        ):
        self.critical = critical
        self.extype = extype
        self.exvalue = exvalue
        if extensionStr:
            self._parse(extensionStr)

    def _parse(self, extension: str):
        extension = extension.strip()
        if not extension:
            # Don't parse empty strings
            self.extype, self.exvalue = None, None
            return
        self.critical = extension[0] == '!'
        if extension[0] == '!':
            extension = extension[1:].strip()
        try:
            self.extype, self.exvalue = extension.split('=', 1)
        except ValueError:
            # No value, just the extype
            self.extype, self.exvalue = extension, None
        else:
            self.exvalue = url_unquote(self.exvalue.strip(), encoding='utf-8')
        self.extype = self.extype.strip()

    def unparse(self) -> str:
        """
        generate string representation of single LDAP URL extension
        """
        if self.exvalue is None:
            return '%s%s' % ('!'*bool(self.critical), self.extype)
        return '%s%s=%s' % (
            '!'*bool(self.critical),
            self.extype,
            escape_str(self.exvalue or ''),
        )

    def __str__(self) -> str:
        return self.unparse()

    def __repr__(self) -> str:
        return '<%s.%s instance at %s: %s>' % (
            self.__class__.__module__,
            self.__class__.__name__,
            hex(id(self)),
            self.__dict__
        )

    def __eq__(self, other) -> bool:
        return \
            (self.critical == other.critical) and \
            (self.extype == other.extype) and \
            (self.exvalue == other.exvalue)

    def __ne__(self, other) -> bool:
        return not self.__eq__(other)


class LDAPUrlExtensions(UserDict):
    """
    Models a collection of LDAP URL extensions as
    dictionary type
    """

    def __init__(self, default: Optional[LDAPUrlExtension] = None):
        UserDict.__init__(self)
        for key, val in (default or {}).items():
            self[key] = val

    def __setitem__(self, name: str, value: LDAPUrlExtension):
        """
        value
            Either LDAPUrlExtension instance, (critical,exvalue)
            or string'ed exvalue
        """
        assert isinstance(value, LDAPUrlExtension)
        assert name == value.extype
        self.data[name] = value

    def values(self):
        return [
            self[key]
            for key in self.keys()
        ]

    def __str__(self) -> str:
        return ','.join(map(str, self.values()))

    def __repr__(self) -> str:
        return '<%s.%s instance at %s: %s>' % (
            self.__class__.__module__,
            self.__class__.__name__,
            hex(id(self)),
            self.data
        )

    def __eq__(self, other) -> bool:
        assert isinstance(other, self.__class__), TypeError(
            "other has to be instance of %s" % (self.__class__)
        )
        return self.data == other.data

    def parse(self, extListStr):
        """
        parse string into list of LDAPURLExtension instances
        """
        for extension_str in extListStr.strip().split(','):
            if extension_str:
                ext = LDAPUrlExtension(extension_str)
                self[ext.extype] = ext

    def unparse(self) -> str:
        """
        return comma-separated string representation of LDAP URL extensions
        """
        return ','.join([val.unparse() for val in self.values()])


class LDAPUrl:
    """
    Class for parsing and unparsing LDAP URLs
    as described in RFC 4516.

    Usable class attributes:
      urlscheme
          URL scheme (either ldap, ldaps or ldapi)
      hostport
          LDAP host (default '')
      dn
          String holding distinguished name (default '')
      attrs
          list of attribute types (default None)
      scope
          integer search scope for ldap-module
      filterstr
          String representation of LDAP Search Filters
          (see RFC 4515)
      extensions
          Dictionary used as extensions store
      who
          Maps automagically to bindname LDAP URL extension
      cred
          Maps automagically to X-BINDPW LDAP URL extension
    """

    attr2extype = {
        'who': 'bindname',
        'cred': 'X-BINDPW',
        'trace_level': 'trace',
        'pwd_filename': 'x-pwdfilename',
        'sasl_mech': 'x-saslmech',
        'sasl_authzid': 'x-saslauthzid',
        'sasl_realm': 'x-saslrealm',
        'start_tls': 'x-starttls',
    }
    urlscheme: Optional[str]
    hostport: Optional[str]
    dn: Optional[str]
    attrs: Optional[List[str]]
    scope: Optional[int]
    filterstr: Optional[str]
    extensions: Optional[LDAPUrlExtensions]

    def __init__(
            self,
            ldapUrl: Optional[str] = None,
            urlscheme: str = 'ldap',
            hostport: str = '',
            dn: str = '',
            attrs=None,
            scope=None,
            filterstr=None,
            extensions=None,
            who=None,
            cred=None,
        ):
        self.urlscheme = urlscheme
        self.hostport = hostport
        self.dn = dn
        self.attrs = attrs
        self.scope = scope
        self.filterstr = filterstr
        self.extensions = (extensions or LDAPUrlExtensions())
        if ldapUrl is not None:
            self._parse(ldapUrl)
        if who is not None:
            self.who = who
        if cred is not None:
            self.cred = cred

    def __eq__(self, other) -> bool:
        return \
            self.urlscheme == other.urlscheme and \
            self.hostport == other.hostport and \
            self.dn == other.dn and \
            self.attrs == other.attrs and \
            self.scope == other.scope and \
            self.filterstr == other.filterstr and \
            self.extensions == other.extensions

    def __ne__(self, other) -> bool:
        return not self.__eq__(other)

    def _parse(self, ldap_url):
        """
        parse a LDAP URL and set the class attributes
        urlscheme,host,dn,attrs,scope,filterstr,extensions
        """
        if not is_ldapurl(ldap_url):
            raise ValueError('Value %r for ldap_url does not seem to be a LDAP URL.' % (ldap_url))
        scheme, rest = ldap_url.split('://', 1)
        self.urlscheme = scheme.strip()
        if not self.urlscheme in LDAPURL_SCHEMES:
            raise ValueError('LDAP URL contains unsupported URL scheme %s.' % (self.urlscheme))
        slash_pos = rest.find('/')
        qemark_pos = rest.find('?')
        if (slash_pos == -1) and (qemark_pos == -1):
            # No / and ? found at all
            self.hostport = url_unquote(rest, encoding='utf-8')
            self.dn = ''
            return
        if slash_pos != -1 and (qemark_pos == -1 or (slash_pos < qemark_pos)):
            # Slash separates DN from hostport
            self.hostport = url_unquote(rest[:slash_pos], encoding='utf-8')
            # Eat the slash from rest
            rest = rest[slash_pos+1:]
        elif qemark_pos != 1 and (slash_pos == -1 or (slash_pos > qemark_pos)):
            # Question mark separates hostport from rest, DN is assumed to be empty
            self.hostport = url_unquote(rest[:qemark_pos], encoding='utf-8')
            # Do not eat question mark
            rest = rest[qemark_pos:]
        else:
            raise ValueError('Something completely weird happened!')
        paramlist = rest.split('?', 4)
        paramlist_len = len(paramlist)
        if paramlist_len >= 1:
            self.dn = url_unquote(paramlist[0], encoding='utf-8').strip()
        if (paramlist_len >= 2) and (paramlist[1]):
            self.attrs = url_unquote(paramlist[1].strip(), encoding='utf-8').split(',')
        if paramlist_len >= 3:
            scope = paramlist[2].strip()
            try:
                self.scope = SEARCH_SCOPE[scope]
            except KeyError:
                raise ValueError('Invalid search scope %r' % (scope,))
        if paramlist_len >= 4:
            filterstr = paramlist[3].strip()
            if not filterstr:
                self.filterstr = None
            else:
                self.filterstr = url_unquote(filterstr, encoding='utf-8')
        if paramlist_len >= 5:
            if paramlist[4]:
                self.extensions = LDAPUrlExtensions()
                self.extensions.parse(paramlist[4])
            else:
                self.extensions = None
        return

    def connect_uri(self) -> str:
        """
        Returns LDAP URL suitable to be passed to
        ldap0.ldapobject.LDAPObject()
        """
        if self.urlscheme == 'ldapi':
            # hostport part might contain slashes when ldapi:// is used
            hostport = escape_str(self.hostport)
        else:
            hostport = self.hostport
        return '%s://%s' % (self.urlscheme, hostport)

    def unparse(self) -> str:
        """
        Returns LDAP URL depending on class attributes set.
        """
        if self.attrs is None:
            attrs_str = ''
        else:
            attrs_str = ','.join(self.attrs)
        scope_str = SEARCH_SCOPE_STR[self.scope]
        if self.filterstr is None:
            filterstr = ''
        else:
            filterstr = escape_str(self.filterstr)
        dn = escape_str(self.dn)
        if self.urlscheme == 'ldapi':
            # hostport part might contain slashes when ldapi:// is used
            hostport = escape_str(self.hostport)
        else:
            hostport = self.hostport
        ldap_url = '%s://%s/%s?%s?%s?%s' % (
            self.urlscheme,
            hostport,
            dn,
            attrs_str,
            scope_str,
            filterstr,
        )
        if self.extensions:
            ldap_url = ldap_url+'?'+self.extensions.unparse()
        return ldap_url

    def htmlHREF(
            self,
            urlPrefix='',
            hrefText=None,
            hrefTarget=None
        ) -> str:
        """
        Returns a string with HTML link for this LDAP URL.

        urlPrefix
            Prefix before LDAP URL (e.g. for addressing another web-based client)
        hrefText
            link text/description
        hrefTarget
            string added as link target attribute
        """
        assert isinstance(urlPrefix, str), TypeError("urlPrefix must be str, was %r" % urlPrefix)
        if hrefText is None:
            hrefText = self.unparse()
        assert isinstance(hrefText, str), TypeError("hrefText must be str, was %r" % hrefText)
        if hrefTarget is None:
            target = ''
        else:
            assert isinstance(hrefTarget, str), TypeError("hrefTarget must be str, was %r" % hrefTarget)
            target = ' target="%s"' % hrefTarget
        return '<a%s href="%s%s">%s</a>' % (
            target,
            urlPrefix,
            self.unparse(),
            hrefText,
        )

    def __str__(self) -> str:
        return self.unparse()

    def __repr__(self) -> str:
        return '%s.%s(%r)' % (
            self.__class__.__module__,
            self.__class__.__name__,
            self.__str__(),
        )

    def __getattr__(self, name):
        if name in self.attr2extype:
            extype = self.attr2extype[name]
            if self.extensions and \
               extype in self.extensions and \
               not self.extensions[extype].exvalue is None:
                result = url_unquote(self.extensions[extype].exvalue, encoding='utf-8')
            else:
                return None
        else:
            raise AttributeError('%s has no attribute %s' % (
                self.__class__.__name__,
                name,
            ))
        return result # __getattr__()

    def __setattr__(self, name, value):
        if name in self.attr2extype:
            extype = self.attr2extype[name]
            if value is None:
                # A value of None means that extension is deleted
                delattr(self, name)
            elif value is not None:
                # Add appropriate extension
                self.extensions[extype] = LDAPUrlExtension(
                    extype=extype,
                    exvalue=url_unquote(value, encoding='utf-8'),
                )
        else:
            self.__dict__[name] = value

    def __delattr__(self, name):
        if name in self.attr2extype:
            extype = self.attr2extype[name]
            if self.extensions:
                try:
                    del self.extensions[extype]
                except KeyError:
                    pass
        else:
            del self.__dict__[name]

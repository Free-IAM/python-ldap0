# -*- coding: utf-8 -*-
"""
ldap0.openldap -- OpenLDAP-specific stuff
"""

from typing import Optional, Set

from .ldapurl import LDAPUrl
from .ldapurl import SEARCH_SCOPE as LDAPURL_SEARCH_SCOPE
from .functions import attr_set

__all__ = [
    'SyncReplDesc',
    'ldapsearch_cmd',
]

LDAPSEARCH_TMPL = (
    'ldapsearch '
    '-LL '
    '-H "{uri}" '
    '{tls} '
    '-b "{dn}" '
    '-s {scope} '
    '{authc} '
    '{authz} '
    '"{filterstr}" '
    '{attrs}'
)


def ldapsearch_cmd(ldap_url: LDAPUrl) -> str:
    """
    Returns string with OpenLDAP compatible ldapsearch command based on LDAPUrl instance.
    """
    if ldap_url.attrs is None:
        attrs_str = ''
    else:
        attrs_str = ' '.join(ldap_url.attrs)
    scope_str = {
        0: 'base',
        1: 'one',
        2: 'sub',
        3: 'children',
    }[ldap_url.scope]
    if ldap_url.sasl_mech:
        authc_str = '-Y "{saslmech}"'.format(saslmech=ldap_url.sasl_mech)
    elif ldap_url.who:
        authc_str = '-x -D "{who}" -W'.format(who=ldap_url.who or '')
    else:
        authc_str = '-x -D "" -w ""'
    if ldap_url.start_tls:
        tls_str = '-ZZ'
    else:
        tls_str = ''
    if ldap_url.sasl_authzid:
        authz_str = '-X "{authz}"'.format(authz=ldap_url.sasl_authzid)
    else:
        authz_str = ''
    if ldap_url.extensions:
        # FIX ME! Set extended controls
        pass
    return LDAPSEARCH_TMPL.format(
        uri=ldap_url.connect_uri(),
        dn=ldap_url.dn,
        scope=scope_str,
        attrs=attrs_str,
        filterstr=ldap_url.filterstr or '(objectClass=*)',
        authc=authc_str,
        authz=authz_str,
        tls=tls_str,
    ).strip()
    # end of ldapsearch_cmd()


class SyncReplDesc:
    """
    Parser class for OpenLDAP syncrepl directives
    """
    known_keywords = (
        'attrs',
        'attrsonly',
        'authcid',
        'authzid',
        'binddn',
        'bindmethod',
        'credentials',
        'exattrs',
        'filter',
        'interval',
        'keepalive',
        'logbase',
        'logfilter',
        'network-timeout',
        'provider',
        'realm',
        'retry',
        'rid',
        'saslmech',
        'schemachecking',
        'scope',
        'searchbase',
        'secprops',
        'sizelimit',
        'starttls',
        'suffixmassage',
        'syncdata',
        'timelimit',
        'timeout',
        'tls_cacert',
        'tls_cacertdir',
        'tls_cert',
        'tls_cipher_suite',
        'tls_crlcheck',
        'tls_key',
        'tls_reqcert',
        'tls_protocol_min',
        'tls_reqsan',
        'type',
    )
    enum_args = {
        'bindmethod': {'simple', 'sasl'},
        'scope': {'sub', 'one', 'base', 'subord'},
        'starttls': {'no', 'demand', 'critical'},
        'syncdata': {'default', 'accesslog', 'changelog'},
        'tls_crlcheck': {'none', 'peer', 'all'},
        'tls_reqcert': {'never', 'allow', 'try', 'demand'},
        'tls_reqsan': {'never', 'allow', 'try', 'demand'},
        'type': {'refreshonly', 'refreshandpersist'},
    }
    sanitize_func = {
        'attrs': attr_set,
        'exattrs': attr_set,
        'timeout': int,
        'network-timeout': int,
        'sizelimit': int,
        'timelimit': int,
        'bindmethod': str.lower,
        'saslmech': str.upper,
    }
    attrs: Optional[Set[str]]
    attrsonly: Optional[str]
    authcid: Optional[str]
    authzid: Optional[str]
    binddn: Optional[str]
    bindmethod: Optional[str]
    credentials: Optional[str]
    exattrs: Optional[Set[str]]
    filter: Optional[str]
    interval: Optional[str]
    keepalive: Optional[str]
    logbase: Optional[str]
    logfilter: Optional[str]
    network_timeout: Optional[int]
    provider: Optional[str]
    realm: Optional[str]
    retry: Optional[str]
    rid: Optional[str]
    saslmech: Optional[str]
    schemachecking: Optional[str]
    scope: Optional[int]
    searchbase: Optional[str]
    secprops: Optional[str]
    sizelimit: Optional[int]
    starttls: Optional[str]
    suffixmassage: Optional[str]
    syncdata: Optional[str]
    timelimit: Optional[int]
    timeout: Optional[int]
    tls_cacert: Optional[str]
    tls_cacertdir: Optional[str]
    tls_cert: Optional[str]
    tls_cipher_suite: Optional[str]
    tls_crlcheck: Optional[str]
    tls_key: Optional[str]
    tls_reqcert: Optional[str]
    tls_protocol_min: Optional[str]
    type: Optional[str]

    def __init__(self, syncrepl_statement: str):
        """
        syncrepl_statement
           syncrepl statement without any line breaks
        """
        # strip all white spaces from syncrepl statement parameters
        syncrepl_statement = syncrepl_statement.strip()
        # Set class attributes for all known keywords
        for keyword in self.known_keywords:
            setattr(self, keyword.replace('-', '_'), None)
        parts = []
        for keyword in self.known_keywords:
            k_pos = syncrepl_statement.find(keyword+'=')
            if k_pos == 0 or (k_pos > 0 and syncrepl_statement[k_pos-1] == ' '):
                parts.append(k_pos)
        parts.sort()
        parts_len = len(parts)
        for ind in range(parts_len):
            if ind == parts_len-1:
                next_pos = len(syncrepl_statement)
            else:
                next_pos = parts[ind+1]
            key, val = syncrepl_statement[parts[ind]:next_pos].split('=', 1)
            key = key.strip()
            val = val.strip()
            if val[0] == '"' and val[-1] == '"':
                val = val[1:-1]
            if key in self.sanitize_func:
                val = self.sanitize_func[key](val)
            if key in self.enum_args and val.lower() not in self.enum_args[key]:
                raise ValueError('%r not in %r, was %r' % (
                    key, self.enum_args[key], val
                ))
            setattr(self, key.replace('-', '_'), val)
        # transform scope
        if self.scope is not None:
            self.scope = LDAPURL_SEARCH_SCOPE[self.scope]

    def __repr__(self) -> str:
        return '%s(rid=%s)' % (self.__class__.__name__, self.rid)

    def ldap_url(self) -> LDAPUrl:
        """
        Return ldapurl.LDAPUrl object representing some syncrepl parameters
        as close as possible.
        """
        ldap_url = LDAPUrl(self.provider)
        ldap_url.dn = self.searchbase
        ldap_url.scope = self.scope
        ldap_url.filterstr = self.filter
        ldap_url.who = self.authcid or self.binddn
        ldap_url.cred = self.credentials
        ldap_url.attrs = list(self.attrs or ['*', '+'])
        return ldap_url

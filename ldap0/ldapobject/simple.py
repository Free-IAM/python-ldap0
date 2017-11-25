# -*- coding: utf-8 -*-
"""
ldap0.ldapobject - wraps class _ldap0.LDAPObject
"""

from __future__ import absolute_import

import sys
import time
from os import strerror

if __debug__:
    # Tracing is only supported in debugging mode
    import pprint
    import traceback

from ldap0.pkginfo import __version__, __author__, __license__

import _libldap0
from _libldap0 import LDAPError

import ldap0
import ldap0.functions

from ldap0.schema.subentry import SCHEMA_ATTRS
from ldap0.controls import DecodeControlTuples, RequestControlTuples
from ldap0.controls.openldap import SearchNoOpControl
from ldap0.sasl import SaslNoninteractiveAuth
from ldap0.modlist import addModlist


__all__ = [
    'SimpleLDAPObject',
    'NO_UNIQUE_ENTRY',
]


class NO_UNIQUE_ENTRY(_libldap0.NO_SUCH_OBJECT):
    """
    Exception raised if a LDAP search returned more than entry entry
    although assumed to return a unique single search result.
    """


class SimpleLDAPObject:
    """
    Wrapper class around _libldap0.LDAPObject
    """

    CLASSATTR_OPTION_MAPPING = {
        "protocol_version": _libldap0.OPT_PROTOCOL_VERSION,
        "deref": _libldap0.OPT_DEREF,
        "referrals": _libldap0.OPT_REFERRALS,
        "timelimit": _libldap0.OPT_TIMELIMIT,
        "sizelimit": _libldap0.OPT_SIZELIMIT,
        "network_timeout": _libldap0.OPT_NETWORK_TIMEOUT,
        "error_number": _libldap0.OPT_ERROR_NUMBER,
        "error_string": _libldap0.OPT_ERROR_STRING,
        "matched_dn": _libldap0.OPT_MATCHED_DN,
    }

    def __init__(
            self,
            uri,
            trace_level=0,
            trace_file=None,
            trace_stack_limit=5
        ):
        self._trace_level = trace_level
        self._trace_file = trace_file or sys.stdout
        self._trace_stack_limit = trace_stack_limit
        self._uri = uri
        self._ldap_object_lock = self._ldap_lock('opcall')
        self._l = ldap0.functions._ldap_function_call(
            ldap0._ldap_module_lock,
            _libldap0.initialize,
            self._uri,
        )
        self.timeout = -1
        self.protocol_version = _libldap0.VERSION3

    def _ldap_lock(self, desc=''):
        if _libldap0.LIBLDAP_R:
            return ldap0.LDAPLock(desc='%s within %r' % (desc, self))
        return ldap0._ldap_module_lock

    def _ldap_call(self, func, *args, **kwargs):
        """
        Wrapper method mainly for serializing calls into OpenLDAP libs
        and trace logs
        """
        self._ldap_object_lock.acquire()
        if __debug__:
            if self._trace_level >= 1:
                self._trace_file.write('*** %s %s - %s\n%s\n' % (
                    repr(self),
                    self._uri,
                    '.'.join((self.__class__.__name__, func.__name__)),
                    pprint.pformat((args, kwargs))
                ))
                if self._trace_level >= 9:
                    traceback.print_stack(limit=self._trace_stack_limit, file=self._trace_file)
        diagnostic_message_success = None
        try:
            try:
                result = func(*args, **kwargs)
                if __debug__ and self._trace_level >= 2:
                    if func.__name__ != "unbind_ext":
                        diagnostic_message_success = self._l.get_option(_libldap0.OPT_DIAGNOSTIC_MESSAGE)
            finally:
                self._ldap_object_lock.release()
        except LDAPError as e:
            exc_type, exc_value, exc_traceback = sys.exc_info()
            try:
                if 'info' not in e.args[0] and 'errno' in e.args[0]:
                    e.args[0]['info'] = strerror(e.args[0]['errno'])
            except IndexError:
                pass
            if __debug__ and self._trace_level >= 2:
                self._trace_file.write(
                    '=> LDAPError - %s: %s\n' % (e.__class__.__name__, e)
                )
            raise exc_type, exc_value, exc_traceback
        else:
            if __debug__ and self._trace_level >= 2:
                if not diagnostic_message_success is None:
                    self._trace_file.write(
                        '=> diagnosticMessage: %r\n' % (diagnostic_message_success)
                    )
                self._trace_file.write('=> result:\n%s\n' % (pprint.pformat(result)))
        return result

    def __setattr__(self, name, value):
        if name in self.CLASSATTR_OPTION_MAPPING:
            self.set_option(self.CLASSATTR_OPTION_MAPPING[name], value)
        else:
            self.__dict__[name] = value

    def __getattr__(self, name):
        if name in self.CLASSATTR_OPTION_MAPPING:
            return self.get_option(self.CLASSATTR_OPTION_MAPPING[name])
        elif name in self.__dict__:
            return self.__dict__[name]
        else:
            raise AttributeError('%s has no attribute %r' % (
                self.__class__.__name__,
                name
            ))

    def fileno(self):
        return self.get_option(_libldap0.OPT_DESC)

    def abandon(
            self,
            msgid,
            serverctrls=None,
            clientctrls=None
        ):
        return self._ldap_call(
            self._l.abandon_ext,
            msgid,
            RequestControlTuples(serverctrls),
            RequestControlTuples(clientctrls)
        )

    def cancel(
            self,
            cancelid,
            serverctrls=None,
            clientctrls=None
        ):
        return self._ldap_call(
            self._l.cancel,
            cancelid,
            RequestControlTuples(serverctrls),
            RequestControlTuples(clientctrls)
        )

    def cancel_s(
            self,
            cancelid,
            serverctrls=None,
            clientctrls=None
        ):
        msgid = self.cancel(cancelid, serverctrls, clientctrls)
        try:
            res = self.result(msgid, all=1, timeout=self.timeout)
        except (_libldap0.CANCELLED, _libldap0.SUCCESS):
            res = None
        return res

    def add(self, dn, modlist, serverctrls=None, clientctrls=None):
        if isinstance(modlist, dict):
            modlist = addModlist(modlist)
        return self._ldap_call(
            self._l.add_ext,
            dn,
            modlist,
            RequestControlTuples(serverctrls),
            RequestControlTuples(clientctrls)
        )

    def add_s(self, dn, modlist, serverctrls=None, clientctrls=None):
        msgid = self.add(dn, modlist, serverctrls, clientctrls)
        resp_type, resp_data, resp_msgid, resp_ctrls, _, _ = self.result(
            msgid,
            all=1,
            timeout=self.timeout
        )
        return resp_type, resp_data, resp_msgid, resp_ctrls

    def simple_bind(
            self,
            who='',
            cred='',
            serverctrls=None,
            clientctrls=None
        ):
        return self._ldap_call(
            self._l.simple_bind,
            who,
            cred,
            RequestControlTuples(serverctrls),
            RequestControlTuples(clientctrls)
        )

    def simple_bind_s(
            self,
            who='',
            cred='',
            serverctrls=None,
            clientctrls=None
        ):
        msgid = self.simple_bind(who, cred, serverctrls, clientctrls)
        resp_type, resp_data, resp_msgid, resp_ctrls, _, _ = self.result(
            msgid,
            all=1,
            timeout=self.timeout
        )
        return resp_type, resp_data, resp_msgid, resp_ctrls

    def bind(self, who, cred, method=_libldap0.AUTH_SIMPLE):
        assert method == _libldap0.AUTH_SIMPLE, ValueError(
            'Only simple bind method supported, but method was %r' % (method)
        )
        return self.simple_bind(who, cred)

    def bind_s(self, who, cred, method=_libldap0.AUTH_SIMPLE):
        msgid = self.bind(who, cred, method)
        return self.result(msgid, all=1, timeout=self.timeout)

    def sasl_interactive_bind_s(
            self,
            who,
            auth,
            serverctrls=None,
            clientctrls=None,
            sasl_flags=_libldap0.SASL_QUIET
        ):
        return self._ldap_call(
            self._l.sasl_interactive_bind_s,
            who,
            auth,
            RequestControlTuples(serverctrls),
            RequestControlTuples(clientctrls),
            sasl_flags
        )

    def sasl_non_interactive_bind_s(
            self,
            sasl_mech,
            serverctrls=None,
            clientctrls=None,
            sasl_flags=_libldap0.SASL_QUIET,
            authz_id=''
        ):
        auth = SaslNoninteractiveAuth(
            sasl_mech,
            authz_id=authz_id,
        )
        self.sasl_interactive_bind_s(
            '',
            auth,
            serverctrls,
            clientctrls,
            sasl_flags
        )

    def sasl_external_bind_s(
            self,
            serverctrls=None,
            clientctrls=None,
            sasl_flags=_libldap0.SASL_QUIET,
            authz_id=''
        ):
        self.sasl_non_interactive_bind_s(
            'EXTERNAL',
            serverctrls,
            clientctrls,
            sasl_flags,
            authz_id
        )

    def sasl_gssapi_bind_s(
            self,
            serverctrls=None,
            clientctrls=None,
            sasl_flags=_libldap0.SASL_QUIET,
            authz_id=''
        ):
        self.sasl_non_interactive_bind_s(
            'GSSAPI',
            serverctrls,
            clientctrls,
            sasl_flags,
            authz_id
        )

    def sasl_bind_s(self, dn, mechanism, cred, serverctrls=None, clientctrls=None):
        return self._ldap_call(
            self._l.sasl_bind_s,
            dn,
            mechanism,
            cred,
            RequestControlTuples(serverctrls),
            RequestControlTuples(clientctrls)
        )

    def compare(self, dn, attr, value, serverctrls=None, clientctrls=None):
        return self._ldap_call(
            self._l.compare_ext, dn,
            attr,
            value,
            RequestControlTuples(serverctrls),
            RequestControlTuples(clientctrls),
        )

    def compare_s(self, dn, attr, value, serverctrls=None, clientctrls=None):
        msgid = self.compare(dn, attr, value, serverctrls, clientctrls)
        try:
            ldap_res = self.result(
                msgid,
                all=1,
                timeout=self.timeout
            )
        except _libldap0.COMPARE_TRUE:
            return True
        except _libldap0.COMPARE_FALSE:
            return False
        raise _libldap0.PROTOCOL_ERROR(
            'Compare operation returned wrong result: %r' % (ldap_res)
        )

    def delete(self, dn, serverctrls=None, clientctrls=None):
        return self._ldap_call(
            self._l.delete_ext,
            dn,
            RequestControlTuples(serverctrls),
            RequestControlTuples(clientctrls)
        )

    def delete_s(self, dn, serverctrls=None, clientctrls=None):
        msgid = self.delete(dn, serverctrls, clientctrls)
        resp_type, resp_data, resp_msgid, resp_ctrls, _, _ = self.result(
            msgid,
            all=1,
            timeout=self.timeout
        )
        return resp_type, resp_data, resp_msgid, resp_ctrls

    def extop(self, extreq, serverctrls=None, clientctrls=None):
        return self._ldap_call(
            self._l.extop,
            extreq.requestName,
            extreq.encodedRequestValue(),
            RequestControlTuples(serverctrls),
            RequestControlTuples(clientctrls)
        )

    def extop_result(self, msgid=_libldap0.RES_ANY, all=1, timeout=None):
        resulttype, msg, msgid, respctrls, respoid, respvalue = self.result(
            msgid,
            all=1,
            timeout=self.timeout,
            add_ctrls=1,
            add_intermediates=1,
            add_extop=1
        )
        return (respoid, respvalue)

    def extop_s(self, extreq, serverctrls=None, clientctrls=None, extop_resp_class=None):
        msgid = self.extop(extreq, serverctrls, clientctrls)
        res = self.extop_result(msgid, all=1, timeout=self.timeout)
        if extop_resp_class:
            respoid, respvalue = res
            if extop_resp_class.responseName != respoid:
                raise _libldap0.PROTOCOL_ERROR(
                    "Wrong OID in extended response! Expected %s, got %s" % (
                        extop_resp_class.responseName,
                        respoid
                    )
                )
            return extop_resp_class(extop_resp_class.responseName, respvalue)
        else:
            return res

    def modify(self, dn, modlist, serverctrls=None, clientctrls=None):
        return self._ldap_call(
            self._l.modify_ext, dn,
            modlist,
            RequestControlTuples(serverctrls),
            RequestControlTuples(clientctrls)
        )

    def modify_s(self, dn, modlist, serverctrls=None, clientctrls=None):
        msgid = self.modify(dn, modlist, serverctrls, clientctrls)
        resp_type, resp_data, resp_msgid, resp_ctrls, _, _ = self.result(
            msgid,
            all=1,
            timeout=self.timeout
        )
        return resp_type, resp_data, resp_msgid, resp_ctrls

    def modrdn(self, dn, newrdn, delold=1):
        return self.rename(dn, newrdn, None, delold)

    def modrdn_s(self, dn, newrdn, delold=1):
        return self.rename_s(dn, newrdn, None, delold)

    def passwd(self, user, oldpw, newpw, serverctrls=None, clientctrls=None):
        return self._ldap_call(
            self._l.passwd,
            user,
            oldpw,
            newpw,
            RequestControlTuples(serverctrls),
            RequestControlTuples(clientctrls)
        )

    def passwd_s(self, user, oldpw, newpw, serverctrls=None, clientctrls=None):
        msgid = self.passwd(user, oldpw, newpw, serverctrls, clientctrls)
        return self.extop_result(msgid, all=1, timeout=self.timeout)

    def rename(
            self,
            dn,
            newrdn,
            newsuperior=None,
            delold=1,
            serverctrls=None,
            clientctrls=None
        ):
        return self._ldap_call(
            self._l.rename,
            dn,
            newrdn,
            newsuperior,
            delold,
            RequestControlTuples(serverctrls),
            RequestControlTuples(clientctrls)
        )

    def rename_s(
            self,
            dn,
            newrdn,
            newsuperior=None,
            delold=1,
            serverctrls=None,
            clientctrls=None
        ):
        msgid = self.rename(dn, newrdn, newsuperior, delold, serverctrls, clientctrls)
        resp_type, resp_data, resp_msgid, resp_ctrls, _, _ = self.result(
            msgid,
            all=1,
            timeout=self.timeout
        )
        return resp_type, resp_data, resp_msgid, resp_ctrls

    def result(
            self, msgid=_libldap0.RES_ANY,
            all=1,
            timeout=None,
            add_ctrls=0,
            add_intermediates=0,
            add_extop=0,
            resp_ctrl_classes=None
        ):
        if timeout is None:
            timeout = self.timeout
        ldap_result = self._ldap_call(
            self._l.result,
            msgid,
            all,
            timeout,
            add_ctrls,
            add_intermediates,
            add_extop
        )
        if ldap_result is None:
            resp_type, resp_data, resp_msgid, resp_ctrls, resp_name, resp_value = (
                None, None, None, None, None, None
            )
        else:
            if len(ldap_result) == 4:
                resp_type, resp_data, resp_msgid, resp_ctrls = ldap_result
                resp_name, resp_value = None, None
            else:
                resp_type, resp_data, resp_msgid, resp_ctrls, resp_name, resp_value = ldap_result
            if add_ctrls:
                resp_data = [
                    (t, r, DecodeControlTuples(c, resp_ctrl_classes))
                    for t, r, c in resp_data
                ]
        decoded_resp_ctrls = DecodeControlTuples(resp_ctrls, resp_ctrl_classes)
        return resp_type, resp_data, resp_msgid, decoded_resp_ctrls, resp_name, resp_value

    def search(
            self,
            base,
            scope,
            filterstr='(objectClass=*)',
            attrlist=None,
            attrsonly=0,
            serverctrls=None,
            clientctrls=None,
            timeout=-1,
            sizelimit=0
        ):
        return self._ldap_call(
            self._l.search_ext,
            base,
            scope,
            filterstr,
            attrlist,
            attrsonly,
            RequestControlTuples(serverctrls),
            RequestControlTuples(clientctrls),
            timeout,
            sizelimit,
        )

    def search_s(
            self,
            base,
            scope,
            filterstr='(objectClass=*)',
            attrlist=None,
            attrsonly=0,
            serverctrls=None,
            clientctrls=None,
            timeout=-1,
            sizelimit=0
        ):
        msgid = self.search(
            base,
            scope,
            filterstr,
            attrlist,
            attrsonly,
            serverctrls,
            clientctrls,
            timeout,
            sizelimit
        )
        return self.result(msgid, all=1, timeout=timeout)[1]

    def noop_search(
            self,
            base,
            scope=_libldap0.SCOPE_SUBTREE,
            filterstr='(objectClass=*)',
            serverctrls=None,
            clientctrls=None,
            timeout=-1,
            sizelimit=0,
        ):
        serverctrls = serverctrls or []
        serverctrls.append(SearchNoOpControl(criticality=True))
        try:
            msg_id = self.search(
                base,
                scope,
                filterstr=filterstr,
                attrlist=['1.1'],
                serverctrls=serverctrls,
                clientctrls=clientctrls,
                timeout=timeout,
                sizelimit=sizelimit,
            )
            _, _, _, search_response_ctrls, _, _ = self.result(
                msg_id,
                all=1,
                timeout=timeout,
            )
        except (
                _libldap0.TIMEOUT,
                _libldap0.TIMELIMIT_EXCEEDED,
                _libldap0.SIZELIMIT_EXCEEDED,
                _libldap0.ADMINLIMIT_EXCEEDED
            ) as err:
            self.abandon(msg_id)
            raise err
        else:
            noop_srch_ctrl = [
                c
                for c in search_response_ctrls
                if c.controlType == SearchNoOpControl.controlType
            ]
            if noop_srch_ctrl:
                return noop_srch_ctrl[0].numSearchResults, noop_srch_ctrl[0].numSearchContinuations
            return (None, None)

    def start_tls_s(self):
        return self._ldap_call(self._l.start_tls_s)

    def unbind(self, serverctrls=None, clientctrls=None):
        res = self._ldap_call(
            self._l.unbind_ext,
            RequestControlTuples(serverctrls),
            RequestControlTuples(clientctrls),
        )
        try:
            del self._l
        except AttributeError:
            pass
        return res

    def unbind_s(self, serverctrls=None, clientctrls=None):
        msgid = self.unbind(serverctrls, clientctrls)
        if msgid != None:
            result = self.result(msgid, all=1, timeout=self.timeout)
        else:
            result = None
        if __debug__ and self._trace_level >= 1:
            try:
                self._trace_file.flush()
            except AttributeError:
                pass
        return result

    def whoami_s(self, serverctrls=None, clientctrls=None):
        return self._ldap_call(self._l.whoami_s, serverctrls, clientctrls)

    def get_option(self, option):
        result = self._ldap_call(self._l.get_option, option)
        if option == _libldap0.OPT_SERVER_CONTROLS or option == _libldap0.OPT_CLIENT_CONTROLS:
            result = DecodeControlTuples(result)
        return result

    def set_option(self, option, invalue):
        if option == _libldap0.OPT_SERVER_CONTROLS or option == _libldap0.OPT_CLIENT_CONTROLS:
            invalue = RequestControlTuples(invalue)
        return self._ldap_call(self._l.set_option, option, invalue)

    def search_subschemasubentry_s(self, dn=''):
        try:
            r = self.search_s(
                dn,
                _libldap0.SCOPE_BASE,
                '(objectClass=*)',
                attrlist=['subschemaSubentry'],
            )
        except (
                _libldap0.NO_SUCH_OBJECT,
                _libldap0.NO_SUCH_ATTRIBUTE,
                _libldap0.INSUFFICIENT_ACCESS,
            ):
            r = []
        except _libldap0.UNDEFINED_TYPE:
            return None
        try:
            if r:
                e = ldap0.cidict.cidict(r[0][1])
                search_subschemasubentry_dn = e.get('subschemaSubentry', [None])[0]
                if search_subschemasubentry_dn is None:
                    if dn:
                        # Try to find sub schema sub entry in root DSE
                        return self.search_subschemasubentry_s(dn='')
                    else:
                        # If dn was already root DSE we can return here
                        return None
                return search_subschemasubentry_dn
        except IndexError:
            return None

    def read_s(
            self,
            dn,
            filterstr=None,
            attrlist=None,
            serverctrls=None,
            clientctrls=None,
            timeout=-1
        ):
        r = self.search_s(
            dn,
            _libldap0.SCOPE_BASE,
            filterstr or '(objectClass=*)',
            attrlist=attrlist,
            serverctrls=serverctrls,
            clientctrls=clientctrls,
            timeout=timeout,
        )
        if r:
            return r[0][1]
        else:
            return None

    def read_subschemasubentry_s(self, subschemasubentry_dn, attrs=None):
        try:
            subschemasubentry = self.read_s(
                subschemasubentry_dn,
                filterstr='(objectClass=subschema)',
                attrlist=attrs or SCHEMA_ATTRS
            )
        except _libldap0.NO_SUCH_OBJECT:
            return None
        else:
            return subschemasubentry

    def find_unique_entry(
            self,
            base,
            scope=_libldap0.SCOPE_SUBTREE, filterstr='(objectClass=*)',
            attrlist=None,
            attrsonly=0,
            serverctrls=None,
            clientctrls=None,
            timeout=-1
        ):
        r = self.search_s(
            base,
            scope,
            filterstr,
            attrlist=attrlist or ['*'],
            attrsonly=attrsonly,
            serverctrls=serverctrls,
            clientctrls=clientctrls,
            timeout=timeout,
            sizelimit=2,
        )
        if len(r) != 1:
            raise NO_UNIQUE_ENTRY('No or non-unique search result for %r' % (filterstr))
        return r[0]

    def read_rootdse_s(self, filterstr='(objectClass=*)', attrlist=None):
        ldap_rootdse = self.read_s(
            '',
            filterstr=filterstr,
            attrlist=attrlist or ['*', '+'],
        )
        return ldap_rootdse  # read_rootdse_s()

    def get_naming_contexts(self):
        return self.read_rootdse_s(
            attrlist=['namingContexts']
        ).get('namingContexts', [])

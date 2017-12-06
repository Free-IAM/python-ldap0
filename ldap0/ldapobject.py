# -*- coding: utf-8 -*-
"""
ldap0.ldapobject - wrapper classes above _libldap0.LDAPObject
"""

from __future__ import absolute_import

import sys
import time
from os import strerror

if __debug__:
    # Tracing is only supported in debugging mode
    import pprint
    import traceback

import _libldap0
from _libldap0 import LDAPError

from ldap0.pkginfo import __version__, __author__, __license__
import ldap0
import ldap0.functions
from ldap0.schema.subentry import SCHEMA_ATTRS
from ldap0.controls import DecodeControlTuples, RequestControlTuples
from ldap0.controls.openldap import SearchNoOpControl
from ldap0.extop.dds import RefreshRequest, RefreshResponse
from ldap0.extop.whoami import WhoAmIRequest, WhoAmIResponse
from ldap0.sasl import SaslNoninteractiveAuth
from ldap0.modlist import add_modlist

__all__ = [
    'NO_UNIQUE_ENTRY',
    'LDAPObject',
    'LDAPObject',
    'ReconnectLDAPObject',
]


class NO_UNIQUE_ENTRY(_libldap0.NO_SUCH_OBJECT):
    """
    Exception raised if a LDAP search returned more than entry entry
    although assumed to return a unique single search result.
    """


class LDAPObject:
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
            trace_stack_limit=5,
            cache_ttl=0.0,
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
        self.cache_ttl = cache_ttl
        self.flush_cache()

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

    def __enter__(self):
        return self

    def __exit__(self, *args):
        try:
            self.unbind_s()
        except LDAPError:
            pass

    def set_tls_options(
            self,
            cacert_filename=None,
            client_cert_filename=None,
            client_key_filename=None,
        ):
        """
        set TLS options for connection even with checking whether cert/key
        files are readable
        """
        # Set path names of TLS related files
        for tls_option, tls_pathname in (
                (_libldap0.OPT_X_TLS_CACERTFILE, cacert_filename),
                (_libldap0.OPT_X_TLS_CERTFILE, client_cert_filename),
                (_libldap0.OPT_X_TLS_KEYFILE, client_key_filename),
            ):
            try:
                if not tls_pathname:
                    # get global default
                    tls_pathname = _libldap0.get_option(tls_option)
                if tls_pathname:
                    # Check whether CA cert file can be read
                    open(tls_pathname, 'rb')
                    self._l.set_option(tls_option, tls_pathname)
            except ValueError, value_error:
                if sys.platform != 'darwin' and \
                   str(value_error) != 'ValueError: option error':
                    raise
        # Force server cert validation
        self._l.set_option(_libldap0.OPT_X_TLS_REQUIRE_CERT, _libldap0.OPT_X_TLS_DEMAND)
        # this has to be the last option set to let libldap reinitialize TLS context
        self._l.set_option(_libldap0.OPT_X_TLS_NEWCTX, 0)
        return # set_tls_options()

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
        self.uncache(dn)
        if isinstance(modlist, dict):
            modlist = add_modlist(modlist)
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
        self.flush_cache()
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
        self.flush_cache()
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

    def sasl_bind_s(self, dn, mechanism, cred, serverctrls=None, clientctrls=None):
        self.flush_cache()
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
        self.uncache(dn)
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
        self.uncache(dn)
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
        self.uncache(user)
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

    def results(self, msgid, timeout=-1, add_ctrls=False):
        """
        Generator method which returns an iterator for processing all LDAP
        operation results of the given msgid like retrieved with
        LDAPObject.result()
        """
        result_type, result_list, result_msgid, result_serverctrls, _, _ = \
            self.result(
                msgid,
                0,
                timeout,
                add_ctrls=add_ctrls
            )
        while result_type and result_list:
            yield (
                result_type,
                result_list,
                result_msgid,
                result_serverctrls
            )
            result_type, result_list, result_msgid, result_serverctrls, _, _ = \
                self.result(
                    msgid,
                    0,
                    timeout,
                    add_ctrls=add_ctrls
                )
        return # results()

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

    def cache_hit_ratio(self):
        """
        Returns percentage of cache hit ratio
        """
        try:
            return (
                100 * float(self._cache_hits) /
                float(self._cache_hits+self._cache_misses)
            )
        except ZeroDivisionError:
            return None

    def flush_cache(self):
        """
        reset/flush the internal cache
        """
        self._cache_misses = 0
        self._cache_hits = 0
        self._cache = {}

    def uncache(self, entry_dn):
        """
        remove all cached entries related to dn from internal cache
        """
        entry_dn = entry_dn.lower()
        for cache_key_args, cached_results in self._cache.items():
            if cache_key_args[0].lower() == entry_dn:
                del self._cache[cache_key_args]
            else:
                for cached_dn, _ in cached_results[1]:
                    if not cached_dn is None and cached_dn.lower() == entry_dn:
                        del self._cache[cache_key_args]
                        break # stop looping through results

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
            sizelimit=0,
            cache_ttl=None,
            add_ctrls=False,
        ):
        """
        caching variant of LDAPObject.search_ext_s()
        """
        if cache_ttl is None:
            cache_ttl = self.cache_ttl
        current_time = time.time()
        if cache_ttl > 0:
            cache_key_args = (
                base,
                scope,
                filterstr,
                tuple(attrlist or []),
                attrsonly,
                tuple([
                    c.encodeControlValue()
                    for c in serverctrls or []
                ]),
                tuple(clientctrls or []),
                timeout,
                sizelimit,
                add_ctrls,
            )
            # first look into cache for non-expired search results
            try:
                result_cache_time, resp_type, resp_data, resp_msgid, resp_ctrls, _, _ = self._cache[cache_key_args]
            except KeyError:
                pass
            else:
                if current_time > result_cache_time + cache_ttl:
                    # cache entry is expired => remove it no matter what happens later
                    del self._cache[cache_key_args]
                else:
                    self._cache_hits += 1
                    return resp_data
        # no cached result
        self._cache_misses += 1
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
        resp_type, resp_data, resp_msgid, resp_ctrls, _, _ = self.result(
            msgid, all=1,
            timeout=timeout,
            add_ctrls=add_ctrls
        )
        if self.cache_ttl > 0:
            # store result in cache if caching is enabled at all
            self._cache[cache_key_args] = (
                current_time,
                resp_type, resp_data, resp_msgid, resp_ctrls, _, _
            )
        return resp_data # search_s()

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
        wai = self.extop_s(
            WhoAmIRequest(),
            extop_resp_class=WhoAmIResponse,
            serverctrls=serverctrls,
            clientctrls=clientctrls,
        )
        return wai.responseValue

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

    def refresh(self, dn, ttl=None):
        self.uncache(dn)
        return self.extop(RefreshRequest(entryName=dn, requestTtl=ttl))

    def refresh_s(self, dn, ttl=None):
        self.uncache(dn)
        res = self.extop_s(
            RefreshRequest(entryName=dn, requestTtl=ttl),
            extop_resp_class=RefreshResponse,
        )
        return res.responseTtl

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
        """
        convenience wrapper around read_s() for reading rootDSE
        """
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


class ReconnectLDAPObject(LDAPObject):
    """
    In case of server failure (_libldap0.SERVER_DOWN) the implementations
    of all synchronous operation methods (search_s() etc.) are doing
    an automatic reconnect and rebind and will retry the very same
    operation.

    This is very handy for broken LDAP server implementations
    (e.g. in Lotus Domino) which drop connections very often making
    it impossible to have a long-lasting control flow in the
    application.
    """

    __transient_attrs__ = set([
        '_l',
        '_ldap_object_lock',
        '_trace_file',
        '_reconnect_lock',
        '_last_bind',
    ])

    def __init__(
            self,
            uri,
            trace_level=0,
            trace_file=None,
            trace_stack_limit=5,
            cache_ttl=0.0,
            retry_max=1,
            retry_delay=60.0,
        ):
        """
        Parameters like LDAPObject.__init__() with these
        additional arguments:

        retry_max
            Maximum count of reconnect trials
        retry_delay
            Time span to wait between two reconnect trials
        """
        self._uri = uri
        self._options = []
        self._last_bind = None
        LDAPObject.__init__(
            self,
            uri,
            trace_level=trace_level,
            trace_file=trace_file,
            trace_stack_limit=trace_stack_limit,
            cache_ttl=cache_ttl,
        )
        self._reconnect_lock = ldap0.LDAPLock(desc='reconnect lock within %r' % self)
        self._retry_max = retry_max
        self._retry_delay = retry_delay
        self._start_tls = 0
        self._reconnects_done = 0

    def __getstate__(self):
        """
        return data representation for pickled object
        """
        state = dict([
            (key, val)
            for key, val in self.__dict__.items()
            if key not in self.__transient_attrs__
        ])
        state['_last_bind'] = (
            self._last_bind[0].__name__,
            self._last_bind[1],
            self._last_bind[2],
        )
        return state

    def __setstate__(self, data):
        """
        set up the object from pickled data
        """
        self.__dict__.update(data)
        self._last_bind = (
            getattr(LDAPObject, self._last_bind[0]),
            self._last_bind[1],
            self._last_bind[2],
        )
        self._ldap_object_lock = self._ldap_lock()
        self._reconnect_lock = ldap0.LDAPLock(desc='reconnect lock within %r' % (self))
        self._trace_file = sys.stdout
        self.reconnect(self._uri)

    def _store_last_bind(self, method, *args, **kwargs):
        self._last_bind = (method, args, kwargs)

    def _apply_last_bind(self):
        if self._last_bind != None:
            func, args, kwargs = self._last_bind
            func(self, *args, **kwargs)
        else:
            # Send explicit anon simple bind request to provoke
            # _libldap0.SERVER_DOWN in method reconnect()
            LDAPObject.simple_bind_s(self, '', '')

    def _restore_options(self):
        """
        Restore all recorded options
        """
        for key, val in self._options:
            LDAPObject.set_option(self, key, val)

    def passwd_s(self, *args, **kwargs):
        return self._apply_method_s(LDAPObject.passwd_s, *args, **kwargs)

    def reconnect(self, uri, retry_max=1, retry_delay=60.0):
        """
        Drop and clean up old connection completely and reconnect
        """
        self._reconnect_lock.acquire()
        try:
            reconnect_counter = retry_max
            while reconnect_counter:
                counter_text = '%d. (of %d)' % (retry_max-reconnect_counter+1, retry_max)
                if __debug__ and self._trace_level >= 1:
                    self._trace_file.write('*** Trying %s reconnect to %s...\n' % (
                        counter_text, uri
                    ))
                try:
                    # Do the connect
                    self._l = ldap0.functions._ldap_function_call(
                        ldap0._ldap_module_lock,
                        _libldap0.initialize,
                        uri
                    )
                    self._restore_options()
                    # StartTLS extended operation in case this was called before
                    if self._start_tls:
                        LDAPObject.start_tls_s(self)
                    # Repeat last simple or SASL bind
                    self._apply_last_bind()
                except (_libldap0.SERVER_DOWN, _libldap0.TIMEOUT) as ldap_error:
                    if __debug__ and self._trace_level >= 1:
                        self._trace_file.write('*** %s reconnect to %s failed\n' % (
                            counter_text, uri
                        ))
                    reconnect_counter = reconnect_counter-1
                    if not reconnect_counter:
                        raise ldap_error
                    if __debug__ and self._trace_level >= 1:
                        self._trace_file.write('=> delay %s...\n' % (retry_delay))
                    time.sleep(retry_delay)
                    LDAPObject.unbind_s(self)
                else:
                    if __debug__ and self._trace_level >= 1:
                        self._trace_file.write(
                            '*** %s reconnect to %s successful => repeat last operation\n' % (
                                counter_text,
                                uri,
                            )
                        )
                    self._reconnects_done += 1
                    break
        finally:
            self._reconnect_lock.release()
        return # reconnect()

    def _apply_method_s(self, func, *args, **kwargs):
        if not hasattr(self, '_l'):
            self.reconnect(self._uri, retry_max=self._retry_max, retry_delay=self._retry_delay)
        try:
            return func(self, *args, **kwargs)
        except _libldap0.SERVER_DOWN:
            LDAPObject.unbind_s(self)
            # Try to reconnect
            self.reconnect(self._uri, retry_max=self._retry_max, retry_delay=self._retry_delay)
            # Re-try last operation
            return func(self, *args, **kwargs)

    def set_option(self, option, invalue):
        self._options.append((option, invalue))
        return LDAPObject.set_option(self, option, invalue)

    def bind_s(self, *args, **kwargs):
        res = self._apply_method_s(LDAPObject.bind_s, *args, **kwargs)
        self._store_last_bind(LDAPObject.bind_s, *args, **kwargs)
        return res

    def simple_bind_s(self, *args, **kwargs):
        res = self._apply_method_s(LDAPObject.simple_bind_s, *args, **kwargs)
        self._store_last_bind(LDAPObject.simple_bind_s, *args, **kwargs)
        return res

    def start_tls_s(self, *args, **kwargs):
        res = self._apply_method_s(LDAPObject.start_tls_s, *args, **kwargs)
        self._start_tls = 1
        return res

    def sasl_interactive_bind_s(self, *args, **kwargs):
        """
        sasl_interactive_bind_s(who, auth) -> None
        """
        res = self._apply_method_s(LDAPObject.sasl_interactive_bind_s, *args, **kwargs)
        self._store_last_bind(LDAPObject.sasl_interactive_bind_s, *args, **kwargs)
        return res

    def sasl_bind_s(self, *args, **kwargs):
        res = self._apply_method_s(LDAPObject.sasl_bind_s, *args, **kwargs)
        self._store_last_bind(LDAPObject.sasl_bind_s, *args, **kwargs)
        return res

    def add_s(self, *args, **kwargs):
        return self._apply_method_s(LDAPObject.add_s, *args, **kwargs)

    def cancel_s(self, *args, **kwargs):
        return self._apply_method_s(LDAPObject.cancel_s, *args, **kwargs)

    def compare_s(self, *args, **kwargs):
        return self._apply_method_s(LDAPObject.compare_s, *args, **kwargs)

    def delete_s(self, *args, **kwargs):
        return self._apply_method_s(LDAPObject.delete_s, *args, **kwargs)

    def extop_s(self, *args, **kwargs):
        return self._apply_method_s(LDAPObject.extop_s, *args, **kwargs)

    def modify_s(self, *args, **kwargs):
        return self._apply_method_s(LDAPObject.modify_s, *args, **kwargs)

    def rename_s(self, *args, **kwargs):
        return self._apply_method_s(LDAPObject.rename_s, *args, **kwargs)

    def search_s(self, *args, **kwargs):
        return self._apply_method_s(LDAPObject.search_s, *args, **kwargs)

    def whoami_s(self, *args, **kwargs):
        return self._apply_method_s(LDAPObject.whoami_s, *args, **kwargs)

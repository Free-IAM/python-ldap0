# -*- coding: utf-8 -*-
"""
ldap0.ldapobject - wrapper classes above _libldap0.LDAPObject
"""

import sys
import time
import logging
from os import strerror

import _libldap0
from _libldap0 import LDAPError

import ldap0
from .__about__ import __version__, __author__, __license__
from .err import \
    PasswordPolicyChangeAfterReset, \
    PasswordPolicyExpirationWarning, \
    PasswordPolicyExpiredError
from .err import NoUniqueEntry
from .base import encode_list
from .res import SearchResultEntry, LDAPResult
from .lock import LDAPLock
from .functions import _libldap0_function_call
from .schema.subentry import SCHEMA_ATTRS
from .controls import decode_response_ctrls, encode_request_ctrls
from .controls.openldap import SearchNoOpControl
from .controls.ppolicy import PasswordPolicyControl
from .extop import ExtendedResponse
from .extop.dds import RefreshRequest, RefreshResponse
from .extop.whoami import WhoAmIRequest, WhoAmIResponse
from .extop.passmod import PassmodRequest, PassmodResponse
from .extop.cancel import CancelRequest
from .sasl import SaslNoninteractiveAuth
from .modlist import add_modlist
from .ldapurl import LDAPUrl

if __debug__:
    # Tracing is only supported in debugging mode
    import pprint

__all__ = [
    'LDAPObject',
    'LDAPObject',
    'ReconnectLDAPObject',
]

NO_FINAL_RESULT_TYPES = {_libldap0.RES_SEARCH_ENTRY, _libldap0.RES_SEARCH_REFERENCE, _libldap0.RES_INTERMEDIATE}

#-----------------------------------------------------------------------
# the real connection classes
#-----------------------------------------------------------------------

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
    encoding = 'utf-8'

    def __init__(
            self,
            uri,
            trace_level=0,
            cache_ttl=0.0,
        ):
        self._trace_level = trace_level
        if isinstance(uri, str):
            ldap_url = LDAPUrl(uri)
        elif isinstance(uri, LDAPUrl):
            ldap_url = uri
        else:
            raise TypeError('Expected uri to be of type LDAPUrl or str, got %r' % (uri))
        self._libldap0_lock = LDAPLock(
            '_libldap0_lock in %r' % self,
            trace_level=self._trace_level,
        )
        self.uri = None
        conn_uri = ldap_url.connect_uri()
        self._l = _libldap0_function_call(_libldap0.initialize, conn_uri.encode('ascii'))
        self._msgid_funcs = {
            self._l.add_ext,
            self._l.simple_bind,
            self._l.compare_ext,
            self._l.delete_ext,
            self._l.extop,
            self._l.modify_ext,
            self._l.rename,
            self._l.search_ext,
            self._l.unbind_ext,
        }
        self._outstanding_requests = {}
        self.uri = conn_uri
        self._whoami_dn = None
        self.timeout = -1
        self.protocol_version = _libldap0.VERSION3
        self.cache_ttl = cache_ttl
        self.flush_cache()
        self.set_option(_libldap0.OPT_RESTART, False)
        self.set_option(_libldap0.OPT_DEREF, False)
        self.set_option(_libldap0.OPT_REFERRALS, False)
        self.set_option(_libldap0.OPT_X_TLS_REQUIRE_CERT, _libldap0.OPT_X_TLS_HARD)

    def _ldap_call(self, func, *args, **kwargs):
        """
        Wrapper method mainly for serializing calls into OpenLDAP libs
        and trace logs
        """
        with self._libldap0_lock:
            if __debug__:
                if self._trace_level >= 1:
                    logging.debug(
                        '%r %s - %s.%s(%s)',
                        self,
                        self.uri,
                        self.__class__.__name__,
                        func.__name__,
                        pprint.pformat((args, kwargs)),
                        exc_info=(self._trace_level >= 9),
                    )
            try:
                result = func(*args, **kwargs)
            except LDAPError as ldap_err:
                if hasattr(ldap_err, 'args') \
                   and ldap_err.args \
                   and 'info' not in ldap_err.args[0] \
                   and 'errno' in ldap_err.args[0]:
                    ldap_err.args[0]['info'] = strerror(ldap_err.args[0]['errno'])
                if __debug__ and self._trace_level >= 2:
                    logging.debug(
                        '-> LDAPError - %s',
                        ldap_err,
                    )
                raise ldap_err
            if __debug__ and self._trace_level >= 2 and func.__name__ != "unbind_ext":
                diag_msg_ok = self._l.get_option(_libldap0.OPT_DIAGNOSTIC_MESSAGE)
                if diag_msg_ok:
                    logging.debug(
                        '-> diagnosticMessage: %r',
                        diag_msg_ok,
                    )
                logging.debug('-> %s', pprint.pformat(result))
        if func in self._msgid_funcs:
            if __debug__:
                self._outstanding_requests[result] = (func, args, kwargs)
            else:
                self._outstanding_requests[result] = (func,)
        return result

    def __setattr__(self, name, value):
        if name in self.CLASSATTR_OPTION_MAPPING:
            self.set_option(self.CLASSATTR_OPTION_MAPPING[name], value)
        else:
            self.__dict__[name] = value

    def __getattr__(self, name):
        if name in self.CLASSATTR_OPTION_MAPPING:
            return self.get_option(self.CLASSATTR_OPTION_MAPPING[name])
        if name in self.__dict__:
            return self.__dict__[name]
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
            req_cert=_libldap0.OPT_X_TLS_DEMAND,
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
                    with open(tls_pathname, 'rb'):
                        pass
                    self._l.set_option(tls_option, tls_pathname)
            except ValueError as value_error:
                if sys.platform != 'darwin' and \
                   str(value_error) != 'ValueError: option error':
                    raise
        # Force server cert validation
        self._l.set_option(_libldap0.OPT_X_TLS_REQUIRE_CERT, req_cert)
        # this has to be the last option set to let libldap reinitialize TLS context
        self._l.set_option(_libldap0.OPT_X_TLS_NEWCTX, 0)
        # end of set_tls_options()

    def fileno(self):
        return self.get_option(_libldap0.OPT_DESC)

    def abandon(self, msgid, req_ctrls=None):
        if msgid not in self._outstanding_requests:
            raise ldap0.NO_SUCH_OPERATION('Unexpected msgid value %s' % (msgid,))
        res = self._ldap_call(
            self._l.abandon_ext,
            msgid,
            encode_request_ctrls(req_ctrls),
        )
        del self._outstanding_requests[msgid]
        return res

    def cancel(self, cancelid, req_ctrls=None):
        if cancelid not in self._outstanding_requests:
            raise ldap0.NO_SUCH_OPERATION('Unexpected cancelid value %s' % (cancelid,))
        return self.extop(
            CancelRequest(cancelid),
            req_ctrls=req_ctrls,
        )

    def cancel_s(self, cancelid, req_ctrls=None):
        try:
            msgid = self.cancel(cancelid, req_ctrls=req_ctrls)
            res = self.result(msgid, _libldap0.MSG_ALL, self.timeout)
            assert res.rtype == _libldap0.RES_EXTENDED, ValueError('Wrong result type %d' % (res.rtype,))
            return res
        except _libldap0.CANCELLED:
            pass
        del self._outstanding_requests[cancelid]

    def add(self, dn, entry, req_ctrls=None):
        self.uncache(dn)
        entry = add_modlist(entry)
        return self._ldap_call(
            self._l.add_ext,
            dn.encode(self.encoding),
            entry,
            encode_request_ctrls(req_ctrls),
        )

    def add_s(self, dn, entry, req_ctrls=None):
        msgid = self.add(dn, entry, req_ctrls)
        res = self.result(msgid, _libldap0.MSG_ALL, self.timeout)
        assert res.rtype == _libldap0.RES_ADD, ValueError('Wrong result type %d' % (res.rtype,))
        return res

    def simple_bind(self, who='', cred=b'', req_ctrls=None):
        self.flush_cache()
        return self._ldap_call(
            self._l.simple_bind,
            who.encode(self.encoding),
            cred,
            encode_request_ctrls(req_ctrls),
        )

    def simple_bind_s(self, who='', cred=b'', req_ctrls=None):
        msgid = self.simple_bind(who, cred, req_ctrls)
        res = self.result(msgid, _libldap0.MSG_ALL, self.timeout)
        assert res.rtype == _libldap0.RES_BIND, ValueError('Wrong result type %d' % (res.rtype,))
        if res.ctrls:
            # Extract the password policy response control and raise
            # appropriate exceptions if needed
            ppolicy_ctrls = [
                c
                for c in res.ctrls
                if c.controlType == PasswordPolicyControl.controlType
            ]
            if ppolicy_ctrls and len(ppolicy_ctrls) == 1:
                ppolicy_ctrl = ppolicy_ctrls[0]
                if ppolicy_ctrl.error == 2:
                    raise PasswordPolicyChangeAfterReset(
                        who=who,
                        desc='Password change is needed after reset!',
                    )
                if ppolicy_ctrl.timeBeforeExpiration is not None:
                    raise PasswordPolicyExpirationWarning(
                        who=who,
                        desc='Password will expire in %d seconds!' % (
                            ppolicy_ctrl.timeBeforeExpiration
                        ),
                        timeBeforeExpiration=ppolicy_ctrl.timeBeforeExpiration,
                    )
                if ppolicy_ctrl.graceAuthNsRemaining is not None:
                    raise PasswordPolicyExpiredError(
                        who=who,
                        desc='Password expired! %d grace logins left.' % (
                            ppolicy_ctrl.graceAuthNsRemaining
                        ),
                        graceAuthNsRemaining=ppolicy_ctrl.graceAuthNsRemaining,
                    )
        return res

    def sasl_interactive_bind_s(
            self,
            sasl_mech,
            auth,
            req_ctrls=None,
            sasl_flags=_libldap0.SASL_QUIET
        ):
        self.flush_cache()
        return self._ldap_call(
            self._l.sasl_interactive_bind_s,
            sasl_mech.encode('ascii'),
            auth,
            encode_request_ctrls(req_ctrls),
            sasl_flags
        )

    def sasl_non_interactive_bind_s(
            self,
            sasl_mech,
            req_ctrls=None,
            sasl_flags=_libldap0.SASL_QUIET,
            authz_id=''
        ):
        if not authz_id:
            # short-cut allows really non-interactive SASL bind
            # without the flaky C call-backs
            return self.sasl_bind_s(sasl_mech, b'')
        auth = SaslNoninteractiveAuth(
            authz_id=authz_id,
            trace_level=self._trace_level,
        )
        return self.sasl_interactive_bind_s(sasl_mech, auth, req_ctrls, sasl_flags)

    def sasl_bind_s(self, sasl_mech, cred, req_ctrls=None):
        self.flush_cache()
        return self._ldap_call(
            self._l.sasl_bind_s,
            sasl_mech.encode('ascii'),
            cred,
            encode_request_ctrls(req_ctrls),
        )

    def compare(self, dn, attr, value, req_ctrls=None):
        return self._ldap_call(
            self._l.compare_ext,
            dn.encode(self.encoding),
            attr.encode('ascii'),
            value,
            encode_request_ctrls(req_ctrls),
        )

    def compare_s(self, dn, attr, value, req_ctrls=None):
        msgid = self.compare(dn, attr, value, req_ctrls)
        try:
            res = self.result(msgid, _libldap0.MSG_ALL, self.timeout)
        except _libldap0.COMPARE_TRUE:
            return True
        except _libldap0.COMPARE_FALSE:
            return False
        raise _libldap0.PROTOCOL_ERROR(
            'Compare operation returned wrong result: %r' % (res,)
        )

    def delete(self, dn, req_ctrls=None):
        self.uncache(dn)
        return self._ldap_call(
            self._l.delete_ext,
            dn.encode(self.encoding),
            encode_request_ctrls(req_ctrls),
        )

    def delete_s(self, dn, req_ctrls=None):
        msgid = self.delete(dn, req_ctrls)
        res = self.result(msgid, _libldap0.MSG_ALL, self.timeout)
        assert res.rtype == _libldap0.RES_DELETE, ValueError('Wrong result type %d' % (res.rtype,))
        return res

    def extop(self, extreq, req_ctrls=None):
        extop_req_value = extreq.encode()
        assert extop_req_value is None or isinstance(extop_req_value, bytes), TypeError(
            'Expected extop_req_value to be bytes or None, got %r' % (extop_req_value,)
        )
        return self._ldap_call(
            self._l.extop,
            extreq.requestName.encode('ascii'),
            extop_req_value,
            encode_request_ctrls(req_ctrls),
        )

    def extop_result(self, msgid=_libldap0.RES_ANY, extop_resp_class=None, timeout=-1):
        _, _, _, _, respoid, respvalue = self._ldap_call(
            self._l.result,
            msgid,
            1,
            max(self.timeout, timeout),
            True,
            False,
            True,
        )
        if extop_resp_class is None:
            extop_response = ExtendedResponse(respoid, respvalue)
        else:
            if not extop_resp_class.check_resp_name(
                None if respoid is None else respoid.decode('ascii')
            ):
                raise _libldap0.PROTOCOL_ERROR(
                    "Wrong OID in extended response! Expected %s, got %s" % (
                        extop_resp_class.responseName,
                        respoid
                    )
                )
            extop_response = extop_resp_class(encodedResponseValue=respvalue)
        if __debug__ and self._trace_level >= 2:
            logging.debug('%s.extop_result(): %r', self.__class__.__name__, extop_response)
        return extop_response

    def extop_s(self, extreq, req_ctrls=None, extop_resp_class=None):
        msgid = self.extop(extreq, req_ctrls)
        return self.extop_result(msgid, extop_resp_class=extop_resp_class)

    def modify(self, dn, modlist, req_ctrls=None):
        self.uncache(dn)
        return self._ldap_call(
            self._l.modify_ext,
            dn.encode(self.encoding),
            modlist,
            encode_request_ctrls(req_ctrls),
        )

    def modify_s(self, dn, modlist, req_ctrls=None):
        msgid = self.modify(dn, modlist, req_ctrls)
        res = self.result(msgid, _libldap0.MSG_ALL, self.timeout)
        assert res.rtype == _libldap0.RES_MODIFY, ValueError('Wrong result type %d' % (res.rtype,))
        return res

    def passwd(self, user=None, oldpw=None, newpw=None, req_ctrls=None):
        self.uncache(user)
        return self.extop(
            PassmodRequest(
                userIdentity=user,
                oldPasswd=oldpw,
                newPasswd=newpw,
            ),
            req_ctrls=req_ctrls,
        )

    def passwd_s(self, user=None, oldpw=None, newpw=None, req_ctrls=None):
        msgid = self.passwd(
            user=user,
            oldpw=oldpw,
            newpw=newpw,
            req_ctrls=req_ctrls,
        )
        res = self.extop_result(msgid, extop_resp_class=PassmodResponse)
        if res.responseValue is None:
            return None
        return res.genPasswd

    def rename(
            self,
            dn,
            newrdn,
            newsuperior=None,
            delold=1,
            req_ctrls=None,
        ):
        if newsuperior is not None:
            newsuperior = newsuperior.encode(self.encoding)
        return self._ldap_call(
            self._l.rename,
            dn.encode(self.encoding),
            newrdn.encode(self.encoding),
            newsuperior,
            delold,
            encode_request_ctrls(req_ctrls),
        )

    def rename_s(
            self,
            dn,
            newrdn,
            newsuperior=None,
            delold=1,
            req_ctrls=None,
        ):
        msgid = self.rename(dn, newrdn, newsuperior, delold, req_ctrls)
        res = self.result(msgid, _libldap0.MSG_ALL, self.timeout)
        assert res.rtype == _libldap0.RES_MODRDN, ValueError('Wrong result type %d' % (res.rtype,))
        return res

    def result(
            self,
            msgid,
            all_results=_libldap0.MSG_ALL,
            timeout=None,
            add_intermediates=False,
            resp_ctrl_classes=None,
        ):
        if msgid != _libldap0.RES_ANY and msgid not in self._outstanding_requests:
            raise ldap0.NO_SUCH_OPERATION('Unexpected msgid value %s' % (msgid,))
        res_type, res_data, res_msgid, res_ctrls = self._ldap_call(
            self._l.result,
            msgid,
            all_results,
            timeout,
            True,
            add_intermediates,
            False
        )
        assert res_msgid == msgid, ValueError('Expected LDAP result with msgid %d, got %d' % (msgid, res_msgid))
        if res_type not in NO_FINAL_RESULT_TYPES:
            del self._outstanding_requests[res_msgid]
        return LDAPResult(
            res_type,
            [
                (dn, entry, decode_response_ctrls(ctrls, resp_ctrl_classes))
                for dn, entry, ctrls in res_data
            ],
            res_msgid,
            decode_response_ctrls(res_ctrls, resp_ctrl_classes),
        )

    def results(
            self,
            msgid,
            timeout=-1,
            add_intermediates=False,
            resp_ctrl_classes=None,
        ):
        """
        Generator method which returns an iterator for processing all LDAP
        operation results of the given msgid like retrieved with
        LDAPObject.result()
        """
        if msgid != _libldap0.RES_ANY and msgid not in self._outstanding_requests:
            raise ldap0.NO_SUCH_OPERATION('Unexpected msgid value %s' % (msgid,))
        start_time = time.time()
        if timeout >=0:
            end_time = start_time + timeout
        while timeout < 0 or time.time() <= end_time:
            try:
                res = self.result(
                    msgid,
                    all_results=_libldap0.MSG_ONE,
                    timeout=min(timeout, 0.5),
                    add_intermediates=add_intermediates,
                    resp_ctrl_classes=resp_ctrl_classes,
                )
            except _libldap0.TIMEOUT:
                if timeout >= 0 and time.time() > end_time:
                    raise _libldap0.TIMEOUT('Timeout of %0.4f secs reached.' % (timeout,))
                continue
            yield res
            if res.rtype not in NO_FINAL_RESULT_TYPES:
                break
        # end of results()

    def search(
            self,
            base,
            scope,
            filterstr='(objectClass=*)',
            attrlist=None,
            attrsonly=0,
            req_ctrls=None,
            timeout=-1,
            sizelimit=0
        ):
        assert isinstance(base, str), TypeError('Expected str for base, got %r' % (base,))
        assert isinstance(filterstr, str), TypeError('Expected str for filterstr, got %r' % (filterstr,))
        if attrlist is not None:
            attrlist = encode_list(attrlist, encoding='ascii')
        else:
            attrlist = [b'*']
        return self._ldap_call(
            self._l.search_ext,
            base.encode(self.encoding),
            scope,
            filterstr.encode(self.encoding),
            attrlist,
            attrsonly,
            encode_request_ctrls(req_ctrls),
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
        self._whoami_dn = None
        self._cache_misses = 0
        self._cache_hits = 0
        self._cache = {}

    def uncache(self, entry_dn):
        """
        remove all cached entries related to dn from internal cache
        """
        entry_dn = entry_dn.lower()
        remove_keys = set()
        # first find the items to be removed from cache
        for cache_key_args, cached_results in self._cache.items():
            cached_results = self._cache[cache_key_args]
            if cache_key_args[0].lower() == entry_dn:
                remove_keys.add(cache_key_args)
            else:
                for cached_res in cached_results[1]:
                    if isinstance(cached_res, SearchResultEntry) and cached_res.dn_s.lower() == entry_dn:
                        remove_keys.add(cache_key_args)
        # finally remove items from cache dict
        for cache_key_args in remove_keys:
            try:
                del self._cache[cache_key_args]
            except KeyError:
                pass
        # end of uncache()

    def search_s(
            self,
            base,
            scope,
            filterstr='(objectClass=*)',
            attrlist=None,
            attrsonly=0,
            req_ctrls=None,
            timeout=-1,
            sizelimit=0,
            cache_ttl=None,
        ):
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
                    c.encode()
                    for c in req_ctrls or []
                ]),
                timeout,
                sizelimit,
            )
            # first look into cache for non-expired search results
            try:
                result_cache_time, res = self._cache[cache_key_args]
            except KeyError:
                pass
            else:
                if current_time > result_cache_time + cache_ttl:
                    # cache entry is expired => remove it no matter what happens later
                    del self._cache[cache_key_args]
                else:
                    self._cache_hits += 1
                    return res
        # no cached result
        self._cache_misses += 1
        msgid = self.search(
            base,
            scope,
            filterstr,
            attrlist,
            attrsonly,
            req_ctrls,
            timeout,
            sizelimit
        )
        res = []
        for ldap_res in self.results(msgid, timeout=timeout):
            res.extend(ldap_res.rdata)
        if cache_ttl > 0:
            # store result in cache if caching is enabled at all
            self._cache[cache_key_args] = (
                current_time,
                res
            )
        return res # search_s()

    def noop_search(
            self,
            base,
            scope=_libldap0.SCOPE_SUBTREE,
            filterstr='(objectClass=*)',
            req_ctrls=None,
            timeout=-1,
            sizelimit=0,
        ):
        req_ctrls = req_ctrls or []
        req_ctrls.append(SearchNoOpControl(criticality=True))
        try:
            msg_id = self.search(
                base,
                scope,
                filterstr=filterstr,
                attrlist=['1.1'],
                req_ctrls=req_ctrls,
                timeout=timeout,
                sizelimit=sizelimit,
            )
            noop_srch_res = list(self.results(
                msg_id,
                timeout=timeout,
            ))[0]
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
                for c in noop_srch_res.ctrls
                if c.controlType == SearchNoOpControl.controlType
            ]
            if noop_srch_ctrl:
                return noop_srch_ctrl[0].numSearchResults, noop_srch_ctrl[0].numSearchContinuations
            return (None, None)

    def start_tls_s(self):
        return self._ldap_call(self._l.start_tls_s)

    def unbind(self, req_ctrls=None):
        res = self._ldap_call(
            self._l.unbind_ext,
            encode_request_ctrls(req_ctrls),
        )
        try:
            del self._l
        except AttributeError:
            pass
        return res

    def unbind_s(self, req_ctrls=None):
        msgid = self.unbind(req_ctrls)
        if msgid is None:
            return None
        res = self.result(msgid, _libldap0.MSG_ALL, self.timeout)
        return res

    def whoami_s(self, req_ctrls=None):
        wai = self.extop_s(
            WhoAmIRequest(),
            extop_resp_class=WhoAmIResponse,
            req_ctrls=req_ctrls,
        )
        if wai.responseValue and wai.responseValue.lower().startswith('dn:'):
            # cache this for later calls to get_whoami_dn()
            self._whoami_dn = wai.responseValue[3:]
        return wai.responseValue

    def get_option(self, option):
        result = self._ldap_call(self._l.get_option, option)
        if option == _libldap0.OPT_SERVER_CONTROLS:
            result = decode_response_ctrls(result)
        return result

    def set_option(self, option, invalue):
        if option == _libldap0.OPT_SERVER_CONTROLS:
            invalue = encode_request_ctrls(invalue)
        return self._ldap_call(self._l.set_option, option, invalue)

    def search_subschemasubentry_s(self, dn='', rootdse=True):
        res = None
        try:
            ldap_res = self.read_s(dn, attrlist=['subschemaSubentry'])
        except (
                _libldap0.NO_SUCH_OBJECT,
                _libldap0.INSUFFICIENT_ACCESS,
                _libldap0.NO_SUCH_ATTRIBUTE,
                _libldap0.UNDEFINED_TYPE,
                _libldap0.REFERRAL,
            ):
            pass
        else:
            if ldap_res is not None and 'subschemaSubentry' in ldap_res.entry_s:
                res = ldap_res.entry_s['subschemaSubentry'][0]
        if res is None and dn and rootdse:
            # fall back reading attribute subschemaSubentry from rootDSE
            res = self.search_subschemasubentry_s(dn='')
        return res # end of search_subschemasubentry_s()

    def read_s(
            self,
            dn,
            filterstr='(objectClass=*)',
            attrlist=None,
            req_ctrls=None,
            timeout=-1,
            cache_ttl=None,
        ):
        ldap_res = self.search_s(
            dn,
            _libldap0.SCOPE_BASE,
            filterstr,
            attrlist=attrlist,
            req_ctrls=req_ctrls,
            timeout=timeout,
            cache_ttl=cache_ttl,
        )
        if not ldap_res:
            return None
        return ldap_res[0]

    def read_subschemasubentry_s(self, subschemasubentry_dn, attrs=None):
        try:
            subschemasubentry = self.read_s(
                subschemasubentry_dn,
                filterstr='(objectClass=subschema)',
                attrlist=attrs or SCHEMA_ATTRS
            )
        except _libldap0.NO_SUCH_OBJECT:
            return None
        if subschemasubentry is None:
            return None
        return subschemasubentry.entry_s

    def refresh(self, dn, ttl=None):
        self.uncache(dn)
        return self.extop(RefreshRequest(entryName=dn, requestTtl=ttl))

    def refresh_s(self, dn, ttl=None):
        self.uncache(dn)
        msgid = self.refresh(dn, ttl=ttl)
        res = self.extop_result(msgid, extop_resp_class=RefreshResponse)
        return res.responseTtl

    def find_unique_entry(
            self,
            base,
            scope=_libldap0.SCOPE_SUBTREE,
            filterstr='(objectClass=*)',
            attrlist=None,
            attrsonly=0,
            req_ctrls=None,
            timeout=-1,
            cache_ttl=None,
        ):
        try:
            ldap_res = list(self.search_s(
                base,
                scope,
                filterstr,
                attrlist=attrlist,
                attrsonly=attrsonly,
                req_ctrls=req_ctrls,
                timeout=timeout,
                sizelimit=2,
                cache_ttl=cache_ttl,
            ))
        except _libldap0.SIZELIMIT_EXCEEDED:
            raise NoUniqueEntry('Size limit exceeded for %r ()' % (filterstr))
        # strip search continuations
        ldap_res = [res for res in ldap_res if isinstance(res, SearchResultEntry)]
        # now check again for length
        if not ldap_res:
            raise NoUniqueEntry('No search result for %r' % (filterstr))
        if len(ldap_res) > 1:
            raise NoUniqueEntry(
                'Non-unique search results (%d) for %r' % (len(ldap_res), filterstr)
            )
        return ldap_res[0]

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

    def get_whoami_dn(self):
        if self._whoami_dn is None:
            wai = self.whoami_s()
            if wai == '':
                self._whoami_dn = wai
            elif wai.lower().startswith('dn:'):
                self._whoami_dn = wai[3:]
            else:
                self._whoami_dn = None
                raise ValueError('Expected dn: form of Who Am I? result, got %r' % wai)
        return self._whoami_dn


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

    __transient_attrs__ = {
        '_l',
        '_libldap0_lock',
        '_reconnect_lock',
        '_last_bind',
        '_outstanding_requests',
        '_msgid_funcs',
    }

    def __init__(
            self,
            uri,
            trace_level=0,
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
        self.uri = uri
        self._options = []
        self._last_bind = None
        LDAPObject.__init__(
            self,
            uri,
            trace_level=trace_level,
            cache_ttl=cache_ttl,
        )
        self._reconnect_lock = LDAPLock(
            '_reconnect_lock in %r' % self,
            trace_level=self._trace_level,
        )
        self._retry_max = retry_max
        self._retry_delay = retry_delay
        self._start_tls = 0
        self._reconnects_done = 0

    def __getstate__(self):
        """
        return data representation for pickled object
        """
        state = {}
        for key, val in self.__dict__.items():
            if key not in self.__transient_attrs__:
                state[key] = val
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
        self._libldap0_lock = LDAPLock(
            '_libldap0_lock in %r' % self,
            trace_level=self._trace_level,
        )
        self._reconnect_lock = LDAPLock(
            '_reconnect_lock in %r' % self,
            trace_level=self._trace_level,
        )
        self.reconnect(self.uri)

    def _store_last_bind(self, method, *args, **kwargs):
        self._last_bind = (method, args, kwargs)

    def _apply_last_bind(self):
        if self._last_bind is not None:
            func, args, kwargs = self._last_bind
            func(self, *args, **kwargs)
        else:
            # Send explicit anon simple bind request to provoke
            # _libldap0.SERVER_DOWN in method reconnect()
            LDAPObject.simple_bind_s(self, '', b'')

    def _restore_options(self):
        """
        Restore all recorded options
        """
        for key, val in self._options:
            LDAPObject.set_option(self, key, val)

    def passwd_s(self, *args, **kwargs):
        return self._apply_method_s(LDAPObject.passwd_s, *args, **kwargs)

    def reconnect(self, uri, retry_max=1, retry_delay=60.0, reset_last_bind=False):
        """
        Drop and clean up old connection completely and reconnect
        """
        self._reconnect_lock.acquire()
        if reset_last_bind:
            self._last_bind = None
        try:
            reconnect_counter = retry_max
            while reconnect_counter:
                counter_text = '%d. (of %d)' % (retry_max-reconnect_counter+1, retry_max)
                if __debug__ and self._trace_level >= 1:
                    logging.debug(
                        'Trying %s reconnect to %s...\n',
                        counter_text, uri,
                    )
                try:
                    # Do the connect
                    self._l = _libldap0_function_call(_libldap0.initialize, uri.encode(self.encoding))
                    self._msgid_funcs = {
                        self._l.add_ext,
                        self._l.simple_bind,
                        self._l.compare_ext,
                        self._l.delete_ext,
                        self._l.extop,
                        self._l.modify_ext,
                        self._l.rename,
                        self._l.search_ext,
                        self._l.unbind_ext,
                    }
                    self._outstanding_requests = {}
                    self._restore_options()
                    # StartTLS extended operation in case this was called before
                    if self._start_tls:
                        LDAPObject.start_tls_s(self)
                    # Repeat last simple or SASL bind
                    self._apply_last_bind()
                except (_libldap0.SERVER_DOWN, _libldap0.TIMEOUT) as ldap_error:
                    if __debug__ and self._trace_level >= 1:
                        logging.debug(
                            '%s reconnect to %s failed\n',
                            counter_text, uri
                        )
                    reconnect_counter = reconnect_counter-1
                    if not reconnect_counter:
                        raise ldap_error
                    if __debug__ and self._trace_level >= 1:
                        logging.debug('=> delay %s...\n', retry_delay)
                    time.sleep(retry_delay)
                    LDAPObject.unbind_s(self)
                else:
                    if __debug__ and self._trace_level >= 1:
                        logging.debug(
                            '%s reconnect to %s successful => repeat last operation\n',
                            counter_text,
                            uri,
                        )
                    self._reconnects_done += 1
                    break
        finally:
            self._reconnect_lock.release()
        # end of reconnect()

    def _apply_method_s(self, func, *args, **kwargs):
        if not hasattr(self, '_l'):
            self.reconnect(self.uri, retry_max=self._retry_max, retry_delay=self._retry_delay)
        try:
            return func(self, *args, **kwargs)
        except _libldap0.SERVER_DOWN:
            if self._retry_max <= 0:
                raise
            LDAPObject.unbind_s(self)
            # Try to reconnect
            self.reconnect(self.uri, retry_max=self._retry_max, retry_delay=self._retry_delay)
            # Re-try last operation
            return func(self, *args, **kwargs)

    def set_option(self, option, invalue):
        res = LDAPObject.set_option(self, option, invalue)
        self._options.append((option, invalue))
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

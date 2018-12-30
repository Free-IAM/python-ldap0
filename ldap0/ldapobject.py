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

from .__about__ import __version__, __author__, __license__
import ldap0
from . import err
from .err import PasswordPolicyChangeAfterReset, PasswordPolicyExpirationWarning, PasswordPolicyExpiredError
from .base import LDAPResult
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
from .extop.cancel import CancelRequest, CancelResponse
from .sasl import SaslNoninteractiveAuth
from .modlist import add_modlist
from .ldapurl import LDAPUrl

__all__ = [
    'NO_UNIQUE_ENTRY',
    'LDAPObject',
    'LDAPObject',
    'ReconnectLDAPObject',
]

NO_UNIQUE_ENTRY = ldap0.err.NO_UNIQUE_ENTRY

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

    def __init__(
            self,
            uri,
            trace_level=0,
            trace_file=None,
            trace_stack_limit=5,
            cache_ttl=0.0,
        ):
        self._trace_level = trace_level
        self._trace_file = trace_file or ldap0._trace_file
        self._trace_stack_limit = trace_stack_limit
        if isinstance(uri, str):
            ldap_url = LDAPUrl(uri)
        elif isinstance(uri, LDAPUrl):
            ldap_url = uri
        else:
            raise TypeError('Expected uri to be of type LDAPUrl or str, got %r' % (uri))
        self._libldap0_lock = LDAPLock(
            desc='_libldap0_lock within %r' % self,
            trace_level=trace_level,
        )
        conn_uri = ldap_url.connect_uri()
        self._l = _libldap0_function_call(_libldap0.initialize, conn_uri)
        self._uri = self.uri = conn_uri
        self.timeout = -1
        self.protocol_version = _libldap0.VERSION3
        self.cache_ttl = cache_ttl
        self.flush_cache()
        self.set_option(_libldap0.OPT_RESTART, _libldap0.OPT_OFF)
        self.set_option(_libldap0.OPT_DEREF, _libldap0.OPT_OFF)
        self.set_option(_libldap0.OPT_REFERRALS, _libldap0.OPT_OFF)
        self.set_option(_libldap0.OPT_X_TLS_REQUIRE_CERT, _libldap0.OPT_X_TLS_HARD)

    def _ldap_call(self, func, *args, **kwargs):
        """
        Wrapper method mainly for serializing calls into OpenLDAP libs
        and trace logs
        """
        self._libldap0_lock.acquire()
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
                self._libldap0_lock.release()
        except LDAPError as e:
            if hasattr(e, 'args') \
               and e.args \
               and 'info' not in e.args[0] \
               and 'errno' in e.args[0]:
                e.args[0]['info'] = strerror(e.args[0]['errno'])
            if __debug__ and self._trace_level >= 2:
                self._trace_file.write(
                    '-> LDAPError - %s: %s\n' % (e.__class__.__name__, e)
                )
            raise e
        else:
            if __debug__ and self._trace_level >= 2:
                if not diagnostic_message_success is None:
                    self._trace_file.write(
                        '-> diagnosticMessage: %r\n' % (diagnostic_message_success)
                    )
                self._trace_file.write('-> %s\n' % (pprint.pformat(result)))
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
                    with open(tls_pathname, 'rb') as tls_fileobj:
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
        return # set_tls_options()

    def fileno(self):
        return self.get_option(_libldap0.OPT_DESC)

    def abandon(self, msgid, serverctrls=None):
        return self._ldap_call(
            self._l.abandon_ext,
            msgid,
            encode_request_ctrls(serverctrls),
        )

    def cancel(self, cancelid, serverctrls=None):
        return self.extop(
            CancelRequest(cancelid),
            serverctrls=serverctrls,
        )

    def cancel_s(self, cancelid, serverctrls=None):
        try:
            msgid = self.cancel(cancelid, serverctrls=serverctrls)
            ldap_res = self.result(msgid, all=1, timeout=self.timeout)
        except _libldap0.CANCELLED:
            pass
        #else:
        #    raise _libldap0.PROTOCOL_ERROR('cancel operation returned {0}'.format(ldap_res))

    def add(self, dn, modlist, serverctrls=None):
        self.uncache(dn)
        if isinstance(modlist, dict):
            modlist = add_modlist(modlist)
        return self._ldap_call(
            self._l.add_ext,
            dn,
            modlist,
            encode_request_ctrls(serverctrls),
        )

    def add_s(self, dn, modlist, serverctrls=None):
        msgid = self.add(dn, modlist, serverctrls)
        res = self.result(
            msgid,
            all=1,
            timeout=self.timeout
        )
        return res

    def simple_bind(self, who='', cred='', serverctrls=None):
        self.flush_cache()
        return self._ldap_call(
            self._l.simple_bind,
            who,
            cred,
            encode_request_ctrls(serverctrls),
        )

    def simple_bind_s(self, who='', cred='', serverctrls=None):
        msgid = self.simple_bind(who, cred, serverctrls)
        res = self.result(
            msgid,
            all=1,
            timeout=self.timeout
        )
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
                elif ppolicy_ctrl.timeBeforeExpiration != None:
                    raise PasswordPolicyExpirationWarning(
                        who=who,
                        desc='Password will expire in %d seconds!' % (
                            ppolicy_ctrl.timeBeforeExpiration
                        ),
                        timeBeforeExpiration=ppolicy_ctrl.timeBeforeExpiration,
                    )
                elif ppolicy_ctrl.graceAuthNsRemaining != None:
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
            who,
            auth,
            serverctrls=None,
            sasl_flags=_libldap0.SASL_QUIET
        ):
        self.flush_cache()
        return self._ldap_call(
            self._l.sasl_interactive_bind_s,
            who,
            auth,
            encode_request_ctrls(serverctrls),
            sasl_flags
        )

    def sasl_non_interactive_bind_s(
            self,
            sasl_mech,
            serverctrls=None,
            sasl_flags=_libldap0.SASL_QUIET,
            authz_id=''
        ):
        if not authz_id:
            # short-cut allows really non-interactive SASL bind
            # without the flaky C call-backs
            return self.sasl_bind_s(None, 'EXTERNAL', '')
        auth = SaslNoninteractiveAuth(
            sasl_mech,
            authz_id=authz_id,
            trace_level=self._trace_level,
            trace_file=self._trace_file,
        )
        return self.sasl_interactive_bind_s(
            '',
            auth,
            serverctrls,
            sasl_flags
        )

    def sasl_bind_s(self, dn, mechanism, cred, serverctrls=None):
        self.flush_cache()
        return self._ldap_call(
            self._l.sasl_bind_s,
            dn,
            mechanism,
            cred,
            encode_request_ctrls(serverctrls),
        )

    def compare(self, dn, attr, value, serverctrls=None):
        return self._ldap_call(
            self._l.compare_ext, dn,
            attr,
            value,
            encode_request_ctrls(serverctrls),
        )

    def compare_s(self, dn, attr, value, serverctrls=None):
        msgid = self.compare(dn, attr, value, serverctrls)
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

    def delete(self, dn, serverctrls=None):
        self.uncache(dn)
        return self._ldap_call(
            self._l.delete_ext,
            dn,
            encode_request_ctrls(serverctrls),
        )

    def delete_s(self, dn, serverctrls=None):
        msgid = self.delete(dn, serverctrls)
        res = self.result(
            msgid,
            all=1,
            timeout=self.timeout
        )
        return res

    def extop(self, extreq, serverctrls=None):
        return self._ldap_call(
            self._l.extop,
            extreq.requestName,
            extreq.encodedRequestValue(),
            encode_request_ctrls(serverctrls),
        )

    def extop_result(self, msgid=_libldap0.RES_ANY, extop_resp_class=None):
        _, _, _, _, respoid, respvalue = self._ldap_call(
            self._l.result,
            msgid,
            1,
            self.timeout,
            True,
            True,
            True,
        )
        if extop_resp_class is None:
            extop_response = ExtendedResponse(respoid, respvalue)
        else:
            if not extop_resp_class.check_resp_name(respoid):
                raise _libldap0.PROTOCOL_ERROR(
                    "Wrong OID in extended response! Expected %s, got %s" % (
                        extop_resp_class.responseName,
                        respoid
                    )
                )
            extop_response = extop_resp_class(encodedResponseValue=respvalue)
        if __debug__ and self._trace_level >= 2:
            self._trace_file.write(
                '%s.extop_result(): %r' % (
                    self.__class__.__name__,
                    extop_response
                )
            )
        return extop_response

    def extop_s(self, extreq, serverctrls=None, extop_resp_class=None):
        msgid = self.extop(extreq, serverctrls)
        return self.extop_result(msgid, extop_resp_class=extop_resp_class)

    def modify(self, dn, modlist, serverctrls=None):
        self.uncache(dn)
        return self._ldap_call(
            self._l.modify_ext, dn,
            modlist,
            encode_request_ctrls(serverctrls),
        )

    def modify_s(self, dn, modlist, serverctrls=None):
        msgid = self.modify(dn, modlist, serverctrls)
        res = self.result(
            msgid,
            all=1,
            timeout=self.timeout
        )
        return res

    def passwd(self, user=None, oldpw=None, newpw=None, serverctrls=None):
        self.uncache(user)
        return self.extop(
            PassmodRequest(
                userIdentity=user,
                oldPasswd=oldpw,
                newPasswd=newpw,
            ),
            serverctrls=serverctrls,
        )

    def passwd_s(self, user=None, oldpw=None, newpw=None, serverctrls=None):
        msgid = self.passwd(
            user=user,
            oldpw=oldpw,
            newpw=newpw,
            serverctrls=serverctrls,
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
            serverctrls=None,
        ):
        return self._ldap_call(
            self._l.rename,
            dn,
            newrdn,
            newsuperior,
            delold,
            encode_request_ctrls(serverctrls),
        )

    def rename_s(
            self,
            dn,
            newrdn,
            newsuperior=None,
            delold=1,
            serverctrls=None,
        ):
        msgid = self.rename(dn, newrdn, newsuperior, delold, serverctrls)
        res = self.result(
            msgid,
            all=1,
            timeout=self.timeout
        )
        return res

    def result(
            self,
            msgid=_libldap0.RES_ANY,
            all=1,
            timeout=None,
            add_ctrls=0,
            add_intermediates=0,
            resp_ctrl_classes=None
        ):
        if timeout is None:
            timeout = self.timeout
        ldap_result = self._ldap_call(
            self._l.result,
            msgid,
            all,
            timeout,
            True,
            add_intermediates,
        )
        if ldap_result is None:
            resp_type = resp_data = resp_msgid = resp_ctrls = None
        else:
            resp_type, resp_data, resp_msgid, resp_ctrls = ldap_result
            if add_ctrls:
                resp_data = [
                    (t, r, decode_response_ctrls(c, resp_ctrl_classes))
                    for t, r, c in resp_data
                ]
            else:
                resp_data = [
                    (t, r)
                    for t, r, c in resp_data
                ]
        decoded_resp_ctrls = decode_response_ctrls(resp_ctrls, resp_ctrl_classes)
        return LDAPResult(resp_type, resp_data, resp_msgid, decoded_resp_ctrls)

    def results(
            self,
            msgid,
            timeout=-1,
            add_ctrls=False,
            add_intermediates=False,
            resp_ctrl_classes=None,
        ):
        """
        Generator method which returns an iterator for processing all LDAP
        operation results of the given msgid like retrieved with
        LDAPObject.result()
        """
        ldap_result = self._ldap_call(
            self._l.result,
            msgid,
            0,
            timeout,
            True,
            add_intermediates,
            False
        )
        while ldap_result and ldap_result[1]:
            res_type, res_data, res_msgid, res_ctrls = ldap_result
            if add_ctrls:
                res_data = [
                    (t, r, decode_response_ctrls(c, resp_ctrl_classes))
                    for t, r, c in res_data
                ]
            else:
                res_data = [
                    (t, r)
                    for t, r, c in res_data
                ]
            yield LDAPResult(res_type, res_data, res_msgid, res_ctrls)
            ldap_result = self._ldap_call(
                self._l.result,
                msgid,
                0,
                timeout,
                True,
                add_intermediates,
                False
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
            encode_request_ctrls(serverctrls),
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
        for cache_key_args, cached_results in self._cache.items():
            if cache_key_args[0].lower() == entry_dn:
                del self._cache[cache_key_args]
            else:
                for cached_res in cached_results[1].data:
                    cached_dn = cached_res[0]
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
                timeout,
                sizelimit,
                add_ctrls,
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
                    return res.data
        # no cached result
        self._cache_misses += 1
        msgid = self.search(
            base,
            scope,
            filterstr,
            attrlist,
            attrsonly,
            serverctrls,
            timeout,
            sizelimit
        )
        res = self.result(
            msgid, all=1,
            timeout=timeout,
            add_ctrls=add_ctrls
        )
        if cache_ttl > 0:
            # store result in cache if caching is enabled at all
            self._cache[cache_key_args] = (
                current_time,
                res
            )
        return res.data # search_s()

    def noop_search(
            self,
            base,
            scope=_libldap0.SCOPE_SUBTREE,
            filterstr='(objectClass=*)',
            serverctrls=None,
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
                timeout=timeout,
                sizelimit=sizelimit,
            )
            _, _, _, search_response_ctrls = self.result(
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

    def unbind(self, serverctrls=None):
        res = self._ldap_call(
            self._l.unbind_ext,
            encode_request_ctrls(serverctrls),
        )
        try:
            del self._l
        except AttributeError:
            pass
        return res

    def unbind_s(self, serverctrls=None):
        msgid = self.unbind(serverctrls)
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

    def whoami_s(self, serverctrls=None):
        wai = self.extop_s(
            WhoAmIRequest(),
            extop_resp_class=WhoAmIResponse,
            serverctrls=serverctrls,
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

    def search_subschemasubentry_s(self, dn=''):
        try:
            entry = self.read_s(dn, attrlist=['subschemaSubentry'])
        except (
                _libldap0.NO_SUCH_OBJECT,
                _libldap0.INSUFFICIENT_ACCESS,
                _libldap0.NO_SUCH_ATTRIBUTE,
                _libldap0.UNDEFINED_TYPE,
            ):
            res = None
        else:
            res = entry.get('subschemaSubentry',[None])[0]
        if res is None and dn:
            # fall back reading attribute subschemaSubentry from rootDSE
            res = self.search_subschemasubentry_s(dn='')
        return res # end of search_subschemasubentry_s()

    def read_s(
            self,
            dn,
            filterstr=None,
            attrlist=None,
            serverctrls=None,
            timeout=-1,
            cache_ttl=None,
        ):
        r = self.search_s(
            dn,
            _libldap0.SCOPE_BASE,
            filterstr or '(objectClass=*)',
            attrlist=attrlist,
            serverctrls=serverctrls,
            timeout=timeout,
            cache_ttl=cache_ttl,
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
            serverctrls=None,
            timeout=-1,
            cache_ttl=None,
            add_ctrls=False,
        ):
        try:
            ldap_res = self.search_s(
                base,
                scope,
                filterstr,
                attrlist=attrlist or ['*'],
                attrsonly=attrsonly,
                serverctrls=serverctrls,
                timeout=timeout,
                sizelimit=2,
                cache_ttl=cache_ttl,
                add_ctrls=add_ctrls,
            )
        except _libldap0.SIZELIMIT_EXCEEDED:
            raise NO_UNIQUE_ENTRY('Size limit exceeded for %r ()' % (filterstr))
        # strip search continuations
        ldap_res = [ res for res in ldap_res if res[0] is not None ]
        # now check again for length
        if not ldap_res:
            raise NO_UNIQUE_ENTRY('No search result for %r' % (filterstr))
        elif len(ldap_res) > 1:
            raise NO_UNIQUE_ENTRY('Non-unique search results (%d) for %r' % (len(ldap_res), filterstr))
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
            if not wai:
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
        '_trace_file',
        '_reconnect_lock',
        '_last_bind',
    }

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
        self._reconnect_lock = LDAPLock(
            desc='_reconnect_lock within %r' % self,
            trace_level=trace_level,
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
            desc='_libldap0_lock within %r' % self,
            trace_level=self._trace_level,
        )
        self._reconnect_lock = LDAPLock(
            desc='_reconnect_lock within %r' % self,
            trace_level=self._trace_level,
        )
        self._trace_file = sys.stderr
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
                    self._l = _libldap0_function_call(_libldap0.initialize, uri)
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
            if self._retry_max <= 0:
                raise
            LDAPObject.unbind_s(self)
            # Try to reconnect
            self.reconnect(self._uri, retry_max=self._retry_max, retry_delay=self._retry_delay)
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

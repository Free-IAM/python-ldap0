# -*- coding: utf-8 -*-
"""
ldap0.sasl - support for SASL mechanism
"""

from __future__ import absolute_import

from ldap0.pkginfo import __version__, __author__, __license__

if __debug__:
    # Tracing is only supported in debugging mode
    from ldap0 import _trace_level, _trace_file


# These are the SASL callback id's , as defined in sasl.h
CB_USER = 0x4001
CB_AUTHNAME = 0x4002
CB_LANGUAGE = 0x4003
CB_PASS = 0x4004
CB_ECHOPROMPT = 0x4005
CB_NOECHOPROMPT = 0x4006
CB_GETREALM = 0x4008


class SaslAuth:
    """
    This class handles SASL interactions for authentication.
    """

    def __init__(self, cb_value_dict, mech=None):
        self.cb_value_dict = cb_value_dict or {}
        if mech is not None:
            self.mech = mech

    def callback(self, cb_id, challenge, prompt, defresult):
        # The following print command might be useful for debugging
        # new sasl mechanisms. So it is left here
        cb_result = self.cb_value_dict.get(cb_id, defresult) or ''
        if __debug__ and _trace_level >= 1:
            _trace_file.write("*** id=%d, challenge=%s, prompt=%s, defresult=%s\n-> %s\n" % (
                cb_id,
                challenge,
                prompt,
                repr(defresult),
                repr(self.cb_value_dict.get(cb_result))
            ))
        return cb_result


class cram_md5(SaslAuth):
    """
    This class handles SASL CRAM-MD5 authentication.
    """
    mech = "CRAM-MD5"

    def __init__(self, authc_id, password, authz_id=""):
        auth_dict = {
            CB_AUTHNAME: authc_id,
            CB_PASS: password,
            CB_USER: authz_id,
        }
        SaslAuth.__init__(self, auth_dict)


class digest_md5(SaslAuth):
    """
    This class handles SASL DIGEST-MD5 authentication.
    """
    mech = "DIGEST-MD5"
 
    def __init__(self, authc_id, password, authz_id=""):
        auth_dict = {
            CB_AUTHNAME: authc_id,
            CB_PASS: password,
            CB_USER: authz_id,
        }
        SaslAuth.__init__(self, auth_dict)


class gssapi(SaslAuth):
    """
    This class handles SASL GSSAPI (i.e. Kerberos V) authentication.
    """
    mech = "GSSAPI"

    def __init__(self, authz_id=""):
        SaslAuth.__init__(self, {CB_USER: authz_id})


class external(SaslAuth):
    """
    This class handles SASL EXTERNAL authentication
    (i.e. X.509 client certificate)
    """
    mech = "EXTERNAL"

    def __init__(self, authz_id=""):
        SaslAuth.__init__(self, {CB_USER: authz_id})

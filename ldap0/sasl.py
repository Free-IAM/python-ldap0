# -*- coding: utf-8 -*-
"""
ldap0.sasl - support for SASL mechanism
"""

from __future__ import absolute_import

from ldap0.pkginfo import __version__, __author__, __license__

if __debug__:
    # Tracing is only supported in debugging mode
    from ldap0 import _trace_level, _trace_file

__all__ = [
    'SaslAuth',
    'SaslNoninteractiveAuth',
    'SaslPasswordAuth',
]


# These are the SASL callback id's , as defined in sasl.h
CB_USER = 0x4001
CB_AUTHNAME = 0x4002
CB_LANGUAGE = 0x4003
CB_PASS = 0x4004
CB_ECHOPROMPT = 0x4005
CB_NOECHOPROMPT = 0x4006
CB_GETREALM = 0x4008

SASL_PASSWORD_MECHS = set(('CRAM-MD5','PLAIN','LOGIN','DIGEST-MD5','NTLM','OTP','SCRAM-SHA-1'))
SASL_NONINTERACTIVE_MECHS = set(['EXTERNAL','GSSAPI'])

class SaslAuth:
    """
    This class handles SASL interactions for authentication.
    """

    def __init__(self, cb_value_dict, mech):
        self.cb_value_dict = cb_value_dict or {}
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


class SaslPasswordAuth(SaslAuth):
    """
    This class handles SASL CRAM-MD5 authentication.
    """

    def __init__(self, mech, authc_id, password, authz_id=''):
        assert mech in SASL_PASSWORD_MECHS, ValueError(
            'Invalid SASL mech %r for %s' % (mech, self.__class__.__name__)
        )
        auth_dict = {
            CB_AUTHNAME: authc_id,
            CB_PASS: password,
            CB_USER: authz_id,
        }
        SaslAuth.__init__(self, auth_dict, mech=mech)


class SaslNoninteractiveAuth(SaslAuth):
    """
    This class handles SASL CRAM-MD5 authentication.
    """

    def __init__(self, mech, authz_id=""):
        assert mech in SASL_NONINTERACTIVE_MECHS, ValueError(
            'Invalid SASL mech %r for %s' % (mech, self.__class__.__name__)
        )
        auth_dict = {
            CB_USER: authz_id,
        }
        SaslAuth.__init__(self, auth_dict, mech=mech)

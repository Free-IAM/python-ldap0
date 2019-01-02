# -*- coding: utf-8 -*-
"""
ldap0.sasl - support for SASL mechanism
"""

from __future__ import absolute_import

import logging

from .__about__ import __version__, __author__, __license__


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

# SASL mechs known to only require username and password
SASL_PASSWORD_MECHS = {
    'CRAM-MD5',
    'DIGEST-MD5',
    'LOGIN',
    'NTLM',
    'OTP',
    'PLAIN',
    'SCRAM-SHA-1',
}

# SASL mechs known to not require application-provided authc information
SASL_NONINTERACTIVE_MECHS = {
    'EXTERNAL',
    'GSSAPI',
}


class SaslAuth(object):
    """
    This class handles SASL interactions for authentication.
    """

    def __init__(self, cb_value_dict, mech, trace_level=0):
        self.cb_value_dict = cb_value_dict or {}
        self.mech = mech.upper()
        self._trace_level = trace_level

    def callback(self, cb_id, challenge, prompt, defresult):
        """
        callback method invoked by SASL lib
        """
        # The following print command might be useful for debugging
        # new sasl mechanisms. So it is left here
        cb_result = self.cb_value_dict.get(cb_id, defresult) or ''
        if __debug__ and self._trace_level >= 1:
            logging.debug(
                'cb_id=%d, challenge=%r, prompt=%r, defresult=%r -> %r', 
                cb_id, challenge, prompt, defresult, cb_result,
            )
        return cb_result


class SaslPasswordAuth(SaslAuth):
    """
    This class handles password-based SASL authentication mechs
    like PLAIN, DIGEST-MD5 or CRAM-MD5 etc.
    """

    def __init__(
            self,
            mech,
            authc_id,
            password,
            authz_id='',
            trace_level=0,
        ):
        assert mech in SASL_PASSWORD_MECHS, ValueError(
            'Invalid SASL mech %r for %s' % (mech, self.__class__.__name__)
        )
        auth_dict = {
            CB_AUTHNAME: authc_id,
            CB_PASS: password,
            CB_USER: authz_id,
        }
        SaslAuth.__init__(
            self,
            auth_dict,
            mech=mech,
            trace_level=trace_level,
        )


class SaslNoninteractiveAuth(SaslAuth):
    """
    This class handles non-interactive SASL authentication mechs
    like EXTERNAL or GSSAPI.
    """

    def __init__(
            self,
            mech,
            authz_id="",
            trace_level=0,
        ):
        assert mech in SASL_NONINTERACTIVE_MECHS, ValueError(
            'Invalid SASL mech %r for %s' % (mech, self.__class__.__name__)
        )
        auth_dict = {
            CB_USER: authz_id,
        }
        SaslAuth.__init__(
            self,
            auth_dict,
            mech=mech,
            trace_level=trace_level,
        )

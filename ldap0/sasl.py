# -*- coding: utf-8 -*-
"""
ldap0.sasl - support for SASL mechanism
"""

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
    b'CRAM-MD5',
    b'DIGEST-MD5',
    b'LOGIN',
    b'NTLM',
    b'OTP',
    b'PLAIN',
    b'SCRAM-SHA-1',
}

# SASL mechs known to not require application-provided authc information
SASL_NONINTERACTIVE_MECHS = {
    b'EXTERNAL',
    b'GSSAPI',
}


class SaslAuth:
    """
    This class handles SASL interactions for authentication.
    """
    encoding = 'utf-8'

    def __init__(self, cb_value_dict, trace_level=0):
        self.cb_value_dict = {}
        for key, val in (cb_value_dict or {}).items():
            assert isinstance(val, bytes), TypeError(
                'Expected value for SASL param %d to be bytes, got %r' % (key, val)
            )
            self.cb_value_dict[key] = val
        self._trace_level = trace_level

    def callback(self, cb_id, challenge, prompt, defresult):
        """
        callback method invoked by SASL lib
        """
        # The following print command might be useful for debugging
        # new sasl mechanisms. So it is left here
        cb_result = self.cb_value_dict.get(cb_id, defresult) or b''
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
            authc_id,
            password,
            authz_id='',
            trace_level=0,
        ):
        SaslAuth.__init__(
            self,
            {
                CB_AUTHNAME: authc_id.encode(self.encoding),
                CB_PASS: password,
                CB_USER: authz_id.encode(self.encoding),
            },
            trace_level=trace_level,
        )


class SaslNoninteractiveAuth(SaslAuth):
    """
    This class handles non-interactive SASL authentication mechs
    like EXTERNAL or GSSAPI.
    """

    def __init__(
            self,
            authz_id=b'',
            trace_level=0,
        ):
        SaslAuth.__init__(
            self,
            {
                CB_USER: authz_id.encode(self.encoding),
            },
            trace_level=trace_level,
        )

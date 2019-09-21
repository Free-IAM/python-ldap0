# -*- coding: utf-8 -*-
"""
ldap0.err - error classes
"""

import _libldap0
from . import LDAPError

from .__about__ import __version__, __author__, __license__

__all__ = [
    'LIMIT_EXCEPTIONS',
    'NoUniqueEntry',
    'PasswordPolicyException',
    'PasswordPolicyChangeAfterReset',
    'PasswordPolicyExpirationWarning',
    'PasswordPolicyExpiredError',
]

LIMIT_EXCEPTIONS = (
    _libldap0.TIMEOUT,
    _libldap0.TIMELIMIT_EXCEEDED,
    _libldap0.SIZELIMIT_EXCEEDED,
    _libldap0.ADMINLIMIT_EXCEEDED,
)

#-----------------------------------------------------------------------
# Some custom exception classes for password policy handling
#-----------------------------------------------------------------------

class PasswordPolicyException(LDAPError):
    """
    Base class for raising password policy related exceptions
    """

    def __init__(self, who=None, desc=None):
        self.who = who
        self.desc = desc

    def __str__(self):
        return self.desc


class PasswordPolicyChangeAfterReset(PasswordPolicyException):
    """
    Exception class for password change after reset warning
    """


class PasswordPolicyExpirationWarning(PasswordPolicyException):
    """
    Exception class for password expiry warning
    """

    def __init__(self, who=None, desc=None, timeBeforeExpiration=None):
        PasswordPolicyException.__init__(self, who, desc)
        self.timeBeforeExpiration = timeBeforeExpiration


class PasswordPolicyExpiredError(PasswordPolicyException):
    """
    Exception class for password expired error
    """

    def __init__(self, who=None, desc=None, graceAuthNsRemaining=None):
        PasswordPolicyException.__init__(self, who, desc)
        self.graceAuthNsRemaining = graceAuthNsRemaining


#-----------------------------------------------------------------------
# Some custom exception classes for search errors
#-----------------------------------------------------------------------

class NoUniqueEntry(_libldap0.NO_SUCH_OBJECT):
    """
    Exception raised if a LDAP search returned more than entry entry
    although assumed to return a unique single search result.
    """

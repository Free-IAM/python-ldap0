# -*- coding: utf-8 -*-
"""
ldap0.pw - stuff for passwords
"""

from __future__ import absolute_import

import string
from random import SystemRandom

__all__ = [
    'random_string',
    'unicode_pwd',
]

# default length for generated passwords
PWD_LENGTH = 40

# alphabet used  for generated passwords
PWD_ALPHABET = string.ascii_letters + string.digits


def random_string(alphabet=PWD_ALPHABET, length=PWD_LENGTH):
    """
    Returns a random password byte string consisting of `length' bytes of
    chars found in `alphabet'.
    """
    sys_rand = SystemRandom()
    random_upper_bound = len(alphabet) - 1
    return ''.join([
        alphabet[sys_rand.randint(0, random_upper_bound)]
        for _ in range(length)
    ])


def unicode_pwd(password=None, alphabet=PWD_ALPHABET, length=PWD_LENGTH):
    """
    returns password or random generated password as properly encoded
    'unicodePwd' value for MS AD

    see also:
    https://msdn.microsoft.com/en-us/library/cc223248.aspx
    https://support.microsoft.com/en-us/help/269190/how-to-change-a-windows-active-directory-and-lds-user-password-through-ldap
    """
    if password is None:
        password = random_string(alphabet=alphabet, length=length)
    return u'"{}"'.format(password.decode('utf-8')).encode('utf-16-le')

# -*- coding: utf-8 -*-
"""
ldap0.pw - stuff for passwords
"""

import hashlib
import string
import secrets
from binascii import hexlify
from typing import Union, Optional

from .__about__ import __version__, __author__, __license__

__all__ = [
    'ntlm_password_hash',
    'random_string',
    'unicode_pwd',
    'PWD_ALPHABET',
    'PWD_LENGTH',
]

# default length for generated passwords
PWD_LENGTH = 40

# alphabet used for generated passwords
PWD_ALPHABET = (string.ascii_letters + string.digits).encode('ascii')

# Alphabet for encrypted passwords (see module crypt)
PWD_UNIX_CRYPT_ALPHABET = b'./0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ'


def random_string(
        alphabet: Union[str, bytes, None] = PWD_ALPHABET,
        length: int = PWD_LENGTH,
    ) -> Union[str, bytes]:
    """
    Returns a random password byte string consisting of `length' bytes of
    chars found in `alphabet'.
    """
    if alphabet is None:
        return secrets.token_bytes(length)
    random_upper_bound = len(alphabet) - 1
    res = []
    for _ in range(length):
        res.append(secrets.choice(alphabet))
    if isinstance(alphabet, bytes):
        return bytes(res)
    return ''.join(res)


def unicode_pwd(
        password: Optional[bytes] = None,
        alphabet: bytes = PWD_ALPHABET,
        length: int = PWD_LENGTH,
    ) -> bytes:
    """
    returns password or random generated password as properly encoded
    'unicodePwd' value for MS AD

    :password: must be UTF-8 encoded bytes

    see also:
    https://msdn.microsoft.com/en-us/library/cc223248.aspx
    https://support.microsoft.com/en-us/help/269190/how-to-change-a-windows-active-directory-and-lds-user-password-through-ldap
    """
    if password is None:
        password = random_string(alphabet=alphabet, length=length)
    return u'"{}"'.format(password.decode('utf-8')).encode('utf-16-le')


def ntlm_password_hash(password: bytes) -> bytes:
    """
    returns MD4-based NT password hash for a password.

    :password: must be UTF-8 encoded bytes
    """
    md4_digest = hashlib.new('md4')
    md4_digest.update(password.decode('utf-8')[:128].encode('utf-16-le'))
    return hexlify(md4_digest.digest()).upper()

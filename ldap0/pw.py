# -*- coding: utf-8 -*-
"""
ldap0.pw - stuff for passwords
"""

import hashlib
import string
from binascii import hexlify
from random import SystemRandom

from .__about__ import __version__, __author__, __license__

__all__ = [
    'ntlm_password_hash',
    'random_string',
    'unicode_pwd',
    'PWD_ALPHABET',
    'PWD_LENGTH',
    'PWD_OCTETS_ALPHABET',
]

# default length for generated passwords
PWD_LENGTH = 40

# alphabet used for generated passwords
PWD_ALPHABET = (string.ascii_letters + string.digits).encode('ascii')

# Alphabet for encrypted passwords (see module crypt)
PWD_UNIX_CRYPT_ALPHABET = b'./0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ'

# alphabet used for generating completely random byte strings
PWD_OCTETS_ALPHABET = (
    b'\x00\x01\x02\x03\x04\x05\x06\x07\x08\t\n\x0b\x0c\r\x0e\x0f'
    b'\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f'
    b' !"#$%&\'()*+,-./'
    b'0123456789:;<=>?'
    b'@ABCDEFGHIJKLMNO'
    b'PQRSTUVWXYZ[\\]^_'
    b'`abcdefghijklmno'
    b'pqrstuvwxyz{|}~\x7f'
    b'\x80\x81\x82\x83\x84\x85\x86\x87\x88\x89\x8a\x8b\x8c\x8d\x8e\x8f'
    b'\x90\x91\x92\x93\x94\x95\x96\x97\x98\x99\x9a\x9b\x9c\x9d\x9e\x9f'
    b'\xa0\xa1\xa2\xa3\xa4\xa5\xa6\xa7\xa8\xa9\xaa\xab\xac\xad\xae\xaf'
    b'\xb0\xb1\xb2\xb3\xb4\xb5\xb6\xb7\xb8\xb9\xba\xbb\xbc\xbd\xbe\xbf'
    b'\xc0\xc1\xc2\xc3\xc4\xc5\xc6\xc7\xc8\xc9\xca\xcb\xcc\xcd\xce\xcf'
    b'\xd0\xd1\xd2\xd3\xd4\xd5\xd6\xd7\xd8\xd9\xda\xdb\xdc\xdd\xde\xdf'
    b'\xe0\xe1\xe2\xe3\xe4\xe5\xe6\xe7\xe8\xe9\xea\xeb\xec\xed\xee\xef'
    b'\xf0\xf1\xf2\xf3\xf4\xf5\xf6\xf7\xf8\xf9\xfa\xfb\xfc\xfd\xfe\xff'
)

def random_string(alphabet=PWD_ALPHABET, length=PWD_LENGTH):
    """
    Returns a random password byte string consisting of `length' bytes of
    chars found in `alphabet'.
    """
    sys_rand = SystemRandom()
    random_upper_bound = len(alphabet) - 1
    res = []
    for _ in range(length):
        pos = sys_rand.randint(0, random_upper_bound)
        res.append(alphabet[pos:pos+1])
    return b''.join(res)


def unicode_pwd(password=None, alphabet=PWD_ALPHABET, length=PWD_LENGTH):
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


def ntlm_password_hash(password):
    """
    returns MD4-based NT password hash for a password.

    :password: must be UTF-8 encoded bytes
    """
    md4_digest = hashlib.new('md4')
    md4_digest.update(password.decode('utf-8')[:128].encode('utf-16-le'))
    return hexlify(md4_digest.digest()).upper()

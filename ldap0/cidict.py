# -*- coding: utf-8 -*-
"""
ldap0.cidict - custom dictionary classes with case-insensitive string-keys
"""

from collections import UserDict

from .__about__ import __version__, __author__, __license__


class CIDict(UserDict):
    """
    Case-insensitive but case-respecting dictionary.
    """

    def __init__(self, default=None, keytype=None):
        self._keys = {}
        self._keytype = keytype
        UserDict.__init__(self, {})
        self.update(default or {})

    def __getitem__(self, key):
        return self.data[key.lower()]

    def __setitem__(self, key, value):
        if self._keytype is None:
            self._keytype = type(key)
        if not isinstance(key, self._keytype):
            raise TypeError('Expected %s for key, got %r' % (self._keytype.__name__, key))
        lower_key = key.lower()
        self._keys[lower_key] = key
        self.data[lower_key] = value

    def __delitem__(self, key):
        lower_key = key.lower()
        del self._keys[lower_key]
        del self.data[lower_key]

    def update(self, data):
        for key in data.keys():
            self[key] = data[key]

    def has_key(self, key):
        raise NotImplementedError('do not use %s.has_key() method' % (self.__class__.__name__,))

    def __contains__(self, key):
        return UserDict.__contains__(self, key.lower())

    def keys(self):
        return self._keys.values()

    def items(self):
        for k in self._keys.values():
            yield (k, self[k])
        return


class SingleValueDict(CIDict):
    """
    dictionary for reading only the 1st attribute value
    (strictly relational data model)
    """

    def __setitem__(self, key, val):
        return CIDict.__setitem__(self, key, val[0])

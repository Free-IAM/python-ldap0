# -*- coding: utf-8 -*-
"""
ldap0.cidict - custom dictionary class with keys being strings handled case-insensitive
"""

from __future__ import absolute_import

from .compat import User_Dict
from .__about__ import __version__, __author__, __license__


class cidict(User_Dict):
    """
    Case-insensitive but case-respecting dictionary.
    """

    def __init__(self, default=None):
        self._keys = {}
        User_Dict.__init__(self, {})
        self.update(default or {})

    def __getitem__(self, key):
        return self.data[key.lower()]

    def __setitem__(self, key, value):
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
        return key in self

    def __contains__(self, key):
        return User_Dict.__contains__(self, key.lower())

    def keys(self):
        return self._keys.values()

    def items(self):
        result = []
        for k in self._keys.values():
            result.append((k, self[k]))
        return result


class SingleValueDict(cidict):
    """
    dictionary for reading only the 1st attribute value
    (strictly relational data model)
    """

    def __setitem__(self, key, val):
        return cidict.__setitem__(self, key, val[0])

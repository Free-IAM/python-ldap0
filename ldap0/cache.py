# -*- coding: utf-8 -*-
"""
ldap0.cache - dict-like cache class
"""

#-----------------------------------------------------------------------
# Imports
#-----------------------------------------------------------------------

# from Python's standard lib
import time

#-----------------------------------------------------------------------
# Constants
#-----------------------------------------------------------------------

__all__ = [
    'Cache',
]


class Cache(dict):

    """
    Class implements a cache dictionary with
    timestamps attached to all dict keys
    """

    def __init__(self, cache_ttl=-1.0):
        """
        :cache_ttl: Time-to-live for cached entries in seconds
        """
        dict.__init__({})
        self._cache_ttl = cache_ttl
        self.cache_hit_count = 0
        self.max_cache_hit_time = 0.0

    def __getitem__(self, k):
        val, not_after = dict.__getitem__(self, k)
        if time.time() > not_after:
            dict.__delitem__(self, k)
            raise KeyError('cache entry expired')
        self.cache_hit_count += 1
        self.max_cache_hit_time = max(
            self.max_cache_hit_time,
            time.time() - not_after + self._cache_ttl
        )
        return val

    def __setitem__(self, k, v):
        return dict.__setitem__(
            self,
            k,
            (v, time.time()+self._cache_ttl)
        )

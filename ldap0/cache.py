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
    __slots__ = (
        '_ttl',
        'hit_count',
        'access_count',
        'max_cache_hit_time',
    )

    def __init__(self, ttl=-1.0):
        """
        :ttl: Time-to-live for cached entries in seconds
        """
        dict.__init__({})
        self._ttl = ttl
        self.hit_count = 0
        self.access_count = 0
        self.max_cache_hit_time = 0.0

    @property
    def miss_count(self) -> int:
        return self.access_count - self.hit_count

    @property
    def hit_ratio(self) -> float:
        """
        Returns percentage of cache hit ratio
        """
        try:
            return 100 * float(self.hit_count) / self.access_count
        except ZeroDivisionError:
            return 0.0

    def __getitem__(self, key):
        self.access_count += 1
        current_time = time.time()
        val, not_after = dict.__getitem__(self, key)
        if current_time > not_after:
            dict.__delitem__(self, key)
            raise KeyError('cache entry expired')
        self.hit_count += 1
        self.max_cache_hit_time = max(
            self.max_cache_hit_time,
            current_time - not_after + self._ttl
        )
        return val

    def __setitem__(self, key, val):
        return dict.__setitem__(
            self,
            key,
            (val, time.time()+self._ttl)
        )

    def cache(self, key, val, ttl=None):
        if ttl is None:
            ttl = self._ttl
        return dict.__setitem__(
            self,
            key,
            (val, time.time()+ttl)
        )

    def flush(self):
        self.hit_count = 0
        self.access_count = 0
        for key in self.keys():
            try:
                dict.__delitem__(self, key)
            except KeyError:
                pass

# -*- coding: utf-8 -*-
"""
Simple tests for module ldap0.cache
"""

# from Python's standard lib
import time
import unittest

import ldap0.cache


class TestCache(unittest.TestCase):
    """
    test ldap0.cache.Cache
    """

    def test_cache_simple(self):
        cache = ldap0.cache.Cache(ttl=1.0)
        with self.assertRaises(KeyError):
            cache['foo']
        self.assertEqual(cache.miss_count, 1)
        # seed the cache
        cache['foo'] = 'bar'
        self.assertEqual(len(cache), 1)
        orig_miss_count = cache.miss_count
        for i in range(0, 5):
            self.assertEqual(cache['foo'], 'bar')
            self.assertEqual(cache.hit_count, i+1)
            self.assertEqual(cache.miss_count, orig_miss_count)
        self.assertEqual(cache.hit_count, 5)
        # test expiry
        time.sleep(1.1)
        with self.assertRaises(KeyError):
            cache['foo']
        self.assertEqual(len(cache), 0)

    def test_cache_flush(self):
        cache = ldap0.cache.Cache(ttl=1.0)
        # seed the cache
        cache['foo'] = 'bar'
        self.assertEqual(len(cache), 1)
        self.assertEqual(cache['foo'], 'bar')
        self.assertEqual(cache.miss_count, 0)
        # test whether flushing cache works
        cache.flush()
        self.assertEqual(cache.hit_count, 0)
        self.assertEqual(cache.miss_count, 0)
        self.assertEqual(len(cache), 0)
        with self.assertRaises(KeyError):
            cache['foo']


if __name__ == '__main__':
    unittest.main()

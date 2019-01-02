# -*- coding: utf-8 -*-
"""
ldap0.logger - Helper class for using logging as trace file object
"""

from __future__ import absolute_import

import logging

from .__about__ import __version__, __author__, __license__

__all__ = [
    'LoggerFileObj',
]


class LoggerFileObj(object):
    """
    file-like helper class which sends log lines to a logging instance
    """

    def __init__(self, logger=None, logging_level=logging.DEBUG):
        if logger is None:
            self._logger = logging.getLogger()
        else:
            self._logger = logger
        self._logging_level = logging_level
        self.log_lines = 0

    def write(self, msg):
        """
        write msg to log
        """
        self._logger.log(self._logging_level, msg[:-1])
        self.log_lines += 1

    def read(self, size=None):
        """
        dummy read() method which raises IOError
        """
        raise IOError('File object of class %s is write-only' % (self.__class__.__name__))

    def flush(self):
        return


LOGGING_FILE_OBJ = LoggerFileObj()

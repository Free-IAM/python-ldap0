# -*- coding: utf-8 -*-
"""
Helper class for using logging as trace file object

See https://www.stroeder.com/python-ldap0 for details.
"""

import logging

from ldap0.pkginfo import __version__, __author__, __license__

class logging_file_class(object):

    def __init__(self, logging_level):
        self._logging_level = logging_level

    def write(self, msg):
        logging.log(self._logging_level, msg[:-1])

    def flush(self):
        return

logging_file_obj = logging_file_class(logging.DEBUG)

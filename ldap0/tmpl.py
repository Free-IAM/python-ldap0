# -*- coding: utf-8 -*-
"""
ldap0.tmpl - templating
"""

from typing import Optional, Tuple

from .__about__ import __version__, __author__, __license__
from .base import decode_entry_dict
from .typehints import EntryMixed, EntryStr


class TemplateEntry:
    """
    Base class typically not directly used
    """
    t_dn: Optional[str] = None
    t_entry: Optional[EntryStr] = None

    def __init__(
            self,
            t_dn: Optional[str] = None,
            t_entry: Optional[EntryStr] = None,
        ):
        # Strip out empty values
        if t_dn is not None:
            self.t_dn = t_dn
        if t_entry is not None:
            self.t_entry = t_entry

    def ldap_entry(self, data_dict, encoding: str = 'utf-8') -> Tuple[str, EntryMixed]:
        """
        returns 2-tuple (dn, entry) derived from
        string-keyed, single-valued :data_dict:
        """
        ldap_entry = {}
        for attr_type in self.t_entry:
            attr_values = []
            attr_value_set = set()
            for av_template in self.t_entry[attr_type]:
                try:
                    attr_value = av_template.format(**data_dict).encode(encoding)
                except KeyError:
                    continue
                if attr_value and attr_value not in attr_value_set:
                    attr_values.append(attr_value)
                    attr_value_set.add(attr_value)
            if attr_values:
                ldap_entry[attr_type.encode(encoding)] = attr_values
        ldap_dn = self.t_dn.format(**data_dict)
        return (ldap_dn, ldap_entry) # end of ldap_entry()

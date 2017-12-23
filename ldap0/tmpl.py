# -*- coding: utf-8 -*-
"""
ldap0.tmpl - templating
"""

from __future__ import absolute_import


class TemplateEntry(object):
    """
    Base class typically not directly used
    """
    dn_template = ''
    entry_template = {'objectClass': ['top']}

    def __init__(self, data):
        # Strip out empty values
        self.data = data

    def ldap_entry(self):
        """
        returns LDAP entry derived from data as 2-tuple (dn, entry)
        """
        ldap_entry = {}
        for attr_type in self.entry_template:
            attr_values = []
            attr_value_set = set()
            for av_template in self.entry_template[attr_type]:
                try:
                    attr_value = av_template.format(**self.data)
                except KeyError:
                    continue
                if attr_value and attr_value not in attr_value_set:
                    attr_values.append(attr_value)
                    attr_value_set.add(attr_value)
            if attr_values:
                ldap_entry[attr_type] = attr_values
        ldap_dn = self.dn_template.format(**self.data)
        return (ldap_dn, ldap_entry) # end of ldap_entry()

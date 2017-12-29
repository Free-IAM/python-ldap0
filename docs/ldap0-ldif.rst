:mod:`ldap0.ldif` LDIF parser and generator
===========================================

.. py:module:: ldap0.ldif
   :synopsis: Parses and generates LDIF files
.. moduleauthor:: Michael Ströder <michael@stroeder.com>


This module parses and generates LDAP data in the format LDIF.

.. seealso::

   :rfc:`2849` - The LDAP Data Interchange Format (LDIF) - Technical Specification


Classes
^^^^^^^

.. autoclass:: ldap0.ldif.LDIFWriter
   :members:

.. autoclass:: ldap0.ldif.LDIFParser
   :members:


.. _ldif-example:

Example
^^^^^^^

The following example demonstrates how to write LDIF output
of an LDAP entry with :mod:`ldif` module.

>>> import sys, ldap0.ldif
>>> entry={'objectClass':['top','person'],'cn':['Michael Stroeder'],'sn':['Stroeder']}
>>> dn='cn=Michael Stroeder,ou=Test'
>>> ldif_writer=ldap0.ldif.LDIFWriter(sys.stdout)
>>> ldif_writer.unparse(dn,entry)
dn: cn=Michael Stroeder,ou=Test
cn: Michael Stroeder
objectClass: top
objectClass: person
sn: Stroeder


The following example demonstrates how to parse an LDIF file
with :mod:`ldif` module, skip some entries and write the result to stdout. ::

   import sys
   from ldap0.ldif import LDIFParser, LDIFWriter

   parser = LDIFParser(open("input.ldif", 'rb'), sys.stdout)
   for dn, entry in parser.parse_entry_records():
       print dn, entry

:mod:`ldap0.ldif` LDIF parser and generator
===========================================

.. py:module:: ldap0.ldif
   :synopsis: Parses and generates LDIF files
.. moduleauthor:: Michael Ströder <michael@stroeder.com>


This module parses and generates LDAP data in the format LDIF.

.. seealso::

   :rfc:`2849` - The LDAP Data Interchange Format (LDIF) - Technical Specification


Functions
^^^^^^^^^

.. autofunction:: ldap0.ldif.CreateLDIF

.. autofunction:: ldap0.ldif.ParseLDIF


Classes
^^^^^^^

.. autoclass:: ldap0.ldif.LDIFWriter
   :members:

.. autoclass:: ldap0.ldif.LDIFParser
   :members:

.. autoclass:: LDIFRecordList
   :members:

.. autoclass:: LDIFCopy
   :members:


.. _ldif-example:

Example
^^^^^^^

The following example demonstrates how to write LDIF output
of an LDAP entry with :mod:`ldif` module.

>>> import sys,ldif
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
   from ldif import LDIFParser,LDIFWriter

   SKIP_DN = ["uid=foo,ou=People,dc=example,dc=com",
      "uid=bar,ou=People,dc=example,dc=com"]

   class MyLDIF(LDIFParser):
      def __init__(self,input,output):
         LDIFParser.__init__(self,input)
         self.writer = LDIFWriter(output)

      def handle(self,dn,entry):
         if dn in SKIP_DN:
           return
         self.writer.unparse(dn,entry)

   parser = MyLDIF(open("input.ldif", 'rb'), sys.stdout)
   parser.parse()


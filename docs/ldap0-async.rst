***************************************************************
:py:mod:`ldap0.async` Stream-processing of large search results
***************************************************************

.. py:module:: ldap0.async
   :synopsis: Framework for stream-processing of large search results.

Consider to use method :py:meth:`ldap0.ldapobject.LDAPObject.results()` instead.

Classes
=======

.. autoclass:: ldap0.async.AsyncSearchHandler
   :members:

.. autoclass:: ldap0.async.List
   :members:

.. autoclass:: ldap0.async.Dict
   :members:

.. autoclass:: ldap0.async.IndexedDict
   :members:

.. autoclass:: ldap0.async.LDIFWriter
   :members:

.. _ldap0.async-example:

Examples
========

.. _ldap0.async-example.List:

Using ldap0.async.List
^^^^^^^^^^^^^^^^^^^^^^

This example demonstrates how to use class ldap0.async.List for
retrieving partial search results even though the exception
:exc:`ldap0.SIZELIMIT_EXCEEDED` was raised because a server side limit was hit. ::

   import sys, ldap0, ldap0.ldapobject, ldap0.async

   s = ldap0.async.List(
       ldap0.ldapobject.LDAPObject('ldap://localhost'),
   )

   s.startSearch(
       'dc=stroeder,dc=com', ldap0.SCOPE_SUBTREE, '(objectClass=*)',
   )

   try:
      partial = s.processResults()
   except ldap0.SIZELIMIT_EXCEEDED:
       sys.stderr.write('Warning: Server-side size limit exceeded.\n')
   else:
       if partial:
           sys.stderr.write('Warning: Only partial results received.\n')

   sys.stdout.write(
       '%d results received.\n' % (
         len(s.allResults)
       )
   )

.. _ldap0.async-example.LDIFWriter:

Using ldap0.async.LDIFWriter
^^^^^^^^^^^^^^^^^^^^^^^^^^^^

This example demonstrates how to use class ldap0.async.LDIFWriter
for writing search results as LDIF to stdout. ::

   import sys, ldap0, ldap0.ldapobject, ldap0.async

   s = ldap0.async.LDIFWriter(
       ldap0.ldapobject.LDAPObject('ldap://localhost:1390'),
       sys.stdout
   )

   s.startSearch(
       'dc=stroeder,dc=com', ldap0.SCOPE_SUBTREE, '(objectClass=*)',
   )

   try:
       partial = s.processResults()
   except ldap0.SIZELIMIT_EXCEEDED:
       sys.stderr.write('Warning: Server-side size limit exceeded.\n')
   else:
       if partial:
           sys.stderr.write('Warning: Only partial results received.\n')

   sys.stderr.write(
       '%d results received.\n' % (
           s.endResultBreak-s.beginResultsDropped
       )
   )


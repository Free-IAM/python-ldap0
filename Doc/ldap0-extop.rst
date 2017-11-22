********************************************************************
:py:mod:`ldap0.extop` High-level access to LDAPv3 extended operations
********************************************************************

.. py:module:: ldap0.extop
   :synopsis: High-level access to LDAPv3 extended operations.


Classes
=======

This module defines the following classes:

.. autoclass:: ldap0.extop.ExtendedRequest
   :members:


.. autoclass:: ldap0.extop.ExtendedResponse
   :members:


:py:mod:`ldap0.extop.dds` Classes for Dynamic Entries extended operations
========================================================================

.. py:module:: ldap0.extop.dds
   :synopsis: Classes for Dynamic Entries extended operations

This requires :py:mod:`pyasn1` and :py:mod:`pyasn1_modules` to be installed.

.. seealso::

   :rfc:`2589` - Lightweight Directory Access Protocol (v3): Extensions for Dynamic Directory Services


.. autoclass:: ldap0.extop.dds.RefreshRequest
   :members:


.. autoclass:: ldap0.extop.dds.RefreshResponse
   :members:


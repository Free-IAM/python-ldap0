:py:mod:`ldap0.filter` LDAP filter handling
===========================================

.. py:module:: ldap0.filter
   :synopsis: LDAP filter handling.
.. moduleauthor:: Michael Ströder <michael@stroeder.com>


.. % Author of the module code;


.. seealso::

   :rfc:`4515` - Lightweight Directory Access Protocol (LDAP): String Representation of Search Filters.

The :mod:`ldap0.filter` module defines the following functions:


.. function:: escape_str(assertion_value)

   This function escapes characters in *assertion_value* which  are special in LDAP
   filters. You should use this function when  building LDAP filter strings from
   arbitrary input.

   .. % -> string

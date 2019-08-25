:py:mod:`ldap0.dn` LDAP Distinguished Name handling
===================================================

.. py:module:: ldap0.dn
   :synopsis: LDAP Distinguished Name handling.
.. moduleauthor:: Michael Ströder <michael@stroeder.com>


.. % Author of the module code;


.. seealso::

   For LDAPv3 DN syntax see:

   :rfc:`4514` - Lightweight Directory Access Protocol (LDAP): String Representation of Distinguished Names

.. seealso::

   For deprecated LDAPv2 DN syntax (obsoleted by LDAPv3) see:

   :rfc:`1779` - A String Representation of Distinguished Names

The :mod:`ldap0.dn` module defines the following functions:


.. function:: escape_chars(val) -> string

   This function escapes characters in string *val* which  are special in LDAP
   distinguished names. You should use  this function when building LDAP DN strings
   from arbitrary input.


.. function:: is_dn(dn[, flags=0]) -> boolean

   This function checks whether *dn* is a valid LDAP distinguished name by
   passing it to function :func:`str2dn`.

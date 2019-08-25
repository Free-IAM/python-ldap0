Module ldap0
============

Module package *ldap0* provides an object-oriented API to access LDAP
directory servers from Python programs. Mainly it wraps the OpenLDAP 2.x
libs for that purpose.

Additionally the package contains some Python modules for:

  * parsing and producing LDIF
  * handling LDAP URLs
  * parse and handle LDAPv3 subschema
  * LDAPv3 extended operations and controls
  * automatic tests with OpenLDAP server

Installing this module is required for running this software:

  * [web2ldap](https://web2ldap.de)
  * [Æ-DIR](https://ae-dir.com)
  * [OATH-LDAP](https://oath-ldap.stroeder.com/)
  * [slapdcheck](https://pypi.org/project/slapdcheck/)

Further notes:

  * _ldap0_ means _ldap_ reset.
  * Version 0.3.0+ only works with Python 3.6 or newer!
    For Python 2 release 0.2.7 must be used.
  * This module is of no general use!
  * Don't use it for your own project!
    The API may change at any time without further notice!
    **You have been warned!**

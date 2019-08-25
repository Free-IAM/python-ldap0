*****************************************
:py:mod:`ldap0.ldapurl` LDAP URL handling
*****************************************

.. py:module:: ldap0.ldapurl
   :synopsis: Parses and generates LDAP URLs
.. moduleauthor:: Michael Ströder <michael@stroeder.com>


This module parses and generates LDAP URLs.

.. seealso::

   :rfc:`4516` - The LDAP URL Format


Constants
=========

The :mod:`ldap0.ldapurl` module exports the following constants:

.. py:data:: SEARCH_SCOPE

   This dictionary maps a search scope string identifier  to the corresponding
   integer value used with search operations  in :mod:`ldap`.


.. py:data:: SEARCH_SCOPE_STR

   This dictionary is the inverse to :const:`SEARCH_SCOPE`. It  maps a search scope
   integer value to the corresponding string identifier  used in a LDAP URL string
   representation.


.. py:data:: LDAP_SCOPE_BASE


.. py:data:: LDAP_SCOPE_ONELEVEL


.. py:data:: LDAP_SCOPE_SUBTREE


Functions
=========

.. autofunction:: ldap0.ldapurl.is_ldapurl


.. autofunction:: ldap0.ldapurl.escape_str


Classes
=======

.. _ldapurl-ldapurl:

LDAP URLs
^^^^^^^^^

A :py:class:`LDAPUrl` object represents a complete LDAP URL.

.. autoclass:: ldap0.ldapurl.LDAPUrl
   :members:


LDAP URL extensions
^^^^^^^^^^^^^^^^^^^

A :py:class:`LDAPUrlExtension` object represents a single LDAP URL extension
whereas :py:class:`LDAPUrlExtensions` represents a list of LDAP URL extensions.


.. _ldapurl-ldapurlextension:

.. autoclass:: ldap0.ldapurl.LDAPUrlExtension
   :members:

.. _ldapurl-ldapurlextensions:

.. autoclass:: ldap0.ldapurl.LDAPUrlExtensions
   :members:


.. _ldapurl-example:

Example
^^^^^^^

Important security advice:
For security reasons you shouldn't specify passwords in LDAP URLs
unless you really know what you are doing.

The following example demonstrates how to parse a LDAP URL
with :mod:`ldapurl` module.


>>> import ldap0.ldapurl
>>> ldap_url = ldap0.ldapurlLDAPUrl('ldap://localhost:1389/dc=example,dc=com?cn,mail???bindname=cn=Michael%2cdc=stroeder%2cdc=com,X-BINDPW=secret')
>>> # Using the parsed LDAP URL by reading the class attributes
>>> ldap_url.dn
'dc=example,dc=com'
>>> ldap_url.hostport
'localhost:1389'
>>> ldap_url.attrs
['cn','mail']
>>> ldap_url.filterstr
'(objectclass=*)'
>>> ldap_url.who
'cn=Michael,dc=example,dc=com'
>>> ldap_url.cred
'secret'
>>> ldap_url.scope
0


The following example demonstrates how to generate a LDAP URL
with \module{ldapurl} module.

>>> from ldap0.ldapurl import LDAPUrl
>>> ldap_url = LDAPUrl(hostport='localhost:1389',dn='dc=example,dc=com',attrs=['cn','mail'],who='cn=Michael,dc=example,dc=com',cred='secret')
>>> ldap_url.unparse()
'ldap://localhost:1389/dc=example,dc=com?cn,mail?base?(objectclass=*)?bindname=cn=Michael%2Cdc=stroeder%2Cdc=com,X-BINDPW=secret'


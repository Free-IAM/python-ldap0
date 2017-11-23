************************************************
:py:mod:`ldap0.sasl` SASL Authentication Methods
************************************************

.. py:module:: ldap0.sasl

This module implements various authentication methods for SASL bind.

.. seealso::

   :rfc:`4422` - Simple Authentication and Security Layer (SASL)
   :rfc:`4513` - Lightweight Directory Access Protocol (LDAP): Authentication Methods and Security Mechanisms


Constants
=========

.. py:data:: CB_USER

.. py:data:: CB_AUTHNAME

.. py:data:: CB_LANGUAGE

.. py:data:: CB_PASS

.. py:data:: CB_ECHOPROMPT

.. py:data:: CB_NOECHOPROMPT

.. py:data:: CB_GETREALM


Classes
=======

.. autoclass:: ldap0.sasl.sasl
   :members:
   
   This class is used with :py:meth:`ldap.LDAPObject.sasl_interactive_bind_s()`.


.. autoclass:: ldap0.sasl.cram_md5
   :members:


.. autoclass:: ldap0.sasl.digest_md5
   :members:


.. autoclass:: ldap0.sasl.gssapi
   :members:

   You might consider using convenience method :py:meth:`ldap.LDAPObject.sasl_gssapi_bind_s()`.


.. autoclass:: ldap0.sasl.external
   :members:

   You might consider using convenience method :py:meth:`ldap.LDAPObject.sasl_external_bind_s()`.


.. _ldap0.sasl-example:

Examples for ldap0.sasl
^^^^^^^^^^^^^^^^^^^^^^^

This example connects to an OpenLDAP server via LDAP over IPC
(see `draft-chu-ldap-ldapi <https://tools.ietf.org/html/draft-chu-ldap-ldapi>`_)
and sends a SASL external bind request.

::

   import ldap, ldap0.sasl, urllib

   ldapi_path = '/tmp/openldap-socket'
   ldap_conn = ldap.initialize(
       'ldapi://%s' % (
           urllib.quote_plus(ldapi_path)
       )
   )
   # Send SASL bind request for mechanism EXTERNAL
   ldap_conn.sasl_non_interactive_bind_s('EXTERNAL')
   # Find out the SASL Authorization Identity
   print ldap_conn.whoami_s()


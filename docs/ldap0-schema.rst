*********************************************
:py:mod:`ldap0.schema` Handling LDAPv3 schema
*********************************************

.. py:module:: ldap0.schema
   :synopsis: Parses and handles LDAPv3 subschema information
.. moduleauthor:: Michael Ströder <michael@stroeder.com>

This module deals with schema information usually retrieved from
a special subschema subentry provided by the server.
It is closely modeled along the directory information model described
in the following RFC with which you should make yourself familiar
when trying to use this module:

.. seealso::

   :rfc:`4512` - Lightweight Directory Access Protocol (LDAP): Directory Information Models


:py:mod:`ldap0.schema.subentry` Processing LDAPv3 subschema subentry
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

.. py:module:: ldap0.schema.subentry


.. py:data:: NOT_HUMAN_READABLE_LDAP_SYNTAXES

   Dictionary where the keys are the OIDs of LDAP syntaxes known to be
   not human-readable when displayed to a console without conversion
   and which cannot be decoded to a :py:data:`types.UnicodeType`.


Functions
=========

.. autofunction:: ldap0.schema.util.urlfetch

Classes
=======

.. autoclass:: ldap0.schema.subentry.SubSchema
   :members:


:py:mod:`ldap0.schema.models` Schema elements
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

.. py:module:: ldap0.schema.models


.. autoclass:: ldap0.schema.models.Entry
   :members:

.. autoclass:: ldap0.schema.models.SchemaElement
   :members:

.. autoclass:: ldap0.schema.models.AttributeType
   :members:

.. autoclass:: ldap0.schema.models.ObjectClass
   :members:

.. autoclass:: ldap0.schema.models.MatchingRule
   :members:

.. autoclass:: ldap0.schema.models.MatchingRuleUse
   :members:

.. autoclass:: ldap0.schema.models.DITContentRule
   :members:

.. autoclass:: ldap0.schema.models.NameForm
   :members:

.. autoclass:: ldap0.schema.models.DITStructureRule
   :members:


.. _ldap0.schema-example:

Examples for ldap0.schema
^^^^^^^^^^^^^^^^^^^^^^^^^

::

   import ldap0.schema

# -*- coding: utf-8 -*-
"""
Automatic tests for class ldap0.schema.SubSchema
"""

import unittest
from pprint import pformat

import ldap0.ldif
from ldap0.schema.util import urlfetch, modify_modlist
from ldap0.schema.subentry import SubSchema, SCHEMA_ATTR_MAPPING, SCHEMA_CLASS_MAPPING, OIDNotUnique, NameNotUnique
from ldap0.schema.models import AttributeType, ObjectClass, NameForm, Entry, SchemaElementOIDSet

class TestBasics(unittest.TestCase):

    def test_constants(self):
        self.assertEqual(len(SCHEMA_ATTR_MAPPING), 8)
        self.assertEqual(len(SCHEMA_CLASS_MAPPING), 8)


class SubschemaTest(unittest.TestCase):
    """
    Base class for implementing checks based on local schema files
    """
    maxDiff = 10000
    schema_file = 'file:tests/ldif/subschema-openldap-all.ldif'

    @classmethod
    def setUpClass(cls):
        super(SubschemaTest, cls).setUpClass()
        cls.schema_dn, cls.sub_schema = urlfetch(cls.schema_file, check_uniqueness=2)


class TestSubschema(SubschemaTest):
    """
    test ldap0.schema.SubSchema with subschema subentries read from LDIF files
    """

    def test001_basics(self):
        self.assertEqual(self.schema_dn, b'cn=Subschema')
        self.assertEqual(
            len(SCHEMA_CLASS_MAPPING),
            len(self.sub_schema.name2oid),
        )
        self.assertEqual(
            len(SCHEMA_CLASS_MAPPING),
            len(self.sub_schema.sed),
        )

    def test002_attribute_cn(self):
        # check the attribute type 'cn' alias 'commonName'
        oid = self.sub_schema.name2oid[ldap0.schema.models.AttributeType]['cn']
        self.assertEqual(oid, '2.5.4.3')
        self.assertEqual(oid, self.sub_schema.name2oid[ldap0.schema.models.AttributeType]['commonName'])
        cn_at = self.sub_schema.sed[ldap0.schema.models.AttributeType][oid]
        self.assertEqual(cn_at.names, ('cn', 'commonName'))
        self.assertEqual(cn_at.desc, 'RFC4519: common name(s) for which the entity is known by')
        self.assertEqual(cn_at.sup, ('name',))
        self.assertEqual(cn_at.syntax, None)
        self.assertEqual(cn_at.equality, None)
        self.assertEqual(cn_at.substr, None)
        self.assertEqual(cn_at.ordering, None)

    def test003_objectclass_inetorgperson(self):
        # check the object class 'inetOrgPerson'
        oid = self.sub_schema.name2oid[ldap0.schema.models.ObjectClass]['inetOrgPerson']
        self.assertEqual(oid, '2.16.840.1.113730.3.2.2')
        inop_oc = self.sub_schema.sed[ldap0.schema.models.ObjectClass][oid]
        self.assertEqual(inop_oc.names, ('inetOrgPerson',))
        self.assertEqual(inop_oc.desc, 'RFC2798: Internet Organizational Person')
        self.assertEqual(inop_oc.sup, ('organizationalPerson',))
        self.assertEqual(inop_oc.must, ())
        self.assertEqual(
            inop_oc.may,
            (
                'audio', 'businessCategory', 'carLicense',
                'departmentNumber', 'displayName', 'employeeNumber',
                'employeeType', 'givenName', 'homePhone',
                'homePostalAddress', 'initials', 'jpegPhoto',
                'labeledURI', 'mail', 'manager', 'mobile', 'o',
                'pager', 'photo', 'roomNumber', 'secretary', 'uid',
                'userCertificate', 'x500uniqueIdentifier',
                'preferredLanguage', 'userSMIMECertificate',
                'userPKCS12'
            ),
        )

    def test004_attribute_inheritance(self):
        # check SubSchema.get_syntax()
        self.assertEqual(self.sub_schema.get_syntax('does_not_exist_in_self.sub_schema'), None)
        self.assertEqual(self.sub_schema.get_syntax('cn'), '1.3.6.1.4.1.1466.115.121.1.15')
        # check some class attributes inherited by attribute type 'name'
        self.assertEqual(
            self.sub_schema.get_inheritedattr(AttributeType, 'cn', 'syntax'),
            '1.3.6.1.4.1.1466.115.121.1.15',
        )
        self.assertEqual(
            self.sub_schema.get_inheritedattr(AttributeType, 'cn', 'equality'),
            'caseIgnoreMatch',
        )
        self.assertEqual(
            self.sub_schema.get_inheritedattr(AttributeType, 'cn', 'substr'),
            'caseIgnoreSubstringsMatch',
        )
        cn_i_at = self.sub_schema.get_inheritedobj(
            AttributeType,
            'cn',
            ('syntax', 'equality', 'substr', 'ordering'),
        )
        self.assertEqual(cn_i_at.sup, ('name',))
        self.assertEqual(cn_i_at.syntax, '1.3.6.1.4.1.1466.115.121.1.15')
        self.assertEqual(cn_i_at.equality, 'caseIgnoreMatch')
        self.assertEqual(cn_i_at.substr, 'caseIgnoreSubstringsMatch')
        self.assertEqual(cn_i_at.ordering, None)

    def test005_determine_no_user_mod_attrs(self):
        """
        test SubSchema.determine_no_user_mod_attrs()
        """
        no_user_mod_attrs = self.sub_schema.determine_no_user_mod_attrs()
        self.assertEqual(len(no_user_mod_attrs), 54)
        self.assertIn('2.5.18.4', no_user_mod_attrs) # modifiersName
        no_user_mod_attrs_set = SchemaElementOIDSet(self.sub_schema, AttributeType, no_user_mod_attrs)
        self.assertIn('2.5.18.4', no_user_mod_attrs_set)
        self.assertIn('modifiersName', no_user_mod_attrs_set)
        # test SubSchema.determine_no_user_mod_attrs()
        op_attrs = self.sub_schema.get_all_operational_attributes()
        self.assertIn('2.5.18.4', op_attrs)
        self.assertIn('modifiersName', op_attrs)
        # check SubSchema.get_applicable_aux_classes()
        aux_classes = self.sub_schema.get_applicable_aux_classes('aeUser-dcr')
        self.assertEqual(
            sorted(aux_classes),
            [
                'inetLocalMailRecipient', 'ldapPublicKey', 'msPwdResetObject',
                'oathHOTPUser', 'oathTOTPUser', 'pkiUser', 'posixAccount'
            ],
        )

    def test006_get_structural_oc(self):
        """
        check SubSchema.get_structural_oc()
        """
        self.assertEqual(self.sub_schema.get_structural_oc([]), None)
        self.assertEqual(self.sub_schema.get_structural_oc(['posixAccount']), None)
        self.assertEqual(
            self.sub_schema.get_structural_oc(['inetOrgPerson']),
            '2.16.840.1.113730.3.2.2',
        )
        self.assertEqual(
            self.sub_schema.get_structural_oc(['inetOrgPerson', 'posixAccount']),
            '2.16.840.1.113730.3.2.2',
        )
        self.assertEqual(
            self.sub_schema.get_structural_oc([
                'person', 'organizationalPerson', 'inetOrgPerson', 'posixAccount'
            ]),
            '2.16.840.1.113730.3.2.2',
        )

    def test007_models_entry(self):
        """
        test ldap0.schema.models.Entry
        """
        ldap_entry = {
            b'objectClass': [b'aeSrvGroup'],
            b'cn': [b'test-srvgroup-1'],
            b'description': [b'testing...'],
        }
        ae_dn = 'cn=test-srvgroup-1,ou=ae-dir'
        ae_entry = Entry(self.sub_schema, ae_dn, ldap_entry)
        self.assertIn('cn', ae_entry)
        self.assertIn('2.5.4.3', ae_entry)
        self.assertNotIn('aeLoginGroups', ae_entry)
        self.assertEqual(
            list(ae_entry.get_possible_dit_structure_rules(ae_dn)),
            ['5'],
        )
        self.assertEqual(
            sorted(ae_entry.keys()),
            sorted([at.decode('ascii') for at in ldap_entry.keys()])
        )
        self.assertEqual(
            sorted(ae_entry.items()),
            sorted([(at.decode('ascii'), av) for at, av in ldap_entry.items()])
        )
        self.assertEqual(
            sorted(ae_entry.object_class_oid_set()),
            ['1.3.6.1.4.1.5427.1.389.100.6.13'],
        )
        self.assertEqual(ae_entry.get_rdn_templates(), ['cn='])

    def test008_name_forms(self):
        """
        test SubSchema.get_applicable_name_form_objs()
        """
        aeperson_oid = self.sub_schema.get_oid(ObjectClass, 'aePerson')
        self.assertEqual(aeperson_oid, '1.3.6.1.4.1.5427.1.389.100.6.8')
        name_forms = self.sub_schema.get_applicable_name_form_objs(
            'uniqueIdentifier=foo,cn=hr,ou=ae-dir',
            aeperson_oid,
        )
        self.assertEqual(len(name_forms), 1)
        self.assertEqual(
            str(name_forms[0]),
            str(NameForm("( 1.3.6.1.4.1.5427.1.389.42.15.12 NAME 'aePerson-aeZone-NF-uniqueIdentifier' OC aePerson MUST ( uniqueIdentifier ) )")),
        )

    def test009_tree(self):
        """
        test SubSchema.tree()
        """
        tree = self.sub_schema.tree(AttributeType)
        self.assertEqual(len(tree), 1490)

    def test010_check_uniqueness(self):
        """
        provoke exceptions to be raised because of non-unique OIDs or NAMEs
        """
        for non_unique_oid_tests in (
            {
                'attributeTypes': [
                    '( 1.2.3.4 NAME foo )',
                    '( 1.2.3.4 NAME bar )',
                ],
            },
            {
                'objectClasses': [
                    '( 1.2.3.4 NAME foo )',
                    '( 1.2.3.4 NAME bar )',
                ],
            },
        ):
            with self.assertRaises(OIDNotUnique):
                SubSchema(non_unique_oid_tests, check_uniqueness=2)
        for non_unique_name_tests in (
            {
                'attributeTypes': [
                    '( 1.2.3.4 NAME foo )',
                    '( 2.3.4.5 NAME foo )',
                ],
            },
            {
                'objectClasses': [
                    '( 1.2.3.4 NAME foo )',
                    '( 2.3.4.5 NAME foo )',
                ],
            },
        ):
            with self.assertRaises(NameNotUnique):
                SubSchema(non_unique_name_tests, check_uniqueness=2)

    def test011_get_subord_structural_oc_names(self):
        self.assertEqual(
            list(self.sub_schema.get_subord_structural_oc_names('42')[0]),
            [],
        )


class TestSchemaElementOIDSet(SubschemaTest):
    """
    Tests for class SchemaElementOIDSet
    """

    def test001_AttributeType(self):
        self.assertNotIn('cn', SchemaElementOIDSet(self.sub_schema, AttributeType, []))
        self.assertNotIn('cn', SchemaElementOIDSet(self.sub_schema, AttributeType, ['objectClass']))
        self.assertIn('cn', SchemaElementOIDSet(self.sub_schema, AttributeType, ['cn']))
        self.assertIn('2.5.4.3', SchemaElementOIDSet(self.sub_schema, AttributeType, ['cn']))
        self.assertIn('cn', SchemaElementOIDSet(self.sub_schema, AttributeType, ['2.5.4.3']))
        self.assertIn('commonName', SchemaElementOIDSet(self.sub_schema, AttributeType, ['2.5.4.3']))
        self.assertEqual(len(SchemaElementOIDSet(self.sub_schema, AttributeType, ['2.5.4.3', 'cn', 'commonName'])), 1)
        self.assertEqual(len(SchemaElementOIDSet(self.sub_schema, AttributeType, ['', ' ', '  '])), 0)
        self.assertIn('cn', SchemaElementOIDSet(self.sub_schema, AttributeType, ['@person']))
        self.assertEqual(
            sorted(SchemaElementOIDSet(self.sub_schema, AttributeType, ['@person'])),
            [
                '2.5.4.0',
                '2.5.4.13',
                '2.5.4.20',
                '2.5.4.3',
                '2.5.4.34',
                '2.5.4.35',
                '2.5.4.4',
            ]
        )
        self.assertEqual(
            sorted(SchemaElementOIDSet(self.sub_schema, AttributeType, ['foo', 'bar'])),
            ['bar', 'foo']
        )
        with self.assertRaises(KeyError):
            SchemaElementOIDSet(self.sub_schema, AttributeType, ['@foo'])
        se_set = SchemaElementOIDSet(self.sub_schema, AttributeType, ['cn'])
        self.assertNotIn('mail', se_set)
        se_set.add('mail')
        self.assertIn('mail', se_set)

    def test002_ObjectClass(self):
        self.assertNotIn('person', SchemaElementOIDSet(self.sub_schema, ObjectClass, []))
        self.assertIn('person', SchemaElementOIDSet(self.sub_schema, ObjectClass, ['person']))
        self.assertIn('person', SchemaElementOIDSet(self.sub_schema, ObjectClass, ['2.5.6.6']))
        self.assertEqual(len(SchemaElementOIDSet(self.sub_schema, ObjectClass, ['2.5.6.6', 'person'])), 1)
        self.assertEqual(len(SchemaElementOIDSet(self.sub_schema, ObjectClass, ['', ' ', '  '])), 0)
        self.assertEqual(
            sorted(SchemaElementOIDSet(self.sub_schema, ObjectClass, ['foo', 'bar'])),
            ['bar', 'foo']
        )
        with self.assertRaises(ValueError):
            SchemaElementOIDSet(self.sub_schema, ObjectClass, ['@foo'])
        se_set = SchemaElementOIDSet(self.sub_schema, ObjectClass, ['person'])
        self.assertNotIn('organizationalPerson', se_set)
        se_set.add('organizationalPerson')
        self.assertIn('organizationalPerson', se_set)

    def test003_names_property(self):
        self.assertEqual(SchemaElementOIDSet(self.sub_schema, ObjectClass, ['person', '2.5.6.6']).names, ['person'])
        self.assertEqual(SchemaElementOIDSet(self.sub_schema, AttributeType, ['cn', 'commonName', '2.5.4.3']).names, ['cn'])
        self.assertEqual(
            sorted(SchemaElementOIDSet(self.sub_schema, AttributeType, ['@person']).names),
            [
                'cn',
                'description',
                'objectClass',
                'seeAlso',
                'sn',
                'telephoneNumber',
                'userPassword',
            ]
        )


class TestModifyModlist(SubschemaTest):
    modify_modlist_tests = [
        (
            {
                b'objectClass':[b'person', b'pilotPerson'],
                b'cn':[b'Michael Str\303\266der', b'Michael Stroeder'],
                b'sn':[b'Str\303\266der'],
                b'enum':[b'a', b'b', b'c'],
                b'c':[b'DE'],
            },
            {
                b'objectClass':[b'person', b'inetOrgPerson'],
                b'cn':[b'Michael Str\303\266der', b'Michael Stroeder'],
                b'sn':[],
                b'enum':[b'a', b'b', b'd'],
                b'mail':[b'michael@stroeder.com'],
            },
            [],
            [
                (ldap0.MOD_DELETE, b'objectClass', [b'person', b'pilotPerson']),
                (ldap0.MOD_ADD, b'objectClass', [b'person', b'inetOrgPerson']),
                (ldap0.MOD_DELETE, b'c', [b'DE']),
                (ldap0.MOD_DELETE, b'sn', [b'Str\303\266der']),
                (ldap0.MOD_ADD, b'mail', [b'michael@stroeder.com']),
                (ldap0.MOD_DELETE, b'enum', None),
                (ldap0.MOD_ADD, b'enum', [b'a', b'b', b'd']),
            ]
        ),

        (
            {
                b'c':[b'DE'],
            },
            {
                b'c':[b'FR'],
            },
            [],
            [
                (ldap0.MOD_DELETE, b'c', [b'DE']),
                (ldap0.MOD_ADD, b'c', [b'FR']),
            ]
        ),

        (
            {
                b'objectClass':[b'person'],
                b'cn':[b'Michael Str\303\266der', b'Michael Stroeder'],
                b'sn':[b'Str\303\266der'],
                b'enum':[b'a', b'b'],
            },
            {
                b'objectClass':[b'inetOrgPerson'],
                b'cn':[b'Michael Str\303\266der', b'Michael Stroeder'],
                b'sn':[],
                b'enum':[b'a', b'B'],
            },
            ['objectClass'],
            [
                (ldap0.MOD_DELETE, b'sn', [b'Str\303\266der']),
                (ldap0.MOD_DELETE, b'enum', None),
                (ldap0.MOD_ADD, b'enum', [b'a', b'B']),
            ]
        ),

    ]

    def test_modify_modlist(self):
        for old_entry, new_entry, ignore_attr_types, test_modlist in self.modify_modlist_tests:
            result_modlist = modify_modlist(
                self.sub_schema,
                ldap0.schema.models.Entry(self.sub_schema, 'cn=test', old_entry),
                ldap0.schema.models.Entry(self.sub_schema, 'cn=test', new_entry),
                ignore_attr_types=ignore_attr_types,
            )
            self.assertEqual(
                sorted(test_modlist),
                sorted(result_modlist),
                '\nmodify_modlist(\n%s,\n%s\n)\nreturns\n%s\ninstead of\n%s.' % (
                    pformat(old_entry),
                    pformat(new_entry),
                    pformat(sorted(result_modlist)),
                    pformat(sorted(test_modlist)),
                )
            )
            result_modlist = modify_modlist(
                self.sub_schema,
                ldap0.schema.models.Entry(self.sub_schema, 'cn=test', old_entry),
                ldap0.schema.models.Entry(self.sub_schema, 'cn=test', new_entry),
                ignore_attr_types=SchemaElementOIDSet(self.sub_schema, AttributeType, ignore_attr_types),
            )
            self.assertEqual(
                sorted(test_modlist),
                sorted(result_modlist),
                '\nmodify_modlist(\n%s,\n%s\n)\nreturns\n%s\ninstead of\n%s.' % (
                    pformat(old_entry),
                    pformat(new_entry),
                    pformat(sorted(result_modlist)),
                    pformat(sorted(test_modlist)),
                )
            )


if __name__ == '__main__':
    unittest.main()

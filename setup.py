# -*- coding: utf-8 -*-
"""
package/install module package ldap0
"""

import sys
import os
import textwrap
from configparser import ConfigParser
from setuptools import setup, Extension, find_packages

PKG_NAME = 'ldap0'
BASEDIR = os.path.dirname(os.path.realpath(__file__))

sys.path.insert(0, os.path.join(BASEDIR, PKG_NAME))
import __about__

class OpenLDAP2BuildConfig:
    """
    class describing the features and requirements of OpenLDAP 2.x
    """

    def __init__(self, meta_defines):
        self.library_dirs = []
        self.include_dirs = []
        self.extra_compile_args = []
        self.extra_link_args = []
        self.extra_objects = []
        self.libs = ['ldap', 'lber']
        self.defines = []
        #-- Read the [_libldap0] section of setup.cfg
        cfg = ConfigParser()
        cfg.read(os.path.join(BASEDIR, 'setup.cfg'))
        _ldap_cfg = dict(cfg.items('_libldap0'))
        for name, value in _ldap_cfg.items():
            _ldap_cfg[name] = [ val for val in value.split(' ') if val ]
        for name, val in _ldap_cfg.items():
            setattr(self, name, val)
        if 'ldap_r' in self.libs or 'oldap_r' in self.libs:
            self.defines.append('HAVE_LIBLDAP_R')
        if 'sasl' in self.libs or 'sasl2' in self.libs or 'libsasl' in self.libs:
            self.defines.append('HAVE_SASL')
        if 'ssl' in self.libs and 'crypto' in self.libs:
            self.defines.append('HAVE_TLS')
        self.define_macros = [
            (defm, None)
            for defm in set(self.defines)
        ]
        self.define_macros.extend(meta_defines)
        self.include_dirs.insert(0, '_libldap0')
        if sys.platform.startswith("win"):
            self.library_dirs = []


LDAP_CLASS = OpenLDAP2BuildConfig(
    [
        ('LDAP0_MODULE_VERSION', __about__.__version__),
        ('LDAP0_MODULE_AUTHOR', __about__.__author__),
        ('LDAP0_MODULE_LICENSE', __about__.__license__),
    ],
)


setup(
    name=PKG_NAME,
    license=__about__.__license__,
    version=__about__.__version__,
    description='Module package for implementing LDAP clients'.format(PKG_NAME),
    author=__about__.__author__,
    author_email='michael@stroeder.com',
    maintainer=__about__.__author__,
    maintainer_email='michael@stroeder.com',
    url='https://gitlab.com/ae-dir/python-%s' % (PKG_NAME),
    download_url='https://pypi.python.org/pypi/%s/' % (PKG_NAME),
    keywords=[
        'LDAP',
        'OpenLDAP',
    ],
    #-- C extension modules
    ext_modules=[
        Extension(
            name='_libldap0',
            sources=[
                '_libldap0/ldapobject.c',
                '_libldap0/ldapcontrol.c',
                '_libldap0/common.c',
                '_libldap0/constants.c',
                '_libldap0/errors.c',
                '_libldap0/functions.c',
                '_libldap0/libldap0module.c',
                '_libldap0/message.c',
                '_libldap0/options.c',
            ],
            depends = [
                '_libldap0/ldapobject.h',
                '_libldap0/common.h',
                '_libldap0/constants.h',
                '_libldap0/functions.h',
                '_libldap0/ldapcontrol.h',
                '_libldap0/message.h',
                '_libldap0/options.h',
            ],
            libraries=LDAP_CLASS.libs,
            include_dirs=LDAP_CLASS.include_dirs,
            library_dirs=LDAP_CLASS.library_dirs,
            extra_compile_args=LDAP_CLASS.extra_compile_args,
            extra_link_args=LDAP_CLASS.extra_link_args,
            extra_objects=LDAP_CLASS.extra_objects,
            runtime_library_dirs=LDAP_CLASS.library_dirs,
            define_macros=LDAP_CLASS.define_macros,
        ),
    ],
    packages=find_packages(exclude=['tests']),
    package_dir={'': '.'},
    test_suite='tests',
    python_requires='>=3.6',
    include_package_data=True,
    install_requires=[
        'setuptools',
        'pyasn1>=0.4.5',
        'pyasn1_modules>=0.2.5',
    ],
    zip_safe=True,
)

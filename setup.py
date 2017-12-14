"""
setup.py - Setup package with the help Python's DistUtils
"""

import sys
import os
from ConfigParser import ConfigParser
from setuptools import setup, Extension

LDAP0_BASEDIR = os.path.dirname(os.path.realpath(__file__))

sys.path.insert(0, os.path.join(LDAP0_BASEDIR, 'ldap0'))
import pkginfo

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
        cfg.read(os.path.join(LDAP0_BASEDIR, 'setup.cfg'))
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
        ('LDAPMODULE_VERSION', pkginfo.__version__),
        ('LDAPMODULE_AUTHOR', pkginfo.__author__),
        ('LDAPMODULE_LICENSE', pkginfo.__license__),
    ],
)


#-- Let distutils/setuptools do the rest

setup(
    name='ldap0',
    license=pkginfo.__license__,
    version=pkginfo.__version__,
    description='Python modules for implementing LDAP clients',
    long_description="""ldap0 is a fork of python-ldap in separate module name-space:
    ldap0 provides an object-oriented API to access LDAP directory servers
    from Python programs. Mainly it wraps the OpenLDAP 2.x libs for that purpose.
    Additionally the package contains modules for other LDAP-related stuff
    (e.g. processing LDIF, LDAPURLs, LDAPv3 schema, LDAPv3 extended operations
    and controls, etc.).
    """,
    author=pkginfo.__author__,
    author_email='michael@stroeder.com',
    maintainer=pkginfo.__author__,
    maintainer_email='michael@stroeder.com',
    url='https://pypi.python.org/pypi/ldap0/',
    download_url='https://pypi.python.org/pypi/ldap0/',
    classifiers=[
        'Development Status :: 5 - Production/Stable',
        'Intended Audience :: Developers',
        'Intended Audience :: System Administrators',
        'Operating System :: OS Independent',
        'Operating System :: MacOS :: MacOS X',
        'Operating System :: Microsoft :: Windows',
        'Operating System :: POSIX',
        'Programming Language :: C',
        'Programming Language :: Python',
        'Programming Language :: Python :: 2',
        'Topic :: Database',
        'Topic :: Internet',
        'Topic :: Software Development :: Libraries :: Python Modules',
        'Topic :: System :: Systems Administration :: Authentication/Directory :: LDAP',
        'License :: OSI Approved :: Python Software Foundation License',
    ],
    #-- C extension modules
    ext_modules=[
        Extension(
            name='_libldap0',
            sources=[
                '_libldap0/LDAPObject.c',
                '_libldap0/ldapcontrol.c',
                '_libldap0/common.c',
                '_libldap0/constants.c',
                '_libldap0/errors.c',
                '_libldap0/functions.c',
                '_libldap0/libldap0module.c',
                '_libldap0/message.c',
                '_libldap0/options.c',
                '_libldap0/berval.c',
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
    packages = [
        'ldap0',
        'ldap0.schema',
        'ldap0.extop',
        'ldap0.controls',
    ],
    package_dir={'': '.'},
    test_suite='tests',
    python_requires = '==2.7.*',
    include_package_data=True,
    install_requires=[
        'setuptools',
        'pyasn1>=0.3.7',
        'pyasn1_modules>=0.1.5',
    ],
    zip_safe=True,
)

#include "common.h"
#include "constants.h"
#include "errors.h"
#include "functions.h"
#include "ldapcontrol.h"

#include "ldapobject.h"

#define _STR(x) #x
#define STR(x) _STR(x)

void
LDAPinit_pkginfo( PyObject* d )
{
    PyObject *version;
    PyObject *author;
    PyObject *license;

    version = PyBytes_FromString(STR(LDAP0_MODULE_VERSION));
    author = PyBytes_FromString(STR(LDAP0_MODULE_AUTHOR));
    license = PyBytes_FromString(STR(LDAP0_MODULE_LICENSE));

    PyDict_SetItemString(d, "__version__", version);
    PyDict_SetItemString(d, "__author__", author);
    PyDict_SetItemString(d, "__license__", license);

    Py_DECREF(version);
    Py_DECREF(author);
    Py_DECREF(license);
}

/* dummy module methods */
static PyMethodDef methods[]  = {
    { NULL, NULL }
};

/* module initialisation */

PyObject* init_libldap0(void)
{
    PyObject *m, *d;

    /* Create the module and add the functions */
    static struct PyModuleDef ldap_moduledef = {
            PyModuleDef_HEAD_INIT,
            "_libldap0",          /* m_name */
            "",                   /* m_doc */
            -1,                   /* m_size */
            methods,              /* m_methods */
    };
    m = PyModule_Create(&ldap_moduledef);
    if (PyType_Ready(&LDAP_Type) < 0) {
        Py_DECREF(m);
        return NULL;
    }

    /* Add some symbolic constants to the module */
    d = PyModule_GetDict(m);

    LDAPinit_pkginfo(d);
    LDAPinit_constants(d);
    LDAPinit_errors(d);
    LDAPinit_functions(d);
    LDAPinit_control(d);

    /* Check for errors */
    if (PyErr_Occurred())
        Py_FatalError("can't initialize module _libldap0");

    return m;
}

PyMODINIT_FUNC PyInit__libldap0() {
    return init_libldap0();
}

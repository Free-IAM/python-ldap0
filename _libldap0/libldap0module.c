/* See https://www.python-ldap.org/ for details. */

#include "common.h"
#include "constants.h"
#include "errors.h"
#include "functions.h"
#include "ldapcontrol.h"

#include "LDAPObject.h"

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

    PyDict_SetItemString( d, "__version__", version );
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

#if defined(MS_WINDOWS) || defined(__CYGWIN__)
    LDAP_Type.ob_type = &PyType_Type;
#endif

    /* Create the module and add the functions */
    m = Py_InitModule("_libldap0", methods);
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

PyMODINIT_FUNC init__libldap0() {
    init_libldap0();
}

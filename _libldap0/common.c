/* Miscellaneous common routines */

#include "common.h"

/* dynamically add the methods into the module dictionary d */

void
LDAPadd_methods( PyObject* d, PyMethodDef* methods )
{
    PyMethodDef *meth;

    for( meth = methods; meth->ml_meth; meth++ ) {
        PyObject *f = PyCFunction_New( meth, NULL );
        PyDict_SetItemString( d, meth->ml_name, f );
        Py_DECREF(f);
    }
}


/*
 * Copies out the data from a berval, and returns it as a new Python object,
 * Returns None if the berval pointer is NULL.
 *
 * Returns a new Python object on success, or NULL on failure.
 */
PyObject *
LDAPberval_to_object(const struct berval *bv)
{
    PyObject *ret = NULL;

    if (!bv) {
        ret = Py_None;
        Py_INCREF(ret);
    }
    else {
        ret = PyBytes_FromStringAndSize(bv->bv_val, bv->bv_len);
    }

    return ret;
}

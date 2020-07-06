#include "common.h"
#include "ldapobject.h"
#include "ldapcontrol.h"
#include "constants.h"
#include "errors.h"

#include "lber.h"

/* Free a single LDAPControl object created by Tuple_to_LDAPControl */

static void
LDAPControl_DEL(LDAPControl* lc)
{
    if (lc == NULL)
        return;

    if (lc->ldctl_oid)
        PyMem_DEL(lc->ldctl_oid);
    PyMem_DEL(lc);
}

/* Free an array of LDAPControl objects created by LDAPControls_from_object */

void
LDAPControl_List_DEL(LDAPControl** lcs)
{
    LDAPControl** lcp;
    if (lcs == NULL)
        return;

    for (lcp = lcs; *lcp; lcp++)
        LDAPControl_DEL(*lcp);

    PyMem_DEL(lcs);
}

/* Takes a tuple of the form:
 * (OID: string, Criticality: int/boolean, Value: string/None)
 * and converts it into an LDAPControl structure.
 *
 * The Value string should represent an ASN.1 encoded structure.
 */

static LDAPControl*
Tuple_to_LDAPControl(PyObject* tup)
{
    char *oid;
    char iscritical;
    struct berval berbytes;
    PyObject *bytes;
    LDAPControl *lc = NULL;
    Py_ssize_t len;

    if (!PyTuple_Check(tup)) {
        PyErr_SetObject(PyExc_TypeError, Py_BuildValue("yO", "expected a tuple", tup));
        return NULL;
    }

    if (!PyArg_ParseTuple(tup, "ybO:Tuple_to_LDAPControl", &oid, &iscritical, &bytes))
        return NULL;

    lc = PyMem_NEW(LDAPControl, 1);
    if (lc == NULL) {
        PyErr_NoMemory();
        return NULL;
    }

    lc->ldctl_iscritical = iscritical;

    len = strlen(oid);
    lc->ldctl_oid = PyMem_NEW(char, len + 1);
    if (lc->ldctl_oid == NULL) {
        PyErr_NoMemory();
        LDAPControl_DEL(lc);
        return NULL;
    }
    memcpy(lc->ldctl_oid, oid, len + 1);

    /* The berval can either be None or a String */
    if (bytes == Py_None) {
        berbytes.bv_len = 0;
        berbytes.bv_val = NULL;
    }
    else if (PyBytes_Check(bytes)) {
        berbytes.bv_len = PyBytes_Size(bytes);
        berbytes.bv_val = PyBytes_AsString(bytes);
    }
    else {
        PyErr_SetObject(PyExc_TypeError, Py_BuildValue("sO", "expected a byte-string", bytes));
        LDAPControl_DEL(lc);
        return NULL;
    }

    lc->ldctl_value = berbytes;

    return lc;
}

/* Convert a list of tuples (of a format acceptable to the Tuple_to_LDAPControl
 * function) into an array of LDAPControl objects. */

int
LDAPControls_from_object(PyObject* list, LDAPControl ***controls_ret)
{
    Py_ssize_t len, i;
    LDAPControl** ldcs;
    LDAPControl* ldc;
    PyObject* item;

    if (!PySequence_Check(list)) {
        PyErr_SetObject(PyExc_TypeError, Py_BuildValue("yO", "expected a list", list));
        return 0;
    }

    len = PySequence_Length(list);
    ldcs = PyMem_NEW(LDAPControl*, len + 1);
    if (ldcs == NULL) {
        PyErr_NoMemory();
        return 0;
    }

    for (i = 0; i < len; i++) {
        item = PySequence_GetItem(list, i);
        if (item == NULL) {
            PyMem_DEL(ldcs);
            return 0;
        }

        ldc = Tuple_to_LDAPControl(item);
        if (ldc == NULL) {
            Py_DECREF(item);
            PyMem_DEL(ldcs);
            return 0;
        }

        ldcs[i] = ldc;
        Py_DECREF(item);
    }

    ldcs[len] = NULL;
    *controls_ret = ldcs;
    return 1;
}

PyObject*
LDAPControls_to_List(LDAPControl **ldcs)
{
    PyObject *res = 0, *pyctrl;
    LDAPControl **tmp = ldcs;
    Py_ssize_t num_ctrls = 0, i;

    if (tmp)
        while (*tmp++) num_ctrls++;

    if ((res = PyList_New(num_ctrls)) == NULL) {
        return NULL;
    }

    for (i = 0; i < num_ctrls; i++) {
        pyctrl = Py_BuildValue(
            "ybO&",
            ldcs[i]->ldctl_oid,
            ldcs[i]->ldctl_iscritical,
            LDAPberval_to_object, &ldcs[i]->ldctl_value);
        if (pyctrl == NULL) {
            Py_DECREF(res);
            return NULL;
        }
        PyList_SET_ITEM(res, i, pyctrl);
    }
    return res;
}



/* --------------- en-/decoders ------------- */

/* Matched Values, aka, Values Return Filter */
static PyObject*
encode_rfc3876(PyObject *self, PyObject *args)
{
    PyObject *res = 0;
    int err;
    BerElement *vrber = 0;
    char *vrFilter;
    struct berval *ctrl_val;

    if (!PyArg_ParseTuple(args, "y:encode_valuesreturnfilter_control", &vrFilter)) {
        goto endlbl;
    }

    if (!(vrber = ber_alloc_t(LBER_USE_DER))) {
        LDAPerr(LDAP_NO_MEMORY);
        goto endlbl;
    }

    err = ldap_put_vrFilter(vrber, vrFilter);
    if (err == -1) {
        LDAPerr(LDAP_FILTER_ERROR);
        goto endlbl;
    }

    err = ber_flatten(vrber, &ctrl_val);
    if (err == -1) {
        LDAPerr(LDAP_NO_MEMORY);
        goto endlbl;
    }

    res = LDAPberval_to_object(ctrl_val);
    ber_bvfree(ctrl_val);

endlbl:
    if (vrber)
        ber_free(vrber, 1);

    return res;
}

static PyObject*
encode_assertion_control(PyObject *self, PyObject *args)
{
    int err;
    PyObject *res = 0;
    char *assertion_filterstr;
    struct berval ctrl_val;
    LDAP *ld = NULL;

    if (!PyArg_ParseTuple(args, "y:encode_assertion_control", &assertion_filterstr)) {
        goto endlbl;
    }

    Py_BEGIN_ALLOW_THREADS
    err = ldap_create(&ld);
    Py_END_ALLOW_THREADS
    if (err != LDAP_SUCCESS)
        return LDAPerror(ld);

    err = ldap_create_assertion_control_value(ld, assertion_filterstr, &ctrl_val);

    if (err != LDAP_SUCCESS) {
        LDAPerror(ld);
        Py_BEGIN_ALLOW_THREADS
        ldap_unbind_ext(ld, NULL, NULL);
        Py_END_ALLOW_THREADS
        return NULL;
    }
    Py_BEGIN_ALLOW_THREADS
    ldap_unbind_ext(ld, NULL, NULL);
    Py_END_ALLOW_THREADS

    res = LDAPberval_to_object(&ctrl_val);
    if (ctrl_val.bv_val != NULL) {
        ber_memfree(ctrl_val.bv_val);
    }
    endlbl:

    return res;
}

static PyMethodDef methods[] = {
    {
        "encode_valuesreturnfilter_control",
        encode_rfc3876,
        METH_VARARGS
    },
    {
        "encode_assertion_control",
        encode_assertion_control,
        METH_VARARGS
    },
    { NULL, NULL }
};

void
LDAPinit_control(PyObject *d)
{
    LDAPadd_methods(d, methods);
}

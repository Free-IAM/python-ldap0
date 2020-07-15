/*
 * errors that arise from ldap use
 * Most errors become their own exception */

#include "common.h"
#include "errors.h"
#include "ldapcontrol.h"
#include <errno.h>
#include <string.h>

/* the base exception class */

PyObject*
LDAPexception_class;

/* list of error objects */

#define LDAP_ERROR_MIN          LDAP_REFERRAL_LIMIT_EXCEEDED

#ifdef LDAP_PROXIED_AUTHORIZATION_DENIED
  #define LDAP_ERROR_MAX          LDAP_PROXIED_AUTHORIZATION_DENIED
#else
  #ifdef LDAP_ASSERTION_FAILED
    #define LDAP_ERROR_MAX          LDAP_ASSERTION_FAILED
  #else
    #define LDAP_ERROR_MAX          LDAP_OTHER
  #endif
#endif

#define LDAP_ERROR_OFFSET       -LDAP_ERROR_MIN

static PyObject* errobjects[ LDAP_ERROR_MAX-LDAP_ERROR_MIN+1 ];


/* Convert a bare LDAP error number into an exception */
PyObject*
LDAPerr(int errnum)
{
    if (errnum >= LDAP_ERROR_MIN && errnum <= LDAP_ERROR_MAX)
        PyErr_SetNone(errobjects[errnum+LDAP_ERROR_OFFSET]);
    else
        PyErr_SetObject(LDAPexception_class,
        Py_BuildValue("{s:i}", "errnum", errnum));
    return NULL;
}

/* Convert an LDAP error into an informative python exception */
PyObject*
LDAPraise_for_message(LDAP *l, LDAPMessage *m)
{
    if (l == NULL) {
        PyErr_SetFromErrno(LDAPexception_class);
        ldap_msgfree(m);
        return NULL;
    } else {

        int myerrno, errnum, opt_errnum, msgid = -1, msgtype = 0;
        PyObject *errobj;
        PyObject *info;
        PyObject *str;
        PyObject *pyerrno;
        PyObject *pyresult;
        PyObject *pyctrls = NULL;
        char *matched = NULL,
             *error = NULL,
             **refs = NULL;
        LDAPControl **serverctrls = NULL;

        /* at first save errno for later use before it gets overwritten by another call */
        myerrno = errno;

        if (m != NULL) {
            msgid = ldap_msgid(m);
            msgtype = ldap_msgtype(m);
            ldap_parse_result(l, m, &errnum, &matched, &error, &refs,
                              &serverctrls, 1);
        }

        if (msgtype <= 0) {
            opt_errnum = ldap_get_option(l, LDAP_OPT_ERROR_NUMBER, &errnum);
            if (opt_errnum != LDAP_OPT_SUCCESS)
                errnum = opt_errnum;

            if (errnum == LDAP_NO_MEMORY) {
                return PyErr_NoMemory();
            }

            ldap_get_option(l, LDAP_OPT_MATCHED_DN, &matched);
            ldap_get_option(l, LDAP_OPT_ERROR_STRING, &error);
        }

        if (errnum >= LDAP_ERROR_MIN && errnum <= LDAP_ERROR_MAX)
            errobj = errobjects[errnum+LDAP_ERROR_OFFSET];
        else
            errobj = LDAPexception_class;

        info = PyDict_New();
        if (info == NULL) {
            ldap_memfree(matched);
            ldap_memfree(error);
            ldap_memvfree((void **)refs);
            ldap_controls_free(serverctrls);
            return NULL;
        }

        if (msgtype > 0) {
            pyresult = PyLong_FromLong(msgtype);
            if (pyresult)
                PyDict_SetItemString(info, "msgtype", pyresult);
            Py_XDECREF(pyresult);
        }

        if (msgid >= 0) {
            pyresult = PyLong_FromLong(msgid);
            if (pyresult)
                PyDict_SetItemString(info, "msgid", pyresult);
            Py_XDECREF(pyresult);
        }

        pyresult = PyLong_FromLong(errnum);
        if (pyresult)
            PyDict_SetItemString(info, "result", pyresult);
        Py_XDECREF(pyresult);

        str = PyBytes_FromString(ldap_err2string(errnum));
        if (str)
            PyDict_SetItemString( info, "desc", str );
        Py_XDECREF(str);

        if (myerrno != 0) {
            pyerrno = PyLong_FromLong(myerrno);
            if (pyerrno)
                PyDict_SetItemString( info, "errno", pyerrno );
            Py_XDECREF(pyerrno);
        }

        if (!(pyctrls = LDAPControls_to_List(serverctrls))) {
            int err = LDAP_NO_MEMORY;

            ldap_set_option(l, LDAP_OPT_ERROR_NUMBER, &err);
            ldap_memfree(matched);
            ldap_memfree(error);
            ldap_memvfree((void **)refs);
            ldap_controls_free(serverctrls);
            return PyErr_NoMemory();
        }
        ldap_controls_free(serverctrls);
        PyDict_SetItemString(info, "ctrls", pyctrls);
        Py_XDECREF(pyctrls);

        if (matched != NULL) {
            if (*matched != '\0') {
                str = PyBytes_FromString(matched);
                if (str)
                    PyDict_SetItemString(info, "matched", str);
                Py_XDECREF(str);
            }
            ldap_memfree(matched);
        }

        if (errnum == LDAP_REFERRAL && refs != NULL && refs[0] != NULL) {
            /* Keep old behaviour, overshadow error message */
            char err[1024];

            snprintf(err, sizeof(err), "Referral:\n%s", refs[0]);
            str = PyBytes_FromString(err);
            PyDict_SetItemString(info, "info", str);
            Py_XDECREF(str);
        } else if (error != NULL && *error != '\0') {
            str = PyBytes_FromString(error);
            if (str)
                PyDict_SetItemString( info, "info", str );
            Py_XDECREF(str);
        }

        PyErr_SetObject( errobj, info );
        Py_DECREF(info);
        ldap_memvfree((void **)refs);
        ldap_memfree(error);
        return NULL;
    }
}

PyObject *
LDAPerror(LDAP *l)
{
    return LDAPraise_for_message(l, NULL);
}


/* initialisation */

void
LDAPinit_errors( PyObject*d ) {

    /* create the base exception class */
    LDAPexception_class = PyErr_NewException("ldap0.LDAPError", NULL, NULL);
    PyDict_SetItemString( d, "LDAPError", LDAPexception_class );

    /* XXX - backward compatibility with pre-1.8 */
    PyDict_SetItemString( d, "error", LDAPexception_class );

    /* create each LDAP error object */

# define seterrobj2(n,o) \
    PyDict_SetItemString(d, #n, (errobjects[LDAP_##n+LDAP_ERROR_OFFSET] = o))


# define seterrobj(n) { \
        PyObject *e = PyErr_NewException("ldap0." #n, \
        LDAPexception_class, NULL); \
        PyObject *nobj = PyLong_FromLong(LDAP_##n); \
        PyObject_SetAttrString(e, "errnum", nobj); \
        Py_DECREF(nobj); \
        seterrobj2(n, e); \
        Py_INCREF(e); \
    }

    seterrobj(ADMINLIMIT_EXCEEDED);
    seterrobj(AFFECTS_MULTIPLE_DSAS);
    seterrobj(ALIAS_DEREF_PROBLEM);
    seterrobj(ALIAS_PROBLEM);
    seterrobj(ALREADY_EXISTS);
    seterrobj(AUTH_METHOD_NOT_SUPPORTED);
    seterrobj(AUTH_UNKNOWN);
    seterrobj(BUSY);
    seterrobj(CLIENT_LOOP);
    seterrobj(COMPARE_FALSE);
    seterrobj(COMPARE_TRUE);
    seterrobj(CONFIDENTIALITY_REQUIRED);
    seterrobj(CONNECT_ERROR);
    seterrobj(CONSTRAINT_VIOLATION);
    seterrobj(CONTROL_NOT_FOUND);
    seterrobj(DECODING_ERROR);
    seterrobj(ENCODING_ERROR);
    seterrobj(FILTER_ERROR);
    seterrobj(INAPPROPRIATE_AUTH);
    seterrobj(INAPPROPRIATE_MATCHING);
    seterrobj(INSUFFICIENT_ACCESS);
    seterrobj(INVALID_CREDENTIALS);
    seterrobj(INVALID_DN_SYNTAX);
    seterrobj(INVALID_SYNTAX);
    seterrobj(IS_LEAF);
    seterrobj(LOCAL_ERROR);
    seterrobj(LOOP_DETECT);
    seterrobj(MORE_RESULTS_TO_RETURN);
    seterrobj(NAMING_VIOLATION);
    seterrobj(NO_MEMORY);
    seterrobj(NO_OBJECT_CLASS_MODS);
    seterrobj(NO_OBJECT_CLASS_MODS);
    seterrobj(NO_RESULTS_RETURNED);
    seterrobj(NO_SUCH_ATTRIBUTE);
    seterrobj(NO_SUCH_OBJECT);
    seterrobj(NOT_ALLOWED_ON_NONLEAF);
    seterrobj(NOT_ALLOWED_ON_RDN);
    seterrobj(NOT_SUPPORTED);
    seterrobj(OBJECT_CLASS_VIOLATION);
    seterrobj(OPERATIONS_ERROR);
    seterrobj(OTHER);
    seterrobj(PARAM_ERROR);
    seterrobj(PARTIAL_RESULTS);
    seterrobj(PROTOCOL_ERROR);
    seterrobj(REFERRAL);
    seterrobj(REFERRAL_LIMIT_EXCEEDED);
    seterrobj(RESULTS_TOO_LARGE);
    seterrobj(SASL_BIND_IN_PROGRESS);
    seterrobj(SERVER_DOWN);
    seterrobj(SIZELIMIT_EXCEEDED);
    seterrobj(STRONG_AUTH_NOT_SUPPORTED);
    seterrobj(STRONG_AUTH_REQUIRED);
    seterrobj(SUCCESS);
    seterrobj(TIMELIMIT_EXCEEDED);
    seterrobj(TIMEOUT);
    seterrobj(TYPE_OR_VALUE_EXISTS);
    seterrobj(UNAVAILABLE);
    seterrobj(UNAVAILABLE_CRITICAL_EXTENSION);
    seterrobj(UNDEFINED_TYPE);
    seterrobj(UNWILLING_TO_PERFORM);
    seterrobj(USER_CANCELLED);
    seterrobj(VLV_ERROR);
    seterrobj(X_PROXY_AUTHZ_FAILURE);

#ifdef LDAP_API_FEATURE_CANCEL
    seterrobj(CANCELLED);
    seterrobj(NO_SUCH_OPERATION);
    seterrobj(TOO_LATE);
    seterrobj(CANNOT_CANCEL);
#endif

#ifdef LDAP_ASSERTION_FAILED
    seterrobj(ASSERTION_FAILED);
#endif

#ifdef LDAP_PROXIED_AUTHORIZATION_DENIED
    seterrobj(PROXIED_AUTHORIZATION_DENIED);
#endif

}

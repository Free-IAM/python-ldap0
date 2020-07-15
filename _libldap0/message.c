#include "common.h"
#include "message.h"
#include "errors.h"
#include "ldapcontrol.h"
#include "constants.h"

/*
 * Converts an LDAP message into a Python structure.
 *
 * On success, returns a list of dictionaries.
 * On failure, returns NULL, and sets an error.
 *
 * The message m is always freed, regardless of return value.
 *
 * If add_ctrls is non-zero, per-entry/referral/partial/intermediate
 * controls will be added as a third item to each entry tuple
 *
 * If add_intermediates is non-zero, intermediate/partial results will
 * be returned
 */
PyObject *
LDAPmessage_to_python(LDAP *ld, LDAPMessage *m, int add_ctrls, int add_intermediates)
{
    /* we convert an LDAP message into a python structure.
     * It is always a list of dictionaries.
     * We always free m.
     */

    PyObject *result, *pyctrls = 0;
    LDAPMessage* entry;
    LDAPControl **req_ctrls = 0;
    int rc;

    result = PyList_New(0);
    if (result == NULL) {
        ldap_msgfree(m);
        return NULL;
    }

    for(
        entry = ldap_first_entry(ld, m);
        entry != NULL;
        entry = ldap_next_entry(ld, entry)
    ) {
        char *dn;
        char *attr;
        BerElement *ber = NULL;
        PyObject* entrytuple;
        PyObject* attrdict;

        dn = ldap_get_dn(ld, entry);
        if (dn == NULL)  {
            Py_DECREF(result);
            ldap_msgfree(m);
            return LDAPerror(ld);
        }

        attrdict = PyDict_New();
        if (attrdict == NULL) {
            Py_DECREF(result);
            ldap_msgfree(m);
            ldap_memfree(dn);
            return NULL;
        }

        rc = ldap_get_entry_controls( ld, entry, &req_ctrls );
        if (rc) {
            Py_DECREF(result);
            ldap_msgfree(m);
            ldap_memfree(dn);
            return LDAPerror(ld);
        }

        /* convert req_ctrls to list of tuples */
        if ( ! ( pyctrls = LDAPControls_to_List( req_ctrls ) ) ) {
            int err = LDAP_NO_MEMORY;
            ldap_set_option( ld, LDAP_OPT_ERROR_NUMBER, &err );
            Py_DECREF(result);
            ldap_msgfree(m);
            ldap_memfree(dn);
            ldap_controls_free(req_ctrls);
            return LDAPerror(ld);
        }
        ldap_controls_free(req_ctrls);

        /* Fill attrdict with lists */
        for (
            attr = ldap_first_attribute(ld, entry, &ber);
            attr != NULL;
            attr = ldap_next_attribute(ld, entry, ber)
        ) {
            PyObject* valuelist;
            PyObject *attr_key;
            struct berval **bvals;

            attr_key = PyBytes_FromString(attr);
            bvals = ldap_get_values_len(ld, entry, attr);

            /* Find which list to append to */
            if ( PyDict_Contains(attrdict, attr_key) ) {
                valuelist = PyDict_GetItem(attrdict, attr_key);
                if (valuelist != NULL)
                    /* own the ref from here */
                    Py_INCREF(valuelist);
            } else {
                valuelist = PyList_New(0);
                if (
                    valuelist != NULL &&
                    PyDict_SetItem(attrdict, attr_key, valuelist) == -1
                ) {
                    Py_DECREF(valuelist);
                    valuelist = NULL; /* catch error later */
                }
            }

            if (valuelist == NULL) {
                Py_DECREF(attrdict);
                Py_DECREF(result);
                if (ber != NULL)
                    ber_free(ber, 0);
                ldap_msgfree(m);
                ldap_memfree(attr);
                ldap_memfree(dn);
                Py_XDECREF(pyctrls);
                return NULL;
            }

            if (bvals != NULL) {
                Py_ssize_t i;

                for (i=0; bvals[i]; i++) {
                    PyObject *valuestr;
                    valuestr = LDAPberval_to_object(bvals[i]);
                    if (PyList_Append( valuelist, valuestr ) == -1) {
                        Py_DECREF(attrdict);
                        Py_DECREF(result);
                        Py_DECREF(valuestr);
                        Py_DECREF(valuelist);
                        if (ber != NULL)
                            ber_free(ber, 0);
                        ldap_msgfree(m);
                        ldap_memfree(attr);
                        ldap_memfree(dn);
                        Py_XDECREF(pyctrls);
                        return NULL;
                    }
                    Py_DECREF(valuestr);
                }

                ldap_value_free_len(bvals);
            }

            Py_DECREF(valuelist);
            ldap_memfree(attr);
        }

        if (add_ctrls) {
            entrytuple = Py_BuildValue("(yOO)", dn, attrdict, pyctrls);
        } else {
            entrytuple = Py_BuildValue("(yO)", dn, attrdict);
        }
        ldap_memfree(dn);
        Py_DECREF(attrdict);
        Py_XDECREF(pyctrls);
        PyList_Append(result, entrytuple);
        Py_DECREF(entrytuple);
        if (ber != NULL)
            ber_free(ber, 0);

    }

    for(
        entry = ldap_first_reference(ld,m);
        entry != NULL;
        entry = ldap_next_reference(ld,entry)
    ) {
        char **refs = NULL;
        PyObject* entrytuple;
        PyObject* reflist = PyList_New(0);

        if (reflist == NULL)  {
            Py_DECREF(result);
            ldap_msgfree(m);
            return NULL;
        }

        if (ldap_parse_reference(ld, entry, &refs, &req_ctrls, 0) != LDAP_SUCCESS) {
            Py_DECREF(reflist);
            Py_DECREF(result);
            ldap_msgfree(m);
            return LDAPerror(ld);
        }

        /* convert req_ctrls to list of tuples */
        if ( ! ( pyctrls = LDAPControls_to_List( req_ctrls ) ) ) {
            int err = LDAP_NO_MEMORY;
            ldap_set_option( ld, LDAP_OPT_ERROR_NUMBER, &err );
                  Py_DECREF(reflist);
            Py_DECREF(result);
            ldap_msgfree(m);
            ldap_controls_free(req_ctrls);
            return LDAPerror(ld);
        }
        ldap_controls_free(req_ctrls);
        if (refs) {
            Py_ssize_t i;
            for (i=0; refs[i] != NULL; i++) {
                PyObject *refstr = PyBytes_FromString(refs[i]);
                PyList_Append(reflist, refstr);
                Py_DECREF(refstr);
            }
            ber_memvfree( (void **) refs );
        }
        if (add_ctrls) {
            entrytuple = Py_BuildValue("(yOO)", NULL, reflist, pyctrls);
        } else {
            entrytuple = Py_BuildValue("(yO)", NULL, reflist);
        }
        Py_DECREF(reflist);
        Py_XDECREF(pyctrls);
        PyList_Append(result, entrytuple);
        Py_DECREF(entrytuple);
    }

    if (add_intermediates) {
        for(
            entry = ldap_first_message(ld,m);
            entry != NULL;
            entry = ldap_next_message(ld,entry)
        ) {
            /* list of tuples */
            /* each tuple is OID, Berval, controllist */
            if ( LDAP_RES_INTERMEDIATE == ldap_msgtype( entry ) ) {
                PyObject* valtuple;
                PyObject *valuestr;
                char *retoid = 0;
                struct berval *retdata = 0;

                if (ldap_parse_intermediate( ld, entry, &retoid, &retdata, &req_ctrls, 0 ) != LDAP_SUCCESS) {
                    Py_DECREF(result);
                    ldap_msgfree(m);
                    return LDAPerror(ld);
                }

                /* convert req_ctrls to list of tuples */
                if ( ! ( pyctrls = LDAPControls_to_List( req_ctrls ) ) ) {
                    int err = LDAP_NO_MEMORY;
                    ldap_set_option( ld, LDAP_OPT_ERROR_NUMBER, &err );
                    Py_DECREF(result);
                    ldap_msgfree(m);
                    ldap_controls_free(req_ctrls);
                    ldap_memfree(retoid);
                    ber_bvfree(retdata);
                    return LDAPerror(ld);
                }
                ldap_controls_free(req_ctrls);

                valuestr = LDAPberval_to_object(retdata);
                ber_bvfree( retdata );
                valtuple = Py_BuildValue("(yOO)", retoid, valuestr ? valuestr : Py_None, pyctrls);
                ldap_memfree( retoid );
                Py_DECREF(valuestr);
                Py_XDECREF(pyctrls);
                PyList_Append(result, valtuple);
                Py_DECREF(valtuple);
            }
        }
    }

    ldap_msgfree(m);
    return result;

}

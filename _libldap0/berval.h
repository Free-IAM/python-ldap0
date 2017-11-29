/* See https://www.python-ldap.org/ for details. */

#ifndef __h_berval
#define __h_berval

#include "common.h"
#include "lber.h"

int  LDAPberval_from_object(PyObject *obj, struct berval *bv);
void LDAPberval_release(struct berval *bv);
PyObject *LDAPberval_to_object(const struct berval *bv);

#endif /* __h_berval_ */

#ifndef __h_errors_
#define __h_errors_

#include "common.h"
#include "lber.h"
#include "ldap.h"

extern PyObject* LDAPexception_class;
extern PyObject* LDAPerror(LDAP*);
extern PyObject *LDAPraise_for_message(LDAP *, LDAPMessage *m);
extern void LDAPinit_errors(PyObject*);
PyObject* LDAPerr(int errnum);

#endif /* __h_errors */

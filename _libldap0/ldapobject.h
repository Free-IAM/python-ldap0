#ifndef __h_ldapobject
#define __h_ldapobject

#include "common.h"

#include "lber.h"
#include "ldap.h"
#if LDAP_API_VERSION < 2040
#error Module _libldap0 requires OpenLDAP 2.4.x
#endif

typedef PyThreadState* _threadstate;

typedef struct {
    PyObject_HEAD
    LDAP* ldap;
    _threadstate _save; /* for thread saving on referrals */
    int valid;
} LDAPObject;

extern PyTypeObject LDAP_Type;
#define LDAPObject_Check(v) (Py_TYPE(v) == &LDAP_Type)

extern LDAPObject *newLDAPObject( LDAP* );

/* macros to allow thread saving in the context of an LDAP connection */

#define LDAP_BEGIN_ALLOW_THREADS( l ) { \
    LDAPObject *lo = (l); \
    if (lo->_save != NULL) \
      Py_FatalError( "saving thread twice?" ); \
    lo->_save = PyEval_SaveThread(); \
}

#define LDAP_END_ALLOW_THREADS( l ) { \
    LDAPObject *lo = (l); \
    _threadstate _save = lo->_save; \
    lo->_save = NULL; \
    PyEval_RestoreThread( _save ); \
  }

#endif /* __h_ldapobject */

from typing import Any

import ldap0
API_VERSION: int
AUTH_NONE: int
AUTH_SIMPLE: int
AVA_BINARY: int
AVA_NONPRINTABLE: int
AVA_NULL: int
AVA_STRING: int
CONTROL_ASSERT: bytes
CONTROL_MANAGEDSAIT: bytes
CONTROL_PAGEDRESULTS: bytes
CONTROL_PASSWORDPOLICYREQUEST: bytes
CONTROL_PASSWORDPOLICYRESPONSE: bytes
CONTROL_POST_READ: bytes
CONTROL_PRE_READ: bytes
CONTROL_PROXY_AUTHZ: bytes
CONTROL_RELAX: bytes
CONTROL_SORTREQUEST: bytes
CONTROL_SORTRESPONSE: bytes
CONTROL_SUBENTRIES: bytes
CONTROL_SYNC: bytes
CONTROL_SYNC_DONE: bytes
CONTROL_SYNC_STATE: bytes
CONTROL_VALUESRETURNFILTER: bytes
DEREF_ALWAYS: int
DEREF_FINDING: int
DEREF_NEVER: int
DEREF_SEARCHING: int
DN_FORMAT_AD_CANONICAL: int
DN_FORMAT_DCE: int
DN_FORMAT_LDAP: int
DN_FORMAT_LDAPV2: int
DN_FORMAT_LDAPV3: int
DN_FORMAT_MASK: int
DN_FORMAT_UFN: int
DN_PEDANTIC: int
DN_PRETTY: int
DN_P_NOLEADTRAILSPACES: int
DN_P_NOSPACEAFTERRDN: int
DN_SKIP: int
MOD_ADD: int
MOD_BVALUES: int
MOD_DELETE: int
MOD_INCREMENT: int
MOD_REPLACE: int
MSG_ALL: int
MSG_ONE: int
MSG_RECEIVED: int
NO_LIMIT: int
OPT_API_FEATURE_INFO: int
OPT_API_INFO: int
OPT_CONNECT_ASYNC: int
OPT_DEBUG_LEVEL: int
OPT_DEFBASE: int
OPT_DEREF: int
OPT_DESC: int
OPT_DIAGNOSTIC_MESSAGE: int
OPT_ERROR_NUMBER: int
OPT_ERROR_STRING: int
OPT_HOST_NAME: int
OPT_MATCHED_DN: int
OPT_NETWORK_TIMEOUT: int
OPT_PROTOCOL_VERSION: int
OPT_REFERRALS: int
OPT_REFHOPLIMIT: int
OPT_RESTART: int
OPT_SERVER_CONTROLS: int
OPT_SIZELIMIT: int
OPT_SUCCESS: int
OPT_TIMELIMIT: int
OPT_TIMEOUT: int
OPT_URI: int
OPT_X_KEEPALIVE_IDLE: int
OPT_X_KEEPALIVE_INTERVAL: int
OPT_X_KEEPALIVE_PROBES: int
OPT_X_SASL_AUTHCID: int
OPT_X_SASL_AUTHZID: int
OPT_X_SASL_MECH: int
OPT_X_SASL_NOCANON: int
OPT_X_SASL_REALM: int
OPT_X_SASL_SECPROPS: int
OPT_X_SASL_SSF: int
OPT_X_SASL_SSF_EXTERNAL: int
OPT_X_SASL_SSF_MAX: int
OPT_X_SASL_SSF_MIN: int
OPT_X_SASL_USERNAME: int
OPT_X_TLS: int
OPT_X_TLS_ALLOW: int
OPT_X_TLS_CACERTDIR: int
OPT_X_TLS_CACERTFILE: int
OPT_X_TLS_CERTFILE: int
OPT_X_TLS_CIPHER_SUITE: int
OPT_X_TLS_CRLCHECK: int
OPT_X_TLS_CRLFILE: int
OPT_X_TLS_CRL_ALL: int
OPT_X_TLS_CRL_NONE: int
OPT_X_TLS_CRL_PEER: int
OPT_X_TLS_CTX: int
OPT_X_TLS_DEMAND: int
OPT_X_TLS_DHFILE: int
OPT_X_TLS_HARD: int
OPT_X_TLS_KEYFILE: int
OPT_X_TLS_NEVER: int
OPT_X_TLS_NEWCTX: int
OPT_X_TLS_PACKAGE: int
OPT_X_TLS_PROTOCOL_MIN: int
OPT_X_TLS_RANDOM_FILE: int
OPT_X_TLS_REQUIRE_CERT: int
OPT_X_TLS_TRY: int
PORT: int
REQ_ABANDON: int
REQ_ADD: int
REQ_BIND: int
REQ_COMPARE: int
REQ_DELETE: int
REQ_EXTENDED: int
REQ_MODIFY: int
REQ_MODRDN: int
REQ_SEARCH: int
REQ_UNBIND: int
RES_ADD: int
RES_ANY: int
RES_BIND: int
RES_COMPARE: int
RES_DELETE: int
RES_EXTENDED: int
RES_INTERMEDIATE: int
RES_MODIFY: int
RES_MODRDN: int
RES_SEARCH_ENTRY: int
RES_SEARCH_REFERENCE: int
RES_SEARCH_RESULT: int
RES_UNSOLICITED: int
SASL_AUTOMATIC: int
SASL_AVAIL: int
SASL_INTERACTIVE: int
SASL_QUIET: int
SCOPE_BASE: int
SCOPE_ONELEVEL: int
SCOPE_SUBORDINATE: int
SCOPE_SUBTREE: int
SYNC_INFO: bytes
TAG_CONTROLS: int
TAG_EXOP_REQ_OID: int
TAG_EXOP_REQ_VALUE: int
TAG_EXOP_RES_OID: int
TAG_EXOP_RES_VALUE: int
TAG_LDAPCRED: int
TAG_LDAPDN: int
TAG_MESSAGE: int
TAG_MSGID: int
TAG_NEWSUPERIOR: int
TAG_REFERRAL: int
TAG_SASL_RES_CREDS: int
TLS_AVAIL: int
VENDOR_VERSION: int
VERSION: int
VERSION1: int
VERSION2: int
VERSION3: int
VERSION_MAX: int
VERSION_MIN: int
_forward: Any
_reverse: Any

def _initialize(*args, **kwargs) -> Any: ...
def encode_assertion_control(*args, **kwargs) -> bytes: ...
def encode_valuesreturnfilter_control(*args, **kwargs) -> bytes: ...
def get_option(*args, **kwargs) -> Any: ...
def set_option(*args, **kwargs) -> Any: ...
def str2dn(*args, **kwargs) -> Any: ...

class ADMINLIMIT_EXCEEDED(ldap0.LDAPError): ...

class AFFECTS_MULTIPLE_DSAS(ldap0.LDAPError): ...

class ALIAS_DEREF_PROBLEM(ldap0.LDAPError): ...

class ALIAS_PROBLEM(ldap0.LDAPError): ...

class ALREADY_EXISTS(ldap0.LDAPError): ...

class ASSERTION_FAILED(ldap0.LDAPError): ...

class AUTH_METHOD_NOT_SUPPORTED(ldap0.LDAPError): ...

class AUTH_UNKNOWN(ldap0.LDAPError): ...

class BUSY(ldap0.LDAPError): ...

class CANCELLED(ldap0.LDAPError): ...

class CANNOT_CANCEL(ldap0.LDAPError): ...

class CLIENT_LOOP(ldap0.LDAPError): ...

class COMPARE_FALSE(ldap0.LDAPError): ...

class COMPARE_TRUE(ldap0.LDAPError): ...

class CONFIDENTIALITY_REQUIRED(ldap0.LDAPError): ...

class CONNECT_ERROR(ldap0.LDAPError): ...

class CONSTRAINT_VIOLATION(ldap0.LDAPError): ...

class CONTROL_NOT_FOUND(ldap0.LDAPError): ...

class DECODING_ERROR(ldap0.LDAPError): ...

class ENCODING_ERROR(ldap0.LDAPError): ...

class FILTER_ERROR(ldap0.LDAPError): ...

class INAPPROPRIATE_AUTH(ldap0.LDAPError): ...

class INAPPROPRIATE_MATCHING(ldap0.LDAPError): ...

class INSUFFICIENT_ACCESS(ldap0.LDAPError): ...

class INVALID_CREDENTIALS(ldap0.LDAPError): ...

class INVALID_DN_SYNTAX(ldap0.LDAPError): ...

class INVALID_SYNTAX(ldap0.LDAPError): ...

class IS_LEAF(ldap0.LDAPError): ...

class LDAPError(Exception): ...

class LOCAL_ERROR(ldap0.LDAPError): ...

class LOOP_DETECT(ldap0.LDAPError): ...

class MORE_RESULTS_TO_RETURN(ldap0.LDAPError): ...

class NAMING_VIOLATION(ldap0.LDAPError): ...

class NOT_ALLOWED_ON_NONLEAF(ldap0.LDAPError): ...

class NOT_ALLOWED_ON_RDN(ldap0.LDAPError): ...

class NOT_SUPPORTED(ldap0.LDAPError): ...

class NO_MEMORY(ldap0.LDAPError): ...

class NO_OBJECT_CLASS_MODS(ldap0.LDAPError): ...

class NO_RESULTS_RETURNED(ldap0.LDAPError): ...

class NO_SUCH_ATTRIBUTE(ldap0.LDAPError): ...

class NO_SUCH_OBJECT(ldap0.LDAPError): ...

class NO_SUCH_OPERATION(ldap0.LDAPError): ...

class OBJECT_CLASS_VIOLATION(ldap0.LDAPError): ...

class OPERATIONS_ERROR(ldap0.LDAPError): ...

class OTHER(ldap0.LDAPError): ...

class PARAM_ERROR(ldap0.LDAPError): ...

class PARTIAL_RESULTS(ldap0.LDAPError): ...

class PROTOCOL_ERROR(ldap0.LDAPError): ...

class PROXIED_AUTHORIZATION_DENIED(ldap0.LDAPError): ...

class REFERRAL(ldap0.LDAPError): ...

class REFERRAL_LIMIT_EXCEEDED(ldap0.LDAPError): ...

class RESULTS_TOO_LARGE(ldap0.LDAPError): ...

class SASL_BIND_IN_PROGRESS(ldap0.LDAPError): ...

class SERVER_DOWN(ldap0.LDAPError): ...

class SIZELIMIT_EXCEEDED(ldap0.LDAPError): ...

class STRONG_AUTH_NOT_SUPPORTED(ldap0.LDAPError): ...

class STRONG_AUTH_REQUIRED(ldap0.LDAPError): ...

class SUCCESS(ldap0.LDAPError): ...

class TIMELIMIT_EXCEEDED(ldap0.LDAPError): ...

class TIMEOUT(ldap0.LDAPError): ...

class TOO_LATE(ldap0.LDAPError): ...

class TYPE_OR_VALUE_EXISTS(ldap0.LDAPError): ...

class UNAVAILABLE(ldap0.LDAPError): ...

class UNAVAILABLE_CRITICAL_EXTENSION(ldap0.LDAPError): ...

class UNDEFINED_TYPE(ldap0.LDAPError): ...

class UNWILLING_TO_PERFORM(ldap0.LDAPError): ...

class USER_CANCELLED(ldap0.LDAPError): ...

class VLV_ERROR(ldap0.LDAPError): ...

class X_PROXY_AUTHZ_FAILURE(ldap0.LDAPError): ...

class error(Exception): ...
